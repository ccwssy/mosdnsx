package adguard_rule

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// newDnsQuery 构造一个单问题查询报文。
func newDnsQuery(name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	return q
}


// testLists 把若干规则文本包装成 ruleList，名字按下标生成，用于验证列表归属回查。
func testLists(texts ...string) []ruleList {
	lists := make([]ruleList, 0, len(texts))
	for i, text := range texts {
		lists = append(lists, ruleList{Name: fmt.Sprintf("list-%d", i+1), Text: text})
	}
	return lists
}

// 本测试锁定「过滤语义与 AdGuard Home 一致」这一契约。
// 旧的自写解析器会在 $important / $badfilter / $client / $dnstype / hosts 上行为错误，
// 这些用例即为其回归防线。
func TestFilterEngineSemantics(t *testing.T) {
	const list = `
! 注释行
||ads.example.com^
||tracker.example.net^$important
||log.example.org^
||log.example.org^$badfilter
@@||allowlisted.example.com^
|192.168.1.5^$client=192.168.1.5
||clientonly.example.com^$client=192.168.1.5
||aaaa-only.example.com^$dnstype=AAAA
0.0.0.0 hosts-blocked.example.com
1.2.3.4 hosts-rewritten.example.com
/^regex-ad[0-9]+\.example\.com$/
`
	eng, err := newFilterEngine(testLists(list))
	if err != nil {
		t.Fatalf("newFilterEngine: %v", err)
	}

	cases := []struct {
		name   string
		host   string
		qtype  uint16
		client string
		want   bool
	}{
		{"普通拦截", "ads.example.com", 1, "", true},
		{"子域继承拦截", "sub.ads.example.com", 1, "", true},
		{"$important 拦截生效", "tracker.example.net", 1, "", true},
		{"$badfilter 抵消前一条", "log.example.org", 1, "", false},
		{"例外规则放行", "allowlisted.example.com", 1, "", false},
		{"$client 命中指定客户端", "clientonly.example.com", 1, "192.168.1.5", true},
		{"$client 非目标客户端放行", "clientonly.example.com", 1, "192.168.1.6", false},
		{"$dnstype=AAAA 命中 AAAA", "aaaa-only.example.com", 28, "", true},
		{"$dnstype=AAAA 不命中 A", "aaaa-only.example.com", 1, "", false},
		{"hosts 0.0.0.0 拦截", "hosts-blocked.example.com", 1, "", true},
		{"hosts 重写不算拦截", "hosts-rewritten.example.com", 1, "", false},
		{"正则规则", "regex-ad42.example.com", 1, "", true},
		{"无关域名放行", "normal.example.com", 1, "", false},
	}

	for _, c := range cases {
		var ip netip.Addr
		if c.client != "" {
			ip = netip.MustParseAddr(c.client)
		}
		got := eng.match(c.host, c.qtype, ip).Blocked
		if got != c.want {
			t.Errorf("%s: match(%q, qtype=%d, client=%q) blocked=%v, want %v",
				c.name, c.host, c.qtype, c.client, got, c.want)
		}
	}
}

// 白名单 $important 必须压过黑名单，这是 AGH 用户规则里最常见的写法。
// 注意：$important 例外规则按域名规则本身生效——写成 @@||sohu.com^ 会放行全部子域，
// 精确到子域时必须写 @@||pv.sohu.com^，与 AdGuard Home 行为一致。
func TestExceptionBeatsBlocklist(t *testing.T) {
	eng, err := newFilterEngine(testLists(
		"||pv.sohu.com^\n||sohu.com^\n",
		"@@||pv.sohu.com^$important\n",
	))
	if err != nil {
		t.Fatalf("newFilterEngine: %v", err)
	}
	if eng.match("pv.sohu.com", 1, netip.Addr{}).Blocked {
		t.Error("白名单 $important 未生效：pv.sohu.com 被误拦")
	}
	if !eng.match("other-ads.sohu.com", 1, netip.Addr{}).Blocked {
		t.Error("非白名单子域应继续被 ||sohu.com^ 拦截")
	}
}

// $important 例外规则对子域同样生效（与 AGH 语义一致），用作语义固定。
func TestImportantExceptionCoversSubdomains(t *testing.T) {
	eng, err := newFilterEngine(testLists(
		"||sohu.com^\n",
		"@@||sohu.com^$important\n",
	))
	if err != nil {
		t.Fatalf("newFilterEngine: %v", err)
	}
	if eng.match("any.sohu.com", 1, netip.Addr{}).Blocked {
		t.Error("$important 例外规则应对子域生效")
	}
}

// hosts 重写规则应给出目标地址而不是简单拦截。
func TestHostsRewriteIPs(t *testing.T) {
	eng, err := newFilterEngine(testLists("1.2.3.4 hosts-rewritten.example.com\n"))
	if err != nil {
		t.Fatalf("newFilterEngine: %v", err)
	}
	res := eng.match("hosts-rewritten.example.com", 1, netip.Addr{})
	if res.Blocked {
		t.Fatal("hosts 重写不应判为拦截")
	}
	if len(res.IPs) != 1 || res.IPs[0].String() != "1.2.3.4" {
		t.Fatalf("hosts 重写地址=%v, want [1.2.3.4]", res.IPs)
	}
}

// 空规则集不应 panic，且匹配恒为 false。
func TestEmptyEngine(t *testing.T) {
	eng, err := newFilterEngine(nil)
	if err != nil {
		t.Fatalf("newFilterEngine(nil): %v", err)
	}
	if eng.match("anything.example.com", 1, netip.Addr{}).Blocked {
		t.Error("空引擎不应拦截任何域名")
	}
	if eng.rulesCount() != 0 {
		t.Errorf("空引擎规则数=%d, want 0", eng.rulesCount())
	}
}

// buildBlockResponse 的三种模式都要产出合法应答。
func TestBuildBlockResponseModes(t *testing.T) {
	q := newDnsQuery("ads.example.com", 1)

	for _, mode := range []string{"null_ip", "nxdomain", "refused"} {
		r := buildBlockResponse(q, q.Question[0], mode, nil)
		if r == nil || len(r.Question) != 1 {
			t.Fatalf("mode %s: 应答非法", mode)
		}
		switch mode {
		case "null_ip":
			if len(r.Answer) != 1 {
				t.Errorf("mode %s: 答案数=%d, want 1", mode, len(r.Answer))
			}
		case "nxdomain":
			if r.Rcode != 3 {
				t.Errorf("mode %s: rcode=%d, want 3", mode, r.Rcode)
			}
		case "refused":
			if r.Rcode != 5 {
				t.Errorf("mode %s: rcode=%d, want 5", mode, r.Rcode)
			}
		}
	}
}

// 命中后必须能回查到「命中的是哪个规则集」以及命中的规则原文。
// 这是审计 filter_list / matched_rule 的数据来源，顺序错位会让归属全错。
func TestMatchReportsFilterList(t *testing.T) {
	eng, err := newFilterEngine(testLists(
		"||first.example.com^\n",
		"||second.example.com^\n0.0.0.0 hosts-second.example.com\n",
	))
	if err != nil {
		t.Fatalf("newFilterEngine: %v", err)
	}

	cases := []struct {
		host     string
		wantList string
		wantRule string
	}{
		{"first.example.com", "list-1", "||first.example.com^"},
		{"second.example.com", "list-2", "||second.example.com^"},
		{"hosts-second.example.com", "list-2", "0.0.0.0 hosts-second.example.com"},
	}
	for _, c := range cases {
		res := eng.match(c.host, 1, netip.Addr{})
		if !res.Blocked {
			t.Fatalf("%s: 期望被拦截", c.host)
		}
		if got := eng.listName(res.ListID); got != c.wantList {
			t.Errorf("%s: 规则集=%q, want %q", c.host, got, c.wantList)
		}
		if res.Rule != c.wantRule {
			t.Errorf("%s: 规则原文=%q, want %q", c.host, res.Rule, c.wantRule)
		}
	}

	// 例外规则放行时不应产生归属信息（审计侧对放行不做归属）。
	if res := eng.match("allow.example.com", 1, netip.Addr{}); res.Blocked || res.Rule != "" {
		t.Errorf("未命中的域名不应产生结果: %+v", res)
	}
}
