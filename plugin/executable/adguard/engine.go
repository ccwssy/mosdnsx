package adguard_rule

// 本文件为 mosdns 的 adguard_rule 插件提供 AdGuard Home 同源过滤引擎。
//
// 背景：原先插件用自写的简化解析器（只认 ||domain^ / @@||domain^ / /regex/ / 裸域名），
// $important、$badfilter、$client、$dnstype、$denyallow、路径规则、hosts 双列规则等
// Adblock/AdGuard 语义全部被丢弃。本实现改用 AdGuard 官方 urlfilter 库
// （AdGuardHome 自身使用的同一个引擎），使过滤行为与 AdGuard Home 保持一致。

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// ruleList 是一个规则列表：Name 是 config.json 里的规则集名称（审计展示用），
// Text 是该列表的规则原文。引擎用它在命中后回查「命中的是哪个列表」。
type ruleList struct {
	Name string
	Text string
}

// filterEngine 是 urlfilter DNS 引擎的只读封装，构建完成后可并发查询。
type filterEngine struct {
	engine *urlfilter.DNSEngine
	count  uint64
	// listNames 把 urlfilter 的 ListID 下标映射回 config.json 里的规则集名称。
	// 下标与构建引擎时传入的 lists 下标严格一致（见 newFilterEngine 的注释）。
	listNames []string
}

// newFilterEngine 由若干规则列表构建引擎。每个列表视为一个独立规则列表。
// 列表文本为空白项时跳过，但 ListID 仍取它在 lists 中的下标，
// 因此 listNames 可以与 lists 逐项对齐，命中后能直接查回规则集名称。
// 全部为空时返回空引擎（匹配恒为 false）。
func newFilterEngine(lists []ruleList) (*filterEngine, error) {
	storage := make([]filterlist.Interface, 0, len(lists))
	names := make([]string, len(lists))
	for i, list := range lists {
		names[i] = list.Name
		if strings.TrimSpace(list.Text) == "" {
			continue
		}
		storage = append(storage, filterlist.NewString(&filterlist.StringConfig{
			RulesText: list.Text,
			ID:        rules.ListID(i),
			// DNS 层过滤用不到元素隐藏规则，跳过以省内存。
			IgnoreCosmetic: true,
		}))
	}
	if len(storage) == 0 {
		return &filterEngine{listNames: names}, nil
	}

	ruleStorage, err := filterlist.NewRuleStorage(storage)
	if err != nil {
		return nil, fmt.Errorf("build rule storage: %w", err)
	}

	eng := urlfilter.NewDNSEngine(ruleStorage)
	return &filterEngine{engine: eng, count: eng.RulesCount(), listNames: names}, nil
}

// listName 把 ListID 翻译成 config.json 里的规则集名称；查不到时返回空串。
func (f *filterEngine) listName(id uint32) string {
	if f == nil || int(id) < 0 || int(id) >= len(f.listNames) {
		return ""
	}
	return f.listNames[id]
}

// matchResult 是一次过滤判定的结果。
type matchResult struct {
	// Rule 是命中的原始规则文本，便于审计与日志。
	Rule string

	// ListID 是命中规则所属列表的 urlfilter 下标，配合 filterEngine.listName
	// 可回查规则集名称；0 表示该分支拿不到列表信息（hosts/$dnsrewrite 之外的兜底）。
	ListID uint32

	// IPs 非 nil 时表示命中 $dnsrewrite 或 hosts 规则给出了具体地址。
	IPs []netip.Addr

	// Blocked 表示该查询应被拦截。
	Blocked bool
}

// match 在给定 host / qtype / 客户端 IP 上执行过滤。
// qtype 传 0 表示不限定类型；clientIP 无效时会跳过 $client 类规则。
func (f *filterEngine) match(host string, qtype uint16, clientIP netip.Addr) (r matchResult) {
	if f == nil || f.engine == nil {
		return matchResult{}
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return matchResult{}
	}

	req := &urlfilter.DNSRequest{
		Hostname: host,
		DNSType:  rules.RRType(qtype),
	}
	if clientIP.IsValid() {
		req.ClientIP = clientIP
		// $client=IP 与 $client=客户端ID 共用同一套匹配：这里把 IP 当作标识符喂进去。
		req.ClientIdentifiers = container.NewSortedSliceSet(clientIP.String())
	}

	// matched 的返回值对 $dnsrewrite 等特殊规则不敏感，一律以 NetworkRules 内容为准。
	res, _ := f.engine.MatchRequest(req)

	// 1) 基础网络规则：已由 urlfilter 处理 $important / $badfilter / 例外规则的优先级。
	if basic := rules.GetDNSBasicRule(res.NetworkRules); basic != nil {
		if basic.Whitelist {
			// 例外（whitelist）判定不填列表信息：审计侧对放行不做归属。
			return matchResult{}
		}
		return matchResult{
			Blocked: true,
			Rule:    basic.Text(),
			ListID:  uint32(basic.GetFilterListID()),
		}
	}

	// 2) $dnsrewrite 规则：给出具体地址（含 0.0.0.0/null 视为拦截）。
	if rewrites := res.DNSRewrites(); len(rewrites) > 0 {
		var (
			ips    []netip.Addr
			ruleID uint32
			ruleTx string
		)
		for _, nr := range rewrites {
			if nr == nil || nr.DNSRewrite == nil {
				continue
			}
			addr, ok := nr.DNSRewrite.Value.(netip.Addr)
			if !ok || !addr.IsValid() {
				continue
			}
			ips = append(ips, addr)
			if ruleTx == "" {
				ruleTx = nr.Text()
				ruleID = uint32(nr.GetFilterListID())
			}
		}
		if len(ips) > 0 {
			if ruleTx == "" {
				ruleTx = "$dnsrewrite"
			}
			return matchResult{Blocked: true, IPs: ips, Rule: ruleTx, ListID: ruleID}
		}
	}

	// 3) hosts 格式规则：0.0.0.0 / :: 视为拦截，其它地址视为重写。
	var (
		hostIPs  []netip.Addr
		ruleTxt  string
		hostList uint32
	)
	for _, hr := range res.HostRulesV4 {
		if hr == nil {
			continue
		}
		hostIPs = append(hostIPs, hr.IP)
		if ruleTxt == "" {
			ruleTxt = hr.IP.String() + " " + strings.Join(hr.Hostnames, " ")
			hostList = uint32(hr.GetFilterListID())
		}
	}
	for _, hr := range res.HostRulesV6 {
		if hr == nil {
			continue
		}
		hostIPs = append(hostIPs, hr.IP)
		if ruleTxt == "" {
			ruleTxt = hr.IP.String() + " " + strings.Join(hr.Hostnames, " ")
			hostList = uint32(hr.GetFilterListID())
		}
	}
	if len(hostIPs) > 0 {
		for _, ip := range hostIPs {
			if ip.IsUnspecified() {
				return matchResult{Blocked: true, Rule: ruleTxt, ListID: hostList}
			}
		}
		return matchResult{IPs: hostIPs, Rule: ruleTxt, ListID: hostList}
	}

	return matchResult{}
}

// rulesCount 返回引擎实际加载的规则条数。
func (f *filterEngine) rulesCount() uint64 {
	if f == nil {
		return 0
	}
	return f.count
}
