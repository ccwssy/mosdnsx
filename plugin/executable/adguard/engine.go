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

// filterEngine 是 urlfilter DNS 引擎的只读封装，构建完成后可并发查询。
type filterEngine struct {
	engine *urlfilter.DNSEngine
	count  uint64
}

// newFilterEngine 由若干规则文本构建引擎。每个文本视为一个独立规则列表。
// texts 中空白项会被忽略；全部为空时返回空引擎（匹配恒为 false）。
func newFilterEngine(texts []string) (*filterEngine, error) {
	lists := make([]filterlist.Interface, 0, len(texts))
	for i, text := range texts {
		if strings.TrimSpace(text) == "" {
			continue
		}
		lists = append(lists, filterlist.NewString(&filterlist.StringConfig{
			RulesText: text,
			ID:        rules.ListID(i),
			// DNS 层过滤用不到元素隐藏规则，跳过以省内存。
			IgnoreCosmetic: true,
		}))
	}
	if len(lists) == 0 {
		return &filterEngine{}, nil
	}

	storage, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		return nil, fmt.Errorf("build rule storage: %w", err)
	}

	eng := urlfilter.NewDNSEngine(storage)
	return &filterEngine{engine: eng, count: eng.RulesCount()}, nil
}

// matchResult 是一次过滤判定的结果。
type matchResult struct {
	// Rule 是命中的原始规则文本，便于审计与日志。
	Rule string

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
			return matchResult{}
		}
		return matchResult{Blocked: true, Rule: basic.Text()}
	}

	// 2) $dnsrewrite 规则：给出具体地址（含 0.0.0.0/null 视为拦截）。
	if ips := dnsRewriteIPs(res); len(ips) > 0 {
		return matchResult{Blocked: true, IPs: ips, Rule: "$dnsrewrite"}
	}

	// 3) hosts 格式规则：0.0.0.0 / :: 视为拦截，其它地址视为重写。
	var (
		hostIPs []netip.Addr
		ruleTxt string
	)
	for _, hr := range res.HostRulesV4 {
		if hr == nil {
			continue
		}
		hostIPs = append(hostIPs, hr.IP)
		if ruleTxt == "" {
			ruleTxt = hr.IP.String() + " " + strings.Join(hr.Hostnames, " ")
		}
	}
	for _, hr := range res.HostRulesV6 {
		if hr == nil {
			continue
		}
		hostIPs = append(hostIPs, hr.IP)
		if ruleTxt == "" {
			ruleTxt = hr.IP.String() + " " + strings.Join(hr.Hostnames, " ")
		}
	}
	if len(hostIPs) > 0 {
		for _, ip := range hostIPs {
			if ip.IsUnspecified() {
				return matchResult{Blocked: true, Rule: ruleTxt}
			}
		}
		return matchResult{IPs: hostIPs, Rule: ruleTxt}
	}

	return matchResult{}
}

// dnsRewriteIPs 提取 $dnsrewrite 规则中的 IP 地址。
func dnsRewriteIPs(res *urlfilter.DNSResult) (ips []netip.Addr) {
	for _, nr := range res.DNSRewrites() {
		if nr == nil || nr.DNSRewrite == nil {
			continue
		}
		if addr, ok := nr.DNSRewrite.Value.(netip.Addr); ok && addr.IsValid() {
			ips = append(ips, addr)
		}
	}
	return ips
}

// rulesCount 返回引擎实际加载的规则条数。
func (f *filterEngine) rulesCount() uint64 {
	if f == nil {
		return 0
	}
	return f.count
}
