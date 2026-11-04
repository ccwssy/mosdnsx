package coremain

// DNS 诊断接口。
//
// GET /api/v1/diagnose?name=<域名>&type=<A|AAAA> 向本机 DNS 监听地址真实发一次
// 查询，把应答整理成诊断 JSON 返回，用于回答「这个域名现在解析成什么、是不是
// fake-ip、命中了哪个 domain_set」。
//
// 查询走 127.0.0.1:5335 的真实解析链路（与客户端请求同一个入口），因此诊断结果
// 反映的是面板实际生效的配置，而不是另起一条旁路解析。

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/IrineSistiana/mosdns/v5/mlog"
)

const (
	// diagnoseDNSAddr 是本机 mosdns 的 DNS 监听地址，诊断查询走真实解析链路。
	diagnoseDNSAddr = "127.0.0.1:5335"
	// diagnoseTimeout 是单次诊断查询的总超时上限。
	diagnoseTimeout = 3 * time.Second
	// diagnoseFakeIPCIDR 是 fake-ip 网段，应答 IP 落在其中即判定为伪造地址。
	diagnoseFakeIPCIDR = "198.18.0.0/15"
)

// diagnoseFakeIPPrefix 缓存 fake-ip 网段，避免每次请求重复解析 CIDR。
var diagnoseFakeIPPrefix = netip.MustParsePrefix(diagnoseFakeIPCIDR)

// DiagnoseResponse 是 GET /api/v1/diagnose 的应答体，JSON 键名与前端约定一致。
type DiagnoseResponse struct {
	Name       string   `json:"name"`
	QType      string   `json:"qtype"`
	Answers    []string `json:"answers"`
	DurationMs float64  `json:"duration_ms"`
	Rcode      string   `json:"rcode"`
	IsFakeIP   bool     `json:"is_fakeip"`
	DomainSet  string   `json:"domain_set"`
}

// RegisterDiagnoseAPI 注册 DNS 诊断接口。
func RegisterDiagnoseAPI(router *chi.Mux) {
	router.Get("/api/v1/diagnose", handleDiagnose)
}

// handleDiagnose 校验参数、发一次真实查询并输出诊断结果。
func handleDiagnose(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeDiagnoseError(w, http.StatusBadRequest, "缺少参数 name")
		return
	}

	// 缺省 A；大小写不敏感，但只接受 A 与 AAAA，其它取值在发查询前就拒绝。
	qtypeName := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))
	if qtypeName == "" {
		qtypeName = "A"
	}
	var qtype uint16
	switch qtypeName {
	case "A":
		qtype = dns.TypeA
	case "AAAA":
		qtype = dns.TypeAAAA
	default:
		writeDiagnoseError(w, http.StatusBadRequest, "type 只支持 A 或 AAAA")
		return
	}

	reply, durationMs, err := exchangeDiagnose(name, qtype)
	if err != nil {
		mlog.L().Warn("diagnose query failed",
			zap.String("name", name), zap.String("type", qtypeName), zap.Error(err))
		writeDiagnoseError(w, http.StatusBadGateway, "DNS 查询失败: "+err.Error())
		return
	}

	// answers 预先分配空切片：无应答时序列化成 []，不是 null，前端不用额外判空。
	answers := make([]string, 0, len(reply.Answer))
	fakeIP := false
	for _, rr := range reply.Answer {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		default:
			continue
		}
		answers = append(answers, ip.String())
		if !fakeIP && isDiagnoseFakeIP(ip) {
			fakeIP = true
		}
	}

	rcode := dns.RcodeToString[reply.Rcode]
	if rcode == "" {
		// 未知 rcode 用数字兜底，避免返回空串让前端无法判断。
		rcode = "RCODE" + strconv.Itoa(reply.Rcode)
	}

	result := DiagnoseResponse{
		Name:       name,
		QType:      qtypeName,
		Answers:    answers,
		DurationMs: durationMs,
		Rcode:      rcode,
		IsFakeIP:   fakeIP,
		DomainSet:  latestDomainSet(name),
	}
	if err := json.NewEncoder(w).Encode(result); err != nil {
		mlog.L().Error("failed to encode diagnose response", zap.Error(err))
	}
}

// exchangeDiagnose 向本机 DNS 发一次查询，返回应答与实际耗时（毫秒）。
// 上下文与客户端各自带 3s 上限，保证整体不超过 diagnoseTimeout。
func exchangeDiagnose(name string, qtype uint16) (*dns.Msg, float64, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true

	client := &dns.Client{Net: "udp", Timeout: diagnoseTimeout}
	ctx, cancel := context.WithTimeout(context.Background(), diagnoseTimeout)
	defer cancel()

	start := time.Now()
	reply, _, err := client.ExchangeContext(ctx, msg, diagnoseDNSAddr)
	durationMs := float64(time.Since(start).Nanoseconds()) / 1e6
	if err != nil {
		return nil, durationMs, err
	}
	return reply, durationMs, nil
}

// isDiagnoseFakeIP 判断应答地址是否落在 fake-ip 网段。
func isDiagnoseFakeIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	// Unmap 把 IPv4-mapped 的 IPv6 地址还原成 IPv4，否则 Contains 对 198.18 段会判否。
	return diagnoseFakeIPPrefix.Contains(addr.Unmap())
}

// latestDomainSet 从审计环形缓冲里取该域名最新一条日志的 domain_set，取不到返回空串。
//
// GetLogs 返回的切片按「最旧 -> 最新」排列：未写满时是 append 顺序，写满后从
// head（指向最旧一条）开始展开，历史回填 SeedLogs 也是按磁盘里的时间升序追加，
// 因此最新一条总在末尾，这里从尾向前找第一个同名记录即可停止扫描。
func latestDomainSet(name string) string {
	logs := GlobalAuditCollector.GetLogs()
	target := normalizeQueryName(name)
	for i := len(logs) - 1; i >= 0; i-- {
		if normalizeQueryName(logs[i].QueryName) == target {
			return logs[i].DomainSet
		}
	}
	return ""
}

// normalizeQueryName 统一大小写并去掉末尾的点；审计日志写入时已去掉尾点，
// 这里再归一化一次，兼容历史数据与用户传参的 FQDN 写法。
func normalizeQueryName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// writeDiagnoseError 输出 JSON 错误体，Content-Type 与成功路径一致。
func writeDiagnoseError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		mlog.L().Error("failed to encode diagnose error", zap.Error(err))
	}
}
