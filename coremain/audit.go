package coremain

import (
	"container/heap"
	"container/list"
	"encoding/json"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// --- Optimized String Interning (Lock-Free) ---
const lruCacheSize = 16384

type lruEntry struct {
	key   string
	value string
}

// lruCache 已经移除了互斥锁，因为在优化后的设计中，它仅由单个 worker 协程调用
type lruCache struct {
	capacity int
	cache    map[string]*list.Element
	ll       *list.List
}

func newLRUCache(capacity int) *lruCache {
	if capacity <= 0 {
		capacity = lruCacheSize
	}
	return &lruCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element, capacity),
		ll:       list.New(),
	}
}

func (l *lruCache) Get(key string) (value string, ok bool) {
	if elem, hit := l.cache[key]; hit {
		l.ll.MoveToFront(elem)
		return elem.Value.(*lruEntry).value, true
	}
	return "", false
}

func (l *lruCache) Put(key, value string) {
	if elem, hit := l.cache[key]; hit {
		l.ll.MoveToFront(elem)
		elem.Value.(*lruEntry).value = value
		return
	}

	if l.ll.Len() >= l.capacity {
		oldest := l.ll.Back()
		if oldest != nil {
			l.ll.Remove(oldest)
			delete(l.cache, oldest.Value.(*lruEntry).key)
		}
	}

	elem := l.ll.PushFront(&lruEntry{key: key, value: value})
	l.cache[key] = elem
}

type auditContext struct {
	Ctx                *query_context.Context
	ProcessingDuration time.Duration
}

// Pool for auditContext to minimize GC overhead
var auditCtxPool = sync.Pool{
	New: func() any { return new(auditContext) },
}

type AnswerDetail struct {
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

type AuditLog struct {
	ClientIP      string         `json:"client_ip"`
	QueryType     string         `json:"query_type"`
	QueryName     string         `json:"query_name"`
	QueryClass    string         `json:"query_class"`
	QueryTime     time.Time      `json:"query_time"`
	DurationMs    float64        `json:"duration_ms"`
	TraceID       string         `json:"trace_id"`
	ResponseCode  string         `json:"response_code"`
	ResponseFlags ResponseFlags  `json:"response_flags"`
	Answers       []AnswerDetail `json:"answers"`
	DomainSet     string         `json:"domain_set,omitempty"`
	// FakeIP 表示该应答来自 fake-ip 段（走代理的域名），落盘时单独成一份日志。
	FakeIP bool `json:"fakeip,omitempty"`
	// ClientName 是该 client_ip 对应的客户端别名，写日志时按别名表填充，查不到则为空串。
	// 该字段为新增字段，旧日志文件里没有它，omitempty 保证旧数据仍能正常解析、无别名时不输出。
	ClientName string `json:"client_name,omitempty"`
	// FilterList 是命中规则所属规则集的展示名（如 config.json 里的列表 name），
	// 只在 adguard 命中且能查到映射时填充。它是 DomainSet 的并列字段，
	// DomainSet 的取值体系（adguard / unmatched_rule / 各规则集 tag）不因此改变。
	FilterList string `json:"filter_list,omitempty"`
	// MatchedRule 是命中的规则原文，供详情/悬停查看，不进列表列。
	MatchedRule string `json:"matched_rule,omitempty"`
}

type ResponseFlags struct {
	AA bool `json:"aa"`
	TC bool `json:"tc"`
	RA bool `json:"ra"`
}

const (
	defaultAuditCapacity   = 100000
	maxAuditCapacity       = 400000
	slowestQueriesCapacity = 300
	auditChannelCapacity   = 10240
	auditSettingsFilename  = "audit_settings.json"
)

type AuditSettings struct {
	Capacity int `json:"capacity"`

	// FileEnabled 开启查询日志落盘（对齐 AdGuardHome 的 querylog.file_enabled）。
	FileEnabled bool `json:"file_enabled"`
	// FileDir 是落盘目录，留空时使用 <config_base_dir>/audit。
	FileDir string `json:"file_dir,omitempty"`
	// RetentionDays 是日志保留天数，留空或 <=0 时按 7 天。
	RetentionDays int `json:"retention_days,omitempty"`
	// FileMaxMB 是单个日志文件的体积上限（MB），超过后滚动新文件。
	FileMaxMB int64 `json:"file_max_mb,omitempty"`

	// FakeIPCidrs 是判定"该应答属于 fake-ip"的网段，命中则单独写入 fakeip 日志文件。
	// 留空时使用默认 198.18.0.0/15（RFC 2544 保留段，OpenClash 默认 fake-ip 池）。
	FakeIPCidrs []string `json:"fakeip_cidrs,omitempty"`
	// FakeIPPrefix 是 fake-ip 日志的文件名前缀，默认 audit-fakeip-。
	FakeIPPrefix string `json:"fakeip_prefix,omitempty"`
}

type slowestQueryHeap []AuditLog

func (h slowestQueryHeap) Len() int           { return len(h) }
func (h slowestQueryHeap) Less(i, j int) bool { return h[i].DurationMs < h[j].DurationMs }
func (h slowestQueryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *slowestQueryHeap) Push(x any) {
	*h = append(*h, x.(AuditLog))
}

func (h *slowestQueryHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

type AuditCollector struct {
	mu                 sync.RWMutex
	capturing          atomic.Bool
	capacity           atomic.Int64
	logs               []AuditLog
	head               int
	slowestQueries     slowestQueryHeap
	domainCounts       map[string]int
	clientCounts       map[string]int
	domainSetCounts    map[string]int
	totalQueryDuration float64
	ctxChan            chan *auditContext
	quitChan           chan struct{}
	workerDone         chan struct{}

	stringLRU *lruCache // 实例级锁消除

	// Global Statistics for monitoring without mutex pressure
	totalQueryCountGlobal    atomic.Uint64
	totalQueryDurationGlobal atomic.Uint64 // Stored in microseconds
}

var GlobalAuditCollector = NewAuditCollector(defaultAuditCapacity)

// GlobalAuditFileStore 是查询日志落盘器，未启用时为 nil。
var GlobalAuditFileStore *AuditFileStore

// GlobalAuditFakeIPStore 是 fake-ip 查询的独立落盘器，未启用时为 nil。
var GlobalAuditFakeIPStore *AuditFileStore

// auditFakeIPNets 是 fake-ip 判定网段，空切片表示不做拆分。
var auditFakeIPNets []netip.Prefix

// auditSettingsPath 记录配置文件路径，供后续保存设置时复用。
var auditSettingsPath string

// auditFileCfg 保存当前生效的落盘配置，避免保存容量时丢失这些字段。
var auditFileCfg AuditSettings

func InitializeAuditCollector(configBaseDir string) {
	initialCapacity := defaultAuditCapacity
	settingsPath := filepath.Join(configBaseDir, auditSettingsFilename)
	auditSettingsPath = settingsPath
	settings := &AuditSettings{}
	data, err := os.ReadFile(settingsPath)

	if err == nil {
		if json.Unmarshal(data, settings) == nil {
			initialCapacity = settings.Capacity
			if initialCapacity < 0 {
				initialCapacity = 0
			}
			if initialCapacity > maxAuditCapacity {
				initialCapacity = maxAuditCapacity
			}
			mlog.S().Infof("Loaded audit log capacity: %d", initialCapacity)
		}
	}

	auditFileCfg = *settings

	if initialCapacity != defaultAuditCapacity {
		GlobalAuditCollector = NewAuditCollector(initialCapacity)
	}

	// 查询日志落盘：先回填历史，再启动写入。
	if settings.FileEnabled {
		dir := settings.FileDir
		if dir == "" {
			dir = filepath.Join(configBaseDir, "audit")
		} else if !filepath.IsAbs(dir) {
			dir = filepath.Join(configBaseDir, dir)
		}
		dir = filepath.Clean(dir)

		// fake-ip 网段：留空用默认 198.18.0.0/15（RFC 2544，OpenClash 默认池）。
		cidrs := settings.FakeIPCidrs
		if len(cidrs) == 0 {
			cidrs = []string{"198.18.0.0/15"}
		}
		auditFakeIPNets = nil
		for _, c := range cidrs {
			if pfx, perr := netip.ParsePrefix(strings.TrimSpace(c)); perr == nil {
				auditFakeIPNets = append(auditFakeIPNets, pfx)
			} else {
				mlog.L().Warn("invalid fakeip cidr in audit settings", zap.String("cidr", c), zap.Error(perr))
			}
		}
		prefix := settings.FakeIPPrefix
		if prefix == "" {
			prefix = auditFakeIPFilePrefix
		}

		if store, err := newAuditFileStore(dir, auditLogFilePrefix, settings.RetentionDays, settings.FileMaxMB); err == nil {
			GlobalAuditFileStore = store
			if history := loadAuditLogsFromDisk(dir, GlobalAuditCollector.GetCapacity()); len(history) > 0 {
				GlobalAuditCollector.SeedLogs(history)
				mlog.S().Infof("Loaded %d audit logs from disk", len(history))
			}
			mlog.S().Infof("Audit log file persistence enabled: %s (retention=%d days, max=%d MB)",
				dir, settings.RetentionDays, settings.FileMaxMB)
		} else {
			mlog.L().Error("failed to enable audit log file persistence", zap.Error(err))
		}

		// fake-ip 单独一份日志（同一目录、不同前缀）。
		if len(auditFakeIPNets) > 0 {
			if store, ferr := newAuditFileStore(dir, prefix, settings.RetentionDays, settings.FileMaxMB); ferr == nil {
				GlobalAuditFakeIPStore = store
				mlog.S().Infof("Fake-IP audit log split enabled: %s (%d cidr)",
					filepath.Join(dir, prefix+"*.jsonl"), len(auditFakeIPNets))
			} else {
				mlog.L().Error("failed to enable fake-ip audit log persistence", zap.Error(ferr))
			}
		}
	}
}

func NewAuditCollector(capacity int) *AuditCollector {
	c := &AuditCollector{
		logs:               make([]AuditLog, 0, capacity),
		slowestQueries:     make(slowestQueryHeap, 0, slowestQueriesCapacity),
		domainCounts:       make(map[string]int),
		clientCounts:       make(map[string]int),
		domainSetCounts:    make(map[string]int),
		totalQueryDuration: 0.0,
		ctxChan:            make(chan *auditContext, auditChannelCapacity),
		quitChan:           make(chan struct{}),
		workerDone:         make(chan struct{}),
		stringLRU:          newLRUCache(lruCacheSize),
	}
	c.capacity.Store(int64(capacity))
	c.capturing.Store(true)
	heap.Init(&c.slowestQueries)
	return c
}

func (c *AuditCollector) internString(s string) string {
	switch s {
	case "A", "AAAA", "CNAME", "TXT", "NS", "MX", "PTR", "SOA", "SRV", "HTTPS", "SVCB",
		"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "IN",
		"NO_RESPONSE", "unmatched_rule", "adguard":
		return s
	}

	if val, ok := c.stringLRU.Get(s); ok {
		return val
	}
	c.stringLRU.Put(s, s)
	return s
}

func (c *AuditCollector) StartWorker() {
	go c.worker()
}

func (c *AuditCollector) StopWorker() {
	close(c.quitChan)
	<-c.workerDone

	if store := GlobalAuditFakeIPStore; store != nil {
		store.Close()
		GlobalAuditFakeIPStore = nil
	}
	if store := GlobalAuditFileStore; store != nil {
		store.Close()
		GlobalAuditFileStore = nil
	}
}

func (c *AuditCollector) worker() {
	defer close(c.workerDone)
	batch := make([]*auditContext, 0, 256)

	for {
		batch = batch[:0]

		select {
		case <-c.quitChan:
			return
		case wrappedCtx := <-c.ctxChan:
			batch = append(batch, wrappedCtx)
		}

		// Non-blocking drain to fill the batch
	drainLoop:
		for len(batch) < cap(batch) {
			select {
			case <-c.quitChan:
				break drainLoop // 快速逃逸并处理剩余 batch
			case nextItem := <-c.ctxChan:
				batch = append(batch, nextItem)
			default:
				break drainLoop
			}
		}

		c.processBatch(batch)

		for _, item := range batch {
			auditCtxPool.Put(item)
		}

		select {
		case <-c.quitChan:
			return
		default:
		}
	}
}

func (c *AuditCollector) processBatch(batch []*auditContext) {
	parsedLogs := make([]AuditLog, 0, len(batch))
	capVal := int(c.capacity.Load())

	// Step 1: 在无锁环境下进行结构组装、字符串解析、LRU 缓存等耗时操作
	for _, wrappedCtx := range batch {
		if wrappedCtx == nil || wrappedCtx.Ctx == nil {
			continue
		}

		qCtx := wrappedCtx.Ctx
		qQuestion := qCtx.QQuestion()
		duration := wrappedCtx.ProcessingDuration
		durationMs := float64(duration.Microseconds()) / 1000.0

		// Instant update of global atomic statistics
		c.totalQueryCountGlobal.Add(1)
		c.totalQueryDurationGlobal.Add(uint64(duration.Microseconds()))

		if !c.capturing.Load() || capVal == 0 {
			continue
		}

		// Prefer the real client IP conveyed by a trusted local forwarder
		// (xdp-tool) via the private EDNS option; fall back to the transport peer.
		auditAddr := qCtx.ServerMeta.ClientAddr
		if qCtx.ServerMeta.RealClientAddr.IsValid() {
			auditAddr = qCtx.ServerMeta.RealClientAddr
		}
		clientAddr := auditAddr.String()
		if host, _, err := net.SplitHostPort(clientAddr); err == nil {
			clientAddr = host
		}

		qName := qQuestion.Name
		if len(qName) > 1 && qName[len(qName)-1] == '.' {
			qName = qName[:len(qName)-1]
		}

		log := AuditLog{
			ClientIP:   c.internString(clientAddr),
			QueryType:  c.internString(dns.TypeToString[qQuestion.Qtype]),
			QueryName:  c.internString(qName),
			QueryClass: c.internString(dns.ClassToString[qQuestion.Qclass]),
			QueryTime:  qCtx.StartTime(),
			DurationMs: durationMs,
			TraceID:    qCtx.TraceID,
		}

		// 按 client_ip 查别名表填充客户端名称：clientAddr 已在上方去掉端口，LookupClientName 内部
		// 已剥掉 ::ffff: 前缀且只取读锁，查不到返回空串，这里不再重复处理前缀、也不额外加锁。
		if clientName := LookupClientName(clientAddr); clientName != "" {
			log.ClientName = clientName
		}

		if val, ok := qCtx.GetValue(query_context.KeyDomainSet); ok {
			if name, isString := val.(string); isString {
				log.DomainSet = name
			}
		}

		// 归属与规则原文是并列字段：只有插件确实写了才填充，旧链路/白名单放行都没有。
		if val, ok := qCtx.GetValue(query_context.KeyFilterList); ok {
			if name, isString := val.(string); isString {
				log.FilterList = c.internString(name)
			}
		}
		if val, ok := qCtx.GetValue(query_context.KeyMatchedRule); ok {
			if text, isString := val.(string); isString {
				log.MatchedRule = c.internString(text)
			}
		}

		if log.DomainSet == "" {
			log.DomainSet = "unmatched_rule"
		}

		if resp := qCtx.R(); resp != nil {
			log.ResponseCode = c.internString(dns.RcodeToString[resp.Rcode])
			log.ResponseFlags = ResponseFlags{
				AA: resp.Authoritative,
				TC: resp.Truncated,
				RA: resp.RecursionAvailable,
			}

			if len(resp.Answer) > 0 {
				log.Answers = make([]AnswerDetail, 0, len(resp.Answer))
				for _, ans := range resp.Answer {
					header := ans.Header()
					detail := AnswerDetail{
						Type: c.internString(dns.TypeToString[header.Rrtype]),
						TTL:  header.Ttl,
					}
					switch record := ans.(type) {
					case *dns.A:
						detail.Data = c.internString(record.A.String())
					case *dns.AAAA:
						detail.Data = c.internString(record.AAAA.String())
					case *dns.CNAME:
						detail.Data = c.internString(record.Target)
					case *dns.PTR:
						detail.Data = c.internString(record.Ptr)
					case *dns.NS:
						detail.Data = c.internString(record.Ns)
					case *dns.MX:
						detail.Data = c.internString(record.Mx)
					case *dns.TXT:
						detail.Data = c.internString(strings.Join(record.Txt, " "))
					default:
						detail.Data = c.internString(ans.String())
					}
					log.Answers = append(log.Answers, detail)
				}
			}
			// 判定是否走 fake-ip：任一 A 应答落在 fake-ip 网段即算。
			if len(auditFakeIPNets) > 0 {
				for _, a := range log.Answers {
					if a.Type != "A" {
						continue
					}
					if addr, aerr := netip.ParseAddr(a.Data); aerr == nil {
						for _, pfx := range auditFakeIPNets {
							if pfx.Contains(addr) {
								log.FakeIP = true
								break
							}
						}
					}
					if log.FakeIP {
						break
					}
				}
			}
		} else {
			log.ResponseCode = "NO_RESPONSE"
		}
		parsedLogs = append(parsedLogs, log)
	}

	if len(parsedLogs) == 0 {
		return
	}

	// 落盘（异步、非阻塞），按 fake-ip 与否分流到两个文件。
	var normalLogs, fakeIPLogs []AuditLog
	for _, log := range parsedLogs {
		if log.FakeIP {
			fakeIPLogs = append(fakeIPLogs, log)
		} else {
			normalLogs = append(normalLogs, log)
		}
	}
	if store := GlobalAuditFileStore; store != nil && len(normalLogs) > 0 {
		store.Write(normalLogs)
	}
	if store := GlobalAuditFakeIPStore; store != nil && len(fakeIPLogs) > 0 {
		store.Write(fakeIPLogs)
	}

	// Step 2: 细粒度锁定，仅处理数组追加与增量状态更新，彻底消除耗时
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, log := range parsedLogs {
		if len(c.logs) == capVal {
			c.decrementStats(c.logs[c.head])
		}

		c.incrementStats(log)

		// Circular array logic
		if len(c.logs) < capVal {
			c.logs = append(c.logs, log)
		} else {
			c.logs[c.head] = log
			c.head = (c.head + 1) % capVal
		}

		// Update slowest queries heap
		if c.slowestQueries.Len() < slowestQueriesCapacity {
			heap.Push(&c.slowestQueries, log)
		} else if log.DurationMs > c.slowestQueries[0].DurationMs {
			c.slowestQueries[0] = log
			heap.Fix(&c.slowestQueries, 0)
		}
	}
}

// 增量统计函数（配合无全量大锁的设计）
func (c *AuditCollector) incrementStats(log AuditLog) {
	c.domainCounts[log.QueryName]++
	c.clientCounts[log.ClientIP]++
	c.domainSetCounts[log.DomainSet]++
	c.totalQueryDuration += log.DurationMs
}

func (c *AuditCollector) decrementStats(log AuditLog) {
	if c.domainCounts[log.QueryName] > 1 {
		c.domainCounts[log.QueryName]--
	} else {
		delete(c.domainCounts, log.QueryName)
	}

	if c.clientCounts[log.ClientIP] > 1 {
		c.clientCounts[log.ClientIP]--
	} else {
		delete(c.clientCounts, log.ClientIP)
	}

	if c.domainSetCounts[log.DomainSet] > 1 {
		c.domainSetCounts[log.DomainSet]--
	} else {
		delete(c.domainSetCounts, log.DomainSet)
	}

	c.totalQueryDuration -= log.DurationMs
	if c.totalQueryDuration < 0 {
		c.totalQueryDuration = 0
	}
}

func (c *AuditCollector) Collect(qCtx *query_context.Context) {
	if !c.IsCapturing() {
		return
	}

	duration := time.Since(qCtx.StartTime())

	wrappedCtx := auditCtxPool.Get().(*auditContext)
	wrappedCtx.Ctx = qCtx
	wrappedCtx.ProcessingDuration = duration

	select {
	case c.ctxChan <- wrappedCtx:
	default:
		auditCtxPool.Put(wrappedCtx)
	}
}

func (c *AuditCollector) Start()            { c.capturing.Store(true) }
func (c *AuditCollector) Stop()             { c.capturing.Store(false) }
func (c *AuditCollector) IsCapturing() bool { return c.capturing.Load() }

func (c *AuditCollector) GetLogs() []AuditLog {
	c.mu.RLock()
	defer c.mu.RUnlock()

	capVal := int(c.capacity.Load())
	if capVal == 0 || len(c.logs) == 0 {
		return []AuditLog{}
	}

	if len(c.logs) < capVal {
		logsCopy := make([]AuditLog, len(c.logs))
		copy(logsCopy, c.logs)
		return logsCopy
	}

	logsCopy := make([]AuditLog, capVal)
	copy(logsCopy, c.logs[c.head:])
	copy(logsCopy[capVal-c.head:], c.logs[:c.head])
	return logsCopy
}

// filterLogsByDomainSet 按 domain_set 做精确的包含/剔除过滤，语义为先包含再剔除。
//
// 供 v1 日志接口使用：include 与 exclude 都为空时直接返回入参切片，调用方在参数为空时
// 根本不会调用本函数，因此这里只保证不产生多余的拷贝。
func filterLogsByDomainSet(logs []AuditLog, include, exclude string) []AuditLog {
	if include == "" && exclude == "" {
		return logs
	}
	filtered := make([]AuditLog, 0, len(logs))
	for _, log := range logs {
		if include != "" && log.DomainSet != include {
			continue
		}
		if exclude != "" && log.DomainSet == exclude {
			continue
		}
		filtered = append(filtered, log)
	}
	return filtered
}

func (c *AuditCollector) ClearLogs() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.logs != nil {
		c.logs = c.logs[:0]
	}

	c.head = 0
	c.slowestQueries = make(slowestQueryHeap, 0, slowestQueriesCapacity)
	heap.Init(&c.slowestQueries)
	c.domainCounts = make(map[string]int)
	c.clientCounts = make(map[string]int)
	c.domainSetCounts = make(map[string]int)
	c.totalQueryDuration = 0.0
}

func (c *AuditCollector) GetCapacity() int {
	return int(c.capacity.Load())
}

func (c *AuditCollector) SetCapacity(newCapacity int, configBaseDir string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if newCapacity < 0 {
		newCapacity = 0
	}
	if newCapacity > maxAuditCapacity {
		newCapacity = maxAuditCapacity
	}

	c.saveSettings(newCapacity, configBaseDir)

	c.capacity.Store(int64(newCapacity))
	c.logs = make([]AuditLog, 0, newCapacity)
	c.head = 0
	c.slowestQueries = make(slowestQueryHeap, 0, slowestQueriesCapacity)
	heap.Init(&c.slowestQueries)
	c.domainCounts = make(map[string]int)
	c.clientCounts = make(map[string]int)
	c.domainSetCounts = make(map[string]int)
	c.totalQueryDuration = 0.0
}

func (c *AuditCollector) saveSettings(capacityToSave int, configBaseDir string) {
	settings := auditFileCfg
	settings.Capacity = capacityToSave
	auditFileCfg = settings
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		mlog.L().Error("failed to marshal audit settings", zap.Error(err))
		return
	}
	settingsPath := filepath.Join(configBaseDir, auditSettingsFilename)
	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		mlog.L().Error("failed to write audit settings file", zap.String("path", settingsPath), zap.Error(err))
	} else {
		mlog.L().Info("successfully saved audit settings", zap.String("path", settingsPath), zap.Int("capacity", capacityToSave))
	}
}

type V2GetLogsParams struct {
	Page        int
	Limit       int
	Domain      string
	AnswerIP    string
	AnswerCNAME string
	ClientIP    string
	Q           string
	Exact       bool
	// FakeIP 为 "true" 时只返回 fake-ip 应答，"false" 时只返回非 fake-ip，空串不过滤。
	FakeIP string
	// 以下为仿 AGH 的精确过滤条件，空串/0 不过滤。
	QType        string // A / AAAA / HTTPS / PTR ...
	RCode        string // NOERROR / NXDOMAIN / SERVFAIL ...
	DomainSet    string // 命中的规则标签，含 unmatched_rule
	SinceMinutes int    // 只看最近 N 分钟
	// DomainSetExclude 是需要排除的规则标签（同样含 unmatched_rule），空串不剔除；
	// 与 DomainSet 同时给出时语义为先包含再剔除，即命中两者的记录会被排除。
	DomainSetExclude string
}

func (c *AuditCollector) CalculateV2Stats() V2StatsResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalQueryCount := uint64(len(c.logs))
	avgDuration := 0.0
	if totalQueryCount > 0 {
		avgDuration = c.totalQueryDuration / float64(totalQueryCount)
	}

	// 被拦截查询数：环形缓冲中命中 adguard 规则集的记录条数。
	// c.logs 未写满时是前缀填充，写满后靠 c.head 回绕，两种状态下下标 0..len(c.logs)-1
	// 恰好覆盖全部有效元素且不重复，head 只影响顺序、不影响集合。
	var blockedQueries uint64
	for i := 0; i < len(c.logs); i++ {
		if c.logs[i].DomainSet == "adguard" {
			blockedQueries++
		}
	}

	// 拦截占比：总数为 0 时直接返回 0，避免除零。
	blockedRatio := 0.0
	if totalQueryCount > 0 {
		blockedRatio = float64(blockedQueries) / float64(totalQueryCount)
	}

	// 今日查询数复用 processBatch 内维护的原子计数，不读审计文件、不引入新锁。
	return V2StatsResponse{
		TotalQueries:      totalQueryCount,
		AverageDurationMs: avgDuration,
		BlockedQueries:    blockedQueries,
		BlockedRatio:      blockedRatio,
		TodayQueries:      c.totalQueryCountGlobal.Load(),
	}
}

type rankHeap []V2RankItem

func (h rankHeap) Len() int           { return len(h) }
func (h rankHeap) Less(i, j int) bool { return h[i].Count < h[j].Count }
func (h rankHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *rankHeap) Push(x any)        { *h = append(*h, x.(V2RankItem)) }
func (h *rankHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func (c *AuditCollector) getRankFromMap(sourceMap map[string]int, limit int) []V2RankItem {
	if len(sourceMap) == 0 {
		return []V2RankItem{}
	}

	if len(sourceMap) <= limit {
		res := make([]V2RankItem, 0, len(sourceMap))
		for k, v := range sourceMap {
			res = append(res, V2RankItem{Key: k, Count: v})
		}
		sort.Slice(res, func(i, j int) bool {
			return res[i].Count > res[j].Count
		})
		return res
	}

	h := &rankHeap{}
	heap.Init(h)

	for key, count := range sourceMap {
		if h.Len() < limit {
			heap.Push(h, V2RankItem{Key: key, Count: count})
		} else if count > (*h)[0].Count {
			heap.Pop(h)
			heap.Push(h, V2RankItem{Key: key, Count: count})
		}
	}

	result := make([]V2RankItem, h.Len())
	for i := h.Len() - 1; i >= 0; i-- {
		result[i] = heap.Pop(h).(V2RankItem)
	}

	return result
}

type RankType string

const (
	RankByDomain    RankType = "domain"
	RankByClient    RankType = "client"
	RankByDomainSet RankType = "domain_set"
)

func (c *AuditCollector) CalculateRank(rankType RankType, limit int) []V2RankItem {
	c.mu.RLock()
	defer c.mu.RUnlock()

	switch rankType {
	case RankByDomain:
		return c.getRankFromMap(c.domainCounts, limit)
	case RankByClient:
		return c.getRankFromMap(c.clientCounts, limit)
	case RankByDomainSet:
		return c.getRankFromMap(c.domainSetCounts, limit)
	default:
		return []V2RankItem{}
	}
}

// CalculateRankFiltered 按 domain_set 精确过滤后统计排行。
// domainSet 为空时直接委托 CalculateRank，保持原有基于增量统计 map 的快速路径；
// 非空时在 c.mu.RLock() 下扫描环形缓冲 c.logs 聚合到临时 map，再复用 getRankFromMap 出榜。
func (c *AuditCollector) CalculateRankFiltered(rankType RankType, domainSet string, limit int) []V2RankItem {
	if domainSet == "" {
		return c.CalculateRank(rankType, limit)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// 环形缓冲语义：len(c.logs) < capVal 时是前缀填充（head 保持 0）；
	// 写满后新记录覆盖 c.logs[c.head] 并让 head 后移回绕。
	// 因此下标 0..len(c.logs)-1 在两种状态下都恰好覆盖全部有效元素，不重不漏，
	// head 只决定时间顺序，聚合到 map 时无需考虑。
	counts := make(map[string]int)
	for i := 0; i < len(c.logs); i++ {
		log := c.logs[i]
		if log.DomainSet != domainSet {
			continue
		}

		var key string
		switch rankType {
		case RankByDomain:
			key = log.QueryName
		case RankByClient:
			key = log.ClientIP
		case RankByDomainSet:
			key = log.DomainSet
		default:
			return []V2RankItem{}
		}
		counts[key]++
	}

	return c.getRankFromMap(counts, limit)
}

func (c *AuditCollector) GetSlowestQueries(limit int) []AuditLog {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.slowestQueries.Len() == 0 {
		return []AuditLog{}
	}

	snapshot := make([]AuditLog, c.slowestQueries.Len())
	copy(snapshot, c.slowestQueries)

	sort.Slice(snapshot, func(i, j int) bool {
		return snapshot[i].DurationMs > snapshot[j].DurationMs
	})

	if len(snapshot) > limit {
		return snapshot[:limit]
	}
	return snapshot
}

// GetSlowestQueriesSince 返回 since 之后的最慢 limit 条查询（按耗时降序）。
// 与 GetSlowestQueries 的区别：不复用全局 slowestQueries 堆（那是 7 天历史榜），
// 而是遍历内存环形日志按时间过滤后做 partial top-N。
func (c *AuditCollector) GetSlowestQueriesSince(since time.Time, limit int) []AuditLog {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 || len(c.logs) == 0 {
		return []AuditLog{}
	}

	// 容量 limit 的最小堆，堆顶为当前候选里最慢的一条；
	// 判定条件与 processBatch 里 slowestQueries 的维护方式保持一致。
	h := make(slowestQueryHeap, 0, limit)
	for i := range c.logs {
		log := c.logs[i]
		// 环形数组的物理顺序与时间无关，这里只按时间窗口过滤
		if log.QueryTime.Before(since) {
			continue
		}
		if len(h) < limit {
			heap.Push(&h, log)
		} else if log.DurationMs > h[0].DurationMs {
			h[0] = log
			heap.Fix(&h, 0)
		}
	}

	if len(h) == 0 {
		return []AuditLog{}
	}

	result := make([]AuditLog, len(h))
	copy(result, h)
	sort.Slice(result, func(i, j int) bool {
		return result[i].DurationMs > result[j].DurationMs
	})
	return result
}

// 零内存分配的极速 ASCII 忽略大小写匹配函数
func containsFold(s, substrLower string) bool {
	if len(substrLower) == 0 {
		return true
	}
	if len(s) < len(substrLower) {
		return false
	}

	hasNonASCII := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 128 {
			hasNonASCII = true
			break
		}
	}
	if hasNonASCII {
		return strings.Contains(strings.ToLower(s), substrLower)
	}

	for i := 0; i <= len(s)-len(substrLower); i++ {
		match := true
		for j := 0; j < len(substrLower); j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			if c != substrLower[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func (c *AuditCollector) GetV2Logs(params V2GetLogsParams) V2PaginatedLogsResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()

	capVal := int(c.capacity.Load())
	totalLogs := len(c.logs)
	if totalLogs == 0 || capVal == 0 {
		return V2PaginatedLogsResponse{
			Pagination: V2PaginationInfo{CurrentPage: params.Page, ItemsPerPage: params.Limit},
			Logs:       []AuditLog{},
		}
	}

	if params.Page < 1 {
		params.Page = 1
	}
	if params.Limit <= 0 {
		params.Limit = 50
	}

	searchTerm := params.Q
	searchTermLower := ""
	if params.Q != "" && !params.Exact {
		searchTermLower = strings.ToLower(searchTerm) // 仅在此处转换一次
	}

	matchCount := 0
	offset := (params.Page - 1) * params.Limit
	filteredLogs := make([]AuditLog, 0, params.Limit)

	curr := (c.head - 1 + totalLogs) % totalLogs

	for i := 0; i < totalLogs; i++ {
		log := c.logs[curr]
		isMatched := true

		// fake-ip 过滤：三态（空=全部，true=只看 fake-ip，false=只看非 fake-ip）
		if params.FakeIP != "" {
			wantFake := params.FakeIP == "true" || params.FakeIP == "1"
			if log.FakeIP != wantFake {
				isMatched = false
			}
		}

		if params.Q != "" {
			foundInQ := false
			if params.Exact {
				if log.QueryName == searchTerm {
					foundInQ = true
				} else if log.ClientIP == searchTerm {
					foundInQ = true
				} else if log.TraceID == searchTerm {
					foundInQ = true
				} else if log.DomainSet != "" && log.DomainSet == searchTerm {
					foundInQ = true
				} else {
					for _, answer := range log.Answers {
						if answer.Data == searchTerm {
							foundInQ = true
							break
						}
					}
				}
			} else {
				if containsFold(log.QueryName, searchTermLower) {
					foundInQ = true
				} else if containsFold(log.ClientIP, searchTermLower) {
					foundInQ = true
				} else if containsFold(log.TraceID, searchTermLower) {
					foundInQ = true
				} else if log.DomainSet != "" && containsFold(log.DomainSet, searchTermLower) {
					foundInQ = true
				} else {
					for _, answer := range log.Answers {
						if containsFold(answer.Data, searchTermLower) {
							foundInQ = true
							break
						}
					}
				}
			}
			if !foundInQ {
				isMatched = false
			}
		}

		if isMatched && params.ClientIP != "" && log.ClientIP != params.ClientIP {
			isMatched = false
		}
		if isMatched && params.Domain != "" && !strings.Contains(log.QueryName, params.Domain) {
			isMatched = false
		}
		if isMatched && params.AnswerIP != "" {
			found := false
			for _, answer := range log.Answers {
				if (answer.Type == "A" || answer.Type == "AAAA") && answer.Data == params.AnswerIP {
					found = true
					break
				}
			}
			if !found {
				isMatched = false
			}
		}
		if isMatched && params.QType != "" && !strings.EqualFold(log.QueryType, params.QType) {
			isMatched = false
		}
		if isMatched && params.RCode != "" && !strings.EqualFold(log.ResponseCode, params.RCode) {
			isMatched = false
		}
		if isMatched && params.DomainSet != "" && log.DomainSet != params.DomainSet {
			isMatched = false
		}
		// 排除过滤放在包含过滤之后，保证“先包含再剔除”的语义；参数为空时短路，不做任何额外判断。
		if isMatched && params.DomainSetExclude != "" && log.DomainSet == params.DomainSetExclude {
			isMatched = false
		}
		if isMatched && params.SinceMinutes > 0 {
			cutoff := time.Now().Add(-time.Duration(params.SinceMinutes) * time.Minute)
			if log.QueryTime.Before(cutoff) {
				isMatched = false
			}
		}
		if isMatched && params.AnswerCNAME != "" {
			found := false
			for _, answer := range log.Answers {
				if answer.Type == "CNAME" && strings.Contains(answer.Data, params.AnswerCNAME) {
					found = true
					break
				}
			}
			if !found {
				isMatched = false
			}
		}

		if isMatched {
			if matchCount >= offset && len(filteredLogs) < params.Limit {
				filteredLogs = append(filteredLogs, log)
			}
			matchCount++
		}

		curr = (curr - 1 + totalLogs) % totalLogs
	}

	totalPages := int(math.Ceil(float64(matchCount) / float64(params.Limit)))
	return V2PaginatedLogsResponse{
		Pagination: V2PaginationInfo{
			TotalItems:   matchCount,
			TotalPages:   totalPages,
			CurrentPage:  params.Page,
			ItemsPerPage: params.Limit,
		},
		Logs: filteredLogs,
	}
}
