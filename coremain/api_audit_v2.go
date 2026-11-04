package coremain

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// --- V2 API Data Structures ---

// V2StatsResponse for API: /api/v2/audit/stats
type V2StatsResponse struct {
	TotalQueries      uint64  `json:"total_queries"` // MODIFIED: Changed from int to uint64
	AverageDurationMs float64 `json:"average_duration_ms"`
	// 以下为概览页新增指标，均为只增不删的附加字段
	BlockedQueries uint64  `json:"blocked_queries"` // 环形缓冲中被拦截的查询条数，0 值也照实返回
	BlockedRatio   float64 `json:"blocked_ratio"`   // 拦截占比，无数据时为 0，0 值也照实返回
	TodayQueries   uint64  `json:"today_queries"`   // 服务启动后累计查询数，取自原子计数，0 值也照实返回
}

// V2RankItem for ranking APIs
type V2RankItem struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// V2PaginatedLogsResponse for API: /api/v2/audit/logs
type V2PaginatedLogsResponse struct {
	Pagination V2PaginationInfo `json:"pagination"`
	Logs       []AuditLog       `json:"logs"`
}

type V2PaginationInfo struct {
	TotalItems   int `json:"total_items"`
	TotalPages   int `json:"total_pages"`
	CurrentPage  int `json:"current_page"`
	ItemsPerPage int `json:"items_per_page"`
}

// RegisterAuditAPIV2 registers all new v2 audit log APIs.
// This function is completely separate from the v1 registration.
func RegisterAuditAPIV2(router *chi.Mux) {
	router.Route("/api/v2/audit", func(r chi.Router) {
		// 为所有高频/重数据接口套上 WithAsyncGC
		r.Get("/stats", WithAsyncGC(handleV2GetStats))                   // 概览页调用
		r.Get("/rank/domain", WithAsyncGC(handleV2GetDomainRank))        // 概览页调用
		r.Get("/rank/client", WithAsyncGC(handleV2GetClientRank))        // 概览页调用
		r.Get("/rank/domain_set", WithAsyncGC(handleV2GetDomainSetRank)) // 概览页调用
		r.Get("/rank/slowest", WithAsyncGC(handleV2GetSlowestQueries))   // 概览页调用

		r.Get("/logs", WithAsyncGC(handleV2GetLogs)) // 已有的
	})
}

// --- V2 API Handlers ---

// 1. Handler for: Get total queries and average duration
func handleV2GetStats(w http.ResponseWriter, r *http.Request) {
	stats := GlobalAuditCollector.CalculateV2Stats()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		mlog.L().Error("failed to encode v2 stats", zap.Error(err))
	}
}

// 2. Handler for: Get domain query ranking
func handleV2GetDomainRank(w http.ResponseWriter, r *http.Request) {
	limit := parseQueryInt(r, "limit", 20) // Default to top 20
	// domain_set 非空时只统计该规则集下的记录，为空时走原有快速路径
	domainSet := r.URL.Query().Get("domain_set")
	// MODIFIED: Use the new RankByDomain enum
	rank := GlobalAuditCollector.CalculateRankFiltered(RankByDomain, domainSet, limit) // Changed function argument
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rank); err != nil {
		mlog.L().Error("failed to encode v2 domain rank", zap.Error(err))
	}
}

// 3. Handler for: Get client IP query ranking
func handleV2GetClientRank(w http.ResponseWriter, r *http.Request) {
	limit := parseQueryInt(r, "limit", 20) // Default to top 20
	// domain_set 非空时只统计该规则集下的记录，为空时走原有快速路径
	domainSet := r.URL.Query().Get("domain_set")
	// MODIFIED: Use the new RankByClient enum
	rank := GlobalAuditCollector.CalculateRankFiltered(RankByClient, domainSet, limit) // Changed function argument
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rank); err != nil {
		mlog.L().Error("failed to encode v2 client rank", zap.Error(err))
	}
}

// --- ADDED START ---
// 4. Handler for: Get domain_set query ranking
func handleV2GetDomainSetRank(w http.ResponseWriter, r *http.Request) {
	limit := parseQueryInt(r, "limit", 20) // Default to top 20
	rank := GlobalAuditCollector.CalculateRank(RankByDomainSet, limit)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rank); err != nil {
		mlog.L().Error("failed to encode v2 domain_set rank", zap.Error(err))
	}
}

// --- ADDED END ---

// 5. Handler for: Get slowest queries
func handleV2GetSlowestQueries(w http.ResponseWriter, r *http.Request) {
	limit := parseQueryInt(r, "limit", 100) // Default to 100 slowest
	logs := GlobalAuditCollector.GetSlowestQueries(limit)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(logs); err != nil {
		mlog.L().Error("failed to encode v2 slowest queries", zap.Error(err))
	}
}

// 6. Handler for: Get logs with advanced filtering and pagination
func handleV2GetLogs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	exactSearch, _ := strconv.ParseBool(query.Get("exact"))

	params := V2GetLogsParams{
		Page:         parseQueryInt(r, "page", 1),
		Limit:        parseQueryInt(r, "limit", 50),
		Domain:       query.Get("domain"),
		AnswerIP:     query.Get("answer_ip"),
		AnswerCNAME:  query.Get("cname"),
		ClientIP:     query.Get("client_ip"),
		Q:            query.Get("q"),
		Exact:        exactSearch,
		FakeIP:       query.Get("fakeip"),
		QType:        query.Get("qtype"),
		RCode:        query.Get("rcode"),
		DomainSet:    query.Get("domain_set"),
		SinceMinutes: parseQueryInt(r, "since", 0),
	}
	// domain_set_exclude 是需要排除的规则标签，与 domain_set 同时给出时先包含再剔除；空串不剔除。
	params.DomainSetExclude = query.Get("domain_set_exclude")

	response := GlobalAuditCollector.GetV2Logs(params)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		mlog.L().Error("failed to encode v2 paginated logs", zap.Error(err))
	}
}

// Helper function to parse integer from query string with a default value.
func parseQueryInt(r *http.Request, key string, defaultValue int) int {
	if valueStr := r.URL.Query().Get(key); valueStr != "" {
		if value, err := strconv.Atoi(valueStr); err == nil && value > 0 {
			return value
		}
	}
	return defaultValue
}
