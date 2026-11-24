// /root/mosdns/coremain/api_audit.go
package coremain

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// RegisterAuditAPI registers the audit log APIs to the given router.
func RegisterAuditAPI(router *chi.Mux) {
	router.Route("/api/v1/audit", func(r chi.Router) {
		r.Post("/start", handleAuditStart)
		r.Post("/stop", handleAuditStop)
		r.Get("/status", handleAuditStatus)
		r.Get("/logs", WithAsyncGC(handleGetAuditLogs))
		r.Post("/clear", WithAsyncGC(handleClearAuditLogs))
		// ADDED: New routes for capacity management
		r.Get("/capacity", handleGetAuditCapacity)
		r.Post("/capacity", handleSetAuditCapacity)
		// 日志保留策略（保留天数 / 单文件体积上限），前端日志页直接消费。
		r.Get("/settings", handleGetAuditSettings)
		r.Post("/settings", handleSetAuditSettings)
	})
}

func handleAuditStart(w http.ResponseWriter, r *http.Request) {
	GlobalAuditCollector.Start()
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Audit log collection started.")
}

func handleAuditStop(w http.ResponseWriter, r *http.Request) {
	GlobalAuditCollector.Stop()
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Audit log collection stopped.")
}

func handleAuditStatus(w http.ResponseWriter, r *http.Request) {
	status := struct {
		Capturing bool `json:"capturing"`
	}{
		Capturing: GlobalAuditCollector.IsCapturing(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func handleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	domainSet := query.Get("domain_set")
	domainSetExclude := query.Get("domain_set_exclude")

	logs := GlobalAuditCollector.GetLogs()
	// 两个过滤参数都为空时保持改造前的路径：只取环形缓冲快照后直接编码，不做任何过滤遍历。
	if domainSet != "" || domainSetExclude != "" {
		logs = filterLogsByDomainSet(logs, domainSet, domainSetExclude)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(logs); err != nil {
		mlog.L().Error("failed to encode audit logs to client", zap.Error(err))
	}
}

func handleClearAuditLogs(w http.ResponseWriter, r *http.Request) {
	GlobalAuditCollector.ClearLogs()
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "In-memory audit logs cleared.")
}

// ADDED: Handler to get current audit log capacity.
func handleGetAuditCapacity(w http.ResponseWriter, r *http.Request) {
	capacity := struct {
		Capacity int `json:"capacity"`
	}{
		Capacity: GlobalAuditCollector.GetCapacity(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(capacity)
}

// MODIFIED: Handler to set new audit log capacity.
func handleSetAuditCapacity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Capacity int `json:"capacity"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// <<< MODIFIED: Pass the MainConfigBaseDir to the SetCapacity function >>>
	GlobalAuditCollector.SetCapacity(req.Capacity, MainConfigBaseDir)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Audit log capacity set to %d. Existing logs have been cleared.", req.Capacity)
}

// auditSettingsResponse 是 /api/v1/audit/settings 的响应体，字段名与前端约定写死。
type auditSettingsResponse struct {
	Capacity       int   `json:"capacity"`
	RetentionDays  int   `json:"retention_days"`
	FileMaxMB      int64 `json:"file_max_mb"`
	FileEnabled    bool  `json:"file_enabled"`
	AuditDirBytes  int64 `json:"audit_dir_bytes"`
	AuditFileCount int   `json:"audit_file_count"`
}

// handleGetAuditSettings 返回当前日志保留策略与落盘目录占用。
func handleGetAuditSettings(w http.ResponseWriter, r *http.Request) {
	cfg := getAuditFileCfg()

	retentionDays := cfg.RetentionDays
	if retentionDays <= 0 {
		retentionDays = defaultAuditRetentionDays
	}
	fileMaxMB := cfg.FileMaxMB
	if fileMaxMB <= 0 {
		fileMaxMB = defaultAuditFileMaxMB
	}

	// 目录统计失败时返回 0，不把统计问题升级成 500。
	dirBytes, fileCount := auditDirStats()

	resp := auditSettingsResponse{
		Capacity:       GlobalAuditCollector.GetCapacity(),
		RetentionDays:  retentionDays,
		FileMaxMB:      fileMaxMB,
		FileEnabled:    cfg.FileEnabled,
		AuditDirBytes:  dirBytes,
		AuditFileCount: fileCount,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		mlog.L().Error("failed to encode audit settings to client", zap.Error(err))
	}
}

// handleSetAuditSettings 更新日志保留策略。
// 两项均可选：字段缺省表示不改；显式给出的值必须在允许区间内，越界（含 0）一律 400。
func handleSetAuditSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RetentionDays *int   `json:"retention_days"`
		FileMaxMB     *int64 `json:"file_max_mb"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求体格式错误: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.RetentionDays != nil && (*req.RetentionDays < minAuditRetentionDays || *req.RetentionDays > maxAuditRetentionDays) {
		http.Error(w, fmt.Sprintf("retention_days 超出允许范围（%d-%d 天）", minAuditRetentionDays, maxAuditRetentionDays), http.StatusBadRequest)
		return
	}
	if req.FileMaxMB != nil && (*req.FileMaxMB < minAuditFileMaxMB || *req.FileMaxMB > maxAuditFileMaxMB) {
		http.Error(w, fmt.Sprintf("file_max_mb 超出允许范围（%d-%d MB）", minAuditFileMaxMB, maxAuditFileMaxMB), http.StatusBadRequest)
		return
	}

	cfg := getAuditFileCfg()
	retentionDays := cfg.RetentionDays
	if retentionDays <= 0 {
		retentionDays = defaultAuditRetentionDays
	}
	if req.RetentionDays != nil {
		retentionDays = *req.RetentionDays
	}
	fileMaxMB := cfg.FileMaxMB
	if fileMaxMB <= 0 {
		fileMaxMB = defaultAuditFileMaxMB
	}
	if req.FileMaxMB != nil {
		fileMaxMB = *req.FileMaxMB
	}

	if err := applyAuditRetentionSettings(retentionDays, fileMaxMB, MainConfigBaseDir); err != nil {
		mlog.L().Error("failed to apply audit retention settings", zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	dirBytes, fileCount := auditDirStats()
	resp := auditSettingsResponse{
		Capacity:       GlobalAuditCollector.GetCapacity(),
		RetentionDays:  retentionDays,
		FileMaxMB:      fileMaxMB,
		FileEnabled:    getAuditFileCfg().FileEnabled,
		AuditDirBytes:  dirBytes,
		AuditFileCount: fileCount,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		mlog.L().Error("failed to encode audit settings to client", zap.Error(err))
	}
}
