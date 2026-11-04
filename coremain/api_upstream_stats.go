package coremain

import (
	"encoding/json"
	"math"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
	dto "github.com/prometheus/client_model/go"
)

// forward 插件在 registry 中的指标全名：mosdns_ 前缀 + forward_ 插件前缀 + 指标名。
const (
	metricForwardQueryTotal = "mosdns_forward_query_total"
	metricForwardErrTotal   = "mosdns_forward_err_total"
	metricForwardLatency    = "mosdns_forward_response_latency_millisecond"

	labelForwardPluginTag = "tag"      // forward 插件 tag
	labelForwardUpstream  = "upstream" // 上游 tag
)

// upstreamStatsItem 是 GET /api/v1/upstream/stats 返回数组中的一项。
type upstreamStatsItem struct {
	Upstream string  `json:"upstream"`
	Plugin   string  `json:"plugin"`
	Queries  int64   `json:"queries"`
	Errors   int64   `json:"errors"`
	AvgMs    float64 `json:"avg_ms"`
	P95Ms    float64 `json:"p95_ms"`

	avg float64 // 未取整的平均延迟，毫秒
	p95 float64 // 未取整的 p95 延迟，毫秒
}

// upstreamStatsKey 是聚合键：同一上游 tag 可能出现在多个 forward 插件下。
type upstreamStatsKey struct {
	plugin   string
	upstream string
}

// RegisterUpstreamStatsAPI 注册 forward 上游指标聚合接口。
func RegisterUpstreamStatsAPI(router *chi.Mux, m *Mosdns) {
	router.Get("/api/v1/upstream/stats", handleUpstreamStats(m))
}

func handleUpstreamStats(m *Mosdns) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items, err := collectUpstreamStats(m)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		body, err := json.Marshal(items)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

// collectUpstreamStats 从实例自身的 prometheus registry 聚合 forward 的 per-upstream 指标。
// 没有任何 mosdns_forward_* 指标时返回空切片（JSON 为 []）。
func collectUpstreamStats(m *Mosdns) ([]upstreamStatsItem, error) {
	acc := make(map[upstreamStatsKey]*upstreamStatsItem)
	// registry 未初始化时按“无指标”处理，避免空指针。
	if m == nil || m.metricsReg == nil {
		return []upstreamStatsItem{}, nil
	}
	mfs, err := m.metricsReg.Gather()
	if err != nil {
		return nil, err
	}

	getItem := func(pluginTag, upstreamTag string) *upstreamStatsItem {
		key := upstreamStatsKey{plugin: pluginTag, upstream: upstreamTag}
		if it, ok := acc[key]; ok {
			return it
		}
		it := &upstreamStatsItem{Plugin: pluginTag, Upstream: upstreamTag}
		acc[key] = it
		return it
	}

	for _, mf := range mfs {
		switch mf.GetName() {
		case metricForwardQueryTotal:
			for _, mt := range mf.GetMetric() {
				pluginTag, upstreamTag, ok := forwardMetricLabels(mt)
				if !ok {
					continue
				}
				getItem(pluginTag, upstreamTag).Queries = int64(mt.GetCounter().GetValue())
			}
		case metricForwardErrTotal:
			for _, mt := range mf.GetMetric() {
				pluginTag, upstreamTag, ok := forwardMetricLabels(mt)
				if !ok {
					continue
				}
				getItem(pluginTag, upstreamTag).Errors = int64(mt.GetCounter().GetValue())
			}
		case metricForwardLatency:
			for _, mt := range mf.GetMetric() {
				pluginTag, upstreamTag, ok := forwardMetricLabels(mt)
				if !ok {
					continue
				}
				it := getItem(pluginTag, upstreamTag)
				h := mt.GetHistogram()
				if cnt := h.GetSampleCount(); cnt > 0 {
					it.avg = h.GetSampleSum() / float64(cnt)
				}
				it.p95 = histogramP95(h)
			}
		}
	}

	items := make([]upstreamStatsItem, 0, len(acc))
	for _, it := range acc {
		it.AvgMs = roundTo2(it.avg)
		it.P95Ms = roundTo2(it.p95)
		items = append(items, *it)
	}
	// plugin 升序，同一 plugin 内 upstream 升序。
	sort.Slice(items, func(i, j int) bool {
		if items[i].Plugin != items[j].Plugin {
			return items[i].Plugin < items[j].Plugin
		}
		return items[i].Upstream < items[j].Upstream
	})
	return items, nil
}

// forwardMetricLabels 取出 forward 指标的 tag（插件）与 upstream（上游）标签。
func forwardMetricLabels(mt *dto.Metric) (pluginTag, upstreamTag string, ok bool) {
	for _, lp := range mt.GetLabel() {
		switch lp.GetName() {
		case labelForwardPluginTag:
			pluginTag = lp.GetValue()
		case labelForwardUpstream:
			upstreamTag = lp.GetValue()
		}
	}
	if len(pluginTag) == 0 || len(upstreamTag) == 0 {
		return "", "", false
	}
	return pluginTag, upstreamTag, true
}

// histogramP95 用 _bucket 的累计计数估算 p95，返回命中桶的上界（毫秒）。
// total 取 +Inf 桶的累计值（无 +Inf 桶时取最大桶的累计值）；total 为 0 或无桶时返回 0。
// le=+Inf 的桶不会被返回：若只有它满足阈值，退回最大的有限桶（无有限桶时返回 0）。
func histogramP95(h *dto.Histogram) float64 {
	buckets := h.GetBucket()
	if len(buckets) == 0 {
		return 0
	}

	total := 0.0
	hasInf := false
	maxCum := 0.0
	maxUB := math.Inf(-1)
	finite := make([]*dto.Bucket, 0, len(buckets))
	for _, b := range buckets {
		ub := b.GetUpperBound()
		if math.IsInf(ub, 1) {
			hasInf = true
			total = float64(b.GetCumulativeCount())
			continue
		}
		finite = append(finite, b)
		if ub > maxUB {
			maxUB = ub
			maxCum = float64(b.GetCumulativeCount())
		}
	}
	if !hasInf {
		total = maxCum
	}
	if total <= 0 || len(finite) == 0 {
		return 0
	}

	// 按上界升序找第一个累计值 >= 阈值的桶。
	sort.Slice(finite, func(i, j int) bool { return finite[i].GetUpperBound() < finite[j].GetUpperBound() })
	threshold := total * 0.95
	for _, b := range finite {
		if float64(b.GetCumulativeCount()) >= threshold {
			return b.GetUpperBound()
		}
	}
	return finite[len(finite)-1].GetUpperBound()
}

// roundTo2 保留 2 位小数。
func roundTo2(v float64) float64 {
	return math.Round(v*100) / 100
}
