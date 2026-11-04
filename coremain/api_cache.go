package coremain

// 缓存插件枚举 API。
//
// 面板「缓存管理」需要知道配置里到底有哪些缓存实例，而不是写死一套 tag：
// 原来前端硬编码的 cache_all / cache_cn / cache_node / cache_google 等在官方
// 配置里根本不存在，表格永远是 0，点「清空」直接打不存在的插件。
//
// GET /api/v1/cache/modules 返回配置中所有 type == "cache" 的插件：
//   [{"tag":"cache","name":"主缓存"},{"tag":"cache_fakeip","name":"FakeIP 缓存"}]
//
// 已知 tag 用中文友好名，未知 tag 直接显示原 tag（兜底，方便以后加缓存分片）。

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// cachePluginType 是缓存插件的 type 名（plugin/executable/cache 的 PluginType）。
const cachePluginType = "cache"

// cacheDisplayNames 把缓存 tag 映射成中文友好名，表里没有的 tag 沿用原 tag。
var cacheDisplayNames = map[string]string{
	"cache":        "主缓存",
	"cache_fakeip": "FakeIP 缓存",
}

// CachePluginInfo 描述一个缓存插件实例。
type CachePluginInfo struct {
	Tag  string `json:"tag"`
	Name string `json:"name"`
}

// RegisterCacheAPI 注册缓存枚举接口。
func RegisterCacheAPI(router *chi.Mux) {
	router.Get("/api/v1/cache/modules", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(collectCachePlugins()); err != nil {
			mlog.L().Error("failed to encode cache plugins", zap.Error(err))
		}
	})
}

// collectCachePlugins 从当前加载的配置里筛出缓存插件。
func collectCachePlugins() []CachePluginInfo {
	if MainConfig == nil {
		return []CachePluginInfo{}
	}

	out := make([]CachePluginInfo, 0, len(MainConfig.Plugins))
	for _, p := range MainConfig.Plugins {
		if p.Tag == "" || p.Type != cachePluginType {
			continue
		}
		name := p.Tag
		if displayName, ok := cacheDisplayNames[p.Tag]; ok {
			name = displayName
		}
		out = append(out, CachePluginInfo{Tag: p.Tag, Name: name})
	}

	// 按 tag 字典序输出，保证接口结果稳定（缓存分片的增删不影响其余行顺序）。
	sort.SliceStable(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}
