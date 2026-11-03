package coremain

// 名单插件枚举 API。
//
// 面板的「名单管理」需要知道配置里到底有哪些可编辑的名单文件，而不是写死一套
// tag（作者原始配置的 whitelist/blocklist/... 在官方 mosdns 配置里并不存在）。
//
// GET /api/v1/lists 返回配置中所有 domain_set / hosts / ip_set 插件：
//   [{"tag":"...","name":"my_whitelist.txt","type":"domain_set",
//     "files":["..."],"editable":true,"entry_count":28}]
//
// editable 表示该类型支持在线编辑（目前只有 domain_set 提供 /show /post /save）。

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// listPluginTypes 是可以在「名单管理」里展示的插件类型。
var listPluginTypes = map[string]bool{
	"domain_set":       true,
	"domain_set_light": true,
	"hosts":            true,
	"ip_set":           true,
}

// ListPluginInfo 描述一个名单型插件。
type ListPluginInfo struct {
	Tag        string   `json:"tag"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Files      []string `json:"files"`
	Editable   bool     `json:"editable"`
	// Managed 表示这是用户自建名单（data/rule/ 下或以 my_ 开头），
	// 自动下载的大规则集（geosite_cn 等）不应出现在在线编辑列表里。
	Managed    bool `json:"managed"`
	EntryCount int  `json:"entry_count"`
}

// RegisterListsAPI 注册名单枚举接口。
func RegisterListsAPI(router *chi.Mux) {
	router.Get("/api/v1/lists", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(collectListPlugins()); err != nil {
			mlog.L().Error("failed to encode list plugins", zap.Error(err))
		}
	})
}

// collectListPlugins 从当前加载的配置里筛出名单型插件。
func collectListPlugins() []ListPluginInfo {
	if MainConfig == nil {
		return []ListPluginInfo{}
	}

	out := make([]ListPluginInfo, 0, len(MainConfig.Plugins))
	for _, p := range MainConfig.Plugins {
		if p.Tag == "" || !listPluginTypes[p.Type] {
			continue
		}
		files := extractPluginFiles(p.Args)
		info := ListPluginInfo{
			Tag:      p.Tag,
			Type:     p.Type,
			Files:    files,
			Editable: p.Type == "domain_set" || p.Type == "domain_set_light" || p.Type == "hosts",
			Name:     p.Tag,
		}
		if len(files) > 0 {
			// 名称优先用文件名，方便按文件名识别（用户自己维护的名单都带语义化文件名）。
			info.Name = filepath.Base(files[0])
			info.EntryCount = countRulesInFile(files[0])
			for _, f := range files {
				if strings.Contains(f, "/rule/") || strings.HasPrefix(filepath.Base(f), "my_") {
					info.Managed = true
					break
				}
			}
		}
		out = append(out, info)
	}

	// 有 files 的排前面，其余按 tag 字典序。
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].Files) != len(out[j].Files) {
			return len(out[i].Files) > len(out[j].Files)
		}
		return out[i].Tag < out[j].Tag
	})
	return out
}

// extractPluginFiles 从插件 args 里取出文件列表（兼容 files / hosts 两种字段）。
func extractPluginFiles(args any) []string {
	m, ok := args.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	for _, key := range []string{"files", "hosts"} {
		v, exists := m[key]
		if !exists {
			continue
		}
		switch vv := v.(type) {
		case []any:
			for _, item := range vv {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
		case []string:
			out = append(out, vv...)
		case string:
			out = append(out, vv)
		}
	}
	return out
}

// countRulesInFile 统计名单文件里的有效规则行数，读不到就返回 0。
func countRulesInFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
	}
	return count
}
