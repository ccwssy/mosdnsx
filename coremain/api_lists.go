package coremain

// 名单插件枚举 API。
//
// 面板的「名单管理」需要知道配置里到底有哪些可编辑的名单文件，而不是写死一套
// tag（作者原始配置的 whitelist/blocklist/... 在官方 mosdns 配置里并不存在）。
//
// GET /api/v1/lists 返回配置中所有 domain_set / hosts / ip_set / sd_set / si_set 插件：
//   [{"tag":"...","name":"my_whitelist.txt","type":"domain_set","kind":"text",
//     "files":["..."],"editable":true,"entry_count":28}]
//
// editable 表示该类型支持在线编辑：文本类走 /show + /post，
// sd_set / si_set 走数据源管理接口（/config、/update）。

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
	"sd_set":           true,
	"si_set":           true,
}

// sourceFileTypes 是文件路径不在 args.files / args.hosts，而在 sources 里的插件类型。
// 这类插件没有 /post 文本编辑接口，名单内容改由数据源管理接口（/config、/update）维护。
var sourceFileTypes = map[string]bool{
	"sd_set": true,
	"si_set": true,
}

// listKinds 把插件类型映射成前端渲染用的编辑器类型：
//
//	text   —— 文本编辑器（走 /show + /post）
//	sd_set —— 数据源管理界面（域名类 SRS）
//	si_set —— 数据源管理界面（IP 类 SRS）
//
// 表里没有的类型不下发 kind 字段，前端按 text 处理，保证向后兼容。
var listKinds = map[string]string{
	"domain_set":       "text",
	"domain_set_light": "text",
	"hosts":            "text",
	"ip_set":           "text",
	"sd_set":           "sd_set",
	"si_set":           "si_set",
}

// editableListTypes 是支持在线编辑的插件类型：
// 文本类提供 /show + /post，sd_set / si_set 提供数据源配置接口。
var editableListTypes = map[string]bool{
	"domain_set":       true,
	"domain_set_light": true,
	"hosts":            true,
	"sd_set":           true,
	"si_set":           true,
}

// listDisplayNames 把已知名单的 tag 映射成中文友好名（面板 nav 直接展示这个字段）。
// 前端 coremain/www/assets/js/log.js 里的 LIST_DISPLAY_NAMES 是同一份映射：
// 前端优先用本地表，这里返回一致的名字，保证没升级前端时也能看到中文。
// 表里没有的 tag（用户自建名单）仍沿用文件名，保持原有语义。
var listDisplayNames = map[string]string{
	"ddns_hosts":              "静态域名映射",
	"blocklist":               "黑名单（手动拦截）",
	"sd_ads":                  "广告拦截(SRS)",
	"sd_nocn":                 "国外域名集储备(SRS)",
	"sd_tld":                  "国外TLD储备(SRS)",
	"si_cn":                   "国内 IP 段(SRS)",
	"si_private":              "内网 IP 段(SRS)",
	"high_priority_whitelist": "白名单（强制直连）",
	"high_priority_greylist":  "灰名单（优先代理）",
	"geosite_cn":              "国内域名集(SRS)",
	"geosite_gfw":             "国外域名集",
	"geoip_cn":                "国内 IP 段",
	"geoip_private":           "内网 IP 段",
}

// ListPluginInfo 描述一个名单型插件。
type ListPluginInfo struct {
	Tag  string `json:"tag"`
	Name string `json:"name"`
	Type string `json:"type"`
	// Kind 是前端渲染用的编辑器类型：text 为文本编辑器，sd_set / si_set 为数据源管理界面。
	// 未知类型不下发该字段（omitempty），前端按 text 兜底。
	Kind     string   `json:"kind,omitempty"`
	Files    []string `json:"files"`
	Editable bool     `json:"editable"`
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
		if sourceFileTypes[p.Type] {
			files = extractSourceFiles(p.Args)
		}
		info := ListPluginInfo{
			Tag:      p.Tag,
			Type:     p.Type,
			Kind:     listKinds[p.Type],
			Files:    files,
			Editable: editableListTypes[p.Type],
			// sd_set / si_set 的数据源由用户在「名单管理」里维护，始终算自建名单。
			Managed: sourceFileTypes[p.Type],
			Name:    p.Tag,
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
		// 已知名单用中文友好名覆盖文件名：nav 上「my_hosts.txt」看不出用途。
		if name, ok := listDisplayNames[p.Tag]; ok {
			info.Name = name
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

// extractSourceFiles 汇总 sd_set / si_set 各数据源的文件路径。
//
// 这两类插件的 yaml args 只有 socks5 / local_config，真正的数据源放在
// local_config 指向的 JSON 里（内容是 []RuleSource，每个元素带 files 字段）；
// 若 args 里直接内联了 sources，也一并支持。
func extractSourceFiles(args any) []string {
	m, ok := args.(map[string]any)
	if !ok {
		return nil
	}

	var out []string
	// 1) args.sources 内联形式。
	if v, exists := m["sources"]; exists {
		out = append(out, sourceFilesFrom(v)...)
	}
	// 2) local_config 指向的 JSON 文件形式。
	if p, ok := m["local_config"].(string); ok && strings.TrimSpace(p) != "" {
		cfg := readSourceConfigJSON(p)
		if cfg == nil && !filepath.IsAbs(p) && MainConfigBaseDir != "" {
			// 插件本身按进程工作目录读相对路径，读不到时再按配置目录兜底。
			cfg = readSourceConfigJSON(filepath.Join(MainConfigBaseDir, p))
		}
		if cfg != nil {
			out = append(out, sourceFilesFrom(cfg)...)
		}
	}
	return out
}

// readSourceConfigJSON 把数据源配置文件解析成通用结构，读不到或解析失败返回 nil。
func readSourceConfigJSON(path string) any {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil
	}
	return v
}

// sourceFilesFrom 从任意形状的 sources 结构里取出 files 字段。
func sourceFilesFrom(v any) []string {
	switch vv := v.(type) {
	case []any:
		var out []string
		for _, item := range vv {
			out = append(out, sourceFilesFrom(item)...)
		}
		return out
	case map[string]any:
		f, exists := vv["files"]
		if !exists {
			return nil
		}
		return stringList(f)
	}
	return nil
}

// stringList 把 files 字段（字符串或字符串数组）展开成文件路径列表。
func stringList(v any) []string {
	switch vv := v.(type) {
	case string:
		if vv == "" {
			return nil
		}
		return []string{vv}
	case []string:
		return vv
	case []any:
		var out []string
		for _, item := range vv {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
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
