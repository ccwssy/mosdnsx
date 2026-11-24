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
// editable 表示该名单支持在线编辑：文本类走 /show + /post，
// sd_set / si_set 走数据源管理接口（/config、/update）。
// editable 受三重约束：插件类型、readOnlyListTags 里的 SRS 生成物
// （geosite_cn / geosite_gfw / si_cn / si_private），以及文件所在目录的语义
// （见 data_dir_manifest.json，目录级 editable=false 即只读）。
//
// managed 表示「用户自建名单」，同样按文件所在目录的 manifest role 判定，
// role 在 managed_roles 里才算自建；自动下载/补丁/数据源目录一律不算。

import (
	"encoding/json"
	"errors"
	"io/fs"
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

// readOnlyListTags 是 SRS 生成物对应的 tag 集合（单一真源）。
// 这些名单由 auto_update.sh 从订阅源生成到 data/ 下，手工改动会被下次自动更新覆盖，
// 因此一律置为只读：面板显示「由数据源自动生成，修改请到数据源管理」，
// 编辑入口走「数据源管理」而不是名单文本编辑器。
// 新增此类生成物时只改这一处，前端不再维护第二份只读名单。
var readOnlyListTags = map[string]bool{
	"geosite_cn":  true,
	"geosite_gfw": true,
	"si_cn":       true,
	"si_private":  true,
}

// dataDirManifestFilename 是目录语义配置文件名，位于 MainConfigBaseDir 下。
// 生产环境即 /etc/mosdns/data_dir_manifest.json；文件缺失时用内置默认值。
const dataDirManifestFilename = "data_dir_manifest.json"

// builtinDataDirManifestJSON 是内置默认 manifest，内容与
// coremain/data_dir_manifest.example.json 完全一致（含每个目录的 path）。
// path 是该目录相对 MainConfigBaseDir 的真实位置，只给数据目录统计用；
// role 的匹配始终按键名（见 dirOfPath）。
// 用字符串常量 + encoding/json 解析，不用 go:embed：模板文件不在编译期依赖里，
// 用户删掉 example 也不影响二进制里的默认值。
const builtinDataDirManifestJSON = `{
  "version": 1,
  "directories": {
    "diydata":  {"role": "user",          "editable": true,  "path": "data/rule/diydata",  "desc": "用户自建名单（面板可编辑，永不被自动更新覆盖）"},
    "txtdata":  {"role": "download",      "editable": false, "path": "data/rule/txtdata",  "desc": "auto_update.sh 每日下载的主名单"},
    "txtpatch": {"role": "patch",         "editable": false, "path": "data/rule/txtpatch", "desc": "静态补丁，补齐 srs→txt 迁移时的条目损失"},
    "srscfg":   {"role": "source_config", "editable": false, "path": "data/rule/srscfg",   "desc": "数据源配置 json（sd_*/si_*）"},
    "srsdata":  {"role": "source_data",   "editable": false, "path": "data/srsdata",       "desc": "srs 规则集二进制"}
  },
  "managed_roles": ["user"]
}
`

// dataDirRole 是目录角色取值。
const (
	dataDirRoleUnknown      = "unknown"
	dataDirRoleUser         = "user"
	dataDirRoleDownload     = "download"
	dataDirRolePatch        = "patch"
	dataDirRoleSourceConfig = "source_config"
	dataDirRoleSourceData   = "source_data"
)

// dataDirEntry 描述一个目录的语义。
type dataDirEntry struct {
	// Role 取值：user / download / patch / source_config / source_data（未登记为 unknown）。
	Role string `json:"role"`
	// Editable 表示该目录下的名单允许面板在线编辑。
	Editable bool `json:"editable"`
	// Path 是该目录相对 MainConfigBaseDir 的路径，供 /api/v1/data-dirs 统计用；
	// 为空时回落到以目录名本身作为相对路径。
	// 目录语义仍按键名用「包含 /<dir>/」匹配，不受此字段影响。
	Path string `json:"path,omitempty"`
	// Desc 是给人看的中文说明。
	Desc string `json:"desc,omitempty"`
}

// dataDirManifest 是 data_dir_manifest.json 的内存形式。
type dataDirManifest struct {
	Version      int                     `json:"version"`
	Directories  map[string]dataDirEntry `json:"directories"`
	ManagedRoles []string                `json:"managed_roles"`
	// source 记录这份 manifest 从哪来：file（用户 json）或 builtin（内置默认）。
	// 不参与 json 序列化，只给 /api/v1/data-dirs 回答「我改了为什么不生效」。
	source string
}

// manifestSourceFile / manifestSourceBuiltin 是 dataDirManifest.source 的两个取值。
const (
	manifestSourceFile    = "file"
	manifestSourceBuiltin = "builtin"
)

// builtinDataDirManifest 解析一次内置默认值；常量是编译期固定的，解析失败只能是
// 有人改坏了常量，此时返回空 manifest（全部目录 unknown），不 panic。
var builtinDataDirManifest = func() dataDirManifest {
	var m dataDirManifest
	if err := json.Unmarshal([]byte(builtinDataDirManifestJSON), &m); err != nil {
		mlog.L().Error("builtin data dir manifest is invalid", zap.Error(err))
		m = dataDirManifest{Version: 1}
	}
	m.source = manifestSourceBuiltin
	return m
}()

// loadDataDirManifest 读取 MainConfigBaseDir/data_dir_manifest.json；
// 文件缺失或解析失败时回落到内置默认，绝不让名单接口 500。
//
// 每次调用都读文件（不做进程级缓存）：用户改完 json 立即生效，不需要重启。
func loadDataDirManifest() dataDirManifest {
	if MainConfigBaseDir == "" {
		return builtinDataDirManifest
	}
	path := filepath.Join(MainConfigBaseDir, dataDirManifestFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		// 文件不存在是常态（用户不建就用内置默认），不刷 WARN。
		if !errors.Is(err, fs.ErrNotExist) {
			mlog.L().Warn("failed to read data dir manifest, falling back to builtin",
				zap.String("path", path), zap.Error(err))
		}
		return builtinDataDirManifest
	}
	var m dataDirManifest
	if err := json.Unmarshal(data, &m); err != nil {
		mlog.L().Warn("failed to parse data dir manifest, falling back to builtin",
			zap.String("path", path), zap.Error(err))
		return builtinDataDirManifest
	}
	if len(m.Directories) == 0 {
		// 空文件 / {"version":1} 这类残缺配置一律当坏配置处理。
		mlog.L().Warn("data dir manifest has no directories, falling back to builtin",
			zap.String("path", path))
		return builtinDataDirManifest
	}
	m.source = manifestSourceFile
	return m
}

// managedRoles 把 managed_roles 转成集合，空配置时退回 {user}。
func (m dataDirManifest) managedRoles() map[string]bool {
	roles := m.ManagedRoles
	if len(roles) == 0 {
		roles = []string{dataDirRoleUser}
	}
	out := make(map[string]bool, len(roles))
	for _, r := range roles {
		if r = strings.TrimSpace(r); r != "" {
			out[r] = true
		}
	}
	return out
}

// roleOfPath 返回路径所在目录的 role；未登记目录返回 unknown。
// 匹配规则：路径归一化为 / 分隔后，用「包含 /<dir>/」判定，不做前缀猜测；
// 多个目录同时命中时取最长的目录名（嵌套目录优先），保证结果稳定。
func (m dataDirManifest) roleOfPath(path string) string {
	dir := m.dirOfPath(path)
	if dir == "" {
		return dataDirRoleUnknown
	}
	if e, ok := m.Directories[dir]; ok && strings.TrimSpace(e.Role) != "" {
		return e.Role
	}
	return dataDirRoleUnknown
}

// dirOfPath 返回路径命中的 manifest 目录名，未命中返回空串。
func (m dataDirManifest) dirOfPath(path string) string {
	if path == "" {
		return ""
	}
	slash := filepath.ToSlash(path)
	best := ""
	for dir := range m.Directories {
		if dir == "" {
			continue
		}
		if !strings.Contains(slash, "/"+filepath.ToSlash(dir)+"/") {
			continue
		}
		if len(dir) > len(best) {
			best = dir
		}
	}
	return best
}

// isManagedPath 判定路径是否属于「用户自建名单」。
// 目录语义优先（role 在 managed_roles 里）；my_ 前缀作为兜底保留，
// 兼容老配置里名单不在 diydata 下的情况。
func (m dataDirManifest) isManagedPath(path string) bool {
	if path == "" {
		return false
	}
	if m.managedRoles()[m.roleOfPath(path)] {
		return true
	}
	return strings.HasPrefix(filepath.Base(path), "my_")
}

// isEditablePath 判定路径所在目录是否允许面板在线编辑。
// 未登记目录（role=unknown）沿用原有按插件类型的判定，即视为可编辑。
func (m dataDirManifest) isEditablePath(path string) bool {
	dir := m.dirOfPath(path)
	if dir == "" {
		return true
	}
	e, ok := m.Directories[dir]
	if !ok {
		return true
	}
	return e.Editable
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
	// Role 是文件所在目录的语义：user / download / patch / source_config /
	// source_data / unknown（见 data_dir_manifest.json）。前端据此做分类展示。
	Role string `json:"role,omitempty"`
	// Managed 表示这是用户自建名单：文件所在目录的 role 在 manifest 的
	// managed_roles 里（默认只有 user），或文件名以 my_ 开头。
	// 自动下载的大规则集（geosite_cn 等）不算自建。
	Managed    bool `json:"managed"`
	EntryCount int  `json:"entry_count"`
}

// RegisterListsAPI 注册名单枚举接口。
//
// 缓存枚举（/api/v1/cache/modules）与名单枚举同属「按配置文件自动发现」的只读
// 接口，共用这一个注册入口，避免在 mosdns.go 里再加一行注册。
func RegisterListsAPI(router *chi.Mux) {
	router.Get("/api/v1/lists", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(collectListPlugins()); err != nil {
			mlog.L().Error("failed to encode list plugins", zap.Error(err))
		}
	})
	// 目录语义只读接口（/api/v1/data-dirs）。注册在这里，避免在 mosdns.go 里再加一行。
	RegisterDataDirsAPI(router)
	RegisterCacheAPI(router)
}

// collectListPlugins 从当前加载的配置里筛出名单型插件。
func collectListPlugins() []ListPluginInfo {
	if MainConfig == nil {
		return []ListPluginInfo{}
	}

	// 每次请求都读一次 manifest：用户改完 json 立即生效（文件很小，几十字节）。
	manifest := loadDataDirManifest()

	out := make([]ListPluginInfo, 0, len(MainConfig.Plugins))
	for _, p := range MainConfig.Plugins {
		if p.Tag == "" || !listPluginTypes[p.Type] {
			continue
		}
		files := extractPluginFiles(p.Args)
		if sourceFileTypes[p.Type] {
			files = extractSourceFiles(p.Args)
		}
		// Editable 三重判定：插件类型 + tag 白名单（兼容老配置）+ 目录语义。
		// Managed / Role 全部按文件所在目录的 manifest role 重算。
		info := ListPluginInfo{
			Tag:      p.Tag,
			Type:     p.Type,
			Kind:     listKinds[p.Type],
			Files:    files,
			Editable: editableListTypes[p.Type] && !readOnlyListTags[p.Tag],
			Role:     dataDirRoleUnknown,
			Name:     p.Tag,
		}
		if len(files) > 0 {
			// 名称优先用文件名，方便按文件名识别（用户自己维护的名单都带语义化文件名）。
			info.Name = filepath.Base(files[0])
			info.EntryCount = countRulesInFile(files[0])
			info.Role = manifest.roleOfPath(files[0])
			info.Editable = info.Editable && manifest.isEditablePath(files[0])
			for _, f := range files {
				if manifest.isManagedPath(f) {
					info.Managed = true
					break
				}
			}
		} else {
			// 拿不到文件（数据源配置文件读不到等）：用 tag 名里能匹配到的目录兜底，
			// 匹配不上才是 unknown。
			info.Role = manifest.roleOfPath(p.Tag)
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
