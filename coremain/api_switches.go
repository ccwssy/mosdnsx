package coremain

// 开关聚合 API。
//
// switchN 插件自带的是「一实例一接口」：GET /plugins/switchN/show 读值、
// POST /plugins/switchN/post 写值。开关中心要一次拿全部开关，前端逐个请求既
// 慢又难统一错误处理，因此在 coremain 里做一层聚合：
//
//	GET  /api/v1/switches        返回全部 switchN 实例的当前值、取值枚举、位号
//	POST /api/v1/switches/{tag}  写一个开关（PUT 同样注册，JSON 与表单两种 body 都收）
//
// 实例清单不硬编码，遍历 MainConfig.Plugins 自动发现：新增一个 switchN 实例
// 只改配置，不用改这里。values / desc 这类展示文案来自
// MainConfigBaseDir/switch_meta.json，缺失或坏 json 回落内置默认（模式同
// api_lists.go 的 loadDataDirManifest），绝不让接口 500。
//
// 读值读状态文件、写值走 HTTP 自调用，两者不能互换：switchN 的内存值才是分流
// 真值，只改文件内存不会变（见 switcher3.go 的 updateGlobalMask），所以写必须
// POST /plugins/<tag>/post；读则读文件，省掉每个实例一次 HTTP。

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

const (
	// switchMetaFilename 是用户可覆盖的开关元数据文件名（放在 MainConfigBaseDir 下）。
	switchMetaFilename = "switch_meta.json"
	// switchBitBase 是位号推导基数：switch3 占掩码第 34 位（32 + 3 - 1）。
	switchBitBase = 32
	// switchPostTimeout 卡住调用方：插件 HTTP 在回环上，3 秒不返回就是真卡住了。
	switchPostTimeout = 3 * time.Second
)

// builtinSwitchMetaJSON 是内置默认元数据，与 switch_meta.example.json 语义一致。
// 用户没建 switch_meta.json 时用它，保证开箱即可用。
const builtinSwitchMetaJSON = `{
  "version": 1,
  "switches": {
    "switch3": {"values": ["A", "B"], "desc": "核心模式 A/B"},
    "switch4": {"values": ["A", "B"], "desc": "备用开关 4"}
  }
}`

// switchMetaEntry 是单个开关的展示元数据。
type switchMetaEntry struct {
	Values []string `json:"values"`
	Desc   string   `json:"desc"`
}

// switchMeta 是 switch_meta.json 的结构。
type switchMeta struct {
	Version  int                        `json:"version"`
	Switches map[string]switchMetaEntry `json:"switches"`
}

// builtinSwitchMeta 解析一次内置默认值；常量是编译期固定的，解析失败只能是
// 有人改坏了常量，此时返回空集合（全部走字段缺省），不 panic。
var builtinSwitchMeta = func() switchMeta {
	var m switchMeta
	if err := json.Unmarshal([]byte(builtinSwitchMetaJSON), &m); err != nil {
		mlog.L().Error("builtin switch meta is invalid", zap.Error(err))
		m = switchMeta{Version: 1}
	}
	return m
}()

// loadSwitchMeta 读取 MainConfigBaseDir/switch_meta.json；文件缺失、解析失败
// 或没有 switches 时回落到内置默认，绝不让开关接口不可用。
//
// 每次调用都读文件（不做进程级缓存）：用户改完 json 立即生效，不需要重启。
func loadSwitchMeta() switchMeta {
	if MainConfigBaseDir == "" {
		return builtinSwitchMeta
	}
	path := filepath.Join(MainConfigBaseDir, switchMetaFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		// 文件不存在是常态（用户不建就用内置默认），不刷 WARN。
		if !errors.Is(err, fs.ErrNotExist) {
			mlog.L().Warn("failed to read switch meta, falling back to builtin",
				zap.String("path", path), zap.Error(err))
		}
		return builtinSwitchMeta
	}
	var m switchMeta
	if err := json.Unmarshal(data, &m); err != nil {
		mlog.L().Warn("failed to parse switch meta, falling back to builtin",
			zap.String("path", path), zap.Error(err))
		return builtinSwitchMeta
	}
	if len(m.Switches) == 0 {
		// 空文件 / {"version":1} 这类残缺配置一律当坏配置处理。
		mlog.L().Warn("switch meta has no switches, falling back to builtin",
			zap.String("path", path))
		return builtinSwitchMeta
	}
	return m
}

// SwitchInfo 是 /api/v1/switches 里的一个开关。字段名是前端冻结契约，不要改。
type SwitchInfo struct {
	Tag    string   `json:"tag"`
	Name   string   `json:"name"`
	Value  string   `json:"value"`
	Values []string `json:"values"`
	Bit    int      `json:"bit"`
	Desc   string   `json:"desc"`
}

// switchBitOf 从插件类型反推位号：switch3 → 34（公式 32 + N - 1）。
// 解析不出数字（例如未编译的 "switch"）时返回 false，调用方跳过该实例。
func switchBitOf(pluginType string) (int, bool) {
	if !strings.HasPrefix(pluginType, "switch") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(pluginType, "switch"))
	if err != nil || n < 1 {
		return 0, false
	}
	return switchBitBase + n - 1, true
}

// isSwitchPluginType 判断配置里的 type 是不是可用的 switchN 实例：
// 以 "switch" 开头、带数字后缀（排除未编译的 "switch"）且位号可推导。
func isSwitchPluginType(pluginType string) bool {
	if pluginType == "switch" {
		return false
	}
	_, ok := switchBitOf(pluginType)
	return ok
}

// switchStateFile 取实例的状态文件路径。args 里的 initial_value 名字误导，
// 它其实是状态文件路径（见 switcher3.go 的 Init）。
//
// 插件自己按配置原样打开这个路径（相对路径相对进程 CWD），所以这里先按原样
// 判断：原样存在就用它，否则才当作相对 MainConfigBaseDir 的路径，避免读错文件
// 把别的开关的值显示出来。
func switchStateFile(p PluginConfig) string {
	path := switchInitialValueArg(p.Args)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return path
	}
	if _, err := os.Stat(path); err == nil {
		return path
	}
	if MainConfigBaseDir == "" {
		return path
	}
	return filepath.Join(MainConfigBaseDir, path)
}

// switchInitialValueArg 从插件 args 里取 initial_value；args 不是 map 或字段缺失
// 时返回空串（该实例仍然列出，只是值为空）。
func switchInitialValueArg(args any) string {
	m, ok := args.(map[string]any)
	if !ok {
		return ""
	}
	if v, ok := m["initial_value"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// switchCurrentValue 读状态文件作为当前值：switchN 的 Init 已把文件内容读进内存，
// 文件就是落盘真值，读它省掉每个实例一次 HTTP。读不到按空值处理，不算错误。
func switchCurrentValue(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// switchStateOnOff 与 switchStateAB 是两套互斥的二元取值族。
// 插件 Match() 对 "A" 走 fast flag、其余走字面比对（switcher1.go:133-141），
// 所以 on/off 与 A/B 都是合法族；API 不应把取值钉死在 A/B。
var (
	switchStateOnOff = []string{"on", "off"}
	switchStateAB    = []string{"A", "B"}
)

// switchStatePath 取 tag 对应实例的状态文件路径：先看配置里的 initial_value
// （经 switchStateFile 做相对路径裁决），字段缺失时按生产既有约定
// <MainConfigBaseDir>/data/switches/<tag>.state 兜底。
func switchStatePath(tag string) string {
	if cfg, ok := findSwitchConfig(tag); ok {
		if path := switchStateFile(cfg); path != "" {
			return path
		}
	}
	if MainConfigBaseDir == "" {
		return ""
	}
	return filepath.Join(MainConfigBaseDir, "data", "switches", tag+".state")
}

// readSwitchStateValue 读某个 switch 实例状态文件的当前值（trim 后）。
// 读不到返回空串：文件缺失是常态，不报错也不刷 warn。
func readSwitchStateValue(tag string) string {
	return switchCurrentValue(switchStatePath(tag))
}

// switchedValuesFor 把状态文件当前值映射成合法取值族：on/off 与 A/B 各自成族，
// 其它值只能取自身（无法枚举出别的合法值），空值返回 nil 交给调用方兜底。
func switchedValuesFor(state string) []string {
	switch state {
	case "on", "off":
		return append([]string(nil), switchStateOnOff...)
	case "A", "B":
		return append([]string(nil), switchStateAB...)
	case "":
		return nil
	default:
		return []string{state}
	}
}

// switchValuesOf 取一个开关的取值白名单。
//
// 优先级：显式 meta > 状态文件当前值推导 > 兜底 A/B。不能硬编码 A/B：生产状态
// 文件写的是 on/off，而 "off" 与 "A"/"B" 都是插件 Match() 认的合法值，钉死 A/B
// 会让 on/off 型开关永远写不进去（写 off → 400，写 A → 200 但语义跑偏）。
func switchValuesOf(meta switchMeta, tag string) []string {
	// 1. 显式声明优先：switch_meta.json 里配了 values 就以它为准。
	if entry, ok := meta.Switches[tag]; ok && len(entry.Values) > 0 {
		out := make([]string, 0, len(entry.Values))
		for _, v := range entry.Values {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	// 2. 按状态文件当前值推导取值族：当前值必然合法，且其所属族是用户唯一
	//    会切到的目标集合。
	if derived := switchedValuesFor(readSwitchStateValue(tag)); len(derived) > 0 {
		return derived
	}
	// 3. 兜底：无状态文件、无配置引用时保持既有行为。
	return []string{"A", "B"}
}

// switchDescOf 取一个开关的中文说明，meta 里没配时用 tag 兜底。
func switchDescOf(meta switchMeta, tag string) string {
	if entry, ok := meta.Switches[tag]; ok {
		if desc := strings.TrimSpace(entry.Desc); desc != "" {
			return desc
		}
	}
	return "开关 " + tag
}

// switchValueAllowed 判断取值是否在白名单里：错值写下去会让 rules 永不命中，
// 所以宁可在这里 400 掉。
func switchValueAllowed(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// collectSwitches 遍历当前配置里的 switchN 实例，拼出聚合视图。
func collectSwitches() []SwitchInfo {
	out := make([]SwitchInfo, 0, 2)
	if MainConfig == nil {
		return out
	}
	// 每次请求都读一次 meta：用户改完 json 立即生效（文件很小）。
	meta := loadSwitchMeta()
	for _, p := range MainConfig.Plugins {
		if p.Tag == "" || !isSwitchPluginType(p.Type) {
			continue
		}
		bit, ok := switchBitOf(p.Type)
		if !ok {
			continue
		}
		out = append(out, SwitchInfo{
			Tag:    p.Tag,
			Name:   p.Tag,
			Value:  switchCurrentValue(switchStateFile(p)),
			Values: switchValuesOf(meta, p.Tag),
			Bit:    bit,
			Desc:   switchDescOf(meta, p.Tag),
		})
	}
	return out
}

// findSwitchConfig 按 tag 找配置里的 switchN 实例。
func findSwitchConfig(tag string) (PluginConfig, bool) {
	if MainConfig == nil {
		return PluginConfig{}, false
	}
	for _, p := range MainConfig.Plugins {
		if p.Tag == tag && isSwitchPluginType(p.Type) {
			return p, true
		}
	}
	return PluginConfig{}, false
}

// postSwitchValue 通过 HTTP 自调用把新值交给插件：只有插件自己会同时更新内存
// 掩码和状态文件，直接写文件会让内存与文件分叉（分流仍按旧值走）。
func postSwitchValue(tag, value string) error {
	addr := ""
	if MainConfig != nil {
		addr = strings.TrimSpace(MainConfig.API.HTTP)
	}
	if addr == "" {
		return errors.New("api http address is not configured")
	}
	body, err := json.Marshal(map[string]string{"value": value})
	if err != nil {
		return err
	}
	url := "http://" + addr + "/plugins/" + tag + "/post"
	client := &http.Client{Timeout: switchPostTimeout}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("switch plugin returned " + resp.Status)
	}
	return nil
}

// handleSwitchWrite 处理单个开关的写请求（POST / PUT 共用）。
func handleSwitchWrite(w http.ResponseWriter, r *http.Request) {
	tag := strings.TrimSpace(chi.URLParam(r, "tag"))
	if tag == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing switch tag"})
		return
	}
	if _, ok := findSwitchConfig(tag); !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "unknown switch tag: " + tag})
		return
	}

	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body: " + err.Error()})
		return
	}
	value := strings.TrimSpace(body.Value)
	if value == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "empty value"})
		return
	}
	if values := switchValuesOf(loadSwitchMeta(), tag); !switchValueAllowed(values, value) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":     false,
			"error":  "value not allowed: " + value + " (allowed: " + strings.Join(values, ",") + ")",
			"values": values,
		})
		return
	}
	if err := postSwitchValue(tag, value); err != nil {
		mlog.L().Warn("failed to set switch value",
			zap.String("tag", tag), zap.String("value", value), zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tag": tag, "value": value})
}

// RegisterSwitchesAPI 注册开关聚合接口。
//
// 与名单枚举（/api/v1/lists）同属「按配置文件自动发现」的接口，写接口并存
// POST 与 PUT，前端不复用方法语义的差异。
func RegisterSwitchesAPI(router *chi.Mux) {
	router.Get("/api/v1/switches", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "switches": collectSwitches()})
	})
	router.Post("/api/v1/switches/{tag}", handleSwitchWrite)
	router.Put("/api/v1/switches/{tag}", handleSwitchWrite)
}
