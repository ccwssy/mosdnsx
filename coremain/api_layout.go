package coremain

// 面板模块排版后端（按页分键的双键结构）。
//
// 首页与 /log 概览页各自有一套可拖拽的模块顺序，分别落在 panel_layout.json 的
// home / log 两个键下，互不覆盖。文件与 aliases.json 同目录、同风格：写临时文件后
// os.Rename 原子替换，内存与磁盘保持一致。
//
// 契约（前端只认这个契约，模块标识由前端定义）：
//   GET  /api/v1/layout/?page=<home|log> → 该页的裸 JSON 数组，元素为模块标识字符串；无存档时返回 []
//   POST /api/v1/layout/?page=<home|log> → 请求体为该页的完整裸数组，校验后只覆盖该页键，返回 {"ok":true}
//   page 缺省按 home；page 非法值返回 400，不静默降级（避免前端拼错参数却以为保存成功）
//
// 落盘结构是 map[string][]string，例如 {"home":["a","b"],"log":["c"]}。
// 兼容旧格式：磁盘顶层若仍是裸数组，加载时整体归入 home 键并立即以新格式原子回写一次，
// 保证已保存的首页布局不丢。
//
// 后端只做存储与校验，不识别任何具体模块标识；缺失模块由前端补到默认位置，
// 因此未来新增模块不需要改后端。

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// layoutFilename 是面板布局在配置目录下的文件名。
const layoutFilename = "panel_layout.json"

const (
	// layoutMaxModules 是一次布局允许的模块上限，只用于挡住异常请求体。
	layoutMaxModules = 64
	// layoutMaxIDLen 是单个模块标识的长度上限。
	layoutMaxIDLen = 64

	// layoutPageHome 是首页模块排版的键名。
	layoutPageHome = "home"
	// layoutPageLog 是 /log 概览页模块排版的键名。
	layoutPageLog = "log"
)

// allowedLayoutPages 是允许的 page 取值集合，前端拼错的 page 一律拒绝而不是降级。
var allowedLayoutPages = map[string]bool{
	layoutPageHome: true,
	layoutPageLog:  true,
}

var (
	// layoutMu 保护 panelLayout。写盘期间持写锁，读取只取读锁。
	layoutMu sync.RWMutex

	// panelLayout 是各页已保存的模块顺序，按页键存储；初始化为空 map，避免加载前读到 nil。
	panelLayout = make(map[string][]string, len(allowedLayoutPages))
)

// layoutPath 返回布局文件的落盘路径：<配置目录>/panel_layout.json。
func layoutPath() string {
	dir := MainConfigBaseDir
	if dir == "" {
		// 与 aliasesPath 一致：配置目录未知时退回当前目录。
		dir = "."
	}
	return filepath.Join(dir, layoutFilename)
}

// resolveLayoutPage 归一化 page 参数：空串按 home，其余必须在 allowedLayoutPages 里。
// 返回 error 时表示 page 非法，调用方应回 400。
func resolveLayoutPage(r *http.Request) (string, error) {
	page := strings.TrimSpace(r.URL.Query().Get("page"))
	if page == "" {
		return layoutPageHome, nil
	}
	if !allowedLayoutPages[page] {
		return "", errors.New("未知的 page 取值: " + page + "（只支持 home / log）")
	}
	return page, nil
}

// copyLayoutLocked 复制某一页的布局，保证返回非 nil 切片（JSON 里是 [] 而不是 null）。
// 调用方必须持有 layoutMu 的读锁或写锁。
func copyLayoutLocked(page string) []string {
	saved := panelLayout[page]
	out := make([]string, len(saved))
	copy(out, saved)
	return out
}

// loadPanelLayout 启动时从磁盘加载布局；文件不存在或内容损坏都按空布局处理，不 panic。
// 顶层是裸数组（旧格式）时整体归入 home 键，并立即以新格式原子回写一次。
func loadPanelLayout() {
	layoutMu.Lock()
	defer layoutMu.Unlock()

	panelLayout = make(map[string][]string, len(allowedLayoutPages))

	path := layoutPath()
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		loaded, legacy, uerr := decodePanelLayout(data)
		if uerr != nil {
			mlog.L().Warn("panel layout file is broken, starting with empty layout",
				zap.String("path", path), zap.Error(uerr))
			loaded = make(map[string][]string, len(allowedLayoutPages))
		}
		panelLayout = loaded
		if legacy {
			// 旧格式（裸数组）已归入 home 键，立刻以新格式回写一次，之后的读取不再走兼容分支。
			if serr := savePanelLayoutLocked(); serr != nil {
				mlog.L().Warn("failed to migrate legacy panel layout file",
					zap.String("path", path), zap.Error(serr))
			} else {
				mlog.L().Info("legacy panel layout migrated to per-page format", zap.String("path", path))
			}
		}
		mlog.L().Info("panel layout loaded", zap.String("path", path),
			zap.Int("home_modules", len(panelLayout[layoutPageHome])),
			zap.Int("log_modules", len(panelLayout[layoutPageLog])))
	case !os.IsNotExist(err):
		mlog.L().Warn("failed to read panel layout file, starting with empty layout",
			zap.String("path", path), zap.Error(err))
	}
}

// decodePanelLayout 解析落盘内容，返回各页布局与「是否命中了旧格式」标记。
// 顶层是数组 → 旧格式，整体归入 home；顶层是对象 → 按对象读。
// 各页的条目都要过 sanitizeLayout，校验失败的那一页按空布局处理，不影响另一页。
func decodePanelLayout(data []byte) (map[string][]string, bool, error) {
	out := make(map[string][]string, len(allowedLayoutPages))
	if strings.TrimSpace(string(data)) == "" {
		return out, false, nil
	}

	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return out, false, err
	}

	legacyArray := false
	mapped := make(map[string][]string, len(allowedLayoutPages))
	switch v := raw.(type) {
	case []any:
		legacyArray = true
		mapped[layoutPageHome] = stringsFromAny(v)
	case map[string]any:
		for page := range allowedLayoutPages {
			if items, ok := v[page]; ok {
				if list, ok := items.([]any); ok {
					mapped[page] = stringsFromAny(list)
				}
			}
		}
	default:
		return out, false, errors.New("panel layout root must be an object or array")
	}

	// 只有全部页都通过校验才允许迁移回写：否则保留磁盘原文件，用户修好后仍能恢复。
	allValid := true
	for page, items := range mapped {
		clean, cerr := sanitizeLayout(items)
		if cerr != nil {
			allValid = false
			mlog.L().Warn("panel layout page has invalid entries, page ignored",
				zap.String("page", page), zap.Error(cerr))
			continue
		}
		if len(clean) > 0 {
			out[page] = clean
		}
	}
	return out, legacyArray && allValid, nil
}

// stringsFromAny 把 JSON 解析出的数组转成字符串切片，非字符串元素直接忽略。
func stringsFromAny(items []any) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// sanitizeLayout 规范化前端提交的顺序：去空白、去空串、去重、限长限量。
// 校验失败只影响本次请求，不会改动内存或磁盘。
func sanitizeLayout(in []string) ([]string, error) {
	if len(in) > layoutMaxModules {
		return nil, errors.New("too many modules")
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, id := range in {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if len(id) > layoutMaxIDLen {
			return nil, errors.New("module id too long")
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

// savePanelLayoutLocked 把整份双键布局原子写入磁盘（临时文件 + os.Rename），调用方必须持有写锁。
func savePanelLayoutLocked() error {
	path := layoutPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// 值为 nil 的键序列化成 null，这里统一补成空数组，落盘结构保持一致便于人工查看。
	snapshot := make(map[string][]string, len(panelLayout))
	for page, items := range panelLayout {
		if items == nil {
			snapshot[page] = []string{}
			continue
		}
		snapshot[page] = items
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, layoutFilename+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// 重命名成功后这里会因文件不存在而失败，忽略即可；失败路径上负责清理残留。
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// RegisterLayoutAPI 注册排版接口，并在此处完成启动时的一次性加载。
func RegisterLayoutAPI(router *chi.Mux) {
	loadPanelLayout()

	router.Route("/api/v1/layout", func(r chi.Router) {
		r.Get("/", handleGetLayout)
		r.Post("/", handleSetLayout)
	})
}

// handleGetLayout 返回 page 指定页已保存的模块顺序；无存档时返回空数组而不是 null。
func handleGetLayout(w http.ResponseWriter, r *http.Request) {
	page, err := resolveLayoutPage(r)
	if err != nil {
		writeLayoutError(w, http.StatusBadRequest, "page 参数不合法: "+err.Error())
		return
	}

	layoutMu.RLock()
	out := copyLayoutLocked(page)
	layoutMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		mlog.L().Error("failed to encode panel layout", zap.Error(err))
	}
}

// handleSetLayout 接收 page 指定页的完整顺序并落盘，只覆盖该页键，不碰另一页；
// 校验或写盘失败时内存与磁盘都不变。
func handleSetLayout(w http.ResponseWriter, r *http.Request) {
	page, err := resolveLayoutPage(r)
	if err != nil {
		writeLayoutError(w, http.StatusBadRequest, "page 参数不合法: "+err.Error())
		return
	}

	var req []string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeLayoutError(w, http.StatusBadRequest, "布局必须是模块标识数组")
		return
	}
	next, err := sanitizeLayout(req)
	if err != nil {
		writeLayoutError(w, http.StatusBadRequest, "布局不合法: "+err.Error())
		return
	}

	layoutMu.Lock()
	prev, hadPrev := panelLayout[page]
	panelLayout[page] = next
	if serr := savePanelLayoutLocked(); serr != nil {
		// 写盘失败则回滚内存，保证内存与磁盘一致。
		if hadPrev {
			panelLayout[page] = prev
		} else {
			delete(panelLayout, page)
		}
		layoutMu.Unlock()
		mlog.L().Error("failed to save panel layout", zap.String("path", layoutPath()), zap.Error(serr))
		writeLayoutError(w, http.StatusInternalServerError, "布局写入失败")
		return
	}
	layoutMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]bool{"ok": true}); err != nil {
		mlog.L().Error("failed to encode panel layout response", zap.Error(err))
	}
}

// writeLayoutError 以 JSON 形式返回错误，前端 api 封装会读取 error 字段。
func writeLayoutError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
