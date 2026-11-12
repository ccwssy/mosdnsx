package coremain

// 首页模块排版后端。
//
// 面板首页的模块顺序由用户在页面上拖拽决定，顺序落盘到 <配置目录>/panel_layout.json，
// 与 aliases.json 同目录、同风格：写临时文件后 os.Rename 原子替换，内存与磁盘保持一致。
//
// 契约（前端只认这个契约，模块标识由前端定义）：
//   GET  /api/v1/layout/ → 裸 JSON 数组，元素为模块标识字符串；无存档时返回 []
//   POST /api/v1/layout/ → 请求体为完整数组，校验后落盘，返回 {"ok":true}
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
)

var (
	// layoutMu 保护 panelLayout。写盘期间持写锁，读取只取读锁。
	layoutMu sync.RWMutex

	// panelLayout 是已保存的模块顺序，初始化为空切片，避免加载前读到 nil。
	panelLayout = make([]string, 0, layoutMaxModules)
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

// loadPanelLayout 启动时从磁盘加载布局；文件不存在或内容损坏都按空布局处理，不 panic。
func loadPanelLayout() {
	layoutMu.Lock()
	defer layoutMu.Unlock()

	path := layoutPath()
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var saved []string
		if len(data) > 0 {
			if uerr := json.Unmarshal(data, &saved); uerr != nil {
				mlog.L().Warn("panel layout file is broken, starting with empty layout",
					zap.String("path", path), zap.Error(uerr))
				saved = nil
			}
		}
		clean, cerr := sanitizeLayout(saved)
		if cerr != nil {
			mlog.L().Warn("panel layout file has invalid entries, layout ignored",
				zap.String("path", path), zap.Error(cerr))
			clean = make([]string, 0, layoutMaxModules)
		}
		panelLayout = clean
		mlog.L().Info("panel layout loaded", zap.String("path", path), zap.Int("modules", len(clean)))
	case !os.IsNotExist(err):
		mlog.L().Warn("failed to read panel layout file, starting with empty layout",
			zap.String("path", path), zap.Error(err))
		panelLayout = make([]string, 0, layoutMaxModules)
	}
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

// savePanelLayoutLocked 把布局原子写入磁盘（临时文件 + os.Rename），调用方必须持有写锁。
func savePanelLayoutLocked(layout []string) error {
	path := layoutPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(layout, "", "  ")
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

// RegisterLayoutAPI 注册首页排版接口，并在此处完成启动时的一次性加载。
func RegisterLayoutAPI(router *chi.Mux) {
	loadPanelLayout()

	router.Route("/api/v1/layout", func(r chi.Router) {
		r.Get("/", handleGetLayout)
		r.Post("/", handleSetLayout)
	})
}

// handleGetLayout 返回已保存的模块顺序；无存档时返回空数组而不是 null。
func handleGetLayout(w http.ResponseWriter, r *http.Request) {
	layoutMu.RLock()
	out := make([]string, len(panelLayout))
	copy(out, panelLayout)
	layoutMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		mlog.L().Error("failed to encode panel layout", zap.Error(err))
	}
}

// handleSetLayout 接收完整顺序并落盘；校验或写盘失败时内存与磁盘都不变。
func handleSetLayout(w http.ResponseWriter, r *http.Request) {
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
	if serr := savePanelLayoutLocked(next); serr != nil {
		layoutMu.Unlock()
		mlog.L().Error("failed to save panel layout", zap.String("path", layoutPath()), zap.Error(serr))
		writeLayoutError(w, http.StatusInternalServerError, "布局写入失败")
		return
	}
	panelLayout = next
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
