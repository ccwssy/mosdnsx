package coremain

// 数据目录语义只读 API。
//
// 目录语义（哪个目录是用户自建、哪个是自动下载、哪个是补丁/数据源）由
// MainConfigBaseDir/data_dir_manifest.json 决定，缺失时用内置默认值
// （见 api_lists.go 的 builtinDataDirManifestJSON）。
//
// GET /api/v1/data-dirs 返回：
//
//	{"manifest_source":"file|builtin",
//	 "directories":{"diydata":{"role":"user","editable":true,"path":"data/rule/diydata","desc":"..."}, ...},
//	 "stats":{"diydata":{"files":5,"bytes":2000}, ...}}
//
// directories 是 manifest 原样的目录语义（含 path）；stats 按每个目录的 path
// 去 MainConfigBaseDir 下统计真实文件，缺 path 的旧配置回落成目录键名。
//
// manifest_source 用来回答「我改了 json 为什么不生效」：file 表示正在用用户的
// json，builtin 表示回落到了内置默认值。
// 本接口只读：只做目录枚举与 stat，不写任何文件。

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

// DataDirStat 是一个目录的非递归统计结果。
type DataDirStat struct {
	// Files 是目录下普通文件数（不递归、不统计子目录）。
	Files int `json:"files"`
	// Bytes 是这些普通文件的总字节数。
	Bytes int64 `json:"bytes"`
}

// DataDirsResponse 是 GET /api/v1/data-dirs 的响应体。
type DataDirsResponse struct {
	// ManifestSource 是 file（用户 json）或 builtin（内置默认值）。
	ManifestSource string                  `json:"manifest_source"`
	Directories    map[string]dataDirEntry `json:"directories"`
	Stats          map[string]DataDirStat  `json:"stats"`
}

// RegisterDataDirsAPI 注册数据目录语义只读接口。
//
// 注意：本函数是导出函数，但当前没有被 coremain/mosdns.go 引用（该文件不授权
// 改动）。它由 RegisterListsAPI（coremain/api_lists.go）内部调用完成挂载；
// 若 RegisterListsAPI 未被调用，本接口不可达。
func RegisterDataDirsAPI(router *chi.Mux) {
	router.Get("/api/v1/data-dirs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(collectDataDirs()); err != nil {
			mlog.L().Error("failed to encode data dirs", zap.Error(err))
		}
	})
}

// collectDataDirs 汇总目录语义与实时统计。任何单项失败都不影响整体响应。
func collectDataDirs() DataDirsResponse {
	manifest := loadDataDirManifest()
	if manifest.source == "" {
		manifest.source = manifestSourceBuiltin
	}

	dirs := make(map[string]dataDirEntry, len(manifest.Directories))
	names := make([]string, 0, len(manifest.Directories))
	for dir, entry := range manifest.Directories {
		if dir == "" {
			continue
		}
		if entry.Role == "" {
			entry.Role = dataDirRoleUnknown
		}
		dirs[dir] = entry
		names = append(names, dir)
	}
	// 排序只为日志/调试顺序稳定，json 的 map 键本身由 encoding/json 排序。
	sort.Strings(names)

	stats := make(map[string]DataDirStat, len(names))
	for _, dir := range names {
		// 统计走 entry.path（相对 MainConfigBaseDir 的真实位置）；
		// 老 json 没有 path 字段时回落成目录名本身，与改造前行为一致。
		rel := strings.TrimSpace(dirs[dir].Path)
		if rel == "" {
			rel = dir
		}
		stats[dir] = countDirFiles(rel)
		if stats[dir].Files == 0 {
			continue
		}
		mlog.L().Debug("data dir stats",
			zap.String("dir", dir), zap.String("path", rel),
			zap.Int("files", stats[dir].Files), zap.Int64("bytes", stats[dir].Bytes))
	}

	return DataDirsResponse{
		ManifestSource: manifest.source,
		Directories:    dirs,
		Stats:          stats,
	}
}

// countDirFiles 非递归统计 MainConfigBaseDir/<relPath> 下普通文件数与总字节。
// relPath 来自 manifest 每个目录的 path 字段（如 data/rule/txtdata），
// 而非目录键名本身——键名只是语义标签，未必是真实路径。
// 目录不存在或读取失败一律返回 0（记 0 而不报错，单项失败不影响其它目录）。
func countDirFiles(relPath string) DataDirStat {
	if MainConfigBaseDir == "" || relPath == "" {
		return DataDirStat{}
	}
	entries, err := os.ReadDir(filepath.Join(MainConfigBaseDir, relPath))
	if err != nil {
		return DataDirStat{}
	}
	var stat DataDirStat
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		stat.Files++
		stat.Bytes += info.Size()
	}
	return stat
}
