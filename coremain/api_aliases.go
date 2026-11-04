package coremain

// 客户端别名后端。
//
// 别名把「IP -> 可读名字」存成一张小表，落盘到 <配置目录>/aliases.json，
// 供审计日志展示（LookupClientName）和面板维护（本文件的 HTTP 接口）。
//
// 并发模型：
//   - 读取（热路径 LookupClientName / GET 接口）只取读锁，读者之间不互斥；
//   - 写入（POST / DELETE）持写锁、先写临时文件再 os.Rename 原子替换，
//     落盘失败时内存保持原样，保证内存与磁盘一致。
//
// 配置目录来源：MainConfigBaseDir（见 coremain/run.go），与配置里 include 的相对
// 路径、config_overrides.json 等使用同一个目录，因此这里不硬编码任何路径。

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// aliasesFilename 是别名单在配置目录下的文件名。
const aliasesFilename = "aliases.json"

// aliasesMu 保护 aliasesTable。写盘期间持写锁，查询只取读锁。
var aliasesMu sync.RWMutex

// aliasesTable 保存 IP -> 别名，初始化为空表，避免加载前查询出现 nil map。
var aliasesTable = make(map[string]string)

// aliasesPath 返回别名单的落盘路径：<配置目录>/aliases.json。
func aliasesPath() string {
	dir := MainConfigBaseDir
	if dir == "" {
		// 与 loadUpstreamOverrides 等既有逻辑保持一致：配置目录未知时退回当前目录。
		dir = "."
	}
	return filepath.Join(dir, aliasesFilename)
}

// loadAliases 启动时从磁盘加载别名单；文件不存在或内容损坏都按空表处理，不 panic。
func loadAliases() {
	aliasesMu.Lock()
	defer aliasesMu.Unlock()

	path := aliasesPath()
	table := make(map[string]string)
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(data) > 0 {
			if uerr := json.Unmarshal(data, &table); uerr != nil {
				mlog.L().Warn("client aliases file is broken, starting with empty table",
					zap.String("path", path), zap.Error(uerr))
				table = make(map[string]string)
			}
		}
	case !os.IsNotExist(err):
		mlog.L().Warn("failed to read client aliases file, starting with empty table",
			zap.String("path", path), zap.Error(err))
	}
	if table == nil {
		// JSON 里是 null 时 unmarshal 会把 map 置空，这里补一个空表便于后续写入。
		table = make(map[string]string)
	}
	aliasesTable = table
	mlog.L().Info("client aliases loaded", zap.String("path", path), zap.Int("entries", len(table)))
}

// saveAliasesLocked 把别名单原子写入磁盘（临时文件 + os.Rename），调用方必须持有写锁。
func saveAliasesLocked(table map[string]string) error {
	path := aliasesPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(table, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, aliasesFilename+".tmp-*")
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

// setAlias 写入一条别名；name 为空表示删除该 IP。返回错误时内存与磁盘都没变。
func setAlias(ip, name string) error {
	aliasesMu.Lock()
	defer aliasesMu.Unlock()

	next := make(map[string]string, len(aliasesTable)+1)
	for k, v := range aliasesTable {
		next[k] = v
	}
	if name == "" {
		delete(next, ip)
	} else {
		next[ip] = name
	}
	// 先落盘再切换内存：写盘失败时保留旧表，避免内存领先于磁盘。
	if err := saveAliasesLocked(next); err != nil {
		return err
	}
	aliasesTable = next
	return nil
}

// LookupClientName 返回 IP 对应的客户端别名，查不到返回空串。
//
// 可被 HTTP 请求与审计热路径并发调用：只取读锁，且不会修改任何状态。
func LookupClientName(ip string) string {
	ip = strings.TrimSpace(ip)
	// 双栈监听下 IPv4 地址常以 ::ffff:1.2.3.4 形式出现，查表前统一剥掉前缀。
	if len(ip) >= 7 && strings.EqualFold(ip[:7], "::ffff:") {
		ip = ip[7:]
	}
	aliasesMu.RLock()
	defer aliasesMu.RUnlock()
	return aliasesTable[ip]
}

// RegisterAliasesAPI 注册客户端别名接口，并在此处完成启动时的一次性加载。
func RegisterAliasesAPI(router *chi.Mux) {
	loadAliases()

	router.Route("/api/v1/aliases", func(r chi.Router) {
		r.Get("/", handleListAliases)
		r.Post("/", handleSetAlias)
		r.Delete("/{ip}", handleDeleteAlias)
	})
}

// handleListAliases 返回整张别名表。
func handleListAliases(w http.ResponseWriter, r *http.Request) {
	aliasesMu.RLock()
	out := make(map[string]string, len(aliasesTable))
	for k, v := range aliasesTable {
		out[k] = v
	}
	aliasesMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		mlog.L().Error("failed to encode client aliases", zap.Error(err))
	}
}

// handleSetAlias 新增/更新一条别名；name 为空表示删除该 IP。
func handleSetAlias(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAliasesError(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		writeAliasesError(w, http.StatusBadRequest, "ip 不能为空")
		return
	}
	name := strings.TrimSpace(req.Name)
	if err := setAlias(ip, name); err != nil {
		mlog.L().Error("failed to save client alias",
			zap.String("ip", ip), zap.String("name", name), zap.Error(err))
		writeAliasesError(w, http.StatusInternalServerError, "别名写入失败")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"ip": ip, "name": name}); err != nil {
		mlog.L().Error("failed to encode client alias response", zap.Error(err))
	}
}

// handleDeleteAlias 删除一条别名；记录不存在也算成功，便于前端幂等删除。
func handleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(chi.URLParam(r, "ip"))
	if ip == "" {
		writeAliasesError(w, http.StatusBadRequest, "ip 不能为空")
		return
	}
	if err := setAlias(ip, ""); err != nil {
		mlog.L().Error("failed to delete client alias", zap.String("ip", ip), zap.Error(err))
		writeAliasesError(w, http.StatusInternalServerError, "别名删除失败")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeAliasesError 以 JSON 形式返回错误信息。
func writeAliasesError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
