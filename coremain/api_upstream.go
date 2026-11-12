package coremain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"go.uber.org/zap"
)

const upstreamOverridesFilename = "upstream_overrides.json"

// UpstreamOverrideConfig 定义 UI/API 交互的完整数据结构
type UpstreamOverrideConfig struct {
	Tag      string `json:"tag"`      // 上游名称 (Upstream Name)
	Enabled  bool   `json:"enabled"`  // 是否启用
	Protocol string `json:"protocol"` // UI类型: aliapi, udp, tcp, dot, doh...

	// 通用字段
	Addr                 string `json:"addr,omitempty"`
	DialAddr             string `json:"dial_addr,omitempty"`
	IdleTimeout          int    `json:"idle_timeout,omitempty"`
	UpstreamQueryTimeout int    `json:"upstream_query_timeout,omitempty"`

	// DNS (DoT/DoH/TCP/UDP) 专用
	EnablePipeline     bool   `json:"enable_pipeline,omitempty"`
	EnableHTTP3        bool   `json:"enable_http3,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	Socks5             string `json:"socks5,omitempty"`
	SoMark             int    `json:"so_mark,omitempty"`
	BindToDevice       string `json:"bind_to_device,omitempty"`
	Bootstrap          string `json:"bootstrap,omitempty"`
	BootstrapVer       int    `json:"bootstrap_version,omitempty"`

	// AliAPI 专用
	AccountID       string `json:"account_id,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
	ServerAddr      string `json:"server_addr,omitempty"`
	EcsClientIP     string `json:"ecs_client_ip,omitempty"`
	EcsClientMask   uint8  `json:"ecs_client_mask,omitempty"`
}

// GlobalUpstreamOverrides 映射关系: 插件Tag -> 上游配置列表
type GlobalUpstreamOverrides map[string][]UpstreamOverrideConfig

var (
	upstreamOverridesLock sync.RWMutex
	upstreamOverrides     GlobalUpstreamOverrides
)

// GetUpstreamOverrides 供 aliapi 插件初始化调用
func GetUpstreamOverrides(pluginTag string) []UpstreamOverrideConfig {
	upstreamOverridesLock.RLock()
	defer upstreamOverridesLock.RUnlock()

	if upstreamOverrides == nil {
		// 释放读锁，获取写锁加载 (简化处理)
		upstreamOverridesLock.RUnlock()
		_ = loadUpstreamOverrides()
		upstreamOverridesLock.RLock()
	}

	entries, ok := upstreamOverrides[pluginTag]
	if !ok || len(entries) == 0 {
		return nil
	}
	return entries
}

// loadUpstreamOverrides 内部加载函数
func loadUpstreamOverrides() error {
	upstreamOverridesLock.Lock()
	defer upstreamOverridesLock.Unlock()

	dir := MainConfigBaseDir
	if dir == "" {
		dir = "."
	}
	// 获取绝对路径用于 Debug
	absDir, _ := filepath.Abs(dir)
	path := filepath.Join(dir, upstreamOverridesFilename)
	
	mlog.L().Info("[Debug UpstreamAPI] Loading overrides", 
		zap.String("MainConfigBaseDir", dir), 
		zap.String("AbsoluteDir", absDir),
		zap.String("File", path))

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			mlog.L().Info("[Debug UpstreamAPI] File not found, creating new map", zap.String("path", path))
			upstreamOverrides = make(GlobalUpstreamOverrides)
			return nil
		}
		mlog.L().Error("[Debug UpstreamAPI] Failed to read file", zap.Error(err))
		return err
	}

	var cfg GlobalUpstreamOverrides
	if err := json.Unmarshal(data, &cfg); err != nil {
		mlog.L().Error("[Debug UpstreamAPI] JSON parse error", zap.Error(err))
		return err
	}
	
	// Count items for debug
	count := 0
	for _, v := range cfg {
		count += len(v)
	}
	mlog.L().Info("[Debug UpstreamAPI] Loaded success", zap.Int("groups", len(cfg)), zap.Int("total_items", count))
	
	upstreamOverrides = cfg
	return nil
}
