package coremain

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mkLog(name string, d time.Duration) AuditLog {
	return AuditLog{
		ClientIP:     "192.168.2.10",
		QueryType:    "A",
		QueryName:    name,
		QueryTime:    time.Now().Add(-d),
		DurationMs:   1.5,
		ResponseCode: "NOERROR",
		DomainSet:    "geosite_cn",
	}
}

// 落盘后应能按时间顺序读回，且条数不超上限。
func TestAuditFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()

	store, err := newAuditFileStore(dir, 7, 16)
	if err != nil {
		t.Fatalf("newAuditFileStore: %v", err)
	}

	batch := []AuditLog{
		mkLog("a.example.com", 3*time.Second),
		mkLog("b.example.com", 2*time.Second),
		mkLog("c.example.com", time.Second),
	}
	store.Write(batch)
	store.Close()

	got := loadAuditLogsFromDisk(dir, 10)
	if len(got) != 3 {
		t.Fatalf("读回 %d 条, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].QueryTime.Before(got[i-1].QueryTime) {
			t.Fatalf("读回顺序未按时间升序: %v then %v", got[i-1].QueryTime, got[i].QueryTime)
		}
	}

	// limit 生效：只取最后 2 条
	tail := loadAuditLogsFromDisk(dir, 2)
	if len(tail) != 2 {
		t.Fatalf("limit 未生效: 读回 %d 条, want 2", len(tail))
	}
}

// 超过保留期的文件应被清理。
func TestAuditFileStorePurgeExpired(t *testing.T) {
	dir := t.TempDir()

	old := filepath.Join(dir, "audit-20200101.jsonl")
	if err := os.WriteFile(old, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().AddDate(0, 0, -30)
	if err := os.Chtimes(old, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	store, err := newAuditFileStore(dir, 7, 16)
	if err != nil {
		t.Fatalf("newAuditFileStore: %v", err)
	}
	store.Close()

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("过期日志文件未被清理: %v", err)
	}
}

// 文件体积超过上限后应滚动到新分片，且历史仍可完整读取。
func TestAuditFileStoreRollBySize(t *testing.T) {
	dir := t.TempDir()

	// maxFileMB 最小粒度为 MB，这里直接用小数值验证滚动逻辑（1MB 太大，用 1 并塞满）。
	store, err := newAuditFileStore(dir, 7, 1)
	if err != nil {
		t.Fatalf("newAuditFileStore: %v", err)
	}
	big := mkLog("roll.example.com", 0)
	big.Answers = make([]AnswerDetail, 0, 200)
	for i := 0; i < 200; i++ {
		big.Answers = append(big.Answers, AnswerDetail{Type: "A", TTL: 300, Data: "203.0.113.1"})
	}
	for i := 0; i < 400; i++ {
		store.Write([]AuditLog{big})
	}
	store.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Errorf("未发生体积滚动: 只有 %d 个文件", len(entries))
	}

	if got := loadAuditLogsFromDisk(dir, 1000); len(got) == 0 {
		t.Error("滚动后读回为空")
	}
}

// SeedLogs 应回填内存缓冲并重建统计。
func TestSeedLogsRebuildsStats(t *testing.T) {
	c := NewAuditCollector(10)
	history := []AuditLog{
		mkLog("x.example.com", 3*time.Second),
		mkLog("x.example.com", 2*time.Second),
		mkLog("y.example.com", time.Second),
	}
	c.SeedLogs(history)

	if got := len(c.logs); got != 3 {
		t.Fatalf("回填 %d 条, want 3", got)
	}
	if c.domainCounts["x.example.com"] != 2 {
		t.Errorf("域名统计未重建: %d, want 2", c.domainCounts["x.example.com"])
	}
	if c.clientCounts["192.168.2.10"] != 3 {
		t.Errorf("客户端统计未重建: %d, want 3", c.clientCounts["192.168.2.10"])
	}
}
