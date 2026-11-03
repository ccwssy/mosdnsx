package coremain

// 查询日志落盘支持。
//
// 默认行为保持原样（只存内存环形缓冲，重启清零）。开启 file_enabled 后：
//   - 每条查询日志追加写入 <dir>/audit-YYYYMMDD.jsonl（按天切分）
//   - 启动时从磁盘回填最近 N 条到内存环形缓冲，面板重启后仍能看到历史
//   - 按 retention_days 清理过期文件
//
// 写盘走独立 goroutine + 有界 channel，查询路径不会因磁盘慢而阻塞。

import (
	"bufio"
	"container/heap"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"go.uber.org/zap"
)

const (
	auditLogFilePrefix        = "audit-"
	auditLogFileSuffix        = ".jsonl"
	defaultAuditRetentionDays = 7
	defaultAuditFileMaxMB     = 64
	auditFileQueueSize        = 2048
)

// AuditFileStore 负责查询日志的落盘与回填。
type AuditFileStore struct {
	ch   chan []AuditLog
	done chan struct{}

	mu        sync.Mutex
	dir       string
	retention int
	maxBytes  int64
	curPath   string
	curDate   string
	curSeq    int
	curSize   int64
	dropped   int64
}

// newAuditFileStore 创建落盘器并启动后台写入协程。
func newAuditFileStore(dir string, retentionDays int, maxFileMB int64) (*AuditFileStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("empty audit log dir")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create audit log dir %s: %w", dir, err)
	}
	if retentionDays <= 0 {
		retentionDays = defaultAuditRetentionDays
	}
	if maxFileMB <= 0 {
		maxFileMB = defaultAuditFileMaxMB
	}

	s := &AuditFileStore{
		ch:        make(chan []AuditLog, auditFileQueueSize),
		done:      make(chan struct{}),
		dir:       dir,
		retention: retentionDays,
		maxBytes:  maxFileMB << 20,
	}
	s.purgeExpired()
	go s.writer()
	return s, nil
}

// Write 非阻塞投递一批日志；队列满时丢弃并计数，宁可丢日志也不拖慢查询。
func (s *AuditFileStore) Write(logs []AuditLog) {
	if s == nil || len(logs) == 0 {
		return
	}
	batch := make([]AuditLog, len(logs))
	copy(batch, logs)
	select {
	case s.ch <- batch:
	default:
		s.mu.Lock()
		s.dropped += int64(len(batch))
		s.mu.Unlock()
	}
}

// Close 停止后台写入并落盘残留数据。
func (s *AuditFileStore) Close() {
	if s == nil {
		return
	}
	close(s.ch)
	<-s.done
}

func (s *AuditFileStore) writer() {
	defer close(s.done)
	for batch := range s.ch {
		s.writeBatch(batch)
	}
}

func (s *AuditFileStore) writeBatch(logs []AuditLog) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.ensureFileLocked()
	if err != nil {
		mlog.L().Error("failed to open audit log file", zap.String("dir", s.dir), zap.Error(err))
		return
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		mlog.L().Error("failed to append audit log file", zap.String("path", path), zap.Error(err))
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	var written int64
	for _, log := range logs {
		b, err := json.Marshal(log)
		if err != nil {
			continue
		}
		n, _ := w.Write(b)
		w.WriteByte('\n')
		written += int64(n) + 1
	}
	if err := w.Flush(); err != nil {
		mlog.L().Error("failed to flush audit log file", zap.String("path", path), zap.Error(err))
		return
	}
	s.curSize += written
}

// ensureFileLocked 返回当前写入文件路径，必要时按天或按体积滚动。
func (s *AuditFileStore) ensureFileLocked() (string, error) {
	date := time.Now().Format("20060102")
	if s.curPath != "" && s.curDate == date && s.curSize < s.maxBytes {
		return s.curPath, nil
	}

	seq := 0
	for {
		name := auditLogFilePrefix + date + auditLogFileSuffix
		if seq > 0 {
			name = fmt.Sprintf("%s%s-%d%s", auditLogFilePrefix, date, seq, auditLogFileSuffix)
		}
		path := filepath.Join(s.dir, name)

		st, err := os.Stat(path)
		if os.IsNotExist(err) {
			// 新文件：按天切换时从 0 开始，体积滚动时沿用递增序号。
			s.curPath, s.curDate, s.curSeq, s.curSize = path, date, seq, 0
			return path, nil
		}
		if err != nil {
			return "", err
		}
		// 当天第一次落盘或换天：只有当文件未超限才继续追加。
		if s.curDate != date || seq > 0 {
			if st.Size() < s.maxBytes {
				s.curPath, s.curDate, s.curSeq, s.curSize = path, date, seq, st.Size()
				return path, nil
			}
		} else if st.Size() < s.maxBytes {
			s.curPath, s.curDate, s.curSeq, s.curSize = path, date, seq, st.Size()
			return path, nil
		}
		seq++
		if seq > 9999 {
			return "", fmt.Errorf("too many audit log segments for %s", date)
		}
	}
}

// purgeExpired 删除超过保留期的日志文件。
func (s *AuditFileStore) purgeExpired() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -s.retention)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, auditLogFilePrefix) || !strings.HasSuffix(name, auditLogFileSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(s.dir, name))
		}
	}
}

// loadAuditLogsFromDisk 读取最近 limit 条日志，返回按时间升序排列的结果。
func loadAuditLogsFromDisk(dir string, limit int) (logs []AuditLog) {
	if dir == "" || limit <= 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, auditLogFilePrefix) || !strings.HasSuffix(name, auditLogFileSuffix) {
			continue
		}
		names = append(names, name)
	}
	// 文件名含日期与序号，字典序即时间序；从最新文件往回读。
	sort.Sort(sort.Reverse(sort.StringSlice(names)))

	collected := make([]AuditLog, 0, limit)
	for _, name := range names {
		part, err := readAuditFileTail(filepath.Join(dir, name), limit-len(collected))
		if err != nil {
			continue
		}
		// part 内部保持文件顺序（时间升序），倒序拼接后整体再排序。
		collected = append(part, collected...)
		if len(collected) >= limit {
			break
		}
	}

	if len(collected) > limit {
		collected = collected[len(collected)-limit:]
	}
	sort.SliceStable(collected, func(i, j int) bool {
		return collected[i].QueryTime.Before(collected[j].QueryTime)
	})
	return collected
}

// readAuditFileTail 读取单个文件最后 limit 条记录。
func readAuditFileTail(path string, limit int) ([]AuditLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ring := make([]AuditLog, 0, limit)
	scanner := bufio.NewScanner(f)
	// 单条日志可能较长（多答案），放宽缓冲。
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var log AuditLog
		if err := json.Unmarshal(line, &log); err != nil {
			continue
		}
		if len(ring) == limit {
			copy(ring, ring[1:])
			ring[len(ring)-1] = log
			continue
		}
		ring = append(ring, log)
	}
	return ring, scanner.Err()
}

// SeedLogs 用磁盘历史回填内存环形缓冲，仅在启动时调用一次。
func (c *AuditCollector) SeedLogs(history []AuditLog) {
	if len(history) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	capVal := int(c.capacity.Load())
	if capVal <= 0 {
		return
	}

	c.logs = c.logs[:0]
	c.head = 0

	start := 0
	if len(history) > capVal {
		start = len(history) - capVal
	}
	for _, log := range history[start:] {
		c.incrementStats(log)
		c.logs = append(c.logs, log)

		if c.slowestQueries.Len() < slowestQueriesCapacity {
			heap.Push(&c.slowestQueries, log)
		} else if log.DurationMs > c.slowestQueries[0].DurationMs {
			c.slowestQueries[0] = log
			heap.Fix(&c.slowestQueries, 0)
		}
	}
}
