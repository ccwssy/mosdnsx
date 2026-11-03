/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package hosts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/hosts"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
)

const PluginType = "hosts"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ sequence.Executable = (*Hosts)(nil)

type Args struct {
	Entries []string `yaml:"entries"`
	Files   []string `yaml:"files"`
}

type Hosts struct {
	// mu 保护 h 与 rules：在线编辑会整体重建 matcher，查询侧同时读取。
	mu       sync.RWMutex
	h        *hosts.Hosts
	rules    []string // 文件里的可编辑规则（原始行，不含注释与空行）
	ruleFile string   // 写回目标：args.files[0]
}

func Init(bp *coremain.BP, args any) (any, error) {
	a := args.(*Args)
	h, err := NewHosts(a)
	if err != nil {
		return nil, err
	}
	if len(a.Files) > 0 {
		h.ruleFile = a.Files[0]
	}
	// 保留文件原始行，供 /show 与在线编辑使用（entries 属配置内联项，不在面板编辑范围）。
	for _, f := range a.Files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			h.rules = append(h.rules, line)
		}
	}
	bp.RegAPI(h.api())
	return h, nil
}

func NewHosts(args *Args) (*Hosts, error) {
	m := domain.NewMixMatcher[*hosts.IPs]()
	m.SetDefaultMatcher(domain.MatcherFull)
	for i, entry := range args.Entries {
		if err := domain.Load[*hosts.IPs](m, entry, hosts.ParseIPs); err != nil {
			return nil, fmt.Errorf("failed to load entry #%d %s, %w", i, entry, err)
		}
	}
	for i, file := range args.Files {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read file #%d %s, %w", i, file, err)
		}
		if err := domain.LoadFromTextReader[*hosts.IPs](m, bytes.NewReader(b), hosts.ParseIPs); err != nil {
			return nil, fmt.Errorf("failed to load file #%d %s, %w", i, file, err)
		}
	}

	return &Hosts{
		h: hosts.NewHosts(m),
	}, nil
}

func (h *Hosts) Response(q *dns.Msg) *dns.Msg {
	h.mu.RLock()
	hh := h.h
	h.mu.RUnlock()
	return hh.LookupMsg(q)
}

func (h *Hosts) Exec(_ context.Context, qCtx *query_context.Context) error {
	h.mu.RLock()
	r := h.h.LookupMsg(qCtx.Q())
	h.mu.RUnlock()
	if r != nil {
		qCtx.SetResponse(r)
	}
	return nil
}

// rebuild 用新规则整体重建 matcher，构建成功后才替换，避免半成品对外可见。
func (h *Hosts) rebuild(lines []string) error {
	m := domain.NewMixMatcher[*hosts.IPs]()
	m.SetDefaultMatcher(domain.MatcherFull)
	for _, line := range lines {
		if err := domain.Load[*hosts.IPs](m, line, hosts.ParseIPs); err != nil {
			return fmt.Errorf("invalid rule %q: %w", line, err)
		}
	}
	nh := hosts.NewHosts(m)
	h.mu.Lock()
	h.h = nh
	h.rules = append([]string(nil), lines...)
	h.mu.Unlock()
	return nil
}

type hostsPayload struct {
	Values []string `json:"values"`
}

// api 提供与 domain_set 一致的 /show /save /post /flush，供面板「名单管理」在线编辑。
func (h *Hosts) api() *chi.Mux {
	r := chi.NewRouter()

	r.Get("/show", func(w http.ResponseWriter, _ *http.Request) {
		h.mu.RLock()
		defer h.mu.RUnlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, rule := range h.rules {
			fmt.Fprintln(w, rule)
		}
	})

	r.Get("/save", func(w http.ResponseWriter, _ *http.Request) {
		h.mu.RLock()
		rules := append([]string(nil), h.rules...)
		path := h.ruleFile
		h.mu.RUnlock()
		if err := writeHostsFile(path, rules); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	r.Post("/post", func(w http.ResponseWriter, req *http.Request) {
		var p hostsPayload
		if err := json.NewDecoder(req.Body).Decode(&p); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		h.mu.RLock()
		path := h.ruleFile
		h.mu.RUnlock()
		if path == "" || !strings.EqualFold(extOf(path), ".txt") {
			http.Error(w, "no txt file configured, cannot post", http.StatusBadRequest)
			return
		}
		if err := h.rebuild(p.Values); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := writeHostsFile(path, p.Values); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	r.Post("/flush", func(w http.ResponseWriter, _ *http.Request) {
		h.mu.RLock()
		path := h.ruleFile
		h.mu.RUnlock()
		if err := h.rebuild(nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if path != "" {
			if err := writeHostsFile(path, nil); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	})

	return r
}

func writeHostsFile(path string, rules []string) error {
	if path == "" {
		return fmt.Errorf("no file configured")
	}
	var b strings.Builder
	for _, r := range rules {
		b.WriteString(r)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func extOf(p string) string {
	if i := strings.LastIndexByte(p, '.'); i >= 0 {
		return p[i:]
	}
	return ""
}
