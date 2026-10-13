// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package engine orchestration + scheduler + correlate/noisy-breaker/taint'tir (A-03/A-16/A-17/A-18).
package engine

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// Config tarama bayraklarının motor karşılığıdır (§14.1).
type Config struct {
	Safe                 bool
	Deep                 bool
	Active               bool
	HasAuth              bool
	Scope                []string
	MaxRequestsPerTarget int64
	MaxRequestsTotal     int64
	PluginTimeoutMs      int64
	RatePerSecond        float64
	Parallelism          int
	OOBServer            string
	NoisyThreshold       int
	StrictPlugins        bool
	ShowTentative        bool
	IgnorePlugins        map[string]bool
	Target               string
}

// DefaultConfig bayrak default'larıdır.
func DefaultConfig() Config {
	return Config{
		Safe:                 true,
		MaxRequestsPerTarget: 1000,
		MaxRequestsTotal:     10000,
		PluginTimeoutMs:      30000,
		RatePerSecond:        10,
		Parallelism:          8,
		NoisyThreshold:       10,
		IgnorePlugins:        make(map[string]bool),
	}
}

// Report tarama çıktısıdır (reporter girdisi).
type Report struct {
	Findings  []*finding.Finding
	Skipped   []plugin.SkippedPlugin
	Stats     map[string]int
	Target    string
	ScanID    string
	NoisyNote []string
}

// Engine scheduler + verify hattıdır.
type Engine struct {
	registry      *plugin.Registry
	cfg           Config
	trustDB       map[string]string
	trustPlatform map[string]string
}

// New motor kurar.
func New(reg *plugin.Registry, cfg Config) *Engine {
	if cfg.IgnorePlugins == nil {
		cfg.IgnorePlugins = make(map[string]bool)
	}
	return &Engine{
		registry:      reg,
		cfg:           cfg,
		trustDB:       make(map[string]string),
		trustPlatform: make(map[string]string),
	}
}

// Schedule politika filtresi + toposort uygular (B9/B10 burada skip'e dönüşür).
// Sessiz drop YOK — elenen her plugin skipped sebebiyle döner.
func (e *Engine) Schedule(_ context.Context) (ordered []plugin.PluginSpec, skipped []plugin.SkippedPlugin, err error) {
	specs := e.registry.Specs()
	// Ignore-listesi.
	var kept []plugin.PluginSpec
	for _, s := range specs {
		if e.cfg.IgnorePlugins[s.ID] {
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: s.ID, Reason: "skipped (ignored via --ignore-plugin)"})
			continue
		}
		kept = append(kept, s)
	}
	// Politika filtresi.
	var runnable []plugin.PluginSpec
	for _, s := range kept {
		if reason, ok := e.filterReason(s); !ok {
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: s.ID, Reason: reason})
			continue
		}
		runnable = append(runnable, s)
	}
	ordered, err = plugin.SortByPhase(runnable)
	if err != nil {
		return nil, skipped, fmt.Errorf("engine schedule: %w", err)
	}
	return ordered, skipped, nil
}

// filterReason returns the scheduler skip reason for one plugin spec.
// What: Single gate for active/deep/auth/OOB/trust requirements.
// Why: One consistent English "skipped (...)" format keeps reports auditable.
func (e *Engine) filterReason(s plugin.PluginSpec) (string, bool) {
	// Active plugins need explicit opt-in via --active.
	if s.Active && !e.cfg.Active {
		return "skipped (requires --active)", false
	}
	if s.Deep && !e.cfg.Deep {
		return "skipped (requires --deep)", false
	}
	if s.RequiresAuth && !e.cfg.HasAuth {
		return "skipped (requires auth)", false
	}
	// OOB discipline (R-OOB-01/02, B9).
	if s.OOB == plugin.OOBRequired && e.cfg.OOBServer == "" {
		return "skipped (oob-not-configured, requires --oob-server)", false
	}
	// Tier3 trust (B10).
	if s.Tier == plugin.TierNative {
		pinned, ok := e.trustDB[s.ID]
		if !ok || pinned == "" {
			return "skipped (tier3-untrusted, requires trust via `gash plugins trust`)", false
		}
		if p := e.trustPlatform[s.ID]; p != "" && p != loader.AnyPlatform && p != loader.CurrentPlatform() {
			return fmt.Sprintf("skipped (tier3-platform-mismatch trusted=%s host=%s)", p, loader.CurrentPlatform()), false
		}
		if e.cfg.StrictPlugins && !ok {
			return "skipped (requires trust for --strict-plugins)", false
		}
	}
	return "", true
}

// SetTrust digest-only trust kapısıdır (platform kısıtı yok).
func (e *Engine) SetTrust(id, sha string) {
	e.trustDB[id] = sha
	e.trustPlatform[id] = loader.AnyPlatform
}

// SetTrustRecord digest + platform pini yazar (Faz 4: platform duyarlı onay).
// What: Records which platform an approval was granted for.
// Why: A digest proven on one host must not authorize a rebuild on another.
func (e *Engine) SetTrustRecord(id, sha, platform string) {
	if platform == "" {
		platform = loader.AnyPlatform
	}
	e.trustDB[id] = sha
	e.trustPlatform[id] = platform
}

// TrustedPlatform returns the platform pin of a Tier 3 approval.
func (e *Engine) TrustedPlatform(id string) string { return e.trustPlatform[id] }

// Run executes scheduled plugins against the target with live probing.
// What: Validated target plus scheduled execution plus correlated findings.
// Why: Empty registries still return a valid empty report while live targets
// get deterministic Tier1/Tier2/Tier3 verification through one pipeline.
func (e *Engine) Run(ctx context.Context, target string) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("engine run ctx: %w", err)
	}
	normalized, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	ordered, skipped, err := e.Schedule(ctx)
	if err != nil {
		return nil, err
	}
	if len(ordered) == 0 {
		rep := &Report{
			Target:   normalized,
			Findings: []*finding.Finding{},
			Stats:    map[string]int{"scheduled": 0, "skipped": len(skipped), "findings": 0, "errors": 0},
			Skipped:  skipped,
			ScanID:   newScanID(),
		}
		if rep.Skipped == nil {
			rep.Skipped = []plugin.SkippedPlugin{}
		}
		// B2: empty registry yields a valid empty report, not an error.
		return rep, nil
	}
	return e.runLive(ctx, normalized, ordered, skipped)
}

// Correlate motor-tarafı dedup uygular (A-16).
func Correlate(in []*finding.Finding) []*finding.Finding {
	return finding.Dedup(in)
}

// NoisyBreaker aynı Evidence hash'iyle N>threshold aday üreteni demote eder (A-17).
// Girdi: fingerprint → sayı. Eşik aşımı varsa demoted id'ler + not döner.
func NoisyBreaker(counts map[string]int, threshold int) (demoted []string, note string) {
	if threshold <= 0 {
		threshold = 10
	}
	for fp, n := range counts {
		if n > threshold {
			demoted = append(demoted, fp)
		}
	}
	sort.Strings(demoted)
	if len(demoted) > 0 {
		note = fmt.Sprintf("noisy plugin: %d fingerprint eşik (%d) aştı", len(demoted), threshold)
	}
	return demoted, note
}

// TaintStore scan-içi taint etiketleridir (A-18, TTL=scan).
type TaintStore struct {
	mu    sync.RWMutex
	marks map[string]string // evidence_ref → plugin id
}

// NewTaintStore boş store.
func NewTaintStore() *TaintStore { return &TaintStore{marks: make(map[string]string)} }

// Mark iz bırakır.
func (t *TaintStore) Mark(ref, pluginID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.marks[ref] = pluginID
}

// TaintedBy referansın kirli mi + kimin tarafından.
func (t *TaintStore) TaintedBy(ref string) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	v, ok := t.marks[ref]
	return v, ok
}

// IsTainted başka plugin'in kanıtı olarak kullanılamaz (oracle guard tamamlayıcısı).
func (t *TaintStore) IsTainted(ref, requester string) bool {
	by, ok := t.TaintedBy(ref)
	if !ok {
		return false
	}
	return by != "" // kendi taint'ini kanıt saymak da yasak (self-confirm engeli) → her taint ret
}
