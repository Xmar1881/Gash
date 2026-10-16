// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package engine orchestration + scheduler + correlate/noisy-breaker/taint'tir (A-03/A-16/A-17/A-18).
package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Xmar1881/Gash/internal/auth"
	"github.com/Xmar1881/Gash/internal/config"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// Config tarama bayraklarının motor karşılığıdır (§14.1).
type Config struct {
	Safe    bool
	Deep    bool
	Active  bool
	HasAuth bool
	// Auth kimlik doğrulama bağlamıdır (P2.5). Nil-güvenlidir; HasAuth buradan türetilir.
	Auth *auth.Context
	// AuthA/AuthB çift-kullanıcı BOLA matrisi bağlamlarıdır (--auth-user-a/b).
	// Nil-güvenlidir; yalnızca ikisi de doluyken ve --active varken matris koşar.
	AuthA *auth.Context
	AuthB *auth.Context
	// Technologies bilinen/tespit edilen teknolojiler (P2.3 chain kapısı, örn. "wordpress").
	Technologies []string
	// TCPBanners açık TCP banner probları "host:port" (P2.1, --active şart).
	TCPBanners           []string
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
	MaxPages             int    // Maximum pages to crawl (default 50)
	Depth                int    // Maximum crawl depth (default 3)
	ProxyURL             string // Upstream HTTP proxy URL (e.g. http://127.0.0.1:8080)
	// OpenAPISpec --openapi-spec karşılığıdır (dosya yolu veya http(s) URL).
	// Doluysa ParseSpec endpoint+parametreleri hedef bazında surfacePoints'e
	// eklenir; URL ise yalnızca kapsam-içi/loopback çekilir (fail-closed).
	OpenAPISpec string

	// P1.2: Scan profile (Safe/Standard/Deep)
	Profile config.ProfileName
	// P1.2: Custom profile override (from config file)
	CustomProfile *config.Profile
	// P1.2: Effective detectors enabled by profile (populated at runtime)
	enabledDetectors map[string]bool
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
		MaxPages:             50,
		Depth:                3,
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
	// detectedTech çalışma-anı pasif parmak izidir (header/favicon/cookie/known-path).
	// Run öncesi tek GET ile dolar; knownTechSet ile birleşir.
	detectedTech map[string]bool
	// detectedCaps çalışma-anı yetenek kümesidir (login-form, graphql-endpoint, ...).
	// ResolveChain Capabilities girdisini besler.
	detectedCaps map[string]bool
	// sharedPolicy is an optional shared PolicySession used across multi-target bulk scans.
	sharedPolicy *plugin.PolicySession
}

// New motor kurar.
func New(reg *plugin.Registry, cfg Config) *Engine {
	if cfg.IgnorePlugins == nil {
		cfg.IgnorePlugins = make(map[string]bool)
	}
	// P2.5: kimlik bağlamı requires_auth kapısını açar (açık bayrak da korunur).
	if cfg.Auth != nil && cfg.Auth.HasAuth() {
		cfg.HasAuth = true
	}
	// Initialize profile-based detector enablement
	e := &Engine{
		registry:      reg,
		cfg:           cfg,
		trustDB:       make(map[string]string),
		trustPlatform: make(map[string]string),
	}
	e.cfg.enabledDetectors = e.resolveEnabledDetectors()
	return e
}

// detectorEnabled profil dedektör kapısıdır (proto recon + raporlama kullanır).
func (e *Engine) detectorEnabled(name string) bool {
	return e.cfg.enabledDetectors[strings.ToLower(name)]
}

// HasDualAuth iki farklı kullanıcı bağlamı tanımlı mı (BOLA matris kapısı).
func (e *Engine) HasDualAuth() bool {
	return e.cfg.AuthA != nil && e.cfg.AuthA.HasAuth() &&
		e.cfg.AuthB != nil && e.cfg.AuthB.HasAuth()
}

// knownTechSet chain teknoloji kapısının kümesidir (P2.3).
// What: Kullanıcı --tech bayrağı + çalışma-anı pasif parmak izi birleşimi.
// Why: Bildirilmemiş teknoloji (örn. yanıtta wp-json) ilgili dedektörü
// otomatik açar; yanlış teknoloji hiçbir şeyi sessizce kapatmaz (skip izi).
func (e *Engine) knownTechSet() map[string]bool {
	merged := plugin.NormalizeTech(e.cfg.Technologies)
	for k := range e.detectedTech {
		merged[strings.ToLower(strings.TrimSpace(k))] = true
	}
	return merged
}

// capabilitySet chain sağlayıcı kümesinin çalışma-anı girdisidir.
// What: Pasif yetenekler (login-form, graphql-endpoint, ...) + boş-güvenli.
// Why: requires/provides zinciri statik değil; sayfada form/graphQL
// görülmesi ilgili tüketiciyi koşulabilir kılar.
func (e *Engine) capabilitySet() map[string]bool {
	out := make(map[string]bool, len(e.detectedCaps))
	for k, v := range e.detectedCaps {
		if v {
			out[strings.ToLower(strings.TrimSpace(k))] = true
		}
	}
	return out
}

// resolveEnabledDetectors computes the effective detector set from profile.
func (e *Engine) resolveEnabledDetectors() map[string]bool {
	detectors := make(map[string]bool)
	var profile *config.Profile

	if e.cfg.CustomProfile != nil {
		profile = e.cfg.CustomProfile
	} else if e.cfg.Profile != "" {
		profile = config.GetProfile(e.cfg.Profile)
	} else {
		// Default to Standard profile
		profile = config.GetProfile(config.ProfileStandard)
	}

	if profile != nil {
		for _, d := range profile.ActiveDetectors {
			detectors[d] = true
		}
	}
	return detectors
}

// EffectiveProfile returns the resolved profile for reporting.
func (e *Engine) EffectiveProfile() *config.Profile {
	if e.cfg.CustomProfile != nil {
		return e.cfg.CustomProfile
	}
	if e.cfg.Profile != "" {
		return config.GetProfile(e.cfg.Profile)
	}
	return config.GetProfile(config.ProfileStandard)
}

// Schedule politika filtresi + zincir + toposort uygular (B9/B10 burada skip'e dönüşür).
// Sessiz drop YOK — elenen her plugin skipped sebebiyle döner.
// Sıra: ignore → politika → chain (teknoloji + sağlayıcı) → faz sıralaması.
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
	// P2.3: koşullu zincir (teknoloji kapısı + sağlayıcısız requires → skip, fail-open).
	chainRes, err := plugin.ResolveChain(plugin.ChainInput{
		Specs:        runnable,
		KnownTech:    e.knownTechSet(),
		Capabilities: e.capabilitySet(),
	})
	if err != nil {
		return nil, skipped, fmt.Errorf("engine schedule: %w", err)
	}
	skipped = append(skipped, chainRes.Skipped...)
	ordered, err = plugin.SortByPhase(chainRes.Runnable)
	if err != nil {
		return nil, skipped, fmt.Errorf("engine schedule: %w", err)
	}
	return ordered, skipped, nil
}

// filterReason returns the scheduler skip reason for one plugin spec.
// What: Single gate for active/deep/auth/OOB/trust/profile requirements.
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
	// P1.2: Profile-based detector enablement check (after explicit flags)
	// Exception: if plugin explicitly requires OOB and OOB server is configured, allow it.
	if oracle := e.oracleForPlugin(s); oracle != "" {
		if oracle == "oob" && s.OOB == plugin.OOBRequired && e.cfg.OOBServer != "" {
			// Explicit OOB configuration overrides profile
		} else if !e.cfg.enabledDetectors[oracle] {
			return fmt.Sprintf("skipped (detector %s disabled by profile %s)", oracle, e.EffectiveProfile().Name), false
		}
	}
	return "", true
}

// oracleForPlugin returns the oracle name a plugin uses.
// What: Maps plugin spec to oracle for profile-based filtering.
// Why: Profile enables/disables detectors (oracles), not plugins directly.
func (e *Engine) oracleForPlugin(s plugin.PluginSpec) string {
	// For Tier1 YAML plugins, the oracle is defined in the plugin file.
	// We can't easily read it here without loading the file.
	// Instead, we infer from plugin ID patterns and tags.
	// This is a heuristic; Tier2/3 plugins declare oracle in code.

	// Check if plugin has explicit oracle tag
	for _, tag := range s.Tags {
		switch tag {
		case "header", "redirect", "reflection", "error", "differential", "timing", "execution", "oob", "cookie", "cors", "version", "tls", "dns", "tcp":
			return tag
		}
	}

	// Fallback: infer from plugin ID
	id := strings.ToLower(s.ID)
	switch {
	case strings.Contains(id, "tls") || strings.Contains(id, "cert"):
		return "tls"
	case strings.Contains(id, "dns") || strings.Contains(id, "spf") || strings.Contains(id, "dmarc"):
		return "dns"
	case strings.Contains(id, "banner") || strings.HasPrefix(id, "tcp"):
		return "tcp"
	case strings.Contains(id, "redirect"):
		return "redirect"
	case strings.Contains(id, "time"):
		return "timing"
	case strings.Contains(id, "oob"):
		return "oob"
	case strings.Contains(id, "differential") || strings.Contains(id, "bool"):
		return "differential"
	case strings.Contains(id, "xss") || strings.Contains(id, "reflection") || strings.Contains(id, "ssti") || strings.Contains(id, "template"):
		return "reflection"
	case strings.Contains(id, "sqli") || strings.Contains(id, "sql") || strings.Contains(id, "command"):
		return "error"
	case strings.Contains(id, "dom"):
		return "execution"
	case strings.Contains(id, "ssrf"):
		return "oob"
	case strings.Contains(id, "cookie"):
		return "cookie"
	case strings.Contains(id, "cors"):
		return "cors"
	case strings.Contains(id, "version"):
		return "version"
	}
	return ""
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

// SetSharedPolicy attaches a shared policy session (for multi-target bulk scans).
func (e *Engine) SetSharedPolicy(p *plugin.PolicySession) {
	e.sharedPolicy = p
}

// SharedPolicy returns the configured shared policy session, if any.
func (e *Engine) SharedPolicy() *plugin.PolicySession {
	return e.sharedPolicy
}

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
	// Çalışma-anı teknoloji tespiti: tek pasif GET ile zincir girdisi.
	// Hata = boş küme (kullanıcı --tech tek başına yeterli); ek trafik yok.
	e.detectRuntimeTech(ctx, normalized)
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
