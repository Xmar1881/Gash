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
	"github.com/Xmar1881/Gash/internal/detector"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/headless"
	"github.com/Xmar1881/Gash/internal/oob"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/proto"

	"time"
)

// Config tarama bayraklarının motor karşılığıdır (§14.1).
type Config struct {
	Safe    bool
	Deep    bool
	Active  bool
	HasAuth bool
	// Auth kimlik doğrulama bağlamıdır (P2.5). Nil-güvenlidir; HasAuth buradan türetilir.
	Auth *auth.Context
	// Login kullanıcı-beyanlı oturum kurulumudur (P2.6). Nil-güvenli.
	// Başarılıysa kurulan oturum Auth bağlamına AD bazında birleşir (açık
	// --auth-header/--cookie kazanır) ve requires_auth kapısı açılır.
	Login *auth.LoginOptions
	// AuthA/AuthB çift-kullanıcı BOLA matrisi bağlamlarıdır (--auth-user-a/b).
	// Nil-güvenlidir; yalnızca ikisi de doluyken ve --active varken matris koşar.
	AuthA *auth.Context
	AuthB *auth.Context
	// Technologies bilinen/tespit edilen teknolojiler (P2.3 chain kapısı, örn. "wordpress").
	Technologies []string
	// TCPBanners açık TCP banner probları "host:port" (P2.1, --active şart).
	TCPBanners []string
	// Scope explicit --scope allowlist'idir. Boşsa open mod: yazılımsal host
	// engeli yok (redirect/crawl takibi serbest, operatör sorumluluğu).
	Scope                []string
	MaxRequestsPerTarget int64
	MaxRequestsTotal     int64
	PluginTimeoutMs      int64
	RatePerSecond        float64
	Parallelism          int
	OOBServer            string
	// OOBToken authenticates a self-hosted interactsh server (optional).
	OOBToken string
	// BrowserVerify enables the generic controlled browser-verify pass for
	// static-execution-evidence XSS findings (needs a -tags deep build plus a
	// Chrome binary; the CLI gates it behind --active). Off by default.
	BrowserVerify bool
	// BrowserVerifyFunc is a test seam; nil uses the real headless verifier.
	BrowserVerifyFunc func(ctx context.Context, payloadURL, controlURL string) (triggered, controlClean bool, err error)
	// BrowserCrawl enables bounded SPA surface discovery: selected crawl pages
	// are rendered in headless Chrome and their DOM forms/links plus observed
	// XHR/fetch endpoints enter the scan surface. Needs a -tags deep build plus
	// a Chrome binary; GET-only and off by default.
	BrowserCrawl bool
	// BrowserCrawlPages caps rendered pages (default 5, hard cap 10).
	BrowserCrawlPages int
	// BrowserCrawlFunc is a test seam; nil uses the real headless renderer.
	BrowserCrawlFunc func(ctx context.Context, pageURL string, opts headless.RenderOptions) (headless.RenderedPage, error)
	NoisyThreshold   int
	StrictPlugins    bool
	ShowTentative    bool
	IgnorePlugins    map[string]bool
	// OnlyPlugins, when non-empty, restricts scheduling to these plugin IDs.
	// It is an explicit positive selection, so unselected plugins are omitted
	// from the schedule without generating a skipped entry.
	OnlyPlugins map[string]bool
	Target      string
	MaxPages    int    // Maximum pages to crawl (default 50)
	Depth       int    // Maximum crawl depth (default 3)
	ProxyURL    string // Upstream HTTP proxy URL (e.g. http://127.0.0.1:8080)
	// ProxyURLs is a rotating proxy pool (from --proxy/--proxy-file). Empty
	// means direct traffic. The pool rotates on timeouts and block statuses.
	ProxyURLs []string
	// ProxyRotate selects per-host (default) or per-request rotation.
	ProxyRotate string
	// ProxyCooldown skips a failing proxy for this long (0 = pool default).
	ProxyCooldown time.Duration
	// ProxyAttemptTimeout bounds one proxy attempt when the pool has more than
	// one member, so a dead proxy cannot consume the whole request timeout.
	ProxyAttemptTimeout time.Duration
	// RequestTimeout per-HTTP-request timeout (default 15s).
	RequestTimeout time.Duration
	// ScanTimeout bounds the complete engine run, including discovery and
	// plugin scheduling (default 10m). Per-request and per-plugin timeouts do
	// not replace this outer deadline.
	ScanTimeout time.Duration
	// CrawlTimeout bounds the BFS discovery phase so a dead proxy pool cannot
	// spend the whole scan deadline before plugins run (0 = 5m).
	CrawlTimeout time.Duration
	// SkipTLSFailFast disables the HTTPS certificate preflight abort. It is a
	// test seam for self-signed fixture servers; production scans keep the
	// fail-closed default.
	SkipTLSFailFast bool
	// MaxResponseBytes caps stored response bodies (default 5MB).
	MaxResponseBytes int64
	// OpenAPISpec --openapi-spec karşılığıdır (dosya yolu veya http(s) URL).
	// Doluysa ParseSpec endpoint+parametreleri hedef bazında surfacePoints'e
	// eklenir; URL ise yalnızca kapsam-içi/loopback çekilir (fail-closed).
	OpenAPISpec string
	// FlowSeed --flow-seed karşılığıdır: çok-adımlı akış keşfinin başlangıç
	// URL'i. Yalnızca --active ile ve açıkça verildiğinde koşar.
	FlowSeed string
	// FlowMaxSteps akış keşfi adım tavanıdır (varsayılan 4, kesin tavan 6).
	FlowMaxSteps int
	// FlowProbes adım başına SQLi probu sayısıdır (varsayılan 6, tavan 10).
	FlowProbes int

	// Faz 0 altyapı gözlemleri (engine-recon; plugin değildir):
	// SSHAudit --ssh-audit karşılığıdır (SSH banner; --active şart).
	SSHAudit bool
	// DBPortScan --db-port-scan karşılığıdır (salt-okuma port/selamlama; --active şart).
	DBPortScan bool
	// DBPorts taranacak port listesidir (boşsa yaygın DB portları).
	DBPorts []int
	// TLSAuditDeep --tls-audit-deep karşılığıdır (eski TLS sürüm kabul gözlemi).
	TLSAuditDeep bool
	// SSHHandshakeAudit --ssh-handshake-audit karşılığıdır: sürüm değişimi +
	// KEXINIT algoritma listesi gözlemi (GASH-054). --active + ssh dedektörü
	// şart; anahtar değişimi tamamlanmaz, kimlik doğrulama yapılmaz.
	SSHHandshakeAudit bool
	// DBUnauth --db-unauth karşılığıdır: sabit dummy kimlikle tek zararsız
	// istek üzerinden kimlik doğrulamasız erişim gözlemi (GASH-055).
	// --active + db dedektörü şart; veri okuma/komut/parola denemesi yok.
	DBUnauth bool
	// InfraTargets explicit host:port altyapı hedefleridir; boşsa hedef host.
	InfraTargets []string
	// MaxInfraPorts tek taramada en fazla port sayısıdır (varsayılan 20).
	MaxInfraPorts int
	// InfraTimeout altyapı dial/gözlem zaman aşımıdır (varsayılan 5s).
	InfraTimeout time.Duration
	// InfraRatePerSecond altyapı işlem tavanıdır (<=0 sınırsız; test dostu).
	InfraRatePerSecond float64
	// InfraParallelism altyapı eşzamanlılık tavanıdır (varsayılan 4).
	InfraParallelism int

	// P1.2: Scan profile (Safe/Standard/Deep)
	Profile config.ProfileName
	// P1.2: Custom profile override (from config file)
	CustomProfile *config.Profile
	// P1.2: Effective detectors enabled by profile (populated at runtime)
	enabledDetectors map[string]bool
	// OnProgress receives stable phase/detail keys plus formatting args while
	// the engine advances. Display text is owned by the CLI/menu translator;
	// the engine never hardcodes user-visible progress strings.
	OnProgress func(phaseKey, detailKey string, args ...any)
}

// DefaultConfig bayrak default'larıdır.
func DefaultConfig() Config {
	return Config{
		Safe:                 true,
		MaxRequestsPerTarget: 1000,
		MaxRequestsTotal:     10000,
		PluginTimeoutMs:      60000,
		RatePerSecond:        10,
		Parallelism:          8,
		NoisyThreshold:       10,
		IgnorePlugins:        make(map[string]bool),
		MaxPages:             50,
		Depth:                3,
		RequestTimeout:       20 * time.Second,
		ScanTimeout:          10 * time.Minute,
		CrawlTimeout:         5 * time.Minute,
		MaxResponseBytes:     5 * 1024 * 1024,
		ProxyRotate:          "per-host",
		ProxyCooldown:        30 * time.Second,
		DBPorts:              proto.DefaultDBPorts(),
		MaxInfraPorts:        20,
		InfraTimeout:         5 * time.Second,
		InfraRatePerSecond:   5,
		InfraParallelism:     4,
		FlowMaxSteps:         4,
		FlowProbes:           6,
		BrowserCrawlPages:    spaDefaultPages,
	}
}

func (e *Engine) effectiveScanTimeout() time.Duration {
	if e.cfg.ScanTimeout > 0 {
		return e.cfg.ScanTimeout
	}
	return 10 * time.Minute
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
	// detectors holds the engine-owned detector registry (raw sockets, byte
	// analysis over crawler output, wordlist probing). It is the single
	// enumerable list of scan units that cannot be YAML or JS plugins.
	detectors *detector.Registry
	// passiveCache coalesces identical static GET/HEAD responses within one
	// Run. It is reset per target and only serves read-only Tier 1 oracles.
	passiveCache *passiveResponseCache
	// oobOnce caches the OOB provider so interactsh registers one session per
	// scan instead of once per detector/plugin.
	oobOnce    sync.Once
	oobProv    oob.Provider
	oobProvErr error
	// runMu serializes Run on one Engine. Run swaps per-target runtime state
	// (auth clone, detected tech/caps), so concurrent calls would otherwise
	// race even though the transport/policy themselves are concurrency-safe.
	runMu sync.Mutex
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
	e.detectors = newDetectorRegistry()
	return e
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
	if len(e.cfg.OnlyPlugins) > 0 {
		var unknown []string
		for id := range e.cfg.OnlyPlugins {
			if _, ok := e.registry.Get(id); !ok {
				unknown = append(unknown, id)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return nil, skipped, fmt.Errorf("engine schedule: unknown --only-plugin ID(s): %s", strings.Join(unknown, ", "))
		}
	}
	// Ignore-listesi.
	var kept []plugin.PluginSpec
	for _, s := range specs {
		if e.cfg.IgnorePlugins[s.ID] {
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: s.ID, Reason: "skipped (ignored via --ignore-plugin)"})
			continue
		}
		// Positive selection is explicit: unselected plugins are not skips.
		if len(e.cfg.OnlyPlugins) > 0 && !e.cfg.OnlyPlugins[s.ID] {
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
			return fmt.Sprintf("skipped (oracle %q disabled by profile %s)", oracle, e.EffectiveProfile().Name), false
		}
	}
	return "", true
}

// oracleForPlugin returns the oracle name a plugin uses.
// What: Maps plugin spec to oracle for profile-based filtering.
// Why: Profile enables/disables detectors (oracles), not plugins directly.
func (e *Engine) oracleForPlugin(s plugin.PluginSpec) string {
	// Discovery records the pinned oracle, so product tags (e.g. "adminer")
	// cannot hide a profile-disabled detector behind the heuristic below.
	if e.registry != nil {
		if entry, ok := e.registry.Get(s.ID); ok && entry.OracleName != "" {
			return entry.OracleName
		}
	}
	// For Tier1 YAML plugins, the oracle is defined in the plugin file.
	// We can't easily read it here without loading the file.
	// Instead, we infer from plugin ID patterns and tags.
	// This is a heuristic; Tier2/3 plugins declare oracle in code.

	// Check if plugin has explicit oracle tag
	for _, tag := range s.Tags {
		switch tag {
		case "header", "redirect", "reflection", "error", "differential", "timing", "execution", "oob", "cookie", "cors", "version", "tls", "dns", "tcp", "verb-tamper":
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
func (e *Engine) notifyProgress(phaseKey, detailKey string, args ...any) {
	if e.cfg.OnProgress != nil {
		e.cfg.OnProgress(phaseKey, detailKey, args...)
	}
}

// What: Validated target plus scheduled execution plus correlated findings.
// Why: Empty registries still return a valid empty report while live targets
// get deterministic Tier1/Tier2/Tier3 verification through one pipeline.
// P2.6 sırası: istemci kur → login → teknoloji tespiti → schedule → koşum.
func (e *Engine) Run(ctx context.Context, target string) (*Report, error) {
	e.runMu.Lock()
	defer e.runMu.Unlock()

	// Each Run gets a fresh passive cache: bulk scans reuse one Engine across
	// hosts, and a response authenticated for target A must never answer B.
	e.passiveCache = newPassiveResponseCache(60*time.Second, 512, 32<<20)

	// Bulk scans reuse one Engine across targets. Login merges new cookies into
	// cfg.Auth, so clone the declared context for this run and restore it after:
	// a session established for target A must never authenticate target B.
	baseAuth, baseHasAuth := e.cfg.Auth, e.cfg.HasAuth
	if baseAuth != nil {
		e.cfg.Auth = baseAuth.Clone()
	}
	defer func() {
		e.cfg.Auth = baseAuth
		e.cfg.HasAuth = baseHasAuth
	}()

	e.notifyProgress(progressPhaseStarting, progressDetailStartingPrepare)
	scanCtx, cancel := context.WithTimeout(ctx, e.effectiveScanTimeout())
	defer cancel()
	if err := scanCtx.Err(); err != nil {
		return nil, fmt.Errorf("engine run ctx: %w", err)
	}
	normalized, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	// P2.6: tarama istemcisi tek kez kurulur; login de bu hattan geçer.
	policy, client, err := e.newScanClient(normalized)
	if err != nil {
		return nil, err
	}
	e.notifyProgress(progressPhaseStarting, progressDetailStartingReady)
	if e.cfg.Login != nil {
		e.notifyProgress(progressPhaseLogin, progressDetailLoginStart)
	}
	login, err := e.runLogin(scanCtx, client)
	if err != nil {
		// Kapsam/politika ihlali: fail-closed, tarama başlamaz.
		return nil, err
	}
	if e.cfg.Login != nil {
		detailKey := progressDetailLoginOK
		if login.succeeded == 0 {
			detailKey = progressDetailLoginFail
		}
		e.notifyProgress(progressPhaseLogin, detailKey,
			login.attempted, login.succeeded, login.cookies)
	}
	if login.succeeded == 1 && login.auth != nil {
		// Açık kimlik beyanı login türevinin üzerindedir (ad bazında).
		if e.cfg.Auth == nil {
			e.cfg.Auth = auth.New()
		}
		e.cfg.Auth.MergeMissing(login.auth)
		e.cfg.HasAuth = true
		client.SetExtraHeaders(e.cfg.Auth.HeaderMap())
	}
	// Çalışma-anı teknoloji tespiti: tek pasif GET ile zincir girdisi.
	// Aynı GET hedef ön kontrolüdür: taşıma/kapsam hatası, yüzlerce plugin'i
	// erişilemeyen hedefe karşı zamanlamak yerine Run'ı erken durdurur.
	e.notifyProgress(progressPhaseTech, progressDetailTechStart)
	preflightErr := e.detectRuntimeTech(scanCtx, normalized, client)
	e.notifyProgress(progressPhaseTech, progressDetailTechDone,
		len(e.detectedTech), len(e.detectedCaps))
	e.notifyProgress(progressPhasePlanning, progressDetailPlanStart)
	ordered, skipped, err := e.Schedule(scanCtx)
	if err != nil {
		return nil, err
	}
	// Login skip izi en başta raporlanır (başarısızlık sessiz kalmaz).
	skipped = append(append([]plugin.SkippedPlugin{}, login.skipped...), skipped...)
	e.notifyProgress(progressPhasePlanning, progressDetailPlanDone,
		len(ordered), len(skipped))
	if len(ordered) == 0 {
		rep := &Report{
			Target:   normalized,
			Findings: []*finding.Finding{},
			Stats: map[string]int{
				"scheduled": 0, "skipped": len(skipped), "partial_plugins": 0,
				"findings": 0, "errors": 0,
				"plugin_selection":  len(e.cfg.OnlyPlugins),
				"plugin_exclusions": len(e.cfg.IgnorePlugins),
				"login_attempted":   login.attempted,
				"login_succeeded":   login.succeeded,
				"login_cookies":     login.cookies,
			},
			Skipped: skipped,
			ScanID:  newScanID(),
		}
		if rep.Skipped == nil {
			rep.Skipped = []plugin.SkippedPlugin{}
		}
		// B2: empty registry yields a valid empty report, not an error.
		return rep, nil
	}
	// Ön kontrol yalnızca koşacak plugin varken bağlayıcıdır: her şey kapıda
	// elendiyse boş rapor dürüst sonuçtur, hedef erişimi anlamsızdır.
	// TLS sertifika hataları runLive'a taşınır: oradaki fail-closed karar
	// SkipTLSFailFast dikişini korur ve ikinci bir ön-uçuş isteği gerekmez.
	if preflightErr != nil && !isTLSCertError(preflightErr) {
		return nil, fmt.Errorf("target preflight failed for %s: %w (check reachability, scope, proxy pool, and request budget; use --no-proxy for direct traffic)", normalized, preflightErr)
	}
	return e.runLive(scanCtx, normalized, ordered, skipped, policy, client, login, preflightErr)
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
