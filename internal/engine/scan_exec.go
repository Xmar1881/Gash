// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/config"
	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/oob"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
	"github.com/Xmar1881/Gash/internal/proto"
	"github.com/Xmar1881/Gash/internal/proxypool"
	"github.com/Xmar1881/Gash/internal/recon"
	"github.com/Xmar1881/Gash/internal/smuggle"
)

// acquireContextSlot makes bounded worker queues cancellation-aware. Without
// the select, a cancelled scan can remain blocked behind occupied slots until
// every earlier network operation returns.
func acquireContextSlot(ctx context.Context, sem chan struct{}) bool {
	select {
	case sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// parseTarget validates a scan target URL.
// What: Strict http/https validation with host presence check.
// Why: Fail-fast on malformed targets keeps probe and policy layers honest.
func parseTarget(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("empty target: %w", plugin.ErrValidation)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("bad target %q: %w", raw, plugin.ErrValidation)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("target scheme must be http or https (got %q): %w", u.Scheme, plugin.ErrValidation)
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", fmt.Errorf("target host missing %q: %w", raw, plugin.ErrValidation)
	}
	if u.User != nil {
		return "", fmt.Errorf("target must not contain userinfo: %w", plugin.ErrValidation)
	}
	return u.String(), nil
}

// ruleAndCWE maps an oracle name to rule and weakness identifiers.
// What: Minimal taxonomy bridge for engine-built findings.
// Why: Keeps e2e assertions meaningful without hardcoding plugin identities.
func ruleAndCWE(oracleName string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(oracleName)) {
	case "reflection":
		return "GASH-001", "CWE-79"
	case "stored", "storedexecution", "stored-execution", "stored_execution":
		return "GASH-002", "CWE-79"
	case "execution", "dom-xss", "dom-sink", "dom":
		return "GASH-003", "CWE-79"
	case "error", "differential":
		return "GASH-004", "CWE-89"
	case "redirect":
		return "GASH-016", "CWE-601"
	case "header":
		return "GASH-019", "CWE-693"
	case "cookie":
		return "GASH-022", "CWE-614"
	case "cors":
		return "GASH-023", "CWE-942"
	case "content", "content-exposure", "contentexposure":
		return "GASH-028", "CWE-200"
	case "oob":
		return "GASH-008", "CWE-918"
	case "tls":
		return "GASH-024", "CWE-295"
	case "dns":
		return "GASH-025", "CWE-693"
	case "tcp":
		return "GASH-026", "CWE-200"
	case "version":
		return "GASH-021", "CWE-200"
	case "verb-tamper":
		return "GASH-036", "CWE-650"
	case "upload-served":
		return "GASH-038", "CWE-434"
	case "middleware-bypass":
		return "GASH-069", "CWE-288"
	case "smuggle", "smuggling-differential", "smugglingdifferential":
		return "GASH-033", "CWE-444"
	default:
		return "GASH-000", "CWE-693"
	}
}

// ruleForPlugin maps a plugin execution to rule and weakness identifiers.
// What: Class-aware override (ssrf/idor) over the oracle-based taxonomy.
// Why: Shared oracles (reflection/differential) would otherwise mislabel
// SSRF as XSS and IDOR as SQLi in findings; the override matches the
// documented evidence standards (docs/metrics/ssrf-blind-oob.md,
// docs/metrics/idor-differential.md).
func ruleForPlugin(pluginID, oracleName string) (string, string) {
	return ruleForPluginMode(pluginID, oracleName, "")
}

// ruleForCandidate uses the candidate's oracle mode so error-oracle families
// keep their documented rule IDs (path traversal, XPath, backup, exposure).
func ruleForCandidate(pluginID string, cand plugin.Candidate, ev *oracle.Evidence) (string, string) {
	mode := ""
	if cand.OracleParams != nil {
		mode = strings.ToLower(strings.TrimSpace(cand.OracleParams["mode"]))
	}
	if mode == "" && ev != nil && ev.Artifacts != nil {
		mode = strings.ToLower(strings.TrimSpace(ev.Artifacts["mode"]))
	}
	return ruleForPluginMode(pluginID, cand.OracleName, mode)
}

func ruleForPluginMode(pluginID, oracleName, mode string) (string, string) {
	// The shared error oracle exposes several distinct evidence families. The
	// mode is authoritative before the plugin-ID heuristics.
	switch mode {
	case "path_traversal", "unix_passwd", "windows_ini", "include_error":
		return "GASH-017", "CWE-22"
	case "xpath":
		return "GASH-034", "CWE-643"
	case "backup_file":
		return "GASH-037", "CWE-538"
	case "phpinfo":
		return "GASH-057", "CWE-200"
	case "management_endpoint":
		return "GASH-058", "CWE-200"
	case "directory_listing":
		return "GASH-059", "CWE-548"
	case "ssi":
		return "GASH-064", "CWE-97"
	case "source_map":
		return "GASH-066", "CWE-540"
	case "critical_exposure", "content":
		return "GASH-028", "CWE-200"
	}
	id := strings.ToLower(strings.TrimSpace(pluginID))
	switch {
	// Framework-specific detectors (GASH-069/070) must precede the generic
	// ssrf keyword match so they keep their own rule IDs.
	case strings.Contains(id, "nextjs-middleware"):
		return "GASH-069", "CWE-288"
	case strings.Contains(id, "nextjs-image-optimizer"):
		return "GASH-070", "CWE-918"
	case strings.Contains(id, "ssrf"):
		return "GASH-008", "CWE-918"
	case strings.Contains(id, "content") || strings.Contains(id, "exposed-path"):
		return "GASH-028", "CWE-200"
	case strings.Contains(id, "path-traversal") || strings.Contains(id, "traversal"):
		return "GASH-017", "CWE-22"
	case strings.Contains(id, "idor") || strings.Contains(id, "bola"):
		return "GASH-005", "CWE-639"
	// Lab-batch dedektörleri (çakışma yok; yeni ID'ler 029-032):
	case strings.Contains(id, "deserial"):
		return "GASH-029", "CWE-502"
	case strings.Contains(id, "takeover") || strings.Contains(id, "subdomain"):
		return "GASH-030", "CWE-693"
	case strings.Contains(id, "mass-assignment") || strings.Contains(id, "massassignment"):
		return "GASH-031", "CWE-915"
	case strings.Contains(id, "rate-limit") || strings.Contains(id, "ratelimit"):
		return "GASH-032", "CWE-770"
	default:
		return ruleAndCWE(oracleName)
	}
}

// newScanID generates a random scan identifier.
// What: Hex scan tag for report correlation.
// Why: Distinguishes concurrent scans without leaking target details.
func newScanID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("scan_%d", time.Now().UnixNano())
	}
	return "scan_" + hex.EncodeToString(b[:])
}

// newScanClient hedef için politika oturumu + probe istemcisini kurar.
// What: Run (login dahil) ve runLive'ın paylaştığı tek istemci kurulum noktası.
// Why: Login akışı ile plugin koşumu aynı policy/probe hattını kullanmalı;
// kimlik bağlamı tek yerden (ExtraHeaders) gömülür ve login sonrası
// SetExtraHeaders ile tazelenir.
func (e *Engine) newScanClient(target string) (*plugin.PolicySession, *probe.Client, error) {
	maxResponseBytes := e.cfg.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = 5 * 1024 * 1024
	}
	policy := e.sharedPolicy
	if policy == nil {
		proxyURLs, rotate, cooldown, err := e.proxyConfig()
		if err != nil {
			return nil, nil, err
		}
		// Start from policy defaults so retry, redirect, request-size, and
		// scan-deadline protections are not lost when engine flags override
		// only the scan-specific limits.
		pcfg := plugin.DefaultPolicyConfig()
		pcfg.MaxRequestsPerTarget = e.cfg.MaxRequestsPerTarget
		pcfg.MaxRequestsTotal = e.cfg.MaxRequestsTotal
		pcfg.Scope = e.cfg.Scope
		pcfg.RatePerSecond = e.cfg.RatePerSecond
		pcfg.MaxResponseBytes = maxResponseBytes
		pcfg.ProxyURLs = proxyURLs
		pcfg.ProxyRotate = rotate
		pcfg.ProxyCooldown = cooldown
		if len(proxyURLs) > 1 && e.cfg.ProxyAttemptTimeout > 0 {
			pcfg.AttemptTimeout = e.cfg.ProxyAttemptTimeout
		}
		pcfg.ScanTimeout = e.effectiveScanTimeout()
		// The target rate limiter is shared by every plugin. A large host
		// semaphore lets many plugin goroutines queue behind the same token
		// bucket and makes otherwise healthy plugins expire together.
		pcfg.MaxConcurrencyPerHost = 8
		pcfg.BackpressureLimit = 32
		policy = plugin.NewPolicySession(pcfg, nil)
	}
	// P1.3: Set original target for scope rebinding detection
	policy.SetOriginalTarget(target)
	// P2.5: kimlik bağlamı probe'a gömülür (requires_auth kapısı New'de açıldı).
	var extraHeaders map[string]string
	if e.cfg.Auth != nil {
		extraHeaders = e.cfg.Auth.HeaderMap()
	}
	requestTimeout := e.cfg.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = 15 * time.Second
	}
	maxBytes := e.cfg.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = 5 * 1024 * 1024
	}
	client := probe.NewClient(probe.Options{
		Policy:         policy,
		RequestTimeout: requestTimeout,
		MaxBytes:       maxBytes,
		ExtraHeaders:   extraHeaders,
		// WAF bypass yalnızca agresif profilde: blok yanıtı WAFDetected
		// işaretlenir, sınırlı varyant aynı politika/kapsam içinden denenir.
		// Varsayılan taramada stealth davranışı YOKTUR (§14).
		EnableWAFBypass: e.cfg.Profile == config.ProfileAggressive,
	})
	return policy, client, nil
}

// proxyConfig parses the configured pool. A single --proxy is just a one-entry
// pool, so the failover path stays dormant until a second proxy is supplied.
func (e *Engine) proxyConfig() ([]*url.URL, proxypool.Strategy, time.Duration, error) {
	raw := make([]string, 0, len(e.cfg.ProxyURLs)+1)
	if strings.TrimSpace(e.cfg.ProxyURL) != "" {
		raw = append(raw, e.cfg.ProxyURL)
	}
	raw = append(raw, e.cfg.ProxyURLs...)
	urls, err := proxypool.ParseList(raw)
	if err != nil {
		return nil, "", 0, fmt.Errorf("invalid proxy configuration: %w", err)
	}
	strategy, err := proxypool.ParseStrategy(e.cfg.ProxyRotate)
	if err != nil {
		return nil, "", 0, err
	}
	return urls, strategy, e.cfg.ProxyCooldown, nil
}

// runLive executes scheduled plugins against a validated target.
// What: Probe-backed Tier1/Tier2/Tier3 execution plus correlate and stats.
// Why: Single live path serves CLI scans and engine e2e tests identically.
// policy/client Run tarafından kurulur (login aynı hattı paylaşır); login
// sonucu istatistik ve skip izi olarak rapora girer.
func (e *Engine) runLive(ctx context.Context, target string, ordered []plugin.PluginSpec, skipped []plugin.SkippedPlugin, policy *plugin.PolicySession, client *probe.Client, login loginOutcome, preflightErr error) (*Report, error) {
	runStart := time.Now()
	var crawlMs, jsReconMs, spaCrawlMs, contentMs, fuzzMs int
	var formFuzzMs, flowMs, matrixMs, smuggleMs, browserVerifyMs, pluginsMs int
	// Fail closed once, not 196 times: an HTTPS target with an unverifiable
	// certificate cannot produce trustworthy evidence. The runtime tech GET
	// already observed this, so reuse its verdict instead of a second request;
	// SkipTLSFailFast stays the test seam.
	if preflightErr != nil && isTLSCertError(preflightErr) && !e.cfg.SkipTLSFailFast {
		return nil, fmt.Errorf("target TLS certificate verification failed: %w (install the issuing CA via SSL_CERT_FILE or use --no-proxy; TLS is fail-closed)", preflightErr)
	}
	timeoutMs := e.cfg.PluginTimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 60000
	}
	pluginTimeout := time.Duration(timeoutMs) * time.Millisecond

	parallelism := e.cfg.Parallelism
	if parallelism <= 0 {
		parallelism = 8
	}
	if parallelism > len(ordered) {
		parallelism = len(ordered)
	}
	var sem chan struct{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	// Faz 2: TLS el sıkışma sonucu burada yakalanır ve altyapı derin TLS
	// denetimine geçirilir; sertifika/zincir olguları ek dial açmadan aynı
	// gözlemden türetilir.
	e.notifyProgress(progressPhaseProtocol, progressDetailProtocolStart)
	protoFindings, protoSkipped, tlsObs := e.runProtoReconTLS(ctx, target)
	e.notifyProgress(progressPhaseProtocol, progressDetailProtocolDone,
		len(protoFindings), len(protoSkipped))
	allFindings := protoFindings
	var execSkipped []plugin.SkippedPlugin
	execSkipped = append(execSkipped, protoSkipped...)
	if strings.TrimSpace(e.cfg.OOBServer) != "" {
		if _, oerr := e.oobProvider(); oerr != nil {
			execSkipped = append(execSkipped, plugin.SkippedPlugin{
				PluginID: "oob-provider",
				Reason:   "oob provider error: " + oerr.Error(),
			})
		}
	}
	// Faz 0/1/2 altyapı recon: SSH banner + DB port envanteri + derin TLS
	// gözlemi. Tüm bayraklar kapalıysa sıfır ek trafik; kapsam fail-closed.
	infraStarted := e.cfg.SSHAudit || e.cfg.DBPortScan || e.cfg.TLSAuditDeep ||
		e.cfg.SSHHandshakeAudit || e.cfg.DBUnauth
	if infraStarted {
		e.notifyProgress(progressPhaseInfra, progressDetailInfraStart)
	}
	infraFindings, infraSkipped, infraStats := e.runInfraReconTLS(ctx, target, tlsObs)
	if infraStarted {
		checks := infraStats["ssh_checks"] + infraStats["ssh_handshake_checks"] +
			infraStats["db_ports_scanned"] + infraStats["db_unauth_checks"] +
			infraStats["tls_deep_checks"]
		e.notifyProgress(progressPhaseInfra, progressDetailInfraDone,
			checks, infraStats["db_open_ports"], len(infraFindings))
	}
	allFindings = append(allFindings, infraFindings...)
	execSkipped = append(execSkipped, infraSkipped...)
	errorCount := 0
	// partialCount: koştu ama ilan ettiği istek tavanına takıldı (partial).
	partialCount := 0

	// Attack surface discovery: crawl target to extract form inputs, query params, and links across pages
	maxPages := e.cfg.MaxPages
	if maxPages <= 0 {
		maxPages = 50
	}
	depth := e.cfg.Depth
	if depth < 0 {
		depth = 3
	}
	crawlOpts := discovery.CrawlOptions{
		MaxPages:    maxPages,
		MaxDepth:    depth,
		Scope:       e.cfg.Scope,
		ReadRobots:  true,
		ReadSitemap: true,
	}
	// Pasif JS recon sayaçları (crawl kapalı/başarısızken 0).
	jsReconStats := map[string]int{
		"js_files_fetched": 0, "js_endpoints_found": 0,
		"js_hash_routes_found": 0,
		"js_secrets_found":     0, "js_maps_fetched": 0,
	}
	// GASH-071/072 content scans (crawl kapalı/başarısızken 0).
	spaStateStats := map[string]int{"spa_state_pages": 0, "spa_state_secrets": 0}
	devBuildStats := map[string]int{"devbuild_markers": 0}
	// SPA render sayaçları (--browser-crawl kapalı/başarısızken 0).
	spaStats := map[string]int{
		"spa_pages_rendered": 0, "spa_forms": 0,
		"spa_endpoints": 0, "spa_skipped": 0,
	}
	e.notifyProgress(progressPhaseCrawl, progressDetailCrawlStart)
	phaseStart := time.Now()
	// Canlı ilerleme: crawl uzun sürebilir (aggressive profilde 500 sayfaya kadar);
	// sayaç olmadan bu faz donmuş gibi görünür.
	crawlOpts.OnPage = func(done, total int, pageURL string) {
		e.notifyProgress(progressPhaseCrawl, progressDetailCrawlPage,
			done, total, crawlPageTarget(pageURL))
	}
	crawlCtx := ctx
	var crawlCancel context.CancelFunc
	if e.cfg.CrawlTimeout > 0 {
		crawlCtx, crawlCancel = context.WithTimeout(ctx, e.cfg.CrawlTimeout)
		defer crawlCancel()
	}
	crawlRes, crawlErr := discovery.Crawl(crawlCtx, client, target, crawlOpts)
	crawlMs = int(time.Since(phaseStart).Milliseconds())
	phaseStart = time.Now()
	crawlBudgetExhausted := 0
	if errors.Is(crawlCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		crawlBudgetExhausted = 1
	}
	crawlIncomplete := 0
	if crawlErr != nil && crawlRes != nil {
		crawlIncomplete = 1
	}
	// A crawl that produced no result and did not stop on its own budget is a
	// failure, not a partial surface; plugins then fall back to the root page.
	crawlFailed := 0
	if crawlErr != nil && crawlRes == nil && ctx.Err() == nil && !errors.Is(crawlCtx.Err(), context.DeadlineExceeded) {
		crawlFailed = 1
	}
	crawlStoredBytes, crawlURLsDropped, crawlBodiesDropped := 0, 0, 0
	if crawlRes != nil {
		crawlStoredBytes = int(crawlRes.StoredBodyBytes)
		crawlURLsDropped = crawlRes.URLsDropped
		crawlBodiesDropped = crawlRes.BodiesDropped
	}
	switch {
	case crawlFailed > 0:
		e.notifyProgress(progressPhaseCrawl, progressDetailCrawlFailed)
	case crawlRes == nil:
		e.notifyProgress(progressPhaseCrawl, progressDetailCrawlEmpty)
	default:
		detailKey := progressDetailCrawlDone
		args := []any{len(crawlRes.Pages), len(crawlRes.SurfacePoints),
			crawlRes.TotalRequests, crawlMs}
		switch {
		case crawlBudgetExhausted > 0:
			detailKey = progressDetailCrawlTimeout
		case crawlIncomplete > 0:
			detailKey = progressDetailCrawlPartial
		case crawlURLsDropped > 0:
			detailKey = progressDetailCrawlDoneLimit
			args = append(args, crawlURLsDropped)
		}
		e.notifyProgress(progressPhaseCrawl, detailKey, args...)
	}
	var surfacePoints []loader.JSPoint
	if crawlRes != nil {
		e.notifyProgress(progressPhaseJS, progressDetailJSStart)
		for _, page := range crawlRes.Pages {
			e.mergeSurfaceTech(page.Headers, nil, page.Body)
		}
		for _, ip := range crawlRes.SurfacePoints {
			surfacePoints = append(surfacePoints, loader.JSPoint{
				URL:           ip.URL,
				Method:        ip.Method,
				ParamName:     ip.ParamName,
				ParamLocation: ip.ParamLocation,
				Value:         ip.Value,
				FormValues:    ip.FormValues,
				FormEnctype:   ip.FormEnctype,
			})
		}
		// Pasif JS recon (GASH-067): crawl'ın topladığı same-origin JS gövdeleri
		// + kaynak haritaları; endpoint'ler yüzeye beslenir, sırlar masked
		// bulgudur. Kimlik, kapsam kararı (URLAllowed), sınırlı takip crawl'ı
		// (FollowCrawl) ve sayaç anahtarları port/kayıt üzerinden gelir
		// (internal/recon/jsrecon.go); motor yalnızca ortamı kurar.
		detEnv := e.detectorEnv(target, client, crawlRes)
		jsRun := e.runDetector(ctx, detEnv, recon.PluginIDJSRecon)
		if jsRun.Ran {
			allFindings = append(allFindings, jsRun.Result.Findings...)
			for _, s := range jsRun.Result.Surface {
				surfacePoints = append(surfacePoints, loader.JSPoint{
					URL: s.URL, Method: s.Method, ParamName: s.ParamName,
					ParamLocation: s.ParamLocation, Value: s.Value,
					FormValues: s.FormValues, FormEnctype: s.FormEnctype,
				})
			}
			for k, v := range jsRun.Result.Stats {
				jsReconStats[k] = v
			}
		}
		jsReconMs = int(time.Since(phaseStart).Milliseconds())
		if jsRun.Ran {
			e.notifyProgress(progressPhaseJS, progressDetailJSDone,
				jsReconStats["js_files_fetched"], jsReconStats["js_endpoints_found"],
				jsReconStats["js_secrets_found"], jsReconStats["js_maps_fetched"], jsReconMs)
		} else if jsRun.Reason != "" {
			e.notifyProgress(progressPhaseJS, progressDetailJSSkipped, jsRun.Reason)
		} else {
			e.notifyProgress(progressPhaseJS, progressDetailJSFailed)
		}
		phaseStart = time.Now()
		e.notifyProgress(progressPhaseSPA, progressDetailSPAStart)
		// GASH-071/072: already-fetched page + external JS bodies are scanned
		// deterministically; no additional requests are issued. Kimlik, kural
		// eşlemesi ve sayaç anahtarları dedektörün Spec'inde yaşar
		// (internal/recon); motor yalnızca ortamı kurar ve sonucu rapora bağlar.
		if run := e.runDetector(ctx, detEnv, recon.PluginIDSPAState); run.Ran {
			allFindings = append(allFindings, run.Result.Findings...)
			for k, v := range run.Result.Stats {
				spaStateStats[k] = v
			}
		}
		if run := e.runDetector(ctx, detEnv, recon.PluginIDDevBuild); run.Ran {
			allFindings = append(allFindings, run.Result.Findings...)
			for k, v := range run.Result.Stats {
				devBuildStats[k] = v
			}
		}
		e.notifyProgress(progressPhaseSPA, progressDetailSPADone,
			spaStateStats["spa_state_pages"], spaStateStats["spa_state_secrets"],
			devBuildStats["devbuild_markers"])
		// SPA yüzeyi: seçilmiş sayfalar render edilir; DOM formları/form
		// fuzz'ına, gözlenen endpoint'ler yüzeye eklenir. Browser yoksa tek
		// dürüst skip kaydı; sayfa hatası taramayı durdurmaz.
		if e.cfg.BrowserCrawl {
			e.notifyProgress(progressPhaseBrowser, progressDetailBrowserStart)
			browserStart := time.Now()
			spaPoints, spaSkipped, spaRunStats := e.runSPACrawl(ctx, target, client, crawlRes, surfacePoints)
			surfacePoints = append(surfacePoints, spaPoints...)
			execSkipped = append(execSkipped, spaSkipped...)
			for k, v := range spaRunStats {
				spaStats[k] = v
			}
			e.notifyProgress(progressPhaseBrowser, progressDetailBrowserDone,
				spaStats["spa_pages_rendered"], spaStats["spa_forms"], spaStats["spa_endpoints"],
				spaStats["spa_skipped"], time.Since(browserStart).Milliseconds())
		}
		spaCrawlMs = int(time.Since(phaseStart).Milliseconds())
		phaseStart = time.Now()
	}
	if len(surfacePoints) == 0 {
		injected := discovery.ExtractSurface(target, nil)
		for _, ip := range injected {
			surfacePoints = append(surfacePoints, loader.JSPoint{
				URL:           ip.URL,
				Method:        ip.Method,
				ParamName:     ip.ParamName,
				ParamLocation: ip.ParamLocation,
				Value:         ip.Value,
				FormValues:    ip.FormValues,
				FormEnctype:   ip.FormEnctype,
			})
		}
	}

	// OpenAPI yüzeyi (--openapi-spec): ParseSpec endpoint+parametreleri hedef
	// bazında surfacePoints'e eklenir. Hedef host dışı + kapsam-dışı URL'ler
	// ekleme anında atlanır (probe PolicySession ikinci kilittir).
	// Hata fail-closed'tur (bozuk/kayıp spec taramayı durdurur).
	if strings.TrimSpace(e.cfg.OpenAPISpec) != "" {
		apiPoints, aerr := e.loadOpenAPISurface(ctx, target)
		if aerr != nil {
			return nil, aerr
		}
		surfacePoints = append(surfacePoints, apiPoints...)
		e.notifyProgress(progressPhaseOpenAPI, progressDetailOpenAPIDone,
			len(apiPoints), len(surfacePoints))
	}

	// İçerik keşfi (wordlist): --active kapılı motor-içi GASH-028 dedektörü
	// (internal/discovery/detector.go). Gerekçe: teknoloji-koşullu wordlist
	// seçimi + hassas path'te HEAD-only + smart-recurse (yedek uzantı, derinlik
	// ≤2) tek-istekli YAML kalıbına sığmaz; kanıt motor-içidir (B3, finding.Build
	// bypass — proto recon disiplini). Kimlik, bütçe ve sayaç anahtarları
	// dedektörün Spec'inde yaşar; motor ortamı kurar, sonucu rapora bağlar ve
	// bulunan path'leri geri-besleme crawl'ı için kullanır. Safe taramada
	// sessizdir (profil disiplini); destructive YOK (GET/HEAD).
	var contentRequests, contentFollowRequests, contentFindingCount int
	var contentBudgetExhausted, contentFollowBudgetExhausted int
	contentRan := false
	contentReason := ""
	if e.cfg.Active {
		e.notifyProgress(progressPhaseContent, progressDetailContentStart)
		contentEnv := e.detectorEnv(target, client, crawlRes)
		contentEnv.Progress = func(done, total int) {
			e.notifyProgress(progressPhaseContent, progressDetailContentProgress, done, total)
		}
		contentRun := e.runDetector(ctx, contentEnv, discovery.PluginIDContentDiscovery)
		contentRan = contentRun.Ran
		contentReason = contentRun.Reason
		if contentRun.Ran {
			contentRequests = contentRun.Result.Stats["content_requests"]
			contentFindingCount = contentRun.Result.Stats["content_findings"]
			contentBudgetExhausted = contentRun.Result.Stats["content_budget_exhausted"]
			allFindings = append(allFindings, contentRun.Result.Findings...)
			for _, p := range contentRun.Result.Paths {
				surfacePoints = append(surfacePoints, loader.JSPoint{URL: p, Method: http.MethodGet})
			}
			// Crawler geri-besleme: dizin-benzeri isabetlerin altında
			// sınırlı mini-crawl (en fazla 3 dizin × 10 sayfa, derinlik 1).
			e.notifyProgress(progressPhaseContent, progressDetailContentFollow)
			followCtx, followCancel := context.WithTimeout(ctx, 60*time.Second)
			dirs := 0
			for _, p := range contentRun.Result.Paths {
				if dirs >= 3 {
					break
				}
				if followCtx.Err() != nil {
					contentFollowBudgetExhausted = 1
					break
				}
				if !strings.HasSuffix(p, "/") {
					continue
				}
				dirs++
				follow, ferr := discovery.Crawl(followCtx, client, p, discovery.CrawlOptions{
					MaxPages: 10, MaxDepth: 1, Scope: e.cfg.Scope,
					ReadRobots: false, ReadSitemap: false, SkipJSRecon: true,
				})
				if ferr != nil || follow == nil {
					continue
				}
				contentFollowRequests += follow.TotalRequests
				for _, ip := range follow.SurfacePoints {
					surfacePoints = append(surfacePoints, loader.JSPoint{
						URL: ip.URL, Method: ip.Method, ParamName: ip.ParamName,
						ParamLocation: ip.ParamLocation, Value: ip.Value,
						FormValues: ip.FormValues, FormEnctype: ip.FormEnctype,
					})
				}
			}
			followCancel()
		}
	}
	contentMs = int(time.Since(phaseStart).Milliseconds())
	phaseStart = time.Now()
	if e.cfg.Active {
		switch {
		case contentRan:
			detailKey := progressDetailContentDone
			if contentBudgetExhausted > 0 || contentFollowBudgetExhausted > 0 {
				detailKey = progressDetailContentBudget
			}
			e.notifyProgress(progressPhaseContent, detailKey,
				contentRequests+contentFollowRequests, contentFindingCount, contentMs)
		case contentReason != "":
			e.notifyProgress(progressPhaseContent, progressDetailContentSkipped, contentReason)
		default:
			e.notifyProgress(progressPhaseContent, progressDetailContentFailed)
		}
	}

	// Görev B: atıl fuzz motoru canlı döngüde. Yalnızca --active koşar
	// (güvenli varsayılan sessizdir); anomali → tentative Finding.
	var fuzzRequests int64
	fuzzFindingCount := 0
	if e.cfg.Active {
		e.notifyProgress(progressPhaseFuzz, progressDetailFuzzStart)
		fuzzFindings, freq := e.runActiveFuzz(ctx, target, client, surfacePoints)
		fuzzRequests = freq
		fuzzFindingCount = len(fuzzFindings)
		allFindings = append(allFindings, fuzzFindings...)
	}
	fuzzMs = int(time.Since(phaseStart).Milliseconds())
	if e.cfg.Active {
		e.notifyProgress(progressPhaseFuzz, progressDetailFuzzDone,
			len(surfacePoints), fuzzRequests, fuzzFindingCount, fuzzMs)
	}
	phaseStart = time.Now()
	// Görev B2: tam-form replay fuzz. Tek-alan gövdeleri sunucu doğrulaması
	// ve CSRF kapısında düşer; keşfedilen formlar tüm alanlarıyla (token'lar
	// tazelenerek) tekrarlanır. Yalnızca --active.
	var formRequests int64
	formFindingCount := 0
	formCount := 0
	if e.cfg.Active && crawlRes != nil && len(crawlRes.Forms) > 0 {
		formCount = len(crawlRes.Forms)
		e.notifyProgress(progressPhaseFormFuzz, progressDetailFormStart)
		formFindings, formReq := e.runActiveFormFuzz(ctx, target, client, crawlRes.Forms)
		formRequests = formReq
		formFindingCount = len(formFindings)
		allFindings = append(allFindings, formFindings...)
	}
	formFuzzMs = int(time.Since(phaseStart).Milliseconds())
	if formCount > 0 {
		e.notifyProgress(progressPhaseFormFuzz, progressDetailFormDone,
			formCount, formRequests, formFindingCount, formFuzzMs)
	}
	phaseStart = time.Now()
	// Çok-adımlı akış replay (--flow-seed): keşif + taze token'lı replay +
	// alt-adım değerlendirmesi + oturumsuz doğrudan erişim ekranı.
	// Yalnızca --active + açık seed ile; kapsam-dışı seed'e istek gitmez.
	var flowFindings []*finding.Finding
	flowStats := map[string]int{
		"flow_seed": 0, "flow_steps": 0, "flow_replays": 0,
		"flow_findings": 0, "flow_bypass_checked": 0, "flow_requests": 0,
	}
	if e.cfg.Active && strings.TrimSpace(e.cfg.FlowSeed) != "" {
		e.notifyProgress(progressPhaseFlow, progressDetailFlowStart)
		var flowSkipped []plugin.SkippedPlugin
		flowFindings, flowSkipped, flowStats = e.runFlowFuzz(ctx, target, client)
		allFindings = append(allFindings, flowFindings...)
		execSkipped = append(execSkipped, flowSkipped...)
	}
	flowMs = int(time.Since(phaseStart).Milliseconds())
	if e.cfg.Active && strings.TrimSpace(e.cfg.FlowSeed) != "" {
		e.notifyProgress(progressPhaseFlow, progressDetailFlowDone,
			flowStats["flow_steps"], flowStats["flow_replays"], flowStats["flow_requests"],
			flowStats["flow_findings"], flowMs)
	}
	phaseStart = time.Now()
	// Görev C: çift-kullanıcı BOLA matrisi. --active + iki kimlik şart;
	// bulgular daima tentative (sahiplik elle doğrulanır).
	var matrixRequests int64
	matrixFindingCount := 0
	if e.cfg.Active && e.HasDualAuth() {
		e.notifyProgress(progressPhaseMatrix, progressDetailMatrixStart)
		matrixFindings, mreq := e.runCrossUserMatrix(ctx, client, surfacePoints)
		matrixRequests = mreq
		matrixFindingCount = len(matrixFindings)
		allFindings = append(allFindings, matrixFindings...)
	}
	matrixMs = int(time.Since(phaseStart).Milliseconds())
	if e.cfg.Active && e.HasDualAuth() {
		e.notifyProgress(progressPhaseMatrix, progressDetailMatrixDone,
			matrixRequests, matrixFindingCount, matrixMs)
	}
	phaseStart = time.Now()

	// Request smuggling (CL.TE/TE.CL/TE.TE): motor-içi GASH-033 dedektörü
	// (internal/smuggle/detector.go). Tier1-YAML değil, motor-içi — gerekçe:
	// net/http chunk çerçevelemeyi denetlemez; ham-TCP dial + keep-alive
	// çift-isabet (muğlak+takip) tek-istekli YAML kalıbına sığmaz ve JS
	// sandbox'ında ham soket yoktur. Kapı, taksonomi, payload tablosu
	// (cases.yaml) ve skip metni dedektörün Spec'inde yaşar; motor yalnızca
	// ortamı (kapsam + bayraklar) kurar ve sonucu rapora bağlar. Hedef
	// kullanıcının verdiği host'tur (Nuclei/Burp smuggler modeli); kapsam
	// preflight yalnızca --scope verilmişse uygulanır. Kapı dışı
	// (safe/standard/deep dahil) sessiz değil, denetim izli skip'tir;
	// kapsam-dışı soket AÇILMAZ (≤10 istek, 5s tavan).
	var smuggleRequests int
	smuggleRelevant := e.cfg.Active && e.cfg.Profile == config.ProfileAggressive
	if smuggleRelevant {
		e.notifyProgress(progressPhaseSmuggle, progressDetailSmuggleStart)
	}
	smuggleRun := e.runDetector(ctx, e.smugglerEnv(target, client, crawlRes), smuggle.PluginID)
	switch {
	case !smuggleRun.Ran:
		if smuggleRun.Reason != "" {
			execSkipped = append(execSkipped, plugin.SkippedPlugin{PluginID: smuggle.PluginID, Reason: smuggleRun.Reason})
			if smuggleRelevant {
				e.notifyProgress(progressPhaseSmuggle, progressDetailSmuggleSkipped, smuggleRun.Reason)
			}
		}
	default:
		smuggleRequests = smuggleRun.Result.Requests
		allFindings = append(allFindings, smuggleRun.Result.Findings...)
		execSkipped = append(execSkipped, smuggleRun.Result.Skips...)
		e.notifyProgress(progressPhaseSmuggle, progressDetailSmuggleDone,
			smuggleRequests, len(smuggleRun.Result.Findings))
	}
	smuggleMs = int(time.Since(phaseStart).Milliseconds())

	// Large discovered surfaces make Tier 2 plugins request-heavy. Keep only
	// two long-running plugin workers in that case so the shared per-target
	// limiter serves whole plugins instead of timing out all of them together.
	if len(surfacePoints) > 16 && e.cfg.RatePerSecond > 0 && parallelism > 2 {
		parallelism = 2
	}
	sem = make(chan struct{}, parallelism)
	totalPlugins := len(ordered)
	findingsBeforePlugins := len(allFindings)
	var completedPlugins atomic.Int32
	pluginsStart := time.Now()
	e.notifyProgress(progressPhasePlugins, progressDetailPluginsStart, 0, totalPlugins)

	for _, spec := range ordered {
		wg.Add(1)
		go func(s plugin.PluginSpec) {
			defer wg.Done()
			if !acquireContextSlot(ctx, sem) {
				done := completedPlugins.Add(1)
				e.notifyProgress(progressPhasePlugins, progressDetailPluginsProgress, done, totalPlugins, s.ID)
				mu.Lock()
				execSkipped = append(execSkipped, plugin.SkippedPlugin{
					PluginID: s.ID,
					Reason:   fmt.Sprintf("skipped (scan context: %v)", ctx.Err()),
				})
				mu.Unlock()
				return
			}
			defer func() { <-sem }()
			points := pluginSurfacePoints(e.cfg, s, surfacePoints)
			run := e.executeOneSafe(ctx, s, target, client, pluginTimeout, points)
			done := completedPlugins.Add(1)
			e.notifyProgress(progressPhasePlugins, progressDetailPluginsProgress, done, totalPlugins, s.ID)
			mu.Lock()
			defer mu.Unlock()
			if !run.ran {
				execSkipped = append(execSkipped, plugin.SkippedPlugin{PluginID: s.ID, Reason: run.reason})
				errorCount++
				return
			}
			allFindings = append(allFindings, run.findings...)
			if run.reason != "" {
				execSkipped = append(execSkipped, plugin.SkippedPlugin{
					PluginID: s.ID,
					Reason:   run.reason,
					Partial:  run.partial,
				})
				if run.partial {
					partialCount++
				}
			}
		}(spec)
	}
	wg.Wait()
	pluginsMs = int(time.Since(pluginsStart).Milliseconds())
	e.notifyProgress(progressPhasePlugins, progressDetailPluginsDone,
		totalPlugins, totalPlugins, len(allFindings)-findingsBeforePlugins,
		partialCount, errorCount, pluginsMs)

	// Generic browser-verify pass (opt-in, deep builds): static XSS findings
	// may reach confirmed only through a real trigger plus a clean control;
	// otherwise the static tier is preserved untouched.
	if e.cfg.BrowserVerify {
		e.notifyProgress(progressPhaseVerify, progressDetailVerifyStart)
		verifyStart := time.Now()
		confirmedBefore := countConfirmedFindings(allFindings)
		verifySkips := e.verifyBrowserFindings(ctx, allFindings)
		execSkipped = append(execSkipped, verifySkips...)
		browserVerifyMs = int(time.Since(verifyStart).Milliseconds())
		e.notifyProgress(progressPhaseVerify, progressDetailVerifyDone,
			countConfirmedFindings(allFindings)-confirmedBefore, len(verifySkips), browserVerifyMs)
	}

	e.notifyProgress(progressPhaseCorrelation, progressDetailCorrelationStart)
	deduped := Correlate(allFindings)
	e.notifyProgress(progressPhaseCorrelation, progressDetailCorrelationDone,
		len(deduped), len(allFindings)-len(deduped))
	counts := make(map[string]int, len(allFindings))
	for _, f := range allFindings {
		counts[f.Fingerprint]++
	}
	threshold := e.cfg.NoisyThreshold
	if threshold <= 0 {
		threshold = 10
	}
	_, note := NoisyBreaker(counts, threshold)

	allSkipped := append(append([]plugin.SkippedPlugin{}, skipped...), execSkipped...)
	wafDet, wafByp := client.WAFStats()
	wafChallenges := client.WAFChallengeStats()
	httpRequests := int64(0)
	if policy != nil {
		httpRequests = policy.TotalCount()
	}
	var proxyStats proxypool.Stats
	if policy != nil {
		proxyStats = policy.ProxyPool().Stats()
	}
	retryBudgetExhausted := 0
	if policy != nil {
		retryBudgetExhausted = int(policy.RetryBudgetExhausted())
	}
	cacheHits, cacheFetches := int64(0), int64(0)
	if e.passiveCache != nil {
		cacheHits, cacheFetches = e.passiveCache.Stats()
	}
	rep := &Report{
		Target:   target,
		Findings: deduped,
		Skipped:  allSkipped,
		Stats: map[string]int{
			"scheduled":       len(ordered),
			"skipped":         len(allSkipped),
			"partial_plugins": partialCount,
			"findings":        len(deduped),
			"errors":          errorCount,
			// Effective engine limits make a report explain its own stopping
			// point (budget/rate/page caps) without re-reading the CLI flags.
			"request_budget_target": int(e.cfg.MaxRequestsPerTarget),
			"request_budget_total":  int(e.cfg.MaxRequestsTotal),
			"rate_limit_per_second": int(math.Round(e.cfg.RatePerSecond)),
			"max_pages":             e.cfg.MaxPages,
			"crawl_depth":           e.cfg.Depth,
			"plugin_selection":      len(e.cfg.OnlyPlugins),
			"plugin_exclusions":     len(e.cfg.IgnorePlugins),
			"http_requests":         int(httpRequests),
			"passive_cache_hits":    int(cacheHits),
			"passive_cache_fetches": int(cacheFetches),
			"waf_detected":          int(wafDet),
			"waf_bypassed":          int(wafByp),
			"waf_challenges":        int(wafChallenges),
			// Phase timings (ms) so a long scan shows where the time went.
			"crawl_ms":               crawlMs,
			"crawl_budget_exhausted": crawlBudgetExhausted,
			"crawl_incomplete":       crawlIncomplete,
			"crawl_failed":           crawlFailed,
			"crawl_stored_bytes":     crawlStoredBytes,
			"crawl_urls_dropped":     crawlURLsDropped,
			"crawl_bodies_dropped":   crawlBodiesDropped,
			"js_recon_ms":            jsReconMs,
			"spa_crawl_ms":           spaCrawlMs,
			"content_discovery_ms":   contentMs,
			"fuzz_ms":                fuzzMs,
			"form_fuzz_ms":           formFuzzMs,
			"flow_ms":                flowMs,
			"matrix_ms":              matrixMs,
			"smuggle_ms":             smuggleMs,
			"browser_verify_ms":      browserVerifyMs,
			"plugins_ms":             pluginsMs,
			"total_ms":               int(time.Since(runStart).Milliseconds()),
			"surface_points":         len(surfacePoints),
			// Proxy pool health (0 when no pool is configured).
			"proxy_pool_size":                 proxyStats.Size,
			"proxy_healthy":                   proxyStats.Healthy,
			"proxy_cooling":                   proxyStats.CoolingDown,
			"proxy_rotations":                 int(proxyStats.Rotations),
			"proxy_failures":                  int(proxyStats.Failures),
			"proxy_direct_fallbacks":          int(proxyStats.DirectFallbacks),
			"retry_budget_exhausted":          retryBudgetExhausted,
			"fuzz_requests":                   int(fuzzRequests),
			"form_requests":                   int(formRequests),
			"matrix_requests":                 int(matrixRequests),
			"content_requests":                contentRequests + contentFollowRequests,
			"content_findings":                contentFindingCount,
			"content_budget_exhausted":        contentBudgetExhausted,
			"content_follow_budget_exhausted": contentFollowBudgetExhausted,
			"smuggle_requests":                smuggleRequests,
			// Çok-adımlı akış replay sayaçları (flow yoksa 0).
			"flow_seed":           flowStats["flow_seed"],
			"flow_steps":          flowStats["flow_steps"],
			"flow_replays":        flowStats["flow_replays"],
			"flow_findings":       flowStats["flow_findings"],
			"flow_bypass_checked": flowStats["flow_bypass_checked"],
			"flow_requests":       flowStats["flow_requests"],
			// Pasif JS recon sayaçları (crawl kapalı/başarısızken 0).
			"js_files_fetched":          jsReconStats["js_files_fetched"],
			"js_endpoints_found":        jsReconStats["js_endpoints_found"],
			"js_hash_routes_found":      jsReconStats["js_hash_routes_found"],
			"js_secrets_found":          jsReconStats["js_secrets_found"],
			"js_maps_fetched":           jsReconStats["js_maps_fetched"],
			"js_recon_budget_exhausted": jsReconStats["js_recon_budget_exhausted"],
			// GASH-071/072 embedded-state and dev-build content scans.
			"spa_state_pages":   spaStateStats["spa_state_pages"],
			"spa_state_secrets": spaStateStats["spa_state_secrets"],
			"devbuild_markers":  devBuildStats["devbuild_markers"],
			// SPA render sayaçları (--browser-crawl kapalıyken 0).
			"spa_pages_rendered": spaStats["spa_pages_rendered"],
			"spa_forms":          spaStats["spa_forms"],
			"spa_endpoints":      spaStats["spa_endpoints"],
			"spa_skipped":        spaStats["spa_skipped"],
			"detected_tech":      len(e.detectedTech),
			"detected_caps":      len(e.detectedCaps),
			"ssh_checks":         infraStats["ssh_checks"],
			"db_ports_scanned":   infraStats["db_ports_scanned"],
			"db_open_ports":      infraStats["db_open_ports"],
			"tls_deep_checks":    infraStats["tls_deep_checks"],
			// Faz 1 altyapı sayaçları (kapalıyken 0).
			"ssh_handshake_checks": infraStats["ssh_handshake_checks"],
			"db_unauth_checks":     infraStats["db_unauth_checks"],
			// P2.6 login sayaçları (login yoksa 0; başarı yalnızca doğrulanmış oturumda 1).
			"login_attempted": login.attempted,
			"login_succeeded": login.succeeded,
			"login_cookies":   login.cookies,
		},
		ScanID: newScanID(),
	}
	if note != "" {
		rep.NoisyNote = []string{note}
	}
	if wafChallenges > 0 {
		rep.NoisyNote = append(rep.NoisyNote, fmt.Sprintf(
			"WAF challenge detected (%d); responses behind the WAF may be incomplete",
			wafChallenges))
	}
	if proxyStats.DirectFallbacks > 0 {
		rep.NoisyNote = append(rep.NoisyNote, fmt.Sprintf(
			"proxy pool failed repeatedly; %d host(s) switched to direct traffic",
			proxyStats.DirectFallbacks))
	}
	if crawlFailed > 0 {
		rep.NoisyNote = append(rep.NoisyNote,
			"surface crawl failed; plugins only saw the root page and earlier phases")
	}
	if crawlURLsDropped > 0 {
		rep.NoisyNote = append(rep.NoisyNote, fmt.Sprintf(
			"crawl discovery cap reached; %d discovered URL(s) were not queued",
			crawlURLsDropped))
	}
	if crawlBodiesDropped > 0 {
		rep.NoisyNote = append(rep.NoisyNote, fmt.Sprintf(
			"crawl body memory budget reached; %d page/JS body copy(ies) were truncated or dropped",
			crawlBodiesDropped))
	}
	if rep.Findings == nil {
		rep.Findings = []*finding.Finding{}
	}
	if rep.Skipped == nil {
		rep.Skipped = []plugin.SkippedPlugin{}
	}
	return rep, nil
}

// countConfirmedFindings counts findings already at the top confidence tier.
// What: Used only for live progress deltas around browser verification.
func countConfirmedFindings(in []*finding.Finding) int {
	n := 0
	for _, f := range in {
		if f != nil && f.Confidence == plugin.ConfidenceConfirmed {
			n++
		}
	}
	return n
}

// isTLSCertError detects certificate-chain failures so the engine can stop
// once instead of emitting the same error for every plugin request.
func isTLSCertError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"failed to verify certificate", "certificate signed by unknown authority",
		"certificate has expired", "certificate is not valid", "x509:",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// crawlProgress crawl fazının tek satırlık canlı ilerleme metnini üretir.
// What: "37/500 sayfa · example.com/admin/users"
// Why: Faz göstergesi sayfa sayısı göstermezse uzun crawl donmuş görünür.
// crawlPageTarget returns the host/path label shown in crawl progress. The
// surrounding "N/M pages" text is translated by the UI.
func crawlPageTarget(pageURL string) string {
	u, err := url.Parse(pageURL)
	if err != nil || u.Host == "" {
		return pageURL
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return u.Host + path
}

// pluginRun tek plugin çalıştırmasının denetlenebilir sonucudur.
// What: findings + insan-okunur reason + ran (hata değil) + partial (yarım kaldı).
// Why: Rapor "atlandı" ile "bütçesine takıldı"yı ayırt etmeli.
type pluginRun struct {
	findings []*finding.Finding
	reason   string
	ran      bool
	partial  bool
}

// executeOneSafe adds a final panic shield around plugin dispatch. The plugin
// closure has its own recover, but a bug in the engine-side switch or point
// selection must not take down every other plugin in the scan.
func (e *Engine) executeOneSafe(parent context.Context, spec plugin.PluginSpec, target string, client *probe.Client, timeout time.Duration, points []loader.JSPoint) (run pluginRun) {
	defer func() {
		if r := recover(); r != nil {
			run = pluginRun{reason: fmt.Sprintf("error (panic): %v", r)}
		}
	}()
	return e.executeOne(parent, spec, target, client, timeout, points)
}

// executeOne runs a single plugin with fault isolation.
// What: Tier dispatch plus finding construction under timeout and recover.
// Why: Panic or timeout in one plugin must never stop the remaining scan.
func (e *Engine) executeOne(parent context.Context, spec plugin.PluginSpec, target string, client *probe.Client, timeout time.Duration, points []loader.JSPoint) pluginRun {
	var collected []*finding.Finding
	var collectMu sync.Mutex
	entry, ok := e.registry.Get(spec.ID)
	sourcePath := ""
	if ok {
		sourcePath = entry.SourcePath
	}
	res := plugin.ExecuteWithTimeout(parent, spec.ID, timeout, func(ctx context.Context) ([]plugin.Candidate, error) {
		pctx := plugin.WithPlugin(ctx, spec.ID, spec.Safe, spec.MaxRequests)
		var cands []plugin.Candidate
		switch spec.Tier {
		case plugin.TierYAML:
			file, err := loadTier1ForScan(sourcePath, spec.ID)
			if err != nil {
				return nil, err
			}
			// Redirect oracles need the original 3xx + Location response;
			// following that hop would erase the evidence they classify.
			pluginCtx := pctx
			if strings.EqualFold(file.Oracle.Name, "redirect") {
				pluginCtx = plugin.WithNoRedirect(pluginCtx)
			}
			// Passive read-only oracles share identical static GET responses.
			// Active/timing/redirect flows keep their own exchange. The shared
			// fetch runs on the scan context (not the first caller's plugin
			// timeout) but keeps the first plugin's quota attribution, so one
			// slow plugin cannot poison waiters and per-plugin caps still hold.
			cacheable := e.passiveCache != nil && tier1PassiveCacheEligible(file)
			fetchCtx := plugin.WithPlugin(parent, spec.ID, spec.Safe, spec.MaxRequests)
			sender := func(c context.Context, method, rawURL string, reqHeaders map[string]string, reqBody []byte) (int, http.Header, string, error) {
				if cacheable {
					if key, ok := passiveCacheKey(method, rawURL, reqHeaders, reqBody); ok {
						resp, err := e.passiveCache.GetOrFetch(c, key, func() (*probe.Response, error) {
							return client.Send(fetchCtx, method, rawURL, reqHeaders, reqBody)
						})
						if err != nil {
							return 0, nil, "", err
						}
						return resp.Status, resp.Headers, string(resp.Body), nil
					}
				}
				resp, err := client.Send(c, method, rawURL, reqHeaders, reqBody)
				if err != nil {
					return 0, nil, "", err
				}
				return resp.Status, resp.Headers, string(resp.Body), nil
			}
			results, err := loader.ExecuteTier1WithOptions(pluginCtx, &spec, file, target, sender, loader.Tier1Options{OOB: e.oobSource()})
			if err != nil {
				return nil, err
			}
			// Keşif geri beslemesi (ölçülmüş recall boşluğu): kökte sonuç
			// yoksa, keşfedilmiş injection noktalarında yalnızca eşleşen tek
			// parametre denenir. Aynı param adını taşıyan farklı endpoint'ler
			// bağımsız olabilir; ilk isabet sonrası durmak sonraki gerçek
			// bulguları gizlediği için cap'e kadar devam edilir. Bütçe plugin
			// politikasıyla aynı kapıdan geçer; bir adayın bütçe hatası
			// sonraki adayların sonuçlarını düşürmez.
			if len(results) == 0 {
				for _, dp := range tier1DiscoveryPoints(target, file.Request.ParamNames, points) {
					pointFile := *file
					pointFile.Request.ParamNames = []string{dp.Param}
					pointResults, _ := loader.ExecuteTier1WithOptions(pluginCtx, &spec, &pointFile, dp.URL, sender, loader.Tier1Options{OOB: e.oobSource()})
					results = append(results, pointResults...)
				}
			}
			for _, r := range results {
				rule, cwe := ruleForCandidate(spec.ID, r.Candidate, r.Evidence)
				f, err := finding.Build(spec, r.Candidate, r.Evidence, rule, cwe, "", "")
				if err != nil || f == nil {
					continue
				}
				collectMu.Lock()
				collected = append(collected, f)
				collectMu.Unlock()
				cands = append(cands, r.Candidate)
			}
			return cands, nil
		case plugin.TierJS:
			source, err := os.ReadFile(sourcePath)
			if err != nil {
				return nil, fmt.Errorf("js read %s: %w", sourcePath, err)
			}
			// Safe plugin'ler durum-değiştiren metoda dokunamaz: POST/PUT
			// noktaları yüzeyden çıkarılır (politika backstop'u durur; bu
			// yalnızca panic yerine sessiz-düzgün kapsam daraltmadır).
			pts := points
			if spec.Safe {
				pts = readOnlyJSPoints(points)
			}
			env := e.jsEnvForScan(pctx, target, client, pts)
			got, err := loader.ExecuteJS(pctx, &spec, string(source), env, timeout)
			if err != nil {
				return nil, err
			}
			for _, jc := range got {
				rule, cwe := ruleForCandidate(spec.ID, jc.Candidate, jc.Evidence)
				f, err := finding.Build(spec, jc.Candidate, jc.Evidence, rule, cwe, "", "")
				if err != nil || f == nil {
					continue
				}
				collectMu.Lock()
				collected = append(collected, f)
				collectMu.Unlock()
				cands = append(cands, jc.Candidate)
			}
			return cands, nil
		case plugin.TierNative:
			manifest, err := loadTier3ForScan(sourcePath)
			if err != nil {
				return nil, err
			}
			trust := map[string]string{}
			for id, sha := range e.trustDB {
				trust[id] = sha
			}
			poc, err := loader.SpawnPOC(pctx, sourcePath, manifest, trust, 10*time.Second)
			if err != nil {
				return nil, err
			}
			defer func() { _ = poc.Close() }()
			rawCands, err := poc.Run(pctx, target, timeout)
			if err != nil {
				return nil, err
			}
			for _, cand := range rawCands {
				ev, err := verifyTier3Candidate(pctx, client, target, cand.OracleName)
				if err != nil {
					continue
				}
				if ev == nil || ev.Verdict != oracle.VerdictAccept {
					continue
				}
				if cand.PluginID == "" {
					cand.PluginID = spec.ID
				}
				if cand.Target == "" {
					cand.Target = target
				}
				rule, cwe := ruleForCandidate(spec.ID, cand, ev)
				f, err := finding.Build(spec, cand, ev, rule, cwe, "", "")
				if err != nil || f == nil {
					continue
				}
				collectMu.Lock()
				collected = append(collected, f)
				collectMu.Unlock()
				cands = append(cands, cand)
			}
			return cands, nil
		default:
			return nil, fmt.Errorf("unknown tier %q: %w", spec.Tier, plugin.ErrValidation)
		}
	})
	switch res.Status {
	case plugin.StatusOK:
		return pluginRun{findings: collected, ran: true}
	case plugin.StatusSkipped:
		reason := res.Reason
		if reason == "" {
			reason = string(res.Status)
		}
		return pluginRun{findings: collected, reason: "skipped (bounded: " + reason + ")", ran: true}
	case plugin.StatusPartial:
		reason := res.Reason
		if reason == "" {
			reason = string(res.Status)
		}
		// Bütçe/rate tavanına takıldı: plugin koştu, karar veremeden durdu.
		// "skipped" demek yanıltıcı; partial olarak ayrı sayılır.
		return pluginRun{
			findings: collected,
			reason:   "partial (not fully executed): " + reason,
			ran:      true,
			partial:  true,
		}
	case plugin.StatusTimeout:
		if parent.Err() != nil {
			return pluginRun{findings: collected, reason: fmt.Sprintf("skipped (scan context: %v)", parent.Err()), ran: true}
		}
		reason := res.Reason
		if reason == "" {
			reason = string(res.Status)
		}
		return pluginRun{findings: collected, reason: "error (" + string(res.Status) + "): " + reason}
	case plugin.StatusError, plugin.StatusPolicyError, plugin.StatusPanic:
		reason := res.Reason
		if reason == "" {
			reason = string(res.Status)
		}
		// Policy and budget failures are skip-style; panics and timeouts are
		// error-style, but all keep the scan alive with an auditable reason.
		return pluginRun{findings: collected, reason: "error (" + string(res.Status) + "): " + reason}
	default:
		return pluginRun{findings: collected, reason: "error (" + string(res.Status) + "): " + res.Reason}
	}
}

// loadTier1ForScan reloads a Tier 1 file for live execution.
// What: Source-path reload shared by scan workers.
// Why: Registry holds metadata only; live runs need request and oracle blocks.
func loadTier1ForScan(sourcePath, id string) (*loader.Tier1File, error) {
	if strings.TrimSpace(sourcePath) == "" {
		return nil, fmt.Errorf("tier1 %s: empty source path: %w", id, plugin.ErrValidation)
	}
	_, file, err := loader.LoadTier1File(sourcePath)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// loadTier3ForScan reloads a Tier 3 manifest for live execution.
// What: Manifest reload without spawning the binary.
// Why: Spawn needs the pinned digest plus binary path from this exact file.
func loadTier3ForScan(sourcePath string) (*loader.Tier3Manifest, error) {
	if strings.TrimSpace(sourcePath) == "" {
		return nil, fmt.Errorf("tier3: empty source path: %w", plugin.ErrValidation)
	}
	_, manifest, err := loader.LoadTier3Manifest(sourcePath)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

// jsEnvForScan builds live JS bindings over the probe client with real surface and OOB.
// What: Dynamic injection points (URL, body, headers) plus probe, OOB, and
// (deep/opt-in) browser-verify backends.
// Why: Reference scripts expect points; live scans provide honest multi-point
// surface. OOB URL/domain bindings point at the operator's self-hosted server
// (never a public service), and callback polling uses the bounded window.
func (e *Engine) jsEnvForScan(pctx context.Context, target string, client *probe.Client, points []loader.JSPoint) *loader.JSEnv {
	sendOne := func(p loader.JSPoint, value string) (loader.JSResponse, error) {
		method := p.Method
		if method == "" {
			method = http.MethodGet
		}
		rawURL := p.URL
		if rawURL == "" {
			rawURL = target
		}
		var reqHeaders map[string]string
		var reqBody []byte

		switch strings.ToLower(p.ParamLocation) {
		case "body":
			if p.ParamName != "" {
				reqHeaders, reqBody = formRequestBody(p, p.ParamName, value)
			} else {
				reqHeaders = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				if ct := headerValue(p.Headers, "Content-Type"); ct != "" {
					reqHeaders["Content-Type"] = ct
				}
				reqBody = []byte(value)
			}
		case "header":
			reqHeaders = map[string]string{p.ParamName: value}
		case "fragment", "hash":
			// Fragments are never sent to the server. Only the browser probe
			// binding may exercise them; an HTTP replay here would silently
			// test the base page and could fabricate unrelated evidence.
			return loader.JSResponse{URL: rawURL}, nil
		default: // "query"
			rawURL = pointQueryURL(rawURL, p, value)
		}
		// Script-declared headers are merged on top of the derived set; an
		// explicit Content-Type therefore also overrides the form default.
		// They travel through the same PolicySession and scope checks.
		if len(p.Headers) > 0 {
			if reqHeaders == nil {
				reqHeaders = make(map[string]string, len(p.Headers))
			}
			for k, v := range p.Headers {
				reqHeaders[k] = v
			}
		}

		resp, err := client.Send(pctx, method, rawURL, reqHeaders, reqBody)
		if err != nil {
			return loader.JSResponse{}, err
		}
		headers := make(map[string]string, len(resp.Headers))
		for k, vals := range resp.Headers {
			if len(vals) > 0 {
				headers[k] = vals[0]
			}
		}
		rttMs := float64(resp.RTT.Milliseconds())
		if resp.RTT > 0 && rttMs == 0 {
			rttMs = float64(resp.RTT.Microseconds()) / 1000.0
		}
		return loader.JSResponse{Status: resp.Status, Headers: headers, Body: string(resp.Body), URL: rawURL, RTTMs: rttMs}, nil
	}

	jsPoints := points
	if len(jsPoints) == 0 {
		jsPoints = []loader.JSPoint{{URL: target, Method: http.MethodGet, ParamName: "q", ParamLocation: "query"}}
	}

	var oobProvider oob.Provider
	if strings.TrimSpace(e.cfg.OOBServer) != "" {
		oobProvider, _ = e.oobProvider()
	}

	env := &loader.JSEnv{
		Points: jsPoints,
		Send: func(p loader.JSPoint) (loader.JSResponse, error) {
			return sendOne(p, p.Value)
		},
		OOBEnabled:   oobProvider != nil && oobProvider.Enabled(),
		OOBNamespace: "scan",
		OOBCallbackSeen: func(corrID string) bool {
			// Bounded window (10s / 2 polls, docs/known-limits.md): any
			// protocol matches because the token is unique per payload.
			_, ok := oob.WaitForCallback(pctx, oobProvider, corrID, oob.DefaultWaitWindow, oob.DefaultWaitPolls)
			return ok
		},
		OOBCallbackSeenAny: func(corrIDs []string) []string {
			// Shared window across a plugin's whole payload corpus so the
			// per-payload token count never multiplies the wait budget.
			return oob.WaitForCallbacks(pctx, oobProvider, corrIDs, oob.DefaultWaitWindow, oob.DefaultWaitPolls)
		},
	}
	if oobProvider != nil && oobProvider.Enabled() {
		env.OOBDomain = func(c string) string { return oobProvider.DNSCallbackDomain(c) }
		env.OOBURL = func(c string) string { return oobProvider.HTTPCallbackURL(c) }
	}
	// Browser-verify seam: only when explicitly enabled; the stub build
	// refuses through Supported() so a default binary never fabricates a
	// browser proof.
	if e.cfg.BrowserVerify {
		if verifier, _ := e.browserVerifier(); verifier != nil {
			env.BrowserVerify = func(payloadURL, controlURL string) (bool, bool, bool, error) {
				t, c, err := verifier(pctx, payloadURL, controlURL)
				return err == nil, t, c, err
			}
			env.BrowserProbe = func(p loader.JSPoint, payload string) (bool, bool, bool, error) {
				base := strings.TrimSpace(p.URL)
				if base == "" {
					base = target
				}
				payloadURL := pointValueURL(base, p, payload)
				controlURL := pointValueURL(base, p, controlNeutralValue)
				if payloadURL == "" || controlURL == "" || payloadURL == controlURL {
					return false, false, false, fmt.Errorf("browser probe: payload and control URL must differ")
				}
				triggered, clean, err := verifier(pctx, payloadURL, controlURL)
				if err != nil {
					return false, false, false, err
				}
				return true, triggered, clean, nil
			}
		}
	}
	return env
}

// readOnlyJSPoints safe Tier 2 plugin'lere verilen yüzeydir.
// What: Yalnızca GET/HEAD/OPTIONS noktaları (boş metot GET sayılır).
// Why: Safe plugin POST noktasında politika ihlaliyle panic'lemek yerine
// hiç görmez; aktif plugin'ler tam yüzeyi almaya devam eder.
func readOnlyJSPoints(points []loader.JSPoint) []loader.JSPoint {
	out := make([]loader.JSPoint, 0, len(points))
	for _, p := range points {
		switch strings.ToUpper(strings.TrimSpace(p.Method)) {
		case "", http.MethodGet, http.MethodHead, http.MethodOptions:
			out = append(out, p)
		}
	}
	return out
}

// pluginSurfacePoints bounds the fan-out of Tier 2 plugins over very large
// discovered surfaces. A single JS plugin can otherwise issue several
// requests per point; when seven such plugins share one target limiter, the
// later plugins all expire while waiting for tokens. The selection is stable
// and prefers points that carry an observed value or form context.
func pluginSurfacePoints(cfg Config, spec plugin.PluginSpec, points []loader.JSPoint) []loader.JSPoint {
	if spec.Tier != plugin.TierJS || len(points) == 0 {
		return points
	}
	// These scripts enforce their own request cap while ranking the full
	// surface. Truncating before they rank it would hide valid late points.
	switch spec.ID {
	case "sqli-error-based", "ssrf-blind-oob", "xss-reflected-basic", "xss-stored-two-step":
		return points
	}
	limit := 16
	switch cfg.Profile {
	case config.ProfileDeep:
		limit = 32
	case config.ProfileAggressive:
		limit = 48
	}
	if len(points) <= limit {
		return points
	}

	var tiers [4][]loader.JSPoint
	seen := make(map[string]struct{}, len(points))
	for _, p := range points {
		key := strings.ToUpper(strings.TrimSpace(p.Method)) + "|" + p.URL + "|" + strings.ToLower(strings.TrimSpace(p.ParamLocation)) + "|" + p.ParamName
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		location := strings.ToLower(strings.TrimSpace(p.ParamLocation))
		tier := 3
		if len(p.FormValues) > 0 && (location == "query" || location == "body") {
			tier = 0
		} else if (location == "query" || location == "body") && (p.ParamName != "" || p.Value != "") {
			tier = 1
		} else if location == "fragment" || location == "hash" {
			tier = 2
		}
		tiers[tier] = append(tiers[tier], p)
	}

	out := make([]loader.JSPoint, 0, limit)
	for _, tier := range tiers {
		for _, p := range tier {
			if len(out) == limit {
				return out
			}
			out = append(out, p)
		}
	}
	return out
}

// tier1DiscoveryPointCap bounds discovery feedback per Tier 1 plugin run.
// What: At most this many discovered points get a root-miss fallback attempt.
// Why: Keeps the added requests bounded even on large discovered surfaces.
const tier1DiscoveryPointCap = 6

// tier1DiscoveryPoint pairs a discovered injection-point URL with the single
// query parameter that matched the plugin's declared parameter list.
type tier1DiscoveryPoint struct {
	URL   string
	Param string
}

// tier1DiscoveryPoints returns discovered query injection points carrying a
// parameter name the Tier 1 plugin declared.
// What: Bounded, parameter-matched discovery feedback for root-only probing.
// Why: Multi-endpoint surfaces made root-only probing miss real findings
// (measured recall gap). Each point pins exactly one declared parameter so the
// fallback costs one parameter's probes instead of the full matrix; host,
// method, and location filters keep the extra requests targeted and in-scope.
func tier1DiscoveryPoints(target string, paramNames []string, points []loader.JSPoint) []tier1DiscoveryPoint {
	if len(paramNames) == 0 || len(points) == 0 {
		return nil
	}
	want := make(map[string]bool, len(paramNames))
	for _, p := range paramNames {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			want[p] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	tu, err := url.Parse(target)
	if err != nil {
		return nil
	}
	var out []tier1DiscoveryPoint
	seen := map[string]bool{}
	for _, pt := range points {
		if len(out) >= tier1DiscoveryPointCap {
			break
		}
		if pt.URL == "" || pt.URL == target || seen[pt.URL] {
			continue
		}
		param := strings.ToLower(strings.TrimSpace(pt.ParamName))
		if !want[param] {
			continue
		}
		if pt.ParamLocation != "" && !strings.EqualFold(pt.ParamLocation, "query") {
			continue
		}
		if m := strings.ToUpper(strings.TrimSpace(pt.Method)); m != "" && m != http.MethodGet {
			continue
		}
		pu, err := url.Parse(pt.URL)
		if err != nil || !strings.EqualFold(pu.Host, tu.Host) {
			continue
		}
		seen[pt.URL] = true
		out = append(out, tier1DiscoveryPoint{URL: pt.URL, Param: param})
	}
	return out
}

// verifyTier3Candidate verifies a native candidate with engine oracles.
// What: Probe fetch plus oracle dispatch for Tier 3 header, redirect, cookie, cors, version, error, reflection.
// Why: Native binaries propose; engine evidence confirms findings.
func verifyTier3Candidate(pctx context.Context, client *probe.Client, target, oracleName string) (*oracle.Evidence, error) {
	resp, err := client.Send(pctx, http.MethodGet, target, nil, nil)
	if err != nil {
		return nil, err
	}
	cls := baseline.ClassifyStatic(resp.Status, resp.Headers, resp.Body)
	switch strings.ToLower(strings.TrimSpace(oracleName)) {
	case "header", "":
		var o oracle.HeaderOracle
		return o.Verify(pctx, cls, false, oracle.HeaderParams{Headers: resp.Headers})
	case "redirect":
		var o oracle.RedirectOracle
		return o.Verify(pctx, cls, false, oracle.RedirectParams{
			Location: resp.Headers.Get("Location"), PayloadHost: "",
			ControlNoRedir: true, ResolveDNS: false,
		})
	case "cookie":
		var o oracle.CookieOracle
		return o.Verify(pctx, cls, false, oracle.CookieParams{Headers: resp.Headers, Target: target})
	case "cors":
		var o oracle.CORSOracle
		return o.Verify(pctx, cls, false, oracle.CORSParams{Headers: resp.Headers})
	case "version":
		var o oracle.VersionOracle
		return o.Verify(pctx, cls, false, oracle.VersionParams{Banner: string(resp.Body), Mode: "banner"})
	case "error":
		var o oracle.ErrorSignatureOracle
		return o.Verify(pctx, cls, false, oracle.ErrorSignatureParams{Body: string(resp.Body)})
	case "reflection":
		var o oracle.ReflectionOracle
		return o.Verify(pctx, string(resp.Body), resp.Headers, cls, false, oracle.ReflectionParams{Canary: "gash", Contexts: []string{"html", "attr", "script"}})
	default:
		return nil, fmt.Errorf("tier3 oracle %q not supported live: %w", oracleName, plugin.ErrValidation)
	}
}

// infraTargets explicit --infra-target girdilerini host:port olarak döndürür;
// liste boşsa hedef host + verilen varsayılan port kullanılır.
func (e *Engine) infraTargets(defaultHost, defaultPort string) []string {
	var out []string
	for _, t := range e.cfg.InfraTargets {
		addr := strings.TrimSpace(t)
		if addr == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, defaultPort)
		}
		out = append(out, addr)
	}
	if len(out) > 0 {
		return out
	}
	return []string{net.JoinHostPort(defaultHost, defaultPort)}
}

// infraHosts DB taraması için hedef host listesidir (tekilleştirilmiş);
// liste boşsa hedef host döner.
func (e *Engine) infraHosts(defaultHost string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, t := range e.cfg.InfraTargets {
		trimmed := strings.TrimSpace(t)
		if trimmed == "" {
			continue
		}
		if h, _, err := net.SplitHostPort(trimmed); err == nil {
			add(h)
			continue
		}
		add(trimmed)
	}
	if len(out) > 0 {
		return out
	}
	return []string{defaultHost}
}

// smuggleGateOK smuggle recon kapısıdır (registry Spec'inden okunur):
// --active + agresif profil + profilde smuggle dedektörü (hepsi şart;
// dışı → denetim izli skip). Kapı mantığı tek kaynaktan gelir
// (internal/detector Spec.Evaluate); bu sarmalayıcı yalnızca test ve rapor
// okunabilirliği için durur.
func smuggleGateOK(e *Engine) bool {
	if e == nil || e.detectors == nil {
		return false
	}
	d, ok := e.detectors.Get(smuggle.PluginID)
	if !ok {
		return false
	}
	allowed, _ := d.Spec().Evaluate(e.detectorPolicy())
	return allowed
}

// protoAllow proto kontrollerinin kapsam kararıdır.
// What: Hedef host her zaman izinli (açık tarama niyeti); diğer host'lar yalnızca
// explicit --scope ile (domain/CIDR/URL-prefix eşleşmesi).
// Why: Proto kontroller plugin HTTP hattının dışındadır; aynı fail-closed
// kapsam burada da uygulanır (kapsam-dışı istek yok).
func (e *Engine) protoAllow(target *url.URL) proto.AllowHost {
	targetHost := strings.ToLower(target.Hostname())
	sm := NewScopeManager(e.cfg.Scope)
	sm.SetOriginalTarget(target.String())
	return func(host string) bool {
		h := strings.ToLower(strings.TrimSpace(host))
		if h == "" {
			return false
		}
		if h == targetHost {
			return true
		}
		if len(e.cfg.Scope) == 0 {
			return false // open mod: proto kontrolleri yalnızca hedefte koşar
		}
		checkURL := &url.URL{Scheme: "https", Host: h}
		return sm.CheckScope(context.Background(), checkURL) == nil
	}
}
