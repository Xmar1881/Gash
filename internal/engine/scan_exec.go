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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/config"
	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/headless"
	"github.com/Xmar1881/Gash/internal/oob"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
	"github.com/Xmar1881/Gash/internal/proto"
	"github.com/Xmar1881/Gash/internal/smuggle"
	"golang.org/x/time/rate"
)

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
	id := strings.ToLower(strings.TrimSpace(pluginID))
	switch {
	case strings.Contains(id, "ssrf"):
		return "GASH-008", "CWE-918"
	case strings.Contains(id, "content") || strings.Contains(id, "exposed-path"):
		return "GASH-028", "CWE-200"
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

// runLive executes scheduled plugins against a validated target.
// What: Probe-backed Tier1/Tier2/Tier3 execution plus correlate and stats.
// Why: Single live path serves CLI scans and engine e2e tests identically.
func (e *Engine) runLive(ctx context.Context, target string, ordered []plugin.PluginSpec, skipped []plugin.SkippedPlugin) (*Report, error) {
	timeoutMs := e.cfg.PluginTimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 30000
	}
	pluginTimeout := time.Duration(timeoutMs) * time.Millisecond

	var parsedProxy *url.URL
	if strings.TrimSpace(e.cfg.ProxyURL) != "" {
		var err error
		parsedProxy, err = url.Parse(strings.TrimSpace(e.cfg.ProxyURL))
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", e.cfg.ProxyURL, err)
		}
	}

	maxResponseBytes := e.cfg.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = 5 * 1024 * 1024
	}
	policy := e.sharedPolicy
	if policy == nil {
		policy = plugin.NewPolicySession(plugin.PolicyConfig{
			MaxRequestsPerTarget: e.cfg.MaxRequestsPerTarget,
			MaxRequestsTotal:     e.cfg.MaxRequestsTotal,
			Scope:                e.cfg.Scope,
			RatePerSecond:        e.cfg.RatePerSecond,
			MaxResponseBytes:     maxResponseBytes,
			ProxyURL:             parsedProxy,
		}, nil)
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
		ProxyURL:        parsedProxy,
	})

	parallelism := e.cfg.Parallelism
	if parallelism <= 0 {
		parallelism = 8
	}
	if parallelism > len(ordered) {
		parallelism = len(ordered)
	}
	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	var mu sync.Mutex
	// Faz 2: TLS el sıkışma sonucu burada yakalanır ve altyapı derin TLS
	// denetimine geçirilir; sertifika/zincir olguları ek dial açmadan aynı
	// gözlemden türetilir.
	protoFindings, protoSkipped, tlsObs := e.runProtoReconTLS(ctx, target)
	allFindings := protoFindings
	var execSkipped []plugin.SkippedPlugin
	execSkipped = append(execSkipped, protoSkipped...)
	// Faz 0/1/2 altyapı recon: SSH banner + DB port envanteri + derin TLS
	// gözlemi. Tüm bayraklar kapalıysa sıfır ek trafik; kapsam fail-closed.
	infraFindings, infraSkipped, infraStats := e.runInfraReconTLS(ctx, target, tlsObs)
	allFindings = append(allFindings, infraFindings...)
	execSkipped = append(execSkipped, infraSkipped...)
	errorCount := 0

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
		"js_secrets_found": 0, "js_maps_fetched": 0,
	}
	crawlRes, err := discovery.Crawl(ctx, client, target, crawlOpts)
	var surfacePoints []loader.JSPoint
	if err == nil && crawlRes != nil {
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
		// Pasif JS recon: crawl'ın topladığı same-origin JS gövdeleri +
		// kaynak haritaları; endpoint'ler yüzeye beslenir, sırlar GASH-067.
		jsFindings, jsPoints, jsStats := e.runJSRecon(ctx, target, client, crawlRes)
		allFindings = append(allFindings, jsFindings...)
		surfacePoints = append(surfacePoints, jsPoints...)
		for k, v := range jsStats {
			jsReconStats[k] = v
		}
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
	}

	// İçerik keşfi (wordlist): --active kapılı engine-recon (GASH-028).
	// Tier1-YAML değil, engine-recon — gerekçe: teknoloji-koşullu wordlist
	// seçimi + hassas path'te HEAD-only + smart-recurse (yedek uzantı,
	// derinlik ≤2) + crawler geri-besleme tek-istekli YAML kalıbına sığmaz;
	// kanıt motor-içidir (B3, finding.Build bypass — proto recon disiplini).
	// Safe taramada sessizdir (profil disiplini); destructive YOK (GET/HEAD).
	var contentRequests, contentFollowRequests, contentFindingCount int
	if e.cfg.Active {
		fpTech := discovery.TechFingerprint{Capabilities: map[string]bool{}}
		for t := range e.detectedTech {
			fpTech.Tech = append(fpTech.Tech, t)
		}
		cres, cerr := discovery.DiscoverContent(ctx, client, target, fpTech, nil, discovery.DefaultContentOptions())
		if cerr == nil && cres != nil {
			contentRequests = cres.Requests
			contentFindingCount = len(cres.Findings)
			allFindings = append(allFindings, cres.Findings...)
			for _, p := range cres.DiscoveredPaths {
				surfacePoints = append(surfacePoints, loader.JSPoint{URL: p, Method: http.MethodGet})
			}
			// Crawler geri-besleme: dizin-benzeri isabetlerin altında
			// sınırlı mini-crawl (en fazla 3 dizin × 10 sayfa, derinlik 1).
			dirs := 0
			for _, p := range cres.DiscoveredPaths {
				if dirs >= 3 {
					break
				}
				if !strings.HasSuffix(p, "/") {
					continue
				}
				dirs++
				follow, ferr := discovery.Crawl(ctx, client, p, discovery.CrawlOptions{
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
		}
	}

	// Görev B: atıl fuzz motoru canlı döngüde. Yalnızca --active koşar
	// (güvenli varsayılan sessizdir); anomali → tentative Finding.
	var fuzzRequests int64
	if e.cfg.Active {
		fuzzFindings, freq := e.runActiveFuzz(ctx, target, client, surfacePoints)
		fuzzRequests = freq
		allFindings = append(allFindings, fuzzFindings...)
	}
	// Görev B2: tam-form replay fuzz. Tek-alan gövdeleri sunucu doğrulaması
	// ve CSRF kapısında düşer; keşfedilen formlar tüm alanlarıyla (token'lar
	// tazelenerek) tekrarlanır. Yalnızca --active.
	var formRequests int64
	if e.cfg.Active && crawlRes != nil && len(crawlRes.Forms) > 0 {
		formFindings, formReq := e.runActiveFormFuzz(ctx, target, client, crawlRes.Forms)
		formRequests = formReq
		allFindings = append(allFindings, formFindings...)
	}
	// Görev C: çift-kullanıcı BOLA matrisi. --active + iki kimlik şart;
	// bulgular daima tentative (sahiplik elle doğrulanır).
	var matrixRequests int64
	if e.cfg.Active && e.HasDualAuth() {
		matrixFindings, mreq := e.runCrossUserMatrix(ctx, client, surfacePoints)
		matrixRequests = mreq
		allFindings = append(allFindings, matrixFindings...)
	}

	// Request smuggling (CL.TE/TE.CL/TE.TE): --active + --aggressive kapılı
	// engine-recon (GASH-033, CWE-444). Tier1-YAML değil, engine-recon —
	// gerekçe: net/http chunk çerçevelemeyi denetlemez; ham-TCP dial +
	// keep-alive çift-isabet (muğlak+takip) tek-istekli YAML kalıbına sığmaz;
	// kanıt motor-içidir (finding.Build bypass — proto/content-discovery
	// recon disiplini). Hedef kullanıcının verdiği host'tur (Nuclei/Burp
	// smuggler modeli); kapsam preflight yalnızca --scope verilmişse uygulanır.
	// Kapı dışı (safe/standard/deep dahil) sessiz değil, denetim izli
	// skip'tir; kapsam-dışı soket AÇILMAZ (≤10 istek, 5s tavan).
	var smuggleRequests int
	if smuggleGateOK(e) {
		var smuggleAllow smuggle.AllowHost
		if len(e.cfg.Scope) > 0 {
			targetURL, perr := url.Parse(target)
			if perr != nil {
				// Scope verilmiş ama hedef ayrıştırılamadı: fail-closed kapı.
				smuggleAllow = func(string) bool { return false }
			} else {
				// Strict mod: smuggler yalnızca hedefe dial eder; hedef
				// kapsam-dışıysa soket AÇILMAZ (plugin hattıyla tutarlı).
				// Hedef-host muafiyeti (protoAllow) BURADA uygulanmaz.
				sm := NewScopeManager(e.cfg.Scope)
				sm.SetOriginalTarget(targetURL.String())
				scheme := targetURL.Scheme
				port := targetURL.Port()
				if port == "" {
					if scheme == "https" {
						port = "443"
					} else {
						port = "80"
					}
				}
				smuggleAllow = func(host string) bool {
					checkURL := &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port)}
					return sm.CheckScope(context.Background(), checkURL) == nil
				}
			}
		}
		sres, serr := smuggle.Scan(ctx, target, smuggle.Options{
			Timeout:    5 * time.Second,
			Allow:      smuggleAllow,
			Active:     e.cfg.Active,
			Aggressive: e.cfg.Profile == config.ProfileAggressive,
		})
		switch {
		case serr != nil && errors.Is(serr, plugin.ErrScopeViolation):
			execSkipped = append(execSkipped, plugin.SkippedPlugin{PluginID: smuggle.PluginID, Reason: "skipped (smuggle-probe scope violation, no socket opened)"})
		case serr != nil:
			// Ölçülemeyen hedef sessiz geçilir (TCP banner recon disiplini);
			// tarama durmaz, sahte bulgu YOK.
		case sres != nil:
			smuggleRequests = sres.Requests
			if sres.Finding != nil {
				allFindings = append(allFindings, sres.Finding)
			}
			if sres.Skipped != "" {
				execSkipped = append(execSkipped, plugin.SkippedPlugin{PluginID: smuggle.PluginID, Reason: sres.Skipped})
			}
		}
	} else {
		execSkipped = append(execSkipped, plugin.SkippedPlugin{PluginID: smuggle.PluginID, Reason: "skipped (smuggle-probe requires --active --aggressive)"})
	}

	for _, spec := range ordered {
		wg.Add(1)
		go func(s plugin.PluginSpec) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			found, reason, ok := e.executeOne(ctx, s, target, client, pluginTimeout, surfacePoints)
			mu.Lock()
			defer mu.Unlock()
			if !ok {
				execSkipped = append(execSkipped, plugin.SkippedPlugin{PluginID: s.ID, Reason: reason})
				errorCount++
				return
			}
			allFindings = append(allFindings, found...)
			if reason != "" {
				execSkipped = append(execSkipped, plugin.SkippedPlugin{PluginID: s.ID, Reason: reason})
			}
		}(spec)
	}
	wg.Wait()

	// Generic browser-verify pass (opt-in, deep builds): static XSS findings
	// may reach confirmed only through a real trigger plus a clean control;
	// otherwise the static tier is preserved untouched.
	if e.cfg.BrowserVerify {
		execSkipped = append(execSkipped, e.verifyBrowserFindings(ctx, allFindings)...)
	}

	deduped := Correlate(allFindings)
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
	rep := &Report{
		Target:   target,
		Findings: deduped,
		Skipped:  allSkipped,
		Stats: map[string]int{
			"scheduled":        len(ordered),
			"skipped":          len(allSkipped),
			"findings":         len(deduped),
			"errors":           errorCount,
			"waf_detected":     int(wafDet),
			"waf_bypassed":     int(wafByp),
			"fuzz_requests":    int(fuzzRequests),
			"form_requests":    int(formRequests),
			"matrix_requests":  int(matrixRequests),
			"content_requests": contentRequests + contentFollowRequests,
			"content_findings": contentFindingCount,
			"smuggle_requests": smuggleRequests,
			// Pasif JS recon sayaçları (crawl kapalı/başarısızken 0).
			"js_files_fetched":   jsReconStats["js_files_fetched"],
			"js_endpoints_found": jsReconStats["js_endpoints_found"],
			"js_secrets_found":   jsReconStats["js_secrets_found"],
			"js_maps_fetched":    jsReconStats["js_maps_fetched"],
			"detected_tech":      len(e.detectedTech),
			"detected_caps":      len(e.detectedCaps),
			"ssh_checks":         infraStats["ssh_checks"],
			"db_ports_scanned":   infraStats["db_ports_scanned"],
			"db_open_ports":      infraStats["db_open_ports"],
			"tls_deep_checks":    infraStats["tls_deep_checks"],
			// Faz 1 altyapı sayaçları (kapalıyken 0).
			"ssh_handshake_checks": infraStats["ssh_handshake_checks"],
			"db_unauth_checks":     infraStats["db_unauth_checks"],
		},
		ScanID: newScanID(),
	}
	if note != "" {
		rep.NoisyNote = []string{note}
	}
	if rep.Findings == nil {
		rep.Findings = []*finding.Finding{}
	}
	if rep.Skipped == nil {
		rep.Skipped = []plugin.SkippedPlugin{}
	}
	return rep, nil
}

// executeOne runs a single plugin with fault isolation.
// What: Tier dispatch plus finding construction under timeout and recover.
// Why: Panic or timeout in one plugin must never stop the remaining scan.
func (e *Engine) executeOne(parent context.Context, spec plugin.PluginSpec, target string, client *probe.Client, timeout time.Duration, points []loader.JSPoint) ([]*finding.Finding, string, bool) {
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
			sender := func(c context.Context, method, rawURL string, reqHeaders map[string]string, reqBody []byte) (int, http.Header, string, error) {
				resp, err := client.Send(c, method, rawURL, reqHeaders, reqBody)
				if err != nil {
					return 0, nil, "", err
				}
				return resp.Status, resp.Headers, string(resp.Body), nil
			}
			results, err := loader.ExecuteTier1WithOptions(pctx, &spec, file, target, sender, loader.Tier1Options{OOB: e.oobSource()})
			if err != nil {
				return nil, err
			}
			for _, r := range results {
				rule, cwe := ruleForPlugin(spec.ID, r.Candidate.OracleName)
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
				rule, cwe := ruleForPlugin(spec.ID, jc.Candidate.OracleName)
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
				rule, cwe := ruleForPlugin(spec.ID, cand.OracleName)
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
		return collected, "", true
	case plugin.StatusSkipped, plugin.StatusTimeout, plugin.StatusError, plugin.StatusPolicyError, plugin.StatusPanic:
		reason := res.Reason
		if reason == "" {
			reason = string(res.Status)
		}
		// Policy and budget failures are skip-style; panics and timeouts are
		// error-style, but all keep the scan alive with an auditable reason.
		return collected, "error (" + string(res.Status) + "): " + reason, false
	default:
		return collected, "error (" + string(res.Status) + "): " + res.Reason, false
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
				reqBody = []byte(value)
			}
		case "header":
			reqHeaders = map[string]string{p.ParamName: value}
		default: // "query"
			if p.ParamName != "" {
				built, err := withScanQueryParam(rawURL, p.ParamName, value)
				if err == nil {
					rawURL = built
				}
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
		oobProvider = oob.NewSelfHostedProvider(e.cfg.OOBServer, "")
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
		switch {
		case e.cfg.BrowserVerifyFunc != nil:
			env.BrowserVerify = func(payloadURL, controlURL string) (bool, bool, bool, error) {
				t, c, err := e.cfg.BrowserVerifyFunc(pctx, payloadURL, controlURL)
				return err == nil, t, c, err
			}
		case headless.Supported() && headless.Available():
			env.BrowserVerify = func(payloadURL, controlURL string) (bool, bool, bool, error) {
				res, err := headless.VerifyXSS(pctx, payloadURL, controlURL, headless.DefaultTimeout)
				if err != nil {
					return false, false, false, err
				}
				return true, res.Triggered, res.ControlClean, nil
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

// withScanQueryParam sets one query value on a URL.
// What: Deterministic point-to-request mapping for live JS sends.
// Why: Centralizes URL mutation so scans and tests cannot diverge.
func withScanQueryParam(target, param, value string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
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

// runProtoRecon DNS/TLS/TCP protokol kontrollerini koşar (P2.1).
// Faz 2 sarmalayıcısıdır: TLS gözlemi dışa taşınmaz (eski imza korunur).
func (e *Engine) runProtoRecon(ctx context.Context, target string) ([]*finding.Finding, []plugin.SkippedPlugin) {
	findings, skipped, _ := e.runProtoReconTLS(ctx, target)
	return findings, skipped
}

// runProtoReconTLS DNS/TLS/TCP kontrollerini koşar ve TLS el sıkışma
// gözlemini döner (Faz 2: altyapı derin TLS denetimi aynı gözlemi yeniden
// kullanır; ek dial açılmaz).
// What: Profil kapılı (tls/dns safe'de; tcp yalnızca --active + açık --tcp-banner),
// kapsam-izinli, süre-sınırlı pasif gözlem. Hata = bulgusuz (tarama durmaz).
// Why: Protokol yüzeyi plugin HTTP hattının dışındadır (el sıkışması/DNS okuma);
// ayrı recon adımı safe varsayılanı bozmaz (yıkıcı işlem yok).
func (e *Engine) runProtoReconTLS(ctx context.Context, target string) ([]*finding.Finding, []plugin.SkippedPlugin, *proto.TLSResult) {
	var out []*finding.Finding
	var skipped []plugin.SkippedPlugin
	var tlsObs *proto.TLSResult
	u, err := url.Parse(target)
	if err != nil {
		return nil, nil, nil
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil, nil, nil
	}
	allow := e.protoAllow(u)
	po := proto.Options{Timeout: 10 * time.Second, Allow: allow}

	// TLS: yalnızca https hedefte, tls dedektörü açıksa.
	if e.detectorEnabled("tls") && strings.EqualFold(u.Scheme, "https") {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		func(check context.Context) {
			c, cancel := context.WithTimeout(check, 12*time.Second)
			defer cancel()
			res, err := proto.CheckTLS(c, net.JoinHostPort(host, port), po)
			if err != nil || res == nil {
				return
			}
			tlsObs = res
			for _, pf := range proto.TLSFindings(target, res) {
				pf := pf
				out = append(out, pf.ToFinding())
			}
		}(ctx)
	}
	// DNS: IP literal hariç, dns dedektörü açıksa.
	if e.detectorEnabled("dns") && net.ParseIP(host) == nil {
		func(check context.Context) {
			c, cancel := context.WithTimeout(check, 12*time.Second)
			defer cancel()
			res, err := proto.CheckDNS(c, host, po)
			if err != nil || res == nil {
				return
			}
			for _, pf := range proto.DNSFindings(target, res) {
				pf := pf
				out = append(out, pf.ToFinding())
			}
			// CAA: aynı dns dedektörü, aynı kapsam/izin; hata = sessiz (FP yok).
			caaRes, cerr := proto.CheckCAA(c, host, po)
			if cerr != nil || caaRes == nil {
				return
			}
			for _, pf := range proto.CAAFindings(target, caaRes) {
				pf := pf
				out = append(out, pf.ToFinding())
			}
		}(ctx)
	}
	// TCP banner: açık bayrak + --active + tcp dedektörü (hepsi şart).
	if len(e.cfg.TCPBanners) > 0 && e.detectorEnabled("tcp") {
		if !e.cfg.Active {
			// Aktivasyon yoksa her bayrak denetim iziyle skip'e düşer (sessiz drop yok).
			for _, addr := range e.cfg.TCPBanners {
				if strings.TrimSpace(addr) == "" {
					continue
				}
				skipped = append(skipped, plugin.SkippedPlugin{
					PluginID: "proto-tcp-banner",
					Reason:   "skipped (tcp-banner " + strings.TrimSpace(addr) + " requires --active)",
				})
			}
		} else {
			for _, addr := range e.cfg.TCPBanners {
				addr := strings.TrimSpace(addr)
				if addr == "" {
					continue
				}
				func(check context.Context) {
					c, cancel := context.WithTimeout(check, 12*time.Second)
					defer cancel()
					res, err := proto.GrabBanner(c, addr, po)
					if err != nil || res == nil {
						return
					}
					for _, pf := range proto.BannerFindings(target, res) {
						pf := pf
						out = append(out, pf.ToFinding())
					}
				}(ctx)
			}
		}
	}
	return out, skipped, tlsObs
}

// runInfraRecon altyapı kontrollerini koşar (eski imza sarmalayıcısı).
func (e *Engine) runInfraRecon(ctx context.Context, target string) ([]*finding.Finding, []plugin.SkippedPlugin, map[string]int) {
	return e.runInfraReconTLS(ctx, target, nil)
}

// runInfraReconTLS altyapı kontrollerini koşar (Faz 0 MVP + Faz 1/2 derin
// denetim). tlsObs, runProtoReconTLS'ten gelen TLS el sıkışma gözlemidir;
// Faz 2 sertifika/zincir bulguları bu gözlemden ek dial açmadan türetilir
// (nil ise derin TLS dalı tek bir yerel CheckTLS ile tazeler).
// What: Profil + --active kapılı, kapsam-izinli, rate-limitli ve semaforlu
// salt-okuma gözlem: SSH banner (GASH-052) + sürüm→bildirim eşlemesi (GASH-056),
// DB port envanteri (GASH-053), derin TLS sürüm kabulü + sertifika/zincir
// olguları (GASH-024), SSH KEXINIT algoritma denetimi (GASH-054) ve DB unauth
// erişim denetimi (GASH-055). Bayraklar kapalıysa sıfır ek trafik; kapsam-dışı
// host'ta sıfır soket (fail-closed).
// Why: Altyapı yüzeyi plugin HTTP hattının dışındadır; her kapı denetim izli
// skip üretir (sessiz drop yok) ve hiçbir gözlem yıkıcı işlem içermez.
func (e *Engine) runInfraReconTLS(ctx context.Context, target string, tlsObs *proto.TLSResult) ([]*finding.Finding, []plugin.SkippedPlugin, map[string]int) {
	stats := map[string]int{
		"ssh_checks": 0, "ssh_handshake_checks": 0,
		"db_ports_scanned": 0, "db_open_ports": 0, "db_unauth_checks": 0,
		"tls_deep_checks": 0,
	}
	if !e.cfg.SSHAudit && !e.cfg.DBPortScan && !e.cfg.TLSAuditDeep && !e.cfg.SSHHandshakeAudit && !e.cfg.DBUnauth {
		return nil, nil, stats
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, nil, stats
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil, nil, stats
	}
	allow := e.protoAllow(u)
	timeout := e.cfg.InfraTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	po := proto.Options{Timeout: timeout, Allow: allow}
	var out []*finding.Finding
	var skipped []plugin.SkippedPlugin

	sshOn := e.cfg.SSHAudit
	sshHandshakeOn := e.cfg.SSHHandshakeAudit
	dbOn := e.cfg.DBPortScan
	dbUnauthOn := e.cfg.DBUnauth
	tlsDeepOn := e.cfg.TLSAuditDeep
	if sshOn {
		switch {
		case !e.cfg.Active:
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-ssh-banner", Reason: "skipped (requires --active)"})
			sshOn = false
		case !e.detectorEnabled("ssh"):
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-ssh-banner",
				Reason: fmt.Sprintf("skipped (detector ssh disabled by profile %s)", e.EffectiveProfile().Name)})
			sshOn = false
		}
	}
	// Faz 1: SSH KEXINIT denetimi de aktif probdur (--active + ssh dedektörü).
	if sshHandshakeOn {
		switch {
		case !e.cfg.Active:
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-ssh-handshake", Reason: "skipped (requires --active)"})
			sshHandshakeOn = false
		case !e.detectorEnabled("ssh"):
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-ssh-handshake",
				Reason: fmt.Sprintf("skipped (detector ssh disabled by profile %s)", e.EffectiveProfile().Name)})
			sshHandshakeOn = false
		}
	}
	if dbOn {
		switch {
		case !e.cfg.Active:
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-db-ports", Reason: "skipped (requires --active)"})
			dbOn = false
		case !e.detectorEnabled("db"):
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-db-ports",
				Reason: fmt.Sprintf("skipped (detector db disabled by profile %s)", e.EffectiveProfile().Name)})
			dbOn = false
		}
	}
	// Faz 1: DB unauth denetimi aynı kapı disiplinine tabidir.
	if dbUnauthOn {
		switch {
		case !e.cfg.Active:
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-db-unauth", Reason: "skipped (requires --active)"})
			dbUnauthOn = false
		case !e.detectorEnabled("db"):
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-db-unauth",
				Reason: fmt.Sprintf("skipped (detector db disabled by profile %s)", e.EffectiveProfile().Name)})
			dbUnauthOn = false
		}
	}
	if tlsDeepOn && !e.detectorEnabled("tls") {
		skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-tls-deep",
			Reason: fmt.Sprintf("skipped (detector tls disabled by profile %s)", e.EffectiveProfile().Name)})
		tlsDeepOn = false
	}
	if tlsDeepOn && !strings.EqualFold(u.Scheme, "https") {
		skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-tls-deep",
			Reason: "skipped (tls-audit-deep requires an https target)"})
		tlsDeepOn = false
	}
	if !sshOn && !sshHandshakeOn && !dbOn && !dbUnauthOn && !tlsDeepOn {
		return nil, skipped, stats
	}

	parallelism := e.cfg.InfraParallelism
	if parallelism <= 0 {
		parallelism = 4
	}
	var limiter *rate.Limiter
	if e.cfg.InfraRatePerSecond > 0 {
		burst := parallelism
		if burst < 1 {
			burst = 1
		}
		limiter = rate.NewLimiter(rate.Limit(e.cfg.InfraRatePerSecond), burst)
	}
	wait := func() bool {
		if limiter == nil {
			return true
		}
		return limiter.Wait(ctx) == nil
	}
	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	var mu sync.Mutex

	if sshOn {
		for _, addr := range e.infraTargets(host, "22") {
			h, p, aerr := net.SplitHostPort(addr)
			if aerr != nil {
				continue
			}
			if !allow(h) {
				skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-ssh-banner",
					Reason: "skipped (infra target " + addr + " outside scope, no socket opened)"})
				continue
			}
			wg.Add(1)
			go func(h, p, addr string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if !wait() {
					return
				}
				c, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				res, err := proto.CheckSSH(c, h, p, po)
				mu.Lock()
				defer mu.Unlock()
				stats["ssh_checks"]++
				if err != nil || res == nil {
					return
				}
				fs := proto.SSHFindings(target, res)
				// Faz 2: sürüm→bildirim eşlemesi (GASH-056) tetiklendiğinde jenerik
				// "ssh-old-software" sinyali düşürülür; protokol 1.x bulgusu korunur.
				vfs := proto.SSHVersionFindings(target, res.Software)
				if len(vfs) > 0 {
					kept := fs[:0]
					for _, f := range fs {
						if f.Evidence["signal"] != "ssh-old-software" {
							kept = append(kept, f)
						}
					}
					fs = kept
				}
				for _, pf := range fs {
					pf := pf
					out = append(out, pf.ToFinding())
				}
				for _, pf := range vfs {
					pf := pf
					out = append(out, pf.ToFinding())
				}
			}(h, p, addr)
		}
	}

	// Faz 1: SSH KEXINIT algoritma denetimi (GASH-054). Faz 0 ile aynı hedef
	// seçimi/kapsam/limiter/semafor; anahtar değişimi tamamlanmaz, auth yok.
	if sshHandshakeOn {
		for _, addr := range e.infraTargets(host, "22") {
			h, p, aerr := net.SplitHostPort(addr)
			if aerr != nil {
				continue
			}
			if !allow(h) {
				skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-ssh-handshake",
					Reason: "skipped (infra target " + addr + " outside scope, no socket opened)"})
				continue
			}
			wg.Add(1)
			go func(h, p, addr string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if !wait() {
					return
				}
				c, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				res, err := proto.AuditSSHHandshake(c, h, p, po)
				mu.Lock()
				defer mu.Unlock()
				stats["ssh_handshake_checks"]++
				if err != nil || res == nil {
					return
				}
				for _, pf := range proto.SSHHandshakeFindings(target, res) {
					pf := pf
					out = append(out, pf.ToFinding())
				}
			}(h, p, addr)
		}
	}

	if dbOn {
		ports := e.cfg.DBPorts
		if len(ports) == 0 {
			ports = proto.DefaultDBPorts()
		}
		maxPorts := e.cfg.MaxInfraPorts
		if maxPorts <= 0 {
			maxPorts = 20
		}
		if len(ports) > maxPorts {
			ports = ports[:maxPorts]
		}
		for _, h := range e.infraHosts(host) {
			if !allow(h) {
				skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-db-ports",
					Reason: "skipped (infra target " + h + " outside scope, no socket opened)"})
				continue
			}
			for _, port := range ports {
				port := port
				wg.Add(1)
				go func(h string, port int) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					if !wait() {
						return
					}
					c, cancel := context.WithTimeout(ctx, timeout)
					defer cancel()
					results, err := proto.ScanDBPorts(c, h, []int{port}, po)
					if err != nil || len(results) == 0 {
						return
					}
					fs := proto.DBPortFindings(results)
					mu.Lock()
					defer mu.Unlock()
					stats["db_ports_scanned"] += len(results)
					for _, r := range results {
						if r.Open {
							stats["db_open_ports"]++
						}
					}
					for _, pf := range fs {
						pf := pf
						out = append(out, pf.ToFinding())
					}
				}(h, port)
			}
		}
	}

	// Faz 1: DB kimlik doğrulamasız erişim denetimi (GASH-055). Port listesi
	// DBPortScan ile aynıdır (MaxInfraPorts tavanlı); port taraması kapalı
	// portu zaten elediyse burada aynı sınırlarla yeniden dial edilir (basit
	// ve güvenli: tek zararsız istek, kapsam/limiter/semafor aynı).
	if dbUnauthOn {
		ports := e.cfg.DBPorts
		if len(ports) == 0 {
			ports = proto.DefaultDBPorts()
		}
		maxPorts := e.cfg.MaxInfraPorts
		if maxPorts <= 0 {
			maxPorts = 20
		}
		if len(ports) > maxPorts {
			ports = ports[:maxPorts]
		}
		for _, h := range e.infraHosts(host) {
			if !allow(h) {
				skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-db-unauth",
					Reason: "skipped (infra target " + h + " outside scope, no socket opened)"})
				continue
			}
			for _, port := range ports {
				port := port
				wg.Add(1)
				go func(h string, port int) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					if !wait() {
						return
					}
					c, cancel := context.WithTimeout(ctx, timeout)
					defer cancel()
					res, err := proto.CheckDBUnauth(c, h, port, po)
					mu.Lock()
					defer mu.Unlock()
					stats["db_unauth_checks"]++
					if err != nil || res == nil {
						return
					}
					for _, pf := range proto.DBUnauthFindings(target, *res) {
						pf := pf
						out = append(out, pf.ToFinding())
					}
				}(h, port)
			}
		}
	}

	if tlsDeepOn {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		addr := net.JoinHostPort(host, port)
		if !allow(host) {
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: "proto-tls-deep",
				Reason: "skipped (tls-audit-deep target outside scope, no socket opened)"})
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if !wait() {
					return
				}
				c, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				// Faz 2: sertifika/zincir olguları aynı el sıkışmadan türetilir;
				// runProtoReconTLS gözlemi yoksa (hata/dedektör kapısı) tek dial.
				obs := tlsObs
				if obs == nil {
					res, err := proto.CheckTLS(c, addr, po)
					if err != nil || res == nil {
						return
					}
					obs = res
				}
				deepFS := proto.TLSDeepFindings(target, obs)
				probes := 0
				var versionFS []proto.Finding
				if audit, err := proto.CheckTLSVersionSupport(c, addr, po); err == nil && audit != nil {
					versionFS = proto.TLSAuditFindings(target, audit)
					probes = len(audit.Probes)
				}
				mu.Lock()
				defer mu.Unlock()
				stats["tls_deep_checks"] += probes
				for _, pf := range versionFS {
					pf := pf
					out = append(out, pf.ToFinding())
				}
				for _, pf := range deepFS {
					pf := pf
					out = append(out, pf.ToFinding())
				}
			}()
		}
	}
	wg.Wait()
	return out, skipped, stats
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

// smuggleGateOK smuggle recon kapısıdır: --active + agresif profil +
// profilde smuggle dedektörü (hepsi şart; dışı → denetim izli skip).
func smuggleGateOK(e *Engine) bool {
	if e == nil || !e.cfg.Active {
		return false
	}
	if e.cfg.Profile != config.ProfileAggressive {
		return false
	}
	return e.detectorEnabled("smuggle")
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
