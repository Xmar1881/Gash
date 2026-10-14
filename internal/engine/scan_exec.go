// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"github.com/Xmar1881/Gash/internal/oob"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
	"github.com/Xmar1881/Gash/internal/proto"
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
	case "oob":
		return "GASH-008", "CWE-918"
	case "tls":
		return "GASH-024", "CWE-295"
	case "dns":
		return "GASH-025", "CWE-693"
	case "tcp":
		return "GASH-026", "CWE-200"
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
	case strings.Contains(id, "idor") || strings.Contains(id, "bola"):
		return "GASH-005", "CWE-639"
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

	policy := plugin.NewPolicySession(plugin.PolicyConfig{
		MaxRequestsPerTarget: e.cfg.MaxRequestsPerTarget,
		MaxRequestsTotal:     e.cfg.MaxRequestsTotal,
		Scope:                e.cfg.Scope,
		RatePerSecond:        e.cfg.RatePerSecond,
		MaxResponseBytes:     5 * 1024 * 1024,
	}, nil)
	// P1.3: Set original target for scope rebinding detection
	policy.SetOriginalTarget(target)
	// P2.5: kimlik bağlamı probe'a gömülür (requires_auth kapısı New'de açıldı).
	var extraHeaders map[string]string
	if e.cfg.Auth != nil {
		extraHeaders = e.cfg.Auth.HeaderMap()
	}
	client := probe.NewClient(probe.Options{
		Policy:         policy,
		RequestTimeout: 15 * time.Second,
		MaxBytes:       5 * 1024 * 1024,
		ExtraHeaders:   extraHeaders,
		// WAF bypass yalnızca agresif profilde: blok yanıtı WAFDetected
		// işaretlenir, sınırlı varyant aynı politika/kapsam içinden denenir.
		// Varsayılan taramada stealth davranışı YOKTUR (§14).
		EnableWAFBypass: e.cfg.Profile == config.ProfileAggressive,
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
	protoFindings, protoSkipped := e.runProtoRecon(ctx, target)
	allFindings := protoFindings
	var execSkipped []plugin.SkippedPlugin
	execSkipped = append(execSkipped, protoSkipped...)
	errorCount := 0

	// Attack surface discovery: probe target to extract form inputs, query params, and links
	var surfacePoints []loader.JSPoint
	initResp, err := client.Send(ctx, http.MethodGet, target, nil, nil)
	if err == nil && initResp != nil {
		e.mergeSurfaceTech(initResp.Headers, nil, initResp.Body)
		injected := discovery.ExtractSurface(target, initResp.Body)
		for _, ip := range injected {
			surfacePoints = append(surfacePoints, loader.JSPoint{
				URL:           ip.URL,
				Method:        ip.Method,
				ParamName:     ip.ParamName,
				ParamLocation: ip.ParamLocation,
				Value:         ip.Value,
			})
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
			})
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
	// Görev C: çift-kullanıcı BOLA matrisi. --active + iki kimlik şart;
	// bulgular daima tentative (sahiplik elle doğrulanır).
	var matrixRequests int64
	if e.cfg.Active && e.HasDualAuth() {
		matrixFindings, mreq := e.runCrossUserMatrix(ctx, client, surfacePoints)
		matrixRequests = mreq
		allFindings = append(allFindings, matrixFindings...)
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
			"scheduled":       len(ordered),
			"skipped":         len(allSkipped),
			"findings":        len(deduped),
			"errors":          errorCount,
			"waf_detected":    int(wafDet),
			"waf_bypassed":    int(wafByp),
			"fuzz_requests":   int(fuzzRequests),
			"matrix_requests": int(matrixRequests),
			"detected_tech":   len(e.detectedTech),
			"detected_caps":   len(e.detectedCaps),
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
			sender := func(c context.Context, method, rawURL string) (int, http.Header, string, error) {
				resp, err := client.Send(c, method, rawURL, nil, nil)
				if err != nil {
					return 0, nil, "", err
				}
				return resp.Status, resp.Headers, string(resp.Body), nil
			}
			results, err := loader.ExecuteTier1(pctx, &spec, file, target, sender)
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
			env := jsEnvForScan(pctx, target, client, e.cfg.OOBServer, pts)
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
// What: Dynamic injection points (URL, body, headers) plus probe and OOB backends.
// Why: Reference scripts expect points; live scans provide honest multi-point surface.
func jsEnvForScan(pctx context.Context, target string, client *probe.Client, oobServer string, points []loader.JSPoint) *loader.JSEnv {
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
			reqHeaders = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
			if p.ParamName != "" {
				form := url.Values{}
				form.Set(p.ParamName, value)
				reqBody = []byte(form.Encode())
			} else {
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
	if oobServer != "" {
		oobProvider = oob.NewSelfHostedProvider(oobServer, "")
	}

	return &loader.JSEnv{
		Points: jsPoints,
		Send: func(p loader.JSPoint) (loader.JSResponse, error) {
			return sendOne(p, p.Value)
		},
		OOBEnabled:   oobServer != "",
		OOBNamespace: "scan",
		OOBCallbackSeen: func(corrID string) bool {
			if oobProvider == nil || !oobProvider.Enabled() {
				return false
			}
			ev, err := oobProvider.PollCallback(pctx, corrID)
			return err == nil && ev != nil
		},
	}
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
// What: Profil kapılı (tls/dns safe'de; tcp yalnızca --active + açık --tcp-banner),
// kapsam-izinli, süre-sınırlı pasif gözlem. Hata = bulgusuz (tarama durmaz).
// Why: Protokol yüzeyi plugin HTTP hattının dışındadır (el sıkışması/DNS okuma);
// ayrı recon adımı safe varsayılanı bozmaz (yıkıcı işlem yok).
func (e *Engine) runProtoRecon(ctx context.Context, target string) ([]*finding.Finding, []plugin.SkippedPlugin) {
	var out []*finding.Finding
	var skipped []plugin.SkippedPlugin
	u, err := url.Parse(target)
	if err != nil {
		return nil, nil
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil, nil
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
	return out, skipped
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
			return false // implicit scope: yalnızca hedef host
		}
		checkURL := &url.URL{Scheme: "https", Host: h}
		return sm.CheckScope(context.Background(), checkURL) == nil
	}
}
