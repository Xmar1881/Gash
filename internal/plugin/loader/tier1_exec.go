// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package loader executes Tier 1 plugins against live targets.
// What: Turns declarative request blocks into real HTTP plus oracle verification.
// Why: Gives the drop-in end-to-end path a single auditable runner instead of
// scattering request logic across the scheduler and the CLI.
package loader

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// Sender issues one HTTP request and returns the classified response parts.
// What: Minimal transport seam between Tier 1 logic and real (or mocked) HTTP.
// Why: Tests inject canned responses while production passes the probe client.
// Extended (GASH-034..039): carries optional request headers and body so
// host-header injection (Host), GraphQL introspection (POST body), and
// HeaderParams/verb-tamper variants can be declared without engine changes.
type Sender func(ctx context.Context, method, rawURL string, reqHeaders map[string]string, reqBody []byte) (status int, headers http.Header, body string, err error)

// Tier1Result pairs a candidate with the evidence that produced it.
// What: Executable outcome of one Tier 1 request attempt.
// Why: The engine builds findings from evidence, never from bare candidates.
type Tier1Result struct {
	// Candidate is the engine-facing candidate.
	Candidate plugin.Candidate
	// Evidence is the oracle verdict behind the candidate.
	Evidence *oracle.Evidence
}

// OOBSource supplies single-use callback tokens for Tier 1 OOB payload
// templates and waits (bounded) for a matching callback.
// What: Decouples the loader from the self-hosted provider while keeping the
// token discipline in one place: one fresh token per payload attempt.
// Why: A Tier 1 OOB payload can only become a finding through a real callback;
// template expansion without a provider would ship literal placeholders.
type OOBSource interface {
	// Generate returns a fresh correlation ID plus the DNS domain and HTTP
	// callback URL that point at the operator's self-hosted OOB server.
	Generate() (correlationID, dnsDomain, httpURL string, err error)
	// Wait reports whether a callback for the token arrived inside the
	// bounded window. false means "no callback" (no finding), never
	// "inconclusive that may be upgraded".
	Wait(ctx context.Context, correlationID string) bool
	// WaitAny reports every token in the set that received a callback
	// inside ONE bounded window (shared by all tokens).
	// What: Lets a multi-payload detector ship all variants first and pay
	// the callback window once instead of once per payload.
	// Why: Per-payload windows would multiply past plugin time budgets and
	// turn honest misses into timeouts; token uniqueness is unchanged.
	WaitAny(ctx context.Context, correlationIDs []string) []string
}

// Tier1Options carries optional execution knobs. The zero value reproduces
// the pre-OOB behavior exactly (no token, CallbackSeen false, no finding).
type Tier1Options struct {
	// OOB, when non-nil, expands {{OOB_DOMAIN}}/{{OOB_URL}}/{{CORRELATION}}
	// placeholders in `oracle: oob` payloads and polls for the callback.
	OOB OOBSource

	// pending accumulates OOB attempts awaiting the shared post-loop wait;
	// unexported because callers never inject it (tests drive via OOB).
	pending []pendingOOB
}

// pendingOOB is one sent OOB payload waiting for its bounded callback check.
// What: Everything needed to rebuild the candidate once a token matches.
// Why: The request must go out per payload, but verification is deferred so
// the bounded wait window is paid once per plugin run, not once per payload.
type pendingOOB struct {
	pluginID string
	target   string
	cls      baseline.Classification
	method   string
	rawURL   string
	param    string
	value    string
	corr     string
	ns       string
}

// ExecuteTier1 runs a Tier 1 file against one target URL.
// What: Sends declarative requests then verifies each response with the pinned oracle.
// Why: Keeps Tier 1 behavior identical for scans, fixtures, and CLI tests.
func ExecuteTier1(ctx context.Context, spec *plugin.PluginSpec, file *Tier1File, target string, send Sender) ([]Tier1Result, error) {
	return ExecuteTier1WithOptions(ctx, spec, file, target, send, Tier1Options{})
}

// ExecuteTier1WithOptions is ExecuteTier1 plus optional OOB callback wiring.
// What: Same request/oracle flow; OOB-templated payloads get a unique token
// and a bounded callback wait before the oracle decides.
// Why: The live confirmed path for blind classes must go through one code
// path shared by scans and tests (no plugin-side fake confirmation).
func ExecuteTier1WithOptions(ctx context.Context, spec *plugin.PluginSpec, file *Tier1File, target string, send Sender, opts Tier1Options) ([]Tier1Result, error) {
	if spec == nil || file == nil {
		return nil, fmt.Errorf("tier1 execute: nil spec or file: %w", plugin.ErrValidation)
	}
	if send == nil {
		return nil, fmt.Errorf("tier1 execute: nil sender: %w", plugin.ErrValidation)
	}
	method := file.Request.Method
	if method == "" {
		method = http.MethodGet
	}

	// Paths: sabit yol listesi (GASH-036/037/038). Declared yollar kök yerine
	// geçer; her yol tek executeSingle denemesidir (param/payload yok).
	if len(file.Request.Paths) > 0 {
		var out []Tier1Result
		for _, p := range file.Request.Paths {
			pathURL, err := joinTargetPath(target, p)
			if err != nil {
				return nil, fmt.Errorf("tier1 execute: bad target %q: %w", target, err)
			}
			res, err := executeSingle(ctx, spec, file, pathURL, method, "", "", send, &opts)
			if err != nil {
				return nil, err
			}
			out = append(out, res...)
		}
		out = append(out, finishPendingOOB(ctx, &opts)...)
		return out, nil
	}

	params := file.Request.ParamNames
	if len(params) == 0 {
		params = []string{""}
	}
	payloads := effectivePayloads(file.Request)
	var out []Tier1Result
	for _, param := range params {
		for _, payload := range payloads {
			res, err := executeSingle(ctx, spec, file, target, method, param, payload, send, &opts)
			if err != nil {
				return nil, err
			}
			out = append(out, res...)
			if len(res) > 0 {
				break // ilk kabul eden payload yeter: istek bütçesi korunur
			}
		}
	}
	// OOB attempts are verified in one shared bounded window after every
	// payload is on the wire; unmatched tokens yield no finding at all.
	out = append(out, finishPendingOOB(ctx, &opts)...)
	return out, nil
}

// finishPendingOOB drains collected OOB attempts with ONE bounded wait.
// What: Polls every token inside the source's single window; accepted tokens
// become candidates whose evidence is the real callback.
// Why: Keeps the request-per-payload model while bounding total wait time so
// multi-variant plugins stay inside their time budget. A miss stays a miss.
func finishPendingOOB(ctx context.Context, opts *Tier1Options) []Tier1Result {
	if opts == nil || opts.OOB == nil || len(opts.pending) == 0 {
		return nil
	}
	ids := make([]string, 0, len(opts.pending))
	for _, p := range opts.pending {
		if p.corr != "" {
			ids = append(ids, p.corr)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	matched := opts.OOB.WaitAny(ctx, ids)
	if len(matched) == 0 {
		return nil
	}
	matchedSet := make(map[string]bool, len(matched))
	for _, id := range matched {
		matchedSet[id] = true
	}
	o := oracle.OOBOracle{Enabled: true}
	var out []Tier1Result
	for _, p := range opts.pending {
		if !matchedSet[p.corr] {
			continue
		}
		ev, err := o.Verify(ctx, p.cls, false, oracle.OOBParams{
			CorrelationID: p.corr,
			Namespace:     p.ns,
			CallbackSeen:  true,
		})
		if err != nil || ev.Verdict != oracle.VerdictAccept {
			continue
		}
		out = append(out, Tier1Result{Candidate: plugin.Candidate{
			PluginID:       p.pluginID,
			Target:         p.target,
			InjectionPoint: plugin.InjectionPoint{URL: p.rawURL, Method: p.method, ParamName: p.param, ParamLocation: "query", Value: p.value},
			OracleName:     "oob",
			OracleParams:   map[string]string{"correlation": p.corr, "namespace": p.ns},
		}, Evidence: ev})
	}
	opts.pending = nil
	return out
}

// effectivePayloads tek payload + varyant listesini deterministik sıraya koyar.
// What: Payload boşsa tek boş deneme döner (eski davranış aynen korunur).
// Why: Çoklu payload desteği mevcut pluginleri değiştirmeden deney sunar.
func effectivePayloads(r Tier1Request) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(r.Payload)
	for _, p := range r.Payloads {
		add(p)
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

// joinTargetPath base target'a plugin-beyanlı yolu ekler (GASH-036/037/038).
// What: Path ve query korunur; yollar tek '/' ile birleştirilir.
// Why: Yol listesi pluginlerinin URL üretimi tek noktadan ve deterministik kalsın.
func joinTargetPath(target, path string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if path == "" {
		return u.String(), nil
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")
	return u.String(), nil
}

// executeRateLimit bütçeli burst ile eksik rate-limit ekranı yapar (GASH-032).
// What: Aynı endpoint'e N istek (params burst, default 20, tavan 50) gönderip
// 429/lockout/rate-limit sinyali yokluğunu tentative bulguya dönüştürür.
// Why: Tekil prob politika yokluğunu kanıtlamaz; burst gözlemsel tavanda kalır
// (tentative). Tüm istekler policy-session Sender'dan geçer: --scope dışı
// hedefe istek YOK, profil + max_requests bütçesi motorca zorlanır, isimsiz
// GET burst'ünde credential stuffing ve hesap kilitleme riski YOKTUR.
func executeRateLimit(ctx context.Context, spec *plugin.PluginSpec, file *Tier1File, target, method, param, rawURL string, status int, headers http.Header, body string, oracleParams map[string]any, send Sender) ([]Tier1Result, error) {
	burst := getIntParam(oracleParams, "burst", 20)
	if burst < 1 {
		burst = 1
	}
	if burst > 50 {
		burst = 50
	}
	statuses := []int{status}
	lastStatus, lastHeaders, lastBody := status, headers, body
	for i := 1; i < burst; i++ {
		s, h, b, err := send(ctx, method, rawURL, nil, nil)
		if err != nil {
			break // bütçe/kapsam kesintisi: toplananla devam (sinyal uydurma YOK)
		}
		statuses = append(statuses, s)
		lastStatus, lastHeaders, lastBody = s, h, b
	}
	cls := baseline.ClassifyStatic(lastStatus, lastHeaders, []byte(lastBody))
	var o oracle.HeaderOracle
	ev, err := o.Verify(ctx, cls, false, oracle.HeaderParams{
		Headers: lastHeaders,
		Mode:    "ratelimit",
		Body:    lastBody,
		Status:  lastStatus,
		Burst:   statuses,
	})
	if err != nil {
		return nil, err
	}
	if ev.Verdict != oracle.VerdictAccept {
		return nil, nil
	}
	return []Tier1Result{{Candidate: plugin.Candidate{
		PluginID:       spec.ID,
		Target:         target,
		InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query"},
		OracleName:     "header",
		OracleParams:   map[string]string{"mode": "ratelimit"},
	}, Evidence: ev}}, nil
}

// oobPayloadPlaceholders are the template tokens Tier 1 OOB payloads may use.
// Expansion happens per attempt with a fresh single-use correlation ID.
var oobPayloadPlaceholders = []string{"{{OOB_DOMAIN}}", "{{OOB_URL}}", "{{CORRELATION}}"}

// expandOOBPayload substitutes the OOB template tokens. The correlation token
// is single-use: every call receives its own ID from OOBSource.Generate.
func expandOOBPayload(payload, correlationID, dnsDomain, httpURL string) string {
	r := strings.NewReplacer(
		"{{OOB_DOMAIN}}", dnsDomain,
		"{{OOB_URL}}", httpURL,
		"{{CORRELATION}}", correlationID,
	)
	return r.Replace(payload)
}

func executeSingle(ctx context.Context, spec *plugin.PluginSpec, file *Tier1File, target, method, param, payload string, send Sender, opts *Tier1Options) ([]Tier1Result, error) {
	// OOB template expansion: `oracle: oob` payloads carry placeholders that
	// must point at the operator's self-hosted server before the request is
	// built. Without a provider the payload is sent verbatim and no callback
	// can match ([[OOB]] stays inert), so no finding is fabricated.
	effPayload := payload
	oobCorr := ""
	if strings.EqualFold(file.Oracle.Name, "oob") && opts != nil && opts.OOB != nil {
		corr, domain, cbURL, gerr := opts.OOB.Generate()
		if gerr == nil && corr != "" {
			oobCorr = corr
			effPayload = expandOOBPayload(payload, corr, domain, cbURL)
		}
	}
	rawURL := target
	if param != "" {
		var err error
		rawURL, err = withQueryParam(target, param, effPayload)
		if err != nil {
			return nil, fmt.Errorf("tier1 execute: bad target %q: %w", target, err)
		}
	}
	reqHeaders := file.Request.Headers
	var reqBody []byte
	if file.Request.Body != "" {
		reqBody = []byte(file.Request.Body)
	}
	status, headers, body, err := send(ctx, method, rawURL, reqHeaders, reqBody)
	if err != nil {
		return nil, fmt.Errorf("tier1 execute: probe %s: %w", rawURL, err)
	}
	cls := baseline.ClassifyStatic(status, headers, []byte(body))

	// Parse oracle params from YAML
	oracleParams := file.Oracle.Params
	if oracleParams == nil {
		oracleParams = make(map[string]any)
	}

	switch strings.ToLower(file.Oracle.Name) {
	case "header":
		var o oracle.HeaderOracle
		mode := getStringParam(oracleParams, "mode", "security")
		if mode == "ratelimit" {
			return executeRateLimit(ctx, spec, file, target, method, param, rawURL, status, headers, body, oracleParams, send)
		}
		if mode == "host_header" {
			return executeHostHeader(ctx, spec, file, target, method, rawURL, body, oracleParams, send)
		}
		var reqHeadersChk http.Header
		if rh, ok := oracleParams["request_headers"]; ok {
			if rhMap, ok := rh.(map[string]any); ok {
				reqHeadersChk = make(http.Header)
				for k, v := range rhMap {
					if vs, ok := v.([]any); ok {
						for _, vi := range vs {
							reqHeadersChk.Add(k, fmt.Sprintf("%v", vi))
						}
					} else {
						reqHeadersChk.Set(k, fmt.Sprintf("%v", v))
					}
				}
			}
		}
		ev, err := o.Verify(ctx, cls, false, oracle.HeaderParams{
			Headers:        headers,
			Mode:           mode,
			RequestHeaders: reqHeadersChk,
			Body:           body,
		})
		if err != nil {
			return nil, err
		}
		if ev.Verdict != oracle.VerdictAccept {
			return nil, nil
		}
		return []Tier1Result{{Candidate: plugin.Candidate{
			PluginID:       spec.ID,
			Target:         target,
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method},
			OracleName:     "header",
			OracleParams:   map[string]string{"mode": mode},
		}, Evidence: ev}}, nil
	case "cookie":
		var o oracle.CookieOracle
		ev, err := o.Verify(ctx, cls, false, oracle.CookieParams{Headers: headers, Target: target})
		if err != nil {
			return nil, err
		}
		if ev.Verdict != oracle.VerdictAccept {
			return nil, nil
		}
		return []Tier1Result{{Candidate: plugin.Candidate{
			PluginID:       spec.ID,
			Target:         target,
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method},
			OracleName:     "cookie",
		}, Evidence: ev}}, nil
	case "cors":
		var o oracle.CORSOracle
		requestOrigin := getStringParam(oracleParams, "request_origin", "")
		ev, err := o.Verify(ctx, cls, false, oracle.CORSParams{Headers: headers, RequestOrigin: requestOrigin})
		if err != nil {
			return nil, err
		}
		if ev.Verdict != oracle.VerdictAccept {
			return nil, nil
		}
		return []Tier1Result{{Candidate: plugin.Candidate{
			PluginID:       spec.ID,
			Target:         target,
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method},
			OracleName:     "cors",
		}, Evidence: ev}}, nil
	case "redirect":
		payloadHost := payloadHostname(payload)
		loc := headers.Get("Location")
		controlClean := true
		if param != "" {
			neutralURL, err := withQueryParam(target, param, "gash-control-neutral")
			if err == nil {
				if cStatus, cHeaders, _, cErr := send(ctx, method, neutralURL, nil, nil); cErr == nil {
					_ = cStatus
					if cl := cHeaders.Get("Location"); cl != "" && isAbsolute(cl) {
						controlClean = false
					}
				}
			}
		}
		var o oracle.RedirectOracle
		ev, err := o.Verify(ctx, cls, false, oracle.RedirectParams{
			Location: loc, PayloadHost: payloadHost,
			ControlNoRedir: controlClean, ResolveDNS: false,
		})
		if err != nil {
			return nil, err
		}
		if ev.Verdict != oracle.VerdictAccept {
			return nil, nil
		}
		return []Tier1Result{{Candidate: plugin.Candidate{
			PluginID:       spec.ID,
			Target:         target,
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query", Value: payload},
			OracleName:     "redirect",
			OracleParams:   map[string]string{"location": loc},
		}, Evidence: ev}}, nil
	case "error":
		var o oracle.ErrorSignatureOracle
		mode := getStringParam(oracleParams, "mode", "sqli")
		signatureSet := getStringSliceParam(oracleParams, "signature_set")
		controlBody := ""
		if param != "" {
			neutralURL, err := withQueryParam(target, param, "gash-control-neutral")
			if err == nil {
				if cStatus, _, cBody, cErr := send(ctx, method, neutralURL, nil, nil); cErr == nil && cStatus == http.StatusOK {
					controlBody = cBody
				}
			}
		} else if strings.EqualFold(mode, "backup_file") {
			// Soft-404 kontrolü (GASH-037): imza genel hata/SPA sayfasından
			// gelmiyorsa kanıt değeri vardır. Kontrol isteği tek ve isimsizdir.
			ctrlURL := rawURL + ".gash-soft404-check"
			if cStatus, _, cBody, cErr := send(ctx, http.MethodGet, ctrlURL, nil, nil); cErr == nil && cStatus == http.StatusOK {
				controlBody = cBody
			}
		}
		ev, err := o.Verify(ctx, cls, false, oracle.ErrorSignatureParams{
			Body:         body,
			ControlBody:  controlBody,
			SignatureSet: signatureSet,
			Mode:         mode,
		})
		if err != nil {
			return nil, err
		}
		if ev.Verdict != oracle.VerdictAccept {
			return nil, nil
		}
		return []Tier1Result{{Candidate: plugin.Candidate{
			PluginID:       spec.ID,
			Target:         target,
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query", Value: payload},
			OracleName:     "error",
			OracleParams:   map[string]string{"mode": mode},
		}, Evidence: ev}}, nil
	case "version":
		var o oracle.VersionOracle
		mode := getStringParam(oracleParams, "mode", "banner")
		bannerRegex := getStringParam(oracleParams, "banner_regex", "")
		ev, err := o.Verify(ctx, cls, false, oracle.VersionParams{
			Banner:      body, // Use response body as banner for graphql modes
			BannerRegex: bannerRegex,
			Mode:        mode,
		})
		if err != nil {
			return nil, err
		}
		if ev.Verdict != oracle.VerdictAccept {
			return nil, nil
		}
		return []Tier1Result{{Candidate: plugin.Candidate{
			PluginID:       spec.ID,
			Target:         target,
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method},
			OracleName:     "version",
			OracleParams:   map[string]string{"mode": mode},
		}, Evidence: ev}}, nil
	case "reflection":
		var o oracle.ReflectionOracle
		canary := payload
		if c := getStringParam(oracleParams, "canary", ""); c != "" {
			canary = c
		}
		// SSRF (GASH-005/012) çok-sağlayıcı: payload'a özel kanarya eşlemesi.
		if m, ok := oracleParams["canary_by_payload"].(map[string]any); ok {
			if v, ok := m[payload].(string); ok && v != "" {
				canary = v
			}
		}
		ctrlBody := ""
		if param != "" {
			neutralURL, err := withQueryParam(target, param, "gash-control-neutral")
			if err == nil {
				if _, _, cBody, cErr := send(ctx, method, neutralURL, nil, nil); cErr == nil {
					ctrlBody = cBody
				}
			}
		}
		reqExecutable := false
		if v, ok := oracleParams["require_executable_context"]; ok {
			if b, ok := v.(bool); ok {
				reqExecutable = b
			}
		}
		contexts := getStringSliceParam(oracleParams, "contexts")
		if len(contexts) == 0 {
			contexts = []string{"html", "attr", "attr-executable", "script", "url", "url-executable"}
		}
		ev, err := o.Verify(ctx, body, headers, cls, false, oracle.ReflectionParams{
			Canary:                   canary,
			Contexts:                 contexts,
			RequireExecutableContext: reqExecutable,
			ControlBody:              ctrlBody,
		})
		if err != nil {
			return nil, err
		}
		if ev.Verdict != oracle.VerdictAccept {
			return nil, nil
		}
		return []Tier1Result{{Candidate: plugin.Candidate{
			PluginID:       spec.ID,
			Target:         target,
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query", Value: payload},
			OracleName:     "reflection",
			OracleParams:   map[string]string{"canary": canary},
		}, Evidence: ev}}, nil
	case "timing":
		var o oracle.TimingOracle
		minDelayMs := getFloat64Param(oracleParams, "min_delay_ms", 5000)
		repeats := getIntParam(oracleParams, "repeats", 3)
		strategy := getStringParam(oracleParams, "strategy", "mann-whitney-u")
		var delaySamples, controlSamples []float64

		// Delay samples
		for i := 0; i < repeats; i++ {
			t0 := time.Now()
			_, _, _, _ = send(ctx, method, rawURL, reqHeaders, reqBody)
			delaySamples = append(delaySamples, float64(time.Since(t0).Milliseconds()))
		}

		// Control samples
		neutralURL := target
		if param != "" {
			if nu, err := withQueryParam(target, param, "gash-control-neutral"); err == nil {
				neutralURL = nu
			}
		}
		for i := 0; i < repeats; i++ {
			t0 := time.Now()
			_, _, _, _ = send(ctx, method, neutralURL, nil, nil)
			controlSamples = append(controlSamples, float64(time.Since(t0).Milliseconds()))
		}

		ev, err := o.Verify(ctx, cls, false, oracle.TimingParams{
			DelaySamples:   delaySamples,
			ControlSamples: controlSamples,
			MinDelayMs:     minDelayMs,
			Repeats:        repeats,
			Strategy:       strategy,
		})
		if err != nil {
			return nil, err
		}
		if ev.Verdict != oracle.VerdictAccept {
			return nil, nil
		}
		return []Tier1Result{{Candidate: plugin.Candidate{
			PluginID:       spec.ID,
			Target:         target,
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query", Value: payload},
			OracleName:     "timing",
		}, Evidence: ev}}, nil
	case "differential":
		var o oracle.DifferentialOracle
		repeats := getIntParam(oracleParams, "repeats", 3)
		falsePayload := getStringParam(oracleParams, "false_payload", "gash_diff_false_val")
		falseBodyParam := getStringParam(oracleParams, "false_body", "")
		ceiling := getStringParam(oracleParams, "confidence_ceiling", "")
		var trueBodies, falseBodies []string

		trueBodies = append(trueBodies, body)
		for i := 1; i < repeats; i++ {
			if _, _, tBody, tErr := send(ctx, method, rawURL, reqHeaders, reqBody); tErr == nil {
				trueBodies = append(trueBodies, tBody)
			}
		}

		// False dalı: gövde-tabanlı (GASH-039) önce, sonra query tabanlı.
		falseURL := rawURL
		falseBody := reqBody
		if falseBodyParam != "" && file.Request.Body != "" {
			falseBody = []byte(falseBodyParam)
		} else if param != "" {
			if fu, err := withQueryParam(target, param, falsePayload); err == nil {
				falseURL = fu
			}
		}
		for i := 0; i < repeats; i++ {
			if _, _, fBody, fErr := send(ctx, method, falseURL, reqHeaders, falseBody); fErr == nil {
				falseBodies = append(falseBodies, fBody)
			}
		}

		ctrlBody := ""
		if param != "" {
			if nu, err := withQueryParam(target, param, "gash-control-neutral"); err == nil {
				if _, _, cBody, cErr := send(ctx, method, nu, nil, nil); cErr == nil {
					ctrlBody = cBody
				}
			}
		}

		ev, err := o.Verify(ctx, cls, false, oracle.DifferentialParams{
			TrueBodies:        trueBodies,
			FalseBodies:       falseBodies,
			ControlBody:       ctrlBody,
			Repeats:           repeats,
			ConfidenceCeiling: ceiling,
		})
		if err != nil {
			return nil, err
		}
		if ev.Verdict != oracle.VerdictAccept {
			return nil, nil
		}
		return []Tier1Result{{Candidate: plugin.Candidate{
			PluginID:       spec.ID,
			Target:         target,
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query", Value: payload},
			OracleName:     "differential",
		}, Evidence: ev}}, nil
	case "verb-tamper", "verbtamper", "verb_tamper":
		return executeVerbTamper(ctx, spec, file, target, method, rawURL, status, headers, body, send)
	case "oob":
		// No provider or no minted token: the payload went out verbatim and
		// no callback can ever match it. The oracle would answer skipped;
		// returning here keeps the intent obvious and fabricates nothing.
		if opts == nil || opts.OOB == nil || oobCorr == "" {
			return nil, nil
		}
		ns := getStringParam(oracleParams, "namespace", "tier1")
		// Verification is deferred: all payloads for this plugin run share
		// ONE bounded callback window (finishPendingOOB). A token that never
		// fires simply disappears: no finding, no downgraded placeholder.
		opts.pending = append(opts.pending, pendingOOB{
			pluginID: spec.ID,
			target:   target,
			cls:      cls,
			method:   method,
			rawURL:   rawURL,
			param:    param,
			value:    effPayload,
			corr:     oobCorr,
			ns:       ns,
		})
		return nil, nil
	case "stored", "storedexecution", "stored-execution", "stored_execution":
		var o oracle.StoredOracle
		canary := payload
		if c := getStringParam(oracleParams, "canary", ""); c != "" {
			canary = c
		}
		contexts := getStringSliceParam(oracleParams, "contexts")
		if len(contexts) == 0 {
			contexts = []string{"html", "attr-executable", "script", "url", "url-executable"}
		}
		reqExecutable := true
		if v, ok := oracleParams["require_executable_context"]; ok {
			if b, ok := v.(bool); ok {
				reqExecutable = b
			}
		}
		// Exchange 1 is the declarative request already sent (store).
		storeStatus, storeBody := status, body
		// Exchange 2 is the render page GET on the base target.
		renderStatus, renderHeaders, renderBody, renderErr := status, headers, body, error(nil)
		renderStatus, renderHeaders, renderBody, renderErr = send(ctx, http.MethodGet, target, nil, nil)
		if renderErr != nil {
			return nil, fmt.Errorf("tier1 stored render %s: %w", target, renderErr)
		}
		renderCls := baseline.ClassifyStatic(renderStatus, renderHeaders, []byte(renderBody))
		ctrlBody := ""
		if _, _, cBody, cErr := send(ctx, http.MethodGet, target, nil, nil); cErr == nil {
			ctrlBody = cBody
		}
		ev, err := o.Verify(ctx, renderCls, false, oracle.StoredParams{
			Canary: canary, Contexts: contexts,
			RequireExecutableContext: reqExecutable,
			StoreStatus:              storeStatus, StoreBody: storeBody,
			RenderBody: renderBody, RenderHeaders: renderHeaders,
			ControlBody: ctrlBody,
		})
		if err != nil {
			return nil, err
		}
		if ev.Verdict != oracle.VerdictAccept {
			return nil, nil
		}
		return []Tier1Result{{Candidate: plugin.Candidate{
			PluginID:       spec.ID,
			Target:         target,
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query", Value: payload},
			OracleName:     "stored",
			OracleParams:   map[string]string{"canary": canary},
		}, Evidence: ev}}, nil
	default:
		return nil, fmt.Errorf("tier1 execute: unsupported oracle %q: %w", file.Oracle.Name, plugin.ErrValidation)
	}
}

// executeHostHeader Host başlığı yansımasını sınırlı varyantlarla arar (GASH-035).
// What: Kontrol (başlıksız) yanıtta kanarya yokken Host/X-Forwarded-Host/Forwarded
// varyantlarından birinde kanarya gövdeye yansırsa firm bulgu üretir.
// Why: Absolute-URI request-line varyantı Go std transport ile gönderilemez;
// kapsam dürüstçe üç yansıma başlığıyla sınırlıdır. Yalnızca idempotent GET
// kullanılır; yıkıcı metot yoktur. İstek sayısı: 1 kontrol + ≤3 varyant.
func executeHostHeader(ctx context.Context, spec *plugin.PluginSpec, file *Tier1File, target, method, rawURL, ctrlBody string, oracleParams map[string]any, send Sender) ([]Tier1Result, error) {
	canary := getStringParam(oracleParams, "canary_host", "gash-host-canary.example")
	names := getStringSliceParam(oracleParams, "header_names")
	if len(names) == 0 {
		names = []string{"Host", "X-Forwarded-Host", "Forwarded"}
	}
	var out []Tier1Result
	for _, name := range names {
		value := canary
		if strings.EqualFold(name, "Forwarded") {
			value = "host=" + canary
		}
		vStatus, vHeaders, vBody, vErr := send(ctx, method, rawURL, map[string]string{name: value}, nil)
		if vErr != nil {
			continue // varyant hatası kanıt değildir; diğer varyantlar denenir
		}
		vCls := baseline.ClassifyStatic(vStatus, vHeaders, []byte(vBody))
		var o oracle.HeaderOracle
		ev, err := o.Verify(ctx, vCls, false, oracle.HeaderParams{
			Headers:     vHeaders,
			Mode:        "host_header",
			Body:        vBody,
			CanaryHost:  canary,
			ControlBody: ctrlBody,
		})
		if err != nil {
			return nil, err
		}
		if ev.Verdict != oracle.VerdictAccept {
			continue
		}
		out = append(out, Tier1Result{Candidate: plugin.Candidate{
			PluginID:       spec.ID,
			Target:         target,
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: strings.ToLower(name), ParamLocation: "header", Value: value},
			OracleName:     "header",
			OracleParams:   map[string]string{"mode": "host_header", "header": strings.ToLower(name)},
		}, Evidence: ev})
	}
	return out, nil
}

// executeVerbTamper metot/başlık varyantlarıyla auth atlatma arar (GASH-036).
// What: Baseline 401/403 iken HEAD, OPTIONS, X-HTTP-Method-Override,
// X-Original-URL ve X-Rewrite-URL varyantlarını dener; varyant 2xx + boş
// olmayan gövde ise oracle firm karar verir.
// Why: Metot/başlık düzeyi auth kısıtları tek GET ile ölçülemez; varyantlar
// sınırlıdır (yol başına ≤5) ve yıkıcı metot YOKTUR (yalnızca okuma).
func executeVerbTamper(ctx context.Context, spec *plugin.PluginSpec, file *Tier1File, target, method, rawURL string, baseStatus int, baseHeaders http.Header, baseBody string, send Sender) ([]Tier1Result, error) {
	if baseStatus != http.StatusUnauthorized && baseStatus != http.StatusForbidden {
		return nil, nil // korumalı görünmüyor: bu dedektörün konusu değil
	}
	type variant struct {
		method  string
		headers map[string]string
		name    string
	}
	variants := []variant{
		{method: http.MethodHead, name: "head"},
		{method: http.MethodOptions, name: "options"},
		{method: http.MethodGet, headers: map[string]string{"X-HTTP-Method-Override": http.MethodGet}, name: "x-http-method-override"},
		{method: http.MethodGet, headers: map[string]string{"X-Original-URL": "/"}, name: "x-original-url"},
		{method: http.MethodGet, headers: map[string]string{"X-Rewrite-URL": "/"}, name: "x-rewrite-url"},
	}
	var out []Tier1Result
	for _, v := range variants {
		headers := v.headers
		if headers == nil {
			headers = file.Request.Headers
		}
		vStatus, vHeaders, vBody, vErr := send(ctx, v.method, rawURL, headers, nil)
		if vErr != nil {
			continue
		}
		vCls := baseline.ClassifyStatic(vStatus, vHeaders, []byte(vBody))
		var o oracle.VerbTamperOracle
		ev, err := o.Verify(ctx, vCls, false, oracle.VerbTamperParams{
			BaselineStatus: baseStatus,
			BaselineBody:   baseBody,
			VariantStatus:  vStatus,
			VariantBody:    vBody,
			VariantMethod:  v.name,
		})
		if err != nil {
			return nil, err
		}
		if ev.Verdict != oracle.VerdictAccept {
			continue
		}
		out = append(out, Tier1Result{Candidate: plugin.Candidate{
			PluginID:       spec.ID,
			Target:         target,
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: v.method, ParamName: v.name, ParamLocation: "method", Value: v.method},
			OracleName:     "verb-tamper",
			OracleParams:   map[string]string{"variant": v.name},
		}, Evidence: ev})
	}
	return out, nil
}

func getStringParam(params map[string]any, key, defaultVal string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultVal
}

func getStringSliceParam(params map[string]any, key string) []string {
	if v, ok := params[key]; ok {
		if arr, ok := v.([]any); ok {
			out := make([]string, len(arr))
			for i, vi := range arr {
				out[i] = fmt.Sprintf("%v", vi)
			}
			return out
		}
	}
	return nil
}

func getFloat64Param(params map[string]any, key string, defaultVal float64) float64 {
	if params == nil {
		return defaultVal
	}
	if v, ok := params[key]; ok {
		switch val := v.(type) {
		case float64:
			return val
		case int:
			return float64(val)
		case int64:
			return float64(val)
		}
	}
	return defaultVal
}

func getIntParam(params map[string]any, key string, defaultVal int) int {
	if params == nil {
		return defaultVal
	}
	if v, ok := params[key]; ok {
		switch val := v.(type) {
		case int:
			return val
		case int64:
			return int(val)
		case float64:
			return int(val)
		}
	}
	return defaultVal
}

// withQueryParam returns target with one query value replaced.
// What: Deterministic URL builder for param-injection requests.
// Why: Centralizes URL mutation so scans and tests cannot diverge.
func withQueryParam(target, param, value string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// payloadHostname extracts the host from an absolute payload URL.
// What: Derives the redirect allowlist host from plugin config.
// Why: The oracle compares the Location host against this exact value.
func payloadHostname(payload string) string {
	u, err := url.Parse(payload)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// isAbsolute reports whether a Location value is an absolute HTTP URL.
// What: Classifies control redirects without DNS lookups.
// Why: Offline evaluation must not depend on resolver availability.
func isAbsolute(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}
