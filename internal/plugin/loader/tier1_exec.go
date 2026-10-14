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
// What: Minimal transport seam between Tier 1 logic and real or mocked HTTP.
// Why: Tests inject canned responses while production passes the probe client.
type Sender func(ctx context.Context, method, rawURL string) (status int, headers http.Header, body string, err error)

// Tier1Result pairs a candidate with the evidence that produced it.
// What: Executable outcome of one Tier 1 request attempt.
// Why: The engine builds findings from evidence, never from bare candidates.
type Tier1Result struct {
	// Candidate is the engine-facing candidate.
	Candidate plugin.Candidate
	// Evidence is the oracle verdict behind the candidate.
	Evidence *oracle.Evidence
}

// ExecuteTier1 runs a Tier 1 file against one target URL.
// What: Sends declarative requests then verifies each response with the pinned oracle.
// Why: Keeps Tier 1 behavior identical for scans, fixtures, and CLI tests.
func ExecuteTier1(ctx context.Context, spec *plugin.PluginSpec, file *Tier1File, target string, send Sender) ([]Tier1Result, error) {
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
	if len(file.Request.ParamNames) == 0 {
		return executeSingle(ctx, spec, file, target, method, "", send)
	}
	var out []Tier1Result
	for _, param := range file.Request.ParamNames {
		res, err := executeSingle(ctx, spec, file, target, method, param, send)
		if err != nil {
			return nil, err
		}
		out = append(out, res...)
	}
	return out, nil
}

func executeSingle(ctx context.Context, spec *plugin.PluginSpec, file *Tier1File, target, method, param string, send Sender) ([]Tier1Result, error) {
	rawURL := target
	if param != "" {
		var err error
		rawURL, err = withQueryParam(target, param, file.Request.Payload)
		if err != nil {
			return nil, fmt.Errorf("tier1 execute: bad target %q: %w", target, err)
		}
	}
	status, headers, body, err := send(ctx, method, rawURL)
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
		var reqHeaders http.Header
		if rh, ok := oracleParams["request_headers"]; ok {
			if rhMap, ok := rh.(map[string]any); ok {
				reqHeaders = make(http.Header)
				for k, v := range rhMap {
					if vs, ok := v.([]any); ok {
						for _, vi := range vs {
							reqHeaders.Add(k, fmt.Sprintf("%v", vi))
						}
					} else {
						reqHeaders.Set(k, fmt.Sprintf("%v", v))
					}
				}
			}
		}
		ev, err := o.Verify(ctx, cls, false, oracle.HeaderParams{
			Headers:        headers,
			Mode:           mode,
			RequestHeaders: reqHeaders,
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
		payloadHost := payloadHostname(file.Request.Payload)
		loc := headers.Get("Location")
		controlClean := true
		if param != "" {
			neutralURL, err := withQueryParam(target, param, "gash-control-neutral")
			if err == nil {
				if cStatus, cHeaders, _, cErr := send(ctx, method, neutralURL); cErr == nil {
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
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query", Value: file.Request.Payload},
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
				if cStatus, _, cBody, cErr := send(ctx, method, neutralURL); cErr == nil && cStatus == http.StatusOK {
					controlBody = cBody
				}
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
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query", Value: file.Request.Payload},
			OracleName:     "error",
			OracleParams:   map[string]string{"mode": mode},
		}, Evidence: ev}}, nil
	case "version":
		var o oracle.VersionOracle
		mode := getStringParam(oracleParams, "mode", "banner")
		bannerRegex := getStringParam(oracleParams, "banner_regex", "")
		ev, err := o.Verify(ctx, cls, false, oracle.VersionParams{
			Banner:      body, // Use response body as banner for graphql mode
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
		canary := file.Request.Payload
		if c := getStringParam(oracleParams, "canary", ""); c != "" {
			canary = c
		}
		ctrlBody := ""
		if param != "" {
			neutralURL, err := withQueryParam(target, param, "gash-control-neutral")
			if err == nil {
				if _, _, cBody, cErr := send(ctx, method, neutralURL); cErr == nil {
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
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query", Value: file.Request.Payload},
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
			_, _, _, _ = send(ctx, method, rawURL)
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
			_, _, _, _ = send(ctx, method, neutralURL)
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
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query", Value: file.Request.Payload},
			OracleName:     "timing",
		}, Evidence: ev}}, nil
	case "differential":
		var o oracle.DifferentialOracle
		repeats := getIntParam(oracleParams, "repeats", 3)
		falsePayload := getStringParam(oracleParams, "false_payload", "gash_diff_false_val")
		var trueBodies, falseBodies []string

		trueBodies = append(trueBodies, body)
		for i := 1; i < repeats; i++ {
			if _, _, tBody, tErr := send(ctx, method, rawURL); tErr == nil {
				trueBodies = append(trueBodies, tBody)
			}
		}

		falseURL := rawURL
		if param != "" {
			if fu, err := withQueryParam(target, param, falsePayload); err == nil {
				falseURL = fu
			}
		}
		for i := 0; i < repeats; i++ {
			if _, _, fBody, fErr := send(ctx, method, falseURL); fErr == nil {
				falseBodies = append(falseBodies, fBody)
			}
		}

		ctrlBody := ""
		if param != "" {
			if nu, err := withQueryParam(target, param, "gash-control-neutral"); err == nil {
				if _, _, cBody, cErr := send(ctx, method, nu); cErr == nil {
					ctrlBody = cBody
				}
			}
		}

		ev, err := o.Verify(ctx, cls, false, oracle.DifferentialParams{
			TrueBodies:  trueBodies,
			FalseBodies: falseBodies,
			ControlBody: ctrlBody,
			Repeats:     repeats,
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
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query", Value: file.Request.Payload},
			OracleName:     "differential",
		}, Evidence: ev}}, nil
	case "oob":
		var o oracle.OOBOracle
		ev, err := o.Verify(ctx, cls, false, oracle.OOBParams{
			CorrelationID: "tier1-" + param, // Use param as correlation ID for tier1
			Namespace:     "tier1",
			CallbackSeen:  false, // Tier 1 doesn't have OOB callback by default
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
			InjectionPoint: plugin.InjectionPoint{URL: rawURL, Method: method, ParamName: param, ParamLocation: "query", Value: file.Request.Payload},
			OracleName:     "oob",
		}, Evidence: ev}}, nil
	default:
		return nil, fmt.Errorf("tier1 execute: unsupported oracle %q: %w", file.Oracle.Name, plugin.ErrValidation)
	}
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
