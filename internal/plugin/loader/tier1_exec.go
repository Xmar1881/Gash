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
	switch strings.ToLower(file.Oracle.Name) {
	case "header":
		var o oracle.HeaderOracle
		ev, err := o.Verify(ctx, cls, false, oracle.HeaderParams{Headers: headers})
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
	default:
		return nil, fmt.Errorf("tier1 execute: unsupported oracle %q: %w", file.Oracle.Name, plugin.ErrValidation)
	}
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
