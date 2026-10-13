// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
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
	case "oob":
		return "GASH-008", "CWE-918"
	default:
		return "GASH-000", "CWE-693"
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
	client := probe.NewClient(probe.Options{
		Policy:         policy,
		RequestTimeout: 15 * time.Second,
		MaxBytes:       5 * 1024 * 1024,
		MaxRedirects:   5,
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
	var allFindings []*finding.Finding
	var execSkipped []plugin.SkippedPlugin
	errorCount := 0

	for _, spec := range ordered {
		wg.Add(1)
		go func(s plugin.PluginSpec) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			found, reason, ok := e.executeOne(ctx, s, target, client, pluginTimeout)
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
	rep := &Report{
		Target:   target,
		Findings: deduped,
		Skipped:  allSkipped,
		Stats: map[string]int{
			"scheduled": len(ordered),
			"skipped":   len(allSkipped),
			"findings":  len(deduped),
			"errors":    errorCount,
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
func (e *Engine) executeOne(parent context.Context, spec plugin.PluginSpec, target string, client *probe.Client, timeout time.Duration) ([]*finding.Finding, string, bool) {
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
				rule, cwe := ruleAndCWE(r.Candidate.OracleName)
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
			env := jsEnvForScan(pctx, target, client, e.cfg.OOBServer != "")
			got, err := loader.ExecuteJS(pctx, &spec, string(source), env, timeout)
			if err != nil {
				return nil, err
			}
			for _, jc := range got {
				rule, cwe := ruleAndCWE(jc.Candidate.OracleName)
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
				rule, cwe := ruleAndCWE(cand.OracleName)
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

// jsEnvForScan builds live JS bindings over the probe client.
// What: Single generic injection point plus probe and OOB backends.
// Why: Reference scripts expect points; live scans provide one honest target.
func jsEnvForScan(pctx context.Context, target string, client *probe.Client, oobEnabled bool) *loader.JSEnv {
	sendOne := func(p loader.JSPoint, value string) (loader.JSResponse, error) {
		method := p.Method
		if method == "" {
			method = http.MethodGet
		}
		rawURL := p.URL
		if rawURL == "" {
			rawURL = target
		}
		if p.ParamName != "" {
			built, err := withScanQueryParam(rawURL, p.ParamName, value)
			if err == nil {
				rawURL = built
			}
		}
		resp, err := client.Send(pctx, method, rawURL, nil, nil)
		if err != nil {
			return loader.JSResponse{}, err
		}
		headers := make(map[string]string, len(resp.Headers))
		for k, vals := range resp.Headers {
			if len(vals) > 0 {
				headers[k] = vals[0]
			}
		}
		return loader.JSResponse{Status: resp.Status, Headers: headers, Body: string(resp.Body), URL: rawURL}, nil
	}
	return &loader.JSEnv{
		Points: []loader.JSPoint{{URL: target, Method: http.MethodGet, ParamName: "q", ParamLocation: "query"}},
		Send: func(p loader.JSPoint) (loader.JSResponse, error) {
			return sendOne(p, p.Value)
		},
		OOBEnabled:   oobEnabled,
		OOBNamespace: "scan",
		OOBCallbackSeen: func(string) bool {
			return false
		},
	}
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
// What: Probe fetch plus oracle dispatch for Tier 3 header and redirect.
// Why: Native binaries propose; only engine evidence can confirm a finding.
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
	default:
		return nil, fmt.Errorf("tier3 oracle %q not supported live: %w", oracleName, plugin.ErrValidation)
	}
}
