// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package recon

import (
	"context"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/detector"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// scanPagesFixture mirrors the crawler output every test below drives.
// What: HTML pages first, then external JS, with one inline script that must be
// skipped because it is already part of its page body.
// Why: The page-selection rule is shared by both detectors and must stay
// identical to the pre-port behaviour.
func scanPagesFixture(pageURL string, pageBody, jsBody []byte, extraJS ...detector.Page) []detector.Page {
	pages := []detector.Page{
		{URL: pageURL, Body: pageBody},
		{URL: "http://target.test/public", Body: []byte(`<html>no state</html>`)},
		{URL: pageURL, Body: pageBody, JS: true, Inline: true},
		{URL: "http://target.test/app.js", Body: jsBody, JS: true},
	}
	return append(pages, extraJS...)
}

func TestScanSPAState(t *testing.T) {
	const (
		pageURL = "http://target.test/app"
		token   = "ghp_" + "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LmNvBc"
		pass    = "correct-horse-battery-staple"
	)
	pageBody := []byte(`<script id="__NEXT_DATA__" type="application/json">` +
		`{"props":{"pageProps":{"accessToken":"` + token + `","password":"` + pass + `"}}}</script>`)
	jsBody := []byte(`<script>window.__INITIAL_STATE__={"auth":{"refreshToken":"rt_9f8e7d6c5b4a3210"}}</script>`)
	got, stats := ScanSPAState(context.Background(), scanPagesFixture(pageURL, pageBody, jsBody))
	if stats["spa_state_pages"] != 1 {
		t.Fatalf("spa_state_pages=%d want 1", stats["spa_state_pages"])
	}
	if stats["spa_state_secrets"] != len(got) || len(got) != 3 {
		t.Fatalf("findings=%d stats=%+v", len(got), stats)
	}
	for _, f := range got {
		if f.RuleID != RuleIDSPAState || f.PluginID != PluginIDSPAState {
			t.Fatalf("bad finding ids: %+v", f)
		}
		if f.Confidence != plugin.ConfidenceStaticExecution {
			t.Fatalf("confidence %q", f.Confidence)
		}
		if f.CWE != CWESPAStateCredential {
			t.Fatalf("cwe %q", f.CWE)
		}
		for _, v := range f.Evidence {
			if strings.Contains(v, token) || strings.Contains(v, pass) {
				t.Fatalf("full secret value leaked: %+v", f.Evidence)
			}
		}
		if f.Evidence["framework"] == "" || f.Evidence["container"] == "" || f.Evidence["masked_value"] == "" {
			t.Fatalf("missing evidence: %+v", f.Evidence)
		}
	}
}

func TestScanSPAStateJWTUsesExposureCWE(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	body := []byte(`<script>window.__INITIAL_STATE__={"token":"` + jwt + `"}</script>`)
	got, _ := ScanSPAState(context.Background(), []detector.Page{{URL: "http://target.test/", Body: body}})
	if len(got) != 1 {
		t.Fatalf("want 1 jwt finding, got %d", len(got))
	}
	if got[0].CWE != CWESPAStateExposure {
		t.Fatalf("jwt cwe=%q want %q", got[0].CWE, CWESPAStateExposure)
	}
}

func TestScanDevBuild(t *testing.T) {
	pageBody := []byte(`<script src="/react-dom.development.js"></script><script>jsxDEV(type, props, key, false);</script>`)
	jsBody := []byte(`const el = ng.probe(document.querySelector('app-root'));`)
	pages := []detector.Page{
		{URL: "http://target.test/", Body: pageBody},
		{URL: "http://target.test/", Body: pageBody, JS: true, Inline: true},
		{URL: "http://target.test/main.js", Body: jsBody, JS: true},
		{URL: "http://target.test/prod.js", Body: []byte(`window.__VUE_DEVTOOLS_GLOBAL_HOOK__ = {};`), JS: true},
	}
	got, stats := ScanDevBuild(context.Background(), pages)
	if len(got) != 2 {
		t.Fatalf("want one finding per source, got %d: %+v", len(got), got)
	}
	if stats["devbuild_markers"] != 3 {
		t.Fatalf("devbuild_markers=%d want 3", stats["devbuild_markers"])
	}
	for _, f := range got {
		if f.RuleID != RuleIDDevBuild || f.CWE != CWEDevBuild || f.PluginID != PluginIDDevBuild {
			t.Fatalf("bad finding: %+v", f)
		}
		if f.Confidence != plugin.ConfidenceFirm || f.Severity != plugin.SeverityLow {
			t.Fatalf("severity/confidence: %s/%s", f.Severity, f.Confidence)
		}
		if f.Evidence["markers"] == "" || f.Evidence["snippet"] == "" {
			t.Fatalf("missing evidence: %+v", f.Evidence)
		}
	}
}

func TestScanDevBuildProductionNoise(t *testing.T) {
	body := []byte(`<script>
window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = {};
window.__VUE_DEVTOOLS_GLOBAL_HOOK__ = {};
console.warn("warnings");
</script><script src="/react-dom.production.min.js"></script>`)
	got, stats := ScanDevBuild(context.Background(), []detector.Page{{URL: "http://target.test/", Body: body}})
	if len(got) != 0 || stats["devbuild_markers"] != 0 {
		t.Fatalf("production noise matched: %+v %+v", got, stats)
	}
}

// TestJSReconSpecAndHonestSkip proves the passive recon port contract.
// What: Identity/gates plus the no-probe fast path.
// Why: The live end-to-end path is covered by TestScanJSReconEndToEnd in
// internal/engine; this test locks the detector's own contract and the fact
// that it never invents telemetry when it cannot run.
func TestJSReconSpecAndHonestSkip(t *testing.T) {
	reg := detector.NewRegistry()
	if err := reg.Register(JSRecon{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	spec := JSRecon{}.Spec()
	if spec.RuleID != RuleIDJSSecret || spec.CWE != CWEJSSecret || spec.Oracle != OracleJSSecret {
		t.Fatalf("identity drift: %+v", spec)
	}
	if spec.Gate != "" || spec.RequiresActive || spec.RequiresDeep || spec.RequiresAggressive {
		t.Fatalf("passive recon must not be gated: %+v", spec)
	}
	if spec.MaxRequests != jsMaxFollowPages+jsMaxSourceMapFetch {
		t.Fatalf("declared budget must match the two bounds: %d", spec.MaxRequests)
	}
	ok, reason := spec.Evaluate(detector.Policy{Flags: detector.Flags{Profile: "safe"}})
	if !ok {
		t.Fatalf("safe profile must run passive recon: %s", reason)
	}

	for _, env := range []*detector.Env{nil, {}} {
		res, err := JSRecon{}.Run(context.Background(), env)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(res.Findings) != 0 || len(res.Surface) != 0 {
			t.Fatalf("without a probe client nothing may be claimed: %+v", res)
		}
		if len(res.Stats) != 5 || res.Stats["js_secrets_found"] != 0 {
			t.Fatalf("counters must stay zeroed: %+v", res.Stats)
		}
	}
}

// TestScanPagesSkipsInlineAndDuplicates proves the shared selection rule.
// What: Inline scripts and repeated URLs are visited once.
// Why: A double scan would duplicate findings the moment two detectors share
// the same page set.
func TestScanPagesSkipsInlineAndDuplicates(t *testing.T) {
	var seen []string
	scanPages(context.Background(), []detector.Page{
		{URL: "http://t/a", Body: []byte("a")},
		{URL: "http://t/a", Body: []byte("a")},
		{URL: "http://t/b", Body: []byte("b"), JS: true, Inline: true},
		{URL: "", Body: []byte("c")},
		{URL: "http://t/d", Body: nil},
	}, func(p detector.Page, _ bool) { seen = append(seen, p.URL) })
	if len(seen) != 1 || seen[0] != "http://t/a" {
		t.Fatalf("unexpected scan set: %v", seen)
	}
}

// TestScanPagesHonoursCancellation proves a cancelled scan stops the pass.
// What: A cancelled context stops before the next page.
// Why: Deep scans must not keep analysing bytes after the operator aborted.
func TestScanPagesHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var visited int
	scanPages(ctx, []detector.Page{{URL: "http://t/a", Body: []byte("a")}}, func(detector.Page, bool) { visited++ })
	if visited != 0 {
		t.Fatalf("cancelled scan must not visit pages, visited=%d", visited)
	}
}

// TestDetectorsRegisterAndStayUngated proves the port contract.
// What: Both detectors register and run without any flag or profile gate.
// Why: They are pure content observations; gating them would silently drop
// GASH-071/072 from every scan.
func TestDetectorsRegisterAndStayUngated(t *testing.T) {
	reg := detector.NewRegistry()
	for _, d := range []detector.Detector{SPAState{}, DevBuild{}} {
		if err := reg.Register(d); err != nil {
			t.Fatalf("register %s: %v", d.Spec().ID, err)
		}
	}
	if reg.Len() != 2 {
		t.Fatalf("want 2 detectors, got %d", reg.Len())
	}
	policy := detector.Policy{Flags: detector.Flags{Profile: "safe"}, Enabled: map[string]bool{}}
	for _, d := range []detector.Detector{SPAState{}, DevBuild{}} {
		spec := d.Spec()
		if spec.Gate != "" || spec.RequiresActive || spec.RequiresDeep || spec.RequiresAggressive {
			t.Fatalf("%s must not be gated: %+v", spec.ID, spec)
		}
		if ok, reason := spec.Evaluate(policy); !ok {
			t.Fatalf("%s must run in the safe profile: %s", spec.ID, reason)
		}
	}

	t.Run("detector run returns the declared stat keys", func(t *testing.T) {
		res, err := SPAState{}.Run(context.Background(), &detector.Env{Pages: []detector.Page{}})
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if _, ok := res.Stats["spa_state_pages"]; !ok {
			t.Fatalf("spa_state_pages missing: %+v", res.Stats)
		}
		dev, err := DevBuild{}.Run(context.Background(), nil)
		if err != nil {
			t.Fatalf("run without env: %v", err)
		}
		if _, ok := dev.Stats["devbuild_markers"]; !ok {
			t.Fatalf("devbuild_markers missing: %+v", dev.Stats)
		}
	})
}
