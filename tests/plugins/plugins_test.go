// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package plugins verifies Phase 3 reference plugins end to end.
// What: Metric-gate plus B1, B4, B5, and B9 coverage over discovered plugins.
// Why: New plugins cannot land without fixtures, metrics, and isolation proof;
// discovery stays dynamic so no check count or name is hardcoded here.
package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/engine"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/plugintest"
)

// repoRoot locates the module root from the test file position.
// What: Anchor for plugin, fixture, and metrics paths.
// Why: Tests must run from any working directory without hardcoded roots.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// discoveredSpec pairs a spec with its file and tier-specific extras.
// What: Uniform view over three tiers for gate assertions.
// Why: One loop enforces metadata, fixture, and metric rules everywhere.
type discoveredSpec struct {
	spec       plugin.PluginSpec
	path       string
	oracleName string
}

// discoverAll loads every reference plugin without naming any of them.
// What: Dynamic registry plus oracle resolution for the whole plugins tree.
// Why: Adding or removing a plugin changes coverage automatically.
func discoverAll(t *testing.T) ([]discoveredSpec, string) {
	t.Helper()
	root := repoRoot(t)
	reg := plugin.NewRegistry()
	warns, err := loader.Discover([]string{filepath.Join(root, "plugins")}, reg)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	for _, w := range warns {
		t.Logf("discover warn: %s", w)
	}
	snap := reg.Snapshot()
	if len(snap) == 0 {
		t.Fatal("no reference plugins discovered")
	}
	var out []discoveredSpec
	for _, e := range snap {
		oracleName := ""
		path := e.SourcePath
		lower := strings.ToLower(path)
		switch {
		case strings.HasSuffix(lower, ".gashplugin.yaml"):
			_, m, err := loader.LoadTier3Manifest(path)
			if err != nil {
				t.Fatalf("tier3 reload %s: %v", path, err)
			}
			oracleName = m.Oracle
			if oracleName == "" {
				oracleName = "header"
			}
		case strings.HasSuffix(lower, ".js"):
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			oracleName = plugintest.InferJSOracle(string(data))
			if oracleName == "" {
				t.Fatalf("no oracle reference in %s", path)
			}
		default:
			_, f, err := loader.LoadTier1File(path)
			if err != nil {
				t.Fatalf("tier1 reload %s: %v", path, err)
			}
			oracleName = f.Oracle.Name
		}
		out = append(out, discoveredSpec{spec: e.Spec, path: path, oracleName: oracleName})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].spec.ID < out[j].spec.ID })
	return out, root
}

// TestMetricGate enforces the no-metrics-no-plugin rule.
// What: Fixture plus precision plus documentation check per discovered plugin.
// Why: The 99 percent precision gate is a test, not a review convention.
func TestMetricGate(t *testing.T) {
	specs, root := discoverAll(t)
	for _, d := range specs {
		d := d
		t.Run(d.spec.ID, func(t *testing.T) {
			if err := plugin.Validate(d.spec); err != nil {
				t.Fatalf("spec invalid: %v", err)
			}
			if warns := plugin.ValidateWarnings(d.spec); len(warns) != 0 {
				t.Fatalf("reference plugin must be warning-free: %v", warns)
			}
			if d.spec.Tests == "" {
				t.Fatal("Tests must point at fixtures (R-06)")
			}
			fixtureRoot := plugintest.ResolveFixtureRoot(d.path, d.spec.Tests)
			// Load oracle params from the plugin file
			var oracleParams map[string]any
			if strings.HasSuffix(strings.ToLower(d.path), ".yaml") || strings.HasSuffix(strings.ToLower(d.path), ".yml") {
				_, f, err := loader.LoadTier1File(d.path)
				if err == nil && f.Oracle.Params != nil {
					oracleParams = f.Oracle.Params
				}
			}
			sum, err := plugintest.Run(context.Background(), d.spec.ID, d.oracleName, fixtureRoot, true, oracleParams)
			if err != nil {
				t.Fatalf("fixtures: %v", err)
			}
			if !sum.Pass {
				for _, c := range sum.Cases {
					if !c.Pass {
						t.Logf("FAIL %s/%s: %s", map[bool]string{true: "positive", false: "negative"}[c.Positive], c.Name, c.Detail)
					}
				}
				t.Fatal("fixture failures")
			}
			if sum.Precision < 0.99 {
				t.Fatalf("precision gate 0.99 not met: %.4f", sum.Precision)
			}
			metrics := filepath.Join(root, "docs", "metrics", d.spec.ID+".md")
			data, err := os.ReadFile(metrics)
			if err != nil {
				t.Fatalf("missing metrics report %s: %v", metrics, err)
			}
			body := string(data)
			for _, want := range []string{"Precision", "Recall", "Corpus", "Lab", "Gate Verdict"} {
				if !strings.Contains(body, want) {
					t.Fatalf("metrics %s must contain %q", metrics, want)
				}
			}
			// P0.3: rapor, ölçülen fixture veri setinin hash'ini aynen taşımalı.
			// Sessiz fixture değişikliği raporu bayatlatır ve kapıyı düşürür.
			if sum.DatasetHash == "" || sum.FixtureFiles == 0 {
				t.Fatalf("dataset provenance missing for %s", d.spec.ID)
			}
			if os.Getenv("UPDATE_METRICS") == "1" && !strings.Contains(body, sum.DatasetHash) {
				re := regexp.MustCompile(`- Dataset hash: ` + "`[a-f0-9]{64}`")
				body = re.ReplaceAllString(body, "- Dataset hash: `"+sum.DatasetHash+"`")
				if !strings.HasSuffix(body, "\n") {
					body += "\n"
				}
				if err := os.WriteFile(metrics, []byte(body), 0o644); err != nil {
					t.Fatalf("failed to update metrics %s: %v", metrics, err)
				}
			}
			if !strings.Contains(body, sum.DatasetHash) {
				t.Fatalf("metrics %s must pin dataset hash %s (re-run fixtures, update report)", metrics, sum.DatasetHash)
			}
		})
	}
}

// newTestServer starts a local HTTP server for drop-in execution.
// What: Hermetic backend for Tier 1 live runs.
// Why: No external network may be required by reference tests.
func newTestServer(t *testing.T, h http.HandlerFunc) *testServer {
	t.Helper()
	srv := &http.Server{Handler: h}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln) //nolint:errcheck // test server lifetime ends with Close.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return &testServer{URL: "http://" + ln.Addr().String(), srv: srv}
}

// testServer is the handle returned by newTestServer.
// What: URL plus shutdown lifecycle for tests.
// Why: Cleanup hooks guarantee no leaked listeners.
type testServer struct {
	// URL is the server base address.
	URL string
	srv *http.Server
}

// vulnerableResponder serves one generic vulnerable backend for Tier 1 e2e.
// What: Per-oracle canned responses behind a single httptest handler.
// Why: Drop-in proof must work for whichever Tier 1 file is discovered.
func vulnerableResponder(tier1 *loader.Tier1File) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch strings.ToLower(tier1.Oracle.Name) {
		case "redirect":
			payload := tier1.Request.Payload
			hit := false
			for _, p := range tier1.Request.ParamNames {
				if r.URL.Query().Get(p) == payload {
					hit = true
				}
			}
			if hit {
				w.Header().Set("Location", payload+"/landing")
				w.WriteHeader(http.StatusFound)
				_, _ = w.Write([]byte("redirect"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("home"))
		case "cookie":
			// What: Bare session cookie triggers the confirmed path.
			// Why: Drop-in proof needs a deterministic vulnerable backend per oracle.
			w.Header().Set("Set-Cookie", "sessionid=abc; Path=/")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>hello</body></html>"))
		case "cors":
			// What: Wildcard plus credentials triggers the confirmed path.
			// Why: Same per-oracle determinism as cookie and redirect cases.
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>hello</body></html>"))
		case "error":
			// What: Error signature oracle needs a 500 with error signature in body.
			// Why: generic_error mode matches stack traces, exceptions, etc.
			payload := tier1.Request.Payload
			hit := false
			for _, p := range tier1.Request.ParamNames {
				if r.URL.Query().Get(p) == payload {
					hit = true
				}
			}
			if hit {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("Fatal error: Uncaught Exception: stack trace at line 42\nException: command injection detected"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>hello</body></html>"))
		default: // header and friends: bare response without hardening.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>hello</body></html>"))
		}
	}
}

// TestB1Tier1DropIn proves single-file Tier 1 drop-in without core changes.
// What: Copy one discovered Tier 1 file to a temp dir, discover, execute live.
// Why: B1 requires file-drop plus finding with zero engine modification.
func TestB1Tier1DropIn(t *testing.T) {
	specs, _ := discoverAll(t)
	var target *discoveredSpec
	for i := range specs {
		if specs[i].spec.Tier == plugin.TierYAML && specs[i].spec.OOB != plugin.OOBRequired {
			target = &specs[i]
			break
		}
	}
	if target == nil {
		t.Skip("no non-OOB Tier 1 reference plugin")
	}
	// Single-file drop-in: exactly one file in a fresh directory.
	dir := t.TempDir()
	data, err := os.ReadFile(target.path)
	if err != nil {
		t.Fatal(err)
	}
	drop := filepath.Join(dir, "drop-in.yaml")
	if err := os.WriteFile(drop, data, 0o644); err != nil {
		t.Fatal(err)
	}
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("exactly one plugin must be discovered, got %d", reg.Len())
	}
	spec, file, err := loader.LoadTier1File(drop)
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(t, vulnerableResponder(file))
	sender := func(ctx context.Context, method, rawURL string) (int, http.Header, string, error) {
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			return 0, nil, "", err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil, "", err
		}
		defer resp.Body.Close()
		rest, err := io.ReadAll(resp.Body)
		if err != nil {
			return 0, nil, "", err
		}
		return resp.StatusCode, resp.Header, string(rest), nil
	}
	results, err := loader.ExecuteTier1(context.Background(), spec, file, srv.URL+"/go", sender)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("drop-in Tier 1 must produce at least one result")
	}
	confirmed := false
	for _, r := range results {
		if r.Evidence != nil && (r.Evidence.ConfidenceContribution == plugin.ConfidenceConfirmed || r.Evidence.ConfidenceContribution == plugin.ConfidenceFirm) {
			confirmed = true
			f, err := finding.Build(*spec, r.Candidate, r.Evidence, ruleFor(target.oracleName), cweFor(target.oracleName), "", "")
			if err != nil || f == nil {
				t.Fatalf("finding build: %v", err)
			}
		}
	}
	if !confirmed {
		t.Fatal("drop-in Tier 1 must reach firm or confirmed on the vulnerable backend")
	}
}

// TestB1Tier2DropIn proves single-file Tier 2 drop-in with mocked transport.
// What: Execute a discovered JS plugin through the real goja bindings.
// Why: B1 covers both drop-in tiers; mocks keep the proof hermetic.
func TestB1Tier2DropIn(t *testing.T) {
	specs, _ := discoverAll(t)
	var target *discoveredSpec
	for i := range specs {
		if specs[i].spec.Tier == plugin.TierJS && specs[i].oracleName != "oob" {
			target = &specs[i]
			break
		}
	}
	if target == nil {
		t.Skip("no non-OOB Tier 2 reference plugin")
	}
	source, err := os.ReadFile(target.path)
	if err != nil {
		t.Fatal(err)
	}
	const canary = "gash_e2e_canary"
	env := &loader.JSEnv{
		Points: []loader.JSPoint{{URL: "http://example.com/search", Method: "GET", ParamName: "q", ParamLocation: "query"}},
		Canary: canary,
		Send: func(p loader.JSPoint) (loader.JSResponse, error) {
			return jsMockResponse(p, canary), nil
		},
		OOBEnabled:   true,
		OOBNamespace: "scan_e2e",
		OOBCallbackSeen: func(string) bool {
			return true
		},
	}
	cands, err := loader.ExecuteJS(context.Background(), &target.spec, string(source), env, 10*time.Second)
	if err != nil {
		t.Fatalf("js execute: %v", err)
	}
	if len(cands) == 0 {
		t.Fatal("drop-in Tier 2 must produce at least one candidate")
	}
	for _, c := range cands {
		if c.Evidence == nil || c.Evidence.Verdict != oracle.VerdictAccept {
			t.Fatalf("candidate without accepted evidence: %+v", c)
		}
	}
}

// jsMockResponse answers script probes for every oracle through one switch.
// What: Value-routed canned backend for hermetic JS execution.
// Why: One responder keeps the e2e proof generic across discovered plugins.
func jsMockResponse(p loader.JSPoint, canary string) loader.JSResponse {
	v := p.Value
	h := map[string]string{"Content-Type": "text/html"}
	switch {
	case strings.Contains(v, "gash-dom-probe"):
		return loader.JSResponse{Status: 200, Headers: h, Body: `<div id="o"></div><script>var h=location.hash; document.getElementById('o').innerHTML=h;</script>`, URL: p.URL}
	case strings.Contains(v, "'1'='1"):
		return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>welcome admin panel</body></html>", URL: p.URL}
	case strings.Contains(v, "'1'='2"):
		return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>login failed</body></html>", URL: p.URL}
	case strings.Contains(v, "CONVERT") || (strings.Contains(v, "'") && strings.Contains(v, "AND")):
		return loader.JSResponse{Status: 500, Headers: h, Body: "<html><body>SQLServer conversion failed varchar to int</body></html>", URL: p.URL}
	case strings.HasPrefix(v, "gash_"):
		return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><script>" + v + "</script></body></html>", URL: p.URL}
	default:
		return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>neutral page</body></html>", URL: p.URL}
	}
}

// TestB4CorpusZeroFirmPlus runs every oracle against clean corpus bodies.
// What: Generic zero false-positive proof independent of plugin identities.
// Why: B4 must hold for the oracles the reference plugins rely on.
func TestB4CorpusZeroFirmPlus(t *testing.T) {
	ctx := context.Background()
	clean := []struct {
		name   string
		status int
		header map[string]string
		body   string
	}{
		{"clean-app", 200, nil, "<html><body><h1>Hello</h1><p>Welcome</p></body></html>"},
		{"spa-catchall", 200, nil, "<html><body><div id=root></div><script src=/static/js/main.js></script></body></html>"},
		{"waf-block", 403, nil, "<html><body>cf-chl challenge Please verify</body></html>"},
		{"encoded-app", 200, nil, "<html><body><p>&lt;script&gt;gash_test</p></body></html>"},
		{"dynamic", 200, nil, "<html><body><input name=\"csrf_token\" value=\"abc123\"><p>2026-10-12</p></body></html>"},
	}
	for _, tc := range clean {
		f := plugintest.Fixture{
			Name: tc.name, Status: tc.status, Headers: tc.header, Body: tc.body,
			ControlBody: "neutral page", Canary: "gash_never_present_xyz",
			TrueBodies:  []string{"same", "same", "same"},
			FalseBodies: []string{"same", "same", "same"},
			PayloadHost: "gash-canary.example",
		}
		for _, orName := range []string{"header", "redirect", "reflection", "error", "differential", "oob", "cookie", "cors"} {
			ff := f
			if orName == "header" {
				// Bare corpus pages truly miss headers, so a header finding
				// there is a true positive. The false-positive proof uses
				// hardened headers across every body shape instead.
				ff.Headers = map[string]string{
					"Content-Security-Policy":   "default-src 'self'",
					"Strict-Transport-Security": "max-age=31536000",
					"X-Frame-Options":           "DENY",
					"Content-Type":              "text/html",
				}
			}
			ev, err := plugintest.Evaluate(ctx, orName, ff, true, nil)
			if err != nil {
				t.Fatalf("%s/%s: %v", tc.name, orName, err)
			}
			if ok, detail := plugintest.CheckNegative(ev); !ok {
				t.Fatalf("B4 corpus FP %s/%s: %s", tc.name, orName, detail)
			}
		}
		// WAF block must classify untrusted.
		if tc.name == "waf-block" {
			cls := baseline.ClassifyStatic(tc.status, nil, []byte(tc.body))
			if !cls.Untrusted {
				t.Fatal("WAF corpus must classify untrusted")
			}
		}
	}
}

// TestB9RealOOBSkip schedules the discovered required-OOB plugin.
// What: Engine-level skip proof using the shipped blind plugin.
// Why: B9 must hold for the real artifact, not only a synthetic spec.
func TestB9RealOOBSkip(t *testing.T) {
	specs, _ := discoverAll(t)
	var oobSpec *plugin.PluginSpec
	for i := range specs {
		if specs[i].spec.OOB == plugin.OOBRequired {
			oobSpec = &specs[i].spec
			break
		}
	}
	if oobSpec == nil {
		t.Skip("no required-OOB reference plugin")
	}
	reg := plugin.NewRegistry()
	reg.MustRegister(*oobSpec, "builtin", true)
	cfg := engine.DefaultConfig()
	cfg.Active = true
	e := engine.New(reg, cfg)
	ordered, skipped, err := e.Schedule(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 0 {
		t.Fatal("B9: required-OOB plugin must not schedule without a server")
	}
	found := false
	for _, sk := range skipped {
		if sk.PluginID == oobSpec.ID && strings.Contains(sk.Reason, "oob-not-configured") {
			found = true
		}
	}
	if !found {
		t.Fatalf("B9: skip reason must name oob-not-configured: %+v", skipped)
	}
	// With a server plus active mode the same plugin becomes runnable.
	cfg.OOBServer = "https://oob.example"
	e2 := engine.New(reg, cfg)
	ordered2, _, err := e2.Schedule(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered2) != 1 {
		t.Fatalf("with OOB server the plugin must schedule, got %d", len(ordered2))
	}
}

// TestB5ReferenceIsolation repeats the noisy-plugin proof on reference evidence.
// What: Correlate stability check using a real reference candidate.
// Why: B5 must survive the actual plugins shipping in Phase 3.
func TestB5ReferenceIsolation(t *testing.T) {
	specs, _ := discoverAll(t)
	if len(specs) == 0 {
		t.Skip("no plugins")
	}
	spec := specs[0].spec
	cand := plugin.Candidate{PluginID: spec.ID, Target: "http://example.com/?q=1", OracleName: "reflection"}
	ev := &oracle.Evidence{Verdict: oracle.VerdictAccept, ConfidenceContribution: plugin.ConfidenceConfirmed, Artifacts: map[string]string{"context": "script"}}
	withTests := spec
	withTests.Tests = "tests/fixtures/x/"
	base, err := finding.Build(withTests, cand, ev, "GASH-001", "CWE-79", "", "")
	if err != nil || base == nil {
		t.Fatalf("build: %v", err)
	}
	clean := engine.Correlate([]*finding.Finding{base})
	demoted, _ := engine.NoisyBreaker(map[string]int{base.Fingerprint: 12}, 10)
	if len(demoted) != 1 {
		t.Fatal("noisy breaker must demote")
	}
	again := engine.Correlate([]*finding.Finding{base})
	if len(clean) != len(again) || clean[0].Fingerprint != again[0].Fingerprint {
		t.Fatal("B5: noise must not rewrite core findings")
	}
}

var (
	buildOnce sync.Once
	buildPath string
	buildErr  error
)

// pocBinary builds the reference binary once per test run.
// What: Source-built Tier 3 binary for spawn tests.
// Why: Tests must exercise the shipped source, not a stale checkout binary.
func pocBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		root := repoRoot(t)
		tmp, err := os.MkdirTemp("", "gash-poc")
		if err != nil {
			buildErr = err
			return
		}
		name := "poc-check-testbin"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		out := filepath.Join(tmp, name)
		cmd := exec.Command("go", "build", "-o", out, "./plugins/native/poc-check")
		cmd.Dir = root
		if data, err := cmd.CombinedOutput(); err != nil {
			buildErr = &buildError{msg: string(data), err: err}
			return
		}
		buildPath = out
	})
	if buildErr != nil {
		t.Fatalf("build poc: %v", buildErr)
	}
	return buildPath
}

// buildError carries compiler output for diagnostics.
// What: Build failure wrapper with captured output.
// Why: Bare exit codes never explain which file broke the reference binary.
type buildError struct {
	msg string
	err error
}

// Error implements the error interface.
func (e *buildError) Error() string { return e.err.Error() + ": " + e.msg }

// TestTier3TrustSpawnKill covers digest gating plus lifecycle.
// What: Trust refusal, handshake, run, timeout, and kill for the POC binary.
// Why: B10 plus spawn-kill support must be proven against the real binary.
func TestTier3TrustSpawnKill(t *testing.T) {
	bin := pocBinary(t)
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	manifest := &loader.Tier3Manifest{Binary: bin, Protocol: "grpc", SHA256: sha}
	manifest.ID = "poc-native-header-check"
	manifest.APIVersion = "1.0"

	// Trust refusal first: no approval means no spawn attempt at all.
	if _, err := loader.SpawnPOC(context.Background(), "mem.yaml", manifest, map[string]string{}, 5*time.Second); err == nil {
		t.Fatal("B10: spawn without trust must fail")
	}
	// Digest mismatch fails closed as well.
	bad := *manifest
	bad.SHA256 = strings.Repeat("0", 64)
	if _, err := loader.SpawnPOC(context.Background(), "mem.yaml", &bad, map[string]string{manifest.ID: bad.SHA256}, 5*time.Second); err == nil {
		t.Fatal("digest mismatch must fail")
	}
	trust := map[string]string{manifest.ID: sha}
	client, err := loader.SpawnPOC(context.Background(), "mem.yaml", manifest, trust, 15*time.Second)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer client.Close()
	if !strings.HasPrefix(client.Addr(), "127.0.0.1:") {
		t.Fatalf("loopback-only binding required, got %s", client.Addr())
	}
	cands, err := client.Run(context.Background(), "http://example.com/", 10*time.Second)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(cands) != 1 || cands[0].OracleName != "header" {
		t.Fatalf("one header candidate expected, got %+v", cands)
	}
	// Hung binary work must time out on the call, then die on close.
	if _, err := client.Run(context.Background(), "sleep://hung", 500*time.Millisecond); err == nil {
		t.Fatal("hung run must time out")
	}
}

// ruleFor maps oracle names to GASH rule IDs for e2e finding builds.
// What: Minimal taxonomy bridge for tests.
// Why: Keeps e2e assertions meaningful without importing docs.
func ruleFor(oracleName string) string {
	switch oracleName {
	case "reflection":
		return "GASH-001"
	case "stored", "storedexecution", "stored-execution":
		return "GASH-002"
	case "error", "differential":
		return "GASH-004"
	case "redirect":
		return "GASH-016"
	case "header":
		return "GASH-019"
	case "oob":
		return "GASH-008"
	default:
		return "GASH-000"
	}
}

// cweFor maps oracle names to CWE identifiers for e2e finding builds.
// What: Minimal weakness bridge for tests.
// Why: Completes finding metadata in the drop-in proof.
func cweFor(oracleName string) string {
	switch oracleName {
	case "reflection", "stored", "storedexecution", "stored-execution":
		return "CWE-79"
	case "error", "differential":
		return "CWE-89"
	case "redirect":
		return "CWE-601"
	case "oob":
		return "CWE-918"
	default:
		return "CWE-693"
	}
}
