// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

func TestScanSPAState(t *testing.T) {
	const (
		pageURL = "http://target.test/app"
		token   = "ghp_" + "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LmNvBc"
		pass    = "correct-horse-battery-staple"
	)
	pageBody := []byte(`<script id="__NEXT_DATA__" type="application/json">` +
		`{"props":{"pageProps":{"accessToken":"` + token + `","password":"` + pass + `"}}}</script>`)
	jsBody := []byte(`<script>window.__INITIAL_STATE__={"auth":{"refreshToken":"rt_9f8e7d6c5b4a3210"}}</script>`)
	crawl := &discovery.CrawlResult{
		Pages: []discovery.CrawlPage{
			{URL: pageURL, Body: pageBody},
			{URL: "http://target.test/public", Body: []byte(`<html>no state</html>`)},
		},
		JSSources: []discovery.JSSource{
			{URL: pageURL, Body: pageBody, Inline: true},
			{URL: "http://target.test/app.js", Body: jsBody},
		},
	}
	got, stats := scanSPAState(crawl)
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
	got, _ := scanSPAState(&discovery.CrawlResult{Pages: []discovery.CrawlPage{{URL: "http://target.test/", Body: body}}})
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
	crawl := &discovery.CrawlResult{
		Pages: []discovery.CrawlPage{{URL: "http://target.test/", Body: pageBody}},
		JSSources: []discovery.JSSource{
			{URL: "http://target.test/", Body: pageBody, Inline: true},
			{URL: "http://target.test/main.js", Body: jsBody},
			{URL: "http://target.test/prod.js", Body: []byte(`window.__VUE_DEVTOOLS_GLOBAL_HOOK__ = {};`)},
		},
	}
	got, stats := scanDevBuild(crawl)
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
	got, stats := scanDevBuild(&discovery.CrawlResult{Pages: []discovery.CrawlPage{{URL: "http://target.test/", Body: body}}})
	if len(got) != 0 || stats["devbuild_markers"] != 0 {
		t.Fatalf("production noise matched: %+v %+v", got, stats)
	}
}

func TestRunReportsEmbeddedStateAndDevBuildStats(t *testing.T) {
	const token = "ghp_" + "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LmNvBc"
	page := `<html><body><h1>App</h1>` +
		`<script id="__NEXT_DATA__" type="application/json">{"props":{"token":"` + token + `"}}</script>` +
		`<script src="/react-dom.development.js"></script>` +
		`</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/react-dom.development.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`console.log("react-dom.development.js");`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()
	e := New(plugin.NewRegistry(), DefaultConfig())
	reg := e.registry
	if _, err := loader.Discover([]string{writeE2EPlugin(t)}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var state, dev bool
	for _, f := range rep.Findings {
		switch f.RuleID {
		case RuleIDSPAState:
			state = true
		case RuleIDDevBuild:
			dev = true
		}
	}
	if !state || !dev {
		t.Fatalf("missing findings: state=%v dev=%v stats=%+v findings=%+v", state, dev, rep.Stats, rep.Findings)
	}
	if rep.Stats["spa_state_pages"] != 1 || rep.Stats["spa_state_secrets"] != 1 {
		t.Fatalf("spa stats: %+v", rep.Stats)
	}
	if rep.Stats["devbuild_markers"] != 2 {
		t.Fatalf("devbuild stats: %+v", rep.Stats)
	}
}
