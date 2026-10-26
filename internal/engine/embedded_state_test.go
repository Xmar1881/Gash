// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/recon"
)

// TestRunReportsEmbeddedStateAndDevBuildStats proves the engine wires the
// GASH-071/072 detectors into the live scan report.
// What: Live scan over a page carrying both an embedded-state secret and a
// development build marker, asserting findings plus the report counters.
// Why: The rules themselves are covered in internal/recon; this test owns the
// engine-side contract (detector registration, gate, stats plumbing).
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
		case recon.RuleIDSPAState:
			state = true
		case recon.RuleIDDevBuild:
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
