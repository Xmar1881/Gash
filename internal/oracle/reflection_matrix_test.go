// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"net/http"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// TestReflectionMatrixPositive maps the §3 fixture matrix positive rows to the
// honest evidence ladder: executable reflections reach static-execution
// evidence at most (never confirmed without a browser run), DOM sink/source
// caps at firm without headless.
func TestReflectionMatrixPositive(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		canary     string
		wantConf   plugin.Confidence
		wantExec   string
		requireExe bool
	}{
		{
			name: "reflected script", body: `<html><body><script>alert(gash_m1)</script></body></html>`,
			canary: "gash_m1", wantConf: plugin.ConfidenceStaticExecution, wantExec: "static", requireExe: true,
		},
		{
			name: "attribute event handler", body: `<html><body><div onerror="alert(gash_m2)">x</div></body></html>`,
			canary: "gash_m2", wantConf: plugin.ConfidenceStaticExecution, wantExec: "static", requireExe: true,
		},
		{
			name: "url javascript", body: `<html><body><a href="javascript:alert(gash_m3)">t</a></body></html>`,
			canary: "gash_m3", wantConf: plugin.ConfidenceStaticExecution, wantExec: "static", requireExe: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var o ReflectionOracle
			ev, err := o.Verify(context.Background(), tc.body, nil, cls(), false, ReflectionParams{
				Canary: tc.canary, Contexts: []string{"html", "attr", "attr-executable", "script", "url", "url-executable"},
				RequireExecutableContext: tc.requireExe, ControlBody: `<p>clean</p>`,
			})
			if err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != VerdictAccept {
				t.Fatalf("accept bekleniyordu: %+v", ev)
			}
			if ev.ConfidenceContribution != tc.wantConf {
				t.Fatalf("confidence %s bekleniyordu, got %s (%s)", tc.wantConf, ev.ConfidenceContribution, ev.Note)
			}
			if ev.Artifacts["execution"] != tc.wantExec {
				t.Fatalf("execution=%q isaretlenmeli: %+v", tc.wantExec, ev)
			}
			if ev.ConfidenceContribution == plugin.ConfidenceConfirmed {
				t.Fatalf("browser calismadan confirmed YOK: %+v", ev)
			}
		})
	}
}

// TestReflectionMatrixNegative maps the §3 negative rows: JSON blocks, encoded
// reflections, comments/strings and indistinguishable controls never reach
// static evidence or above.
func TestReflectionMatrixNegative(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		headers http.Header
		canary  string
	}{
		{name: "raw JSON document", body: `{"q":"gash_m9"}`, headers: http.Header{"Content-Type": []string{"application/json"}}, canary: "gash_m9"},
		{name: "json script block", body: `<script type="application/json">{"q":"gash_m9"}</script>`, canary: "gash_m9"},
		{name: "json block string", body: `<html><body><script>let x = {"a":"gash_m9"};</script></body></html>`, canary: "gash_m9"},
		{name: "encoded entity", body: `<p>&lt;script&gt;gash_m9</p>`, canary: "gash_m9"},
		{name: "html comment", body: `<!-- q=gash_m9 -->`, canary: "gash_m9"},
		{name: "js string", body: `<script>const v = "gash_m9";</script>`, canary: "gash_m9"},
		{name: "js line comment", body: "<script>// gash_m9\nalert(1)</script>", canary: "gash_m9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var o ReflectionOracle
			ev, err := o.Verify(context.Background(), tc.body, tc.headers, cls(), false, ReflectionParams{
				Canary: tc.canary, Contexts: []string{"html", "attr", "attr-executable", "script", "url", "url-executable"},
				RequireExecutableContext: true, ControlBody: `<p>clean</p>`,
			})
			if err != nil {
				t.Fatal(err)
			}
			if ev.Verdict == VerdictAccept {
				switch ev.ConfidenceContribution {
				case plugin.ConfidenceStaticExecution, plugin.ConfidenceFirm, plugin.ConfidenceConfirmed:
					t.Fatalf("negatif fixture FP olmamali: %+v", ev)
				}
			}
		})
	}
}

// TestReflectionMatrixStoredWorkflow notes the stored-XSS boundary: a
// write-then-render round trip through the static oracle still caps at
// static-execution-evidence; browser execution is a separate claim.
func TestReflectionMatrixStoredWorkflow(t *testing.T) {
	var o ReflectionOracle
	rendered := `<html><body><div class="comment"><script>alert(gash_stored)</script></div></body></html>`
	ev, err := o.Verify(context.Background(), rendered, nil, cls(), false, ReflectionParams{
		Canary: "gash_stored", RequireExecutableContext: true, ControlBody: `<p>clean</p>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceStaticExecution {
		t.Fatalf("stored render statik tavanda kalmali: %+v", ev)
	}
	if ev.Artifacts["execution"] != "static" {
		t.Fatalf("browser calismadi isareti sart: %+v", ev)
	}
}

// TestExecutionMatrixDOMCap locks the DOM row: sink+source without headless is
// firm at most, never browser-confirmed.
func TestExecutionMatrixDOMCap(t *testing.T) {
	var o ExecutionOracle
	ev, err := o.Verify(context.Background(), cls(), false, ExecutionParams{
		Sink: "innerHTML", Source: "location.hash", HeadlessEnabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceFirm {
		t.Fatalf("headless yokken DOM tavani firm: %+v", ev)
	}
}
