// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// TestStoredWorkflowAcceptsWritePlusRender locks the two-exchange model:
// an accepted store plus an executable render with a clean control reaches
// static-execution-evidence at most (never confirmed without a browser run).
func TestStoredWorkflowAcceptsWritePlusRender(t *testing.T) {
	var o StoredOracle
	ev, err := o.Verify(context.Background(), cls(), false, StoredParams{
		Canary:      "gash_store_ut_1",
		StoreStatus: 200, StoreBody: "<html><body>stored</body></html>",
		RenderBody:  `<html><body><div class="comment"><img src=x onerror=alert(gash_store_ut_1)></div></body></html>`,
		ControlBody: `<html><body><div class="comment">nice post</div></body></html>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceStaticExecution {
		t.Fatalf("stored render statik tavanda kalmali: %+v", ev)
	}
	if ev.Artifacts["workflow"] != "store+render" {
		t.Fatalf("workflow stamp sart: %+v", ev)
	}
	if ev.Artifacts["execution"] != "static" {
		t.Fatalf("browser calismadi isareti sart: %+v", ev)
	}
	if ev.ConfidenceContribution == plugin.ConfidenceConfirmed {
		t.Fatalf("browser calismadan confirmed YOK: %+v", ev)
	}
}

// TestStoredWorkflowRejectsWithoutRenderCanary ensures a missing render
// reflection (filtered) never becomes a finding.
func TestStoredWorkflowRejectsWithoutRenderCanary(t *testing.T) {
	var o StoredOracle
	ev, err := o.Verify(context.Background(), cls(), false, StoredParams{
		Canary:      "gash_store_ut_2",
		StoreStatus: 200, StoreBody: "<html><body>stored</body></html>",
		RenderBody:  `<html><body><div class="comment">nice post</div></body></html>`,
		ControlBody: `<html><body><div class="comment">nice post</div></body></html>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("render yoksa reject: %+v", ev)
	}
}

// TestStoredWorkflowRejectsDirtyControl ensures an indistinguishable control
// (same executable context) cannot become static evidence.
func TestStoredWorkflowRejectsDirtyControl(t *testing.T) {
	var o StoredOracle
	render := `<html><body><div class="comment"><img src=x onerror=alert(gash_store_ut_3)></div></body></html>`
	ev, err := o.Verify(context.Background(), cls(), false, StoredParams{
		Canary:      "gash_store_ut_3",
		StoreStatus: 200, StoreBody: "<html><body>stored</body></html>",
		RenderBody: render, ControlBody: render,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("kirli kontrol reject etmeli: %+v", ev)
	}
	if ev.ConfidenceContribution == plugin.ConfidenceStaticExecution ||
		ev.ConfidenceContribution == plugin.ConfidenceFirm ||
		ev.ConfidenceContribution == plugin.ConfidenceConfirmed {
		t.Fatalf("kirli kontrol FP olmamali: %+v", ev)
	}
}

// TestStoredWorkflowRejectsFailedStore ensures a rejected write cannot be
// relabeled as stored XSS even when the render page already contains the canary.
func TestStoredWorkflowRejectsFailedStore(t *testing.T) {
	var o StoredOracle
	ev, err := o.Verify(context.Background(), cls(), false, StoredParams{
		Canary:      "gash_store_ut_4",
		StoreStatus: 500, StoreBody: "error",
		RenderBody:  `<html><body><img src=x onerror=alert(gash_store_ut_4)></body></html>`,
		ControlBody: `<html><body>clean</body></html>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("basarisiz store reject etmeli: %+v", ev)
	}
}

// TestStoredWorkflowConfirmedNeedsBrowser locks the ceiling: a headless run
// flag without trigger/control stays rejected, and full browser proof is the
// only confirmed path (no new level is invented here).
func TestStoredWorkflowConfirmedNeedsBrowser(t *testing.T) {
	var o StoredOracle
	ev, err := o.Verify(context.Background(), cls(), false, StoredParams{
		Canary:      "gash_store_ut_5",
		StoreStatus: 200, StoreBody: "<html><body>stored</body></html>",
		RenderBody:  `<html><body><script>alert(gash_store_ut_5)</script></body></html>`,
		ControlBody: `<p>clean</p>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.ConfidenceContribution == plugin.ConfidenceConfirmed {
		t.Fatalf("browser kaniti yokken confirmed YOK: %+v", ev)
	}
	ev, err = o.Verify(context.Background(), cls(), false, StoredParams{
		Canary:      "gash_store_ut_5",
		StoreStatus: 200, StoreBody: "<html><body>stored</body></html>",
		RenderBody:      `<html><body><script>alert(gash_store_ut_5)</script></body></html>`,
		ControlBody:     `<p>clean</p>`,
		BrowserVerified: true, BrowserTriggered: true, BrowserControlClean: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
		t.Fatalf("browser kanitiyla confirmed bekleniyordu: %+v", ev)
	}
}
