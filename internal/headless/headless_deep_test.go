//go:build deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package headless

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/oracle"
)

// domLab serves a deterministic sink page: location.hash carrying the trigger
// token flips a JS marker. Localhost only (httptest), no external traffic.
func domLab() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>lab</title></head><body><div id="sink"></div><script>window.__gash_triggered=false;var h=location.hash||"";if(h.indexOf("gash_trigger")>=0){document.title="triggered";window.__gash_triggered=true;document.getElementById("sink").innerHTML="pwn";}</script></body></html>`)
	}))
}

// TestDeepVerifiesDOMExecution runs the real headless proof when Chrome
// exists, otherwise skips. Sahte browser-confirmed YOK: confirmed only via
// this browser run plus oracle.ExecutionParams.
func TestDeepVerifiesDOMExecution(t *testing.T) {
	if !Available() {
		if os.Getenv("CI") != "" {
			t.Fatal("headless zorunlu: CI ortaminda chrome bulunamadi (no Chrome binary found in CI)")
		}
		t.Skip("headless yok: chrome bulunamadı, skip")
	}
	srv := domLab()
	defer srv.Close()
	// Query farkı + blank-hop: hash-only fark reload tetiklemez, izolasyon şart.
	payloadURL := srv.URL + "/page?p=1#gash_trigger"
	controlURL := srv.URL + "/page?p=2#clean"
	probe := `window.__gash_triggered === true`

	res, err := VerifyDOM(context.Background(), payloadURL, controlURL, probe, 30*time.Second)
	if err != nil {
		t.Fatalf("headless dogrulama calismali: %v", err)
	}
	if !res.Triggered {
		t.Fatal("payload tetiklenmeli (Triggered=true)")
	}
	if !res.ControlClean {
		t.Fatal("kontrol temiz olmali (ControlClean=true)")
	}
	// Headless kanıtla DOM confirmed yolu açık: oracle confirmed verir.
	var o oracle.ExecutionOracle
	ev, err := o.Verify(context.Background(), baseline.Classification{Note: "normal"}, false, oracle.ExecutionParams{
		Sink: "innerHTML", Source: "location.hash",
		HeadlessEnabled: true, Triggered: res.Triggered, ControlClean: res.ControlClean,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != oracle.VerdictAccept || string(ev.ConfidenceContribution) != "confirmed" {
		t.Fatalf("headless kanit confirmed vermeli: %+v", ev)
	}
	// Negatif kontrol: tetiklenmeyen payload confirmed vermez.
	ev2, err := o.Verify(context.Background(), baseline.Classification{Note: "normal"}, false, oracle.ExecutionParams{
		Sink: "innerHTML", Source: "location.hash",
		HeadlessEnabled: true, Triggered: false, ControlClean: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev2.Verdict == oracle.VerdictAccept && string(ev2.ConfidenceContribution) == "confirmed" {
		t.Fatalf("tetiklenmeyen headless confirmed olmamali: %+v", ev2)
	}
}

// TestFindChrome verifies that FindChrome returns a valid executable path.
func TestFindChrome(t *testing.T) {
	p := FindChrome()
	if !Available() {
		if os.Getenv("CI") != "" {
			t.Fatal("FindChrome CI ortaminda chrome binary bulamadi")
		}
		t.Skip("chrome bulunamadi, skip")
	}
	if p == "" {
		t.Fatal("Available() true iken FindChrome() bos donemez")
	}
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		t.Fatalf("FindChrome() gecerli bir dosya dondurmedi: %s (err: %v)", p, err)
	}
}
