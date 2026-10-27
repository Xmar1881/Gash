// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestScanSpinnerLifecycle(t *testing.T) {
	setActiveUILang(uiLangTR)
	var buf bytes.Buffer
	sp := newScanSpinner(&buf, "https://example.com")
	sp.isTTY = true // force TTY for test buffer

	sp.Start()
	sp.OnProgress("Sayfa Keşfi", "Test ediliyor...")
	time.Sleep(150 * time.Millisecond)
	sp.OnProgress("Güvenlik Testleri", "Pluginler koşturuluyor...")
	time.Sleep(150 * time.Millisecond)
	sp.Stop()

	out := buf.String()
	if !strings.Contains(out, "Tarama tamamlandı!") {
		t.Errorf("expected spinner output to contain completion message, got %q", out)
	}
	if !strings.Contains(out, "Sayfa Keşfi") && !strings.Contains(out, "Güvenlik Testleri") {
		t.Errorf("expected spinner output to contain phase names, got %q", out)
	}
}

func TestScanSpinnerNonTTYPrintsCleanLines(t *testing.T) {
	setActiveUILang(uiLangTR)
	var buf bytes.Buffer
	sp := newScanSpinner(&buf, "https://example.com")
	sp.isTTY = false

	sp.Start()
	sp.OnProgress("Sayfa Keşfi", "Non-TTY test")
	sp.Stop()

	out := buf.String()
	if strings.Contains(out, "\r") {
		t.Errorf("expected non-TTY output to not contain carriage return, got %q", out)
	}
	if !strings.Contains(out, "Sayfa Keşfi") || !strings.Contains(out, "Tarama tamamlandı!") {
		t.Errorf("expected non-TTY output to log progress lines, got %q", out)
	}
}

// TestScanSpinnerKeepsPhaseDetails locks the phase log: when a phase ends, its
// last detail and measured duration stay visible, not just the current line.
func TestScanSpinnerKeepsPhaseDetails(t *testing.T) {
	setActiveUILang(uiLangTR)
	var buf bytes.Buffer
	sp := newScanSpinner(&buf, "https://example.com")
	sp.isTTY = false

	sp.Start()
	sp.OnProgress("Crawl", "12/50 sayfa · /admin")
	sp.OnProgress("Crawl", "50 sayfa · 140 yüzey · 52 istek")
	sp.OnProgress("JS", "8 dosya · 12 endpoint")
	sp.Stop()

	out := buf.String()
	for _, want := range []string{
		"✔ [Crawl] 50 sayfa · 140 yüzey · 52 istek",
		"› [JS] 8 dosya · 12 endpoint",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("phase log missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\r") {
		t.Fatalf("non-TTY phase log must not use carriage returns: %q", out)
	}
}

func TestScanSpinnerTTYFinalizesPhase(t *testing.T) {
	setActiveUILang(uiLangTR)
	var buf bytes.Buffer
	sp := newScanSpinner(&buf, "https://example.com")
	sp.isTTY = true

	sp.Start()
	sp.OnProgress("Crawl", "50 sayfa")
	sp.OnProgress("JS", "8 dosya")
	sp.Stop()

	out := buf.String()
	if !strings.Contains(out, "✔") || !strings.Contains(out, "[Crawl] 50 sayfa") {
		t.Fatalf("TTY must print a finalized phase line, got %q", out)
	}
}

// TestScanSpinnerTranslatesEngineKeys proves scan progress follows the active
// UI language; the engine only sends keys and arguments.
func TestScanSpinnerTranslatesEngineKeys(t *testing.T) {
	setActiveUILang(uiLangEN)
	t.Cleanup(func() { setActiveUILang(uiLangTR) })
	var buf bytes.Buffer
	sp := newScanSpinner(&buf, "https://example.com")
	sp.isTTY = false
	sp.width = 200

	sp.Start()
	sp.OnProgress("progress.phase.crawl", "progress.detail.crawl.page", 3, 4, "example.com/admin")
	sp.OnProgress("progress.phase.js", "progress.detail.js.done", 8, 12, 1, 2, 15)
	sp.Stop()

	out := buf.String()
	for _, want := range []string{
		"[Page & surface discovery] 3/4 pages · example.com/admin",
		"✔ [JS & source analysis] complete · 8 files · 12 endpoints · 1 secrets · 2 maps · 15 ms",
		"Scan complete!",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("localized progress missing %q:\n%s", want, out)
		}
	}
}
