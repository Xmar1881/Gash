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
