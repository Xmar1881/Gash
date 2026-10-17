//go:build !deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package headless

import (
	"testing"
	"time"
)

// TestStubNeverConfirms locks the default-build contract: without -tags deep
// no browser proof is fabricated; callers must stay at firm maximum.
func TestStubNeverConfirms(t *testing.T) {
	_, err := VerifyDOM(t.Context(), "http://127.0.0.1:1/p#x", "http://127.0.0.1:1/p#clean", "true", 2*time.Second)
	if err == nil {
		t.Fatal("default build VerifyDOM must error (requires -tags deep), never confirm")
	}
}

// TestStubSupportedFalse pins the capability flag the engine gates on.
func TestStubSupportedFalse(t *testing.T) {
	if Supported() {
		t.Fatal("default build Supported() false olmalı (browser linklenmez)")
	}
}

// TestStubVerifyXSSNeverConfirms: default build XSS doğrulaması hata verir;
// statik kanıt asla tarayıcı kanıtı gibi sunulamaz.
func TestStubVerifyXSSNeverConfirms(t *testing.T) {
	_, err := VerifyXSS(t.Context(), "http://127.0.0.1:1/p?q=1", "http://127.0.0.1:1/p?q=2", 2*time.Second)
	if err == nil {
		t.Fatal("default build VerifyXSS must error (requires -tags deep), never confirm")
	}
}
