// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package main

import (
	"io"
	"strings"
	"testing"
)

// TestScanBrowserVerifyRequiresActive: tarayıcı doğrulaması aktif probdur;
// --active olmadan scan erken hata vermeli (OOB kapısıyla aynı disiplin).
func TestScanBrowserVerifyRequiresActive(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--browser-verify"})
	err := root.Execute()
	if err == nil {
		t.Fatal("--browser-verify tek başına hata vermeli")
	}
	if !strings.Contains(err.Error(), "--browser-verify") || !strings.Contains(err.Error(), "--active") {
		t.Fatalf("gerekçe --browser-verify + --active taşımalı: %v", err)
	}
}

// TestScanOOBServerRequiresActive: mevcut OOB kapısı pini (regresyon ağı).
func TestScanOOBServerRequiresActive(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--oob-server", "http://127.0.0.1:9"})
	err := root.Execute()
	if err == nil {
		t.Fatal("--oob-server tek başına hata vermeli")
	}
	if !strings.Contains(err.Error(), "--oob-server") || !strings.Contains(err.Error(), "--active") {
		t.Fatalf("gerekçe --oob-server + --active taşımalı: %v", err)
	}
}
