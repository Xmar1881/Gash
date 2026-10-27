// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/proxypool"
)

func TestResolveProxySettingsMergesAndDeduplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxies.txt")
	content := strings.Join([]string{
		"# datacenter pool",
		"http://127.0.0.1:8081",
		"",
		"http://127.0.0.1:8082",
		"http://127.0.0.1:8081",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveProxySettings("http://127.0.0.1:8080", path, "per-request", "45s", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.URLs) != 3 {
		t.Fatalf("expected 3 unique proxies, got %v", got.URLs)
	}
	if got.Rotate != proxypool.PerRequest {
		t.Fatalf("rotate = %q", got.Rotate)
	}
	if got.Cooldown != 45*time.Second {
		t.Fatalf("cooldown = %s", got.Cooldown)
	}
}

func TestResolveProxySettingsValidation(t *testing.T) {
	if _, err := resolveProxySettings("not-a-proxy", "", "per-host", "30s", false); err == nil ||
		!strings.Contains(err.Error(), "--proxy geçersiz") {
		t.Fatalf("invalid proxy error = %v", err)
	}
	if _, err := resolveProxySettings("", "", "random", "30s", false); err == nil ||
		!strings.Contains(err.Error(), "--proxy-rotate") {
		t.Fatalf("invalid rotate error = %v", err)
	}
	if _, err := resolveProxySettings("", "", "per-host", "soon", false); err == nil ||
		!strings.Contains(err.Error(), "--proxy-cooldown") {
		t.Fatalf("invalid cooldown error = %v", err)
	}
	if _, err := resolveProxySettings("", filepath.Join(t.TempDir(), "missing.txt"), "per-host", "30s", false); err == nil ||
		!strings.Contains(err.Error(), "--proxy-file") {
		t.Fatalf("missing file error = %v", err)
	}
}

func TestScanCmdAcceptsProxyFileFlags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxies.txt")
	if err := os.WriteFile(path, []byte("http://127.0.0.1:9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd, _, err := newRoot().Find([]string{"scan"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"proxy-file", "proxy-rotate", "proxy-cooldown", "no-proxy"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Fatalf("scan is missing --%s", name)
		}
	}
	if err := cmd.Flags().Set("proxy-file", path); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("proxy-rotate", "per-request"); err != nil {
		t.Fatal(err)
	}
}

// TestResolveProxySettingsAutoDiscovery proves the local default list is used
// only when no proxy flag is given, and that explicit flags win.
func TestResolveProxySettingsAutoDiscovery(t *testing.T) {
	t.Setenv("GASH_PROXY_FILE", "")
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll(filepath.Join(dir, ".gash", "proxies"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".gash", "proxies", "alive.txt")
	if err := os.WriteFile(path, []byte("http://127.0.0.1:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveProxySettings("", "", "per-host", "30s", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.URLs) != 1 || got.AutoFile != path {
		t.Fatalf("auto discovery = %+v, want one proxy from %s", got, path)
	}

	off, err := resolveProxySettings("", "", "per-host", "30s", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(off.URLs) != 0 || off.AutoFile != "" {
		t.Fatalf("auto disabled must not load a list: %+v", off)
	}

	explicit, err := resolveProxySettings("http://127.0.0.1:9090", "", "per-host", "30s", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(explicit.URLs) != 1 || explicit.AutoFile != "" || explicit.URLs[0] != "http://127.0.0.1:9090" {
		t.Fatalf("explicit proxy must win: %+v", explicit)
	}
}

// TestDefaultProxyFileEnvOverride proves GASH_PROXY_FILE takes precedence.
func TestDefaultProxyFileEnvOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.txt")
	if err := os.WriteFile(path, []byte("http://127.0.0.1:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GASH_PROXY_FILE", path)
	if got := defaultProxyFile(); got != path {
		t.Fatalf("defaultProxyFile = %q, want %q", got, path)
	}
}

// TestScanCmdAcceptsOOOFlags keeps the new OOB provider flags discoverable.
func TestScanCmdAcceptsOOOFlags(t *testing.T) {
	cmd, _, err := newRoot().Find([]string{"scan"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"oob-server", "oob-token"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Fatalf("scan is missing --%s", name)
		}
	}
}
