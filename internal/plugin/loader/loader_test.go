// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package loader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const tier1Good = `id: open-redirect-param
name: Open Redirect via Query Parameter
description: Detects unvalidated redirect targets in common redirect parameters for testing purposes.
severity: medium
tags: [redirect, client]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 30
api_version: "1.0"
request:
  method: GET
  param_names: [redirect, url]
  payload: "https://gash-canary.example/"
oracle:
  name: redirect
  params:
    expect_external_host: true
`

const tier2Good = `/* ---
id: xss-reflected-basic
name: Reflected XSS basic contexts for testing purposes here
description: Detects reflected XSS via canary reflection in html contexts for testing purposes long enough.
severity: high
tags: [xss, client]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 40
api_version: "1.0"
--- */
function run(probe, ctx) { return []; }
`

const tier3Good = `id: custom-binary-proto-check
name: Custom Binary Protocol Fuzzer for testing purposes here
description: Native protocol checker manifest used only for loader unit tests with enough length.
severity: high
tags: [custom, binary-proto]
safe: false
deep: false
active: true
requires_auth: false
phase: deep
order: 10
api_version: "1.0"
binary: ./bin/custom-proto-check
protocol: grpc
sha256: "a1b2c3"
`

func TestTier1Parse(t *testing.T) {
	spec, f, err := ParseTier1YAML("mem.yaml", []byte(tier1Good))
	if err != nil {
		t.Fatalf("tier1: %v", err)
	}
	if spec.Tier != plugin.TierYAML {
		t.Fatalf("tier %s", spec.Tier)
	}
	if f.Oracle.Name != "redirect" {
		t.Fatalf("oracle %s", f.Oracle.Name)
	}
}

func TestTier1RejectsCode(t *testing.T) {
	bad := tier1Good + "script: evil()\n"
	if _, _, err := ParseTier1YAML("mem.yaml", []byte(bad)); err == nil {
		t.Fatal("kod bloğu reddedilmeli")
	}
}

func TestTier2FrontmatterNoVM(t *testing.T) {
	spec, err := ParseTier2Frontmatter("mem.js", []byte(tier2Good))
	if err != nil {
		t.Fatalf("tier2 frontmatter: %v", err)
	}
	if spec.ID != "xss-reflected-basic" {
		t.Fatalf("id %s", spec.ID)
	}
}

func TestTier2LazyVM(t *testing.T) {
	spec, err := ParseTier2Frontmatter("p.js", []byte(tier2Good))
	if err != nil {
		t.Fatal(err)
	}
	j := NewJSPlugin(*spec, "p.js", "function run(probe, ctx) { return []; }")
	if j.vm != nil {
		t.Fatal("lazy: VM erken başlatılmamalı")
	}
	if err := j.EnsureLoaded(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
}

func TestTier2SandboxNoRequire(t *testing.T) {
	spec, err := ParseTier2Frontmatter("p.js", []byte(tier2Good))
	if err != nil {
		t.Fatal(err)
	}
	j := NewJSPlugin(*spec, "p.js", "function run(probe, ctx) { return require('fs'); }")
	if err := j.EnsureLoaded(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	// run require içermemeli — goja'da require tanımsız olmalı (çalıştırınca hata).
	if err := j.RunTimeout(t.Context(), 2000000000); err == nil {
		t.Fatal("require erişimi engellenmeli")
	}
}

func TestTier2InvalidReturn(t *testing.T) {
	spec, err := ParseTier2Frontmatter("p.js", []byte(tier2Good))
	if err != nil {
		t.Fatal(err)
	}
	j := NewJSPlugin(*spec, "p.js", `function run(probe, ctx) { return "not-an-array"; }`)
	if err := j.EnsureLoaded(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := j.RunTimeout(t.Context(), 2000000000); err == nil {
		t.Fatal("geçersiz dönüş (string) plugin hatası olmalı (B7)")
	}
}

func TestTier3ManifestNoSpawn(t *testing.T) {
	spec, m, err := ParseTier3Manifest("x.gashplugin.yaml", []byte(tier3Good))
	if err != nil {
		t.Fatalf("tier3: %v", err)
	}
	if spec.Tier != plugin.TierNative {
		t.Fatalf("tier %s", spec.Tier)
	}
	// Trust'suz client kurulamaz (B10) — spawn denenmez bile.
	if _, err := NewTier3Client(m, map[string]string{}); err == nil {
		t.Fatal("trust'suz client kurulmamalı")
	}
}

func TestDiscoverDeterministic(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "b.yaml", tier1Good)
	a := tier1Good
	a = replaceID(a, "aaa-first-plugin")
	write(t, dir, "a.yaml", a)
	reg := plugin.NewRegistry()
	warns, err := Discover([]string{dir}, reg)
	if err != nil {
		t.Fatal(err)
	}
	_ = warns
	snap := reg.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("2 plugin bekleniyordu, got %d (%v)", len(snap), warns)
	}
	if snap[0].Spec.ID != "aaa-first-plugin" {
		t.Fatalf("deterministik sıra bozuldu: %v", snap[0].Spec.ID)
	}
}

func replaceID(s, id string) string {
	out := ""
	start := 0
	for i := 0; i < len(s); i++ {
		if i+3 <= len(s) && s[i:i+3] == "id:" {
			// satırı değiştir
			end := i
			for end < len(s) && s[end] != '\n' {
				end++
			}
			out += s[start:i] + "id: " + id
			start = end
			break
		}
	}
	out += s[start:]
	return out
}
