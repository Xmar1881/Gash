// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package plugintest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInferJSOracleMatrix(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{"host.oracles.stored.verify()", "stored"},
		{"host.oracles.reflection.verify()", "reflection"},
		{"HOST.ORACLES.HEADER.VERIFY()", "header"},
		{"host.oracles.error and host.oracles.header", "error"},
		{"host.oracles.header and host.oracles.error", "error"},
		{"host.oracles.execution", "execution"},
		{"host.oracles.cookie", "cookie"},
		{"host.oracles.cors", "cors"},
		{"host.probe.send()", ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := InferJSOracle(tc.source); got != tc.want {
			t.Fatalf("InferJSOracle(%q) = %q, want %q", tc.source, got, tc.want)
		}
	}
	seen := map[string]bool{}
	for _, name := range KnownOracles {
		if seen[name] {
			t.Fatalf("duplicate oracle %q", name)
		}
		seen[name] = true
	}
}

func TestResolveFixtureRootMatrix(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pluginDir := filepath.Join(root, "plugins", "xss")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootFixtures := filepath.Join(root, "tests", "xss")
	if err := os.MkdirAll(rootFixtures, 0o700); err != nil {
		t.Fatal(err)
	}
	pluginFixtures := filepath.Join(pluginDir, "cases")
	if err := os.MkdirAll(pluginFixtures, 0o700); err != nil {
		t.Fatal(err)
	}
	pluginFile := filepath.Join(pluginDir, "dom.js")
	if err := os.WriteFile(pluginFile, []byte("// x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ResolveFixtureRoot(pluginFile, ""); got != "" {
		t.Fatalf("empty tests = %q", got)
	}
	if got := ResolveFixtureRoot(pluginFile, pluginFixtures); got != pluginFixtures {
		t.Fatalf("absolute = %q", got)
	}
	if got := ResolveFixtureRoot(pluginFile, "cases"); got != pluginFixtures {
		t.Fatalf("plugin-relative = %q", got)
	}
	if got := ResolveFixtureRoot(pluginFile, filepath.Join("tests", "xss")); got != rootFixtures {
		t.Fatalf("repo-relative = %q", got)
	}
	missing := filepath.Join("does", "not", "exist")
	if got := ResolveFixtureRoot(pluginFile, missing); got != missing {
		t.Fatalf("missing = %q", got)
	}
}

func TestFindRepoRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := findRepoRoot(deep); got != root {
		t.Fatalf("findRepoRoot = %q, want %q", got, root)
	}
	orphan := t.TempDir()
	if got := findRepoRoot(orphan); got != "" {
		t.Fatalf("orphan root = %q", got)
	}
}

func TestTrustPathResolutionMatrix(t *testing.T) {
	t.Setenv("GASH_TRUST_FILE", filepath.Join("env", "trust.db"))
	if got := ResolveTrustPath("  explicit.db \t"); got != "  explicit.db \t" {
		t.Fatalf("explicit path = %q", got)
	}
	if got := ResolveTrustPath(""); got != filepath.Join("env", "trust.db") {
		t.Fatalf("env path = %q", got)
	}
	t.Setenv("GASH_TRUST_FILE", "")
	if got := ResolveTrustPath(""); got != DefaultTrustPath() {
		t.Fatalf("default path = %q", got)
	}
	if !strings.HasSuffix(DefaultTrustPath(), filepath.Join(".gash", "trust.db")) {
		t.Fatalf("default trust suffix = %q", DefaultTrustPath())
	}
	if !strings.HasSuffix(LegacyTrustPath(), filepath.Join(".gash", "trust.json")) {
		t.Fatalf("legacy trust suffix = %q", LegacyTrustPath())
	}
}

func TestLoadTrustLayouts(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		path    string
		content string
		want    map[string]string
		wantErr bool
	}{
		{"missing", filepath.Join(dir, "missing.json"), "", map[string]string{}, false},
		{"empty", filepath.Join(dir, "empty.json"), "  \n", map[string]string{}, false},
		{"flat", filepath.Join(dir, "flat.json"), `{"a":"ABC","b":"def"}`, map[string]string{"a": "ABC", "b": "def"}, false},
		{"v2", filepath.Join(dir, "v2.json"), `{"schema":"v2","records":{"a":{"sha256":" ABC "},"b":{"sha256":"DEF"}}}`, map[string]string{"a": "abc", "b": "def"}, false},
		{"malformed", filepath.Join(dir, "bad.json"), `{`, nil, true},
		{"directory", dir, "", nil, true},
		{"empty path", "", "", map[string]string{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.content != "" {
				if err := os.WriteFile(tc.path, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := LoadTrust(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("LoadTrust(%q) = %v, nil", tc.path, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("LoadTrust = %#v, want %#v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("LoadTrust[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestSaveTrustMergesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "trust.json")
	if err := SaveTrust(path, "one", " ABC "); err != nil {
		t.Fatal(err)
	}
	if err := SaveTrust(path, "two", "DEF"); err != nil {
		t.Fatal(err)
	}
	got, err := LoadTrust(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["one"] != "abc" || got["two"] != "def" {
		t.Fatalf("trust = %#v", got)
	}
	if err := SaveTrust("", "x", "y"); err == nil {
		t.Fatal("empty save path must fail")
	}
}

func TestLoadDirMatrix(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"name":"second","target":"https://b"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"target":"https://a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	fixtures, files, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != 2 || len(files) != 2 {
		t.Fatalf("fixtures=%d files=%d", len(fixtures), len(files))
	}
	if fixtures[0].Name != "a" || fixtures[1].Name != "second" {
		t.Fatalf("order/names = %q,%q", fixtures[0].Name, fixtures[1].Name)
	}
	if _, _, err := LoadDir(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing dir must fail")
	}
	if err := os.WriteFile(filepath.Join(dir, "c.json"), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDir(dir); err == nil {
		t.Fatal("malformed fixture must fail")
	}
}
