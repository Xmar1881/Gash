// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package fuzz

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestSQLiCorpusMatchesJSPlugin locks the Go corpus and the Tier 2 plugin
// SQLI_PROBES array to identical bytes so live engine fuzzing and the
// fixture-tested plugin can never drift apart.
func TestSQLiCorpusMatchesJSPlugin(t *testing.T) {
	path := filepath.Join("..", "..", "plugins", "sqli", "sqli-error-based.js")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read plugin: %v", err)
	}
	arr := regexp.MustCompile(`(?s)const SQLI_PROBES = \[(.*?)\];`).FindSubmatch(data)
	if arr == nil {
		t.Fatal("SQLI_PROBES array not found in plugin")
	}
	var jsProbes []string
	for _, m := range regexp.MustCompile(`"([^"]*)"`).FindAllSubmatch(arr[1], -1) {
		jsProbes = append(jsProbes, string(m[1]))
	}
	goProbes := SQLiProbes()
	if len(jsProbes) != len(goProbes) {
		t.Fatalf("corpus length drift: go %d vs js %d", len(goProbes), len(jsProbes))
	}
	for i := range goProbes {
		if jsProbes[i] != goProbes[i] {
			t.Errorf("probe %d drift: go %q vs js %q", i, goProbes[i], jsProbes[i])
		}
	}
}
