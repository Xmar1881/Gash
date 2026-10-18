// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package fuzz

import (
	"regexp"
	"strings"
	"testing"
)

// TestSQLiCorpusDestructiveFree lint: probes must never carry write/dump or
// credential-grabbing constructs (word boundaries keep UPDATEXML/INSERT-adjacent
// payloads honest — UPDATEXML is a read-only error probe).
func TestSQLiCorpusDestructiveFree(t *testing.T) {
	destructive := regexp.MustCompile(`\b(DROP|DELETE|TRUNCATE|GRANT|UPDATE|INSERT|ALTER)\b`)
	credentials := regexp.MustCompile(`(?i)(password|passwd|credential|secret)`)
	dangerous := []string{"into outfile", "load_file", "xp_cmdshell", "sp_configure"}
	for _, p := range SQLiProbes() {
		if m := destructive.FindString(p); m != "" {
			t.Errorf("probe %q contains destructive keyword %q", p, m)
		}
		if m := credentials.FindString(p); m != "" {
			t.Errorf("probe %q contains credential keyword %q", p, m)
		}
		lower := strings.ToLower(p)
		for _, d := range dangerous {
			if strings.Contains(lower, d) {
				t.Errorf("probe %q contains dangerous construct %q", p, d)
			}
		}
	}
}

func TestSQLiCorpusShape(t *testing.T) {
	if len(SQLiBooleanProbes) != 2 {
		t.Fatalf("boolean pair must be exactly 2 probes, got %d", len(SQLiBooleanProbes))
	}
	if len(SQLiErrorProbes) != 10 {
		t.Fatalf("error probe corpus must be exactly 10, got %d", len(SQLiErrorProbes))
	}
	probes := SQLiProbes()
	if len(probes) != 12 {
		t.Fatalf("full corpus must be 12 probes (engine per-field cap), got %d", len(probes))
	}
	if probes[0] != SQLiBooleanProbes[0] || probes[1] != SQLiBooleanProbes[1] {
		t.Fatalf("boolean pair must run first: %v", probes[:2])
	}
	seen := make(map[string]bool, len(probes))
	for _, p := range probes {
		if strings.TrimSpace(p) == "" {
			t.Fatal("empty probe in corpus")
		}
		if seen[p] {
			t.Fatalf("duplicate probe %q", p)
		}
		seen[p] = true
	}
}
