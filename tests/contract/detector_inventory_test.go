// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package contract holds the cross-cutting invariants of the scanner.
// What: B-gates plus the detector-inventory parity gate.
// Why: Engine-owned detectors became data (registry Specs); the inventory page
// must stay in lockstep with that data instead of drifting by hand.

package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/engine"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// TestDetectorInventoryParity keeps the registry and the inventory page equal.
// What: Every registered detector must appear in docs/detector-inventory.md with
// its rule id, and the page must not list a detector the registry does not have.
// Why: The port made the registry the single source of truth; without this gate
// the documentation could silently describe units that no longer exist (or miss
// a newly registered one), which is exactly the drift the port removed.
func TestDetectorInventoryParity(t *testing.T) {
	root := filepath.Join("..", "..")
	docPath := filepath.Join(root, "docs", "detector-inventory.md")
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	doc := string(data)

	e := engine.New(plugin.NewRegistry(), engine.DefaultConfig())
	specs := e.DetectorSpecs()
	if len(specs) == 0 {
		t.Fatal("no engine-owned detectors registered")
	}
	registered := make(map[string]string, len(specs))
	for _, spec := range specs {
		if spec.RuleID == "" {
			t.Fatalf("detector %q has no rule id", spec.ID)
		}
		registered[spec.ID] = spec.RuleID
	}

	documented := documentedDetectorRules(doc, registered)
	for id, rule := range registered {
		got, ok := documented[id]
		if !ok {
			t.Fatalf("detector %q is registered but missing from %s", id, docPath)
		}
		if got != rule {
			t.Fatalf("detector %q rule=%q but the inventory documents %q", id, rule, got)
		}
	}
	for id := range documented {
		if _, ok := registered[id]; !ok {
			t.Fatalf("inventory documents %q but no such detector is registered", id)
		}
	}
}

// documentedDetectorRules parses the detector table rows from the inventory.
// What: Maps detector id to the rule id declared on the same row.
// Why: The parity check must compare identity and taxonomy together; a row that
// names a detector with the wrong rule is as broken as a missing row. Only rows
// that name a registered detector are considered, so unrelated tables in the
// page can never be mistaken for registry entries.
func documentedDetectorRules(doc string, registered map[string]string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := strings.Split(trimmed, "|")
		if len(cells) < 3 {
			continue
		}
		id := strings.Trim(strings.TrimSpace(cells[1]), "`")
		if _, ok := registered[id]; !ok {
			continue
		}
		out[id] = strings.TrimSpace(cells[2])
	}
	return out
}
