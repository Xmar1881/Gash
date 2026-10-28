// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package plugin

import "strings"

// KnownOracles lists the oracle names Tier 2 source inference may return,
// most specific first. One vocabulary is shared by discovery (profile gating)
// and `gash plugins test` (fixture evaluation).
var KnownOracles = []string{
	"stored", "reflection", "differential", "error", "timing",
	"oob", "header", "redirect", "version", "execution",
	"cookie", "cors", "uploadserved",
}

// InferOracleFromSource returns the first known oracle referenced by a Tier 2
// script via `host.oracles.<name>`. Empty means the source needs a manual tag
// or the scheduler falls back to its heuristic.
func InferOracleFromSource(source string) string {
	lower := strings.ToLower(source)
	for _, name := range KnownOracles {
		if strings.Contains(lower, "host.oracles."+name) {
			return name
		}
	}
	return ""
}
