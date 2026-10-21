// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import "testing"

func TestRuleForPluginPathTraversal(t *testing.T) {
	rule, cwe := ruleForPlugin("path-traversal-error", "error")
	if rule != "GASH-017" || cwe != "CWE-22" {
		t.Fatalf("path traversal taxonomy = %s/%s, want GASH-017/CWE-22", rule, cwe)
	}
}
