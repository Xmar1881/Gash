// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

func TestRuleForPluginPathTraversal(t *testing.T) {
	rule, cwe := ruleForPlugin("path-traversal-error", "error")
	if rule != "GASH-017" || cwe != "CWE-22" {
		t.Fatalf("path traversal taxonomy = %s/%s, want GASH-017/CWE-22", rule, cwe)
	}
}

func TestRuleForCandidateExposureModes(t *testing.T) {
	cases := []struct {
		mode string
		rule string
		cwe  string
	}{
		{"critical_exposure", "GASH-028", "CWE-200"},
		{"phpinfo", "GASH-057", "CWE-200"},
		{"management_endpoint", "GASH-058", "CWE-200"},
		{"directory_listing", "GASH-059", "CWE-548"},
		{"backup_file", "GASH-037", "CWE-538"},
		{"source_map", "GASH-066", "CWE-540"},
		{"ssi", "GASH-064", "CWE-97"},
		{"xpath", "GASH-034", "CWE-643"},
	}
	for _, tc := range cases {
		cand := plugin.Candidate{
			OracleName:   "error",
			OracleParams: map[string]string{"mode": tc.mode},
		}
		rule, cwe := ruleForCandidate("metabase-api-exposure", cand, nil)
		if rule != tc.rule || cwe != tc.cwe {
			t.Fatalf("mode %s = %s/%s, want %s/%s", tc.mode, rule, cwe, tc.rule, tc.cwe)
		}
	}
}

func TestRuleForPluginAdditionalOracles(t *testing.T) {
	cases := []struct {
		oracle string
		rule   string
		cwe    string
	}{
		{"version", "GASH-021", "CWE-200"},
		{"verb-tamper", "GASH-036", "CWE-650"},
		{"upload-served", "GASH-038", "CWE-434"},
	}
	for _, tc := range cases {
		rule, cwe := ruleForPlugin("check", tc.oracle)
		if rule != tc.rule || cwe != tc.cwe {
			t.Fatalf("oracle %s = %s/%s, want %s/%s", tc.oracle, rule, cwe, tc.rule, tc.cwe)
		}
	}
}
