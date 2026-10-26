// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package plugintest resolves fixture paths and trust state for the CLI.
// What: Repo-root discovery, JS oracle inference, and trust-file storage.
// Why: `gash plugins test` must work from any working directory without
// hardcoding plugin identities or check counts.
package plugintest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KnownOracles lists oracle names the JS inference may return, most specific first.
// What: Ordered oracle vocabulary shared by inference and validation.
// Why: One list prevents the CLI and the gate tests from drifting apart.
var KnownOracles = []string{
	"stored", "reflection", "differential", "error", "timing",
	"oob", "header", "redirect", "version", "execution",
	"cookie", "cors", "uploadserved",
}

// InferJSOracle returns the first known oracle referenced by a Tier 2 source.
// What: Static oracle detection for `gash plugins test`.
// Why: The fixture runner needs an oracle name without executing the script.
func InferJSOracle(source string) string {
	lower := strings.ToLower(source)
	for _, name := range KnownOracles {
		if strings.Contains(lower, "host.oracles."+name) {
			return name
		}
	}
	return ""
}

// ResolveFixtureRoot turns a spec Tests field into an existing directory.
// What: Working-directory plus plugin-relative plus repo-root fixture lookup.
// Why: Contributors run `gash plugins test` from the repo root, subfolders,
// or a scaffold output directory outside the repository.
func ResolveFixtureRoot(pluginFile, testsField string) string {
	if testsField == "" {
		return ""
	}
	if filepath.IsAbs(testsField) {
		return testsField
	}
	if st, err := os.Stat(testsField); err == nil && st.IsDir() {
		return testsField
	}
	if pluginFile != "" {
		if cand := filepath.Join(filepath.Dir(pluginFile), testsField); true {
			if st, err := os.Stat(cand); err == nil && st.IsDir() {
				return cand
			}
		}
	}
	if root := findRepoRoot(filepath.Dir(pluginFile)); root != "" {
		if cand := filepath.Join(root, testsField); true {
			if st, err := os.Stat(cand); err == nil && st.IsDir() {
				return cand
			}
		}
	}
	return testsField
}

// findRepoRoot walks upward until go.mod is found.
// What: Repository root locator for fixture and plugin paths.
// Why: Relative spec fields stay portable across checkouts.
func findRepoRoot(start string) string {
	abs, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(abs, "go.mod")); err == nil {
			return abs
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return ""
		}
		abs = parent
	}
}

// DefaultTrustPath returns the user-level Tier 3 trust file.
// What: Shared location for explicit native plugin approvals.
// Why: One path keeps CLI writes and engine reads consistent.
func DefaultTrustPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".gash", "trust.db")
}

// LegacyTrustPath returns the pre-S1 trust file location.
// What: Previous default kept for automatic migration.
// Why: Existing approvals stay valid without manual copying.
func LegacyTrustPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".gash", "trust.json")
}

// ResolveTrustPath returns the effective trust file.
// What: Explicit flag plus env override plus default resolution.
// Why: Flag wins over env wins over default; migration only applies to default.
func ResolveTrustPath(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if alt := os.Getenv("GASH_TRUST_FILE"); alt != "" {
		return alt
	}
	return DefaultTrustPath()
}

// LoadTrust reads the trust file into a manifest-id to digest map.
// What: Trust state loader tolerating a missing file and both layouts.
// Why: First-time users have no trust file yet; legacy flat and v2 wrapper
// layouts must both stay readable after the S1 default rename.
func LoadTrust(path string) (map[string]string, error) {
	out := map[string]string{}
	if path == "" {
		return out, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("plugintest load trust %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return out, nil
	}
	var wrapped struct {
		Schema  string `json:"schema"`
		Records map[string]struct {
			SHA256 string `json:"sha256"`
		} `json:"records"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Records != nil {
		for id, rec := range wrapped.Records {
			out[id] = strings.ToLower(strings.TrimSpace(rec.SHA256))
		}
		return out, nil
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("plugintest decode trust %s: %w", path, err)
	}
	return out, nil
}

// SaveTrust persists one approval keyed by manifest ID.
// What: Explicit-approval writer for `gash plugins trust`.
// Why: Approvals survive restarts and are auditable as plain JSON.
func SaveTrust(path, id, sha string) error {
	if path == "" {
		return fmt.Errorf("plugintest save trust: empty path")
	}
	m, err := LoadTrust(path)
	if err != nil {
		return err
	}
	m[id] = strings.ToLower(strings.TrimSpace(sha))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("plugintest trust dir: %w", err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("plugintest trust encode: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("plugintest trust write: %w", err)
	}
	return nil
}
