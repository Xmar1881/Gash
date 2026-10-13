// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package loader

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// AnyPlatform marks a trust record that is valid on every platform.
// What: Escape hatch for legacy approvals and portable reference builds.
// Why: A digest proven on one platform must not silently grant rights on another.
const AnyPlatform = "*"

// TrustRecord is one explicit Tier 3 approval.
// What: Digest plus platform pin recorded outside the repository.
// Why: Native binaries stay fail-closed until a human approves this exact build.
type TrustRecord struct {
	ID           string `json:"id"`
	SHA256       string `json:"sha256"`
	Platform     string `json:"platform"`
	ManifestPath string `json:"manifest_path,omitempty"`
	TrustedAt    string `json:"trusted_at,omitempty"`
}

// TrustFile is the on-disk trust database shape.
// What: Versioned wrapper around id to TrustRecord mappings.
// Why: A schema field keeps the legacy flat digest map readable forever.
type TrustFile struct {
	Schema  string                 `json:"schema"`
	Records map[string]TrustRecord `json:"records"`
}

// trustFileSchema identifies the current trust file layout.
const trustFileSchema = "gash-trust-v2"

// FormatPlatform renders the GOOS/GOARCH pair used by trust pins.
func FormatPlatform(goos, goarch string) string { return goos + "/" + goarch }

// CurrentPlatform reports the platform the engine runs on.
func CurrentPlatform() string { return FormatPlatform(runtime.GOOS, runtime.GOARCH) }

// LoadTrustRecords reads the trust file, tolerating legacy flat digests.
// What: Version-aware loader for v1 (id to sha256) and v2 (id to record).
// Why: Existing approvals keep working without a manual migration step.
func LoadTrustRecords(path string) (map[string]TrustRecord, error) {
	out := map[string]TrustRecord{}
	if path == "" {
		return out, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("tier3 trust read %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return out, nil
	}
	var file TrustFile
	if err := json.Unmarshal(data, &file); err == nil && file.Schema == trustFileSchema {
		for id, rec := range file.Records {
			rec.ID = id
			if rec.Platform == "" {
				rec.Platform = AnyPlatform
			}
			out[id] = rec
		}
		return out, nil
	}
	legacy := map[string]string{}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, fmt.Errorf("tier3 trust decode %s: %w", path, plugin.ErrValidation)
	}
	for id, sha := range legacy {
		out[id] = TrustRecord{ID: id, SHA256: strings.ToLower(strings.TrimSpace(sha)), Platform: AnyPlatform}
	}
	return out, nil
}

// MigrateLegacyTrust copies legacy approvals into the new trust file.
// What: One-way copy from the legacy path to the new path without touching legacy.
// Why: The S1 default rename keeps existing approvals valid without manual steps.
func MigrateLegacyTrust(newPath, legacyPath string) (bool, error) {
	if strings.TrimSpace(newPath) == "" || strings.TrimSpace(legacyPath) == "" {
		return false, nil
	}
	if newPath == legacyPath {
		return false, nil
	}
	if _, err := os.Stat(newPath); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("tier3 trust stat %s: %w", newPath, err)
	}
	if _, err := os.Stat(legacyPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("tier3 trust stat %s: %w", legacyPath, err)
	}
	records, err := LoadTrustRecords(legacyPath)
	if err != nil {
		return false, err
	}
	if len(records) == 0 {
		return false, nil
	}
	file := TrustFile{Schema: trustFileSchema, Records: records}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return false, fmt.Errorf("tier3 trust encode %s: %w", newPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(newPath), 0o700); err != nil {
		return false, fmt.Errorf("tier3 trust dir %s: %w", filepath.Dir(newPath), err)
	}
	if err := os.WriteFile(newPath, append(data, '\n'), 0o600); err != nil {
		return false, fmt.Errorf("tier3 trust write %s: %w", newPath, err)
	}
	return true, nil
}

// LoadTrustRecordsWithMigration loads the new trust file with legacy fallback.
// What: Migrating loader that reads legacy approvals when the new file is empty.
// Why: Operators with only a legacy file keep working on first run after S1.
func LoadTrustRecordsWithMigration(newPath, legacyPath string) (map[string]TrustRecord, error) {
	records, err := LoadTrustRecords(newPath)
	if err != nil {
		return nil, err
	}
	if len(records) > 0 || newPath == "" || legacyPath == "" || newPath == legacyPath {
		return records, nil
	}
	if _, err := MigrateLegacyTrust(newPath, legacyPath); err != nil {
		return nil, err
	}
	after, err := LoadTrustRecords(newPath)
	if err != nil {
		return nil, err
	}
	if len(after) > 0 {
		return after, nil
	}
	legacy, err := LoadTrustRecords(legacyPath)
	if err != nil {
		return records, nil
	}
	return legacy, nil
}

// SaveTrustRecord upserts one approval and keeps the file owner-only.
// What: Atomic-ish writer with 0600 permissions on the trust file.
// Why: Approvals are security relevant, so group or world read is refused.
func SaveTrustRecord(path string, rec TrustRecord) error {
	if path == "" {
		return fmt.Errorf("tier3 trust: empty path: %w", plugin.ErrValidation)
	}
	if rec.Platform == "" {
		rec.Platform = AnyPlatform
	}
	if rec.TrustedAt == "" {
		rec.TrustedAt = time.Now().UTC().Format(time.RFC3339)
	}
	rec.SHA256 = strings.ToLower(strings.TrimSpace(rec.SHA256))
	records, err := LoadTrustRecords(path)
	if err != nil {
		return err
	}
	records[rec.ID] = rec
	file := TrustFile{Schema: trustFileSchema, Records: records}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("tier3 trust encode %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("tier3 trust dir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("tier3 trust write %s: %w", path, err)
	}
	return nil
}

// CheckTrustRecords enforces digest plus platform before any spawn.
// What: Fail-closed gate used by CLI, engine, and spawn path.
// Why: B10 requires an explicit approval; a foreign platform needs re-pinning.
func CheckTrustRecords(m *Tier3Manifest, records map[string]TrustRecord, platform string) error {
	if m == nil {
		return fmt.Errorf("tier3 trust: nil manifest: %w", plugin.ErrValidation)
	}
	rec, ok := records[m.ID]
	if !ok || strings.TrimSpace(rec.SHA256) == "" {
		return fmt.Errorf("tier3 %s has no trust record (run gash plugins trust): %w", m.ID, plugin.ErrTrustRequired)
	}
	if !strings.EqualFold(strings.TrimSpace(rec.SHA256), strings.TrimSpace(m.SHA256)) {
		return fmt.Errorf("tier3 %s digest mismatch (record=%s manifest=%s): %w",
			m.ID, rec.SHA256, m.SHA256, plugin.ErrTrustRequired)
	}
	if platform != "" && rec.Platform != AnyPlatform && rec.Platform != platform {
		return fmt.Errorf("tier3 %s platform mismatch (trusted=%s host=%s): %w",
			m.ID, rec.Platform, platform, plugin.ErrTrustRequired)
	}
	return nil
}

// PlatformMismatch reports a foreign-platform pin without failing.
// What: Advisory used by listing and info output.
// Why: Operators see "re-pin" instead of a silent skip at scan time.
func PlatformMismatch(rec TrustRecord, platform string) bool {
	return platform != "" && rec.Platform != AnyPlatform && rec.Platform != platform
}
