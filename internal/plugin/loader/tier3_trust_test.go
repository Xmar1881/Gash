// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package loader S1 trust migration gates live here.
// What: Legacy-read plus migrate plus default-path coverage.
// Why: The trust.db rename must keep existing approvals working.
package loader

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadLegacyFlatReads verifies the pre-S1 flat digest map stays readable.
// What: Legacy flat layout load check.
// Why: Operators with only trust.json must keep working after S1.
func TestLoadLegacyFlatReads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	legacy := map[string]string{"legacy-plugin": "ABCDEF0123456789"}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := LoadTrustRecords(path)
	if err != nil {
		t.Fatalf("legacy read: %v", err)
	}
	rec, ok := records["legacy-plugin"]
	if !ok {
		t.Fatalf("legacy id missing: %v", records)
	}
	if rec.SHA256 != "abcdef0123456789" {
		t.Fatalf("sha must be lowercased, got %q", rec.SHA256)
	}
	if rec.Platform != AnyPlatform {
		t.Fatalf("legacy platform must be %q, got %q", AnyPlatform, rec.Platform)
	}
}

// TestLoadV2Reads verifies the current wrapper layout.
// What: V2 trust file load check.
// Why: New trust.db writes must round-trip.
func TestLoadV2Reads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.db")
	file := TrustFile{
		Schema: trustFileSchema,
		Records: map[string]TrustRecord{
			"native-x": {SHA256: "aabbcc", Platform: CurrentPlatform()},
		},
	}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := LoadTrustRecords(path)
	if err != nil {
		t.Fatalf("v2 read: %v", err)
	}
	if records["native-x"].SHA256 != "aabbcc" {
		t.Fatalf("v2 sha mismatch: %+v", records["native-x"])
	}
}

// TestMigrateLegacyToDB verifies one-way copy without touching legacy.
// What: S1 migration copy check.
// Why: Legacy approvals must survive migration byte for byte.
func TestMigrateLegacyToDB(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "trust.json")
	newPath := filepath.Join(dir, "trust.db")
	legacy := map[string]string{"migrated-plugin": "DEADbeef"}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateLegacyTrust(newPath, legacyPath)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !migrated {
		t.Fatal("expected migration to run")
	}
	after, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("legacy file must stay untouched")
	}
	records, err := LoadTrustRecords(newPath)
	if err != nil {
		t.Fatalf("new read: %v", err)
	}
	rec, ok := records["migrated-plugin"]
	if !ok {
		t.Fatalf("migrated id missing: %v", records)
	}
	if !strings.EqualFold(rec.SHA256, "deadbeef") {
		t.Fatalf("migrated sha mismatch: %q", rec.SHA256)
	}
}

// TestMigrateNoOverwrite verifies an existing new file wins.
// What: Migration overwrite guard.
// Why: New approvals must never be clobbered by stale legacy content.
func TestMigrateNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "trust.json")
	newPath := filepath.Join(dir, "trust.db")
	if err := os.WriteFile(legacyPath, []byte(`{"p":"aa"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	existing := TrustFile{Schema: trustFileSchema, Records: map[string]TrustRecord{"p": {ID: "p", SHA256: "bb", Platform: AnyPlatform}}}
	data, err := json.Marshal(existing)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateLegacyTrust(newPath, legacyPath)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if migrated {
		t.Fatal("must not overwrite an existing new file")
	}
	records, err := LoadTrustRecords(newPath)
	if err != nil {
		t.Fatal(err)
	}
	if records["p"].SHA256 != "bb" {
		t.Fatalf("new file must stay intact, got %q", records["p"].SHA256)
	}
}

// TestLoadWithMigrationFallback verifies legacy-only installs read through.
// What: Migrating loader fallback check.
// Why: First run after S1 must see legacy approvals even before disk copy.
func TestLoadWithMigrationFallback(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "trust.json")
	newPath := filepath.Join(dir, "trust.db")
	if err := os.WriteFile(legacyPath, []byte(`{"fallback-plugin":"cc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := LoadTrustRecordsWithMigration(newPath, legacyPath)
	if err != nil {
		t.Fatalf("migrating load: %v", err)
	}
	if _, ok := records["fallback-plugin"]; !ok {
		t.Fatalf("fallback record missing: %v", records)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("migration should create the new file: %v", err)
	}
}
