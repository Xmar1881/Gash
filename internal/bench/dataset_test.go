// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAndValidateShippedDatasets(t *testing.T) {
	repo := repoRoot(t)
	for _, name := range []string{"fixtures.yaml", "fixtures-deep.yaml", "compose-lab.yaml"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(repo, "bench", "datasets", name)
			ds, err := LoadDataset(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if err := Validate(ds, false); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if ds.SHA256 == "" || len(ds.Scenarios) == 0 {
				t.Fatalf("dataset not populated: %+v", ds)
			}
		})
	}
}

func TestValidateRejectsNonLabHost(t *testing.T) {
	ds, err := LoadDataset(filepath.Join(repoRoot(t), "bench", "datasets", "fixtures.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ds.Targets[0].BaseURL = "https://example.com"
	if err := Validate(ds, false); err == nil {
		t.Fatal("non-lab host must be rejected without allowNonLab")
	}
	if err := Validate(ds, true); err != nil {
		t.Fatalf("explicit opt-in must pass: %v", err)
	}
}

func TestValidateRejectsDuplicateScenarioID(t *testing.T) {
	ds, err := LoadDataset(filepath.Join(repoRoot(t), "bench", "datasets", "fixtures.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ds.Scenarios = append(ds.Scenarios, ds.Scenarios[0])
	if err := Validate(ds, false); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate scenario id must be rejected, got %v", err)
	}
}

func TestValidateRejectsUnknownVerifyKind(t *testing.T) {
	ds, err := LoadDataset(filepath.Join(repoRoot(t), "bench", "datasets", "fixtures.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ds.Scenarios[0].Verify.Kind = "made-up"
	if err := Validate(ds, false); err == nil || !strings.Contains(err.Error(), "verify") {
		t.Fatalf("unknown verify kind must be rejected, got %v", err)
	}
}

func TestValidateRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	content := "version: \"1\"\nname: bad\nkind: fixtures\nunknown_field: true\ntargets: []\nscenarios: []\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDataset(path); err == nil {
		t.Fatal("strict decoding must reject unknown fields")
	}
}
