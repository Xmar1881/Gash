// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

func validSpec(id string) PluginSpec {
	max := 100
	return PluginSpec{
		ID: id, Name: "Test plugin name", Description: "Bu plugin test için yeterli uzunlukta açıklamadır.",
		Severity: SeverityMedium, Tags: []string{"test"}, Safe: true, Deep: false, Active: false,
		RequiresAuth: false, MaxRequests: &max, Phase: PhaseProbe, Order: 10, APIVersion: "1.0",
	}
}

func TestValidateOK(t *testing.T) {
	if err := Validate(validSpec("ok-plugin")); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateR01(t *testing.T) {
	s := validSpec("r01")
	s.Safe = true
	s.Active = true
	if err := Validate(s); err == nil {
		t.Fatal("R-01 bekleniyordu")
	}
}

func TestValidateR02R03(t *testing.T) {
	s := validSpec("r02")
	s.OOB = OOBRequired
	s.Active = false
	s.Safe = false
	if err := Validate(s); err == nil {
		t.Fatal("R-02 bekleniyordu")
	}
	s.Active = true
	s.Safe = true
	if err := Validate(s); err == nil {
		t.Fatal("R-03 bekleniyordu")
	}
}

func TestValidateSlug(t *testing.T) {
	s := validSpec("Bad_ID!")
	if err := Validate(s); err == nil {
		t.Fatal("slug hatası bekleniyordu")
	}
}

func TestRegistryConflict(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(validSpec("dup"), "builtin://a", true)
	if err := r.Register(validSpec("dup"), "user://b", false); err == nil {
		t.Fatal("çakışma hatası bekleniyordu")
	}
	// Built-in kazanır.
	e, _ := r.Get("dup")
	if e.SourcePath != "builtin://a" {
		t.Fatalf("builtin kazanmalı, got %s", e.SourcePath)
	}
}

func TestRegistryOverride(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(validSpec("base"), "builtin://base", true)
	over := validSpec("custom")
	over.Overrides = "base"
	if err := r.Register(over, "user://custom", false); err != nil {
		t.Fatalf("override: %v", err)
	}
}

func TestRegistryDeadOverride(t *testing.T) {
	r := NewRegistry()
	over := validSpec("custom")
	over.Overrides = "yok"
	if err := r.Register(over, "user://custom", false); err == nil {
		t.Fatal("ölü override hatası bekleniyordu")
	}
}

func TestTopoSortOrder(t *testing.T) {
	a := validSpec("a")
	a.Provides = []string{"tech"}
	b := validSpec("b")
	b.Requires = []string{"tech"}
	b.Order = 5
	sorted, err := TopoSort([]PluginSpec{b, a})
	if err != nil {
		t.Fatalf("toposort: %v", err)
	}
	if sorted[0].ID != "a" || sorted[1].ID != "b" {
		t.Fatalf("sıra yanlış: %v", sorted)
	}
}

func TestTopoSortCycle(t *testing.T) {
	a := validSpec("a")
	a.Provides = []string{"pa"}
	a.Requires = []string{"pb"}
	b := validSpec("b")
	b.Provides = []string{"pb"}
	b.Requires = []string{"pa"}
	if _, err := TopoSort([]PluginSpec{a, b}); err == nil {
		t.Fatal("döngü hatası bekleniyordu")
	}
}

func TestSchemaSync(t *testing.T) {
	b, err := GenerateJSONSchema()
	if err != nil {
		t.Fatalf("schema gen: %v", err)
	}
	path := filepath.Join("..", "..", "schemas", "plugin.schema.json")
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("schema dosya yok %s: %v", path, err)
	}
	if string(b) != string(disk) {
		t.Fatal("schemas/plugin.schema.json rules.go ile senkron değil (yeniden üretin)")
	}
}
