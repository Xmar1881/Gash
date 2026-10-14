// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"strings"
	"testing"
)

func chainSpec(id string, phase Phase, provides, requires, tech []string) PluginSpec {
	return PluginSpec{
		ID: id, Name: "Zincir test plugin aciklama", Description: "Zincir cozumu icin yeterli uzunlukta aciklama metni.",
		Severity: SeverityMedium, Tags: []string{"t"}, Safe: true,
		Phase: phase, Order: 10, APIVersion: "1.0",
		Provides: provides, Requires: requires, RequiresTech: tech,
	}
}

func TestChainTechGate(t *testing.T) {
	detector := chainSpec("wp-detector", PhaseProbe, nil, nil, []string{"wordpress"})
	other := chainSpec("generic", PhaseProbe, nil, nil, nil)

	// Teknoloji bilinmiyorsa kapılanır.
	res, err := ResolveChain(ChainInput{Specs: []PluginSpec{detector, other}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Runnable) != 1 || res.Runnable[0].ID != "generic" {
		t.Fatalf("teknoloji kapısı: %+v", res.Runnable)
	}
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, "requires tech") {
		t.Fatalf("skip sebebi: %+v", res.Skipped)
	}

	// Teknoloji biliniyorsa koşar (--tech wordpress).
	res, err = ResolveChain(ChainInput{
		Specs:     []PluginSpec{detector, other},
		KnownTech: map[string]bool{"wordpress": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Runnable) != 2 {
		t.Fatalf("teknoloji varken ikisi de koşmalı: %+v", res.Runnable)
	}
}

func TestChainMissingProviderSkipsNotFails(t *testing.T) {
	consumer := chainSpec("consumer", PhaseProbe, nil, []string{"yok-olan-yetenek"}, nil)
	loner := chainSpec("loner", PhaseProbe, nil, nil, nil)
	res, err := ResolveChain(ChainInput{Specs: []PluginSpec{consumer, loner}})
	if err != nil {
		t.Fatalf("eksik sağlayıcı tüm çizelgeyi devirmemeli: %v", err)
	}
	if len(res.Runnable) != 1 || res.Runnable[0].ID != "loner" {
		t.Fatalf("runnable: %+v", res.Runnable)
	}
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, "no live provider") {
		t.Fatalf("skip: %+v", res.Skipped)
	}
}

func TestChainCascadeSkip(t *testing.T) {
	// a üretir X; b ister X, üretir Y; c ister Y. a elenirse (teknoloji) b ve c kaskad düşer.
	a := chainSpec("a", PhaseProbe, []string{"x"}, nil, []string{"eski-tech"})
	b := chainSpec("b", PhaseProbe, []string{"y"}, []string{"x"}, nil)
	c := chainSpec("c", PhaseProbe, nil, []string{"y"}, nil)
	res, err := ResolveChain(ChainInput{Specs: []PluginSpec{a, b, c}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Runnable) != 0 {
		t.Fatalf("kaskad: hepsi düşmeli: %+v", res.Runnable)
	}
	if len(res.Skipped) != 3 {
		t.Fatalf("kaskad skip sayısı: %+v", res.Skipped)
	}
}

func TestChainOrderAndCycle(t *testing.T) {
	prod := chainSpec("prod", PhaseProbe, []string{"cap"}, nil, nil)
	prod.Order = 1
	cons := chainSpec("cons", PhaseProbe, nil, []string{"cap"}, nil)
	cons.Order = 99
	res, err := ResolveChain(ChainInput{Specs: []PluginSpec{cons, prod}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Runnable) != 2 || res.Runnable[0].ID != "prod" {
		t.Fatalf("üretici önce: %+v", res.Runnable)
	}
	// Döngü fail-closed.
	x := chainSpec("x", PhaseProbe, []string{"cx"}, []string{"cy"}, nil)
	y := chainSpec("y", PhaseProbe, []string{"cy"}, []string{"cx"}, nil)
	if _, err := ResolveChain(ChainInput{Specs: []PluginSpec{x, y}}); err == nil {
		t.Fatal("döngü hata vermeli")
	}
}

func TestNormalizeTech(t *testing.T) {
	got := NormalizeTech([]string{"WordPress, GraphQL", "php"})
	for _, want := range []string{"wordpress", "graphql", "php"} {
		if !got[want] {
			t.Fatalf("tech %q yok: %v", want, got)
		}
	}
}
