// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"fmt"
	"sort"
)

// TopoSort faz-içi requires/provides kenarlarını Kahn algoritmasıyla sıralar.
// Deterministik: hazır kuyruğu order+id sıralı. Döngü fail-closed'dır (B-fail).
// Fazlar arası kenar yasaktır (faz-barrier ihlali → validasyon hatası).
func TopoSort(specs []PluginSpec) ([]PluginSpec, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	// provides → üretici id'leri.
	provideToProducers := make(map[string][]string)
	for _, s := range specs {
		for _, p := range s.Provides {
			provideToProducers[p] = append(provideToProducers[p], s.ID)
		}
	}
	byID := make(map[string]PluginSpec, len(specs))
	phaseOf := make(map[string]Phase, len(specs))
	for _, s := range specs {
		if _, dup := byID[s.ID]; dup {
			return nil, fmt.Errorf("toposort duplicate id %q: %w", s.ID, ErrConflict)
		}
		byID[s.ID] = s
		phaseOf[s.ID] = s.Phase
	}
	// Kenarlar + R-09 + faz-barrier kontrolü.
	edges := make(map[string]map[string]bool) // producer → consumers
	indeg := make(map[string]int, len(specs))
	for _, s := range specs {
		indeg[s.ID] = 0
	}
	for _, s := range specs {
		for _, req := range s.Requires {
			producers, ok := provideToProducers[req]
			if !ok {
				return nil, &ValidationError{
					PluginID: s.ID, Field: "requires", Rule: "R-09",
					Msg: fmt.Sprintf("bilinmeyen provides %q", req),
				}
			}
			for _, prod := range producers {
				if prod == s.ID {
					continue
				}
				if phaseOf[prod] != s.Phase {
					return nil, &ValidationError{
						PluginID: s.ID, Field: "requires", Rule: "phase-barrier",
						Msg: fmt.Sprintf("fazlar arası kenar yasak: %q (%s) → %q (%s)", prod, phaseOf[prod], s.ID, s.Phase),
					}
				}
				if edges[prod] == nil {
					edges[prod] = make(map[string]bool)
				}
				if !edges[prod][s.ID] {
					edges[prod][s.ID] = true
					indeg[s.ID]++
				}
			}
		}
	}
	// Kahn (deterministik).
	less := func(a, b string) bool {
		sa, sb := byID[a], byID[b]
		if sa.Order != sb.Order {
			return sa.Order < sb.Order
		}
		return a < b
	}
	var ready []string
	for id, d := range indeg {
		if d == 0 {
			ready = append(ready, id)
		}
	}
	sort.Slice(ready, func(i, j int) bool { return less(ready[i], ready[j]) })
	var out []PluginSpec
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		out = append(out, byID[id])
		// Consumers deterministik sırada azaltılır.
		var consumers []string
		for c := range edges[id] {
			consumers = append(consumers, c)
		}
		sort.Slice(consumers, func(i, j int) bool { return less(consumers[i], consumers[j]) })
		for _, c := range consumers {
			indeg[c]--
			if indeg[c] == 0 {
				ready = append(ready, c)
			}
		}
		sort.Slice(ready, func(i, j int) bool { return less(ready[i], ready[j]) })
	}
	if len(out) != len(specs) {
		var cycle []string
		for id, d := range indeg {
			if d > 0 {
				cycle = append(cycle, id)
			}
		}
		sort.Strings(cycle)
		return nil, &CycleError{Cycle: cycle}
	}
	return out, nil
}

// SortByPhase faz → order → id sırasına sokar; her faz içi toposort uygulanır.
func SortByPhase(specs []PluginSpec) ([]PluginSpec, error) {
	grouped := make(map[Phase][]PluginSpec)
	for _, s := range specs {
		grouped[s.Phase] = append(grouped[s.Phase], s)
	}
	var out []PluginSpec
	for _, p := range ValidPhases {
		g := grouped[p]
		if len(g) == 0 {
			continue
		}
		sorted, err := TopoSort(g)
		if err != nil {
			return nil, fmt.Errorf("phase %s: %w", p, err)
		}
		out = append(out, sorted...)
	}
	return out, nil
}
