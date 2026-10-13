// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"fmt"
	"sort"
	"sync"
)

// Registry id → spec + loader kaydıdır. Scheduler'a salt-okunur snapshot verir.
// Aynı id çakışması sessizce ezilmez (R-07); built-in kazanır.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]RegistryEntry
	order   []string // kayıt sırası (deterministik listeleme için)
}

// RegistryEntry tek kayıt.
type RegistryEntry struct {
	Spec       PluginSpec
	SourcePath string
	Builtin    bool
	Trusted    bool // Tier3 için trust durumu
	SkipReason string
}

// NewRegistry boş registry döner.
func NewRegistry() *Registry {
	return &Registry{entries: make(map[string]RegistryEntry)}
}

// Register tek spec kaydeder. Çakışma kuralları:
//   - aynı id varsa ve yeni spec.Overrides hedef id'ye eşit değilse → ErrConflict,
//     mevcut kayıt korunur (built-in kazanır).
//   - Overrides hedef id'ye eşitse bilinçli override kabul edilir (R-07/R-08).
//   - Overrides var ama hedef yoksa → ErrValidation (R-08, ölü override).
func (r *Registry) Register(spec PluginSpec, sourcePath string, builtin bool) error {
	if err := Validate(spec); err != nil {
		return fmt.Errorf("register %s: %w", spec.ID, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if spec.Overrides != "" {
		target, ok := r.entries[spec.Overrides]
		if !ok {
			// Ölü override: hedef yoksa geçersiz (R-08). Kendini override da geçersiz sayılır
			// (hedef henüz kayıtlı değilse).
			return fmt.Errorf("register %s overrides %q: %w", spec.ID, spec.Overrides, &ValidationError{
				PluginID: spec.ID, Field: "overrides", Rule: "R-08", Msg: "hedef id bulunamadı",
			})
		}
		_ = target
		// Bilinçli override: hedefi değiştir (uyarı yok).
		if _, exists := r.entries[spec.ID]; !exists {
			r.order = append(r.order, spec.ID)
		}
		r.entries[spec.ID] = RegistryEntry{Spec: spec, SourcePath: sourcePath, Builtin: builtin}
		return nil
	}

	if existing, ok := r.entries[spec.ID]; ok {
		_ = existing
		return fmt.Errorf("register %s: %w (existing %s wins, use overrides for intentional replace)",
			spec.ID, ErrConflict, existing.SourcePath)
	}
	r.entries[spec.ID] = RegistryEntry{Spec: spec, SourcePath: sourcePath, Builtin: builtin}
	r.order = append(r.order, spec.ID)
	return nil
}

// MustRegister test kolaylığıdır; hata verirse panic atar.
func (r *Registry) MustRegister(spec PluginSpec, sourcePath string, builtin bool) {
	if err := r.Register(spec, sourcePath, builtin); err != nil {
		panic(err)
	}
}

// Get id ile getirir.
func (r *Registry) Get(id string) (RegistryEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[id]
	return e, ok
}

// Len kayıt sayısı.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// Snapshot deterministik (alfabetik) kopya döner (yarış yok).
func (r *Registry) Snapshot() []RegistryEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]RegistryEntry, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Spec.ID < out[j].Spec.ID })
	return out
}

// Specs snapshot'ın spec izdüşümüdür.
func (r *Registry) Specs() []PluginSpec {
	ents := r.Snapshot()
	out := make([]PluginSpec, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Spec)
	}
	return out
}

// MarkTrusted Tier3 trust durumunu günceller.
func (r *Registry) MarkTrusted(id string, trusted bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.entries[id]; ok {
		e.Trusted = trusted
		r.entries[id] = e
	}
}
