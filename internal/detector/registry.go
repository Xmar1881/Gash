// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/detector/registry.go
// What: Detector registry: the single enumerable list of engine-owned units.
// Why: "Which units exist, in what order, with which rule" must be data, not
// control flow. The registry makes the engine-owned recon auditable next to the
// plugin catalog, and it lets tests assert the whole set instead of one unit.

package detector

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// Registry holds the engine-owned detectors for one engine instance.
// What: ID-indexed detector set with deterministic ordering.
// Why: Explicit construction (no init-time magic) keeps registration visible
// at the engine wiring site and lets tests build a subset registry.
type Registry struct {
	mu   sync.RWMutex
	byID map[string]Detector
}

// NewRegistry returns an empty registry.
// What: Constructor for explicit engine wiring and tests.
// Why: A fresh registry per engine avoids cross-scan global state.
func NewRegistry() *Registry {
	return &Registry{byID: make(map[string]Detector)}
}

// Register adds one detector after validating its spec.
// What: Rejects duplicate IDs and incomplete specs.
// Why: A detector without rule, CWE, oracle, or version would produce an
// untraceable finding; failing at wiring time beats failing in a report.
func (r *Registry) Register(d Detector) error {
	if d == nil {
		return fmt.Errorf("detector: nil detector")
	}
	s := d.Spec()
	if err := validateSpec(s); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[s.ID]; exists {
		return fmt.Errorf("detector: duplicate id %q", s.ID)
	}
	r.byID[s.ID] = d
	return nil
}

// MustRegister registers a detector and panics on failure.
// What: Wiring-time convenience for statically known detectors.
// Why: Engine wiring is a programming error surface; a duplicate ID must be
// impossible to ship silently.
func (r *Registry) MustRegister(d Detector) {
	if err := r.Register(d); err != nil {
		panic(err)
	}
}

// Get returns one detector by ID.
// What: Lookup used by the engine call sites.
// Why: The engine addresses detectors by ID, never by function reference.
func (r *Registry) Get(id string) (Detector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.byID[id]
	return d, ok
}

// Specs returns every spec ordered by Order then ID.
// What: Deterministic enumeration for docs, tests, and reporting.
// Why: Toposort-free determinism keeps reports stable across builds.
func (r *Registry) Specs() []Spec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Spec, 0, len(r.byID))
	for _, d := range r.byID {
		out = append(out, d.Spec())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// All returns every detector in the Specs order.
// What: Ordered detector enumeration.
// Why: The engine iterates detectors for phase reporting and future scheduling.
func (r *Registry) All() []Detector {
	specs := r.Specs()
	out := make([]Detector, 0, len(specs))
	for _, s := range specs {
		if d, ok := r.Get(s.ID); ok {
			out = append(out, d)
		}
	}
	return out
}

// Len returns the detector count.
// What: Registry size for reporting and tests.
// Why: The scan report must state how many engine-owned units were considered.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// validateSpec enforces the traceability contract of a detector spec.
// What: ID shape plus the identity fields every finding needs.
// Why: Rule/CWE/oracle/version are what make an engine-owned finding auditable
// exactly like a plugin finding; a missing one is a wiring bug.
func validateSpec(s Spec) error {
	if strings.TrimSpace(s.ID) == "" {
		return fmt.Errorf("detector: empty id")
	}
	if !strings.Contains(s.ID, "-") {
		return fmt.Errorf("detector %q: id must be a slug-like identity", s.ID)
	}
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("detector %q: empty name", s.ID)
	}
	if strings.TrimSpace(s.Description) == "" {
		return fmt.Errorf("detector %q: empty description", s.ID)
	}
	if strings.TrimSpace(s.RuleID) == "" {
		return fmt.Errorf("detector %q: empty rule id", s.ID)
	}
	if strings.TrimSpace(s.CWE) == "" {
		return fmt.Errorf("detector %q: empty cwe", s.ID)
	}
	if strings.TrimSpace(s.Oracle) == "" {
		return fmt.Errorf("detector %q: empty oracle", s.ID)
	}
	if strings.TrimSpace(s.DetectorVersion) == "" {
		return fmt.Errorf("detector %q: empty detector version", s.ID)
	}
	if !validSeverity(s.Severity) {
		return fmt.Errorf("detector %q: invalid severity %q", s.ID, s.Severity)
	}
	if !validPhase(s.Phase) {
		return fmt.Errorf("detector %q: invalid phase %q", s.ID, s.Phase)
	}
	if s.MaxRequests < 0 {
		return fmt.Errorf("detector %q: negative max requests", s.ID)
	}
	return nil
}

// validSeverity reports whether the severity is one of the engine set.
// What: Shared enum check mirroring plugin.ValidSeverities.
// Why: Severity must stay inside the same vocabulary as plugin findings.
func validSeverity(s plugin.Severity) bool {
	for _, v := range plugin.ValidSeverities {
		if s == v {
			return true
		}
	}
	return false
}

// validPhase reports whether the phase is one of the engine set.
// What: Shared enum check mirroring plugin.ValidPhases.
// Why: Phase drives reporting and (later) phase-scoped scheduling.
func validPhase(p plugin.Phase) bool {
	for _, v := range plugin.ValidPhases {
		if p == v {
			return true
		}
	}
	return false
}
