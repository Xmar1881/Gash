// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package plugin, PluginSpec IR (tek doğruluk kaynağı) + Candidate tiplerini tanımlar.
// architecture.md §7.1 (A-07) ve benioku.txt §4.1 karşılığıdır.
package plugin

import "fmt"

// Severity yazar beyanıdır; final severity motor tarafından tavanlanır (R-SEV-01).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ValidSeverities tek kural kaynağının parçasıdır (rules.go + schema üretimi kullanır).
var ValidSeverities = []Severity{
	SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical,
}

// Phase scheduler fazıdır; sabit sıra recon→discovery→probe→deep.
type Phase string

const (
	PhaseRecon     Phase = "recon"
	PhaseDiscovery Phase = "discovery"
	PhaseProbe     Phase = "probe"
	PhaseDeep      Phase = "deep"
)

// ValidPhases tek kural kaynağı.
var ValidPhases = []Phase{PhaseRecon, PhaseDiscovery, PhaseProbe, PhaseDeep}

// PhaseOrder faz sırasını verir (toposort + scheduler kullanır).
func PhaseOrder(p Phase) int {
	switch p {
	case PhaseRecon:
		return 0
	case PhaseDiscovery:
		return 1
	case PhaseProbe:
		return 2
	case PhaseDeep:
		return 3
	default:
		return 99
	}
}

// OOBRequirement OOB gereksinimidir.
type OOBRequirement string

const (
	OOBNone     OOBRequirement = ""
	OOBOptional OOBRequirement = "optional"
	OOBRequired OOBRequirement = "required"
)

// ValidOOB tek kural kaynağı.
var ValidOOB = []OOBRequirement{OOBNone, OOBOptional, OOBRequired}

// PluginTier yükleyici tarafından set edilir; metadata'da yoktur.
type PluginTier string

const (
	TierYAML   PluginTier = "yaml"
	TierJS     PluginTier = "js"
	TierNative PluginTier = "native"
)

// Confidence motor-içidir; plugin API'sinde yazma metodu yoktur (B3).
type Confidence string

const (
	ConfidenceTentative       Confidence = "tentative"
	ConfidenceStaticExecution Confidence = "static-execution-evidence"
	ConfidenceFirm            Confidence = "firm"
	ConfidenceConfirmed       Confidence = "confirmed"
)

// PluginSpec iç temsil (IR). Tüm tier'lar buna derlenir.
type PluginSpec struct {
	ID           string         `json:"id" yaml:"id" validate:"required"`
	Name         string         `json:"name" yaml:"name" validate:"required"`
	Description  string         `json:"description" yaml:"description" validate:"required"`
	Author       string         `json:"author,omitempty" yaml:"author,omitempty"`
	Severity     Severity       `json:"severity" yaml:"severity" validate:"required"`
	Tags         []string       `json:"tags" yaml:"tags" validate:"required"`
	Safe         bool           `json:"safe" yaml:"safe"`
	Deep         bool           `json:"deep" yaml:"deep"`
	Active       bool           `json:"active" yaml:"active"`
	RequiresAuth bool           `json:"requires_auth" yaml:"requires_auth"`
	RequiresTech []string       `json:"requires_tech,omitempty" yaml:"requires_tech,omitempty"`
	MaxRequests  *int           `json:"max_requests,omitempty" yaml:"max_requests,omitempty"`
	Phase        Phase          `json:"phase" yaml:"phase" validate:"required"`
	Order        int            `json:"order" yaml:"order"`
	Requires     []string       `json:"requires,omitempty" yaml:"requires,omitempty"`
	Provides     []string       `json:"provides,omitempty" yaml:"provides,omitempty"`
	Overrides    string         `json:"overrides,omitempty" yaml:"overrides,omitempty"`
	OOB          OOBRequirement `json:"oob,omitempty" yaml:"oob,omitempty"`
	APIVersion   string         `json:"api_version" yaml:"api_version" validate:"required"`
	Tests        string         `json:"tests,omitempty" yaml:"tests,omitempty"`

	Tier PluginTier `json:"-" yaml:"-"`
}

// Source returns insan-okunur kimlik (hata mesajları için).
func (s PluginSpec) Source() string {
	return fmt.Sprintf("%s (%s)", s.ID, s.Tier)
}

// InjectionPoint hedefte enjeksiyon noktasıdır.
type InjectionPoint struct {
	URL           string `json:"url"`
	Method        string `json:"method"`
	ParamName     string `json:"param_name,omitempty"`
	ParamLocation string `json:"param_location,omitempty"` // query/hash/fragment/body/header/path/cookie
	Value         string `json:"value,omitempty"`
	// SourceKind names the client-side source family (query, hash, hash_route).
	// What: keeps query and fragment tests independent in reports.
	SourceKind string `json:"source_kind,omitempty"`
	// TestID is the stable identity of this injection-point test pair.
	TestID string `json:"test_id,omitempty"`
}

// WithValue noktanın kopyasını verilen değerle döner (Tier2 `point.withValue(canary)` karşılığı).
func (p InjectionPoint) WithValue(v string) InjectionPoint {
	p.Value = v
	return p
}

// Candidate plugin'in dönebildiği tek şeydir. Finding ÜRETEMEZ (B3).
// Confidence/Severity alanı YOKTUR — motor-içidir.
type Candidate struct {
	PluginID       string            `json:"plugin_id"`
	Target         string            `json:"target"`
	InjectionPoint InjectionPoint    `json:"injection_point"`
	OracleName     string            `json:"oracle_name"`
	OracleParams   map[string]string `json:"oracle_params,omitempty"`
	RawEvidenceRef string            `json:"raw_evidence_ref,omitempty"`
	TaintLabels    map[string]string `json:"taint_labels,omitempty"`
}

// PluginStatus yürütme sonucudur.
type PluginStatus string

const (
	StatusOK          PluginStatus = "ok"
	StatusError       PluginStatus = "error"
	StatusPolicyError PluginStatus = "policy_error"
	StatusSkipped     PluginStatus = "skipped"
	StatusTimeout     PluginStatus = "timeout"
	StatusPanic       PluginStatus = "panic"
)

// PluginResult scheduler'a döner; tarama durmaz (B7).
type PluginResult struct {
	PluginID   string
	Status     PluginStatus
	Candidates []Candidate
	Reason     string
}

// SkippedPlugin denetlenebilirlik için sessiz drop YOKTUR.
type SkippedPlugin struct {
	PluginID string
	Reason   string
}
