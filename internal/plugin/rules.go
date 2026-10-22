// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

var structValidator = validator.New()

// Tek kural kaynağı (architecture.md A-08). Hem Validate hem schema üretimi buradan beslenir.
// İki ayrı doğrulama mantığı YOKTUR.

var (
	slugRe       = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	apiVersionRe = regexp.MustCompile(`^1\.0$`)
)

const (
	maxIDLen        = 64
	minNameLen      = 3
	maxNameLen      = 120
	minDescLen      = 10
	maxDescLen      = 2000
	minOrder        = 0
	maxOrder        = 1000
	minMaxRequests  = 1
	maxMaxRequests  = 10000
	supportedAPIVer = "1.0"
	schemaID        = "https://github.com/Xmar1881/Gash/raw/main/schemas/plugin-1.0.json"
)

// Validate PluginSpec'i R-01..R-12 + alan kurallarına göre doğrular.
// context.Context almaz (saf fonksiyon); çağıran ctx'i loader/scheduler'da yönetir.
// Struct-tag validasyonu (go-playground/validator) + tek-kaynak R-kuralları birlikte çalışır.
func Validate(s PluginSpec) error {
	// Struct-tag ön kontrolü (spec.go'daki `validate:"required"` tag'leri).
	// Eksik-zorunlu alanları erken yakalar; detay kurallar aşağıda tek kaynaktan uygulanır.
	if err := structValidator.Struct(s); err != nil {
		return &ValidationError{PluginID: s.ID, Field: "struct", Rule: "required", Msg: err.Error()}
	}
	id := s.ID
	fail := func(field, rule, msg string) error {
		return &ValidationError{PluginID: id, Field: field, Rule: rule, Msg: msg}
	}

	if id == "" {
		return fail("id", "required", "id zorunlu")
	}
	if len(id) > maxIDLen || !slugRe.MatchString(id) {
		return fail("id", "slug", "id slug olmalı ^[a-z0-9]+(-[a-z0-9]+)*$, <=64")
	}
	if l := len(strings.TrimSpace(s.Name)); l < minNameLen || len(s.Name) > maxNameLen {
		return fail("name", "length", fmt.Sprintf("name 3-120 karakter olmalı (got %d)", l))
	}
	if l := len(strings.TrimSpace(s.Description)); l < minDescLen || len(s.Description) > maxDescLen {
		return fail("description", "length", fmt.Sprintf("description 10-2000 karakter olmalı (got %d)", l))
	}
	if !validSeverity(s.Severity) {
		return fail("severity", "oneof", fmt.Sprintf("severity info|low|medium|high|critical olmalı (got %q)", s.Severity))
	}
	if len(s.Tags) == 0 {
		return fail("tags", "required", "en az 1 tag zorunlu")
	}
	for _, t := range s.Tags {
		if !slugRe.MatchString(strings.ToLower(t)) {
			return fail("tags", "slug", fmt.Sprintf("tag %q slug olmalı", t))
		}
	}
	if !validPhase(s.Phase) {
		return fail("phase", "oneof", fmt.Sprintf("phase recon|discovery|probe|deep olmalı (got %q)", s.Phase))
	}
	if s.Order < minOrder || s.Order > maxOrder {
		return fail("order", "range", "order 0-1000 olmalı")
	}
	if s.MaxRequests != nil {
		if *s.MaxRequests < minMaxRequests || *s.MaxRequests > maxMaxRequests {
			return fail("max_requests", "R-11", "max_requests 1-10000 olmalı")
		}
	}
	if !apiVersionRe.MatchString(s.APIVersion) {
		return fail("api_version", "R-10", fmt.Sprintf("api_version yalnızca %q desteklenir (got %q)", supportedAPIVer, s.APIVersion))
	}
	if !validOOB(s.OOB) {
		return fail("oob", "enum", fmt.Sprintf("oob ''|optional|required olmalı (got %q)", s.OOB))
	}
	for _, t := range s.RequiresTech {
		if !slugRe.MatchString(strings.ToLower(t)) {
			return fail("requires_tech", "slug", fmt.Sprintf("requires_tech %q slug olmalı", t))
		}
	}
	for _, p := range s.Provides {
		if !slugRe.MatchString(strings.ToLower(p)) {
			return fail("provides", "slug", fmt.Sprintf("provides %q slug olmalı", p))
		}
	}
	if s.Overrides != "" && !slugRe.MatchString(s.Overrides) {
		return fail("overrides", "slug", "overrides slug olmalı")
	}

	// Tutarlılık kuralları R-01..R-03 (fail-closed).
	if s.Safe && s.Active {
		return fail("safe+active", "R-01", "safe=true && active=true geçersiz")
	}
	if s.OOB == OOBRequired && !s.Active {
		return fail("oob+active", "R-02", "oob=required && active=false geçersiz (OOB invasive'dir)")
	}
	if s.OOB == OOBRequired && s.Safe {
		return fail("oob+safe", "R-03", "oob=required && safe=true geçersiz")
	}
	return nil
}

// ValidateWarnings hata-değil-uyarı kurallarıdır (R-04, R-05, R-06, R-12).
// Dönüş: uyarı metinleri (boşsa temiz).
func ValidateWarnings(s PluginSpec) []string {
	var out []string
	if s.Deep && s.Phase != PhaseDeep {
		out = append(out, "R-04: deep=true ama phase != deep")
	}
	if s.Severity == SeverityCritical && s.Safe {
		out = append(out, "R-05: severity=critical && safe=true — inceleme önerilir")
	}
	if s.Tests == "" {
		out = append(out, "R-06: tests='' — bulgular tentative ile sınırlı")
	}
	if s.Phase == PhaseDeep && !s.Deep {
		out = append(out, "R-12: phase=deep ama deep=false — politika filtresi şaşırtabilir")
	}
	return out
}

// CheckRequires bilinmeyen provides referansını yakalar (R-09).
// providesSet: sistemde bilinen tüm provides slug'ları.
func CheckRequires(s PluginSpec, providesSet map[string]bool) error {
	for _, r := range s.Requires {
		if !providesSet[r] {
			return &ValidationError{
				PluginID: s.ID, Field: "requires", Rule: "R-09",
				Msg: fmt.Sprintf("bilinmeyen provides %q", r),
			}
		}
	}
	return nil
}

// OOB sınıflarında oob=required yalnızca izinli kurallarda geçerlidir (evidence-standard GASH-008/010/012/013 + 005/006/015 optional).
// Faz 2'de kural-ID bilgisi plugin'de olmadığı için yalnızca genel tutarlılık zorlanır;
// sınıf-bazlı "OOB geçersiz sınıfta required" kontrolü Tier1 oracle adı üzerinden yapılır.
var oobInvalidOracles = map[string]bool{
	"reflection": true, "stored": true, "header": true, "redirect": true, "version": true, "execution": true,
	"cookie": true, "cors": true, "verb-tamper": true,
}

// CheckOOBOracle kuralı: OOB geçersiz oracle'da oob=required validasyon hatasıdır (G-03).
func CheckOOBOracle(oracleName string, oob OOBRequirement, pluginID string) error {
	if oob == OOBRequired && oobInvalidOracles[strings.ToLower(oracleName)] {
		return &ValidationError{
			PluginID: pluginID, Field: "oob", Rule: "G-03",
			Msg: fmt.Sprintf("oracle %q OOB geçersiz sınıfta, required olamaz", oracleName),
		}
	}
	return nil
}

func validSeverity(s Severity) bool {
	for _, v := range ValidSeverities {
		if s == v {
			return true
		}
	}
	return false
}

func validPhase(p Phase) bool {
	for _, v := range ValidPhases {
		if p == v {
			return true
		}
	}
	return false
}

func validOOB(o OOBRequirement) bool {
	for _, v := range ValidOOB {
		if o == v {
			return true
		}
	}
	return false
}
