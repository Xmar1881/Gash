// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package finding motor-içi Finding inşası + fingerprint + dedup'tur (A-15/A-16).
// Plugin Finding üretemez (B3); kurucu yalnızca buradadır.
package finding

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// Finding SARIF-uyumlu, GASH-ID birincil bulgudur.
//
// Güven eşlemesi (düzenleme P0.2 — ayrı bir enum YOK, mevcut şema korunur):
//
//	düzenleme terimi              GASH karşılığı (tek doğruluk kaynağı)
//	candidate                     tentative altı belirti / accept-tentative
//	suspected                     firm (güçlü ama tek-kanallı kanıt)
//	confirmed                     confirmed (yeniden üretilebilir + kontrollü)
//	inconclusive                  oracle.VerdictInconclusive → bulgu üretilmez (nil)
//	not_vulnerable_under_test     oracle.VerdictReject → bulgu üretilmez (nil);
//	                              "test edildi, kanıt yok" bilgisi tarama
//	                              istatistiklerinde (engine.Report.Stats) taşınır,
//	                              bulgu listesinde değil.
type Finding struct {
	ID              string                `json:"id"`
	RuleID          string                `json:"rule_id"`
	CWE             string                `json:"cwe,omitempty"`
	Title           string                `json:"title"`
	Description     string                `json:"description"`
	Severity        plugin.Severity       `json:"severity"`
	Confidence      plugin.Confidence     `json:"confidence"`
	Target          string                `json:"target"`
	InjectionPoint  plugin.InjectionPoint `json:"injection_point"`
	Evidence        map[string]string     `json:"evidence,omitempty"`
	Reproducibility map[string]string     `json:"reproducibility,omitempty"`
	PluginID        string                `json:"plugin_id"`
	OracleName      string                `json:"oracle_name"`
	Tags            []string              `json:"tags,omitempty"`
	Fingerprint     string                `json:"fingerprint"`
	DuplicateOf     string                `json:"duplicate_of,omitempty"`
	// Method isteğin HTTP metodudur (kanıt: hangi fiille tekrar üretilir).
	Method string `json:"method,omitempty"`
	// VerificationMethod doğrulama yöntemi + tekrar/kontrol özetidir
	// (kanıt: tespit gerekçesi ve doğrulama yöntemi).
	VerificationMethod string `json:"verification_method,omitempty"`
	// Note oracle gerekçesidir (kanıt: neden bu karar).
	Note string `json:"note,omitempty"`
	// DetectorVersion üreten dedektörün API sürümüdür (izlenebilirlik).
	DetectorVersion string `json:"detector_version,omitempty"`
	// References kural referanslarıdır (CWE URL vb.).
	References []string `json:"references,omitempty"`
	// Remediation düzeltme önerisidir (kural şablonundan, yazar beyanından değil).
	Remediation string `json:"remediation,omitempty"`
	// Masked kanıtın hangi bölümlerinin maskelendiğini listeler.
	Masked []string `json:"masked,omitempty"`
}

// Meta kural şablonundan gelen isteğe bağlı bulgu üstverisidir.
// Boş Meta ile Build çağrısı eski çıktıyla aynıdır (alanlar omitempty).
type Meta struct {
	References  []string
	Remediation string
	Masked      []string
}

// Build Candidate + Evidence'tan Finding üretir (motor-içi).
func Build(spec plugin.PluginSpec, cand plugin.Candidate, ev *oracle.Evidence, ruleID, cwe, title, desc string) (*Finding, error) {
	return BuildWithMeta(spec, cand, ev, ruleID, cwe, title, desc, Meta{})
}

// BuildWithMeta Build ile aynıdır; ek olarak kural-şablon üstverisini işler
// (references/remediation/masked). Boş Meta byte-uyumlu eski çıktıyı verir.
func BuildWithMeta(spec plugin.PluginSpec, cand plugin.Candidate, ev *oracle.Evidence, ruleID, cwe, title, desc string, meta Meta) (*Finding, error) {
	if ev == nil {
		return nil, fmt.Errorf("nil evidence: %w", plugin.ErrValidation)
	}
	if ev.Verdict == oracle.VerdictSkipped {
		return nil, nil
	}
	if ev.Verdict != oracle.VerdictAccept {
		return nil, nil
	}
	conf := ev.ConfidenceContribution
	if conf == "" {
		conf = plugin.ConfidenceTentative // kanıtsız ≤ tentative (B3)
	}
	// Fixture'sız tavan (P6/R-06).
	if spec.Tests == "" && (conf == plugin.ConfidenceStaticExecution || conf == plugin.ConfidenceFirm || conf == plugin.ConfidenceConfirmed) {
		conf = plugin.ConfidenceTentative
	}
	sev := spec.Severity
	if conf == plugin.ConfidenceTentative && severityRank(sev) > severityRank(plugin.SeverityMedium) {
		sev = plugin.SeverityMedium // R-SEV-01
	}
	id, err := newFindingID()
	if err != nil {
		return nil, fmt.Errorf("finding id: %w", err)
	}
	if ruleID == "" {
		ruleID = "GASH-000"
	}
	if title == "" {
		title = spec.Name
	}
	if desc == "" {
		desc = spec.Description
	}
	f := &Finding{
		ID:             id,
		RuleID:         ruleID,
		CWE:            cwe,
		Title:          title,
		Description:    desc,
		Severity:       sev,
		Confidence:     conf,
		Target:         cand.Target,
		InjectionPoint: cand.InjectionPoint,
		Evidence:       ev.Artifacts,
		Reproducibility: map[string]string{
			"repeats": itoa(ev.Repeats),
			"control": ev.ControlResult,
			"note":    ev.Note,
		},
		PluginID:   spec.ID,
		OracleName: cand.OracleName,
		Tags:       append([]string{}, spec.Tags...),
		// Kanıt gerekçesi ve tekrar üretilebilirlik (P0.2, motor-türetilmiş).
		Method:             cand.InjectionPoint.Method,
		VerificationMethod: verificationSummary(cand.OracleName, ev),
		Note:               ev.Note,
		DetectorVersion:    spec.APIVersion,
		References:         append([]string{}, meta.References...),
		Remediation:        meta.Remediation,
		Masked:             append([]string{}, meta.Masked...),
	}
	f.Fingerprint = Fingerprint(f)
	return f, nil
}

// verificationSummary oracle adı + tekrar/kontrol özetidir.
func verificationSummary(oracleName string, ev *oracle.Evidence) string {
	if oracleName == "" {
		oracleName = "unknown"
	}
	return fmt.Sprintf("oracle %s, repeats=%d, control=%s", oracleName, ev.Repeats, ev.ControlResult)
}

func newFindingID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "finding_" + hex.EncodeToString(b[:]), nil
}

func severityRank(s plugin.Severity) int {
	switch s {
	case plugin.SeverityInfo:
		return 0
	case plugin.SeverityLow:
		return 1
	case plugin.SeverityMedium:
		return 2
	case plugin.SeverityHigh:
		return 3
	case plugin.SeverityCritical:
		return 4
	default:
		return 2
	}
}

func itoa(i int) string { return fmt.Sprintf("%d", i) }

// confidenceRank dedup çakışma çözümüdür: confirmed > firm > tentative.
func confidenceRank(c plugin.Confidence) int {
	switch c {
	case plugin.ConfidenceConfirmed:
		return 3
	case plugin.ConfidenceFirm:
		return 2
	case plugin.ConfidenceStaticExecution:
		return 1
	default:
		return 0
	}
}

// Fingerprint sha256(rule + normalized_target + point + evidence_hash) (A-16).
func Fingerprint(f *Finding) string {
	nt := normalizeURL(f.Target)
	pt := f.InjectionPoint.ParamName + "|" + f.InjectionPoint.Method + "|" + f.InjectionPoint.ParamLocation
	ev := ""
	if len(f.Evidence) > 0 {
		keys := make([]string, 0, len(f.Evidence))
		for k := range f.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		for _, k := range keys {
			sb.WriteString(k + "=" + f.Evidence[k] + ";")
		}
		sum := sha256.Sum256([]byte(sb.String()))
		ev = hex.EncodeToString(sum[:])[:16]
	}
	sum := sha256.Sum256([]byte(f.RuleID + "|" + nt + "|" + pt + "|" + ev))
	return hex.EncodeToString(sum[:])[:32]
}

func normalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	// Preserve the fragment: hash-routed SPAs expose distinct surfaces at
	// /#/a and /#/b, and dropping it would collapse their findings.
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		u.Host = u.Hostname()
	}
	u.Host = strings.ToLower(u.Host)
	q := u.Query()
	u.RawQuery = q.Encode() // query sırası normalize
	s := u.String()
	s = strings.TrimSuffix(s, "/")
	return s
}

// Dedup aynı fingerprint'i tekler (çoklu plugin şişirmez).
// Çakışmada yüksek güvenli bulgu kazanır: tentative fuzz anomalisi,
// confirmed oracle kanıtını gölgeleyemez (lab kanıtı: /sqli).
func Dedup(in []*Finding) []*Finding {
	seen := make(map[string]*Finding)
	var out []*Finding
	for _, f := range in {
		if prev, ok := seen[f.Fingerprint]; ok {
			if confidenceRank(f.Confidence) > confidenceRank(prev.Confidence) {
				keepID := prev.ID
				*prev = *f
				prev.ID = keepID
				f.DuplicateOf = keepID
			} else {
				f.DuplicateOf = prev.ID
			}
			continue // bastırılan listeye girmez (correlate'te ayrı sayılır)
		}
		seen[f.Fingerprint] = f
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}
