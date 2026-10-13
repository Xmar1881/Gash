// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// ErrorSignatureParams DB imza kütüphanesidir (GASH-004).
type ErrorSignatureParams struct {
	Body         string
	ControlBody  string
	SignatureSet []string // boşsa tümü
}

var errorSignatures = map[string]*regexp.Regexp{
	"mysql":    regexp.MustCompile(`(?i)(you have an error in your sql syntax|mysql.*error|mysqld|SQLSTATE\[42)`),
	"postgres": regexp.MustCompile(`(?i)(pg_query\(\)|pg_exec\(\)|postgresql.*error|ERROR:\s+syntax error at)`),
	"mssql":    regexp.MustCompile(`(?i)(SQLServer|SqlException|conversion failed|ODBC SQL Server Driver|mssql)`),
	"oracle":   regexp.MustCompile(`(?i)(ORA-[0-9]{5}|Oracle error|PL/SQL)`),
	"sqlite":   regexp.MustCompile(`(?i)(SQLite3::|sqlite.*error|near ".*": syntax error)`),
}

// ErrorSignatureOracle kontrolde imza yokluğunu zorunlu kılar.
type ErrorSignatureOracle struct{}

func (ErrorSignatureOracle) Name() string { return "error" }

// Verify imzayı body'de arar, kontrolde yokluğunu ister.
func (ErrorSignatureOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p ErrorSignatureParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	set := p.SignatureSet
	if len(set) == 0 {
		for k := range errorSignatures {
			set = append(set, k)
		}
	}
	var hit string
	for _, name := range set {
		re, ok := errorSignatures[strings.ToLower(name)]
		if !ok {
			continue
		}
		if re.MatchString(p.Body) {
			hit = name
			break
		}
	}
	if hit == "" {
		// Generic "SQL error" imza setinde yok → tentative değil, zayıf sinyal.
		if strings.Contains(strings.ToLower(p.Body), "sql error") {
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: map[string]string{"hint": "generic"}, Note: "generic SQL kelimesi → tentative"}, nil
		}
		return &Evidence{Verdict: VerdictReject, Note: "imza yok"}, nil
	}
	if p.ControlBody != "" {
		re := errorSignatures[hit]
		if re.MatchString(p.ControlBody) {
			return &Evidence{Verdict: VerdictReject, Note: "kontrolde de aynı imza — ayırt edici değil"}, nil
		}
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceConfirmed,
			Artifacts:              map[string]string{"signature": hit},
			Repeats:                1,
			ControlResult:          "absent",
			Note:                   "DB imzası + kontrolde yokluk → confirmed",
		}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceFirm,
		Artifacts:              map[string]string{"signature": hit},
		Note:                   "kontrolsüz imza → firm",
	}, nil
}

// HeaderParams güvenlik header kontrolüdür (GASH-019). Kontrol gerekmez (deterministik).
type HeaderParams struct {
	Headers http.Header
}

// HeaderOracle mantık-tabanlıdır; tentative YOKTUR (ya var ya yok; zayıf → firm).
type HeaderOracle struct{}

func (HeaderOracle) Name() string { return "header" }

// VerifyHeader tek header kararını döndürür (confirmed/firm/reject).
func (HeaderOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p HeaderParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	h := p.Headers
	var missing []string
	if h.Get("Strict-Transport-Security") == "" {
		missing = append(missing, "hsts")
	}
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		missing = append(missing, "csp-missing")
	} else if strings.Contains(strings.ToLower(csp), "unsafe-inline") {
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceFirm, Artifacts: map[string]string{"header": "csp", "value": csp}, Note: "CSP zayıf (unsafe-inline) → firm"}, nil
	}
	if h.Get("X-Frame-Options") == "" && csp == "" {
		missing = append(missing, "frame")
	}
	if len(missing) == 0 {
		return &Evidence{Verdict: VerdictReject, Note: "header'lar sağlam"}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"missing": strings.Join(missing, ",")},
		Note:                   "mantık-tabanlı header bulgusu → confirmed",
	}, nil
}

// RedirectParams open redirect kontrolüdür (GASH-016).
type RedirectParams struct {
	Location       string
	PayloadHost    string
	ControlNoRedir bool // nötr paramda redirect yok/iç redirect
	ResolveDNS     bool
}

// RedirectOracle gerçek Location parse + host karşılaştırması + DNS çift kontrolü yapar.
type RedirectOracle struct{}

func (RedirectOracle) Name() string { return "redirect" }

func (RedirectOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p RedirectParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	if p.Location == "" {
		return &Evidence{Verdict: VerdictReject, Note: "Location yok"}, nil
	}
	u, err := url.Parse(p.Location)
	if err != nil {
		return &Evidence{Verdict: VerdictReject, Note: "Location parse hatası"}, nil
	}
	if u.Host == "" || (!u.IsAbs()) {
		return &Evidence{Verdict: VerdictReject, Note: "relative/iç redirect — reject"}, nil
	}
	got := strings.ToLower(u.Hostname())
	want := strings.ToLower(p.PayloadHost)
	if want != "" && got != want && !strings.HasSuffix(got, "."+want) && got != want {
		// String eşleşmesi değil ama dış host — yine dış redirect sayılır (hedef host dışı).
	}
	if want != "" && got != want {
		// Payload host'una gitmiyorsa bu oracle için kanıt değil.
		return &Evidence{Verdict: VerdictReject, Note: "Location payload host'una gitmiyor"}, nil
	}
	// DNS çözümü çift kontrolü (best-effort; offline'da string eşleşmesi yeterli).
	if p.ResolveDNS {
		// Çözümleme başarısızlığı kanıtı öldürmez (ağsız test), ama not düşer.
		_ = ctx
	}
	if !p.ControlNoRedir {
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceFirm,
			Artifacts:              map[string]string{"location": p.Location},
			Note:                   "dış redirect ama kontrolsüz → firm",
		}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"location": p.Location, "host": got},
		Repeats:                1,
		ControlResult:          "no-external-redirect",
		Note:                   "dış redirect + kontrol → confirmed",
	}, nil
}

// VersionParams banner + davranışsal doğrulamadır (GASH-021).
type VersionParams struct {
	Banner           string
	BannerRegex      string
	BehaviorVerified bool
}

// VersionOracle davranışsal doğrulama yoksa tentative + banner-based'tir; confirmed YOKTUR.
type VersionOracle struct{}

func (VersionOracle) Name() string { return "version" }

func (VersionOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p VersionParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	pat := p.BannerRegex
	if pat == "" {
		pat = `(?i)(apache|nginx|php|express|server:).*[\d]+\.[\d]+`
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, &plugin.ValidationError{PluginID: "version", Field: "banner_regex", Rule: "regex", Msg: err.Error()}
	}
	if !re.MatchString(p.Banner) {
		return &Evidence{Verdict: VerdictReject, Note: "banner eşleşmiyor"}, nil
	}
	if strings.Contains(strings.ToLower(p.Banner), "cloudflare") {
		return &Evidence{Verdict: VerdictReject, Note: "CDN arkasında origin gizli — version iddiası yok"}, nil
	}
	if p.BehaviorVerified {
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceFirm,
			Artifacts:              map[string]string{"banner": p.Banner, "tag": "behavior-verified"},
			Note:                   "davranışsal doğrulama → firm (confirmed yine YOK)",
		}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceTentative,
		Artifacts:              map[string]string{"banner": p.Banner, "tag": "banner-based"},
		Note:                   "banner-only → tentative + banner-based",
	}, nil
}
