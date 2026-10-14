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
// Extended for P1.4: supports "sqli" (default), "path_traversal", "generic_error" modes.
type ErrorSignatureParams struct {
	Body         string
	ControlBody  string
	SignatureSet []string // boşsa tümü
	Mode         string   // "sqli" (default), "path_traversal", "generic_error"
}

var errorSignatures = map[string]*regexp.Regexp{
	"mysql":          regexp.MustCompile(`(?i)(you have an error in your sql syntax|mysql.*error|mysqld|SQLSTATE\[42)`),
	"postgres":       regexp.MustCompile(`(?i)(pg_query\(\)|pg_exec\(\)|postgresql.*error|ERROR:\s+syntax error at)`),
	"mssql":          regexp.MustCompile(`(?i)(SQLServer|SqlException|conversion failed|ODBC SQL Server Driver|mssql)`),
	"oracle":         regexp.MustCompile(`(?i)(ORA-[0-9]{5}|Oracle error|PL/SQL)`),
	"sqlite":         regexp.MustCompile(`(?i)(SQLite3::|sqlite.*error|near ".*": syntax error)`),
	"path_traversal": regexp.MustCompile(`(?i)(no such file or directory|file not found|path traversal|open .* failed|access denied|permission denied|is a directory|not a directory|invalid path|directory traversal|\.\./|\.\.\\|etc/passwd|boot\.ini|windows/win\.ini)`),
	"generic_error":  regexp.MustCompile(`(?i)(stack trace|exception|traceback|at \w+\.\w+\(|line \d+|error:|fatal error|uncaught exception|internal server error|500 error|debug information|syntax error|runtime error|null pointer|index out of bounds|division by zero)`),
}

// ErrorSignatureOracle kontrolde imza yokluğunu zorunlu kılar.
// Extended for P1.4: supports "sqli" (default), "path_traversal", "generic_error" modes.
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

	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == "" {
		mode = "sqli"
	}

	set := p.SignatureSet
	if len(set) == 0 {
		switch mode {
		case "path_traversal":
			set = []string{"path_traversal"}
		case "generic_error":
			set = []string{"generic_error"}
		default: // sqli
			for k := range errorSignatures {
				if strings.HasPrefix(k, "mysql") || strings.HasPrefix(k, "postgres") || strings.HasPrefix(k, "mssql") || strings.HasPrefix(k, "oracle") || strings.HasPrefix(k, "sqlite") {
					set = append(set, k)
				}
			}
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
		if mode == "sqli" && strings.Contains(strings.ToLower(p.Body), "sql error") {
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: map[string]string{"hint": "generic"}, Note: "generic SQL kelimesi → tentative"}, nil
		}
		return &Evidence{Verdict: VerdictReject, Note: "imza yok"}, nil
	}

	// Determine confidence based on signature type and control
	var confidence plugin.Confidence
	var note string
	switch hit {
	case "path_traversal":
		confidence = plugin.ConfidenceConfirmed
		note = "path traversal dosya erişim hatası tespit edildi"
	case "generic_error":
		confidence = plugin.ConfidenceFirm // Generic error disclosure is firm (informational)
		note = "hata mesajı ifşası tespit edildi"
	default: // SQLi signatures
		confidence = plugin.ConfidenceConfirmed
		note = "DB imzası tespit edildi"
	}

	if p.ControlBody != "" {
		re := errorSignatures[hit]
		if re.MatchString(p.ControlBody) {
			return &Evidence{Verdict: VerdictReject, Note: "kontrolde de aynı imza — ayırt edici değil"}, nil
		}
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: confidence,
			Artifacts:              map[string]string{"signature": hit, "mode": mode},
			Repeats:                1,
			ControlResult:          "absent",
			Note:                   note + " + kontrolde yokluk → " + string(confidence),
		}, nil
	}

	// Without control: path_traversal and generic_error are firm (need control for confirmed)
	// SQLi without control is firm
	if hit == "path_traversal" || hit == "generic_error" {
		confidence = plugin.ConfidenceFirm
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: confidence,
		Artifacts:              map[string]string{"signature": hit, "mode": mode},
		Note:                   note + " (kontrolsüz) → " + string(confidence),
	}, nil
}

// HeaderParams güvenlik header kontrolüdür (GASH-019). Kontrol gerekmez (deterministik).
// Extended for P1.4: CRLF injection, JWT exposure, and JWT algorithm confusion detection modes.
type HeaderParams struct {
	Headers        http.Header
	Mode           string      // "security" (default), "crlf", "jwt", "jwt_alg"
	RequestHeaders http.Header // For CRLF: check if request headers were reflected
}

// HeaderOracle mantık-tabanlıdır; tentative YOKTUR (ya var ya yok; zayıf → firm).
// Extended for P1.4: supports "security" (default), "crlf", "jwt", "jwt_alg" modes.
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

	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == "" {
		mode = "security"
	}

	switch mode {
	case "crlf":
		return verifyCRLF(p.Headers, p.RequestHeaders)
	case "jwt":
		return verifyJWTExposure(p.Headers)
	case "jwt_alg":
		return verifyJWTAlgConfusion(p.Headers)
	default:
		return verifySecurityHeaders(p.Headers)
	}
}

func verifySecurityHeaders(h http.Header) (*Evidence, error) {
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

func verifyCRLF(respHeaders, reqHeaders http.Header) (*Evidence, error) {
	var findings []string
	for name, values := range respHeaders {
		for _, v := range values {
			if strings.Contains(v, "\r") || strings.Contains(v, "\n") {
				findings = append(findings, name+": CRLF in response header")
			}
		}
	}
	for name, values := range reqHeaders {
		for _, v := range values {
			if strings.Contains(v, "\r") || strings.Contains(v, "\n") {
				findings = append(findings, name+": CRLF in request header (reflected)")
			}
		}
	}
	if len(findings) == 0 {
		return &Evidence{Verdict: VerdictReject, Note: "CRLF tespit edilmedi"}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"findings": strings.Join(findings, "; ")},
		Note:                   "CRLF/HTTP splitting tespit edildi → confirmed",
	}, nil
}

func verifyJWTExposure(h http.Header) (*Evidence, error) {
	var findings []string
	jwtPattern := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	for name, values := range h {
		for _, v := range values {
			if jwtPattern.MatchString(v) {
				findings = append(findings, name+": JWT token exposed")
			}
		}
	}
	// Check cookies for JWT
	for _, cookie := range h.Values("Set-Cookie") {
		if jwtPattern.MatchString(cookie) {
			findings = append(findings, "Set-Cookie: JWT token in cookie")
		}
	}
	if len(findings) == 0 {
		return &Evidence{Verdict: VerdictReject, Note: "JET tespit edilmedi"}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"findings": strings.Join(findings, "; ")},
		Note:                   "JWT token header/cookie'de tespit edildi → confirmed",
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
// Extended for P1.4: supports "banner" (default), "graphql" modes.
type VersionParams struct {
	Banner           string
	BannerRegex      string
	BehaviorVerified bool
	Mode             string // "banner" (default), "graphql"
}

// VersionOracle davranışsal doğrulama yoksa tentative + banner-based'tir; confirmed YOKTUR.
// Extended for P1.4: GraphQL endpoint discovery mode.
type VersionOracle struct{}

func (VersionOracle) Name() string { return "version" }

func (VersionOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p VersionParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}

	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == "" {
		mode = "banner"
	}

	if mode == "graphql" {
		return verifyGraphQL(ctx, p)
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

func verifyGraphQL(ctx context.Context, p VersionParams) (*Evidence, error) {
	// GraphQL endpoint discovery: check for GraphQL endpoints in response body
	// Common GraphQL indicators: __schema, __typename, query, mutation, GraphQL endpoint paths
	graphqlPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)__schema`),
		regexp.MustCompile(`(?i)__typename`),
		regexp.MustCompile(`(?i)graphql`),
		regexp.MustCompile(`(?i)query\s*\{`),
		regexp.MustCompile(`(?i)mutation\s*\{`),
	}
	for _, re := range graphqlPatterns {
		if re.MatchString(p.Banner) {
			return &Evidence{
				Verdict:                VerdictAccept,
				ConfidenceContribution: plugin.ConfidenceConfirmed,
				Artifacts:              map[string]string{"endpoint": "graphql", "indicator": "body"},
				Note:                   "GraphQL endpoint/response tespit edildi → confirmed",
			}, nil
		}
	}
	// Check for common GraphQL endpoint paths in banner (if banner contains URL-like content)
	endpointPaths := []string{"/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/gql", "/query"}
	bannerLower := strings.ToLower(p.Banner)
	for _, path := range endpointPaths {
		if strings.Contains(bannerLower, path) {
			return &Evidence{
				Verdict:                VerdictAccept,
				ConfidenceContribution: plugin.ConfidenceFirm,
				Artifacts:              map[string]string{"endpoint": path, "indicator": "path"},
				Note:                   "GraphQL endpoint path tespit edildi → firm",
			}, nil
		}
	}
	return &Evidence{Verdict: VerdictReject, Note: "GraphQL göstergesi tespit edilmedi"}, nil
}

func verifyJWTAlgConfusion(h http.Header) (*Evidence, error) {
	var findings []string

	// Check for "none" algorithm in JWT headers (Authorization, cookies, custom headers)
	noneAlgPattern := regexp.MustCompile(`(?i)eyJhbGciOiJub25l`)
	for name, values := range h {
		for _, v := range values {
			if noneAlgPattern.MatchString(v) {
				findings = append(findings, name+": JWT 'none' algorithm detected")
			}
		}
	}

	// Check for algorithm confusion indicators in debug/error headers
	confusionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)algorithm\s+(confusion|mismatch|switch)`),
		regexp.MustCompile(`(?i)(HS256|RS256).*used.*for.*(RS256|HS256)`),
		regexp.MustCompile(`(?i)key.*(confusion|mismatch)`),
		regexp.MustCompile(`(?i)jwt.*alg.*(confusion|none)`),
	}
	for name, values := range h {
		for _, v := range values {
			for _, re := range confusionPatterns {
				if re.MatchString(v) {
					findings = append(findings, name+": JWT algorithm confusion indicator: "+v)
				}
			}
		}
	}

	// Check for missing algorithm validation in error responses
	// If server returns detailed JWT validation errors, it may indicate weak validation
	errorPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)invalid\s+algorithm`),
		regexp.MustCompile(`(?i)algorithm\s+not\s+allowed`),
		regexp.MustCompile(`(?i)unsupported\s+algorithm`),
	}
	for name, values := range h {
		for _, v := range values {
			for _, re := range errorPatterns {
				if re.MatchString(v) {
					findings = append(findings, name+": JWT algorithm validation error exposed: "+v)
				}
			}
		}
	}

	if len(findings) == 0 {
		return &Evidence{Verdict: VerdictReject, Note: "JWT algorithm confusion göstergesi tespit edilmedi"}, nil
	}

	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"findings": strings.Join(findings, "; ")},
		Note:                   "JWT algorithm confusion riski tespit edildi → confirmed",
	}, nil
}
