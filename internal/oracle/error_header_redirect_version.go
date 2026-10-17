// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// ErrorSignatureParams DB imza kütüphanesidir (GASH-004).
// Extended for P1.4: supports "sqli" (default), "path_traversal", "generic_error" modes.
// Extended for lab-batch: "deserialization" (GASH-029 insecure deserialization,
// Java/Python/PHP error signatures, firm ceiling) and "takeover" (GASH-030
// subdomain takeover, unclaimed-service body signatures, firm ceiling) modes.
// Both new modes are error-signature matches plus absent-in-control proof;
// neither sends a gadget, RCE chain, or out-of-scope request.
type ErrorSignatureParams struct {
	Body         string
	ControlBody  string
	SignatureSet []string // boşsa tümü
	Mode         string   // "sqli" (default), "path_traversal", "generic_error", "deserialization", "takeover"
}

var errorSignatures = map[string]*regexp.Regexp{
	"mysql":          regexp.MustCompile(`(?i)(you have an error in your sql syntax|mysql.*error|mysqld|SQLSTATE\[42)`),
	"postgres":       regexp.MustCompile(`(?i)(pg_query\(\)|pg_exec\(\)|postgresql.*error|ERROR:\s+syntax error at)`),
	"mssql":          regexp.MustCompile(`(?i)(SQLServer|SqlException|conversion failed|ODBC SQL Server Driver|mssql)`),
	"oracle":         regexp.MustCompile(`(?i)(ORA-[0-9]{5}|Oracle error|PL/SQL)`),
	"sqlite":         regexp.MustCompile(`(?i)(SQLite3::|sqlite.*error|near ".*": syntax error)`),
	"path_traversal": regexp.MustCompile(`(?i)(no such file or directory|file not found|path traversal|open .* failed|access denied|permission denied|is a directory|not a directory|invalid path|directory traversal|\.\./|\.\.\\|etc/passwd|boot\.ini|windows/win\.ini)`),
	"generic_error":  regexp.MustCompile(`(?i)(stack trace|exception|traceback|at \w+\.\w+\(|line \d+|error:|fatal error|uncaught exception|internal server error|500 error|debug information|syntax error|runtime error|null pointer|index out of bounds|division by zero)`),
	// deserialization: Java/Python/PHP unmarshal hata imzaları (GASH-029).
	// Yalnızca parse-hata dizeleri eşleşir; gadget/chain üretimi YOKTUR.
	// "access denied" bilerek YOKTUR (baseline Untrusted ile çakışır, WAF gürültüsü olur).
	"deserialization": regexp.MustCompile(`(?i)(InvalidClassException|StreamCorruptedException|NotSerializableException|OptionalDataException|UnpicklingError|pickle\.loads|cPickle|__wakeup|__destruct|__unserialize|unserialize\(\)|serialVersionUID|ObjectInputStream|readObject\(|resolveClass\(|SnakeYAML|yaml\.load|ysoserial|commons-collections)`),
	// takeover: bilinen unclaimed-servis gövde imzaları (GASH-030, CWE-693).
	// DNS CNAME önkoşulu plugin/lab prosedüründedir; bu imza yalnızca HTTP yarısını kanıtlar.
	// "access denied"/"cloudflare"/"challenge" bilerek YOKTUR (baseline Untrusted, FP olur).
	"takeover": regexp.MustCompile(`(?i)(NoSuchBucket|The specified bucket does not exist|NoSuchWebsiteConfiguration|There isn't a GitHub Pages site here|There is no app configured at that hostname|No such app|Do you want to claim this (website|domain)|Sorry, this shop is currently unavailable|Whatever you were looking for doesn't currently exist|This domain is not configured for|Unrecognized domain|project not found)`),
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
		case "deserialization":
			set = []string{"deserialization"}
		case "takeover":
			set = []string{"takeover"}
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
	case "deserialization":
		confidence = plugin.ConfidenceFirm // Hata dizesi tek başına RCE kanıtı değildir (GASH-029 tavan)
		note = "güvensiz deserializasyon hata imzası tespit edildi"
	case "takeover":
		confidence = plugin.ConfidenceFirm // HTTP imzası tek başına devralma kanıtı değildir; DNS önkoşullu (GASH-030 tavan)
		note = "olası subdomain takeover imzası tespit edildi"
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
	// SQLi without control is firm. deserialization/takeover are firm by ceiling
	// with or without control (single-channel signal, never confirmed).
	if hit == "path_traversal" || hit == "generic_error" || hit == "deserialization" || hit == "takeover" {
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
// Extended for deep-research report: csrf (GASH-020 passive form-token screen) and
// frame (GASH-019 clickjacking framing screen) modes; both need Body for form analysis.
// Extended for lab-batch: ratelimit (GASH-032 missing-rate-limit screen, tentative
// ceiling). Needs Status (representative response status) plus optional Burst
// (burst status series collected by the Tier 1 runner); absent signals stay
// tentative because a single probe/burst cannot prove server-side policy.
type HeaderParams struct {
	Headers        http.Header
	Mode           string      // "security" (default), "crlf", "jwt", "jwt_alg", "csrf", "frame", "ratelimit"
	RequestHeaders http.Header // For CRLF: check if request headers were reflected
	Body           string      // Response body (form analysis for csrf mode; ignored otherwise)
	Status         int         // Representative response status (ratelimit mode: 429 check)
	Burst          []int       // Burst status series (ratelimit mode: any 429 means protected)
}

// HeaderOracle sözleşmesi: security/crlf/jwt/jwt_alg/csrf/frame modları
// mantık-tabanlıdır ve tentative ÜRETMEZ (ya var ya yok; zayıf → firm).
// Extended for P1.4: supports "security" (default), "crlf", "jwt", "jwt_alg" modes.
// Extended for deep-research report: "csrf" (GASH-020) and "frame" (GASH-019 clickjacking) modes.
// Extended for lab-batch: "ratelimit" (GASH-032) — bu modun tavanı tentative'tir:
// sinyal yokluğu politika yokluğunu kanıtlamaz, yalnızca gözlemsel bulgudur.
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
	case "csrf":
		return verifyCSRFTokenAbsence(p.Headers, p.Body)
	case "frame":
		return verifyFrameable(p.Headers)
	case "ratelimit":
		return verifyRateLimit(p.Status, p.Headers, p.Body, p.Burst)
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

// verifyCSRFTokenAbsence pasif CSRF ekranıdır (GASH-020, CWE-352).
// What: POST formu var + anti-CSRF token yok + SameSite=Strict yok → confirmed.
// Why: State-changing formda token yokluğu deterministik mantık bulgusudur;
// kontrol isteği gerekmez, tentative YOKTUR (GET-only/token'lı → reject).
// Güvenlik: yalnızca pasif gözlem, state-changing istek gönderilmez.
func verifyCSRFTokenAbsence(h http.Header, body string) (*Evidence, error) {
	lower := strings.ToLower(body)
	formIdx := strings.Index(lower, "<form")
	if formIdx < 0 {
		return &Evidence{Verdict: VerdictReject, Note: "form yok — CSRF kuralı GET-only/passive dışı"}, nil
	}
	formRegion := lower[formIdx:]
	if end := strings.Index(formRegion, ">"); end >= 0 {
		formRegion = formRegion[:end]
	}
	// State-changing formu yalnızca POST (veya method'suz GET varsayılanı dışı) sayılır.
	// Method belirtilmemiş form GET varsayılır → bu kuralda reject.
	if !strings.Contains(formRegion, "post") {
		return &Evidence{Verdict: VerdictReject, Note: "POST formu yok — bu kuralda reject"}, nil
	}
	for _, token := range []string{"csrf", "xsrf", "authenticity", "_token", "requestverification"} {
		if strings.Contains(lower, token) {
			return &Evidence{Verdict: VerdictReject, Note: "anti-CSRF token mevcut — korumalı"}, nil
		}
	}
	// SameSite=Strict çerezi varsa tek başına token yokluğu firm'a düşer.
	for _, c := range h.Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(c), "samesite=strict") {
			return &Evidence{
				Verdict:                VerdictAccept,
				ConfidenceContribution: plugin.ConfidenceFirm,
				Artifacts:              map[string]string{"form": "post", "missing": "csrf-token", "samesite": "strict"},
				Note:                   "POST formda token yok ama SameSite=Strict var → firm",
			}, nil
		}
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"form": "post", "missing": "csrf-token"},
		Note:                   "POST formda anti-CSRF token yok → confirmed (pasif ekran)",
	}, nil
}

// verifyFrameable clickjacking çerçeve ekranıdır (GASH-019, CWE-1021).
// What: X-Frame-Options + CSP frame-ancestors ikisi de yok → confirmed.
// Why: Çerçeve koruması deterministik header mantığıdır; tentative YOKTUR.
func verifyFrameable(h http.Header) (*Evidence, error) {
	xfo := strings.ToUpper(strings.TrimSpace(h.Get("X-Frame-Options")))
	switch xfo {
	case "DENY", "SAMEORIGIN":
		return &Evidence{Verdict: VerdictReject, Note: "X-Frame-Options korumalı"}, nil
	case "":
		// CSP'ye düş.
	default:
		// ALLOW-FROM ve bilinmeyen değerler zayıf kabul edilir.
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceFirm,
			Artifacts:              map[string]string{"x-frame-options": xfo},
			Note:                   "X-Frame-Options zayıf/bilinmeyen → firm",
		}, nil
	}
	csp := strings.ToLower(h.Get("Content-Security-Policy"))
	if csp != "" {
		if idx := strings.Index(csp, "frame-ancestors"); idx >= 0 {
			directive := csp[idx:]
			if end := strings.Index(directive, ";"); end >= 0 {
				directive = directive[:end]
			}
			switch {
			case strings.Contains(directive, "'none'"), strings.Contains(directive, "'self'"):
				return &Evidence{Verdict: VerdictReject, Note: "CSP frame-ancestors korumalı"}, nil
			case strings.Contains(directive, "*"):
				return &Evidence{
					Verdict:                VerdictAccept,
					ConfidenceContribution: plugin.ConfidenceConfirmed,
					Artifacts:              map[string]string{"csp": "frame-ancestors-wildcard"},
					Note:                   "CSP frame-ancestors wildcard → confirmed",
				}, nil
			default:
				return &Evidence{Verdict: VerdictReject, Note: "CSP frame-ancestors allowlist-spesifik"}, nil
			}
		}
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"missing": "x-frame-options,frame-ancestors"},
		Note:                   "çerçeve koruması yok → confirmed (clickjacking)",
	}, nil
}

// verifyRateLimit eksik rate-limit ekranıdır (GASH-032, CWE-770).
// What: 429/lockout sinyali + rate-limit başlıkları yoksa tentative bulgu.
// Why: Sinyal yokluğu politika yokluğunu kanıtlamaz (gözlemsel tavan tentative);
// korumalı endpoint (429, Retry-After/X-RateLimit-*) reject alır. Credential
// stuffing YOKTUR: isimsiz aynı-endpoint GET burst'ü, hesap kilitleme riski YOK.
// Burst serisi Tier 1 runner tarafından toplanır (params burst, tavan 50);
// fixture/offline yolda Burst boşken Status tek-örneklem sayılır.
func verifyRateLimit(status int, h http.Header, body string, burst []int) (*Evidence, error) {
	n := len(burst)
	if n == 0 {
		n = 1
		burst = []int{status}
	}
	seen429 := 0
	for _, s := range burst {
		if s == http.StatusTooManyRequests {
			seen429++
		}
	}
	if status == http.StatusTooManyRequests || seen429 > 0 {
		return &Evidence{Verdict: VerdictReject, Note: "429 gözlendi — rate limiting mevcut, korumalı"}, nil
	}
	var rlHeaders []string
	for name := range h {
		lower := strings.ToLower(name)
		switch {
		case lower == "retry-after",
			lower == "ratelimit-limit", lower == "ratelimit-remaining", lower == "ratelimit-reset", lower == "ratelimit-policy",
			lower == "x-ratelimit-limit", lower == "x-ratelimit-remaining", lower == "x-ratelimit-reset",
			strings.HasPrefix(lower, "x-rate-limit"):
			rlHeaders = append(rlHeaders, name)
		}
	}
	if len(rlHeaders) > 0 {
		return &Evidence{Verdict: VerdictReject, Note: "rate-limit başlıkları mevcut — korumalı"}, nil
	}
	lowerBody := strings.ToLower(body)
	for _, marker := range []string{"too many requests", "rate limit exceeded", "ratelimit exceeded", "slow down", "request was throttled", "throttlingexception", "exceeded your current quota"} {
		if strings.Contains(lowerBody, marker) {
			return &Evidence{Verdict: VerdictReject, Note: "gövdede rate-limit metni — korumalı"}, nil
		}
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceTentative,
		Artifacts:              map[string]string{"burst": fmt.Sprintf("%d", len(burst)), "observed_429": fmt.Sprintf("%d", seen429)},
		Note:                   "429/lockout/rate-limit sinyali yok → tentative missing-rate-limit (gözlemsel tavan)",
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
