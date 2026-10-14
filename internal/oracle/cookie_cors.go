// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// CookieParams inspects Set-Cookie response headers (GASH-022).
// What: Passive cookie-flag check for Secure/HttpOnly/SameSite.
// Why: Missing flags are deterministic logic findings; no control request needed.
type CookieParams struct {
	Headers http.Header
	// Target is the request URL; used to grade Secure on http vs https.
	Target string
}

// CookieOracle is logic-based; tentative is never emitted (firm minimum on accept).
type CookieOracle struct{}

func (CookieOracle) Name() string { return "cookie" }

// splitSetCookies returns individual Set-Cookie values.
// What: Handles single header value plus newline-joined multi-cookie fixtures.
// Why: net/http joins multiple Set-Cookie values; fixtures use "\n" to encode them.
func splitSetCookies(h http.Header) []string {
	vals := h.Values("Set-Cookie")
	var out []string
	for _, v := range vals {
		// Fixtures may encode two cookies in one value with newline.
		for _, part := range strings.Split(v, "\n") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// cookieFlags parses one Set-Cookie value into flag presence.
// What: Case-insensitive Secure/HttpOnly/SameSite detection.
// Why: Servers vary in case and attribute order; parsing must be stable.
func cookieFlags(setCookie string) (secure, httpOnly bool, sameSite string) {
	parts := strings.Split(setCookie, ";")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if i == 0 {
			continue // name=value pair
		}
		lower := strings.ToLower(p)
		switch {
		case lower == "secure":
			secure = true
		case lower == "httponly":
			httpOnly = true
		case strings.HasPrefix(lower, "samesite"):
			// Forms: SameSite=Strict|Lax|None (case-insensitive, optional spaces).
			eq := strings.Index(p, "=")
			if eq >= 0 && eq+1 < len(p) {
				sameSite = strings.TrimSpace(p[eq+1:])
			} else {
				sameSite = "present"
			}
		}
	}
	return secure, httpOnly, sameSite
}

// isHTTPS reports whether the target uses https (default true when unknown).
// What: Scheme grading for the Secure flag.
// Why: Missing Secure on https is directly exploitable; on plain http the
// transport is already cleartext so the finding is downgraded to firm.
func isHTTPS(target string) bool {
	if strings.TrimSpace(target) == "" {
		return true
	}
	u, err := url.Parse(target)
	if err != nil {
		return true
	}
	if u.Scheme == "" {
		return true
	}
	return strings.EqualFold(u.Scheme, "https")
}

// Verify grades cookie flags deterministically.
// What: Bare cookies confirm; single-flag gaps confirm (HttpOnly) or firm.
// Why: Logic-based findings need no control; untrusted baseline still rejects.
func (CookieOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p CookieParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	cookies := splitSetCookies(p.Headers)
	if len(cookies) == 0 {
		return &Evidence{Verdict: VerdictReject, Note: "Set-Cookie yok — cookie bulgusu yok"}, nil
	}
	https := isHTTPS(p.Target)
	var missingHTTPOnly, missingSecure, missingSameSite []string
	var weakSameSiteNone []string
	for _, c := range cookies {
		name := c
		if i := strings.Index(c, ";"); i >= 0 {
			name = c[:i]
		}
		if i := strings.Index(name, "="); i >= 0 {
			name = strings.TrimSpace(name[:i])
		} else {
			name = strings.TrimSpace(name)
		}
		if name == "" {
			name = "(unnamed)"
		}
		secure, httpOnly, sameSite := cookieFlags(c)
		if !httpOnly {
			missingHTTPOnly = append(missingHTTPOnly, name)
		}
		if !secure {
			missingSecure = append(missingSecure, name)
		}
		if strings.TrimSpace(sameSite) == "" {
			missingSameSite = append(missingSameSite, name)
		} else if strings.EqualFold(strings.TrimSpace(sameSite), "none") && !secure {
			weakSameSiteNone = append(weakSameSiteNone, name)
		}
	}
	// Priority: HttpOnly absence is directly XSS-stealable -> confirmed.
	if len(missingHTTPOnly) > 0 {
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceConfirmed,
			Artifacts:              map[string]string{"cookies": strings.Join(missingHTTPOnly, ","), "missing": "httponly"},
			Note:                   "HttpOnly yok — XSS ile calinabilir -> confirmed",
		}, nil
	}
	// SameSite=None without Secure is rejected by modern browsers -> confirmed misconfig.
	if len(weakSameSiteNone) > 0 {
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceConfirmed,
			Artifacts:              map[string]string{"cookies": strings.Join(weakSameSiteNone, ","), "missing": "samesite-none-without-secure"},
			Note:                   "SameSite=None Secure olmadan etkisiz -> confirmed",
		}, nil
	}
	// Missing Secure on https -> confirmed; on http -> firm (transport zaten acik).
	if len(missingSecure) > 0 {
		if https {
			return &Evidence{
				Verdict:                VerdictAccept,
				ConfidenceContribution: plugin.ConfidenceConfirmed,
				Artifacts:              map[string]string{"cookies": strings.Join(missingSecure, ","), "missing": "secure"},
				Note:                   "https hedefte Secure yok -> confirmed",
			}, nil
		}
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceFirm,
			Artifacts:              map[string]string{"cookies": strings.Join(missingSecure, ","), "missing": "secure"},
			Note:                   "http hedefte Secure yok -> firm (transport zaten acik)",
		}, nil
	}
	// Missing SameSite alone -> firm (CSRF hardening gap, not directly exploitable).
	if len(missingSameSite) > 0 {
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceFirm,
			Artifacts:              map[string]string{"cookies": strings.Join(missingSameSite, ","), "missing": "samesite"},
			Note:                   "SameSite yok -> firm (CSRF hardening eksigi)",
		}, nil
	}
	return &Evidence{Verdict: VerdictReject, Note: "cookie flagleri saglam"}, nil
}

// CORSParams inspects ACAO/ACAC response headers (GASH-023).
// What: Passive wildcard plus reflected-origin check.
// Why: Wildcard with credentials is deterministic; reflection needs request Origin.
type CORSParams struct {
	Headers http.Header
	// RequestOrigin is the Origin sent (empty when the probe did not send one).
	RequestOrigin string
}

// CORSOracle is logic-based; tentative is never emitted.
type CORSOracle struct{}

func (CORSOracle) Name() string { return "cors" }

// Verify grades CORS misconfiguration.
// What: ACAO "*" plus credentials confirms; plain "*" firms; reflected origin confirms/firms.
// Why: No control request needed; untrusted baseline still rejects.
func (CORSOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p CORSParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	acao := strings.TrimSpace(p.Headers.Get("Access-Control-Allow-Origin"))
	if acao == "" {
		return &Evidence{Verdict: VerdictReject, Note: "ACAO yok — CORS bulgusu yok"}, nil
	}
	acac := strings.EqualFold(strings.TrimSpace(p.Headers.Get("Access-Control-Allow-Credentials")), "true")
	origin := strings.TrimSpace(p.RequestOrigin)
	// Reflected origin: response echoes the exact request Origin.
	if origin != "" && acao == origin {
		if acac {
			return &Evidence{
				Verdict:                VerdictAccept,
				ConfidenceContribution: plugin.ConfidenceConfirmed,
				Artifacts:              map[string]string{"acao": acao, "origin": origin, "credentials": "true"},
				Note:                   "origin yansimasi + credentials -> confirmed",
			}, nil
		}
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceFirm,
			Artifacts:              map[string]string{"acao": acao, "origin": origin},
			Note:                   "origin yansimasi (credentialsiz) -> firm",
		}, nil
	}
	if acao == "*" {
		if acac {
			return &Evidence{
				Verdict:                VerdictAccept,
				ConfidenceContribution: plugin.ConfidenceConfirmed,
				Artifacts:              map[string]string{"acao": "*", "credentials": "true"},
				Note:                   "wildcard + credentials -> confirmed",
			}, nil
		}
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceFirm,
			Artifacts:              map[string]string{"acao": "*"},
			Note:                   "wildcard ACAO (credentialsiz) -> firm",
		}, nil
	}
	// "null" origin allowance is a known bypass vector.
	if strings.EqualFold(acao, "null") {
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceFirm,
			Artifacts:              map[string]string{"acao": acao},
			Note:                   "ACAO null -> firm (sandbox bypass riski)",
		}, nil
	}
	return &Evidence{Verdict: VerdictReject, Note: "ACAO allowlist-spesifik — bulgu yok"}, nil
}
