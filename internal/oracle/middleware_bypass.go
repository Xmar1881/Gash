// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// MiddlewareBypassParams is one control-vs-bypass comparison for the
// Next.js middleware authorization bypass class (CVE-2025-29927, GASH-069).
// What: Control request without the bypass header plus one request carrying
// an `x-middleware-subrequest` value.
// Why: The header is only meaningful when the control request is actually
// access-denied; a public route must never produce a finding.
type MiddlewareBypassParams struct {
	ControlStatus   int
	ControlLocation string
	ControlBody     string
	BypassStatus    int
	BypassHeaders   http.Header
	BypassBody      string
	Header          string
	HeaderValue     string
	Path            string
}

// MiddlewareBypassOracle decides whether a middleware bypass was observed.
// What: Accept only when control is access-denied (401/403 or login redirect)
// and the bypass request returns a materially different 2xx body.
// Why: Differential evidence is the only defensible signal here; header echo,
// identical bodies, and WAF block pages are explicit rejects.
type MiddlewareBypassOracle struct{}

// Name returns the canonical oracle name.
func (MiddlewareBypassOracle) Name() string { return "middleware-bypass" }

// middlewareBypassMinBody is the minimum meaningful body size; protocol or
// empty 2xx replies are not protected-content proof.
const middlewareBypassMinBody = 32

// middlewareLoginRedirect matches login/session/auth path segments only, so
// paths such as /authors do not look like a login redirect.
var middlewareLoginRedirect = regexp.MustCompile(`(?:^|[/?=&._-])(login|signin|sign-in|sso|auth|session)(?:[/?=&._-]|$)`)

// Verify applies the differential middleware-bypass rule.
func (MiddlewareBypassOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p MiddlewareBypassParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	if !MiddlewareControlDenied(p.ControlStatus, p.ControlLocation) {
		return &Evidence{Verdict: VerdictReject, Note: "control response is not access-denied (no 401/403 or login redirect)"}, nil
	}
	if p.BypassStatus < 200 || p.BypassStatus >= 300 {
		return &Evidence{Verdict: VerdictReject, Note: "bypass response is not 2xx"}, nil
	}
	body := strings.TrimSpace(p.BypassBody)
	if len(body) < middlewareBypassMinBody {
		return &Evidence{Verdict: VerdictReject, Note: "bypass body too small to prove protected content"}, nil
	}
	if bodyLooksLikeWAFBlock(body) {
		return &Evidence{Verdict: VerdictReject, Note: "bypass body is a WAF/block page"}, nil
	}
	m := baseline.NewDefaultModel()
	if string(m.Mask([]byte(body))) == string(m.Mask([]byte(p.ControlBody))) {
		return &Evidence{Verdict: VerdictReject, Note: "bypass body is identical to control body"}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceFirm,
		Artifacts: map[string]string{
			"control_status": itoa(int64(p.ControlStatus)),
			"bypass_status":  itoa(int64(p.BypassStatus)),
			"header":         strings.ToLower(strings.TrimSpace(p.Header)),
			"header_value":   p.HeaderValue,
			"path":           p.Path,
		},
		Repeats:       1,
		ControlResult: "control-denied (no bypass header)",
		Note:          "middleware authorization bypass: control denied, bypass header returned 2xx protected content (firm ceiling)",
	}, nil
}

// MiddlewareControlDenied reports whether the control response proves the
// route is protected: 401/403 or a redirect to a login/session path.
// Exported for the Tier 1 loader so non-protected routes cost one request.
func MiddlewareControlDenied(status int, location string) bool {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return true
	}
	if status < 300 || status >= 400 {
		return false
	}
	loc := strings.ToLower(strings.TrimSpace(location))
	if loc == "" {
		return false
	}
	return middlewareLoginRedirect.MatchString(loc)
}

// bodyLooksLikeWAFBlock is a second, narrow guard for 2xx challenge pages
// that the static classifier may not flag when markers live in the body.
func bodyLooksLikeWAFBlock(body string) bool {
	lower := strings.ToLower(body)
	for _, m := range []string{
		"attention required", "request blocked", "access denied",
		"cf-chl", "cf_chl", "cloudflare", "captcha", "challenge-platform",
		"web application firewall", "the requested url was rejected",
	} {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
