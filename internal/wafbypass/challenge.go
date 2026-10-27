// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package wafbypass

import (
	"net/http"
	"strings"
)

// strongChallengeMarkers identify a vendor challenge page by themselves.
// These strings are distinctive enough that a normal documentation page or a
// generic 403 cannot contain them accidentally.
var strongChallengeMarkers = []struct {
	vendor string
	marker string
}{
	{"cloudflare", "cf-chl"},
	{"cloudflare", "cf_chl"},
	{"cloudflare", "just a moment..."},
	{"cloudflare", "attention required! | cloudflare"},
	{"cloudflare", "cf-error-details"},
	{"cloudflare", "cf-mitigated"},
	{"imperva", "incapsula incident id"},
	{"imperva", "_incapsula_resource"},
	{"datadome", "captcha-delivery.com"},
	{"datadome", "datadome captcha"},
	{"perimeterx", "px-captcha"},
	{"aws-waf", "aws-waf-token"},
	{"aws-waf", "awswaf"},
	{"sucuri", "sucuri website firewall"},
	{"f5", "the requested url was rejected"},
	{"akamai", "akamai reference #"},
}

// weakChallengeMarkers only count on a block status (403/429/503); on a 200
// page these words are common in security documentation and product pages.
var weakChallengeMarkers = []struct {
	vendor string
	marker string
}{
	{"cloudflare", "cloudflare"},
	{"akamai", "reference #"},
	{"akamai", "akamai"},
	{"imperva", "incapsula"},
	{"imperva", "imperva"},
	{"generic", "captcha"},
	{"f5", "f5 networks"},
}

// ChallengeKind returns the vendor name for a WAF challenge page, or "".
// What: Strong markers apply to any status; weak markers only on 403/429/503.
// Why: A 200 documentation page containing "captcha" must not be marked as a
// challenge, while a Cloudflare "Just a moment..." page usually returns 200.
func ChallengeKind(status int, headers http.Header, body []byte) string {
	lower := strings.ToLower(string(body))
	for _, c := range strongChallengeMarkers {
		if strings.Contains(lower, c.marker) {
			return c.vendor
		}
	}
	if status != http.StatusForbidden && status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable {
		return ""
	}
	for _, c := range weakChallengeMarkers {
		if strings.Contains(lower, c.marker) {
			return c.vendor
		}
	}
	if headers != nil && headers.Get("Retry-After") != "" {
		return "rate-limit"
	}
	return ""
}

// ChallengeText is the browser-side variant (title + rendered text).
// It only accepts strong markers: a rendered 200 page has no HTTP status to
// gate weak words on.
func ChallengeText(title, body string) string {
	text := strings.ToLower(title + "\n" + body)
	for _, c := range strongChallengeMarkers {
		if strings.Contains(text, c.marker) {
			return c.vendor
		}
	}
	return ""
}
