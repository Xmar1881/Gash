// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

func oracleCls() baseline.Classification { return baseline.Classification{Note: "normal"} }

func TestErrorSignatureModeMatrix(t *testing.T) {
	tests := []struct {
		name     string
		params   ErrorSignatureParams
		verdict  Verdict
		conf     plugin.Confidence
		artifact string
	}{
		{"mysql confirmed", ErrorSignatureParams{Body: "error: You have an error in your SQL syntax", ControlBody: "clean"}, VerdictAccept, plugin.ConfidenceConfirmed, "mysql"},
		{"postgres no control", ErrorSignatureParams{Body: "ERROR: syntax error at or near \"x\""}, VerdictAccept, plugin.ConfidenceConfirmed, "postgres"},
		{"mssql", ErrorSignatureParams{Body: "Incorrect syntax near '1'"}, VerdictAccept, plugin.ConfidenceConfirmed, "mssql"},
		{"oracle", ErrorSignatureParams{Body: "ORA-00933: SQL command not properly ended"}, VerdictAccept, plugin.ConfidenceConfirmed, "oracle"},
		{"sqlite", ErrorSignatureParams{Body: `near "x": syntax error`}, VerdictAccept, plugin.ConfidenceConfirmed, "sqlite"},
		{"access", ErrorSignatureParams{Body: "Microsoft Access Driver error"}, VerdictAccept, plugin.ConfidenceConfirmed, "access"},
		{"firebird", ErrorSignatureParams{Body: "GDS Exception. 335544569"}, VerdictAccept, plugin.ConfidenceConfirmed, "firebird"},
		{"hql", ErrorSignatureParams{Body: "org.hibernate.QuerySyntaxException"}, VerdictAccept, plugin.ConfidenceConfirmed, "hql"},
		{"control also matches", ErrorSignatureParams{Body: "mysql error", ControlBody: "mysql error"}, VerdictReject, "", ""},
		{"generic sql hint", ErrorSignatureParams{Body: "sql error happened"}, VerdictAccept, plugin.ConfidenceTentative, ""},
		{"no signal", ErrorSignatureParams{Body: "everything is fine"}, VerdictReject, "", ""},
		{"custom set", ErrorSignatureParams{Body: "MySqlException", SignatureSet: []string{"mysql"}}, VerdictAccept, plugin.ConfidenceConfirmed, "mysql"},
		{"unknown set", ErrorSignatureParams{Body: "MySqlException", SignatureSet: []string{"unknown"}}, VerdictReject, "", ""},
		{"path traversal with control", ErrorSignatureParams{Mode: "path_traversal", Body: "No such file or directory", ControlBody: "clean"}, VerdictAccept, plugin.ConfidenceConfirmed, "path_traversal"},
		{"path traversal without control", ErrorSignatureParams{Mode: "path_traversal", Body: "No such file or directory"}, VerdictAccept, plugin.ConfidenceFirm, "path_traversal"},
		{"unix passwd", ErrorSignatureParams{Mode: "path_traversal", Body: "root:x:0:0:root:/root:/bin/bash", ControlBody: "clean"}, VerdictAccept, plugin.ConfidenceConfirmed, "unix_passwd"},
		{"windows ini", ErrorSignatureParams{Mode: "path_traversal", Body: "[fonts]\r\n", ControlBody: "clean"}, VerdictAccept, plugin.ConfidenceConfirmed, "windows_ini"},
		{"generic error without control", ErrorSignatureParams{Mode: "generic_error", Body: "Traceback (most recent call last)"}, VerdictAccept, plugin.ConfidenceFirm, "generic_error"},
		{"deserialization", ErrorSignatureParams{Mode: "deserialization", Body: "java.io.InvalidClassException"}, VerdictAccept, plugin.ConfidenceFirm, "deserialization"},
		{"takeover", ErrorSignatureParams{Mode: "takeover", Body: "NoSuchBucket"}, VerdictAccept, plugin.ConfidenceFirm, "takeover"},
		{"xpath", ErrorSignatureParams{Mode: "xpath", Body: "XPathException: invalid XPath"}, VerdictAccept, plugin.ConfidenceFirm, "xpath"},
		{"backup file", ErrorSignatureParams{Mode: "backup_file", Body: "APP_KEY=base64:abc"}, VerdictAccept, plugin.ConfidenceFirm, "backup_file"},
		{"phpinfo", ErrorSignatureParams{SignatureSet: []string{"phpinfo"}, Body: "PHP Version => 8.2"}, VerdictAccept, plugin.ConfidenceFirm, "phpinfo"},
		{"management endpoint", ErrorSignatureParams{SignatureSet: []string{"management_endpoint"}, Body: `{"propertySources":[]}`}, VerdictAccept, plugin.ConfidenceFirm, "management_endpoint"},
		{"directory listing", ErrorSignatureParams{SignatureSet: []string{"directory_listing"}, Body: "<title>Index of /</title>"}, VerdictAccept, plugin.ConfidenceFirm, "directory_listing"},
		{"source map", ErrorSignatureParams{SignatureSet: []string{"source_map"}, Body: `{"version":3,"sources":["a.js"]}`}, VerdictAccept, plugin.ConfidenceFirm, "source_map"},
		{"ssi", ErrorSignatureParams{SignatureSet: []string{"ssi"}, Body: "GATEWAY_INTERFACE=CGI/1.1 DOCUMENT_ROOT=/srv"}, VerdictAccept, plugin.ConfidenceFirm, "ssi"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := (ErrorSignatureOracle{}).Verify(context.Background(), oracleCls(), false, tc.params)
			if err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != tc.verdict || ev.ConfidenceContribution != tc.conf {
				t.Fatalf("evidence = %+v", ev)
			}
			if tc.artifact != "" && ev.Artifacts["signature"] != tc.artifact {
				t.Fatalf("signature = %q, want %q", ev.Artifacts["signature"], tc.artifact)
			}
		})
	}
}

func TestHeaderSecurityModeMatrix(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		verdict Verdict
		conf    plugin.Confidence
	}{
		{"empty headers", http.Header{}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"complete", http.Header{
			"Strict-Transport-Security": {"max-age=31536000"},
			"Content-Security-Policy":   {"default-src 'self'"},
			"X-Frame-Options":           {"DENY"},
		}, VerdictReject, ""},
		{"missing hsts", http.Header{
			"Content-Security-Policy": {"default-src 'self'"},
			"X-Frame-Options":         {"DENY"},
		}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"weak csp", http.Header{
			"Strict-Transport-Security": {"max-age=31536000"},
			"Content-Security-Policy":   {"default-src 'self' 'unsafe-inline'"},
			"X-Frame-Options":           {"DENY"},
		}, VerdictAccept, plugin.ConfidenceFirm},
		{"csp covers frame", http.Header{
			"Strict-Transport-Security": {"max-age=31536000"},
			"Content-Security-Policy":   {"frame-ancestors 'none'"},
		}, VerdictReject, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := (HeaderOracle{}).Verify(context.Background(), oracleCls(), false, HeaderParams{Headers: tc.headers})
			if err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != tc.verdict || ev.ConfidenceContribution != tc.conf {
				t.Fatalf("evidence = %+v", ev)
			}
		})
	}
}

func TestHeaderSpecialModesMatrix(t *testing.T) {
	tests := []struct {
		name    string
		params  HeaderParams
		verdict Verdict
		conf    plugin.Confidence
	}{
		{"webdav write", HeaderParams{Mode: "webdav", Headers: http.Header{"Allow": {"GET, PUT, PROPPATCH"}}}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"webdav read", HeaderParams{Mode: "webdav", Headers: http.Header{"Allow": {"GET, HEAD, OPTIONS"}}}, VerdictReject, ""},
		{"webdav missing", HeaderParams{Mode: "webdav"}, VerdictReject, ""},
		{"crlf response", HeaderParams{Mode: "crlf", Headers: http.Header{"X-Test": {"a\r\nInjected: yes"}}}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"crlf request", HeaderParams{Mode: "crlf", RequestHeaders: http.Header{"X-Test": {"a\nb"}}}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"crlf clean", HeaderParams{Mode: "crlf", Headers: http.Header{"X-Test": {"ok"}}}, VerdictReject, ""},
		{"jwt header", HeaderParams{Mode: "jwt", Headers: http.Header{"Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}}}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"jwt cookie", HeaderParams{Mode: "jwt", Headers: http.Header{"Set-Cookie": {"token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}}}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"jwt none alg", HeaderParams{Mode: "jwt_alg", Headers: http.Header{"Authorization": {"Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.sig"}}}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"jwt confusion text", HeaderParams{Mode: "jwt_alg", Headers: http.Header{"X-Debug": {"algorithm confusion detected"}}}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"jwt validation error", HeaderParams{Mode: "jwt_alg", Headers: http.Header{"X-Error": {"invalid algorithm"}}}, VerdictReject, ""},
		{"host reflection", HeaderParams{Mode: "host_header", CanaryHost: "gash.example", Body: "link https://gash.example/x"}, VerdictAccept, plugin.ConfidenceFirm},
		{"host control dirty", HeaderParams{Mode: "host_header", CanaryHost: "gash.example", Body: "gash.example", ControlBody: "gash.example"}, VerdictReject, ""},
		{"host no canary", HeaderParams{Mode: "host_header", CanaryHost: "gash.example", Body: "clean"}, VerdictReject, ""},
		{"host empty canary", HeaderParams{Mode: "host_header", Body: "gash.example"}, VerdictReject, ""},
		{"rate limited status", HeaderParams{Mode: "ratelimit", Status: http.StatusTooManyRequests}, VerdictReject, ""},
		{"rate limited burst", HeaderParams{Mode: "ratelimit", Status: 200, Burst: []int{200, 429}}, VerdictReject, ""},
		{"rate limited header", HeaderParams{Mode: "ratelimit", Status: 200, Headers: http.Header{"X-RateLimit-Limit": {"10"}}}, VerdictReject, ""},
		{"rate limited body", HeaderParams{Mode: "ratelimit", Status: 200, Body: "Too Many Requests"}, VerdictReject, ""},
		{"rate limit missing", HeaderParams{Mode: "ratelimit", Status: 200}, VerdictAccept, plugin.ConfidenceTentative},
		{"csrF post no token", HeaderParams{Mode: "csrf", Body: `<form method="POST"><input name="a"></form>`}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"csrf get", HeaderParams{Mode: "csrf", Body: `<form method="GET"><input name="q"></form>`}, VerdictReject, ""},
		{"csrf token", HeaderParams{Mode: "csrf", Body: `<form method="POST"><input name="_token" value="x"></form>`}, VerdictReject, ""},
		{"csrf samesite strict", HeaderParams{Mode: "csrf", Headers: http.Header{"Set-Cookie": {"a=b; SameSite=Strict"}}, Body: `<form method="POST"></form>`}, VerdictAccept, plugin.ConfidenceFirm},
		{"frame protected", HeaderParams{Mode: "frame", Headers: http.Header{"X-Frame-Options": {"SAMEORIGIN"}}}, VerdictReject, ""},
		{"frame weak", HeaderParams{Mode: "frame", Headers: http.Header{"X-Frame-Options": {"ALLOW-FROM https://x"}}}, VerdictAccept, plugin.ConfidenceFirm},
		{"frame csp wildcard", HeaderParams{Mode: "frame", Headers: http.Header{"Content-Security-Policy": {"frame-ancestors *"}}}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"frame csp allowlist", HeaderParams{Mode: "frame", Headers: http.Header{"Content-Security-Policy": {"frame-ancestors https://x"}}}, VerdictReject, ""},
		{"policy missing", HeaderParams{Mode: "policy", HeaderName: "Permissions-Policy", Policy: "missing"}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"policy required token missing", HeaderParams{Mode: "policy", HeaderName: "Strict-Transport-Security", Policy: "required", RequiredTokens: []string{"max-age=31536000"}, Headers: http.Header{"Strict-Transport-Security": {"max-age=60"}}}, VerdictAccept, plugin.ConfidenceFirm},
		{"policy forbidden header", HeaderParams{Mode: "policy", HeaderName: "Server", Policy: "forbidden", Headers: http.Header{"Server": {"nginx"}}}, VerdictAccept, plugin.ConfidenceFirm},
		{"policy forbidden token absent", HeaderParams{Mode: "policy", HeaderName: "Content-Security-Policy", Policy: "forbidden_tokens", ForbiddenTokens: []string{"unsafe-inline"}, Headers: http.Header{"Content-Security-Policy": {"default-src 'self'"}}}, VerdictReject, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := (HeaderOracle{}).Verify(context.Background(), oracleCls(), false, tc.params)
			if err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != tc.verdict || ev.ConfidenceContribution != tc.conf {
				t.Fatalf("evidence = %+v", ev)
			}
		})
	}
}

func TestRedirectVersionMatrix(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		tests := []struct {
			name    string
			params  RedirectParams
			verdict Verdict
			conf    plugin.Confidence
		}{
			{"empty", RedirectParams{}, VerdictReject, ""},
			{"relative", RedirectParams{Location: "/login"}, VerdictReject, ""},
			{"scheme relative", RedirectParams{Location: "//evil.example/x"}, VerdictReject, ""},
			{"wrong host", RedirectParams{Location: "https://other.example/", PayloadHost: "evil.example"}, VerdictReject, ""},
			{"external no control", RedirectParams{Location: "https://evil.example/x", PayloadHost: "evil.example"}, VerdictAccept, plugin.ConfidenceFirm},
			{"external control", RedirectParams{Location: "https://evil.example/x", PayloadHost: "evil.example", ControlNoRedir: true}, VerdictAccept, plugin.ConfidenceConfirmed},
			{"case insensitive", RedirectParams{Location: "https://EVIL.example/x", PayloadHost: "evil.example", ControlNoRedir: true}, VerdictAccept, plugin.ConfidenceConfirmed},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				ev, err := (RedirectOracle{}).Verify(context.Background(), oracleCls(), false, tc.params)
				if err != nil {
					t.Fatal(err)
				}
				if ev.Verdict != tc.verdict || ev.ConfidenceContribution != tc.conf {
					t.Fatalf("evidence = %+v", ev)
				}
			})
		}
	})

	t.Run("version", func(t *testing.T) {
		tests := []struct {
			name    string
			params  VersionParams
			verdict Verdict
			conf    plugin.Confidence
		}{
			{"no banner", VersionParams{}, VerdictReject, ""},
			{"banner match", VersionParams{Banner: "nginx/1.25.3"}, VerdictAccept, plugin.ConfidenceTentative},
			{"behavior verified", VersionParams{Banner: "Apache/2.4.58", BehaviorVerified: true}, VerdictAccept, plugin.ConfidenceFirm},
			{"cloudflare", VersionParams{Banner: "cloudflare nginx/1.25.3"}, VerdictReject, ""},
			{"graphql schema", VersionParams{Mode: "graphql", Banner: `{"__schema":{}}`}, VerdictAccept, plugin.ConfidenceConfirmed},
			{"graphql path", VersionParams{Mode: "graphql", Banner: "try /gql"}, VerdictAccept, plugin.ConfidenceFirm},
			{"graphql absent", VersionParams{Mode: "graphql", Banner: "plain html"}, VerdictReject, ""},
			{"introspection open", VersionParams{Mode: "graphql_introspection", Banner: `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`}, VerdictAccept, plugin.ConfidenceFirm},
			{"introspection disabled", VersionParams{Mode: "graphql_introspection", Banner: `{"errors":["introspection is disabled __schema queryType"]}`}, VerdictReject, ""},
			{"introspection missing", VersionParams{Mode: "graphql_introspection", Banner: `__schema`}, VerdictReject, ""},
			{"bad regex", VersionParams{Banner: "nginx/1.0", BannerRegex: "("}, VerdictReject, ""},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				ev, err := (VersionOracle{}).Verify(context.Background(), oracleCls(), false, tc.params)
				if tc.name == "bad regex" {
					var verr *plugin.ValidationError
					if !errors.As(err, &verr) {
						t.Fatalf("err = %v, want ValidationError", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if ev.Verdict != tc.verdict || ev.ConfidenceContribution != tc.conf {
					t.Fatalf("evidence = %+v", ev)
				}
			})
		}
	})
}

func TestVerbTamperMatrix(t *testing.T) {
	tests := []struct {
		name    string
		params  VerbTamperParams
		verdict Verdict
	}{
		{"baseline 200", VerbTamperParams{BaselineStatus: 200, VariantStatus: 200, VariantBody: strings.Repeat("x", 30), BaselineBody: "denied"}, VerdictReject},
		{"variant 403", VerbTamperParams{BaselineStatus: 401, VariantStatus: 403, VariantBody: strings.Repeat("x", 30), BaselineBody: "denied"}, VerdictReject},
		{"short body", VerbTamperParams{BaselineStatus: 401, VariantStatus: 200, VariantBody: "OK", BaselineBody: "denied"}, VerdictReject},
		{"same masked body", VerbTamperParams{BaselineStatus: 401, VariantStatus: 200, VariantBody: strings.Repeat("x", 30), BaselineBody: strings.Repeat("x", 30)}, VerdictReject},
		{"bypass", VerbTamperParams{BaselineStatus: 403, VariantStatus: 200, VariantBody: strings.Repeat("dashboard ", 3), BaselineBody: "access denied", VariantMethod: "head"}, VerdictAccept},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := (VerbTamperOracle{}).Verify(context.Background(), oracleCls(), false, tc.params)
			if err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != tc.verdict {
				t.Fatalf("evidence = %+v", ev)
			}
		})
	}
}

func TestStoredExchangeMatrix(t *testing.T) {
	base := StoredParams{
		Canary:      "gash_canary",
		StoreStatus: 200,
		StoreBody:   "saved",
		RenderBody:  `<script>alert(gash_canary)</script>`,
		ControlBody: `<div>clean</div>`,
	}
	tests := []struct {
		name     string
		mutate   func(*StoredParams)
		want     Verdict
		workflow bool
	}{
		{"empty canary", func(p *StoredParams) { p.Canary = " " }, VerdictReject, false},
		{"store missing", func(p *StoredParams) { p.StoreStatus = 0; p.StoreBody = "" }, VerdictReject, false},
		{"store rejected", func(p *StoredParams) { p.StoreStatus = 500 }, VerdictReject, true},
		{"render missing", func(p *StoredParams) { p.RenderBody = "clean" }, VerdictReject, true},
		{"render reflection", func(p *StoredParams) {}, VerdictAccept, true},
		{"dirty control", func(p *StoredParams) { p.ControlBody = p.RenderBody }, VerdictReject, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mutate(&p)
			ev, err := (StoredOracle{}).Verify(context.Background(), oracleCls(), false, p)
			if err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != tc.want {
				t.Fatalf("evidence = %+v", ev)
			}
			if tc.workflow && ev.Artifacts["workflow"] != "store+render" {
				t.Fatalf("workflow artifact = %q", ev.Artifacts["workflow"])
			}
		})
	}
}

func TestCookieHelpers(t *testing.T) {
	h := http.Header{"Set-Cookie": {"a=1; Secure; HttpOnly; SameSite=Lax\nb=2"}}
	cookies := splitSetCookies(h)
	if len(cookies) != 2 || cookies[0] != "a=1; Secure; HttpOnly; SameSite=Lax" || cookies[1] != "b=2" {
		t.Fatalf("splitSetCookies = %#v", cookies)
	}
	if got := splitSetCookies(http.Header{"Set-Cookie": {"\n \n"}}); len(got) != 0 {
		t.Fatalf("blank cookies = %#v", got)
	}
	tests := []struct {
		raw      string
		secure   bool
		httpOnly bool
		sameSite string
	}{
		{"a=b", false, false, ""},
		{"a=b; secure; httponly; samesite=strict", true, true, "strict"},
		{"a=b; SameSite=None", false, false, "None"},
		{"a=b; SameSite", false, false, "present"},
		{"a=b; Secure=true", false, false, ""},
	}
	for _, tc := range tests {
		secure, httpOnly, sameSite := cookieFlags(tc.raw)
		if secure != tc.secure || httpOnly != tc.httpOnly || sameSite != tc.sameSite {
			t.Fatalf("cookieFlags(%q) = %v,%v,%q", tc.raw, secure, httpOnly, sameSite)
		}
	}
	for _, tc := range []struct {
		target string
		want   bool
	}{
		{"", true}, {"https://x", true}, {"HTTPS://x", true}, {"http://x", false}, {"//x", true}, {"::bad", true},
	} {
		if got := isHTTPS(tc.target); got != tc.want {
			t.Fatalf("isHTTPS(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}

func TestCookieAndCORSEdgeMatrix(t *testing.T) {
	cookieCases := []struct {
		name    string
		params  CookieParams
		verdict Verdict
		conf    plugin.Confidence
	}{
		{"no cookie", CookieParams{}, VerdictReject, ""},
		{"http secure missing", CookieParams{Headers: http.Header{"Set-Cookie": {"a=b; HttpOnly; SameSite=Lax"}}, Target: "http://x"}, VerdictAccept, plugin.ConfidenceFirm},
		{"https secure missing", CookieParams{Headers: http.Header{"Set-Cookie": {"a=b; HttpOnly; SameSite=Lax"}}, Target: "https://x"}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"samesite none without secure", CookieParams{Headers: http.Header{"Set-Cookie": {"a=b; HttpOnly; SameSite=None"}}, Target: "http://x"}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"samesite missing", CookieParams{Headers: http.Header{"Set-Cookie": {"a=b; Secure; HttpOnly"}}, Target: "https://x"}, VerdictAccept, plugin.ConfidenceFirm},
		{"hardened", CookieParams{Headers: http.Header{"Set-Cookie": {"a=b; Secure; HttpOnly; SameSite=Strict"}}, Target: "https://x"}, VerdictReject, ""},
	}
	for _, tc := range cookieCases {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := (CookieOracle{}).Verify(context.Background(), oracleCls(), false, tc.params)
			if err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != tc.verdict || ev.ConfidenceContribution != tc.conf {
				t.Fatalf("evidence = %+v", ev)
			}
		})
	}
	corsCases := []struct {
		name    string
		params  CORSParams
		verdict Verdict
		conf    plugin.Confidence
	}{
		{"none", CORSParams{}, VerdictReject, ""},
		{"specific", CORSParams{Headers: http.Header{"Access-Control-Allow-Origin": {"https://app.example"}}}, VerdictReject, ""},
		{"null", CORSParams{Headers: http.Header{"Access-Control-Allow-Origin": {"null"}}}, VerdictAccept, plugin.ConfidenceFirm},
		{"reflected no credentials", CORSParams{Headers: http.Header{"Access-Control-Allow-Origin": {"https://evil.example"}}, RequestOrigin: "https://evil.example"}, VerdictAccept, plugin.ConfidenceFirm},
	}
	for _, tc := range corsCases {
		t.Run("cors "+tc.name, func(t *testing.T) {
			ev, err := (CORSOracle{}).Verify(context.Background(), oracleCls(), false, tc.params)
			if err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != tc.verdict || ev.ConfidenceContribution != tc.conf {
				t.Fatalf("evidence = %+v", ev)
			}
		})
	}
}

func TestDifferentialControlMustDiverge(t *testing.T) {
	base := DifferentialParams{
		TrueBodies:  []string{"aaa TRUE bb", "aaa TRUE bb", "aaa TRUE bb"},
		FalseBodies: []string{"aaa FALSE bb", "aaa FALSE bb", "aaa FALSE bb"},
		Repeats:     3,
	}
	tests := []struct {
		name    string
		control string
		verdict Verdict
	}{
		{"neutral control", "aaa bb", VerdictAccept},
		{"control equals true", "aaa TRUE bb", VerdictReject},
		{"control equals false", "aaa FALSE bb", VerdictAccept},
		{"empty control", "", VerdictAccept},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			p.ControlBody = tc.control
			ev, err := (DifferentialOracle{}).Verify(context.Background(), oracleCls(), false, p)
			if err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != tc.verdict {
				t.Fatalf("evidence = %+v", ev)
			}
		})
	}
}

func TestDifferentialHelpers(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want bool
	}{
		{nil, true}, {[]string{"a"}, true}, {[]string{"a", "a"}, true}, {[]string{"a", "b"}, false},
	} {
		if got := allEqual(tc.in); got != tc.want {
			t.Fatalf("allEqual(%v) = %v", tc.in, got)
		}
	}
	for _, tc := range []struct {
		conf plugin.Confidence
		want int
	}{
		{plugin.ConfidenceTentative, 0}, {plugin.ConfidenceStaticExecution, 1},
		{plugin.ConfidenceFirm, 2}, {plugin.ConfidenceConfirmed, 3}, {"unknown", -1},
	} {
		if got := confidenceRank(tc.conf); got != tc.want {
			t.Fatalf("confidenceRank(%q) = %d", tc.conf, got)
		}
	}
	for _, tc := range []struct {
		raw  string
		ok   bool
		want plugin.Confidence
	}{
		{"", false, ""}, {"tentative", true, plugin.ConfidenceTentative},
		{"firm", true, plugin.ConfidenceFirm}, {"confirmed", true, plugin.ConfidenceConfirmed},
		{"bogus", false, ""},
	} {
		got, ok := confidenceCeiling(tc.raw)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("confidenceCeiling(%q) = %q,%v", tc.raw, got, ok)
		}
	}
	for _, tc := range []struct {
		ts, fs, div bool
		want        Verdict
	}{
		{true, true, true, VerdictAccept}, {true, true, false, VerdictReject},
		{true, false, true, VerdictReject}, {false, false, false, VerdictReject},
	} {
		if got := (DifferentialOracle{}).VerifyPartial(tc.ts, tc.fs, tc.div); got.Verdict != tc.want {
			t.Fatalf("VerifyPartial(%v,%v,%v) = %+v", tc.ts, tc.fs, tc.div, got)
		}
	}
}

func TestTimingHelpers(t *testing.T) {
	for _, tc := range []struct {
		in   []float64
		want float64
	}{
		{nil, 0}, {[]float64{5}, 5}, {[]float64{3, 1, 2}, 2},
		{[]float64{4, 1, 3, 2}, 2.5}, {[]float64{-1, 1}, 0},
	} {
		if got := median(tc.in); got != tc.want {
			t.Fatalf("median(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if _, z := mannWhitneyU([]float64{1, 1, 1}, []float64{1, 1, 1}); z != 0 {
		t.Fatalf("identical samples z = %v, want 0", z)
	}
	if u, z := mannWhitneyU([]float64{10, 11, 12}, []float64{1, 2, 3}); u != 9 || z <= 1.645 {
		t.Fatalf("separated samples u=%v z=%v", u, z)
	}
	for _, tc := range []struct {
		f    float64
		want string
	}{{0, "0"}, {42, "42"}, {-7, "-7"}, {1.5, "1.5"}} {
		if got := ftoa(tc.f); !strings.HasPrefix(got, tc.want) {
			t.Fatalf("ftoa(%v) = %q, want prefix %q", tc.f, got, tc.want)
		}
	}
}

func TestVerifierGuardAndContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (VersionOracle{}).Verify(ctx, oracleCls(), false, VersionParams{Banner: "nginx/1.0"}); err == nil {
		t.Fatal("canceled context must return error")
	}
	untrusted := baseline.Classification{Untrusted: true}
	ev, err := (CookieOracle{}).Verify(context.Background(), untrusted, false, CookieParams{
		Headers: http.Header{"Set-Cookie": {"a=b"}},
	})
	if err != nil || ev.Verdict != VerdictReject {
		t.Fatalf("untrusted evidence = %+v, err=%v", ev, err)
	}
	ev, err = (CookieOracle{}).Verify(context.Background(), oracleCls(), true, CookieParams{
		Headers: http.Header{"Set-Cookie": {"a=b"}},
	})
	if err != nil || ev.Verdict != VerdictReject {
		t.Fatalf("tainted evidence = %+v, err=%v", ev, err)
	}
}
