// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"net/url"
	"testing"
)

func TestInjectParamTargetsNamedParameter(t *testing.T) {
	got := injectParam("http://127.0.0.1:8081/vulnerabilities/sqli/?id=1&Submit=Submit", "1'", "probe", "id")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	if q.Get("id") != "1'" {
		t.Fatalf("id = %q, want %q", q.Get("id"), "1'")
	}
	if q.Get("Submit") != "Submit" {
		t.Fatalf("Submit = %q, want preserved %q", q.Get("Submit"), "Submit")
	}
}

func TestInjectParamFallbacks(t *testing.T) {
	got := injectParam("http://127.0.0.1/x?a=hello&b=keep", "payload", "probe", "")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	if q.Get("b") != "keep" {
		t.Fatalf("unnamed injection dropped other parameter: %q", got)
	}

	got = injectParam("http://127.0.0.1/x", "payload", "probe", "")
	u, err = url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if q := u.Query(); q.Get("probe") != "payload" {
		t.Fatalf("fallback param not used: %q", got)
	}

	got = injectParam("http://127.0.0.1/x?a=hello", "payload", "probe", "missing")
	u, err = url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q = u.Query()
	if q.Get("missing") != "payload" || q.Get("a") != "hello" {
		t.Fatalf("named param injection appended incorrectly: %q", got)
	}
}
