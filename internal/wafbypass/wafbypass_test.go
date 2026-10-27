// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package wafbypass

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestBypassHeadersLoopback(t *testing.T) {
	h := BypassHeaders()
	if len(h) == 0 {
		t.Fatal("bypass başlıkları boş olmamalı")
	}
	for _, k := range []string{"X-Forwarded-For", "X-Originating-IP", "X-Remote-IP", "Client-IP", "X-Real-IP"} {
		if h[k] != "127.0.0.1" {
			t.Fatalf("%s loopback olmalı, got %q", k, h[k])
		}
	}
}

func TestMutateQueryTechniques(t *testing.T) {
	raw := "http://example.com/s?id=1' UNION SELECT"
	double, err := MutateQuery(raw, TechDoubleEncode)
	if err != nil {
		t.Fatalf("double-encode: %v", err)
	}
	if !strings.Contains(double, "%25") {
		t.Fatalf("double-encode %%25 içermeli: %s", double)
	}
	comment, err := MutateQuery(raw, TechSQLComment)
	if err != nil {
		t.Fatalf("sql-comment: %v", err)
	}
	if !strings.Contains(comment, "/**/") {
		t.Fatalf("sql-comment /**/ içermeli: %s", comment)
	}
	mixed, err := MutateQuery("http://example.com/s?q=union", TechMixedCase)
	if err != nil {
		t.Fatalf("mixed-case: %v", err)
	}
	if strings.Contains(mixed, "q=union") {
		t.Fatalf("mixed-case değeri değiştirmeli: %s", mixed)
	}
	hpp, err := MutateQuery("http://example.com/s?id=1", TechHPPDuplicate)
	if err != nil {
		t.Fatalf("hpp: %v", err)
	}
	if strings.Count(hpp, "id=") != 2 {
		t.Fatalf("hpp parametreyi çoğaltmalı: %s", hpp)
	}
	// Query'siz URL aynen dönmeli.
	same, err := MutateQuery("http://example.com/s", TechDoubleEncode)
	if err != nil || same != "http://example.com/s" {
		t.Fatalf("query'siz URL değişmemeli: %q %v", same, err)
	}
}

func TestMutateFormBody(t *testing.T) {
	out := MutateFormBody([]byte("user=admin&pass=x"), TechHPPDuplicate)
	if strings.Count(string(out), "user=") != 2 {
		t.Fatalf("form HPP çoğaltmalı: %s", out)
	}
	enc := MutateFormBody([]byte("q=a b"), TechDoubleEncode)
	if !strings.Contains(string(enc), "%25") {
		t.Fatalf("form double-encode %%25 içermeli: %s", enc)
	}
	// Form olmayan gövdeye dokunulmaz.
	raw := []byte(`{"a":1}`)
	if got := MutateFormBody(raw, TechDoubleEncode); string(got) != string(raw) {
		t.Fatalf("JSON gövde değişmemeli: %s", got)
	}
}

func TestIsBlocked(t *testing.T) {
	if !IsBlocked(403, nil, []byte("Forbidden")) {
		t.Fatal("düz 403 blok sayılmalı")
	}
	if !IsBlocked(200, nil, []byte("<html>cf-chl challenge</html>")) {
		t.Fatal("WAF işaretli 200 blok sayılmalı")
	}
	if IsBlocked(200, nil, []byte("<html>hello</html>")) {
		t.Fatal("temiz 200 blok sayılmamalı")
	}
	if IsBlocked(503, nil, []byte("maintenance")) {
		t.Fatal("işaretsiz 503 blok sayılmamalı (hedefe ek yük yok)")
	}
}

func TestShouldAttemptBypassSeparatesWAFFromAuth(t *testing.T) {
	if !ShouldAttemptBypass(403, nil, []byte("request blocked by waf")) {
		t.Fatal("WAF-marked 403 should be eligible for an opt-in attempt")
	}
	if ShouldAttemptBypass(403, nil, []byte("authorization required")) {
		t.Fatal("generic authorization 403 must not trigger bypass attempts")
	}
}

func TestVerifyApplicationBehaviorRequiresStableCleanResponse(t *testing.T) {
	body := []byte("<html>application page</html>")
	if !VerifyApplicationBehavior(200, nil, body, 200, nil, body) {
		t.Fatal("stable application responses should verify")
	}
	if VerifyApplicationBehavior(200, nil, []byte("request id=a"), 200, nil, []byte("request id=b")) {
		t.Fatal("dynamic responses must not verify")
	}
	if VerifyApplicationBehavior(200, nil, []byte("login required"), 200, nil, []byte("login required")) {
		t.Fatal("authentication rejection must not verify")
	}
}

func TestBuildAttemptsBounded(t *testing.T) {
	atts := BuildAttempts("http://example.com/s?id=1' OR 1=1", nil, nil)
	if len(atts) == 0 || len(atts) > MaxAttempts {
		t.Fatalf("deneme sayısı 1..%d olmalı, got %d", MaxAttempts, len(atts))
	}
	if atts[0].Name != TechHeaderOnly {
		t.Fatalf("ilk deneme header-only olmalı, got %s", atts[0].Name)
	}
	// Açık başlık korunur (bypass ezmez).
	atts2 := BuildAttempts("http://example.com/s?id=1", map[string]string{"X-Forwarded-For": "10.0.0.5"}, nil)
	for _, a := range atts2 {
		if a.Headers["X-Forwarded-For"] == "127.0.0.1" {
			t.Fatal("açık istek başlığı bypass ile ezilmemeli")
		}
	}
	// Query'siz + gövdesiz: yalnızca header-only.
	atts3 := BuildAttempts("http://example.com/s", nil, nil)
	if len(atts3) != 1 {
		t.Fatalf("query'siz hedefte tek deneme olmalı, got %d", len(atts3))
	}
	_ = http.StatusForbidden
}

func TestChallengeKindModernVendors(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   string
	}{
		{200, "Just a moment...", "cloudflare"},
		{200, "<div>Incapsula incident ID: 123</div>", "imperva"},
		{200, "https://captcha-delivery.com/c.js", "datadome"},
		{403, "please solve the captcha", "generic"},
		{200, "a tutorial about captcha and WAF", ""},
		{403, "authorization required", ""},
	}
	for _, tc := range cases {
		if got := ChallengeKind(tc.status, http.Header{}, []byte(tc.body)); got != tc.want {
			t.Fatalf("ChallengeKind(%d, %q) = %q, want %q", tc.status, tc.body, got, tc.want)
		}
	}
	if got := ChallengeText("Just a moment...", "checking your browser"); got != "cloudflare" {
		t.Fatalf("ChallengeText = %q", got)
	}
}

func TestBuildAttemptsForPluginSQLi(t *testing.T) {
	payload := "' OR '1'='1"
	raw := "http://example.com/s?q=" + url.QueryEscape(payload)
	atts := BuildAttemptsForPlugin(raw, nil, nil, "sqli-boolean-differential")
	if len(atts) <= MaxAttempts || len(atts) > MaxAttemptsForPlugin {
		t.Fatalf("semantic attempt count = %d, want %d..%d", len(atts), MaxAttempts+1, MaxAttemptsForPlugin)
	}
	found := false
	for _, a := range atts {
		if strings.HasPrefix(a.Name, "sqli-") {
			found = true
			if a.URL == raw {
				t.Fatalf("semantic attempt did not change the payload: %+v", a)
			}
		}
	}
	if !found {
		t.Fatalf("no SQLi semantic variants: %+v", atts)
	}
}

func TestBuildAttemptsForPluginXSSKeepsCanary(t *testing.T) {
	payload := `<script>alert(gash_canary_7c1d)</script>`
	raw := "http://example.com/s?q=" + url.QueryEscape(payload)
	atts := BuildAttemptsForPlugin(raw, nil, nil, "xss-reflected-basic")
	found := false
	for _, a := range atts {
		if !strings.HasPrefix(a.Name, "xss-") {
			continue
		}
		u, err := url.Parse(a.URL)
		if err != nil {
			continue
		}
		v := u.Query().Get("q")
		if strings.Contains(v, "gash_canary_7c1d") && strings.Contains(strings.ToLower(v), "<svg") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("XSS semantic variant must preserve the canary: %+v", atts)
	}
}

func TestBuildAttemptsContentTypeSwitching(t *testing.T) {
	raw := "http://example.com/api/items"
	body := []byte(`{"q":"' OR '1'='1"}`)
	atts := BuildAttemptsForPlugin(raw, map[string]string{"Content-Type": "application/json"}, body, "sqli-json-body-error")
	if len(atts) > MaxAttemptsForPlugin {
		t.Fatalf("attempt cap exceeded: %d", len(atts))
	}
	foundPlain := false
	foundMultipart := false
	foundMultipartDup := false
	for _, a := range atts {
		if strings.HasPrefix(a.Name, "content-type-") && strings.EqualFold(a.Headers["Content-Type"], "text/plain") {
			foundPlain = true
		}
	}
	if !foundPlain {
		t.Fatalf("JSON content-type switch missing: %+v", atts)
	}
	form := []byte(url.Values{"q": {"' OR '1'='1"}}.Encode())
	atts2 := BuildAttemptsForPlugin(raw, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, form, "sqli-json-body-error")
	for _, a := range atts2 {
		if strings.HasPrefix(a.Name, "content-type-multipart") && strings.HasPrefix(a.Headers["Content-Type"], "multipart/form-data") {
			foundMultipart = true
		}
		if strings.HasPrefix(a.Name, "multipart-duplicate-q") && strings.Contains(string(a.Body), "gash-waf-benign") {
			foundMultipartDup = true
		}
	}
	if !foundMultipart || !foundMultipartDup {
		t.Fatalf("multipart content-type/duplicate switch missing: %+v", atts2)
	}
}

func TestBuildAttemptsPathConfusion(t *testing.T) {
	atts := BuildAttemptsForPlugin("http://example.com/a/b?q=1", nil, nil, "sqli-error-based")
	found := false
	for _, a := range atts {
		if strings.HasPrefix(a.Name, "path-confusion-") {
			found = true
			if !strings.Contains(a.URL, "/a/") && !strings.Contains(a.URL, "/a//") {
				t.Fatalf("unexpected path confusion URL: %s", a.URL)
			}
		}
	}
	if !found {
		t.Fatalf("path confusion attempts missing: %+v", atts)
	}
}

func TestBuildAttemptsJSONParserDifferentials(t *testing.T) {
	body := []byte(`{"q":"' OR '1'='1"}`)
	atts := BuildAttemptsForPlugin("http://example.com/api/items", map[string]string{"Content-Type": "application/json"}, body, "sqli-json-body-error")
	foundDup, foundUni := false, false
	for _, a := range atts {
		switch {
		case strings.HasPrefix(a.Name, "json-duplicate-key-"):
			foundDup = true
			if !json.Valid(a.Body) {
				t.Fatalf("duplicate-key body is not valid JSON: %s", a.Body)
			}
			if !strings.Contains(string(a.Body), "gash-waf-benign") {
				t.Fatalf("duplicate-key body missing benign first value: %s", a.Body)
			}
		case strings.HasPrefix(a.Name, "json-unicode-"):
			foundUni = true
			if !json.Valid(a.Body) {
				t.Fatalf("unicode-escape body is not valid JSON: %s", a.Body)
			}
			if !strings.Contains(string(a.Body), `\u0027`) {
				t.Fatalf("unicode-escape body missing escaped quote: %s", a.Body)
			}
		}
	}
	if !foundDup || !foundUni {
		t.Fatalf("JSON parser differential attempts missing: %+v", atts)
	}
}
