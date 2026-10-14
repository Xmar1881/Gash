// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package wafbypass

import (
	"net/http"
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
