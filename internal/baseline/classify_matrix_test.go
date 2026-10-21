// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package baseline

import (
	"net/http"
	"strings"
	"testing"
)

func TestClassifyStaticMatrix(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		headers   http.Header
		body      string
		untrusted bool
		soft404   bool
		note      string
	}{
		{"strong cf-chl", 200, nil, "<html>cf-chl challenge</html>", true, false, "waf/block: cf-chl"},
		{"strong cloudflare moment", 200, nil, "Just a moment...", true, false, "waf/block: just a moment..."},
		{"strong cloudflare attention", 200, nil, "Attention Required! | Cloudflare", true, false, "attention required"},
		{"strong sucuri", 200, nil, "Sucuri Website Firewall", true, false, "sucuri"},
		{"weak cloudflare on 403", 403, nil, "<title>Cloudflare</title>", true, false, "cloudflare"},
		{"weak captcha on 200", 200, nil, "<title>Cloudflare</title>", false, false, "normal"},
		{"block marker on 403", 403, nil, "<h1>Access Denied</h1>", true, false, "access denied"},
		{"block marker on 200", 200, nil, "<h1>Access Denied</h1>", false, false, "normal"},
		{"request blocked on 503", 503, nil, "Request Blocked", true, false, "request blocked"},
		{"429 always untrusted", 429, nil, "slow down", true, false, "429 rate-limit"},
		{"403 retry after", 403, http.Header{"Retry-After": []string{"30"}}, "wait", true, false, "retry-after"},
		{"429 retry after", 429, http.Header{"Retry-After": []string{"30"}}, "wait", true, false, "429 rate-limit"},
		{"503 retry after", 503, http.Header{"Retry-After": []string{"30"}}, "wait", true, false, "retry-after"},
		{"200 retry after", 200, http.Header{"Retry-After": []string{"30"}}, "wait", false, false, "normal"},
		{"500 retry after", 500, http.Header{"Retry-After": []string{"30"}}, "wait", false, false, "normal"},
		{"normal html", 200, nil, "<html>hello</html>", false, false, "normal"},
		{"normal not found", 404, nil, "not found", false, false, "normal"},
		{"empty body", 204, nil, "", false, false, "normal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyStatic(tc.status, tc.headers, []byte(tc.body))
			if got.Untrusted != tc.untrusted || got.Soft404 != tc.soft404 {
				t.Fatalf("ClassifyStatic() = %+v, want untrusted=%v soft404=%v", got, tc.untrusted, tc.soft404)
			}
			if tc.note != "" && !strings.Contains(strings.ToLower(got.Note), tc.note) {
				t.Fatalf("note = %q, want substring %q", got.Note, tc.note)
			}
		})
	}
}

func TestClassifyStrongMarkersAreCaseInsensitive(t *testing.T) {
	for _, body := range []string{
		"CF-CHL-BYPASS",
		"JUST A MOMENT...",
		"ATTENTION REQUIRED! | CLOUDFLARE",
		"SUCURI WEBSITE FIREWALL",
	} {
		got := ClassifyStatic(200, nil, []byte(body))
		if !got.Untrusted || !got.WAFDetected {
			t.Fatalf("%q must be a strong WAF marker: %+v", body, got)
		}
	}
}

func TestMaskMatrix(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"csrf token", `<input name="csrf_token" value="abc123">`, `<input __MASKED__>`},
		{"nonce", `<script nonce="abc123">`, `<script __MASKED__>`},
		{"timestamp", `at 2026-10-21T12:34:56Z ok`, `at __MASKED__ ok`},
		{"uuid", `id 123e4567-e89b-12d3-a456-426614174000 end`, `id __MASKED__ end`},
		{"viewstate", `<input __VIEWSTATE="secret"/>`, `<input __MASKED__`},
		{"jwt", `token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature`, `token __MASKED__`},
		{"ten digits", `cache 1234567890`, `cache __MASKED__`},
		{"thirteen digits", `cache 1234567890123`, `cache __MASKED__`},
		{"nine digits", `cache 123456789`, `cache 123456789`},
		{"plain text", `<p>hello</p>`, `<p>hello</p>`},
	}
	m := NewDefaultModel()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := string(m.Mask([]byte(tc.in)))
			if got != tc.want {
				t.Fatalf("Mask(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMaskNilModel(t *testing.T) {
	body := []byte(`<input name="csrf_token" value="abc">`)
	var m *Model
	if got := m.Mask(body); string(got) != string(body) {
		t.Fatalf("nil model changed body: %q", got)
	}
	if got := MaskString(`<input name="csrf_token" value="abc">`); got != `<input __MASKED__>` {
		t.Fatalf("MaskString = %q", got)
	}
}

func TestMaskStableAcrossDynamicValues(t *testing.T) {
	a := `name="csrf_token" value="one" nonce="aaa" id="123e4567-e89b-12d3-a456-426614174000"`
	b := `name="csrf_token" value="two" nonce="bbb" id="123e4567-e89b-12d3-a456-426614174111"`
	ma, mb := MaskString(a), MaskString(b)
	if ma != mb {
		t.Fatalf("dynamic values must mask to the same shape:\n%s\n%s", ma, mb)
	}
}

func TestMaskDoesNotMutateInput(t *testing.T) {
	m := NewDefaultModel()
	original := `<input name="csrf_token" value="abc">`
	body := []byte(original)
	_ = m.Mask(body)
	if string(body) != original {
		t.Fatalf("Mask mutated its input: %q", body)
	}
}

func TestLearnSoft404AndClassify(t *testing.T) {
	m := NewDefaultModel()
	m.LearnSoft404([][]byte{
		[]byte(`<html><input name="csrf_token" value="aaa"></html>`),
		[]byte(`<html><input name="csrf_token" value="bbb"></html>`),
	}, []int{200, 404})
	if len(m.Soft404Bodies) != 1 {
		t.Fatalf("masked bodies must collapse to one fingerprint, got %d", len(m.Soft404Bodies))
	}
	if !m.Soft404Status[200] || !m.Soft404Status[404] {
		t.Fatalf("learned statuses missing: %+v", m.Soft404Status)
	}
	got := m.Classify(200, nil, []byte(`<html><input name="csrf_token" value="ccc"></html>`))
	if !got.Soft404 {
		t.Fatalf("dynamic soft-404 page not recognized: %+v", got)
	}
	other := m.Classify(200, nil, []byte(`<html><h1>a real product</h1></html>`))
	if other.Soft404 {
		t.Fatalf("different body must not be soft-404: %+v", other)
	}
}

func TestClassifyWAFPrecedesSoft404(t *testing.T) {
	m := NewDefaultModel()
	body := []byte(`<html>cf-chl challenge</html>`)
	m.LearnSoft404([][]byte{body}, []int{200})
	got := m.Classify(200, nil, body)
	if !got.Untrusted || !got.WAFDetected || got.Soft404 {
		t.Fatalf("WAF must win over soft-404: %+v", got)
	}
}

func TestHashMasked(t *testing.T) {
	m := NewDefaultModel()
	if hashMasked(nil, []byte("a")) != hashMasked(nil, []byte("a")) {
		t.Fatal("nil-model hash must be deterministic")
	}
	if hashMasked(nil, []byte("a")) == hashMasked(nil, []byte("b")) {
		t.Fatal("different bodies must hash differently")
	}
	a := hashMasked(m, []byte(`<input name="csrf_token" value="a">`))
	b := hashMasked(m, []byte(`<input name="csrf_token" value="b">`))
	if a != b {
		t.Fatal("masked dynamic fields must hash identically")
	}
}

func TestDetectTechMatrix(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		cookies []*http.Cookie
		body    string
		want    []string
	}{
		{"wordpress body", nil, nil, `<a href="/wp-json/">api</a>`, []string{"wordpress"}},
		{"wordpress server", http.Header{"Server": []string{"WordPress"}}, nil, "", []string{"wordpress"}},
		{"nginx", http.Header{"Server": []string{"nginx/1.25"}}, nil, "", []string{"nginx"}},
		{"apache powered", http.Header{"X-Powered-By": []string{"Apache"}}, nil, "", []string{"apache"}},
		{"express", http.Header{"X-Powered-By": []string{"Express"}}, nil, "", []string{"express"}},
		{"php cookie", nil, []*http.Cookie{{Name: "PHPSESSID"}}, "", []string{"php"}},
		{"next cookie", nil, []*http.Cookie{{Name: "next-auth.session-token"}}, "", []string{"nextjs"}},
		{"next body", nil, nil, `<script src="/_next/static/chunk.js"></script>`, []string{"nextjs"}},
		{"nginx and php", http.Header{"Server": []string{"nginx"}}, []*http.Cookie{{Name: "PHPSESSID"}}, "", []string{"nginx", "php"}},
		{"wordpress and php", nil, []*http.Cookie{{Name: "PHPSESSID"}}, `<link href="/wp-json/">`, []string{"wordpress", "php"}},
		{"dedupe next", nil, []*http.Cookie{{Name: "next"}}, `/_next/`, []string{"nextjs"}},
		{"none", nil, nil, `<html>plain</html>`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectTech(tc.headers, tc.cookies, tc.body)
			if len(got) != len(tc.want) {
				t.Fatalf("DetectTech() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("DetectTech() = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestDetectTechNilHeaders(t *testing.T) {
	got := DetectTech(nil, []*http.Cookie{{Name: "PHPSESSID"}}, "")
	if len(got) != 1 || got[0] != "php" {
		t.Fatalf("DetectTech(nil) = %v, want [php]", got)
	}
}
