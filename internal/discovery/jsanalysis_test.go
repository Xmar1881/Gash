// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package discovery

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAnalyzeJSEndpointsAndSourceMap JS çağrı kalıplarının + rota
// literallerinin + sourceMappingURL'in yakalandığını kanıtlar.
// What: fetch/axios/$get/XHR/rota/mutlak URL/şablon literal örnekleri.
// Why: Yüzey beslemesinin tek deterministik kaynağı bu çıkarımdır.
func TestAnalyzeJSEndpointsAndSourceMap(t *testing.T) {
	body := []byte(`
const a = fetch("/api/v2/users?debug=1");
const b = axios.post('/graphql', {data: 1});
const c = $.get("/legacy/list?page=1");
const d = new XMLHttpRequest(); d.open("PUT", "/inventory/item/42");
const e = "/admin/dashboard";
const f = "https://api.example.com/v1/status";
const g = ` + "`/api/${userId}/items`" + `;
//# sourceMappingURL=app.js.map
`)
	rep := AnalyzeJS("https://app.example.com/static/app.js", body)

	got := map[string]JSEndpoint{}
	for _, ep := range rep.Endpoints {
		got[ep.Resolved] = ep
	}
	want := map[string]string{
		"https://app.example.com/api/v2/users?debug=1": "GET",
		"https://app.example.com/graphql":              "POST",
		"https://app.example.com/legacy/list?page=1":   "GET",
		"https://app.example.com/inventory/item/42":    "PUT",
		"https://app.example.com/admin/dashboard":      "GET",
		"https://api.example.com/v1/status":            "GET",
		"https://app.example.com/api/1/items":          "GET",
	}
	if len(rep.Endpoints) != len(want) {
		t.Fatalf("endpoint sayısı %d, beklenen %d: %+v", len(rep.Endpoints), len(want), rep.Endpoints)
	}
	for url, method := range want {
		ep, ok := got[url]
		if !ok {
			t.Fatalf("endpoint eksik: %s (gelen: %+v)", url, rep.Endpoints)
		}
		if ep.Method != method {
			t.Errorf("%s metodu %q, beklenen %q", url, ep.Method, method)
		}
	}
	if ep := got["https://app.example.com/api/v2/users?debug=1"]; len(ep.Params) != 1 || ep.Params[0] != "debug" {
		t.Errorf("debug param beklenir, gelen: %v", ep.Params)
	}
	if rep.Stats.Endpoints != len(want) {
		t.Errorf("Stats.Endpoints %d, beklenen %d", rep.Stats.Endpoints, len(want))
	}
	if len(rep.SourceMaps) != 1 || rep.SourceMaps[0] != "https://app.example.com/static/app.js.map" {
		t.Fatalf("source map çözümü yanlış: %v", rep.SourceMaps)
	}
}

func TestAnalyzeJSHashRoutes(t *testing.T) {
	body := []byte(`
const a = "#/search";
const b = "#/search?q=apple";
const c = "#section-anchor";
const d = "#!/not-a-route";
const e = "#/product?id=5";
`)
	rep := AnalyzeJS("https://app.example.com/static/app.js", body)
	got := map[string][]string{}
	for _, hr := range rep.HashRoutes {
		got[hr.Path] = hr.Params
	}
	if len(got) != 2 {
		t.Fatalf("hash routes = %+v, want /search and /product", rep.HashRoutes)
	}
	if params := got["/search"]; len(params) != 1 || params[0] != "q" {
		t.Fatalf("explicit search params must win over fallback: %v", params)
	}
	if params := got["/product"]; len(params) != 1 || params[0] != "id" {
		t.Fatalf("product params = %v", params)
	}
	if _, ok := got["/section-anchor"]; ok {
		t.Fatal("ordinary anchors must not become hash routes")
	}
}

func TestAnalyzeJSHashRouteFallback(t *testing.T) {
	rep := AnalyzeJS("https://app.example.com/static/app.js", []byte(`const route = "#/search";`))
	if len(rep.HashRoutes) != 1 {
		t.Fatalf("hash routes = %+v", rep.HashRoutes)
	}
	params := rep.HashRoutes[0].Params
	if len(params) != 3 || params[0] != "q" || params[1] != "query" || params[2] != "search" {
		t.Fatalf("fallback params = %v", params)
	}
}

// TestAnalyzeJSSecretsMaskedAndPlaceholders sır kural tablosunu, maskelemeyi
// ve yer tutucu/entropi filtrelerini kanıtlar.
// What: Stripe/AWS/generic/JWT ateşler; placeholder/pk_test_/2-segment JWT söner.
// Why: GASH-067 kanıtı yalnızca maskeli olabilir; FP freni precision şartıdır.
func TestAnalyzeJSSecretsMaskedAndPlaceholders(t *testing.T) {
	const (
		stripeKey = "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc"
		awsKey    = "AK" + "IAJK4N2PQRSTUVWXYZ"
		generic   = "f8K2mQ9xLp3ZtR7vN4wB"
		jwt       = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	)
	body := []byte(`
const stripeKey = "` + stripeKey + `";
const awsKey = "` + awsKey + `";
const apiKey = "` + generic + `";
const password = "changeme_please_123";
const publishable = "pk_test_51H8xY2zQabcdefghij";
const token = "` + jwt + `";
const shortJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0";
`)
	rep := AnalyzeJS("https://app.example.com/app.js", body)

	byType := map[string]Secret{}
	for _, s := range rep.Secrets {
		byType[s.Type] = s
	}
	for _, want := range []string{"stripe-live-secret-key", "aws-access-key", "generic-secret", "jwt"} {
		if _, ok := byType[want]; !ok {
			t.Fatalf("%s sırrı beklenirdi (gelen: %+v)", want, rep.Secrets)
		}
	}
	if len(rep.Secrets) != 4 {
		t.Fatalf("tam 4 sır beklenir, gelen %d: %+v", len(rep.Secrets), rep.Secrets)
	}
	if m := byType["stripe-live-secret-key"].Masked; m != "sk_l…p7dc" {
		t.Errorf("stripe maskesi %q, beklenen %q", m, "sk_l…p7dc")
	}
	if vn := byType["generic-secret"].VarName; vn != "apikey" {
		t.Errorf("generic var_name %q, beklenen apikey", vn)
	}
	if byType["jwt"].Severity != "medium" {
		t.Errorf("jwt şiddeti %q, beklenen medium", byType["jwt"].Severity)
	}

	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, full := range []string{stripeKey, awsKey, generic, jwt} {
		if strings.Contains(string(raw), full) {
			t.Fatalf("tam sır değeri raporda sızıyor: %s", full)
		}
	}
	if !strings.Contains(byType["generic-secret"].Context, "f8K2…N4wB") {
		t.Errorf("bağlam maskeli değeri içermeli: %q", byType["generic-secret"].Context)
	}
}

// TestAnalyzeJSSizeGuard 2 MB üzeri gövdenin analiz edilmediğini kanıtlar.
func TestAnalyzeJSSizeGuard(t *testing.T) {
	big := make([]byte, MaxJSAnalysisBytes+1)
	rep := AnalyzeJS("https://app.example.com/app.js", big)
	if !rep.Stats.Skipped {
		t.Fatal("boyut tavanı aşılınca Skipped işareti beklenir")
	}
	if len(rep.Endpoints) != 0 || len(rep.Secrets) != 0 {
		t.Fatal("boyut tavanı aşılınca hiçbir bulgu üretilmemeli")
	}
}

// TestAnalyzeJSNoiseFiltered CDN/w3.org/asset/data: adaylarının elendiğini kanıtlar.
func TestAnalyzeJSNoiseFiltered(t *testing.T) {
	body := []byte(`
fetch("https://cdn.jsdelivr.net/npm/jquery.min.js");
fetch("/assets/logo.png");
fetch("data:text/plain,hello");
fetch("mailto:admin@example.com");
const s = "http://www.w3.org/2001/XMLSchema";
axios.get("https://fonts.googleapis.com/css2");
`)
	rep := AnalyzeJS("https://app.example.com/", body)
	if len(rep.Endpoints) != 0 {
		t.Fatalf("gürültü endpoint üretmemeli: %+v", rep.Endpoints)
	}
}

// TestAnalyzeSecretsLocation Kaynak haritası taramasının Location etiketini
// ve endpoint çıkarımı YAPMADIĞINI kanıtlar.
func TestAnalyzeSecretsLocation(t *testing.T) {
	const key = "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc"
	body := []byte(`{"version":3,"sourcesContent":["const k = \"` + key + `\"; fetch(\"/api/x\");"]}`)
	secrets := AnalyzeSecrets(body, "https://app.example.com/app.js.map")
	if len(secrets) != 1 {
		t.Fatalf("tek sır beklenir, gelen %d", len(secrets))
	}
	if secrets[0].Location != "https://app.example.com/app.js.map" {
		t.Errorf("location %q yanlış", secrets[0].Location)
	}
	if strings.Contains(secrets[0].Context, key) {
		t.Fatal("bağlamda tam değer sızmamalı")
	}
}

// TestAnalyzeJSTemplateHostKeepsQueryParam proves a template host prefix does
// not corrupt the endpoint/query surface (Juice Shop main.js pattern).
func TestAnalyzeJSTemplateHostKeepsQueryParam(t *testing.T) {
	body := []byte("search(e){return this.http.get(`${this.hostServer}/rest/products/search?q=${e}`)}")
	rep := AnalyzeJS("http://shop.local/main.js", body)
	for _, ep := range rep.Endpoints {
		if ep.Resolved == "http://shop.local/rest/products/search?q=1" {
			if len(ep.Params) != 1 || ep.Params[0] != "q" {
				t.Fatalf("params = %v, want [q]", ep.Params)
			}
			return
		}
	}
	t.Fatalf("template endpoint missing: %+v", rep.Endpoints)
}
