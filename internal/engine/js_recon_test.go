// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/recon"
)

// TestScanJSReconEndToEnd kanıt zinciri (tek uçtan uca yol):
//   - same-origin app.js çekilir; fetch ile bulunan parametreli endpoint
//     doğrudan yüzeye beslenir (istek üretmez), parametresiz endpoint 1 sayfa
//     sınırlı takip crawl'ına girer (sunucuda gözlenir);
//   - sahte Stripe anahtarı TAM 1 GASH-067 üretir (maskeli kanıt);
//   - placeholder/2-segment JWT sessizdir; kaynak haritası aynı-origin çekilir
//     ve sır içermediğinden ek bulgu üretmez;
//   - üçüncü taraf script trap sunucusuna HİÇ istek gitmez.
//
// What: httptest hedef + trap + kayıtlı e2e header plugin'i ile gerçek Run.
// Why: Motor stats + besleme + maskeleme disiplinini tek testte kilitler.
func TestScanJSReconEndToEnd(t *testing.T) {
	const stripeKey = "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc"

	var thirdHits, apiHits, adminHits, mapHits, appHits int32
	third := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&thirdHits, 1)
		_, _ = w.Write([]byte(`fetch("/third?q=1");`))
	}))
	defer third.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head>` +
			`<script src="/app.js"></script>` +
			`<script src="` + third.URL + `/tracker.js"></script>` +
			`</head><body>hello</body></html>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&appHits, 1)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(
			"const stripeKey = \"" + stripeKey + "\";\n" +
				"const api_key = \"your_api_key_here\";\n" +
				"const token = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0\";\n" +
				"fetch(\"/api/v2/users?debug=1\");\n" +
				"fetch(\"/admin/dashboard\");\n" +
				"//# sourceMappingURL=app.js.map\n"))
	})
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&mapHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":3,"sources":["app.src.js"],"sourcesContent":["export const ok = 1;"]}`))
	})
	mux.HandleFunc("/api/v2/users", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&apiHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&adminHits, 1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body>admin</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := writeE2EPlugin(t)
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	e := New(reg, DefaultConfig())
	rep, err := e.Run(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// GASH-067: tam olarak 1, maskeli, static-execution-evidence.
	var secretFindings []int
	for i, f := range rep.Findings {
		if f.RuleID == recon.RuleIDJSSecret {
			secretFindings = append(secretFindings, i)
		}
	}
	if len(secretFindings) != 1 {
		t.Fatalf("tam 1 GASH-067 beklenir, gelen %d (findings=%d)", len(secretFindings), len(rep.Findings))
	}
	f := rep.Findings[secretFindings[0]]
	if f.CWE != recon.CWEJSSecret {
		t.Errorf("CWE %q, beklenen %q", f.CWE, recon.CWEJSSecret)
	}
	if f.Confidence != plugin.ConfidenceStaticExecution {
		t.Errorf("confidence %q, beklenen %q", f.Confidence, plugin.ConfidenceStaticExecution)
	}
	if got := f.Evidence["masked_value"]; got != "sk_l…p7dc" {
		t.Errorf("masked_value %q, beklenen sk_l…p7dc", got)
	}
	if !strings.HasSuffix(f.Evidence["location"], "/app.js") {
		t.Errorf("location %q /app.js ile bitmeli", f.Evidence["location"])
	}
	raw, merr := json.Marshal(rep.Findings)
	if merr != nil {
		t.Fatalf("marshal: %v", merr)
	}
	if strings.Contains(string(raw), stripeKey) {
		t.Fatal("tam sır değeri raporda sızıyor")
	}

	// Besleme kanıtı: parametresiz endpoint takip crawl'ında görülür; parametreli
	// endpoint yalnızca yüzeye girer (bu taramada hiç istenmez).
	if atomic.LoadInt32(&adminHits) < 1 {
		t.Fatalf("takip crawl'ı /admin/dashboard'a uğramadı (hits=%d)", adminHits)
	}
	if atomic.LoadInt32(&apiHits) != 0 {
		t.Fatalf("/api/v2/users doğrudan nokta olmalı, istek gitmemeli (hits=%d)", apiHits)
	}
	if atomic.LoadInt32(&appHits) != 1 {
		t.Fatalf("app.js isabeti %d, beklenen 1", appHits)
	}
	if atomic.LoadInt32(&mapHits) != 1 {
		t.Fatalf("app.js.map isabeti %d, beklenen 1", mapHits)
	}
	if got := atomic.LoadInt32(&thirdHits); got != 0 {
		t.Fatalf("üçüncü taraf trap sunucusuna istek gitti: %d", got)
	}

	wantStats := map[string]int{
		"js_files_fetched":   1,
		"js_endpoints_found": 2,
		"js_secrets_found":   1,
		"js_maps_fetched":    1,
	}
	for k, v := range wantStats {
		if got := rep.Stats[k]; got != v {
			t.Errorf("stat %s = %d, beklenen %d", k, got, v)
		}
	}
}
