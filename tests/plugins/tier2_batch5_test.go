// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package plugins

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// runTier2 executes one script and fails on execution errors.
// What: Small shared driver for the batch-5 E2E cases.
// Why: Keeps every case to its plugin-specific assertions.
func runTier2(t *testing.T, spec *plugin.PluginSpec, src string, env *loader.JSEnv) []loader.JSCandidate {
	t.Helper()
	cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	return cands
}

// TestSQLiXMLBodyErrorE2E proves XML-body SQLi injection.
func TestSQLiXMLBodyErrorE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/sqli/sqli-xml-body-error.js", "sqli-xml-body-error")
	point := loader.JSPoint{URL: "http://example.com/api/import", Method: "POST", ParamName: "id", ParamLocation: "body"}
	const signature = "<error>You have an error in your SQL syntax</error>"

	t.Run("element closure triggers a database signature", func(t *testing.T) {
		var xmlContentType atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "xml") {
					xmlContentType.Store(true)
				}
				if strings.Contains(p.Value, "'") {
					return loader.JSResponse{Status: 500, Headers: map[string]string{"Content-Type": "application/xml"}, Body: signature, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/xml"}, Body: "<request><id>1</id></request>", URL: p.URL}, nil
			},
		}
		cands := runTier2(t, spec, src, env)
		if len(cands) != 1 {
			t.Fatalf("one XML SQLi candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "error" {
			t.Fatalf("oracle must stay error, got %q", cands[0].Candidate.OracleName)
		}
		if !xmlContentType.Load() {
			t.Fatal("the document must carry an XML content type")
		}
	})

	t.Run("parameterised XML handler rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/xml"}, Body: "<request><id>1</id></request>", URL: p.URL}, nil
			},
		}
		if cands := runTier2(t, spec, src, env); len(cands) != 0 {
			t.Fatalf("neutral XML must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.error"},
			[]string{"host.oracles.reflection", "host.oracles.differential", "host.oracles.timing"})
	})
}

// TestXPathXMLBodyErrorE2E proves XML-body XPath injection at the firm ceiling.
func TestXPathXMLBodyErrorE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/xpath/xpath-xml-body-error.js", "xpath-xml-body-error")
	point := loader.JSPoint{URL: "http://example.com/api/search", Method: "POST", ParamName: "title", ParamLocation: "body"}
	const signature = "<error>XPathExpressionException: Invalid XPath expression</error>"

	if mode, _ := spec.OracleParams["mode"].(string); mode != "xpath" {
		t.Fatalf("oracle_params mode must be xpath, got %q", mode)
	}

	t.Run("closure payload provokes an xpath parser error", func(t *testing.T) {
		var xmlContentType atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "xml") {
					xmlContentType.Store(true)
				}
				if strings.Contains(p.Value, "'") {
					return loader.JSResponse{Status: 500, Headers: map[string]string{"Content-Type": "application/xml"}, Body: signature, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/xml"}, Body: "<result><item>1</item></result>", URL: p.URL}, nil
			},
		}
		cands := runTier2(t, spec, src, env)
		if len(cands) != 1 {
			t.Fatalf("one XPath candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceFirm {
			t.Fatalf("firm evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "error" {
			t.Fatalf("oracle must stay error, got %q", cands[0].Candidate.OracleName)
		}
		if !xmlContentType.Load() {
			t.Fatal("the document must carry an XML content type")
		}
	})

	t.Run("universal parser error rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 500, Headers: map[string]string{"Content-Type": "application/xml"}, Body: signature, URL: p.URL}, nil
			},
		}
		if cands := runTier2(t, spec, src, env); len(cands) != 0 {
			t.Fatalf("signature present for every document must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "POST", "body")
	})

	t.Run("mode is declared in oracle_params", func(t *testing.T) {
		if !strings.Contains(strings.ToLower(src), "mode: xpath") {
			t.Fatal("the xpath mode must be declared in oracle_params")
		}
		assertOracleSurface(t, src,
			[]string{"host.oracles.error"},
			[]string{"host.oracles.reflection", "host.oracles.differential", "host.oracles.timing"})
	})
}

// TestSQLiMultipartErrorE2E proves multipart field injection with sibling replay.
func TestSQLiMultipartErrorE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/sqli/sqli-multipart-error.js", "sqli-multipart-error")
	point := loader.JSPoint{
		URL: "http://example.com/api/items", Method: "POST", ParamName: "title", ParamLocation: "body",
		FormEnctype: "multipart/form-data",
		FormValues:  map[string]string{"csrf": "tok-123", "title": "old"},
	}
	const signature = "<html><body>You have an error in your SQL syntax</body></html>"

	t.Run("multipart closure triggers a signature and replays siblings", func(t *testing.T) {
		var multipartSeen, siblingSeen atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				ct := strings.ToLower(jsHeaderValue(p.Headers, "Content-Type"))
				if strings.HasPrefix(ct, "multipart/form-data; boundary=") {
					multipartSeen.Store(true)
				}
				if strings.Contains(p.Value, `name="csrf"`) && strings.Contains(p.Value, "tok-123") {
					siblingSeen.Store(true)
				}
				if strings.Contains(p.Value, "\r\n\r\n'") {
					return loader.JSResponse{Status: 500, Headers: map[string]string{"Content-Type": "text/html"}, Body: signature, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<html><body>saved</body></html>", URL: p.URL}, nil
			},
		}
		cands := runTier2(t, spec, src, env)
		if len(cands) != 1 {
			t.Fatalf("one multipart SQLi candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if !multipartSeen.Load() || !siblingSeen.Load() {
			t.Fatalf("multipart body and sibling fields required: multipart=%v sibling=%v", multipartSeen.Load(), siblingSeen.Load())
		}
	})

	t.Run("urlencoded point is ignored", func(t *testing.T) {
		var sends atomic.Int64
		other := point
		other.FormEnctype = "application/x-www-form-urlencoded"
		env := &loader.JSEnv{
			Points: []loader.JSPoint{other},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				sends.Add(1)
				return loader.JSResponse{Status: 200, Body: "neutral", URL: p.URL}, nil
			},
		}
		if cands := runTier2(t, spec, src, env); len(cands) != 0 || sends.Load() != 0 {
			t.Fatalf("non-multipart point must be skipped: cands=%d sends=%d", len(cands), sends.Load())
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.error"},
			[]string{"host.oracles.reflection", "host.oracles.differential"})
	})
}

// TestXXEXMLBodyOOBE2E proves direct XML-body blind XXE.
func TestXXEXMLBodyOOBE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/xxe/xxe-xml-body-oob.js", "xxe-xml-body-oob")
	point := loader.JSPoint{URL: "http://example.com/soap/import", Method: "POST", ParamName: "payload", ParamLocation: "body"}

	t.Run("callback confirms entity resolution", func(t *testing.T) {
		var xmlContentType, systemLiteral atomic.Bool
		env := &loader.JSEnv{
			Points:     []loader.JSPoint{point},
			OOBEnabled: true,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "xml") {
					xmlContentType.Store(true)
				}
				if strings.Contains(p.Value, "SYSTEM '") && strings.Contains(p.Value, "oob.example") {
					systemLiteral.Store(true)
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/xml"}, Body: "<response><status>accepted</status></response>", URL: p.URL}, nil
			},
			OOBCallbackSeenAny: func(ids []string) []string {
				if len(ids) == 0 {
					return nil
				}
				return ids[:1]
			},
		}
		cands := runTier2(t, spec, src, env)
		if len(cands) != 1 {
			t.Fatalf("one XML XXE candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "oob" {
			t.Fatalf("oracle must stay oob, got %q", cands[0].Candidate.OracleName)
		}
		if !xmlContentType.Load() || !systemLiteral.Load() {
			t.Fatalf("raw XML with a single-quoted SYSTEM literal required: xml=%v system=%v", xmlContentType.Load(), systemLiteral.Load())
		}
	})

	t.Run("without an OOB server nothing is sent", func(t *testing.T) {
		var sends atomic.Int64
		env := &loader.JSEnv{
			Points:     []loader.JSPoint{point},
			OOBEnabled: false,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				sends.Add(1)
				return loader.JSResponse{Status: 200, Body: "neutral", URL: p.URL}, nil
			},
		}
		if cands := runTier2(t, spec, src, env); len(cands) != 0 || sends.Load() != 0 {
			t.Fatalf("no OOB server means no request and no finding: cands=%d sends=%d", len(cands), sends.Load())
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oob.generate", "host.oracles.oobAny"},
			[]string{"host.oracles.reflection", "host.oracles.differential", "host.oracles.timing"})
	})
}

// TestXXESVGUploadOOBE2E proves SVG upload blind XXE.
func TestXXESVGUploadOOBE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/xxe/xxe-svg-upload-oob.js", "xxe-svg-upload-oob")
	point := loader.JSPoint{
		URL: "http://example.com/api/avatar", Method: "POST", ParamName: "avatar", ParamLocation: "body",
		FormEnctype: "multipart/form-data",
		FormValues:  map[string]string{"csrf": "tok-456", "avatar": ""},
	}

	t.Run("callback from the svg parser confirms", func(t *testing.T) {
		var filePart, systemLiteral, siblingSeen atomic.Bool
		env := &loader.JSEnv{
			Points:     []loader.JSPoint{point},
			OOBEnabled: true,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				ct := strings.ToLower(jsHeaderValue(p.Headers, "Content-Type"))
				if strings.HasPrefix(ct, "multipart/form-data; boundary=") &&
					strings.Contains(p.Value, `filename="`) && strings.Contains(p.Value, ".svg") &&
					strings.Contains(p.Value, "image/svg+xml") {
					filePart.Store(true)
				}
				if strings.Contains(p.Value, "SYSTEM '") && strings.Contains(p.Value, "oob.example") {
					systemLiteral.Store(true)
				}
				if strings.Contains(p.Value, `name="csrf"`) && strings.Contains(p.Value, "tok-456") {
					siblingSeen.Store(true)
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"uploaded":true}`, URL: p.URL}, nil
			},
			OOBCallbackSeenAny: func(ids []string) []string {
				if len(ids) == 0 {
					return nil
				}
				return ids[:1]
			},
		}
		cands := runTier2(t, spec, src, env)
		if len(cands) != 1 {
			t.Fatalf("one SVG XXE candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if !filePart.Load() || !systemLiteral.Load() || !siblingSeen.Load() {
			t.Fatalf("svg file part, SYSTEM literal and sibling replay required: file=%v system=%v sibling=%v",
				filePart.Load(), systemLiteral.Load(), siblingSeen.Load())
		}
	})

	t.Run("accepted upload without a callback proves nothing", func(t *testing.T) {
		env := &loader.JSEnv{
			Points:     []loader.JSPoint{point},
			OOBEnabled: true,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 200, Body: `{"uploaded":true}`, URL: p.URL}, nil
			},
		}
		if cands := runTier2(t, spec, src, env); len(cands) != 0 {
			t.Fatalf("an accepted upload alone must not confirm, got %d", len(cands))
		}
	})

	t.Run("without an OOB server nothing is sent", func(t *testing.T) {
		var sends atomic.Int64
		env := &loader.JSEnv{
			Points:     []loader.JSPoint{point},
			OOBEnabled: false,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				sends.Add(1)
				return loader.JSResponse{Status: 200, Body: "neutral", URL: p.URL}, nil
			},
		}
		if cands := runTier2(t, spec, src, env); len(cands) != 0 || sends.Load() != 0 {
			t.Fatalf("no OOB server means no request and no finding: cands=%d sends=%d", len(cands), sends.Load())
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oob.generate", "host.oracles.oobAny"},
			[]string{"host.oracles.reflection", "host.oracles.uploadServed"})
	})
}

// TestXSSPathSegmentE2E proves path-borne reflection with a clean base control.
func TestXSSPathSegmentE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/xss/xss-path-segment.js", "xss-path-segment")
	const canary = "gash_path_e2e"
	point := loader.JSPoint{URL: "http://example.com/products?sort=asc", Method: "GET", ParamName: "sort", ParamLocation: "query"}

	t.Run("executable path reflection confirms", func(t *testing.T) {
		var controlFetched atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Canary: canary,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				if strings.Contains(p.URL, "%3Csvg") || strings.Contains(p.URL, "%3csvg") {
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><svg onload=alert(" + canary + ")></body></html>", URL: p.URL}, nil
				}
				if p.URL == "http://example.com/products" {
					controlFetched.Store(true)
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><p>products</p></body></html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 404, Headers: h, Body: "<html><body><p>not found</p></body></html>", URL: p.URL}, nil
			},
		}
		cands := runTier2(t, spec, src, env)
		if len(cands) != 1 {
			t.Fatalf("one path XSS candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceStaticExecution {
			t.Fatalf("static-execution evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "reflection" {
			t.Fatalf("oracle must stay reflection, got %q", cands[0].Candidate.OracleName)
		}
		if !controlFetched.Load() {
			t.Fatal("the unmodified base page must be fetched as the clean control")
		}
	})

	t.Run("encoded path without reflection rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Canary: canary,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 404, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<html><body><p>not found</p></body></html>", URL: p.URL}, nil
			},
		}
		if cands := runTier2(t, spec, src, env); len(cands) != 0 {
			t.Fatalf("no reflection must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "GET", "query")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.reflection"},
			[]string{"host.oracles.differential", "host.oracles.stored", "host.oracles.error"})
	})
}

// TestXSSReflectedHeaderE2E proves header-borne reflection with a clean control.
func TestXSSReflectedHeaderE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/xss/xss-reflected-header.js", "xss-reflected-header")
	const canary = "gash_header_e2e"
	point := loader.JSPoint{URL: "http://example.com/welcome", Method: "GET", ParamName: "", ParamLocation: "query"}

	t.Run("user-agent reflection confirms", func(t *testing.T) {
		var controlClean atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Canary: canary,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				ua := jsHeaderValue(p.Headers, "User-Agent") + jsHeaderValue(p.Headers, "Referer")
				if strings.Contains(ua, "<svg") {
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><svg onload=alert(" + canary + ")></body></html>", URL: p.URL}, nil
				}
				controlClean.Store(true)
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><p>welcome</p></body></html>", URL: p.URL}, nil
			},
		}
		cands := runTier2(t, spec, src, env)
		if len(cands) != 1 {
			t.Fatalf("one header XSS candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceStaticExecution {
			t.Fatalf("static-execution evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "reflection" {
			t.Fatalf("oracle must stay reflection, got %q", cands[0].Candidate.OracleName)
		}
		if !controlClean.Load() {
			t.Fatal("the header-less control request must run")
		}
	})

	t.Run("header reflection as comment rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Canary: canary,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<html><body><!-- " + canary + " --><p>welcome</p></body></html>", URL: p.URL}, nil
			},
		}
		if cands := runTier2(t, spec, src, env); len(cands) != 0 {
			t.Fatalf("comment reflection must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "GET", "query")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.reflection"},
			[]string{"host.oracles.differential", "host.oracles.stored", "host.oracles.error"})
	})
}

// TestOpenRedirectPathParserE2E proves path parser-confusion redirects.
func TestOpenRedirectPathParserE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/redirect/open-redirect-path-parser.js", "open-redirect-path-parser")
	const canary = "gash_redir_e2e"
	const payloadHost = "gash-gash-redir-e2e.example"
	point := loader.JSPoint{URL: "http://example.com/go", Method: "GET", ParamName: "", ParamLocation: "query"}

	t.Run("path confusion hop confirms", func(t *testing.T) {
		var neutralPath atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Canary: canary,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				if strings.Contains(p.URL, payloadHost) {
					h["Location"] = "https://" + payloadHost + "/login"
					return loader.JSResponse{Status: 302, Headers: h, Body: "<html>redirecting</html>", URL: p.URL}, nil
				}
				if strings.Contains(p.URL, "gash-neutral-path") {
					neutralPath.Store(true)
					h["Location"] = "/home"
					return loader.JSResponse{Status: 302, Headers: h, Body: "<html>redirecting</html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html>home</html>", URL: p.URL}, nil
			},
		}
		cands := runTier2(t, spec, src, env)
		if len(cands) != 1 {
			t.Fatalf("one path redirect candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "redirect" {
			t.Fatalf("oracle must stay redirect, got %q", cands[0].Candidate.OracleName)
		}
		if !neutralPath.Load() {
			t.Fatal("the neutral-path control must run before confirming")
		}
	})

	t.Run("relative path hop rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Canary: canary,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 302, Headers: map[string]string{"Content-Type": "text/html", "Location": "/login"}, Body: "<html>redirecting</html>", URL: p.URL}, nil
			},
		}
		if cands := runTier2(t, spec, src, env); len(cands) != 0 {
			t.Fatalf("a relative hop must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "GET", "query")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.redirect"},
			[]string{"host.oracles.reflection", "host.oracles.differential", "host.oracles.stored"})
	})
}

// TestNoSQLNestedJSONOperatorE2E proves nested-envelope operator injection.
func TestNoSQLNestedJSONOperatorE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/nosql/nosql-nested-json-operator.js", "nosql-nested-json-operator")
	point := loader.JSPoint{URL: "http://example.com/api/users", Method: "POST", ParamName: "username", ParamLocation: "body"}
	const trueBody = `{"result":"admin"}`
	const falseBody = `{"error":"not found"}`

	t.Run("nested operator diverges and confirms", func(t *testing.T) {
		var nestedSeen atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				if strings.Contains(p.Value, `"filter"`) {
					nestedSeen.Store(true)
				}
				switch {
				case strings.Contains(p.Value, "$ne") || strings.Contains(p.Value, "$gt"):
					return loader.JSResponse{Status: 200, Headers: h, Body: trueBody, URL: p.URL}, nil
				case strings.Contains(p.Value, "gash-no-such-entry"):
					return loader.JSResponse{Status: 200, Headers: h, Body: falseBody, URL: p.URL}, nil
				default:
					return loader.JSResponse{Status: 200, Headers: h, Body: falseBody, URL: p.URL}, nil
				}
			},
		}
		cands := runTier2(t, spec, src, env)
		if len(cands) != 1 {
			t.Fatalf("one nested NoSQL candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "differential" {
			t.Fatalf("oracle must stay differential, got %q", cands[0].Candidate.OracleName)
		}
		if !nestedSeen.Load() {
			t.Fatal("the field must be carried inside a nested filter object")
		}
	})

	t.Run("literal operator handling rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: falseBody, URL: p.URL}, nil
			},
		}
		if cands := runTier2(t, spec, src, env); len(cands) != 0 {
			t.Fatalf("identical branches must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.differential"},
			[]string{"host.oracles.error", "host.oracles.oob", "host.oracles.timing"})
	})
}

// TestPathTraversalEncodingBypassE2E proves encoded traversal families.
func TestPathTraversalEncodingBypassE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/path-traversal/path-traversal-encoding-bypass.js", "path-traversal-encoding-bypass")
	point := loader.JSPoint{URL: "http://example.com/download?file=readme.txt", Method: "GET", ParamName: "file", ParamLocation: "query"}
	const signature = "<html><body>Warning: failed to open stream: No such file or directory</body></html>"

	if mode, _ := spec.OracleParams["mode"].(string); mode != "path_traversal" {
		t.Fatalf("oracle_params mode must be path_traversal, got %q", mode)
	}

	t.Run("encoded family provokes a file-access error", func(t *testing.T) {
		var singleEncoded, doubleEncoded atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				lower := strings.ToLower(p.URL)
				if strings.Contains(lower, "..%2f..%2f") && !strings.Contains(lower, "%252f") {
					singleEncoded.Store(true)
				}
				if strings.Contains(lower, "%252f") {
					doubleEncoded.Store(true)
				}
				h := map[string]string{"Content-Type": "text/html"}
				if strings.Contains(lower, "%252f") {
					// Only the double-encoded variant reaches the filesystem: a
					// filter strips one layer, so the single-encoded probe is
					// served as a harmless page.
					return loader.JSResponse{Status: 500, Headers: h, Body: signature, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>Welcome</body></html>", URL: p.URL}, nil
			},
		}
		cands := runTier2(t, spec, src, env)
		if len(cands) != 1 {
			t.Fatalf("one traversal candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "error" {
			t.Fatalf("oracle must stay error, got %q", cands[0].Candidate.OracleName)
		}
		if !singleEncoded.Load() || !doubleEncoded.Load() {
			t.Fatalf("single- and double-encoded variants must both be sent: single=%v double=%v", singleEncoded.Load(), doubleEncoded.Load())
		}
	})

	t.Run("reflected payload without an access error rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<html><body>file not allowed</body></html>", URL: p.URL}, nil
			},
		}
		if cands := runTier2(t, spec, src, env); len(cands) != 0 {
			t.Fatalf("no access error must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "GET", "query")
	})

	t.Run("mode is declared in oracle_params", func(t *testing.T) {
		if !strings.Contains(strings.ToLower(src), "mode: path_traversal") {
			t.Fatal("the path_traversal mode must be declared in oracle_params")
		}
		assertOracleSurface(t, src,
			[]string{"host.oracles.error"},
			[]string{"host.oracles.reflection", "host.oracles.differential", "host.oracles.timing"})
	})
}
