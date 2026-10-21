// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"net/http"
	"testing"

	"github.com/Xmar1881/Gash/internal/baseline"
)

func cls() baseline.Classification { return baseline.Classification{Note: "normal"} }

func TestReflectionStaticExecutionEvidence(t *testing.T) {
	var o ReflectionOracle
	ev, err := o.Verify(context.Background(), `<script>alert(gash_abc123)</script>`, nil, cls(), false, ReflectionParams{
		Canary: "gash_abc123", RequireExecutableContext: true, ControlBody: `<p>zzz</p>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "static-execution-evidence" {
		t.Fatalf("static execution evidence bekleniyordu: %+v", ev)
	}
	if ev.Artifacts["execution"] != "static" {
		t.Fatalf("browser calistirilmadigi acikca isaretlenmeli: %+v", ev)
	}
}

func TestReflectionBrowserConfirmedRequiresHeadlessExecution(t *testing.T) {
	var o ReflectionOracle
	params := ReflectionParams{
		Canary: "gash_abc123", RequireExecutableContext: true,
		ControlBody: `<p>clean</p>`, BrowserVerified: true,
	}
	ev, err := o.Verify(context.Background(), `<script>alert(gash_abc123)</script>`, nil, cls(), false, params)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("headless calistirilmadiysa kabul edilmemeli: %+v", ev)
	}

	params.BrowserTriggered = true
	params.BrowserControlClean = true
	ev, err = o.Verify(context.Background(), `<script>alert(gash_abc123)</script>`, nil, cls(), false, params)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "confirmed" || ev.Artifacts["execution"] != "browser-confirmed" {
		t.Fatalf("browser confirmed bekleniyordu: %+v", ev)
	}
}

func TestReflectionStaticEvidenceWithoutControlNeverBecomesConfirmed(t *testing.T) {
	var o ReflectionOracle
	ev, err := o.Verify(context.Background(), `<script>alert(gash_abc123)</script>`, nil, cls(), false, ReflectionParams{
		Canary: "gash_abc123", Contexts: []string{"script"}, RequireExecutableContext: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "static-execution-evidence" || ev.Artifacts["execution"] != "static" {
		t.Fatalf("control olmadan browser confirmed veya firm donmemeli: %+v", ev)
	}
}

func TestReflectionEncodedTentative(t *testing.T) {
	var o ReflectionOracle
	body := `<p>&lt;script&gt;gash_abc123</p>`
	if got := ContextOf(body, "gash_abc123"); got != "encoded" {
		t.Fatalf("encoded bağlam bekleniyordu, got %q", got)
	}
	ev, err := o.Verify(context.Background(), body, nil, cls(), false, ReflectionParams{
		Canary: "gash_abc123", RequireExecutableContext: true, ControlBody: `<p>zzz</p>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "tentative" {
		t.Fatalf("encoded en fazla tentative olmalı: %+v", ev)
	}
}

func TestReflectionCommentReject(t *testing.T) {
	var o ReflectionOracle
	// Yorum içindeki `<script>` yazımı yürütülemez; eski pencere sezgisi
	// bunu `script` sayardı (FP). Tokenizer-öncelikli sınıflandırma `comment`
	// üretmeli ve Verify reddetmelidir.
	for _, body := range []string{
		`<!-- q=gash_abc123 -->`,
		`<!-- <script>gash_abc123</script> -->`,
	} {
		if got := ContextOf(body, "gash_abc123"); got != "comment" {
			t.Fatalf("comment bağlam bekleniyordu (%s), got %q", body, got)
		}
		ev, err := o.Verify(context.Background(), body, nil, cls(), false, ReflectionParams{
			Canary: "gash_abc123", RequireExecutableContext: true, ControlBody: `<p>zzz</p>`,
		})
		if err != nil {
			t.Fatal(err)
		}
		if ev.Verdict != VerdictReject {
			t.Fatalf("yorum içi yansıma reject olmalı (%s): %+v", body, ev)
		}
	}
}

func TestReflectionStyleTentative(t *testing.T) {
	var o ReflectionOracle
	body := `<style>.a{width:gash_abc123}</style>`
	if got := ContextOf(body, "gash_abc123"); got != "style" {
		t.Fatalf("style bağlam bekleniyordu, got %q", got)
	}
	ev, err := o.Verify(context.Background(), body, nil, cls(), false, ReflectionParams{
		Canary: "gash_abc123", RequireExecutableContext: true, ControlBody: `<p>zzz</p>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "tentative" {
		t.Fatalf("style en fazla tentative olmalı: %+v", ev)
	}
}

func TestReflectionNonExecutableScriptFormsReject(t *testing.T) {
	var o ReflectionOracle
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "quoted string", body: `<script>const value = "gash_abc123";</script>`},
		{name: "line comment", body: `<script>// gash_abc123
alert(1)</script>`},
		{name: "block comment", body: `<script>/* gash_abc123 */ alert(1)</script>`},
		{name: "json", body: `<script type="application/json">{"value":"gash_abc123"}</script>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ContextOf(tc.body, "gash_abc123"); got == "script" {
				t.Fatalf("non-executable script form classified as script: %q", got)
			}
			ev, err := o.Verify(context.Background(), tc.body, nil, cls(), false, ReflectionParams{
				Canary: "gash_abc123", Contexts: []string{"script"},
				RequireExecutableContext: true, ControlBody: `<p>clean</p>`,
			})
			if err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != VerdictReject || ev.ConfidenceContribution == "confirmed" || ev.ConfidenceContribution == "static-execution-evidence" {
				t.Fatalf("non-executable script must reject: %+v", ev)
			}
		})
	}
}

func TestReflectionCanaryNeedsExecutionPayload(t *testing.T) {
	var o ReflectionOracle
	ev, err := o.Verify(context.Background(), `<script>gash_abc123</script>`, nil, cls(), false, ReflectionParams{
		Canary: "gash_abc123", Contexts: []string{"script"},
		RequireExecutableContext: true, ControlBody: `<p>clean</p>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "tentative" {
		t.Fatalf("bare canary must not be confirmed: %+v", ev)
	}
}

func TestReflectionContextsAreEnforced(t *testing.T) {
	var o ReflectionOracle
	ev, err := o.Verify(context.Background(), `<div onerror="alert(gash_abc123)">x</div>`, nil, cls(), false, ReflectionParams{
		Canary: "gash_abc123", Contexts: []string{"html"},
		RequireExecutableContext: true, ControlBody: `<p>clean</p>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("disallowed event-handler context must reject: %+v", ev)
	}
}

func TestReflectionCSPDowngradesInlineExecution(t *testing.T) {
	var o ReflectionOracle
	h := http.Header{"Content-Security-Policy": []string{"default-src 'self'"}}
	ev, err := o.Verify(context.Background(), `<script>alert(gash_abc123)</script>`, h, cls(), false, ReflectionParams{
		Canary: "gash_abc123", Contexts: []string{"script"},
		RequireExecutableContext: true, ControlBody: `<p>clean</p>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "tentative" {
		t.Fatalf("CSP-blocked inline execution must be tentative: %+v", ev)
	}
}

func TestReflectionURLPrecision(t *testing.T) {
	// Metin yansıması, 200 karakter yakınında ilgisiz bir `href=` var diye
	// `url` sayılmamalı (eski pencere sezgisinin FP'si). Bağlam tokenizer
	// ile çözülür; gerçek href-içi yansıma hâlâ `url` üretir.
	textBody := `<a href="/home">home</a><div><p>gash_abc123</p></div>`
	if got := ContextOf(textBody, "gash_abc123"); got != "html-text" {
		t.Fatalf("html-text bekleniyordu, got %q", got)
	}
	urlBody := `<a href="http://example.com/?x=gash_abc123">tikla</a>`
	if got := ContextOf(urlBody, "gash_abc123"); got != "url" {
		t.Fatalf("url bekleniyordu, got %q", got)
	}
}

func TestReflectionControlIndistinguishable(t *testing.T) {
	var o ReflectionOracle
	// Kontrol yanıtı da aynı executable bağlamda canary taşıyorsa aday ayırt
	// edici değildir → reject (kontrolsüz confirmed YOK kuralı).
	ev, err := o.Verify(context.Background(), `<script>alert(gash_abc123)</script>`, nil, cls(), false, ReflectionParams{
		Canary: "gash_abc123", RequireExecutableContext: true,
		ControlBody: `<script>alert(gash_abc123)</script>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("ayırt edici olmayan kontrol reject olmalı: %+v", ev)
	}
}

func TestReflectionUntrustedReject(t *testing.T) {
	var o ReflectionOracle
	ev, _ := o.Verify(context.Background(), `<script>gash_x</script>`, nil,
		baseline.Classification{Untrusted: true}, false, ReflectionParams{Canary: "gash_x"})
	if ev.Verdict != VerdictReject {
		t.Fatalf("untrusted reject olmalı: %+v", ev)
	}
}

func TestDifferentialConfirmed(t *testing.T) {
	var o DifferentialOracle
	ev, err := o.Verify(context.Background(), cls(), false, DifferentialParams{
		TrueBodies:  []string{"aaa TRUE bb", "aaa TRUE bb", "aaa TRUE bb"},
		FalseBodies: []string{"aaa FALSE bb", "aaa FALSE bb", "aaa FALSE bb"},
		ControlBody: "aaa bb", Repeats: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "confirmed" {
		t.Fatalf("confirmed: %+v", ev)
	}
}

func TestDifferentialUnstableReject(t *testing.T) {
	var o DifferentialOracle
	ev, _ := o.Verify(context.Background(), cls(), false, DifferentialParams{
		TrueBodies: []string{"a", "b", "a"}, FalseBodies: []string{"x", "x", "x"}, Repeats: 3,
	})
	if ev.Verdict != VerdictReject {
		t.Fatalf("kararsız reject olmalı: %+v", ev)
	}
}

func TestTimingFirm(t *testing.T) {
	var o TimingOracle
	ev, err := o.Verify(context.Background(), cls(), false, TimingParams{
		DelaySamples: []float64{5200, 5300, 5100}, ControlSamples: []float64{300, 310, 290},
		BaselineStddev: 100, Repeats: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "firm" {
		t.Fatalf("firm bekleniyordu: %+v", ev)
	}
}

func TestTimingSingleReject(t *testing.T) {
	var o TimingOracle
	ev, _ := o.Verify(context.Background(), cls(), false, TimingParams{
		DelaySamples: []float64{5200}, ControlSamples: []float64{300}, Repeats: 1,
	})
	if ev.Verdict != VerdictReject {
		t.Fatalf("N<3 reject olmalı: %+v", ev)
	}
}

func TestErrorSignatureConfirmed(t *testing.T) {
	var o ErrorSignatureOracle
	ev, _ := o.Verify(context.Background(), cls(), false, ErrorSignatureParams{
		Body: "SQLServer conversion failed int", ControlBody: "normal page",
	})
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "confirmed" {
		t.Fatalf("confirmed: %+v", ev)
	}
}

func TestHeaderConfirmed(t *testing.T) {
	var o HeaderOracle
	h := http.Header{}
	ev, _ := o.Verify(context.Background(), cls(), false, HeaderParams{Headers: h})
	if ev.Verdict != VerdictAccept {
		t.Fatalf("missing header confirmed olmalı: %+v", ev)
	}
}

func TestRedirectConfirmed(t *testing.T) {
	var o RedirectOracle
	ev, _ := o.Verify(context.Background(), cls(), false, RedirectParams{
		Location: "https://gash-canary.example/x", PayloadHost: "gash-canary.example", ControlNoRedir: true, ResolveDNS: false,
	})
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "confirmed" {
		t.Fatalf("confirmed: %+v", ev)
	}
}

func TestVersionTentative(t *testing.T) {
	var o VersionOracle
	ev, _ := o.Verify(context.Background(), cls(), false, VersionParams{Banner: "Server: Apache/2.4.49"})
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "tentative" {
		t.Fatalf("tentative: %+v", ev)
	}
}

func TestExecutionFirmWithoutHeadless(t *testing.T) {
	var o ExecutionOracle
	ev, _ := o.Verify(context.Background(), cls(), false, ExecutionParams{Sink: "innerHTML", Source: "location.hash"})
	if ev.ConfidenceContribution != "firm" {
		t.Fatalf("firm tavan: %+v", ev)
	}
}

func TestExecutionBrowserOnlyConfirmedWithoutStaticSink(t *testing.T) {
	var o ExecutionOracle
	ev, err := o.Verify(context.Background(), cls(), false, ExecutionParams{
		HeadlessEnabled: true, Triggered: true, ControlClean: true,
		Payload: "payload",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "confirmed" {
		t.Fatalf("browser-only execution must confirm: %+v", ev)
	}
	if ev.Artifacts["browser"] != "execution" || ev.Artifacts["payload"] != "payload" {
		t.Fatalf("browser-only evidence missing artifacts: %+v", ev.Artifacts)
	}
	if _, ok := ev.Artifacts["sink"]; ok {
		t.Fatalf("browser-only evidence must not invent a sink: %+v", ev.Artifacts)
	}
}

func TestOOBSkippedWhenDisabled(t *testing.T) {
	o := OOBOracle{Enabled: false}
	ev, _ := o.Verify(context.Background(), cls(), false, OOBParams{CorrelationID: "c_x", Namespace: "n"})
	if ev.Verdict != VerdictSkipped {
		t.Fatalf("skipped bekleniyordu: %+v", ev)
	}
}

func TestHeaderCSRFConfirmed(t *testing.T) {
	var o HeaderOracle
	body := `<html><body><form action="/transfer" method="POST"><input name="amount"></form></body></html>`
	ev, err := o.Verify(context.Background(), cls(), false, HeaderParams{Headers: http.Header{}, Mode: "csrf", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "confirmed" {
		t.Fatalf("POST formda token yok confirmed olmalı: %+v", ev)
	}
}

func TestHeaderCSRFRejects(t *testing.T) {
	var o HeaderOracle
	// Token'lı form korumalıdır.
	body := `<html><body><form action="/transfer" method="POST"><input type="hidden" name="csrf_token" value="abc"></form></body></html>`
	ev, _ := o.Verify(context.Background(), cls(), false, HeaderParams{Headers: http.Header{}, Mode: "csrf", Body: body})
	if ev.Verdict != VerdictReject {
		t.Fatalf("token'lı form reject olmalı: %+v", ev)
	}
	// GET formu bu kuralda rejecttir.
	ev, _ = o.Verify(context.Background(), cls(), false, HeaderParams{Headers: http.Header{}, Mode: "csrf", Body: `<form action="/s" method="GET"><input name="q"></form>`})
	if ev.Verdict != VerdictReject {
		t.Fatalf("GET form reject olmalı: %+v", ev)
	}
	// Form yoksa rejecttir.
	ev, _ = o.Verify(context.Background(), cls(), false, HeaderParams{Headers: http.Header{}, Mode: "csrf", Body: `<p>hello</p>`})
	if ev.Verdict != VerdictReject {
		t.Fatalf("formsuz sayfa reject olmalı: %+v", ev)
	}
	// SameSite=Strict varsa firm'a düşer.
	h := http.Header{}
	h.Set("Set-Cookie", "sess=abc; Path=/; SameSite=Strict")
	ev, _ = o.Verify(context.Background(), cls(), false, HeaderParams{Headers: h, Mode: "csrf", Body: `<form action="/t" method="POST"><input name="a"></form>`})
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "firm" {
		t.Fatalf("Strict çerezli tokensiz form firm olmalı: %+v", ev)
	}
}

func TestHeaderFrameConfirmed(t *testing.T) {
	var o HeaderOracle
	// Çerçeve koruması yok → confirmed.
	ev, _ := o.Verify(context.Background(), cls(), false, HeaderParams{Headers: http.Header{"Content-Type": {"text/html"}}, Mode: "frame"})
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "confirmed" {
		t.Fatalf("korumasız sayfa confirmed olmalı: %+v", ev)
	}
	// X-Frame-Options DENY → reject.
	h := http.Header{"X-Frame-Options": {"DENY"}}
	ev, _ = o.Verify(context.Background(), cls(), false, HeaderParams{Headers: h, Mode: "frame"})
	if ev.Verdict != VerdictReject {
		t.Fatalf("DENY reject olmalı: %+v", ev)
	}
	// CSP frame-ancestors 'self' → reject.
	h2 := http.Header{"Content-Security-Policy": {"frame-ancestors 'self'"}}
	ev, _ = o.Verify(context.Background(), cls(), false, HeaderParams{Headers: h2, Mode: "frame"})
	if ev.Verdict != VerdictReject {
		t.Fatalf("frame-ancestors self reject olmalı: %+v", ev)
	}
	// CSP frame-ancestors wildcard → confirmed.
	h3 := http.Header{"Content-Security-Policy": {"frame-ancestors * "}}
	ev, _ = o.Verify(context.Background(), cls(), false, HeaderParams{Headers: h3, Mode: "frame"})
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "confirmed" {
		t.Fatalf("wildcard confirmed olmalı: %+v", ev)
	}
}
