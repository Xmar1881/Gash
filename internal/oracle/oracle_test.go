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

func TestReflectionConfirmed(t *testing.T) {
	var o ReflectionOracle
	ev, err := o.Verify(context.Background(), `<script>gash_abc123</script>`, nil, cls(), false, ReflectionParams{
		Canary: "gash_abc123", RequireExecutableContext: true, ControlBody: `<p>zzz</p>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "confirmed" {
		t.Fatalf("confirmed bekleniyordu: %+v", ev)
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
	ev, err := o.Verify(context.Background(), `<script>gash_abc123</script>`, nil, cls(), false, ReflectionParams{
		Canary: "gash_abc123", RequireExecutableContext: true,
		ControlBody: `<script>gash_abc123</script>`,
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

func TestOOBSkippedWhenDisabled(t *testing.T) {
	o := OOBOracle{Enabled: false}
	ev, _ := o.Verify(context.Background(), cls(), false, OOBParams{CorrelationID: "c_x", Namespace: "n"})
	if ev.Verdict != VerdictSkipped {
		t.Fatalf("skipped bekleniyordu: %+v", ev)
	}
}
