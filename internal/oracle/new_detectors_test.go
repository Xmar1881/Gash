// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"net/http"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// Lab-batch dedektörleri için oracle-seviyesi kanıt testleri:
// deserialization/takeover imza modları (GASH-029/030, firm tavan),
// ratelimit gözlem modu (GASH-032, tentative tavan) ve differential
// güven tavanı (GASH-031). Fixture kapısı (TestMetricGate) uçtan-uca
// ölçer; burası saf oracle mantığını ve korpus sessizliğini pinler.

func TestPathTraversalContentSignatures(t *testing.T) {
	var o ErrorSignatureOracle
	ctx := context.Background()
	pos := []struct {
		body string
		sig  string
	}{
		{"<pre>root:x:0:0:root:/root:/bin/bash</pre>", "unix_passwd"},
		{"<pre>[fonts]\r\nfor 16-bit app support</pre>", "windows_ini"},
	}
	for _, tc := range pos {
		ev, err := o.Verify(ctx, cls(), false, ErrorSignatureParams{
			Body: tc.body, ControlBody: "<p>clean</p>", Mode: "path_traversal",
			SignatureSet: []string{"unix_passwd", "windows_ini"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("%s confirmed bekleniyordu: %+v", tc.sig, ev)
		}
		if ev.Artifacts["signature"] != tc.sig {
			t.Fatalf("signature=%q, want %q", ev.Artifacts["signature"], tc.sig)
		}
	}
	// Reflected traversal text and include warnings alone are not file proof.
	for _, body := range []string{
		"<p>Requested file: ../../../etc/passwd</p>",
		"Warning: include(gash-control-neutral): failed to open stream: No such file or directory",
	} {
		ev, err := o.Verify(ctx, cls(), false, ErrorSignatureParams{
			Body: body, ControlBody: "<p>clean</p>", Mode: "path_traversal",
			SignatureSet: []string{"unix_passwd", "windows_ini"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if ev.Verdict == VerdictAccept {
			t.Fatalf("reflection/warning must not count as file content: %+v", ev)
		}
	}
	// Same successful content in the control means the marker is not distinguishing.
	ev, err := o.Verify(ctx, cls(), false, ErrorSignatureParams{
		Body: "<pre>[fonts]</pre>", ControlBody: "<pre>[fonts]</pre>", Mode: "path_traversal",
		SignatureSet: []string{"unix_passwd", "windows_ini"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("control-equal content reject olmalı: %+v", ev)
	}
}

func TestPathTraversalControlledIncludeError(t *testing.T) {
	var o ErrorSignatureOracle
	ctx := context.Background()
	for _, body := range []string{
		"Warning: include(../../../../etc/passwd): failed to open stream: No such file or directory",
		`open() "/srv/app/../../etc/passwd" failed (2: No such file or directory)`,
	} {
		ev, err := o.Verify(ctx, cls(), false, ErrorSignatureParams{
			Body: body, ControlBody: "<p>file is unavailable</p>", Mode: "path_traversal",
			SignatureSet: []string{"include_error"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("control-differential include error confirmed olmalı: %+v", ev)
		}
		if ev.Artifacts["signature"] != "include_error" || ev.ControlResult != "absent" {
			t.Fatalf("include_error artifact/control bekleniyordu: %+v", ev)
		}
	}
	rejects := []struct {
		name        string
		body        string
		controlBody string
	}{
		{"same warning in control", "Warning: include(x): failed to open stream: No such file or directory", "Warning: include(x): failed to open stream: No such file or directory"},
		{"reflected payload only", "<p>Requested file: ../../../../etc/passwd</p>", "<p>file is unavailable</p>"},
	}
	for _, tc := range rejects {
		ev, err := o.Verify(ctx, cls(), false, ErrorSignatureParams{
			Body: tc.body, ControlBody: tc.controlBody, Mode: "path_traversal",
			SignatureSet: []string{"include_error"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if ev.Verdict != VerdictReject {
			t.Fatalf("%s reject olmalı: %+v", tc.name, ev)
		}
	}
	ev, err := o.Verify(ctx, cls(), false, ErrorSignatureParams{
		Body: "Warning: include(../../etc/passwd): failed to open stream: No such file or directory",
		Mode: "path_traversal", SignatureSet: []string{"include_error"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceFirm {
		t.Fatalf("include error without control firm olmalı: %+v", ev)
	}
}

func TestDeserializationSignature(t *testing.T) {
	var o ErrorSignatureOracle
	ctx := context.Background()
	pos := []string{
		`java.io.InvalidClassException: bad serial at java.io.ObjectInputStream.readObject(ObjectInputStream.java:42)`,
		"Traceback (most recent call last): pickle.loads(data) _pickle.UnpicklingError: invalid load key",
		`Fatal error: unserialize(): Error at offset 5 in index.php on line 42 with __wakeup mismatch`,
	}
	for _, body := range pos {
		ev, err := o.Verify(ctx, cls(), false, ErrorSignatureParams{
			Body: body, ControlBody: `<p>clean</p>`, Mode: "deserialization", SignatureSet: []string{"deserialization"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceFirm {
			t.Fatalf("firm bekleniyordu: %+v", ev)
		}
	}
	// Kontrolde aynı imza → ayırt edici değil.
	ev, err := o.Verify(ctx, cls(), false, ErrorSignatureParams{
		Body: pos[0], ControlBody: pos[0], Mode: "deserialization", SignatureSet: []string{"deserialization"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("kontrol-aynı reject olmalı: %+v", ev)
	}
	// Temiz korpus gövdeleri sessiz.
	for _, body := range []string{
		`<html><body><h1>Hello</h1><p>Welcome</p></body></html>`,
		`<html><body><div id=root></div><script src=/static/js/main.js></script></body></html>`,
		`<html><body>cf-chl challenge Please verify</body></html>`,
	} {
		ev, err := o.Verify(ctx, cls(), false, ErrorSignatureParams{
			Body: body, ControlBody: `<p>clean</p>`, Mode: "deserialization", SignatureSet: []string{"deserialization"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if ev.Verdict == VerdictAccept && (ev.ConfidenceContribution == plugin.ConfidenceFirm || ev.ConfidenceContribution == plugin.ConfidenceConfirmed) {
			t.Fatalf("korpus FP: %+v", ev)
		}
	}
}

func TestTakeoverSignature(t *testing.T) {
	var o ErrorSignatureOracle
	ctx := context.Background()
	pos := []string{
		`NoSuchBucket: The specified bucket does not exist`,
		`There isn't a GitHub Pages site here.`,
		`There is no app configured at that hostname.`,
	}
	for _, body := range pos {
		ev, err := o.Verify(ctx, cls(), false, ErrorSignatureParams{
			Body: body, ControlBody: `<p>clean</p>`, Mode: "takeover", SignatureSet: []string{"takeover"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceFirm {
			t.Fatalf("firm bekleniyordu: %+v", ev)
		}
	}
	// Kontrolsüz de tavan firm (DNS-bağımlı, confirmed YOK).
	ev, err := o.Verify(ctx, cls(), false, ErrorSignatureParams{
		Body: pos[0], Mode: "takeover", SignatureSet: []string{"takeover"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceFirm {
		t.Fatalf("kontrolsüz firm bekleniyordu: %+v", ev)
	}
	// Parked sayfa + kontrol-aynı → reject.
	for _, tc := range []struct {
		body, control string
	}{
		{`<p>This domain is under construction.</p>`, `<p>clean</p>`},
		{pos[1], pos[1]},
	} {
		ev, err := o.Verify(ctx, cls(), false, ErrorSignatureParams{
			Body: tc.body, ControlBody: tc.control, Mode: "takeover", SignatureSet: []string{"takeover"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if ev.Verdict == VerdictAccept && (ev.ConfidenceContribution == plugin.ConfidenceFirm || ev.ConfidenceContribution == plugin.ConfidenceConfirmed) {
			t.Fatalf("negatif FP: %+v", ev)
		}
	}
}

func TestRateLimitMode(t *testing.T) {
	var o HeaderOracle
	ctx := context.Background()
	h := func(pairs ...string) http.Header {
		out := make(http.Header)
		for i := 0; i+1 < len(pairs); i += 2 {
			out.Set(pairs[i], pairs[i+1])
		}
		return out
	}
	// Sinyalsiz → tentative.
	ev, err := o.Verify(ctx, cls(), false, HeaderParams{
		Headers: h("Content-Type", "text/html"), Mode: "ratelimit", Body: `<p>hi</p>`, Status: 200, Burst: []int{200, 200, 200},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceTentative {
		t.Fatalf("tentative bekleniyordu: %+v", ev)
	}
	if ev.Artifacts["burst"] != "3" {
		t.Fatalf("burst sayacı taşınmalı: %+v", ev)
	}
	// Burst içinde tek 429 bile korumalı demektir.
	ev, err = o.Verify(ctx, cls(), false, HeaderParams{
		Headers: h("Content-Type", "text/html"), Mode: "ratelimit", Body: `<p>hi</p>`, Status: 200,
		Burst: []int{200, 429, 200},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("burst-429 reject olmalı: %+v", ev)
	}
	// Rate-limit başlıkları → korumalı.
	ev, err = o.Verify(ctx, cls(), false, HeaderParams{
		Headers: h("Content-Type", "text/html", "X-RateLimit-Remaining", "99"), Mode: "ratelimit", Body: `<p>hi</p>`, Status: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("rl-header reject olmalı: %+v", ev)
	}
	// Gövde metni → korumalı.
	ev, err = o.Verify(ctx, cls(), false, HeaderParams{
		Headers: h("Content-Type", "text/html"), Mode: "ratelimit", Body: `<p>Too Many Requests, slow down</p>`, Status: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("gövde-metni reject olmalı: %+v", ev)
	}
	// Diğer header modları tentative üretmez (sözleşme korunur).
	ev, err = o.Verify(ctx, cls(), false, HeaderParams{
		Headers: h("Content-Type", "text/html"), Mode: "security", Body: `<p>hi</p>`, Status: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict == VerdictAccept && ev.ConfidenceContribution == plugin.ConfidenceTentative {
		t.Fatalf("security modu tentative üretmemeli: %+v", ev)
	}
}

func TestDifferentialCeiling(t *testing.T) {
	var o DifferentialOracle
	ctx := context.Background()
	mk := func(tv, fv string) DifferentialParams {
		return DifferentialParams{
			TrueBodies:  []string{tv, tv, tv},
			FalseBodies: []string{fv, fv, fv},
			ControlBody: `<p>neutral</p>`, Repeats: 3,
		}
	}
	// Tavansız → confirmed (mevcut sözleşme).
	p := mk(`{"role":"0"}`, `{"role":"x"}`)
	ev, err := o.Verify(ctx, cls(), false, p)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
		t.Fatalf("tavansız confirmed bekleniyordu: %+v", ev)
	}
	// firm tavan → firm + artifact.
	p.ConfidenceCeiling = "firm"
	ev, err = o.Verify(ctx, cls(), false, p)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceFirm {
		t.Fatalf("firm tavan bekleniyordu: %+v", ev)
	}
	if ev.Artifacts["ceiling"] != "firm" {
		t.Fatalf("tavan artifact taşınmalı: %+v", ev)
	}
	// tentative tavan → tentative.
	p.ConfidenceCeiling = "tentative"
	ev, err = o.Verify(ctx, cls(), false, p)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceTentative {
		t.Fatalf("tentative tavan bekleniyordu: %+v", ev)
	}
	// Bilinmeyen tavan → yok say (sözleşme korunur).
	p.ConfidenceCeiling = "bogus"
	ev, err = o.Verify(ctx, cls(), false, p)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
		t.Fatalf("bilinmeyen tavan no-op olmalı: %+v", ev)
	}
	// Kararsız girdi tavanla bile kabul edilmez.
	p = DifferentialParams{
		TrueBodies: []string{"a", "b", "a"}, FalseBodies: []string{"c", "c", "c"},
		ControlBody: `<p>neutral</p>`, Repeats: 3, ConfidenceCeiling: "firm",
	}
	ev, err = o.Verify(ctx, cls(), false, p)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict == VerdictAccept {
		t.Fatalf("kararsız differential reject olmalı: %+v", ev)
	}
}
