// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/headless"
	"github.com/Xmar1881/Gash/internal/plugin"
)

func staticXSSFinding() *finding.Finding {
	return &finding.Finding{
		RuleID:     "GASH-001",
		Confidence: plugin.ConfidenceStaticExecution,
		Target:     "http://example.com/page?q=1",
		InjectionPoint: plugin.InjectionPoint{
			URL:           "http://example.com/page",
			Method:        "GET",
			ParamName:     "q",
			ParamLocation: "query",
			Value:         `"><img src=x onerror=alert(1)>`,
		},
		Evidence:           map[string]string{"context": "attr-executable"},
		Reproducibility:    map[string]string{"repeats": "1", "control": "clean", "note": "statik kanıt"},
		Note:               "executable context kanıtı",
		VerificationMethod: "reflection, executable-context",
	}
}

// TestBrowserVerifyUpgradesOnTriggerAndCleanControl: gerçek tetikleme + temiz
// kontrol → confirmed; kanıt notu ve fingerprint güncellenir.
func TestBrowserVerifyUpgradesOnTriggerAndCleanControl(t *testing.T) {
	var gotPayload, gotControl string
	e := &Engine{cfg: Config{
		BrowserVerify: true,
		BrowserVerifyFunc: func(ctx context.Context, payloadURL, controlURL string) (bool, bool, error) {
			gotPayload, gotControl = payloadURL, controlURL
			return true, true, nil
		},
	}}
	f := staticXSSFinding()
	skipped := e.verifyBrowserFindings(context.Background(), []*finding.Finding{f})
	if len(skipped) != 0 {
		t.Fatalf("skip beklenmiyordu: %+v", skipped)
	}
	if f.Confidence != plugin.ConfidenceConfirmed {
		t.Fatalf("confirmed bekleniyordu: %s", f.Confidence)
	}
	if f.Evidence["execution"] != "browser-confirmed" {
		t.Fatalf("execution kanıtı yazılmalı: %+v", f.Evidence)
	}
	if !strings.Contains(f.Note, "browser-confirmed") {
		t.Fatalf("not gerekçeyi taşımalı: %q", f.Note)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint yeniden hesaplanmalı")
	}
	// Payload ve kontrol URL'leri gerçek enjeksiyon değerini taşımalı.
	if !strings.Contains(gotPayload, "example.com/page") {
		t.Fatalf("payload URL hedefi taşımalı: %q", gotPayload)
	}
	if !strings.Contains(gotControl, "gash-control-neutral") {
		t.Fatalf("kontrol URL nötr değeri taşımalı: %q", gotControl)
	}
	if gotPayload == gotControl {
		t.Fatal("payload ve kontrol URL farklı olmalı")
	}
}

// TestBrowserVerifyControlDirtyKeepsStaticTier: tetikleme var ama kontrol de
// tetikliyorsa seviye YÜKSELMEZ (kanıt sahteleme yok).
func TestBrowserVerifyControlDirtyKeepsStaticTier(t *testing.T) {
	e := &Engine{cfg: Config{
		BrowserVerify: true,
		BrowserVerifyFunc: func(context.Context, string, string) (bool, bool, error) {
			return true, false, nil
		},
	}}
	f := staticXSSFinding()
	_ = e.verifyBrowserFindings(context.Background(), []*finding.Finding{f})
	if f.Confidence != plugin.ConfidenceStaticExecution {
		t.Fatalf("statik seviye korunmalı: %s", f.Confidence)
	}
	if f.Evidence["browser_verify"] != "control-dirty" {
		t.Fatalf("control-dirty notu bekleniyordu: %+v", f.Evidence)
	}
	if f.Evidence["execution"] != "" {
		t.Fatal("browser-confirmed yazılmamalı")
	}
}

// TestBrowserVerifyNotTriggeredKeepsStaticTier: tetiklenmeyen statik bulgu
// ne yükselir ne düşer.
func TestBrowserVerifyNotTriggeredKeepsStaticTier(t *testing.T) {
	e := &Engine{cfg: Config{
		BrowserVerify: true,
		BrowserVerifyFunc: func(context.Context, string, string) (bool, bool, error) {
			return false, true, nil
		},
	}}
	f := staticXSSFinding()
	_ = e.verifyBrowserFindings(context.Background(), []*finding.Finding{f})
	if f.Confidence != plugin.ConfidenceStaticExecution {
		t.Fatalf("statik seviye korunmalı: %s", f.Confidence)
	}
	if f.Evidence["browser_verify"] != "not-triggered" {
		t.Fatalf("not-triggered notu bekleniyordu: %+v", f.Evidence)
	}
}

// TestBrowserVerifyVerifierErrorReportedOnce: doğrulayıcı hatası tek skip
// kaydıyla raporlanır; bulgu seviyesi değişmez.
func TestBrowserVerifyVerifierErrorReportedOnce(t *testing.T) {
	e := &Engine{cfg: Config{
		BrowserVerify: true,
		BrowserVerifyFunc: func(context.Context, string, string) (bool, bool, error) {
			return false, false, errors.New("chrome çöktü")
		},
	}}
	f1, f2 := staticXSSFinding(), staticXSSFinding()
	skipped := e.verifyBrowserFindings(context.Background(), []*finding.Finding{f1, f2})
	if len(skipped) != 1 {
		t.Fatalf("tek skip kaydı bekleniyordu: %+v", skipped)
	}
	if !strings.Contains(skipped[0].Reason, "error:") {
		t.Fatalf("hata gerekçesi taşınmalı: %+v", skipped[0])
	}
	if f1.Confidence != plugin.ConfidenceStaticExecution || f2.Confidence != plugin.ConfidenceStaticExecution {
		t.Fatal("hata halinde seviye değişmemeli")
	}
}

// TestBrowserVerifyIneligibleFindingsUntouched: kapsam dışı bulgular (rule,
// metot, konum, boş değer) doğrulayıcıya hiç gitmez.
func TestBrowserVerifyIneligibleFindingsUntouched(t *testing.T) {
	calls := 0
	e := &Engine{cfg: Config{
		BrowserVerify: true,
		BrowserVerifyFunc: func(context.Context, string, string) (bool, bool, error) {
			calls++
			return true, true, nil
		},
	}}
	base := staticXSSFinding()
	variants := []*finding.Finding{
		func() *finding.Finding { f := staticXSSFinding(); f.RuleID = "GASH-999"; return f }(),
		func() *finding.Finding { f := staticXSSFinding(); f.Confidence = plugin.ConfidenceFirm; return f }(),
		func() *finding.Finding {
			f := staticXSSFinding()
			f.InjectionPoint.ParamLocation = "body"
			return f
		}(),
		func() *finding.Finding {
			f := staticXSSFinding()
			f.InjectionPoint.Method = "POST"
			return f
		}(),
		func() *finding.Finding { f := staticXSSFinding(); f.InjectionPoint.Value = ""; return f }(),
		func() *finding.Finding { f := base; f.InjectionPoint.ParamName = ""; return f }(),
	}
	_ = e.verifyBrowserFindings(context.Background(), variants)
	if calls != 0 {
		t.Fatalf("kapsam dışı bulgu doğrulanmamalı, %d çağrı", calls)
	}
}

// TestBrowserVerifyDisabledNoCalls: bayrak kapalıyken doğrulayıcı çağrılmaz.
func TestBrowserVerifyDisabledNoCalls(t *testing.T) {
	calls := 0
	e := &Engine{cfg: Config{
		BrowserVerify: false,
		BrowserVerifyFunc: func(context.Context, string, string) (bool, bool, error) {
			calls++
			return true, true, nil
		},
	}}
	if skipped := e.verifyBrowserFindings(context.Background(), []*finding.Finding{staticXSSFinding()}); skipped != nil {
		t.Fatalf("kapalıyken skip de dönmemeli: %+v", skipped)
	}
	if calls != 0 {
		t.Fatal("kapalıyken doğrulayıcı çağrılmamalı")
	}
}

// TestBrowserVerifyStubBuildSkipsHonestly: default build'de (stub) skip kaydı
// dürüst gerekçeyle döner; bulgu asla confirmed olmaz (kanıt sahteleme yok).
func TestBrowserVerifyStubBuildSkipsHonestly(t *testing.T) {
	if headless.Supported() {
		t.Skip("-tags deep build'de stub testi anlamsız")
	}
	e := &Engine{cfg: Config{BrowserVerify: true}}
	f := staticXSSFinding()
	skipped := e.verifyBrowserFindings(context.Background(), []*finding.Finding{f})
	if len(skipped) != 1 {
		t.Fatalf("tek skip kaydı bekleniyordu: %+v", skipped)
	}
	if !strings.Contains(skipped[0].Reason, "tags deep") {
		t.Fatalf("gerekçe deep build gerektirmeli: %q", skipped[0].Reason)
	}
	if f.Confidence != plugin.ConfidenceStaticExecution {
		t.Fatal("stub build'de seviye değişmemeli")
	}
}
