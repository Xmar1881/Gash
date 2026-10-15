// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package loader

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

func timeoutSpec() *plugin.PluginSpec {
	return &plugin.PluginSpec{
		ID: "js-timeout-probe", Name: "JS timeout probe", Description: "Tier2 zaman asimi abort davranisini dogrulayan test eklentisi.",
		Severity: plugin.SeverityLow, Tags: []string{"test"}, Safe: true,
		Phase: plugin.PhaseProbe, Order: 50, APIVersion: "1.0",
	}
}

func timeoutEnv() *JSEnv {
	return &JSEnv{
		Points: []JSPoint{{URL: "http://127.0.0.1/", Method: "GET", ParamName: "q", ParamLocation: "query"}},
		Send: func(p JSPoint) (JSResponse, error) {
			return JSResponse{Status: 200, Body: "<p>ok</p>", URL: p.URL}, nil
		},
	}
}

// TestExecuteJSInfiniteLoopAborts proves the P1.1 resource bound: a
// never-ending script is interrupted on timeout and the runner survives.
func TestExecuteJSInfiniteLoopAborts(t *testing.T) {
	src := `function run(probe, ctx) { while (true) {} return []; }`
	start := time.Now()
	_, err := ExecuteJS(context.Background(), timeoutSpec(), src, timeoutEnv(), 500*time.Millisecond)
	elapsed := time.Since(start)
	if !errors.Is(err, plugin.ErrTimeout) {
		t.Fatalf("zaman asan JS ErrTimeout donmeli, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("abort cok uzun surdu: %v", elapsed)
	}
	// Tarama cokmez: ayni runner hemen sonra normal script calistirabilir.
	okSrc := `function run(probe, ctx) { return []; }`
	got, err := ExecuteJS(context.Background(), timeoutSpec(), okSrc, timeoutEnv(), 2*time.Second)
	if err != nil {
		t.Fatalf("abort sonrasi runner saglikli olmali: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("bos script aday uretmemeli: %+v", got)
	}
}

// TestExecuteJSTopLevelInfiniteLoopAborts proves the load-phase bound: a
// top-level `while(true)` (outside run()) is interrupted on timeout and the
// runner survives. Same DefaultJSPluginBudget discipline as run().
func TestExecuteJSTopLevelInfiniteLoopAborts(t *testing.T) {
	src := `while (true) {} function run(probe, ctx) { return []; }`
	start := time.Now()
	_, err := ExecuteJS(context.Background(), timeoutSpec(), src, timeoutEnv(), 500*time.Millisecond)
	elapsed := time.Since(start)
	if !errors.Is(err, plugin.ErrTimeout) {
		t.Fatalf("top-level sonsuz dongu ErrTimeout donmeli, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("top-level abort cok uzun surdu: %v", elapsed)
	}
	// Runner sağlıklı: aynı süreç hemen sonra normal script çalıştırabilir.
	okSrc := `function run(probe, ctx) { return []; }`
	got, err := ExecuteJS(context.Background(), timeoutSpec(), okSrc, timeoutEnv(), 2*time.Second)
	if err != nil {
		t.Fatalf("top-level abort sonrasi runner saglikli olmali: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("bos script aday uretmemeli: %+v", got)
	}
}

// TestEnsureLoadedTopLevelInfiniteLoopAborts proves JSPlugin.EnsureLoaded
// applies the same timeout+Interrupt discipline to the load-phase RunString.
func TestEnsureLoadedTopLevelInfiniteLoopAborts(t *testing.T) {
	spec, err := ParseTier2Frontmatter("p.js", []byte(tier2Good))
	if err != nil {
		t.Fatal(err)
	}
	j := NewJSPlugin(*spec, "p.js", `while (true) {} function run(probe, ctx) { return []; }`)
	start := time.Now()
	err = j.EnsureLoadedWithTimeout(500 * time.Millisecond)
	elapsed := time.Since(start)
	if !errors.Is(err, plugin.ErrTimeout) {
		t.Fatalf("EnsureLoaded top-level dongu ErrTimeout donmeli, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("EnsureLoaded abort cok uzun surdu: %v", elapsed)
	}
	// Zehirli VM saklanmamalı: aynı spec ile temiz yükleme yapılabilmeli.
	j2 := NewJSPlugin(*spec, "p.js", `function run(probe, ctx) { return []; }`)
	if err := j2.EnsureLoadedWithTimeout(2 * time.Second); err != nil {
		t.Fatalf("abort sonrasi temiz yukleme saglikli olmali: %v", err)
	}
	if err := j2.RunTimeout(t.Context(), 2*time.Second); err != nil {
		t.Fatalf("temiz plugin run saglikli olmali: %v", err)
	}
}
