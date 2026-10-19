// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFixtureLabVerifiesEveryScenario is the ground-truth gate: every shipped
// scenario must independently verify against the real lab before any scoring
// run can trust it. Browser-only scenarios must stay unverified (never scored)
// when the build links no browser.
func TestFixtureLabVerifiesEveryScenario(t *testing.T) {
	lab, err := StartFixtureLab()
	if err != nil {
		t.Fatalf("lab: %v", err)
	}
	defer lab.Close()

	ds, err := LoadDataset(filepath.Join(repoRoot(t), "bench", "datasets", "fixtures.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range ds.Targets {
		ds.Targets[i].BaseURL = strings.ReplaceAll(ds.Targets[i].BaseURL, FixtureBasePlaceholder, lab.URL())
	}
	verifier := NewVerifier()
	marker := NewMarker()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for i := range ds.Scenarios {
		sc := &ds.Scenarios[i]
		t.Run(sc.ID, func(t *testing.T) {
			res := verifier.VerifyScenario(ctx, ds, sc, marker)
			needsBrowser := sc.Verify.Kind == VerifyBrowserExec
			if needsBrowser && browserVerifyUnavailable() {
				if res.Verified || res.Error == "" {
					t.Fatalf("browser scenario must be honest unverified without a browser: %+v", res)
				}
				t.Skip("no browser in this build")
			}
			if !res.Verified {
				t.Fatalf("scenario does not verify: %+v", res)
			}
		})
	}
}

func TestFixtureLabCountsObservedRequests(t *testing.T) {
	lab, err := StartFixtureLab()
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	before := lab.Total()
	verifier := NewVerifier()
	ctx := context.Background()
	resp := verifier.do(ctx, "GET", lab.URL()+"/clean/search?q=hello", "", 5*time.Second)
	if resp.err != nil {
		t.Fatal(resp.err)
	}
	if got := lab.Total(); got <= before {
		t.Fatalf("lab must count observed requests: before=%d after=%d", before, got)
	}
}
