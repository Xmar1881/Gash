// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package smuggle

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/detector"
)

// TestCaseTableIsValidAndOrdered proves the embedded data contract.
// What: Table loads, kinds are unique, and they match the declared constants.
// Why: The probe axes are data now; a silent table change would silently change
// what the scanner sends.
func TestCaseTableIsValidAndOrdered(t *testing.T) {
	cases := Cases()
	if len(cases) != 3 {
		t.Fatalf("want 3 declared cases, got %d", len(cases))
	}
	want := []string{KindCLTE, KindTECL, KindTETE}
	for i, c := range cases {
		if c.Kind != want[i] {
			t.Fatalf("case %d kind=%q want %q", i, c.Kind, want[i])
		}
		if strings.TrimSpace(c.Name) == "" {
			t.Fatalf("case %q must explain the axis it exercises", c.Kind)
		}
	}
	if got := ProbeKinds(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ProbeKinds=%v want %v (table order)", got, want)
	}
}

// TestCaseBodiesStayHarmless proves the safety property of every case.
// What: No case body smuggles a real request.
// Why: The probe proves desynchronization; a poisoned embedded request would
// turn a detector into an attack tool.
func TestCaseBodiesStayHarmless(t *testing.T) {
	for _, c := range Cases() {
		body := strings.ToUpper(c.Body)
		for _, forbidden := range []string{"GET ", "POST ", "HOST:", "HTTP/1.1"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("case %q body carries an embedded request (%q): %q", c.Kind, forbidden, c.Body)
			}
		}
		if !strings.HasPrefix(c.Body, "0\r\n") {
			t.Fatalf("case %q body must be a chunk terminator, got %q", c.Kind, c.Body)
		}
	}
}

// TestAmbiguousFirstRendersTheDeclaredCase proves the wire format.
// What: One CL line, the declared number of TE lines, then the case body.
// Why: This is the exact byte shape the smuggling axes depend on; it must come
// from the table, in the table's order, for every kind.
func TestAmbiguousFirstRendersTheDeclaredCase(t *testing.T) {
	dt := dialTarget{host: "example.com", port: "80", scheme: "http", path: "/"}
	for _, c := range Cases() {
		got := ambiguousFirst(dt, c.Kind)
		if !strings.HasPrefix(got, "POST / HTTP/1.1\r\n") {
			t.Fatalf("case %q: request line missing in %q", c.Kind, got)
		}
		cl := fmt.Sprintf("Content-Length: %d\r\n", c.ContentLength)
		if !strings.Contains(got, cl) {
			t.Fatalf("case %q: missing %q in %q", c.Kind, cl, got)
		}
		teLines := strings.Count(got, "Transfer-Encoding: ")
		if teLines != len(c.TransferEncoding) {
			t.Fatalf("case %q: %d TE lines, want %d", c.Kind, teLines, len(c.TransferEncoding))
		}
		if strings.Index(got, "Content-Length:") > strings.Index(got, "Transfer-Encoding:") {
			t.Fatalf("case %q: Content-Length must precede Transfer-Encoding", c.Kind)
		}
		if !strings.HasSuffix(got, c.Body) {
			t.Fatalf("case %q: body %q missing at the end of %q", c.Kind, c.Body, got)
		}
	}
}

// TestAmbiguousFirstUnknownKindFallsBackToTheFirstCase proves the default.
// What: An unknown kind renders the declared default framing.
// Why: Falling back silently to "no framing" would send an unambiguous request
// and turn a measurement into a false negative.
func TestAmbiguousFirstUnknownKindFallsBackToTheFirstCase(t *testing.T) {
	dt := dialTarget{host: "example.com", port: "80", scheme: "http", path: "/"}
	def := Cases()[0].Kind
	if got, want := ambiguousFirst(dt, "NO.SUCH.AXIS"), ambiguousFirst(dt, def); got != want {
		t.Fatalf("unknown kind must render the %s framing", def)
	}
}

// TestDetectorSpecRegisters proves the port contract for this detector.
// What: Spec passes registry validation and declares its gates.
// Why: Gate and taxonomy must be readable from the registry, not from engine
// control flow.
func TestDetectorSpecRegisters(t *testing.T) {
	reg := detector.NewRegistry()
	if err := reg.Register(Detector{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	spec := Detector{}.Spec()
	if spec.ID != PluginID || spec.RuleID != RuleID || spec.CWE != CWE || spec.Oracle != OracleName {
		t.Fatalf("identity drift: %+v", spec)
	}
	if !spec.RequiresActive || !spec.RequiresAggressive || spec.Gate != "smuggle" {
		t.Fatalf("gates must stay --active + --aggressive + profile smuggle: %+v", spec)
	}
	if got := spec.Requirement(); got != "--active --aggressive" {
		t.Fatalf("requirement=%q", got)
	}
	policy := detector.Policy{
		Flags:   detector.Flags{Active: true, Aggressive: true, Profile: "aggressive"},
		Enabled: map[string]bool{"smuggle": true},
	}
	if ok, reason := spec.Evaluate(policy); !ok {
		t.Fatalf("aggressive profile must run the probe: %s", reason)
	}
	if ok, reason := spec.Evaluate(detector.Policy{Flags: detector.Flags{Profile: "standard"}}); ok ||
		reason != "skipped (smuggle-probe requires --active --aggressive)" {
		t.Fatalf("gate drift: ok=%v reason=%q", ok, reason)
	}
}

// TestDetectorRunMapsScopeViolationToSkip proves the fail-closed path.
// What: An out-of-scope target yields an audited skip and no finding.
// Why: The scope decision must cost zero sockets and must never be reported as
// a detector error.
func TestDetectorRunMapsScopeViolationToSkip(t *testing.T) {
	env := &detector.Env{
		Target: "http://127.0.0.1:1/",
		Flags:  detector.Flags{Active: true, Aggressive: true, Profile: "aggressive"},
		Scope:  func(string) bool { return false },
	}
	res, err := Detector{}.Run(context.Background(), env)
	if err != nil {
		t.Fatalf("scope violation must not be an error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("out-of-scope target must not produce findings: %+v", res.Findings)
	}
	if len(res.Skips) != 1 || res.Skips[0].PluginID != PluginID || res.Skips[0].Reason != ScopeViolationReason {
		t.Fatalf("skip trail=%+v want one %s entry", res.Skips, ScopeViolationReason)
	}
	if res.Stats["smuggle_requests"] != 0 {
		t.Fatalf("no socket may be opened: %+v", res.Stats)
	}
}

// TestDetectorRunRejectsNilEnv proves the wiring guard.
// What: A nil env is a wiring bug, not a silent no-op.
// Why: Detectors run inside the scan; a nil env means the engine forgot to
// build one, which must surface immediately.
func TestDetectorRunRejectsNilEnv(t *testing.T) {
	if _, err := (Detector{}).Run(context.Background(), nil); err == nil {
		t.Fatal("nil env must be rejected")
	}
}
