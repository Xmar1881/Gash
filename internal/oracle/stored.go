// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
)

// StoredParams models a stored-XSS write/render workflow as TWO separate
// HTTP exchanges (GASH-002). Request 1 is the write (POST store with a canary
// payload); request 2 is the render page GET whose body is checked with the
// reflection discipline. A clean control render is required to distinguish a
// persisted reflection from a pre-existing page payload.
//
// Evidence ladder is preserved: tentative / static-execution-evidence /
// confirmed. No new level is invented. Confirmed requires a supplied
// controlled headless result (BrowserVerified+Triggered+ControlClean);
// otherwise the ceiling is static-execution-evidence.
type StoredParams struct {
	Canary                   string
	Contexts                 []string
	RequireExecutableContext bool
	StoreStatus              int
	StoreBody                string
	RenderBody               string
	RenderHeaders            http.Header
	ControlBody              string
	BrowserVerified          bool
	BrowserTriggered         bool
	BrowserControlClean      bool
}

// StoredOracle verifies persisted reflections across store+render.
type StoredOracle struct{}

func (StoredOracle) Name() string { return "stored" }

// Verify enforces the two-exchange workflow before delegating the render
// body to the reflection oracle. The store exchange proves the write was
// accepted; it is never itself XSS proof (a store echo is reflected, not
// stored). The render exchange carries the reflection claim with a clean
// control comparison. Missing canary in render rejects.
func (StoredOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p StoredParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	if strings.TrimSpace(p.Canary) == "" {
		return &Evidence{Verdict: VerdictReject, Note: "empty canary"}, nil
	}
	// Exchange 1: write must have been attempted and accepted. A missing
	// exchange (status 0 with no body) means the workflow was not modeled;
	// a 4xx/5xx store means the payload was not persisted.
	if p.StoreStatus == 0 && strings.TrimSpace(p.StoreBody) == "" {
		return &Evidence{Verdict: VerdictReject, Note: "store exchange missing"}, nil
	}
	if p.StoreStatus >= 400 {
		return &Evidence{
			Verdict: VerdictReject,
			Artifacts: map[string]string{
				"workflow":     "store+render",
				"canary":       p.Canary,
				"store_status": strconv.Itoa(p.StoreStatus),
			},
			Note: "store rejected the payload",
		}, nil
	}
	contexts := p.Contexts
	if len(contexts) == 0 {
		contexts = []string{"html", "attr-executable", "script", "url", "url-executable"}
	}
	// Exchange 2: render must contain the canary; absence means filtered.
	if !strings.Contains(p.RenderBody, p.Canary) {
		if likelyEncoded(p.RenderBody, p.Canary) {
			ev, err := ReflectionOracle{}.Verify(ctx, p.RenderBody, p.RenderHeaders, cls, tainted, ReflectionParams{
				Canary: p.Canary, Contexts: contexts,
				RequireExecutableContext: requireStoredExecutable(p),
				ControlBody:              p.ControlBody,
				BrowserVerified:          p.BrowserVerified,
				BrowserTriggered:         p.BrowserTriggered,
				BrowserControlClean:      p.BrowserControlClean,
			})
			if err != nil {
				return nil, err
			}
			stampStored(ev, p)
			return ev, nil
		}
		return &Evidence{
			Verdict: VerdictReject,
			Artifacts: map[string]string{
				"workflow": "store+render",
				"canary":   p.Canary,
			},
			Note: "no reflection in render",
		}, nil
	}
	ev, err := ReflectionOracle{}.Verify(ctx, p.RenderBody, p.RenderHeaders, cls, tainted, ReflectionParams{
		Canary: p.Canary, Contexts: contexts,
		RequireExecutableContext: requireStoredExecutable(p),
		ControlBody:              p.ControlBody,
		BrowserVerified:          p.BrowserVerified,
		BrowserTriggered:         p.BrowserTriggered,
		BrowserControlClean:      p.BrowserControlClean,
	})
	if err != nil {
		return nil, err
	}
	stampStored(ev, p)
	return ev, nil
}

func requireStoredExecutable(p StoredParams) bool {
	// Stored XSS without an executable render context is at most tentative.
	// Default to true when the caller leaves contexts empty (zero value
	// would otherwise weaken the gate); explicit contexts may opt out via
	// RequireExecutableContext:false for tentative-only checks.
	if len(p.Contexts) == 0 {
		return true
	}
	return p.RequireExecutableContext
}

func stampStored(ev *Evidence, p StoredParams) {
	if ev == nil {
		return
	}
	if ev.Artifacts == nil {
		ev.Artifacts = map[string]string{}
	}
	if _, ok := ev.Artifacts["workflow"]; !ok {
		ev.Artifacts["workflow"] = "store+render"
	}
	if p.StoreStatus != 0 {
		if _, ok := ev.Artifacts["store_status"]; !ok {
			ev.Artifacts["store_status"] = strconv.Itoa(p.StoreStatus)
		}
	}
	if strings.HasPrefix(ev.Note, "stored ") {
		return
	}
	switch ev.Verdict {
	case VerdictAccept:
		ev.Note = "stored write+render: " + ev.Note
	case VerdictReject:
		// Keep the reflection reason but mark the workflow for audit.
		if ev.Note != "" && !strings.Contains(ev.Note, "store+render") {
			ev.Note = "stored write+render: " + ev.Note
		}
	}
}
