// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oob

import (
	"context"
	"time"
)

// Bounded callback window defaults. The window is intentionally short and the
// poll count small: every candidate payload owns a unique single-use
// correlation token, so a slow delivery only delays the finding, it never
// merges tokens across candidates. Documented in docs/known-limits.md.
const (
	// DefaultWaitWindow is the total wait for one correlation token.
	DefaultWaitWindow = 10 * time.Second
	// DefaultWaitPolls is how many provider polls happen inside the window.
	DefaultWaitPolls = 2
)

// WaitForCallbacks polls a provider for a set of correlation IDs inside ONE
// bounded window and returns every ID that matched (order preserved, deduped).
// What: rounds = polls; each round polls every ID once (any protocol: DNS-only
// exfil confirms exactly like HTTP because the token is unique per payload).
// Why: Multi-payload detectors must not multiply the wait window per payload:
// all tokens share the single bounded window so plugin time budgets hold.
func WaitForCallbacks(ctx context.Context, p Provider, corrIDs []string, window time.Duration, polls int) []string {
	if p == nil || !p.Enabled() || len(corrIDs) == 0 {
		return nil
	}
	if window <= 0 {
		window = DefaultWaitWindow
	}
	if polls <= 0 {
		polls = DefaultWaitPolls
	}
	deadline := time.Now().Add(window)
	interval := window / time.Duration(polls)
	if interval <= 0 {
		interval = window
	}
	matched := make(map[string]bool)
	var out []string
	for i := 0; i < polls; i++ {
		if err := ctx.Err(); err != nil {
			return out
		}
		for _, id := range corrIDs {
			if id == "" || matched[id] {
				continue
			}
			ev, err := p.PollCallback(ctx, id)
			if err == nil && ev != nil {
				matched[id] = true
				out = append(out, id)
			}
		}
		if i == polls-1 {
			break
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		wait := interval
		if wait > remaining {
			wait = remaining
		}
		select {
		case <-ctx.Done():
			return out
		case <-time.After(wait):
		}
	}
	return out
}

// WaitForCallback polls a provider for one correlation ID inside a bounded
// window (window split into polls, first poll immediate). It returns the first
// matching event and true, or nil and false when the window expires. Any
// protocol (dns or http) is accepted: a DNS-only exfil path confirms the same
// way an HTTP callback does because the correlation token is unique per
// payload and the provider matches it exactly.
//
// A nil provider disables the wait and returns false immediately; callers must
// treat that as "no callback" and reject, never as a finding.
func WaitForCallback(ctx context.Context, p Provider, corrID string, window time.Duration, polls int) (*CallbackEvent, bool) {
	if p == nil || !p.Enabled() || corrID == "" {
		return nil, false
	}
	if window <= 0 {
		window = DefaultWaitWindow
	}
	if polls <= 0 {
		polls = DefaultWaitPolls
	}
	deadline := time.Now().Add(window)
	interval := window / time.Duration(polls)
	if interval <= 0 {
		interval = window
	}
	for i := 0; i < polls; i++ {
		if err := ctx.Err(); err != nil {
			return nil, false
		}
		ev, err := p.PollCallback(ctx, corrID)
		if err == nil && ev != nil {
			return ev, true
		}
		if i == polls-1 {
			break
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		wait := interval
		if wait > remaining {
			wait = remaining
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(wait):
		}
	}
	return nil, false
}
