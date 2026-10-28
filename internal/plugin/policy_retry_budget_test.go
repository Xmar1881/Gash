// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package plugin

import (
	"net/http"
	"testing"
	"time"
)

func TestRetryBudgetStopsAmplification(t *testing.T) {
	ps := NewPolicySession(DefaultPolicyConfig(), nil)
	for i := 0; i < 32; i++ {
		if !ps.allowRetry() {
			t.Fatalf("initial retry %d must be allowed", i)
		}
	}
	if ps.allowRetry() {
		t.Fatal("retry budget must stop after the initial allowance")
	}
	if ps.RetryBudgetExhausted() == 0 {
		t.Fatal("suppressed retry must be counted")
	}
	ps.responses.Add(500)
	if !ps.allowRetry() {
		t.Fatal("retry budget must grow with observed responses")
	}
}

func TestRetryAfterParsing(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "3")
	if d, ok := retryAfterDelay(h, time.Now()); !ok || d != 3*time.Second {
		t.Fatalf("seconds Retry-After = %v/%v", d, ok)
	}
	when := time.Now().Add(4 * time.Second).UTC().Truncate(time.Second)
	h.Set("Retry-After", when.Format(http.TimeFormat))
	if d, ok := retryAfterDelay(h, time.Now()); !ok || d < 2*time.Second || d > 5*time.Second {
		t.Fatalf("date Retry-After = %v/%v", d, ok)
	}
	h.Set("Retry-After", "bogus")
	if _, ok := retryAfterDelay(h, time.Now()); ok {
		t.Fatal("invalid Retry-After must be ignored")
	}
}

func TestIdempotentMethod(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "PUT", "DELETE"} {
		if !isIdempotentMethod(method) {
			t.Fatalf("%s must be idempotent", method)
		}
	}
	for _, method := range []string{"POST", "PATCH"} {
		if isIdempotentMethod(method) {
			t.Fatalf("%s must not be retried on ambiguous server errors", method)
		}
	}
}
