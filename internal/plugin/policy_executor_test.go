// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type okRT struct{ code int }

func (o okRT) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: o.code, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
}

func TestPolicySafeBlocksPOST(t *testing.T) {
	p := NewPolicySession(PolicyConfig{}, okRT{code: 200})
	req, _ := http.NewRequestWithContext(WithPlugin(context.Background(), "p1", true, nil), http.MethodPost, "http://example.com/", nil)
	if _, err := p.RoundTrip(req); !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("safe POST engellenmeli, got %v", err)
	}
}

func TestPolicySafeAllowsGET(t *testing.T) {
	p := NewPolicySession(PolicyConfig{}, okRT{code: 200})
	req, _ := http.NewRequestWithContext(WithPlugin(context.Background(), "p1", true, nil), http.MethodGet, "http://example.com/", nil)
	resp, err := p.RoundTrip(req)
	if err != nil {
		t.Fatalf("safe GET geçmeli: %v", err)
	}
	_ = resp.Body.Close()
}

func TestPolicyBudget(t *testing.T) {
	p := NewPolicySession(PolicyConfig{MaxRequestsTotal: 1}, okRT{code: 200})
	ctx := WithPlugin(context.Background(), "p1", false, nil)
	req1, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req1 = req1.WithContext(ctx)
	if _, err := p.RoundTrip(req1); err != nil {
		t.Fatalf("ilk istek: %v", err)
	}
	req2, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req2 = req2.WithContext(ctx)
	if _, err := p.RoundTrip(req2); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("bütçe aşımı bekleniyordu, got %v", err)
	}
}

func TestPolicyScope(t *testing.T) {
	p := NewPolicySession(PolicyConfig{Scope: []string{"example.com"}}, okRT{code: 200})
	ctx := WithPlugin(context.Background(), "p1", false, nil)
	bad, _ := http.NewRequest(http.MethodGet, "http://evil.com/", nil)
	bad = bad.WithContext(ctx)
	if _, err := p.RoundTrip(bad); !errors.Is(err, ErrScopeViolation) {
		t.Fatalf("scope dışı engellenmeli, got %v", err)
	}
	good, _ := http.NewRequest(http.MethodGet, "http://example.com/x", nil)
	good = good.WithContext(ctx)
	if _, err := p.RoundTrip(good); err != nil {
		t.Fatalf("scope içi geçmeli: %v", err)
	}
}

func TestExecutePanic(t *testing.T) {
	res := Execute(context.Background(), "bad", func(ctx context.Context) ([]Candidate, error) {
		panic("boom")
	})
	if res.Status != StatusPanic {
		t.Fatalf("panic statüsü bekleniyordu, got %s", res.Status)
	}
}

func TestExecuteTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	res := Execute(ctx, "slow", func(ctx context.Context) ([]Candidate, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, nil
		}
	})
	if res.Status != StatusTimeout {
		t.Fatalf("timeout bekleniyordu, got %s (%s)", res.Status, res.Reason)
	}
}

func TestExecutePolicyError(t *testing.T) {
	res := Execute(context.Background(), "p", func(ctx context.Context) ([]Candidate, error) {
		return nil, &PolicyError{PluginID: "p", Op: "method", Err: ErrPolicyViolation}
	})
	if res.Status != StatusPolicyError {
		t.Fatalf("policy_error bekleniyordu, got %s", res.Status)
	}
}
