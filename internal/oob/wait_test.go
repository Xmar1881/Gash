// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oob

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeProvider is a hermetic in-memory Provider: no network, no sleeps beyond
// the caller's window. delayedHits makes a token answer only after N polls so
// the retry loop inside the shared window is exercised deterministically.
type fakeProvider struct {
	mu          sync.Mutex
	polls       map[string]int
	delayedHits map[string]int
	events      map[string]*CallbackEvent
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{
		polls:       map[string]int{},
		delayedHits: map[string]int{},
		events:      map[string]*CallbackEvent{},
	}
}

func (f *fakeProvider) Type() ProviderType { return ProviderSelfHosted }
func (f *fakeProvider) Name() string       { return "fake" }
func (f *fakeProvider) Enabled() bool      { return true }
func (f *fakeProvider) RegisterScan(context.Context, string, string) error {
	return nil
}
func (f *fakeProvider) HTTPCallbackURL(corr string) string   { return "http://fake.test/cb/" + corr }
func (f *fakeProvider) DNSCallbackDomain(corr string) string { return corr + ".fake.test" }
func (f *fakeProvider) Close() error                         { return nil }

func (f *fakeProvider) PollCallback(_ context.Context, corr string) (*CallbackEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls[corr]++
	if n := f.delayedHits[corr]; n > 0 {
		f.delayedHits[corr] = n - 1
		return nil, nil
	}
	if ev, ok := f.events[corr]; ok {
		cp := *ev
		return &cp, nil
	}
	return nil, nil
}

func (f *fakeProvider) pollCount(corr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polls[corr]
}

func TestWaitForCallbackImmediateHit(t *testing.T) {
	p := newFakeProvider()
	p.events["c_hit"] = &CallbackEvent{CorrelationID: "c_hit", Protocol: "dns"}
	ev, ok := WaitForCallback(context.Background(), p, "c_hit", 200*time.Millisecond, 2)
	if !ok || ev == nil {
		t.Fatal("eşleşen token callback ile true dönmeli")
	}
	if ev.Protocol != "dns" {
		t.Fatalf("DNS protokolü kabul edilmeli, got %q", ev.Protocol)
	}
}

func TestWaitForCallbackMissRespectsWindow(t *testing.T) {
	p := newFakeProvider()
	start := time.Now()
	ev, ok := WaitForCallback(context.Background(), p, "c_miss", 60*time.Millisecond, 2)
	elapsed := time.Since(start)
	if ok || ev != nil {
		t.Fatal("callback yoksa false dönmeli")
	}
	if elapsed > time.Second {
		t.Fatalf("pencere sınırlı olmalı, %v sürdü", elapsed)
	}
	if p.pollCount("c_miss") < 2 {
		t.Fatalf("2 poll bekleniyordu, got %d", p.pollCount("c_miss"))
	}
}

func TestWaitForCallbackNilOrDisabledProvider(t *testing.T) {
	ev, ok := WaitForCallback(context.Background(), nil, "c1", 10*time.Millisecond, 1)
	if ok || ev != nil {
		t.Fatal("nil provider callback saymamalı")
	}
	disabled := NewSelfHostedProvider("", "")
	ev, ok = WaitForCallback(context.Background(), disabled, "c1", 10*time.Millisecond, 1)
	if ok || ev != nil {
		t.Fatal("kapalı provider callback saymamalı")
	}
}

func TestWaitForCallbacksSharedWindow(t *testing.T) {
	p := newFakeProvider()
	p.events["c_a"] = &CallbackEvent{CorrelationID: "c_a", Protocol: "http"}
	// c_b needs one retry round; c_c and c_d never fire.
	p.events["c_b"] = &CallbackEvent{CorrelationID: "c_b", Protocol: "dns"}
	p.delayedHits["c_b"] = 1
	ids := []string{"c_a", "c_b", "c_c", "c_d"}
	start := time.Now()
	matched := WaitForCallbacks(context.Background(), p, ids, 120*time.Millisecond, 2)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("tek paylaşılan pencere aşılmalı, %v sürdü", elapsed)
	}
	if len(matched) != 2 || matched[0] != "c_a" || matched[1] != "c_b" {
		t.Fatalf("tam eşleşen set bekleniyordu: %v", matched)
	}
}

func TestWaitForCallbacksNoMatch(t *testing.T) {
	p := newFakeProvider()
	if got := WaitForCallbacks(context.Background(), p, []string{"c_x", "c_y"}, 30*time.Millisecond, 2); got != nil {
		t.Fatalf("eşleşme yoksa nil dönmeli: %v", got)
	}
}

func TestWaitForCallbacksNilAndEmpty(t *testing.T) {
	if got := WaitForCallbacks(context.Background(), nil, []string{"c1"}, 10*time.Millisecond, 1); got != nil {
		t.Fatal("nil provider nil dönmeli")
	}
	p := newFakeProvider()
	if got := WaitForCallbacks(context.Background(), p, nil, 10*time.Millisecond, 1); got != nil {
		t.Fatal("boş token listesi nil dönmeli")
	}
}

func TestWaitForCallbacksCanceledContext(t *testing.T) {
	p := newFakeProvider()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if got := WaitForCallbacks(ctx, p, []string{"c1", "c2"}, time.Second, 5); got != nil {
		t.Fatalf("iptal edilen ctx nil dönmeli: %v", got)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("iptal edilen ctx beklemeden çıkmalı")
	}
}
