// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oob

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Verdict OOB doğrulama sonucu.
type Verdict int

const (
	// VerdictNoCallback callback yok — zafiyet yok DEĞİL, inconclusive.
	VerdictNoCallback Verdict = iota
	// VerdictTentative gecikmeli callback — zaman aşımı içinde gelmedi.
	VerdictTentative
	// VerdictConfirmed callback eşleşti — confirmed.
	VerdictConfirmed
)

// String verdict metni.
func (v Verdict) String() string {
	switch v {
	case VerdictConfirmed:
		return "confirmed"
	case VerdictTentative:
		return "tentative"
	case VerdictNoCallback:
		return "no_callback"
	default:
		return "unknown"
	}
}

// VerifyResult OOB doğrulama sonucu.
type VerifyResult struct {
	Verdict       Verdict
	CorrelationID string
	Namespace     string
	Protocol      string // "dns", "http", ""
	RemoteIP      string
	Timestamp     time.Time
	Note          string
}

// Engine OOB doğrulama motoru.
// Provider arayüzü ile çalışır; provider yoksa temel tarama devam eder.
type Engine struct {
	provider Provider
	timeout  time.Duration
	pollInt  time.Duration
	mu       sync.Mutex
	closed   bool
}

// EngineConfig motor ayarları.
type EngineConfig struct {
	Provider Provider
	Timeout  time.Duration // toplam bekleme süresi (0 = 30s)
	PollInt  time.Duration // polling aralığı (0 = 2s)
}

// DefaultEngineConfig varsayılan ayarlar.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		Timeout: 30 * time.Second,
		PollInt: 2 * time.Second,
	}
}

// NewEngine OOB doğrulama motoru kurar.
func NewEngine(cfg EngineConfig) *Engine {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.PollInt <= 0 {
		cfg.PollInt = 2 * time.Second
	}
	return &Engine{
		provider: cfg.Provider,
		timeout:  cfg.Timeout,
		pollInt:  cfg.PollInt,
	}
}

// Provider motorun sağlayıcısı.
func (e *Engine) Provider() Provider { return e.provider }

// Enabled OOB motoru aktif mi (provider var mı).
func (e *Engine) Enabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.closed && e.provider != nil && e.provider.Enabled()
}

// Verify correlation ID için callback bekler.
// Callback gelirse VerdictConfirmed, timeout'ta gelmezse VerdictTentative.
// Provider yoksa VerdictNoCallback (inconclusive).
func (e *Engine) Verify(ctx context.Context, corrID, namespace string) *VerifyResult {
	if corrID == "" {
		return &VerifyResult{Verdict: VerdictNoCallback, Note: "correlation id yok"}
	}
	if !e.Enabled() {
		return &VerifyResult{
			Verdict:       VerdictNoCallback,
			CorrelationID: corrID,
			Namespace:     namespace,
			Note:          "oob provider yok — inconclusive",
		}
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	deadline := time.Now().Add(e.timeout)
	for {
		select {
		case <-ctx.Done():
			return &VerifyResult{
				Verdict:       VerdictTentative,
				CorrelationID: corrID,
				Namespace:     namespace,
				Timestamp:     time.Now(),
				Note:          fmt.Sprintf("timeout %s — gecikmeli callback olabilir", e.timeout),
			}
		default:
		}

		if time.Now().After(deadline) {
			return &VerifyResult{
				Verdict:       VerdictTentative,
				CorrelationID: corrID,
				Namespace:     namespace,
				Timestamp:     time.Now(),
				Note:          "timeout — inconclusive",
			}
		}

		event, err := e.provider.PollCallback(ctx, corrID)
		if err == nil && event != nil {
			return &VerifyResult{
				Verdict:       VerdictConfirmed,
				CorrelationID: corrID,
				Namespace:     namespace,
				Protocol:      event.Protocol,
				RemoteIP:      event.RemoteIP,
				Timestamp:     event.Timestamp,
				Note:          "callback eşleşti",
			}
		}

		select {
		case <-ctx.Done():
			return &VerifyResult{
				Verdict:       VerdictTentative,
				CorrelationID: corrID,
				Namespace:     namespace,
				Timestamp:     time.Now(),
				Note:          "timeout — inconclusive",
			}
		case <-time.After(e.pollInt):
		}
	}
}

// Close motoru kapatır.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	if e.provider != nil {
		return e.provider.Close()
	}
	return nil
}

// HTTPCallbackURL correlation ID için HTTP callback URL üretir.
// Provider yoksa boş string.
func (e *Engine) HTTPCallbackURL(corrID string) string {
	if !e.Enabled() {
		return ""
	}
	return e.provider.HTTPCallbackURL(corrID)
}

// DNSCallbackDomain correlation ID için DNS callback domain üretir.
// Provider yoksa boş string.
func (e *Engine) DNSCallbackDomain(corrID string) string {
	if !e.Enabled() {
		return ""
	}
	return e.provider.DNSCallbackDomain(corrID)
}
