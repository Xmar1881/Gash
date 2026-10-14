// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package probe HTTP client wrapper + canary üretimi + response store'dur.
// Tüm gönderimler PolicySession (http.RoundTripper) üzerinden geçer (B6).
// P1.1: Centralized retry/backoff, redirect+scope re-validation, error classification.
package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/wafbypass"
)

// Response ham body'yi store'da tutar; Candidate yalnızca id referansı taşır (bellek disiplini).
type Response struct {
	ID        string
	URL       string
	Method    string
	Status    int
	Headers   http.Header
	Body      []byte
	RTT       time.Duration
	Untrusted bool
	Soft404   bool
	// WAFDetected baseline WAF/blok işareti (403/429/işaret).
	// Taramayı durdurmaz; rapor istatistiğine işlenir.
	WAFDetected bool
	// WAFBypassed agresif-mod varyant denemesi engeli aştıysa true.
	WAFBypassed  bool
	ClassifyNote string
	TaintedBy    string
	ErrorClass   plugin.ErrorClass // P1.1: classified error for deterministic logging
	RetryCount   int               // P1.1: number of retries attempted
}

// Store thread-safe response deposudur.
type Store struct {
	mu      sync.RWMutex
	items   map[string]*Response
	counter atomic.Int64
}

// NewStore boş store döner.
func NewStore() *Store { return &Store{items: make(map[string]*Response)} }

// Put yanıtı kaydeder, id döner.
func (s *Store) Put(r *Response) string {
	id := fmt.Sprintf("resp_%d", s.counter.Add(1))
	s.mu.Lock()
	defer s.mu.Unlock()
	r.ID = id
	s.items[id] = r
	return id
}

// Get id ile getirir.
func (s *Store) Get(id string) (*Response, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.items[id]
	return r, ok
}

// Client politika-filtreli HTTP istemcisidir.
type Client struct {
	policy     *plugin.PolicySession
	store      *Store
	maxBytes   int64
	extra      map[string]string
	classifier func(status int, headers http.Header, body []byte) baseline.Classification
	// enableWAFBypass blok yanıtında sınırlı varyant denemesine izin verir.
	// Yalnızca agresif profil açar (varsayılan kapalı — stealth YOK).
	enableWAFBypass bool
	wafDetected     atomic.Int64
	wafBypassed     atomic.Int64
}

// Options istemci ayarlarıdır.
type Options struct {
	Policy         *plugin.PolicySession
	RequestTimeout time.Duration
	MaxBytes       int64
	// ExtraHeaders her isteğe uygulanan bağlam başlıklarıdır (P2.5 auth).
	// What: Tarama-ölçekli kimlik bilgisi (Authorization/Cookie); istekteki
	// açık değer korunur, bağlam ezmez. Değerler asla loglanmaz.
	ExtraHeaders map[string]string
	// EnableWAFBypass blok (403/429/WAF) yanıtında en fazla 5 varyant
	// (header/HPP/encode/comment/case) denemesine izin verir. Yalnızca
	// --aggressive profili açar; tüm denemeler politika/kapsam içindedir.
	EnableWAFBypass bool
}

// NewClient politika + baseline sınıflandırmalı istemci kurar.
// P1.1: Retry/redirect/backpressure handled by PolicySession.RoundTripWithRetry.
func NewClient(opts Options) *Client {
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 15 * time.Second
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 5 * 1024 * 1024
	}
	c := &Client{
		policy:   opts.Policy,
		store:    NewStore(),
		maxBytes: opts.MaxBytes,
		extra:    cloneMap(opts.ExtraHeaders),
		classifier: func(status int, headers http.Header, body []byte) baseline.Classification {
			return baseline.ClassifyStatic(status, headers, body)
		},
		enableWAFBypass: opts.EnableWAFBypass,
	}
	return c
}

// extraHeaders bağlam başlıklarının kopyasını döner (çağıran değiştiremez).
func (c *Client) extraHeaders() map[string]string {
	return cloneMap(c.extra)
}

func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Canary benzersiz kanıt değeri üretir (gash_hex8, kriptografik rastgele).
func Canary() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("canary rand: %w", err)
	}
	return "gash_" + hex.EncodeToString(b[:]), nil
}

// MustCanary test kolaylığıdır.
func MustCanary() string {
	c, err := Canary()
	if err != nil {
		panic(err)
	}
	return c
}

// Send politika + baseline sınıflandırmalı GET/POST gönderir.
// ctx pluginCtx (WithPlugin) taşımalıdır; taşımazsa safe=false sayılır.
// P1.1: Uses PolicySession.RoundTripWithRetry for retry/redirect/scope/backpressure.
// Agresif modda (EnableWAFBypass) blok yanıtı WAFDetected işaretlenir ve
// sınırlı bypass varyantı aynı politika/kapsam içinden denenir.
func (c *Client) Send(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (*Response, error) {
	r, err := c.doSingle(ctx, method, rawURL, headers, body)
	if err != nil {
		return nil, err
	}
	if r.WAFDetected {
		c.wafDetected.Add(1)
	}
	if !c.enableWAFBypass || !wafbypass.ShouldAttemptBypass(r.Status, r.Headers, r.Body) {
		return r, nil
	}
	for _, att := range wafbypass.BuildAttempts(rawURL, headers, body) {
		if ctx.Err() != nil {
			break
		}
		r2, err := c.doSingle(ctx, method, att.URL, att.Headers, att.Body)
		if err != nil {
			continue
		}
		if wafbypass.IsBlocked(r2.Status, r2.Headers, r2.Body) {
			continue
		}
		// A non-block response is only a candidate. Replay the exact variant
		// once and require stable application behavior before counting it.
		check, err := c.doSingle(ctx, method, att.URL, att.Headers, att.Body)
		if err != nil || !wafbypass.VerifyApplicationBehavior(
			r2.Status, r2.Headers, r2.Body,
			check.Status, check.Headers, check.Body,
		) {
			continue
		}
		r2.WAFDetected = r.WAFDetected || r2.WAFDetected
		r2.WAFBypassed = true
		r2.ClassifyNote += " + waf-bypass-verified:" + att.Name
		c.wafBypassed.Add(1)
		return r2, nil
	}
	return r, nil
}

// WAFStats tarama boyunca görülen WAF işareti ve başarılı bypass sayısını
// döner (Report.Stats girdisi; bulgu DEĞİLDIR).
func (c *Client) WAFStats() (detected, bypassed int64) {
	return c.wafDetected.Load(), c.wafBypassed.Load()
}

func (c *Client) doSingle(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, readerOf(body))
	if err != nil {
		return nil, fmt.Errorf("probe new request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// P2.5: bağlam başlıkları (auth) — açık istek değeri kazanır.
	for k, v := range c.extraHeaders() {
		if strings.TrimSpace(req.Header.Get(k)) == "" {
			req.Header.Set(k, v)
		}
	}

	start := time.Now()
	var resp *http.Response
	var errResp error
	retryCount := 0

	if c.policy != nil {
		// Use PolicySession's centralized RoundTripWithRetry
		resp, errResp = c.policy.RoundTripWithRetry(req)
		if errResp != nil {
			// Classify error for deterministic logging
			errClass := plugin.ClassifyError(errResp)
			r := &Response{
				URL:          rawURL,
				Method:       method,
				Untrusted:    false,
				Soft404:      false,
				ClassifyNote: fmt.Sprintf("error: %v", errResp),
				ErrorClass:   errClass,
				RetryCount:   retryCount,
			}
			c.store.Put(r)
			return nil, fmt.Errorf("probe do %s %s: %w", method, rawURL, errResp)
		}
	} else {
		// Fallback: direct transport without policy (tests only)
		tr := http.DefaultTransport
		resp, errResp = tr.RoundTrip(req)
		if errResp != nil {
			errClass := plugin.ClassifyError(errResp)
			r := &Response{
				URL:          rawURL,
				Method:       method,
				Untrusted:    false,
				Soft404:      false,
				ClassifyNote: fmt.Sprintf("error: %v", errResp),
				ErrorClass:   errClass,
				RetryCount:   retryCount,
			}
			c.store.Put(r)
			return nil, fmt.Errorf("probe do %s %s: %w", method, rawURL, errResp)
		}
	}

	defer resp.Body.Close()
	rtt := time.Since(start)
	limited := io.LimitReader(resp.Body, c.maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("probe read body: %w", err)
	}
	if int64(len(data)) > c.maxBytes {
		data = data[:c.maxBytes]
	}
	cls := c.classifier(resp.StatusCode, resp.Header, data)
	r := &Response{
		URL:          rawURL,
		Method:       method,
		Status:       resp.StatusCode,
		Headers:      resp.Header.Clone(),
		Body:         data,
		RTT:          rtt,
		Untrusted:    cls.Untrusted,
		Soft404:      cls.Soft404,
		WAFDetected:  cls.WAFDetected,
		ClassifyNote: cls.Note,
		ErrorClass:   plugin.ErrorClassUnknown,
		RetryCount:   retryCount,
	}
	c.store.Put(r)
	return r, nil
}

// Store depoyu dışa açar (oracle/evidence referansı için).
func (c *Client) Store() *Store { return c.store }

func readerOf(b []byte) io.Reader {
	if len(b) == 0 {
		return nil
	}
	return &ioReader{b: b}
}

type ioReader struct {
	b []byte
	i int
}

func (r *ioReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
