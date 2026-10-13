// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package probe HTTP client wrapper + canary üretimi + response store'dur.
// Tüm gönderimler PolicySession (http.RoundTripper) üzerinden geçer (B6).
package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// Response ham body'yi store'da tutar; Candidate yalnızca id referansı taşır (bellek disiplini).
type Response struct {
	ID           string
	URL          string
	Method       string
	Status       int
	Headers      http.Header
	Body         []byte
	RTT          time.Duration
	Untrusted    bool
	Soft404      bool
	ClassifyNote string
	TaintedBy    string
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
	http       *http.Client
	policy     *plugin.PolicySession
	store      *Store
	maxBytes   int64
	classifier func(status int, headers http.Header, body []byte) baseline.Classification
}

// Options istemci ayarlarıdır.
type Options struct {
	Policy         *plugin.PolicySession
	BaseTransport  http.RoundTripper
	RequestTimeout time.Duration
	MaxBytes       int64
	MaxRedirects   int
}

// NewClient politika + baseline sınıflandırmalı istemci kurar.
func NewClient(opts Options) *Client {
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 15 * time.Second
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 5 * 1024 * 1024
	}
	if opts.MaxRedirects < 0 {
		opts.MaxRedirects = 0
	}
	if opts.MaxRedirects == 0 {
		opts.MaxRedirects = 5
	}
	var rt http.RoundTripper = opts.BaseTransport
	if rt == nil {
		rt = http.DefaultTransport
	}
	if opts.Policy != nil {
		// PolicySession base'i sarar; istemci policy üzerinden konuşur.
		// Not: PolicySession'ın base'i opts.BaseTransport olmalıydı; burada istemci
		// transport'u doğrudan policy yapıyoruz (policy zaten base'i içeriyor).
		rt = opts.Policy
	}
	c := &Client{
		policy:   opts.Policy,
		store:    NewStore(),
		maxBytes: opts.MaxBytes,
		classifier: func(status int, headers http.Header, body []byte) baseline.Classification {
			return baseline.ClassifyStatic(status, headers, body)
		},
	}
	c.http = &http.Client{
		Transport: rt,
		Timeout:   opts.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= opts.MaxRedirects {
				return fmt.Errorf("redirect limiti (%d): %w", opts.MaxRedirects, http.ErrUseLastResponse)
			}
			return nil
		},
	}
	return c
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
func (c *Client) Send(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, readerOf(body))
	if err != nil {
		return nil, fmt.Errorf("probe new request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("probe do %s %s: %w", method, rawURL, err)
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
		ClassifyNote: cls.Note,
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
