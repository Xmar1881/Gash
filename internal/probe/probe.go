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
	"net"
	"net/http"
	"net/url"
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
	transport  *http.Transport
	proxyURL   *url.URL
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
	// ProxyURL upstream HTTP proxy URL (örn. http://127.0.0.1:8080).
	ProxyURL *url.URL
	// Transport doğrudan özel transport enjeksiyonudur (nil ise DefaultTransport clone).
	Transport *http.Transport
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
	tr := opts.Transport
	if tr == nil {
		if defTr, ok := http.DefaultTransport.(*http.Transport); ok {
			tr = defTr.Clone()
		} else {
			tr = &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
		}
	}
	if opts.ProxyURL != nil {
		tr.Proxy = http.ProxyURL(opts.ProxyURL)
	}
	if opts.Policy != nil {
		opts.Policy.SetBase(tr)
	}
	c := &Client{
		policy:    opts.Policy,
		transport: tr,
		proxyURL:  opts.ProxyURL,
		store:     NewStore(),
		maxBytes:  opts.MaxBytes,
		extra:     cloneMap(opts.ExtraHeaders),
		classifier: func(status int, headers http.Header, body []byte) baseline.Classification {
			return baseline.ClassifyStatic(status, headers, body)
		},
		enableWAFBypass: opts.EnableWAFBypass,
	}
	return c
}

// Policy returns the underlying policy session, or nil if none configured.
func (c *Client) Policy() *plugin.PolicySession {
	if c == nil {
		return nil
	}
	return c.policy
}

// Transport returns the underlying *http.Transport used for HTTP requests.
func (c *Client) Transport() *http.Transport {
	if c == nil {
		return nil
	}
	return c.transport
}

// ProxyURL returns the configured upstream proxy URL, or nil.
func (c *Client) ProxyURL() *url.URL {
	if c == nil {
		return nil
	}
	return c.proxyURL
}

// extraHeaders bağlam başlıklarının kopyasını döner (çağıran değiştiremez).
func (c *Client) extraHeaders() map[string]string {
	return cloneMap(c.extra)
}

// SetExtraHeaders bağlam başlıklarını değiştirir (login sonrası auth tazeleme).
// What: Haritayı kopyalayarak saklar; mevcut ekstra başlıkların yerini alır.
// Why: Login akışının kurduğu oturum (MergeMissing sonucu) taramanın geri
// kalanına taşınmalı. Yarış koşulundan kaçınmak için tarama işçileri
// başlamadan ÖNCE çağrılmalıdır (engine sırası bunu garanti eder).
func (c *Client) SetExtraHeaders(headers map[string]string) {
	if c == nil {
		return
	}
	c.extra = cloneMap(headers)
}

// noWAFBypassKey login akışının WAF-bypass varyant denemesini kapatır.
type noWAFBypassKey struct{}

// WithNoWAFBypass ctx'e "WAF-bypass varyantı deneme" iptal işareti gömer.
// What: Send agresif modda olsa bile blok yanıtında varyant ÜRETMEZ.
// Why: Login POST'u kimlik bilgisi taşır; bypass mutasyonlarıyla kimlik
// yeniden oynatılmamalı (tek gönderim politikası).
func WithNoWAFBypass(ctx context.Context) context.Context {
	return context.WithValue(ctx, noWAFBypassKey{}, true)
}

// noWAFBypassFromCtx işaretçiyi okur (yoksa false).
func noWAFBypassFromCtx(ctx context.Context) bool {
	v, _ := ctx.Value(noWAFBypassKey{}).(bool)
	return v
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
	if !c.enableWAFBypass || noWAFBypassFromCtx(ctx) || !wafbypass.ShouldAttemptBypass(r.Status, r.Headers, r.Body) {
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
		// Host özel-case: net/http host'u req.Host'tan okur; Header.Set("Host")
		// sessizce yok sayılır. Host-header-injection (GASH-035) kanıtı bu
		// alan üzerinden taşınır.
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
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
		if c.transport != nil {
			tr = c.transport
		}
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
