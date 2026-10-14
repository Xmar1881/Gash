// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oob

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ProviderType OOB sağlayıcı türüdür.
type ProviderType int

const (
	// ProviderSelfHosted interactsh-benzeri kendi barındırılan sağlayıcı.
	ProviderSelfHosted ProviderType = iota
	// ProviderExternal dış servis (opsiyonel).
	ProviderExternal
)

// Provider OOB callback sağlayıcı arayüzüdür.
// Self-hosted ve dış sağlayıcılar bu arayüzü uygular.
type Provider interface {
	// Type sağlayıcı türü.
	Type() ProviderType
	// Name sağlayıcı adı.
	Name() string
	// Enabled sağlayıcı aktif mi.
	Enabled() bool
	// RegisterScan scan namespace + correlation ID kaydeder.
	RegisterScan(ctx context.Context, scanID, corrID string) error
	// PollCallback correlation ID için callback sorgular.
	PollCallback(ctx context.Context, corrID string) (*CallbackEvent, error)
	// HTTPCallback URL'leri oluşturur (payload enjeksiyonu için).
	HTTPCallbackURL(corrID string) string
	// DNSCallback domain'i oluşturur (payload enjeksiyonu için).
	DNSCallbackDomain(corrID string) string
	// Close sağlayıcıyı kapatır.
	Close() error
}

// CallbackEvent tek bir OOB callback kaydıdır.
type CallbackEvent struct {
	CorrelationID string    `json:"correlation_id"`
	ScanID        string    `json:"scan_id"`
	Protocol      string    `json:"protocol"` // "dns", "http"
	RemoteIP      string    `json:"remote_ip"`
	Timestamp     time.Time `json:"timestamp"`
	Payload       string    `json:"payload,omitempty"`
}

// SelfHostedProvider interactsh-benzeri kendi barındırılan sağlayıcıdır.
// HTTP endpoint üzerinden polling yapar.
type SelfHostedProvider struct {
	serverURL string
	token     string
	client    *http.Client
	timeout   time.Duration
	mu        sync.Mutex
	closed    bool
}

// NewSelfHostedProvider self-hosted sağlayıcı kurar.
// serverURL boşsa disabled provider döner (Enabled()=false).
func NewSelfHostedProvider(serverURL, token string) *SelfHostedProvider {
	p := &SelfHostedProvider{
		serverURL: serverURL,
		token:     token,
		client:    &http.Client{Timeout: 15 * time.Second},
		timeout:   15 * time.Second,
	}
	return p
}

// Type sağlayıcı türü.
func (p *SelfHostedProvider) Type() ProviderType { return ProviderSelfHosted }

// Name sağlayıcı adı.
func (p *SelfHostedProvider) Name() string { return "self-hosted" }

// Enabled sağlayıcı aktif mi.
func (p *SelfHostedProvider) Enabled() bool { return p.serverURL != "" && !p.closed }

// RegisterScan scan + correlation kaydeder (self-hosted'te no-op).
func (p *SelfHostedProvider) RegisterScan(ctx context.Context, scanID, corrID string) error {
	if !p.Enabled() {
		return fmt.Errorf("%w: self-hosted provider disabled", ErrNotConfigured)
	}
	return nil
}

// PollCallback correlation ID için HTTP callback sorgular.
func (p *SelfHostedProvider) PollCallback(ctx context.Context, corrID string) (*CallbackEvent, error) {
	if !p.Enabled() {
		return nil, fmt.Errorf("%w: self-hosted provider disabled", ErrNotConfigured)
	}
	base, err := url.Parse(p.serverURL)
	if err != nil {
		return nil, fmt.Errorf("oob server url: %w", err)
	}
	base.Path = "/api/v1/poll"
	q := base.Query()
	q.Set("corr", corrID)
	base.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("oob poll req: %w", err)
	}
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oob poll do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oob poll status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("oob poll read: %w", err)
	}

	var events []CallbackEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("oob poll decode: %w", err)
	}
	for _, ev := range events {
		if ev.CorrelationID == corrID {
			return &ev, nil
		}
	}
	return nil, nil
}

// HTTPCallbackURL correlation ID için HTTP callback URL üretir.
func (p *SelfHostedProvider) HTTPCallbackURL(corrID string) string {
	if !p.Enabled() {
		return ""
	}
	base, _ := url.Parse(p.serverURL)
	base.Path = "/cb/" + corrID
	return base.String()
}

// DNSCallbackDomain correlation ID için DNS callback domain üretir.
func (p *SelfHostedProvider) DNSCallbackDomain(corrID string) string {
	if !p.Enabled() {
		return ""
	}
	base, _ := url.Parse(p.serverURL)
	host := base.Host
	if h, _, err := splitHost(host); err == nil {
		return corrID + "." + h
	}
	return corrID + "." + host
}

// Close sağlayıcıyı kapatır.
func (p *SelfHostedProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// splitHost host:port ayrıştırır.
func splitHost(hostport string) (string, string, error) {
	return net.SplitHostPort(hostport)
}
