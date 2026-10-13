// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package oob interactsh-uyumlu OOB client'tır (A-14).
// Varsayılan KAPALIDIR; --oob-server yokken skipped (B9).
package oob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Config OOB istemci ayarıdır.
type Config struct {
	ServerURL string
	Token     string
	Wait      time.Duration // --oob-wait (0-600s)
	PollEvery time.Duration // default 5s
}

// Interaction sunucu isabet kaydıdır.
type Interaction struct {
	CorrelationID string `json:"correlation_id"`
	Namespace     string `json:"namespace"`
	Timestamp     string `json:"timestamp"`
	RemoteIP      string `json:"remote_ip"`
	Protocol      string `json:"protocol"`
}

// Client polling/push korelasyon yapar.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient istemci kurar; ServerURL boşsa disabled-client döner (Enabled()==false).
func NewClient(cfg Config) *Client {
	if cfg.PollEvery <= 0 {
		cfg.PollEvery = 5 * time.Second
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second}}
}

// Enabled OOB açık mı (opt-in var mı).
func (c *Client) Enabled() bool { return c.cfg.ServerURL != "" }

// NewScanNamespace scan başına namespace üretir: scan_<hex16>.
func NewScanNamespace() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("oob scan id: %w", err)
	}
	return "scan_" + hex.EncodeToString(b[:]), nil
}

// NewCorrelationID candidate başına unique ID üretir: c_<hex12>.
func NewCorrelationID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("oob corr id: %w", err)
	}
	return "c_" + hex.EncodeToString(b[:]), nil
}

// Poll scan namespace'e ait interaction'ları çeker (token auth, cursor'lu).
func (c *Client) Poll(ctx context.Context, scanID, since string) ([]Interaction, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("oob not configured: %w", ErrNotConfigured)
	}
	base, err := url.Parse(c.cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("oob server url: %w", err)
	}
	base.Path = "/api/v1/poll"
	q := base.Query()
	q.Set("scan", scanID)
	q.Set("since", since)
	base.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("oob poll req: %w", err)
	}
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	resp, err := c.http.Do(req)
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
	var out []Interaction
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("oob poll decode: %w", err)
	}
	return out, nil
}

// Match correlation+namespace birebir eşleşme arar (başka scan gürültüsü bulaşmaz).
func Match(inters []Interaction, correlationID, namespace string) bool {
	for _, in := range inters {
		if in.CorrelationID == correlationID && in.Namespace == namespace {
			return true
		}
	}
	return false
}
