// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package oob interactsh-protocol OOB provider.
// What: Minimal stdlib client for the interactsh register/poll protocol.
// Why: Self-hosted-only OOB is honest but hostile to first-time users; the
// official public interactsh servers give a plug-and-play option without
// pulling the full ProjectDiscovery server dependency tree into Gash.
package oob

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// PublicInteractshServers is the official public interactsh fleet.
// The operator explicitly opts in with --oob-server interactsh; the service is
// third-party and must never be the default for sensitive engagements.
const PublicInteractshServers = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"

const (
	interactshCorrelationLen = 20
	interactshNonceLen       = 13
	interactshAlphabet       = "0123456789abcdefghijklmnopqrstuv"
)

// InteractshProvider is a minimal interactsh client implementing Provider.
// What: One registered session, per-correlation subdomains, decrypted polling.
// Why: Confirmation still comes only from a real callback; the provider merely
// supplies the public callback channel.
type InteractshProvider struct {
	serverURL     *url.URL
	token         string
	client        *http.Client
	privKey       *rsa.PrivateKey
	correlationID string
	secretKey     string

	mu           sync.Mutex
	closed       bool
	domains      map[string]string // Gash correlation ID -> full subdomain label
	interactions map[string]CallbackEvent
	lastPoll     time.Time
}

type interactshPollResponse struct {
	Data    []string `json:"data"`
	Extra   []string `json:"extra"`
	AESKey  string   `json:"aes_key"`
	TLDData []string `json:"tlddata,omitempty"`
}

type interactshInteraction struct {
	Protocol      string    `json:"protocol"`
	UniqueID      string    `json:"unique-id"`
	FullID        string    `json:"full-id"`
	RawRequest    string    `json:"raw-request,omitempty"`
	RemoteAddress string    `json:"remote-address"`
	Timestamp     time.Time `json:"timestamp"`
}

// NewInteractshProvider registers one interactsh session.
// serverList may be "interactsh" (public fleet), "interactsh://host",
// a bare host, or a comma-separated list. HTTP is allowed for self-hosted
// servers; the public fleet is HTTPS.
func NewInteractshProvider(serverList, token string) (*InteractshProvider, error) {
	servers, err := parseInteractshServers(serverList)
	if err != nil {
		return nil, err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("interactsh rsa key: %w", err)
	}
	p := &InteractshProvider{
		token:         strings.TrimSpace(token),
		client:        &http.Client{Timeout: 15 * time.Second},
		privKey:       priv,
		correlationID: randomInteractshID(interactshCorrelationLen),
		secretKey:     randomInteractshUUID(),
		domains:       map[string]string{},
		interactions:  map[string]CallbackEvent{},
	}
	publicKey, err := interactshPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]string{
		"public-key":     publicKey,
		"secret-key":     p.secretKey,
		"correlation-id": p.correlationID,
	})
	if err != nil {
		return nil, fmt.Errorf("interactsh register payload: %w", err)
	}
	var lastErr error
	for _, server := range servers {
		if err := p.register(context.Background(), server, payload); err != nil {
			lastErr = err
			continue
		}
		p.serverURL = server
		return p, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no interactsh server configured")
	}
	return nil, fmt.Errorf("interactsh registration failed: %w", lastErr)
}

func parseInteractshServers(raw string) ([]*url.URL, error) {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	switch {
	case lower == "" || lower == "interactsh" || lower == "interactsh://":
		raw = PublicInteractshServers
	case strings.HasPrefix(lower, "interactsh://"):
		raw = raw[len("interactsh://"):]
	case strings.HasPrefix(lower, "interactsh:"):
		raw = raw[len("interactsh:"):]
	}
	var out []*url.URL
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "://") {
			part = "https://" + part
		}
		u, err := url.Parse(part)
		if err != nil || u.Host == "" {
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		u.Path = ""
		u.RawQuery = ""
		u.Fragment = ""
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("interactsh server list is empty")
	}
	return out, nil
}

func (p *InteractshProvider) register(ctx context.Context, server *url.URL, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(server.String(), "/")+"/register", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.token != "" {
		req.Header.Set("Authorization", p.token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: register status %d: %s", server.Host, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var rr struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &rr); err != nil || rr.Message != "registration successful" {
		return fmt.Errorf("%s: unexpected registration response", server.Host)
	}
	return nil
}

// Type implements Provider.
func (p *InteractshProvider) Type() ProviderType { return ProviderInteractsh }

// Name implements Provider.
func (p *InteractshProvider) Name() string { return "interactsh" }

// Enabled implements Provider.
func (p *InteractshProvider) Enabled() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && p.serverURL != nil && p.correlationID != ""
}

// RegisterScan implements Provider (session is registered at construction).
func (p *InteractshProvider) RegisterScan(ctx context.Context, scanID, corrID string) error {
	if !p.Enabled() {
		return fmt.Errorf("%w: interactsh provider disabled", ErrNotConfigured)
	}
	return nil
}

// HTTPCallbackURL implements Provider.
func (p *InteractshProvider) HTTPCallbackURL(corrID string) string {
	label, host := p.callbackLabel(corrID)
	if label == "" {
		return ""
	}
	return "http://" + label + "." + host + "/"
}

// DNSCallbackDomain implements Provider.
func (p *InteractshProvider) DNSCallbackDomain(corrID string) string {
	label, host := p.callbackLabel(corrID)
	if label == "" {
		return ""
	}
	return label + "." + host
}

func (p *InteractshProvider) callbackLabel(corrID string) (string, string) {
	if !p.Enabled() || strings.TrimSpace(corrID) == "" {
		return "", ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if label, ok := p.domains[corrID]; ok {
		return label, p.serverURL.Hostname()
	}
	label := p.correlationID + randomInteractshID(interactshNonceLen)
	p.domains[corrID] = label
	return label, p.serverURL.Hostname()
}

// PollCallback implements Provider.
func (p *InteractshProvider) PollCallback(ctx context.Context, corrID string) (*CallbackEvent, error) {
	if !p.Enabled() {
		return nil, fmt.Errorf("%w: interactsh provider disabled", ErrNotConfigured)
	}
	p.mu.Lock()
	if ev, ok := p.interactions[corrID]; ok {
		delete(p.interactions, corrID)
		p.mu.Unlock()
		return &ev, nil
	}
	due := time.Since(p.lastPoll) >= 700*time.Millisecond
	if due {
		p.lastPoll = time.Now()
	}
	p.mu.Unlock()
	if due {
		if err := p.poll(ctx); err != nil {
			return nil, err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ev, ok := p.interactions[corrID]; ok {
		delete(p.interactions, corrID)
		return &ev, nil
	}
	return nil, nil
}

func (p *InteractshProvider) poll(ctx context.Context) error {
	if p.serverURL == nil {
		return errors.New("interactsh server not registered")
	}
	pollURL := strings.TrimSuffix(p.serverURL.String(), "/") + "/poll?id=" +
		url.QueryEscape(p.correlationID) + "&secret=" + url.QueryEscape(p.secretKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
	if err != nil {
		return err
	}
	if p.token != "" {
		req.Header.Set("Authorization", p.token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("interactsh poll status %d", resp.StatusCode)
	}
	var pr interactshPollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&pr); err != nil {
		return fmt.Errorf("interactsh poll decode: %w", err)
	}
	for _, encrypted := range pr.Data {
		plain, err := p.decrypt(pr.AESKey, encrypted)
		if err != nil {
			continue
		}
		p.addInteraction(plain)
	}
	for _, plain := range pr.Extra {
		p.addInteraction([]byte(plain))
	}
	for _, plain := range pr.TLDData {
		p.addInteraction([]byte(plain))
	}
	return nil
}

func (p *InteractshProvider) addInteraction(plain []byte) {
	var in interactshInteraction
	if err := json.Unmarshal(bytes.TrimSpace(plain), &in); err != nil {
		return
	}
	full := strings.TrimSpace(in.FullID)
	if full == "" {
		full = strings.TrimSpace(in.UniqueID)
	}
	if full == "" {
		return
	}
	label := full
	if idx := strings.IndexByte(label, '.'); idx > 0 {
		label = label[:idx]
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var match string
	for corrID, stored := range p.domains {
		if label == stored || strings.HasPrefix(full, stored) {
			match = corrID
			break
		}
	}
	if match == "" {
		return
	}
	if _, exists := p.interactions[match]; exists {
		return
	}
	payload := in.RawRequest
	if len(payload) > 512 {
		payload = payload[:512]
	}
	ts := in.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	p.interactions[match] = CallbackEvent{
		CorrelationID: match,
		Protocol:      strings.ToLower(strings.TrimSpace(in.Protocol)),
		RemoteIP:      in.RemoteAddress,
		Timestamp:     ts,
		Payload:       payload,
	}
}

func (p *InteractshProvider) decrypt(key, secureMessage string) ([]byte, error) {
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	keyPlaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, p.privKey, decodedKey, nil)
	if err != nil {
		return nil, err
	}
	cipherText, err := base64.StdEncoding.DecodeString(secureMessage)
	if err != nil {
		return nil, err
	}
	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("interactsh ciphertext too short")
	}
	block, err := aes.NewCipher(keyPlaintext)
	if err != nil {
		return nil, err
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	out := make([]byte, len(cipherText))
	cipher.NewCTR(block, iv).XORKeyStream(out, cipherText)
	return out, nil
}

// Close deregisters the session and disables the provider.
func (p *InteractshProvider) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	server := p.serverURL
	p.mu.Unlock()
	if server == nil {
		return nil
	}
	body, _ := json.Marshal(map[string]string{
		"correlation-id": p.correlationID,
		"secret-key":     p.secretKey,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(server.String(), "/")+"/deregister", bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if p.token != "" {
		req.Header.Set("Authorization", p.token)
	}
	resp, err := p.client.Do(req)
	if err == nil && resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return nil
}

func interactshPublicKey(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})
	return base64.StdEncoding.EncodeToString(pemBytes), nil
}

func randomInteractshID(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	for i := range b {
		b[i] = interactshAlphabet[int(b[i])%len(interactshAlphabet)]
	}
	return string(b)
}

func randomInteractshUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return randomInteractshID(36)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	hexs := hex.EncodeToString(b)
	return hexs[0:8] + "-" + hexs[8:12] + "-" + hexs[12:16] + "-" + hexs[16:20] + "-" + hexs[20:32]
}
