// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package oob

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeInteractsh struct {
	mu       sync.Mutex
	corr     string
	secret   string
	pub      *rsa.PublicKey
	interact []string
	aesKey   string
	srv      *httptest.Server
}

func newFakeInteractsh(t *testing.T) *fakeInteractsh {
	t.Helper()
	f := &fakeInteractsh{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			var req struct {
				PublicKey     string `json:"public-key"`
				SecretKey     string `json:"secret-key"`
				CorrelationID string `json:"correlation-id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			pub, err := parseTestPublicKey(req.PublicKey)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			f.mu.Lock()
			f.corr, f.secret, f.pub = req.CorrelationID, req.SecretKey, pub
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
		case "/poll":
			f.mu.Lock()
			data := f.interact
			key := f.aesKey
			f.interact = nil
			f.aesKey = ""
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "aes_key": key})
		case "/deregister":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func parseTestPublicKey(encoded string) (*rsa.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errBadKey
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errBadKey
	}
	return pub, nil
}

var errBadKey = &testError{"bad public key"}

type testError struct{ s string }

func (e *testError) Error() string { return e.s }

func (f *fakeInteractsh) encryptInteraction(t *testing.T, interaction map[string]any) {
	t.Helper()
	plain, err := json.Marshal(interaction)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(plain))
	cipher.NewCTR(block, iv).XORKeyStream(ct, plain)
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, f.pub, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.interact = append(f.interact, base64.StdEncoding.EncodeToString(append(iv, ct...)))
	f.aesKey = base64.StdEncoding.EncodeToString(encKey)
	f.mu.Unlock()
}

func TestInteractshRegistrationAndCallbackURL(t *testing.T) {
	f := newFakeInteractsh(t)
	p, err := NewInteractshProvider(f.srv.URL, "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer p.Close()
	if !p.Enabled() || p.Type() != ProviderInteractsh || p.Name() != "interactsh" {
		t.Fatalf("provider state: enabled=%v type=%v name=%q", p.Enabled(), p.Type(), p.Name())
	}
	f.mu.Lock()
	corr := f.corr
	f.mu.Unlock()
	if len(corr) != 20 {
		t.Fatalf("correlation id = %q, want 20 chars", corr)
	}
	u := p.HTTPCallbackURL("c1")
	d := p.DNSCallbackDomain("c1")
	if !strings.HasPrefix(u, "http://"+corr) || !strings.Contains(u, ".") {
		t.Fatalf("HTTP callback URL %q does not carry the interactsh session", u)
	}
	if !strings.HasPrefix(d, corr) || !strings.Contains(d, ".") {
		t.Fatalf("DNS callback domain %q does not carry the interactsh session", d)
	}
}

func TestInteractshPollEmpty(t *testing.T) {
	f := newFakeInteractsh(t)
	p, err := NewInteractshProvider(f.srv.URL, "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer p.Close()
	ev, err := p.PollCallback(context.Background(), "c1")
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if ev != nil {
		t.Fatalf("empty poll returned event: %+v", ev)
	}
}

func TestInteractshDecryptsCallback(t *testing.T) {
	f := newFakeInteractsh(t)
	p, err := NewInteractshProvider(f.srv.URL, "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer p.Close()
	domain := p.DNSCallbackDomain("c1")
	label := strings.SplitN(domain, ".", 2)[0]
	f.encryptInteraction(t, map[string]any{
		"protocol":       "dns",
		"unique-id":      label,
		"full-id":        domain,
		"remote-address": "203.0.113.9",
		"timestamp":      time.Now().UTC(),
	})
	// The fake server returns the AES key with the same poll response.
	ev, err := p.PollCallback(context.Background(), "c1")
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if ev == nil {
		t.Fatal("callback not decrypted")
	}
	if ev.CorrelationID != "c1" || ev.Protocol != "dns" || ev.RemoteIP != "203.0.113.9" {
		t.Fatalf("unexpected callback: %+v", ev)
	}
}

func TestInteractshRegistrationFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := NewInteractshProvider(srv.URL, ""); err == nil {
		t.Fatal("registration failure must return an error")
	}
}
