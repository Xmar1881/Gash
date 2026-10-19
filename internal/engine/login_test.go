// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Xmar1881/Gash/internal/auth"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// e2eAuthHeaderPlugin yalnızca oturum kurulduğunda koşan pasif fixture'dır.
// What: requires_auth kapısını login entegrasyonuyla sınar.
// Why: Oturum gerçekten kurulduysa plugin koşar ve kanıt üretir.
const e2eAuthHeaderPlugin = `id: e2e-auth-header-check
name: E2E Auth Header Check For Testing Purposes
description: Auth gate check that only runs when a verified session exists here.
severity: low
tags: [headers]
safe: true
deep: false
active: false
requires_auth: true
phase: probe
order: 10
api_version: "1.0"
tests: tests/fixtures/missing-security-headers/
request:
  method: GET
oracle:
  name: header
`

// writeAuthE2EPlugin auth-kapılı fixture'ı temp dizine bırakır.
func writeAuthE2EPlugin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "e2e-auth-header.yaml")
	if err := os.WriteFile(path, []byte(e2eAuthHeaderPlugin), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// loginTargetServer oturum kurulan test hedefidir.
// What: GET /login form, POST /session kimlik kontrolü, anonim/kontrol sayfaları.
// Why: Uçtan uca login akışını gerçek policy+probe hattından geçirir.
type loginTargetServer struct {
	formGets              atomic.Int64
	loginPosts            atomic.Int64
	pluginSawSid          atomic.Bool
	pluginSawSessionValue atomic.Value // string
}

func harden(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("X-Frame-Options", "DENY")
}

func (s *loginTargetServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/login":
			s.formGets.Add(1)
			_, _ = fmt.Fprintf(w, `<html><body><form action="/session" method="POST">`+
				`<input type="hidden" name="csrf" value="tok-%d">`+
				`<input type="text" name="username">`+
				`<input type="password" name="password"></form></body></html>`, s.formGets.Load())
		case r.Method == http.MethodPost && r.URL.Path == "/session":
			s.loginPosts.Add(1)
			_ = r.ParseForm()
			if r.FormValue("username") == "admin" && r.FormValue("password") == "S3cretVer!li" {
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "good", Path: "/"})
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte(`<html><body><form><input type="password" name="password"></form></body></html>`))
		case r.URL.Path == "/dashboard":
			if c, err := r.Cookie("sid"); err == nil && c.Value == "good" {
				_, _ = w.Write([]byte(`<html><body>panel</body></html>`))
				return
			}
			_, _ = w.Write([]byte(`<html><body><form><input type="password" name="password"></form></body></html>`))
		case r.URL.Path == "/session":
			// Doğrulama/kontrol ucu: oturumlu panel, anonim parola sayfası.
			if c, err := r.Cookie("sid"); err == nil && c.Value == "good" {
				_, _ = w.Write([]byte(`<html><body>panel</body></html>`))
				return
			}
			_, _ = w.Write([]byte(`<html><body><form><input type="password" name="password"></form></body></html>`))
		default:
			// Plugin/browser hatası: oturumlu isteklerde hardening YOK (kanıt),
			// anonim isteklerde tam hardening (boş rapor).
			if c, err := r.Cookie("sid"); err == nil && c.Value == "good" {
				s.pluginSawSid.Store(true)
				s.pluginSawSessionValue.Store(c.Value)
				_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
				return
			}
			harden(w)
			_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
		}
	}
}

func newLoginTestRegistry(t *testing.T) *plugin.Registry {
	t.Helper()
	reg := plugin.NewRegistry()
	dir := writeAuthE2EPlugin(t)
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if reg.Len() != 1 {
		t.Fatalf("tek plugin bekleniyordu, got %d", reg.Len())
	}
	return reg
}

// TestEngineLoginUnlocksRequiresAuth: doğrulanmış oturum requires_auth plugin'i
// koşturur ve oturum cookie'si plugin isteklerine taşınır.
func TestEngineLoginUnlocksRequiresAuth(t *testing.T) {
	s := &loginTargetServer{}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()

	reg := newLoginTestRegistry(t)
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.Login = &auth.LoginOptions{
		LoginURL: srv.URL + "/login",
		User:     "admin",
		Pass:     "S3cretVer!li",
	}
	e := New(reg, cfg)
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Stats["login_attempted"] != 1 || rep.Stats["login_succeeded"] != 1 {
		t.Fatalf("login sayaçları: %+v", rep.Stats)
	}
	if rep.Stats["login_cookies"] < 1 {
		t.Fatalf("cookie sayısı: %+v", rep.Stats)
	}
	for _, sk := range rep.Skipped {
		if sk.PluginID == "login" {
			t.Fatalf("başarıda login skip kaydı olmamalı: %+v", sk)
		}
	}
	if len(rep.Findings) == 0 {
		t.Fatalf("oturumlu hedefte kanıt bekleniyordu (skipped=%+v)", rep.Skipped)
	}
	if !s.pluginSawSid.Load() {
		t.Fatal("plugin isteği oturum cookie'si taşımadı")
	}
	if v, _ := s.pluginSawSessionValue.Load().(string); v != "good" {
		t.Fatalf("taşınan cookie değeri: %q", v)
	}
}

// TestEngineLoginFailureHonestSkip: başarısız login taramayı DURDURMAZ;
// tek skip kaydı düşer, requires_auth plugin'ler kapalı kalır ve kimlik
// bilgisi rapora sızmaz.
func TestEngineLoginFailureHonestSkip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`<html><body><form><input type="password" name="password"></form></body></html>`))
			return
		}
		_, _ = w.Write([]byte(`<html><body><form action="/session" method="POST">` +
			`<input type="text" name="username"><input type="password" name="password"></form></body></html>`))
	}))
	defer srv.Close()

	reg := newLoginTestRegistry(t)
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.Login = &auth.LoginOptions{
		LoginURL: srv.URL + "/login",
		User:     "admin",
		Pass:     "SuperSecretVer123!",
	}
	e := New(reg, cfg)
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("başarısız login Run'ı durdurmamalı: %v", err)
	}
	if rep.Stats["login_attempted"] != 1 || rep.Stats["login_succeeded"] != 0 {
		t.Fatalf("login sayaçları: %+v", rep.Stats)
	}
	loginSkips := 0
	for _, sk := range rep.Skipped {
		if sk.PluginID == "login" {
			loginSkips++
			if !strings.Contains(sk.Reason, "login-failed:") {
				t.Fatalf("login skip sebebi dürüst olmalı: %+v", sk)
			}
		}
	}
	if loginSkips != 1 {
		t.Fatalf("tek login skip kaydı bekleniyordu: %+v", rep.Skipped)
	}
	requiresAuthSkip := false
	for _, sk := range rep.Skipped {
		if strings.Contains(sk.Reason, "requires auth") {
			requiresAuthSkip = true
		}
	}
	if !requiresAuthSkip {
		t.Fatalf("requires_auth skip bekleniyordu: %+v", rep.Skipped)
	}
	// Kimlik bilgisi hiçbir yerde görünmez (skip + stats + findings özeti).
	dump := fmt.Sprintf("%+v %+v", rep, rep.Skipped)
	for _, secret := range []string{"SuperSecretVer123!", "S3cretVer!li"} {
		if strings.Contains(dump, secret) {
			t.Fatalf("kimlik bilgisi rapora sızdı: %s", secret)
		}
	}
}

// TestEngineLoginScopeViolationFatal: kapsam-dışı login hedefi fail-closed'dur;
// istek gönderilmeden Run hata döner (kimlik sızmaz).
func TestEngineLoginScopeViolationFatal(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
	}))
	defer srv.Close()

	reg := newLoginTestRegistry(t)
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.Scope = []string{"203.0.113.0/24"}
	cfg.Login = &auth.LoginOptions{
		LoginURL: srv.URL + "/login",
		User:     "admin",
		Pass:     "p@ss",
	}
	e := New(reg, cfg)
	_, err := e.Run(context.Background(), srv.URL)
	if err == nil || !errors.Is(err, plugin.ErrScopeViolation) {
		t.Fatalf("kapsam ihlali fail-closed olmalı, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("kapsam-dışı hedefe istek gitmemeli, got %d", hits.Load())
	}
}

// TestEngineLoginExplicitAuthWins: açık --cookie login türevini AD bazında yener.
// What: Login session=login-session set eder; açık cookie session=explicit'tir.
// Why: Kullanıcının açık beyanı login türevinin üzerindedir (precedence).
func TestEngineLoginExplicitAuthWins(t *testing.T) {
	type seen struct{ session, sid string }
	var got atomic.Value // seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/login":
			_, _ = w.Write([]byte(`<html><body><form action="/session" method="POST">` +
				`<input type="text" name="username"><input type="password" name="password"></form></body></html>`))
		case r.Method == http.MethodPost && r.URL.Path == "/session":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "login-session", Path: "/"})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		case r.URL.Path == "/dashboard" || r.URL.Path == "/session":
			if c, err := r.Cookie("session"); err == nil && c.Value == "login-session" {
				_, _ = w.Write([]byte(`<html><body>panel</body></html>`))
				return
			}
			_, _ = w.Write([]byte(`<html><body><form><input type="password" name="password"></form></body></html>`))
		default:
			sess, sid := "", ""
			if c, err := r.Cookie("session"); err == nil {
				sess = c.Value
			}
			if c, err := r.Cookie("sid"); err == nil {
				sid = c.Value
			}
			got.Store(seen{session: sess, sid: sid})
			if sess == "explicit" {
				// Açık değer taşındıysa kanıt (hardening yok).
				_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
				return
			}
			harden(w)
			_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
		}
	}))
	defer srv.Close()

	reg := newLoginTestRegistry(t)
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.Auth = auth.New()
	if err := cfg.Auth.ParseCookie("session=explicit"); err != nil {
		t.Fatal(err)
	}
	cfg.Login = &auth.LoginOptions{
		LoginURL: srv.URL + "/login",
		User:     "admin",
		Pass:     "p@ss",
	}
	e := New(reg, cfg)
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Stats["login_succeeded"] != 1 {
		t.Fatalf("login kurulmalı: %+v", rep.Stats)
	}
	if len(rep.Findings) == 0 {
		t.Fatalf("açık cookie taşınmalıydı (skipped=%+v)", rep.Skipped)
	}
	if v, ok := got.Load().(seen); ok {
		if v.session != "explicit" {
			t.Fatalf("açık cookie değeri login türeviyle ezildi: %+v", v)
		}
	}
}
