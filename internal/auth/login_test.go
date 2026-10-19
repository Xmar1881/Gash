// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// rawSender httptest sunucusuna ham http.Client ile istek atan test sender'ıdır.
// What: Redirect'leri KENDİSİ izlemez (login akışı manuel izler).
// Why: Gerçek politikadan bağımsız, deterministik akış testleri için.
func rawSender(client *http.Client) Sender {
	return func(ctx context.Context, method, rawURL string, headers map[string]string, payload []byte) (int, http.Header, string, error) {
		req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(payload))
		if err != nil {
			return 0, nil, "", err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return 0, nil, "", err
		}
		return resp.StatusCode, resp.Header, string(b), nil
	}
}

// noRedirectClient httptest istemcisini 3xx'te durduracak şekilde ayarlar.
func noRedirectClient(srv *httptest.Server) *http.Client {
	c := srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

const loginFormPage = `<html><body><form action="/session" method="POST">` +
	`<input type="hidden" name="csrf" value="%s">` +
	`<input type="text" name="username">` +
	`<input type="password" name="password">` +
	`<button type="submit">Giriş</button></form></body></html>`

const authedPage = `<html><body>hoş geldin panel</body></html>`

const anonRequiredPage = `<html><body>giriş gerekli<form><input type="password" name="password"></form></body></html>`

// csrfServer dönen token + tek kimlik seti doğrulayan test sunucusudur.
type csrfServer struct {
	tokens     atomic.Int64
	lastIssued atomic.Value // string
	posts      atomic.Int64
	gets       atomic.Int64
	failFirst  atomic.Bool
}

func newCSRFServer() *csrfServer {
	s := &csrfServer{}
	s.lastIssued.Store("")
	return s
}

func (s *csrfServer) handler(validPass string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/login":
			s.gets.Add(1)
			tok := fmt.Sprintf("csrf-%d", s.tokens.Add(1))
			s.lastIssued.Store(tok)
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintf(w, loginFormPage, tok)
		case r.Method == http.MethodPost && r.URL.Path == "/session":
			s.posts.Add(1)
			_ = r.ParseForm()
			if r.FormValue("csrf") != s.lastIssued.Load().(string) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = fmt.Fprintf(w, loginFormPage, r.FormValue("csrf"))
				return
			}
			if s.failFirst.CompareAndSwap(true, false) {
				// Sunucu-tarafı nonce yenilemesi: sonraki deneme TAZE token ister.
				tok := fmt.Sprintf("csrf-%d", s.tokens.Add(1))
				s.lastIssued.Store(tok)
				w.Header().Set("Content-Type", "text/html")
				_, _ = fmt.Fprintf(w, loginFormPage, tok)
				return
			}
			if r.FormValue("username") != "admin" || r.FormValue("password") != validPass {
				w.Header().Set("Content-Type", "text/html")
				_, _ = fmt.Fprintf(w, loginFormPage, r.FormValue("csrf"))
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "good", Path: "/"})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		case r.URL.Path == "/dashboard":
			if c, err := r.Cookie("session"); err == nil && c.Value == "good" {
				_, _ = w.Write([]byte(authedPage))
				return
			}
			_, _ = w.Write([]byte(anonRequiredPage))
		default:
			// Oturumlu /session panel, anonim istekte parola alanlı sayfa.
			if c, err := r.Cookie("session"); err == nil && c.Value == "good" {
				_, _ = w.Write([]byte(authedPage))
				return
			}
			_, _ = w.Write([]byte(anonRequiredPage))
		}
	}
}

func mkLoginOpts(srv *httptest.Server) LoginOptions {
	return LoginOptions{LoginURL: srv.URL + "/login", User: "admin", Pass: "p@ss"}
}

// TestLoginFlowRotatingCSRFFreshPerAttempt: token her denemede tazelenir.
// What: İlk POST sunucu-tarafı token yenilemesiyle reddedilir; ikinci deneme
// TAZE GET olmadan başarısız olur.
// Why: Bayat CSRF token'ıyla POST (klasik hata) bu testte yakalanır.
func TestLoginFlowRotatingCSRFFreshPerAttempt(t *testing.T) {
	s := newCSRFServer()
	s.failFirst.Store(true)
	srv := httptest.NewServer(s.handler("p@ss"))
	defer srv.Close()

	res, err := LoginFlow(context.Background(), rawSender(noRedirectClient(srv)), mkLoginOpts(srv))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !res.Success || res.Reason != ReasonSuccess {
		t.Fatalf("başarı bekleniyordu: %+v", res)
	}
	if res.Attempts != 2 {
		t.Fatalf("2 deneme bekleniyordu, got %d", res.Attempts)
	}
	if res.Cookies == 0 || res.Context == nil || res.Context.Cookies["session"] != "good" {
		t.Fatalf("oturum cookie bekleniyordu: %+v", res)
	}
	if got := s.gets.Load(); got != 2 {
		t.Fatalf("deneme başına taze GET bekleniyordu, gets=%d", got)
	}
}

// TestLoginFlowHappyPath tek denemede oturum kurar.
func TestLoginFlowHappyPath(t *testing.T) {
	s := newCSRFServer()
	srv := httptest.NewServer(s.handler("p@ss"))
	defer srv.Close()

	res, err := LoginFlow(context.Background(), rawSender(noRedirectClient(srv)), mkLoginOpts(srv))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !res.Success || res.Reason != ReasonSuccess || res.Attempts != 1 {
		t.Fatalf("tek denemede başarı bekleniyordu: %+v", res)
	}
	if res.UsedFields != "username,password" {
		t.Fatalf("alanlar: %q", res.UsedFields)
	}
	// Kimlik değerleri Result içinde asla görünmez.
	dump := fmt.Sprintf("%+v", res)
	if strings.Contains(dump, "p@ss") || strings.Contains(dump, "admin") {
		t.Fatalf("kimlik Result'a sızdı: %s", dump)
	}
}

// TestLoginFlowWrongPassword iki denemede dürüst login-failed döner ve tekrar
// denemeyi sınırlar.
func TestLoginFlowWrongPassword(t *testing.T) {
	s := newCSRFServer()
	srv := httptest.NewServer(s.handler("p@ss"))
	defer srv.Close()

	opts := mkLoginOpts(srv)
	opts.Pass = "yanlis-parola"
	res, err := LoginFlow(context.Background(), rawSender(noRedirectClient(srv)), opts)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Success || res.Reason != ReasonLoginFailed {
		t.Fatalf("login-failed bekleniyordu: %+v", res)
	}
	if res.Attempts != DefaultLoginMaxAttempts {
		t.Fatalf("varsayılan deneme sayısı: %d", res.Attempts)
	}
	if got := s.posts.Load(); got != int64(DefaultLoginMaxAttempts) {
		t.Fatalf("deneme tavanı uygulanmadı, posts=%d", got)
	}
	// Parola hiçbir raporda görünmez.
	if strings.Contains(fmt.Sprintf("%+v", res), "yanlis-parola") {
		t.Fatal("parola Result'a sızdı")
	}
}

// TestLoginFlowAttemptsHardCap MaxAttempts üst sınırı 3'tür.
func TestLoginFlowAttemptsHardCap(t *testing.T) {
	s := newCSRFServer()
	srv := httptest.NewServer(s.handler("p@ss"))
	defer srv.Close()

	opts := mkLoginOpts(srv)
	opts.Pass = "yanlis"
	opts.MaxAttempts = 99
	res, err := LoginFlow(context.Background(), rawSender(noRedirectClient(srv)), opts)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Attempts != HardLoginMaxAttempts {
		t.Fatalf("sert tavan %d bekleniyordu, got %d", HardLoginMaxAttempts, res.Attempts)
	}
	if got := s.posts.Load(); got != int64(HardLoginMaxAttempts) {
		t.Fatalf("posts=%d", got)
	}
}

// TestLoginFlowTwoFANoRetry: OTP sayfası görülürse tekrar DENENMEZ.
func TestLoginFlowTwoFANoRetry(t *testing.T) {
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == http.MethodGet && r.URL.Path == "/login" {
			_, _ = fmt.Fprintf(w, loginFormPage, "tok")
			return
		}
		if r.Method == http.MethodPost {
			posts++
			http.Redirect(w, r, "/otp", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`<html><body><form><input name="otp_code" placeholder="Verification code"></form></body></html>`))
	}))
	defer srv.Close()

	res, err := LoginFlow(context.Background(), rawSender(noRedirectClient(srv)), mkLoginOpts(srv))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Success || res.Reason != Reason2FADetected {
		t.Fatalf("2fa-detected bekleniyordu: %+v", res)
	}
	if posts != 1 || res.Attempts != 1 {
		t.Fatalf("2FA'da tekrar yasak: posts=%d attempts=%d", posts, res.Attempts)
	}
}

// TestLoginFlowUnverifiedSession: cookie set edildi ama doğrulama belirsiz.
func TestLoginFlowUnverifiedSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/login":
			_, _ = fmt.Fprintf(w, loginFormPage, "tok")
		case r.Method == http.MethodPost:
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "abc", Path: "/"})
			// Parola alanlı sayfa döner: doğrulama KANITI yok.
			_, _ = fmt.Fprintf(w, loginFormPage, "tok")
		default:
			_, _ = w.Write([]byte(anonRequiredPage))
		}
	}))
	defer srv.Close()

	res, err := LoginFlow(context.Background(), rawSender(noRedirectClient(srv)), mkLoginOpts(srv))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Success || res.Reason != ReasonUnverifiedSession {
		t.Fatalf("unverified-session bekleniyordu: %+v", res)
	}
	if res.Cookies == 0 {
		t.Fatal("gözlenen cookie sayısı raporlanmalı")
	}
}

// TestLoginFlowNoSetCookieHonestFailure: POST gövdesi panel gibi görünse bile
// cookie yoksa ve doğrulama anonim kalıyorsa başarı İLAN EDİLMEZ.
func TestLoginFlowNoSetCookieHonestFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/login":
			_, _ = fmt.Fprintf(w, loginFormPage, "tok")
		case r.Method == http.MethodPost:
			_, _ = w.Write([]byte(authedPage))
		default:
			_, _ = w.Write([]byte(anonRequiredPage))
		}
	}))
	defer srv.Close()

	res, err := LoginFlow(context.Background(), rawSender(noRedirectClient(srv)), mkLoginOpts(srv))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Success || res.Reason != ReasonLoginFailed {
		t.Fatalf("login-failed bekleniyordu (kanıtsız başarı yasak): %+v", res)
	}
}

// TestLoginFlowFormHeuristics: parolasız form / kullanıcı alanı bulunamayan
// form / GET form sebepleri dürüstçe ayrılır.
func TestLoginFlowFormHeuristics(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"no-password-form", `<html><form action="/x" method="POST"><input type="text" name="q"></form></html>`, ReasonNoPasswordForm},
		{"no-user-field", `<html><form action="/x" method="POST"><input type="hidden" name="t" value="1"><input type="password" name="password"></form></html>`, ReasonNoUserField},
		{"login-form-get", `<html><form action="/x" method="GET"><input type="text" name="user"><input type="password" name="password"></form></html>`, ReasonLoginFormGET},
		{"unsupported-enctype", `<html><form action="/x" method="POST" enctype="text/plain"><input type="text" name="user"><input type="password" name="password"></form></html>`, ReasonUnsupportedEnctype},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			res, err := LoginFlow(context.Background(), rawSender(noRedirectClient(srv)), mkLoginOpts(srv))
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if res.Success || res.Reason != tc.want {
				t.Fatalf("want %s, got %+v", tc.want, res)
			}
		})
	}
}

// TestLoginFlowFieldOverrides: sezgisel seçim yerine açık alan override'ları.
// What: İlk text alan "q" kullanıcı adı DEĞİL; override olmadan POST başarısız.
// Why: Override'ın gerçekten alan eşlemesini değiştirdiğini kanıtlar.
func TestLoginFlowFieldOverrides(t *testing.T) {
	page := `<html><body><form action="/auth" method="POST">` +
		`<input type="text" name="q">` +
		`<input type="text" name="kerndata">` +
		`<input type="password" name="geheim">` +
		`</form></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/login":
			_, _ = w.Write([]byte(page))
		case r.Method == http.MethodPost:
			_ = r.ParseForm()
			if r.FormValue("kerndata") == "admin" && r.FormValue("geheim") == "p@ss" {
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "1", Path: "/"})
				_, _ = w.Write([]byte(authedPage))
				return
			}
			_, _ = w.Write([]byte(page))
		default:
			if c, err := r.Cookie("sid"); err == nil && c.Value == "1" {
				_, _ = w.Write([]byte(authedPage))
				return
			}
			_, _ = w.Write([]byte(anonRequiredPage))
		}
	}))
	defer srv.Close()

	// Override'sız sezgisel seçim "q"ya düşer ve sunucu reddeder.
	nos := LoginOptions{LoginURL: srv.URL + "/login", User: "admin", Pass: "p@ss"}
	bad, err := LoginFlow(context.Background(), rawSender(noRedirectClient(srv)), nos)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if bad.Success {
		t.Fatalf("override'sız başarı BEKLENMEZ: %+v", bad)
	}

	opts := LoginOptions{
		LoginURL:  srv.URL + "/login",
		User:      "admin",
		Pass:      "p@ss",
		UserField: "kerndata",
		PassField: "geheim",
	}
	res, err := LoginFlow(context.Background(), rawSender(noRedirectClient(srv)), opts)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Success {
		t.Fatalf("override ile başarı bekleniyordu: %+v", res)
	}
	if res.UsedFields != "kerndata,geheim" {
		t.Fatalf("kullanılan alanlar: %q", res.UsedFields)
	}
}

// TestLoginFlowScopeViolationFatal: kapsam ihlali fataldır (fail-closed).
func TestLoginFlowScopeViolationFatal(t *testing.T) {
	sender := func(context.Context, string, string, map[string]string, []byte) (int, http.Header, string, error) {
		return 0, nil, "", fmt.Errorf("policy: %w: host dışı", plugin.ErrScopeViolation)
	}
	_, err := LoginFlow(context.Background(), sender, LoginOptions{LoginURL: "http://x.example/login", User: "u", Pass: "p"})
	if err == nil || !errors.Is(err, plugin.ErrScopeViolation) {
		t.Fatalf("kapsam hatası fırlatılmalı, got %v", err)
	}
}

// TestLoginFlowRequiresCredentials: boş/eksik kimlik reddedilir.
func TestLoginFlowRequiresCredentials(t *testing.T) {
	sender := rawSender(&http.Client{})
	if _, err := LoginFlow(context.Background(), sender, LoginOptions{LoginURL: "http://x.example/login", User: "", Pass: "p"}); err == nil {
		t.Fatal("kullanıcısız akış reddedilmeli")
	}
	if _, err := LoginFlow(context.Background(), sender, LoginOptions{LoginURL: "http://x.example/login", User: "u", Pass: ""}); err == nil {
		t.Fatal("parolasız akış reddedilmeli")
	}
	if _, err := LoginFlow(context.Background(), sender, LoginOptions{LoginURL: "ftp://x.example/login", User: "u", Pass: "p"}); err == nil {
		t.Fatal("http(s) dışı login URL reddedilmeli")
	}
}

// TestMergeMissingExplicitWins: açık kimlik beyanı login türevini ad bazında yener.
func TestMergeMissingExplicitWins(t *testing.T) {
	c := New()
	if err := c.ParseCookie("session=explicit; tema=koyu"); err != nil {
		t.Fatal(err)
	}
	if err := c.ParseAuthHeader("Cookie: hdr-session=hdr"); err != nil {
		t.Fatal(err)
	}
	src := New()
	src.Cookies["session"] = "login-turevi"
	src.Cookies["sid"] = "yeni"
	src.Cookies["hdr-session"] = "login-turevi-2"
	src.hasAuth = true // login akışı bağlamı HasAuth ile doğar
	c.MergeMissing(src)

	if c.Cookies["session"] != "explicit" {
		t.Fatalf("açık cookie ezildi: %v", c.Cookies)
	}
	if c.Cookies["sid"] != "yeni" {
		t.Fatalf("eksik cookie eklenmedi: %v", c.Cookies)
	}
	if _, exists := c.Cookies["hdr-session"]; exists {
		t.Fatalf("açık Cookie header adı haritaya eklenmemeli: %v", c.Cookies)
	}
	hm := c.HeaderMap()
	if !strings.Contains(hm["Cookie"], "hdr-session=hdr") || !strings.Contains(hm["Cookie"], "sid=yeni") {
		t.Fatalf("birleşik Cookie header beklenen adları taşımalı: %q", hm["Cookie"])
	}
	if !c.HasAuth() {
		t.Fatal("merge sonrası HasAuth true olmalı")
	}
}
