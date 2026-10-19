// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Login akışı (P2.6): kullanıcı-beyanlı login formundan gerçek oturum kurar.
// What: GET form → alan seçimi → policy sender üzerinden POST → redirect takibi
// → doğrulama GET'i → dürüst Success/Reason kararı.
// Why: requires_auth plugin'leri yalnızca gerçek bir oturumla açılmalı; kimlik
// bilgisi asla Reason/Result/log'a sızmaz ve başarı asla durum kodundan
// uydurulmaz (kontrolsüz iyimserlik yok).
package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/plugin"
)

const (
	// DefaultLoginMaxAttempts kilitlenme güvenliği için varsayılan deneme sayısıdır.
	DefaultLoginMaxAttempts = 2
	// HardLoginMaxAttempts hiçbir koşulda aşılmaz (hesap kilidi riski).
	HardLoginMaxAttempts = 3
	// maxLoginRedirects login akışında izlenen en fazla redirect sayısıdır.
	maxLoginRedirects = 5
)

// Login reason sözlüğü: Result.Reason daima bu değerlerden biridir.
const (
	// ReasonSuccess: doğrulanmış oturum (Success=true).
	ReasonSuccess = "success"
	// ReasonLoginFailed: POST sonrası oturum kanıtı yok (yanlış kimlik/red).
	ReasonLoginFailed = "login-failed"
	// Reason2FADetected: OTP/MFA/CAPTCHA sayfası algılandı (tekrar YOK).
	Reason2FADetected = "2fa-detected"
	// ReasonUnverifiedSession: cookie set edildi ama doğrulama belirsiz.
	ReasonUnverifiedSession = "unverified-session"
	// ReasonNoPasswordForm: sayfada type=password içeren form yok.
	ReasonNoPasswordForm = "no-password-form"
	// ReasonNoUserField: kullanıcı alanı seçilemedi.
	ReasonNoUserField = "no-user-field"
	// ReasonLoginFormGET: login formu GET ile gönderiyor (parola URL'e düşer → red).
	ReasonLoginFormGET = "login-form-get"
	// ReasonUnsupportedEnctype: text/plain gibi desteklenmeyen form kodlaması.
	ReasonUnsupportedEnctype = "unsupported-enctype"
	// ReasonRedirectDowngrade: https→http downgrade izlenmedi (fail-closed).
	ReasonRedirectDowngrade = "redirect-downgrade-blocked"
	// ReasonRequestFailed: istekler tamamlanamadı (ağ/politika dışı hata).
	ReasonRequestFailed = "request-failed"
)

// LoginOptions login akışı girdisidir (CLI bayrakları → buraya).
// What: URL'ler + tek kimlik seti + alan override'ları + deneme tavanı.
// Why: Tek set kuralı: parola denemesi (guessing) YOK; MaxAttempts kilit
// güvenliği için sınırlıdır.
type LoginOptions struct {
	// LoginURL login formunun bulunduğu sayfadır (GET).
	LoginURL string
	// VerifyURL opsiyonel doğrulama hedefidir; boşsa login action target,
	// o da yoksa LoginURL kullanılır.
	VerifyURL string
	// User/Pass tek kimlik setidir; asla loglanmaz.
	User string
	Pass string
	// UserField/PassField alan adı override'larıdır (boşsa otomatik seçim).
	UserField string
	PassField string
	// MaxAttempts POST deneme tavanıdır (varsayılan 2, üst sınır 3).
	MaxAttempts int
}

// Sender tek bir HTTP isteğini politika hattından geçirerek gönderen fonksiyondur.
// What: Engine'in canlı plugin/browser hattıyla aynı imza (status, header, body).
// Why: Login akışı asla ham istemci kullanmaz; scope/bütçe/rate burada uygulanır.
type Sender func(ctx context.Context, method, rawURL string, headers map[string]string, payload []byte) (status int, respHeaders http.Header, body string, err error)

// Result login akışı sonucudur (kimlik değeri taşımaz).
// What: Oturum bağlamı + sayaçlar + dürüst Reason + kullanılan alan adları.
// Why: Kimlik değerleri Context cookie'lerinden ibarettir; User/Pass asla
// Result içine kopyalanmaz.
type Result struct {
	// Context başarılı oturumun tarama bağlamıdır (yalnızca Success'te dolu).
	Context *Context
	// Cookies kurulan bağlamdaki cookie sayısıdır (başarısızlıkta gözlenen sayı).
	Cookies int
	// Attempts yapılan POST denemesi sayısıdır (≤ HardLoginMaxAttempts).
	Attempts int
	// Success yalnızca doğrulanmış oturumda true'dur.
	Success bool
	// Reason yukarıdaki Reason* sabitlerinden biridir.
	Reason string
	// UsedFields kullanılan alan adlarıdır ("userField,passField"); değer yok.
	UsedFields string
}

// login redirect downgrade'i için iç sentinel.
var errLoginDowngrade = errors.New("login: redirect scheme downgrade blocked")

// userFieldRe kullanıcı alanı adı sezgisidir (task şartnamesi).
var userFieldRe = regexp.MustCompile(`(?i)(user|email|login|account|mail)`)

// sessionCookieRe oturum-benzeri cookie adı sezgisidir.
var sessionCookieRe = regexp.MustCompile(`(?i)(sess|sid|token|auth|jwt|login|jsession|phpsessid)`)

// passwordInputRe yanıtta parola alanı arar (doğrulama kapısı).
var passwordInputRe = regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']?password`)

// otpFieldRe 2FA/CAPTCHA alan adlarını nitelik bağlamında arar.
var otpFieldRe = regexp.MustCompile(`(?i)(name|id|placeholder|aria-label)\s*=\s*["'][^"']*(otp|2fa|mfa|captcha|totp|verification\s*code)[^"']*["']`)

// controlValueRe kontrol normalizasyonunda value içeriklerini boşaltır.
var controlValueRe = regexp.MustCompile(`(?i)\bvalue\s*=\s*("[^"]*"|'[^']*')`)

// controlSpaceRe kontrol normalizasyonunda boşlukları sadeleştirir.
var controlSpaceRe = regexp.MustCompile(`\s+`)

// LoginFlow kullanıcı-beyanlı login formundan oturum kurmayı dener.
// What: Her denemede taze GET (taze token) + form POST + redirect takibi +
// doğrulama GET'i; başarı yalnızca doğrulama kanıtıyla ilan edilir.
// Why: Kimlik tahmini yok; tek set, sınırlı deneme, kapsam/bütçe/rate policy
// sender'da kalır. Dönüş error'u yalnızca akışı sürdürememe (istek/politika)
// durumudur; mantıksal başarısızlık Result.Reason ile dürüstçe raporlanır.
func LoginFlow(ctx context.Context, sender Sender, opts LoginOptions) (Result, error) {
	if sender == nil {
		return Result{}, fmt.Errorf("login: sender zorunlu")
	}
	loginURL, err := normalizeLoginURL(opts.LoginURL)
	if err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(opts.User) == "" || opts.Pass == "" {
		// Parola/parolasız giriş denemesi yapılmaz (tek set kuralı).
		return Result{}, fmt.Errorf("login: kullanıcı ve parola zorunlu")
	}
	maxAttempts := opts.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultLoginMaxAttempts
	}
	if maxAttempts > HardLoginMaxAttempts {
		maxAttempts = HardLoginMaxAttempts
	}

	var last Result
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		res, aerr := loginAttempt(ctx, sender, opts, loginURL)
		res.Attempts = attempt
		if aerr != nil {
			if isFatalLoginError(aerr) {
				return res, aerr
			}
			lastErr = aerr
			continue
		}
		// 2FA/CAPTCHA'da tekrar YOK (hesap kilidi/uyarı riski).
		if res.Success || res.Reason == Reason2FADetected {
			return res, nil
		}
		last = res
		lastErr = nil
	}
	if last.Reason != "" {
		return last, nil
	}
	return Result{Attempts: maxAttempts, Reason: ReasonRequestFailed}, lastErr
}

// loginAttempt tek bir GET→POST→verify denemesidir.
// What: Taze login sayfası + taze token'larla POST + dürüst doğrulama.
// Why: CSRF token'ı her denemede yeniden okunur; başarı yalnızca doğrulama
// farkı + parola-alanı yokluğu ile ilan edilir.
func loginAttempt(ctx context.Context, sender Sender, opts LoginOptions, loginURL *url.URL) (Result, error) {
	jar := newLoginJar()

	// 1) Anonim login sayfası (taze token kaynağı).
	_, _, pageBody, pageURL, _, err := loginDo(ctx, sender, jar, http.MethodGet, loginURL.String(), htmlGetHeaders(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("login: login sayfası alınamadı: %w", err)
	}

	forms := discovery.ExtractForms(pageURL, []byte(pageBody))
	form, ok := pickLoginForm(forms)
	if !ok {
		return Result{Reason: ReasonNoPasswordForm}, nil
	}
	if !strings.EqualFold(form.Method, http.MethodPost) {
		return Result{Reason: ReasonLoginFormGET}, nil
	}
	if strings.Contains(strings.ToLower(form.Enctype), "text/plain") {
		return Result{Reason: ReasonUnsupportedEnctype}, nil
	}
	userField := pickUserField(form, opts.UserField)
	if userField == "" {
		return Result{Reason: ReasonNoUserField}, nil
	}
	passField := strings.TrimSpace(opts.PassField)
	if passField == "" {
		passField = passwordFieldName(form)
	}
	if passField == "" {
		return Result{Reason: ReasonNoPasswordForm}, nil
	}
	used := userField + "," + passField

	// 2) Tüm diğer alanlar (hidden token dahil) sayfadan taze değerleriyle korunur.
	values := make(map[string]string, len(form.Fields))
	for _, f := range form.Fields {
		if f.InputType == "file" {
			continue // dosya alanı asla uydurulmaz
		}
		if strings.EqualFold(f.Name, userField) || strings.EqualFold(f.Name, passField) {
			continue
		}
		values[f.Name] = f.Value
	}
	values[userField] = opts.User
	values[passField] = opts.Pass

	contentType, payload, err := encodeLoginForm(form.Enctype, values)
	if err != nil {
		return Result{Reason: ReasonUnsupportedEnctype}, nil
	}
	postHeaders := map[string]string{
		"Content-Type": contentType,
		"Accept":       "text/html,*/*",
	}
	_, _, postBody, _, postCookieNames, err := loginDo(ctx, sender, jar, http.MethodPost, form.ActionURL, postHeaders, payload)
	if err != nil {
		if errors.Is(err, errLoginDowngrade) {
			return Result{Reason: ReasonRedirectDowngrade, UsedFields: used}, nil
		}
		return Result{}, fmt.Errorf("login: giriş isteği başarısız: %w", err)
	}
	postCookieNames = uniqueCookieNames(postCookieNames)
	postCookies := len(postCookieNames)
	sessionish := sessionCookieNames(postCookieNames) > 0

	// 3) 2FA/CAPTCHA kapısı: POST yanıtı doğrudan OTP/MFA sayfasıysa tekrar yok.
	if otpDetected(postBody) {
		return Result{Reason: Reason2FADetected, UsedFields: used}, nil
	}

	// 4) Doğrulama hedefi: --login-verify-url > form action > login URL.
	verifyRaw := strings.TrimSpace(opts.VerifyURL)
	if verifyRaw == "" {
		verifyRaw = form.ActionURL
	}
	if verifyRaw == "" {
		verifyRaw = loginURL.String()
	}
	verifyURL, verr := normalizeLoginURL(verifyRaw)
	if verr != nil {
		return Result{}, fmt.Errorf("login: doğrulama URL'i geçersiz: %w", verr)
	}

	// 5) Anonim kontrol: verify hedefi login sayfasıyla aynıysa sayfa gövdesi
	// kontrol sayılır; farklıysa anonim bir GET ile kontrol alınır.
	controlBody := pageBody
	if !sameLoginURL(verifyURL, loginURL) {
		_, _, cBody, _, _, cerr := loginDo(ctx, sender, newLoginJar(), http.MethodGet, verifyURL.String(), htmlGetHeaders(), nil)
		if cerr != nil {
			if isFatalLoginError(cerr) {
				return Result{}, cerr
			}
			// Kontrol alınamadıysa "farklı" iddiası kurulamaz → dürüst tavan.
			reason := ReasonLoginFailed
			if sessionish {
				reason = ReasonUnverifiedSession
			}
			return Result{Reason: reason, Cookies: postCookies, UsedFields: used}, nil
		}
		controlBody = cBody
	}

	// 6) Oturumlu doğrulama GET'i (cookie jar taşınır).
	_, _, verifyBody, _, _, verr2 := loginDo(ctx, sender, jar, http.MethodGet, verifyURL.String(), htmlGetHeaders(), nil)
	if verr2 != nil {
		return Result{}, fmt.Errorf("login: doğrulama isteği başarısız: %w", verr2)
	}
	if otpDetected(verifyBody) {
		return Result{Reason: Reason2FADetected, UsedFields: used}, nil
	}

	authenticated := !passwordInputRe.MatchString(verifyBody) &&
		normalizeControl(verifyBody) != normalizeControl(controlBody)
	if !authenticated {
		reason := ReasonLoginFailed
		if sessionish {
			// Oturum-benzeri cookie set edildi ama doğrulama belirsiz:
			// başarı İLAN EDİLMEZ (dürüst tavan).
			reason = ReasonUnverifiedSession
		}
		return Result{Reason: reason, Cookies: postCookies, UsedFields: used}, nil
	}

	// 7) Başarı: yalnızca akış host'larının cookie'leri tarama bağlamına girer.
	hosts := map[string]bool{
		strings.ToLower(loginURL.Hostname()): true,
	}
	if u, err := url.Parse(form.ActionURL); err == nil && u.Hostname() != "" {
		hosts[strings.ToLower(u.Hostname())] = true
	}
	hosts[strings.ToLower(verifyURL.Hostname())] = true
	cookies := jar.cookiesForHosts(hosts)
	actx := New()
	for name, value := range cookies {
		if strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		actx.Cookies[name] = value
	}
	if len(actx.Cookies) > 0 {
		actx.hasAuth = true
	}
	return Result{
		Context:    actx,
		Cookies:    len(actx.Cookies),
		Success:    true,
		Reason:     ReasonSuccess,
		UsedFields: used,
	}, nil
}

// isFatalLoginError kapsam/politika ihlalini anında durdurur (fail-closed).
// What: plugin sentinel'lerine errors.Is ile bakar (sarmalama güvenli).
// Why: Kapsam/politika ihlalinde tekrar denemek anlamsız ve gürültülüdür;
// engine bu hatayı scan'i durdurmak için yeniden sınar.
func isFatalLoginError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, plugin.ErrScopeViolation) || errors.Is(err, plugin.ErrPolicyViolation)
}

// normalizeLoginURL login/verify URL'ini doğrular (http/https + host + userinfo yok).
func normalizeLoginURL(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("login: URL zorunlu")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("login: geçersiz URL %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("login: URL http(s) olmalı (got %q)", u.Scheme)
	}
	if strings.TrimSpace(u.Host) == "" {
		return nil, fmt.Errorf("login: URL host içermeli %q", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("login: URL userinfo içermemeli")
	}
	return u, nil
}

// sameLoginURL iki URL'i fragment'sız kanonik biçimde karşılaştırır.
func sameLoginURL(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	ca, cb := *a, *b
	ca.Fragment, cb.Fragment = "", ""
	if ca.Path == "" {
		ca.Path = "/"
	}
	if cb.Path == "" {
		cb.Path = "/"
	}
	return ca.String() == cb.String()
}

// pickLoginForm type=password alanı içeren ilk formu seçer.
func pickLoginForm(forms []discovery.Form) (discovery.Form, bool) {
	for _, f := range forms {
		for _, fld := range f.Fields {
			if strings.EqualFold(fld.InputType, "password") {
				return f, true
			}
		}
	}
	return discovery.Form{}, false
}

// pickUserField kullanıcı alanını seçer: override > ad-deseni ilk text/email >
// ilk text/email (dokümante edilmiş ikinci kademe).
func pickUserField(form discovery.Form, override string) string {
	if v := strings.TrimSpace(override); v != "" {
		return v
	}
	for _, f := range form.Fields {
		if f.InputType != "text" && f.InputType != "email" {
			continue
		}
		if userFieldRe.MatchString(f.Name) {
			return f.Name
		}
	}
	for _, f := range form.Fields {
		if f.InputType == "text" || f.InputType == "email" {
			return f.Name
		}
	}
	return ""
}

// passwordFieldName ilk type=password alanının adını döner.
func passwordFieldName(form discovery.Form) string {
	for _, f := range form.Fields {
		if strings.EqualFold(f.InputType, "password") {
			return f.Name
		}
	}
	return ""
}

// encodeLoginForm gövdeyi form enctype'ına göre üretir (engine gövde kurucusu
// konvansiyonları: urlencoded veya multipart, adlar sıralı).
func encodeLoginForm(enctype string, values map[string]string) (string, []byte, error) {
	if strings.Contains(strings.ToLower(enctype), "multipart/form-data") {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		contentType := w.FormDataContentType()
		names := make([]string, 0, len(values))
		for k := range values {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if err := w.WriteField(k, values[k]); err != nil {
				return "", nil, err
			}
		}
		if err := w.Close(); err != nil {
			return "", nil, err
		}
		return contentType, buf.Bytes(), nil
	}
	form := url.Values{}
	for k, v := range values {
		form.Set(k, v)
	}
	return "application/x-www-form-urlencoded", []byte(form.Encode()), nil
}

// htmlGetHeaders HTML GET isteklerinin ortak başlıklarıdır.
func htmlGetHeaders() map[string]string {
	return map[string]string{"Accept": "text/html,application/xhtml+xml,*/*"}
}

// otpDetected yanıtta OTP/MFA/CAPTCHA alanı arar (tekrar yasağı tetikleyicisi).
func otpDetected(body string) bool {
	return otpFieldRe.MatchString(body)
}

// normalizeControl kontrol karşılaştırması için değişken nonce değerlerini
// (value="...") ve boşluk farklarını nötrler.
func normalizeControl(body string) string {
	scrubbed := controlValueRe.ReplaceAllString(body, `value=""`)
	return strings.TrimSpace(controlSpaceRe.ReplaceAllString(scrubbed, " "))
}

// loginDo bir isteği gönderir ve policy-güvenli redirect'leri kendisi izler.
// What: Her hop sırayla sender'dan geçer (scope/rate/bütçe her hop'ta yeniden
// uygulanır); 301/302/303 GET'e döner, 307/308 metot+gövdeyi korur; https→http
// downgrade asla izlenmez; dönen isim listesi zincirde set edilen cookie'lerdir.
// Why: Set-Cookie her hop'ta görülebilmeli (oturum cookie'si 302 üzerinde
// gelir) ve downgrade kararı akışın kendi elinde olmalı.
func loginDo(ctx context.Context, sender Sender, jar *loginJar, method, rawURL string, headers map[string]string, payload []byte) (int, http.Header, string, string, []string, error) {
	curURL := rawURL
	curMethod := method
	curBody := payload
	curHeaders := cloneLoginHeaders(headers)
	var setCookies []string
	for hop := 0; ; hop++ {
		u, err := url.Parse(curURL)
		if err != nil {
			return 0, nil, "", curURL, setCookies, fmt.Errorf("login: URL ayrıştırılamadı: %w", err)
		}
		reqHeaders := cloneLoginHeaders(curHeaders)
		if c := jar.cookieHeader(u.Hostname()); c != "" {
			if existing := strings.TrimSpace(reqHeaders["Cookie"]); existing != "" {
				reqHeaders["Cookie"] = existing + "; " + c
			} else {
				reqHeaders["Cookie"] = c
			}
		}
		status, respHeaders, respBody, err := sender(ctx, curMethod, curURL, reqHeaders, curBody)
		if err != nil {
			return 0, nil, "", curURL, setCookies, err
		}
		setCookies = append(setCookies, jar.absorb(u.Hostname(), respHeaders)...)
		if !isLoginRedirect(status) || hop >= maxLoginRedirects {
			return status, respHeaders, respBody, curURL, setCookies, nil
		}
		loc := ""
		if respHeaders != nil {
			loc = strings.TrimSpace(respHeaders.Get("Location"))
		}
		if loc == "" {
			return status, respHeaders, respBody, curURL, setCookies, nil
		}
		next, err := u.Parse(loc)
		if err != nil {
			return status, respHeaders, respBody, curURL, setCookies, nil
		}
		switch strings.ToLower(next.Scheme) {
		case "http", "https":
		default:
			// Desteklenmeyen şema: takip edilmez, son yanıt döner.
			return status, respHeaders, respBody, curURL, setCookies, nil
		}
		if strings.EqualFold(u.Scheme, "https") && strings.EqualFold(next.Scheme, "http") {
			return 0, nil, "", curURL, setCookies, errLoginDowngrade
		}
		if status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect {
			curURL = next.String()
			continue
		}
		curMethod = http.MethodGet
		curBody = nil
		curHeaders = htmlGetHeaders()
		curURL = next.String()
	}
}

// isLoginRedirect 3xx yönlendirme kodlarını bildirir.
func isLoginRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// cloneLoginHeaders haritayı kopyalar (çağıran mutasyonu izole).
func cloneLoginHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// loginJar akış-içi cookie deposudur: cookie YALNIZCA onu set eden host'a
// geri gönderilir (cross-host sızıntı yok; Domain paylaşımı bilinçli olarak
// desteklenmez — güvenli taraf).
type loginJar struct {
	byHost map[string]map[string]string
}

// newLoginJar boş jar döner.
func newLoginJar() *loginJar {
	return &loginJar{byHost: make(map[string]map[string]string)}
}

// absorb yanıt Set-Cookie'lerini kaydeder; kaydedilen cookie adlarını döner.
// Süresi geçmiş/silinen cookie'ler düşürülür.
func (j *loginJar) absorb(host string, h http.Header) []string {
	if j == nil || h == nil {
		return nil
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil
	}
	resp := http.Response{Header: h}
	var added []string
	for _, c := range resp.Cookies() {
		if c == nil || strings.TrimSpace(c.Name) == "" {
			continue
		}
		if c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now())) {
			if m, ok := j.byHost[host]; ok {
				delete(m, c.Name)
			}
			continue
		}
		m, ok := j.byHost[host]
		if !ok {
			m = make(map[string]string)
			j.byHost[host] = m
		}
		m[c.Name] = c.Value
		added = append(added, c.Name)
	}
	return added
}

// cookieHeader host için "n=v; ..." başlığını (adlar sıralı) döner.
func (j *loginJar) cookieHeader(host string) string {
	if j == nil {
		return ""
	}
	m := j.byHost[strings.ToLower(strings.TrimSpace(host))]
	if len(m) == 0 {
		return ""
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, n+"="+m[n])
	}
	return strings.Join(parts, "; ")
}

// cookiesForHosts verilen host kümesinin cookie'lerini tek haritada toplar.
// Aynı adlı cookie birden fazla host'ta set edildiyse host sırası deterministik
// olacak şekilde (sıralı) son değer kazanır.
func (j *loginJar) cookiesForHosts(hosts map[string]bool) map[string]string {
	out := make(map[string]string)
	if j == nil {
		return out
	}
	keys := make([]string, 0, len(j.byHost))
	for h := range j.byHost {
		if hosts[h] {
			keys = append(keys, h)
		}
	}
	sort.Strings(keys)
	for _, h := range keys {
		for name, value := range j.byHost[h] {
			out[name] = value
		}
	}
	return out
}

// sessionCookieNames verilen cookie adı listesinden oturum-benzeri olanları sayar.
func sessionCookieNames(names []string) int {
	n := 0
	for _, name := range names {
		if sessionCookieRe.MatchString(name) {
			n++
		}
	}
	return n
}

// uniqueCookieNames adları tekilleştirir (zincir boyunca tekrar set edilebilir).
func uniqueCookieNames(names []string) []string {
	if len(names) == 0 {
		return names
	}
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}
