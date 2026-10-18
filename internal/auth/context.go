// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package auth scan-scoped kimlik doğrulama bağlamıdır (P2.5).
// What: --auth-header/--cookie/--basic-auth bayraklarının parse + taşıma + redact tek kaynağı.
// Why: requires_auth plugin'ler açık kimlik bilgisi olmadan çalışmaz; kimlik bilgisi
// asla bulgu/rapora sızmamalı ve CRLF enjeksiyonuna kapalı olmalı (fail-closed).
package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Context tarama boyunca gönderilen kimlik bilgilerini taşır.
// What: Header + cookie + basic-auth üçlüsünün normalize edilmiş hali.
// Why: Engine/probe/cli aynı struct'ı paylaşır; redact tek noktadadır.
type Context struct {
	// Headers "Name: value" çiftleri (--auth-header, tekrarlanabilir).
	Headers map[string]string
	// Cookies cookie adı → değer (--cookie, tekrarlanabilir).
	Cookies map[string]string
	// BasicUser/BasicPass --basic-auth "kullanıcı:parola" ayrıştırmasıdır.
	BasicUser string
	BasicPass string
	// hasAuth en az bir kimlik bilgisi var mı (HasAuth kapısı).
	hasAuth bool
}

// New boş bağlam döner.
func New() *Context {
	return &Context{Headers: make(map[string]string), Cookies: make(map[string]string)}
}

// HasAuth en az bir kimlik bilgisi tanımlı mı (engine requires_auth kapısı).
func (c *Context) HasAuth() bool {
	if c == nil {
		return false
	}
	return c.hasAuth
}

// ParseAuthHeader "--auth-header" bayrağını ayrıştırır ("Name: value").
// What: Tek header bildirimi; tekrarlı çağrı biriktirir.
// Why: Erken fail-closed: CRLF veya boş ad/değer reddedilir.
func (c *Context) ParseAuthHeader(raw string) error {
	name, value, err := splitHeader(raw)
	if err != nil {
		return err
	}
	if c.Headers == nil {
		c.Headers = make(map[string]string)
	}
	c.Headers[name] = value
	c.hasAuth = true
	return nil
}

// ParseCookie "--cookie" bayrağını ayrıştırır ("a=b" veya "a=b; c=d").
// What: Cookie dizesindeki her çifti bağlama ekler.
// Why: Tarayıcı-dışı istemciler oturumu böyle taşır; değerler ham saklanır.
func (c *Context) ParseCookie(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("auth: boş --cookie")
	}
	if strings.ContainsAny(trimmed, "\r\n") {
		return fmt.Errorf("auth: --cookie CRLF içeremez")
	}
	added := false
	for _, part := range strings.Split(trimmed, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !ok || name == "" || value == "" {
			return fmt.Errorf("auth: --cookie %q a=b biçiminde olmalı", part)
		}
		if strings.ContainsAny(name+value, "\r\n") {
			return fmt.Errorf("auth: --cookie CRLF içeremez")
		}
		if c.Cookies == nil {
			c.Cookies = make(map[string]string)
		}
		c.Cookies[name] = value
		added = true
	}
	if !added {
		return fmt.Errorf("auth: boş --cookie")
	}
	c.hasAuth = true
	return nil
}

// ParseBasicAuth "--basic-auth" bayrağını ayrıştırır ("kullanıcı:parola").
// What: Basic kimliğini kullanıcı/parola çiftine böler.
// Why: Parola boş olabilir ama kullanıcı zorunludur; ayraçsız girdi reddedilir.
func (c *Context) ParseBasicAuth(raw string) error {
	user, pass, ok := strings.Cut(raw, ":")
	user = strings.TrimSpace(user)
	if strings.ContainsAny(raw, "\r\n") {
		return fmt.Errorf("auth: --basic-auth CRLF içeremez")
	}
	if !ok || user == "" {
		return fmt.Errorf("auth: --basic-auth kullanıcı:parola biçiminde olmalı")
	}
	c.BasicUser = user
	c.BasicPass = pass
	c.hasAuth = true
	return nil
}

// ApplyToRequest giden isteğe kimlik bilgilerini uygular (probe/taşıyıcı kullanır).
// What: Authorization/basic header + Cookie header birleşimi; istekteki mevcut
// değerler korunur (açık istek başlığı bağlamı ezmez).
// Why: Tek uygulama noktası; her gönderici aynı önceliği uygular.
func (c *Context) ApplyToRequest(req *http.Request) {
	if c == nil || req == nil || !c.hasAuth {
		return
	}
	for name, value := range c.Headers {
		if strings.TrimSpace(req.Header.Get(name)) == "" {
			req.Header.Set(name, value)
		}
	}
	if c.BasicUser != "" && strings.TrimSpace(req.Header.Get("Authorization")) == "" {
		creds := base64.StdEncoding.EncodeToString([]byte(c.BasicUser + ":" + c.BasicPass))
		req.Header.Set("Authorization", "Basic "+creds)
	}
	if len(c.Cookies) > 0 {
		var parts []string
		if existing := strings.TrimSpace(req.Header.Get("Cookie")); existing != "" {
			parts = append(parts, existing)
		}
		names := make([]string, 0, len(c.Cookies))
		for n := range c.Cookies {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			parts = append(parts, n+"="+c.Cookies[n])
		}
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}
}

// HeaderMap probe.Client ExtraHeaders girdisini üretir (değerler hamdır).
// What: Bağlamın header görünümü; basic-auth Authorization'a dönüşür.
// Why: Taşıyıcı-agnostik: probe.Send öncesi Options'a gömülür.
func (c *Context) HeaderMap() map[string]string {
	if c == nil || !c.hasAuth {
		return nil
	}
	out := make(map[string]string, len(c.Headers)+2)
	for k, v := range c.Headers {
		out[k] = v
	}
	if c.BasicUser != "" {
		if _, ok := out["Authorization"]; !ok {
			creds := base64.StdEncoding.EncodeToString([]byte(c.BasicUser + ":" + c.BasicPass))
			out["Authorization"] = "Basic " + creds
		}
	}
	if len(c.Cookies) > 0 {
		names := make([]string, 0, len(c.Cookies))
		for n := range c.Cookies {
			names = append(names, n)
		}
		sort.Strings(names)
		var parts []string
		if existing, ok := out["Cookie"]; ok && strings.TrimSpace(existing) != "" {
			parts = append(parts, existing)
		}
		for _, n := range names {
			parts = append(parts, n+"="+c.Cookies[n])
		}
		out["Cookie"] = strings.Join(parts, "; ")
	}
	return out
}

// Redacted log/rapor amaçlı maskeli özet döner (değerler asla yazılmaz).
// What: Yalnızca adlar + var/yok bilgisi.
// Why: Kimlik bilgisi stdout/rapora sızmamalı (§14).
func (c *Context) Redacted() string {
	if c == nil || !c.hasAuth {
		return "auth: none"
	}
	var names []string
	for n := range c.Headers {
		names = append(names, n)
	}
	sort.Strings(names)
	cookies := make([]string, 0, len(c.Cookies))
	for n := range c.Cookies {
		cookies = append(cookies, n)
	}
	sort.Strings(cookies)
	basic := "no"
	if c.BasicUser != "" {
		basic = "yes"
	}
	return fmt.Sprintf("auth: headers=[%s] cookies=[%s] basic=%s",
		strings.Join(names, ","), strings.Join(cookies, ","), basic)
}

// splitHeader "Name: value" ayrıştırır (CRLF fail-closed).
func splitHeader(raw string) (string, string, error) {
	name, value, ok := strings.Cut(raw, ":")
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if !ok || name == "" || value == "" {
		return "", "", fmt.Errorf("auth: --auth-header Ad: değer biçiminde olmalı (got %q)", raw)
	}
	if strings.ContainsAny(name+value, "\r\n") {
		return "", "", fmt.Errorf("auth: --auth-header CRLF içeremez")
	}
	// Ad jeton olmalı (boşluk/özel karakter yok).
	for _, r := range name {
		if r <= 32 || r >= 127 || r == ':' {
			return "", "", fmt.Errorf("auth: geçersiz header adı %q", name)
		}
	}
	return http.CanonicalHeaderKey(name), value, nil
}
