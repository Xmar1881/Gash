// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package flow keşfedilen çok-adımlı iş akışlarını temiz bir oturumla
// yeniden oynatır ve tek alanı mutasyona uğratarak alt adımlardaki etkiyi
// ölçer.
//
// What: Form tabanlı akış keşfi (DiscoverFlow), taze token'lı replay
// (ReplayFlow), hata/yansıma/diferansiyel değerlendirmesi (Evaluate) ve
// oturumsuz doğrudan erişim ekranı (ProbeFlowBypass).
// Why: Tek istekli fuzz'lar çok-adımlı sihirbazlarda sunucu doğrulaması,
// CSRF kapısı ve ara adım durumunda düşer; gerçek akış sırayla
// tekrarlanmadan sink'e ulaşılamaz.
package flow

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/discovery"
)

// Sender auth.Sender ile aynı sözleşmedir; motor probe.Client'ı sarar.
type Sender func(ctx context.Context, method, rawURL string, headers map[string]string, payload []byte) (status int, respHeaders http.Header, body string, err error)

// Akış sınırları.
const (
	// DefaultMaxSteps keşfin varsayılan adım tavanıdır.
	DefaultMaxSteps = 4
	// HardMaxSteps adım sayısının kesin üst sınırıdır.
	HardMaxSteps = 6
	// DefaultMaxRequests akış başına toplam istek bütçesidir.
	DefaultMaxRequests = 120
	// MaxRedirects manuel izlenen yönlendirme tavanıdır.
	MaxRedirects = 5
	// materialDifference altında kalan benzerlik maddi sapma sayılır.
	materialDifference = 0.90
	// bypassSimilarity doğrudan erişimin aynı içerik sayılma eşiğidir.
	bypassSimilarity = 0.95
	// maxSimilarityTokens benzerlik hesabında örneklenen token tavanıdır.
	maxSimilarityTokens = 20000
)

// ErrBudget akış istek bütçesinin tükendiğini bildirir.
var ErrBudget = errors.New("flow request budget exhausted")

// ErrRedirectDowngrade https->http yönlendirmesinin engellendiğini bildirir.
var ErrRedirectDowngrade = errors.New("flow redirect downgrade blocked")

// Options akış keşfi/replay ayarlarıdır.
type Options struct {
	SeedURL     string
	MaxSteps    int
	MaxRequests int
	// SeedCookies temel oturum cookie'leridir (cfg.Auth). Flow kendi
	// jar'ını kurar; açık Cookie başlığı probe.ExtraHeaders'ı ezdiği için
	// taban cookie'ler jar'a tohumlanır.
	SeedCookies map[string]string
}

// Budget akış başına istek sayacıdır.
type Budget struct {
	Max  int
	Used int
}

// Take bir istek hakkı tüketir; bütçe yoksa true döner.
func (b *Budget) Take() bool {
	if b == nil {
		return true
	}
	if b.Max > 0 && b.Used >= b.Max {
		return false
	}
	b.Used++
	return true
}

// Exhausted bütçe tükendi mi.
func (b *Budget) Exhausted() bool {
	return b != nil && b.Max > 0 && b.Used >= b.Max
}

// Remaining kalan istek hakkıdır.
func (b *Budget) Remaining() int {
	if b == nil || b.Max <= 0 {
		return DefaultMaxRequests
	}
	if b.Used >= b.Max {
		return 0
	}
	return b.Max - b.Used
}

// Step keşfedilen tek iş akışı adımıdır.
type Step struct {
	Index     int
	PageURL   string
	ActionURL string
	Method    string
	Enctype   string
	Fields    []discovery.FormField
	FormIndex int
	ResultURL string
	Status    int
	Signature string
}

// Baseline temiz akışın maskelenmiş/normalize gövdeleridir.
type Baseline struct {
	// StepBodies normalize edilmiş gövdelerdir (benzerlik için).
	StepBodies []string
	// StepRawBodies ham gövdelerdir (oracle kontrolü için).
	StepRawBodies  []string
	FinalSignature string
	FinalBody      string
	FinalRaw       string
	FinalURL       string
}

// Flow keşfedilmiş akıştır.
type Flow struct {
	SeedURL  string
	Steps    []Step
	Baseline Baseline
	Budget   *Budget
	Stopped  string
}

// Payload mutasyon türüdür.
type Payload struct {
	Value string
	Kind  string
	// Marker XSS kanaryasının benzersiz işaretidir (diğer türlerde boş).
	Marker string
}

// Payload türleri.
const (
	PayloadSQLi      = "sqli"
	PayloadXSSHTML   = "xss-html"
	PayloadXSSAttr   = "xss-attr"
	PayloadXSSScript = "xss-script"
)

// StepResponse replay sırasında tek adımın yanıtıdır.
type StepResponse struct {
	Index      int
	URL        string
	Status     int
	Headers    http.Header
	Body       string
	Normalized string
}

// Replay tek mutasyonlu akış koşusudur.
type Replay struct {
	StepIndex int
	Field     string
	Payload   Payload
	Responses []StepResponse
	Final     StepResponse
	Stopped   string
	// Requests bu replay'in tükettiği istek sayısıdır.
	Requests int
}

// client akış-yerel cookie jar + manuel redirect izleyicisidir.
type client struct {
	send   Sender
	jar    http.CookieJar
	budget *Budget
}

func newClient(send Sender, seedURL string, seedCookies map[string]string, budget *Budget) *client {
	jar, _ := cookiejar.New(nil)
	if u, err := url.Parse(seedURL); err == nil && len(seedCookies) > 0 {
		root := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}
		cookies := make([]*http.Cookie, 0, len(seedCookies))
		names := make([]string, 0, len(seedCookies))
		for name := range seedCookies {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			cookies = append(cookies, &http.Cookie{Name: name, Value: seedCookies[name], Path: "/"})
		}
		jar.SetCookies(root, cookies)
	}
	return &client{send: send, jar: jar, budget: budget}
}

type response struct {
	Status  int
	Headers http.Header
	Body    string
	URL     string
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// do tek isteği jar cookie'leri + manuel redirect izleme ile gönderir.
func (c *client) do(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return response{}, fmt.Errorf("flow parse %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return response{}, fmt.Errorf("flow scheme %q not allowed", u.Scheme)
	}
	// İstek başlıkları hop'lar arasında taşınır: POST→GET dönüşümünde silinen
	// Content-Type sonraki hop'ta yeniden doğmamalıdır.
	reqHeaders := cloneHeaders(headers)
	for hop := 0; ; hop++ {
		if !c.budget.Take() {
			return response{}, ErrBudget
		}
		h := cloneHeaders(reqHeaders)
		if cookies := c.jar.Cookies(u); len(cookies) > 0 {
			names := make([]string, 0, len(cookies))
			values := make(map[string]string, len(cookies))
			for _, ck := range cookies {
				if _, ok := values[ck.Name]; !ok {
					names = append(names, ck.Name)
				}
				values[ck.Name] = ck.Value
			}
			sort.Strings(names)
			parts := make([]string, 0, len(names))
			for _, name := range names {
				parts = append(parts, name+"="+values[name])
			}
			h["Cookie"] = strings.Join(parts, "; ")
		}
		status, rh, respBody, serr := c.send(ctx, method, u.String(), h, body)
		if serr != nil {
			return response{}, serr
		}
		if rh != nil {
			if cookies := (&http.Response{Header: rh}).Cookies(); len(cookies) > 0 {
				c.jar.SetCookies(u, cookies)
			}
		}
		if !isRedirect(status) || hop >= MaxRedirects {
			return response{Status: status, Headers: rh, Body: respBody, URL: u.String()}, nil
		}
		loc := ""
		if rh != nil {
			loc = strings.TrimSpace(rh.Get("Location"))
		}
		if loc == "" {
			return response{Status: status, Headers: rh, Body: respBody, URL: u.String()}, nil
		}
		rel, perr := url.Parse(loc)
		if perr != nil {
			return response{Status: status, Headers: rh, Body: respBody, URL: u.String()}, nil
		}
		next := u.ResolveReference(rel)
		if next.Scheme != "http" && next.Scheme != "https" {
			return response{}, fmt.Errorf("flow redirect scheme %q not allowed", next.Scheme)
		}
		if strings.EqualFold(u.Scheme, "https") && strings.EqualFold(next.Scheme, "http") {
			return response{}, ErrRedirectDowngrade
		}
		switch status {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
			if method != http.MethodGet && method != http.MethodHead {
				method = http.MethodGet
				body = nil
				delete(reqHeaders, "Content-Type")
			}
		}
		u = next
	}
}

func cloneHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Normalize imza normalizasyonudur: script/style blokları atılır, token ve
// dinamik değerler maskelenir, boşluklar tekilleştirilir.
func Normalize(body string) string {
	s := scriptStyleRe.ReplaceAllString(body, " ")
	s = tokenValueRe.ReplaceAllString(s, "${1}__MASKED__")
	s = hiddenInputRe.ReplaceAllString(s, "__MASKED_HIDDEN__")
	s = string(baseline.NewDefaultModel().Mask([]byte(s)))
	s = whitespaceRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

var (
	scriptStyleRe = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>|<style\b[^>]*>.*?</style\s*>`)
	tokenValueRe  = regexp.MustCompile(`(?i)(name\s*=\s*["'][^"']*(csrf|xsrf|token|nonce)[^"']*["'][^>]*value\s*=\s*["'])[^"']*`)
	hiddenInputRe = regexp.MustCompile(`(?is)<input\b[^>]*type\s*=\s*["']?hidden["']?[^>]*>`)
	whitespaceRe  = regexp.MustCompile(`\s+`)
)

// Similarity iki normalize gövdenin 3-token shingle Jaccard benzerliğidir.
func Similarity(a, b string) float64 {
	if a == b {
		return 1
	}
	if a == "" || b == "" {
		return 0
	}
	sa := shingles(a)
	sb := shingles(b)
	if len(sa) == 0 || len(sb) == 0 {
		return 0
	}
	inter := 0
	for h := range sa {
		if _, ok := sb[h]; ok {
			inter++
		}
	}
	union := len(sa) + len(sb) - inter
	if union == 0 {
		return 1
	}
	return float64(inter) / float64(union)
}

func shingles(s string) map[uint64]struct{} {
	tokens := strings.Fields(s)
	if len(tokens) == 0 {
		return nil
	}
	if len(tokens) > maxSimilarityTokens {
		stride := (len(tokens) + maxSimilarityTokens - 1) / maxSimilarityTokens
		sampled := make([]string, 0, maxSimilarityTokens)
		for i := 0; i < len(tokens); i += stride {
			sampled = append(sampled, tokens[i])
		}
		tokens = sampled
	}
	out := make(map[uint64]struct{}, len(tokens))
	if len(tokens) < 3 {
		h := fnv.New64a()
		for _, t := range tokens {
			_, _ = h.Write([]byte(t))
			_, _ = h.Write([]byte{0})
		}
		out[h.Sum64()] = struct{}{}
		return out
	}
	for i := 0; i+2 < len(tokens); i++ {
		h := fnv.New64a()
		for j := 0; j < 3; j++ {
			_, _ = h.Write([]byte(tokens[i+j]))
			_, _ = h.Write([]byte{0})
		}
		out[h.Sum64()] = struct{}{}
	}
	return out
}
