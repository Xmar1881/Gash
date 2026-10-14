// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package wafbypass WAF/blok algılama ve agresif-mod bypass mutasyonlarıdır.
//
// What: Saf (ağsız) istek varyantı üretimi: header bypass, HPP çoğaltma,
// double URL-encode, SQL yorum enjeksiyonu ve mixed-case mutasyonları.
// Blok kararı baseline sınıflandırmasına dayanır.
//
// Why: WAF görüldüğünde taramayı sessizce durdurmak yerine durumu
// WAFDetected olarak işaretleyip (probe.Response + Report.Stats) yalnızca
// açık opt-in ile (--aggressive profili) sınırlı sayıda varyant denemek,
// recall'u artırırken güvenli varsayılanları korur.
//
// Güvenlik sınırları (§14):
//   - Varsayılan kapalı: probe.Client EnableWAFBypass verilmedikçe bu paket
//     çağrılmaz; normal taramada stealth/log-kaçınma davranışı YOKTUR.
//   - Tüm varyantlar aynı PolicySession/kapsam/bütçe denetiminden geçer;
//     kapsam-dışı istek üretilmez, bütçe aşılmaz (en fazla 5 deneme).
//   - Blok sayfasının kendisi asla kanıt sayılmaz (oracle guard reject);
//     yalnızca bypass sonrası gelen temiz yanıt normal doğrulanır.
//   - Chunked Transfer-Encoding burada YOKTUR: net/http istemcisi gövde
//     parçalamayı denetlemez; kalan iş olarak raporda kayıtlıdır.
package wafbypass

import (
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/Xmar1881/Gash/internal/baseline"
)

// Teknik adları (sıralı deneme düzeni).
const (
	TechHeaderOnly   = "header-only"
	TechHPPDuplicate = "hpp-duplicate"
	TechDoubleEncode = "double-encode"
	TechSQLComment   = "sql-comment"
	TechMixedCase    = "mixed-case"
)

// Techniques deneme sırasındaki mutasyon teknikleridir (header-only hariç).
// What: URL/body değerlerine uygulanan param-agnostik dönüşümler.
// Why: Aktif taramada query/body değerleri payload taşıdığı için hangi
// parametre olduğu bilinmeden de payload dönüşümü uygulanabilir.
func Techniques() []string {
	return []string{TechHPPDuplicate, TechDoubleEncode, TechSQLComment, TechMixedCase}
}

// MaxAttempts tek blok yanıtı başına en fazla varyant denemesidir.
const MaxAttempts = 5

// BypassHeaders WAF kuralının istemci IP başlığına güvenmesini test eden
// loopback başlıklarıdır. Yalnızca agresif mod denemelerinde gönderilir;
// açık istek başlığı varsa istek kazanır (üzerine yazılmaz).
func BypassHeaders() map[string]string {
	return map[string]string{
		"X-Forwarded-For":  "127.0.0.1",
		"X-Originating-IP": "127.0.0.1",
		"X-Remote-IP":      "127.0.0.1",
		"Client-IP":        "127.0.0.1",
		"X-Real-IP":        "127.0.0.1",
	}
}

// IsBlocked yanıtın WAF/blok/rate-limit engeli sayılıp sayılmayacağını
// bildirir. Tetikleyici: baseline WAF işareti veya 403/429 durumu.
// Düz 503 (işaretsiz bakım sayfası) dahil DEĞİLDİR — zor durumdaki hedefe
// ek yük bindirilmez.
func IsBlocked(status int, headers http.Header, body []byte) bool {
	cls := baseline.ClassifyStatic(status, headers, body)
	if cls.WAFDetected || cls.Untrusted {
		return true
	}
	return status == http.StatusForbidden || status == http.StatusTooManyRequests
}

// MutateValue tek bir query/form değerine teknik uygular.
func MutateValue(v, technique string) string {
	switch technique {
	case TechDoubleEncode:
		return url.QueryEscape(url.QueryEscape(v))
	case TechSQLComment:
		return strings.ReplaceAll(v, " ", "/**/")
	case TechMixedCase:
		return mixedCase(v)
	default:
		return v
	}
}

// MutateQuery URL'nin tüm query değerlerine teknik uygular.
// HPP çoğaltmada her anahtar iki kez yazılır (id=1 → id=1&id=1).
func MutateQuery(rawURL, technique string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.RawQuery == "" || !strings.Contains(u.RawQuery, "=") {
		return rawURL, nil
	}
	vals, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return rawURL, nil
	}
	if technique == TechHPPDuplicate {
		var parts []string
		for _, k := range sortedKeys(vals) {
			for _, v := range vals[k] {
				parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
				parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
			}
		}
		u.RawQuery = strings.Join(parts, "&")
		return u.String(), nil
	}
	out := make(url.Values, len(vals))
	for _, k := range sortedKeys(vals) {
		for _, v := range vals[k] {
			out.Add(k, MutateValue(v, technique))
		}
	}
	encoded := out.Encode()
	if technique == TechSQLComment {
		// Yorum işaretleri ham taşınır: WAF normalizasyon farkını yoklamak
		// için /**/ encode'lanmaz (query'de ham / ve * geçerlidir).
		encoded = strings.ReplaceAll(encoded, "%2F%2A%2A%2F", "/**/")
	}
	u.RawQuery = encoded
	return u.String(), nil
}

// MutateFormBody x-www-form-urlencoded gövdeye teknik uygular.
// Ayrıştırılamayan gövde aynen iade edilir (ikili/JSON gövdeye dokunulmaz).
func MutateFormBody(body []byte, technique string) []byte {
	if len(body) == 0 || !strings.Contains(string(body), "=") {
		return body
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil || len(vals) == 0 {
		return body
	}
	if technique == TechHPPDuplicate {
		var parts []string
		for _, k := range sortedKeys(vals) {
			for _, v := range vals[k] {
				parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
				parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
			}
		}
		return []byte(strings.Join(parts, "&"))
	}
	out := make(url.Values, len(vals))
	for _, k := range sortedKeys(vals) {
		for _, v := range vals[k] {
			out.Add(k, MutateValue(v, technique))
		}
	}
	encoded := out.Encode()
	if technique == TechSQLComment {
		encoded = strings.ReplaceAll(encoded, "%2F%2A%2A%2F", "/**/")
	}
	return []byte(encoded)
}

// Attempt tek bypass denemesidir (yeni URL + başlık + gövde).
type Attempt struct {
	Name    string
	URL     string
	Headers map[string]string
	Body    []byte
}

// BuildAttempts orijinal istekten en fazla MaxAttempts varyant üretir.
// İlk deneme her zaman header-only'dir; URL'de query yoksa ve gövde form
// değilse yalnızca header-only döner (anlamsız tekrar YOK).
func BuildAttempts(rawURL string, headers map[string]string, body []byte) []Attempt {
	base := cloneStrMap(headers)
	for k, v := range BypassHeaders() {
		if !hasHeaderKey(base, k) {
			base[k] = v
		}
	}
	attempts := []Attempt{{
		Name:    TechHeaderOnly,
		URL:     rawURL,
		Headers: cloneStrMap(base),
		Body:    body,
	}}
	for _, tech := range Techniques() {
		if len(attempts) >= MaxAttempts {
			break
		}
		mutURL, err := MutateQuery(rawURL, tech)
		if err != nil {
			continue
		}
		mutBody := MutateFormBody(body, tech)
		if mutURL == rawURL && sameBytes(mutBody, body) {
			continue
		}
		attempts = append(attempts, Attempt{
			Name:    tech,
			URL:     mutURL,
			Headers: cloneStrMap(base),
			Body:    mutBody,
		})
	}
	return attempts
}

func mixedCase(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	li := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			if li%2 == 0 {
				r = unicode.ToUpper(r)
			} else {
				r = unicode.ToLower(r)
			}
			li++
		}
		b.WriteRune(r)
	}
	return b.String()
}

func sortedKeys(vals url.Values) []string {
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func cloneStrMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m)+5)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// hasHeaderKey başlık adının map'te farklı yazımla var olup olmadığını
// bildirir (net/http kanonikleştirmeden bağımsız güvenli birleşim).
func hasHeaderKey(m map[string]string, k string) bool {
	if _, ok := m[k]; ok {
		return true
	}
	lk := strings.ToLower(k)
	for existing := range m {
		if strings.ToLower(existing) == lk {
			return true
		}
	}
	return false
}

func sameBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
