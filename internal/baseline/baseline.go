// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package baseline tarama-öncesi gürültü parmak izidir (A-05).
// Soft-404/SPA, WAF/CDN/captcha, dinamik maskeleme, teknoloji parmak izi, jitter.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
)

// Classification probe.Send dönüşüne otomatik işlenir; Untrusted hiçbir oracle'da kanıt olamaz.
type Classification struct {
	Untrusted    bool
	Soft404      bool
	WAFDetected  bool
	Note         string
	Technologies []string
}

// Model tarama-öncesi çıkarılan imzadır.
type Model struct {
	Soft404Bodies map[string]bool
	Soft404Status map[int]bool
	WAFMarkers    []string
	Technologies  []string
	MaskRe        []*regexp.Regexp
}

var (
	wafMarkers = []string{
		"cf-chl", "cf-ray", "cloudflare", "akamai", "incapsula", "imperva",
		"__cf_bm", "cf_chl", "recaptcha", "hcaptcha", "captcha",
		"retry-after", "access denied", "request blocked", "waf",
	}
	maskPatterns = []string{
		`name="csrf[^"]*" value="[^"]*"`,
		`nonce="[^"]*"`,
		`[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z?`,
		`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
		`__VIEWSTATE[^<]*`,
		`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`,
		`[0-9]{10,13}`,
	}
)

// NewDefaultModel varsayılan imza setiyle model kurar.
func NewDefaultModel() *Model {
	var res []*regexp.Regexp
	for _, p := range maskPatterns {
		res = append(res, regexp.MustCompile(p))
	}
	return &Model{
		Soft404Bodies: make(map[string]bool),
		Soft404Status: make(map[int]bool),
		WAFMarkers:    append([]string{}, wafMarkers...),
		MaskRe:        res,
	}
}

// Mask dinamik içeriği normalizer (differential + baseline aynı fonksiyon).
func (m *Model) Mask(body []byte) []byte {
	s := string(body)
	if m == nil {
		return body
	}
	for _, re := range m.MaskRe {
		s = re.ReplaceAllString(s, "__MASKED__")
	}
	return []byte(s)
}

// MaskString kolaylık.
func MaskString(s string) string {
	m := NewDefaultModel()
	return string(m.Mask([]byte(s)))
}

// hashMasked maskelenmiş gövde hash'i.
func hashMasked(m *Model, body []byte) string {
	var masked []byte
	if m != nil {
		masked = m.Mask(body)
	} else {
		masked = body
	}
	sum := sha256.Sum256(masked)
	return hex.EncodeToString(sum[:])
}

// ClassifyStatic saf sınıflandırma (ağsız, test-edilebilir).
// soft404Hashes: baseline'da öğrenilen maskeli hash seti (nil ise yalnızca heuristik).
func ClassifyStatic(status int, headers http.Header, body []byte) Classification {
	return classifyWith(status, headers, body, nil)
}

// Classify model-bilgili sınıflandırmadır.
func (m *Model) Classify(status int, headers http.Header, body []byte) Classification {
	return classifyWith(status, headers, body, m)
}

func classifyWith(status int, headers http.Header, body []byte, m *Model) Classification {
	lower := strings.ToLower(string(body))
	for _, marker := range wafMarkers {
		if strings.Contains(lower, marker) {
			// 429 + Retry-After veya marker varlığı → Untrusted.
			return Classification{Untrusted: true, WAFDetected: true, Note: "waf/block: " + marker}
		}
	}
	if status == http.StatusTooManyRequests {
		return Classification{Untrusted: true, WAFDetected: true, Note: "429 rate-limit"}
	}
	if headers != nil {
		if headers.Get("Retry-After") != "" && (status == 403 || status == 429 || status == 503) {
			return Classification{Untrusted: true, WAFDetected: true, Note: "retry-after block"}
		}
	}
	if m != nil && len(m.Soft404Bodies) > 0 {
		h := hashMasked(m, body)
		if m.Soft404Bodies[h] {
			return Classification{Soft404: true, Note: "soft404 fingerprint"}
		}
	}
	return Classification{Note: "normal"}
}

// LearnSoft404 rastgele path yanıtlarından fingerprint öğrenir.
func (m *Model) LearnSoft404(bodies [][]byte, statuses []int) {
	for _, b := range bodies {
		m.Soft404Bodies[hashMasked(m, b)] = true
	}
	for _, s := range statuses {
		m.Soft404Status[s] = true
	}
}

// DetectTech basit header/cookie/known-path parmak izidir.
func DetectTech(headers http.Header, cookies []*http.Cookie, body string) []string {
	var out []string
	add := func(t string) {
		for _, e := range out {
			if e == t {
				return
			}
		}
		out = append(out, t)
	}
	srv := strings.ToLower(headers.Get("Server") + " " + headers.Get("X-Powered-By") + " " + headers.Get("X-AspNet-Version"))
	switch {
	case strings.Contains(srv, "wordpress") || strings.Contains(body, "wp-json"):
		add("wordpress")
	case strings.Contains(srv, "nginx"):
		add("nginx")
	case strings.Contains(srv, "apache"):
		add("apache")
	case strings.Contains(srv, "express"):
		add("express")
	}
	for _, c := range cookies {
		n := strings.ToLower(c.Name)
		if strings.Contains(n, "php") {
			add("php")
		}
		if strings.Contains(n, "next") || strings.Contains(body, "_next/") {
			add("nextjs")
		}
	}
	if strings.Contains(body, "_next/") {
		add("nextjs")
	}
	return out
}

// JitterStats TimingOracle girdisidir (medyan/p95/stddev, ms).
type JitterStats struct {
	Median float64
	P95    float64
	Stddev float64
	Count  int
}
