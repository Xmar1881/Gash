// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"bytes"
	"mime/multipart"
	"net/url"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

const controlNeutralValue = "gash-control-neutral"

// formRequestBody builds headers and body for one body-location injection.
// What: full-form replay when the point carries FormValues (target field =
// payload, every other field verbatim, tokens included); legacy single-field
// urlencoded body otherwise, or the raw value when no parameter name exists.
// Why: real forms enforce server-side state and CSRF checks, so single-field
// bodies are rejected before the vulnerable sink is reached.
// pointQueryURL builds a query-location request URL with full-form replay:
// the target field carries value and every co-field keeps its browser value.
// Why: PHP handlers commonly gate on the submit button (?Submit=Submit), so
// mutating only the text field never reaches the vulnerable sink.
func pointQueryURL(rawURL string, p loader.JSPoint, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	for k, v := range p.FormValues {
		if k != p.ParamName {
			q.Set(k, v)
		}
	}
	if p.ParamName != "" {
		q.Set(p.ParamName, value)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// pointValueURL applies one value to either the server query or a hash-route
// query. A fragment never reaches the server, so callers must use it only for
// browser navigation, never for an HTTP request.
func pointValueURL(rawURL string, p loader.JSPoint, value string) string {
	if strings.EqualFold(strings.TrimSpace(p.ParamLocation), "fragment") {
		return fragmentQueryURL(rawURL, p, value)
	}
	return pointQueryURL(rawURL, p, value)
}

func fragmentQueryURL(rawURL string, p loader.JSPoint, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	route, rawQuery, _ := strings.Cut(u.Fragment, "?")
	if strings.TrimSpace(route) == "" {
		return rawURL
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		q = url.Values{}
	}
	for k, v := range p.FormValues {
		if k != p.ParamName {
			q.Set(k, v)
		}
	}
	if p.ParamName != "" {
		q.Set(p.ParamName, value)
	}
	// Build the fragment manually: URL.String re-escapes percent signs in
	// Fragment, which would turn an encoded payload into %2522... and break
	// raw location.hash consumers. Keep the server query untouched.
	encodedRoute := (&url.URL{Fragment: route}).EscapedFragment()
	base := *u
	base.Fragment = ""
	base.RawFragment = ""
	return base.String() + "#" + encodedRoute + "?" + strings.ReplaceAll(q.Encode(), "+", "%20")
}

func formRequestBody(p loader.JSPoint, param, value string) (map[string]string, []byte) {
	if param != "" && len(p.FormValues) > 0 {
		if strings.Contains(strings.ToLower(p.FormEnctype), "multipart/form-data") {
			return multipartFormBody(p.FormValues, param, value)
		}
		return urlencodedFormBody(p.FormValues, param, value)
	}
	if param != "" {
		form := url.Values{}
		form.Set(param, value)
		return map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(form.Encode())
	}
	return nil, []byte(value)
}

func urlencodedFormBody(values map[string]string, param, value string) (map[string]string, []byte) {
	form := url.Values{}
	for k, v := range values {
		form.Set(k, v)
	}
	form.Set(param, value)
	return map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(form.Encode())
}

// multipartFormBody writes text-only fields; file inputs are never replayed
// (no fabricated upload), so every part is a plain form field.
func multipartFormBody(values map[string]string, param, value string) (map[string]string, []byte) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if k == param {
			continue // target field is replaced by the payload
		}
		_ = w.WriteField(k, values[k])
	}
	_ = w.WriteField(param, value)
	_ = w.Close()
	return map[string]string{"Content-Type": w.FormDataContentType()}, buf.Bytes()
}
