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

// formRequestBody builds headers and body for one body-location injection.
// What: full-form replay when the point carries FormValues (target field =
// payload, every other field verbatim, tokens included); legacy single-field
// urlencoded body otherwise, or the raw value when no parameter name exists.
// Why: real forms enforce server-side state and CSRF checks, so single-field
// bodies are rejected before the vulnerable sink is reached.
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
