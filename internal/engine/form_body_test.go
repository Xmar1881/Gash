// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

func TestFormRequestBodyLegacy(t *testing.T) {
	p := loader.JSPoint{ParamName: "id"}
	headers, body := formRequestBody(p, "id", "1'")
	if headers["Content-Type"] != "application/x-www-form-urlencoded" {
		t.Fatalf("content-type wrong: %v", headers)
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil || vals.Get("id") != "1'" {
		t.Fatalf("legacy body wrong: %q (%v)", body, err)
	}

	headers, body = formRequestBody(loader.JSPoint{}, "", "raw-payload")
	if headers != nil || string(body) != "raw-payload" {
		t.Fatalf("raw body path wrong: %v %q", headers, body)
	}
}

func TestFormRequestBodyFullForm(t *testing.T) {
	p := loader.JSPoint{
		ParamName: "q",
		FormValues: map[string]string{
			"csrf_token": "tok-1",
			"page":       "2",
		},
		FormEnctype: "application/x-www-form-urlencoded",
	}
	headers, body := formRequestBody(p, "q", "' OR 1=1--")
	if headers["Content-Type"] != "application/x-www-form-urlencoded" {
		t.Fatalf("content-type wrong: %v", headers)
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatal(err)
	}
	if vals.Get("csrf_token") != "tok-1" || vals.Get("page") != "2" || vals.Get("q") != "' OR 1=1--" {
		t.Fatalf("full form body wrong: %q", body)
	}
}

func TestPointValueURLFragment(t *testing.T) {
	p := loader.JSPoint{ParamName: "q", ParamLocation: "fragment"}
	payload := `"><iframe src="javascript:alert(window.__gashCanary=true)"></iframe>`
	got := pointValueURL("http://example.com/app#/search?q=apple&page=2", p, payload)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	want := "/search?page=2&q=" + payload
	if u.Fragment != want {
		t.Fatalf("fragment = %q, want %q", u.Fragment, want)
	}
	if strings.Contains(got, "%2522") {
		t.Fatalf("fragment is double-encoded: %q", got)
	}
	if u.RawQuery != "" {
		t.Fatalf("fragment injection must not touch the server query: %q", u.RawQuery)
	}
	if got == pointValueURL("http://example.com/app#/search?q=apple&page=2", p, controlNeutralValue) {
		t.Fatal("payload and control URLs must differ")
	}
}

func TestPointValueURLRawHash(t *testing.T) {
	p := loader.JSPoint{ParamLocation: "hash"}
	payload := `"><iframe src="javascript:alert(1)"></iframe>`
	got := pointValueURL("http://example.com/app?next=keep#/old", p, payload)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.RawQuery != "next=keep" {
		t.Fatalf("raw hash test must keep the server query: %q", u.RawQuery)
	}
	if u.Fragment != payload {
		t.Fatalf("fragment = %q, want %q", u.Fragment, payload)
	}
	if got == pointValueURL("http://example.com/app?next=keep#/old", p, controlNeutralValue) {
		t.Fatal("payload and control hash URLs must differ")
	}
}

func TestPointQueryURLReplaysFormFields(t *testing.T) {
	p := loader.JSPoint{
		ParamName:     "id",
		ParamLocation: "query",
		FormValues: map[string]string{
			"Submit": "Submit",
			"id":     "1",
		},
	}
	got := pointQueryURL("http://example.com/sqli", p, "1'")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("id") != "1'" || q.Get("Submit") != "Submit" {
		t.Fatalf("query replay wrong: %q", got)
	}
}

func TestFormRequestBodyMultipart(t *testing.T) {
	p := loader.JSPoint{
		ParamName: "q",
		FormValues: map[string]string{
			"csrf_token": "tok-1",
			"page":       "2",
		},
		FormEnctype: "multipart/form-data",
	}
	headers, body := formRequestBody(p, "q", "payload")
	ct := headers["Content-Type"]
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		t.Fatalf("multipart content-type wrong: %q (%v)", ct, err)
	}
	reader := multipart.NewReader(strings.NewReader(string(body)), params["boundary"])
	got := map[string]string{}
	for {
		part, perr := reader.NextPart()
		if perr != nil {
			break
		}
		buf := make([]byte, 1024)
		n, _ := part.Read(buf)
		got[part.FormName()] = string(buf[:n])
	}
	if got["csrf_token"] != "tok-1" || got["page"] != "2" || got["q"] != "payload" {
		t.Fatalf("multipart fields wrong: %+v", got)
	}
}
