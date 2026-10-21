// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import "testing"

func TestIsTokenField(t *testing.T) {
	yes := []string{
		"csrf_token", "CSRF_TOKEN", "_csrf", "XSRF-TOKEN", "myXsrfValue",
		"authenticity_token", "__RequestVerificationToken", "_token", "nonce",
	}
	no := []string{"token", "token_count", "user_id", "event", "redirect", "", "name"}
	for _, name := range yes {
		if !IsTokenField(name) {
			t.Errorf("IsTokenField(%q) = false, want true", name)
		}
	}
	for _, name := range no {
		if IsTokenField(name) {
			t.Errorf("IsTokenField(%q) = true, want false", name)
		}
	}
}

func TestExtractForms_FullModel(t *testing.T) {
	page := "http://example.com/app"
	body := []byte(`<html><body>
<form action="/comment" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="csrf_token" value="tok-123">
  <input type="text" name="title" value="hello">
  <textarea name="body">multi
line</textarea>
  <select name="kind">
    <option value="a">A</option>
    <option value="b" selected>B</option>
  </select>
  <input type="checkbox" name="vip" checked>
  <input type="checkbox" name="cold">
  <input type="radio" name="color" value="red" checked>
  <input type="radio" name="color" value="blue">
  <input type="file" name="upload">
  <input type="submit" name="go" value="Send">
</form>
</body></html>`)
	forms := ExtractForms(page, body)
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	f := forms[0]
	if f.SourceURL != page || f.ActionURL != "http://example.com/comment" {
		t.Fatalf("URLs wrong: %+v", f)
	}
	if f.Method != "POST" || f.Enctype != "multipart/form-data" {
		t.Fatalf("method/enctype wrong: %+v", f)
	}
	type want struct {
		name, value, inputType string
		token                  bool
	}
	wants := []want{
		{"csrf_token", "tok-123", "hidden", true},
		{"title", "hello", "text", false},
		{"body", "multi\nline", "textarea", false},
		{"kind", "b", "select", false},
		{"vip", "on", "checkbox", false},
		{"color", "red", "radio", false},
		{"upload", "", "file", false},
		{"go", "Send", "submit", false},
	}
	if len(f.Fields) != len(wants) {
		t.Fatalf("expected %d fields, got %d: %+v", len(wants), len(f.Fields), f.Fields)
	}
	for i, w := range wants {
		got := f.Fields[i]
		if got.Name != w.name || got.Value != w.value || got.InputType != w.inputType || got.IsToken != w.token {
			t.Errorf("field %d = %+v, want %+v", i, got, w)
		}
	}
}

func TestExtractForms_Defaults(t *testing.T) {
	page := "http://example.com/page"
	forms := ExtractForms(page, []byte(`<form><input name="q" value="x"></form>`))
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	f := forms[0]
	if f.Method != "GET" || f.ActionURL != page || f.SourceURL != page {
		t.Fatalf("defaults wrong: %+v", f)
	}
	if f.Enctype != "application/x-www-form-urlencoded" {
		t.Fatalf("default enctype wrong: %q", f.Enctype)
	}
	if len(f.Fields) != 1 || f.Fields[0].Name != "q" || f.Fields[0].InputType != "text" {
		t.Fatalf("fields wrong: %+v", f.Fields)
	}
}

func TestExtractForms_EmptyAndInvalid(t *testing.T) {
	if forms := ExtractForms("http://example.com/", nil); forms != nil {
		t.Fatalf("nil body should yield nil forms, got %+v", forms)
	}
	if forms := ExtractForms("not a url:::", []byte("<form><input name=a></form>")); forms != nil {
		t.Fatalf("invalid page URL should yield nil forms, got %+v", forms)
	}
	if forms := ExtractForms("http://example.com/", []byte("<html><body>no forms</body></html>")); len(forms) != 0 {
		t.Fatalf("no forms expected, got %+v", forms)
	}
}
