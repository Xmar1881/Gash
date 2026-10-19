// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import (
	"strings"
	"testing"
)

func TestSPAStateContainers(t *testing.T) {
	const pageURL = "http://target.test/app"
	cases := []struct {
		name      string
		body      string
		framework string
		container string
		parsed    bool
	}{
		{
			name:      "next data script tag",
			body:      `<script id="__NEXT_DATA__" type="application/json">{"props":{"ok":true}}</script>`,
			framework: "next",
			container: "__NEXT_DATA__",
			parsed:    true,
		},
		{
			name:      "nuxt window assignment",
			body:      `<script>window.__NUXT__={data:{config:{site:"x"}}}</script>`,
			framework: "nuxt",
			container: "__NUXT__",
			parsed:    false,
		},
		{
			name:      "redux initial state",
			body:      `<script>window.__INITIAL_STATE__ = {"auth":{"user":"a"}};</script>`,
			framework: "redux",
			container: "__INITIAL_STATE__",
			parsed:    true,
		},
		{
			name:      "apollo cache",
			body:      `<script>window.__APOLLO_STATE__={"ROOT_QUERY":{"me":1}}</script>`,
			framework: "apollo",
			container: "__APOLLO_STATE__",
			parsed:    true,
		},
		{
			name:      "angular ng-state",
			body:      `<script id="ng-state" type="application/json">{"user":{"id":1}}</script>`,
			framework: "angular",
			container: "ng-state",
			parsed:    true,
		},
		{
			name:      "next flight push",
			body:      `<script>self.__next_f.push([1,"{\"user\":{\"id\":1}}"])</script>`,
			framework: "next",
			container: "self.__next_f.push",
			parsed:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := AnalyzeSPAState([]byte(tc.body), pageURL)
			found := false
			for _, c := range rep.Containers {
				if c.Framework == tc.framework && c.Key == tc.container {
					found = true
					if c.Parsed != tc.parsed {
						t.Fatalf("parsed=%v want %v (text=%q)", c.Parsed, tc.parsed, c.Text)
					}
				}
			}
			if !found {
				t.Fatalf("container %s/%s missing: %#v", tc.framework, tc.container, rep.Containers)
			}
		})
	}
}

func TestSPAStateSecretsMasked(t *testing.T) {
	const (
		pageURL = "http://target.test/app"
		token   = "ghp_" + "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LmNvBc"
		pass    = "correct-horse-battery-staple"
	)
	body := []byte(`<script id="__NEXT_DATA__" type="application/json">` +
		`{"props":{"pageProps":{"accessToken":"` + token + `","password":"` + pass + `"}}}</script>`)
	rep := AnalyzeSPAState(body, pageURL)
	if len(rep.Containers) != 1 || rep.Containers[0].Framework != "next" {
		t.Fatalf("containers: %#v", rep.Containers)
	}
	if len(rep.Secrets) != 2 {
		t.Fatalf("want 2 secrets, got %d: %#v", len(rep.Secrets), rep.Secrets)
	}
	var seenToken, seenPassword bool
	for _, s := range rep.Secrets {
		if strings.Contains(s.Secret.Masked, token) || strings.Contains(s.Secret.Context, token) || strings.Contains(s.Secret.Context, pass) {
			t.Fatalf("full value leaked in evidence: %#v", s.Secret)
		}
		if s.Framework != "next" || s.Container != "__NEXT_DATA__" {
			t.Fatalf("secret container: %#v", s)
		}
		if s.Secret.Type == "github-token" {
			seenToken = true
		}
		if s.Secret.VarName == "password" {
			seenPassword = true
		}
	}
	if !seenToken || !seenPassword {
		t.Fatalf("missing expected secret matches: %#v", rep.Secrets)
	}
}

func TestSPAStateSensitiveCamelKeysAndPlaceholders(t *testing.T) {
	body := []byte(`<script>window.__INITIAL_STATE__={"auth":{` +
		`"refreshToken":"rt_9f8e7d6c5b4a3210",` +
		`"clientSecret":"s3cr3t-value-9z8y7x",` +
		`"password":"process.env.DB_PASSWORD",` +
		`"apiKey":"your_api_key_here",` +
		`"token":"${SESSION_TOKEN}",` +
		`"note":"short"}}</script>`)
	rep := AnalyzeSPAState(body, "http://target.test/app")
	if len(rep.Secrets) != 2 {
		t.Fatalf("want 2 real secrets (placeholders filtered), got %d: %#v", len(rep.Secrets), rep.Secrets)
	}
	for _, s := range rep.Secrets {
		if s.Secret.Type != "sensitive-state-key" && s.Secret.Type != "generic-secret" {
			t.Fatalf("unexpected type %q", s.Secret.Type)
		}
		if s.Secret.VarName != "refreshtoken" && s.Secret.VarName != "clientsecret" {
			t.Fatalf("var name %q", s.Secret.VarName)
		}
	}
}

func TestSPAStateDedupesSameValueAcrossContainers(t *testing.T) {
	const token = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
	body := []byte(`<script id="__NEXT_DATA__" type="application/json">{"config":{"apiKey":"` + token + `"}}</script>` +
		`<script id="ng-state" type="application/json">{"apiKey":"` + token + `"}</script>`)
	rep := AnalyzeSPAState(body, "http://target.test/app")
	if len(rep.Secrets) != 1 {
		t.Fatalf("same value must dedupe across containers, got %d: %#v", len(rep.Secrets), rep.Secrets)
	}
}

func TestSPAStateSizeGuard(t *testing.T) {
	body := make([]byte, MaxJSAnalysisBytes+1)
	if got := ExtractSPAState(body); len(got) != 0 {
		t.Fatalf("oversize body must be ignored, got %d containers", len(got))
	}
}
