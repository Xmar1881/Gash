// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// TestReflectedXSSPluginAgainstFixtureLab runs the production
// xss-reflected-basic plugin against the fixture lab through the real JS
// binding and the real reflection oracle (no engine). It separates
// plugin/oracle/lab behavior from engine discovery and budgeting: the plugin
// must produce static-execution evidence for every raw-reflection endpoint
// and must never reach firm/static for the escaped endpoint.
func TestReflectedXSSPluginAgainstFixtureLab(t *testing.T) {
	repo := repoRoot(t)
	srcPath := filepath.Join(repo, "plugins", "xss", "xss-reflected-basic.js")
	src, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read plugin: %v", err)
	}
	spec, err := loader.LoadTier2Frontmatter(srcPath)
	if err != nil {
		t.Fatalf("frontmatter: %v", err)
	}
	lab, err := StartFixtureLab()
	if err != nil {
		t.Fatalf("lab: %v", err)
	}
	defer lab.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	send := func(p loader.JSPoint) (loader.JSResponse, error) {
		u, err := url.Parse(p.URL)
		if err != nil {
			return loader.JSResponse{}, err
		}
		if p.ParamName != "" {
			q := u.Query()
			q.Set(p.ParamName, p.Value)
			u.RawQuery = q.Encode()
		}
		resp, err := client.Get(u.String())
		if err != nil {
			return loader.JSResponse{}, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return loader.JSResponse{}, err
		}
		headers := map[string]string{}
		for k := range resp.Header {
			headers[k] = resp.Header.Get(k)
		}
		return loader.JSResponse{Status: resp.StatusCode, Headers: headers, Body: string(body), URL: u.String()}, nil
	}

	cases := []struct {
		path        string
		wantStatic  bool
		description string
	}{
		{"/xss/reflect?q=hello", true, "raw reflection in HTML text"},
		{"/xss/attr?q=hello", true, "raw reflection in double-quoted attribute"},
		{"/xss/attr-quoted?q=hello", true, "raw reflection in unquoted attribute"},
		{"/xss/js?q=hello", true, "raw reflection in script string"},
		{"/xss/escape?q=hello", false, "escaped reflection must stay tentative"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			env := &loader.JSEnv{
				Points: []loader.JSPoint{{URL: lab.URL() + tc.path, Method: "GET", ParamName: "q", ParamLocation: "query"}},
				Send:   send,
			}
			cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 30*time.Second)
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			t.Logf("%d candidate(s)", len(cands))
			for _, c := range cands {
				ev := c.Evidence
				if ev == nil {
					t.Logf("  candidate %s without evidence", c.Candidate.Target)
					continue
				}
				t.Logf("  confidence=%s context=%s note=%s", ev.ConfidenceContribution, ev.Artifacts["context"], ev.Note)
				if tc.wantStatic && ev.ConfidenceContribution == plugin.ConfidenceStaticExecution {
					return
				}
				if !tc.wantStatic && (ev.ConfidenceContribution == plugin.ConfidenceStaticExecution || ev.ConfidenceContribution == plugin.ConfidenceFirm || ev.ConfidenceContribution == plugin.ConfidenceConfirmed) {
					t.Fatalf("%s: escaped endpoint must not reach %s", tc.description, ev.ConfidenceContribution)
				}
			}
			if tc.wantStatic {
				t.Fatalf("%s: expected static-execution-evidence, got none", tc.description)
			}
		})
	}
}
