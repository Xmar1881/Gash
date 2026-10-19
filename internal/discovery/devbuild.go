// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/discovery/devbuild.go
// What: Detects genuinely development-only frontend build artifacts in
// already-fetched HTML/JS bodies (GASH-072).
// Why: Shipping a debug build lowers the bar for client-side abuse and often
// exposes internals. The marker table is deliberately narrow: devtools hooks
// (__REACT_DEVTOOLS_GLOBAL_HOOK__ / __VUE_DEVTOOLS_GLOBAL_HOOK__) also appear
// in production bundles, and generic `warnings` text is not evidence, so both
// are rejected as markers. No requests are made here.

package discovery

import (
	"regexp"
	"strings"
)

// devBuildSnippetMask masks long token-like literals inside evidence snippets.
var devBuildSnippetMask = regexp.MustCompile(`(["'])([A-Za-z0-9_\-\.+/]{40,})(["'])`)

// devBuildMarker is one deterministic dev-build signal.
type devBuildMarker struct {
	name      string
	framework string
	re        *regexp.Regexp
}

// devBuildMarkers is ordered; each marker is reported at most once per body.
// Rejected on purpose:
//   - __REACT_DEVTOOLS_GLOBAL_HOOK__: installed by production React too.
//   - __VUE_DEVTOOLS_GLOBAL_HOOK__: present in production Vue builds.
//   - isDevMode()/warnings: framework internals, not proof of a dev bundle.
var devBuildMarkers = []devBuildMarker{
	{"react-dom.development.js", "react", regexp.MustCompile(`(?i)\breact-dom\.development\.js\b`)},
	{"react.development.js", "react", regexp.MustCompile(`(?i)\breact\.development\.js\b`)},
	{"jsxDEV(", "react", regexp.MustCompile(`\bjsxDEV\s*\(`)},
	{"vue.global.js", "vue", regexp.MustCompile(`(?i)(?:^|[/"'\s])vue\.global\.js(?:[?"'\s]|$)`)},
	{"ng.probe(", "angular", regexp.MustCompile(`(?i)\bng\.probe\s*\(`)},
	{"ng.getComponent(", "angular", regexp.MustCompile(`(?i)\bng\.getComponent\s*\(`)},
}

// DevBuildMarker is one dev-build artifact hit with a bounded, masked snippet.
type DevBuildMarker struct {
	Framework string
	Marker    string
	Snippet   string
}

// DetectDevBuildMarkers returns unique dev-build markers found in one body.
// What: Marker regex hits with quote-aware, whitespace-collapsed snippets.
// Why: The engine aggregates one finding per fetched source, so detection is
// deterministic and duplicates within the same bundle are collapsed.
func DetectDevBuildMarkers(body []byte) []DevBuildMarker {
	if len(body) == 0 || len(body) > MaxJSAnalysisBytes {
		return nil
	}
	text := string(body)
	var out []DevBuildMarker
	for _, m := range devBuildMarkers {
		loc := m.re.FindStringIndex(text)
		if loc == nil {
			continue
		}
		out = append(out, DevBuildMarker{
			Framework: m.framework,
			Marker:    m.name,
			Snippet:   devBuildSnippet(text, loc[0], loc[1]),
		})
	}
	return out
}

// devBuildSnippet returns a bounded context window around the marker.
// What: ±48 chars, collapsed whitespace, 160-char cap, long literals masked.
// Why: Evidence must be reviewable without copying whole minified bundles or
// leaking token-like strings that happen to sit next to the marker.
func devBuildSnippet(text string, start, end int) string {
	const pad = 48
	from := start - pad
	if from < 0 {
		from = 0
	}
	to := end + pad
	if to > len(text) {
		to = len(text)
	}
	snippet := text[from:to]
	snippet = devBuildSnippetMask.ReplaceAllString(snippet, `$1...$3`)
	snippet = strings.Join(strings.Fields(snippet), " ")
	if len(snippet) > 160 {
		snippet = snippet[:160]
	}
	return strings.TrimSpace(snippet)
}
