// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/discovery/spa_state.go
// What: Extracts framework-embedded SPA state containers (Next/Nuxt/Redux/
// Apollo/Angular) from already-fetched HTML and scans them for secrets.
// Why: State serialized into the page is a common credential leak that plain
// JS-file recon misses. This is a deterministic, no-request analyzer; values
// are masked (first4...last4) and the full value never leaves this package.

package discovery

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/Xmar1881/Gash/internal/plugin"
)

const (
	// spaStateMaxContainerBytes bounds one embedded state container.
	spaStateMaxContainerBytes = 512 * 1024
	// spaStateMaxContainers bounds containers per page (audit-friendly).
	spaStateMaxContainers = 32
	// spaStateMaxFlightPayloads bounds Next.js flight-payload extraction.
	spaStateMaxFlightPayloads = 64
	// spaStateMinSensitiveValue is the minimum sensitive value length.
	spaStateMinSensitiveValue = 12
)

// SPAStateContainer is one framework state blob found in an HTML document.
type SPAStateContainer struct {
	// Framework is next|nuxt|redux|apollo|angular.
	Framework string
	// Key names the container (script id, window assignment, or flight push).
	Key string
	// Text is the extracted state payload (bounded).
	Text string
	// Parsed reports whether Text is valid JSON.
	Parsed bool
}

// SPAStateSecret couples a matched secret with its framework container.
type SPAStateSecret struct {
	Framework string
	Container string
	Secret    Secret
}

// SPAStateReport is the deterministic output of one page-body analysis.
type SPAStateReport struct {
	Containers []SPAStateContainer
	Secrets    []SPAStateSecret
}

// spaStateScriptTag finds state-bearing script tags by id.
var spaStateScriptTag = regexp.MustCompile(`(?is)<script\b[^>]*\sid\s*=\s*["']?(__NEXT_DATA__|__NUXT_DATA__|ng-state)["']?[^>]*>(.*?)</script>`)

// spaStateFlightPush locates Next.js App Router flight pushes.
var spaStateFlightPush = regexp.MustCompile(`__next_f\.push\s*\(`)

// spaStateAssignments lists window state assignments in deterministic order.
var spaStateAssignments = []struct {
	key       string
	framework string
	re        *regexp.Regexp
}{
	{"__NEXT_DATA__", "next", regexp.MustCompile(`(?:window\.)?\b__NEXT_DATA__\s*=`)},
	{"__NUXT__", "nuxt", regexp.MustCompile(`(?:window\.)?\b__NUXT__\s*=`)},
	{"__NUXT_DATA__", "nuxt", regexp.MustCompile(`(?:window\.)?\b__NUXT_DATA__\s*=`)},
	{"__INITIAL_STATE__", "redux", regexp.MustCompile(`(?:window\.)?\b__INITIAL_STATE__\s*=`)},
	{"__PRELOADED_STATE__", "redux", regexp.MustCompile(`(?:window\.)?\b__PRELOADED_STATE__\s*=`)},
	{"__APOLLO_STATE__", "apollo", regexp.MustCompile(`(?:window\.)?\b__APOLLO_STATE__\s*=`)},
}

// spaStateSensitiveKey matches credentials by their state key name.
// Why: embedded state often carries session tokens that do not match the
// provider-specific JS secret rules (e.g. `"accessToken": "..."`).
var spaStateSensitiveKey = regexp.MustCompile(`(?i)["']?\b(password|passwd|secret|token|secret[_-]?key|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?token|id[_-]?token)\b["']?\s*[:=]\s*["']([^"'\r\n]{12,512})["']`)

// ExtractSPAState returns embedded state containers from one HTML/JS body.
// What: Script-tag ids first, then window assignments with balanced JSON when
// possible, then Next.js flight payloads; duplicates collapse deterministically.
// Why: Every framework serializes state differently; extraction must stay
// bounded and side-effect free so the engine can reuse crawled bytes.
func ExtractSPAState(body []byte) []SPAStateContainer {
	if len(body) == 0 || len(body) > MaxJSAnalysisBytes {
		return nil
	}
	text := string(body)
	var out []SPAStateContainer
	seen := make(map[string]bool)
	add := func(c SPAStateContainer) {
		c.Text = strings.TrimSpace(c.Text)
		if c.Text == "" || len(out) >= spaStateMaxContainers {
			return
		}
		if len(c.Text) > spaStateMaxContainerBytes {
			c.Text = c.Text[:spaStateMaxContainerBytes]
		}
		key := c.Key + "|" + c.Framework + "|" + c.Text
		if seen[key] {
			return
		}
		seen[key] = true
		var parsed any
		c.Parsed = json.Unmarshal([]byte(c.Text), &parsed) == nil
		out = append(out, c)
	}

	for _, m := range spaStateScriptTag.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 6 {
			continue
		}
		id := text[m[2]:m[3]]
		add(SPAStateContainer{
			Framework: spaStateFrameworkForID(id),
			Key:       id,
			Text:      text[m[4]:m[5]],
		})
	}

	for _, a := range spaStateAssignments {
		for _, loc := range a.re.FindAllStringIndex(text, -1) {
			start := loc[1]
			for start < len(text) && (text[start] == ' ' || text[start] == '\t' || text[start] == '\r' || text[start] == '\n') {
				start++
			}
			capture := spaStateAssignmentText(text, start)
			add(SPAStateContainer{Framework: a.framework, Key: a.key, Text: capture})
		}
	}

	if strings.Contains(text, "__next_f.push") {
		if flight := spaStateFlightText(text); flight != "" {
			add(SPAStateContainer{Framework: "next", Key: "self.__next_f.push", Text: flight})
		}
	}
	return out
}

// AnalyzeSPAState extracts containers and scans them for secrets.
// What: Reuses the JS secret rules, then adds sensitive state-key matches
// (password/token/secret/...); duplicates by masked value collapse per page.
// Why: One page-level report keeps engine findings and stats deterministic.
func AnalyzeSPAState(body []byte, pageURL string) SPAStateReport {
	containers := ExtractSPAState(body)
	rep := SPAStateReport{Containers: containers}
	seenMasked := make(map[string]bool)
	for _, c := range containers {
		found, _ := scanSecrets(c.Text, pageURL)
		for _, s := range found {
			if seenMasked[s.Masked] {
				continue
			}
			seenMasked[s.Masked] = true
			rep.Secrets = append(rep.Secrets, SPAStateSecret{Framework: c.Framework, Container: c.Key, Secret: s})
		}
		for _, m := range spaStateSensitiveKey.FindAllStringSubmatchIndex(c.Text, -1) {
			if len(m) < 6 {
				continue
			}
			value := c.Text[m[4]:m[5]]
			if !spaStateSensitiveValue(value) {
				continue
			}
			masked := jsMaskSecret(value)
			if seenMasked[masked] {
				continue
			}
			seenMasked[masked] = true
			rep.Secrets = append(rep.Secrets, SPAStateSecret{
				Framework: c.Framework,
				Container: c.Key,
				Secret: Secret{
					Type:     "sensitive-state-key",
					RuleName: "sensitive-state-key",
					Masked:   masked,
					VarName:  strings.ToLower(c.Text[m[2]:m[3]]),
					Severity: plugin.SeverityHigh,
					Context:  jsSecretContext(c.Text, m[4], m[5], value, masked),
					Location: pageURL,
				},
			})
		}
	}
	return rep
}

// spaStateFrameworkForID maps a state script id to its framework.
func spaStateFrameworkForID(id string) string {
	switch id {
	case "__NEXT_DATA__":
		return "next"
	case "__NUXT_DATA__":
		return "nuxt"
	case "ng-state":
		return "angular"
	default:
		return "unknown"
	}
}

// spaStateAssignmentText captures the value after an assignment marker.
// What: Balanced JSON/object/array when possible; otherwise the rest of the
// script element (bounded) for IIFE/parse forms.
// Why: Nuxt uses an IIFE and Redux may use JSON.parse, so balanced-only would
// silently drop the most common Nuxt shape.
func spaStateAssignmentText(text string, start int) string {
	if start >= len(text) {
		return ""
	}
	if text[start] == '{' || text[start] == '[' {
		if s, ok := spaBalancedValue(text, start); ok {
			return s
		}
	}
	end := len(text)
	if i := strings.Index(strings.ToLower(text[start:]), "</script"); i >= 0 {
		end = start + i
	}
	if end-start > spaStateMaxContainerBytes {
		end = start + spaStateMaxContainerBytes
	}
	return text[start:end]
}

// spaBalancedValue returns one balanced {...} or [...] literal.
// What: Quote- and escape-aware nesting for JSON and JS object literals.
// Why: A naive closing-brace search truncates state on nested objects/strings.
func spaBalancedValue(text string, start int) (string, bool) {
	if start >= len(text) || (text[start] != '{' && text[start] != '[') {
		return "", false
	}
	var stack []byte
	inString := false
	var quote byte
	escaped := false
	for i := start; i < len(text); i++ {
		c := text[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				inString = false
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			inString = true
			quote = c
		case '{', '[':
			stack = append(stack, c)
		case '}', ']':
			if len(stack) == 0 {
				return "", false
			}
			open := stack[len(stack)-1]
			if (open == '{' && c != '}') || (open == '[' && c != ']') {
				return "", false
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return text[start : i+1], true
			}
		}
	}
	return "", false
}

// spaStateFlightText decodes Next.js flight push payload strings.
// What: `self.__next_f.push([1,"..."])` strings are JSON-decoded and joined.
// Why: App Router state lives in flight chunks instead of __NEXT_DATA__.
func spaStateFlightText(text string) string {
	var parts []string
	total := 0
	for _, loc := range spaStateFlightPush.FindAllStringIndex(text, -1) {
		start := loc[1]
		for start < len(text) && (text[start] == ' ' || text[start] == '\t' || text[start] == '\r' || text[start] == '\n') {
			start++
		}
		if start >= len(text) || text[start] != '[' {
			continue
		}
		raw, ok := spaBalancedValue(text, start)
		if !ok {
			continue
		}
		payload := raw
		var arr []any
		if json.Unmarshal([]byte(raw), &arr) == nil && len(arr) > 1 {
			if s, isStr := arr[1].(string); isStr {
				payload = s
			}
		}
		if payload == "" {
			continue
		}
		if total+len(payload) > spaStateMaxContainerBytes {
			payload = payload[:spaStateMaxContainerBytes-total]
		}
		if payload == "" {
			break
		}
		parts = append(parts, payload)
		total += len(payload)
		if len(parts) >= spaStateMaxFlightPayloads {
			break
		}
	}
	return strings.Join(parts, "\n")
}

// spaStateSensitiveValue applies placeholder/environment-reference filters.
// What: Rejects template/env indirections and documented sample values.
// Why: Serialized defaults are extremely common; precision comes first.
func spaStateSensitiveValue(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < spaStateMinSensitiveValue || jsSecretPlaceholder(v) {
		return false
	}
	lower := strings.ToLower(v)
	for _, m := range []string{
		"{{", "${", "process.env", "import.meta.env", "os.environ",
		"env[", "<%", "****", "redacted", "replace_me",
	} {
		if strings.Contains(lower, m) {
			return false
		}
	}
	return true
}
