// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	nethtml "golang.org/x/net/html"
)

// ReflectionParams describes the canary and the contexts that are allowed to
// support a reflection claim. Contexts is intentionally enforced by Verify;
// it is not merely a hint for a plugin author.
type ReflectionParams struct {
	Canary                   string
	Contexts                 []string // html, attr, attr-executable, script, url
	RequireExecutableContext bool
	ControlBody              string // clean control; required for confirmed
	BrowserVerified          bool   // controlled headless run was performed
	BrowserTriggered         bool   // the canary executed in that run
	BrowserControlClean      bool   // neutral control did not execute
}

// ReflectionOracle performs HTML tokenization plus parser-backed JavaScript
// call analysis. It does not render a browser; static evidence and browser
// confirmation are separate outcomes.
type ReflectionOracle struct{}

func (ReflectionOracle) Name() string { return "reflection" }

type reflectionMatch struct {
	Context string
	Source  string
}

// ContextOf returns the strongest context in which canary occurs. The
// script-string/script-comment/json results are deliberately distinct from
// executable script: HTML tokenization alone is not JavaScript proof.
func ContextOf(body, canary string) string {
	matches := inspectReflection(body, canary)
	if likelyEncoded(body, canary) {
		return "encoded"
	}
	if len(matches) == 0 {
		return "none"
	}
	best := matches[0].Context
	bestRank := contextRank(best)
	for _, m := range matches[1:] {
		if r := contextRank(m.Context); r > bestRank {
			best, bestRank = m.Context, r
		}
	}
	return best
}

func contextRank(ctx string) int {
	switch ctx {
	case "script", "attr-executable":
		return 6
	case "url-executable":
		return 5
	case "url", "attr":
		return 4
	case "style":
		return 3
	case "html-text":
		return 2
	case "script-string", "script-comment", "json", "script-inert":
		return 1
	case "comment":
		return 0
	default:
		return -1
	}
}

// inspectReflection identifies each occurrence instead of letting one high
// level string label every canary in the response.
func inspectReflection(body, canary string) []reflectionMatch {
	if canary == "" || !strings.Contains(body, canary) {
		return nil
	}
	var matches []reflectionMatch
	add := func(ctx, source string) {
		if source == "" {
			source = body
		}
		matches = append(matches, reflectionMatch{Context: ctx, Source: source})
	}

	tok := nethtml.NewTokenizer(strings.NewReader(body))
	inScript, inStyle := false, false
	scriptExecutable := false
	scriptContext := "script-inert"
	for {
		tt := tok.Next()
		switch tt {
		case nethtml.ErrorToken:
			return matches
		case nethtml.CommentToken:
			if strings.Contains(string(tok.Text()), canary) {
				add("comment", string(tok.Text()))
			}
		case nethtml.StartTagToken, nethtml.SelfClosingTagToken:
			tn, hasAttr := tok.TagName()
			tag := strings.ToLower(string(tn))
			typeValue := ""
			if hasAttr {
				for {
					k, v, more := tok.TagAttr()
					name, value := strings.ToLower(string(k)), string(v)
					if tag == "script" && name == "type" {
						typeValue = value
					}
					if strings.Contains(value, canary) {
						switch {
						case strings.HasPrefix(name, "on"):
							add("attr-executable", value)
						case isURLAttribute(name) && isJavaScriptURL(value):
							add("url-executable", value)
						case isURLAttribute(name):
							add("url", value)
						default:
							add("attr", value)
						}
					}
					if !more {
						break
					}
				}
			}
			if tag == "script" {
				scriptExecutable = executableScriptType(typeValue)
				if scriptExecutable {
					scriptContext = "script"
				} else if isJSONScriptType(typeValue) {
					scriptContext = "json"
				} else {
					scriptContext = "script-inert"
				}
				inScript = tt == nethtml.StartTagToken
			}
			if tag == "style" {
				inStyle = tt == nethtml.StartTagToken
			}
		case nethtml.EndTagToken:
			tn, _ := tok.TagName()
			tag := strings.ToLower(string(tn))
			if tag == "script" {
				inScript = false
				scriptExecutable = false
				scriptContext = "script-inert"
			}
			if tag == "style" {
				inStyle = false
			}
		case nethtml.TextToken:
			text := string(tok.Text())
			if !strings.Contains(text, canary) {
				continue
			}
			switch {
			case inScript && scriptExecutable:
				add(jsContext(text, canary), text)
			case inScript:
				add(scriptContext, text)
			case inStyle:
				add("style", text)
			default:
				add("html-text", text)
			}
		}
	}
}

func isURLAttribute(name string) bool {
	switch name {
	case "href", "src", "action", "formaction", "xlink:href":
		return true
	default:
		return false
	}
}

func isJavaScriptURL(value string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "javascript:")
}

func executableScriptType(value string) bool {
	t := strings.ToLower(strings.TrimSpace(value))
	if t == "" || t == "module" {
		return true
	}
	if strings.Contains(t, ";") {
		t = strings.TrimSpace(strings.SplitN(t, ";", 2)[0])
	}
	switch t {
	case "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript":
		return true
	default:
		return false
	}
}

func isJSONScriptType(value string) bool {
	t := strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(t, "json") || t == "importmap"
}

// jsContext classifies the canary token, not the whole script element. A
// canary in a string or comment can coexist with executable code elsewhere,
// but it is not evidence that the canary itself is executable.
func jsContext(source, canary string) string {
	const (
		jsCode = iota
		jsSingle
		jsDouble
		jsTemplate
		jsLineComment
		jsBlockComment
	)
	state := jsCode
	foundCode, foundString, foundComment := false, false, false
	for i := 0; i < len(source); {
		if strings.HasPrefix(source[i:], canary) {
			switch state {
			case jsCode:
				foundCode = true
			case jsLineComment, jsBlockComment:
				foundComment = true
			default:
				foundString = true
			}
			i += len(canary)
			continue
		}
		ch := source[i]
		switch state {
		case jsCode:
			switch {
			case ch == '/' && i+1 < len(source) && source[i+1] == '/':
				state, i = jsLineComment, i+2
			case ch == '/' && i+1 < len(source) && source[i+1] == '*':
				state, i = jsBlockComment, i+2
			case ch == '\\' && i+1 < len(source):
				i += 2
			case ch == '\'':
				state, i = jsSingle, i+1
			case ch == '"':
				state, i = jsDouble, i+1
			case ch == '`':
				state, i = jsTemplate, i+1
			default:
				i++
			}
		case jsSingle, jsDouble, jsTemplate:
			if ch == '\\' && i+1 < len(source) {
				i += 2
			} else if (state == jsSingle && ch == '\'') || (state == jsDouble && ch == '"') || (state == jsTemplate && ch == '`') {
				state, i = jsCode, i+1
			} else {
				i++
			}
		case jsLineComment:
			if ch == '\n' || ch == '\r' {
				state = jsCode
			}
			i++
		case jsBlockComment:
			if ch == '*' && i+1 < len(source) && source[i+1] == '/' {
				state, i = jsCode, i+2
			} else {
				i++
			}
		}
	}
	if foundCode {
		return "script"
	}
	if foundString {
		return "script-string"
	}
	if foundComment {
		return "script-comment"
	}
	return "script"
}

// likelyEncoded is intentionally local to the canary. An unrelated entity in
// a large response must not downgrade a genuine reflection.
func likelyEncoded(body, canary string) bool {
	for from := 0; ; {
		rel := strings.Index(body[from:], canary)
		if rel < 0 {
			return false
		}
		idx := from + rel
		lo := max(0, idx-12)
		prefix := strings.ToLower(body[lo:idx])
		if strings.HasSuffix(prefix, "&lt;") || strings.HasSuffix(prefix, "&gt;") || strings.HasSuffix(prefix, "&amp;") || strings.HasSuffix(prefix, "&quot;") || strings.Contains(prefix, "&#") || strings.HasSuffix(prefix, `\u`) {
			return true
		}
		from = idx + len(canary)
		if from >= len(body) {
			return false
		}
	}
}

// Verify applies baseline, allowed-context, parser and control checks. A
// canary alone can at most produce tentative reflection; static execution
// evidence requires a recognizable call plus a clean control. Confirmed is
// reserved for a supplied controlled headless result.
func (ReflectionOracle) Verify(ctx context.Context, body string, headers http.Header, cls baseline.Classification, tainted bool, p ReflectionParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	if p.Canary == "" {
		return &Evidence{Verdict: VerdictReject, Note: "empty canary"}, nil
	}
	matches := inspectReflection(body, p.Canary)
	if len(matches) == 0 {
		if likelyEncoded(body, p.Canary) {
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: map[string]string{"context": "encoded", "canary": p.Canary}, Note: "encoded reflection"}, nil
		}
		return &Evidence{Verdict: VerdictReject, Note: "no reflection"}, nil
	}

	selected, proof := selectReflectionMatch(matches, p)
	if selected == nil {
		return &Evidence{Verdict: VerdictReject, Note: "reflection context is not allowed"}, nil
	}
	art := map[string]string{"context": selected.Context, "canary": p.Canary}
	if !contextAllowed(selected.Context, p.Contexts) {
		return &Evidence{Verdict: VerdictReject, Artifacts: art, Note: "reflection context is not allowed"}, nil
	}

	switch selected.Context {
	case "encoded":
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: art, Note: "encoded reflection"}, nil
	case "comment", "script-comment", "script-string", "json", "script-inert":
		return &Evidence{Verdict: VerdictReject, Artifacts: art, Note: "non-executable reflection"}, nil
	case "style":
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: art, Note: "CSS reflection is not execution proof"}, nil
	case "html-text":
		if p.RequireExecutableContext {
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: art, Note: "HTML text reflection is not execution proof"}, nil
		}
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceFirm, Artifacts: art, Note: "text reflection"}, nil
	case "attr", "url":
		if p.RequireExecutableContext {
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: art, Note: "non-executable attribute/URL reflection"}, nil
		}
		return controlEvidence(p, art, selected.Context, false)
	case "script", "attr-executable", "url-executable":
		if strings.Contains(p.ControlBody, p.Canary) && ContextOf(p.ControlBody, p.Canary) == selected.Context {
			return &Evidence{Verdict: VerdictReject, Artifacts: art, Note: "control also reflects in the same executable context"}, nil
		}
		if p.RequireExecutableContext && !proof {
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: art, Note: "canary reflection without an execution payload"}, nil
		}
		if cspBlocksInline(headers) {
			art["csp"] = "inline-execution-blocked"
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: art, Note: "CSP blocks inline execution"}, nil
		}
		return controlEvidence(p, art, selected.Context, proof)
	default:
		return &Evidence{Verdict: VerdictReject, Note: fmt.Sprintf("unknown reflection context %q", selected.Context)}, nil
	}
}

func selectReflectionMatch(matches []reflectionMatch, p ReflectionParams) (*reflectionMatch, bool) {
	var selected *reflectionMatch
	selectedRank := -1
	selectedProof := false
	for i := range matches {
		m := &matches[i]
		if !contextAllowed(m.Context, p.Contexts) {
			continue
		}
		proof := executableProof(m.Context, m.Source, p.Canary)
		rank := contextRank(m.Context)
		if proof {
			rank += 10
		}
		if selected == nil || rank > selectedRank {
			selected, selectedRank, selectedProof = m, rank, proof
		}
	}
	return selected, selectedProof
}

func contextAllowed(actual string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, raw := range allowed {
		a := strings.ToLower(strings.TrimSpace(raw))
		switch a {
		case "html", "html-text":
			a = "html-text"
		case "script":
			a = "script"
		case "attr-executable", "event-handler":
			a = "attr-executable"
		case "url-executable", "javascript-url":
			a = "url-executable"
		case "json":
			a = "json"
		}
		if actual == a {
			return true
		}
	}
	return false
}

func executableProof(ctx, source, canary string) bool {
	if ctx != "script" && ctx != "attr-executable" && ctx != "url-executable" {
		return false
	}
	if ctx == "url-executable" {
		lower := strings.ToLower(strings.TrimSpace(source))
		if !strings.HasPrefix(lower, "javascript:") {
			return false
		}
		source = strings.TrimSpace(source[len("javascript:"):])
	}
	program, err := parser.ParseFile(nil, "reflection.js", source, 0)
	if err != nil {
		return false
	}
	return astHasExecution(program, source, canary)
}

// astHasExecution requires a parsed call expression whose source range also
// contains the canary. This avoids treating comments or unrelated literals as
// execution proof while keeping event-handler snippets supported.
func astHasExecution(program *ast.Program, source, canary string) bool {
	markers := map[string]bool{
		"alert": true, "confirm": true, "prompt": true, "eval": true,
		"fetch": true, "settimeout": true, "setinterval": true,
		"write": true, "writeln": true, "open": true,
	}
	found := false
	var walk func(reflect.Value)
	walk = func(v reflect.Value) {
		if found || !v.IsValid() {
			return
		}
		switch v.Kind() {
		case reflect.Interface:
			if !v.IsNil() {
				walk(v.Elem())
			}
		case reflect.Pointer:
			if v.IsNil() {
				return
			}
			if call, ok := v.Interface().(*ast.CallExpression); ok {
				if markers[astCalleeName(call.Callee)] && nodeContainsCanary(call, source, canary) {
					found = true
					return
				}
			}
			walk(v.Elem())
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Field(i).CanInterface() {
					walk(v.Field(i))
				}
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
			}
		}
	}
	walk(reflect.ValueOf(program))
	return found
}

func astCalleeName(expr ast.Expression) string {
	switch e := expr.(type) {
	case *ast.Identifier:
		return strings.ToLower(e.Name.String())
	case *ast.DotExpression:
		return strings.ToLower(e.Identifier.Name.String())
	default:
		return ""
	}
}

func nodeContainsCanary(node ast.Node, source, canary string) bool {
	start, end := int(node.Idx0())-1, int(node.Idx1())-1
	if start < 0 || end < start || start > len(source) {
		return false
	}
	if end > len(source) {
		end = len(source)
	}
	return strings.Contains(strings.ToLower(source[start:end]), strings.ToLower(canary))
}

func controlEvidence(p ReflectionParams, art map[string]string, ctx string, proof bool) (*Evidence, error) {
	if p.ControlBody == "" {
		if proof {
			art["execution"] = "static"
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceStaticExecution, Artifacts: art, Note: "static execution payload; clean control unavailable; browser not executed"}, nil
		}
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceFirm, Artifacts: art, Note: "executable reflection without control"}, nil
	}
	if strings.Contains(p.ControlBody, p.Canary) {
		controlCtx := ContextOf(p.ControlBody, p.Canary)
		if controlCtx == ctx || executableProof(controlCtx, p.ControlBody, p.Canary) {
			return &Evidence{Verdict: VerdictReject, Note: "control also reflects the canary"}, nil
		}
		return &Evidence{Verdict: VerdictReject, Note: "control contains the canary"}, nil
	}
	if proof {
		if p.BrowserVerified {
			if p.BrowserTriggered && p.BrowserControlClean {
				art["execution"] = "browser-confirmed"
				return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceConfirmed, Artifacts: art, Repeats: 1, ControlResult: "clean", Note: "browser execution plus clean control"}, nil
			}
			return &Evidence{Verdict: VerdictReject, Artifacts: art, Note: "headless browser did not execute the canary"}, nil
		}
		art["execution"] = "static"
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceStaticExecution, Artifacts: art, Repeats: 1, ControlResult: "clean", Note: "static execution payload plus clean control; browser not executed"}, nil
	}
	return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceFirm, Artifacts: art, ControlResult: "clean", Note: "executable context without payload proof"}, nil
}

func cspBlocksInline(headers http.Header) bool {
	if headers == nil {
		return false
	}
	policy := headers.Get("Content-Security-Policy")
	if policy == "" {
		return false
	}
	defaultBlocks, scriptBlocks := false, false
	hasScriptSource := false
	for _, directive := range strings.Split(strings.ToLower(policy), ";") {
		fields := strings.Fields(directive)
		if len(fields) == 0 || (fields[0] != "script-src" && fields[0] != "default-src") {
			continue
		}
		blocks := true
		for _, token := range fields[1:] {
			if token == "'unsafe-inline'" {
				blocks = false
				break
			}
		}
		if fields[0] == "script-src" {
			hasScriptSource = true
			scriptBlocks = blocks
		} else {
			defaultBlocks = blocks
		}
	}
	if hasScriptSource {
		return scriptBlocks
	}
	return defaultBlocks
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
