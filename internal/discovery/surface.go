// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// InjectionPoint represents a testable injection target (URL parameter, form input, header, etc.).
type InjectionPoint struct {
	URL           string
	Method        string
	ParamName     string
	ParamLocation string // "query", "body", "header"
	Value         string
	// FormValues, when non-nil, marks this point as living inside an HTML form
	// and holds every other field's current value so the engine replays the
	// complete form with only this field replaced by the payload. Token fields
	// are kept verbatim so replay is accepted; findings MUST NOT serialize
	// this map (secrets would leak into reports).
	FormValues map[string]string
	// FormEnctype is the owning form's encoding
	// ("application/x-www-form-urlencoded" or "multipart/form-data").
	FormEnctype string
}

// FormField is one replayable control inside an HTML form.
type FormField struct {
	Name      string
	Value     string
	InputType string // "text", "hidden", "textarea", "select", "file", ...
	IsToken   bool   // CSRF/XSRF token fields are refreshed, never fuzzed
}

// Form is a parsed HTML form captured for full-form replay and fuzzing.
type Form struct {
	SourceURL string // page the form was extracted from (CSRF refresh target)
	ActionURL string // resolved submission target (empty action -> page URL)
	Method    string // uppercased, default "GET"
	Enctype   string // normalized: urlencoded, multipart/form-data, text/plain
	Fields    []FormField
}

// IsTokenField reports whether a field name looks like a CSRF/XSRF token.
// What: substring "csrf"/"xsrf" or a well-known exact token name.
// Why: tokens must be refreshed (not fuzzed) so full-form replay stays valid.
func IsTokenField(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	if strings.Contains(lower, "csrf") || strings.Contains(lower, "xsrf") {
		return true
	}
	switch lower {
	case "authenticity_token", "__requestverificationtoken", "requestverificationtoken", "_token", "nonce":
		return true
	}
	return false
}

// CommonCandidateParams is the default parameter dictionary used when no parameters are exposed.
var CommonCandidateParams = []string{
	"id", "query", "search", "q", "page", "url", "redirect", "file", "path", "user", "cat", "item", "input",
}

// ExtractSurface analyzes target URL and HTML response body to discover all injection points.
func ExtractSurface(targetURL string, body []byte) []InjectionPoint {
	return extractSurface(targetURL, body, true)
}

// extractSurface is ExtractSurface with an explicit fallback switch.
// What: allowFallback populates CommonCandidateParams when nothing was found.
// Why: Rendered SPA harvest must add only observed surface; synthetic fallback
// points are already supplied by the engine when the whole surface is empty.
func extractSurface(targetURL string, body []byte, allowFallback bool) []InjectionPoint {
	var points []InjectionPoint
	seen := make(map[string]bool)

	addPoint := func(p InjectionPoint) {
		if strings.TrimSpace(p.ParamName) == "" {
			return
		}
		if p.Method == "" {
			p.Method = "GET"
		}
		if p.ParamLocation == "" {
			p.ParamLocation = "query"
		}
		key := strings.ToUpper(p.Method) + "|" + p.URL + "|" + p.ParamLocation + "|" + p.ParamName
		if !seen[key] {
			seen[key] = true
			points = append(points, p)
		}
	}

	targetParsed, err := url.Parse(targetURL)
	if err != nil {
		return points
	}

	// 1. Extract query parameters from target URL
	for param, vals := range targetParsed.Query() {
		val := ""
		if len(vals) > 0 {
			val = vals[0]
		}
		addPoint(InjectionPoint{
			URL:           targetURL,
			Method:        "GET",
			ParamName:     param,
			ParamLocation: "query",
			Value:         val,
		})
	}

	// 2. Parse HTML forms and links if body is provided
	if len(body) > 0 {
		doc, err := html.Parse(bytes.NewReader(body))
		if err == nil {
			extractHTMLPoints(doc, targetParsed, addPoint)
		}
	}

	// 3. Fallback: If no injection points were discovered, populate common candidate params
	if allowFallback && len(points) == 0 {
		for _, param := range CommonCandidateParams {
			addPoint(InjectionPoint{
				URL:           targetURL,
				Method:        "GET",
				ParamName:     param,
				ParamLocation: "query",
				Value:         "",
			})
		}
	}

	return points
}

func extractHTMLPoints(n *html.Node, base *url.URL, addPoint func(InjectionPoint)) {
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch strings.ToLower(node.Data) {
			case "form":
				handleForm(node, base, addPoint)
			case "a":
				for _, attr := range node.Attr {
					if strings.ToLower(attr.Key) == "href" {
						handleLink(attr.Val, base, addPoint)
					}
				}
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
}

func handleForm(form *html.Node, base *url.URL, addPoint func(InjectionPoint)) {
	f, ok := parseForm(form, base)
	if !ok {
		return
	}

	paramLoc := "query"
	if f.Method == "POST" || f.Method == "PUT" || f.Method == "PATCH" {
		paramLoc = "body"
	}

	// Replayable co-fields: every other field a browser would submit. File
	// inputs are recorded but never replayed; text/plain forms stay legacy.
	coFields := make([]FormField, 0, len(f.Fields))
	if f.Enctype == "application/x-www-form-urlencoded" || f.Enctype == "multipart/form-data" {
		for _, fld := range f.Fields {
			if fld.InputType != "file" {
				coFields = append(coFields, fld)
			}
		}
	}

	for _, fld := range f.Fields {
		point := InjectionPoint{
			URL:           f.ActionURL,
			Method:        f.Method,
			ParamName:     fld.Name,
			ParamLocation: paramLoc,
			Value:         fld.Value,
		}
		if paramLoc == "body" && len(coFields) > 1 {
			vals := make(map[string]string, len(coFields)-1)
			for _, other := range coFields {
				if other.Name == fld.Name {
					continue
				}
				vals[other.Name] = other.Value
			}
			if len(vals) > 0 {
				point.FormValues = vals
				point.FormEnctype = f.Enctype
			}
		}
		addPoint(point)
	}
}

// ExtractForms parses body and returns every form with all replayable fields.
// What: Submission-accurate form model for full-form replay (engine side).
// Why: handleForm's point view drops hidden/token context, which breaks
// server-side validation and CSRF checks on real forms.
func ExtractForms(pageURL string, body []byte) []Form {
	if len(body) == 0 {
		return nil
	}
	base, err := url.Parse(pageURL)
	if err != nil || base.Host == "" {
		return nil
	}
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	var forms []Form
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "form") {
			if f, ok := parseForm(n, base); ok {
				forms = append(forms, f)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return forms
}

// parseForm builds the replayable Form model for one <form> element.
// Only controls that a browser would submit are captured: named inputs minus
// submit/image/button/reset, checked checkboxes/radios, selected select
// options, and textarea text. File inputs are recorded but never replayed.
// ok is false for forms without any replayable field.
func parseForm(form *html.Node, base *url.URL) (Form, bool) {
	f := Form{
		SourceURL: base.String(),
		ActionURL: base.String(),
		Method:    "GET",
		Enctype:   "application/x-www-form-urlencoded",
	}
	for _, attr := range form.Attr {
		switch strings.ToLower(attr.Key) {
		case "method":
			if m := strings.ToUpper(strings.TrimSpace(attr.Val)); m != "" {
				f.Method = m
			}
		case "action":
			if raw := strings.TrimSpace(attr.Val); raw != "" {
				if rel, err := url.Parse(raw); err == nil {
					f.ActionURL = base.ResolveReference(rel).String()
				}
			}
		case "enctype":
			enc := strings.ToLower(strings.TrimSpace(attr.Val))
			switch {
			case strings.Contains(enc, "multipart/form-data"):
				f.Enctype = "multipart/form-data"
			case strings.Contains(enc, "text/plain"):
				f.Enctype = "text/plain"
			}
		}
	}

	var collect func(*html.Node)
	collect = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "input":
				if field, ok := parseInputField(n); ok {
					f.Fields = append(f.Fields, field)
				}
			case "textarea":
				if name := nodeAttr(n, "name"); name != "" {
					f.Fields = append(f.Fields, FormField{
						Name:      name,
						Value:     nodeText(n),
						InputType: "textarea",
						IsToken:   IsTokenField(name),
					})
				}
			case "select":
				if name := nodeAttr(n, "name"); name != "" {
					f.Fields = append(f.Fields, FormField{
						Name:      name,
						Value:     selectValue(n),
						InputType: "select",
						IsToken:   IsTokenField(name),
					})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			collect(c)
		}
	}
	collect(form)
	if len(f.Fields) == 0 {
		return Form{}, false
	}
	return f, true
}

func parseInputField(n *html.Node) (FormField, bool) {
	name, val, inputType, checked := "", "", "text", false
	for _, attr := range n.Attr {
		switch strings.ToLower(attr.Key) {
		case "name":
			name = strings.TrimSpace(attr.Val)
		case "value":
			val = attr.Val
		case "type":
			inputType = strings.ToLower(strings.TrimSpace(attr.Val))
		case "checked":
			checked = true
		}
	}
	if name == "" {
		return FormField{}, false
	}
	switch inputType {
	case "submit", "image", "button", "reset":
		return FormField{}, false
	case "checkbox", "radio":
		if !checked {
			return FormField{}, false
		}
		if inputType == "checkbox" && val == "" {
			val = "on" // browser default for a checked valueless checkbox
		}
	}
	return FormField{
		Name:      name,
		Value:     val,
		InputType: inputType,
		IsToken:   IsTokenField(name),
	}, true
}

func nodeAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, key) {
			return strings.TrimSpace(attr.Val)
		}
	}
	return ""
}

func nodeText(n *html.Node) string {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			return strings.TrimSpace(c.Data)
		}
	}
	return ""
}

// selectValue returns the value a browser would submit: the first selected
// option, else the first option (value attr, falling back to its text).
func selectValue(selectNode *html.Node) string {
	var first, selected string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "option") {
			v := nodeAttr(n, "value")
			if v == "" {
				v = nodeText(n)
			}
			if first == "" && v != "" {
				first = v
			}
			if selected == "" {
				for _, attr := range n.Attr {
					if strings.EqualFold(attr.Key, "selected") {
						selected = v
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(selectNode)
	if selected != "" {
		return selected
	}
	return first
}

func handleLink(href string, base *url.URL, addPoint func(InjectionPoint)) {
	u, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return
	}
	resolved := base.ResolveReference(u)
	if !strings.EqualFold(resolved.Hostname(), base.Hostname()) {
		return
	}
	for param, vals := range resolved.Query() {
		val := ""
		if len(vals) > 0 {
			val = vals[0]
		}
		cleanURL := *resolved
		cleanURL.RawQuery = ""
		addPoint(InjectionPoint{
			URL:           cleanURL.String(),
			Method:        "GET",
			ParamName:     param,
			ParamLocation: "query",
			Value:         val,
		})
	}
}
