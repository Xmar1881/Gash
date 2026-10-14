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
}

// CommonCandidateParams is the default parameter dictionary used when no parameters are exposed.
var CommonCandidateParams = []string{
	"id", "query", "search", "q", "page", "url", "redirect", "file", "path", "user", "cat", "item", "input",
}

// ExtractSurface analyzes target URL and HTML response body to discover all injection points.
func ExtractSurface(targetURL string, body []byte) []InjectionPoint {
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
	if len(points) == 0 {
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
	method := "GET"
	action := base.String()

	for _, attr := range form.Attr {
		switch strings.ToLower(attr.Key) {
		case "method":
			method = strings.ToUpper(strings.TrimSpace(attr.Val))
		case "action":
			if rel, err := url.Parse(strings.TrimSpace(attr.Val)); err == nil {
				action = base.ResolveReference(rel).String()
			}
		}
	}

	paramLoc := "query"
	if method == "POST" || method == "PUT" || method == "PATCH" {
		paramLoc = "body"
	}

	var collectInputs func(*html.Node)
	collectInputs = func(n *html.Node) {
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			if tag == "input" || tag == "textarea" || tag == "select" {
				name, val, inputType := "", "", "text"
				for _, attr := range n.Attr {
					switch strings.ToLower(attr.Key) {
					case "name":
						name = strings.TrimSpace(attr.Val)
					case "value":
						val = attr.Val
					case "type":
						inputType = strings.ToLower(strings.TrimSpace(attr.Val))
					}
				}
				// Skip submit buttons and image inputs with no relevant name
				if name != "" && inputType != "submit" && inputType != "image" && inputType != "button" {
					addPoint(InjectionPoint{
						URL:           action,
						Method:        method,
						ParamName:     name,
						ParamLocation: paramLoc,
						Value:         val,
					})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			collectInputs(c)
		}
	}
	collectInputs(form)
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
