// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"context"
	"fmt"
	"html"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// FixturePasswdHint is the traversal signature the lab emits on traversal payloads.
	FixturePasswdHint = "etc/passwd"
	// FixtureOpenFailed is the file-access error signature emitted on traversal payloads.
	FixtureOpenFailed = "failed to open stream: No such file or directory"
	// FixtureSQLError is the MySQL error string emitted on quote payloads.
	FixtureSQLError = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near 'x' at line 1"
	// FixtureShellError is the shell error string emitted on shell-metachar payloads.
	FixtureShellError = "sh: 1: Syntax error: '(' unexpected"
	// FixtureSoft404 is the fake 200 page used by the soft-404 trap.
	FixtureSoft404 = "Nothing to see here (bench soft-404 page)"
	// FixtureWAFBlock is the body served when the experiment WAF blocks a payload.
	FixtureWAFBlock = "Request blocked by bench WAF (experiment)"
	// FixtureDenied is the body of the access-denied trap.
	FixtureDenied = "Forbidden"
)

// FixtureLab is the seeded localhost application used by the fixtures dataset.
// It is intentionally a plain HTTP server: every scenario is reachable through
// links from the index page so the scanner discovers the same surface it would
// find on a real target. It counts every request it receives per path, giving
// the benchmark an independent request counter for both tools.
type FixtureLab struct {
	srv    *http.Server
	ln     net.Listener
	host   string
	total  atomic.Int64
	mu     sync.Mutex
	counts map[string]int64
	store  []string
}

// StartFixtureLab binds 127.0.0.1:0 and serves the lab until Close.
func StartFixtureLab() (*FixtureLab, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bench fixture lab: listen: %w", err)
	}
	lab := &FixtureLab{ln: ln, host: "127.0.0.1", counts: map[string]int64{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", lab.handle)
	lab.srv = &http.Server{Handler: lab.countMiddleware(mux), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = lab.srv.Serve(ln) }()
	return lab, nil
}

// URL is the lab base URL (http://127.0.0.1:<port>).
func (l *FixtureLab) URL() string { return "http://" + l.ln.Addr().String() }

// Close shuts the lab down.
func (l *FixtureLab) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return l.srv.Shutdown(ctx)
}

// Total returns the number of requests observed since start.
func (l *FixtureLab) Total() int64 { return l.total.Load() }

// Snapshot copies the per-path request counters.
func (l *FixtureLab) Snapshot() map[string]int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]int64, len(l.counts))
	for k, v := range l.counts {
		out[k] = v
	}
	return out
}

func (l *FixtureLab) countMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.total.Add(1)
		l.mu.Lock()
		l.counts[r.URL.Path]++
		l.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (l *FixtureLab) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/":
		l.index(w)
	case r.URL.Path == "/xss/reflect" || r.URL.Path == "/xss/reflect2" ||
		r.URL.Path == "/xss/attr" || r.URL.Path == "/xss/attr2" ||
		r.URL.Path == "/xss/attr-quoted" || r.URL.Path == "/xss/attr-quoted2" ||
		r.URL.Path == "/xss/attr-single" || r.URL.Path == "/xss/attr-single2" ||
		r.URL.Path == "/xss/js" || r.URL.Path == "/xss/js2" ||
		r.URL.Path == "/xss/js-double" || r.URL.Path == "/xss/js-double2" ||
		r.URL.Path == "/xss/url" || r.URL.Path == "/xss/url2" ||
		r.URL.Path == "/xss/json-raw" || r.URL.Path == "/xss/json-raw2" ||
		r.URL.Path == "/xss/escape" || r.URL.Path == "/xss/escape2" ||
		r.URL.Path == "/xss/textarea" || r.URL.Path == "/xss/title" || r.URL.Path == "/xss/dom":
		l.xss(w, r)
	case r.URL.Path == "/stored":
		l.stored(w, r)
	case r.URL.Path == "/sqli/error" || r.URL.Path == "/sqli/numeric":
		l.sqli(w, r)
	case r.URL.Path == "/sqli/clean" || r.URL.Path == "/sqli/clean2":
		l.sqliClean(w, r)
	case r.URL.Path == "/traversal" || r.URL.Path == "/traversal/passwd":
		l.traversal(w, r)
	case r.URL.Path == "/cmdi":
		l.cmdi(w, r)
	case r.URL.Path == "/redirect" || r.URL.Path == "/redirect/next":
		l.redirect(w, r)
	case r.URL.Path == "/redirect/clean" || r.URL.Path == "/redirect/clean2":
		l.redirectClean(w, r)
	case r.URL.Path == "/README.md":
		l.artifact(w, "# Gash Bench Lab\n\nSeeded fixture README for benchmark exposure coverage.\n")
	case r.URL.Path == "/.gitignore":
		l.artifact(w, "bench-notes.txt\nconfig.inc.php.bak\n.DS_Store\n")
	case r.URL.Path == "/.github/workflows/main.yml":
		l.artifact(w, "name: Bench CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n")
	case r.URL.Path == "/robots.txt":
		l.artifact(w, "User-agent: *\nDisallow: /admin\nDisallow: /backup\n")
	case r.URL.Path == "/clean/search" || r.URL.Path == "/clean/search2":
		l.cleanSearch(w, r)
	case r.URL.Path == "/clean/inline":
		l.cleanInline(w)
	case r.URL.Path == "/denied" || r.URL.Path == "/denied2":
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(FixtureDenied))
	case r.URL.Path == "/waf" || r.URL.Path == "/waf2":
		l.waf(w, r)
	case r.URL.Path == "/slow" || r.URL.Path == "/slow2":
		time.Sleep(1500 * time.Millisecond)
		l.page(w, "slow page done")
	case strings.HasPrefix(r.URL.Path, "/soft404/"):
		l.page(w, FixtureSoft404)
	case r.URL.Path == "/auth/a/secret":
		l.authSecret(w, r, "alice", "bench-user-a")
	case r.URL.Path == "/auth/b/secret":
		l.authSecret(w, r, "bob", "bench-user-b")
	default:
		http.NotFound(w, r)
	}
}

func (l *FixtureLab) page(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "<!doctype html><html><body>%s</body></html>", body)
}

func (l *FixtureLab) index(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, `<!doctype html><html><body>
<h1>Bench Lab</h1>
<ul>
<li><a href="/xss/reflect?q=hello">reflect</a></li>
<li><a href="/xss/attr?q=hello">attr</a></li>
<li><a href="/xss/attr-quoted?q=hello">attr-quoted</a></li>
<li><a href="/xss/attr-single?q=hello">attr-single</a></li>
<li><a href="/xss/js?q=hello">js</a></li>
<li><a href="/xss/js-double?q=hello">js-double</a></li>
<li><a href="/xss/url?q=hello">url</a></li>
<li><a href="/xss/json-raw?q=hello">json-raw</a></li>
<li><a href="/xss/textarea?q=hello">textarea</a></li>
<li><a href="/xss/title?q=hello">title</a></li>
<li><a href="/xss/escape?q=hello">escape</a></li>
<li><a href="/xss/dom?q=hello">dom</a></li>
<li><a href="/stored?message=hello">stored</a></li>
<li><a href="/sqli/error?id=1">sqli</a></li>
<li><a href="/sqli/numeric?id=1">sqli-numeric</a></li>
<li><a href="/sqli/clean?id=1">sqli-clean</a></li>
<li><a href="/traversal?file=readme.txt">traversal</a></li>
<li><a href="/traversal/passwd?file=readme.txt">traversal-passwd</a></li>
<li><a href="/cmdi?cmd=ping">cmdi</a></li>
<li><a href="/redirect?url=/home">redirect</a></li>
<li><a href="/redirect/next?next=/home">redirect-next</a></li>
<li><a href="/redirect/clean?next=/home">redirect-clean</a></li>
<li><a href="/README.md">readme</a></li>
<li><a href="/xss/reflect2?q=hello">reflect-2</a></li>
<li><a href="/xss/attr2?q=hello">attr-2</a></li>
<li><a href="/xss/attr-quoted2?q=hello">attr-quoted-2</a></li>
<li><a href="/xss/attr-single2?q=hello">attr-single-2</a></li>
<li><a href="/xss/js2?q=hello">js-2</a></li>
<li><a href="/xss/js-double2?q=hello">js-double-2</a></li>
<li><a href="/xss/url2?q=hello">url-2</a></li>
<li><a href="/xss/escape2?q=hello">escape-2</a></li>
<li><a href="/xss/json-raw2?q=hello">json-raw-2</a></li>
<li><a href="/clean/search2?q=hello">clean-search-2</a></li>
<li><a href="/sqli/clean2?id=1">sqli-clean-2</a></li>
<li><a href="/redirect/clean2?next=/home">redirect-clean-2</a></li>
<li><a href="/denied2?q=hello">denied-2</a></li>
<li><a href="/waf2?q=hello">waf-2</a></li>
<li><a href="/slow2?q=hello">slow-2</a></li>
<li><a href="/robots.txt">robots</a></li>
<li><a href="/.gitignore">gitignore</a></li>
<li><a href="/.github/workflows/main.yml">workflow</a></li>
<li><a href="/clean/search?q=hello">clean-search</a></li>
<li><a href="/clean/inline">clean-inline</a></li>
<li><a href="/soft404/help?q=hello">docs-page</a></li>
<li><a href="/denied?q=hello">legacy-page</a></li>
<li><a href="/waf?q=hello">waf-proxy</a></li>
<li><a href="/slow?q=hello">slow-report</a></li>
<li><a href="/auth/a/secret?id=1">account-a</a></li>
<li><a href="/auth/b/secret?id=1">account-b</a></li>
</ul>
<form method="POST" action="/stored"><input name="message" value=""><button>post</button></form>
</body></html>`)
}

var xssParamNames = []string{"q", "query", "search", "name", "input", "value", "title", "message", "comment"}

func (l *FixtureLab) xss(w http.ResponseWriter, r *http.Request) {
	v := firstParam(r, xssParamNames...)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	path := strings.TrimSuffix(r.URL.Path, "2")
	switch path {
	case "/xss/reflect":
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body><div id=\"result\">%s</div></body></html>", v)
	case "/xss/attr-quoted":
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body><input value=%s></body></html>", v)
	case "/xss/attr":
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body><input value=\"%s\"></body></html>", v)
	case "/xss/attr-single":
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body><input value='%s'></body></html>", v)
	case "/xss/js":
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body><script>var q='%s';</script></body></html>", v)
	case "/xss/js-double":
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body><script>var q=\"%s\";</script></body></html>", v)
	case "/xss/url":
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body><a href=\"%s\">next</a></body></html>", v)
	case "/xss/json-raw":
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"q":"%s"}`, v)
	case "/xss/textarea":
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body><textarea>%s</textarea></body></html>", v)
	case "/xss/title":
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body><title>%s</title><h1>page</h1></body></html>", v)
	case "/xss/escape":
		rp := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body><div id=\"result\">%s</div></body></html>", rp.Replace(v))
	case "/xss/dom":
		_, _ = fmt.Fprint(w, `<!doctype html><html><body><div id="out">default</div>
<script>document.write(decodeURIComponent(location.hash.slice(1)))</script></body></html>`)
	}
}

func (l *FixtureLab) stored(w http.ResponseWriter, r *http.Request) {
	if v := firstParam(r, "message", "comment", "body", "input", "name", "title", "content"); v != "" {
		l.mu.Lock()
		l.store = append(l.store, v)
		if len(l.store) > 50 {
			l.store = l.store[len(l.store)-50:]
		}
		l.mu.Unlock()
	}
	l.mu.Lock()
	items := strings.Join(l.store, "</div><div>")
	l.mu.Unlock()
	l.page(w, "<div>"+items+"</div>")
}

func (l *FixtureLab) sqli(w http.ResponseWriter, r *http.Request) {
	v := firstParam(r, "id", "q", "user", "category", "item")
	if strings.ContainsAny(v, "'\"") || strings.Contains(strings.ToUpper(v), " OR ") || strings.Contains(strings.ToUpper(v), "SLEEP(") {
		w.WriteHeader(http.StatusInternalServerError)
		l.page(w, FixtureSQLError)
		return
	}
	l.page(w, "item "+html.EscapeString(v))
}

func (l *FixtureLab) sqliClean(w http.ResponseWriter, r *http.Request) {
	v := firstParam(r, "id", "q", "user", "category", "item")
	l.page(w, "item "+html.EscapeString(v))
}

func (l *FixtureLab) traversal(w http.ResponseWriter, r *http.Request) {
	v := firstParam(r, "file", "path", "page", "include", "template")
	if strings.Contains(strings.ToLower(v), "..") || strings.Contains(strings.ToLower(v), "etc/passwd") ||
		strings.Contains(strings.ToLower(v), "win.ini") || strings.Contains(v, "%2e") {
		if r.URL.Path == "/traversal/passwd" {
			l.page(w, "<pre>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</pre>")
			return
		}
		l.page(w, "Warning: include("+html.EscapeString(v)+"): "+FixtureOpenFailed)
		return
	}
	l.page(w, "requested file is not available")
}

func (l *FixtureLab) artifact(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprint(w, body)
}

func (l *FixtureLab) cmdi(w http.ResponseWriter, r *http.Request) {
	v := firstParam(r, "cmd", "exec", "command", "ip", "host", "target", "arg")
	if strings.ContainsAny(v, ";|`&$") || strings.Contains(v, "$(") {
		l.page(w, FixtureShellError)
		return
	}
	l.page(w, "ping result for "+html.EscapeString(v))
}

func (l *FixtureLab) redirect(w http.ResponseWriter, r *http.Request) {
	v := firstParam(r, "url", "redirect", "next", "return_to", "return")
	lower := strings.ToLower(v)
	if (strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")) &&
		!strings.Contains(lower, "127.0.0.1") && !strings.Contains(lower, "localhost") {
		http.Redirect(w, r, v, http.StatusFound)
		return
	}
	l.page(w, "redirect target accepted")
}

func (l *FixtureLab) redirectClean(w http.ResponseWriter, r *http.Request) {
	l.page(w, "redirect target accepted (no redirect performed)")
}

func (l *FixtureLab) cleanSearch(w http.ResponseWriter, r *http.Request) {
	v := firstParam(r, "q", "query", "search", "name", "input", "value", "title")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	_, _ = fmt.Fprintf(w, "<!doctype html><html><body><div id=\"result\">%s</div></body></html>", html.EscapeString(v))
}

func (l *FixtureLab) cleanInline(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "geolocation=()")
	_, _ = fmt.Fprint(w, "<!doctype html><html><body><h1>bench inline page</h1></body></html>")
}

func (l *FixtureLab) waf(w http.ResponseWriter, r *http.Request) {
	v := firstParam(r, "q", "query", "search", "name", "input", "value", "title", "id", "file", "url", "cmd", "redirect", "next")
	if looksLikeAttack(v) {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body>%s</body></html>", FixtureWAFBlock)
		return
	}
	l.page(w, "proxy page for "+html.EscapeString(v))
}

func (l *FixtureLab) authSecret(w http.ResponseWriter, r *http.Request, user, marker string) {
	if r.Header.Get("X-Bench-User") != user {
		w.WriteHeader(http.StatusUnauthorized)
		l.page(w, "auth required")
		return
	}
	l.page(w, "secret page for "+marker)
}

func firstParam(r *http.Request, names ...string) string {
	q := r.URL.Query()
	for _, n := range names {
		if v := q.Get(n); v != "" {
			return v
		}
	}
	return ""
}

func looksLikeAttack(v string) bool {
	if v == "" {
		return false
	}
	lower := strings.ToLower(v)
	for _, sig := range []string{"<", ">", "'", "\"", "..", ";", "|", "`", "$(", "script", "union", "select", "sleep(", "onerror", "onload"} {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}
