// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Verification is the independent ground-truth check result for one scenario.
type Verification struct {
	Kind       string `json:"kind"`
	Verified   bool   `json:"verified"`
	Detail     string `json:"detail,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// Verifier independently verifies scenarios before scoring: it never consumes
// scanner output and never trusts dataset labels alone.
type Verifier struct {
	Client *http.Client
}

// NewVerifier builds a verifier with a bounded default client.
func NewVerifier() *Verifier {
	return &Verifier{Client: &http.Client{Timeout: 15 * time.Second}}
}

// NewMarker returns a unique per-run verification marker.
func NewMarker() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "gashbench" + hex.EncodeToString(b[:])
}

// VerifyScenario runs the scenario's independent verification procedure.
func (v *Verifier) VerifyScenario(ctx context.Context, ds *Dataset, sc *Scenario, marker string) Verification {
	start := time.Now()
	res := v.verify(ctx, ds, sc, marker)
	res.Kind = sc.Verify.Kind
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

func (v *Verifier) verify(ctx context.Context, ds *Dataset, sc *Scenario, marker string) Verification {
	t, err := ds.ScenarioTarget(sc)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	base := t.BaseURL
	auth, err := ds.AuthHeader(sc)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	switch sc.Verify.Kind {
	case VerifyHTTPReflection:
		return v.httpReflection(ctx, base, sc, marker, auth)
	case VerifyHTTPError:
		return v.httpError(ctx, base, sc, marker, auth)
	case VerifyHTTPStored:
		return v.httpStored(ctx, base, sc, marker, auth)
	case VerifyHTTPJSONRaw:
		return v.httpJSONRaw(ctx, base, sc, marker, auth)
	case VerifyHTTPClean:
		return v.httpClean(ctx, base, sc, marker, auth)
	case VerifyHTTPDenied:
		return v.httpStatus(ctx, base, sc, marker, auth, []int{401, 403}, "denied")
	case VerifyHTTPSoft404:
		return v.httpSoft404(ctx, base, sc, marker, auth)
	case VerifyHTTPWAF:
		return v.httpWAF(ctx, base, sc, auth)
	case VerifyHTTPTimeout:
		return v.httpTimeout(ctx, base, sc, marker, auth)
	case VerifyHTTPRedirect:
		return v.httpRedirect(ctx, base, sc, auth)
	case VerifyHTTPExposure:
		return v.httpExposure(ctx, base, sc, marker, auth)
	case VerifyBrowserExec:
		return v.browserExec(ctx, base, sc, auth)
	default:
		return Verification{Error: "unsupported verify kind " + sc.Verify.Kind}
	}
}

type verifyResponse struct {
	status  int
	header  http.Header
	body    string
	at      string
	elapsed time.Duration
	err     error
}

func (v *Verifier) do(ctx context.Context, method, rawURL, auth string, timeout time.Duration) verifyResponse {
	if method == "" {
		method = http.MethodGet
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	start := time.Now()
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, rawURL, nil)
	if err != nil {
		return verifyResponse{err: err, elapsed: time.Since(start)}
	}
	if auth != "" {
		if name, value, ok := strings.Cut(auth, ":"); ok {
			req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}
	resp, err := v.Client.Do(req)
	if err != nil {
		return verifyResponse{err: err, elapsed: time.Since(start)}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return verifyResponse{status: resp.StatusCode, header: resp.Header, at: resp.Request.URL.String(), err: err, elapsed: time.Since(start)}
	}
	return verifyResponse{status: resp.StatusCode, header: resp.Header, body: string(body), at: resp.Request.URL.String(), elapsed: time.Since(start)}
}

func scenarioRequest(sc *Scenario, base, pathTemplate, marker string) (string, error) {
	path := pathTemplate
	if path == "" {
		path = sc.Verify.Path
	}
	if path == "" {
		path = sc.Path
	}
	path = strings.ReplaceAll(path, "{marker}", url.QueryEscape(marker))
	if strings.Contains(path, "{{") {
		return "", fmt.Errorf("scenario %s: unresolved placeholder in %q", sc.ID, path)
	}
	u, err := joinURL(base, path)
	if err != nil {
		return "", err
	}
	if strings.Contains(u, "{{") {
		return "", fmt.Errorf("scenario %s: unresolved base placeholder %q", sc.ID, u)
	}
	return u, nil
}

func (v *Verifier) httpReflection(ctx context.Context, base string, sc *Scenario, marker, auth string) Verification {
	payload := sc.Verify.Payload
	if payload == "" {
		payload = "<bench-" + marker + ">"
	}
	payload = strings.ReplaceAll(payload, "{marker}", marker)
	target, err := scenarioRequest(sc, base, "", marker)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	target = injectParam(target, payload, marker, sc.Verify.Param)
	resp := v.do(ctx, sc.Verify.Method, target, auth, verifyTimeout(sc))
	if resp.err != nil {
		return Verification{Error: resp.err.Error()}
	}
	if !statusOK(sc.Verify.ExpectStatus, resp.status, 200) {
		return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: "unexpected status"}
	}
	if !strings.Contains(resp.body, payload) {
		return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: "raw payload not reflected (escaped or absent)"}
	}
	return Verification{Verified: true, Detail: fmt.Sprintf("raw reflection confirmed (status=%d)", resp.status)}
}

func (v *Verifier) httpError(ctx context.Context, base string, sc *Scenario, marker, auth string) Verification {
	payload := sc.Verify.Payload
	if payload == "" {
		return Verification{Error: "http-error requires verify.payload"}
	}
	target, err := scenarioRequest(sc, base, "", marker)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	attackURL := injectParam(target, payload, marker, sc.Verify.Param)
	resp := v.do(ctx, sc.Verify.Method, attackURL, auth, verifyTimeout(sc))
	if resp.err != nil {
		return Verification{Error: resp.err.Error()}
	}
	for _, want := range sc.Verify.ExpectContains {
		if !strings.Contains(resp.body, want) {
			return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: fmt.Sprintf("attack response missing %q", want)}
		}
	}
	ctrl := v.do(ctx, sc.Verify.Method, target, auth, verifyTimeout(sc))
	if ctrl.err != nil {
		return Verification{Error: "control request: " + ctrl.err.Error()}
	}
	for _, want := range sc.Verify.ExpectContains {
		if strings.Contains(ctrl.body, want) {
			return Verification{Error: fmt.Sprintf("control response unexpectedly contains %q", want)}
		}
	}
	return Verification{Verified: true, Detail: fmt.Sprintf("attack-only signature confirmed (status=%d, control=%d)", resp.status, ctrl.status)}
}

func (v *Verifier) httpStored(ctx context.Context, base string, sc *Scenario, marker, auth string) Verification {
	payload := sc.Verify.Payload
	if payload == "" {
		payload = marker
	}
	payload = strings.ReplaceAll(payload, "{marker}", marker)
	storeURL, err := scenarioRequest(sc, base, sc.Verify.StorePath, marker)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	storeURL = injectParam(storeURL, payload, marker, sc.Verify.Param)
	resp := v.do(ctx, http.MethodGet, storeURL, auth, verifyTimeout(sc))
	if resp.err != nil {
		return Verification{Error: "store request: " + resp.err.Error()}
	}
	renderURL, err := scenarioRequest(sc, base, sc.Verify.RenderPath, marker)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	rendered := v.do(ctx, http.MethodGet, renderURL, auth, verifyTimeout(sc))
	if rendered.err != nil {
		return Verification{Error: "render request: " + rendered.err.Error()}
	}
	if !strings.Contains(rendered.body, payload) {
		return Verification{Detail: fmt.Sprintf("store=%d render=%d", resp.status, rendered.status), Error: "stored payload not present in render page"}
	}
	return Verification{Verified: true, Detail: fmt.Sprintf("two-request store+render confirmed (store=%d render=%d)", resp.status, rendered.status)}
}

func (v *Verifier) httpJSONRaw(ctx context.Context, base string, sc *Scenario, marker, auth string) Verification {
	payload := sc.Verify.Payload
	if payload == "" {
		payload = marker
	}
	payload = strings.ReplaceAll(payload, "{marker}", marker)
	target, err := scenarioRequest(sc, base, "", marker)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	target = injectParam(target, payload, marker, sc.Verify.Param)
	resp := v.do(ctx, sc.Verify.Method, target, auth, verifyTimeout(sc))
	if resp.err != nil {
		return Verification{Error: resp.err.Error()}
	}
	ct := resp.header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(ct), "application/json") {
		return Verification{Detail: "content-type=" + ct, Error: "expected application/json"}
	}
	if !strings.Contains(resp.body, payload) {
		return Verification{Detail: "content-type=" + ct, Error: "payload not present raw in JSON body"}
	}
	return Verification{Verified: true, Detail: "raw reflection inside application/json (non-HTML content type): not browser-executable; ground truth clean"}
}

func (v *Verifier) httpClean(ctx context.Context, base string, sc *Scenario, marker, auth string) Verification {
	payload := sc.Verify.Payload
	if payload == "" {
		payload = marker
	}
	payload = strings.ReplaceAll(payload, "{marker}", marker)
	target, err := scenarioRequest(sc, base, "", marker)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	target = injectParam(target, payload, marker, sc.Verify.Param)
	resp := v.do(ctx, sc.Verify.Method, target, auth, verifyTimeout(sc))
	if resp.err != nil {
		return Verification{Error: resp.err.Error()}
	}
	if !statusOK(sc.Verify.ExpectStatus, resp.status, 200) {
		return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: "unexpected status"}
	}
	for _, banned := range sc.Verify.ExpectNotContains {
		if strings.Contains(resp.body, banned) {
			return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: fmt.Sprintf("clean response exposes %q", banned)}
		}
	}
	return Verification{Verified: true, Detail: fmt.Sprintf("response clean of raw payload markers (status=%d)", resp.status)}
}

func (v *Verifier) httpStatus(ctx context.Context, base string, sc *Scenario, marker, auth string, want []int, label string) Verification {
	target, err := scenarioRequest(sc, base, "", marker)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	if sc.Verify.ExpectStatus != nil {
		want = sc.Verify.ExpectStatus
	}
	resp := v.do(ctx, sc.Verify.Method, target, auth, verifyTimeout(sc))
	if resp.err != nil {
		return Verification{Error: resp.err.Error()}
	}
	for _, s := range want {
		if resp.status == s {
			return Verification{Verified: true, Detail: fmt.Sprintf("%s confirmed (status=%d)", label, resp.status)}
		}
	}
	return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: fmt.Sprintf("expected %s status in %v", label, want)}
}

func (v *Verifier) httpSoft404(ctx context.Context, base string, sc *Scenario, marker, auth string) Verification {
	target, err := scenarioRequest(sc, base, "", marker)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	resp := v.do(ctx, sc.Verify.Method, target, auth, verifyTimeout(sc))
	if resp.err != nil {
		return Verification{Error: resp.err.Error()}
	}
	if resp.status != 200 {
		return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: "soft-404 trap must answer 200"}
	}
	for _, want := range sc.Verify.ExpectContains {
		if !strings.Contains(resp.body, want) {
			return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: fmt.Sprintf("soft-404 body missing %q", want)}
		}
	}
	return Verification{Verified: true, Detail: fmt.Sprintf("soft-404 trap confirmed (200 with placeholder body, status=%d)", resp.status)}
}

func (v *Verifier) httpWAF(ctx context.Context, base string, sc *Scenario, auth string) Verification {
	payload := sc.Verify.Payload
	if payload == "" {
		payload = "{marker}' OR 1=1--"
	}
	target, err := scenarioRequest(sc, base, "", "wafprobe")
	if err != nil {
		return Verification{Error: err.Error()}
	}
	target = injectParam(target, payload, "wafprobe", sc.Verify.Param)
	resp := v.do(ctx, sc.Verify.Method, target, auth, verifyTimeout(sc))
	if resp.err != nil {
		return Verification{Error: resp.err.Error()}
	}
	if resp.status != 403 {
		return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: "WAF trap must answer 403"}
	}
	for _, want := range sc.Verify.ExpectContains {
		if !strings.Contains(resp.body, want) {
			return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: fmt.Sprintf("WAF block page missing %q", want)}
		}
	}
	benign, err := scenarioRequest(sc, base, "", "hello")
	if err != nil {
		return Verification{Error: err.Error()}
	}
	ok := v.do(ctx, sc.Verify.Method, benign, auth, verifyTimeout(sc))
	if ok.err != nil {
		return Verification{Error: "benign control: " + ok.err.Error()}
	}
	if ok.status == 403 {
		return Verification{Error: "benign request also blocked: trap would break the whole scenario"}
	}
	return Verification{Verified: true, Detail: fmt.Sprintf("WAF trap confirmed (attack=403, benign=%d)", ok.status)}
}

func (v *Verifier) httpTimeout(ctx context.Context, base string, sc *Scenario, marker, auth string) Verification {
	target, err := scenarioRequest(sc, base, "", marker)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	resp := v.do(ctx, sc.Verify.Method, target, auth, verifyTimeout(sc))
	if resp.err != nil {
		return Verification{Error: resp.err.Error()}
	}
	want := time.Duration(sc.Verify.ExpectSlowMS) * time.Millisecond
	if resp.elapsed < want {
		return Verification{Detail: fmt.Sprintf("elapsed=%s status=%d", resp.elapsed, resp.status), Error: fmt.Sprintf("expected slow response >= %s", want)}
	}
	return Verification{Verified: true, Detail: fmt.Sprintf("slow endpoint confirmed (elapsed=%s status=%d)", resp.elapsed.Round(time.Millisecond), resp.status)}
}

func (v *Verifier) httpRedirect(ctx context.Context, base string, sc *Scenario, auth string) Verification {
	payload := sc.Verify.Payload
	if payload == "" {
		payload = "https://gash-bench-canary.example/landing"
	}
	target, err := scenarioRequest(sc, base, "", "redirect")
	if err != nil {
		return Verification{Error: err.Error()}
	}
	target = injectParam(target, payload, "redirect", sc.Verify.Param)
	client := &http.Client{Timeout: verifyTimeout(sc), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(mustRequest(ctx, target, auth))
	if err != nil {
		return Verification{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return Verification{Detail: fmt.Sprintf("status=%d", resp.StatusCode), Error: "expected 3xx redirect"}
	}
	loc := resp.Header.Get("Location")
	lu, err := url.Parse(loc)
	if err != nil || lu.Host == "" {
		return Verification{Detail: "location=" + loc, Error: "missing absolute Location"}
	}
	if sc.Verify.ExpectExternalLocation {
		bu, _ := url.Parse(target)
		if lu.Host == bu.Host {
			return Verification{Detail: "location=" + loc, Error: "Location must point off-host"}
		}
	}
	if !strings.Contains(loc, "gash-bench-canary.example") {
		return Verification{Detail: "location=" + loc, Error: "Location must contain the injected payload host"}
	}
	return Verification{Verified: true, Detail: "external redirect confirmed (Location=" + loc + ")"}
}

// httpExposure verifies a directly reachable sensitive artifact: the expected
// status and content markers must be present on the scenario path, and the
// same markers must be absent from a random soft-404 control path.
func (v *Verifier) httpExposure(ctx context.Context, base string, sc *Scenario, marker, auth string) Verification {
	if len(sc.Verify.ExpectContains) == 0 {
		return Verification{Error: "http-exposure requires verify.expect_contains"}
	}
	target, err := scenarioRequest(sc, base, "", marker)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	resp := v.do(ctx, sc.Verify.Method, target, auth, verifyTimeout(sc))
	if resp.err != nil {
		return Verification{Error: resp.err.Error()}
	}
	if !statusOK(sc.Verify.ExpectStatus, resp.status, 200) {
		return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: "unexpected status"}
	}
	for _, want := range sc.Verify.ExpectContains {
		if !strings.Contains(resp.body, want) {
			return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: fmt.Sprintf("exposure body missing %q", want)}
		}
	}
	for _, banned := range sc.Verify.ExpectNotContains {
		if strings.Contains(resp.body, banned) {
			return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: fmt.Sprintf("exposure body contains forbidden %q", banned)}
		}
	}
	controlURL, err := scenarioRequest(sc, base, "/gash-bench-missing-"+marker, marker)
	if err != nil {
		return Verification{Error: "control path: " + err.Error()}
	}
	ctrl := v.do(ctx, http.MethodGet, controlURL, auth, verifyTimeout(sc))
	if ctrl.err != nil {
		return Verification{Error: "control request: " + ctrl.err.Error()}
	}
	for _, want := range sc.Verify.ExpectContains {
		if strings.Contains(ctrl.body, want) {
			return Verification{Detail: fmt.Sprintf("status=%d", resp.status), Error: fmt.Sprintf("control path also contains %q; exposure marker is not distinguishing", want)}
		}
	}
	return Verification{Verified: true, Detail: fmt.Sprintf("exposure confirmed (status=%d, control=%d)", resp.status, ctrl.status)}
}

func (v *Verifier) browserExec(ctx context.Context, base string, sc *Scenario, auth string) Verification {
	payload := sc.Verify.Payload
	if payload == "" {
		return Verification{Error: "browser-exec requires verify.payload"}
	}
	path := sc.Verify.Path
	if path == "" {
		path = sc.Path
	}
	if !strings.Contains(path, "{payload}") {
		return Verification{Error: "browser-exec requires {payload} placeholder in verify.path"}
	}
	base = strings.TrimSuffix(base, "/")
	payloadURL := base + strings.ReplaceAll(path, "{payload}", url.PathEscape(payload))
	controlURL := base + strings.ReplaceAll(path, "{payload}", "bench-clean-control")
	executed, err := browserVerify(ctx, payloadURL, controlURL, auth)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	if !executed {
		return Verification{Error: "browser execution not observed on payload URL (control stayed clean)"}
	}
	return Verification{Verified: true, Detail: "controlled browser execution confirmed"}
}

func mustRequest(ctx context.Context, rawURL, auth string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if auth != "" {
		if name, value, ok := strings.Cut(auth, ":"); ok {
			req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}
	return req
}

func injectParam(rawURL, value, fallback, param string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	if param != "" {
		q.Set(param, value)
	} else if len(q) == 0 {
		q.Set(fallback, value)
	} else {
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		q.Set(keys[0], value)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func statusOK(want []int, got, def int) bool {
	if len(want) == 0 {
		return got == def
	}
	for _, w := range want {
		if got == w {
			return true
		}
	}
	return false
}

func verifyTimeout(sc *Scenario) time.Duration {
	if sc.Verify.Timeout != "" {
		if d, err := time.ParseDuration(sc.Verify.Timeout); err == nil && d > 0 {
			return d
		}
	}
	if sc.Verify.Kind == VerifyHTTPTimeout {
		return 4 * time.Second
	}
	return 15 * time.Second
}
