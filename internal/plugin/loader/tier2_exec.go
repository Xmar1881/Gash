// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package loader executes Tier 2 scripts with fully wired host bindings.
// What: Runs goja plugins against injected probe, context, and oracle backends.
// Why: One audited binding layer serves live scans, fixture tests, and the
// drop-in end-to-end proof while keeping evidence decisions in Go oracles.
package loader

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/oob"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/dop251/goja"
)

// controlNeutralValue is the benign replacement used for control requests.
// What: One shared literal keeps control semantics auditable across tiers.
const controlNeutralValue = "gash-control-neutral"

// JSPoint is one injection point visible to scripts.
// What: Serializable point exchanged through the ctx binding.
// Why: A plain struct keeps the JS/G bridge explicit and testable.
type JSPoint struct {
	// URL is the base URL under test.
	URL string
	// Method is the HTTP method to use.
	Method string
	// ParamName is the injectable parameter name.
	ParamName string
	// ParamLocation is query, hash, fragment, body, header, path, or cookie.
	ParamLocation string
	// SourceKind names the client-side source family for this point.
	SourceKind string
	// TestID is the stable identity of the point/payload test.
	TestID string
	// Value is the current parameter value.
	Value string
	// Headers are extra request headers a script may attach to this point
	// (e.g. an explicit Content-Type for raw JSON bodies, or an unkeyed
	// forwarding header for cache-poisoning probes). They are merged on top
	// of the headers the executor derives; an explicit Content-Type wins.
	// Every header still travels through the same PolicySession and scope
	// checks as the rest of the request.
	Headers map[string]string
	// FormValues, when non-nil, holds the other form fields' current values
	// (tokens included) so the executor replays the complete form with only
	// this field replaced by the payload. Findings MUST NOT serialize it.
	FormValues map[string]string
	// FormEnctype is the owning form's encoding
	// ("application/x-www-form-urlencoded" or "multipart/form-data").
	FormEnctype string
}

// JSResponse is one probe response visible to scripts.
// What: Status plus headers plus body returned by probe.send.
// Why: Scripts never see raw transports, only this sanitized view.
type JSResponse struct {
	// Status is the HTTP status code.
	Status int
	// Headers holds response headers.
	Headers map[string]string
	// Body holds the response body.
	Body string
	// URL is the request URL that produced the response.
	URL string
	// RTTMs is the measured round-trip time in milliseconds for timing oracles.
	// Zero means unmeasured (fixture path); timing binding then requires
	// explicit samples via options and rejects instead of guessing.
	RTTMs float64
}

// JSEnv supplies every host capability a script may call.
// What: Injectable backend for probe traffic, OOB state, and canary supply.
// Why: Live scans pass the network backend while fixture tests pass canned
// responses through the exact same binding code.
type JSEnv struct {
	// Points lists injection points returned by ctx.injectionPoints.
	Points []JSPoint
	// Canary, when set, fixes probe.canary for deterministic tests.
	Canary string
	// CanaryCounter prefixes generated canaries when Canary is empty.
	CanaryCounter *int
	// Send issues one request for the given point value.
	Send func(point JSPoint) (JSResponse, error)
	// ControlSend, when set, supplies the neutral control response.
	// When nil, Send is reused with a neutral value.
	ControlSend func(point JSPoint) (JSResponse, error)
	// OOBEnabled gates host.oob.generate and the OOB oracle.
	OOBEnabled bool
	// OOBNamespace fixes the correlation namespace for tests.
	OOBNamespace string
	// OOBCorrelation fixes the next correlation ID for tests.
	OOBCorrelation string
	// OOBCallbackSeen reports whether a correlation ID was observed. Live scans
	// wire this to the bounded multi-channel wait (dns or http).
	OOBCallbackSeen func(correlationID string) bool
	// OOBCallbackSeenAny reports the first correlation ID (input order) with a
	// callback inside ONE bounded window shared by all tokens. Multi-payload
	// plugins use it so the wait is paid once per run, not once per payload.
	OOBCallbackSeenAny func(correlationIDs []string) []string
	// OOBDomain maps a correlation ID to the DNS callback domain of the
	// operator's self-hosted server. Nil keeps the fixture fallback domain.
	OOBDomain func(correlationID string) string
	// OOBURL maps a correlation ID to the HTTP callback URL of the
	// operator's self-hosted server. Nil keeps the fixture fallback URL.
	OOBURL func(correlationID string) string
	// BrowserVerify is the optional controlled-browser proof seam used by the
	// stored binding (render URL vs supplied clean control URL). Nil disables
	// the confirmed path; the static ceiling is preserved. The first return
	// says verification actually ran.
	BrowserVerify func(payloadURL, controlURL string) (verified, triggered, controlClean bool, err error)
	// BrowserProbe navigates a point with an arbitrary payload and its neutral
	// control. It exists for hash-route DOM sinks where an HTTP request cannot
	// carry the injection. Nil disables host.oracles.browserExecution.
	BrowserProbe func(point JSPoint, payload string) (verified, triggered, controlClean bool, err error)
}

// JSCandidate pairs a script candidate with its engine-side evidence.
// What: Executable outcome of one host.candidate call.
// Why: Findings are built from evidence, so the runner must retain both.
type JSCandidate struct {
	// Candidate is the engine-facing candidate.
	Candidate plugin.Candidate
	// Evidence is the oracle verdict behind the candidate.
	Evidence *oracle.Evidence
}

// oracleRefName maps script-level oracle references to engine oracle names.
// What: Normalizes the short references used inside run() functions.
// Why: Scripts stay readable while the engine keeps canonical oracle names.
func oracleRefName(ref string) string {
	switch strings.ToLower(strings.TrimSpace(ref)) {
	case "reflected-xss", "reflection", "xss":
		return "reflection"
	case "sqli-error", "error", "error-signature":
		return "error"
	case "sqli-differential", "differential", "boolean":
		return "differential"
	case "ssrf-blind", "oob", "blind-ssrf":
		return "oob"
	case "header", "headers":
		return "header"
	case "redirect", "open-redirect":
		return "redirect"
	case "timing", "time-based", "sqli-time", "blind-timing":
		return "timing"
	case "cookie", "cookie-flags", "cookies":
		return "cookie"
	case "cors", "cors-misconfig":
		return "cors"
	case "execution", "dom-xss", "dom-sink", "dom":
		return "execution"
	case "stored", "stored-xss", "storedexecution", "stored-execution", "stored_execution", "storedxss":
		return "stored"
	case "upload-served", "uploadserved", "upload":
		return "upload-served"
	default:
		return strings.ToLower(strings.TrimSpace(ref))
	}
}

// DefaultJSPluginBudget caps one Tier2 execution when the caller passes no
// explicit timeout. Live scans pass a per-plugin budget from the engine config
// (PluginTimeoutMs); this default only guards library/fixture callers.
const DefaultJSPluginBudget = 10 * time.Second

// specOracleParam reads one string parameter from the plugin-level
// oracle_params block (Tier 2 frontmatter / Tier 3 manifest).
// What: Default source for oracle parameters declared once per plugin.
// Why: The fixture runner applies the same map, so fixture expectations cannot
// drift from live-scan behaviour.
func specOracleParam(spec *plugin.PluginSpec, name string) string {
	if spec == nil || spec.OracleParams == nil {
		return ""
	}
	if v, ok := spec.OracleParams[name]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// jsInterruptGrace bounds how long ExecuteJS waits for an interrupted VM to
// abort before returning the timeout to the caller.
const jsInterruptGrace = 2 * time.Second

// ExecuteJS runs a Tier 2 source with the given environment and timeout.
// What: Full goja execution returning candidates plus evidence.
// Why: Single entry point for live scans and offline fixture evaluation.
func ExecuteJS(ctx context.Context, spec *plugin.PluginSpec, source string, env *JSEnv, timeout time.Duration) ([]JSCandidate, error) {
	if spec == nil {
		return nil, fmt.Errorf("js execute: nil spec: %w", plugin.ErrValidation)
	}
	if env == nil {
		return nil, fmt.Errorf("js execute: nil env: %w", plugin.ErrValidation)
	}
	if timeout <= 0 {
		timeout = DefaultJSPluginBudget
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		cands []JSCandidate
		err   error
	}
	ch := make(chan outcome, 1)
	vmCh := make(chan *goja.Runtime, 1)
	go func() {
		cands, err := executeJSOnce(spec, source, env, vmCh)
		ch <- outcome{cands: cands, err: err}
	}()

	select {
	case <-runCtx.Done():
		// Best-effort hard abort: interrupt the VM so an infinite loop cannot
		// outlive the timeout (leaked goroutine YOK). The outcome channel is
		// buffered, so the worker never blocks after we return.
		select {
		case vm := <-vmCh:
			vm.Interrupt("plugin timeout")
			select {
			case <-ch:
			case <-time.After(jsInterruptGrace):
			}
		case o := <-ch:
			_ = o
		case <-time.After(jsInterruptGrace):
		}
		return nil, fmt.Errorf("js execute %s: %w", spec.ID, plugin.ErrTimeout)
	case o := <-ch:
		return o.cands, o.err
	}
}

func executeJSOnce(spec *plugin.PluginSpec, source string, env *JSEnv, vmReady chan<- *goja.Runtime) ([]JSCandidate, error) {
	vm := goja.New()
	if vmReady != nil {
		select {
		case vmReady <- vm:
		default:
		}
	}
	vm.SetMaxCallStackSize(512)
	_ = vm.Set("eval", goja.Undefined())
	_ = vm.Set("Function", goja.Undefined())

	var collected []JSCandidate
	var evidences []*oracle.Evidence

	canaryCount := 0
	nextCanary := func() string {
		if env.Canary != "" {
			return env.Canary
		}
		canaryCount++
		return fmt.Sprintf("gash_js_%d", canaryCount)
	}

	sourceKindFor := func(location string) string {
		switch strings.ToLower(strings.TrimSpace(location)) {
		case "query", "search":
			return "query"
		case "hash":
			return "hash"
		case "fragment":
			return "hash_route"
		default:
			return ""
		}
	}
	testIDFor := func(p JSPoint) string {
		location := strings.ToLower(strings.TrimSpace(p.ParamLocation))
		if location == "" {
			location = "query"
		}
		return strings.Join([]string{"point", location, p.ParamName, p.Method, p.URL}, "|")
	}

	var toPointObject func(vm *goja.Runtime, p JSPoint) goja.Value
	toPointObject = func(vm *goja.Runtime, p JSPoint) goja.Value {
		obj := vm.NewObject()
		_ = obj.Set("url", p.URL)
		_ = obj.Set("method", p.Method)
		_ = obj.Set("paramName", p.ParamName)
		_ = obj.Set("paramLocation", p.ParamLocation)
		_ = obj.Set("value", p.Value)
		if p.SourceKind == "" {
			p.SourceKind = sourceKindFor(p.ParamLocation)
		}
		if p.TestID == "" {
			p.TestID = testIDFor(p)
		}
		_ = obj.Set("sourceKind", p.SourceKind)
		_ = obj.Set("testId", p.TestID)
		if len(p.FormValues) > 0 {
			fv := vm.NewObject()
			keys := make([]string, 0, len(p.FormValues))
			for k := range p.FormValues {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				_ = fv.Set(k, p.FormValues[k])
			}
			_ = obj.Set("formValues", fv)
		}
		if p.FormEnctype != "" {
			_ = obj.Set("formEnctype", p.FormEnctype)
		}
		if len(p.Headers) > 0 {
			hd := vm.NewObject()
			keys := make([]string, 0, len(p.Headers))
			for k := range p.Headers {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				_ = hd.Set(k, p.Headers[k])
			}
			_ = obj.Set("headers", hd)
		}
		cur := p
		_ = obj.Set("withValue", func(call goja.FunctionCall) goja.Value {
			v := ""
			if len(call.Arguments) > 0 {
				v = call.Arguments[0].String()
			}
			cur.Value = v
			return toPointObject(vm, cur)
		})
		return obj
	}

	pointFromValue := func(v goja.Value) JSPoint {
		obj := v.ToObject(vm)
		get := func(k string) string {
			if val := obj.Get(k); val != nil && !goja.IsUndefined(val) && !goja.IsNull(val) {
				return val.String()
			}
			return ""
		}
		method := get("method")
		if method == "" {
			method = http.MethodGet
		}
		var formValues map[string]string
		if fv := obj.Get("formValues"); fv != nil && !goja.IsUndefined(fv) && !goja.IsNull(fv) {
			fvObj := fv.ToObject(vm)
			formValues = make(map[string]string)
			for _, k := range fvObj.Keys() {
				if val := fvObj.Get(k); val != nil && !goja.IsUndefined(val) && !goja.IsNull(val) {
					formValues[k] = val.String()
				}
			}
			if len(formValues) == 0 {
				formValues = nil
			}
		}
		var headers map[string]string
		if hv := obj.Get("headers"); hv != nil && !goja.IsUndefined(hv) && !goja.IsNull(hv) {
			hvObj := hv.ToObject(vm)
			headers = make(map[string]string)
			for _, k := range hvObj.Keys() {
				if val := hvObj.Get(k); val != nil && !goja.IsUndefined(val) && !goja.IsNull(val) {
					headers[k] = val.String()
				}
			}
			if len(headers) == 0 {
				headers = nil
			}
		}
		p := JSPoint{
			URL: get("url"), Method: method,
			ParamName: get("paramName"), ParamLocation: get("paramLocation"),
			SourceKind: get("sourceKind"), TestID: get("testId"),
			Value: get("value"), Headers: headers,
			FormValues: formValues, FormEnctype: get("formEnctype"),
		}
		if p.SourceKind == "" {
			p.SourceKind = sourceKindFor(p.ParamLocation)
		}
		if p.TestID == "" {
			p.TestID = testIDFor(p)
		}
		return p
	}

	respToObject := func(vm *goja.Runtime, r JSResponse) goja.Value {
		obj := vm.NewObject()
		_ = obj.Set("status", r.Status)
		hdrs := vm.NewObject()
		keys := make([]string, 0, len(r.Headers))
		for k := range r.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_ = hdrs.Set(k, r.Headers[k])
		}
		_ = obj.Set("headers", hdrs)
		_ = obj.Set("body", r.Body)
		_ = obj.Set("url", r.URL)
		_ = obj.Set("rttMs", r.RTTMs)
		return obj
	}

	respFromValue := func(v goja.Value) JSResponse {
		obj := v.ToObject(vm)
		status := 0
		if s := obj.Get("status"); s != nil && !goja.IsUndefined(s) {
			status = int(s.ToInteger())
		}
		body := ""
		if b := obj.Get("body"); b != nil && !goja.IsUndefined(b) && !goja.IsNull(b) {
			body = b.String()
		}
		rawURL := ""
		if u := obj.Get("url"); u != nil && !goja.IsUndefined(u) && !goja.IsNull(u) {
			rawURL = u.String()
		}
		var rttMs float64
		if r := obj.Get("rttMs"); r != nil && !goja.IsUndefined(r) && !goja.IsNull(r) {
			rttMs = r.ToFloat()
		}
		headers := map[string]string{}
		if h := obj.Get("headers"); h != nil && !goja.IsUndefined(h) && !goja.IsNull(h) {
			if ho, ok := h.(*goja.Object); ok {
				for _, k := range ho.Keys() {
					headers[k] = ho.Get(k).String()
				}
			}
		}
		return JSResponse{Status: status, Headers: headers, Body: body, URL: rawURL, RTTMs: rttMs}
	}

	evToObject := func(vm *goja.Runtime, ev *oracle.Evidence) goja.Value {
		if ev == nil || ev.Verdict != oracle.VerdictAccept {
			return goja.Null()
		}
		idx := len(evidences)
		evidences = append(evidences, ev)
		obj := vm.NewObject()
		_ = obj.Set("verdict", string(ev.Verdict))
		_ = obj.Set("confidence", string(ev.ConfidenceContribution))
		_ = obj.Set("note", ev.Note)
		for _, key := range []string{
			"sink", "source", "payload", "browser", "correlation", "namespace",
			"source_observed", "sink_observed", "source_sink_linked",
			"execution_confirmed", "control_result",
		} {
			if v, ok := ev.Artifacts[key]; ok && v != "" {
				_ = obj.Set(key, v)
			}
		}
		_ = obj.Set("__evIdx", idx)
		return obj
	}

	evFromValue := func(v goja.Value) *oracle.Evidence {
		if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
			return nil
		}
		obj := v.ToObject(vm)
		idxVal := obj.Get("__evIdx")
		if idxVal == nil || goja.IsUndefined(idxVal) {
			return nil
		}
		idx := int(idxVal.ToInteger())
		if idx < 0 || idx >= len(evidences) {
			return nil
		}
		return evidences[idx]
	}

	controlFor := func(p JSPoint) JSResponse {
		if env.ControlSend != nil {
			if r, err := env.ControlSend(p); err == nil {
				return r
			}
		}
		neutral := p
		// URL-derived control point (reflection/stored bindings pass the
		// response URL): the query still carries the attack payload, so a
		// verbatim replay would make every control dirty and reject genuine
		// executable reflections. Neutralize every query value instead.
		// What: value-level neutralization; why: param names can be unknown.
		if neutral.ParamName == "" && neutral.URL != "" {
			if u, err := url.Parse(neutral.URL); err == nil && u.RawQuery != "" {
				q := u.Query()
				for k := range q {
					q.Set(k, controlNeutralValue)
				}
				u.RawQuery = q.Encode()
				neutral.URL = u.String()
			}
		}
		neutral.Value = controlNeutralValue
		if r, err := env.Send(neutral); err == nil {
			return r
		}
		return JSResponse{}
	}

	// ctx binding.
	ctxObj := vm.NewObject()
	_ = ctxObj.Set("injectionPoints", func(goja.FunctionCall) goja.Value {
		objs := make([]any, 0, len(env.Points))
		for _, p := range env.Points {
			objs = append(objs, toPointObject(vm, p))
		}
		return vm.ToValue(objs)
	})
	_ = vm.Set("ctx", ctxObj)

	// probe binding.
	probeObj := vm.NewObject()
	_ = probeObj.Set("canary", func(goja.FunctionCall) goja.Value {
		return vm.ToValue(nextCanary())
	})
	_ = probeObj.Set("send", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			panic("probe.send requires a point argument")
		}
		if env.Send == nil {
			return goja.Null()
		}
		p := pointFromValue(call.Arguments[0])
		resp, err := env.Send(p)
		if err != nil {
			return respToObject(vm, JSResponse{Status: 0, Body: "", URL: p.URL})
		}
		return respToObject(vm, resp)
	})
	_ = vm.Set("probe", probeObj)

	// host binding.
	hostObj := vm.NewObject()
	oraclesObj := vm.NewObject()
	_ = oraclesObj.Set("reflection", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			panic("reflection(resp, canary) requires 2 arguments")
		}
		resp := respFromValue(call.Arguments[0])
		canary := call.Arguments[1].String()
		contexts := []string{"html", "attr", "attr-executable", "script", "url", "url-executable"}
		if len(call.Arguments) >= 3 && !goja.IsNull(call.Arguments[2]) && !goja.IsUndefined(call.Arguments[2]) {
			arr := call.Arguments[2].ToObject(vm)
			if length := int(arr.Get("length").ToInteger()); length > 0 {
				contexts = make([]string, 0, length)
				for i := 0; i < length; i++ {
					contexts = append(contexts, arr.Get(fmt.Sprintf("%d", i)).String())
				}
			}
		}
		cls := baseline.ClassifyStatic(resp.Status, toHTTPHeader(resp.Headers), []byte(resp.Body))
		ctrl := controlFor(JSPoint{URL: resp.URL})
		var o oracle.ReflectionOracle
		ev, err := o.Verify(context.Background(), resp.Body, toHTTPHeader(resp.Headers), cls, false, oracle.ReflectionParams{
			Canary: canary, Contexts: contexts,
			RequireExecutableContext: true, ControlBody: ctrl.Body,
		})
		if err != nil {
			panic(err.Error())
		}
		return evToObject(vm, ev)
	})
	storedVerify := func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 3 {
			panic("storedExecution(storeResp, renderResp, canary[, contexts|opts]) requires 3 arguments")
		}
		storeResp := respFromValue(call.Arguments[0])
		renderResp := respFromValue(call.Arguments[1])
		canary := call.Arguments[2].String()
		contexts := []string{"html", "attr-executable", "script", "url", "url-executable"}
		requireExecutable := true
		controlURL := ""
		if len(call.Arguments) >= 4 && !goja.IsNull(call.Arguments[3]) && !goja.IsUndefined(call.Arguments[3]) {
			arg := call.Arguments[3].ToObject(vm)
			if lengthVal := arg.Get("length"); lengthVal != nil && !goja.IsUndefined(lengthVal) {
				if length := int(lengthVal.ToInteger()); length > 0 {
					contexts = make([]string, 0, length)
					for i := 0; i < length; i++ {
						contexts = append(contexts, arg.Get(fmt.Sprintf("%d", i)).String())
					}
				}
			} else {
				if v := arg.Get("contexts"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					arr := v.ToObject(vm)
					if length := int(arr.Get("length").ToInteger()); length > 0 {
						contexts = make([]string, 0, length)
						for i := 0; i < length; i++ {
							contexts = append(contexts, arr.Get(fmt.Sprintf("%d", i)).String())
						}
					}
				}
				if v := arg.Get("requireExecutableContext"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					requireExecutable = v.ToBoolean()
				}
				if v := arg.Get("require_executable_context"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					requireExecutable = v.ToBoolean()
				}
				// Optional pre-store-clean control render URL: when supplied
				// and browser verification is enabled, a real trigger plus a
				// clean control may lift the render exchange to confirmed.
				if v := arg.Get("controlUrl"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					controlURL = v.String()
				}
				if v := arg.Get("control_url"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					controlURL = v.String()
				}
			}
		}
		cls := baseline.ClassifyStatic(renderResp.Status, toHTTPHeader(renderResp.Headers), []byte(renderResp.Body))
		// Stored renders persist the claim: re-fetching the same URL as the
		// control would always contain the canary and reject genuine findings.
		// A caller-supplied sibling render page is the clean control; fall
		// back to a neutralized same-URL fetch only when none is given.
		controlBody := ""
		if controlURL != "" && controlURL != renderResp.URL {
			if cr, err := env.Send(JSPoint{URL: controlURL, Method: http.MethodGet}); err == nil {
				controlBody = cr.Body
			}
		}
		if controlBody == "" {
			controlBody = controlFor(JSPoint{URL: renderResp.URL}).Body
		}
		params := oracle.StoredParams{
			Canary: canary, Contexts: contexts,
			RequireExecutableContext: requireExecutable,
			StoreStatus:              storeResp.Status, StoreBody: storeResp.Body,
			RenderBody: renderResp.Body, RenderHeaders: toHTTPHeader(renderResp.Headers),
			ControlBody: controlBody,
		}
		var o oracle.StoredOracle
		pre, err := o.Verify(context.Background(), cls, false, params)
		if err != nil {
			panic(err.Error())
		}
		// The controlled browser proof costs two navigations: run it only for
		// attempts that already accept as static execution (and only in deep
		// builds). Ungated, every store+render attempt launched Chrome and
		// blew the plugin time budget (measured: stored XSS went missing in
		// deep runs).
		if pre == nil || pre.Verdict != oracle.VerdictAccept || pre.Artifacts["execution"] != "static" ||
			env.BrowserVerify == nil || controlURL == "" || controlURL == renderResp.URL {
			return evToObject(vm, pre)
		}
		var browserVerified, browserTriggered, browserControlClean bool
		if verified, triggered, clean, err := env.BrowserVerify(renderResp.URL, controlURL); err == nil {
			browserVerified, browserTriggered, browserControlClean = verified, triggered, clean
		}
		params.BrowserVerified = browserVerified
		params.BrowserTriggered = browserTriggered
		params.BrowserControlClean = browserControlClean
		ev, err := o.Verify(context.Background(), cls, false, params)
		if err != nil {
			panic(err.Error())
		}
		return evToObject(vm, ev)
	}
	_ = oraclesObj.Set("stored", storedVerify)
	_ = oraclesObj.Set("storedExecution", storedVerify)
	_ = oraclesObj.Set("error", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			panic("error(resp, controlResp[, opts]) requires 2 arguments")
		}
		resp := respFromValue(call.Arguments[0])
		ctrl := respFromValue(call.Arguments[1])
		// Mode selects the signature family (sqli, path_traversal,
		// generic_error, deserialization, takeover). A script may pass it per
		// call; otherwise the plugin-level oracle_params value applies so the
		// fixture runner sees exactly what a live scan does.
		mode := specOracleParam(spec, "mode")
		if len(call.Arguments) >= 3 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
			if opts, ok := call.Arguments[2].(*goja.Object); ok {
				if v := opts.Get("mode"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					mode = v.String()
				}
			}
		}
		cls := baseline.ClassifyStatic(resp.Status, toHTTPHeader(resp.Headers), []byte(resp.Body))
		var o oracle.ErrorSignatureOracle
		ev, err := o.Verify(context.Background(), cls, false, oracle.ErrorSignatureParams{
			Body: resp.Body, ControlBody: ctrl.Body, Mode: mode,
		})
		if err != nil {
			panic(err.Error())
		}
		return evToObject(vm, ev)
	})
	_ = oraclesObj.Set("differential", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 3 {
			panic("differential(trueResps, falseResps, controlResp[, opts]) requires 3 arguments")
		}
		trueResps := respsFromArray(vm, call.Arguments[0])
		falseResps := respsFromArray(vm, call.Arguments[1])
		ctrl := respFromValue(call.Arguments[2])
		// A ceiling keeps hardening-gap classes honest: divergence proves the
		// behaviour, not always an exploitable vulnerability. Defaults to the
		// plugin-level oracle_params value (Tier 1 declares it in
		// oracle.params) so fixtures and live scans share one source.
		ceiling := specOracleParam(spec, "confidence_ceiling")
		if len(call.Arguments) >= 4 && !goja.IsUndefined(call.Arguments[3]) && !goja.IsNull(call.Arguments[3]) {
			if opts, ok := call.Arguments[3].(*goja.Object); ok {
				if v := opts.Get("confidence_ceiling"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					ceiling = v.String()
				}
			}
		}
		trueBodies := make([]string, 0, len(trueResps))
		for _, r := range trueResps {
			trueBodies = append(trueBodies, r.Body)
		}
		falseBodies := make([]string, 0, len(falseResps))
		for _, r := range falseResps {
			falseBodies = append(falseBodies, r.Body)
		}
		cls := baseline.Classification{Note: "normal"}
		var o oracle.DifferentialOracle
		ev, err := o.Verify(context.Background(), cls, false, oracle.DifferentialParams{
			TrueBodies: trueBodies, FalseBodies: falseBodies,
			ControlBody: ctrl.Body, Repeats: 3,
			ConfidenceCeiling: ceiling,
		})
		if err != nil {
			panic(err.Error())
		}
		return evToObject(vm, ev)
	})
	_ = oraclesObj.Set("uploadServed", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 3 {
			panic("uploadServed(uploadResp, fetchResp, canary[, opts]) requires 3 arguments")
		}
		uploadResp := respFromValue(call.Arguments[0])
		fetchResp := respFromValue(call.Arguments[1])
		canary := call.Arguments[2].String()
		controlBody := ""
		controlStatus := 0
		var activeTypes []string
		if len(call.Arguments) >= 4 && !goja.IsUndefined(call.Arguments[3]) && !goja.IsNull(call.Arguments[3]) {
			if opts, ok := call.Arguments[3].(*goja.Object); ok {
				// A sibling URL that never received an upload is the clean
				// control: it proves the served artifact is ours.
				for _, key := range []string{"controlUrl", "control_url"} {
					v := opts.Get(key)
					if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
						continue
					}
					cu := v.String()
					if cu == "" || cu == fetchResp.URL {
						continue
					}
					if cr, err := env.Send(JSPoint{URL: cu, Method: http.MethodGet}); err == nil {
						controlBody = cr.Body
						controlStatus = cr.Status
					}
				}
				for _, key := range []string{"activeTypes", "active_types"} {
					v := opts.Get(key)
					if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
						continue
					}
					arr := v.ToObject(vm)
					if length := int(arr.Get("length").ToInteger()); length > 0 {
						activeTypes = make([]string, 0, length)
						for i := 0; i < length; i++ {
							activeTypes = append(activeTypes, arr.Get(fmt.Sprintf("%d", i)).String())
						}
					}
				}
			}
		}
		cls := baseline.ClassifyStatic(fetchResp.Status, toHTTPHeader(fetchResp.Headers), []byte(fetchResp.Body))
		var o oracle.UploadServedOracle
		ev, err := o.Verify(context.Background(), cls, false, oracle.UploadServedParams{
			Canary:        canary,
			UploadStatus:  uploadResp.Status,
			UploadBody:    uploadResp.Body,
			FetchStatus:   fetchResp.Status,
			FetchHeaders:  toHTTPHeader(fetchResp.Headers),
			FetchBody:     fetchResp.Body,
			ControlStatus: controlStatus,
			ControlBody:   controlBody,
			ActiveTypes:   activeTypes,
		})
		if err != nil {
			panic(err.Error())
		}
		return evToObject(vm, ev)
	})
	_ = oraclesObj.Set("header", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic("header(resp) requires 1 argument")
		}
		resp := respFromValue(call.Arguments[0])
		cls := baseline.ClassifyStatic(resp.Status, toHTTPHeader(resp.Headers), []byte(resp.Body))
		var o oracle.HeaderOracle
		ev, err := o.Verify(context.Background(), cls, false, oracle.HeaderParams{Headers: toHTTPHeader(resp.Headers), Body: resp.Body})
		if err != nil {
			panic(err.Error())
		}
		return evToObject(vm, ev)
	})
	_ = oraclesObj.Set("cookie", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic("cookie(resp) requires 1 argument")
		}
		resp := respFromValue(call.Arguments[0])
		cls := baseline.ClassifyStatic(resp.Status, toHTTPHeader(resp.Headers), []byte(resp.Body))
		var o oracle.CookieOracle
		ev, err := o.Verify(context.Background(), cls, false, oracle.CookieParams{Headers: toHTTPHeader(resp.Headers), Target: resp.URL})
		if err != nil {
			panic(err.Error())
		}
		return evToObject(vm, ev)
	})
	_ = oraclesObj.Set("cors", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic("cors(resp[, opts]) requires 1 argument")
		}
		resp := respFromValue(call.Arguments[0])
		// The request Origin decides reflection: without it the oracle can
		// only grade wildcard and null allowlists. Defaults to the
		// plugin-level oracle_params value so fixtures and live scans agree.
		origin := specOracleParam(spec, "request_origin")
		if len(call.Arguments) >= 2 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
			if opts, ok := call.Arguments[1].(*goja.Object); ok {
				for _, key := range []string{"requestOrigin", "request_origin"} {
					if v := opts.Get(key); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
						origin = v.String()
					}
				}
			}
		}
		cls := baseline.ClassifyStatic(resp.Status, toHTTPHeader(resp.Headers), []byte(resp.Body))
		var o oracle.CORSOracle
		ev, err := o.Verify(context.Background(), cls, false, oracle.CORSParams{
			Headers: toHTTPHeader(resp.Headers), RequestOrigin: origin,
		})
		if err != nil {
			panic(err.Error())
		}
		return evToObject(vm, ev)
	})
	_ = oraclesObj.Set("redirect", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			panic("redirect(resp, payloadHost) requires 2 arguments")
		}
		resp := respFromValue(call.Arguments[0])
		payloadHost := call.Arguments[1].String()
		loc := ""
		for k, v := range resp.Headers {
			if strings.EqualFold(k, "Location") {
				loc = v
				break
			}
		}
		cls := baseline.ClassifyStatic(resp.Status, toHTTPHeader(resp.Headers), []byte(resp.Body))
		var o oracle.RedirectOracle
		ev, err := o.Verify(context.Background(), cls, false, oracle.RedirectParams{
			Location: loc, PayloadHost: payloadHost,
			ControlNoRedir: true, ResolveDNS: false,
		})
		if err != nil {
			panic(err.Error())
		}
		return evToObject(vm, ev)
	})
	_ = oraclesObj.Set("oob", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			panic("oob(correlationId, namespace) requires 2 arguments")
		}
		corr := call.Arguments[0].String()
		ns := call.Arguments[1].String()
		o := oracle.OOBOracle{Enabled: env.OOBEnabled}
		seen := false
		if env.OOBCallbackSeen != nil {
			seen = env.OOBCallbackSeen(corr)
		}
		ev, err := o.Verify(context.Background(), baseline.Classification{Note: "normal"}, false, oracle.OOBParams{
			CorrelationID: corr, Namespace: ns, CallbackSeen: seen,
		})
		if err != nil {
			panic(err.Error())
		}
		return evToObject(vm, ev)
	})
	_ = oraclesObj.Set("oobAny", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic("oobAny(correlationIds[, namespace]) requires 1 argument")
		}
		arr := call.Arguments[0].ToObject(vm)
		length := int(arr.Get("length").ToInteger())
		ids := make([]string, 0, length)
		for i := 0; i < length; i++ {
			ids = append(ids, arr.Get(fmt.Sprintf("%d", i)).String())
		}
		ns := "scan_js"
		if len(call.Arguments) >= 2 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
			if s := call.Arguments[1].String(); s != "" {
				ns = s
			}
		}
		// One shared bounded window across every token the plugin shipped.
		var matched []string
		if env.OOBCallbackSeenAny != nil {
			matched = env.OOBCallbackSeenAny(ids)
		} else if env.OOBCallbackSeen != nil {
			for _, id := range ids {
				if env.OOBCallbackSeen(id) {
					matched = append(matched, id)
					break
				}
			}
		}
		if len(matched) == 0 {
			return goja.Null()
		}
		o := oracle.OOBOracle{Enabled: env.OOBEnabled}
		ev, err := o.Verify(context.Background(), baseline.Classification{Note: "normal"}, false, oracle.OOBParams{
			CorrelationID: matched[0], Namespace: ns, CallbackSeen: true,
		})
		if err != nil {
			panic(err.Error())
		}
		val := evToObject(vm, ev)
		if val == nil || goja.IsNull(val) || goja.IsUndefined(val) {
			return goja.Null()
		}
		obj := val.ToObject(vm)
		// The plugin maps correlationId back to the exact point+payload that
		// fired; the evidence object itself stays the single source of truth.
		_ = obj.Set("correlationId", matched[0])
		_ = obj.Set("namespace", ns)
		return obj
	})
	_ = oraclesObj.Set("timing", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			panic("timing(delayResps, controlResps[, opts]) requires 2 arguments")
		}
		delayResps := respsFromArray(vm, call.Arguments[0])
		controlResps := respsFromArray(vm, call.Arguments[1])
		minDelayMs := 5000.0
		repeats := 3
		strategy := "mann-whitney-u"
		baselineStddev := 0.0
		if len(call.Arguments) >= 3 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
			if opts, ok := call.Arguments[2].(*goja.Object); ok {
				if v := opts.Get("min_delay_ms"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					minDelayMs = v.ToFloat()
				}
				if v := opts.Get("minDelayMs"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					minDelayMs = v.ToFloat()
				}
				if v := opts.Get("repeats"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					repeats = int(v.ToInteger())
				}
				if v := opts.Get("strategy"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					strategy = v.String()
				}
				if v := opts.Get("baseline_stddev"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					baselineStddev = v.ToFloat()
				}
				if v := opts.Get("baselineStddev"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					baselineStddev = v.ToFloat()
				}
				if v := opts.Get("delay_samples"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					if arr, ok := v.(*goja.Object); ok {
						delayResps = respsFromArray(vm, v)
						_ = arr
					} else {
						delayResps = samplesFromValue(vm, v)
					}
				}
				if v := opts.Get("control_samples"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					controlResps = samplesFromValue(vm, v)
				}
			}
		}
		delaySamples := rttSamples(delayResps)
		controlSamples := rttSamples(controlResps)
		cls := baseline.Classification{Note: "normal"}
		if len(delayResps) > 0 {
			cls = baseline.ClassifyStatic(delayResps[0].Status, toHTTPHeader(delayResps[0].Headers), []byte(delayResps[0].Body))
		}
		var o oracle.TimingOracle
		ev, err := o.Verify(context.Background(), cls, false, oracle.TimingParams{
			DelaySamples: delaySamples, ControlSamples: controlSamples,
			BaselineStddev: baselineStddev, MinDelayMs: minDelayMs,
			Repeats: repeats, Strategy: strategy,
		})
		if err != nil {
			panic(err.Error())
		}
		return evToObject(vm, ev)
	})
	_ = oraclesObj.Set("execution", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic("execution(resp[, opts]) requires 1 argument")
		}
		resp := respFromValue(call.Arguments[0])
		sink := ""
		source := ""
		if len(call.Arguments) >= 2 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
			if opts, ok := call.Arguments[1].(*goja.Object); ok {
				if v := opts.Get("sink"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					sink = v.String()
				}
				if v := opts.Get("source"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					source = v.String()
				}
			} else {
				sink = call.Arguments[1].String()
				if len(call.Arguments) >= 3 {
					source = call.Arguments[2].String()
				}
			}
		}
		if sink == "" {
			sink = detectDOMSink(resp.Body)
		}
		if sink == "" {
			var o oracle.ExecutionOracle
			ev, err := o.Verify(context.Background(), baseline.ClassifyStatic(resp.Status, toHTTPHeader(resp.Headers), []byte(resp.Body)), false, oracle.ExecutionParams{})
			if err != nil {
				panic(err.Error())
			}
			return evToObject(vm, ev)
		}
		if source == "" {
			source = detectDOMSource(resp.Body)
		}
		cls := baseline.ClassifyStatic(resp.Status, toHTTPHeader(resp.Headers), []byte(resp.Body))
		var o oracle.ExecutionOracle
		ev, err := o.Verify(context.Background(), cls, false, oracle.ExecutionParams{
			Sink: sink, Source: source,
			HeadlessEnabled: false,
		})
		if err != nil {
			panic(err.Error())
		}
		annotateDOMEvidence(ev, source, sink, domSourceSinkLinked(resp.Body, source, sink), false)
		return evToObject(vm, ev)
	})
	_ = oraclesObj.Set("browserExecution", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			panic("browserExecution(point, payload[, opts]) requires 2 arguments")
		}
		if env.BrowserProbe == nil {
			return goja.Null()
		}
		p := pointFromValue(call.Arguments[0])
		payload := call.Arguments[1].String()
		sink, source := "", ""
		correlated := false
		if len(call.Arguments) >= 3 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
			if opts, ok := call.Arguments[2].(*goja.Object); ok {
				if v := opts.Get("sink"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					sink = v.String()
				}
				if v := opts.Get("source"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					source = v.String()
				}
				if v := opts.Get("correlated"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					correlated = v.ToBoolean()
				}
			}
		}
		verified, triggered, clean, err := env.BrowserProbe(p, payload)
		if err != nil || !verified {
			return goja.Null()
		}
		var o oracle.ExecutionOracle
		ev, err := o.Verify(context.Background(), baseline.Classification{Note: "browser probe"}, false, oracle.ExecutionParams{
			Sink: sink, Source: source, Payload: payload,
			HeadlessEnabled: true, Triggered: triggered, ControlClean: clean,
		})
		if err != nil {
			panic(err.Error())
		}
		annotateDOMEvidence(ev, source, sink, correlated, true)
		return evToObject(vm, ev)
	})
	_ = hostObj.Set("oracles", oraclesObj)
	_ = hostObj.Set("candidate", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 3 {
			panic("candidate(point, oracleRef, ev) requires 3 arguments")
		}
		p := pointFromValue(call.Arguments[0])
		ref := call.Arguments[1].String()
		ev := evFromValue(call.Arguments[2])
		if ev == nil {
			return goja.Null()
		}
		name := oracleRefName(ref)
		cand := plugin.Candidate{
			PluginID: spec.ID,
			Target:   p.URL,
			InjectionPoint: plugin.InjectionPoint{
				URL: p.URL, Method: p.Method, ParamName: p.ParamName, ParamLocation: p.ParamLocation,
				Value: p.Value, SourceKind: p.SourceKind, TestID: p.TestID,
			},
			OracleName: name,
		}
		collected = append(collected, JSCandidate{Candidate: cand, Evidence: ev})
		obj := vm.NewObject()
		_ = obj.Set("plugin_id", cand.PluginID)
		_ = obj.Set("oracle", name)
		return obj
	})
	oobObj := vm.NewObject()
	_ = oobObj.Set("generate", func(call goja.FunctionCall) goja.Value {
		if !env.OOBEnabled {
			return goja.Null()
		}
		corr := env.OOBCorrelation
		if corr == "" {
			// Cryptographic single-use token per payload (same discipline as
			// the Tier 1 path); the fixture counter is only a fallback.
			if id, err := oob.NewCorrelationID(); err == nil {
				corr = id
			} else {
				corr = nextCanary()
			}
		}
		ns := env.OOBNamespace
		if ns == "" {
			ns = "scan_js"
		}
		// Live scans fill OOBDomain/OOBURL from the self-hosted provider so
		// payloads point at the operator's server; the oob.example fallback
		// is fixture-only and never resolves anywhere.
		domain := ""
		if env.OOBDomain != nil {
			domain = env.OOBDomain(corr)
		}
		if domain == "" {
			domain = corr + "." + ns + ".oob.example"
		}
		cbURL := ""
		if env.OOBURL != nil {
			cbURL = env.OOBURL(corr)
		}
		if cbURL == "" {
			cbURL = "http://" + domain + "/"
		}
		obj := vm.NewObject()
		_ = obj.Set("url", cbURL)
		_ = obj.Set("domain", domain)
		_ = obj.Set("correlationId", corr)
		_ = obj.Set("namespace", ns)
		return obj
	})
	_ = hostObj.Set("oob", oobObj)
	_ = vm.Set("host", hostObj)

	if _, err := vm.RunString(source); err != nil {
		return nil, fmt.Errorf("js execute %s: evaluate: %w", spec.ID, err)
	}
	runVal := vm.Get("run")
	if runVal == nil || goja.IsUndefined(runVal) {
		return nil, fmt.Errorf("js execute %s: run() missing: %w", spec.ID, plugin.ErrValidation)
	}
	runFn, ok := goja.AssertFunction(runVal)
	if !ok {
		return nil, fmt.Errorf("js execute %s: run not callable: %w", spec.ID, plugin.ErrInvalidReturn)
	}
	var runErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				runErr = fmt.Errorf("js execute %s: run panic: %v: %w", spec.ID, r, plugin.ErrPanic)
			}
		}()
		v, err := runFn(goja.Undefined(), vm.Get("probe"), vm.Get("ctx"))
		if err != nil {
			runErr = fmt.Errorf("js execute %s: run: %w", spec.ID, err)
			return
		}
		_ = v
	}()
	if runErr != nil {
		return nil, runErr
	}
	return collected, nil
}

// respsFromArray converts a JS array of responses to Go values.
// What: Array bridge for differential true/false branches.
// Why: Differential evidence needs full repeat sets, not single samples.
func respsFromArray(vm *goja.Runtime, v goja.Value) []JSResponse {
	obj := v.ToObject(vm)
	length := 0
	if l := obj.Get("length"); l != nil && !goja.IsUndefined(l) {
		length = int(l.ToInteger())
	}
	var out []JSResponse
	for i := 0; i < length; i++ {
		item := obj.Get(itoaStr(i))
		if item == nil || goja.IsUndefined(item) || goja.IsNull(item) {
			continue
		}
		inner := item.ToObject(vm)
		status := 0
		if s := inner.Get("status"); s != nil && !goja.IsUndefined(s) {
			status = int(s.ToInteger())
		}
		body := ""
		if b := inner.Get("body"); b != nil && !goja.IsUndefined(b) && !goja.IsNull(b) {
			body = b.String()
		}
		rawURL := ""
		if u := inner.Get("url"); u != nil && !goja.IsUndefined(u) && !goja.IsNull(u) {
			rawURL = u.String()
		}
		var rttMs float64
		if r := inner.Get("rttMs"); r != nil && !goja.IsUndefined(r) && !goja.IsNull(r) {
			rttMs = r.ToFloat()
		}
		headers := map[string]string{}
		if h := inner.Get("headers"); h != nil && !goja.IsUndefined(h) && !goja.IsNull(h) {
			if ho, ok := h.(*goja.Object); ok {
				for _, k := range ho.Keys() {
					headers[k] = ho.Get(k).String()
				}
			}
		}
		out = append(out, JSResponse{Status: status, Headers: headers, Body: body, URL: rawURL, RTTMs: rttMs})
	}
	return out
}

// toHTTPHeader converts script header maps to http.Header.
// What: Header bridge for oracle verification.
// Why: Oracles consume http.Header while scripts use plain objects.
func toHTTPHeader(m map[string]string) http.Header {
	h := make(http.Header)
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}

// rttSamples extracts RTT series for the timing oracle.
// What: Response rttMs projection (zero means unmeasured).
// Why: Timing evidence must come from Go-measured transports, never from
// script-invented numbers; unmeasured zeros force a reject, not a guess.
func rttSamples(in []JSResponse) []float64 {
	out := make([]float64, 0, len(in))
	for _, r := range in {
		out = append(out, r.RTTMs)
	}
	return out
}

// samplesFromValue reads an explicit numeric array (fixture path).
// What: opts.delay_samples / control_samples bridge for offline tests.
// Why: Fixtures have no live RTT; the Go oracle still validates the math.
func samplesFromValue(vm *goja.Runtime, v goja.Value) []JSResponse {
	obj := v.ToObject(vm)
	length := 0
	if l := obj.Get("length"); l != nil && !goja.IsUndefined(l) {
		length = int(l.ToInteger())
	}
	var out []JSResponse
	for i := 0; i < length; i++ {
		item := obj.Get(itoaStr(i))
		if item == nil || goja.IsUndefined(item) || goja.IsNull(item) {
			continue
		}
		out = append(out, JSResponse{RTTMs: item.ToFloat()})
	}
	return out
}

// detectDOMSink finds the first known dangerous sink in a body (static only).
// What: Substring scan over the headless-free sink vocabulary:
// innerHTML/outerHTML/insertAdjacentHTML, document.write/writeln, eval(),
// setTimeout/setInterval (string form is unresolved statically), the Function
// constructor (`new Function(`), and jQuery `.html(`.
// Why: DOM verdicts without a browser cap at firm; the sink name is the only
// static claim the execution oracle accepts. Vocabulary stays deliberately
// specific (`new function(` not bare `function(`) to avoid matching every
// bundled script and turning firm into noise.
func detectDOMSink(body string) string {
	lower := strings.ToLower(body)
	sinks := []string{
		"innerhtml", "outerhtml", "insertadjacenthtml",
		"document.write", "document.writeln",
		"eval(", "settimeout(", "setinterval(",
		".html(", "new function(",
	}
	for _, s := range sinks {
		if strings.Contains(lower, s) {
			return s
		}
	}
	return ""
}

// detectDOMSource finds the first known URL-controlled source in a body.
// What: Substring scan over URL-borne sources only (location.hash/search/href,
// document.URL/location, referrer, URLSearchParams, window.name, postMessage).
// Why: Source presence lifts tentative to firm; absence keeps the floor.
// Cookie/document storage sources are deliberately out of scope.
func detectDOMSource(body string) string {
	lower := strings.ToLower(body)
	sources := []string{
		"location.hash", "location.search", "location.href", "document.location",
		"document.url", "document.referrer", "urlsearchparams",
		"window.name", "postmessage",
	}
	for _, s := range sources {
		if strings.Contains(lower, s) {
			return s
		}
	}
	return ""
}

var inlineScriptRe = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)

// domSourceSinkLinked reports whether one inline script contains both the
// source and the sink. Separate scripts are not a proven data flow.
// What: Conservative same-script correlation for static DOM evidence.
// Why: Source and sink coexistence alone must not become a confirmed finding.
func domSourceSinkLinked(body, source, sink string) bool {
	if source == "" || sink == "" {
		return false
	}
	src := strings.ToLower(source)
	snk := strings.ToLower(sink)
	for _, m := range inlineScriptRe.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		script := strings.ToLower(m[1])
		if strings.Contains(script, src) && strings.Contains(script, snk) {
			return true
		}
	}
	return false
}

// annotateDOMEvidence records the evidence chain without changing oracle
// confidence. Node insertion is not execution; only the browser probe may set
// execution_confirmed=true.
func annotateDOMEvidence(ev *oracle.Evidence, source, sink string, linked, headless bool) {
	if ev == nil || ev.Verdict != oracle.VerdictAccept {
		return
	}
	if ev.Artifacts == nil {
		ev.Artifacts = map[string]string{}
	}
	ev.Artifacts["source_observed"] = boolString(source != "")
	ev.Artifacts["sink_observed"] = boolString(sink != "")
	if source != "" && sink != "" {
		ev.Artifacts["source_sink_linked"] = boolString(linked)
	} else {
		ev.Artifacts["source_sink_linked"] = "false"
	}
	if headless && ev.ConfidenceContribution == plugin.ConfidenceConfirmed {
		ev.Artifacts["execution_confirmed"] = "true"
		ev.Artifacts["execution"] = "browser-confirmed"
		ev.Artifacts["control_result"] = ev.ControlResult
		return
	}
	ev.Artifacts["execution_confirmed"] = "false"
	ev.Artifacts["control_result"] = "not_run"
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// itoaStr formats an array index without importing strconv at call sites.
// What: Tiny index formatter for goja array access.
// Why: Keeps the binding code free of extra conversion helpers.
func itoaStr(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}
