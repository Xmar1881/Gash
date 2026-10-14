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
	"sort"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/dop251/goja"
)

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
	// ParamLocation is query, body, header, path, or cookie.
	ParamLocation string
	// Value is the current parameter value.
	Value string
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
	// OOBCallbackSeen reports whether a correlation ID was observed.
	OOBCallbackSeen func(correlationID string) bool
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
	default:
		return strings.ToLower(strings.TrimSpace(ref))
	}
}

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
		timeout = 30 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		cands []JSCandidate
		err   error
	}
	ch := make(chan outcome, 1)
	go func() {
		cands, err := executeJSOnce(spec, source, env)
		ch <- outcome{cands: cands, err: err}
	}()

	select {
	case <-runCtx.Done():
		return nil, fmt.Errorf("js execute %s: %w", spec.ID, plugin.ErrTimeout)
	case o := <-ch:
		return o.cands, o.err
	}
}

func executeJSOnce(spec *plugin.PluginSpec, source string, env *JSEnv) ([]JSCandidate, error) {
	vm := goja.New()
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

	var toPointObject func(vm *goja.Runtime, p JSPoint) goja.Value
	toPointObject = func(vm *goja.Runtime, p JSPoint) goja.Value {
		obj := vm.NewObject()
		_ = obj.Set("url", p.URL)
		_ = obj.Set("method", p.Method)
		_ = obj.Set("paramName", p.ParamName)
		_ = obj.Set("paramLocation", p.ParamLocation)
		_ = obj.Set("value", p.Value)
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
		return JSPoint{
			URL: get("url"), Method: method,
			ParamName: get("paramName"), ParamLocation: get("paramLocation"),
			Value: get("value"),
		}
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
		neutral.Value = "gash-control-neutral"
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
		p := pointFromValue(call.Arguments[0])
		resp, err := env.Send(p)
		if err != nil {
			panic(err.Error())
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
	_ = oraclesObj.Set("error", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			panic("error(resp, controlResp) requires 2 arguments")
		}
		resp := respFromValue(call.Arguments[0])
		ctrl := respFromValue(call.Arguments[1])
		cls := baseline.ClassifyStatic(resp.Status, toHTTPHeader(resp.Headers), []byte(resp.Body))
		var o oracle.ErrorSignatureOracle
		ev, err := o.Verify(context.Background(), cls, false, oracle.ErrorSignatureParams{
			Body: resp.Body, ControlBody: ctrl.Body,
		})
		if err != nil {
			panic(err.Error())
		}
		return evToObject(vm, ev)
	})
	_ = oraclesObj.Set("differential", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 3 {
			panic("differential(trueResps, falseResps, controlResp) requires 3 arguments")
		}
		trueResps := respsFromArray(vm, call.Arguments[0])
		falseResps := respsFromArray(vm, call.Arguments[1])
		ctrl := respFromValue(call.Arguments[2])
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
		ev, err := o.Verify(context.Background(), cls, false, oracle.HeaderParams{Headers: toHTTPHeader(resp.Headers)})
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
			panic("cors(resp) requires 1 argument")
		}
		resp := respFromValue(call.Arguments[0])
		cls := baseline.ClassifyStatic(resp.Status, toHTTPHeader(resp.Headers), []byte(resp.Body))
		var o oracle.CORSOracle
		ev, err := o.Verify(context.Background(), cls, false, oracle.CORSParams{Headers: toHTTPHeader(resp.Headers)})
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
			PluginID:       spec.ID,
			Target:         p.URL,
			InjectionPoint: plugin.InjectionPoint{URL: p.URL, Method: p.Method, ParamName: p.ParamName, ParamLocation: p.ParamLocation, Value: p.Value},
			OracleName:     name,
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
			corr = nextCanary()
		}
		ns := env.OOBNamespace
		if ns == "" {
			ns = "scan_js"
		}
		obj := vm.NewObject()
		_ = obj.Set("url", fmt.Sprintf("http://%s.%s.oob.example/", corr, ns))
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
// What: Substring scan over the headless-free sink vocabulary.
// Why: DOM verdicts without a browser cap at firm; the sink name is the
// only static claim the execution oracle accepts.
func detectDOMSink(body string) string {
	lower := strings.ToLower(body)
	sinks := []string{"innerhtml", "outerhtml", "document.write", "document.writeln", "eval(", "settimeout(", "setinterval(", "location.hash", "postmessage"}
	for _, s := range sinks {
		if strings.Contains(lower, s) {
			return s
		}
	}
	return ""
}

// detectDOMSource finds the first known URL-controlled source in a body.
// What: Substring scan over location/hash/search style sources.
// Why: Source presence lifts tentative to firm; absence keeps the floor.
func detectDOMSource(body string) string {
	lower := strings.ToLower(body)
	sources := []string{"location.hash", "location.search", "location.href", "document.url", "window.name", "postmessage"}
	for _, s := range sources {
		if strings.Contains(lower, s) {
			return s
		}
	}
	return ""
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
