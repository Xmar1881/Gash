// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package flow

import (
	"context"
	"fmt"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// ResultKind değerlendirme sonucu türüdür.
type ResultKind string

const (
	// ResultSQLiError hata-imzalı SQLi kanıtıdır (GASH-004).
	ResultSQLiError ResultKind = "sqli-error"
	// ResultXSSReflection yürütülebilir bağlamda yansıma kanıtıdır (GASH-001).
	ResultXSSReflection ResultKind = "xss-reflection"
	// ResultDifferential maddi yanıt sapmasıdır (GASH-005, N=1 tentative).
	ResultDifferential ResultKind = "differential"
)

// Result tek mutasyonun değerlendirilmiş kanıtıdır.
type Result struct {
	Kind      ResultKind
	Step      int
	Field     string
	Payload   string
	RuleID    string
	CWE       string
	Evidence  *oracle.Evidence
	Artifacts map[string]string
	Note      string
	// Requests bu sonucun üretilmesi için harcanan istek sayısıdır.
	Requests int
}

// Evaluate replay yanıtlarını temiz baseline'a karşı değerlendirir.
// What: Mutasyon adımından itibaren her yanıtta SQL hata imzası, XSS
// yansıması ve normalize gövde sapması arar.
// Why: Akışın alt adımlarında görünen etki, tek istekli taramanın
// kaçırdığı gerçek sink kanıtıdır; N=1 olduğu için differential daima
// tentative kalır.
func Evaluate(ctx context.Context, f *Flow, r *Replay) []Result {
	if f == nil || r == nil || len(r.Responses) == 0 {
		return nil
	}
	var out []Result
	seen := make(map[string]bool)
	for _, resp := range r.Responses {
		if resp.Index < r.StepIndex {
			continue
		}
		cls := baseline.ClassifyStatic(resp.Status, resp.Headers, []byte(resp.Body))
		if cls.Untrusted {
			continue
		}
		control := ""
		if resp.Index < len(f.Baseline.StepRawBodies) {
			control = f.Baseline.StepRawBodies[resp.Index]
		}
		if ev := evaluateError(ctx, resp, control); ev != nil {
			key := fmt.Sprintf("error|%d", resp.Index)
			if !seen[key] {
				seen[key] = true
				out = append(out, Result{
					Kind: ResultSQLiError, Step: resp.Index, Field: r.Field,
					Payload: r.Payload.Value, RuleID: "GASH-004", CWE: "CWE-89",
					Evidence: ev, Note: ev.Note,
				})
			}
		}
		if r.Payload.Marker != "" {
			if ev := evaluateReflection(ctx, resp, control, r.Payload.Marker); ev != nil {
				key := fmt.Sprintf("xss|%d", resp.Index)
				if !seen[key] {
					seen[key] = true
					out = append(out, Result{
						Kind: ResultXSSReflection, Step: resp.Index, Field: r.Field,
						Payload: r.Payload.Value, RuleID: "GASH-001", CWE: "CWE-79",
						Evidence: ev, Note: ev.Note,
					})
				}
			}
		}
	}
	if len(out) == 0 {
		if res, ok := evaluateDifferential(f, r); ok {
			out = append(out, res)
		}
	}
	return out
}

func evaluateError(ctx context.Context, resp StepResponse, control string) *oracle.Evidence {
	var o oracle.ErrorSignatureOracle
	cls := baseline.ClassifyStatic(resp.Status, resp.Headers, []byte(resp.Body))
	ev, err := o.Verify(ctx, cls, false, oracle.ErrorSignatureParams{
		Body: resp.Body, ControlBody: control, Mode: "sqli",
	})
	if err != nil || ev == nil || ev.Verdict != oracle.VerdictAccept {
		return nil
	}
	return ev
}

func evaluateReflection(ctx context.Context, resp StepResponse, control, marker string) *oracle.Evidence {
	var o oracle.ReflectionOracle
	cls := baseline.ClassifyStatic(resp.Status, resp.Headers, []byte(resp.Body))
	ev, err := o.Verify(ctx, resp.Body, resp.Headers, cls, false, oracle.ReflectionParams{
		Canary: marker,
		Contexts: []string{
			"html-text", "attr", "url", "attr-executable",
			"script", "url-executable",
		},
		RequireExecutableContext: true,
		ControlBody:              control,
	})
	if err != nil || ev == nil || ev.Verdict != oracle.VerdictAccept {
		return nil
	}
	return ev
}

// evaluateDifferential maddi normalize sapmasını tentative kanıta çevirir.
func evaluateDifferential(f *Flow, r *Replay) (Result, bool) {
	final := r.Final
	if final.Index < r.StepIndex || final.Body == "" {
		return Result{}, false
	}
	base := f.Baseline.FinalBody
	if final.Index < len(f.Baseline.StepBodies) {
		base = f.Baseline.StepBodies[final.Index]
	}
	norm := final.Normalized
	if norm == "" {
		norm = Normalize(final.Body)
	}
	if base == "" {
		return Result{}, false
	}
	sim := Similarity(base, norm)
	if sim >= materialDifference {
		return Result{}, false
	}
	ev := &oracle.Evidence{
		Verdict:                oracle.VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceTentative,
		Artifacts: map[string]string{
			"similarity": fmt.Sprintf("%.3f", sim),
			"step":       fmt.Sprintf("%d", final.Index),
			"replay":     "multi-step",
		},
		Repeats:       1,
		ControlResult: "baseline-stable",
		Note:          "çok-adımlı akışta maddi yanıt sapması (N=1, elle doğrulama gerekir)",
	}
	return Result{
		Kind: ResultDifferential, Step: final.Index, Field: r.Field,
		Payload: r.Payload.Value, RuleID: "GASH-005", CWE: "CWE-89",
		Evidence: ev, Note: ev.Note,
	}, true
}

// ProbeFlowBypass akış sonuna oturumsuz doğrudan erişimi dener.
// What: Taze jar ile yalnızca sonuç URL'i çekilir; en az iki adımlı,
// gönderimle ulaşılmış, 2xx, login formu içermeyen ve imzası temiz akışa
// ~0.95 benzer yanıt GASH-068 (CWE-841) tentative adayıdır. İkinci dönüş
// değeri bu ekranın harcadığı istek sayısıdır (bulgu olsun ya da olmasın).
// Why: Aynı içeriğin oturumsuz dönmesi adım atlama şüphesidir; N=1
// olduğundan yalnızca tentative üretilir, kesin ihlal iddiası yoktur.
func ProbeFlowBypass(ctx context.Context, send Sender, f *Flow, opts Options) (*Result, int, error) {
	if f == nil || len(f.Steps) < 2 {
		return nil, 0, nil
	}
	last := f.Steps[len(f.Steps)-1]
	target := strings.TrimSpace(f.Baseline.FinalURL)
	if target == "" {
		target = strings.TrimSpace(last.ResultURL)
	}
	if target == "" {
		return nil, 0, nil
	}
	maxReq := opts.MaxRequests
	if maxReq <= 0 {
		maxReq = DefaultMaxRequests
	}
	budget := &Budget{Max: maxReq}
	c := newClient(send, f.SeedURL, nil, budget) // oturumsuz: tohum cookie YOK
	resp, err := c.do(ctx, "GET", target, nil, nil)
	if err != nil {
		return nil, budget.Used, err
	}
	used := budget.Used
	if resp.Status < 200 || resp.Status >= 300 {
		return nil, used, nil
	}
	body := resp.Body
	if containsLoginForm(body) {
		return nil, used, nil
	}
	norm := Normalize(body)
	sim := Similarity(f.Baseline.FinalBody, norm)
	if sim < bypassSimilarity {
		return nil, used, nil
	}
	ev := &oracle.Evidence{
		Verdict:                oracle.VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceTentative,
		Artifacts: map[string]string{
			"steps_discovered": fmt.Sprintf("%d", len(f.Steps)),
			"direct_access":    "identical",
			"similarity":       fmt.Sprintf("%.3f", sim),
			"heuristic":        "session-bypass",
		},
		Repeats:       1,
		ControlResult: "authenticated-baseline",
		Note:          "sonuç sayfası oturumsuz aynı içerikle döndü (sezgisel, elle doğrulama gerekir)",
	}
	return &Result{
		Kind: ResultDifferential, Step: last.Index, Field: "",
		Payload: "", RuleID: "GASH-068", CWE: "CWE-841",
		Evidence: ev, Note: ev.Note, Requests: used,
	}, used, nil
}

func containsLoginForm(body string) bool {
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "<form") {
		return false
	}
	if strings.Contains(lower, "type=\"password\"") || strings.Contains(lower, "type='password'") || strings.Contains(lower, "type=password") {
		return true
	}
	return false
}
