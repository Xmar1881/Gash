// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/fuzz"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
)

// Tam-form replay fuzz sınırları (Görev B uzantısı).
const (
	// maxFormFuzzForms tarama başına fuzz'lanacak form sayısı.
	maxFormFuzzForms = 5
	// maxFormFuzzFields form başına fuzz'lanacak token-dışı alan sayısı.
	maxFormFuzzFields = 10
	// maxFormFuzzRequestsPerField alan başına en fazla SQLi probu (kontrol hariç).
	maxFormFuzzRequestsPerField = 12
	// maxFormFuzzTokenRefreshes form başına CSRF token tazeleme üst sınırı
	// (ilk tazeleme + 403/419/422 retry'si).
	maxFormFuzzTokenRefreshes = 2
)

// csrfRejectionRegex sunucunun token reddini işaret eden gövde kalıbıdır.
var csrfRejectionRegex = regexp.MustCompile(`(?i)(csrf|xsrf|token).{0,40}(invalid|expired|missing|mismatch)`)

// formFuzzSpec form replay fuzz bulgularının sentetik kural kimliğidir.
// Tests boş olduğu için finding.Build güveni tentative'e kapatır.
func formFuzzSpec() plugin.PluginSpec {
	return plugin.PluginSpec{
		ID:          "form-fuzz-anomaly",
		Name:        "Full-form replay fuzz (active)",
		Description: "Replayed the complete form with one field mutated and observed an anomalous response (tentative, manual review required).",
		Severity:    plugin.SeverityHigh,
		Tags:        []string{"fuzz", "form", "anomaly"},
		Safe:        false,
		Active:      true,
		Phase:       plugin.PhaseProbe,
		APIVersion:  "1.0",
	}
}

// runActiveFormFuzz keşfedilen formları tam-form replay ile fuzz'lar.
// What: Form başına CSRF token tazeleme + kontrol isteği + alan başına
// ≤12 SQLi probu; hata imzası/500/sapma/boolean diferansiyel → tentative.
// Why: Tek-alan gövdeli fuzz'lama sunucu doğrulaması ve CSRF kapısında
// düşer; gerçek form tüm alanlarıyla tekrarlanmadan sink'e ulaşılmaz.
//
// Güvenlik: yalnızca --active koşar; token alanları ASLA fuzz'lanmaz
// (yalnızca tazelenir); çapraz-origin action atlanır (kapsam politikası
// ikinci kilittir); payload'lar yıkıcı değildir (SQLi külliyatı).
func (e *Engine) runActiveFormFuzz(ctx context.Context, target string, client *probe.Client, forms []discovery.Form) ([]*finding.Finding, int64) {
	if !e.cfg.Active || client == nil || len(forms) == 0 {
		return nil, 0
	}
	targetParsed, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return nil, 0
	}
	var out []*finding.Finding
	var total int64
	used := 0
	for _, form := range forms {
		if used >= maxFormFuzzForms || ctx.Err() != nil {
			break
		}
		switch strings.ToUpper(strings.TrimSpace(form.Method)) {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
		default:
			continue
		}
		// Settings/toggle forms (selects + hidden + submit only) are state
		// changers, not injection surface: replaying them enabled DVWA's
		// PHPIDS during a benchmark scan and invalidated later results.
		if !formHasTextInput(form.Fields) {
			continue
		}
		actionParsed, aerr := url.Parse(strings.TrimSpace(form.ActionURL))
		if aerr != nil || !sameSiteOrigin(targetParsed, actionParsed) {
			continue
		}
		got, count := e.fuzzOneForm(ctx, target, client, form)
		out = append(out, got...)
		total += count
		used++
	}
	return out, total
}

// formHasTextInput reports whether the form exposes a user-editable text field.
// Why: select-only/toggle forms mutate application settings (security level,
// PHPIDS) instead of reaching an injection sink; replaying them changes lab
// state and poisons later benchmark scans.
func formHasTextInput(fields []discovery.FormField) bool {
	for _, f := range fields {
		switch strings.ToLower(f.InputType) {
		case "text", "password", "search", "email", "number", "url", "tel", "textarea":
			return true
		}
	}
	return false
}

// fuzzOneForm tek formu tam-replay fuzz'lar.
func (e *Engine) fuzzOneForm(ctx context.Context, target string, client *probe.Client, form discovery.Form) ([]*finding.Finding, int64) {
	fields := make([]discovery.FormField, 0, len(form.Fields))
	for _, f := range form.Fields {
		if f.InputType == "file" {
			continue // dosya alanları hiçbir zaman tekrarlanmaz
		}
		fields = append(fields, f)
	}
	if len(fields) == 0 {
		return nil, 0
	}

	method := strings.ToUpper(strings.TrimSpace(form.Method))
	count := int64(0)
	refreshes := 0
	hasToken := false
	for _, f := range fields {
		if f.IsToken {
			hasToken = true
			break
		}
	}

	// withTokens formu güncel alan değerleriyle JSPoint'e çevirir.
	withTokens := func(name, payload string) loader.JSPoint {
		vals := make(map[string]string, len(fields)-1)
		for _, f := range fields {
			if f.Name == name {
				continue
			}
			vals[f.Name] = f.Value
		}
		return loader.JSPoint{
			URL: form.ActionURL, Method: method,
			ParamName: name, ParamLocation: "body", Value: payload,
			FormValues: vals, FormEnctype: form.Enctype,
		}
	}
	// refreshTokens kaynak sayfayı çeker ve YALNIZCA token değerlerini
	// tazeler; diğer alanlar birebir korunur. En fazla 2 kez çalışır.
	refreshTokens := func() {
		if refreshes >= maxFormFuzzTokenRefreshes {
			return
		}
		refreshes++
		count++
		fresh, ok := e.fetchFreshTokens(ctx, client, form)
		if !ok {
			return
		}
		for i := range fields {
			if !fields[i].IsToken {
				continue
			}
			if v, found := fresh[fields[i].Name]; found {
				fields[i].Value = v
			}
		}
	}
	if hasToken {
		refreshTokens() // ilk tazeleme: kontrol isteği kabul edilsin
	}

	ctrlIdx := -1
	for i, f := range fields {
		if f.InputType != "submit" && !f.IsToken {
			ctrlIdx = i
			break
		}
	}
	if ctrlIdx < 0 {
		return nil, 0
	}

	pctx := plugin.WithPlugin(ctx, "form-fuzz", false, nil)
	buildControl := func() (map[string]string, []byte) {
		p := withTokens(fields[ctrlIdx].Name, fields[ctrlIdx].Value)
		return formRequestBody(p, fields[ctrlIdx].Name, fields[ctrlIdx].Value)
	}
	ctrlHeaders, ctrlBody := buildControl()
	control, cerr := client.Send(pctx, method, form.ActionURL, ctrlHeaders, ctrlBody)
	count++
	if cerr != nil || control == nil {
		return nil, count
	}
	// CSRF retry: yalnızca token varsa, tek kez, yalnızca açık red üzerine.
	if hasToken && isCSRFRejection(control.Status, control.Body) && refreshes < maxFormFuzzTokenRefreshes {
		refreshTokens()
		ctrlHeaders, ctrlBody = buildControl()
		control, cerr = client.Send(pctx, method, form.ActionURL, ctrlHeaders, ctrlBody)
		count++
		if cerr != nil || control == nil {
			return nil, count
		}
	}
	if control.Status >= 500 {
		return nil, count
	}
	ctrlCls := baseline.ClassifyStatic(control.Status, control.Headers, control.Body)
	if ctrlCls.Untrusted {
		return nil, count
	}

	eng := fuzz.NewEngine(client, fuzz.NewBaseline(fuzz.Target{
		Method: method, URL: form.ActionURL, Headers: ctrlHeaders, Body: ctrlBody,
	}, control), fuzz.DefaultBudget(fuzz.ProfileStandard), fuzzSeed)

	tokenVals := make([]string, 0, 4)
	for _, f := range fields {
		if f.IsToken && f.Value != "" {
			tokenVals = append(tokenVals, f.Value)
		}
	}

	probes := fuzz.SQLiProbes()
	if len(probes) > maxFormFuzzRequestsPerField {
		probes = probes[:maxFormFuzzRequestsPerField]
	}

	var out []*finding.Finding
	tried := 0
	for _, fld := range fields {
		if fld.IsToken || fld.InputType == "submit" || ctx.Err() != nil {
			continue
		}
		if tried >= maxFormFuzzFields {
			break
		}
		tried++
		hit := false
		var boolPair [2]*probe.Response
		for idx, payload := range probes {
			if ctx.Err() != nil {
				break
			}
			p := withTokens(fld.Name, payload)
			hdrs, body := formRequestBody(p, fld.Name, payload)
			resp, rerr := client.Send(pctx, method, form.ActionURL, hdrs, body)
			count++
			if rerr != nil || resp == nil {
				continue
			}
			// CSRF reddi sinyal DEĞİLDİR: token varsa tek kez tazeleyip
			// yeniden dene; kap doluysa veya yine reddedilirse probu atla
			// (ret sayfaları sahte sapma üretmesin).
			if isCSRFRejection(resp.Status, resp.Body) {
				if refreshes < maxFormFuzzTokenRefreshes {
					refreshTokens()
					p = withTokens(fld.Name, payload)
					hdrs, body = formRequestBody(p, fld.Name, payload)
					resp, rerr = client.Send(pctx, method, form.ActionURL, hdrs, body)
					count++
				}
				if rerr != nil || resp == nil || isCSRFRejection(resp.Status, resp.Body) {
					continue
				}
			}
			if idx < len(boolPair) {
				boolPair[idx] = resp
			}
			div := eng.Compare(resp)
			if ff := e.formFinding(ctx, target, p, control, payload, resp, div); ff != nil {
				out = append(out, ff)
				hit = true
				break
			}
		}
		if !hit {
			if ff := e.formBooleanFinding(ctx, target, withTokens(fld.Name, ""), control, boolPair, tokenVals); ff != nil {
				out = append(out, ff)
			}
		}
	}
	return out, count
}

// formFinding tek prob yanıtını bulguya çevirir (nil = bulgu yok).
func (e *Engine) formFinding(ctx context.Context, target string, p loader.JSPoint, control *probe.Response, payload string, resp *probe.Response, div fuzz.Divergence) *finding.Finding {
	snippet := truncate(string(resp.Body), 4096)
	cls := baseline.ClassifyStatic(resp.Status, nil, []byte(snippet))
	if cls.Untrusted {
		return nil
	}
	cand := plugin.Candidate{
		PluginID: "form-fuzz-anomaly",
		Target:   target,
		InjectionPoint: plugin.InjectionPoint{
			URL: p.URL, Method: p.Method,
			ParamName: p.ParamName, ParamLocation: "body",
			Value: truncate(payload, 120),
		},
		OracleName:   "error",
		OracleParams: map[string]string{"mutation": "form_field", "replay": "full_form"},
	}
	// 1. SQL/hata imzası + kontrolde yokluk → error oracle kanıtı.
	var o oracle.ErrorSignatureOracle
	ev, err := o.Verify(ctx, cls, false, oracle.ErrorSignatureParams{
		Body: snippet, ControlBody: string(control.Body), Mode: "sqli",
	})
	if err == nil && ev != nil && ev.Verdict == oracle.VerdictAccept {
		ff, ferr := finding.Build(formFuzzSpec(), cand, ev, "GASH-004", "CWE-89", "", "")
		if ferr == nil && ff != nil {
			return ff
		}
	}
	// 2. HTTP 500 (imzasız bile) → tentative anomali.
	if resp.Status >= 500 {
		ev500 := &oracle.Evidence{
			Verdict:                oracle.VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceTentative,
			Artifacts: map[string]string{
				"status":   fmt.Sprintf("%d", resp.Status),
				"mutation": "form_field",
				"snippet":  truncate(snippet, 300),
			},
			Repeats:       1,
			ControlResult: "control-stable",
			Note:          "tam-form replay fuzz HTTP 500 üretti (kontrol stabil) → tentative, elle doğrulama gerekir",
		}
		ff, ferr := finding.Build(formFuzzSpec(), cand, ev500, "GASH-000", "CWE-693", "", "")
		if ferr == nil && ff != nil {
			return ff
		}
		return nil
	}
	// 3. Belirgin yanıt sapması (durum/boyut/zaman) → tentative.
	if div.Significant {
		evd := &oracle.Evidence{
			Verdict:                oracle.VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceTentative,
			Artifacts: map[string]string{
				"status":     fmt.Sprintf("%d", resp.Status),
				"similarity": fmt.Sprintf("%.3f", div.SimScore),
				"mutation":   "form_field",
			},
			Repeats:       1,
			ControlResult: "control-stable",
			Note:          "tam-form replay fuzz belirgin yanıt sapması üretti → tentative, elle doğrulama gerekir",
		}
		cand.OracleName = "differential"
		ff, ferr := finding.Build(formFuzzSpec(), cand, evd, "GASH-000", "CWE-693", "", "")
		if ferr == nil && ff != nil {
			return ff
		}
	}
	return nil
}

// formBooleanFinding boolean çifti (true/false) maskeli diferansiyelini
// bulguya çevirir: true ≠ false VE biri kontrole eşit → tentative.
// Token değerleri maskelenir ki dönen token sapması sinyal sanılmasın.
func (e *Engine) formBooleanFinding(ctx context.Context, target string, p loader.JSPoint, control *probe.Response, pair [2]*probe.Response, tokenVals []string) *finding.Finding {
	if pair[0] == nil || pair[1] == nil || control == nil {
		return nil
	}
	t := maskTokenValues(pair[0].Body, tokenVals)
	f := maskTokenValues(pair[1].Body, tokenVals)
	c := maskTokenValues(control.Body, tokenVals)
	if t == f || (t != c && f != c) {
		return nil
	}
	cls := baseline.ClassifyStatic(pair[0].Status, nil, pair[0].Body)
	if cls.Untrusted {
		return nil
	}
	cand := plugin.Candidate{
		PluginID: "form-fuzz-anomaly",
		Target:   target,
		InjectionPoint: plugin.InjectionPoint{
			URL: p.URL, Method: p.Method,
			ParamName: p.ParamName, ParamLocation: "body",
			Value: fuzz.SQLiBooleanProbes[1],
		},
		OracleName:   "differential",
		OracleParams: map[string]string{"mutation": "form_boolean", "replay": "full_form"},
	}
	ev := &oracle.Evidence{
		Verdict:                oracle.VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceTentative,
		Artifacts: map[string]string{
			"mutation":  "form_boolean",
			"true_len":  fmt.Sprintf("%d", len(t)),
			"false_len": fmt.Sprintf("%d", len(f)),
		},
		Repeats:       1,
		ControlResult: "control-stable",
		Note:          "boolean çifti maskeli gövdede ayrıştı ve biri kontrole eşit → tentative (kör SQLi şüphesi)",
	}
	ff, ferr := finding.Build(formFuzzSpec(), cand, ev, "GASH-004", "CWE-89", "", "")
	if ferr == nil && ff != nil {
		return ff
	}
	return nil
}

// fetchFreshTokens kaynak sayfayı çeker ve eşleşen formun token
// alanlarının taze değerlerini döndürür (yalnızca GET; diğer alanlar
// birebir korunur — kaydedilen durum asla değiştirilmez).
func (e *Engine) fetchFreshTokens(ctx context.Context, client *probe.Client, form discovery.Form) (map[string]string, bool) {
	src := strings.TrimSpace(form.SourceURL)
	if src == "" {
		src = form.ActionURL
	}
	if src == "" {
		return nil, false
	}
	pctx := plugin.WithPlugin(ctx, "form-fuzz", true, nil)
	resp, err := client.Send(pctx, http.MethodGet, src, nil, nil)
	if err != nil || resp == nil || resp.Status >= 500 {
		return nil, false
	}
	for _, cand := range discovery.ExtractForms(src, resp.Body) {
		if !strings.EqualFold(cand.Method, form.Method) || cand.ActionURL != form.ActionURL {
			continue
		}
		out := make(map[string]string)
		for _, f := range cand.Fields {
			if f.IsToken && f.Name != "" {
				out[f.Name] = f.Value
			}
		}
		if len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}

// isCSRFRejection sunucunun token'ı açıkça reddettiğini bildirir.
func isCSRFRejection(status int, body []byte) bool {
	switch status {
	case http.StatusForbidden, 419, 422:
	default:
		return false
	}
	return csrfRejectionRegex.Match(body)
}

// maskTokenValues gövdedeki token değerlerini sabit bir yer tutucuyla
// değiştirir; ki dönen CSRF token'ları diferansiyel sinyal sayılmasın.
func maskTokenValues(body []byte, tokenVals []string) string {
	s := string(body)
	for _, v := range tokenVals {
		if v == "" {
			continue
		}
		s = strings.ReplaceAll(s, v, "[gash-token]")
	}
	return s
}

// sameSiteOrigin action'ın hedef host/scheme ile aynı olmasını zorunlu kılar
// (çapraz-site form POST'u asla gönderilmez).
func sameSiteOrigin(target, action *url.URL) bool {
	if target == nil || action == nil {
		return false
	}
	return strings.EqualFold(target.Scheme, action.Scheme) && strings.EqualFold(target.Host, action.Host)
}
