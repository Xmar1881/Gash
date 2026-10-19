// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package flow

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/discovery"
)

// IsInjectableField alanın akış mutasyonuna uygun olduğunu bildirir.
// What: token, dosya, parola ve gizli kimlik alanları dışlanır.
// Why: CSRF token'ları yalnızca tazelenir; parola/dosya alanları asla
// mutasyona uğratılmaz (v1 kapsamı).
func IsInjectableField(f discovery.FormField) bool {
	if strings.TrimSpace(f.Name) == "" || f.IsToken {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(f.InputType)) {
	case "file", "password", "submit", "image", "button", "reset":
		return false
	}
	name := strings.ToLower(f.Name)
	if strings.Contains(name, "pass") || strings.Contains(name, "password") {
		return false
	}
	return true
}

// InjectableFields formdaki enjekte edilebilir alan indekslerini döner.
func InjectableFields(f discovery.Form) []int {
	var out []int
	for i := range f.Fields {
		if IsInjectableField(f.Fields[i]) {
			out = append(out, i)
		}
	}
	return out
}

// eligibleForm akış adımı için formu seçer (POST tercih edilir).
func eligibleForm(forms []discovery.Form, pageURL, seedURL string) (discovery.Form, int, bool) {
	base, err := url.Parse(seedURL)
	if err != nil {
		return discovery.Form{}, 0, false
	}
	best, bestIdx, bestScore := discovery.Form{}, -1, -1
	for i, form := range forms {
		method := strings.ToUpper(strings.TrimSpace(form.Method))
		if method != http.MethodPost && method != http.MethodGet {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(form.Enctype)) {
		case "", "application/x-www-form-urlencoded", "multipart/form-data":
		default:
			continue
		}
		action, aerr := url.Parse(strings.TrimSpace(form.ActionURL))
		if aerr != nil || action.Host == "" {
			continue
		}
		if !strings.EqualFold(action.Scheme, base.Scheme) || !strings.EqualFold(action.Host, base.Host) {
			continue // çapraz-origin action asla gönderilmez
		}
		if len(InjectableFields(form)) == 0 {
			continue
		}
		score := 0
		if method == http.MethodPost {
			score += 2
		}
		if strings.Contains(strings.ToLower(form.Enctype), "multipart") {
			score--
		}
		if score > bestScore {
			best, bestIdx, bestScore = form, i, score
		}
	}
	if bestIdx < 0 {
		return discovery.Form{}, 0, false
	}
	return best, bestIdx, true
}

// DiscoverFlow tohum URL'inden form tabanlı akışı keşfeder.
// What: Her adımda sayfayı tazeler, ilk uygun formu temiz değerlerle
// gönderir, yönlendirmeleri manuel izler ve sonuç sayfasındaki formla
// devam eder.
// Why: Akışın gerçek durum makinesi ancak sırayla gönderimle görülür;
// tek sayfa form çıkarımı sonraki adımları kaçırır.
func DiscoverFlow(ctx context.Context, send Sender, opts Options) (*Flow, error) {
	seed := strings.TrimSpace(opts.SeedURL)
	if seed == "" {
		return nil, fmt.Errorf("flow seed URL empty")
	}
	seedURL, err := url.Parse(seed)
	if err != nil || seedURL.Host == "" || (seedURL.Scheme != "http" && seedURL.Scheme != "https") {
		return nil, fmt.Errorf("flow seed URL invalid: %q", seed)
	}
	maxSteps := opts.MaxSteps
	if maxSteps <= 0 {
		maxSteps = DefaultMaxSteps
	}
	if maxSteps > HardMaxSteps {
		maxSteps = HardMaxSteps
	}
	maxReq := opts.MaxRequests
	if maxReq <= 0 {
		maxReq = DefaultMaxRequests
	}
	budget := &Budget{Max: maxReq}
	c := newClient(send, seed, opts.SeedCookies, budget)

	flow := &Flow{SeedURL: seedURL.String(), Budget: budget}
	currentURL := seedURL.String()
	prevKey := ""
	for step := 0; step < maxSteps; step++ {
		if ctx.Err() != nil {
			flow.Stopped = "context"
			break
		}
		page, err := c.do(ctx, http.MethodGet, currentURL, nil, nil)
		if err != nil {
			flow.Stopped = "get-error: " + err.Error()
			break
		}
		if page.Status < 200 || page.Status >= 400 {
			flow.Stopped = fmt.Sprintf("page-status-%d", page.Status)
			break
		}
		forms := discovery.ExtractForms(page.URL, []byte(page.Body))
		form, formIdx, ok := eligibleForm(forms, page.URL, flow.SeedURL)
		if !ok {
			flow.Stopped = "no-eligible-form"
			break
		}
		fields := append([]discovery.FormField{}, form.Fields...)
		headers, body, submitURL, err := buildSubmission(form, fields, -1, "")
		if err != nil {
			flow.Stopped = "build-error: " + err.Error()
			break
		}
		resp, err := c.do(ctx, strings.ToUpper(form.Method), submitURL, headers, body)
		if err != nil {
			flow.Stopped = "submit-error: " + err.Error()
			break
		}
		sig := Normalize(resp.Body)
		flow.Steps = append(flow.Steps, Step{
			Index:     step,
			PageURL:   page.URL,
			ActionURL: submitURL,
			Method:    strings.ToUpper(form.Method),
			Enctype:   form.Enctype,
			Fields:    fields,
			FormIndex: formIdx,
			ResultURL: resp.URL,
			Status:    resp.Status,
			Signature: sig,
		})
		flow.Baseline.StepBodies = append(flow.Baseline.StepBodies, sig)
		flow.Baseline.StepRawBodies = append(flow.Baseline.StepRawBodies, resp.Body)
		if resp.Status < 200 || resp.Status >= 400 {
			flow.Stopped = fmt.Sprintf("result-status-%d", resp.Status)
			break
		}
		key := resp.URL + "|" + sig
		if key == prevKey {
			flow.Stopped = "loop"
			break
		}
		prevKey = key
		currentURL = resp.URL
	}
	if len(flow.Steps) > 0 {
		last := flow.Steps[len(flow.Steps)-1]
		flow.Baseline.FinalSignature = last.Signature
		flow.Baseline.FinalBody = last.Signature
		flow.Baseline.FinalRaw = flow.Baseline.StepRawBodies[len(flow.Baseline.StepRawBodies)-1]
		flow.Baseline.FinalURL = last.ResultURL
	}
	return flow, nil
}

// buildSubmission form alanlarını istek başlığı/gövdesine çevirir.
// mutateIdx >= 0 ise o alan payload ile değiştirilir; diğer alanlar tazedir.
func buildSubmission(form discovery.Form, fields []discovery.FormField, mutateIdx int, payload string) (map[string]string, []byte, string, error) {
	method := strings.ToUpper(strings.TrimSpace(form.Method))
	if method == "" {
		method = http.MethodGet
	}
	values := make(map[string]string, len(fields))
	order := make([]string, 0, len(fields))
	for i, f := range fields {
		v := f.Value
		if i == mutateIdx {
			v = payload
		}
		if _, exists := values[f.Name]; !exists {
			order = append(order, f.Name)
		}
		values[f.Name] = v
	}
	action := strings.TrimSpace(form.ActionURL)
	if action == "" {
		action = strings.TrimSpace(form.SourceURL)
	}
	u, err := url.Parse(action)
	if err != nil {
		return nil, nil, "", err
	}
	if method == http.MethodGet {
		q := u.Query()
		for _, name := range order {
			q.Set(name, values[name])
		}
		u.RawQuery = q.Encode()
		return nil, nil, u.String(), nil
	}
	if strings.Contains(strings.ToLower(form.Enctype), "multipart/form-data") {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		sort.Strings(order)
		for _, name := range order {
			_ = w.WriteField(name, values[name])
		}
		_ = w.Close()
		return map[string]string{"Content-Type": w.FormDataContentType()}, buf.Bytes(), u.String(), nil
	}
	formValues := url.Values{}
	for _, name := range order {
		formValues.Set(name, values[name])
	}
	return map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(formValues.Encode()), u.String(), nil
}

// matchStepForm tazelenen sayfadan adımın formunu bulur.
func matchStepForm(forms []discovery.Form, step Step, pageURL string) (discovery.Form, bool) {
	wantAction := normalizeAction(step.ActionURL)
	wantMethod := strings.ToUpper(strings.TrimSpace(step.Method))
	for _, form := range forms {
		if strings.ToUpper(strings.TrimSpace(form.Method)) != wantMethod {
			continue
		}
		if normalizeAction(form.ActionURL) == wantAction {
			return form, true
		}
	}
	// Action dinamikse form sırasına düş (yalnızca aynı metot ve sayfa).
	if step.FormIndex >= 0 && step.FormIndex < len(forms) {
		form := forms[step.FormIndex]
		if strings.ToUpper(strings.TrimSpace(form.Method)) == wantMethod {
			return form, true
		}
	}
	_ = pageURL
	return discovery.Form{}, false
}

func normalizeAction(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	u.Fragment = ""
	return u.String()
}
