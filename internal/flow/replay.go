// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package flow

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Xmar1881/Gash/internal/discovery"
)

// ReplayOptions tek mutasyonlu replay ayarlarıdır.
type ReplayOptions struct {
	StepIndex   int
	Field       string
	Payload     Payload
	SeedCookies map[string]string
	MaxRequests int
}

// ReplayFlow akışı taze oturumla baştan oynatır ve tek alanı mutasyona
// uğratır.
// What: Her adımda sayfa yeniden çekilir (token'lar tazelenir), form canlı
// değerlerle doldurulur, yalnızca hedef alan payload taşır; sonraki adımlar
// temiz değerlerle tamamlanır.
// Why: Kaydedilmiş token'ları yeniden kullanmak CSRF kapısında düşer;
// akış sapması ağ hatası değildir, Stopped nedeniyle dürüstçe raporlanır.
func ReplayFlow(ctx context.Context, send Sender, f *Flow, opts ReplayOptions) (*Replay, error) {
	if f == nil || len(f.Steps) == 0 {
		return nil, fmt.Errorf("flow replay: empty flow")
	}
	if opts.StepIndex < 0 || opts.StepIndex >= len(f.Steps) {
		return nil, fmt.Errorf("flow replay: step %d out of range", opts.StepIndex)
	}
	maxReq := opts.MaxRequests
	if maxReq <= 0 {
		maxReq = DefaultMaxRequests
	}
	budget := &Budget{Max: maxReq}
	c := newClient(send, f.SeedURL, opts.SeedCookies, budget)

	replay := &Replay{StepIndex: opts.StepIndex, Field: opts.Field, Payload: opts.Payload}
	prevURL := f.Steps[0].PageURL
	for i, step := range f.Steps {
		if ctx.Err() != nil {
			replay.Stopped = "context"
			break
		}
		pageURL := step.PageURL
		if i > 0 {
			pageURL = prevURL
		}
		page, err := c.do(ctx, http.MethodGet, pageURL, nil, nil)
		if err != nil {
			replay.Stopped = fmt.Sprintf("get-error-step-%d: %v", i, err)
			break
		}
		if page.Status < 200 || page.Status >= 400 {
			replay.Stopped = fmt.Sprintf("page-status-%d-step-%d", page.Status, i)
			break
		}
		forms := discovery.ExtractForms(page.URL, []byte(page.Body))
		form, ok := matchStepForm(forms, step, page.URL)
		if !ok {
			replay.Stopped = fmt.Sprintf("form-missing-step-%d", i)
			break
		}
		fields := append([]discovery.FormField{}, form.Fields...)
		mutateIdx := -1
		if i == opts.StepIndex {
			mutateIdx = fieldIndex(fields, opts.Field)
			if mutateIdx < 0 {
				replay.Stopped = fmt.Sprintf("field-missing-step-%d", i)
				break
			}
		}
		headers, body, submitURL, berr := buildSubmission(form, fields, mutateIdx, opts.Payload.Value)
		if berr != nil {
			replay.Stopped = fmt.Sprintf("build-error-step-%d: %v", i, berr)
			break
		}
		resp, rerr := c.do(ctx, strings.ToUpper(form.Method), submitURL, headers, body)
		if rerr != nil {
			replay.Stopped = fmt.Sprintf("submit-error-step-%d: %v", i, rerr)
			break
		}
		replay.Responses = append(replay.Responses, StepResponse{
			Index:      i,
			URL:        resp.URL,
			Status:     resp.Status,
			Headers:    resp.Headers,
			Body:       resp.Body,
			Normalized: Normalize(resp.Body),
		})
		prevURL = resp.URL
		if resp.Status < 200 || resp.Status >= 400 {
			replay.Stopped = fmt.Sprintf("result-status-%d-step-%d", resp.Status, i)
			break
		}
	}
	if n := len(replay.Responses); n > 0 {
		replay.Final = replay.Responses[n-1]
	}
	replay.Requests = budget.Used
	return replay, nil
}

func fieldIndex(fields []discovery.FormField, name string) int {
	for i, f := range fields {
		if f.Name == name {
			return i
		}
	}
	return -1
}

// SQLiPayloads verilen prob külliyatını mutasyon payload'larına çevirir.
func SQLiPayloads(probes []string, limit int) []Payload {
	if limit > 0 && len(probes) > limit {
		probes = probes[:limit]
	}
	out := make([]Payload, 0, len(probes))
	for _, p := range probes {
		out = append(out, Payload{Value: p, Kind: PayloadSQLi})
	}
	return out
}

// XSSPayloads tekil marker taşıyan üç yansıma kanaryası üretir.
// What: HTML metin, nitelik ve script-string bağlamları için ayrı
// yürütülebilir payload'lar; marker çağrı argümanı olarak kod konumundadır.
// Why: Yansıma oracle'ı yalnızca marker'ın yürütülebilir bağlamda
// görünmesini kanıt sayar; tırnak içindeki düz marker execution proof
// değildir.
func XSSPayloads(marker string) []Payload {
	return []Payload{
		{Value: `<script>alert(` + marker + `)</script>`, Kind: PayloadXSSHTML, Marker: marker},
		{Value: `"><svg/onload=alert(` + marker + `)>`, Kind: PayloadXSSAttr, Marker: marker},
		{Value: `';alert(` + marker + `);//`, Kind: PayloadXSSScript, Marker: marker},
	}
}
