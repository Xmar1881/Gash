// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
)

// BOLA/IDOR çift-kullanıcı matrisi sınırları (Görev C).
const (
	// maxMatrixPoints tarama başına çapraz sorgulanacak nesne referansı.
	maxMatrixPoints = 5
	// matrixRepeats kullanıcı başına tekrar (kararlılık kanıtı).
	matrixRepeats = 3
)

// idorLikeParam nesne referansına benzeyen parametre adlarıdır.
var idorLikeParam = map[string]bool{
	"id": true, "user_id": true, "account_id": true, "order_id": true,
	"item_id": true, "resource_id": true, "object_id": true,
	"profile_id": true, "uuid": true, "guid": true,
}

// idorMatrixSpec matris bulgularının sentetik kural kimliğidir.
// Tests boş olduğu için bulgular tentative tavanındadır (elle doğrulama şart).
func idorMatrixSpec() plugin.PluginSpec {
	return plugin.PluginSpec{
		ID:          "idor-bola-matrix",
		Name:        "Cross-user object divergence (BOLA screen)",
		Description: "Same object reference returns stably different content for two users (tentative, manual verification required).",
		Severity:    plugin.SeverityHigh,
		Tags:        []string{"idor", "bola", "authorization"},
		Safe:        false,
		Active:      true,
		Phase:       plugin.PhaseProbe,
		APIVersion:  "1.0",
	}
}

// runCrossUserMatrix aynı nesne referansını iki kullanıcı kimliğiyle çapraz
// sorgular. What: Kullanıcı başına 3 tekrar; maskelenmiş gövdeler kullanıcı
// içinde stabil, kullanıcılar arası farklıysa tentative Finding.
// Why: BOLA/IDOR yalnızca çift kimlikle test edilebilir; tekil tarama bunu
// anonim kanıt gibi gösteremez (dürüstlük kuralı).
//
// Güvenlik: --active + iki bayrak + izinli hedef şart; salt okuma
// karşılaştırmasıdır (nesne ID'leri üretilmez, yazma YOK); bütçe/kapsam
// politika katmanında zorlanır.
func (e *Engine) runCrossUserMatrix(ctx context.Context, client *probe.Client, points []loader.JSPoint) ([]*finding.Finding, int64) {
	if !e.cfg.Active || !e.HasDualAuth() {
		return nil, 0
	}
	if client == nil {
		return nil, 0
	}
	headersA := e.cfg.AuthA.HeaderMap()
	headersB := e.cfg.AuthB.HeaderMap()
	masker := baseline.NewDefaultModel()
	var out []*finding.Finding
	var total int64
	checked := 0
	for _, p := range points {
		if checked >= maxMatrixPoints {
			break
		}
		loc := strings.TrimSpace(p.ParamLocation)
		if strings.EqualFold(loc, "fragment") || strings.EqualFold(loc, "hash") {
			continue
		}
		if !idorLikeParam[strings.ToLower(strings.TrimSpace(p.ParamName))] {
			continue
		}
		checked++
		if ctx.Err() != nil {
			break
		}
		ff, n := e.matrixOnePoint(ctx, client, masker, p, headersA, headersB)
		out = append(out, ff...)
		total += n
	}
	return out, total
}

// matrixOnePoint tek referansı iki kimlikle 3'er kez okur.
func (e *Engine) matrixOnePoint(ctx context.Context, client *probe.Client, masker *baseline.Model, p loader.JSPoint, headersA, headersB map[string]string) ([]*finding.Finding, int64) {
	method, rawURL, reqHeaders, reqBody := matrixRequestForPoint(p)
	var count int64
	sendAs := func(headers map[string]string) (int, []byte, bool) {
		merged := make(map[string]string, len(reqHeaders)+len(headers))
		for k, v := range reqHeaders {
			merged[k] = v
		}
		for k, v := range headers {
			if _, ok := merged[k]; !ok {
				merged[k] = v
			}
		}
		pctx := plugin.WithPlugin(ctx, "idor-matrix", isReadOnlyMethod(method), nil)
		resp, err := client.Send(pctx, method, rawURL, merged, reqBody)
		count++
		if err != nil || resp == nil {
			return 0, nil, false
		}
		if resp.Status >= 400 {
			return resp.Status, nil, false
		}
		cls := baseline.ClassifyStatic(resp.Status, resp.Headers, resp.Body)
		if cls.Untrusted || cls.Soft404 {
			return resp.Status, nil, false
		}
		return resp.Status, masker.Mask(resp.Body), true
	}
	var statusA, statusB int
	var bodiesA, bodiesB []string
	ok := true
	for i := 0; i < matrixRepeats; i++ {
		s, b, good := sendAs(headersA)
		if i == 0 {
			statusA = s
		} else if s != statusA {
			ok = false
		}
		if !good {
			ok = false
			break
		}
		bodiesA = append(bodiesA, string(b))
	}
	for i := 0; i < matrixRepeats && ok; i++ {
		s, b, good := sendAs(headersB)
		if i == 0 {
			statusB = s
		} else if s != statusB {
			ok = false
		}
		if !good {
			ok = false
			break
		}
		bodiesB = append(bodiesB, string(b))
	}
	if !ok || len(bodiesA) != matrixRepeats || len(bodiesB) != matrixRepeats {
		return nil, count
	}
	if statusA != statusB {
		return nil, count
	}
	for _, b := range bodiesA[1:] {
		if b != bodiesA[0] {
			return nil, count
		}
	}
	for _, b := range bodiesB[1:] {
		if b != bodiesB[0] {
			return nil, count
		}
	}
	if bodiesA[0] == bodiesB[0] || len(strings.TrimSpace(bodiesA[0])) < 10 {
		return nil, count
	}
	ev := &oracle.Evidence{
		Verdict:                oracle.VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceTentative,
		Artifacts: map[string]string{
			"status":     fmt.Sprintf("%d", statusA),
			"user_a_len": fmt.Sprintf("%d", len(bodiesA[0])),
			"user_b_len": fmt.Sprintf("%d", len(bodiesB[0])),
		},
		Repeats:       matrixRepeats,
		ControlResult: "cross-user-stable",
		Note:          "aynı nesne referansı iki kullanıcıda stabil farklı içerik döndü → tentative BOLA/IDOR, sahiplik elle doğrulanmalı",
	}
	cand := plugin.Candidate{
		PluginID: "idor-bola-matrix",
		Target:   p.URL,
		InjectionPoint: plugin.InjectionPoint{
			URL: p.URL, Method: nonEmpty(p.Method, http.MethodGet),
			ParamName: p.ParamName, ParamLocation: p.ParamLocation,
			Value: matrixProbeValue(p),
		},
		OracleName:   "differential",
		OracleParams: map[string]string{"users": "a-vs-b", "repeats": "3"},
	}
	ff, err := finding.Build(idorMatrixSpec(), cand, ev, "GASH-005", "CWE-639", "", "")
	if err != nil || ff == nil {
		return nil, count
	}
	return []*finding.Finding{ff}, count
}

// matrixProbeValue keşfedilen değeri, boşsa "1" varsayımını kullanır.
func matrixProbeValue(p loader.JSPoint) string {
	if strings.TrimSpace(p.Value) != "" {
		return p.Value
	}
	return "1"
}

// matrixRequestForPoint noktayı tek okuma isteğine çevirir.
func matrixRequestForPoint(p loader.JSPoint) (method, rawURL string, headers map[string]string, body []byte) {
	method = nonEmpty(p.Method, http.MethodGet)
	rawURL = p.URL
	value := matrixProbeValue(p)
	switch strings.ToLower(strings.TrimSpace(p.ParamLocation)) {
	case "body":
		param := p.ParamName
		if param == "" {
			param = "id"
		}
		headers, body = formRequestBody(p, param, value)
	default:
		param := p.ParamName
		if param == "" {
			param = "id"
		}
		if u, err := url.Parse(rawURL); err == nil && u != nil {
			q := u.Query()
			if strings.TrimSpace(q.Get(param)) == "" {
				q.Set(param, value)
				u.RawQuery = q.Encode()
				rawURL = u.String()
			}
		}
	}
	return method, rawURL, headers, body
}
