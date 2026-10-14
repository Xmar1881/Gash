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
	"github.com/Xmar1881/Gash/internal/fuzz"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
)

// Aktif fuzzing sınırları (Görev B).
const (
	// maxFuzzPoints tarama başına fuzz'lanacak enjeksiyon noktası.
	maxFuzzPoints = 10
	// maxFuzzRequestsPerPoint nokta başına fuzz isteği (kontrol hariç).
	maxFuzzRequestsPerPoint = 20
	// fuzzSeed sabit tohumdur: aynı hedefte tekrar üretilebilirlik.
	fuzzSeed = 7
	// fuzzNeutral kontrol değeridir (zararsız, kalıcı etkisiz).
	fuzzNeutral = "gash-fuzz-neutral"
)

// fuzzSpec fuzz anomali bulgularının sentetik kural kimliğidir.
// Tests boş olduğu için finding.Build güveni tentative'e kapatır.
func fuzzSpec() plugin.PluginSpec {
	return plugin.PluginSpec{
		ID:          "fuzz-anomaly",
		Name:        "Fuzz anomaly (active)",
		Description: "Controlled mutation probe produced an anomalous response (tentative, manual review required).",
		Severity:    plugin.SeverityHigh,
		Tags:        []string{"fuzz", "anomaly"},
		Safe:        false,
		Active:      true,
		Phase:       plugin.PhaseProbe,
		APIVersion:  "1.0",
	}
}

// runActiveFuzz ExtractSurface noktalarına kontrollü mutasyon gönderir.
// What: Nokta başına kontrol + ≤20 mutasyon; 500/SQL döküntüsü/boyut
// sıçraması Finding'e dönüşür (daima tentative).
// Why: Atıl fuzz motorunu canlı döngüye bağlar; sabit imza-dışı kapsama.
//
// Güvenlik: yalnızca --active (agresif dahil) koşar; payload'lar yıkıcı
// değildir (DROP/DELETE/RM YOK, kalıcı etki YOK); bütçe + kapsam politika
// katmanında zorlanır; blok sayfalar bulgu olmaz.
func (e *Engine) runActiveFuzz(ctx context.Context, target string, client *probe.Client, points []loader.JSPoint) ([]*finding.Finding, int64) {
	if !e.cfg.Active {
		return nil, 0
	}
	if client == nil || len(points) == 0 {
		return nil, 0
	}
	profile := fuzz.ProfileStandard
	if e.cfg.Deep {
		profile = fuzz.ProfileDeep
	}
	var out []*finding.Finding
	var total int64
	n := len(points)
	if n > maxFuzzPoints {
		n = maxFuzzPoints
	}
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		got, count := e.fuzzOnePoint(ctx, target, client, points[i], profile)
		out = append(out, got...)
		total += count
	}
	return out, total
}

// fuzzOnePoint tek enjeksiyon noktasını fuzz'lar.
func (e *Engine) fuzzOnePoint(ctx context.Context, target string, client *probe.Client, p loader.JSPoint, profile fuzz.Profile) ([]*finding.Finding, int64) {
	ft := fuzzTargetForPoint(p)
	pctx := plugin.WithPlugin(ctx, "fuzz-active", isReadOnlyMethod(ft.Method), nil)
	control, err := client.Send(pctx, ft.Method, ft.URL, ft.Headers, ft.Body)
	if err != nil || control == nil {
		return nil, 0
	}
	if control.Status >= 500 {
		return nil, 1
	}
	ctrlCls := baseline.ClassifyStatic(control.Status, control.Headers, control.Body)
	if ctrlCls.Untrusted {
		return nil, 1
	}
	budget := fuzz.DefaultBudget(profile)
	budget.MaxRequests = maxFuzzRequestsPerPoint
	budget.StopOnDiverge = false
	eng := fuzz.NewEngine(client, fuzz.NewBaseline(ft, control), budget, fuzzSeed)
	if err := eng.Run(ctx, ft); err != nil {
		return nil, eng.Count() + 1
	}
	var out []*finding.Finding
	for _, f := range eng.Findings() {
		ff := e.fuzzFinding(ctx, target, p, control, f)
		if ff != nil {
			out = append(out, ff)
		}
	}
	return out, eng.Count() + 1
}

// fuzzFinding tek fuzz anomalisini bulguya çevirir (nil = bulgu yok).
func (e *Engine) fuzzFinding(ctx context.Context, target string, p loader.JSPoint, control *probe.Response, f fuzz.Finding) *finding.Finding {
	snippet := f.BodyExcerpt
	if snippet == "" {
		snippet = f.BodySnippet
	}
	cls := baseline.ClassifyStatic(f.RespStatus, nil, []byte(snippet))
	if cls.Untrusted {
		return nil
	}
	cand := plugin.Candidate{
		PluginID: "fuzz-anomaly",
		Target:   target,
		InjectionPoint: plugin.InjectionPoint{
			URL: p.URL, Method: nonEmpty(p.Method, http.MethodGet),
			ParamName: p.ParamName, ParamLocation: p.ParamLocation,
			Value: truncate(f.Mutation.Payload, 120),
		},
		OracleName:   "error",
		OracleParams: map[string]string{"mutation": f.Mutation.Kind},
	}
	// 1. SQL/hata imzası + kontrolde yokluk → error oracle kanıtı.
	var o oracle.ErrorSignatureOracle
	ev, err := o.Verify(ctx, cls, false, oracle.ErrorSignatureParams{
		Body: snippet, ControlBody: string(control.Body), Mode: "sqli",
	})
	if err == nil && ev != nil && ev.Verdict == oracle.VerdictAccept {
		cand.OracleName = "error"
		ff, ferr := finding.Build(fuzzSpec(), cand, ev, "GASH-004", "CWE-89", "", "")
		if ferr == nil && ff != nil {
			return ff
		}
	}
	// 2. HTTP 500 (imzasız bile) → tentative anomali.
	if f.RespStatus >= 500 {
		ev500 := &oracle.Evidence{
			Verdict:                oracle.VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceTentative,
			Artifacts: map[string]string{
				"status":   fmt.Sprintf("%d", f.RespStatus),
				"mutation": f.Mutation.Kind,
				"snippet":  truncate(snippet, 300),
			},
			Repeats:       1,
			ControlResult: "control-stable",
			Note:          "fuzz mutasyonu HTTP 500 üretti (kontrol stabil) → tentative, elle doğrulama gerekir",
		}
		ff, ferr := finding.Build(fuzzSpec(), cand, ev500, "GASH-000", "CWE-693", "", "")
		if ferr == nil && ff != nil {
			return ff
		}
		return nil
	}
	// 3. Belirgin yanıt sapması (durum/boyut/zaman) → tentative.
	if f.Divergence.Significant {
		evd := &oracle.Evidence{
			Verdict:                oracle.VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceTentative,
			Artifacts: map[string]string{
				"status":     fmt.Sprintf("%d", f.RespStatus),
				"similarity": fmt.Sprintf("%.3f", f.Divergence.SimScore),
				"mutation":   f.Mutation.Kind,
			},
			Repeats:       1,
			ControlResult: "control-stable",
			Note:          "fuzz mutasyonu belirgin yanıt sapması üretti → tentative, elle doğrulama gerekir",
		}
		cand.OracleName = "differential"
		ff, ferr := finding.Build(fuzzSpec(), cand, evd, "GASH-000", "CWE-693", "", "")
		if ferr == nil && ff != nil {
			return ff
		}
	}
	return nil
}

// fuzzTargetForPoint enjeksiyon noktasını nötr değerli fuzz hedefine çevirir.
func fuzzTargetForPoint(p loader.JSPoint) fuzz.Target {
	method := nonEmpty(p.Method, http.MethodGet)
	rawURL := nonEmpty(p.URL, "")
	param := p.ParamName
	if param == "" {
		param = "q"
	}
	switch strings.ToLower(strings.TrimSpace(p.ParamLocation)) {
	case "body":
		form := url.Values{}
		form.Set(param, fuzzNeutral)
		return fuzz.Target{
			Method:  method,
			URL:     rawURL,
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:    []byte(form.Encode()),
		}
	default:
		built := rawURL
		if u, err := url.Parse(rawURL); err == nil && u != nil {
			q := u.Query()
			q.Set(param, fuzzNeutral)
			u.RawQuery = q.Encode()
			built = u.String()
		}
		return fuzz.Target{Method: method, URL: built}
	}
}

func isReadOnlyMethod(m string) bool {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
