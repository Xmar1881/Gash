// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Çok-adımlı iş akışı replay motoru (--flow-seed).
// What: Keşfedilen form akışını taze token'larla yeniden oynatır, tek alanı
// SQLi/XSS payload'ıyla mutasyona uğratır, alt adımlardaki hata/yansıma/
// sapmayı mevcut oracle'larla değerlendirir ve oturumsuz doğrudan erişim
// ekranını (GASH-068) koşar.
// Why: Tek istekli fuzz'lar sihirbaz/CSRF akışlarında sink'e ulaşamaz;
// akış sırası korunmadan gerçek etki ölçülemez. Bulgular R-06 gereği
// tentative tavanda kalır (fixture'sız sentetik motor spec'i).

package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/flow"
	"github.com/Xmar1881/Gash/internal/fuzz"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/probe"
)

const (
	// flowMaxRequests akış başına toplam istek tavanıdır (keşif + replay +
	// bypass; politika bütçesi ikinci kilittir).
	flowMaxRequests = 120
	// flowDefaultProbes adım başına SQLi probu varsayılanıdır.
	flowDefaultProbes = 6
	// flowMaxProbes adım başına SQLi probu kesin tavanıdır.
	flowMaxProbes = 10
	// flowXSSPerStep adım başına yansıma kanaryası sayısıdır.
	flowXSSPerStep = 3
)

// flowSpec akış bulgularının sentetik motor kimliğidir.
// Tests boş olduğu için finding.Build güveni tentative'e kapatır (R-06).
func flowSpec() plugin.PluginSpec {
	return plugin.PluginSpec{
		ID:          "flow-replay",
		Name:        "Multi-step workflow replay (active)",
		Description: "Replayed a discovered multi-step form workflow with one mutated field and observed a downstream error, reflection, or material response divergence (tentative, manual review required).",
		Severity:    plugin.SeverityHigh,
		Tags:        []string{"flow", "workflow", "replay", "active"},
		Safe:        false,
		Active:      true,
		Phase:       plugin.PhaseProbe,
		APIVersion:  "1.0",
	}
}

// runFlowFuzz --flow-seed verildiyse çok-adımlı akış replay'ini koşar.
// What: Keşif → adım/alan başına SQLi + XSS replay → değerlendirme →
// oturumsuz doğrudan erişim ekranı. Toplam istek tavanı 120'dir.
// Why: Akış sapması ağ hatası değildir; keşif başarısızlığı tek ve dürüst
// bir skip kaydı üretir, tarama durmaz.
func (e *Engine) runFlowFuzz(ctx context.Context, target string, client *probe.Client) ([]*finding.Finding, []plugin.SkippedPlugin, map[string]int) {
	stats := map[string]int{
		"flow_seed":           0,
		"flow_steps":          0,
		"flow_replays":        0,
		"flow_findings":       0,
		"flow_bypass_checked": 0,
		"flow_requests":       0,
	}
	var skipped []plugin.SkippedPlugin
	seed := strings.TrimSpace(e.cfg.FlowSeed)
	if seed == "" {
		return nil, nil, stats
	}
	// Savunma katmanı: --active olmadan akış replay'i asla koşmaz.
	if !e.cfg.Active {
		return nil, nil, stats
	}
	stats["flow_seed"] = 1
	if client == nil {
		skipped = append(skipped, plugin.SkippedPlugin{PluginID: "flow", Reason: "skipped (flow: probe client unavailable)"})
		return nil, skipped, stats
	}
	seedURL, err := url.Parse(seed)
	if err != nil || seedURL.Host == "" || (seedURL.Scheme != "http" && seedURL.Scheme != "https") {
		skipped = append(skipped, plugin.SkippedPlugin{PluginID: "flow", Reason: "skipped (flow: invalid seed URL)"})
		return nil, skipped, stats
	}
	// Kapsam ön kontrolü fail-closed: kapsam-dışı seed'e tek istek gitmez.
	if len(e.cfg.Scope) > 0 {
		sm := NewScopeManager(e.cfg.Scope)
		sm.SetOriginalTarget(target)
		if serr := sm.CheckScope(ctx, seedURL); serr != nil {
			skipped = append(skipped, plugin.SkippedPlugin{PluginID: "flow", Reason: "skipped (flow-seed outside scope, no request sent)"})
			return nil, skipped, stats
		}
	}

	requestTimeout := e.cfg.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = 15 * time.Second
	}
	maxReq := flowMaxRequests
	sendWith := func(c *probe.Client) flow.Sender {
		return func(sctx context.Context, method, rawURL string, headers map[string]string, payload []byte) (int, http.Header, string, error) {
			sctx = plugin.WithPlugin(sctx, "flow-replay", false, &maxReq)
			// Redirect'ler akış tarafından manuel izlenir; Set-Cookie her hop'ta
			// görülür, downgrade kararı flow'dadır. Politika her hop'ta uygulanır.
			sctx = plugin.WithNoRedirect(sctx)
			// Akış oturum cookie'leri taşır: WAF-bypass varyantıyla tekrarlanmaz.
			sctx = probe.WithNoWAFBypass(sctx)
			sctx, cancel := context.WithTimeout(sctx, requestTimeout)
			defer cancel()
			resp, serr := c.Send(sctx, method, rawURL, headers, payload)
			if serr != nil {
				return 0, nil, "", serr
			}
			return resp.Status, resp.Headers, string(resp.Body), nil
		}
	}
	send := sendWith(client)

	seedCookies := map[string]string(nil)
	if e.cfg.Auth != nil && len(e.cfg.Auth.Cookies) > 0 {
		seedCookies = e.cfg.Auth.Cookies
	}
	maxSteps := e.cfg.FlowMaxSteps
	if maxSteps <= 0 {
		maxSteps = flow.DefaultMaxSteps
	}
	f, derr := flow.DiscoverFlow(ctx, send, flow.Options{
		SeedURL: seed, MaxSteps: maxSteps, MaxRequests: flowMaxRequests,
		SeedCookies: seedCookies,
	})
	if derr != nil || f == nil || len(f.Steps) == 0 {
		reason := "no eligible form"
		if derr != nil {
			reason = derr.Error()
		} else if f != nil && f.Stopped != "" {
			reason = f.Stopped
		}
		skipped = append(skipped, plugin.SkippedPlugin{
			PluginID: "flow",
			Reason:   "skipped (flow-discovery: " + truncate(reason, 200) + ")",
		})
		return nil, skipped, stats
	}
	stats["flow_steps"] = len(f.Steps)
	stats["flow_requests"] = f.Budget.Used

	probes := fuzz.SQLiProbes()
	limit := e.cfg.FlowProbes
	if limit <= 0 {
		limit = flowDefaultProbes
	}
	if limit > flowMaxProbes {
		limit = flowMaxProbes
	}
	if limit > len(probes) {
		limit = len(probes)
	}
	sqli := flow.SQLiPayloads(probes, limit)

	var out []*finding.Finding
	used := f.Budget.Used
	seen := make(map[string]bool)
	addFinding := func(res flow.Result, step flow.Step) {
		key := fmt.Sprintf("%s|%d|%s", res.RuleID, res.Step, res.Field)
		if seen[key] {
			return
		}
		ff := e.flowFinding(res, target, step)
		if ff == nil {
			return
		}
		seen[key] = true
		out = append(out, ff)
	}

	for _, step := range f.Steps {
		if ctx.Err() != nil || used >= flowMaxRequests {
			break
		}
		idx := -1
		fieldName := ""
		for _, i := range flow.InjectableFields(discovery.Form{Fields: step.Fields}) {
			idx = i
			fieldName = step.Fields[i].Name
			break
		}
		if idx < 0 || fieldName == "" {
			continue // v1: adım başına ilk uygun alan
		}
		hit := false
		var differential *flow.Result
		for _, p := range sqli {
			remaining := flowMaxRequests - used
			if remaining < len(f.Steps)+2 {
				break
			}
			replay, rerr := flow.ReplayFlow(ctx, send, f, flow.ReplayOptions{
				StepIndex: step.Index, Field: fieldName, Payload: p,
				SeedCookies: seedCookies, MaxRequests: remaining,
			})
			stats["flow_replays"]++
			if rerr != nil || replay == nil {
				continue
			}
			used += replay.Requests
			stats["flow_requests"] += replay.Requests
			for _, res := range flow.Evaluate(ctx, f, replay) {
				switch res.Kind {
				case flow.ResultSQLiError, flow.ResultXSSReflection:
					addFinding(res, step)
					hit = true
				case flow.ResultDifferential:
					if differential == nil {
						r := res
						differential = &r
					}
				}
			}
			if hit {
				break
			}
		}
		// SQLi kanıtı yoksa üç XSS kanaryası (bütçe elverdiğince).
		if !hit {
			for i := 0; i < flowXSSPerStep; i++ {
				remaining := flowMaxRequests - used
				if remaining < len(f.Steps)+2 {
					break
				}
				marker, merr := probe.Canary()
				if merr != nil {
					break
				}
				payload := flow.XSSPayloads(marker)[i]
				replay, rerr := flow.ReplayFlow(ctx, send, f, flow.ReplayOptions{
					StepIndex: step.Index, Field: fieldName, Payload: payload,
					SeedCookies: seedCookies, MaxRequests: remaining,
				})
				stats["flow_replays"]++
				if rerr != nil || replay == nil {
					continue
				}
				used += replay.Requests
				stats["flow_requests"] += replay.Requests
				for _, res := range flow.Evaluate(ctx, f, replay) {
					if res.Kind == flow.ResultXSSReflection {
						addFinding(res, step)
						hit = true
					}
				}
				if hit {
					break
				}
			}
		}
		if !hit && differential != nil {
			addFinding(*differential, step)
		}
	}

	// Oturumsuz doğrudan erişim ekranı (yalnızca ≥2 adım).
	if len(f.Steps) >= 2 && used < flowMaxRequests {
		bypassClient := e.newFlowBypassClient(client)
		if bypassClient != nil {
			stats["flow_bypass_checked"] = 1
			bypassSend := sendWith(bypassClient)
			bypass, bypassUsed, berr := flow.ProbeFlowBypass(ctx, bypassSend, f, flow.Options{
				SeedURL: seed, MaxRequests: flowMaxRequests - used,
			})
			if bypassUsed > 0 {
				used += bypassUsed
				stats["flow_requests"] += bypassUsed
			}
			if berr == nil && bypass != nil {
				addFinding(*bypass, f.Steps[len(f.Steps)-1])
			}
		}
	}
	stats["flow_findings"] = len(out)
	return out, skipped, stats
}

// newFlowBypassClient oturumsuz doğrudan erişim için kimlik başlığı taşımayan
// ikinci bir probe istemcisi kurar.
// What: Aynı PolicySession + transport paylaşılır; ExtraHeaders (Auth cookie/
// Authorization) bilinçli olarak boştur.
// Why: Ana istemci cfg.Auth başlıklarını gömer; bu başlıklarla "oturumsuz"
// erişim ekranı anlamsızlaşır ve GASH-068 yanlış negatif verir.
func (e *Engine) newFlowBypassClient(base *probe.Client) *probe.Client {
	if base == nil || base.Policy() == nil {
		return nil
	}
	timeout := e.cfg.RequestTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	maxBytes := e.cfg.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = 5 * 1024 * 1024
	}
	return probe.NewClient(probe.Options{
		Policy:         base.Policy(),
		Transport:      base.Transport(),
		RequestTimeout: timeout,
		MaxBytes:       maxBytes,
		ProxyURL:       base.ProxyURL(),
	})
}

// flowFinding akış sonucunu mevcut finding.Build hattından geçirir.
// What: Sentetik spec + oracle kanıtı + GASH kural eşlemesi.
// Why: B3 tek-kurucu kuralı korunur; R-06 sentetik spec'i tentative'te tutar.
func (e *Engine) flowFinding(res flow.Result, target string, step flow.Step) *finding.Finding {
	if res.Evidence == nil {
		return nil
	}
	loc := "body"
	if strings.EqualFold(step.Method, http.MethodGet) {
		loc = "query"
	}
	if res.RuleID == "GASH-068" {
		loc = "path"
	}
	cand := plugin.Candidate{
		PluginID: "flow-replay",
		Target:   target,
		InjectionPoint: plugin.InjectionPoint{
			URL:           step.ActionURL,
			Method:        step.Method,
			ParamName:     res.Field,
			ParamLocation: loc,
			Value:         truncate(res.Payload, 120),
		},
		OracleName:   oracleNameForFlow(res.RuleID),
		OracleParams: map[string]string{"replay": "multi-step", "step": fmt.Sprintf("%d", res.Step)},
	}
	title, desc := flowTitles(res.RuleID)
	ff, err := finding.Build(flowSpec(), cand, res.Evidence, res.RuleID, res.CWE, title, desc)
	if err != nil {
		return nil
	}
	return ff
}

func oracleNameForFlow(ruleID string) string {
	switch ruleID {
	case "GASH-001":
		return "reflection"
	case "GASH-004", "GASH-005":
		return "differential"
	case "GASH-068":
		return "differential"
	default:
		return "error"
	}
}

func flowTitles(ruleID string) (string, string) {
	switch ruleID {
	case "GASH-001":
		return "Reflected XSS in a multi-step workflow (tentative)",
			"A field injected at one workflow step was reflected in an executable context on a later step; manual verification is required."
	case "GASH-004":
		return "SQL injection in a multi-step workflow (tentative)",
			"A mutated workflow field produced a database error signature downstream that is absent from the clean baseline; manual verification is required."
	case "GASH-005":
		return "Differential response in a multi-step workflow (tentative)",
			"A mutated workflow field materially changed the downstream response (N=1, no repeated true/false ladder); manual verification is required."
	case "GASH-068":
		return "Multi-step workflow bypass by direct access (tentative)",
			"The final workflow page was reachable without a session and matched the authenticated baseline; the heuristic requires manual verification."
	default:
		return "", ""
	}
}
