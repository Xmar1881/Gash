// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/recon/jsrecon.go
// What: Passive JavaScript recon detector: endpoint harvesting (GASH-067
// compatible surface contribution) plus hardcoded-secret findings.
// Why: The crawler already paid for the same-origin JS bodies (and a bounded
// number of source maps); analyzing them is engine-recon, and it was the last
// engine-owned finding producer still written as engine control flow. The port
// keeps the engine as carrier: it brokered the URL-level scope decision and the
// bounded follow-up crawl, and the detector owns the analysis, dedup, telemetry
// keys, and the masked evidence discipline.

package recon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/detector"
	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
)

const (
	// RuleIDJSSecret gömülü sır bulgusudur (çakışma yok: 001..066 kullanımda).
	RuleIDJSSecret = "GASH-067"
	// CWEJSSecret hardcoded credential ailesidir.
	CWEJSSecret = "CWE-798"
	// PluginIDJSRecon PolicySession kimliğidir (safe=true, yalnızca GET).
	PluginIDJSRecon = "engine-js-recon"
	// OracleJSSecret engine-recon sır oracle adıdır (yeni oracle struct YOK;
	// kanıt deterministik literal gözlemidir, content-discovery disiplini).
	OracleJSSecret = "secret-exposure"
	// DetectorVersionJSRecon izlenebilirlik sürümüdür.
	DetectorVersionJSRecon = "1.0"
)

const (
	// jsMaxFollowPages parametresiz endpoint'ler için toplam takip crawl tavanı.
	jsMaxFollowPages = 25
	// jsMaxSourceMapFetch tarama başına çekilecek kaynak haritası tavanı.
	jsMaxSourceMapFetch = 5
)

// jsReconBudget caps the follow-up crawl and source-map fetches so a slow or
// blocked proxy pool cannot spend the whole scan deadline in JS recon.
// Variable (not const) so tests can shorten it.
var jsReconBudget = 90 * time.Second

// JSRecon analyzes the crawler's JavaScript inventory.
// What: GASH-067 detector: masked secret findings plus harvested surface.
// Why: One detector owns both outputs because they come from the single pass
// over the same bytes; splitting them would duplicate the analysis.
type JSRecon struct{}

// Spec describes the passive JS recon detector.
// What: Identity, taxonomy, phase, and its request ceiling.
// Why: The ceiling counts the two bounded fetches (source maps) and the bounded
// follow-up crawls, so the declared budget matches what the detector may spend.
func (JSRecon) Spec() detector.Spec {
	return detector.Spec{
		ID:              PluginIDJSRecon,
		Name:            "Passive JavaScript recon",
		Description:     "Analyzes already-fetched same-origin JavaScript bodies and a bounded set of source maps for hardcoded secrets, and harvests query, fragment and parameterless endpoints into the scan surface; third-party URLs are recorded only, never requested.",
		RuleID:          RuleIDJSSecret,
		CWE:             CWEJSSecret,
		Oracle:          OracleJSSecret,
		Severity:        plugin.SeverityHigh,
		Phase:           plugin.PhaseDiscovery,
		Order:           5,
		MaxRequests:     jsMaxFollowPages + jsMaxSourceMapFetch,
		Docs:            "docs/detector-inventory.md",
		DetectorVersion: DetectorVersionJSRecon,
	}
}

// Run analyzes the JS inventory and returns findings, surface, and counters.
// What: Deterministic dedup for both outputs plus a bounded fetch budget.
// Why: Duplicate secrets or points would inflate the report and re-probe the
// same endpoint; the bounds keep a large bundle from turning recon into load.
func (JSRecon) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	stats := map[string]int{
		"js_files_fetched": 0, "js_endpoints_found": 0,
		"js_hash_routes_found": 0,
		"js_secrets_found":     0, "js_maps_fetched": 0,
	}
	res := detector.Result{Stats: stats}
	if env == nil || env.Probe == nil {
		return res, nil
	}
	reconCtx, cancel := context.WithTimeout(ctx, jsReconBudget)
	defer cancel()
	stats["js_files_fetched"] = env.Crawl.JSFilesFetched
	targetParsed, err := url.Parse(strings.TrimSpace(env.Target))
	if err != nil || targetParsed.Host == "" {
		return res, nil
	}

	seenSecrets := map[string]bool{}
	seenPoints := map[string]bool{}
	followPages := 0
	mapsFetched := 0

	addSecret := func(s discovery.Secret) {
		key := s.RuleName + "|" + s.Masked
		if seenSecrets[key] {
			return
		}
		seenSecrets[key] = true
		res.Findings = append(res.Findings, buildJSSecretFinding(s))
	}
	addPoint := func(p detector.Surface) {
		key := strings.ToUpper(p.Method) + "|" + p.URL + "|" + p.ParamLocation + "|" + p.ParamName
		if seenPoints[key] {
			return
		}
		seenPoints[key] = true
		res.Surface = append(res.Surface, p)
	}
	allowed := func(rawURL string) bool {
		if env.URLAllowed == nil {
			return false
		}
		return env.URLAllowed(rawURL)
	}

	for _, src := range env.Crawl.JSSources {
		if reconCtx.Err() != nil {
			break
		}
		rep := discovery.AnalyzeJS(src.URL, src.Body)
		stats["js_endpoints_found"] += rep.Stats.Endpoints
		for _, s := range rep.Secrets {
			addSecret(s)
		}

		origin := targetParsed.Scheme + "://" + targetParsed.Host
		for _, hr := range rep.HashRoutes {
			routeURL := origin + "/#" + hr.Path
			if !allowed(routeURL) {
				continue
			}
			stats["js_hash_routes_found"]++
			for _, name := range hr.Params {
				addPoint(detector.Surface{
					URL: routeURL, Method: http.MethodGet,
					ParamName: name, ParamLocation: "fragment",
				})
			}
		}

		for _, ep := range rep.Endpoints {
			u, perr := url.Parse(ep.Resolved)
			if perr != nil || u.Host == "" {
				continue
			}
			if !allowed(ep.Resolved) {
				continue // üçüncü taraf/kapsam-dışı: yalnızca kayıt, istek YOK
			}
			method := strings.ToUpper(strings.TrimSpace(ep.Method))
			if method == "" {
				method = http.MethodGet
			}
			if len(ep.Params) > 0 {
				clean := *u
				clean.RawQuery = ""
				for _, pname := range ep.Params {
					addPoint(detector.Surface{
						URL: clean.String(), Method: method,
						ParamName:     pname,
						ParamLocation: "query",
						Value:         u.Query().Get(pname),
					})
				}
				continue
			}
			if followPages >= jsMaxFollowPages || env.FollowCrawl == nil {
				continue
			}
			followPages++
			// 1 sayfa, derinlik 0: endpoint'in kendisi taranır, yeni BFS YOK;
			// JS recon tekrarlanmaz — çift istek/çift bulgu olmaz. Sınır ve
			// kapsam kararı motorun (FollowCrawl) sorumluluğundadır.
			points, ferr := env.FollowCrawl(reconCtx, ep.Resolved)
			if ferr != nil || len(points) == 0 {
				continue
			}
			for _, p := range points {
				addPoint(p)
			}
		}

		for _, mapURL := range rep.SourceMaps {
			if mapsFetched >= jsMaxSourceMapFetch || reconCtx.Err() != nil {
				break
			}
			if !allowed(mapURL) {
				continue
			}
			pctx := plugin.WithPlugin(reconCtx, PluginIDJSRecon, true, nil)
			resp, rerr := env.Probe.Send(pctx, http.MethodGet, mapURL, nil, nil)
			if rerr != nil {
				if errors.Is(rerr, plugin.ErrBudgetExceeded) {
					break
				}
				continue
			}
			if resp == nil {
				continue
			}
			mapsFetched++
			stats["js_maps_fetched"]++
			for _, s := range discovery.AnalyzeSecrets(resp.Body, mapURL) {
				addSecret(s)
			}
		}
	}
	if errors.Is(reconCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		stats["js_recon_budget_exhausted"] = 1
	}
	stats["js_secrets_found"] = len(res.Findings)
	return res, nil
}

// buildJSSecretFinding GASH-067 bulgusunu kurar (motor-içi; fixture-spec yok).
// What: static-execution-evidence tavanlı, masked_value dışında sır taşımayan
// kanıt sözlüğü (secret_type/location/var_name/context/note).
// Why: Sır literal gözlemi doğrulanmış bir credential DEĞİLDİR; kanıt yalnızca
// deterministik regex eşleşmesi + maskeli bağlamdır, tam değer asla yazılmaz.
func buildJSSecretFinding(s discovery.Secret) *finding.Finding {
	evidence := map[string]string{
		"secret_type":  s.Type,
		"masked_value": s.Masked,
		"location":     s.Location,
		"note":         "full value intentionally not reported (masked first4…last4); remove the literal and rotate the credential",
	}
	if s.VarName != "" {
		evidence["var_name"] = s.VarName
	}
	if s.Context != "" {
		evidence["context"] = s.Context
	}
	f := &finding.Finding{
		ID:          newJSReconID(),
		RuleID:      RuleIDJSSecret,
		CWE:         CWEJSSecret,
		Title:       "Hardcoded secret in JavaScript: " + s.Type,
		Description: fmt.Sprintf("pasif JS recon: %s kuralı %s içinde eşleşti (değer maskeli; tam değer raporlanmaz)", s.RuleName, s.Location),
		Severity:    s.Severity,
		Confidence:  plugin.ConfidenceStaticExecution,
		Target:      s.Location,
		InjectionPoint: plugin.InjectionPoint{
			URL:           s.Location,
			Method:        http.MethodGet,
			ParamLocation: "path",
		},
		Evidence: evidence,
		Reproducibility: map[string]string{
			"repeats": "1",
			"control": "not-applicable (static asset observation)",
			"note":    "secret literal observed in a fetched same-origin asset; no request replay or credential validation",
		},
		PluginID:           PluginIDJSRecon,
		OracleName:         OracleJSSecret,
		Tags:               []string{"recon", "secrets", "hardcoded-secret", "javascript"},
		Method:             http.MethodGet,
		VerificationMethod: "static-content scan (rule " + s.RuleName + "), repeats=1, no live credential check",
		Note:               "static-execution-evidence ceiling: literal observed, not a validated live credential",
		DetectorVersion:    DetectorVersionJSRecon,
		Masked:             []string{"masked_value", "context"},
	}
	f.Fingerprint = finding.Fingerprint(f)
	return f
}

// newJSReconID motor-içi bulgu kimliğidir.
func newJSReconID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "finding_js_fallback"
	}
	return "finding_js_" + hex.EncodeToString(b[:])
}
