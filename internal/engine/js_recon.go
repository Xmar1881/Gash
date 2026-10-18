// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash
//
// File: internal/engine/js_recon.go
// What: Pasif JS recon motor hattı: endpoint besleme + GASH-067 sır bulguları.
// Why: Crawl'ın topladığı same-origin JS gövdeleri (ve sınırlı kaynak
// haritaları) motor-içi analizden geçer; endpoint'ler yüzeye geri beslenir
// (parametreli → doğrudan injection point, parametresiz → 1 sayfalık sınırlı
// takip crawl'ı), sırlar TAM DEĞER RAPORLANMADAN masked GASH-067 bulgusudur.
// Plugin YOK (engine-recon, finding.Build bypass — content-discovery disiplini);
// üçüncü taraf/kapsam-dışı URL'ler yalnızca kayıtta kalır, istek üretmez.

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
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

// runJSRecon crawl'ın topladığı JS gövdelerini pasif analiz eder.
// What: AnalyzeJS → masked sır bulguları (GASH-067) + endpoint beslemesi;
// sourceMappingURL haritaları same-origin/--scope kapılı çekilir (≤5) ve
// sourcesContent sır taramasından geçer. Dönen stats rapor sayaçlarıdır:
// js_files_fetched, js_endpoints_found, js_secrets_found, js_maps_fetched.
// Why: JS yüzeyi GET-only pasif gözlemdir; sır tam değeri asla rapora girmez
// (yalnızca first4…last4 + maskeli bağlam) ve üçüncü taraf host'a istek yoktur.
func (e *Engine) runJSRecon(ctx context.Context, target string, client *probe.Client, crawlRes *discovery.CrawlResult) ([]*finding.Finding, []loader.JSPoint, map[string]int) {
	stats := map[string]int{
		"js_files_fetched": 0, "js_endpoints_found": 0,
		"js_secrets_found": 0, "js_maps_fetched": 0,
	}
	if crawlRes == nil || client == nil {
		return nil, nil, stats
	}
	stats["js_files_fetched"] = crawlRes.JSFilesFetched
	targetParsed, err := url.Parse(strings.TrimSpace(target))
	if err != nil || targetParsed.Host == "" {
		return nil, nil, stats
	}

	sm := NewScopeManager(e.cfg.Scope)
	sm.SetOriginalTarget(targetParsed.String())

	seenSecrets := map[string]bool{}
	seenPoints := map[string]bool{}
	var findings []*finding.Finding
	var points []loader.JSPoint
	followPages := 0
	mapsFetched := 0

	addSecret := func(s discovery.Secret) {
		key := s.RuleName + "|" + s.Masked
		if seenSecrets[key] {
			return
		}
		seenSecrets[key] = true
		findings = append(findings, buildJSSecretFinding(s))
	}
	addPoint := func(p loader.JSPoint) {
		key := strings.ToUpper(p.Method) + "|" + p.URL + "|" + p.ParamLocation + "|" + p.ParamName
		if seenPoints[key] {
			return
		}
		seenPoints[key] = true
		points = append(points, p)
	}

	for _, src := range crawlRes.JSSources {
		if ctx.Err() != nil {
			break
		}
		rep := discovery.AnalyzeJS(src.URL, src.Body)
		stats["js_endpoints_found"] += rep.Stats.Endpoints
		for _, s := range rep.Secrets {
			addSecret(s)
		}

		for _, ep := range rep.Endpoints {
			u, perr := url.Parse(ep.Resolved)
			if perr != nil || u.Host == "" {
				continue
			}
			if !jsReconURLAllowed(targetParsed, u, e.cfg.Scope, sm) {
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
					addPoint(loader.JSPoint{
						URL: clean.String(), Method: method,
						ParamName:     pname,
						ParamLocation: "query",
						Value:         u.Query().Get(pname),
					})
				}
				continue
			}
			if followPages >= jsMaxFollowPages {
				continue
			}
			followPages++
			// 1 sayfa, derinlik 0: endpoint'in kendisi taranır, yeni BFS YOK;
			// JS recon tekrarlanmaz (SkipJSRecon) — çift istek/çift bulgu olmaz.
			follow, ferr := discovery.Crawl(ctx, client, ep.Resolved, discovery.CrawlOptions{
				MaxPages: 1, MaxDepth: 0, Scope: e.cfg.Scope,
				ReadRobots: false, ReadSitemap: false, SkipJSRecon: true,
			})
			if ferr != nil || follow == nil {
				continue
			}
			for _, ip := range follow.SurfacePoints {
				addPoint(loader.JSPoint{
					URL: ip.URL, Method: ip.Method, ParamName: ip.ParamName,
					ParamLocation: ip.ParamLocation, Value: ip.Value,
				})
			}
		}

		for _, mapURL := range rep.SourceMaps {
			if mapsFetched >= jsMaxSourceMapFetch || ctx.Err() != nil {
				break
			}
			mu, merr := url.Parse(mapURL)
			if merr != nil || mu.Host == "" {
				continue
			}
			if !jsReconURLAllowed(targetParsed, mu, e.cfg.Scope, sm) {
				continue
			}
			pctx := plugin.WithPlugin(ctx, PluginIDJSRecon, true, nil)
			resp, rerr := client.Send(pctx, http.MethodGet, mapURL, nil, nil)
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
	stats["js_secrets_found"] = len(findings)
	return findings, points, stats
}

// jsReconURLAllowed JS endpoint/harita besleme kapısıdır.
// What: Hedef origin her zaman; diğer host'lar yalnızca explicit --scope
// içindeyse (ScopeManager: domain/CIDR/URL-prefix + rebinding).
// Why: Open modda üçüncü taraf endpoint takibi YAPILMAZ; kapsam verilmişse
// operatörün allowlist'i genişletir (fail-closed).
func jsReconURLAllowed(target, u *url.URL, scope []string, sm *ScopeManager) bool {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	if strings.EqualFold(target.Scheme, u.Scheme) && strings.EqualFold(target.Host, u.Host) {
		return true
	}
	if len(scope) == 0 {
		return false
	}
	return sm.CheckScope(context.Background(), u) == nil
}

// newJSReconID motor-içi bulgu kimliğidir.
func newJSReconID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "finding_js_fallback"
	}
	return "finding_js_" + hex.EncodeToString(b[:])
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
