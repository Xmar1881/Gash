// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// openAPISpecTimeout uzak spec çekme zaman aşımıdır (gash openapi --timeout varsayılanı).
const openAPISpecTimeout = 15 * time.Second

// pathParamRegex OpenAPI path şablonlarını ({id}) nötr değere çevirir.
// What: /users/{id} → /users/1 (taranabilir somut URL).
// Why: Ham {id} literali probeda 404 üretir; örnek değer yüzeyi taranır kılar.
var pathParamRegex = regexp.MustCompile(`\{[^}/]+\}`)

// isOpenAPISpecURL spec referansının dosya mı URL mi olduğunu ayırır.
// What: http(s) öneki URL, diğer her şey dosya yoludur.
// Why: Tek karar noktası CLI + engine kapılarını aynı çizgide tutar.
func isOpenAPISpecURL(ref string) bool {
	lower := strings.ToLower(strings.TrimSpace(ref))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// isLoopbackSpecHost loopback/spec-izinli host kararıdır.
// What: localhost + loopback IP (v4/v6) true.
// Why: Kapsam-dışı fetch yasağında loopback istisnası tek fonksiyondan denetlenir.
func isLoopbackSpecHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// specURLInScope uzak spec URL'inin çekilebilirliğini denetler (fetch ÖNCESİ).
// What: Loopback her zaman izinli; diğer host'lar yalnızca --scope içinde.
// Why: Dış URL'ye kapsam-dışı fetch YOK — karar ağa çıkmadan verilir.
func (e *Engine) specURLInScope(ctx context.Context, rawSpecURL, target string) error {
	u, err := url.Parse(strings.TrimSpace(rawSpecURL))
	if err != nil {
		return fmt.Errorf("scan: --openapi-spec geçersiz URL %q: %w", rawSpecURL, err)
	}
	if isLoopbackSpecHost(u.Hostname()) {
		return nil
	}
	if len(e.cfg.Scope) == 0 {
		return fmt.Errorf("scan: --openapi-spec URL kapsam-dışı (loopback veya --scope içi olmalı, fetch yapılmadı)")
	}
	sm := NewScopeManager(e.cfg.Scope)
	sm.SetOriginalTarget(target)
	if err := sm.CheckScope(ctx, u); err != nil {
		return fmt.Errorf("scan: --openapi-spec URL kapsam-dışı (fetch yapılmadı): %w", err)
	}
	return nil
}

// resolveOpenAPIPlan spec referansını plana çevirir (dosya veya kapsam-içi URL).
// What: Dosya → LoadSpecFile; URL → kapsam/loopback kapısı + FetchSpec
// (tek GET, redirect yok, 2MB sınır — FetchSpec disiplini).
// Why: Yükleme tek noktadadır; kapsam-dışı URL asla ağa çıkmaz (fail-closed).
func (e *Engine) resolveOpenAPIPlan(ctx context.Context, target string) (*discovery.Plan, error) {
	ref := strings.TrimSpace(e.cfg.OpenAPISpec)
	if ref == "" {
		return nil, nil
	}
	if isOpenAPISpecURL(ref) {
		if err := e.specURLInScope(ctx, ref, target); err != nil {
			return nil, err
		}
		plan, err := discovery.FetchSpec(ctx, ref, openAPISpecTimeout)
		if err != nil {
			return nil, fmt.Errorf("scan: --openapi-spec %q: %w", ref, err)
		}
		return plan, nil
	}
	plan, err := discovery.LoadSpecFile(ref)
	if err != nil {
		return nil, fmt.Errorf("scan: --openapi-spec %q: %w", ref, err)
	}
	return plan, nil
}

// openAPISurfacePoints plan endpoint'lerini hedef-bazlı JSPoint'lere çevirir.
// What: Her endpoint hedef scheme+host[:port] + path olarak çözülür; hedef
// host ile eşleşmeyen mutlak URL'ler ve kapsam-dışı URL'ler atlanır.
// Why: Spec'teki yabancı servers[] girdileri asla probelanmaz; scope
// kararı ekleme anında verilir (probe katmanı ikinci kilittir).
func openAPISurfacePoints(plan *discovery.Plan, target string, scope []string) []loader.JSPoint {
	if plan == nil {
		return nil
	}
	targetURL, err := url.Parse(strings.TrimSpace(target))
	if err != nil || strings.TrimSpace(targetURL.Host) == "" {
		return nil
	}
	targetHost := strings.ToLower(targetURL.Hostname())
	base := strings.ToLower(targetURL.Scheme) + "://" + targetURL.Host
	sm := NewScopeManager(scope)
	sm.SetOriginalTarget(target)

	var out []loader.JSPoint
	seen := make(map[string]bool)
	addPoint := func(p loader.JSPoint) {
		method := strings.ToUpper(strings.TrimSpace(p.Method))
		if method == "" {
			method = http.MethodGet
		}
		p.Method = method
		if strings.TrimSpace(p.ParamLocation) == "" {
			p.ParamLocation = "query"
		}
		key := p.Method + "|" + p.URL + "|" + strings.ToLower(p.ParamLocation) + "|" + p.ParamName
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, p)
	}

	for _, ep := range plan.Endpoints {
		rawPath := strings.TrimSpace(ep.Path)
		if rawPath == "" {
			continue
		}
		// Mutlak URL formundaki path: host hedefle eşleşmiyorsa kapsam-dışı → atla.
		if isOpenAPISpecURL(rawPath) {
			pu, perr := url.Parse(rawPath)
			if perr != nil || !strings.EqualFold(strings.TrimSpace(pu.Hostname()), targetHost) {
				continue
			}
			rawPath = pu.EscapedPath()
			if rawPath == "" {
				rawPath = "/"
			}
		}
		if !strings.HasPrefix(rawPath, "/") {
			rawPath = "/" + rawPath
		}
		concrete := pathParamRegex.ReplaceAllString(rawPath, "1")
		fullURL := base + concrete
		parsed, perr := url.Parse(fullURL)
		if perr != nil || !strings.EqualFold(strings.TrimSpace(parsed.Hostname()), targetHost) {
			continue
		}
		if err := sm.CheckScope(context.Background(), parsed); err != nil {
			continue // kapsam-dışı path → sessiz değil, bilinçli atlama (scope disiplini)
		}
		method := strings.ToUpper(strings.TrimSpace(ep.Method))
		if method == "" {
			method = http.MethodGet
		}
		if len(ep.Params) == 0 {
			addPoint(loader.JSPoint{URL: fullURL, Method: method})
			continue
		}
		dedup := make(map[string]bool)
		for _, pr := range ep.Params {
			loc := strings.ToLower(strings.TrimSpace(pr.In))
			if loc == "" {
				loc = "query"
			}
			key := loc + "\x00" + pr.Name
			if dedup[key] {
				continue
			}
			dedup[key] = true
			addPoint(loader.JSPoint{
				URL: fullURL, Method: method,
				ParamName: pr.Name, ParamLocation: loc,
			})
		}
	}
	return out
}

// loadOpenAPISurface yapılandırılmış spec'i surfacePoints'e çevirir.
// What: Boş spec → nil (sessiz); dolu spec → plan + hedef-bazlı noktalar.
// Why: runLive tek çağrıyla hem yükler hem filtreler; hata fail-closed'tur.
func (e *Engine) loadOpenAPISurface(ctx context.Context, target string) ([]loader.JSPoint, error) {
	if strings.TrimSpace(e.cfg.OpenAPISpec) == "" {
		return nil, nil
	}
	plan, err := e.resolveOpenAPIPlan(ctx, target)
	if err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, nil
	}
	return openAPISurfacePoints(plan, target, e.cfg.Scope), nil
}
