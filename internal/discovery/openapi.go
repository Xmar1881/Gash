// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package discovery API tanımlarından test planı üretir (P2.2).
// What: OpenAPI 3.x / Swagger 2.0 belgesinden endpoint + parametre çıkarma.
// Why: API yüzeyini kör tarama yerine bildirimli plana döker; plan üretimi
// çevrimdışıdır (ağ yok), spec çekme tek açık GET'tir, tarama yapmaz.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Param bir operasyon parametresidir.
type Param struct {
	Name     string `json:"name" yaml:"name"`
	In       string `json:"in" yaml:"in"` // query/header/path/cookie/body
	Required bool   `json:"required" yaml:"required"`
}

// Endpoint tek operasyonun (method + path) plan satırıdır.
type Endpoint struct {
	Method    string  `json:"method" yaml:"method"`
	Path      string  `json:"path" yaml:"path"`
	Params    []Param `json:"params" yaml:"params"`
	Operation string  `json:"operation_id,omitempty" yaml:"operation_id,omitempty"`
}

// Plan spec'ten üretilen tarama planıdır (istek göndermez).
type Plan struct {
	Title     string     `json:"title" yaml:"title"`
	Version   string     `json:"version" yaml:"version"`
	Servers   []string   `json:"servers" yaml:"servers"`
	Endpoints []Endpoint `json:"endpoints" yaml:"endpoints"`
}

// ParseSpec OpenAPI 3.x / Swagger 2.0 belgesini ayrıştırır (JSON veya YAML).
// What: Saf ayrıştırma; ağ yok, dosya yok, yan etki yok.
// Why: Aynı fonksiyon CLI + test + ileri motor kullanımı için tek doğruluk kaynağı.
func ParseSpec(data []byte) (*Plan, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("discovery: boş spec")
	}
	if int64(len(data)) > 10*1024*1024 {
		return nil, fmt.Errorf("discovery: spec 10MB sınırını aşıyor (%d bayt)", len(data))
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("discovery: spec ayrıştırma: %w", err)
	}
	if doc == nil {
		return nil, fmt.Errorf("discovery: spec ayrıştırma: boş belge")
	}
	plan := &Plan{}
	if info, _ := doc["info"].(map[string]any); info != nil {
		plan.Title, _ = info["title"].(string)
		plan.Version, _ = info["version"].(string)
	}
	// Sunucular: OpenAPI3 `servers[].url`, Swagger2 `host`+`basePath`+`schemes`.
	plan.Servers = extractServers(doc)
	paths, _ := doc["paths"].(map[string]any)
	if len(paths) == 0 {
		return nil, fmt.Errorf("discovery: spec paths içermiyor")
	}
	methods := []string{"get", "post", "put", "delete", "patch", "head", "options", "trace"}
	// Deterministik: path + method sıralı.
	allPaths := make([]string, 0, len(paths))
	for p := range paths {
		allPaths = append(allPaths, p)
	}
	sort.Strings(allPaths)
	for _, p := range allPaths {
		item, _ := paths[p].(map[string]any)
		if item == nil {
			continue
		}
		// Path-ortak parametreler ($ref çözülmez — yalnızca düz adlar alınır).
		shared := extractParams(item["parameters"])
		for _, m := range methods {
			op, _ := item[m].(map[string]any)
			if op == nil {
				continue
			}
			ep := Endpoint{Method: strings.ToUpper(m), Path: p}
			if id, _ := op["operationId"].(string); id != "" {
				ep.Operation = id
			}
			seen := make(map[string]bool)
			for _, pr := range append(shared, extractParams(op["parameters"])...) {
				key := pr.In + "\x00" + pr.Name
				if seen[key] {
					continue
				}
				seen[key] = true
				ep.Params = append(ep.Params, pr)
			}
			// OpenAPI3 requestBody varsa gövde sinyali ekle (ad yoksa genel).
			if _, hasBody := op["requestBody"]; hasBody {
				ep.Params = append(ep.Params, Param{Name: "(body)", In: "body"})
			}
			plan.Endpoints = append(plan.Endpoints, ep)
		}
	}
	if len(plan.Endpoints) == 0 {
		return nil, fmt.Errorf("discovery: spec operasyon içermiyor")
	}
	return plan, nil
}

// LoadSpecFile yerel spec dosyasını okur + ayrıştırır.
func LoadSpecFile(path string) (*Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("discovery: spec dosyası %q: %w", path, err)
	}
	return ParseSpec(data)
}

// FetchSpec uzak spec URL'inden tek GET ile belgeyi çeker (tarama değildir).
// What: Boyut-sınırlı (2MB) tek istek; redirect izlenmez (fail-closed).
// Why: Spec URL'i kullanıcı-beyanlıdır; çekme sonrası plan çevrimdışı üretilir.
func FetchSpec(ctx context.Context, rawURL string, timeout time.Duration) (*Plan, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil, fmt.Errorf("discovery: boş spec URL")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("discovery: geçersiz spec URL %q: %w", rawURL, err)
	}
	if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("discovery: spec URL http(s) olmalı (got %q)", u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("discovery: spec URL userinfo içeremez")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("discovery: redirect izlenmez (fail-closed)")
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("discovery: spec isteği: %w", err)
	}
	req.Header.Set("Accept", "application/json, application/yaml, */*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: spec çekme: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: spec HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("discovery: spec okuma: %w", err)
	}
	return ParseSpec(data)
}

// Targets plan endpoint'lerini verilen baz sunucuya çözer (kapsam-dışı üretmez).
// What: base boşsa plan.Servers[0] kullanılır; hepsi aynı host'ta kalır.
// Why: Plan, tarama hedefi değil aday listesidir; kapsam kararı motordadır.
func (p *Plan) Targets(base string) []string {
	if p == nil {
		return nil
	}
	srv := strings.TrimSpace(base)
	if srv == "" && len(p.Servers) > 0 {
		srv = p.Servers[0]
	}
	srv = strings.TrimSuffix(srv, "/")
	var out []string
	for _, ep := range p.Endpoints {
		if srv == "" {
			out = append(out, ep.Method+" "+ep.Path)
			continue
		}
		out = append(out, ep.Method+" "+srv+ep.Path)
	}
	return out
}

// MarshalJSON planı JSON'a döker (CLI --format json).
func (p *Plan) MarshalJSON() ([]byte, error) {
	type alias Plan
	data, err := json.Marshal((*alias)(p))
	if err != nil {
		return nil, fmt.Errorf("discovery: plan encode: %w", err)
	}
	return data, nil
}

// extractServers sunucu listesini çıkarır (3.x + 2.0).
func extractServers(doc map[string]any) []string {
	var out []string
	if servers, _ := doc["servers"].([]any); len(servers) > 0 {
		for _, s := range servers {
			m, _ := s.(map[string]any)
			if m == nil {
				continue
			}
			if u, _ := m["url"].(string); strings.TrimSpace(u) != "" {
				out = append(out, strings.TrimSpace(u))
			}
		}
		return dedup(out)
	}
	// Swagger 2.0.
	host, _ := doc["host"].(string)
	if strings.TrimSpace(host) == "" {
		return nil
	}
	base, _ := doc["basePath"].(string)
	schemes, _ := doc["schemes"].([]any)
	scheme := "https"
	if len(schemes) > 0 {
		if s, _ := schemes[0].(string); s != "" {
			scheme = strings.ToLower(s)
		}
	}
	out = append(out, scheme+"://"+host+base)
	return dedup(out)
}

// extractParams parametre dizisini çıkarır ($ref'ler atlanır — ad yok).
func extractParams(v any) []Param {
	list, _ := v.([]any)
	var out []Param
	for _, item := range list {
		m, _ := item.(map[string]any)
		if m == nil {
			continue
		}
		name, _ := m["name"].(string)
		in, _ := m["in"].(string)
		if strings.TrimSpace(name) == "" {
			continue // $ref veya adsız — sessiz atlanır (plan eksik değil, az olur)
		}
		if strings.TrimSpace(in) == "" {
			in = "query"
		}
		req, _ := m["required"].(bool)
		out = append(out, Param{Name: name, In: strings.ToLower(in), Required: req})
	}
	return out
}

func dedup(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
