// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package bench implements the automated security-scanner benchmark system:
// YAML ground-truth datasets with independent verification, an equal-conditions
// Gash/Nuclei comparison harness, deterministic metrics, honest reports, and a
// baseline regression gate. It never trusts fixture labels: every scenario is
// independently verified before it can be scored.
package bench

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	KindFixtures = "fixtures"
	KindCompose  = "compose"

	ExpectVulnerable = "vulnerable"
	ExpectClean      = "clean"
	ExpectDenied     = "denied"
	ExpectSoft404    = "soft404"
	ExpectWAF        = "waf"
	ExpectTimeout    = "timeout"

	AuthNone   = "none"
	AuthUserA  = "user-a"
	AuthUserB  = "user-b"
	AuthMatrix = "matrix"

	FixtureBasePlaceholder = "{{FIXTURE_BASE}}"

	VerifyHTTPReflection = "http-reflection"
	VerifyHTTPError      = "http-error"
	VerifyHTTPStored     = "http-stored"
	VerifyHTTPJSONRaw    = "http-json-raw"
	VerifyHTTPClean      = "http-clean"
	VerifyHTTPDenied     = "http-denied"
	VerifyHTTPSoft404    = "http-soft404"
	VerifyHTTPWAF        = "http-waf"
	VerifyHTTPTimeout    = "http-timeout"
	VerifyHTTPRedirect   = "http-redirect"
	VerifyBrowserExec    = "browser-exec"

	StatusTP         = "tp"
	StatusFP         = "fp"
	StatusTN         = "tn"
	StatusFN         = "fn"
	StatusWeak       = "weak-evidence"
	StatusUnverified = "unverified"
	StatusNotRun     = "not-run"

	xssCategoryPrefix = "xss"
)

var (
	scenarioIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

	expectedValues = map[string]bool{
		ExpectVulnerable: true, ExpectClean: true, ExpectDenied: true,
		ExpectSoft404: true, ExpectWAF: true, ExpectTimeout: true,
	}
	authValues = map[string]bool{
		AuthNone: true, AuthUserA: true, AuthUserB: true, AuthMatrix: true,
	}
	verifyKinds = map[string]bool{
		VerifyHTTPReflection: true, VerifyHTTPError: true, VerifyHTTPStored: true,
		VerifyHTTPJSONRaw: true, VerifyHTTPClean: true, VerifyHTTPDenied: true,
		VerifyHTTPSoft404: true, VerifyHTTPWAF: true, VerifyHTTPTimeout: true,
		VerifyHTTPRedirect: true, VerifyBrowserExec: true,
	}
)

// Dataset is the benchmark ground truth: targets plus verifiable scenarios.
type Dataset struct {
	Version         string       `yaml:"version" json:"version"`
	Name            string       `yaml:"name" json:"name"`
	Kind            string       `yaml:"kind" json:"kind"`
	Description     string       `yaml:"description" json:"description,omitempty"`
	AllowHosts      []string     `yaml:"allow_hosts" json:"allow_hosts,omitempty"`
	Gash            ToolConfig   `yaml:"gash" json:"gash"`
	Nuclei          NucleiConfig `yaml:"nuclei" json:"nuclei"`
	UnscoredPlugins []string     `yaml:"unscored_plugins" json:"unscored_plugins,omitempty"`
	UnscoredRules   []string     `yaml:"unscored_rules" json:"unscored_rules,omitempty"`
	Targets         []Target     `yaml:"targets" json:"targets"`
	Scenarios       []Scenario   `yaml:"scenarios" json:"scenarios"`

	SHA256 string `yaml:"-" json:"sha256"`
	Path   string `yaml:"-" json:"path"`
}

// ToolConfig bounds one Gash invocation.
type ToolConfig struct {
	Args    []string `yaml:"args" json:"args,omitempty"`
	Timeout string   `yaml:"timeout" json:"timeout,omitempty"`
}

// NucleiConfig bounds one Nuclei invocation.
type NucleiConfig struct {
	Bin       string   `yaml:"bin" json:"bin,omitempty"`
	Tags      []string `yaml:"tags" json:"tags,omitempty"`
	Args      []string `yaml:"args" json:"args,omitempty"`
	Timeout   string   `yaml:"timeout" json:"timeout,omitempty"`
	RateLimit int      `yaml:"rate_limit" json:"rate_limit,omitempty"`
}

// Target is one lab base URL plus optional per-role auth headers.
type Target struct {
	ID      string            `yaml:"id" json:"id"`
	BaseURL string            `yaml:"base_url" json:"base_url"`
	Auth    map[string]string `yaml:"auth" json:"auth,omitempty"`
	Notes   string            `yaml:"notes" json:"notes,omitempty"`
}

// Scenario is one independently verifiable ground-truth entry.
type Scenario struct {
	ID          string     `yaml:"id" json:"id"`
	Category    string     `yaml:"category" json:"category"`
	Subcategory string     `yaml:"subcategory" json:"subcategory,omitempty"`
	CWE         string     `yaml:"cwe" json:"cwe,omitempty"`
	TargetID    string     `yaml:"target_id" json:"target_id,omitempty"`
	Path        string     `yaml:"path" json:"path,omitempty"`
	URL         string     `yaml:"url" json:"url,omitempty"`
	Expected    string     `yaml:"expected" json:"expected"`
	Auth        string     `yaml:"auth" json:"auth,omitempty"`
	Critical    bool       `yaml:"critical" json:"critical,omitempty"`
	XSS         *XSSSpec   `yaml:"xss" json:"xss,omitempty"`
	Verify      VerifySpec `yaml:"verify" json:"verify"`
	Match       MatchSpec  `yaml:"match" json:"match"`
	Notes       string     `yaml:"notes" json:"notes,omitempty"`
}

// XSSSpec records the XSS sub-benchmark dimensions of a scenario.
type XSSSpec struct {
	Kind    string `yaml:"kind" json:"kind"`
	Context string `yaml:"context" json:"context"`
	// ExecutionRequired marks scenarios whose confirmed ground truth is real
	// browser execution; static evidence alone must not count as confirmed.
	ExecutionRequired bool `yaml:"execution_required" json:"execution_required,omitempty"`
}

// VerifySpec describes the independent verification procedure.
type VerifySpec struct {
	Kind                   string   `yaml:"kind" json:"kind"`
	Method                 string   `yaml:"method" json:"method,omitempty"`
	Path                   string   `yaml:"path" json:"path,omitempty"`
	Payload                string   `yaml:"payload" json:"payload,omitempty"`
	StorePath              string   `yaml:"store_path" json:"store_path,omitempty"`
	RenderPath             string   `yaml:"render_path" json:"render_path,omitempty"`
	ExpectStatus           []int    `yaml:"expect_status" json:"expect_status,omitempty"`
	ExpectContains         []string `yaml:"expect_contains" json:"expect_contains,omitempty"`
	ExpectNotContains      []string `yaml:"expect_not_contains" json:"expect_not_contains,omitempty"`
	ExpectExternalLocation bool     `yaml:"expect_external_location" json:"expect_external_location,omitempty"`
	ExpectSlowMS           int      `yaml:"expect_slow_ms" json:"expect_slow_ms,omitempty"`
	Timeout                string   `yaml:"timeout" json:"timeout,omitempty"`
}

// MatchSpec maps tool output (plugin/rule/template) to the scenario class.
type MatchSpec struct {
	PluginIDs  []string `yaml:"plugin_ids" json:"plugin_ids,omitempty"`
	RuleIDs    []string `yaml:"rule_ids" json:"rule_ids,omitempty"`
	NucleiTags []string `yaml:"nuclei_tags" json:"nuclei_tags,omitempty"`
}

// LoadDataset reads and validates a dataset file.
func LoadDataset(path string) (*Dataset, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bench dataset: read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	var ds Dataset
	if err := dec.Decode(&ds); err != nil {
		return nil, fmt.Errorf("bench dataset: parse %s: %w", path, err)
	}
	sum := sha256.Sum256(raw)
	ds.SHA256 = hex.EncodeToString(sum[:])
	ds.Path = path
	return &ds, nil
}

// Validate enforces dataset integrity plus the lab-only safety guard.
func Validate(ds *Dataset, allowNonLab bool) error {
	if ds == nil {
		return fmt.Errorf("bench dataset: nil")
	}
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if ds.Version == "" {
		add("version is required")
	}
	if ds.Name == "" {
		add("name is required")
	}
	switch ds.Kind {
	case KindFixtures, KindCompose:
	default:
		add("kind %q must be %s or %s", ds.Kind, KindFixtures, KindCompose)
	}
	if len(ds.Targets) == 0 {
		add("at least one target is required")
	}
	if len(ds.Scenarios) == 0 {
		add("at least one scenario is required")
	}

	targets := map[string]*Target{}
	for i := range ds.Targets {
		t := &ds.Targets[i]
		if t.ID == "" {
			add("target[%d]: id is required", i)
			continue
		}
		if targets[t.ID] != nil {
			add("target %q: duplicate id", t.ID)
		}
		targets[t.ID] = t
		if t.BaseURL == "" {
			add("target %q: base_url is required", t.ID)
		}
		for role := range t.Auth {
			if !authValues[role] || role == AuthNone || role == AuthMatrix {
				add("target %q: auth role %q must be user-a or user-b", t.ID, role)
			}
		}
	}

	ids := map[string]bool{}
	for i := range ds.Scenarios {
		sc := &ds.Scenarios[i]
		if sc.ID == "" {
			add("scenario[%d]: id is required", i)
			continue
		}
		if !scenarioIDRe.MatchString(sc.ID) {
			add("scenario %q: id must match %s", sc.ID, scenarioIDRe)
		}
		if ids[sc.ID] {
			add("scenario %q: duplicate id", sc.ID)
		}
		ids[sc.ID] = true
		if sc.Category == "" {
			add("scenario %q: category is required", sc.ID)
		}
		if !expectedValues[sc.Expected] {
			add("scenario %q: expected %q invalid", sc.ID, sc.Expected)
		}
		if sc.Auth == "" {
			sc.Auth = AuthNone
		}
		if !authValues[sc.Auth] {
			add("scenario %q: auth %q invalid", sc.ID, sc.Auth)
		}
		if sc.Path == "" && sc.URL == "" {
			add("scenario %q: path or url is required", sc.ID)
		}
		if sc.TargetID != "" && targets[sc.TargetID] == nil {
			add("scenario %q: unknown target_id %q", sc.ID, sc.TargetID)
		}
		if strings.HasPrefix(sc.Category, xssCategoryPrefix) && sc.XSS == nil {
			add("scenario %q: xss block is required for xss categories", sc.ID)
		}
		if sc.XSS != nil {
			if sc.XSS.Kind == "" || sc.XSS.Context == "" {
				add("scenario %q: xss.kind and xss.context are required", sc.ID)
			}
		}
		if !verifyKinds[sc.Verify.Kind] {
			add("scenario %q: verify.kind %q invalid", sc.ID, sc.Verify.Kind)
		}
		if len(sc.Match.PluginIDs) == 0 && len(sc.Match.RuleIDs) == 0 && len(sc.Match.NucleiTags) == 0 {
			add("scenario %q: match must declare plugin_ids, rule_ids or nuclei_tags", sc.ID)
		}
		if sc.Verify.Kind == VerifyHTTPStored && (sc.Verify.StorePath == "" || sc.Verify.RenderPath == "") {
			add("scenario %q: http-stored requires store_path and render_path", sc.ID)
		}
		if sc.Verify.Kind == VerifyHTTPTimeout && sc.Verify.ExpectSlowMS <= 0 {
			add("scenario %q: http-timeout requires expect_slow_ms", sc.ID)
		}
	}

	if !allowNonLab {
		for _, t := range ds.Targets {
			if t.BaseURL == "" || strings.Contains(t.BaseURL, FixtureBasePlaceholder) {
				continue
			}
			if err := checkLabHost(t.BaseURL, ds.AllowHosts); err != nil {
				add("target %q: %v", t.ID, err)
			}
		}
		for i := range ds.Scenarios {
			sc := &ds.Scenarios[i]
			if sc.URL == "" {
				continue
			}
			if err := checkLabHost(sc.URL, ds.AllowHosts); err != nil {
				add("scenario %q: %v", sc.ID, err)
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("bench dataset %s: %d problem(s):\n  - %s", ds.Name, len(problems), strings.Join(problems, "\n  - "))
	}
	return nil
}

func checkLabHost(raw string, allow []string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("invalid URL %q", raw)
	}
	host := strings.ToLower(u.Hostname())
	if len(allow) == 0 {
		allow = []string{"127.0.0.1", "localhost", "::1"}
	}
	for _, a := range allow {
		if strings.EqualFold(a, host) {
			return nil
		}
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("host %q is not in allow_hosts %v: benchmark refuses non-lab targets", host, allow)
}

// TargetByID resolves one target reference.
func (ds *Dataset) TargetByID(id string) (*Target, bool) {
	for i := range ds.Targets {
		if ds.Targets[i].ID == id {
			return &ds.Targets[i], true
		}
	}
	return nil, false
}

// ScenarioTarget returns the target a scenario runs against.
func (ds *Dataset) ScenarioTarget(sc *Scenario) (*Target, error) {
	if sc.TargetID != "" {
		t, ok := ds.TargetByID(sc.TargetID)
		if !ok {
			return nil, fmt.Errorf("scenario %s: unknown target %q", sc.ID, sc.TargetID)
		}
		return t, nil
	}
	if len(ds.Targets) == 0 {
		return nil, fmt.Errorf("scenario %s: dataset has no targets", sc.ID)
	}
	return &ds.Targets[0], nil
}

// ResolveURL returns the absolute scenario URL against its target base.
func (ds *Dataset) ResolveURL(sc *Scenario) (string, error) {
	if sc.URL != "" {
		return sc.URL, nil
	}
	t, err := ds.ScenarioTarget(sc)
	if err != nil {
		return "", err
	}
	return joinURL(t.BaseURL, sc.Path)
}

func joinURL(base, path string) (string, error) {
	bu, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("base url %q: %w", base, err)
	}
	if path == "" {
		return bu.String(), nil
	}
	if pu, err := url.Parse(path); err == nil && pu.IsAbs() {
		return pu.String(), nil
	}
	rel := path
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	ref, err := url.Parse(rel)
	if err != nil {
		return "", fmt.Errorf("path %q: %w", path, err)
	}
	return bu.ResolveReference(ref).String(), nil
}

// AuthHeader returns the scenario's auth header ("Name: value") for a target.
func (ds *Dataset) AuthHeader(sc *Scenario) (string, error) {
	if sc.Auth == "" || sc.Auth == AuthNone {
		return "", nil
	}
	t, err := ds.ScenarioTarget(sc)
	if err != nil {
		return "", err
	}
	if v, ok := t.Auth[sc.Auth]; ok && v != "" {
		return v, nil
	}
	return "", fmt.Errorf("scenario %s: target %s has no auth entry for %q", sc.ID, t.ID, sc.Auth)
}
