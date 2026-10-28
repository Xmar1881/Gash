// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

func TestBuiltinProfiles(t *testing.T) {
	tests := []struct {
		name       ProfileName
		profile    Profile
		active     bool
		deep       bool
		optIn      bool
		rate       float64
		perTarget  int64
		total      int64
		timeout    int64
		parallel   int
		maxPages   int
		crawlDepth int
	}{
		{ProfileSafe, SafeProfile(), false, false, false, 5, 250, 2000, 30000, 4, 20, 2},
		{ProfileStandard, StandardProfile(), true, false, false, 10, 2000, 15000, 60000, 8, 50, 3},
		{ProfileDeep, DeepProfile(), true, true, true, 20, 8000, 40000, 120000, 16, 200, 5},
		{ProfileAggressive, AggressiveProfile(), true, true, false, 100, 50000, 500000, 120000, 32, 500, 10},
	}
	for _, tc := range tests {
		t.Run(string(tc.name), func(t *testing.T) {
			p := tc.profile
			if p.Name != tc.name {
				t.Fatalf("name = %q, want %q", p.Name, tc.name)
			}
			if strings.TrimSpace(p.Description) == "" {
				t.Fatal("description must not be empty")
			}
			if len(p.ActiveDetectors) == 0 {
				t.Fatal("active detectors must not be empty")
			}
			if len(p.RequestTypes) == 0 {
				t.Fatal("request types must not be empty")
			}
			if p.AllowActive != tc.active || p.AllowDeep != tc.deep || p.RequireExplicitOptIn != tc.optIn {
				t.Fatalf("policy flags = active:%v deep:%v optin:%v, want active:%v deep:%v optin:%v",
					p.AllowActive, p.AllowDeep, p.RequireExplicitOptIn, tc.active, tc.deep, tc.optIn)
			}
			if p.RatePerSecond != tc.rate || p.MaxRequestsPerTarget != tc.perTarget ||
				p.MaxRequestsTotal != tc.total || p.PluginTimeoutMs != tc.timeout ||
				p.Parallelism != tc.parallel || p.MaxPages != tc.maxPages || p.CrawlDepth != tc.crawlDepth {
				t.Fatalf("profile budgets drifted: %+v", p)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("built-in profile must validate: %v", err)
			}
		})
	}
}

func TestGetProfileCopies(t *testing.T) {
	for _, name := range []ProfileName{ProfileSafe, ProfileStandard, ProfileDeep, ProfileAggressive} {
		p := GetProfile(name)
		if p == nil {
			t.Fatalf("GetProfile(%q) returned nil", name)
		}
		if p.Name != name {
			t.Fatalf("GetProfile(%q).Name = %q", name, p.Name)
		}
		original := p.MaxRequestsTotal
		p.MaxRequestsTotal = -1
		again := GetProfile(name)
		if again.MaxRequestsTotal != original {
			t.Fatalf("GetProfile must return a copy; mutation leaked into %q", name)
		}
	}
	for _, name := range []ProfileName{"", "SAFE", "unknown", " standard"} {
		if got := GetProfile(name); got != nil {
			t.Fatalf("GetProfile(%q) = %+v, want nil", name, got)
		}
	}
}

func TestAllProfiles(t *testing.T) {
	all := AllProfiles()
	if len(all) != 4 {
		t.Fatalf("AllProfiles len = %d, want 4", len(all))
	}
	for name, p := range all {
		if p.Name != name {
			t.Fatalf("map key %q does not match profile name %q", name, p.Name)
		}
	}
}

func TestDetectorEnabled(t *testing.T) {
	cases := []struct {
		name     string
		profile  *Profile
		detector string
		want     bool
	}{
		{"safe header", profilePtr(SafeProfile()), "header", true},
		{"safe reflection", profilePtr(SafeProfile()), "reflection", false},
		{"standard reflection", profilePtr(StandardProfile()), "reflection", true},
		{"standard execution", profilePtr(StandardProfile()), "execution", false},
		{"deep execution", profilePtr(DeepProfile()), "execution", true},
		{"deep smuggle", profilePtr(DeepProfile()), "smuggle", false},
		{"aggressive smuggle", profilePtr(AggressiveProfile()), "smuggle", true},
		{"unknown detector", profilePtr(StandardProfile()), "does-not-exist", false},
		{"case sensitive", profilePtr(StandardProfile()), "Header", false},
		{"nil profile", nil, "header", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.profile.DetectorEnabled(tc.detector); got != tc.want {
				t.Fatalf("DetectorEnabled(%q) = %v, want %v", tc.detector, got, tc.want)
			}
		})
	}
}

func TestMethodAllowed(t *testing.T) {
	cases := []struct {
		name    string
		profile *Profile
		method  string
		want    bool
	}{
		{"safe get", profilePtr(SafeProfile()), "GET", true},
		{"safe post", profilePtr(SafeProfile()), "POST", false},
		{"standard post", profilePtr(StandardProfile()), "POST", true},
		{"standard put", profilePtr(StandardProfile()), "PUT", false},
		{"deep patch", profilePtr(DeepProfile()), "PATCH", true},
		{"aggressive delete", profilePtr(AggressiveProfile()), "DELETE", true},
		{"lowercase method", profilePtr(DeepProfile()), "get", false},
		{"unknown method", profilePtr(AggressiveProfile()), "TRACE", false},
		{"nil profile", nil, "GET", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.profile.MethodAllowed(tc.method); got != tc.want {
				t.Fatalf("MethodAllowed(%q) = %v, want %v", tc.method, got, tc.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	valid := Profile{Parallelism: 1}
	cases := []struct {
		name  string
		p     *Profile
		field string
	}{
		{"nil profile", nil, ""},
		{"valid minimal", &valid, ""},
		{"negative per target", &Profile{Parallelism: 1, MaxRequestsPerTarget: -1}, "MaxRequestsPerTarget"},
		{"negative total", &Profile{Parallelism: 1, MaxRequestsTotal: -1}, "MaxRequestsTotal"},
		{"negative rate", &Profile{Parallelism: 1, RatePerSecond: -0.1}, "RatePerSecond"},
		{"negative timeout", &Profile{Parallelism: 1, PluginTimeoutMs: -1}, "PluginTimeoutMs"},
		{"zero parallelism", &Profile{}, "Parallelism"},
		{"negative parallelism", &Profile{Parallelism: -1}, "Parallelism"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if tc.field == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			var perr *ProfileError
			if !errors.As(err, &perr) {
				t.Fatalf("Validate() = %v, want *ProfileError", err)
			}
			if perr.Field != tc.field {
				t.Fatalf("field = %q, want %q", perr.Field, tc.field)
			}
			if !strings.Contains(err.Error(), "profile: "+tc.field+":") {
				t.Fatalf("unexpected error text: %q", err.Error())
			}
		})
	}
}

func TestProfileErrorText(t *testing.T) {
	err := &ProfileError{Field: "RatePerSecond", Msg: "must be >= 0"}
	if got, want := err.Error(), "profile: RatePerSecond: must be >= 0"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestApplyToConfig(t *testing.T) {
	base := plugin.PolicyConfig{
		MaxRequestsPerTarget: 11,
		MaxRequestsTotal:     22,
		RatePerSecond:        33,
		MaxResponseBytes:     44,
		ScanTimeout:          time.Minute,
	}
	p := Profile{MaxRequestsPerTarget: 1, MaxRequestsTotal: 2, RatePerSecond: 3, PluginTimeoutMs: 9000}
	cfg := base
	p.ApplyToConfig(&cfg)
	if cfg.MaxRequestsPerTarget != 1 || cfg.MaxRequestsTotal != 2 || cfg.RatePerSecond != 3 {
		t.Fatalf("budget fields not applied: %+v", cfg)
	}
	if cfg.MaxResponseBytes != 44 || cfg.ScanTimeout != time.Minute {
		t.Fatalf("unrelated fields changed: %+v", cfg)
	}
	if base.MaxRequestsPerTarget != 11 || base.MaxRequestsTotal != 22 || base.RatePerSecond != 33 {
		t.Fatalf("base config mutated: %+v", base)
	}
	var nilProfile *Profile
	before := cfg
	nilProfile.ApplyToConfig(&cfg)
	if !reflect.DeepEqual(cfg, before) {
		t.Fatalf("nil profile must not change config: %+v", cfg)
	}
}

func TestEngineConfigFromProfile(t *testing.T) {
	base := plugin.PolicyConfig{
		MaxRequestsPerTarget: 11,
		MaxRequestsTotal:     22,
		RatePerSecond:        33,
		MaxResponseBytes:     44,
		ScanTimeout:          time.Second,
	}
	p := Profile{
		MaxRequestsPerTarget: 100,
		MaxRequestsTotal:     200,
		RatePerSecond:        3.5,
		PluginTimeoutMs:      30000,
	}
	got := EngineConfigFromProfile(&p, base)
	if got.MaxRequestsPerTarget != 100 || got.MaxRequestsTotal != 200 || got.RatePerSecond != 3.5 {
		t.Fatalf("profile budgets not applied: %+v", got)
	}
	if got.ScanTimeout != 300*time.Second {
		t.Fatalf("ScanTimeout = %v, want 5m", got.ScanTimeout)
	}
	if got.MaxResponseBytes != 44 {
		t.Fatalf("unrelated fields changed: %+v", got)
	}
	if base.ScanTimeout != time.Second || base.MaxRequestsTotal != 22 {
		t.Fatalf("base config mutated: %+v", base)
	}
	if got := EngineConfigFromProfile(nil, base); !reflect.DeepEqual(got, base) {
		t.Fatalf("nil profile must return base unchanged: %+v", got)
	}
}

func TestResolveProfile(t *testing.T) {
	var nilConfig *ProfileConfig
	if got := nilConfig.ResolveProfile(); got != nil {
		t.Fatalf("nil config resolved to %+v", got)
	}
	def := DefaultProfileConfig()
	if def.Profile != ProfileStandard {
		t.Fatalf("default profile = %q, want standard", def.Profile)
	}
	if got := def.ResolveProfile(); got == nil || got.Name != ProfileStandard {
		t.Fatalf("default config resolved to %+v", got)
	}
	custom := &Profile{Name: "custom", Parallelism: 1}
	pc := &ProfileConfig{Profile: ProfileDeep, CustomProfile: custom}
	if got := pc.ResolveProfile(); got != custom {
		t.Fatalf("custom profile must win, got %+v", got)
	}
	unknown := &ProfileConfig{Profile: "unknown"}
	if got := unknown.ResolveProfile(); got != nil {
		t.Fatalf("unknown profile resolved to %+v", got)
	}
}

func TestProfileErrorFieldCoverage(t *testing.T) {
	for _, field := range []string{
		"MaxRequestsPerTarget", "MaxRequestsTotal", "RatePerSecond", "PluginTimeoutMs", "Parallelism",
	} {
		p := validProfileFor(field)
		err := p.Validate()
		var perr *ProfileError
		if !errors.As(err, &perr) || perr.Field != field {
			t.Fatalf("field %q not reported: %v", field, err)
		}
	}
}

func profilePtr(p Profile) *Profile { return &p }

func validProfileFor(field string) *Profile {
	p := profilePtr(Profile{Parallelism: 1})
	switch field {
	case "MaxRequestsPerTarget":
		p.MaxRequestsPerTarget = -1
	case "MaxRequestsTotal":
		p.MaxRequestsTotal = -1
	case "RatePerSecond":
		p.RatePerSecond = -1
	case "PluginTimeoutMs":
		p.PluginTimeoutMs = -1
	case "Parallelism":
		p.Parallelism = 0
	}
	return p
}
