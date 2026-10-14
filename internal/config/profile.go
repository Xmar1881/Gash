// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package config defines scan profiles (Safe/Standard/Deep) that control
// which detectors run, request budgets, and risk thresholds.
package config

import (
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// ProfileName identifies a scan profile.
type ProfileName string

const (
	ProfileSafe       ProfileName = "safe"
	ProfileStandard   ProfileName = "standard"
	ProfileDeep       ProfileName = "deep"
	ProfileAggressive ProfileName = "aggressive"
)

// Profile defines a scan profile with detector activation, budgets, and risk thresholds.
// What: Centralizes the active/passive/budget tradeoffs for different use cases.
// Why: CLI --profile flag and config file both map to this single source of truth.
type Profile struct {
	Name                 ProfileName
	Description          string
	ActiveDetectors      []string // Oracle names to enable
	RequestTypes         []string // Allowed HTTP methods
	MaxRequestsPerTarget int64
	MaxRequestsTotal     int64
	RatePerSecond        float64
	PluginTimeoutMs      int64
	Parallelism          int
	AllowActive          bool // Allow active (safe=false) plugins
	AllowDeep            bool // Allow deep (browser/OOB) plugins
	RequireExplicitOptIn bool // Deep requires explicit --deep flag
}

// SafeProfile returns the Safe profile: passive-only, low budget.
func SafeProfile() Profile {
	return Profile{
		Name:                 ProfileSafe,
		Description:          "Passive-only scan with minimal budget. No active probing.",
		ActiveDetectors:      []string{"header", "redirect", "cors", "cookie", "version", "tls", "dns"},
		RequestTypes:         []string{"GET", "HEAD", "OPTIONS"},
		MaxRequestsPerTarget: 100,
		MaxRequestsTotal:     1000,
		RatePerSecond:        5,
		PluginTimeoutMs:      15000,
		Parallelism:          4,
		AllowActive:          false,
		AllowDeep:            false,
		RequireExplicitOptIn: false,
	}
}

// StandardProfile returns the Standard profile: controlled active, extended budget.
func StandardProfile() Profile {
	return Profile{
		Name:                 ProfileStandard,
		Description:          "Controlled active scan with extended detector set and budget.",
		ActiveDetectors:      []string{"header", "redirect", "cors", "cookie", "version", "tls", "dns", "tcp", "reflection", "error", "differential"},
		RequestTypes:         []string{"GET", "POST", "HEAD", "OPTIONS"},
		MaxRequestsPerTarget: 500,
		MaxRequestsTotal:     5000,
		RatePerSecond:        10,
		PluginTimeoutMs:      30000,
		Parallelism:          8,
		AllowActive:          true,
		AllowDeep:            false,
		RequireExplicitOptIn: false,
	}
}

// DeepProfile returns the Deep profile: browser/OOB/high budget, explicit opt-in.
func DeepProfile() Profile {
	return Profile{
		Name:                 ProfileDeep,
		Description:          "Deep scan with browser execution, OOB, and high budget. Requires explicit opt-in.",
		ActiveDetectors:      []string{"header", "redirect", "cors", "cookie", "version", "tls", "dns", "tcp", "reflection", "error", "differential", "timing", "execution", "oob"},
		RequestTypes:         []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"},
		MaxRequestsPerTarget: 2000,
		MaxRequestsTotal:     20000,
		RatePerSecond:        20,
		PluginTimeoutMs:      120000,
		Parallelism:          16,
		AllowActive:          true,
		AllowDeep:            true,
		RequireExplicitOptIn: true,
	}
}

// AggressiveProfile returns the Aggressive profile: full offensive scan with unrestricted budget, all detectors and HTTP methods.
func AggressiveProfile() Profile {
	return Profile{
		Name:                 ProfileAggressive,
		Description:          "Aggressive offensive scan with all detectors enabled, high rate limit and deep probing.",
		ActiveDetectors:      []string{"header", "redirect", "cors", "cookie", "version", "tls", "dns", "tcp", "reflection", "error", "differential", "timing", "execution", "oob"},
		RequestTypes:         []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"},
		MaxRequestsPerTarget: 50000,
		MaxRequestsTotal:     500000,
		RatePerSecond:        100,
		PluginTimeoutMs:      120000,
		Parallelism:          32,
		AllowActive:          true,
		AllowDeep:            true,
		RequireExplicitOptIn: false,
	}
}

// AllProfiles returns all built-in profiles.
func AllProfiles() map[ProfileName]Profile {
	return map[ProfileName]Profile{
		ProfileSafe:       SafeProfile(),
		ProfileStandard:   StandardProfile(),
		ProfileDeep:       DeepProfile(),
		ProfileAggressive: AggressiveProfile(),
	}
}

// GetProfile returns a profile by name, or nil if not found.
func GetProfile(name ProfileName) *Profile {
	profiles := AllProfiles()
	if p, ok := profiles[name]; ok {
		return &p
	}
	return nil
}

// ApplyToConfig applies the profile settings to an engine Config.
func (p *Profile) ApplyToConfig(cfg *plugin.PolicyConfig) {
	if p == nil {
		return
	}
	cfg.MaxRequestsPerTarget = p.MaxRequestsPerTarget
	cfg.MaxRequestsTotal = p.MaxRequestsTotal
	cfg.RatePerSecond = p.RatePerSecond
	// Note: PluginTimeoutMs, Parallelism, AllowActive, AllowDeep are applied at engine level
}

// DetectorEnabled checks if a detector is enabled in this profile.
func (p *Profile) DetectorEnabled(detector string) bool {
	if p == nil {
		return false
	}
	for _, d := range p.ActiveDetectors {
		if d == detector {
			return true
		}
	}
	return false
}

// MethodAllowed checks if an HTTP method is allowed in this profile.
func (p *Profile) MethodAllowed(method string) bool {
	if p == nil {
		return false
	}
	for _, m := range p.RequestTypes {
		if m == method {
			return true
		}
	}
	return false
}

// Validate checks if the profile configuration is valid.
func (p *Profile) Validate() error {
	if p == nil {
		return nil // nil profile means no override
	}
	if p.MaxRequestsPerTarget < 0 {
		return &ProfileError{Field: "MaxRequestsPerTarget", Msg: "must be >= 0"}
	}
	if p.MaxRequestsTotal < 0 {
		return &ProfileError{Field: "MaxRequestsTotal", Msg: "must be >= 0"}
	}
	if p.RatePerSecond < 0 {
		return &ProfileError{Field: "RatePerSecond", Msg: "must be >= 0"}
	}
	if p.PluginTimeoutMs < 0 {
		return &ProfileError{Field: "PluginTimeoutMs", Msg: "must be >= 0"}
	}
	if p.Parallelism < 1 {
		return &ProfileError{Field: "Parallelism", Msg: "must be >= 1"}
	}
	return nil
}

// ProfileError represents a profile validation error.
type ProfileError struct {
	Field string
	Msg   string
}

func (e *ProfileError) Error() string {
	return "profile: " + e.Field + ": " + e.Msg
}

// ProfileConfig holds profile-related settings for config file / CLI.
type ProfileConfig struct {
	Profile       ProfileName `yaml:"profile" json:"profile"`
	CustomProfile *Profile    `yaml:"custom_profile,omitempty" json:"custom_profile,omitempty"`
}

// ResolveProfile returns the effective profile (built-in or custom).
func (pc *ProfileConfig) ResolveProfile() *Profile {
	if pc == nil {
		return nil
	}
	if pc.CustomProfile != nil {
		return pc.CustomProfile
	}
	return GetProfile(pc.Profile)
}

// DefaultProfileConfig returns the default profile config (Standard).
func DefaultProfileConfig() ProfileConfig {
	return ProfileConfig{
		Profile: ProfileStandard,
	}
}

// EngineConfigFromProfile creates an engine.Config from a Profile.
func EngineConfigFromProfile(p *Profile, base plugin.PolicyConfig) plugin.PolicyConfig {
	if p == nil {
		return base
	}
	cfg := base
	cfg.MaxRequestsPerTarget = p.MaxRequestsPerTarget
	cfg.MaxRequestsTotal = p.MaxRequestsTotal
	cfg.RatePerSecond = p.RatePerSecond
	cfg.ScanTimeout = time.Duration(p.PluginTimeoutMs*int64(time.Millisecond)) * 10 // scan timeout = 10x plugin timeout
	return cfg
}
