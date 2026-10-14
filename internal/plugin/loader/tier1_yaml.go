// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package loader

import (
	"fmt"
	"os"
	"strings"

	"github.com/Xmar1881/Gash/internal/plugin"
	"gopkg.in/yaml.v3"
)

// Tier1Request deklaratif istek bloğudur.
type Tier1Request struct {
	Method     string   `yaml:"method" json:"method"`
	ParamNames []string `yaml:"param_names" json:"param_names"`
	Payload    string   `yaml:"payload" json:"payload"`
}

// Tier1Oracle oracle referansıdır (kod bloğu YOK).
type Tier1Oracle struct {
	Name   string         `yaml:"name" json:"name"`
	Params map[string]any `yaml:"params" json:"params"`
}

// Tier1File tek-dosya Tier1 plugin'dir.
type Tier1File struct {
	plugin.PluginSpec `yaml:",inline"`
	Request           Tier1Request `yaml:"request" json:"request"`
	Oracle            Tier1Oracle  `yaml:"oracle" json:"oracle"`
}

// tier1Raw ham anahtar denetimi içindir (matcher whitelist + kod yasağı).
type tier1Raw map[string]any

// allowedTopLevel Tier1 üst-seviye anahtar whitelist'idir.
var allowedTopLevel = map[string]bool{
	"id": true, "name": true, "description": true, "author": true,
	"severity": true, "tags": true, "safe": true, "deep": true, "active": true,
	"requires_auth": true, "requires_tech": true, "max_requests": true,
	"phase": true, "order": true, "requires": true, "provides": true,
	"overrides": true, "oob": true, "api_version": true, "tests": true,
	"request": true, "oracle": true,
}

// forbiddenKeys kod bloğu kabul edilmez (additionalProperties + not karşılığı).
var forbiddenKeys = []string{"script", "code", "eval", "exec", "run", "function", "require", "import"}

// ParseTier1YAML metadata+tanım bloğunu okur (kod çalıştırmaz).
func ParseTier1YAML(path string, data []byte) (*plugin.PluginSpec, *Tier1File, error) {
	var raw tier1Raw
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(false)
	if err := dec.Decode(&raw); err != nil {
		return nil, nil, fmt.Errorf("tier1 yaml decode %s: %w", path, err)
	}
	for k := range raw {
		if !allowedTopLevel[k] {
			return nil, nil, fmt.Errorf("tier1 %s: bilinmeyen anahtar %q: %w", path, k, plugin.ErrValidation)
		}
	}
	lower := strings.ToLower(string(data))
	for _, fk := range forbiddenKeys {
		// Kaba ama etkili: anahtar olarak geçiyorsa reddet.
		if strings.Contains(lower, "\n"+fk+":") || strings.HasPrefix(lower, fk+":") {
			return nil, nil, fmt.Errorf("tier1 %s: yasak anahtar %q (kod bloğu kabul edilmez): %w", path, fk, plugin.ErrValidation)
		}
	}
	var f Tier1File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, nil, fmt.Errorf("tier1 yaml unmarshal %s: %w", path, err)
	}
	f.Tier = plugin.TierYAML
	if err := plugin.Validate(f.PluginSpec); err != nil {
		return nil, nil, fmt.Errorf("tier1 validate %s: %w", path, err)
	}
	if f.Oracle.Name == "" {
		return nil, nil, fmt.Errorf("tier1 %s: oracle.name zorunlu: %w", path, plugin.ErrValidation)
	}
	if err := plugin.CheckOOBOracle(f.Oracle.Name, f.OOB, f.ID); err != nil {
		return nil, nil, fmt.Errorf("tier1 %s: %w", path, err)
	}
	if ww, err := IsWorldWritable(path); err == nil && ww {
		return nil, nil, fmt.Errorf("tier1 %s world-writable: %w", path, plugin.ErrValidation)
	}
	return &f.PluginSpec, &f, nil
}

// LoadTier1File diskten okuyup parse eder (Aşama 1 — execute yok).
func LoadTier1File(path string) (*plugin.PluginSpec, *Tier1File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseTier1YAML(path, data)
}
