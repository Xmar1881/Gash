// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// menuSettings is the persistent operator preference set.
// What: Default profile, logo visibility, proxy mode, and plugin selection.
// Why: The menu is the primary surface; choices should survive a restart
// without touching CLI flags or environment variables.
type menuSettings struct {
	Profile       string   `json:"profile,omitempty"`
	ShowLogo      *bool    `json:"show_logo,omitempty"`
	ProxyMode     string   `json:"proxy_mode,omitempty"`
	PluginOnly    []string `json:"plugin_only,omitempty"`
	PluginExclude []string `json:"plugin_exclude,omitempty"`
}

func (m menuSettings) logoEnabled() bool {
	return m.ShowLogo == nil || *m.ShowLogo
}

func (m menuSettings) defaultProfile() string {
	switch m.Profile {
	case "safe", "standard", "deep", "aggressive":
		return m.Profile
	default:
		return "standard"
	}
}

func (m menuSettings) defaultProxyMode() string {
	switch m.ProxyMode {
	case "auto", "off", "all":
		return m.ProxyMode
	default:
		return "auto"
	}
}

// menuSettingsPath defaults to the repo-local .gash tree and can be pointed
// elsewhere for tests or portable installs.
func menuSettingsPath() string {
	if p := strings.TrimSpace(os.Getenv("GASH_MENU_SETTINGS")); p != "" {
		return p
	}
	return filepath.Join(".gash", "menu-settings.json")
}

func loadMenuSettings() menuSettings {
	var s menuSettings
	data, err := os.ReadFile(menuSettingsPath())
	if err == nil {
		_ = json.Unmarshal(data, &s)
	}
	s.PluginOnly = normalizePluginIDs(s.PluginOnly)
	s.PluginExclude = normalizePluginIDs(s.PluginExclude)
	// Exclusion wins over a stale overlapping only entry.
	excluded := make(map[string]bool, len(s.PluginExclude))
	for _, id := range s.PluginExclude {
		excluded[id] = true
	}
	var only []string
	for _, id := range s.PluginOnly {
		if !excluded[id] {
			only = append(only, id)
		}
	}
	s.PluginOnly = only
	return s
}

func saveMenuSettings(s menuSettings) error {
	s.PluginOnly = normalizePluginIDs(s.PluginOnly)
	s.PluginExclude = normalizePluginIDs(s.PluginExclude)
	// Keep the persisted file non-overlapping: exclusion wins.
	excluded := make(map[string]bool, len(s.PluginExclude))
	for _, id := range s.PluginExclude {
		excluded[id] = true
	}
	var only []string
	for _, id := range s.PluginOnly {
		if !excluded[id] {
			only = append(only, id)
		}
	}
	s.PluginOnly = only
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	path := menuSettingsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func normalizePluginIDs(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	var out []string
	for _, raw := range ids {
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		}) {
			id := strings.ToLower(strings.TrimSpace(part))
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func splitPluginIDs(raw string) []string {
	return normalizePluginIDs([]string{raw})
}
