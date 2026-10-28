// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// settingsFlow edits persisted menu defaults (profile, logo, proxy mode).
func (s *menuSession) settingsFlow() error {
	for {
		s.println()
		s.header("⚙", s.t("settings.title"))
		logoLabel := s.t("settings.logoOff")
		if s.settings.logoEnabled() {
			logoLabel = s.t("settings.logoOn")
		}
		lines := []string{
			s.kv(s.t("settings.profile"), s.t("profile."+s.settings.defaultProfile()+".label")),
			s.kv(s.t("settings.logo"), logoLabel),
			s.kv(s.t("settings.proxy"), s.t("proxy."+s.settings.defaultProxyMode()+".label")),
			s.kv(s.t("settings.selection"), fmt.Sprintf("%d / %d", len(s.settings.PluginOnly), len(s.settings.PluginExclude))),
			"",
			s.th.muted(s.t("settings.defaultNote")),
		}
		s.panel(s.th.bold(s.t("settings.title")), s.th.accent, lines...)
		s.println()
		s.printf("  %s  %s\n",
			kb(s.th, "p", s.t("settings.changeProfile")),
			kb(s.th, "g", s.t("settings.toggleLogo")))
		s.printf("  %s  %s\n",
			kb(s.th, "x", s.t("settings.changeProxy")),
			kb(s.th, "s", s.t("settings.openSelection")))
		s.println("  " + kb(s.th, "0", s.t("common.back")))
		action, err := s.readLine(s.t("input.selection") + ": ")
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "0", "b", "back", "geri", "iptal", "cancel":
			return nil
		case "p", "profil", "profile":
			p, err := s.choose(s.t("settings.profile"), []choice{
				{"safe", "s", "profile.safe.label", "profile.safe.desc"},
				{"standard", "t", "profile.standard.label", "profile.standard.desc"},
				{"deep", "d", "profile.deep.label", "profile.deep.desc"},
				{"aggressive", "g", "profile.aggressive.label", "profile.aggressive.desc"},
			}, s.settings.defaultProfile())
			if err != nil {
				return err
			}
			s.settings.Profile = p
			delete(s.memo, "profile")
			s.saveSettings()
		case "g", "logo":
			enabled := !s.settings.logoEnabled()
			s.settings.ShowLogo = &enabled
			s.saveSettings()
			s.println("  " + s.th.muted(s.t("settings.logoNote")))
		case "x", "proxy", "proksi":
			mode, err := s.choose(s.t("settings.proxy"), []choice{
				{"auto", "a", "proxy.auto.label", "proxy.auto.desc"},
				{"off", "o", "proxy.off.label", "proxy.off.desc"},
				{"all", "l", "proxy.all.label", "proxy.all.desc"},
			}, s.settings.defaultProxyMode())
			if err != nil {
				return err
			}
			s.settings.ProxyMode = mode
			s.saveSettings()
		case "s", "selection", "secim", "seçim":
			if err := s.pluginSelectionFlow(); err != nil {
				return err
			}
		default:
			s.printf("  %s\n", s.th.bad(s.t("common.invalidChoice", action)))
		}
	}
}

// pluginSelectionFlow edits the persisted only/exclude plugin sets.
func (s *menuSession) pluginSelectionFlow() error {
	ids, names, err := s.catalogPluginIDs()
	if err != nil {
		s.printf("  %s\n", s.th.bad(s.t("selection.catalogFailed", err.Error())))
		return nil
	}
	if len(ids) == 0 {
		s.println("  " + s.th.warn(s.t("selection.catalogEmpty")))
		return nil
	}
	known := make(map[string]bool, len(ids))
	for _, id := range ids {
		known[id] = true
	}
	for {
		s.println()
		s.header("◈", s.t("selection.title"))
		lines := []string{
			s.kv(s.t("selection.onlyLabel"), fmt.Sprintf("%d", len(s.settings.PluginOnly))),
			s.kv(s.t("selection.excludeLabel"), fmt.Sprintf("%d", len(s.settings.PluginExclude))),
			s.kv(s.t("selection.onlyList"), s.selectionList(s.settings.PluginOnly)),
			s.kv(s.t("selection.excludeList"), s.selectionList(s.settings.PluginExclude)),
			"",
			s.th.muted(s.t("selection.hint")),
			s.th.muted(fmt.Sprintf(s.t("selection.catalogCount"), len(ids))),
		}
		s.panel(s.th.bold(s.t("selection.title")), s.th.accent, lines...)
		s.println()
		s.printf("  %s  %s\n",
			kb(s.th, "a", s.t("selection.addOnly")),
			kb(s.th, "r", s.t("selection.removeOnly")))
		s.printf("  %s  %s\n",
			kb(s.th, "x", s.t("selection.addExclude")),
			kb(s.th, "u", s.t("selection.removeExclude")))
		s.printf("  %s  %s\n",
			kb(s.th, "l", s.t("selection.list")),
			kb(s.th, "s", s.t("selection.search")))
		s.printf("  %s  %s\n",
			kb(s.th, "c", s.t("selection.clear")),
			kb(s.th, "0", s.t("common.back")))
		action, err := s.readLine(s.t("input.selection") + ": ")
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "0", "b", "back", "geri", "iptal", "cancel":
			return nil
		case "a", "ekle", "add":
			s.selectionAdd(known, false)
		case "r", "cikar", "çıkar", "remove":
			s.selectionRemove(false)
		case "x", "haric", "hariç", "exclude":
			s.selectionAdd(known, true)
		case "u", "unexclude", "dahil":
			s.selectionRemove(true)
		case "l", "list", "liste":
			s.printIDList(s.t("selection.onlyLabel"), s.settings.PluginOnly)
			s.printIDList(s.t("selection.excludeLabel"), s.settings.PluginExclude)
		case "s", "search", "ara":
			query, qerr := s.required(s.t("selection.searchPrompt") + ": ")
			if qerr != nil {
				return qerr
			}
			s.printSearchMatches(strings.ToLower(strings.TrimSpace(query)), ids, names)
		case "c", "clear", "temizle":
			s.settings.PluginOnly = nil
			s.settings.PluginExclude = nil
			s.saveSettings()
			s.println("  " + s.th.good(s.t("selection.cleared")))
		default:
			s.printf("  %s\n", s.th.bad(s.t("common.invalidChoice", action)))
		}
	}
}

func (s *menuSession) selectionAdd(known map[string]bool, exclude bool) {
	raw, err := s.required(s.t("selection.idsPrompt") + ": ")
	if err != nil {
		return
	}
	valid, unknown := validatePluginIDs(splitPluginIDs(raw), known)
	if len(unknown) > 0 {
		s.printf("  %s\n", s.th.warn(s.t("selection.unknown", strings.Join(unknown, ", "))))
	}
	if len(valid) == 0 {
		return
	}
	before := len(s.settings.PluginOnly)
	if exclude {
		before = len(s.settings.PluginExclude)
		s.settings.PluginExclude = mergePluginIDs(s.settings.PluginExclude, valid)
		s.settings.PluginOnly = removePluginIDs(s.settings.PluginOnly, valid)
	} else {
		s.settings.PluginOnly = mergePluginIDs(s.settings.PluginOnly, valid)
		s.settings.PluginExclude = removePluginIDs(s.settings.PluginExclude, valid)
	}
	s.saveSettings()
	after := len(s.settings.PluginOnly)
	if exclude {
		after = len(s.settings.PluginExclude)
	}
	added := after - before
	if added <= 0 {
		s.println("  " + s.th.muted(s.t("selection.unchanged")))
		return
	}
	s.println("  " + s.th.good(fmt.Sprintf(s.t("selection.added"), added)))
}

func (s *menuSession) selectionRemove(exclude bool) {
	raw, err := s.required(s.t("selection.idsPrompt") + ": ")
	if err != nil {
		return
	}
	ids := splitPluginIDs(raw)
	before := len(s.settings.PluginOnly)
	if exclude {
		before = len(s.settings.PluginExclude)
		s.settings.PluginExclude = removePluginIDs(s.settings.PluginExclude, ids)
	} else {
		s.settings.PluginOnly = removePluginIDs(s.settings.PluginOnly, ids)
	}
	s.saveSettings()
	after := len(s.settings.PluginOnly)
	if exclude {
		after = len(s.settings.PluginExclude)
	}
	removed := before - after
	if removed <= 0 {
		s.println("  " + s.th.muted(s.t("selection.unchanged")))
		return
	}
	s.println("  " + s.th.good(fmt.Sprintf(s.t("selection.removed"), removed)))
}

func (s *menuSession) printIDList(title string, ids []string) {
	s.println("  " + s.th.accent(title) + " " + s.th.muted(fmt.Sprintf("(%d)", len(ids))))
	if len(ids) == 0 {
		s.println("    " + s.th.muted(s.t("selection.none")))
		return
	}
	for _, line := range wrapText(strings.Join(ids, ", "), s.boxWidth()-4) {
		s.println("    " + s.th.muted(line))
	}
}

func (s *menuSession) printSearchMatches(query string, ids []string, names map[string]string) {
	if query == "" {
		return
	}
	const limit = 24
	var matches []string
	for _, id := range ids {
		if strings.Contains(id, query) || strings.Contains(strings.ToLower(names[id]), query) {
			matches = append(matches, id)
		}
	}
	if len(matches) == 0 {
		s.println("  " + s.th.warn(s.t("selection.noMatch")))
		return
	}
	shown := matches
	suffix := ""
	if len(shown) > limit {
		suffix = " " + fmt.Sprintf(s.t("selection.more"), len(shown)-limit)
		shown = shown[:limit]
	}
	s.println("  " + s.th.accent(fmt.Sprintf(s.t("selection.matches"), len(matches))))
	for _, id := range shown {
		s.printf("    %s  %s\n", s.th.bold(id), s.th.muted(truncate(names[id], s.boxWidth()-len(id)-8)))
	}
	if suffix != "" {
		s.println("  " + s.th.muted(suffix))
	}
}

// prunePluginSelection removes IDs that disappeared from the catalog, so a
// stale persisted set cannot break the next scan with a CLI validation error.
func (s *menuSession) prunePluginSelection(only, exclude []string) ([]string, []string) {
	if len(only)+len(exclude) == 0 {
		return only, exclude
	}
	ids, _, err := s.catalogPluginIDs()
	if err != nil || len(ids) == 0 {
		return only, exclude
	}
	known := make(map[string]bool, len(ids))
	for _, id := range ids {
		known[id] = true
	}
	validOnly, unknownOnly := validatePluginIDs(only, known)
	validExclude, unknownExclude := validatePluginIDs(exclude, known)
	unknown := append(unknownOnly, unknownExclude...)
	if len(unknown) == 0 {
		return only, exclude
	}
	s.printf("  %s\n", s.th.warn(s.t("selection.stale", strings.Join(unknown, ", "))))
	s.settings.PluginOnly = validOnly
	s.settings.PluginExclude = validExclude
	s.saveSettings()
	return validOnly, validExclude
}

func (s *menuSession) selectionSummary(only, exclude []string) string {
	switch {
	case len(only) > 0 && len(exclude) > 0:
		return fmt.Sprintf(s.t("selection.summaryBoth"), len(only), len(exclude))
	case len(only) > 0:
		return fmt.Sprintf(s.t("selection.summaryOnly"), len(only))
	case len(exclude) > 0:
		return fmt.Sprintf(s.t("selection.summaryExclude"), len(exclude))
	default:
		return s.t("selection.summaryAll")
	}
}

func (s *menuSession) selectionList(ids []string) string {
	if len(ids) == 0 {
		return s.t("selection.none")
	}
	const max = 18
	shown := ids
	suffix := ""
	if len(shown) > max {
		suffix = " " + fmt.Sprintf(s.t("selection.more"), len(shown)-max)
		shown = shown[:max]
	}
	return truncate(strings.Join(shown, ", ")+suffix, s.boxWidth()-20)
}

func (s *menuSession) saveSettings() {
	if err := saveMenuSettings(s.settings); err != nil {
		s.printf("  %s\n", s.th.bad(s.t("settings.saveFailed", err.Error())))
		return
	}
	s.println("  " + s.th.good(s.t("settings.saved")))
}

// catalogPluginIDs loads the discovered catalog for selection/search.
func (s *menuSession) catalogPluginIDs() ([]string, map[string]string, error) {
	root := menuRepoRoot()
	if root == "" {
		root = "."
	}
	dirs := []string{filepath.Join(root, "plugins")}
	if home, herr := os.UserHomeDir(); herr == nil && home != "" {
		dirs = append(dirs, filepath.Join(home, ".gash", "plugins"))
	}
	if extra := os.Getenv("GASH_PLUGIN_PATH"); extra != "" {
		sep := string(os.PathListSeparator)
		for _, part := range strings.Split(extra, sep) {
			if strings.TrimSpace(part) != "" {
				dirs = append(dirs, part)
			}
		}
	}
	var existing []string
	for _, dir := range dirs {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			existing = append(existing, dir)
		}
	}
	if len(existing) == 0 {
		return nil, nil, nil
	}
	reg := plugin.NewRegistry()
	if _, err := loader.Discover(existing, reg); err != nil {
		return nil, nil, err
	}
	specs := reg.Specs()
	ids := make([]string, 0, len(specs))
	names := make(map[string]string, len(specs))
	for _, spec := range specs {
		ids = append(ids, spec.ID)
		names[spec.ID] = spec.Name
	}
	sort.Strings(ids)
	return ids, names, nil
}

func validatePluginIDs(ids []string, known map[string]bool) (valid, unknown []string) {
	for _, id := range ids {
		if known[id] {
			valid = append(valid, id)
		} else {
			unknown = append(unknown, id)
		}
	}
	return valid, unknown
}

func mergePluginIDs(existing, add []string) []string {
	return normalizePluginIDs(append(append([]string{}, existing...), add...))
}

func removePluginIDs(existing, remove []string) []string {
	drop := make(map[string]bool, len(remove))
	for _, id := range remove {
		drop[id] = true
	}
	var out []string
	for _, id := range normalizePluginIDs(existing) {
		if !drop[id] {
			out = append(out, id)
		}
	}
	return out
}
