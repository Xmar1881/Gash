// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package loader

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// DiscoverOptions keşif davranışıdır.
type DiscoverOptions struct {
	// BuiltinFirst kayıt sırası determinizmi içindir (built-in önce).
	Builtin []string // gömülü kaynaklar (embed.FS içeriği testlerde dosya olarak verilir)
}

// Discover iki-aşamalı keşfin Aşama 1'idir: yalnızca metadata taranır.
// Tier2'de VM başlatılmaz, Tier3'te binary'ye dokunulmaz (B8/B10).
// Deterministik alfabetik, recursive. World-writable skip edilir (uyarı döndürülür).
func Discover(dirs []string, reg *plugin.Registry) (warnings []string, err error) {
	var files []string
	for _, d := range dirs {
		st, statErr := os.Stat(d)
		if statErr != nil {
			warnings = append(warnings, fmt.Sprintf("discover: %s okunamadı: %v", d, statErr))
			continue
		}
		if !st.IsDir() {
			files = append(files, d)
			continue
		}
		walkErr := filepath.WalkDir(d, func(p string, de fs.DirEntry, e error) error {
			if e != nil {
				return nil // tek dosya hatası keşfi öldürmez
			}
			if de.IsDir() {
				return nil
			}
			lower := strings.ToLower(de.Name())
			if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") ||
				strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".js") ||
				strings.HasSuffix(lower, ".gashplugin.yaml") {
				files = append(files, p)
			}
			return nil
		})
		if walkErr != nil {
			warnings = append(warnings, fmt.Sprintf("discover walk %s: %v", d, walkErr))
		}
	}
	sort.Strings(files)

	for _, f := range files {
		if ww, werr := IsWorldWritable(f); werr == nil && ww {
			warnings = append(warnings, fmt.Sprintf("skip world-writable %s", f))
			continue
		}
		lower := strings.ToLower(f)
		switch {
		case strings.HasSuffix(lower, ".js"):
			spec, lerr := LoadTier2Frontmatter(f)
			if lerr != nil {
				warnings = append(warnings, fmt.Sprintf("skip %s: %v", f, lerr))
				continue
			}
			if rerr := reg.Register(*spec, f, false); rerr != nil {
				warnings = append(warnings, fmt.Sprintf("conflict %s: %v", f, rerr))
			}
		case strings.HasSuffix(lower, ".gashplugin.yaml"):
			spec, _, lerr := LoadTier3Manifest(f)
			if lerr != nil {
				warnings = append(warnings, fmt.Sprintf("skip %s: %v", f, lerr))
				continue
			}
			if rerr := reg.Register(*spec, f, false); rerr != nil {
				warnings = append(warnings, fmt.Sprintf("conflict %s: %v", f, rerr))
			}
		default: // Tier1 yaml/json
			spec, _, lerr := LoadTier1File(f)
			if lerr != nil {
				warnings = append(warnings, fmt.Sprintf("skip %s: %v", f, lerr))
				continue
			}
			if rerr := reg.Register(*spec, f, false); rerr != nil {
				warnings = append(warnings, fmt.Sprintf("conflict %s: %v", f, rerr))
			}
		}
	}
	return warnings, nil
}
