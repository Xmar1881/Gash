// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/proxypool"
)

// proxySettings is the validated CLI proxy configuration.
type proxySettings struct {
	URLs     []string
	Rotate   proxypool.Strategy
	Cooldown time.Duration
	// AutoFile is the proxy list picked by automatic discovery, empty when the
	// operator supplied an explicit --proxy/--proxy-file.
	AutoFile string
}

// defaultProxyFile finds the operator's local proxy list for automatic use.
// What: GASH_PROXY_FILE override, then .gash/proxies/alive.txt, then all.txt.
// Why: Scans stop timing out on IP blocks without requiring a flag every run;
// the files live under the gitignored local state directory.
func defaultProxyFile() string {
	if p := strings.TrimSpace(os.Getenv("GASH_PROXY_FILE")); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() > 0 {
			if abs, aerr := filepath.Abs(p); aerr == nil {
				return abs
			}
			return p
		}
		return ""
	}
	for _, p := range []string{
		filepath.Join(".gash", "proxies", "alive.txt"),
		filepath.Join(".gash", "proxies", "all.txt"),
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() > 0 {
			if abs, aerr := filepath.Abs(p); aerr == nil {
				return abs
			}
			return p
		}
	}
	// The menu is often launched from a different working directory; the
	// executable's own directory still carries the local state tree.
	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		for _, name := range []string{"alive.txt", "all.txt"} {
			p := filepath.Join(base, ".gash", "proxies", name)
			if st, serr := os.Stat(p); serr == nil && !st.IsDir() && st.Size() > 0 {
				return p
			}
		}
	}
	return ""
}

// resolveProxySettings merges --proxy with --proxy-file, validates every entry,
// and parses the rotation knobs. A single --proxy is a one-entry pool. When no
// proxy flag is given and auto is true, the local default list is used.
func resolveProxySettings(single, listFile, rotateRaw, cooldownRaw string, auto bool) (proxySettings, error) {
	out := proxySettings{Rotate: proxypool.PerHost, Cooldown: proxypool.DefaultCooldown}

	strategy, err := proxypool.ParseStrategy(rotateRaw)
	if err != nil {
		return out, fmt.Errorf("--proxy-rotate geçersiz: %w", err)
	}
	out.Rotate = strategy

	cooldown, err := time.ParseDuration(strings.TrimSpace(cooldownRaw))
	if err != nil {
		return out, fmt.Errorf("--proxy-cooldown geçersiz: %w", err)
	}
	if cooldown < 0 {
		return out, fmt.Errorf("--proxy-cooldown negatif olamaz: %s", cooldown)
	}
	out.Cooldown = cooldown

	autoFile := ""
	if strings.TrimSpace(single) == "" && strings.TrimSpace(listFile) == "" && auto {
		if p := defaultProxyFile(); p != "" {
			listFile = p
			autoFile = p
		}
	}

	var raw []string
	if strings.TrimSpace(single) != "" {
		raw = append(raw, strings.TrimSpace(single))
	}
	fileEntries, err := readProxyFile(listFile)
	if err != nil {
		if autoFile != "" {
			return out, fmt.Errorf("otomatik proxy listesi %q: %w (--no-proxy ile kapatılabilir)", autoFile, err)
		}
		return out, err
	}
	raw = append(raw, fileEntries...)

	seen := make(map[string]struct{}, len(raw))
	for _, entry := range raw {
		u, perr := proxypool.ParseURL(entry)
		if perr != nil {
			return out, fmt.Errorf("--proxy geçersiz: %w", perr)
		}
		key := u.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out.URLs = append(out.URLs, key)
	}
	out.AutoFile = autoFile
	return out, nil
}

// readProxyFile reads one proxy URL per line; blank lines and # comments are
// skipped. A missing path is only an error when the flag was actually set.
func readProxyFile(path string) ([]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("--proxy-file okunamadı %q: %w", path, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		entry := strings.TrimSpace(sc.Text())
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		out = append(out, entry)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("--proxy-file okuma hatası %q: %w", path, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--proxy-file %q içinde geçerli proxy bulunamadı", path)
	}
	return out, nil
}
