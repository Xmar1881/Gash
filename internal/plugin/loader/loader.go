// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package loader üç tier için metadata-tarama (import/execute ETMEDEN) + lazy init sağlar.
// Faz 2'de Tier3 process spawn YOKTUR — yalnızca registry (B10).
package loader

import (
	"fmt"
	"os"
	"runtime"
)

// IsWorldWritable Tier1/2 güvenlik kapısıdır: world-writable dosya/dizin reddedilir.
// Windows'ta Unix permission bitleri anlamlı değildir (ACL modeli); best-effort olarak
// false döner (red kararı Faz 3'te ACL tabanlı sıkılaştırılacaktır).
func IsWorldWritable(path string) (bool, error) {
	if runtime.GOOS == "windows" {
		return false, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if st.Mode().Perm()&0o002 != 0 {
		return true, nil
	}
	return false, nil
}

// CheckNotWorldWritable reddederse açıklayıcı hata döner (uyarı + skip çağırana aittir).
func CheckNotWorldWritable(path string) error {
	ww, err := IsWorldWritable(path)
	if err != nil {
		return err
	}
	if ww {
		return fmt.Errorf("world-writable plugin reddedildi %s", path)
	}
	return nil
}
