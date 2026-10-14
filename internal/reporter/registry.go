// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package reporter

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/Xmar1881/Gash/internal/engine"
)

// Writer tek bir rapor formatının yazıcısıdır.
// What: (w, report, opts) → error sözleşmesi; tüm formatlar buna uyar.
// Why: Yeni format eklemek switch değiştirmek değil Register çağrısıdır (P2.6).
type Writer func(w io.Writer, rep *engine.Report, opts Options) error

var (
	regMu sync.RWMutex
	reg   = make(map[string]Writer)
)

// Register bir format yazıcısını kaydeder (ad küçük harfe normalize edilir).
// What: Genişletilebilir reporter kaydı; tekrar kayıt hata verir.
// Why: Ad çakışması sessiz ezme değil fail-closed olmalı.
func Register(name string, w Writer) error {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return fmt.Errorf("reporter register: boş ad")
	}
	if w == nil {
		return fmt.Errorf("reporter register %q: nil writer", key)
	}
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := reg[key]; dup {
		return fmt.Errorf("reporter register %q: zaten kayıtlı", key)
	}
	reg[key] = w
	return nil
}

// Lookup kayıtlı yazıcıyı döner (bilinmeyen ad → hata, fail-closed).
func Lookup(name string) (Writer, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	regMu.RLock()
	defer regMu.RUnlock()
	w, ok := reg[key]
	if !ok {
		return nil, fmt.Errorf("reporter: bilinmeyen format %q (geçerli: %s)", name, strings.Join(namesLocked(), ", "))
	}
	return w, nil
}

// Names kayıtlı format adlarını sıralı döner.
func Names() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	return namesLocked()
}

func namesLocked() []string {
	out := make([]string, 0, len(reg))
	for n := range reg {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Write adla yazıcıyı çözer ve raporu yazar (CLI'nin tek çağrı noktası).
func Write(name string, w io.Writer, rep *engine.Report, opts Options) error {
	fn, err := Lookup(name)
	if err != nil {
		return err
	}
	return fn(w, rep, opts)
}

func init() {
	// Yerleşik formatlar: kayıt hatası programlama hatasıdır (erken patla).
	mustRegister("json", WriteJSON)
	mustRegister("sarif", WriteSARIF)
	mustRegister("text", WriteText)
	mustRegister("html", WriteHTML)
	mustRegister("junit", WriteJUnit)
}

func mustRegister(name string, fn Writer) {
	if err := Register(name, fn); err != nil {
		panic(err)
	}
}
