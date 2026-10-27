// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

// ─────────────────────────────────────────────────────────────────────────────
// Arayüz dilleri
// ─────────────────────────────────────────────────────────────────────────────

// uiLang: menü arayüzünün dilini temsil eder. Varsayılan TR'dir.
type uiLang string

const (
	uiLangTR uiLang = "tr"
	uiLangEN uiLang = "en"
)

// supportedLangs: kataloğu yüklenecek diller; yeni dil buraya ve
// locales/<kod>.json dosyasına eklenir.
var supportedLangs = []uiLang{uiLangTR, uiLangEN}

// other: dilin karşıtını döndürür; menüdeki 'l' kısayolu bunu kullanır.
func (l uiLang) other() uiLang {
	if l == uiLangEN {
		return uiLangTR
	}
	return uiLangEN
}

// String: kullanıcıya gösterilen kısa dil kodu.
func (l uiLang) String() string {
	if l == uiLangEN {
		return "EN"
	}
	return "TR"
}

// detectLang: dili sırayla açık bayrak (--lang), GASH_LANG, LC_ALL, LC_MESSAGES
// ve LANG üzerinden çözer; tanınmayan veya boş değerlerde TR'ye döner.
// What: "en*" EN'e, "tr*" TR'ye eşlenir; "auto" yok sayılır.
// Why: Menü TR/EN destekler, ancak varsayılan davranış değişmemelidir.
func detectLang(explicit string) uiLang {
	candidates := []string{
		explicit,
		os.Getenv("GASH_LANG"),
		os.Getenv("LC_ALL"),
		os.Getenv("LC_MESSAGES"),
		os.Getenv("LANG"),
	}
	for _, candidate := range candidates {
		v := strings.ToLower(strings.TrimSpace(candidate))
		switch {
		case v == "":
			continue
		case strings.HasPrefix(v, "en"):
			return uiLangEN
		case strings.HasPrefix(v, "tr"):
			return uiLangTR
		}
	}
	return uiLangTR
}

// localized: bir arayüz metninin TR ve EN karşılığı.
type localized struct {
	tr string
	en string
}

// msg: anahtarı verilen dilde çözer. Bilinmeyen anahtar olduğu gibi döner;
// böylece eksik çeviri sessizce boş satır üretmez, görünür olur.
func msg(l uiLang, key string, args ...any) string {
	m, ok := menuMessages[key]
	if !ok {
		return key
	}
	text := m.tr
	if l == uiLangEN {
		text = m.en
	}
	if len(args) > 0 {
		return fmt.Sprintf(text, args...)
	}
	return text
}

// t: oturumun diline göre metni çözer.
func (s *menuSession) t(key string, args ...any) string { return msg(s.lang, key, args...) }

// activeUILang is the process-wide language for non-session surfaces such as
// the scan spinner. The menu updates it when the user toggles languages; CLI
// commands fall back to --lang/GASH_LANG/OS locale via detectLang.
var activeUILang atomic.Value

func setActiveUILang(l uiLang) { activeUILang.Store(l) }

func currentUILang() uiLang {
	if v, ok := activeUILang.Load().(uiLang); ok {
		return v
	}
	return detectLang("")
}

// ─────────────────────────────────────────────────────────────────────────────
// Metin katalogları (gömülü JSON dil dosyaları)
// ─────────────────────────────────────────────────────────────────────────────

// locales: dil dosyaları ikiliye gömülür; çalışma anında diskten okunmaz.
// Her dosya düz bir "anahtar": "metin" eşlemesidir; "_" ile başlayan anahtarlar
// (örn. "_meta") açıklama satırı sayılır ve yüklenmez.
//
//go:embed locales/tr.json locales/en.json
var locales embed.FS

// menuMessages: arayüz metinlerinin tam kataloğu (anahtar → TR/EN).
var menuMessages = loadMessages()

// loadMessages: gömülü dil dosyalarını okur. Dosyalar derlemeye gömülü
// olduğundan okuma/ayrıştırma hatası bir yapı hatasıdır; boş arayüz yerine
// gürültülü hata tercih edilir.
func loadMessages() map[string]localized {
	msgs := map[string]localized{}
	for _, l := range supportedLangs {
		path := "locales/" + string(l) + ".json"
		raw, err := locales.ReadFile(path)
		if err != nil {
			panic("arayüz dili yüklenemedi (" + path + "): " + err.Error())
		}
		entries := map[string]string{}
		if err := json.Unmarshal(raw, &entries); err != nil {
			panic("arayüz dili ayrıştırılamadı (" + path + "): " + err.Error())
		}
		for key, text := range entries {
			if strings.HasPrefix(key, "_") {
				continue
			}
			m := msgs[key]
			if l == uiLangTR {
				m.tr = text
			} else {
				m.en = text
			}
			msgs[key] = m
		}
	}
	return msgs
}
