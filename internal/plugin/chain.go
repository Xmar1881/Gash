// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"fmt"
	"sort"
	"strings"
)

// ChainInput koşullu zincir çözümlemenin girdisidir (P2.3).
// What: Aday spec'ler + bilinen yetenekler (provides) + tespit edilen teknolojiler.
// Why: requires/provides tek başına statiktir; teknoloji kapısı (örn. wordpress
// tespiti → ilgili dedektör) çalışma-anı bağlamıyla burada birleşir.
type ChainInput struct {
	Specs []PluginSpec
	// Capabilities discovery/recon fazının sağladığı yetenekler
	// (örn. "graphql-endpoint", "login-form"). Boşsa yalnızca spec Provides'tan türetilir.
	Capabilities map[string]bool
	// KnownTech tespit edilen / kullanıcı-beyanlı teknolojiler
	// (örn. "wordpress", "graphql"). requires_tech buraya bakılarak kapılanır.
	KnownTech map[string]bool
}

// ChainResult zincir çözümlemenin çıktısıdır.
type ChainResult struct {
	Runnable []PluginSpec
	Skipped  []SkippedPlugin
}

// ResolveChain koşullu zinciri çözer (fail-open per-plugin, fail-closed per-hata).
// What:
//  1. requires[i] için sağlayıcı yoksa tüketici skip'e düşer (tüm çizelge ölmez);
//     sağlayıcısı da elenen tüketici kaskad skip alır (kararlı nokta aranır).
//  2. requires_tech[i] KnownTech'te yoksa tüketici skip alır
//     (teknoloji tespiti → ilgili dedektör kapısı).
//  3. Kalanlar faz-içi toposort sırasına sokulur (SortByPhase); döngü hatadır.
//
// Why: Eksik bir provides veya tespit edilmemiş bir teknoloji tüm taramayı
// devirmemeli; her eleme denetlenebilir skip sebebiyle rapora girer (sessiz drop yok).
func ResolveChain(in ChainInput) (ChainResult, error) {
	// 1. requires_tech kapısı (teknoloji koşulu).
	techOK := make([]PluginSpec, 0, len(in.Specs))
	var skipped []SkippedPlugin
	for _, s := range in.Specs {
		missing := missingTech(s.RequiresTech, in.KnownTech)
		if len(missing) > 0 {
			skipped = append(skipped, SkippedPlugin{
				PluginID: s.ID,
				Reason:   fmt.Sprintf("skipped (chain: requires tech %s not detected)", strings.Join(missing, ", ")),
			})
			continue
		}
		techOK = append(techOK, s)
	}

	// 2. requires/provides kaskad eleme (kararlı nokta).
	// Yetenek kümesi: açık Capabilities + çalışacak adayların Provides'ı.
	provideCount := make(map[string]int)
	for _, s := range techOK {
		for _, p := range s.Provides {
			provideCount[p]++
		}
	}
	for cap := range in.Capabilities {
		if in.Capabilities[cap] {
			provideCount[cap]++
		}
	}
	alive := make(map[string]bool, len(techOK))
	for _, s := range techOK {
		alive[s.ID] = true
	}
	changed := true
	for changed {
		changed = false
		// Canlı sağlayıcı sayısını yeniden hesapla.
		provideCount = make(map[string]int)
		for _, s := range techOK {
			if !alive[s.ID] {
				continue
			}
			for _, p := range s.Provides {
				provideCount[p]++
			}
		}
		for cap := range in.Capabilities {
			if in.Capabilities[cap] {
				provideCount[cap]++
			}
		}
		for _, s := range techOK {
			if !alive[s.ID] {
				continue
			}
			missing := missingRequires(s.Requires, provideCount, s.ID, techOK)
			if len(missing) > 0 {
				alive[s.ID] = false
				skipped = append(skipped, SkippedPlugin{
					PluginID: s.ID,
					Reason:   fmt.Sprintf("skipped (chain: requires %s has no live provider)", strings.Join(missing, ", ")),
				})
				changed = true
			}
		}
	}

	var runnable []PluginSpec
	for _, s := range techOK {
		if alive[s.ID] {
			runnable = append(runnable, s)
		}
	}
	// 3. Sıralama: faz → order → id + faz-içi toposort (döngü fail-closed).
	ordered, err := SortByPhase(runnable)
	if err != nil {
		return ChainResult{}, err
	}
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].PluginID < skipped[j].PluginID })
	return ChainResult{Runnable: ordered, Skipped: skipped}, nil
}

// missingTech RequiresTech'ten KnownTech'te olmayanları döner (küçük harf normalize).
func missingTech(requiresTech []string, known map[string]bool) []string {
	var out []string
	for _, t := range requiresTech {
		key := strings.ToLower(strings.TrimSpace(t))
		if key == "" {
			continue
		}
		if !known[key] {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// missingRequires requires listesinden canlı sağlayıcısı olmayanları döner.
// What: Kendi provides'ı kendini doyurmaz (self-provide sayılmaz).
// Why: Tüketici, üreten bir akran gerçekten çalışacaksa koşabilir.
func missingRequires(requires []string, liveProvides map[string]int, selfID string, specs []PluginSpec) []string {
	var out []string
	for _, r := range requires {
		n := liveProvides[r]
		// Kendi provides'ı düş (üretici kendisi de canlıysa).
		for _, s := range specs {
			if s.ID == selfID {
				for _, p := range s.Provides {
					if p == r {
						n--
					}
				}
			}
		}
		if n <= 0 {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// NormalizeTech kullanıcı bayrağını (--tech "a, b") kümeye çevirir.
func NormalizeTech(raw []string) map[string]bool {
	out := make(map[string]bool)
	for _, chunk := range raw {
		for _, part := range strings.Split(chunk, ",") {
			if key := strings.ToLower(strings.TrimSpace(part)); key != "" {
				out[key] = true
			}
		}
	}
	return out
}
