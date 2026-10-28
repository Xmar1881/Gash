// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runMenu(t *testing.T, input string) (string, error) {
	t.Helper()
	t.Setenv("GASH_LANG", "tr")
	t.Setenv("GASH_MENU_SETTINGS", filepath.Join(t.TempDir(), "menu-settings.json"))
	var out bytes.Buffer
	err := runInteractiveMenu(strings.NewReader(input), &out)
	return out.String(), err
}

// runMenuWithSettings keeps one settings file across multiple menu sessions.
func runMenuWithSettings(t *testing.T, settingsPath, input string) (string, error) {
	t.Helper()
	t.Setenv("GASH_LANG", "tr")
	t.Setenv("GASH_MENU_SETTINGS", settingsPath)
	var out bytes.Buffer
	err := runInteractiveMenu(strings.NewReader(input), &out)
	return out.String(), err
}

// runMenuLang: menüyü --lang bayrağıyla belirtilen dilde çalıştırır.
func runMenuLang(t *testing.T, langFlag, input string) (string, error) {
	t.Helper()
	t.Setenv("GASH_MENU_SETTINGS", filepath.Join(t.TempDir(), "menu-settings.json"))
	var out bytes.Buffer
	err := runInteractiveMenuLang(strings.NewReader(input), &out, langFlag)
	return out.String(), err
}

func TestMenuCommandRegistered(t *testing.T) {
	root := newRoot()
	cmd, _, err := root.Find([]string{"menu"})
	if err != nil {
		t.Fatalf("find menu command: %v", err)
	}
	if cmd.Name() != "menu" {
		t.Fatalf("menu command = %q, want menu", cmd.Name())
	}
}

func TestMenuExit(t *testing.T) {
	out, err := runMenu(t, "q\n")
	if err != nil {
		t.Fatalf("menu exit: %v", err)
	}
	for _, want := range []string{"GASH", "Tarama", "Görüşürüz."} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

// TestMenuShowsLogo pins the main-menu wordmark so a chrome refactor cannot
// silently drop it.
func TestMenuShowsLogo(t *testing.T) {
	out, err := runMenu(t, "q\n")
	if err != nil {
		t.Fatalf("menu logo: %v", err)
	}
	if !strings.Contains(out, "██████╗") || !strings.Contains(out, "GASH") {
		t.Fatalf("main menu must show the GASH wordmark:\n%s", out)
	}
}

// TestMenuSettingsDefaultProfileProxy: persisted defaults are offered by the
// scan flow without extra prompts and reach the command preview.
func TestMenuSettingsDefaultProfileProxy(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "menu-settings.json")
	if err := os.WriteFile(settingsPath, []byte(`{"profile":"safe","proxy_mode":"off"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runMenuWithSettings(t, settingsPath, "1\nhttp://127.0.0.1\n\n\n\n\nh\nq\n")
	if err != nil {
		t.Fatalf("scan with settings defaults: %v", err)
	}
	for _, want := range []string{"--profile safe", "--no-proxy"} {
		if !strings.Contains(out, want) {
			t.Fatalf("scan preview missing %q:\n%s", want, out)
		}
	}
}

// TestMenuSelectionPersistsAndScanUsesIt: the Plugins tab editor writes the
// only-list to disk and the next scan flow adds --only-plugin.
func TestMenuSelectionPersistsAndScanUsesIt(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "menu-settings.json")
	out, err := runMenuWithSettings(t, settingsPath, "2\ns\na\nmissing-security-headers\n0\n0\nq\n")
	if err != nil {
		t.Fatalf("selection editor: %v", err)
	}
	if !strings.Contains(out, "1 plugin eklendi") {
		t.Fatalf("selection add acknowledgement missing:\n%s", out)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved menuSettings
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.PluginOnly) != 1 || saved.PluginOnly[0] != "missing-security-headers" {
		t.Fatalf("saved only list = %+v", saved.PluginOnly)
	}

	out, err = runMenuWithSettings(t, settingsPath, "1\nhttp://127.0.0.1\n\nt\n\n\n\nh\nq\n")
	if err != nil {
		t.Fatalf("scan with selection: %v", err)
	}
	if !strings.Contains(out, "--only-plugin missing-security-headers") {
		t.Fatalf("scan command must include --only-plugin:\n%s", out)
	}
	if !strings.Contains(out, "1 seçili") {
		t.Fatalf("scan summary must show the selection:\n%s", out)
	}
}

// TestMenuSettingsPersistLogo: the Settings screen toggles the persisted logo
// and the next session starts without the wordmark.
func TestMenuSettingsPersistLogo(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "menu-settings.json")
	out, err := runMenuWithSettings(t, settingsPath, "2\ng\ng\n0\n0\nq\n")
	if err != nil {
		t.Fatalf("settings flow: %v", err)
	}
	if !strings.Contains(out, "Ayar kaydedildi") {
		t.Fatalf("settings save acknowledgement missing:\n%s", out)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved menuSettings
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.ShowLogo == nil || *saved.ShowLogo {
		t.Fatalf("show_logo must persist as false: %+v", saved.ShowLogo)
	}
	out, err = runMenuWithSettings(t, settingsPath, "q\n")
	if err != nil {
		t.Fatalf("menu with logo off: %v", err)
	}
	if strings.Contains(out, "██████╗") {
		t.Fatalf("logo must be hidden when show_logo=false:\n%s", out)
	}
}

// TestMenuLogoAnimationGuard keeps animation out of pipes, tests, and the
// explicit opt-out while leaving it on for interactive color terminals.
func TestMenuLogoAnimationGuard(t *testing.T) {
	t.Setenv("GASH_NO_ANIMATION", "")
	s := &menuSession{th: theme{tty: true, color: true}}
	if !s.logoAnimationEnabled() {
		t.Fatal("interactive color terminal must animate")
	}
	s.th = theme{tty: true, color: false}
	if s.logoAnimationEnabled() {
		t.Fatal("NO_COLOR/dumb terminal must stay static")
	}
	s.th = theme{tty: false, color: true}
	if s.logoAnimationEnabled() {
		t.Fatal("piped output must stay static")
	}
	t.Setenv("GASH_NO_ANIMATION", "1")
	s.th = theme{tty: true, color: true}
	if s.logoAnimationEnabled() {
		t.Fatal("GASH_NO_ANIMATION=1 must disable animation")
	}
}

func TestMenuLogoHighlightFrame(t *testing.T) {
	s := &menuSession{th: theme{color: true, truecolor: true}}
	base := s.logoLine(0, gashLogoLines[0], false)
	if !strings.Contains(base, "139;92;246") {
		t.Fatalf("base frame must use the brand gradient: %q", base)
	}
	hot := s.logoLine(0, gashLogoLines[0], true)
	if !strings.Contains(hot, "236;254;255") {
		t.Fatalf("highlight frame must use the bright sweep color: %q", hot)
	}
}

// TestPrintLogoAnimatesOnTTY exercises the real animation path once and pins
// the in-place repaint escape plus the final static frame.
func TestPrintLogoAnimatesOnTTY(t *testing.T) {
	t.Setenv("GASH_NO_ANIMATION", "")
	var out bytes.Buffer
	s := &menuSession{out: &out, th: theme{tty: true, color: true, truecolor: true}}
	s.printLogo()
	got := out.String()
	if !strings.Contains(got, "\033[6A") {
		t.Fatalf("animated logo must repaint in place:\n%q", got)
	}
	if !strings.Contains(got, "236;254;255") {
		t.Fatalf("animated logo must contain the bright sweep frame:\n%q", got)
	}
	if !strings.Contains(got, "139;92;246") {
		t.Fatalf("animated logo must settle on the static gradient:\n%q", got)
	}
}

func TestMenuEOFExitsCleanly(t *testing.T) {
	out, err := runMenu(t, "")
	if err != nil {
		t.Fatalf("menu EOF: %v", err)
	}
	if !strings.Contains(out, "Görüşürüz.") {
		t.Fatalf("EOF should end the menu cleanly:\n%s", out)
	}
}

func TestMenuInvalidChoice(t *testing.T) {
	out, err := runMenu(t, "10\nq\n")
	if err != nil {
		t.Fatalf("menu invalid choice: %v", err)
	}
	if !strings.Contains(out, `Geçersiz seçim: "10"`) {
		t.Fatalf("invalid choice not reported:\n%s", out)
	}
}

func TestMenuCommandConsole(t *testing.T) {
	out, err := runMenu(t, "4\nplugins --help\nmenu\nq\n")
	if err != nil {
		t.Fatalf("menu command console: %v", err)
	}
	if !strings.Contains(out, "Komut terminali") {
		t.Fatalf("console banner missing:\n%s", out)
	}
	if !strings.Contains(out, "Plugin yönetimi") {
		t.Fatalf("console command did not run:\n%s", out)
	}
	if !strings.Contains(out, "Görüşürüz.") {
		t.Fatalf("menu did not exit after console:\n%s", out)
	}
}

func TestMenuCommandConsoleAcceptsGashPrefix(t *testing.T) {
	out, err := runMenu(t, "4\ngash --help\nmenu\nq\n")
	if err != nil {
		t.Fatalf("menu command console: %v", err)
	}
	if !strings.Contains(out, "Usage:") {
		t.Fatalf("gash-prefixed command did not run:\n%s", out)
	}
}

func TestMenuScanInvalidProfile(t *testing.T) {
	out, err := runMenu(t, "1\nhttp://127.0.0.1\n\nbogus\nq\n")
	if err != nil {
		t.Fatalf("menu scan flow: %v", err)
	}
	if !strings.Contains(out, `Geçersiz profil: "bogus"`) {
		t.Fatalf("invalid profile not rejected:\n%s", out)
	}
	if strings.Contains(out, "Tarama başlatılıyor") {
		t.Fatalf("invalid profile must not start a scan:\n%s", out)
	}
}

func TestMenuAggressiveScanRequiresConfirmation(t *testing.T) {
	out, err := runMenu(t, "1\nhttp://127.0.0.1\n\naggressive\nhayır\nq\n")
	if err != nil {
		t.Fatalf("menu aggressive flow: %v", err)
	}
	if !strings.Contains(out, "Tarama iptal edildi.") {
		t.Fatalf("aggressive scan was not cancelled:\n%s", out)
	}
	if strings.Contains(out, "Tarama başlatılıyor") {
		t.Fatalf("cancelled aggressive scan must not start:\n%s", out)
	}
}

// TestMenuAllTabsReachable: her sekme açılabilmeli ve akış paneli görünmeli.
// What: Sekme numarasını verip akışı iptal/geri ile kapatır.
// Why: Menüye eklenen bir sekme akışına bağlanmazsa bu test kırılır.
func TestMenuAllTabsReachable(t *testing.T) {
	for _, tc := range []struct {
		tab    string
		input  string
		marker string
	}{
		{"1 tarama", "1\niptal\nq\n", "Hedef URL"},
		{"2 pluginler", "2\n0\nq\n", "Plugin yönetimi"},
		{"3 araçlar", "3\n0\nq\n", "Dataset doğrula"},
		{"4 konsol", "4\nmenu\nq\n", "Komut terminali"},
		{"5 durum", "5\n0\nq\n", "Sistem durumu"},
		{"6 yardım", "6\nq\n", "Klavye kısayolları"},
	} {
		t.Run(tc.tab, func(t *testing.T) {
			out, err := runMenu(t, tc.input)
			if err != nil {
				t.Fatalf("menu tab %s: %v", tc.tab, err)
			}
			if !strings.Contains(out, tc.marker) {
				t.Fatalf("tab %s akışına bağlı değil (%q yok):\n%s", tc.tab, tc.marker, out)
			}
			if !strings.Contains(out, "Görüşürüz.") {
				t.Fatalf("tab %s sonrası menü temiz kapanmadı:\n%s", tc.tab, out)
			}
		})
	}
}

// TestMenuFlowEntrypoints: komut satırından açılan akışlar "iptal"/EOF'u hata
// olarak raporlamamalı.
// What: Her run*Menu girişini kısa girdiyle çalıştırır.
// Why: Akış girişleri ortak runFlow sarmalayıcısını paylaşmalı; aksi halde
// `gash scan` (ve benzeri) iptalde hata mesajı basar.
func TestMenuFlowEntrypoints(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(io.Reader, io.Writer) error
	}{
		{"plugins", runPluginsMenu},
		{"bench", runBenchMenu},
		{"openapi", runOpenAPIMenu},
		{"diff", runDiffMenu},
		{"suppress", runSuppressMenu},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := tc.run(strings.NewReader("iptal\n"), &out); err != nil {
				t.Fatalf("%s akış girişi iptalde hata döndürdü: %v", tc.name, err)
			}
		})
	}
}

// TestMenuScanEverythingPreset: "HER ŞEY" seçimi tek adımda tüm aktif
// denetimleri (tarayıcı + altyapı derin + OOB) komuta eklemeli.
// What: Profil listesinden 5'i seçip özet komutunu doğrular.
// Why: Kullanıcı uzun bayrak listesi yazmak zorunda kalmamalı.
func TestMenuScanEverythingPreset(t *testing.T) {
	out, err := runMenu(t, "1\nhttp://127.0.0.1\n\n5\ne\n\nh\nq\n")
	if err != nil {
		t.Fatalf("menu scan everything: %v", err)
	}
	if !strings.Contains(out, "Çalıştırılacak işlem:") {
		t.Fatalf("özet komutu basılmadı:\n%s", out)
	}
	for _, want := range []string{
		"--aggressive", "--browser-crawl", "--browser-verify",
		"--ssh-audit", "--db-port-scan", "--tls-audit-deep",
		"--ssh-handshake-audit", "--db-unauth", "--oob-server local",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HER ŞEY komutu %q içermeli:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Tarama başlatılıyor") {
		t.Fatalf("onay 'hayır' iken tarama başlamamalı:\n%s", out)
	}
}

// TestMenuScanUsesAutoProxy: proxy bayrağı verilmese de yerel liste otomatik
// kullanılmalı ve özet komutunda görünmeli.
func TestMenuScanUsesAutoProxy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alive.txt")
	if err := os.WriteFile(path, []byte("http://127.0.0.1:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GASH_PROXY_FILE", path)
	out, err := runMenu(t, "1\nhttp://127.0.0.1\n\n3\n\n\nh\nq\n")
	if err != nil {
		t.Fatalf("menu auto proxy: %v", err)
	}
	for _, want := range []string{"--proxy-file", path, "Proxy"} {
		if !strings.Contains(out, want) {
			t.Fatalf("otomatik proxy komutu %q içermeli:\n%s", want, out)
		}
	}
}

// TestMenuEverythingUsesPerRequestProxy: HER ŞEY modunda proxy her istekte
// dönmeli (IP engeline karşı) ve daha uzun cooldown taşımalı.
func TestMenuEverythingUsesPerRequestProxy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alive.txt")
	if err := os.WriteFile(path, []byte("http://127.0.0.1:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GASH_PROXY_FILE", path)
	out, err := runMenu(t, "1\nhttp://127.0.0.1\n\n5\ne\n\nh\nq\n")
	if err != nil {
		t.Fatalf("menu everything proxy: %v", err)
	}
	for _, want := range []string{"--proxy-file", path, "--proxy-rotate per-request", "--proxy-cooldown 45s"} {
		if !strings.Contains(out, want) {
			t.Fatalf("HER ŞEY proxy komutu %q içermeli:\n%s", want, out)
		}
	}
}

func TestSplitCommandLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{
			name: "simple",
			line: "scan --target https://example.test",
			want: []string{"scan", "--target", "https://example.test"},
		},
		{
			name: "double quotes",
			line: `scan --auth-header "X-Test: a b" --cookie "a=b; c=d"`,
			want: []string{"scan", "--auth-header", "X-Test: a b", "--cookie", "a=b; c=d"},
		},
		{
			name: "single quotes",
			line: `plugins new 'my plugin' --tier js`,
			want: []string{"plugins", "new", "my plugin", "--tier", "js"},
		},
		{
			name: "windows paths",
			line: `diff --old "C:\dev\Gash\old.json" --new 'C:\dev\Gash\new.json'`,
			want: []string{"diff", "--old", `C:\dev\Gash\old.json`, "--new", `C:\dev\Gash\new.json`},
		},
		{
			name: "empty quoted argument",
			line: `scan --target ""`,
			want: []string{"scan", "--target", ""},
		},
		{
			name: "surrounding whitespace",
			line: "  plugins   list  ",
			want: []string{"plugins", "list"},
		},
		{
			name: "empty line",
			line: "",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := splitCommandLine(tt.line)
			if err != nil {
				t.Fatalf("splitCommandLine(%q): %v", tt.line, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("splitCommandLine(%q) = %#v, want %#v", tt.line, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("splitCommandLine(%q)[%d] = %q, want %q", tt.line, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSplitCommandLineUnterminatedQuote(t *testing.T) {
	if _, err := splitCommandLine(`scan --target "https://example.test`); err == nil {
		t.Fatal("expected unterminated quote error")
	}
}

// TestMenuEnglishLanguage: --lang en ile tüm arayüz İngilizce olmalı.
func TestMenuEnglishLanguage(t *testing.T) {
	out, err := runMenuLang(t, "en", "6\nq\n")
	if err != nil {
		t.Fatalf("menu en: %v", err)
	}
	for _, want := range []string{
		"Scan", "Plugins", "Console", "Legal notice", "Goodbye.",
		"Scan a target", "Plugin management", "Interactive menu",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("EN arayüzde %q yok:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Görüşürüz.") {
		t.Fatalf("EN arayüzde TR metni kaldı:\n%s", out)
	}
}

// TestMenuLanguageToggle: 'l' kısayolu TR ⇄ EN geçişini anında uygulamalı.
func TestMenuLanguageToggle(t *testing.T) {
	out, err := runMenuLang(t, "en", "l\nq\n")
	if err != nil {
		t.Fatalf("menu toggle: %v", err)
	}
	if !strings.Contains(out, "Arayüz dili: Türkçe (TR)") {
		t.Fatalf("dil geçişi bildirilmedi:\n%s", out)
	}
	if !strings.Contains(out, "Görüşürüz.") {
		t.Fatalf("geçiş sonrası TR çıkış mesajı yok:\n%s", out)
	}
}

// TestMenuKeyShortcuts: her sekme numara yanında tek harflik kısayolla da açılmalı.
func TestMenuKeyShortcuts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  string
		marker string
	}{
		{"scan", "s\niptal\nq\n", "Hedef URL"},
		{"plugins", "p\n0\nq\n", "Plugin yönetimi"},
		{"tools", "t\n0\nq\n", "Dataset doğrula"},
		{"bench", "b\n0\nq\n", "Dataset doğrula"},
		{"openapi", "o\niptal\nq\n", "Spec dosyası veya http(s) URL"},
		{"diff", "d\niptal\nq\n", "Eski/baseline JSON raporu"},
		{"suppress", "x\n0\nq\n", "Suppress yönetimi"},
		{"console", "c\nmenu\nq\n", "Komut terminali"},
		{"help", "h\nq\n", "Klavye kısayolları"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runMenu(t, tc.input)
			if err != nil {
				t.Fatalf("kısayol %s: %v", tc.name, err)
			}
			if !strings.Contains(out, tc.marker) {
				t.Fatalf("%s kısayolu akışı açmadı (%q yok):\n%s", tc.name, tc.marker, out)
			}
			if !strings.Contains(out, "Görüşürüz.") {
				t.Fatalf("%s sonrası menü temiz kapanmadı:\n%s", tc.name, out)
			}
		})
	}
}

// TestMenuSubmenuKeys: alt menü işlemleri tek harflik kısayolla da seçilebilmeli.
func TestMenuSubmenuKeys(t *testing.T) {
	out, err := runMenu(t, "x\ne\niptal\n0\nq\n")
	if err != nil {
		t.Fatalf("alt menü kısayolu: %v", err)
	}
	if !strings.Contains(out, "Finding ID") {
		t.Fatalf("'e' kısayolu Ekle akışını açmadı:\n%s", out)
	}
	if !strings.Contains(out, "İptal edildi.") {
		t.Fatalf("iptal sonrası alt menüye dönülmedi:\n%s", out)
	}
}

// TestMenuChoiceKeyEverything: profil listesi 'e' kısayoluyla HER ŞEY profilini
// seçmeli (numara yazmadan).
func TestMenuChoiceKeyEverything(t *testing.T) {
	out, err := runMenu(t, "1\nhttp://127.0.0.1\n\ne\ne\n\nh\nq\n")
	if err != nil {
		t.Fatalf("profil kısayolu: %v", err)
	}
	for _, want := range []string{"--aggressive", "--browser-crawl", "--browser-verify", "--oob-server local"} {
		if !strings.Contains(out, want) {
			t.Fatalf("HER ŞEY komutu %q içermeli:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "Tarama iptal edildi.") {
		t.Fatalf("başlatma onayı 'hayır' iken tarama iptal edilmeli:\n%s", out)
	}
}

// TestMenuScanAutoReport: rapor dosyası boş bırakılırsa ("boş=otomatik")
// tarama yine diske rapor yazmalı.
// What: deep profil + boş rapor alanı → komuta --output-dir/--format eklenir.
// Why: Etiket "otomatik" diyordu ama hiç dosya üretilmiyordu.
func TestMenuScanAutoReport(t *testing.T) {
	out, err := runMenu(t, "1\nhttp://127.0.0.1\n\n3\n\n\nh\nq\n")
	if err != nil {
		t.Fatalf("menu scan auto report: %v", err)
	}
	for _, want := range []string{"--output-dir reports", "--format json", "--format text", "--report-stamp", "otomatik (reports/ · json + text · zaman damgalı)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("otomatik rapor komutu %q içermeli:\n%s", want, out)
		}
	}
	if strings.Contains(out, "--output ") {
		t.Fatalf("boş rapor alanında --output kullanılmamalı:\n%s", out)
	}
}

// TestMenuScanSummaryShowsProfileBudget: the pre-scan summary must state the
// limits the engine will enforce, read from the same config profiles.
func TestMenuScanSummaryShowsProfileBudget(t *testing.T) {
	out, err := runMenu(t, "1\nhttp://127.0.0.1\n\nt\n\n\nh\nq\n")
	if err != nil {
		t.Fatalf("menu scan budget summary: %v", err)
	}
	if !strings.Contains(out, "Bütçe") {
		t.Fatalf("summary must label the budget line:\n%s", out)
	}
	if !strings.Contains(out, "2000/hedef · 10 istek/sn · 50 sayfa · derinlik 3") {
		t.Fatalf("summary must show the standard profile limits:\n%s", out)
	}
}

// TestMenuStatusShowsEngineTuning: the status tab surfaces engine defaults
// (request budget and WAF mutation ceiling) instead of hiding them in docs.
func TestMenuStatusShowsEngineTuning(t *testing.T) {
	out, err := runMenu(t, "5\n0\nq\n")
	if err != nil {
		t.Fatalf("menu status engine line: %v", err)
	}
	if !strings.Contains(out, "Motor") || !strings.Contains(out, "WAF 28 varyant") {
		t.Fatalf("status must show engine tuning:\n%s", out)
	}
}

// TestMenuScanOutputFormat: a typed report path selects the matching writer
// instead of writing the default text body into report.json.
func TestMenuScanOutputFormat(t *testing.T) {
	out, err := runMenu(t, "1\nhttp://127.0.0.1\n\nt\nreport.json\nn\nh\nq\n")
	if err != nil {
		t.Fatalf("menu scan output format: %v", err)
	}
	if !strings.Contains(out, "--output report.json --format json") {
		t.Fatalf("json output must select --format json:\n%s", out)
	}
}

// TestMenuStatusViewerRefusesNonText ensures the "view latest" action never
// dumps raw JSON/HTML into the terminal; it names the file instead.
func TestMenuStatusViewerRefusesNonText(t *testing.T) {
	t.Setenv("GASH_MENU_SETTINGS", filepath.Join(t.TempDir(), "menu-settings.json"))
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(jsonPath, []byte(`{"findings":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s := newMenuSession(strings.NewReader(""), &out, uiLangTR)
	s.showLatestReport([]string{jsonPath})
	if !strings.Contains(out.String(), "text raporu yok") || !strings.Contains(out.String(), "report.json") {
		t.Fatalf("non-text report must not be dumped: %q", out.String())
	}
}

// TestMenuSuppressRemoveNeedsConfirmation protects the destructive action.
func TestMenuSuppressRemoveNeedsConfirmation(t *testing.T) {
	out, err := runMenu(t, "x\nk\nF-123\nn\n0\nq\n")
	if err != nil {
		t.Fatalf("suppress remove confirmation: %v", err)
	}
	if !strings.Contains(out, "Bu suppress kaydı kaldırılsın mı?") {
		t.Fatalf("remove confirmation missing:\n%s", out)
	}
	if !strings.Contains(out, "İptal edildi.") {
		t.Fatalf("declined removal must report the cancellation:\n%s", out)
	}
}

func TestMenuMessagesComplete(t *testing.T) {
	for key, m := range menuMessages {
		if strings.TrimSpace(m.tr) == "" || strings.TrimSpace(m.en) == "" {
			t.Fatalf("eksik çeviri: %q (tr=%q en=%q)", key, m.tr, m.en)
		}
	}
}

// TestMenuLocaleParity: locales/tr.json ve locales/en.json aynı anahtar
// kümesine sahip olmalı; eksik anahtar sessizce anahtar adı olarak görünür.
func TestMenuLocaleParity(t *testing.T) {
	load := func(l uiLang) map[string]string {
		raw, err := locales.ReadFile("locales/" + string(l) + ".json")
		if err != nil {
			t.Fatalf("%s katalogu okunamadı: %v", l, err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("%s katalogu ayrıştırılamadı: %v", l, err)
		}
		delete(m, "_meta")
		return m
	}
	tr, en := load(uiLangTR), load(uiLangEN)
	for k := range tr {
		if _, ok := en[k]; !ok {
			t.Fatalf("en.json'da eksik anahtar: %q", k)
		}
	}
	for k := range en {
		if _, ok := tr[k]; !ok {
			t.Fatalf("tr.json'da eksik anahtar: %q", k)
		}
	}
}

// TestDetectLang: dil çözümleme sırası ve tanınmayan değerler doğrulanır.
func TestDetectLang(t *testing.T) {
	t.Setenv("GASH_LANG", "")
	t.Setenv("LANG", "tr_TR.UTF-8")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	if got := detectLang(""); got != uiLangTR {
		t.Fatalf("detectLang(LANG=tr) = %q, want tr", got)
	}
	if got := detectLang("en"); got != uiLangEN {
		t.Fatalf("açık bayrak EN'i geçmeli, got %q", got)
	}
	t.Setenv("LANG", "")
	if got := detectLang("auto"); got != uiLangTR {
		t.Fatalf("tanınmayan değerde varsayılan TR olmalı, got %q", got)
	}
}

// TestMenuScanBulkTargetFile: a file path is detected as a bulk target list.
func TestMenuScanBulkTargetFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(file, []byte("http://127.0.0.1\nhttp://127.0.0.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runMenu(t, "1\n"+file+"\n2\n\n\n\nh\nq\n")
	if err != nil {
		t.Fatalf("menu bulk scan: %v", err)
	}
	for _, want := range []string{"--target-file", file, "Hedef dosya", "--output-dir reports"} {
		if !strings.Contains(out, want) {
			t.Fatalf("bulk scan command %q içermeli:\n%s", want, out)
		}
	}
}

// TestMenuScanAuthHeader: advanced auth header is passed to the scan.
func TestMenuScanAuthHeader(t *testing.T) {
	out, err := runMenu(t, "1\nhttp://127.0.0.1\n\n2\n\ne\n\n\nh\nAuthorization: Bearer tok\n\nn\n\n\nh\nq\n")
	if err != nil {
		t.Fatalf("menu auth scan: %v", err)
	}
	if !strings.Contains(out, "--auth-header") || !strings.Contains(out, "[redacted]") {
		t.Fatalf("auth header command missing or not redacted:\n%s", out)
	}
	if strings.Contains(out, "Bearer tok") {
		t.Fatalf("auth secret leaked into the displayed command:\n%s", out)
	}
}

// TestMenuScanProxyOff: advanced proxy off uses --no-proxy.
func TestMenuScanProxyOff(t *testing.T) {
	out, err := runMenu(t, "1\nhttp://127.0.0.1\n\n2\n\ne\n\no\n\n\nn\n\n\nh\nq\n")
	if err != nil {
		t.Fatalf("menu proxy off: %v", err)
	}
	if !strings.Contains(out, "--no-proxy") {
		t.Fatalf("proxy off did not add --no-proxy:\n%s", out)
	}
}

// TestMenuScanAllowExternal: advanced external toggle adds --allow-external.
func TestMenuScanAllowExternal(t *testing.T) {
	out, err := runMenu(t, "1\nhttp://127.0.0.1\n\n2\n\ne\n\n\n\ne\nn\n\n\nh\nq\n")
	if err != nil {
		t.Fatalf("menu external scan: %v", err)
	}
	if !strings.Contains(out, "--allow-external") {
		t.Fatalf("external toggle missing:\n%s", out)
	}
}

// TestRedactCommandArgs proves credentials never appear in displayed commands.
func TestRedactCommandArgs(t *testing.T) {
	got := strings.Join(redactCommandArgs([]string{
		"scan", "--proxy", "http://user:secretpass@proxy.example:8080",
		"--cookie", "session-secret", "--auth-header=Bearer token123",
		"--oob-token", "oob-secret",
	}), " ")
	for _, secret := range []string{"secretpass", "session-secret", "token123", "oob-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q leaked: %s", secret, got)
		}
	}
	if !strings.Contains(got, "***@proxy.example:8080") {
		t.Fatalf("proxy host should stay visible: %s", got)
	}
}
