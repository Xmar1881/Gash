// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func runMenu(t *testing.T, input string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runInteractiveMenu(strings.NewReader(input), &out)
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
	out, err := runMenu(t, "9\nq\n")
	if err != nil {
		t.Fatalf("menu invalid choice: %v", err)
	}
	if !strings.Contains(out, `Geçersiz seçim: "9"`) {
		t.Fatalf("invalid choice not reported:\n%s", out)
	}
}

func TestMenuCommandConsole(t *testing.T) {
	out, err := runMenu(t, "7\nplugins --help\nmenu\nq\n")
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
	out, err := runMenu(t, "7\ngash --help\nmenu\nq\n")
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
		{"3 benchmark", "3\n0\nq\n", "Dataset doğrula"},
		{"4 openapi", "4\niptal\nq\n", "Spec dosyası veya http(s) URL"},
		{"5 diff", "5\niptal\nq\n", "Eski/baseline JSON raporu"},
		{"6 suppress", "6\n0\nq\n", "Suppress yönetimi"},
		{"7 konsol", "7\nmenu\nq\n", "Komut terminali"},
		{"8 yardım", "8\nq\n", "Klavye kısayolları"},
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
