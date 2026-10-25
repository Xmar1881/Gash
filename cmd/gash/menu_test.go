// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package main

import (
	"bytes"
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
