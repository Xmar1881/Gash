// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/Xmar1881/Gash/internal/config"
	"github.com/Xmar1881/Gash/internal/headless"
	"github.com/Xmar1881/Gash/internal/wafbypass"
)

var (
	errExitMenu = errors.New("exit interactive menu")
	// errCancel: kullanıcı bir soru sırasında "iptal" yazdı; akış sessizce menüye döner.
	errCancel = errors.New("iptal edildi")
	// errUnterminatedQuote: terminale yazılan komutta kapanmamış tırnak var.
	errUnterminatedQuote = errors.New("unterminated quote")
)

// ─────────────────────────────────────────────────────────────────────────────
// Tipler
// ─────────────────────────────────────────────────────────────────────────────

type menuSession struct {
	in          *bufio.Reader
	out         io.Writer
	rootFactory func() *cobra.Command
	currentTab  int
	tabs        []tab
	lang        uiLang

	th      theme
	width   int               // panel genişliği (kenarlar dahil)
	history []string          // konsolda çalıştırılan komutlar
	last    lastRun           // en son çalıştırılan komutun özeti
	memo    map[string]string // oturum boyunca hatırlanan son değerler
	// settings is loaded once at session start and updated by the Settings
	// and plugin-selection flows; every scan reads the current values.
	settings menuSettings
}

// tab: ana menüdeki bir sekme. name/description/details alanları i18n
// anahtarıdır; key ise tek harflik kısayoldur.
type tab struct {
	key         string
	name        string
	short       string
	description string
	handler     func(*menuSession) error
	icon        string
	details     []string
	aliases     []string
}

type lastRun struct {
	cmd    string
	raw    []string
	took   time.Duration
	failed bool
	valid  bool
}

// menuItem: alt menüdeki bir işlem. label ve desc i18n anahtarı, key kısayoldur.
type menuItem struct {
	key   string
	label string
	desc  string
	run   func() error
}

// choice: numaralı seçenek listesindeki bir madde. key tek harflik kısayoldur.
type choice struct {
	value string
	key   string
	label string
	desc  string
}

func newMenuCmd() *cobra.Command {
	var langFlag string
	helpLang := detectLang("")
	cmd := &cobra.Command{
		Use:     "menu",
		Aliases: []string{"console", "interactive", "shell"},
		Short:   msg(helpLang, "menu.cmd.short"),
		Long:    msg(helpLang, "menu.cmd.long"),
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInteractiveMenuLang(cmd.InOrStdin(), cmd.OutOrStdout(), langFlag)
		},
	}
	cmd.Flags().StringVar(&langFlag, "lang", "auto", msg(helpLang, "menu.langFlag"))
	return cmd
}

func runInteractiveMenu(in io.Reader, out io.Writer) error {
	return runInteractiveMenuLang(in, out, "")
}

// runInteractiveMenuLang: menüyü açık dil tercihiyle (--lang) başlatır.
func runInteractiveMenuLang(in io.Reader, out io.Writer, langFlag string) error {
	s := newMenuSession(in, out, detectLang(langFlag))
	return s.run()
}

func newMenuSession(in io.Reader, out io.Writer, l uiLang) *menuSession {
	setActiveUILang(l)
	return &menuSession{
		in:          bufio.NewReader(in),
		out:         out,
		rootFactory: newRoot,
		lang:        l,
		th:          detectTheme(out),
		width:       detectWidth(),
		memo:        map[string]string{},
		settings:    loadMenuSettings(),
	}
}

// runFlow tek bir menü akışını kendi oturumunda çalıştırır.
// What: `scan`, `plugins`, `bench`, `openapi`, `diff`, `suppress` komutları için ortak giriş.
// Why: Akışı komut satırından açan her komut aynı davranışı paylaşmalı; "iptal"
// veya EOF akış sonu demektir, hata mesajı değildir.
func runFlow(in io.Reader, out io.Writer, flow func(*menuSession) error) error {
	s := newMenuSession(in, out, detectLang(""))
	s.initTabs()
	err := flow(s)
	if err == nil || errors.Is(err, errCancel) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func runPluginsMenu(in io.Reader, out io.Writer) error {
	return runFlow(in, out, func(ms *menuSession) error { return ms.pluginsFlow() })
}

func runBenchMenu(in io.Reader, out io.Writer) error {
	return runFlow(in, out, func(ms *menuSession) error { return ms.benchFlow() })
}

func runOpenAPIMenu(in io.Reader, out io.Writer) error {
	return runFlow(in, out, func(ms *menuSession) error { return ms.openAPIFlow() })
}

func runDiffMenu(in io.Reader, out io.Writer) error {
	return runFlow(in, out, func(ms *menuSession) error { return ms.diffFlow() })
}

func runSuppressMenu(in io.Reader, out io.Writer) error {
	return runFlow(in, out, func(ms *menuSession) error { return ms.suppressFlow() })
}

// ─────────────────────────────────────────────────────────────────────────────
// Ana döngü
// ─────────────────────────────────────────────────────────────────────────────

func (s *menuSession) run() error {
	s.initTabs()
	s.printBanner()
	for {
		s.printTabBar()
		s.printTabContent()
		s.printInfoBar()
		promptMark := s.th.accent("❯")
		if s.last.valid {
			if s.last.failed {
				promptMark = s.th.bad("❯")
			} else {
				promptMark = s.th.good("❯")
			}
		}
		raw, err := s.readRaw("  " + s.th.brand("gash") + " " +
			s.th.muted(s.t("menu.prompt.label")) + " " + promptMark + " ")
		if err != nil {
			s.stopOn(err)
			return nil
		}
		raw = strings.TrimSpace(raw)
		choice := strings.ToLower(raw)

		if isQuit(choice) {
			s.goodbye()
			return nil
		}
		// ":plugins list" gibi hızlı komut: menüden çıkmadan çalıştırır.
		if strings.HasPrefix(raw, ":") {
			s.runCommandLine(raw[1:])
			continue
		}
		// Enter: vurgulanan sekmeyi aç.
		if choice == "" {
			if s.openTab(s.currentTab) {
				return nil
			}
			continue
		}
		if idx, convErr := strconv.Atoi(choice); convErr == nil && idx >= 1 && idx <= len(s.tabs) {
			if s.openTab(idx - 1) {
				return nil
			}
			continue
		}
		switch choice {
		case "h", "help", "yardım", "yardim", "?":
			s.helpScreen()
			continue
		case "n", "next", "right", ">":
			s.nextTab()
			continue
		case "<", "prev", "left", "geri":
			s.prevTab()
			continue
		case "l", "lang", "dil", "diller", "language":
			s.lang = s.lang.other()
			setActiveUILang(s.lang)
			s.printf("  %s\n", s.th.muted(s.t("lang.switched")))
			continue
		case "r", "repeat", "tekrar":
			if !s.last.valid || len(s.last.raw) == 0 {
				s.println("  " + s.th.muted(s.t("menu.noLast")))
				continue
			}
			// Args are replayed verbatim so values containing spaces keep their
			// quoting instead of being re-split on the flattened display line.
			s.execute(append([]string(nil), s.last.raw...)...)
			continue
		case "b", "bench", "benchmark":
			if s.openQuickTool("bench") {
				return nil
			}
			continue
		case "o", "openapi", "api":
			if s.openQuickTool("openapi") {
				return nil
			}
			continue
		case "d", "diff", "compare":
			if s.openQuickTool("diff") {
				return nil
			}
			continue
		case "x", "suppress", "sustur":
			if s.openQuickTool("suppress") {
				return nil
			}
			continue
		}
		if i := s.findTab(choice); i >= 0 {
			if s.openTab(i) {
				return nil
			}
			continue
		}
		fmt.Fprintf(s.out, "  %s\n", s.th.bad(s.t("menu.invalidChoice", choice)))
	}
}

func isQuit(choice string) bool {
	switch choice {
	case "q", "quit", "exit", "çıkış", "cikis", ":q":
		return true
	}
	return false
}

func (s *menuSession) openTab(i int) (quit bool) {
	s.currentTab = i
	return s.stopOn(s.tabs[i].handler(s))
}

// openQuickTool jumps straight into one specialized tool while leaving the
// Tools tab selected behind it, so returning lands on the tool group.
func (s *menuSession) openQuickTool(kind string) (quit bool) {
	for i, t := range s.tabs {
		if t.key == "t" {
			s.currentTab = i
			break
		}
	}
	var err error
	switch kind {
	case "bench":
		err = s.benchFlow()
	case "openapi":
		err = s.openAPIFlow()
	case "diff":
		err = s.diffFlow()
	case "suppress":
		err = s.suppressFlow()
	}
	return s.stopOn(err)
}

func (s *menuSession) initTabs() {
	s.tabs = []tab{
		{
			key: "s", short: "1", icon: "◎",
			name: "tab.scan.name", description: "tab.scan.desc",
			handler: func(ms *menuSession) error { return ms.scanFlow() },
			details: []string{"tab.scan.d1", "tab.scan.d2", "tab.scan.d3", "tab.scan.d4"},
			aliases: []string{"scan"},
		},
		{
			key: "p", short: "2", icon: "◈",
			name: "tab.plugins.name", description: "tab.plugins.desc",
			handler: func(ms *menuSession) error { return ms.pluginsFlow() },
			details: []string{"tab.plugins.d1", "tab.plugins.d2", "tab.plugins.d3", "tab.plugins.d4"},
			aliases: []string{"plugin", "plugins"},
		},
		{
			key: "t", short: "3", icon: "⚙",
			name: "tab.tools.name", description: "tab.tools.desc",
			handler: func(ms *menuSession) error { return ms.toolsFlow() },
			details: []string{"tab.tools.d1", "tab.tools.d2"},
			aliases: []string{"tools", "araclar", "araçlar"},
		},
		{
			key: "c", short: "4", icon: "❯",
			name: "tab.console.name", description: "tab.console.desc",
			handler: func(ms *menuSession) error { return ms.commandConsole() },
			details: []string{"tab.console.d1", "tab.console.d2", "tab.console.d3"},
			aliases: []string{"console", "shell", "terminal"},
		},
		{
			key: "u", short: "5", icon: "▣",
			name: "tab.status.name", description: "tab.status.desc",
			handler: func(ms *menuSession) error { return ms.statusFlow() },
			details: []string{"tab.status.d1", "tab.status.d2", "tab.status.d3"},
			aliases: []string{"status", "durum", "info", "sistem"},
		},
		{
			key: "h", short: "6", icon: "?",
			name: "tab.help.name", description: "tab.help.desc",
			handler: func(ms *menuSession) error { ms.helpScreen(); return nil },
			details: []string{"tab.help.d1"},
			aliases: []string{"yardim"},
		},
	}
	s.currentTab = 0
}

func (s *menuSession) nextTab() {
	s.currentTab = (s.currentTab + 1) % len(s.tabs)
}

func (s *menuSession) prevTab() {
	s.currentTab = (s.currentTab - 1 + len(s.tabs)) % len(s.tabs)
}

// findTab: sekme kısayolu, adı, takma adı veya (benzersiz) ön ekiyle sekme bulur.
func (s *menuSession) findTab(q string) int {
	q = strings.ToLower(q)
	for i, t := range s.tabs {
		if q == strings.ToLower(t.key) {
			return i
		}
	}
	for i, t := range s.tabs {
		if q == strings.ToLower(s.t(t.name)) {
			return i
		}
		for _, a := range t.aliases {
			if q == a {
				return i
			}
		}
	}
	if utf8.RuneCountInString(q) >= 2 {
		match := -1
		for i, t := range s.tabs {
			if strings.HasPrefix(strings.ToLower(s.t(t.name)), q) {
				if match >= 0 {
					return -1 // belirsiz
				}
				match = i
			}
		}
		return match
	}
	return -1
}

// ─────────────────────────────────────────────────────────────────────────────
// Tema ve çizim yardımcıları
// ─────────────────────────────────────────────────────────────────────────────

// theme çıktının nereye gittiğine göre renk kullanıp kullanmayacağına karar verir:
// terminal değilse (pipe, dosya, test) veya NO_COLOR tanımlıysa düz metin üretir.
type theme struct {
	tty       bool
	color     bool
	truecolor bool
}

func detectTheme(out io.Writer) theme {
	f, ok := out.(*os.File)
	if !ok {
		return theme{}
	}
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return theme{}
	}
	t := theme{tty: true, color: true}
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor || os.Getenv("TERM") == "dumb" {
		t.color = false
		return t
	}
	switch strings.ToLower(os.Getenv("COLORTERM")) {
	case "truecolor", "24bit":
		t.truecolor = true
	}
	return t
}

func detectWidth() int {
	w := 76
	if v, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && v > 0 {
		w = v - 4
	}
	if w < 56 {
		w = 56
	}
	if w > 100 {
		w = 100
	}
	return w
}

func (t theme) paint(truecolor, basic, text string) string {
	if !t.color || text == "" {
		return text
	}
	code := basic
	if t.truecolor && truecolor != "" {
		code = truecolor
	}
	return "\033[" + code + "m" + text + "\033[0m"
}

func (t theme) accent(s string) string { return t.paint("1;38;2;56;225;255", "36;1", s) }
func (t theme) brand(s string) string  { return t.paint("1;38;2;139;92;246", "35;1", s) }
func (t theme) good(s string) string   { return t.paint("38;2;74;222;128", "32", s) }
func (t theme) warn(s string) string   { return t.paint("38;2;250;204;21", "33", s) }
func (t theme) bad(s string) string    { return t.paint("38;2;248;113;113", "31", s) }
func (t theme) muted(s string) string  { return t.paint("38;2;148;163;184", "90", s) }
func (t theme) bold(s string) string   { return t.paint("1", "1", s) }
func (t theme) pill(s string) string   { return t.paint("1;38;2;15;23;42;48;2;56;225;255", "1;30;46", s) }
func (t theme) keycap(s string) string {
	return t.paint("1;38;2;226;232;240;48;2;30;41;59", "1;37;40", s)
}

// visibleLen ANSI kaçış dizilerini saymadan görünen karakter sayısını döndürür.
func visibleLen(s string) int {
	n, inEsc := 0, false
	for _, r := range s {
		switch {
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		case r == '\033':
			inEsc = true
		default:
			n++
		}
	}
	return n
}

func padVisible(s string, w int) string {
	if n := visibleLen(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

func truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	if max == 1 {
		return "…"
	}
	return string([]rune(s)[:max-1]) + "…"
}

func wrapText(text string, width int) []string {
	var lines []string
	cur := ""
	for _, w := range strings.Fields(text) {
		switch {
		case cur == "":
			cur = w
		case utf8.RuneCountInString(cur)+1+utf8.RuneCountInString(w) <= width:
			cur += " " + w
		default:
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

func fmtDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
}

func (s *menuSession) boxWidth() int {
	if s.width < 40 {
		return 76
	}
	return s.width
}

func (s *menuSession) println(a ...any) { fmt.Fprintln(s.out, a...) }

func (s *menuSession) printf(format string, a ...any) { fmt.Fprintf(s.out, format, a...) }

func (s *menuSession) rule() {
	s.println("  " + s.th.muted(strings.Repeat("─", s.boxWidth())))
}

// lineLR prints a left/right aligned chrome line. ANSI styling is ignored when
// measuring, so colored labels still align on the panel width.
func (s *menuSession) lineLR(left, right string) {
	width := s.boxWidth()
	pad := width - visibleLen(left) - visibleLen(right)
	if pad < 1 {
		if over := visibleLen(right) + visibleLen(left) - width + 1; over > 0 {
			right = truncate(right, maxInt(0, visibleLen(right)-over))
		}
		pad = width - visibleLen(left) - visibleLen(right)
		if pad < 1 {
			pad = 1
		}
	}
	s.println("  " + left + strings.Repeat(" ", pad) + right)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// panel yuvarlak köşeli bir kutu çizer. title ve satırlar önceden boyanmış olabilir.
func (s *menuSession) panel(title string, edge func(string) string, lines ...string) {
	if edge == nil {
		edge = s.th.muted
	}
	w := s.boxWidth()
	inner := w - 4
	var top string
	if title != "" {
		fill := w - 5 - visibleLen(title)
		if fill < 1 {
			fill = 1
		}
		top = edge("╭─ ") + title + edge(" "+strings.Repeat("─", fill)+"╮")
	} else {
		top = edge("╭" + strings.Repeat("─", w-2) + "╮")
	}
	s.println("  " + top)
	for _, l := range lines {
		s.println("  " + edge("│") + " " + padVisible(l, inner) + " " + edge("│"))
	}
	s.println("  " + edge("╰"+strings.Repeat("─", w-2)+"╯"))
}

// kv: panel içinde "Etiket   değer" satırı üretir; uzun değerleri kırpar.
func (s *menuSession) kv(label, value string) string {
	const labelW = 14
	return s.th.muted(padVisible(truncate(label, labelW), labelW)+" ") + truncate(value, s.boxWidth()-5-labelW)
}

func kb(t theme, key, desc string) string {
	return t.accent(key) + " " + t.muted(desc)
}

// keyTag: bir kısayol harfini köşeli parantez içinde vurgular (örn. "[s]").
// ─────────────────────────────────────────────────────────────────────────────
// Ekranlar: banner, sekme çubuğu, içerik, bilgi çubuğu
// ─────────────────────────────────────────────────────────────────────────────

// menuVersion is the operator-facing build line shown in the menu chrome.
const menuVersion = "v0.1.0-dev"

func (s *menuSession) printTabBar() {
	s.println()
	tab := s.tabs[s.currentTab]
	left := s.th.brand("GASH") + " " + s.th.muted("›") + " " +
		s.th.accent(tab.icon) + " " + s.th.bold(s.t(tab.name))
	right := s.th.muted(fmt.Sprintf("%s · %d/%d", s.lang, s.currentTab+1, len(s.tabs)))
	s.lineLR(left, right)
	s.rule()

	var line strings.Builder
	used := 0
	flush := func() {
		if line.Len() > 0 {
			s.println("  " + line.String())
			line.Reset()
			used = 0
		}
	}
	for i, t := range s.tabs {
		text := fmt.Sprintf("%s %s", t.short, s.t(t.name))
		w := utf8.RuneCountInString(text) + 2
		if used > 0 && used+w+1 > s.boxWidth() {
			flush()
		}
		if i == s.currentTab {
			line.WriteString(s.th.pill("▸ " + text + " "))
		} else {
			line.WriteString(s.th.muted(" " + text + " "))
		}
		line.WriteString(" ")
		used += w + 1
	}
	flush()
	s.println()
}

func (s *menuSession) printTabContent() {
	t := s.tabs[s.currentTab]
	inner := s.boxWidth() - 4
	icon := t.icon
	if icon == "" {
		icon = "•"
	}
	lines := []string{s.th.bold(truncate(s.t(t.description), inner))}
	if len(t.details) > 0 {
		lines = append(lines, "")
		for _, d := range t.details {
			lines = append(lines, s.th.accent("›")+" "+truncate(s.t(d), inner-2))
		}
	}
	lines = append(lines, "",
		s.th.keycap(" Enter ↵ ")+s.th.muted(strings.TrimSpace(s.t("tabcontent.open"))))
	title := s.th.accent(icon) + " " + s.th.bold(s.t(t.name))
	s.panel(title, s.th.accent, lines...)
}

func (s *menuSession) printInfoBar() {
	s.println()
	s.rule()
	s.println("  " + s.th.muted(s.t("infobar.main", len(s.tabs))))
	if s.last.valid {
		mark := s.th.good("✔")
		if s.last.failed {
			mark = s.th.bad("✘")
		}
		s.println("  " + s.th.accent("↳") + " " + s.th.muted(s.t("infobar.last")) + " " +
			truncate(s.last.cmd, s.boxWidth()-26) + " " + mark + " " + s.th.muted(fmtDuration(s.last.took)))
	}
}

func (s *menuSession) printBanner() {
	s.println()
	if s.settings.logoEnabled() {
		s.printLogo()
	}
	left := s.th.brand("GASH") + " " + s.th.keycap(" "+menuVersion+" ")
	right := s.th.muted(s.t("banner.meta", s.lang.String(), len(s.tabs)))
	s.lineLR(left, right)
	s.println("  " + s.th.accent(s.t("banner.tagline")))
	s.println("  " + s.th.muted(s.t("banner.credits")))
	s.println()

	prefix := "⚠ " + s.t("banner.legalTitle") + " · "
	wrapWidth := s.boxWidth() - visibleLen(prefix) - 3
	if wrapWidth < 20 {
		wrapWidth = 20
	}
	legal := wrapText(s.t("banner.legalText"), wrapWidth)
	for i, l := range legal {
		if i == 0 {
			s.println("  " + s.th.warn("⚠ "+s.t("banner.legalTitle")) + s.th.muted(" · "+l))
		} else {
			s.println("    " + s.th.muted(l))
		}
	}
}

func (s *menuSession) header(icon, title string) {
	s.println()
	s.printf("  %s %s  %s\n", s.th.accent(icon), s.th.bold(title), s.th.muted(s.t("common.cancelHint")))
	s.rule()
}

func (s *menuSession) goodbye() {
	fmt.Fprintln(s.out, s.th.good("✓")+" "+s.th.bold(s.t("goodbye")))
}

// helpScreen: kısayollar + cobra'dan okunan komut listesi.
func (s *menuSession) helpScreen() {
	s.println()
	inner := s.boxWidth() - 4
	rows := [][2]string{
		{fmt.Sprintf("1-%d", len(s.tabs)), s.t("help.row.tabs")},
		{"Enter", s.t("help.row.enter")},
		{s.t("help.row.keysKey"), s.t("help.row.keys")},
		{"n / <", s.t("help.row.nav")},
		{"l", s.t("help.row.lang")},
		{s.t("help.row.repeatKey"), s.t("help.row.repeat")},
		{s.t("help.row.cmdKey"), s.t("help.row.cmd")},
		{s.t("help.row.cancelKey"), s.t("help.row.cancel")},
		{"Ctrl+C", s.t("help.row.ctrlC")},
		{s.t("help.row.quitKey"), s.t("help.row.quit")},
	}
	var lines []string
	for _, r := range rows {
		lines = append(lines, s.th.accent(padVisible(r[0], 8))+truncate(r[1], inner-8))
	}
	s.panel(s.th.bold(s.t("help.title")), s.th.accent, lines...)
	s.println()
	s.printCommands()
	s.println()
	// Sekme numaraları elle yazılmaz: sekme listesi büyüdükçe metin bayatlar.
	var flowTabs []string
	consoleNo := 0
	for i, t := range s.tabs {
		switch t.name {
		case "tab.console.name":
			consoleNo = i + 1
		case "tab.help.name":
		default:
			flowTabs = append(flowTabs, t.short)
		}
	}
	if n := len(flowTabs); n > 0 {
		s.println("  " + s.th.muted(s.t("help.tabsNote", strings.Join(flowTabs, ", "))))
	}
	if consoleNo > 0 {
		s.println("  " + s.th.muted(s.t("help.consoleNote", consoleNo)))
	}
}

// printCommands gash komutlarını cobra kök komutundan okuyup tablo olarak basar.
func (s *menuSession) printCommands() {
	type row struct{ name, short, subs string }
	var rows []row
	nameW := 0
	for _, c := range s.rootFactory().Commands() {
		if !c.IsAvailableCommand() || c.Name() == "completion" || c.Name() == "help" {
			continue
		}
		var subs []string
		for _, sc := range c.Commands() {
			if sc.IsAvailableCommand() {
				subs = append(subs, sc.Name())
			}
		}
		short := c.Short
		if key := "cmd." + c.Name() + ".short"; msg(s.lang, key) != key {
			short = msg(s.lang, key)
		}
		rows = append(rows, row{c.Name(), short, strings.Join(subs, " · ")})
		if n := utf8.RuneCountInString(c.Name()); n > nameW {
			nameW = n
		}
	}
	if len(rows) == 0 {
		return
	}
	inner := s.boxWidth() - 4
	var lines []string
	for _, r := range rows {
		lines = append(lines, s.th.accent(padVisible(r.name, nameW))+"  "+truncate(r.short, inner-nameW-2))
		if r.subs != "" {
			lines = append(lines, strings.Repeat(" ", nameW+2)+s.th.muted(truncate("▸ "+r.subs, inner-nameW-2)))
		}
	}
	s.panel(s.th.bold(s.t("commands.title")), s.th.accent, lines...)
}

// ─────────────────────────────────────────────────────────────────────────────
// Akışlar
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Durum paneli
// ─────────────────────────────────────────────────────────────────────────────

func (s *menuSession) statusFlow() error {
	for {
		s.println()
		s.header("▣", s.t("status.title"))
		build := s.t("status.buildStandard")
		if headless.Supported() {
			build = s.t("status.buildDeep")
		}
		chrome := headless.FindChrome()
		chromeLabel := s.t("status.chromeNo")
		if chrome != "" {
			chromeLabel = truncate(chrome, s.boxWidth()-18)
		}
		catalog := s.catalogCount()
		catalogLabel := s.t("status.unknown")
		if catalog >= 0 {
			catalogLabel = fmt.Sprintf("%d %s", catalog, s.t("status.pluginsSuffix"))
		}
		proxyLabel := s.t("status.proxyNone")
		if p := defaultProxyFile(); p != "" {
			proxyLabel = fmt.Sprintf("%s (%d)", p, countListEntries(p))
		}
		reports := latestReportFiles(5)
		std := config.StandardProfile()
		engineLabel := s.t("status.engineValue", std.Name, std.MaxRequestsPerTarget, wafbypass.MaxAttemptsForPlugin)
		lines := []string{
			s.kv(s.t("status.build"), build),
			s.kv(s.t("status.engine"), engineLabel),
			s.kv(s.t("status.chrome"), chromeLabel),
			s.kv(s.t("status.go"), runtime.Version()+" · "+runtime.GOOS+"/"+runtime.GOARCH),
			s.kv(s.t("status.catalog"), catalogLabel),
			s.kv(s.t("status.proxy"), proxyLabel),
			s.kv(s.t("status.reports"), fmt.Sprintf("%d", len(reports))),
		}
		for _, r := range reports {
			lines = append(lines, "  "+s.th.muted(truncate(filepath.Base(r), s.boxWidth()-8)))
		}
		s.panel(s.th.bold(s.t("status.title")), s.th.accent, lines...)
		s.println()
		s.printf("  %s  %s  %s  %s  %s\n",
			kb(s.th, "r", s.t("status.refresh")),
			kb(s.th, "o", s.t("status.openReports")),
			kb(s.th, "v", s.t("status.viewLatest")),
			kb(s.th, "p", s.t("status.proxyHelp")),
			kb(s.th, "0", s.t("common.back")))
		choice, err := s.readLine(s.t("input.selection") + ": ")
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "0", "b", "back", "geri", "iptal", "cancel":
			return nil
		case "r", "refresh", "yenile":
			continue
		case "o", "open", "aç", "ac":
			if err := openPath("reports"); err != nil {
				s.printf("  %s\n", s.th.bad(s.t("status.openFailed", err.Error())))
			} else {
				s.printf("  %s\n", s.th.good(s.t("status.opened", "reports")))
			}
		case "v", "view", "göster", "goster":
			s.showLatestReport(reports)
		case "p", "proxy", "proksi":
			proxyPath := defaultProxyFile()
			if proxyPath == "" {
				proxyPath = filepath.Join(".gash", "proxies", "alive.txt")
			}
			script := filepath.Join(".gash", "proxies", "healthcheck.go")
			if root := menuRepoRoot(); root != "" {
				script = filepath.Join(root, ".gash", "proxies", "healthcheck.go")
			}
			s.println("  " + s.th.muted(fmt.Sprintf(
				"go run %s -in %s -out %s -workers 64 -timeout 5s", script, proxyPath, proxyPath)))
		default:
			s.printf("  %s\n", s.th.bad(s.t("common.invalidChoice", choice)))
		}
	}
}

func (s *menuSession) catalogCount() int {
	ids, _, err := s.catalogPluginIDs()
	if err != nil {
		return -1
	}
	return len(ids)
}

// menuRepoRoot walks upward to the module root so the status tab also works
// when the menu is launched from a subdirectory.
func menuRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func countListEntries(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}
	return n
}

func latestReportFiles(limit int) []string {
	entries, err := os.ReadDir("reports")
	if err != nil {
		return nil
	}
	type reportFile struct {
		path string
		mod  time.Time
	}
	var files []reportFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".text") && !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".html") {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		files = append(files, reportFile{path: filepath.Join("reports", e.Name()), mod: info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) })
	if limit > 0 && len(files) > limit {
		files = files[:limit]
	}
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.path
	}
	return out
}

func (s *menuSession) showLatestReport(reports []string) {
	if len(reports) == 0 {
		s.println("  " + s.th.muted(s.t("status.noReports")))
		return
	}
	var path string
	for _, candidate := range reports {
		if strings.HasSuffix(strings.ToLower(candidate), ".text") {
			path = candidate
			break
		}
	}
	if path == "" {
		s.println("  " + s.th.muted(s.t("status.noTextReport", filepath.Base(reports[0]))))
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		s.printf("  %s\n", s.th.bad(err.Error()))
		return
	}
	lines := strings.Split(string(raw), "\n")
	const maxLines = 80
	s.println()
	s.printf("  %s %s\n", s.th.accent(s.t("status.reportHeader")), s.th.bold(truncate(path, s.boxWidth()-20)))
	s.rule()
	for i, line := range lines {
		if i >= maxLines {
			s.printf("  %s\n", s.th.muted(s.t("status.reportTruncated", len(lines)-maxLines)))
			break
		}
		s.println("  " + truncate(line, s.boxWidth()-2))
	}
	s.rule()
}

func openPath(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", path)
	case "darwin":
		cmd = exec.Command("open", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	return cmd.Start()
}

func (s *menuSession) scanFlow() error {
	s.header("◎", s.t("scan.title"))

	var target, targetFile string
	for {
		raw, err := s.withMemo(s.t("scan.target"), s.memo["target"])
		if err != nil {
			return err
		}
		// A path to an existing file is treated as a bulk target list; this
		// avoids a second prompt and keeps the existing single-target flow.
		candidate := strings.Trim(strings.TrimSpace(raw), `"'`)
		if st, statErr := os.Stat(candidate); statErr == nil && !st.IsDir() {
			targetFile = candidate
			s.printf("  %s\n", s.th.muted(s.t("scan.targetFileDetected", candidate, countListEntries(candidate))))
			break
		}
		t, added, err := normalizeTarget(raw, s.lang)
		if err != nil {
			s.printf("  %s\n", s.th.bad(err.Error()))
			continue
		}
		if added {
			s.printf("  %s\n", s.th.muted(s.t("scan.schemeAdded", t)))
		}
		target = t
		break
	}

	scope := ""
	if targetFile == "" {
		var err error
		scope, err = s.optional(s.t("scan.scope") + " " + s.th.muted(s.t("scan.scopeEmpty")) + ": ")
		if err != nil {
			return err
		}
		// Menüde scope boş bırakılırsa hedefin kayıtlı domaini (eTLD+1) kullanılır;
		// dış linkler taranmaz. Kullanıcı açıkça scope yazarsa o kazanır.
		if strings.TrimSpace(scope) == "" {
			scope = sameSiteDomain(target)
			if scope != "" {
				s.printf("  %s\n", s.th.muted(s.t("scan.scopeAuto", scope)))
			}
		}
	}

	defProfile := s.settings.defaultProfile()
	if v := s.memo["profile"]; v != "" {
		defProfile = v
	}
	profile, err := s.choose(s.t("scan.profile"), []choice{
		{"safe", "s", "profile.safe.label", "profile.safe.desc"},
		{"standard", "t", "profile.standard.label", "profile.standard.desc"},
		{"deep", "d", "profile.deep.label", "profile.deep.desc"},
		{"aggressive", "g", "profile.aggressive.label", "profile.aggressive.desc"},
		{"hersey", "e", "profile.everything.label", "profile.everything.desc"},
	}, defProfile)
	if err != nil {
		return err
	}
	// "HER ŞEY" agresif profile eşittir ve ek olarak headless tarayıcı, altyapı
	// (derin SSH/DB dahil) ve yerel OOB denetimlerini tek adımda açar.
	everything := profile == "hersey"
	if everything {
		profile = "aggressive"
	}

	if profile == "aggressive" {
		ok, err := s.confirm(s.th.warn(s.t("scan.aggressiveConfirm")), false)
		if err != nil {
			return err
		}
		if !ok {
			s.println("  " + s.t("scan.cancelled"))
			return nil
		}
	}

	output := ""
	outputDir := "reports"
	if targetFile == "" {
		output, err = s.optional(s.t("scan.output") + " " + s.th.muted(s.t("scan.outputEmpty")) + ": ")
		if err != nil {
			return err
		}
	} else {
		outputDir, err = s.defaulted(s.dprompt(s.t("scan.outputDir"), "reports"), "reports")
		if err != nil {
			return err
		}
	}

	var oobServer, oobToken string
	var browserCrawl bool
	var infraScan bool
	var infraDeep bool
	var customTimeout string
	proxyMode := "auto"
	if !everything {
		proxyMode = s.settings.defaultProxyMode()
	}
	onlyIDs := append([]string(nil), s.settings.PluginOnly...)
	excludeIDs := append([]string(nil), s.settings.PluginExclude...)
	onlyIDs, excludeIDs = s.prunePluginSelection(onlyIDs, excludeIDs)
	proxySingle := ""
	allowExternal := false
	authMode := "none"
	authCookie, authHeader := "", ""
	loginURL, loginUser, loginPassEnv, loginVerify := "", "", "", ""
	resume := false
	// "HER ŞEY" seçildiyse gelişmiş sorular atlanır: hepsi zaten açık.
	advanced := everything
	if !everything {
		var aerr error
		advanced, aerr = s.confirm(s.t("scan.advanced"), false)
		if aerr != nil {
			return aerr
		}
	}
	if everything {
		oobServer = "local"
		browserCrawl = true
		infraScan = true
		infraDeep = true
	} else if advanced {
		oobChoice, err := s.choose(s.t("scan.oobTitle"), []choice{
			{"local", "l", "oob.local.label", "oob.local.desc"},
			{"interactsh", "i", "oob.interactsh.label", "oob.interactsh.desc"},
			{"custom", "c", "oob.custom.label", "oob.custom.desc"},
			{"none", "n", "oob.none.label", "oob.none.desc"},
		}, "local")
		if err != nil {
			return err
		}
		switch oobChoice {
		case "local":
			oobServer = "local"
		case "interactsh":
			ok, cerr := s.confirm(s.th.warn(s.t("scan.oobInteractshConfirm")), false)
			if cerr != nil {
				return cerr
			}
			if ok {
				oobServer = "interactsh"
			}
		case "custom":
			customURL, err := s.withMemo(s.t("scan.oobPrompt")+" "+s.th.muted(s.t("scan.oobExample")), s.memo["oob"])
			if err != nil {
				return err
			}
			oobServer = customURL
			// Self-hosted APIs and self-hosted interactsh both accept a token.
			tok, terr := s.optional(s.t("scan.oobToken") + " " + s.th.muted(s.t("input.emptyHint", "GASH_OOB_TOKEN")) + ": ")
			if terr != nil {
				return terr
			}
			oobToken = strings.TrimSpace(tok)
		default:
			oobServer = ""
		}

		proxyChoice, err := s.choose(s.t("scan.proxyTitle"), []choice{
			{"auto", "a", "proxy.auto.label", "proxy.auto.desc"},
			{"off", "o", "proxy.off.label", "proxy.off.desc"},
			{"single", "s", "proxy.single.label", "proxy.single.desc"},
			{"all", "l", "proxy.all.label", "proxy.all.desc"},
		}, "auto")
		if err != nil {
			return err
		}
		switch proxyChoice {
		case "off":
			proxyMode = "off"
		case "single":
			proxyMode = "single"
			proxySingle, err = s.withMemo(s.t("scan.proxySinglePrompt"), s.memo["proxy"])
			if err != nil {
				return err
			}
			s.remember("proxy", proxySingle)
		case "all":
			proxyMode = "all"
		default:
			proxyMode = "auto"
		}

		authChoice, err := s.choose(s.t("scan.authTitle"), []choice{
			{"none", "n", "auth.none.label", "auth.none.desc"},
			{"cookie", "c", "auth.cookie.label", "auth.cookie.desc"},
			{"header", "h", "auth.header.label", "auth.header.desc"},
			{"login", "l", "auth.login.label", "auth.login.desc"},
		}, "none")
		if err != nil {
			return err
		}
		switch authChoice {
		case "cookie":
			authMode = "cookie"
			s.println("  " + s.th.warn(s.t("scan.authSecretHint")))
			authCookie, err = s.required(s.t("scan.authCookiePrompt") + ": ")
			if err != nil {
				return err
			}
		case "header":
			authMode = "header"
			s.println("  " + s.th.warn(s.t("scan.authSecretHint")))
			for {
				authHeader, err = s.required(s.t("scan.authHeaderPrompt") + ": ")
				if err != nil {
					return err
				}
				if strings.Contains(authHeader, ":") {
					break
				}
				s.printf("  %s\n", s.th.bad(s.t("scan.authInvalidHeader")))
			}
		case "login":
			authMode = "login"
			if profile == "safe" {
				profile = "standard"
				s.printf("  %s\n", s.th.warn(s.t("scan.loginProfileUpgrade")))
			}
			loginURL, err = s.requiredPath(s.t("scan.loginURL")+": ", true)
			if err != nil {
				return err
			}
			loginUser, err = s.required(s.t("scan.loginUser") + ": ")
			if err != nil {
				return err
			}
			loginPassEnv, err = s.defaulted(s.dprompt(s.t("scan.loginPassEnv"), "GASH_LOGIN_PASS"), "GASH_LOGIN_PASS")
			if err != nil {
				return err
			}
			loginVerify, err = s.optional(s.t("scan.loginVerify") + " (" + s.t("scan.outputEmpty") + "): ")
			if err != nil {
				return err
			}
		}

		allowExternal, err = s.confirm(s.t("scan.allowExternal"), false)
		if err != nil {
			return err
		}

		bc, err := s.confirm(s.t("scan.browserConfirm"), true)
		if err != nil {
			return err
		}
		browserCrawl = bc

		infra, err := s.confirm(s.t("scan.infraConfirm"), false)
		if err != nil {
			return err
		}
		infraScan = infra
		if infra {
			deep, err := s.confirm(s.t("scan.infraDeepConfirm"), true)
			if err != nil {
				return err
			}
			infraDeep = deep
		}

		to, err := s.optional(s.t("scan.timeout") + " " + s.th.muted(s.t("scan.timeoutHint")) + ": ")
		if err != nil {
			return err
		}
		customTimeout = strings.TrimSpace(to)
	}

	if len(onlyIDs)+len(excludeIDs) > 0 {
		useSelection, serr := s.confirm(s.t("scan.useSelection", len(onlyIDs), len(excludeIDs)), true)
		if serr != nil {
			return serr
		}
		if !useSelection {
			onlyIDs, excludeIDs = nil, nil
		}
	}

	if targetFile != "" {
		resume, err = s.confirm(s.t("scan.resume"), false)
		if err != nil {
			return err
		}
	}

	// Proxy choice: auto uses the detected alive list; all uses the full list;
	// off is explicit direct traffic; single pins one upstream.
	proxyFile := ""
	var proxyLabel string
	switch proxyMode {
	case "off":
		proxyLabel = s.t("scan.proxyDisabled")
	case "single":
		proxyLabel = maskURLUser(proxySingle)
	case "all":
		allPath := filepath.Join(".gash", "proxies", "all.txt")
		if st, statErr := os.Stat(allPath); statErr == nil && !st.IsDir() {
			proxyFile = allPath
		} else {
			s.printf("  %s\n", s.th.warn(s.t("scan.proxyAllMissing")))
			proxyFile = defaultProxyFile()
		}
		if proxyFile == "" {
			proxyLabel = s.t("status.proxyNone")
		} else {
			proxyLabel = proxyFile
			if everything {
				proxyLabel += " (" + s.t("scan.proxyPerRequest") + ")"
			} else {
				proxyLabel += " (" + s.t("scan.proxyAuto") + ")"
			}
		}
	default:
		proxyFile = defaultProxyFile()
		if proxyFile == "" {
			proxyLabel = s.t("status.proxyNone")
		} else {
			proxyLabel = proxyFile
			if everything {
				proxyLabel += " (" + s.t("scan.proxyPerRequest") + ")"
			} else {
				proxyLabel += " (" + s.t("scan.proxyAuto") + ")"
			}
		}
	}

	args := []string{"scan"}
	if targetFile != "" {
		args = append(args, "--target-file", targetFile)
	} else {
		args = append(args, "--target", target)
	}
	args = append(args, "--profile", profile)
	if scope != "" && targetFile == "" {
		args = append(args, "--scope", scope)
	}
	if profile == "deep" {
		args = append(args, "--deep")
	}
	if profile == "aggressive" {
		args = append(args, "--aggressive")
	}
	if len(onlyIDs) > 0 {
		args = append(args, "--only-plugin", strings.Join(onlyIDs, ","))
	}
	if len(excludeIDs) > 0 {
		args = append(args, "--ignore-plugin", strings.Join(excludeIDs, ","))
	}
	switch proxyMode {
	case "off":
		args = append(args, "--no-proxy")
	case "single":
		if proxySingle != "" {
			args = append(args, "--proxy", proxySingle)
		}
	default:
		if proxyFile != "" {
			args = append(args, "--proxy-file", proxyFile)
			if everything {
				args = append(args, "--proxy-rotate", "per-request", "--proxy-cooldown", "45s")
			}
		}
	}
	if everything {
		args = append(args, "--scan-timeout", "45m", "--crawl-timeout", "10m")
	}
	if customTimeout != "" {
		args = append(args, "--plugin-timeout", customTimeout)
	}
	switch authMode {
	case "cookie":
		args = append(args, "--cookie", authCookie)
	case "header":
		args = append(args, "--auth-header", authHeader)
	case "login":
		args = append(args, "--login-url", loginURL, "--login-user", loginUser,
			"--login-pass-env", loginPassEnv, "--active")
		if strings.TrimSpace(loginVerify) != "" {
			args = append(args, "--login-verify-url", loginVerify)
		}
	}
	if allowExternal {
		args = append(args, "--allow-external")
	}
	if oobServer != "" {
		args = append(args, "--oob-server", oobServer, "--active")
		if oobToken != "" {
			args = append(args, "--oob-token", oobToken)
		}
		s.remember("oob", oobServer)
	}
	if browserCrawl {
		args = append(args, "--browser-crawl", "--browser-verify", "--active")
	}
	if infraScan {
		args = append(args, "--ssh-audit", "--db-port-scan", "--tls-audit-deep", "--active")
	}
	if infraDeep {
		args = append(args, "--ssh-handshake-audit", "--db-unauth")
	}
	if targetFile != "" {
		args = append(args, "--output-dir", outputDir, "--format", "json", "--format", "text", "--report-stamp")
		if resume {
			args = append(args, "--resume")
		}
	} else if output != "" {
		args = append(args, "--output", output, "--format", reportFormatForPath(output))
	} else {
		// "boş=otomatik": rapor yine diske yazılır (json + text) ve terminal
		// özeti korunur. --report-stamp aynı hedefin raporunu ezmez.
		args = append(args, "--output-dir", "reports", "--format", "json", "--format", "text", "--report-stamp")
	}

	scopeLabel, outLabel := scope, output
	if targetFile != "" {
		scopeLabel = s.t("scan.scopeAutoPerTarget")
		outLabel = outputDir
	}
	if scopeLabel == "" {
		scopeLabel = s.t("common.free")
	}
	if outLabel == "" {
		outLabel = s.t("scan.autoReport")
	}
	s.println()
	kvLabelW := 8
	targetLabel := target
	targetKey := s.t("kv.target")
	if targetFile != "" {
		targetKey = s.t("kv.targetFile")
		targetLabel = fmt.Sprintf("%s (%d)", targetFile, countListEntries(targetFile))
	}
	summaryItems := []string{
		s.kv(targetKey, targetLabel),
		s.kv(s.t("kv.scope"), scopeLabel),
		s.th.muted(padVisible(s.t("kv.profile"), kvLabelW)) + s.profileTone(profile),
	}
	if budget := s.profileBudget(profile); budget != "" {
		summaryItems = append(summaryItems, s.kv(s.t("kv.budget"), budget))
	}
	summaryItems = append(summaryItems, s.kv(s.t("kv.plugins"), s.selectionSummary(onlyIDs, excludeIDs)))
	summaryItems = append(summaryItems,
		s.kv(s.t("kv.report"), outLabel),
		s.kv(s.t("kv.proxy"), proxyLabel),
	)
	if authMode != "none" {
		summaryItems = append(summaryItems, s.kv(s.t("kv.auth"), s.t("auth."+authMode+".label")))
	}
	if allowExternal {
		summaryItems = append(summaryItems, s.kv(s.t("kv.external"), s.th.warn(s.t("scan.externalActive"))))
	}
	if oobServer != "" {
		var oobLabel string
		switch oobServer {
		case "local":
			oobLabel = s.th.good(s.t("scan.oobLocalLabel"))
		case "interactsh":
			oobLabel = s.th.warn(s.t("scan.oobInteractshLabel"))
		default:
			oobLabel = oobServer
		}
		summaryItems = append(summaryItems, s.kv(s.t("kv.oob"), oobLabel))
	}
	if customTimeout != "" {
		summaryItems = append(summaryItems, s.kv(s.t("kv.timeout"), customTimeout))
	}
	if browserCrawl {
		summaryItems = append(summaryItems, s.kv(s.t("kv.browser"), s.th.good(s.t("scan.browserActive"))))
	}
	if infraScan {
		label := s.t("scan.infraActive")
		if infraDeep {
			label = s.t("scan.infraActiveDeep")
		}
		summaryItems = append(summaryItems, s.kv(s.t("kv.infra"), s.th.good(label)))
	}
	s.panel(s.th.bold(s.t("scan.summary")), s.th.accent, summaryItems...)
	s.printf("  %s %s\n", s.th.muted(s.t("scan.command")), "gash "+shellJoin(redactCommandArgs(args)))
	s.println()

	ok, err := s.confirm(s.t("scan.startConfirm"), true)
	if err != nil {
		return err
	}
	if !ok {
		s.println("  " + s.t("scan.cancelled"))
		return nil
	}

	if targetFile != "" {
		s.remember("target", targetFile)
	} else {
		s.remember("target", target)
	}
	if profile != "aggressive" { // agresif profil asla varsayılan olarak hatırlanmaz
		s.remember("profile", profile)
	}
	s.printf("  %s %s\n", s.th.accent(s.t("scan.starting")), s.th.muted(s.t("scan.startingHint")))
	s.execute(args...)
	return nil
}

func (s *menuSession) profileTone(p string) string {
	switch p {
	case "safe":
		return s.th.good(p)
	case "deep":
		return s.th.warn(p)
	case "aggressive":
		return s.th.bad(p)
	}
	return s.th.bold(p)
}

// profileBudget renders the limits the engine will enforce for a profile, so
// the pre-scan summary and the actual run can never disagree about budgets.
func (s *menuSession) profileBudget(p string) string {
	profile := config.GetProfile(config.ProfileName(p))
	if profile == nil {
		return ""
	}
	rate := strconv.FormatFloat(profile.RatePerSecond, 'f', -1, 64)
	return s.t("scan.budget", profile.MaxRequestsPerTarget, rate, profile.MaxPages, profile.CrawlDepth)
}

func (s *menuSession) pluginsFlow() error {
	return s.submenu(s.t("plugins.title"), s.t("common.mainMenu"), []menuItem{
		{"l", "plugins.list", "plugins.list.desc", func() error {
			s.execute("plugins", "list")
			return nil
		}},
		{"v", "plugins.validate", "plugins.validate.desc", func() error {
			defPath := "plugins/headers/missing-security-headers.yaml"
			file, err := s.defaulted(s.dprompt(s.t("plugins.file"), defPath), defPath)
			if err != nil {
				return err
			}
			s.execute("plugins", "validate", file)
			return nil
		}},
		{"f", "plugins.test", "plugins.test.desc", func() error {
			defPath := "plugins/headers/missing-security-headers.yaml"
			file, err := s.defaulted(s.dprompt(s.t("plugins.file"), defPath), defPath)
			if err != nil {
				return err
			}
			s.execute("plugins", "test", file)
			return nil
		}},
		{"i", "plugins.info", "plugins.info.desc", func() error {
			defID := "missing-security-headers"
			id, err := s.defaulted(s.dprompt(s.t("plugins.id"), defID), defID)
			if err != nil {
				return err
			}
			s.execute("plugins", "info", id)
			return nil
		}},
		{"n", "plugins.new", "plugins.new.desc", func() error {
			name, err := s.required(s.t("plugins.name") + ": ")
			if err != nil {
				return err
			}
			tier, err := s.choose(s.t("plugins.tier"), []choice{
				{"yaml", "y", "tier.yaml.label", "tier.yaml.desc"},
				{"js", "j", "tier.js.label", "tier.js.desc"},
			}, "yaml")
			if err != nil {
				return err
			}
			s.execute("plugins", "new", name, "--tier", tier)
			return nil
		}},
		{"t", "plugins.trust", "plugins.trust.desc", func() error {
			manifest, err := s.requiredPath(s.t("plugins.trustPrompt")+": ", false)
			if err != nil {
				return err
			}
			ok, err := s.confirm(s.t("plugins.trustConfirm"), false)
			if err != nil {
				return err
			}
			if !ok {
				s.println("  " + s.t("plugins.trustCancelled"))
				return nil
			}
			s.execute("plugins", "trust", manifest)
			return nil
		}},
		{"s", "plugins.selection.label", "plugins.selection.desc", s.pluginSelectionFlow},
		{"g", "plugins.settings.label", "plugins.settings.desc", s.settingsFlow},
	})
}

// toolsFlow groups the specialized report/lab utilities so the primary tab
// bar stays short. Direct b/o/d/x shortcuts still jump straight into a tool.
func (s *menuSession) toolsFlow() error {
	return s.submenu(s.t("tab.tools.name"), s.t("common.mainMenu"), []menuItem{
		{"b", "tab.bench.name", "tab.bench.desc", s.benchFlow},
		{"o", "tab.openapi.name", "tab.openapi.desc", s.openAPIFlow},
		{"d", "tab.diff.name", "tab.diff.desc", s.diffFlow},
		{"x", "tab.suppress.name", "tab.suppress.desc", s.suppressFlow},
	})
}

func (s *menuSession) benchFlow() error {
	const defDataset = "bench/datasets/fixtures.yaml"
	return s.submenu(s.t("bench.title"), s.t("common.mainMenu"), []menuItem{
		{"v", "bench.validate", "bench.validate.desc", func() error {
			dataset, err := s.defaulted(s.dprompt(s.t("bench.dataset"), defDataset), defDataset)
			if err != nil {
				return err
			}
			s.execute("bench", "validate", dataset)
			return nil
		}},
		{"r", "bench.run", "bench.run.desc", func() error {
			dataset, err := s.defaulted(s.dprompt(s.t("bench.dataset"), defDataset), defDataset)
			if err != nil {
				return err
			}
			outDir, err := s.optional(s.t("bench.outDir") + " " + s.th.muted(s.t("scan.outputEmpty")) + ": ")
			if err != nil {
				return err
			}
			tools, err := s.defaulted(s.dprompt(s.t("bench.tools"), "gash,nuclei"), "gash,nuclei")
			if err != nil {
				return err
			}
			args := []string{"bench", "run", "--dataset", dataset, "--tool", tools}
			if outDir != "" {
				args = append(args, "--out", outDir)
			}
			s.execute(args...)
			return nil
		}},
		{"k", "bench.compare", "bench.compare.desc", func() error {
			baseline, err := s.requiredPath(s.t("bench.baselineFile")+": ", false)
			if err != nil {
				return err
			}
			current, err := s.requiredPath(s.t("bench.currentFile")+": ", false)
			if err != nil {
				return err
			}
			s.execute("bench", "compare", "--baseline", baseline, "--current", current)
			return nil
		}},
		{"g", "bench.baseline", "bench.baseline.desc", func() error {
			report, err := s.requiredPath(s.t("bench.report")+": ", false)
			if err != nil {
				return err
			}
			tool, err := s.defaulted(s.dprompt(s.t("bench.tool"), "gash"), "gash")
			if err != nil {
				return err
			}
			outPath, err := s.optional(s.t("bench.outFile") + " " + s.th.muted(s.t("input.emptyHint", "stdout")) + ": ")
			if err != nil {
				return err
			}
			args := []string{"bench", "baseline", "--report", report, "--tool", tool}
			if outPath != "" {
				args = append(args, "--out", outPath)
			}
			s.execute(args...)
			return nil
		}},
		{"l", "bench.lab", "bench.lab.desc", s.labFlow},
	})
}

func (s *menuSession) labFlow() error {
	return s.submenu(s.t("lab.title"), s.t("common.back"), []menuItem{
		{"s", "lab.status", "lab.status.desc", func() error { s.execute("bench", "lab", "status"); return nil }},
		{"u", "lab.up", "lab.up.desc", func() error { s.execute("bench", "lab", "up"); return nil }},
		{"d", "lab.down", "lab.down.desc", func() error { s.execute("bench", "lab", "down"); return nil }},
		{"r", "lab.reset", "lab.reset.desc", func() error {
			ok, err := s.confirm(s.t("lab.resetConfirm"), false)
			if err != nil {
				return err
			}
			if ok {
				s.execute("bench", "lab", "reset")
			}
			return nil
		}},
	})
}

func (s *menuSession) openAPIFlow() error {
	s.header("◆", s.t("openapi.title"))
	spec, err := s.requiredPath(s.t("openapi.spec")+": ", true)
	if err != nil {
		return err
	}
	format, err := s.choose(s.t("openapi.format"), []choice{
		{"text", "t", "format.text.label", "format.text.desc"},
		{"json", "j", "format.json.label", "format.json.desc"},
	}, "text")
	if err != nil {
		return err
	}
	server, err := s.optional(s.t("openapi.server") + " " + s.th.muted(s.t("openapi.serverHint")) + ": ")
	if err != nil {
		return err
	}
	args := []string{"openapi", "--spec", spec, "--format", format}
	if server != "" {
		args = append(args, "--server", server)
	}
	s.execute(args...)
	return nil
}

func (s *menuSession) diffFlow() error {
	s.header("◐", s.t("diff.title"))
	oldPath, err := s.requiredPath(s.t("diff.old")+": ", false)
	if err != nil {
		return err
	}
	newPath, err := s.requiredPath(s.t("diff.new")+": ", false)
	if err != nil {
		return err
	}
	format, err := s.choose(s.t("openapi.format"), []choice{
		{"text", "t", "format.text.label", "format.text.desc"},
		{"json", "j", "format.json.label", "format.json.desc"},
	}, "text")
	if err != nil {
		return err
	}
	failOn, err := s.choose(s.t("diff.gate"), []choice{
		{"", "n", "gate.none.label", "gate.none.desc"},
		{"new", "f", "gate.new.label", "gate.new.desc"},
	}, "")
	if err != nil {
		return err
	}
	args := []string{"diff", "--old", oldPath, "--new", newPath, "--format", format}
	if failOn != "" {
		args = append(args, "--fail-on", failOn)
	}
	s.execute(args...)
	return nil
}

func (s *menuSession) suppressFlow() error {
	return s.submenu(s.t("suppress.title"), s.t("common.mainMenu"), []menuItem{
		{"l", "suppress.list", "suppress.list.desc", func() error {
			s.execute("suppress", "list")
			return nil
		}},
		{"e", "suppress.add", "suppress.add.desc", func() error {
			id, err := s.required(s.t("suppress.findingID") + ": ")
			if err != nil {
				return err
			}
			s.execute("suppress", "add", id)
			return nil
		}},
		{"k", "suppress.remove", "suppress.remove.desc", func() error {
			id, err := s.required(s.t("suppress.findingID") + ": ")
			if err != nil {
				return err
			}
			ok, err := s.confirm(s.t("suppress.removeConfirm", id), false)
			if err != nil {
				return err
			}
			if !ok {
				s.println("  " + s.t("common.cancelled"))
				return nil
			}
			s.execute("suppress", "remove", id)
			return nil
		}},
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Komut terminali
// ─────────────────────────────────────────────────────────────────────────────

func (s *menuSession) commandConsole() error {
	s.println()
	s.panel(s.th.accent("❯")+" "+s.th.bold(s.t("console.title")), s.th.accent,
		s.t("console.help1"),
		kb(s.th, "menu", s.t("console.h.menu"))+"  ·  "+kb(s.th, "exit", s.t("console.h.exit"))+"  ·  "+kb(s.th, "clear", s.t("console.h.clear"))+"  ·  "+kb(s.th, "?", s.t("console.h.help")),
		kb(s.th, s.t("console.h.commandsKey"), s.t("console.h.commands"))+"  ·  "+kb(s.th, s.t("console.h.historyKey"), s.t("console.h.history")),
		kb(s.th, "!!", s.t("console.h.repeat"))+"  ·  "+kb(s.th, "!N", s.t("console.h.run")),
	)
	for {
		line, err := s.readRaw(s.consolePrompt())
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch strings.ToLower(line) {
		case "exit", "quit", "q", "0":
			return errExitMenu
		case "menu", "back", "..", ":q":
			return nil
		case "clear", "cls":
			if s.th.tty {
				fmt.Fprint(s.out, "\x1b[2J\x1b[H")
			}
			continue
		case "?":
			s.execute("--help")
			continue
		case "komutlar", "commands":
			s.println()
			s.printCommands()
			continue
		case "history", "geçmiş", "gecmis":
			s.printHistory()
			continue
		}
		if strings.HasPrefix(line, "!") {
			expanded, ok := s.expandHistory(line)
			if !ok {
				continue
			}
			line = expanded
			s.println("  " + s.th.muted("↳ "+line))
		}
		s.pushHistory(line)
		s.runCommandLine(line)
	}
}

func (s *menuSession) consolePrompt() string {
	arrow := s.th.accent("❯")
	if s.last.valid {
		if s.last.failed {
			arrow = s.th.bad("❯")
		} else {
			arrow = s.th.good("❯")
		}
	}
	return "  " + s.th.brand("gash") + " " + arrow + " "
}

func (s *menuSession) pushHistory(line string) {
	if n := len(s.history); n > 0 && s.history[n-1] == line {
		return
	}
	s.history = append(s.history, line)
	if len(s.history) > 100 {
		s.history = s.history[len(s.history)-100:]
	}
}

func (s *menuSession) expandHistory(line string) (string, bool) {
	if len(s.history) == 0 {
		s.println("  " + s.th.muted(s.t("console.emptyHistory")))
		return "", false
	}
	if line == "!!" {
		return s.history[len(s.history)-1], true
	}
	n, err := strconv.Atoi(strings.TrimPrefix(line, "!"))
	if err != nil || n < 1 || n > len(s.history) {
		s.printf("  %s\n", s.th.bad(s.t("console.badHistory", line)))
		return "", false
	}
	return s.history[n-1], true
}

func (s *menuSession) printHistory() {
	if len(s.history) == 0 {
		s.println("  " + s.th.muted(s.t("console.emptyHistory")))
		return
	}
	for i, h := range s.history {
		s.printf("  %s  %s\n", s.th.muted(fmt.Sprintf("%3d", i+1)), redactCommandLine(h))
	}
}

func (s *menuSession) runCommandLine(line string) {
	args, err := splitCommandLine(line)
	if err != nil {
		s.printf("  %s\n", s.th.bad(s.t("console.badQuote")))
		return
	}
	if len(args) > 0 && strings.EqualFold(args[0], "gash") {
		args = args[1:]
	}
	if len(args) == 0 {
		return
	}
	s.execute(args...)
}

// ─────────────────────────────────────────────────────────────────────────────
// Komut çalıştırma
// ─────────────────────────────────────────────────────────────────────────────

// execute bir gash komutunu çalıştırır, süreyi ölçer ve sonucu özetler.
// Ctrl+C ilk basışta komutun context'ini iptal eder (menüden çıkmaz);
// ikinci basışta süreci zorla sonlandırır.
func (s *menuSession) execute(args ...string) error {
	fmt.Fprintln(s.out)
	cobra.MousetrapHelpText = ""
	root := s.rootFactory()
	root.SetArgs(args)
	root.SetIn(s.in)
	root.SetOut(s.out)
	root.SetErr(s.out)
	root.SilenceUsage = true
	root.SilenceErrors = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := s.watchInterrupt(cancel)

	started := time.Now()
	err := root.ExecuteContext(ctx)
	took := time.Since(started)
	stop()
	cancelled := ctx.Err() != nil

	s.last = lastRun{cmd: strings.Join(redactCommandArgs(args), " "), raw: append([]string(nil), args...), took: took, failed: err != nil || cancelled, valid: true}
	t := s.th.muted(" · " + fmtDuration(took))
	switch {
	case cancelled:
		fmt.Fprintf(s.out, "  %s%s\n", s.th.warn(s.t("exec.cancelled")), t)
	case err != nil:
		fmt.Fprintf(s.out, "  %s%s\n", s.th.bad(s.t("exec.error", err.Error())), t)
	default:
		fmt.Fprintf(s.out, "  %s%s\n", s.th.good(s.t("exec.done")), t)
	}
	fmt.Fprintln(s.out)
	return err
}

func (s *menuSession) watchInterrupt(cancel context.CancelFunc) (stop func()) {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt)
	done := make(chan struct{})
	go func() {
		count := 0
		for {
			select {
			case <-sigCh:
				count++
				if count == 1 {
					fmt.Fprintf(s.out, "\n  %s\n", s.th.warn(s.t("exec.interrupt")))
					cancel()
					continue
				}
				os.Exit(130)
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(sigCh)
		close(done)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Girdi yardımcıları
// ─────────────────────────────────────────────────────────────────────────────

func (s *menuSession) readRaw(rendered string) (string, error) {
	fmt.Fprint(s.out, rendered)
	line, err := s.in.ReadString('\n')
	line = strings.TrimPrefix(line, "\ufeff")
	if err != nil {
		if errors.Is(err, io.EOF) && line != "" {
			return strings.TrimSpace(line), nil
		}
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (s *menuSession) readLine(prompt string) (string, error) {
	return s.readRaw("  " + s.th.accent("›") + " " + prompt)
}

// isCancel: her iki dildeki iptal sözcüklerini kabul eder.
func isCancel(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "iptal", "cancel", ":q":
		return true
	}
	return false
}

func (s *menuSession) required(prompt string) (string, error) {
	for {
		value, err := s.readLine(prompt)
		if err != nil {
			return "", err
		}
		if isCancel(value) {
			return "", errCancel
		}
		if value != "" {
			return value, nil
		}
		s.printf("  %s\n", s.th.warn(s.t("input.required")))
	}
}

func (s *menuSession) defaulted(prompt, fallback string) (string, error) {
	value, err := s.readLine(prompt)
	if err != nil {
		return "", err
	}
	if isCancel(value) {
		return "", errCancel
	}
	if value == "" {
		return fallback, nil
	}
	return value, nil
}

func (s *menuSession) optional(prompt string) (string, error) {
	value, err := s.readLine(prompt)
	if err != nil {
		return "", err
	}
	if isCancel(value) {
		return "", errCancel
	}
	return value, nil
}

// dprompt: "Etiket (varsayılan): " biçiminde, varsayılanı soluk gösteren istem üretir.
func (s *menuSession) dprompt(label, def string) string {
	return label + " " + s.th.muted("("+def+")") + ": "
}

// withMemo: oturumda daha önce girilmiş değer varsa onu varsayılan sunar.
func (s *menuSession) withMemo(label, last string) (string, error) {
	if last == "" {
		return s.required(label + ": ")
	}
	return s.defaulted(s.dprompt(label, last), last)
}

func (s *menuSession) remember(key, value string) {
	if s.memo == nil {
		s.memo = map[string]string{}
	}
	s.memo[key] = value
}

// requiredPath: var olan bir dosya (veya allowURL ise http/https URL) ister.
func (s *menuSession) requiredPath(prompt string, allowURL bool) (string, error) {
	for {
		p, err := s.required(prompt)
		if err != nil {
			return "", err
		}
		p = strings.Trim(p, `"'`) // sürükle-bırak ile gelen tırnakları temizle
		if allowURL {
			low := strings.ToLower(p)
			if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
				return p, nil
			}
		}
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			s.printf("  %s\n", s.th.bad(s.t("input.fileNotFound", p)))
			continue
		}
		return p, nil
	}
}

// confirm: her iki dildeki evet/hayır sözcüklerini kabul eder (e/h, y/n).
func (s *menuSession) confirm(question string, def bool) (bool, error) {
	yes, no := s.t("input.confirmYes"), s.t("input.confirmNo")
	var hint string
	if def {
		hint = "[" + strings.ToUpper(yes) + "/" + strings.ToLower(no) + "]"
	} else {
		hint = "[" + strings.ToLower(yes) + "/" + strings.ToUpper(no) + "]"
	}
	for {
		in, err := s.readLine(question + " " + s.th.muted(hint) + ": ")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(in) {
		case "":
			return def, nil
		case "e", "evet", "y", "yes":
			return true, nil
		case "h", "hayır", "hayir", "n", "no":
			return false, nil
		case "iptal", "cancel", ":q":
			return false, errCancel
		}
		s.printf("  %s\n", s.th.warn(s.t("input.yesNo")))
	}
}

// choose numaralı bir seçenek listesi gösterir; numara, kısayol harfi, ad veya
// Enter (varsayılan) kabul eder.
func (s *menuSession) choose(label string, opts []choice, def string) (string, error) {
	defIdx, labelW := 0, 0
	for i, o := range opts {
		if o.value == def {
			defIdx = i
		}
		if n := utf8.RuneCountInString(s.t(o.label)); n > labelW {
			labelW = n
		}
	}
	s.println()
	s.println("  " + s.th.accent("◆") + " " + s.th.bold(label))
	for i, o := range opts {
		marker := " "
		if i == defIdx {
			marker = s.th.accent("›")
		}
		descWidth := s.boxWidth() - 8 - labelW - 2
		s.printf("  %s %s  %s  %s\n", marker, s.th.keycap(" "+o.key+" "),
			padVisible(s.t(o.label), labelW), s.th.muted(truncate(s.t(o.desc), descWidth)))
	}
	defLabel := s.t(opts[defIdx].label)
	for {
		in, err := s.readLine(s.t("input.selection") + " " + s.th.muted(s.t("input.chooseHint", defLabel)) + ": ")
		if err != nil {
			return "", err
		}
		if isCancel(in) {
			return "", errCancel
		}
		if in == "" {
			return opts[defIdx].value, nil
		}
		if n, convErr := strconv.Atoi(in); convErr == nil && n >= 1 && n <= len(opts) {
			return opts[n-1].value, nil
		}
		for _, o := range opts {
			if o.key != "" && strings.EqualFold(in, o.key) {
				return o.value, nil
			}
		}
		for _, o := range opts {
			if strings.EqualFold(in, s.t(o.label)) || (o.value != "" && strings.EqualFold(in, o.value)) {
				return o.value, nil
			}
		}
		s.printf("  %s\n", s.th.bad(s.t("input.invalid", strings.ToLower(label), in)))
	}
}

// submenu: numaralı/kısayollu alt menü panelini gösterip seçilen işlemi çalıştırır.
// Bir işlem sırasında "iptal" yazılırsa alt menüye dönülür.
func (s *menuSession) submenu(title, backLabel string, items []menuItem) error {
	labelW := 0
	for _, it := range items {
		if n := utf8.RuneCountInString(s.t(it.label)); n > labelW {
			labelW = n
		}
	}
	inner := s.boxWidth() - 4
	s.println()
	s.lineLR(s.th.brand("GASH")+" "+s.th.muted("›")+" "+s.th.bold(s.t(title)), s.th.muted(s.lang.String()))
	s.rule()
	for {
		s.println()
		lines := make([]string, 0, len(items)+4)
		lines = append(lines, "")
		for _, it := range items {
			lines = append(lines, s.th.keycap(" "+it.key+" ")+"  "+padVisible(s.t(it.label), labelW)+"  "+
				s.th.muted(truncate(s.t(it.desc), inner-6-labelW-2)))
		}
		lines = append(lines, "", s.th.keycap(" 0 ")+"  "+backLabel+s.th.muted("   "+s.t("submenu.hint")))
		s.panel("", s.th.accent, lines...)

		choice, err := s.readLine(s.t("input.selection") + ": ")
		if err != nil {
			return err
		}
		lower := strings.ToLower(choice)
		switch lower {
		case "0", "b", "back", "geri":
			return nil
		}
		if idx, convErr := strconv.Atoi(choice); convErr == nil && idx >= 1 && idx <= len(items) {
			if err := s.runSubmenuItem(items[idx-1]); err != nil {
				return err
			}
			continue
		}
		matched := false
		for _, it := range items {
			if (it.key != "" && lower == it.key) || lower == strings.ToLower(s.t(it.label)) {
				matched = true
				if err := s.runSubmenuItem(it); err != nil {
					return err
				}
				break
			}
		}
		if !matched {
			s.printf("  %s\n", s.th.bad(s.t("common.invalidChoice", choice)))
		}
	}
}

// runSubmenuItem: alt menü işlemini çalıştırır; "iptal" alt menüye dönüş demektir.
func (s *menuSession) runSubmenuItem(it menuItem) error {
	if err := it.run(); err != nil {
		if errors.Is(err, errCancel) {
			s.printf("  %s\n", s.th.muted(s.t("common.cancelled")))
			return nil
		}
		return err
	}
	return nil
}

func (s *menuSession) stopOn(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errCancel) {
		s.printf("  %s\n", s.th.muted(s.t("common.cancelled")))
		return false
	}
	if errors.Is(err, errExitMenu) || errors.Is(err, io.EOF) {
		s.goodbye()
		return true
	}
	fmt.Fprintf(s.out, "  %s\n", s.t("common.error", err.Error()))
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Saf yardımcılar
// ─────────────────────────────────────────────────────────────────────────────

// reportFormatForPath keeps a typed report path consistent with its format;
// otherwise --output report.json would silently receive the default text body.
func reportFormatForPath(path string) string {
	switch strings.ToLower(filepath.Ext(strings.TrimSpace(path))) {
	case ".json":
		return "json"
	case ".html", ".htm":
		return "html"
	case ".sarif":
		return "sarif"
	case ".xml":
		return "junit"
	default:
		return "text"
	}
}

// normalizeTarget: şema yoksa https:// ekler, host'u doğrular.
func normalizeTarget(raw string, l uiLang) (target string, schemeAdded bool, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, errors.New(msg(l, "scan.emptyTarget"))
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
		schemeAdded = true
	}
	u, perr := url.Parse(raw)
	if perr != nil || u.Host == "" {
		return "", false, errors.New(msg(l, "scan.invalidURL", raw))
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", false, errors.New(msg(l, "scan.unsupportedScheme", u.Scheme))
	}
	return raw, schemeAdded, nil
}

func shellQuote(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\n\"'\\$&|;<>()*?[]{}!#~`") {
		return a
	}
	return "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
}

// redactCommandArgs masks credential-bearing flag values in the displayed
// command and the info bar; the real argv passed to the command is unchanged.
func redactCommandArgs(args []string) []string {
	out := append([]string{}, args...)
	secretFlags := map[string]bool{
		"--cookie": true, "--auth-header": true, "--oob-token": true,
		"--login-pass": true, "--basic-auth": true,
	}
	for i := 0; i < len(out); i++ {
		for flag := range secretFlags {
			if out[i] == flag && i+1 < len(out) {
				out[i+1] = "[redacted]"
			}
			if strings.HasPrefix(out[i], flag+"=") {
				out[i] = flag + "=[redacted]"
			}
		}
		if out[i] == "--proxy" && i+1 < len(out) {
			out[i+1] = maskURLUser(out[i+1])
		}
		if strings.HasPrefix(out[i], "--proxy=") {
			out[i] = "--proxy=" + maskURLUser(strings.TrimPrefix(out[i], "--proxy="))
		}
	}
	return out
}

// maskURLUser keeps host/port visible but hides proxy credentials. The
// asterisks are inserted after Parse/String so they are not percent-encoded.
func maskURLUser(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = nil
	masked := u.String()
	if i := strings.Index(masked, "://"); i >= 0 {
		return masked[:i+3] + "***@" + masked[i+3:]
	}
	return raw
}

func redactCommandLine(line string) string {
	args, err := splitCommandLine(line)
	if err != nil {
		return line
	}
	return shellJoin(redactCommandArgs(args))
}

func shellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = shellQuote(a)
	}
	return strings.Join(q, " ")
}

// splitCommandLine: tırnak kurallarına uyan basit bir komut satırı ayrıştırıcı.
// Kapanmamış tırnakta errUnterminatedQuote döner; metne çevirisi çağıran tarafta
// yapılır (bkz. console.badQuote).
func splitCommandLine(line string) ([]string, error) {
	var (
		args    []string
		current strings.Builder
		quote   rune
		started bool
	)
	flush := func() {
		if started {
			args = append(args, current.String())
			current.Reset()
			started = false
		}
	}
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
			started = true
		case r == '\'' || r == '"':
			quote = r
			started = true
		case unicode.IsSpace(r):
			flush()
		default:
			current.WriteRune(r)
			started = true
		}
	}
	if quote != 0 {
		return nil, errUnterminatedQuote
	}
	flush()
	return args, nil
}
