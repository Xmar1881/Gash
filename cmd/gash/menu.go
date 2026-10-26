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
	"os/signal"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
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
	cmd := &cobra.Command{
		Use:     "menu",
		Aliases: []string{"console", "interactive", "shell"},
		Short:   "Etkileşimli menü + Gash komut terminali (TR/EN)",
		Long: "Etkileşimli menüyü açar. Menüden tarama, plugin, benchmark, OpenAPI, diff ve suppress\n" +
			"işlemleri yapılabilir; komut terminalinden tüm gash komutları çalıştırılabilir.\n\n" +
			"Dil: varsayılan TR'dir. '--lang en', GASH_LANG=en ortam değişkeni veya menü içindeki 'l'\n" +
			"kısayolu ile EN'e geçilir.\n" +
			"Tuşlar: her sekmeye tek harflik kısayol atanmıştır; Enter vurgulanan sekmeyi açar,\n" +
			"':komut' menüden çıkmadan komut çalıştırır, soru sırasında 'iptal' işlemi iptal eder,\n" +
			"Ctrl+C çalışan komutu durdurur.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInteractiveMenuLang(cmd.InOrStdin(), cmd.OutOrStdout(), langFlag)
		},
	}
	cmd.Flags().StringVar(&langFlag, "lang", "auto", "Arayüz dili / UI language: auto|tr|en")
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
	return &menuSession{
		in:          bufio.NewReader(in),
		out:         out,
		rootFactory: newRoot,
		lang:        l,
		th:          detectTheme(out),
		width:       detectWidth(),
		memo:        map[string]string{},
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
		raw, err := s.readRaw("  " + s.th.brand(s.t("menu.prompt.label")) + " " + s.th.accent("❯") + " ")
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
			s.printf("  %s\n", s.th.muted(s.t("lang.switched")))
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
			details: []string{"tab.plugins.d1", "tab.plugins.d2", "tab.plugins.d3"},
			aliases: []string{"plugin", "plugins"},
		},
		{
			key: "b", short: "3", icon: "▲",
			name: "tab.bench.name", description: "tab.bench.desc",
			handler: func(ms *menuSession) error { return ms.benchFlow() },
			details: []string{"tab.bench.d1", "tab.bench.d2", "tab.bench.d3"},
			aliases: []string{"bench"},
		},
		{
			key: "o", short: "4", icon: "◆",
			name: "tab.openapi.name", description: "tab.openapi.desc",
			handler: func(ms *menuSession) error { return ms.openAPIFlow() },
			details: []string{"tab.openapi.d1", "tab.openapi.d2"},
		},
		{
			key: "d", short: "5", icon: "◐",
			name: "tab.diff.name", description: "tab.diff.desc",
			handler: func(ms *menuSession) error { return ms.diffFlow() },
			details: []string{"tab.diff.d1", "tab.diff.d2"},
		},
		{
			key: "x", short: "6", icon: "■",
			name: "tab.suppress.name", description: "tab.suppress.desc",
			handler: func(ms *menuSession) error { return ms.suppressFlow() },
			details: []string{"tab.suppress.d1"},
		},
		{
			key: "c", short: "7", icon: "❯",
			name: "tab.console.name", description: "tab.console.desc",
			handler: func(ms *menuSession) error { return ms.commandConsole() },
			details: []string{"tab.console.d1", "tab.console.d2", "tab.console.d3"},
			aliases: []string{"console", "shell", "terminal"},
		},
		{
			key: "h", short: "8", icon: "?",
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

// Geriye dönük uyumluluk: paketteki diğer dosyalar bu sabitleri kullanıyor olabilir.
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	BgBlue  = "\033[44m"
	BgGray  = "\033[100m"
)

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

func lerp(a, b int, t float64) int { return a + int(float64(b-a)*t+0.5) }

// gradient: satırı soldan sağa camgöbeği → mor geçişiyle boyar.
func (t theme) gradient(line string, total int) string {
	if !t.color {
		return line
	}
	var b strings.Builder
	for i, r := range []rune(line) {
		if r == ' ' {
			b.WriteRune(r)
			continue
		}
		ratio := float64(i) / float64(total-1)
		if t.truecolor {
			fmt.Fprintf(&b, "\033[38;2;%d;%d;%dm%c",
				lerp(56, 139, ratio), lerp(225, 92, ratio), lerp(255, 246, ratio), r)
		} else if ratio < 0.5 {
			fmt.Fprintf(&b, "\033[36;1m%c", r)
		} else {
			fmt.Fprintf(&b, "\033[35;1m%c", r)
		}
	}
	b.WriteString("\033[0m")
	return b.String()
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
	const labelW = 8
	return s.th.muted(padVisible(label, labelW)) + truncate(value, s.boxWidth()-4-labelW)
}

func kb(t theme, key, desc string) string {
	return t.accent(key) + " " + t.muted(desc)
}

// keyTag: bir kısayol harfini köşeli parantez içinde vurgular (örn. "[s]").
func (s *menuSession) keyTag(key string) string {
	if key == "" {
		return ""
	}
	return s.th.accent("[" + key + "]")
}

// ─────────────────────────────────────────────────────────────────────────────
// Ekranlar: banner, sekme çubuğu, içerik, bilgi çubuğu
// ─────────────────────────────────────────────────────────────────────────────

func (s *menuSession) printTabBar() {
	s.println()
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
		name := s.t(t.name)
		plain := fmt.Sprintf(" %s %s ", t.key, name)
		w := utf8.RuneCountInString(plain)
		if used > 0 && used+w+1 > s.boxWidth() {
			flush()
		}
		if i == s.currentTab {
			line.WriteString(s.th.pill(plain))
		} else {
			line.WriteString(s.th.accent(" "+t.key) + s.th.muted(" "+name+" "))
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
			lines = append(lines, s.th.accent("•")+" "+truncate(s.t(d), inner-2))
		}
	}
	lines = append(lines, "",
		s.th.accent("Enter")+s.th.muted(s.t("tabcontent.open")))
	title := s.th.accent(icon) + " " + s.th.bold(s.t(t.name)) + " " +
		s.th.muted(fmt.Sprintf("[%s/%s]", t.short, t.key))
	s.panel(title, s.th.accent, lines...)
}

func (s *menuSession) printInfoBar() {
	s.println()
	s.println("  " + s.th.muted(s.t("infobar.main", len(s.tabs))))
	if s.last.valid {
		mark := s.th.good("✔")
		if s.last.failed {
			mark = s.th.bad("✘")
		}
		s.println("  " + s.th.muted(s.t("infobar.last")) + " " + truncate(s.last.cmd, s.boxWidth()-24) +
			" " + mark + " " + s.th.muted(fmtDuration(s.last.took)))
	}
}

func (s *menuSession) printBanner() {
	art := []string{
		` ██████╗  █████╗ ███████╗██╗  ██╗`,
		`██╔════╝ ██╔══██╗██╔════╝██║  ██║`,
		`██║  ███╗███████║███████╗███████║`,
		`██║   ██║██╔══██║╚════██║██╔══██║`,
		`╚██████╔╝██║  ██║███████║██║  ██║`,
		` ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝`,
	}
	s.println()
	for _, l := range art {
		s.println("    " + s.th.gradient(l, 33))
	}
	s.println()
	s.println("    " + s.th.accent(s.t("banner.tagline")))
	s.println("    " + s.th.muted(s.t("banner.credits")))
	s.println()

	var warn []string
	for _, l := range wrapText(s.t("banner.legalText"), s.boxWidth()-4) {
		warn = append(warn, s.th.warn(l))
	}
	s.panel(s.th.warn(s.t("banner.legalTitle")), s.th.warn, warn...)
}

func (s *menuSession) header(icon, title string) {
	s.println()
	s.printf("  %s %s  %s\n", s.th.accent(icon), s.th.bold(title), s.th.muted(s.t("common.cancelHint")))
	s.rule()
}

func (s *menuSession) goodbye() {
	fmt.Fprintln(s.out, s.th.accent(s.t("goodbye")))
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
		s.println("  " + s.th.muted(s.t("help.tabsNote", flowTabs[0], flowTabs[n-1])))
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
		rows = append(rows, row{c.Name(), c.Short, strings.Join(subs, " · ")})
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

func (s *menuSession) scanFlow() error {
	s.header("◎", s.t("scan.title"))

	var target string
	for {
		raw, err := s.withMemo(s.t("scan.target"), s.memo["target"])
		if err != nil {
			return err
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

	scope, err := s.optional(s.t("scan.scope") + " " + s.th.muted(s.t("scan.scopeEmpty")) + ": ")
	if err != nil {
		return err
	}

	defProfile := s.memo["profile"]
	if defProfile == "" {
		defProfile = "standard"
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

	output, err := s.optional(s.t("scan.output") + " " + s.th.muted(s.t("scan.outputEmpty")) + ": ")
	if err != nil {
		return err
	}

	var oobServer string
	var browserCrawl bool
	var infraScan bool
	var infraDeep bool
	var customTimeout string
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
			{"custom", "c", "oob.custom.label", "oob.custom.desc"},
			{"none", "n", "oob.none.label", "oob.none.desc"},
		}, "local")
		if err != nil {
			return err
		}
		switch oobChoice {
		case "local":
			oobServer = "local"
		case "custom":
			customURL, err := s.withMemo(s.t("scan.oobPrompt")+" "+s.th.muted(s.t("scan.oobExample")), s.memo["oob"])
			if err != nil {
				return err
			}
			oobServer = customURL
		default:
			oobServer = ""
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

	args := []string{"scan", "--target", target, "--profile", profile}
	if scope != "" {
		args = append(args, "--scope", scope)
	}
	if profile == "deep" {
		args = append(args, "--deep")
	}
	if profile == "aggressive" {
		args = append(args, "--aggressive")
	}
	if customTimeout != "" {
		args = append(args, "--plugin-timeout", customTimeout)
	}
	if oobServer != "" {
		args = append(args, "--oob-server", oobServer, "--active")
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
	if output != "" {
		args = append(args, "--output", output)
	}

	scopeLabel, outLabel := scope, output
	if scopeLabel == "" {
		scopeLabel = s.t("common.free")
	}
	if outLabel == "" {
		outLabel = s.t("common.auto")
	}
	s.println()
	kvLabelW := 8
	summaryItems := []string{
		s.kv(s.t("kv.target"), target),
		s.kv(s.t("kv.scope"), scopeLabel),
		s.th.muted(padVisible(s.t("kv.profile"), kvLabelW)) + s.profileTone(profile),
		s.kv(s.t("kv.report"), outLabel),
	}
	if oobServer != "" {
		oobLabel := oobServer
		if oobServer == "local" {
			oobLabel = s.th.good(s.t("scan.oobLocalLabel"))
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
	s.printf("  %s %s\n", s.th.muted(s.t("scan.command")), "gash "+shellJoin(args))
	s.println()

	ok, err := s.confirm(s.t("scan.startConfirm"), true)
	if err != nil {
		return err
	}
	if !ok {
		s.println("  " + s.t("scan.cancelled"))
		return nil
	}

	s.remember("target", target)
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
			outPath, err := s.optional(s.t("bench.outFile") + " " + s.th.muted("(boş=stdout)") + ": ")
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
		s.printf("  %s  %s\n", s.th.muted(fmt.Sprintf("%3d", i+1)), h)
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

	s.last = lastRun{cmd: strings.Join(args, " "), took: took, failed: err != nil || cancelled, valid: true}
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
	hint := "[" + strings.ToLower(yes) + "/" + strings.ToLower(no) + "]"
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
	s.printf("  %s\n", s.th.bold(label))
	for i, o := range opts {
		marker := " "
		if i == defIdx {
			marker = s.th.accent("›")
		}
		s.printf("  %s %s  %s  %s\n", marker, s.keyTag(o.key),
			padVisible(s.t(o.label), labelW), s.th.muted(s.t(o.desc)))
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
	for {
		s.println()
		lines := make([]string, 0, len(items)+3)
		for _, it := range items {
			lines = append(lines, s.keyTag(it.key)+"  "+padVisible(s.t(it.label), labelW)+"  "+
				s.th.muted(truncate(s.t(it.desc), inner-4-labelW-2)))
		}
		lines = append(lines, "", s.th.accent("0")+"  "+backLabel+s.th.muted("   "+s.t("submenu.hint")))
		s.panel(s.th.bold(title), s.th.accent, lines...)

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
	return raw, schemeAdded, nil
}

func shellQuote(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\n\"'\\$&|;<>()*?[]{}!#~`") {
		return a
	}
	return "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
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
