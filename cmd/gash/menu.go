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

	th      theme
	width   int               // panel genişliği (kenarlar dahil)
	history []string          // konsolda çalıştırılan komutlar
	last    lastRun           // en son çalıştırılan komutun özeti
	memo    map[string]string // oturum boyunca hatırlanan son değerler
}

type tab struct {
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

type menuItem struct {
	label string
	desc  string
	run   func() error
}

type choice struct {
	value string
	label string
	desc  string
}

func newMenuCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "menu",
		Aliases: []string{"console", "interactive", "shell"},
		Short:   "Etkileşimli menü + Gash komut terminali",
		Long: "Etkileşimli menüyü açar. Menüden tarama, plugin, benchmark, OpenAPI, diff ve suppress\n" +
			"işlemleri yapılabilir; komut terminalinden tüm gash komutları çalıştırılabilir.\n\n" +
			"İpuçları: Enter vurgulanan sekmeyi açar, ':komut' menüden çıkmadan komut çalıştırır,\n" +
			"soru sırasında 'iptal' yazmak işlemi iptal eder, Ctrl+C çalışan komutu durdurur.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInteractiveMenu(cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
}

func runInteractiveMenu(in io.Reader, out io.Writer) error {
	s := newMenuSession(in, out)
	return s.run()
}

func newMenuSession(in io.Reader, out io.Writer) *menuSession {
	return &menuSession{
		in:          bufio.NewReader(in),
		out:         out,
		rootFactory: newRoot,
		th:          detectTheme(out),
		width:       detectWidth(),
		memo:        map[string]string{},
	}
}

func runPluginsMenu(in io.Reader, out io.Writer) error {
	s := newMenuSession(in, out)
	s.initTabs()
	return s.pluginsFlow()
}

func runBenchMenu(in io.Reader, out io.Writer) error {
	s := newMenuSession(in, out)
	s.initTabs()
	return s.benchFlow()
}

func runSuppressMenu(in io.Reader, out io.Writer) error {
	s := newMenuSession(in, out)
	s.initTabs()
	return s.suppressFlow()
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
		raw, err := s.readRaw("  " + s.th.brand("menü") + " " + s.th.accent("❯") + " ")
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
		case "p", "prev", "left", "<":
			s.prevTab()
			continue
		}
		if i := s.findTab(choice); i >= 0 {
			if s.openTab(i) {
				return nil
			}
			continue
		}
		fmt.Fprintf(s.out, "  %s\n", s.th.bad(fmt.Sprintf("Geçersiz seçim: %q", choice)))
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
			name: "Tarama", short: "1", icon: "◎",
			description: "Hedef URL tarama ve profil seçimi",
			handler:     func(ms *menuSession) error { return ms.scanFlow() },
			details: []string{
				"Profiller: safe · standard · deep · aggressive",
				"Kapsam sınırı (CIDR/domain) ve rapor dosyası",
				"Başlatmadan önce özet, onay ve eşdeğer komut",
			},
			aliases: []string{"scan"},
		},
		{
			name: "Pluginler", short: "2", icon: "◈",
			description: "Plugin listesi, doğrulama, test, yeni plugin",
			handler:     func(ms *menuSession) error { return ms.pluginsFlow() },
			details: []string{
				"Listele, doğrula, fixture testi çalıştır",
				"Yeni plugin iskeleti (yaml/js)",
				"Tier3 plugin trust",
			},
			aliases: []string{"plugin", "plugins"},
		},
		{
			name: "Benchmark", short: "3", icon: "▲",
			description: "Dataset doğrulama, çalıştırma, baseline, lab",
			handler:     func(ms *menuSession) error { return ms.benchFlow() },
			details: []string{
				"Dataset doğrulama ve araç karşılaştırmalı çalıştırma",
				"Baseline üretme ve karşılaştırma",
				"Yerel lab: durum · başlat · durdur · sıfırla",
			},
			aliases: []string{"bench"},
		},
		{
			name: "OpenAPI", short: "4", icon: "◆",
			description: "Spec'ten test planı üretimi",
			handler:     func(ms *menuSession) error { return ms.openAPIFlow() },
			details: []string{
				"Spec dosyası veya http(s) URL",
				"Çıktı biçimi: text veya json",
			},
		},
		{
			name: "Diff", short: "5", icon: "◐",
			description: "İki raporun farkı (new/fixed/unchanged)",
			handler:     func(ms *menuSession) error { return ms.diffFlow() },
			details: []string{
				"Baseline ile güncel raporu karşılaştır",
				"CI kapısı: yeni bulguda hata koduyla çık",
			},
		},
		{
			name: "Suppress", short: "6", icon: "■",
			description: "Yerel suppress ekle/listele/kaldır",
			handler:     func(ms *menuSession) error { return ms.suppressFlow() },
			details: []string{
				"Finding ID ile yerel suppress yönetimi",
			},
		},
		{
			name: "Konsol", short: "7", icon: "❯",
			description: "Tüm gash komutlarını çalıştır",
			handler:     func(ms *menuSession) error { return ms.commandConsole() },
			details: []string{
				"Komut geçmişi: history, !!, !N",
				"Komut listesi: komutlar",
				"İstem rengi son komutun sonucunu gösterir",
			},
			aliases: []string{"console", "shell", "terminal"},
		},
		{
			name: "Yardım", short: "8", icon: "?",
			description: "Genel yardım ve komut referansı",
			handler:     func(ms *menuSession) error { ms.helpScreen(); return nil },
			details: []string{
				"Klavye kısayolları ve komut listesi",
			},
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

// findTab: tab adı, takma adı veya (benzersiz) ön ekiyle sekme bulur.
func (s *menuSession) findTab(q string) int {
	q = strings.ToLower(q)
	for i, t := range s.tabs {
		if q == strings.ToLower(t.name) {
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
			if strings.HasPrefix(strings.ToLower(t.name), q) {
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
		plain := fmt.Sprintf(" %s %s ", t.short, t.name)
		w := utf8.RuneCountInString(plain)
		if used > 0 && used+w+1 > s.boxWidth() {
			flush()
		}
		if i == s.currentTab {
			line.WriteString(s.th.pill(plain))
		} else {
			line.WriteString(s.th.accent(" "+t.short) + s.th.muted(" "+t.name+" "))
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
	lines := []string{s.th.bold(truncate(t.description, inner))}
	if len(t.details) > 0 {
		lines = append(lines, "")
		for _, d := range t.details {
			lines = append(lines, s.th.accent("•")+" "+truncate(d, inner-2))
		}
	}
	lines = append(lines, "",
		s.th.accent("Enter")+s.th.muted(" ile aç  ·  ya da ")+s.th.accent(t.short)+s.th.muted(" yazın"))
	s.panel(s.th.accent(icon)+" "+s.th.bold(t.name), s.th.accent, lines...)
}

func (s *menuSession) printInfoBar() {
	s.println()
	s.println("  " + s.th.muted(fmt.Sprintf(
		"[1-%d] sekme · Enter aç · n/p gezin · :komut · h yardım · q çıkış", len(s.tabs))))
	if s.last.valid {
		mark := s.th.good("✔")
		if s.last.failed {
			mark = s.th.bad("✘")
		}
		s.println("  " + s.th.muted("son komut:") + " " + truncate(s.last.cmd, s.boxWidth()-24) +
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
	s.println("    " + s.th.accent("GASH  //  hibrit plugin güvenlik tarayıcısı"))
	s.println("    " + s.th.muted("Geliştirici: Xmar1881  •  Lisans: AGPL-3.0-only"))
	s.println()

	var warn []string
	for _, l := range wrapText("Yalnızca sahibi olduğunuz veya yazılı izin aldığınız hedeflerde kullanın.", s.boxWidth()-4) {
		warn = append(warn, s.th.warn(l))
	}
	s.panel(s.th.warn("[!] Yasal uyarı"), s.th.warn, warn...)
}

func (s *menuSession) header(icon, title string) {
	s.println()
	s.printf("  %s %s  %s\n", s.th.accent(icon), s.th.bold(title), s.th.muted("(vazgeçmek için 'iptal' yazın)"))
	s.rule()
}

func (s *menuSession) goodbye() {
	fmt.Fprintln(s.out, s.th.accent("Görüşürüz."))
}

// helpScreen: kısayollar + cobra'dan okunan komut listesi.
func (s *menuSession) helpScreen() {
	s.println()
	inner := s.boxWidth() - 4
	rows := [][2]string{
		{"1-8", "Sekmeyi doğrudan aç"},
		{"Enter", "Vurgulanan sekmeyi aç"},
		{"n / p", "Sonraki / önceki sekme"},
		{":komut", "Menüden çıkmadan komut çalıştır (örn. :plugins list)"},
		{"iptal", "Soru sırasında yazılırsa işlemi iptal eder"},
		{"Ctrl+C", "Çalışan komutu durdurur; ikinci basış zorla çıkar"},
		{"q", "Çıkış"},
	}
	var lines []string
	for _, r := range rows {
		lines = append(lines, s.th.accent(padVisible(r[0], 8))+truncate(r[1], inner-8))
	}
	s.panel(s.th.bold("Klavye kısayolları"), s.th.accent, lines...)
	s.println()
	s.printCommands()
	s.println()
	s.println("  " + s.th.muted("Menüdeki tüm işlemleri [1-6] sekmelerinden etkileşimli olarak yapabilirsiniz."))
	s.println("  " + s.th.muted("İleri düzey veya özel bayraklar için 7 (Konsol) sekmesini kullanabilirsiniz."))
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
	s.panel(s.th.bold("Komutlar"), s.th.accent, lines...)
}

// ─────────────────────────────────────────────────────────────────────────────
// Akışlar
// ─────────────────────────────────────────────────────────────────────────────

func (s *menuSession) scanFlow() error {
	s.header("◎", "Tarama")

	var target string
	for {
		raw, err := s.withMemo("Hedef URL", s.memo["target"])
		if err != nil {
			return err
		}
		t, added, err := normalizeTarget(raw)
		if err != nil {
			s.printf("  %s\n", s.th.bad(err.Error()))
			continue
		}
		if added {
			s.printf("  %s\n", s.th.muted("Şema yazılmadı, https:// eklendi → "+t))
		}
		target = t
		break
	}

	scope, err := s.optional("Kapsam (CIDR/domain) " + s.th.muted("(boş=serbest)") + ": ")
	if err != nil {
		return err
	}

	defProfile := s.memo["profile"]
	if defProfile == "" {
		defProfile = "standard"
	}
	profile, err := s.choose("Profil", []choice{
		{"safe", "safe", "Pasif ve düşük riskli kontroller"},
		{"standard", "standard", "Dengeli varsayılan profil"},
		{"deep", "deep", "Daha kapsamlı, daha yavaş"},
		{"aggressive", "aggressive", "Ofansif — yazılı izin gerekir"},
	}, defProfile)
	if err != nil {
		return err
	}

	if profile == "aggressive" {
		ok, err := s.confirm(s.th.warn("Agresif mod aktif/ofansiftir.")+" Hedef için yetkiniz var mı?", false)
		if err != nil {
			return err
		}
		if !ok {
			s.println("  Tarama iptal edildi.")
			return nil
		}
	}

	output, err := s.optional("Rapor dosyası " + s.th.muted("(boş=otomatik)") + ": ")
	if err != nil {
		return err
	}

	var oobServer string
	var browserCrawl bool
	var infraScan bool
	var customTimeout string
	advanced, err := s.confirm("Gelişmiş ayarları yapılandır (OOB, headless tarayıcı, altyapı)?", false)
	if err != nil {
		return err
	}
	if advanced {
		oobChoice, err := s.choose("OOB Etkileşim Sunucusu", []choice{
			{"local", "local", "Dahili yerel dinleyici — sunucu gerekmez"},
			{"custom", "custom", "Özel URL gir (interactsh vb.)"},
			{"none", "none", "Kapalı — OOB kullanma"},
		}, "local")
		if err != nil {
			return err
		}
		switch oobChoice {
		case "local":
			oobServer = "local"
		case "custom":
			customURL, err := s.withMemo("OOB sunucu URL'i "+s.th.muted("(örn: http://127.0.0.1:8080)"), s.memo["oob"])
			if err != nil {
				return err
			}
			oobServer = customURL
		default:
			oobServer = ""
		}

		bc, err := s.confirm("Headless Chrome ile SPA yüzeyi ve XSS doğrulama açılsın mı?", true)
		if err != nil {
			return err
		}
		browserCrawl = bc

		infra, err := s.confirm("Altyapı (SSH banner / DB port / TLS) denetimleri eklensin mi?", false)
		if err != nil {
			return err
		}
		infraScan = infra

		to, err := s.optional("Zaman aşımı / timeout " + s.th.muted("(boş=varsayılan, örn: 60s, 120s, 180s)") + ": ")
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
	if output != "" {
		args = append(args, "--output", output)
	}

	scopeLabel, outLabel := scope, output
	if scopeLabel == "" {
		scopeLabel = "serbest"
	}
	if outLabel == "" {
		outLabel = "otomatik"
	}
	s.println()
	summaryItems := []string{
		s.kv("Hedef", target),
		s.kv("Kapsam", scopeLabel),
		s.th.muted(padVisible("Profil", 8)) + s.profileTone(profile),
		s.kv("Rapor", outLabel),
	}
	if oobServer != "" {
		oobLabel := oobServer
		if oobServer == "local" {
			oobLabel = s.th.good("local (dahili dinleyici)")
		}
		summaryItems = append(summaryItems, s.kv("OOB", oobLabel))
	}
	if customTimeout != "" {
		summaryItems = append(summaryItems, s.kv("Timeout", customTimeout))
	}
	if browserCrawl {
		summaryItems = append(summaryItems, s.kv("Tarayıcı", s.th.good("aktif (Chrome SPA)")))
	}
	if infraScan {
		summaryItems = append(summaryItems, s.kv("Altyapı", s.th.good("aktif (SSH/DB/TLS)")))
	}
	s.panel(s.th.bold("Tarama özeti"), s.th.accent, summaryItems...)
	s.printf("  %s %s\n", s.th.muted("Çalıştırılacak işlem:"), "gash "+shellJoin(args))
	s.println()

	ok, err := s.confirm("Taramayı başlat?", true)
	if err != nil {
		return err
	}
	if !ok {
		s.println("  Tarama iptal edildi.")
		return nil
	}

	s.remember("target", target)
	if profile != "aggressive" { // agresif profil asla varsayılan olarak hatırlanmaz
		s.remember("profile", profile)
	}
	s.printf("  %s %s\n", s.th.accent("▶ Tarama başlatılıyor..."), s.th.muted("(durdurmak için Ctrl+C)"))
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
	return s.submenu("Plugin yönetimi", "Ana menü", []menuItem{
		{"Listele", "Kayıtlı pluginleri göster", func() error {
			s.execute("plugins", "list")
			return nil
		}},
		{"Doğrula", "Plugin dosyasını doğrula", func() error {
			defPath := "plugins/headers/missing-security-headers.yaml"
			file, err := s.defaulted(s.dprompt("Plugin dosyası", defPath), defPath)
			if err != nil {
				return err
			}
			s.execute("plugins", "validate", file)
			return nil
		}},
		{"Fixture testi", "Plugin fixture testlerini çalıştır", func() error {
			defPath := "plugins/headers/missing-security-headers.yaml"
			file, err := s.defaulted(s.dprompt("Plugin dosyası", defPath), defPath)
			if err != nil {
				return err
			}
			s.execute("plugins", "test", file)
			return nil
		}},
		{"Bilgi göster", "Plugin ID ile ayrıntıları göster", func() error {
			defID := "missing-security-headers"
			id, err := s.defaulted(s.dprompt("Plugin ID", defID), defID)
			if err != nil {
				return err
			}
			s.execute("plugins", "info", id)
			return nil
		}},
		{"Yeni plugin", "İskelet oluştur (yaml/js)", func() error {
			name, err := s.required("Plugin adı: ")
			if err != nil {
				return err
			}
			tier, err := s.choose("Tier", []choice{
				{"yaml", "yaml", "Bildirimsel plugin (önerilen)"},
				{"js", "js", "Betik tabanlı plugin"},
			}, "yaml")
			if err != nil {
				return err
			}
			s.execute("plugins", "new", name, "--tier", tier)
			return nil
		}},
		{"Tier3 trust", "Tier3 plugin manifest'ine güven ver", func() error {
			manifest, err := s.requiredPath("Tier3 manifest dosyası: ", false)
			if err != nil {
				return err
			}
			ok, err := s.confirm("Bu manifest'e güvenilecek. Kaynağını doğruladınız mı?", false)
			if err != nil {
				return err
			}
			if !ok {
				s.println("  Trust işlemi iptal edildi.")
				return nil
			}
			s.execute("plugins", "trust", manifest)
			return nil
		}},
	})
}

func (s *menuSession) benchFlow() error {
	const defDataset = "bench/datasets/fixtures.yaml"
	return s.submenu("Benchmark", "Ana menü", []menuItem{
		{"Dataset doğrula", "Dataset YAML şemasını kontrol et", func() error {
			dataset, err := s.defaulted(s.dprompt("Dataset YAML", defDataset), defDataset)
			if err != nil {
				return err
			}
			s.execute("bench", "validate", dataset)
			return nil
		}},
		{"Benchmark çalıştır", "Araçları dataset üzerinde çalıştır", func() error {
			dataset, err := s.defaulted(s.dprompt("Dataset YAML", defDataset), defDataset)
			if err != nil {
				return err
			}
			outDir, err := s.optional("Rapor dizini " + s.th.muted("(boş=otomatik)") + ": ")
			if err != nil {
				return err
			}
			tools, err := s.defaulted(s.dprompt("Araçlar", "gash,nuclei"), "gash,nuclei")
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
		{"Baseline karşılaştır", "Güncel raporu baseline ile kıyasla", func() error {
			baseline, err := s.requiredPath("Baseline dosyası: ", false)
			if err != nil {
				return err
			}
			current, err := s.requiredPath("Güncel rapor dosyası: ", false)
			if err != nil {
				return err
			}
			s.execute("bench", "compare", "--baseline", baseline, "--current", current)
			return nil
		}},
		{"Baseline üret", "Rapordan baseline oluştur", func() error {
			report, err := s.requiredPath("Benchmark report.json: ", false)
			if err != nil {
				return err
			}
			tool, err := s.defaulted(s.dprompt("Araç", "gash"), "gash")
			if err != nil {
				return err
			}
			outPath, err := s.optional("Çıktı dosyası " + s.th.muted("(boş=stdout)") + ": ")
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
		{"Lab yönetimi", "Yerel benchmark labını yönet", s.labFlow},
	})
}

func (s *menuSession) labFlow() error {
	return s.submenu("Benchmark lab", "Geri", []menuItem{
		{"Durum", "Lab durumunu göster", func() error { s.execute("bench", "lab", "status"); return nil }},
		{"Başlat", "Lab ortamını ayağa kaldır", func() error { s.execute("bench", "lab", "up"); return nil }},
		{"Durdur", "Lab ortamını durdur", func() error { s.execute("bench", "lab", "down"); return nil }},
		{"Sıfırla", "Lab ortamını sıfırla", func() error {
			ok, err := s.confirm("Lab ortamı sıfırlanacak. Devam edilsin mi?", false)
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
	s.header("◆", "OpenAPI test planı")
	spec, err := s.requiredPath("Spec dosyası veya http(s) URL: ", true)
	if err != nil {
		return err
	}
	format, err := s.choose("Çıktı biçimi", []choice{
		{"text", "text", "Okunabilir özet"},
		{"json", "json", "Makine tarafından okunabilir"},
	}, "text")
	if err != nil {
		return err
	}
	server, err := s.optional("Sunucu " + s.th.muted("(boş=spec'teki ilk sunucu)") + ": ")
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
	s.header("◐", "Rapor diff")
	oldPath, err := s.requiredPath("Eski/baseline JSON raporu: ", false)
	if err != nil {
		return err
	}
	newPath, err := s.requiredPath("Yeni/güncel JSON raporu: ", false)
	if err != nil {
		return err
	}
	format, err := s.choose("Çıktı biçimi", []choice{
		{"text", "text", "Okunabilir özet"},
		{"json", "json", "Makine tarafından okunabilir"},
	}, "text")
	if err != nil {
		return err
	}
	failOn, err := s.choose("CI kapısı", []choice{
		{"", "yok", "Yalnızca raporla"},
		{"new", "new", "Yeni bulgu varsa hata koduyla çık"},
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
	return s.submenu("Suppress yönetimi", "Ana menü", []menuItem{
		{"Listele", "Yerel suppress kayıtlarını göster", func() error {
			s.execute("suppress", "list")
			return nil
		}},
		{"Ekle", "Finding ID'yi sustur", func() error {
			id, err := s.required("Finding ID: ")
			if err != nil {
				return err
			}
			s.execute("suppress", "add", id)
			return nil
		}},
		{"Kaldır", "Suppress kaydını sil", func() error {
			id, err := s.required("Finding ID: ")
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
	s.panel(s.th.accent("❯")+" "+s.th.bold("Komut terminali"), s.th.accent,
		"Komutları 'gash' olmadan yazın (örn. plugins list).",
		kb(s.th, "menu", "ana menü")+"  ·  "+kb(s.th, "exit", "çıkış")+"  ·  "+kb(s.th, "clear", "temizle")+"  ·  "+kb(s.th, "?", "tam yardım"),
		kb(s.th, "komutlar", "komut listesi")+"  ·  "+kb(s.th, "history", "geçmiş"),
		kb(s.th, "!!", "son komutu tekrarla")+"  ·  "+kb(s.th, "!N", "geçmişten çalıştır"),
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
		s.println("  " + s.th.muted("Geçmiş boş."))
		return "", false
	}
	if line == "!!" {
		return s.history[len(s.history)-1], true
	}
	n, err := strconv.Atoi(strings.TrimPrefix(line, "!"))
	if err != nil || n < 1 || n > len(s.history) {
		s.printf("  %s\n", s.th.bad("Geçersiz geçmiş numarası: "+line))
		return "", false
	}
	return s.history[n-1], true
}

func (s *menuSession) printHistory() {
	if len(s.history) == 0 {
		s.println("  " + s.th.muted("Geçmiş boş."))
		return
	}
	for i, h := range s.history {
		s.printf("  %s  %s\n", s.th.muted(fmt.Sprintf("%3d", i+1)), h)
	}
}

func (s *menuSession) runCommandLine(line string) {
	args, err := splitCommandLine(line)
	if err != nil {
		fmt.Fprintf(s.out, "Hata: %v\n", err)
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
		fmt.Fprintf(s.out, "  %s%s\n", s.th.warn("■ iptal edildi"), t)
	case err != nil:
		fmt.Fprintf(s.out, "  %s%s\n", s.th.bad("✘ Hata: "+err.Error()), t)
	default:
		fmt.Fprintf(s.out, "  %s%s\n", s.th.good("✔ tamamlandı"), t)
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
					fmt.Fprintf(s.out, "\n  %s\n", s.th.warn("Ctrl+C: komut durduruluyor… (zorla çıkmak için tekrar basın)"))
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
		s.printf("  %s\n", s.th.warn("Bu alan zorunlu."))
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
			s.printf("  %s\n", s.th.bad("Dosya bulunamadı: "+p))
			continue
		}
		return p, nil
	}
}

func (s *menuSession) confirm(question string, def bool) (bool, error) {
	hint := "[E/h]"
	if !def {
		hint = "[e/H]"
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
		s.printf("  %s\n", s.th.warn("Lütfen 'e' (evet) veya 'h' (hayır) yazın."))
	}
}

// choose numaralı bir seçenek listesi gösterir; numara, ad veya Enter (varsayılan) kabul eder.
func (s *menuSession) choose(label string, opts []choice, def string) (string, error) {
	defIdx, labelW := 0, 0
	for i, o := range opts {
		if o.value == def {
			defIdx = i
		}
		if n := utf8.RuneCountInString(o.label); n > labelW {
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
		s.printf("  %s %s  %s  %s\n", marker, s.th.accent(strconv.Itoa(i+1)),
			padVisible(o.label, labelW), s.th.muted(o.desc))
	}
	for {
		in, err := s.readLine("Seçim " + s.th.muted("(numara/ad, Enter="+opts[defIdx].label+")") + ": ")
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
			if strings.EqualFold(in, o.label) || (o.value != "" && strings.EqualFold(in, o.value)) {
				return o.value, nil
			}
		}
		s.printf("  %s\n", s.th.bad(fmt.Sprintf("Geçersiz %s: %q", strings.ToLower(label), in)))
	}
}

// submenu: numaralı alt menü panelini gösterip seçilen işlemi çalıştırır.
// Bir işlem sırasında "iptal" yazılırsa alt menüye dönülür.
func (s *menuSession) submenu(title, backLabel string, items []menuItem) error {
	labelW := 0
	for _, it := range items {
		if n := utf8.RuneCountInString(it.label); n > labelW {
			labelW = n
		}
	}
	inner := s.boxWidth() - 4
	for {
		s.println()
		lines := make([]string, 0, len(items)+3)
		for i, it := range items {
			lines = append(lines, s.th.accent(strconv.Itoa(i+1))+"  "+padVisible(it.label, labelW)+"  "+
				s.th.muted(truncate(it.desc, inner-3-labelW-2)))
		}
		lines = append(lines, "", s.th.accent("0")+"  "+backLabel+s.th.muted("   ·   soru sırasında 'iptal' yazarak vazgeçebilirsiniz"))
		s.panel(s.th.bold(title), s.th.accent, lines...)

		choice, err := s.readLine("Seçim: ")
		if err != nil {
			return err
		}
		switch strings.ToLower(choice) {
		case "0", "b", "back", "geri":
			return nil
		}
		idx, convErr := strconv.Atoi(choice)
		if convErr != nil || idx < 1 || idx > len(items) {
			s.printf("  %s\n", s.th.bad(fmt.Sprintf("Geçersiz seçim: %q", choice)))
			continue
		}
		if err := items[idx-1].run(); err != nil {
			if errors.Is(err, errCancel) {
				s.printf("  %s\n", s.th.muted("İptal edildi."))
				continue
			}
			return err
		}
	}
}

func (s *menuSession) stopOn(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errCancel) {
		s.printf("  %s\n", s.th.muted("İptal edildi."))
		return false
	}
	if errors.Is(err, errExitMenu) || errors.Is(err, io.EOF) {
		s.goodbye()
		return true
	}
	fmt.Fprintf(s.out, "Hata: %v\n", err)
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Saf yardımcılar
// ─────────────────────────────────────────────────────────────────────────────

// normalizeTarget: şema yoksa https:// ekler, host'u doğrular.
func normalizeTarget(raw string) (target string, schemeAdded bool, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, errors.New("hedef boş olamaz")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
		schemeAdded = true
	}
	u, perr := url.Parse(raw)
	if perr != nil || u.Host == "" {
		return "", false, fmt.Errorf("geçersiz URL: %q", raw)
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
		return nil, fmt.Errorf("kapanmamış tırnak")
	}
	flush()
	return args, nil
}
