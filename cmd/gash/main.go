// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Command gash CLI entrypoint'tir (ince: yalnızca Execute; mantık internal/'dadır).
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/auth"
	"github.com/Xmar1881/Gash/internal/config"
	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/engine"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/plugin/scaffold"
	"github.com/Xmar1881/Gash/internal/plugintest"
	"github.com/Xmar1881/Gash/internal/reporter"
	"github.com/spf13/cobra"
)

func init() {
	// Disable Cobra's default Windows Mousetrap splash screen so double-clicking
	// gash.exe opens the interactive menu directly and subcommands executed from
	// within the menu are never intercepted with "This is a command line tool."
	cobra.MousetrapHelpText = ""
}

func main() {
	cobra.MousetrapHelpText = ""
	if len(os.Args) == 1 {
		handleNoArgs(newRoot())
		return
	}
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

// handleNoArgs opens the interactive menu when interactive, or prints usage otherwise.
// What: Launches interactive menu by default; help fallback when non-interactive.
// Why: Explorer double-click or running 'gash' directly opens the interactive menu.
func handleNoArgs(root *cobra.Command) {
	if isInteractive(os.Stdin) {
		if err := runInteractiveMenu(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			if shouldWaitForEnter() {
				waitForEnter()
			}
		}
		return
	}
	printNoArgsUsage(root)
	if shouldWaitForEnter() {
		waitForEnter()
	}
}

// printNoArgsUsage shows a clean overview and command list.
// What: Clean usage guidance without obsolete cmd.exe hints.
// Why: Gash has a full interactive menu; non-interactive runs get concise usage.
func printNoArgsUsage(root *cobra.Command) {
	fmt.Fprintln(os.Stdout, "Gash — hibrit plugin mimarili güvenlik tarayıcı motoru")
	fmt.Fprintln(os.Stdout, "Kullanım: gash [komut] [bayraklar]")
	fmt.Fprintln(os.Stdout, "          gash menu (etkileşimli menüyü açar)")
	fmt.Fprintln(os.Stdout, "")
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	_ = root.Help()
}

// shouldWaitForEnter decides if a pause is needed.
// What: True only on Windows when double-clicked or interactive.
// Why: Double-click consoles vanish on exit; pipes/CI must never block.
func shouldWaitForEnter() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	return isInteractive(os.Stdin)
}

// isInteractive reports whether a stream is connected to an interactive terminal or console.
// What: Char-device check plus Windows terminal environment detection.
// Why: Terminal shells (cmd, powershell, git-bash, wt) should enter interactive flows.
func isInteractive(r any) bool {
	if r == nil {
		return false
	}
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	if fi.Mode()&os.ModeCharDevice != 0 {
		return true
	}
	if runtime.GOOS == "windows" {
		if os.Getenv("WT_SESSION") != "" || os.Getenv("TERM") != "" || os.Getenv("MSYSTEM") != "" {
			return true
		}
	}
	return false
}

// waitForEnter pauses a Windows console.
// What: "Press Enter to exit..." prompt plus single line read.
// Why: Keeps double-click output readable until the user dismisses it.
func waitForEnter() {
	fmt.Fprintln(os.Stdout, "Press Enter to exit...")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}

func newRoot() *cobra.Command {
	cobra.MousetrapHelpText = ""
	root := &cobra.Command{
		Use:   "gash",
		Short: "Gash — hibrit plugin mimarili güvenlik tarayıcı motoru",
		Long:  "Gash çekirdek altyapı. Candidate→Verify→Finding hattı + oracle/baseline/OOB ile referans pluginleri çalıştırır.",
	}
	root.AddCommand(newScanCmd())
	root.AddCommand(newOpenAPICmd())
	root.AddCommand(newPluginsCmd())
	root.AddCommand(newBenchCmd())
	root.AddCommand(newSuppressCmd())
	root.AddCommand(newDiffCmd())
	root.AddCommand(newMenuCmd())
	root.AddCommand(newCompletionCmd())
	return root
}

func newScanCmd() *cobra.Command {
	var (
		target            string
		targetFile        string
		resume            bool
		outputDir         string
		reportStamp       bool
		proxy             string
		proxyFile         string
		proxyRotate       string
		proxyCooldown     string
		proxyTimeout      string
		noProxy           bool
		allowExternal     bool
		scanTimeout       string
		crawlTimeout      string
		safe              bool
		deep              bool
		active            bool
		aggressive        bool
		scope             []string
		maxPerTarget      int64
		maxTotal          int64
		pluginTimeout     string
		oobServer         string
		oobToken          string
		oobWait           string
		browserVerify     bool
		browserCrawl      bool
		browserCrawlPages int
		showTentative     bool
		format            []string
		output            string
		failOn            string
		noPluginCache     bool
		strictPlugins     bool
		profile           string
		ignorePlugins     []string
		onlyPlugins       []string
		rateLimit         float64
		parallelism       int
		authHeaders       []string
		cookies           []string
		basicAuth         string
		authUserA         []string
		authUserB         []string
		loginURL          string
		loginUser         string
		loginPass         string
		loginPassEnv      string
		loginUserField    string
		loginPassField    string
		loginVerifyURL    string
		techFlags         []string
		tcpBanners        []string
		maxPages          int
		depth             int
		openapiSpec       string
		requestTimeout    string
		maxResponseBytes  int64
		sshAudit          bool
		dbPortScan        bool
		dbPorts           string
		tlsAuditDeep      bool
		sshHandshakeAudit bool
		dbUnauth          bool
		infraTargets      []string
		maxInfraPorts     int
		infraTimeout      string
		infraRateLimit    float64
		infraParallelism  int
		flowSeeds         []string
		flowMaxSteps      int
		flowProbes        int
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Hedefi tara (Candidate→Verify→Finding hattı)",
		Long:  "Target scanner with live Tier1/Tier2/Tier3 execution and oracle verification.\n\nLegal: authorized testing only; operator responsibility. Scan only targets you own or have\nwritten permission to test; unauthorized scanning may be illegal.\nBy default the crawl and redirects are locked to the target's registrable domain (eTLD+1),\nso external links are not followed. --allow-external restores open mode; --scope pins an\nexplicit allowlist (CIDR/domain) instead.\nKeep --safe unless you understand active payloads.\nInfra recon is read-only: --ssh-audit (banner) and --db-port-scan (port/salutation) require\n--active; --tls-audit-deep observes legacy TLS 1.0/1.1 acceptance on https targets.\nDeeper infra recon: --ssh-handshake-audit observes the SSH KEXINIT algorithm lists\n(version exchange only; no key exchange, no auth) and --db-unauth probes each supported\ndatabase once with a fixed dummy user (no password, no data read); both require --active.\nScope and rate limits apply to all infra dials.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			if aggressive {
				active = true
				safe = false
				deep = true
				if !cmd.Flags().Changed("profile") {
					profile = "aggressive"
				}
				if !cmd.Flags().Changed("show-tentative") {
					showTentative = true
				}
			}
			if strings.TrimSpace(target) == "" && len(args) > 0 && strings.TrimSpace(args[0]) != "" {
				target = strings.TrimSpace(args[0])
			}
			if strings.TrimSpace(target) == "" && strings.TrimSpace(targetFile) == "" {
				return fmt.Errorf("scan: --target veya --target-file zorunlu")
			}
			if strings.TrimSpace(target) != "" && strings.TrimSpace(targetFile) != "" {
				return fmt.Errorf("scan: --target ve --target-file birlikte kullanılamaz")
			}
			if strings.TrimSpace(targetFile) != "" && strings.TrimSpace(output) != "" {
				return fmt.Errorf("scan: --target-file ile --output yerine --output-dir kullanın")
			}
			if oobServer != "" && !active {
				return fmt.Errorf("scan: --oob-server verildiyse --active zorunlu (OOB invasive'dir)")
			}
			// P2.1: TCP banner açık aktif probdur — bayrak + --active ikisi şart.
			for _, b := range tcpBanners {
				if h, p, err := net.SplitHostPort(strings.TrimSpace(b)); err != nil || strings.TrimSpace(h) == "" || strings.TrimSpace(p) == "" {
					return fmt.Errorf("scan: --tcp-banner host:port olmalı (got %q)", b)
				}
			}
			if len(tcpBanners) > 0 && !active {
				return fmt.Errorf("scan: --tcp-banner verildiyse --active zorunlu (banner probu aktiftir)")
			}
			// Faz 0: altyapı gözlemleri salt-okumadır ama aktif probdur.
			if sshAudit && !active {
				return fmt.Errorf("scan: --ssh-audit verildiyse --active zorunlu (SSH banner probu aktiftir)")
			}
			if dbPortScan && !active {
				return fmt.Errorf("scan: --db-port-scan verildiyse --active zorunlu (port probu aktiftir)")
			}
			// Faz 1: KEXINIT/unauth denetimleri de aktif probdur.
			if sshHandshakeAudit && !active {
				return fmt.Errorf("scan: --ssh-handshake-audit verildiyse --active zorunlu (KEXINIT probu aktiftir)")
			}
			if dbUnauth && !active {
				return fmt.Errorf("scan: --db-unauth verildiyse --active zorunlu (unauth probu tek istek gönderir)")
			}
			for _, tgt := range infraTargets {
				if h, p, err := net.SplitHostPort(strings.TrimSpace(tgt)); err != nil || strings.TrimSpace(h) == "" || strings.TrimSpace(p) == "" {
					return fmt.Errorf("scan: --infra-target host:port olmalı (got %q)", tgt)
				}
			}
			// Tarayıcı doğrulaması yalnızca statik XSS kanıtını gerçek tetikleme
			// + temiz kontrol ile confirmed'a taşır; aktif probdur.
			if browserVerify && !active {
				return fmt.Errorf("scan: --browser-verify verildiyse --active zorunlu (tarayıcı probu aktiftir)")
			}
			// SPA render'ı salt GET gözlemdir (--active gerekmez); sayfa tavanı
			// erken doğrulanır, renderer ayrıca non-GET istekleri bloklar.
			if browserCrawlPages < 1 || browserCrawlPages > 10 {
				return fmt.Errorf("scan: --browser-crawl-pages 1..10 aralığında olmalı (got %d)", browserCrawlPages)
			}
			// Çok-adımlı akış replay'i durum değiştiren form gönderimleri yapar.
			if len(flowSeeds) > 0 && !active {
				return fmt.Errorf("scan: --flow-seed verildiyse --active zorunlu (akış replay'i form POST'u gönderir)")
			}
			if len(flowSeeds) > 1 {
				return fmt.Errorf("scan: --flow-seed tek kez verilebilir (v1 tek akış)")
			}
			if flowMaxSteps < 1 || flowMaxSteps > 6 {
				return fmt.Errorf("scan: --flow-max-steps 1..6 aralığında olmalı (got %d)", flowMaxSteps)
			}
			if flowProbes < 1 || flowProbes > 10 {
				return fmt.Errorf("scan: --flow-probes 1..10 aralığında olmalı (got %d)", flowProbes)
			}
			var flowSeed string
			if len(flowSeeds) == 1 {
				flowSeed = strings.TrimSpace(flowSeeds[0])
				if u, err := url.Parse(flowSeed); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
					return fmt.Errorf("scan: --flow-seed geçersiz (http(s) URL olmalı, got %q)", flowSeed)
				}
				if len(scope) > 0 {
					if err := enforceScanScope(ctx, flowSeed, scope); err != nil {
						return fmt.Errorf("scan: --flow-seed %w", err)
					}
				}
			}
			var normalized string
			if strings.TrimSpace(target) != "" {
				var err error
				normalized, err = validateScanTarget(target)
				if err != nil {
					return err
				}
			}
			pluginDur, err := time.ParseDuration(strings.TrimSpace(pluginTimeout))
			if err != nil {
				return fmt.Errorf("scan: --plugin-timeout geçersiz %q: %w", pluginTimeout, err)
			}
			reqDur, err := time.ParseDuration(strings.TrimSpace(requestTimeout))
			if err != nil {
				return fmt.Errorf("scan: --request-timeout geçersiz %q: %w", requestTimeout, err)
			}
			scanDur, err := time.ParseDuration(strings.TrimSpace(scanTimeout))
			if err != nil || scanDur <= 0 {
				return fmt.Errorf("scan: --scan-timeout geçersiz %q (pozitif süre olmalı)", scanTimeout)
			}
			proxyDur, err := time.ParseDuration(strings.TrimSpace(proxyTimeout))
			if err != nil || proxyDur < 0 {
				return fmt.Errorf("scan: --proxy-timeout geçersiz %q (0 veya pozitif süre)", proxyTimeout)
			}
			crawlDur, err := time.ParseDuration(strings.TrimSpace(crawlTimeout))
			if err != nil || crawlDur <= 0 {
				return fmt.Errorf("scan: --crawl-timeout geçersiz %q (pozitif süre olmalı)", crawlTimeout)
			}
			dbPortsList, err := parseDBPorts(dbPorts)
			if err != nil {
				return err
			}
			infraDur, err := time.ParseDuration(strings.TrimSpace(infraTimeout))
			if err != nil {
				return fmt.Errorf("scan: --infra-timeout geçersiz %q: %w", infraTimeout, err)
			}
			if _, err := time.ParseDuration(strings.TrimSpace(oobWait)); err != nil {
				return fmt.Errorf("scan: --oob-wait geçersiz %q: %w", oobWait, err)
			}
			formats, err := normalizeScanFormats(format)
			if err != nil {
				return err
			}
			failLevel, err := normalizeFailOn(failOn)
			if err != nil {
				return err
			}
			// P2.5: kimlik bağlamı (parse fail-closed; değerler asla loglanmaz).
			authCtx := auth.New()
			for _, h := range authHeaders {
				if err := authCtx.ParseAuthHeader(h); err != nil {
					return err
				}
			}
			for _, c := range cookies {
				if err := authCtx.ParseCookie(c); err != nil {
					return err
				}
			}
			if strings.TrimSpace(basicAuth) != "" {
				if err := authCtx.ParseBasicAuth(basicAuth); err != nil {
					return err
				}
			}
			// Çift-kullanıcı BOLA matrisi (--auth-user-a/b): her biri bağımsız
			// "Ad: değer" başlık setidir (değerler asla loglanmaz).
			authA, authB := auth.New(), auth.New()
			for _, h := range authUserA {
				if err := authA.ParseAuthHeader(h); err != nil {
					return fmt.Errorf("scan: --auth-user-a %w", err)
				}
			}
			for _, h := range authUserB {
				if err := authB.ParseAuthHeader(h); err != nil {
					return fmt.Errorf("scan: --auth-user-b %w", err)
				}
			}
			dualAuth := authA.HasAuth() && authB.HasAuth()
			if (authA.HasAuth() || authB.HasAuth()) && !dualAuth {
				return fmt.Errorf("scan: --auth-user-a ve --auth-user-b birlikte verilmeli (BOLA matrisi iki kimlik ister)")
			}
			if dualAuth && !active {
				fmt.Fprintln(cmd.ErrOrStderr(), "warn: çift kullanıcı verildi ama --active kapalı — BOLA matrisi koşmaz")
			}
			if dualAuth {
				fmt.Fprintln(cmd.ErrOrStderr(), "user-a: "+authA.Redacted())
				fmt.Fprintln(cmd.ErrOrStderr(), "user-b: "+authB.Redacted())
			}
			if authCtx.HasAuth() && !active {
				fmt.Fprintln(cmd.ErrOrStderr(), "warn: kimlik bilgisi verildi ama --active kapalı — requires_auth plugin'ler koşar, aktif problar koşmaz")
			}
			if authCtx.HasAuth() {
				fmt.Fprintln(cmd.ErrOrStderr(), authCtx.Redacted())
			}
			// P2.6: login akışı (--login-url) — oturum kurulumu POST gönderir,
			// bu yüzden --active şart; tek kimlik seti zorunlu (parola denemesi YOK).
			var loginOpts *auth.LoginOptions
			loginFlagUsed := strings.TrimSpace(loginURL) != "" ||
				strings.TrimSpace(loginUser) != "" ||
				strings.TrimSpace(loginPass) != "" ||
				strings.TrimSpace(loginPassEnv) != "" ||
				strings.TrimSpace(loginUserField) != "" ||
				strings.TrimSpace(loginPassField) != "" ||
				strings.TrimSpace(loginVerifyURL) != ""
			if loginFlagUsed {
				if strings.TrimSpace(loginURL) == "" {
					return fmt.Errorf("scan: login bayrakları --login-url gerektirir")
				}
				if !active {
					return fmt.Errorf("scan: --login-url verildiyse --active zorunlu (oturum kurulumu POST gönderir)")
				}
				if strings.TrimSpace(loginUser) == "" {
					return fmt.Errorf("scan: --login-user zorunlu (tek kimlik seti; parola denemesi yapılmaz)")
				}
				hasPass := strings.TrimSpace(loginPass) != ""
				hasEnv := strings.TrimSpace(loginPassEnv) != ""
				switch {
				case hasPass && hasEnv:
					return fmt.Errorf("scan: --login-pass ve --login-pass-env birlikte kullanılamaz")
				case !hasPass && !hasEnv:
					return fmt.Errorf("scan: --login-pass veya --login-pass-env zorunlu")
				}
				resolvedPass := loginPass
				if hasEnv {
					resolvedPass = os.Getenv(strings.TrimSpace(loginPassEnv))
					if resolvedPass == "" {
						return fmt.Errorf("scan: --login-pass-env %q boş veya tanımsız", strings.TrimSpace(loginPassEnv))
					}
				}
				if u, err := url.Parse(strings.TrimSpace(loginURL)); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
					return fmt.Errorf("scan: --login-url geçersiz (http(s) URL olmalı, got %q)", loginURL)
				}
				if strings.TrimSpace(loginVerifyURL) != "" {
					if u, err := url.Parse(strings.TrimSpace(loginVerifyURL)); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
						return fmt.Errorf("scan: --login-verify-url geçersiz (http(s) URL olmalı, got %q)", loginVerifyURL)
					}
				}
				if len(scope) > 0 {
					if err := enforceScanScope(ctx, strings.TrimSpace(loginURL), scope); err != nil {
						return fmt.Errorf("scan: --login-url %w", err)
					}
					if strings.TrimSpace(loginVerifyURL) != "" {
						if err := enforceScanScope(ctx, strings.TrimSpace(loginVerifyURL), scope); err != nil {
							return fmt.Errorf("scan: --login-verify-url %w", err)
						}
					}
				}
				loginOpts = &auth.LoginOptions{
					LoginURL:    strings.TrimSpace(loginURL),
					VerifyURL:   strings.TrimSpace(loginVerifyURL),
					User:        loginUser,
					Pass:        resolvedPass,
					UserField:   strings.TrimSpace(loginUserField),
					PassField:   strings.TrimSpace(loginPassField),
					MaxAttempts: auth.DefaultLoginMaxAttempts,
				}
				verifyNote := "none"
				if loginOpts.VerifyURL != "" {
					verifyNote = loginOpts.VerifyURL
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "login: url=%s verify=%s user=[redacted] pass=[redacted]\n", loginOpts.LoginURL, verifyNote)
			}
			// Default to the target's registrable domain so the crawler stays
			// on-site instead of following external links until the deadline.
			if len(scope) == 0 && !allowExternal && strings.TrimSpace(target) != "" {
				if d := sameSiteDomain(normalized); d != "" {
					scope = []string{d}
					fmt.Fprintf(cmd.ErrOrStderr(), "notice: same-site scope %q (use --allow-external to leave the domain)\n", d)
				}
			}
			if strings.TrimSpace(target) != "" {
				if len(scope) > 0 {
					if err := enforceScanScope(ctx, normalized, scope); err != nil {
						return err
					}
				} else {
					fmt.Fprintln(cmd.ErrOrStderr(), "notice: no --scope set: redirects and crawl links on any host will be followed; scan only systems you are authorized to test.")
				}
			}
			if !safe {
				fmt.Fprintln(cmd.ErrOrStderr(), "warn: --safe=false enables state-changing requests — use only with explicit permission")
			}
			if strings.TrimSpace(openapiSpec) != "" {
				if err := validateOpenAPISpecRef(ctx, strings.TrimSpace(openapiSpec), scope); err != nil {
					return err
				}
			}
			_ = noPluginCache
			reg := discoverDefault()
			trustPath := resolveTrustPath("")
			maybeMigrateTrust(trustPath, "")
			records, err := loadTrustRecords(trustPath, "")
			if err != nil {
				return err
			}
			ignoreSet := make(map[string]bool, len(ignorePlugins))
			for _, id := range ignorePlugins {
				for _, part := range strings.Split(id, ",") {
					if trimmed := strings.ToLower(strings.TrimSpace(part)); trimmed != "" {
						ignoreSet[trimmed] = true
					}
				}
			}
			onlySet := make(map[string]bool, len(onlyPlugins))
			for _, id := range onlyPlugins {
				for _, part := range strings.Split(id, ",") {
					if trimmed := strings.ToLower(strings.TrimSpace(part)); trimmed != "" {
						onlySet[trimmed] = true
					}
				}
			}
			if len(onlySet) > 0 {
				var unknown []string
				for id := range onlySet {
					if _, ok := reg.Get(id); !ok {
						unknown = append(unknown, id)
					}
				}
				if len(unknown) > 0 {
					sort.Strings(unknown)
					return fmt.Errorf("scan: unknown --only-plugin ID(s): %s", strings.Join(unknown, ", "))
				}
				var overlap []string
				for id := range onlySet {
					if ignoreSet[id] {
						overlap = append(overlap, id)
					}
				}
				if len(overlap) > 0 {
					sort.Strings(overlap)
					return fmt.Errorf("scan: --only-plugin and --ignore-plugin overlap: %s", strings.Join(overlap, ", "))
				}
			}
			cfg := engine.DefaultConfig()
			// Bulk scans derive a union of the targets' registrable domains so
			// one target cannot drag the crawl to external hosts.
			if len(scope) == 0 && !allowExternal && strings.TrimSpace(targetFile) != "" {
				if targets, terr := readTargetFile(targetFile); terr == nil {
					for _, t := range targets {
						if d := sameSiteDomain(t); d != "" {
							scope = append(scope, d)
						}
					}
					scope = uniqueStrings(scope)
					if len(scope) > 0 {
						fmt.Fprintf(cmd.ErrOrStderr(), "notice: same-site scope %s (use --allow-external to leave the domains)\n", strings.Join(scope, ", "))
					}
				}
			}
			cfg.Safe = safe
			cfg.Deep = deep
			cfg.Active = active
			cfg.HasAuth = false
			cfg.Auth = authCtx
			cfg.AuthA = authA
			cfg.AuthB = authB
			cfg.Login = loginOpts
			cfg.Technologies = techFlags
			cfg.TCPBanners = tcpBanners
			cfg.Scope = scope
			cfg.MaxRequestsPerTarget = maxPerTarget
			cfg.MaxRequestsTotal = maxTotal
			cfg.PluginTimeoutMs = pluginDur.Milliseconds()
			cfg.ScanTimeout = scanDur
			cfg.CrawlTimeout = crawlDur
			cfg.ProxyAttemptTimeout = proxyDur
			cfg.RatePerSecond = rateLimit
			cfg.Parallelism = parallelism
			cfg.OOBServer = strings.TrimSpace(oobServer)
			cfg.OOBToken = strings.TrimSpace(oobToken)
			if cfg.OOBToken == "" {
				cfg.OOBToken = strings.TrimSpace(os.Getenv("GASH_OOB_TOKEN"))
			}
			if strings.EqualFold(cfg.OOBServer, "interactsh") {
				fmt.Fprintln(cmd.ErrOrStderr(), "warn: public interactsh (third-party OOB) selected; use interactsh://your-server or a self-hosted server for sensitive targets")
			}
			cfg.BrowserVerify = browserVerify
			cfg.BrowserCrawl = browserCrawl
			cfg.BrowserCrawlPages = browserCrawlPages
			cfg.StrictPlugins = strictPlugins
			cfg.ShowTentative = showTentative
			cfg.IgnorePlugins = ignoreSet
			cfg.OnlyPlugins = onlySet
			cfg.Target = normalized
			cfg.MaxPages = maxPages
			cfg.Depth = depth
			cfg.OpenAPISpec = strings.TrimSpace(openapiSpec)
			cfg.FlowSeed = flowSeed
			cfg.FlowMaxSteps = flowMaxSteps
			cfg.FlowProbes = flowProbes
			cfg.RequestTimeout = reqDur
			cfg.MaxResponseBytes = maxResponseBytes
			cfg.SSHAudit = sshAudit
			cfg.DBPortScan = dbPortScan
			cfg.DBPorts = dbPortsList
			cfg.TLSAuditDeep = tlsAuditDeep
			cfg.SSHHandshakeAudit = sshHandshakeAudit
			cfg.DBUnauth = dbUnauth
			cfg.InfraTargets = infraTargets
			cfg.MaxInfraPorts = maxInfraPorts
			cfg.InfraTimeout = infraDur
			cfg.InfraRatePerSecond = infraRateLimit
			cfg.InfraParallelism = infraParallelism
			proxyCfg, err := resolveProxySettings(proxy, proxyFile, proxyRotate, proxyCooldown, !noProxy)
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			if proxyCfg.AutoFile != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "otomatik proxy listesi: %s (%d proxy)\n", proxyCfg.AutoFile, len(proxyCfg.URLs))
			}
			cfg.ProxyURLs = proxyCfg.URLs
			cfg.ProxyRotate = string(proxyCfg.Rotate)
			cfg.ProxyCooldown = proxyCfg.Cooldown

			// P1.2: Apply scan profile
			profileName := config.ProfileName(strings.ToLower(strings.TrimSpace(profile)))
			if profileName != "" {
				cfg.Profile = profileName
				if p := config.GetProfile(profileName); p != nil {
					// Profile sets defaults; explicit flags override
					if !cmd.Flags().Changed("safe") {
						cfg.Safe = !p.AllowActive
					}
					if !cmd.Flags().Changed("deep") {
						cfg.Deep = p.AllowDeep
					}
					if !cmd.Flags().Changed("active") {
						cfg.Active = p.AllowActive
					}
					if !cmd.Flags().Changed("max-requests-per-target") {
						cfg.MaxRequestsPerTarget = p.MaxRequestsPerTarget
					}
					if !cmd.Flags().Changed("max-requests-total") {
						cfg.MaxRequestsTotal = p.MaxRequestsTotal
					}
					if !cmd.Flags().Changed("rate-limit") {
						cfg.RatePerSecond = p.RatePerSecond
					}
					if !cmd.Flags().Changed("parallelism") {
						cfg.Parallelism = p.Parallelism
					}
					if !cmd.Flags().Changed("plugin-timeout") {
						cfg.PluginTimeoutMs = p.PluginTimeoutMs
					}
					if !cmd.Flags().Changed("max-pages") && p.MaxPages > 0 {
						cfg.MaxPages = p.MaxPages
					}
					if !cmd.Flags().Changed("depth") && p.CrawlDepth > 0 {
						cfg.Depth = p.CrawlDepth
					}
					// Deep profile requires explicit opt-in
					if p.RequireExplicitOptIn && !cmd.Flags().Changed("deep") {
						fmt.Fprintln(cmd.ErrOrStderr(), "warn: deep profile requires explicit --deep flag; use --deep to enable")
					}
				}
			}
			if strings.TrimSpace(targetFile) != "" {
				bulkFormats := formats
				if !cmd.Flags().Changed("format") {
					bulkFormats = []string{"json", "sarif"}
				}
				return runBulkScan(ctx, cmd, reg, cfg, records, targetFile, outputDir, resume, bulkFormats, failLevel, showTentative)
			}
			spinner := newScanSpinner(cmd.ErrOrStderr(), normalized)
			cfg.OnProgress = spinner.OnProgress
			spinner.Start()
			eng := engine.New(reg, cfg)
			for id, rec := range records {
				platform := rec.Platform
				if strings.TrimSpace(platform) == "" {
					platform = loader.AnyPlatform
				}
				eng.SetTrustRecord(id, rec.SHA256, platform)
			}
			rep, err := eng.Run(ctx, normalized)
			spinner.Stop()
			if err != nil {
				return err
			}
			opts := reporter.Options{ShowTentative: showTentative, Target: normalized}
			if err := writeScanReports(cmd, rep, formats, opts, output, outputDir); err != nil {
				return err
			}
			if failLevel != "" && scanFailTriggered(rep, failLevel) {
				return fmt.Errorf("scan: --fail-on %s triggered", failLevel)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "hedef URL (yalnızca izinli hedef, only with explicit permission)")
	cmd.Flags().StringVar(&targetFile, "target-file", "", "hedef listesi dosyası (bir satır bir hedef, # yorum)")
	cmd.Flags().BoolVar(&resume, "resume", false, "önceki taramada raporu olan hedefleri atla")
	cmd.Flags().StringVar(&outputDir, "output-dir", "reports", "toplu tarama rapor çıktı dizini")
	cmd.Flags().BoolVar(&reportStamp, "report-stamp", false, "rapor dosya adına zaman damgası ekle (aynı hedefin tekrarlı taramaları birbirini ezmez)")
	cmd.Flags().StringVar(&proxy, "proxy", "", "upstream HTTP proxy URL (örn. http://127.0.0.1:8080); --proxy-file ile birlikte havuz oluşturur")
	cmd.Flags().StringVar(&proxyFile, "proxy-file", "", "proxy listesi dosyası (satır başına URL, # yorum; çoklu proxy'de timeout/blokta rotasyon; verilmezse .gash/proxies/alive.txt otomatik)")
	cmd.Flags().StringVar(&proxyRotate, "proxy-rotate", "per-host", "proxy rotasyonu: per-host (oturum dostu) veya per-request")
	cmd.Flags().StringVar(&proxyCooldown, "proxy-cooldown", "30s", "başarısız/bloklu proxy'nin atlanma süresi")
	cmd.Flags().BoolVar(&noProxy, "no-proxy", false, "otomatik proxy listesini kapat (GASH_PROXY_FILE / .gash/proxies/alive.txt)")
	cmd.Flags().StringVar(&proxyTimeout, "proxy-timeout", "8s", "çoklu proxy'de tek deneme timeout'u (0=request-timeout'u kullan)")
	cmd.Flags().BoolVar(&allowExternal, "allow-external", false, "crawl/redirect ile hedef domain dışına çıkmaya izin ver (varsayılan: yalnızca hedef domain)")
	cmd.Flags().StringVar(&scanTimeout, "scan-timeout", "30m", "tüm taramanın süre tavanı (discovery + pluginler)")
	cmd.Flags().StringVar(&crawlTimeout, "crawl-timeout", "5m", "BFS keşif fazının süre tavanı (pluginlere süre kalsın)")
	cmd.Flags().BoolVar(&safe, "safe", true, "varsayılan safe")
	cmd.Flags().BoolVar(&deep, "deep", false, "deep faz + ExecutionOracle kapısı")
	cmd.Flags().BoolVar(&active, "active", false, "state-changing/OOB payload kapısı")
	cmd.Flags().BoolVar(&aggressive, "aggressive", false, "tam güç ofansif tarama: tüm dedektörler, genişletilmiş bütçe, yüksek rate-limit")
	cmd.Flags().StringSliceVar(&scope, "scope", nil, "CIDR/domain allowlist; verilmezse hedef domain (eTLD+1) otomatik kullanılır (--allow-external ile kapatılır)")
	cmd.Flags().Int64Var(&maxPerTarget, "max-requests-per-target", 2000, "per-target bütçe (profil değeri aksi belirtilmedikçe geçerlidir)")
	cmd.Flags().Int64Var(&maxTotal, "max-requests-total", 15000, "global bütçe (profil değeri aksi belirtilmedikçe geçerlidir)")
	cmd.Flags().StringVar(&pluginTimeout, "plugin-timeout", "60s", "per-plugin timeout")
	cmd.Flags().StringVar(&requestTimeout, "request-timeout", "20s", "per-HTTP-request timeout")
	cmd.Flags().Int64Var(&maxResponseBytes, "max-response-bytes", 5*1024*1024, "max stored response body bytes")
	cmd.Flags().StringVar(&oobWait, "oob-wait", "60s", "scan-sonu OOB penceresi")
	cmd.Flags().StringVar(&oobServer, "oob-server", "", "OOB sağlayıcısı: local | interactsh (public) | interactsh://host | self-hosted API URL (boş=kapalı)")
	cmd.Flags().StringVar(&oobToken, "oob-token", "", "self-hosted interactsh/API token'ı (tercihen GASH_OOB_TOKEN ortam değişkeni)")
	cmd.Flags().BoolVar(&browserVerify, "browser-verify", false, "statik XSS kanıtını gerçek tarayıcı tetiklemesi + temiz kontrol ile doğrula (--active ve -tags deep build şart; stub build'de dürüstçe atlanır)")
	cmd.Flags().BoolVar(&browserCrawl, "browser-crawl", false, "keşfedilen sayfaları gerçek tarayıcıda render edip SPA yüzeyini (DOM form/link + XHR/fetch endpoint) tarama listesine ekler; -tags deep build + Chrome şart; stub build'de dürüstçe atlanır")
	cmd.Flags().IntVar(&browserCrawlPages, "browser-crawl-pages", 5, "SPA render edilecek en fazla sayfa sayısı (1..10)")
	cmd.Flags().BoolVar(&showTentative, "show-tentative", false, "tentative'i dahil et")
	cmd.Flags().StringSliceVar(&format, "format", []string{"text"}, "json|sarif|text|html|junit (tekrarlanabilir)")
	cmd.Flags().StringVar(&output, "output", "", "rapor dosyası (tek format ile kullanın)")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "CI kapısı (firm|confirmed)")
	cmd.Flags().BoolVar(&noPluginCache, "no-plugin-cache", false, "cache bypass (debug)")
	cmd.Flags().BoolVar(&strictPlugins, "strict-plugins", false, "yalnızca trust'lı Tier3")
	cmd.Flags().StringSliceVar(&ignorePlugins, "ignore-plugin", nil, "döngü kırma / susturma")
	cmd.Flags().StringSliceVar(&onlyPlugins, "only-plugin", nil, "yalnızca bu plugin ID'lerini tara (tekrarlanabilir/virgüllü; profil kapıları yine uygulanır)")
	cmd.Flags().Float64Var(&rateLimit, "rate-limit", 10, "per-target req/s")
	cmd.Flags().IntVar(&parallelism, "parallelism", 8, "worker sayısı")
	cmd.Flags().StringVar(&profile, "profile", "standard", "scan profile: safe|standard|deep|aggressive (safe=pasif+düşük bütçe, standard=kontrollü aktif, deep=browser+yüksek bütçe, aggressive=tam ofansif)")
	cmd.Flags().StringSliceVar(&authHeaders, "auth-header", nil, "kimlik header'ı 'Ad: değer' (tekrarlanabilir, requires_auth kapısını açar)")
	cmd.Flags().StringSliceVar(&cookies, "cookie", nil, "oturum cookie'si 'a=b[; c=d]' (tekrarlanabilir)")
	cmd.Flags().StringVar(&basicAuth, "basic-auth", "", "basic kimlik 'kullanıcı:parola'")
	cmd.Flags().StringSliceVar(&authUserA, "auth-user-a", nil, "BOLA matrisi kullanıcı A başlığı 'Ad: değer' (tekrarlanabilir, --auth-user-b ile birlikte, --active şart)")
	cmd.Flags().StringSliceVar(&authUserB, "auth-user-b", nil, "BOLA matrisi kullanıcı B başlığı 'Ad: değer' (tekrarlanabilir, --auth-user-a ile birlikte, --active şart)")
	cmd.Flags().StringVar(&loginURL, "login-url", "", "login formu URL'i; verilirse gerçek oturum kurulur (--active + --login-user + parola şart; başarısızlık dürüstçe raporlanır)")
	cmd.Flags().StringVar(&loginUser, "login-user", "", "tek kimlik seti kullanıcı adı (parola denemesi/guessing YOK)")
	cmd.Flags().StringVar(&loginPass, "login-pass", "", "tek kimlik seti parolası (uyarı: argv süreç listesinde görünebilir; --login-pass-env tercih edilir)")
	cmd.Flags().StringVar(&loginPassEnv, "login-pass-env", "", "parolayı ortam değişkeninden oku (örn. GASH_LOGIN_PASS); --login-pass ile birlikte kullanılamaz")
	cmd.Flags().StringVar(&loginUserField, "login-user-field", "", "kullanıcı alanı adı override'ı (boşsa sezgisel: user|email|login|account|mail)")
	cmd.Flags().StringVar(&loginPassField, "login-pass-field", "", "parola alanı adı override'ı (boşsa ilk type=password alanı)")
	cmd.Flags().StringVar(&loginVerifyURL, "login-verify-url", "", "oturum doğrulama URL'i (boşsa login action target, o da yoksa --login-url)")
	cmd.Flags().StringSliceVar(&techFlags, "tech", nil, "bilinen teknoloji (tekrarlanabilir/virgüllü, örn. wordpress,graphql — chain kapısı)")
	cmd.Flags().StringSliceVar(&tcpBanners, "tcp-banner", nil, "açık TCP banner probu 'host:port' (tekrarlanabilir, --active şart, kapsam-izinli)")
	cmd.Flags().IntVar(&maxPages, "max-pages", 50, "crawler maksimum sayfa sayısı (0=sadece hedef sayfa)")
	cmd.Flags().IntVar(&depth, "depth", 3, "crawler maksimum derinlik")
	cmd.Flags().StringVar(&openapiSpec, "openapi-spec", "", "OpenAPI/Swagger dosyası veya http(s) URL (endpoint+parametreler surfacePoints'e eklenir; URL yalnızca loopback/kapsam-içi)")
	cmd.Flags().BoolVar(&sshAudit, "ssh-audit", false, "SSH banner/protokol denetimi (salt-okuma, veri gönderilmez; --active gerektirir)")
	cmd.Flags().BoolVar(&dbPortScan, "db-port-scan", false, "yaygın veritabanı portlarını tara (salt-okuma selamlama; --active gerektirir)")
	cmd.Flags().StringVar(&dbPorts, "db-ports", "1433,1521,3306,5432,6379,9200,27017,11211,5984,9042", "taranacak veritabanı portları (virgüllü liste; 1..65535)")
	cmd.Flags().BoolVar(&tlsAuditDeep, "tls-audit-deep", false, "eski TLS sürüm kabulünü ayrı el sıkışmalarla gözle (TLS 1.0/1.1; https hedef)")
	cmd.Flags().BoolVar(&sshHandshakeAudit, "ssh-handshake-audit", false, "SSH KEX/hostkey/cipher/MAC algoritma denetimi (sürüm değişimi + KEXINIT; kimlik doğrulama yok; --active gerektirir)")
	cmd.Flags().BoolVar(&dbUnauth, "db-unauth", false, "veritabanı kimlik doğrulamasız erişim denetimi (sabit dummy kullanıcı, tek istek; --active gerektirir)")
	cmd.Flags().StringSliceVar(&infraTargets, "infra-target", nil, "altyapı denetimi hedefi 'host:port' (tekrarlanabilir; boşsa tarama hedef host'u)")
	cmd.Flags().IntVar(&maxInfraPorts, "max-infra-ports", 20, "altyapı taramasında en fazla denenecek port sayısı")
	cmd.Flags().StringVar(&infraTimeout, "infra-timeout", "5s", "altyapı dial/gözlem zaman aşımı")
	cmd.Flags().Float64Var(&infraRateLimit, "infra-rate-limit", 5, "altyapı denetimi saniyedeki işlem tavanı (0=sınırsız)")
	cmd.Flags().IntVar(&infraParallelism, "infra-parallelism", 4, "altyapı denetimi eşzamanlılık tavanı")
	cmd.Flags().StringArrayVar(&flowSeeds, "flow-seed", nil, "çok-adımlı akış keşif URL'i (v1 tek; --active şart; kapsam-dışı seed'e istek gitmez)")
	cmd.Flags().IntVar(&flowMaxSteps, "flow-max-steps", 4, "akış keşfi adım tavanı (1..6)")
	cmd.Flags().IntVar(&flowProbes, "flow-probes", 6, "adım başına SQLi probu (1..10)")
	return cmd
}

// validateScanTarget parses and validates a scan target URL.
// What: Early http/https plus host validation before any discovery work.
// Why: Malformed targets must fail fast with a clear validation error.
func validateScanTarget(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("scan: --target zorunlu")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("scan: geçersiz --target %q: %w", raw, err)
	}
	if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("scan: --target http(s) olmalı (got %q)", u.Scheme)
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", fmt.Errorf("scan: --target host içermeli %q", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("scan: --target userinfo içermemeli")
	}
	return u.String(), nil
}

// validateOpenAPISpecRef --openapi-spec dosya/URL ayrımı + URL kapsam kapısıdır.
// What: http(s) öneki URL'dir — loopback her zaman izinli, diğer host'lar
// yalnızca --scope içinde (fetch ÖNCESİ karar, ağa çıkılmaz); dosya yolu
// aynen geçirilir (yokluk/bozukluk taramada fail-closed hata verir).
// Why: Dış URL'ye kapsam-dışı fetch YOK — karar tek GET'ten önce verilir.
func validateOpenAPISpecRef(ctx context.Context, ref string, scope []string) error {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return nil
	}
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return nil // dosya yolu — varlık kontrolü engine'de (fail-closed)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("scan: --openapi-spec geçersiz URL %q: %w", ref, err)
	}
	if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" {
		return fmt.Errorf("scan: --openapi-spec URL http(s) olmalı (got %q)", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("scan: --openapi-spec URL userinfo içeremez")
	}
	if isLocalScanTarget(u.String()) {
		return nil // loopback istisnası
	}
	if len(scope) == 0 {
		return fmt.Errorf("scan: --openapi-spec URL kapsam-dışı (loopback veya --scope içi olmalı, fetch yapılmadı)")
	}
	if err := enforceScanScope(ctx, u.String(), scope); err != nil {
		return fmt.Errorf("scan: --openapi-spec %w (fetch yapılmadı)", err)
	}
	return nil
}

// normalizeScanFormats validates repeatable reporter formats.
// What: Lowercase plus registry allowlist check (json|sarif|text|html|junit).
// Why: Typos must fail fast instead of producing a silent empty report.
func normalizeScanFormats(formats []string) ([]string, error) {
	if len(formats) == 0 {
		return []string{"text"}, nil
	}
	var out []string
	for _, f := range formats {
		for _, part := range strings.Split(f, ",") {
			name := strings.ToLower(strings.TrimSpace(part))
			if name == "" {
				continue
			}
			if _, err := reporter.Lookup(name); err != nil {
				return nil, fmt.Errorf("scan: --format %q geçersiz (%s)", part, strings.Join(reporter.Names(), "|"))
			}
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return []string{"text"}, nil
	}
	return out, nil
}

// parseDBPorts validates the --db-ports comma list (1..65535, dedupe).
// What: Turkish error on any invalid token; order-preserving dedupe.
// Why: A typo must fail fast before any dial; the engine also caps the list.
func parseDBPorts(raw string) ([]int, error) {
	seen := make(map[int]bool)
	var out []int
	for _, part := range strings.Split(raw, ",") {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		n, err := strconv.Atoi(token)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("scan: --db-ports geçersiz değer %q (1..65535 aralığında port beklenir)", part)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}

// normalizeFailOn validates the CI gate level.
// What: Empty plus firm plus confirmed allowlist.
// Why: Unknown levels would make CI gates silently meaningless.
func normalizeFailOn(level string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(level))
	if trimmed == "" {
		return "", nil
	}
	if trimmed != "firm" && trimmed != "confirmed" {
		return "", fmt.Errorf("scan: --fail-on %q geçersiz (firm|confirmed)", level)
	}
	return trimmed, nil
}

// isLocalScanTarget reports loopback targets for warning policy.
// What: Localhost plus loopback IP detection.
// Why: External targets without scope deserve an explicit responsibility warning.
func isLocalScanTarget(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// enforceScanScope rejects targets outside an explicit allowlist.
// What: Domain suffix plus CIDR check mirroring PolicySession semantics.
// Why: An explicit scope must fail closed before any probe traffic starts.
func enforceScanScope(ctx context.Context, rawURL string, scope []string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("scan: geçersiz --target %q: %w", rawURL, err)
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return fmt.Errorf("scan: --target host içermeli")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, entry := range scope {
		e := strings.ToLower(strings.TrimSpace(entry))
		if e == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(e); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				if cidr.Contains(ip) {
					return nil
				}
				continue
			}
			ips, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				if cidr.Contains(ip.IP) {
					return nil
				}
			}
			continue
		}
		if host == e || strings.HasSuffix(host, "."+e) {
			return nil
		}
	}
	return fmt.Errorf("scan: target %q outside --scope (scope-mismatch)", host)
}

// writeScanReports renders each requested format to stdout, a specific file, or output-dir.
// What: Single-format file output, directory output with multiple formats, or stdout fan-out.
// Why: Prevents corrupting stdout when multiple formats are requested and honors --output-dir.
func writeScanReports(cmd *cobra.Command, rep *engine.Report, formats []string, opts reporter.Options, output, outputDir string) error {
	if strings.TrimSpace(output) != "" && len(formats) > 1 {
		return fmt.Errorf("scan: --output tek --format ile kullanın (got %d format)", len(formats))
	}
	if strings.TrimSpace(output) != "" {
		f, err := openScanOutput(output)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		if err := writeOneScanFormat(f, rep, formats[0], opts); err != nil {
			return err
		}
		_ = f.Sync()
		fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%s, %d findings, %d skipped, %d partial)\n", output, formats[0], len(rep.Findings), len(rep.Skipped), rep.Stats["partial_plugins"])
		return nil
	}

	// Birden fazla format istendiyse veya kullanıcı açıkça --output-dir verdiyse:
	// Dosyalara (reports/<target>.<fmt>) kaydet.
	outputDirChanged := cmd != nil && cmd.Flags().Changed("output-dir")
	if len(formats) > 1 || outputDirChanged {
		if strings.TrimSpace(outputDir) == "" {
			outputDir = "reports"
		}
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			return fmt.Errorf("scan: --output-dir dizini %q: %w", outputDir, err)
		}
		baseName := targetReportBaseName(opts.Target)
		if baseName == "" {
			baseName = "report"
		}
		if reportStampEnabled(cmd) {
			baseName += "-" + time.Now().Format("20060102-150405")
		}
		for _, name := range formats {
			outPath := filepath.Join(outputDir, baseName+"."+name)
			f, err := openScanOutput(outPath)
			if err != nil {
				return err
			}
			err = writeOneScanFormat(f, rep, name, opts)
			_ = f.Close()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%s, %d findings, %d skipped, %d partial)\n", outPath, name, len(rep.Findings), len(rep.Skipped), rep.Stats["partial_plugins"])
		}
		// Eğer formats içinde text varsa, terminale de insan-okur özeti bas
		for _, name := range formats {
			if name == "text" {
				_ = writeOneScanFormat(cmd.OutOrStdout(), rep, "text", opts)
				break
			}
		}
		return nil
	}

	for _, name := range formats {
		if err := writeOneScanFormat(cmd.OutOrStdout(), rep, name, opts); err != nil {
			return err
		}
	}
	return nil
}

// reportStampEnabled: --report-stamp verilmişse rapor adına zaman damgası eklenir.
// What: Same target scanned twice no longer overwrites the previous report.
// Why: Deterministic names stay the default for CI diffing; the interactive
// menu opts in so ad-hoc runs accumulate instead of clobbering each other.
func reportStampEnabled(cmd *cobra.Command) bool {
	if cmd == nil || cmd.Flags().Lookup("report-stamp") == nil {
		return false
	}
	v, err := cmd.Flags().GetBool("report-stamp")
	return err == nil && v
}

// openScanOutput creates a report file with its parent directory.
// What: Parent-dir creation plus truncate-only file open.
// Why: Operators point reports at fresh directories without pre-creating them.
func openScanOutput(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("scan: --output dizini %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("scan: --output %q: %w", path, err)
	}
	return f, nil
}

// writeOneScanFormat dispatches a single reporter format.
// What: Registry router for all registered formats (json|sarif|text|html|junit).
// Why: One router keeps CLI output identical to reporter contract tests.
func writeOneScanFormat(w interface {
	Write([]byte) (int, error)
}, rep *engine.Report, name string, opts reporter.Options) error {
	return reporter.Write(name, w, rep, opts)
}

// scanFailTriggered reports whether the CI gate level is present.
// What: Firm gate matches firm plus confirmed; confirmed gate is strict.
// Why: CI must distinguish weak signals from actionable confidence levels.
func scanFailTriggered(rep *engine.Report, level string) bool {
	for _, f := range rep.Findings {
		switch level {
		case "firm":
			if f.Confidence == "firm" || f.Confidence == "confirmed" {
				return true
			}
		case "confirmed":
			if f.Confidence == "confirmed" {
				return true
			}
		}
	}
	return false
}

func newPluginsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugins",
		Short: "Plugin yönetimi",
		RunE: func(cmd *cobra.Command, args []string) error {
			if isInteractive(cmd.InOrStdin()) {
				return runPluginsMenu(cmd.InOrStdin(), cmd.OutOrStdout())
			}
			return cmd.Help()
		},
	}
	cmd.AddCommand(
		&cobra.Command{Use: "list", Short: "Registry snapshot (çalıştırma yok)", RunE: runPluginsList},
		&cobra.Command{Use: "validate <file>", Short: "Schema + rules kontrolü", Args: cobra.ExactArgs(1), RunE: runPluginsValidate},
		&cobra.Command{Use: "test <file>", Short: "Fixture çalıştırma (positive+negative)", Args: cobra.ExactArgs(1), RunE: runPluginsTest},
		newPluginsNewCmd(),
		newPluginsTrustCmd(),
		&cobra.Command{Use: "info <id>", Short: "Metadata + skip sebebi + trust", Args: cobra.ExactArgs(1), RunE: runPluginsInfo},
	)
	return cmd
}

// pluginKind classifies a plugin file by suffix for the CLI.
// What: Extension router shared by validate and test.
// Why: One router keeps both commands consistent on Tier detection.
func pluginKind(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".gashplugin.yaml"):
		return "tier3"
	case strings.HasSuffix(lower, ".js"):
		return "tier2"
	default:
		return "tier1"
	}
}

// discoverDefault finds plugins across all drop-in sources.
// What: Discovers built-in plus home plus GASH_PLUGIN_PATH without execution.
// Why: List and info must show exactly what a scan would schedule.
func discoverDefault() *plugin.Registry {
	reg := plugin.NewRegistry()
	dirs := []string{"plugins"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs, filepath.Join(home, ".gash", "plugins"))
	}
	if extra := os.Getenv("GASH_PLUGIN_PATH"); extra != "" {
		sep := ":"
		if os.PathSeparator == '\\' {
			sep = ";"
		}
		for _, part := range strings.Split(extra, sep) {
			if strings.TrimSpace(part) != "" {
				dirs = append(dirs, part)
			}
		}
	}
	var existing []string
	for _, dir := range dirs {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			existing = append(existing, dir)
		}
	}
	if len(existing) == 0 {
		return reg
	}
	warns, _ := loader.Discover(existing, reg)
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "warn:", w)
	}
	markTrust(reg)
	return reg
}

// resolveTrustPath returns the effective trust file for reads.
// What: Default path with legacy migration, explicit override without migration.
// Why: GASH_TRUST_FILE and --trust-file win; only the default auto-migrates.
func resolveTrustPath(explicit string) string {
	return plugintest.ResolveTrustPath(explicit)
}

// maybeMigrateTrust copies legacy approvals to the default file.
// What: Best-effort S1 migration applied only on the default path.
// Why: Explicit overrides must never inherit legacy approvals implicitly.
func maybeMigrateTrust(trustPath, explicit string) {
	if strings.TrimSpace(explicit) != "" {
		return
	}
	if os.Getenv("GASH_TRUST_FILE") != "" {
		return
	}
	if trustPath == "" || trustPath != plugintest.DefaultTrustPath() {
		return
	}
	if _, err := loader.MigrateLegacyTrust(trustPath, plugintest.LegacyTrustPath()); err != nil {
		fmt.Fprintln(os.Stderr, "warn: trust migration:", err)
	}
}

// loadTrustRecords reads approvals with legacy fallback on the default path.
// What: Migrating read shared by list and info.
// Why: A legacy-only install must list as trusted on first run after S1.
func loadTrustRecords(trustPath, explicit string) (map[string]loader.TrustRecord, error) {
	if trustPath == "" {
		return map[string]loader.TrustRecord{}, nil
	}
	if explicit == "" && os.Getenv("GASH_TRUST_FILE") == "" && trustPath == plugintest.DefaultTrustPath() {
		return loader.LoadTrustRecordsWithMigration(trustPath, plugintest.LegacyTrustPath())
	}
	return loader.LoadTrustRecords(trustPath)
}

// markTrust annotates native entries with explicit approval state.
// What: Reads the trust file and flags approved manifests in the registry.
// Why: List and info must distinguish runnable native plugins from dormant ones.
func markTrust(reg *plugin.Registry) {
	trustPath := resolveTrustPath("")
	maybeMigrateTrust(trustPath, "")
	records, err := loadTrustRecords(trustPath, "")
	if err != nil || len(records) == 0 {
		return
	}
	for _, e := range reg.Snapshot() {
		if e.Spec.Tier != plugin.TierNative {
			continue
		}
		if rec, ok := records[e.Spec.ID]; ok {
			if strings.EqualFold(strings.TrimSpace(rec.SHA256), "") {
				continue
			}
			reg.MarkTrusted(e.Spec.ID, true)
			_ = rec
		}
	}
}

// runPluginsList prints the discovered registry snapshot.
// What: Read-only listing without executing any plugin.
// Why: Operators audit what would run before any scan starts.
func runPluginsList(cmd *cobra.Command, args []string) error {
	reg := discoverDefault()
	snap := reg.Snapshot()
	fmt.Fprintf(cmd.OutOrStdout(), "%d plugins\n", len(snap))
	for _, e := range snap {
		extra := ""
		if e.Spec.Tier == plugin.TierNative {
			if e.Trusted {
				extra = " trusted=yes"
			} else {
				extra = " trusted=no (needs `gash plugins trust`)"
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "- %s [%s] phase=%s order=%d oob=%s%s %s\n",
			e.Spec.ID, e.Spec.Tier, e.Spec.Phase, e.Spec.Order, e.Spec.OOB, extra, e.SourcePath)
	}
	return nil
}

// runPluginsValidate checks schema plus consistency rules and prints warnings.
// What: Load-time validation for a single plugin file.
// Why: Authors get the same verdict the engine would enforce at startup.
func runPluginsValidate(cmd *cobra.Command, args []string) error {
	path := args[0]
	switch pluginKind(path) {
	case "tier2":
		spec, err := loader.LoadTier2Frontmatter(path)
		if err != nil {
			return err
		}
		return printSpecVerdict(cmd, spec, path)
	case "tier3":
		spec, manifest, err := loader.LoadTier3Manifest(path)
		if err != nil {
			return err
		}
		_ = manifest
		return printSpecVerdict(cmd, spec, path)
	default:
		spec, file, err := loader.LoadTier1File(path)
		if err != nil {
			return err
		}
		if err := plugin.CheckOOBOracle(file.Oracle.Name, spec.OOB, spec.ID); err != nil {
			return err
		}
		return printSpecVerdict(cmd, spec, path)
	}
}

// printSpecVerdict validates a spec and reports warnings.
// What: Shared validation output for all three tiers.
// Why: Identical output keeps tier behavior comparable.
func printSpecVerdict(cmd *cobra.Command, spec *plugin.PluginSpec, pluginPath string) error {
	if err := plugin.Validate(*spec); err != nil {
		return err
	}
	warns := plugin.ValidateWarnings(*spec)
	if spec.Tests == "" {
		warns = append(warns, "R-06: tests='' — findings stay tentative until fixtures land")
	} else if root := plugintest.ResolveFixtureRoot(pluginPath, spec.Tests); root != "" {
		if st, err := os.Stat(root); err != nil || !st.IsDir() {
			warns = append(warns, fmt.Sprintf("fixtures: %q not found — `gash plugins test` will fail", spec.Tests))
		}
	}
	if len(warns) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "valid: %s\n", spec.ID)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "valid with warnings: %s\n", spec.ID)
	for _, w := range warns {
		fmt.Fprintf(cmd.OutOrStdout(), "  warn: %s\n", w)
	}
	return nil
}

// runPluginsTest executes positive plus negative fixtures for one plugin file.
// What: Offline precision check enforcing the 99 percent gate.
// Why: A plugin that fails its fixtures must never reach the metrics report.
func runPluginsTest(cmd *cobra.Command, args []string) error {
	path := args[0]
	ctx := context.Background()
	switch pluginKind(path) {
	case "tier2":
		spec, err := loader.LoadTier2Frontmatter(path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		oracleName := plugintest.InferJSOracle(string(data))
		if oracleName == "" {
			return fmt.Errorf("test %s: no host.oracles.<name> call found", path)
		}
		return runFixtureSuite(cmd, ctx, spec, oracleName, path, spec.OracleParams)
	case "tier3":
		spec, manifest, err := loader.LoadTier3Manifest(path)
		if err != nil {
			return err
		}
		if err := checkTier3Binary(path, manifest); err != nil {
			return err
		}
		oracleName := manifest.Oracle
		if oracleName == "" {
			oracleName = "header"
		}
		return runFixtureSuite(cmd, ctx, spec, oracleName, path, spec.OracleParams)
	default:
		spec, file, err := loader.LoadTier1File(path)
		if err != nil {
			return err
		}
		return runFixtureSuite(cmd, ctx, spec, file.Oracle.Name, path, file.Oracle.Params)
	}
}

// runFixtureSuite resolves fixtures, runs them, and enforces the metric gate.
// What: Single fixture pipeline for every tier.
// Why: Tier-independent gating proves accuracy never depends on plugin format.
func runFixtureSuite(cmd *cobra.Command, ctx context.Context, spec *plugin.PluginSpec, oracleName, path string, oracleParams map[string]any) error {
	if spec.Tests == "" {
		return fmt.Errorf("test %s: no `tests` field — add positive/negative fixtures first (`gash plugins new` generates them)", spec.ID)
	}
	root := plugintest.ResolveFixtureRoot(path, spec.Tests)
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return fmt.Errorf("test %s: fixture root %q not found: %w", spec.ID, spec.Tests, errFixtureRoot(root))
	}
	sum, err := plugintest.Run(ctx, spec.ID, oracleName, root, true, oracleParams)
	if err != nil {
		return err
	}
	for _, c := range sum.Cases {
		mark := "PASS"
		if !c.Pass {
			mark = "FAIL"
		}
		kind := "negative"
		if c.Positive {
			kind = "positive"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s/%s confidence=%s %s\n",
			mark, kind, c.Name, c.Confidence, c.Detail)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "precision=%.2f recall=%d/%d positives, %d false positives\n",
		sum.Precision, sum.TruePositives, sum.TruePositives+sum.FalseNegatives, sum.FalsePositives)
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "dataset=%s fixtures=%d (TP=%d FP=%d TN=%d FN=%d)\n",
		sum.DatasetHash, sum.FixtureFiles, sum.TruePositives, sum.FalsePositives, sum.TrueNegatives, sum.FalseNegatives); err != nil {
		return fmt.Errorf("test %s: dataset satırı yazılamadı: %w", spec.ID, err)
	}
	if positives := sum.TruePositives + sum.FalseNegatives; positives == 0 {
		return fmt.Errorf("test %s: no positive fixtures under %s/positive — add at least one", spec.ID, root)
	}
	if negatives := sum.TrueNegatives + sum.FalsePositives; negatives == 0 {
		return fmt.Errorf("test %s: no negative fixtures under %s/negative — add at least one", spec.ID, root)
	}
	if !sum.Pass {
		return fmt.Errorf("test %s: fixture failures", spec.ID)
	}
	if sum.Precision < 0.99 {
		return fmt.Errorf("test %s: precision gate 0.99 not met (got %.4f)", spec.ID, sum.Precision)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "ok: %s oracle=%s\n", spec.ID, oracleName)
	return nil
}

// errFixtureRoot wraps a missing fixture directory for %w chains.
// What: Stable sentinel for missing tests roots.
// Why: Callers and tests match on one error instead of string comparison.
func errFixtureRoot(root string) error {
	if root == "" {
		return fmt.Errorf("empty fixture root")
	}
	return fmt.Errorf("stat %s", root)
}

// checkTier3Binary verifies the manifest pin against the referenced binary.
// What: Digest check without executing the binary.
// Why: `plugins test` must prove integrity before any spawn attempt.
func checkTier3Binary(manifestPath string, m *loader.Tier3Manifest) error {
	bin := loader.ResolveTier3Binary(manifestPath, m.Binary)
	data, err := os.ReadFile(bin)
	if err != nil {
		return fmt.Errorf("tier3 test: binary %s: %w", bin, err)
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(m.SHA256)) {
		// The committed pin belongs to the reference build; contributors
		// rebuild per platform and re-pin via `gash plugins trust`.
		return fmt.Errorf("tier3 test: sha256 mismatch for %s (re-pin after rebuild)", bin)
	}
	return nil
}

// newPluginsNewCmd scaffolds a plugin skeleton plus passing fixtures.
// What: Tier-aware generator writing the plugin file and tests/fixtures.
// Why: Generated skeletons must already pass validate plus test on day one.
func newPluginsNewCmd() *cobra.Command {
	var tierFlag string
	var outDir string
	var force bool
	c := &cobra.Command{
		Use:   "new <name>",
		Short: "Scaffold a Tier 1/2 plugin with example fixtures",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			tier, err := scaffold.ParseTier(tierFlag)
			if err != nil {
				return err
			}
			dir := outDir
			if dir == "" {
				dir = "."
			}
			res, err := scaffold.Generate(dir, name, tier, force)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", res.PluginPath)
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s/positive/positive_01.json\n", res.FixtureRoot)
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s/negative/negative_01.json\n", res.FixtureRoot)
			fmt.Fprintf(cmd.OutOrStdout(), "next: gash plugins validate %s; gash plugins test %s\n", res.PluginPath, res.PluginPath)
			return nil
		},
	}
	c.Flags().StringVar(&tierFlag, "tier", "yaml", "yaml|js")
	c.Flags().StringVar(&outDir, "dir", ".", "output directory for the plugin and fixtures")
	c.Flags().BoolVar(&force, "force", false, "overwrite existing files")
	return c
}

// newPluginsTrustCmd builds the Tier 3 approval command.
// What: Trust command constructor with an overridable trust-file flag.
// Why: Tests point approvals at temp files while users keep the default.
func newPluginsTrustCmd() *cobra.Command {
	c := &cobra.Command{Use: "trust <manifest>", Short: "Tier3 allowlist + sha256 pin", Args: cobra.ExactArgs(1), RunE: runPluginsTrust}
	c.Flags().String("trust-file", "", "trust database path (default ~/.gash/trust.db)")
	return c
}

// runPluginsTrust pins a Tier 3 binary digest into the user trust file.
// What: Explicit-approval recorder with digest plus platform verification.
// Why: Trust stays explicit, pinned, and auditable outside the repository.
func runPluginsTrust(cmd *cobra.Command, args []string) error {
	path := args[0]
	_, manifest, err := loader.LoadTier3Manifest(path)
	if err != nil {
		return err
	}
	bin := loader.ResolveTier3Binary(path, manifest.Binary)
	data, err := os.ReadFile(bin)
	if err != nil {
		return fmt.Errorf("trust: binary %s: %w", bin, err)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, strings.TrimSpace(manifest.SHA256)) {
		return fmt.Errorf("trust: sha256 mismatch (binary=%s manifest=%s)", got, manifest.SHA256)
	}
	flagPath, _ := cmd.Flags().GetString("trust-file")
	trustPath := resolveTrustPath(flagPath)
	maybeMigrateTrust(trustPath, flagPath)
	rec := loader.TrustRecord{
		ID: manifest.ID, SHA256: got,
		Platform: loader.CurrentPlatform(), ManifestPath: path,
	}
	if err := loader.SaveTrustRecord(trustPath, rec); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "trusted %s sha256=%s platform=%s\n", manifest.ID, got, loader.CurrentPlatform())
	return nil
}

// runPluginsInfo prints metadata plus trust state for one plugin ID.
// What: Read-only registry lookup with full spec plus warnings.
// Why: Operators inspect policy and trust before enabling anything.
func runPluginsInfo(cmd *cobra.Command, args []string) error {
	reg := discoverDefault()
	entry, ok := reg.Get(args[0])
	if !ok {
		return fmt.Errorf("unknown plugin %q", args[0])
	}
	s := entry.Spec
	fmt.Fprintf(cmd.OutOrStdout(), "id: %s\nname: %s\ntier: %s\nphase: %s order: %d\n",
		s.ID, s.Name, s.Tier, s.Phase, s.Order)
	fmt.Fprintf(cmd.OutOrStdout(), "severity: %s tags: %s\n", s.Severity, strings.Join(s.Tags, ","))
	fmt.Fprintf(cmd.OutOrStdout(), "safe: %v deep: %v active: %v requires_auth: %v oob: %s\n",
		s.Safe, s.Deep, s.Active, s.RequiresAuth, s.OOB)
	fmt.Fprintf(cmd.OutOrStdout(), "api_version: %s tests: %s\n", s.APIVersion, s.Tests)
	fmt.Fprintf(cmd.OutOrStdout(), "source: %s\ntrusted: %v\n", entry.SourcePath, entry.Trusted)
	for _, w := range plugin.ValidateWarnings(s) {
		fmt.Fprintf(cmd.OutOrStdout(), "warn: %s\n", w)
	}
	if s.Tests != "" {
		root := plugintest.ResolveFixtureRoot(entry.SourcePath, s.Tests)
		if st, err := os.Stat(root); err != nil || !st.IsDir() {
			fmt.Fprintf(cmd.OutOrStdout(), "fixtures: missing (%s)\n", s.Tests)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "fixtures: %s\n", root)
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "fixtures: none (findings stay tentative)\n")
	}
	return nil
}

// newOpenAPICmd builds the offline API test-plan command (P2.2).
// What: `gash openapi --spec <file|url>` parses OpenAPI 3.x / Swagger 2.0 and
// prints endpoints + parameters as a test plan. No scan, no probing — the only
// network call is the single explicit spec fetch (--spec URL).
// Why: API surface enumeration must be reviewable before any scan traffic.
func newOpenAPICmd() *cobra.Command {
	var spec, format, server, timeout string
	c := &cobra.Command{
		Use:   "openapi",
		Short: "OpenAPI/Swagger spec'ten test planı üret (taramasız)",
		Long:  "Parse an OpenAPI 3.x / Swagger 2.0 document (local file or http(s) URL) and print the endpoint/parameter test plan.\nNo scanning is performed; a remote --spec URL is fetched once and never probed further.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 && isInteractive(cmd.InOrStdin()) {
				return runOpenAPIMenu(cmd.InOrStdin(), cmd.OutOrStdout())
			}
			if strings.TrimSpace(spec) == "" {
				return fmt.Errorf("openapi: --spec zorunlu (dosya yolu veya http(s) URL)")
			}
			var plan *discovery.Plan
			var err error
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(spec)), "http://") ||
				strings.HasPrefix(strings.ToLower(strings.TrimSpace(spec)), "https://") {
				dur, perr := time.ParseDuration(strings.TrimSpace(timeout))
				if perr != nil {
					return fmt.Errorf("openapi: --timeout geçersiz %q: %w", timeout, perr)
				}
				plan, err = discovery.FetchSpec(cmd.Context(), spec, dur)
			} else {
				plan, err = discovery.LoadSpecFile(spec)
			}
			if err != nil {
				return err
			}
			switch strings.ToLower(strings.TrimSpace(format)) {
			case "", "text":
				fmt.Fprintf(cmd.OutOrStdout(), "spec: %s (%s)\n", plan.Title, plan.Version)
				fmt.Fprintf(cmd.OutOrStdout(), "servers: %s\n", strings.Join(plan.Servers, ", "))
				for _, t := range plan.Targets(server) {
					fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", t)
				}
				for _, ep := range plan.Endpoints {
					if len(ep.Params) == 0 {
						continue
					}
					var ps []string
					for _, p := range ep.Params {
						ps = append(ps, p.In+":"+p.Name)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "  %s %s params=[%s]\n", ep.Method, ep.Path, strings.Join(ps, ", "))
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%d endpoints\n", len(plan.Endpoints))
			case "json":
				data, err := plan.MarshalJSON()
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
			default:
				return fmt.Errorf("openapi: --format %q geçersiz (text|json)", format)
			}
			return nil
		},
	}
	c.Flags().StringVar(&spec, "spec", "", "OpenAPI/Swagger dosyası veya http(s) URL")
	c.Flags().StringVar(&format, "format", "text", "text|json")
	c.Flags().StringVar(&server, "server", "", "hedef baz sunucu (boşsa spec'teki ilk servers[] girdisi)")
	c.Flags().StringVar(&timeout, "timeout", "15s", "uzak spec çekme zaman aşımı")
	return c
}

func newSuppressCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "suppress",
		Short: "Yerel suppress yönetimi",
		RunE: func(cmd *cobra.Command, args []string) error {
			if isInteractive(cmd.InOrStdin()) {
				return runSuppressMenu(cmd.InOrStdin(), cmd.OutOrStdout())
			}
			return cmd.Help()
		},
	}
	cmd.AddCommand(
		&cobra.Command{Use: "add <finding-id>", Short: "Suppress ekle", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "suppress add %s\n", args[0])
			return nil
		}},
		&cobra.Command{Use: "list", Short: "Suppress listele", RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "suppress list")
			return nil
		}},
		&cobra.Command{Use: "remove <finding-id>", Short: "Suppress kaldır", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "suppress remove %s\n", args[0])
			return nil
		}},
	)
	return cmd
}

// newDiffCmd builds the baseline-diff command.
// What: Compares two JSON scan reports by finding fingerprint (old vs new).
// Why: CI needs "fail only on new findings" without touching existing ones.
func newDiffCmd() *cobra.Command {
	var oldPath, newPath, format, failOn string
	c := &cobra.Command{
		Use:   "diff",
		Short: "Compare two JSON scan reports by fingerprint",
		Long: "Compare a baseline report (--old) with a current report (--new) using stored finding fingerprints.\n" +
			"Prints NEW / FIXED / UNCHANGED lists as text or JSON.\n" +
			"With --fail-on new, exits non-zero only when at least one NEW finding exists.\n\n" +
			"Examples:\n" +
			"  gash diff --old baseline.json --new current.json\n" +
			"  gash diff --old baseline.json --new current.json --format json --fail-on new",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 && isInteractive(cmd.InOrStdin()) {
				return runDiffMenu(cmd.InOrStdin(), cmd.OutOrStdout())
			}
			if strings.TrimSpace(oldPath) == "" || strings.TrimSpace(newPath) == "" {
				return fmt.Errorf("diff: --old and --new are required")
			}
			failLevel, err := reporter.NormalizeDiffFailOn(failOn)
			if err != nil {
				return err
			}
			fmtName := strings.ToLower(strings.TrimSpace(format))
			if fmtName == "" {
				fmtName = "text"
			}
			if fmtName != "text" && fmtName != "json" {
				return fmt.Errorf("diff: --format %q invalid (text|json)", format)
			}
			oldData, err := os.ReadFile(oldPath)
			if err != nil {
				return fmt.Errorf("diff: --old %q: %w", oldPath, err)
			}
			newData, err := os.ReadFile(newPath)
			if err != nil {
				return fmt.Errorf("diff: --new %q: %w", newPath, err)
			}
			res, err := reporter.DiffReports(oldData, newData)
			if err != nil {
				return err
			}
			if fmtName == "json" {
				if err := reporter.WriteDiffJSON(cmd.OutOrStdout(), res); err != nil {
					return err
				}
			} else {
				if err := reporter.WriteDiffText(cmd.OutOrStdout(), res); err != nil {
					return err
				}
			}
			if res.ShouldFail(failLevel) {
				return fmt.Errorf("diff: --fail-on %s triggered (%d new)", failLevel, len(res.New))
			}
			return nil
		},
	}
	c.Flags().StringVar(&oldPath, "old", "", "baseline (old) JSON report path")
	c.Flags().StringVar(&newPath, "new", "", "current (new) JSON report path")
	c.Flags().StringVar(&format, "format", "text", "output format (text|json)")
	c.Flags().StringVar(&failOn, "fail-on", "", "CI gate (new or empty; empty never fails)")
	return c
}

func newCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "completion", Short: "Shell completion"}
	cmd.AddCommand(
		&cobra.Command{Use: "bash", Short: "bash", RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Root().GenBashCompletion(os.Stdout)
		}},
		&cobra.Command{Use: "zsh", Short: "zsh", RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Root().GenZshCompletion(os.Stdout)
		}},
		&cobra.Command{Use: "fish", Short: "fish", RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Root().GenFishCompletion(os.Stdout, true)
		}},
		&cobra.Command{Use: "powershell", Short: "powershell", RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Root().GenPowerShellCompletion(os.Stdout)
		}},
	)
	return cmd
}
