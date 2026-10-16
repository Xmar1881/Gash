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

func main() {
	if len(os.Args) == 1 {
		handleNoArgs(newRoot())
		return
	}
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

// handleNoArgs prints usage for a bare double-click/no-arg run.
// What: Help plus short usage for interactive console runs without args.
// Why: Explorer double-click would otherwise flash and close with no guidance.
func handleNoArgs(root *cobra.Command) {
	printNoArgsUsage(root)
	if shouldWaitForEnter() {
		waitForEnter()
	}
}

// printNoArgsUsage shows the CLI hint plus full help.
// What: Preserved cmd.exe hint plus short usage and examples.
// Why: Users need copy-pasteable next steps, not just an error.
func printNoArgsUsage(root *cobra.Command) {
	fmt.Fprintln(os.Stdout, "This is a command line tool. You need to open cmd.exe and run it from there.")
	fmt.Fprintln(os.Stdout, "Usage: gash <command> [flags]")
	fmt.Fprintln(os.Stdout, "Examples:")
	fmt.Fprintln(os.Stdout, "  gash --help")
	fmt.Fprintln(os.Stdout, "  gash scan --help")
	fmt.Fprintln(os.Stdout, "  gash plugins list")
	fmt.Fprintln(os.Stdout, "")
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	_ = root.Help()
}

// shouldWaitForEnter decides if a pause is needed.
// What: True only on Windows with an interactive stdin.
// Why: Double-click consoles vanish on exit; pipes/CI must never block.
func shouldWaitForEnter() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	return isStdinTerminal()
}

// isStdinTerminal reports interactive stdin without extra deps.
// What: Char-device check on os.Stdin.
// Why: Pipes and redirections are not char devices, so no pause there.
func isStdinTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
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
	root.AddCommand(newCompletionCmd())
	return root
}

func newScanCmd() *cobra.Command {
	var (
		target        string
		targetFile    string
		resume        bool
		outputDir     string
		proxy         string
		safe          bool
		deep          bool
		active        bool
		aggressive    bool
		scope         []string
		maxPerTarget  int64
		maxTotal      int64
		pluginTimeout string
		oobServer     string
		oobWait       string
		showTentative bool
		format        []string
		output        string
		failOn        string
		noPluginCache bool
		strictPlugins bool
		profile       string
		ignorePlugins []string
		rateLimit     float64
		parallelism   int
		authHeaders   []string
		cookies       []string
		basicAuth     string
		authUserA     []string
		authUserB     []string
		techFlags     []string
		tcpBanners    []string
		maxPages      int
		depth         int
		openapiSpec   string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Hedefi tara (Candidate→Verify→Finding hattı)",
		Long:  "Target scanner with live Tier1/Tier2/Tier3 execution and oracle verification.\n\nResponsibility note: scan only targets you own or have explicit written permission to test.\nScan only with explicit permission; unauthorized scanning may be illegal and is strictly prohibited.\nUse --scope to lock the allowlist and keep --safe unless you understand active payloads.",
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
			if strings.TrimSpace(target) != "" {
				if len(scope) > 0 {
					if err := enforceScanScope(ctx, normalized, scope); err != nil {
						return err
					}
				} else if !isLocalScanTarget(normalized) {
					fmt.Fprintln(cmd.ErrOrStderr(), "warn: external target without --scope — scan only with explicit permission")
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
					if trimmed := strings.TrimSpace(part); trimmed != "" {
						ignoreSet[trimmed] = true
					}
				}
			}
			cfg := engine.DefaultConfig()
			cfg.Safe = safe
			cfg.Deep = deep
			cfg.Active = active
			cfg.HasAuth = false
			cfg.Auth = authCtx
			cfg.AuthA = authA
			cfg.AuthB = authB
			cfg.Technologies = techFlags
			cfg.TCPBanners = tcpBanners
			cfg.Scope = scope
			cfg.MaxRequestsPerTarget = maxPerTarget
			cfg.MaxRequestsTotal = maxTotal
			cfg.PluginTimeoutMs = pluginDur.Milliseconds()
			cfg.RatePerSecond = rateLimit
			cfg.Parallelism = parallelism
			cfg.OOBServer = strings.TrimSpace(oobServer)
			cfg.StrictPlugins = strictPlugins
			cfg.ShowTentative = showTentative
			cfg.IgnorePlugins = ignoreSet
			cfg.Target = normalized
			cfg.MaxPages = maxPages
			cfg.Depth = depth
			cfg.OpenAPISpec = strings.TrimSpace(openapiSpec)
			if strings.TrimSpace(proxy) != "" {
				pu, err := url.Parse(strings.TrimSpace(proxy))
				if err != nil || pu.Host == "" || (pu.Scheme != "http" && pu.Scheme != "https" && pu.Scheme != "socks5") {
					return fmt.Errorf("scan: --proxy geçersiz (http, https veya socks5 URL olmalı, got %q)", proxy)
				}
				cfg.ProxyURL = strings.TrimSpace(proxy)
			}

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
			eng := engine.New(reg, cfg)
			for id, rec := range records {
				platform := rec.Platform
				if strings.TrimSpace(platform) == "" {
					platform = loader.AnyPlatform
				}
				eng.SetTrustRecord(id, rec.SHA256, platform)
			}
			rep, err := eng.Run(ctx, normalized)
			if err != nil {
				return err
			}
			opts := reporter.Options{ShowTentative: showTentative, Target: normalized}
			if err := writeScanReports(cmd, rep, formats, opts, output); err != nil {
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
	cmd.Flags().StringVar(&proxy, "proxy", "", "upstream HTTP proxy URL (örn. http://127.0.0.1:8080)")
	cmd.Flags().BoolVar(&safe, "safe", true, "varsayılan safe")
	cmd.Flags().BoolVar(&deep, "deep", false, "deep faz + ExecutionOracle kapısı")
	cmd.Flags().BoolVar(&active, "active", false, "state-changing/OOB payload kapısı")
	cmd.Flags().BoolVar(&aggressive, "aggressive", false, "tam güç ofansif tarama: tüm dedektörler, genişletilmiş bütçe, yüksek rate-limit")
	cmd.Flags().StringSliceVar(&scope, "scope", nil, "CIDR/domain allowlist (verilirse hedef doğrulanır)")
	cmd.Flags().Int64Var(&maxPerTarget, "max-requests-per-target", 1000, "per-target bütçe")
	cmd.Flags().Int64Var(&maxTotal, "max-requests-total", 10000, "global bütçe")
	cmd.Flags().StringVar(&pluginTimeout, "plugin-timeout", "30s", "per-plugin timeout")
	cmd.Flags().StringVar(&oobWait, "oob-wait", "60s", "scan-sonu OOB penceresi")
	cmd.Flags().StringVar(&oobServer, "oob-server", "", "self-hosted interaction sunucusu (boş=kapalı)")
	cmd.Flags().BoolVar(&showTentative, "show-tentative", false, "tentative'i dahil et")
	cmd.Flags().StringSliceVar(&format, "format", []string{"text"}, "json|sarif|text|html|junit (tekrarlanabilir)")
	cmd.Flags().StringVar(&output, "output", "", "rapor dosyası (tek format ile kullanın)")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "CI kapısı (firm|confirmed)")
	cmd.Flags().BoolVar(&noPluginCache, "no-plugin-cache", false, "cache bypass (debug)")
	cmd.Flags().BoolVar(&strictPlugins, "strict-plugins", false, "yalnızca trust'lı Tier3")
	cmd.Flags().StringSliceVar(&ignorePlugins, "ignore-plugin", nil, "döngü kırma / susturma")
	cmd.Flags().Float64Var(&rateLimit, "rate-limit", 10, "per-target req/s")
	cmd.Flags().IntVar(&parallelism, "parallelism", 8, "worker sayısı")
	cmd.Flags().StringVar(&profile, "profile", "standard", "scan profile: safe|standard|deep|aggressive (safe=pasif+düşük bütçe, standard=kontrollü aktif, deep=browser+yüksek bütçe, aggressive=tam ofansif)")
	cmd.Flags().StringSliceVar(&authHeaders, "auth-header", nil, "kimlik header'ı 'Ad: değer' (tekrarlanabilir, requires_auth kapısını açar)")
	cmd.Flags().StringSliceVar(&cookies, "cookie", nil, "oturum cookie'si 'a=b[; c=d]' (tekrarlanabilir)")
	cmd.Flags().StringVar(&basicAuth, "basic-auth", "", "basic kimlik 'kullanıcı:parola'")
	cmd.Flags().StringSliceVar(&authUserA, "auth-user-a", nil, "BOLA matrisi kullanıcı A başlığı 'Ad: değer' (tekrarlanabilir, --auth-user-b ile birlikte, --active şart)")
	cmd.Flags().StringSliceVar(&authUserB, "auth-user-b", nil, "BOLA matrisi kullanıcı B başlığı 'Ad: değer' (tekrarlanabilir, --auth-user-a ile birlikte, --active şart)")
	cmd.Flags().StringSliceVar(&techFlags, "tech", nil, "bilinen teknoloji (tekrarlanabilir/virgüllü, örn. wordpress,graphql — chain kapısı)")
	cmd.Flags().StringSliceVar(&tcpBanners, "tcp-banner", nil, "açık TCP banner probu 'host:port' (tekrarlanabilir, --active şart, kapsam-izinli)")
	cmd.Flags().IntVar(&maxPages, "max-pages", 50, "crawler maksimum sayfa sayısı (0=sadece hedef sayfa)")
	cmd.Flags().IntVar(&depth, "depth", 3, "crawler maksimum derinlik")
	cmd.Flags().StringVar(&openapiSpec, "openapi-spec", "", "OpenAPI/Swagger dosyası veya http(s) URL (endpoint+parametreler surfacePoints'e eklenir; URL yalnızca loopback/kapsam-içi)")
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

// writeScanReports renders each requested format to stdout or a file.
// What: Single-format file output plus multi-format stdout fan-out.
// Why: One file keeps machine-readable reports parseable; stdout stays human-first.
func writeScanReports(cmd *cobra.Command, rep *engine.Report, formats []string, opts reporter.Options, output string) error {
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
		fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%s, %d findings, %d skipped)\n", output, formats[0], len(rep.Findings), len(rep.Skipped))
		return nil
	}
	for _, name := range formats {
		if err := writeOneScanFormat(cmd.OutOrStdout(), rep, name, opts); err != nil {
			return err
		}
	}
	return nil
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
	cmd := &cobra.Command{Use: "plugins", Short: "Plugin yönetimi"}
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
		return runFixtureSuite(cmd, ctx, spec, oracleName, path, nil)
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
		return runFixtureSuite(cmd, ctx, spec, oracleName, path, nil)
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

func newBenchCmd() *cobra.Command {
	bench := &cobra.Command{Use: "bench", Short: "Benchmark"}
	lab := &cobra.Command{Use: "lab", Short: "Recall lab (DVWA/JuiceShop/WebGoat)", RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), "bench lab (faz2 iskelet — lab Faz 3)")
		return nil
	}}
	bench.AddCommand(lab)
	return bench
}

func newSuppressCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "suppress", Short: "Yerel suppress yönetimi"}
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
