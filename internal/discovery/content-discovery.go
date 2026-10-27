// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/discovery/content-discovery.go
// What: Wordlist tabanlı dizin/dosya keşif motoru (engine-recon, plugin YOK).
// Why: FingerprintTech'e göre teknoloji-özel küçük pinned wordlist seçer,
// PolicySession bütçe/rate disipliniyle dener, soft-404 baseline negatif
// kontrol + içerik sinyaliyle GASH-028 (exposed-path) üretir, bulunan
// path'leri crawler yüzeyine geri besler (smart-recurse, derinlik ≤2).

package discovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/probe"
)

//go:embed wordlists/*.txt
var wordlistFS embed.FS

const (
	// RuleIDExposedPath yeni bulgu tipidir (çakışma yok: 022/023 cookie-cors,
	// 024/025/026/027 proto-recon kullanımda; 028 boş).
	RuleIDExposedPath = "GASH-028"
	// CWEExposedPath bilgi-ifşasıdır (GASH-021/026 ile aynı CWE ailesi, yeni CWE YOK).
	CWEExposedPath = "CWE-200"
	// OracleContentExposure mevcut disiplinin adıdır. Yeni oracle struct YOK:
	// kanıt, differential kontrol disiplini (temiz-kontrol karşılaştırması) +
	// reflection/error imza disiplini (deterministik içerik imzası) ile üretilir.
	// Gerekçe: exposure kanıtı deterministik artefakt + negatif kontrolden ibarettir;
	// yeni soyutlama FP yüzeyi ve test yükü büyütür, mevcut disiplin yeterlidir.
	OracleContentExposure = "differential"
	// PluginIDContentDiscovery PolicySession kimliğidir (safe=true, GET/HEAD).
	PluginIDContentDiscovery = "engine-content-discovery"
	// DetectorVersion izlenebilirlik sürümüdür.
	DetectorVersionContentDiscovery = "1.0"
)

// BackupSuffixes smart-recurse yedek uzantılarıdır (bulunan path'e eklenir).
var BackupSuffixes = []string{".bak", ".old", ".swp", "~"}

// ContentOptions keşif sınırlarıdır.
type ContentOptions struct {
	// MaxProbes toplam istek tavanı (baseline dahil). 0 ise 80.
	MaxProbes int
	// MaxRecurseDepth smart-recurse derinlik tavanı. 0 ise recurse kapalı, default 2.
	MaxRecurseDepth int
	// BaselineSamples soft-404 öğrenme isteği sayısı. <=0 ise 2.
	BaselineSamples int
	// Entries test-override'dır: doluysa teknoloji seçimi BYPASS edilir.
	// Canlı taramada boş bırakılır (pinned wordlist zorunlu).
	Entries []string
	// WordlistName override etiketi (kanıt izlenebilirliği, testlerde raporlanır).
	WordlistName string
	// OnProgress reports completed probes (baseline included) against MaxProbes.
	OnProgress func(done, total int)
}

// DefaultContentOptions önerilen sınırlar.
func DefaultContentOptions() ContentOptions {
	return ContentOptions{MaxProbes: 80, MaxRecurseDepth: 2, BaselineSamples: 2}
}

// contentDiscoveryBudget caps the wordlist phase so a slow proxy pool cannot
// consume the scan deadline. Variable so tests can shorten it.
var contentDiscoveryBudget = 90 * time.Second

// contentDiscoveryWorkers bounds parallel probes. The shared policy session
// still enforces the per-host rate limit and request budget.
const contentDiscoveryWorkers = 8

// ContentResult keşif çıktısıdır.
type ContentResult struct {
	Findings []*finding.Finding
	// DiscoveredPaths crawler'a geri beslenecek kabul URL'leridir (tam URL).
	DiscoveredPaths []string
	// Requests gönderilen istek sayısı (baseline dahil).
	Requests int
	// Wordlist seçilen listedir (kanıt izi).
	Wordlist string
	// BudgetExhausted is set when the phase hit its time cap before probing
	// every wordlist entry.
	BudgetExhausted bool
}

// wordlistLoad gömülü listeyi okur (boş-satır/yorumsuz, sıra korunur).
func wordlistLoad(name string) []string {
	data, err := wordlistFS.ReadFile("wordlists/" + name + ".txt")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// WordlistNames gömülü liste adlarıdır.
func WordlistNames() []string {
	return []string{"common", "wordpress", "php", "node", "java", "python"}
}

// WordlistForTech FingerprintTech sonucuna göre liste seçer.
// What: wordpress > php > node-ailesi > java > python-ailesi > common önceliği;
// common her zaman tabandır (admin/yedek/.git/config klasikleri).
// Why: Küçük pinned yüzey (bütçe disiplini); teknoloji körü dev wordlist YOK.
func WordlistForTech(fp TechFingerprint) (string, []string) {
	set := map[string]bool{}
	for _, t := range fp.Tech {
		set[strings.ToLower(strings.TrimSpace(t))] = true
	}
	tech := "common"
	switch {
	case set["wordpress"]:
		tech = "wordpress"
	case set["php"] || set["laravel"]:
		tech = "php"
	case set["express"] || set["nextjs"] || set["node"]:
		tech = "node"
	case set["java"]:
		tech = "java"
	case set["django"] || set["python"]:
		tech = "python"
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range append(wordlistLoad("common"), wordlistLoad(tech)...) {
		k := strings.ToLower(e)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	name := "common"
	if tech != "common" {
		name = "common+" + tech
	}
	return name, out
}

// IsSensitivePath hassas path kararıdır (gövde çekilmez, HEAD/boyut sinyali).
func IsSensitivePath(p string) bool {
	l := strings.ToLower(strings.TrimSpace(p))
	l = strings.TrimPrefix(l, "/")
	for _, pre := range []string{".git/", ".svn/", ".hg/", ".bzr/"} {
		if strings.HasPrefix(l, pre) || strings.Contains(l, "/"+pre) {
			return true
		}
	}
	for _, ex := range []string{".git/head", ".git/config", ".svn/entries"} {
		if l == ex || strings.HasSuffix(l, "/"+ex) {
			return true
		}
	}
	return false
}

var (
	// configPatterns sır-ifşası imzalarıdır (gövde sinyali, confirmed).
	configPatterns = []string{
		"db_password", "db_pass", "secret_key", "api_key", "aws_secret",
		"private key", "-----begin", "root:x:", "connectionstring",
		"database_password", "django_secret",
	}
	// adminKeywords yönetim-arayüzü sinyalleridir (gövde sinyali, confirmed).
	adminKeywords = []string{
		"admin", "administrator", "dashboard", "control panel",
		"wp-admin", "wp-login", "manager", "console", "sign in",
		`type="password"`, `type='password'`,
	}
	// notFoundMarkers catch-all echo indirimidir: yalnızca admin-keyword
	// sinyali + bu ibareler varsa confirmed yerine tentative (FP freni).
	notFoundMarkers = []string{
		"not found", "404", "page not found", "no such",
		"does not exist", "bulunamad", "sayfa bulunamad",
	}
)

// maxSignalBytes sinyal amaçlı sınırlı okuma penceresidir (toplu indirme YOK).
const maxSignalBytes = 32 * 1024

// signalOf gövde penceresinden içerik sinyalini sınıflar.
func signalOf(path, window string) (signal string, strong bool) {
	lower := strings.ToLower(window)
	pathLower := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	containsAny := func(list []string) bool {
		for _, m := range list {
			if strings.Contains(lower, m) {
				return true
			}
		}
		return false
	}
	if strings.Contains(lower, "ref:") && (strings.Contains(lower, "refs/") || strings.Contains(lower, "commit")) {
		return "git-marker", true
	}
	// Known high-signal disclosure artifacts. Path + content pair keeps this a
	// deterministic marker, not a generic "body is long" heuristic.
	if (pathLower == "/metrics" || pathLower == "/metrics/" || strings.HasSuffix(pathLower, "/metrics")) &&
		(strings.Contains(lower, "# help") || strings.Contains(lower, "# type")) {
		return "prometheus-metrics", true
	}
	if (strings.Contains(pathLower, "api-docs") || strings.Contains(pathLower, "swagger")) &&
		(strings.Contains(lower, "swagger-ui") || strings.Contains(lower, "swagger ui") || strings.Contains(lower, "openapi")) {
		return "api-docs", true
	}
	if strings.HasSuffix(pathLower, ".md") && strings.HasPrefix(strings.TrimSpace(window), "# ") {
		return "markdown-doc", true
	}
	if strings.HasSuffix(pathLower, ".gitignore") &&
		(strings.Contains(lower, "node_modules") || strings.Contains(lower, ".php") || strings.Contains(lower, "dockerfile") || strings.Contains(lower, ".env")) {
		return "gitignore-content", true
	}
	if strings.Contains(pathLower, "/.github/workflows/") &&
		strings.Contains(lower, "on:") && (strings.Contains(lower, "jobs:") || strings.Contains(lower, "runs-on:")) {
		return "workflow-yaml", true
	}
	if strings.HasSuffix(pathLower, "phpinfo.php") &&
		strings.Contains(lower, "php version") && strings.Contains(lower, "phpinfo()") {
		return "phpinfo", true
	}
	// Binary / Data extensions that should NEVER be HTML:
	isHTML := strings.Contains(lower, "<!doctype html") || strings.Contains(lower, "<html") || strings.Contains(lower, "<body")
	if isHTML {
		for _, ext := range []string{".sql", ".zip", ".tar", ".gz", ".tgz", ".swp", ".ds_store", ".log"} {
			if strings.HasSuffix(pathLower, ext) {
				return "", false // HTML body returned for binary/sql/log path is a soft-404, not an exposed file
			}
		}
	}

	if strings.HasSuffix(pathLower, ".sql") {
		if !isHTML && (strings.Contains(lower, "create table") || strings.Contains(lower, "insert into") || strings.Contains(lower, "-- mysql") || strings.Contains(lower, "-- postgres") || strings.Contains(lower, "drop table")) {
			return "sql-dump", true
		}
		return "", false
	}
	if strings.HasSuffix(pathLower, ".swp") {
		if strings.HasPrefix(window, "b0") {
			return "vim-swap", true
		}
		return "", false
	}
	if strings.HasSuffix(pathLower, ".zip") {
		if strings.HasPrefix(window, "PK") {
			return "zip-archive", true
		}
		return "", false
	}
	if containsAny(configPatterns) {
		return "config-pattern", true
	}
	isAdminPath := strings.Contains(pathLower, "admin") || strings.Contains(pathLower, "login") ||
		strings.Contains(pathLower, "dashboard") || strings.Contains(pathLower, "console") ||
		strings.Contains(pathLower, "panel") || strings.Contains(pathLower, "manager")
	if isAdminPath && containsAny(adminKeywords) {
		if containsAny(notFoundMarkers) {
			return "admin-keyword+soft404-phrase", false
		}
		return "admin-keyword", true
	}
	return "", false
}

// randHex test/negatif-kontrol yol etiketi üretir.
func randHex(n int) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "gashfallback"
	}
	return hex.EncodeToString(b[:])[:n]
}

// ensureBaseline soft-404 parmak izini öğrenir (negatif kontrol temeli).
func ensureBaseline(ctx context.Context, client *probe.Client, pctx context.Context, target string, model *baseline.Model, samples int) *baseline.Model {
	if model == nil {
		model = baseline.NewDefaultModel()
	}
	if samples <= 0 {
		samples = 2
	}
	var bodies [][]byte
	var statuses []int
	for i := 0; i < samples; i++ {
		u := strings.TrimSuffix(target, "/") + "/gash-404-" + randHex(8)
		resp, err := client.Send(pctx, http.MethodGet, u, nil, nil)
		if err != nil || resp == nil {
			continue
		}
		bodies = append(bodies, resp.Body)
		statuses = append(statuses, resp.Status)
		_ = ctx
	}
	if len(bodies) > 0 {
		model.LearnSoft404(bodies, statuses)
	}
	return model
}

// newContentID bulgu kimliğidir.
func newContentID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "finding_cd_fallback"
	}
	return "finding_cd_" + hex.EncodeToString(b[:])
}

// buildContentFinding motor-içi bulgu kurar (proto.ToFinding disiplini:
// finding.Build KULLANILMAZ — Build, Tests'siz spec'te confirmed'ı tentative'a
// indirir; engine-recon'un fixture-spec'i yoktur, kanıt disiplini buradadır).
func buildContentFinding(fullURL, method, path string, status int, signal string, conf pluginConfidence, wordlist string, depth int) *finding.Finding {
	confStr := string(conf)
	_ = confStr
	f := &finding.Finding{
		ID:          newContentID(),
		RuleID:      RuleIDExposedPath,
		CWE:         CWEExposedPath,
		Title:       "Exposed path " + path,
		Description: fmt.Sprintf("wordlist keşfi: %s -> %d (%s), soft-404 baseline negatif + içerik sinyali", path, status, signal),
		Severity:    plugin.SeverityMedium,
		Confidence:  conf,
		Target:      fullURL,
		InjectionPoint: plugin.InjectionPoint{
			URL:           fullURL,
			Method:        method,
			ParamLocation: "path",
		},
		Evidence: map[string]string{
			"path":     path,
			"status":   fmt.Sprintf("%d", status),
			"signal":   signal,
			"wordlist": wordlist,
			"depth":    fmt.Sprintf("%d", depth),
			"control":  "soft404-negative",
		},
		Reproducibility: map[string]string{
			"repeats": "1",
			"control": "soft404-negative (baseline hash + HEAD kontrol)",
			"note":    "deterministik artefakt: N=1 kontrol yeterli (istatistiksel differential N=3 gerekmez)",
		},
		PluginID:           PluginIDContentDiscovery,
		OracleName:         OracleContentExposure,
		Tags:               []string{"discovery", "exposed-path", "recon"},
		Method:             method,
		VerificationMethod: "oracle differential, repeats=1, control=soft404-negative",
		Note:               "baseline negatif + içerik sinyali -> " + string(conf) + "; çıplak 200 en fazla tentative",
		DetectorVersion:    DetectorVersionContentDiscovery,
	}
	f.Fingerprint = finding.Fingerprint(f)
	return f
}

// pluginConfidence plugin.Confidence daraltmasıdır (import döngüsü yok).
type pluginConfidence = plugin.Confidence

// DiscoverContent wordlist keşfini koşar.
// What: baseline öğrenme → tech-wordlist deneme → smart-recurse (yedek uzantı, tavan).
// Why: Tek canlı döngü; kapsam-dışı istek YOK (aynı host join + PolicySession),
// destructive YOK (GET/HEAD), gövde toplu indirme YOK (HEAD-only hassas + 32KB pencere).
func DiscoverContent(ctx context.Context, client *probe.Client, target string, fp TechFingerprint, model *baseline.Model, opts ContentOptions) (*ContentResult, error) {
	if client == nil {
		return nil, fmt.Errorf("content-discovery: nil probe client")
	}
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("content-discovery: invalid target %q", target)
	}
	scheme := strings.ToLower(base.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("content-discovery: scheme http/https olmalı")
	}
	if opts.MaxProbes <= 0 {
		opts.MaxProbes = 80
	}
	if opts.MaxRecurseDepth < 0 {
		opts.MaxRecurseDepth = 2
	}
	if opts.MaxRecurseDepth > 2 {
		opts.MaxRecurseDepth = 2
	}

	maxReq := opts.MaxProbes
	discCtx, cancel := context.WithTimeout(ctx, contentDiscoveryBudget)
	defer cancel()
	pctx := plugin.WithPlugin(discCtx, PluginIDContentDiscovery, true, &maxReq)

	model = ensureBaseline(discCtx, client, pctx, strings.TrimSuffix(base.String(), "/"), model, opts.BaselineSamples)

	var entries []string
	wordlist := opts.WordlistName
	if len(opts.Entries) > 0 {
		entries = append([]string{}, opts.Entries...)
		if wordlist == "" {
			wordlist = "override(test)"
		}
	} else {
		wordlist, entries = WordlistForTech(fp)
	}

	// Hassas HEAD kontrolü (aynı oturumda tek istek).
	headControl := -1
	needHEAD := false
	for _, e := range entries {
		if IsSensitivePath(e) {
			needHEAD = true
			break
		}
	}
	requests := opts.BaselineSamples
	progress := func(done int) {
		if opts.OnProgress != nil {
			opts.OnProgress(done, opts.MaxProbes)
		}
	}
	progress(requests)
	if needHEAD {
		cu := strings.TrimSuffix(base.String(), "/") + "/gash-404-" + randHex(8)
		if resp, err := client.Send(pctx, http.MethodHead, cu, nil, nil); err == nil && resp != nil {
			headControl = resp.Status
		}
		requests++
		progress(requests)
	}

	res := &ContentResult{Wordlist: wordlist}
	type item struct {
		entry string
		depth int
	}
	queue := make([]item, 0, len(entries))
	for _, e := range entries {
		queue = append(queue, item{entry: e, depth: 0})
	}
	visited := map[string]bool{}

	joinPath := func(entry string) (fullURL, path string, ok bool) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return "", "", false
		}
		ref, err := url.Parse(entry)
		if err != nil {
			return "", "", false
		}
		if ref.IsAbs() {
			return "", "", false // wordlist mutlak URL taşıyamaz (kapsam kilidi)
		}
		resolved := base.ResolveReference(&url.URL{Path: "/" + strings.TrimPrefix(entry, "/")})
		if !strings.EqualFold(resolved.Hostname(), base.Hostname()) {
			return "", "", false
		}
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			return "", "", false
		}
		return resolved.String(), resolved.EscapedPath(), true
	}

	type probeJob struct {
		it        item
		fullURL   string
		path      string
		sensitive bool
		method    string
	}
	type probeOutcome struct {
		job  probeJob
		resp *probe.Response
		err  error
	}
	for len(queue) > 0 {
		if requests >= opts.MaxProbes || discCtx.Err() != nil {
			break
		}
		batch := make([]probeJob, 0, contentDiscoveryWorkers)
		for len(queue) > 0 && len(batch) < contentDiscoveryWorkers && requests+len(batch) < opts.MaxProbes {
			it := queue[0]
			queue = queue[1:]
			fullURL, path, ok := joinPath(it.entry)
			if !ok {
				continue
			}
			norm := strings.ToLower(path)
			if visited[norm] {
				continue
			}
			visited[norm] = true
			sensitive := IsSensitivePath(it.entry)
			method := http.MethodGet
			if sensitive {
				method = http.MethodHead
			}
			batch = append(batch, probeJob{
				it: it, fullURL: fullURL, path: path,
				sensitive: sensitive, method: method,
			})
		}
		if len(batch) == 0 {
			continue
		}
		outcomes := make([]probeOutcome, len(batch))
		var wg sync.WaitGroup
		for i := range batch {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				resp, err := client.Send(pctx, batch[i].method, batch[i].fullURL, nil, nil)
				outcomes[i] = probeOutcome{job: batch[i], resp: resp, err: err}
			}(i)
		}
		wg.Wait()
		requests += len(batch)
		progress(requests)

		for _, oc := range outcomes {
			resp, err := oc.resp, oc.err
			it := oc.job.it
			fullURL, path := oc.job.fullURL, oc.job.path
			sensitive := oc.job.sensitive
			if err != nil || resp == nil {
				continue
			}
			switch resp.Status {
			case http.StatusOK,
				http.StatusMovedPermanently, http.StatusFound,
				http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
				http.StatusUnauthorized, http.StatusForbidden:
				// candidate
			default:
				continue
			}

			var signal string
			var strong bool
			conf := plugin.ConfidenceTentative
			decision := "tentative"

			if sensitive {
				// HEAD/boyut sinyali: gövde YOK, marker doğrulanamaz → en fazla tentative.
				if resp.Status == headControl {
					continue // kontrolle aynı statü → ayırt edici değil
				}
				cl := strings.TrimSpace(resp.Headers.Get("Content-Length"))
				if resp.Status == http.StatusOK || resp.Status == http.StatusForbidden {
					if cl == "" || cl == "0" {
						// Boyutsuz HEAD tek başına kanıt değil; 403 statü-sinyali yeterli.
						if resp.Status != http.StatusForbidden {
							continue
						}
					}
					signal = "head-size"
					conf = plugin.ConfidenceTentative
					decision = "tentative(head-only)"
				} else {
					continue
				}
			} else {
				cls := model.Classify(resp.Status, resp.Headers, resp.Body)
				if cls.Untrusted || cls.Soft404 {
					continue // baseline/WAF negatifi → reject
				}
				switch resp.Status {
				case http.StatusUnauthorized:
					signal = "status-auth-required"
				case http.StatusForbidden:
					signal = "status-forbidden"
				case http.StatusMovedPermanently, http.StatusFound,
					http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
					loc := strings.TrimSpace(resp.Headers.Get("Location"))
					if loc == "" {
						continue
					}
					signal = "redirect"
				default: // 200
					window := resp.Body
					if len(window) > maxSignalBytes {
						window = window[:maxSignalBytes]
					}
					sig, isStrong := signalOf(path, string(window))
					if sig == "" {
						signal = "bare-200"
						conf = plugin.ConfidenceTentative // çıplak 200 → tentative tavan
					} else {
						signal = sig
						strong = isStrong
						if strong {
							conf = plugin.ConfidenceConfirmed
							decision = "confirmed(signal+control)"
						} else {
							conf = plugin.ConfidenceTentative
							decision = "tentative(weak-signal)"
						}
					}
				}
			}
			_ = decision

			f := buildContentFinding(fullURL, oc.job.method, path, resp.Status, signal, conf, wordlist, it.depth)
			// Soft-404 parmak izi yokluğu kanıt notuna işlenir (denetlenebilirlik).
			sum := sha256.Sum256(model.Mask(resp.Body))
			f.Evidence["body_sha256_16"] = hex.EncodeToString(sum[:])[:16]
			res.Findings = append(res.Findings, f)
			res.DiscoveredPaths = append(res.DiscoveredPaths, fullURL)

			// Smart-recurse: bulunan path'e yedek uzantılar (derinlik tavanlı).
			if it.depth < opts.MaxRecurseDepth {
				trimmed := strings.TrimSuffix(it.entry, "/")
				for _, suf := range BackupSuffixes {
					if requests+len(queue) >= opts.MaxProbes+len(BackupSuffixes) {
						break
					}
					queue = append(queue, item{entry: trimmed + suf, depth: it.depth + 1})
				}
			}
		}
	}
	if errors.Is(discCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		res.BudgetExhausted = true
	}
	res.Requests = requests
	return res, nil
}
