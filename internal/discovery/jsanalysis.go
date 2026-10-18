// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash
//
// File: internal/discovery/jsanalysis.go
// What: Pasif JavaScript yüzey + gömülü sır analizi (engine-recon, plugin YOK).
// Why: Crawl'ın topladığı same-origin JS gövdeleri GET ile bir kez okunur;
// endpoint'ler (fetch/axios/jQuery/XHR + rota-benzeri literaller) yüzeye geri
// beslenir, sır adayları TAM DEĞER RAPORLANMADAN maskelenir (first4…last4) ve
// GASH-067 kanıtına dönüşür. Gürültü (CDN, w3.org/schema.org, data:/mailto:,
// asset uzantıları) burada elenir; kapsam kararı çağıran motordadır.

package discovery

import (
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/plugin"
)

const (
	// MaxJSAnalysisBytes analiz tavanıdır; üzerindeki gövde analiz edilmez
	// (Stats.Skipped ile denetim izi bırakır).
	MaxJSAnalysisBytes = 2 * 1024 * 1024
	// maxJSEndpointsPerFile dosya başına endpoint tavanıdır.
	maxJSEndpointsPerFile = 200
	// maxEndpointLiteralLen tekil endpoint/map literal tavanıdır.
	maxEndpointLiteralLen = 2048
	// jsMaxSourceMapsPerFile dosya başına kaynak haritası tavanıdır.
	jsMaxSourceMapsPerFile = 5
	// jsGenericEntropyMin generic-sır kuralının Shannon entropi eşiğidir.
	jsGenericEntropyMin = 3.5
	// jsMaxSrcCandidates HTML başına harici script src adayı tavanıdır.
	jsMaxSrcCandidates = 200
	// jsMaxFilesPerCrawl tarama başına çekilecek harici JS tavanıdır.
	jsMaxFilesPerCrawl = 50
	// jsMaxInlinePerScript tek inline script gövde tavanıdır (256 KB).
	jsMaxInlinePerScript = 256 * 1024
	// jsMaxInlineTotal crawl başına toplam inline JS tavanıdır (1 MB).
	jsMaxInlineTotal = 1024 * 1024
)

// JSEndpoint JS içinde keşfedilen HTTP uç noktasıdır.
type JSEndpoint struct {
	Raw      string   // kaynaktaki literal (şablon değişkenleri "1" ile doldurulmuş)
	Resolved string   // base URL'e göre çözülmüş mutlak URL
	Method   string   // GET/POST/... (çağrıdan yakalanamazsa GET)
	Params   []string // sorgu parametre adları (tekilleştirilmiş, sıralı)
}

// Secret JS gövdesinde bulunan gömülü sır adayıdır.
// Tam değer ASLA dışarı çıkmaz; yalnızca Masked + Context raporlanır.
type Secret struct {
	Type     string          // sır sınıfı (kural adı, örn. stripe-live-secret-key)
	RuleName string          // kural kimliği (kanıt izi; dedupe anahtarı)
	Masked   string          // first4…last4 (kısa değerlerde tek "…")
	VarName  string          // generic kuralda anahtar adı, yoksa ""
	Severity plugin.Severity // kural sınıfının şiddeti
	Context  string          // ±20 karakter bağlam, değer maskeli
	Location string          // asset URL (dosya veya kaynak haritası)
}

// JSStats analiz sayaçlarıdır.
type JSStats struct {
	Skipped   bool // boyut tavanı aşıldı: analiz atlandı (denetim izli)
	Endpoints int  // keşfedilen endpoint sayısı (Stats.Endpoints ile eş)
	Secrets   int  // bulunan sır sayısı (maskeli)
	Maps      int  // bulunan sourceMappingURL sayısı
}

// JSReport pasif JS analizinin çıktısıdır.
type JSReport struct {
	Endpoints  []JSEndpoint
	Secrets    []Secret
	SourceMaps []string
	Stats      JSStats
}

// JSSource crawl sırasında toplanan JS kaynağıdır (harici veya inline).
type JSSource struct {
	URL    string // harici dosya URL'i veya inline'ın sayfa URL'i
	Body   []byte
	Inline bool
}

const (
	jsQuoteClass = "[\"'`]"
	jsInnerClass = "[^\"'`\n]"
)

var (
	// reFetchCall fetch("...") / fetch('...') / fetch(`...`) çağrılarıdır.
	reFetchCall = regexp.MustCompile(`(?i)\bfetch\s*\(\s*` + jsQuoteClass + `(` + jsInnerClass + `{1,1000})` + jsQuoteClass)
	// reAxiosVerb axios.get/post/... ("...") çağrılarıdır (fiil yakalanır).
	reAxiosVerb = regexp.MustCompile(`(?i)\baxios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*` + jsQuoteClass + `(` + jsInnerClass + `{1,1000})` + jsQuoteClass)
	// reURLProperty axios({url: "..."}) / $.ajax({url: "..."}) konfig nesneleridir.
	reURLProperty = regexp.MustCompile(`(?i)\burl\s*:\s*` + jsQuoteClass + `(` + jsInnerClass + `{1,1000})` + jsQuoteClass)
	// reJQueryCall $.get("...") / $.post("...") çağrılarıdır.
	reJQueryCall = regexp.MustCompile(`(?i)\$\s*\.\s*(get|post)\s*\(\s*` + jsQuoteClass + `(` + jsInnerClass + `{1,1000})` + jsQuoteClass)
	// reXHROpen XMLHttpRequest .open("GET", "...") çiftidir (fiil + URL).
	reXHROpen = regexp.MustCompile(`(?i)\.open\s*\(\s*` + jsQuoteClass + `([A-Za-z]{3,7})` + jsQuoteClass + `\s*,\s*` + jsQuoteClass + `(` + jsInnerClass + `{1,1000})` + jsQuoteClass)
	// reAbsJSURL gövdedeki mutlak http(s) URL'lerdir.
	reAbsJSURL = regexp.MustCompile(`(?i)\bhttps?://[^\s"'` + "`" + `<>(){}]{3,1000}`)
	// reJSString rota-benzeri literalleri taramak için tırnaklı string taramasıdır.
	reJSString = regexp.MustCompile(jsQuoteClass + `(` + jsInnerClass + `{1,512})` + jsQuoteClass)
	// reSourceMap `//# sourceMappingURL=` / `//@ sourceMappingURL=` yorumlarıdır.
	reSourceMap = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=([^\s'"]+)`)
	// reTemplateVar şablon ifadeleridir (${...} -> "1", deterministik).
	reTemplateVar = regexp.MustCompile(`\$\{[^}]{0,64}\}`)
	// reGenericSecret isim + atama + yüksek-entropi değer kuralıdır.
	reGenericSecret = regexp.MustCompile(`(?i)\b(api[_-]?key|apikey|secret[_-]?key|secret|client[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|password|passwd)\s*[:=]\s*` + jsQuoteClass + `([A-Za-z0-9_\-\.+/]{8,128})` + jsQuoteClass)
)

// jsRouteKeywords yol-benzeri literalleri endpoint sayan anahtar parçalardır.
var jsRouteKeywords = []string{
	"/api/", "/graphql", "/rest/", "/oauth", "/admin", "/internal",
	"/webhook", "/upload", "/export",
	"/v1/", "/v2/", "/v3/", "/v4/", "/v5/", "/v6/", "/v7/", "/v8/", "/v9/",
}

// jsAssetExtensions endpoint OLMAYAN statik varlık uzantılarıdır.
var jsAssetExtensions = []string{
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
	".woff", ".woff2", ".ttf", ".otf", ".eot",
	".mp4", ".webm", ".mp3", ".wav", ".pdf",
	".zip", ".gz", ".tar", ".rar", ".7z",
	".js", ".mjs", ".cjs", ".map", ".wasm",
}

// jsNoiseHosts üçüncü taraf CDN/analitik host'larıdır (endpoint değeri taşımaz).
var jsNoiseHosts = []string{
	"jquery.com", "googleapis.com", "gstatic.com", "cloudflare.com",
	"jsdelivr.net", "unpkg.com", "cdnjs.com", "bootstrapcdn.com",
	"fontawesome.com", "google-analytics.com", "googletagmanager.com",
	"doubleclick.net",
}

// IsNoiseJSHost CDN/analitik host kararıdır (veya boş host).
func IsNoiseJSHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return true
	}
	for _, n := range jsNoiseHosts {
		if h == n || strings.HasSuffix(h, "."+n) {
			return true
		}
	}
	return false
}

// jsSecretRule tek bir gömülü sır kuralıdır.
type jsSecretRule struct {
	name     string
	severity plugin.Severity
	re       *regexp.Regexp
	generic  bool // generic: anahtar adı + entropi eşiği ister
}

// jsSecretRules sırası deterministiktir; ilk eşleşen kural değeri yakalar.
var jsSecretRules = []jsSecretRule{
	{name: "aws-access-key", severity: plugin.SeverityHigh, re: regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)},
	{name: "github-token", severity: plugin.SeverityHigh, re: regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,255})\b`)},
	{name: "gitlab-token", severity: plugin.SeverityHigh, re: regexp.MustCompile(`\b(glpat-[A-Za-z0-9_\-]{20,255})\b`)},
	{name: "slack-token", severity: plugin.SeverityHigh, re: regexp.MustCompile(`\b(xox[abposr]-[A-Za-z0-9\-]{10,255})\b`)},
	{name: "google-api-key", severity: plugin.SeverityMedium, re: regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})\b`)},
	{name: "stripe-live-secret-key", severity: plugin.SeverityHigh, re: regexp.MustCompile(`\b(sk_live_[0-9a-zA-Z]{24,255})\b`)},
	{name: "sendgrid-api-key", severity: plugin.SeverityHigh, re: regexp.MustCompile(`\b(SG\.[A-Za-z0-9_\-]{16,64}\.[A-Za-z0-9_\-]{16,64})\b`)},
	{name: "twilio-api-key", severity: plugin.SeverityMedium, re: regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`)},
	{name: "private-key", severity: plugin.SeverityHigh, re: regexp.MustCompile(`(-----BEGIN [A-Z ]{0,32}PRIVATE KEY-----)`)},
	{name: "jwt", severity: plugin.SeverityMedium, re: regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,})\b`)},
	{name: "generic-secret", severity: plugin.SeverityMedium, re: reGenericSecret, generic: true},
}

// jsSecretPlaceholderMarkers bilinen örnek/yer tutucu parçalarıdır (FP freni).
var jsSecretPlaceholderMarkers = []string{
	"your_", "your-", "changeme", "change_me", "example", "dummy",
	"placeholder", "sample", "fake", "xxxx", "xxx", "abcd", "1234",
	"notreal", "redacted",
}

// AnalyzeJS bir JS gövdesini pasif analiz eder (istek ÜRETMEZ).
// What: sourceMappingURL + endpoint + sır adaylarını çıkarır; sır değerleri
// endpoint/map çıktılarından da temizlenir (tam değer sızıntısı YOK).
// Why: Tek deterministik analiz yolu; çağıran motor kapsam/bütçe kararını verir.
func AnalyzeJS(baseURL string, body []byte) JSReport {
	var rep JSReport
	if len(body) == 0 || len(body) > MaxJSAnalysisBytes {
		rep.Stats.Skipped = len(body) > MaxJSAnalysisBytes
		return rep
	}
	base, _ := url.Parse(strings.TrimSpace(baseURL))
	if base != nil && (base.Scheme == "" || base.Host == "") {
		base = nil
	}

	text := string(body)
	secrets, scrubs := scanSecrets(text, baseURL)
	rep.Secrets = secrets
	rep.SourceMaps = findSourceMaps(base, body)
	for i, m := range rep.SourceMaps {
		rep.SourceMaps[i] = scrubSecretValues(m, scrubs)
	}

	seen := map[string]bool{}
	for _, cand := range collectEndpointCandidates(text) {
		if len(rep.Endpoints) >= maxJSEndpointsPerFile {
			break
		}
		raw := strings.TrimSpace(cand.raw)
		if raw == "" || len(raw) > maxEndpointLiteralLen {
			continue
		}
		raw = reTemplateVar.ReplaceAllString(unescapeJSSlash(raw), "1")
		if jsEndpointNoise(raw) {
			continue
		}
		resolved, ok := resolveEndpoint(base, raw)
		if !ok {
			continue
		}
		resolved = scrubSecretValues(resolved, scrubs)
		raw = scrubSecretValues(raw, scrubs)
		method := strings.ToUpper(strings.TrimSpace(cand.method))
		if method == "" {
			method = "GET"
		}
		// URL düzeyinde tekilleştirme: daha spesifik çağrı kalıbı (fetch/axios/
		// XHR fiili) aynı URL'nin rota-literal adayını bastırır; rota literalini
		// yeniden saymayız (deterministik, tek giriş).
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		rep.Endpoints = append(rep.Endpoints, JSEndpoint{
			Raw:      raw,
			Resolved: resolved,
			Method:   method,
			Params:   jsQueryParams(resolved),
		})
	}
	rep.Stats.Endpoints = len(rep.Endpoints)
	rep.Stats.Secrets = len(rep.Secrets)
	rep.Stats.Maps = len(rep.SourceMaps)
	return rep
}

// AnalyzeSecrets yalnızca sır taramasıdır (kaynak haritası gövdeleri vb.).
// What: Aynı kural tablosu + maskeleme; endpoint çıkarımı YOK.
// Why: sourcesContent JSON'u JS parser'ına sokmadan aynı sır disiplinini korur.
func AnalyzeSecrets(body []byte, location string) []Secret {
	if len(body) == 0 || len(body) > MaxJSAnalysisBytes {
		return nil
	}
	secrets, _ := scanSecrets(string(body), location)
	return secrets
}

// scanSecrets kural tablosunu gövde üzerinde koşar.
// Dönüş: maskeli sırlar + (tam değer, maskeli) temizleme çiftleri.
func scanSecrets(text, location string) ([]Secret, [][2]string) {
	var out []Secret
	var scrubs [][2]string
	seen := map[string]bool{}

	add := func(value string, rule jsSecretRule, varName string, start, end int) {
		if jsSecretPlaceholder(value) {
			return
		}
		if rule.generic && shannonEntropy(value) < jsGenericEntropyMin {
			return
		}
		masked := jsMaskSecret(value)
		key := rule.name + "|" + masked
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Secret{
			Type:     rule.name,
			RuleName: rule.name,
			Masked:   masked,
			VarName:  varName,
			Severity: rule.severity,
			Context:  jsSecretContext(text, start, end, value, masked),
			Location: location,
		})
		scrubs = append(scrubs, [2]string{value, masked})
	}

	for _, rule := range jsSecretRules {
		for _, m := range rule.re.FindAllStringSubmatchIndex(text, -1) {
			if rule.generic {
				if len(m) < 6 {
					continue
				}
				name := text[m[2]:m[3]]
				value := text[m[4]:m[5]]
				add(value, rule, strings.ToLower(name), m[4], m[5])
				continue
			}
			if len(m) < 4 {
				continue
			}
			value := text[m[2]:m[3]]
			add(value, rule, "", m[2], m[3])
		}
	}
	return out, scrubs
}

// jsSecretPlaceholder yer tutucu/örnek değerleri eler (precision-first).
func jsSecretPlaceholder(v string) bool {
	if v == "" {
		return true
	}
	lower := strings.ToLower(v)
	if strings.Contains(lower, "${") {
		return true
	}
	for _, m := range jsSecretPlaceholderMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	if strings.HasPrefix(lower, "test") ||
		strings.HasPrefix(lower, "pk_live_") || strings.HasPrefix(lower, "pk_test_") {
		return true
	}
	// Tümü aynı karakter: deterministik dolgu/"aaaa..." değeri.
	same := true
	for i := 1; i < len(v); i++ {
		if v[i] != v[0] {
			same = false
			break
		}
	}
	return same
}

// jsMaskSecret first4…last4 maskesidir; kısa değerde tek "…".
func jsMaskSecret(v string) string {
	if len(v) <= 8 {
		return "…"
	}
	return v[:4] + "…" + v[len(v)-4:]
}

// jsSecretContext ±20 karakter bağlamdır; tam değer maskelenir.
func jsSecretContext(text string, start, end int, full, masked string) string {
	const pad = 20
	from := start - pad
	if from < 0 {
		from = 0
	}
	to := end + pad
	if to > len(text) {
		to = len(text)
	}
	snippet := text[from:to]
	snippet = strings.ReplaceAll(snippet, full, masked)
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	return strings.ReplaceAll(snippet, "\n", " ")
}

// scrubSecretValues tam sır değerlerini maskeli halleriyle değiştirir.
func scrubSecretValues(s string, scrubs [][2]string) string {
	for _, pair := range scrubs {
		s = strings.ReplaceAll(s, pair[0], pair[1])
	}
	return s
}

// shannonEntropy değerin karakter-entropisidir (generic kural eşiği).
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var e float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// endpointCandidate ham yakalanan URL + işaret edilen HTTP fiilidir.
type endpointCandidate struct {
	raw    string
	method string
}

// collectEndpointCandidates bilinen JS çağrı kalıplarını + rota-benzeri
// literalleri toplar (öncelik: çağrı kalıpları, sonra mutlak URL, sonra rota).
func collectEndpointCandidates(s string) []endpointCandidate {
	var out []endpointCandidate
	add := func(raw, method string) {
		out = append(out, endpointCandidate{raw: raw, method: method})
	}
	for _, m := range reFetchCall.FindAllStringSubmatch(s, -1) {
		add(m[1], "GET")
	}
	for _, m := range reAxiosVerb.FindAllStringSubmatch(s, -1) {
		add(m[2], strings.ToUpper(m[1]))
	}
	for _, m := range reURLProperty.FindAllStringSubmatch(s, -1) {
		if looksLikeEndpointLiteral(m[1]) {
			add(m[1], "GET")
		}
	}
	for _, m := range reJQueryCall.FindAllStringSubmatch(s, -1) {
		add(m[2], strings.ToUpper(m[1]))
	}
	for _, m := range reXHROpen.FindAllStringSubmatch(s, -1) {
		add(m[2], strings.ToUpper(m[1]))
	}
	for _, raw := range reAbsJSURL.FindAllString(s, -1) {
		add(trimJSPunctuation(raw), "GET")
	}
	for _, m := range reJSString.FindAllStringSubmatch(s, -1) {
		if looksLikeRoutePath(m[1]) {
			add(m[1], "GET")
		}
	}
	return out
}

// looksLikeEndpointLiteral URL alanı ("url:" konfig) için "/" veya şema şartıdır.
func looksLikeEndpointLiteral(raw string) bool {
	lit := strings.TrimSpace(raw)
	if lit == "" {
		return false
	}
	return strings.HasPrefix(lit, "/") || strings.HasPrefix(lit, "//") || strings.Contains(lit, "://")
}

// looksLikeRoutePath rota-benzeri string literal kararıdır.
// What: "/" ile başlar; >=2 segment VEYA bilinen API anahtar parçası içerir.
// Why: Rastgele string'leri endpoint saymamak precision frenidir.
func looksLikeRoutePath(raw string) bool {
	lit := strings.TrimSpace(raw)
	if !strings.HasPrefix(lit, "/") {
		return false
	}
	if strings.ContainsAny(lit, " \t\n") {
		return false
	}
	lower := strings.ToLower(lit)
	path := lower
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if path == "" || path == "/" {
		return false
	}
	if strings.HasPrefix(path, "//") {
		return true
	}
	segments := 0
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if seg != "" {
			segments++
		}
	}
	if segments >= 2 {
		return true
	}
	for _, kw := range jsRouteKeywords {
		if strings.Contains(path, kw) {
			return true
		}
	}
	return false
}

// jsEndpointNoise statik varlık/scheme gürültüsünü eler (endpoint kararı).
func jsEndpointNoise(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if lower == "" {
		return true
	}
	for _, pre := range []string{"data:", "javascript:", "mailto:", "tel:", "blob:", "about:"} {
		if strings.HasPrefix(lower, pre) {
			return true
		}
	}
	if strings.Contains(lower, "w3.org") || strings.Contains(lower, "schema.org") {
		return true
	}
	path := lower
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	for _, ext := range jsAssetExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// resolveEndpoint literal'i mutlak http(s) URL'e çevirir; CDN host'ları elenir.
func resolveEndpoint(base *url.URL, raw string) (string, bool) {
	ref, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	var resolved *url.URL
	switch {
	case ref.IsAbs():
		resolved = ref
	case base != nil:
		resolved = base.ResolveReference(ref)
	default:
		return "", false
	}
	scheme := strings.ToLower(resolved.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	if resolved.Host == "" {
		return "", false
	}
	if IsNoiseJSHost(resolved.Hostname()) {
		return "", false
	}
	out := resolved.String()
	if len(out) > maxEndpointLiteralLen {
		return "", false
	}
	return out, true
}

// jsQueryParams sorgu parametre adlarını sıralı + tekilleştirilmiş döner.
func jsQueryParams(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	q := u.Query()
	if len(q) == 0 {
		return nil
	}
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	uniq := names[:0]
	for i, n := range names {
		if i > 0 && names[i-1] == n {
			continue
		}
		uniq = append(uniq, n)
	}
	return uniq
}

// unescapeJSSlash JSON-tarzı "\/" kaçışını "/" yapar.
func unescapeJSSlash(s string) string {
	return strings.ReplaceAll(s, `\/`, `/`)
}

// trimJSPunctuation mutlak URL sonundaki cümle noktalama işaretlerini keser.
func trimJSPunctuation(s string) string {
	return strings.TrimRight(s, ".,;:)]}")
}

// findSourceMaps sourceMappingURL yorumlarını mutlak URL'lere çevirir.
func findSourceMaps(base *url.URL, body []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range reSourceMap.FindAllSubmatch(body, -1) {
		raw := strings.TrimSpace(string(m[1]))
		if raw == "" || len(raw) > maxEndpointLiteralLen {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		var abs *url.URL
		switch {
		case u.IsAbs():
			abs = u
		case base != nil:
			abs = base.ResolveReference(u)
		default:
			continue
		}
		scheme := strings.ToLower(abs.Scheme)
		if (scheme != "http" && scheme != "https") || abs.Host == "" {
			continue
		}
		s := abs.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= jsMaxSourceMapsPerFile {
			break
		}
	}
	return out
}

// isJSScriptType inline/harici script gövdesinin JS sayılıp sayılmayacağıdır.
// JSON/template blokları (__NEXT_DATA__ vb.) pasif JS recon kapsamı DIŞIDIR.
func isJSScriptType(t string) bool {
	if t == "" {
		return true
	}
	for _, ok := range []string{"javascript", "ecmascript", "module"} {
		if strings.Contains(t, ok) {
			return true
		}
	}
	return false
}
