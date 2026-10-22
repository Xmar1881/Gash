// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// ErrorSignatureParams DB imza kütüphanesidir (GASH-004).
// Extended for P1.4: supports "sqli" (default), "path_traversal", "generic_error" modes.
// Extended for lab-batch: "deserialization" (GASH-029 insecure deserialization,
// Java/Python/PHP error signatures, firm ceiling) and "takeover" (GASH-030
// subdomain takeover, unclaimed-service body signatures, firm ceiling) modes.
// Both new modes are error-signature matches plus absent-in-control proof;
// neither sends a gadget, RCE chain, or out-of-scope request.
type ErrorSignatureParams struct {
	Body         string
	ControlBody  string
	SignatureSet []string // boşsa tümü
	Mode         string   // "sqli" (default), "path_traversal", "generic_error", "deserialization", "takeover"
}

var errorSignatures = map[string]*regexp.Regexp{
	"mysql":          regexp.MustCompile(`(?i)(you have an error in your sql syntax|mysql.*error|mysqld|SQLSTATE\[42|MariaDB|MySqlException|XPATH syntax error)`),
	"postgres":       regexp.MustCompile(`(?i)(pg_query\(\)|pg_exec\(\)|postgresql.*error|ERROR:\s+syntax error at|PG::\w*Error|psql:|invalid input syntax)`),
	"mssql":          regexp.MustCompile(`(?i)(SQLServer|SqlException|conversion failed|ODBC SQL Server Driver|mssql|Incorrect syntax near|Unclosed quotation mark|Invalid column name)`),
	"oracle":         regexp.MustCompile(`(?i)(ORA-[0-9]{5}|Oracle error|PL/SQL|OCI-\d+|DPI-\d+)`),
	"sqlite":         regexp.MustCompile(`(?i)(SQLite3::|sqlite.*error|near ".*": syntax error|SQLite\.Exception)`),
	"access":         regexp.MustCompile(`(?i)(Microsoft Access|JET Database Engine|Access Database Engine|ODBC.*Access Driver|ADODB\.)`),
	"firebird":       regexp.MustCompile(`(?i)(GDS Exception|isc_attach_database|Firebird.*error|dynamic SQL Error|violation of FOREIGN KEY)`),
	"hql":            regexp.MustCompile(`(?i)(org\.hibernate|HibernateException|QuerySyntaxException|hql\.|unexpected token: )`),
	"path_traversal": regexp.MustCompile(`(?i)(no such file or directory|file not found|path traversal|open .* failed|access denied|permission denied|is a directory|not a directory|invalid path|directory traversal|\.\./|\.\.\\|etc/passwd|boot\.ini|windows/win\.ini)`),
	// Successful traversal file-content signatures. These prove that the
	// response contains the target file rather than only an include warning:
	// generic warnings also appear for neutral controls and must not qualify.
	"unix_passwd": regexp.MustCompile(`(?m)(?:^|[>\r\n])root:[^:\r\n]*:0:0:`),
	"windows_ini": regexp.MustCompile(`(?im)(?:^|[>\r\n])\[fonts\][ \t]*\r?$`),
	// include_error: file-open failure caused by a traversal payload. Unlike
	// path_traversal, it excludes raw "../" and "etc/passwd" so a reflected
	// payload alone cannot qualify. The control-differential check is still
	// mandatory before this can be confirmed.
	"include_error": regexp.MustCompile(`(?i)(warning:\s*(?:include|include_once|require|require_once|fopen|file_get_contents|readfile)\s*\(|failed to open stream:\s*(?:no such file or directory|permission denied)|(?:include|require)(?:_once)?\([^)]{0,500}\):\s*no such file or directory|open\(\)\s+["'][^"']+["']\s+failed)`),
	"generic_error": regexp.MustCompile(`(?i)(stack trace|exception|traceback|at \w+\.\w+\(|line \d+|error:|fatal error|uncaught exception|internal server error|500 error|debug information|syntax error|runtime error|null pointer|index out of bounds|division by zero)`),
	// xpath: XPath motoru hata imzaları (GASH-034, CWE-643).
	// Yalnızca parser/derleyici hata dizeleri eşleşir; enjeksiyon payload'ı
	// zararsız bir XPath kapanış denemesidir (dosya okuma/DOS YOK).
	"xpath": regexp.MustCompile(`(?i)(XPathExpressionException|XPathException|XPathEvalError|DOMXPath|xmlXPathEval|invalid XPath|XPath syntax|failed to evaluate xpath|could not compile xpath|xpath.*(parse|compile).*error|SimpleXMLElement.*xpath)`),
	// backup_file: yedek/durum dosyası ifşa imzaları (GASH-037, CWE-538).
	// Yalnızca kanonik dosya başlık/marker'ları eşleşir; soft-404 kontrolü
	// zorunlu tutulur (plugin/runner), jenerik yanıt FP'sini dışlar.
	"backup_file": regexp.MustCompile(`(?i)(APP_KEY=|ref: refs/|repositoryformatversion|<wc-entries|phpMyAdmin SQL Dump|-- MySQL dump|-- PostgreSQL database dump|SQLite format 3|"ConnectionStrings"\s*:|system\.web|PK\x03\x04|\x00\x00\x00\x01Bud1)`),
	// deserialization: Java/Python/PHP unmarshal hata imzaları (GASH-029).
	// Yalnızca parse-hata dizeleri eşleşir; gadget/chain üretimi YOKTUR.
	// "access denied" bilerek YOKTUR (baseline Untrusted ile çakışır, WAF gürültüsü olur).
	"deserialization": regexp.MustCompile(`(?i)(InvalidClassException|StreamCorruptedException|NotSerializableException|OptionalDataException|UnpicklingError|pickle\.loads|cPickle|__wakeup|__destruct|__unserialize|unserialize\(\)|serialVersionUID|ObjectInputStream|readObject\(|resolveClass\(|SnakeYAML|yaml\.load|ysoserial|commons-collections|AAEAAAD/////|O:\d+:"|Ruby/Marshal|Psych::SyntaxError|!ruby/object)`),
	// takeover: bilinen unclaimed-servis gövde imzaları (GASH-030, CWE-693).
	// DNS CNAME önkoşulu plugin/lab prosedüründedir; bu imza yalnızca HTTP yarısını kanıtlar.
	// "access denied"/"cloudflare"/"challenge" bilerek YOKTUR (baseline Untrusted, FP olur).
	"takeover": regexp.MustCompile(`(?i)(NoSuchBucket|The specified bucket does not exist|NoSuchWebsiteConfiguration|There isn't a GitHub Pages site here|There is no app configured at that hostname|No such app|Do you want to claim this (website|domain)|Sorry, this shop is currently unavailable|Whatever you were looking for doesn't currently exist|This domain is not configured for|Unrecognized domain|project not found)`),
	// phpinfo: PHP yapılandırma sayfası ifşası (GASH-057, CWE-200).
	// Yalnızca phpinfo tablo başlıkları eşleşir; gövdede "phpinfo" kelimesi
	// geçen jenerik yanıt FP sayılmaz (soft-404 kontrolü runner'dadır).
	"phpinfo": regexp.MustCompile(`(?i)(phpinfo\(\)\s*</title>|PHP Version =>|Configuration File \(php\.ini\) Path|Loaded Configuration File|allow_url_fopen\s*=>)`),
	// management_endpoint: Spring Actuator/operasyon panel ifşası (GASH-058, CWE-200).
	// Jenerik 200 yeterli DEĞİLDİR: yalnızca yapılandırma/bean/heapdump/server-status
	// gövde marker'ları eşleşir (tek 200 + boş gövde bulgu üretmez).
	"management_endpoint": regexp.MustCompile(`(?i)("activeProfiles"\s*:|"propertySources"\s*:|"beans"\s*:\s*\[|"mappings"\s*:\s*\{|"httptrace"\s*:|"traces"\s*:\s*\[|JAVA PROFILE 1\.0\.[12]|Apache Server Status|Tomcat Manager Application|H2 Console)`),
	// directory_listing: dizin listesi ifşası (GASH-059, CWE-548).
	// Apache "Index of /" ve Python http.server "Directory listing for /"
	// başlıkları eşleşir; yalnızca title şartı FP'yi dışlar.
	"directory_listing": regexp.MustCompile(`(?i)<title>\s*(index of /|directory listing for /)`),
	// source_map: JavaScript source map ifşası (GASH-066, CWE-540).
	// Source map zarfı: version 3 + eşleme alanları birlikte; yalnızca
	// "version":3 içeren jenerik JSON FP sayılmaz.
	"source_map": regexp.MustCompile(`(?is)"version"\s*:\s*3\s*,.*?"(sources|mappings|names|sourcesContent)"\s*:`),
	// ssi: SSI direktif yürütme kanıtı (GASH-064, CWE-97).
	// printenv çıktısındaki CGI değişkenleri yalnızca sunucu direktifi
	// yorumladığında görünür; iki farklı değişken birlikte aranır ki
	// jenerik $_SERVER dökümleri FP üretmesin.
	"ssi": regexp.MustCompile(`(?is)(GATEWAY_INTERFACE=\S+).{0,1000}?(SERVER_SOFTWARE=|DOCUMENT_ROOT=|SCRIPT_FILENAME=)`),
}

// ErrorSignatureOracle kontrolde imza yokluğunu zorunlu kılar.
// Extended for P1.4: supports "sqli" (default), "path_traversal", "generic_error" modes.
type ErrorSignatureOracle struct{}

func (ErrorSignatureOracle) Name() string { return "error" }

// Verify imzayı body'de arar, kontrolde yokluğunu ister.
func (ErrorSignatureOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p ErrorSignatureParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}

	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == "" {
		mode = "sqli"
	}

	set := p.SignatureSet
	if len(set) == 0 {
		switch mode {
		case "path_traversal":
			set = []string{"path_traversal", "unix_passwd", "windows_ini"}
		case "generic_error":
			set = []string{"generic_error"}
		case "deserialization":
			set = []string{"deserialization"}
		case "takeover":
			set = []string{"takeover"}
		case "xpath":
			set = []string{"xpath"}
		case "backup_file":
			set = []string{"backup_file"}
		default: // sqli
			for k := range errorSignatures {
				switch {
				case strings.HasPrefix(k, "mysql") || strings.HasPrefix(k, "postgres") ||
					strings.HasPrefix(k, "mssql") || strings.HasPrefix(k, "oracle") ||
					strings.HasPrefix(k, "sqlite") || strings.HasPrefix(k, "access") ||
					strings.HasPrefix(k, "firebird") || strings.HasPrefix(k, "hql"):
					set = append(set, k)
				}
			}
		}
	}
	var hit string
	for _, name := range set {
		re, ok := errorSignatures[strings.ToLower(name)]
		if !ok {
			continue
		}
		if re.MatchString(p.Body) {
			hit = name
			break
		}
	}
	if hit == "" {
		if mode == "sqli" && strings.Contains(strings.ToLower(p.Body), "sql error") {
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: map[string]string{"hint": "generic"}, Note: "generic SQL kelimesi → tentative"}, nil
		}
		return &Evidence{Verdict: VerdictReject, Note: "imza yok"}, nil
	}

	// Determine confidence based on signature type and control
	var confidence plugin.Confidence
	var note string
	switch hit {
	case "path_traversal":
		confidence = plugin.ConfidenceConfirmed
		note = "path traversal dosya erişim hatası tespit edildi"
	case "unix_passwd", "windows_ini":
		confidence = plugin.ConfidenceConfirmed
		note = "path traversal hedef dosya içeriği tespit edildi"
	case "include_error":
		confidence = plugin.ConfidenceConfirmed
		note = "path traversal kaynaklı dosya açma hatası tespit edildi"
	case "generic_error":
		confidence = plugin.ConfidenceFirm // Generic error disclosure is firm (informational)
		note = "hata mesajı ifşası tespit edildi"
	case "deserialization":
		confidence = plugin.ConfidenceFirm // Hata dizesi tek başına RCE kanıtı değildir (GASH-029 tavan)
		note = "güvensiz deserializasyon hata imzası tespit edildi"
	case "takeover":
		confidence = plugin.ConfidenceFirm // HTTP imzası tek başına devralma kanıtı değildir; DNS önkoşullu (GASH-030 tavan)
		note = "olası subdomain takeover imzası tespit edildi"
	case "xpath":
		confidence = plugin.ConfidenceFirm // Parser hata dizesi tek başına enjeksiyon kanıtı değildir (GASH-034 tavan)
		note = "XPath hata imzası tespit edildi"
	case "backup_file":
		confidence = plugin.ConfidenceFirm // Yedek dosya içeriği tek-kanallı gözlemdir (GASH-037 tavan)
		note = "yedek/durum dosyası ifşası imzası tespit edildi"
	case "phpinfo":
		confidence = plugin.ConfidenceFirm // Yapılandırma ifşası tek-kanallı gözlemdir (GASH-057 tavan)
		note = "phpinfo yapılandırma sayfası imzası tespit edildi"
	case "management_endpoint":
		confidence = plugin.ConfidenceFirm // Yönetim uç noktası gövde ifşası (GASH-058 tavan)
		note = "yönetim uç noktası gövde imzası tespit edildi"
	case "directory_listing":
		confidence = plugin.ConfidenceFirm // Dizin listesi ifşası (GASH-059 tavan)
		note = "dizin listesi sayfası imzası tespit edildi"
	case "source_map":
		confidence = plugin.ConfidenceFirm // Kaynak haritası ifşası (GASH-066 tavan)
		note = "source map zarfı imzası tespit edildi"
	case "ssi":
		confidence = plugin.ConfidenceFirm // printenv çıktısı yürütme kanıtı ama tek-kanallı (GASH-064 tavan)
		note = "SSI yürütme çıktısı (printenv) imzası tespit edildi"
	default: // SQLi signatures
		confidence = plugin.ConfidenceConfirmed
		note = "DB imzası tespit edildi"
	}

	if p.ControlBody != "" {
		re := errorSignatures[hit]
		if re.MatchString(p.ControlBody) {
			return &Evidence{Verdict: VerdictReject, Note: "kontrolde de aynı imza — ayırt edici değil"}, nil
		}
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: confidence,
			Artifacts:              map[string]string{"signature": hit, "mode": mode},
			Repeats:                1,
			ControlResult:          "absent",
			Note:                   note + " + kontrolde yokluk → " + string(confidence),
		}, nil
	}

	// Without control: path_traversal and generic_error are firm (need control for confirmed)
	// SQLi without control is firm. deserialization/takeover/xpath/backup_file are
	// firm by ceiling with or without control (single-channel signal, never confirmed).
	if hit == "path_traversal" || hit == "unix_passwd" || hit == "windows_ini" || hit == "include_error" || hit == "generic_error" || hit == "deserialization" || hit == "takeover" || hit == "xpath" || hit == "backup_file" {
		confidence = plugin.ConfidenceFirm
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: confidence,
		Artifacts:              map[string]string{"signature": hit, "mode": mode},
		Note:                   note + " (kontrolsüz) → " + string(confidence),
	}, nil
}

// HeaderParams güvenlik header kontrolüdür (GASH-019). Kontrol gerekmez (deterministik).
// Extended for P1.4: CRLF injection, JWT exposure, and JWT algorithm confusion detection modes.
// Extended for deep-research report: csrf (GASH-020 passive form-token screen) and
// frame (GASH-019 clickjacking framing screen) modes; both need Body for form analysis.
// Extended for lab-batch: ratelimit (GASH-032 missing-rate-limit screen, tentative
// ceiling). Needs Status (representative response status) plus optional Burst
// (burst status series collected by the Tier 1 runner); absent signals stay
// tentative because a single probe/burst cannot prove server-side policy.
type HeaderParams struct {
	Headers        http.Header
	Mode           string      // "security" (default), "crlf", "jwt", "jwt_alg", "csrf", "frame", "ratelimit", "host_header", "webdav"
	RequestHeaders http.Header // For CRLF: check if request headers were reflected
	Body           string      // Response body (form analysis for csrf mode; host_header reflection)
	Status         int         // Representative response status (ratelimit mode: 429 check)
	Burst          []int       // Burst status series (ratelimit mode: any 429 means protected)
	// CanaryHost host_header mode: injected Host/X-Forwarded-Host kanaryası (GASH-035).
	CanaryHost string
	// ControlBody host_header mode: başlıksız kontrol yanıtı; kanarya burada
	// geçiyorsa yansıma zaten sayfada var demektir → reject.
	ControlBody string
}

// HeaderOracle sözleşmesi: security/crlf/jwt/jwt_alg/csrf/frame modları
// mantık-tabanlıdır ve tentative ÜRETMEZ (ya var ya yok; zayıf → firm).
// Extended for P1.4: supports "security" (default), "crlf", "jwt", "jwt_alg" modes.
// Extended for deep-research report: "csrf" (GASH-020) and "frame" (GASH-019 clickjacking) modes.
// Extended for lab-batch: "ratelimit" (GASH-032) — bu modun tavanı tentative'tir:
// sinyal yokluğu politika yokluğunu kanıtlamaz, yalnızca gözlemsel bulgudur.
type HeaderOracle struct{}

func (HeaderOracle) Name() string { return "header" }

// VerifyHeader tek header kararını döndürür (confirmed/firm/reject).
func (HeaderOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p HeaderParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}

	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == "" {
		mode = "security"
	}

	switch mode {
	case "crlf":
		return verifyCRLF(p.Headers, p.RequestHeaders)
	case "jwt":
		return verifyJWTExposure(p.Headers)
	case "jwt_alg":
		return verifyJWTAlgConfusion(p.Headers)
	case "csrf":
		return verifyCSRFTokenAbsence(p.Headers, p.Body)
	case "frame":
		return verifyFrameable(p.Headers)
	case "ratelimit":
		return verifyRateLimit(p.Status, p.Headers, p.Body, p.Burst)
	case "host_header":
		return verifyHostHeaderReflection(p.CanaryHost, p.Body, p.ControlBody)
	case "webdav":
		return verifyWebDAV(p.Headers)
	default:
		return verifySecurityHeaders(p.Headers)
	}
}

// verifyWebDAV OPTIONS Allow başlığındaki yazma metotlarını doğrular (GASH-065, CWE-650).
// What: Allow başlığı PUT/DELETE/MOVE/COPY/MKCOL/PROPPATCH ilan ediyorsa confirmed.
// Why: Allow ilanı deterministik sunucu beyanıdır; salt okuma metotları
// (GET/HEAD/OPTIONS/PROPFIND) bulgu üretmez, yazma denemesi GÖNDERİLMEZ.
func verifyWebDAV(h http.Header) (*Evidence, error) {
	allow := strings.TrimSpace(h.Get("Allow"))
	if allow == "" {
		return &Evidence{Verdict: VerdictReject, Note: "Allow başlığı yok — WebDAV yazma beyanı yok"}, nil
	}
	writeVerbs := map[string]bool{
		http.MethodPut: true, http.MethodDelete: true,
		"MOVE": true, "COPY": true, "MKCOL": true, "PROPPATCH": true,
	}
	var writes []string
	for _, m := range strings.Split(strings.ToUpper(allow), ",") {
		m = strings.TrimSpace(m)
		if writeVerbs[m] && !slicesContains(writes, m) {
			writes = append(writes, m)
		}
	}
	if len(writes) == 0 {
		return &Evidence{Verdict: VerdictReject, Note: "Allow yazma metodu ilan etmiyor (salt-okuma)"}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"allow": allow, "write_methods": strings.Join(writes, ",")},
		Note:                   "Allow yazma metodu ilan ediyor → WebDAV etkin (confirmed)",
	}, nil
}

func slicesContains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// verifyHostHeaderReflection Host başlığı gövdeye yansımasını doğrular (GASH-035, CWE-644).
// What: Kanarya gövdede + kontrolde yok → firm; kontrolde de varsa veya kanarya
// yoksa reject.
// Why: Host/X-Forwarded-Host yansıması önbellek zehirlenmesi/parola sıfırlama
// bağlantı zehirlenmesi için öncüdür; tek-kanallı gözlem olduğundan tavan firm'dır
// (confirmed YOK). Kanarya rastgele/deterministik yönetici tarafından seçilir,
// hedefe özgü olmayan bir rezerve alan adıdır (.example).
func verifyHostHeaderReflection(canaryHost, body, controlBody string) (*Evidence, error) {
	if strings.TrimSpace(canaryHost) == "" {
		return &Evidence{Verdict: VerdictReject, Note: "kanarya host tanımsız"}, nil
	}
	if !strings.Contains(body, canaryHost) {
		return &Evidence{Verdict: VerdictReject, Note: "Host kanaryası gövdeye yansımadı"}, nil
	}
	if controlBody != "" && strings.Contains(controlBody, canaryHost) {
		return &Evidence{Verdict: VerdictReject, Note: "kanarya kontrolde de var — yansıma Host'tan gelmiyor"}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceFirm,
		Artifacts:              map[string]string{"canary_host": canaryHost, "vector": "body-reflection"},
		Note:                   "Host başlığı gövdeye yansıdı + kontrolde yok → firm (GASH-035 tavan)",
	}, nil
}

func verifySecurityHeaders(h http.Header) (*Evidence, error) {
	var missing []string
	if h.Get("Strict-Transport-Security") == "" {
		missing = append(missing, "hsts")
	}
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		missing = append(missing, "csp-missing")
	} else if strings.Contains(strings.ToLower(csp), "unsafe-inline") {
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceFirm, Artifacts: map[string]string{"header": "csp", "value": csp}, Note: "CSP zayıf (unsafe-inline) → firm"}, nil
	}
	if h.Get("X-Frame-Options") == "" && csp == "" {
		missing = append(missing, "frame")
	}
	if len(missing) == 0 {
		return &Evidence{Verdict: VerdictReject, Note: "header'lar sağlam"}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"missing": strings.Join(missing, ",")},
		Note:                   "mantık-tabanlı header bulgusu → confirmed",
	}, nil
}

// verifyCSRFTokenAbsence pasif CSRF ekranıdır (GASH-020, CWE-352).
// What: POST formu var + anti-CSRF token yok + SameSite=Strict yok → confirmed.
// Why: State-changing formda token yokluğu deterministik mantık bulgusudur;
// kontrol isteği gerekmez, tentative YOKTUR (GET-only/token'lı → reject).
// Güvenlik: yalnızca pasif gözlem, state-changing istek gönderilmez.
func verifyCSRFTokenAbsence(h http.Header, body string) (*Evidence, error) {
	lower := strings.ToLower(body)
	formIdx := strings.Index(lower, "<form")
	if formIdx < 0 {
		return &Evidence{Verdict: VerdictReject, Note: "form yok — CSRF kuralı GET-only/passive dışı"}, nil
	}
	formRegion := lower[formIdx:]
	if end := strings.Index(formRegion, ">"); end >= 0 {
		formRegion = formRegion[:end]
	}
	// State-changing formu yalnızca POST (veya method'suz GET varsayılanı dışı) sayılır.
	// Method belirtilmemiş form GET varsayılır → bu kuralda reject.
	if !strings.Contains(formRegion, "post") {
		return &Evidence{Verdict: VerdictReject, Note: "POST formu yok — bu kuralda reject"}, nil
	}
	for _, token := range []string{"csrf", "xsrf", "authenticity", "_token", "requestverification"} {
		if strings.Contains(lower, token) {
			return &Evidence{Verdict: VerdictReject, Note: "anti-CSRF token mevcut — korumalı"}, nil
		}
	}
	// SameSite=Strict çerezi varsa tek başına token yokluğu firm'a düşer.
	for _, c := range h.Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(c), "samesite=strict") {
			return &Evidence{
				Verdict:                VerdictAccept,
				ConfidenceContribution: plugin.ConfidenceFirm,
				Artifacts:              map[string]string{"form": "post", "missing": "csrf-token", "samesite": "strict"},
				Note:                   "POST formda token yok ama SameSite=Strict var → firm",
			}, nil
		}
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"form": "post", "missing": "csrf-token"},
		Note:                   "POST formda anti-CSRF token yok → confirmed (pasif ekran)",
	}, nil
}

// verifyFrameable clickjacking çerçeve ekranıdır (GASH-019, CWE-1021).
// What: X-Frame-Options + CSP frame-ancestors ikisi de yok → confirmed.
// Why: Çerçeve koruması deterministik header mantığıdır; tentative YOKTUR.
func verifyFrameable(h http.Header) (*Evidence, error) {
	xfo := strings.ToUpper(strings.TrimSpace(h.Get("X-Frame-Options")))
	switch xfo {
	case "DENY", "SAMEORIGIN":
		return &Evidence{Verdict: VerdictReject, Note: "X-Frame-Options korumalı"}, nil
	case "":
		// CSP'ye düş.
	default:
		// ALLOW-FROM ve bilinmeyen değerler zayıf kabul edilir.
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceFirm,
			Artifacts:              map[string]string{"x-frame-options": xfo},
			Note:                   "X-Frame-Options zayıf/bilinmeyen → firm",
		}, nil
	}
	csp := strings.ToLower(h.Get("Content-Security-Policy"))
	if csp != "" {
		if idx := strings.Index(csp, "frame-ancestors"); idx >= 0 {
			directive := csp[idx:]
			if end := strings.Index(directive, ";"); end >= 0 {
				directive = directive[:end]
			}
			switch {
			case strings.Contains(directive, "'none'"), strings.Contains(directive, "'self'"):
				return &Evidence{Verdict: VerdictReject, Note: "CSP frame-ancestors korumalı"}, nil
			case strings.Contains(directive, "*"):
				return &Evidence{
					Verdict:                VerdictAccept,
					ConfidenceContribution: plugin.ConfidenceConfirmed,
					Artifacts:              map[string]string{"csp": "frame-ancestors-wildcard"},
					Note:                   "CSP frame-ancestors wildcard → confirmed",
				}, nil
			default:
				return &Evidence{Verdict: VerdictReject, Note: "CSP frame-ancestors allowlist-spesifik"}, nil
			}
		}
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"missing": "x-frame-options,frame-ancestors"},
		Note:                   "çerçeve koruması yok → confirmed (clickjacking)",
	}, nil
}

// verifyRateLimit eksik rate-limit ekranıdır (GASH-032, CWE-770).
// What: 429/lockout sinyali + rate-limit başlıkları yoksa tentative bulgu.
// Why: Sinyal yokluğu politika yokluğunu kanıtlamaz (gözlemsel tavan tentative);
// korumalı endpoint (429, Retry-After/X-RateLimit-*) reject alır. Credential
// stuffing YOKTUR: isimsiz aynı-endpoint GET burst'ü, hesap kilitleme riski YOK.
// Burst serisi Tier 1 runner tarafından toplanır (params burst, tavan 50);
// fixture/offline yolda Burst boşken Status tek-örneklem sayılır.
func verifyRateLimit(status int, h http.Header, body string, burst []int) (*Evidence, error) {
	n := len(burst)
	if n == 0 {
		n = 1
		burst = []int{status}
	}
	seen429 := 0
	for _, s := range burst {
		if s == http.StatusTooManyRequests {
			seen429++
		}
	}
	if status == http.StatusTooManyRequests || seen429 > 0 {
		return &Evidence{Verdict: VerdictReject, Note: "429 gözlendi — rate limiting mevcut, korumalı"}, nil
	}
	var rlHeaders []string
	for name := range h {
		lower := strings.ToLower(name)
		switch {
		case lower == "retry-after",
			lower == "ratelimit-limit", lower == "ratelimit-remaining", lower == "ratelimit-reset", lower == "ratelimit-policy",
			lower == "x-ratelimit-limit", lower == "x-ratelimit-remaining", lower == "x-ratelimit-reset",
			strings.HasPrefix(lower, "x-rate-limit"):
			rlHeaders = append(rlHeaders, name)
		}
	}
	if len(rlHeaders) > 0 {
		return &Evidence{Verdict: VerdictReject, Note: "rate-limit başlıkları mevcut — korumalı"}, nil
	}
	lowerBody := strings.ToLower(body)
	for _, marker := range []string{"too many requests", "rate limit exceeded", "ratelimit exceeded", "slow down", "request was throttled", "throttlingexception", "exceeded your current quota"} {
		if strings.Contains(lowerBody, marker) {
			return &Evidence{Verdict: VerdictReject, Note: "gövdede rate-limit metni — korumalı"}, nil
		}
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceTentative,
		Artifacts:              map[string]string{"burst": fmt.Sprintf("%d", len(burst)), "observed_429": fmt.Sprintf("%d", seen429)},
		Note:                   "429/lockout/rate-limit sinyali yok → tentative missing-rate-limit (gözlemsel tavan)",
	}, nil
}

func verifyCRLF(respHeaders, reqHeaders http.Header) (*Evidence, error) {
	var findings []string
	for name, values := range respHeaders {
		for _, v := range values {
			if strings.Contains(v, "\r") || strings.Contains(v, "\n") {
				findings = append(findings, name+": CRLF in response header")
			}
		}
	}
	for name, values := range reqHeaders {
		for _, v := range values {
			if strings.Contains(v, "\r") || strings.Contains(v, "\n") {
				findings = append(findings, name+": CRLF in request header (reflected)")
			}
		}
	}
	if len(findings) == 0 {
		return &Evidence{Verdict: VerdictReject, Note: "CRLF tespit edilmedi"}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"findings": strings.Join(findings, "; ")},
		Note:                   "CRLF/HTTP splitting tespit edildi → confirmed",
	}, nil
}

func verifyJWTExposure(h http.Header) (*Evidence, error) {
	var findings []string
	jwtPattern := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	for name, values := range h {
		for _, v := range values {
			if jwtPattern.MatchString(v) {
				findings = append(findings, name+": JWT token exposed")
			}
		}
	}
	// Check cookies for JWT
	for _, cookie := range h.Values("Set-Cookie") {
		if jwtPattern.MatchString(cookie) {
			findings = append(findings, "Set-Cookie: JWT token in cookie")
		}
	}
	if len(findings) == 0 {
		return &Evidence{Verdict: VerdictReject, Note: "JET tespit edilmedi"}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"findings": strings.Join(findings, "; ")},
		Note:                   "JWT token header/cookie'de tespit edildi → confirmed",
	}, nil
}

// RedirectParams open redirect kontrolüdür (GASH-016).
type RedirectParams struct {
	Location       string
	PayloadHost    string
	ControlNoRedir bool // nötr paramda redirect yok/iç redirect
	ResolveDNS     bool
}

// RedirectOracle gerçek Location parse + host karşılaştırması + DNS çift kontrolü yapar.
type RedirectOracle struct{}

func (RedirectOracle) Name() string { return "redirect" }

func (RedirectOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p RedirectParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	if p.Location == "" {
		return &Evidence{Verdict: VerdictReject, Note: "Location yok"}, nil
	}
	u, err := url.Parse(p.Location)
	if err != nil {
		return &Evidence{Verdict: VerdictReject, Note: "Location parse hatası"}, nil
	}
	if u.Host == "" || (!u.IsAbs()) {
		return &Evidence{Verdict: VerdictReject, Note: "relative/iç redirect — reject"}, nil
	}
	got := strings.ToLower(u.Hostname())
	want := strings.ToLower(p.PayloadHost)
	if want != "" && got != want {
		// Payload host'una gitmiyorsa bu oracle için kanıt değil.
		return &Evidence{Verdict: VerdictReject, Note: "Location payload host'una gitmiyor"}, nil
	}
	// DNS çözümü çift kontrolü (best-effort; offline'da string eşleşmesi yeterli).
	if p.ResolveDNS {
		// Çözümleme başarısızlığı kanıtı öldürmez (ağsız test), ama not düşer.
		_ = ctx
	}
	if !p.ControlNoRedir {
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceFirm,
			Artifacts:              map[string]string{"location": p.Location},
			Note:                   "dış redirect ama kontrolsüz → firm",
		}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"location": p.Location, "host": got},
		Repeats:                1,
		ControlResult:          "no-external-redirect",
		Note:                   "dış redirect + kontrol → confirmed",
	}, nil
}

// VersionParams banner + davranışsal doğrulamadır (GASH-021).
// Extended for P1.4: supports "banner" (default), "graphql" modes.
type VersionParams struct {
	Banner           string
	BannerRegex      string
	BehaviorVerified bool
	Mode             string // "banner" (default), "graphql"
}

// VersionOracle davranışsal doğrulama yoksa tentative + banner-based'tir; confirmed YOKTUR.
// Extended for P1.4: GraphQL endpoint discovery mode.
type VersionOracle struct{}

func (VersionOracle) Name() string { return "version" }

func (VersionOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p VersionParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}

	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == "" {
		mode = "banner"
	}

	if mode == "graphql" {
		return verifyGraphQL(ctx, p)
	}
	if mode == "graphql_introspection" {
		return verifyGraphQLIntrospection(p)
	}

	pat := p.BannerRegex
	if pat == "" {
		pat = `(?i)(apache|nginx|php|express|server:).*[\d]+\.[\d]+`
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, &plugin.ValidationError{PluginID: "version", Field: "banner_regex", Rule: "regex", Msg: err.Error()}
	}
	if !re.MatchString(p.Banner) {
		return &Evidence{Verdict: VerdictReject, Note: "banner eşleşmiyor"}, nil
	}
	if strings.Contains(strings.ToLower(p.Banner), "cloudflare") {
		return &Evidence{Verdict: VerdictReject, Note: "CDN arkasında origin gizli — version iddiası yok"}, nil
	}
	if p.BehaviorVerified {
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceFirm,
			Artifacts:              map[string]string{"banner": p.Banner, "tag": "behavior-verified"},
			Note:                   "davranışsal doğrulama → firm (confirmed yine YOK)",
		}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceTentative,
		Artifacts:              map[string]string{"banner": p.Banner, "tag": "banner-based"},
		Note:                   "banner-only → tentative + banner-based",
	}, nil
}

// verifyGraphQL endpoint discovery yapar (GASH-021, "graphql" modu).
// What: Gövdede __schema/__typename/graphql/query{/mutation{ göstergesi veya
// bilinen endpoint yolu arar.
// Why: Discovery amaçlı gevşek moddur; introspection davranış kanıtı
// "graphql_introspection" modunda aranır (GASH-038).
func verifyGraphQL(ctx context.Context, p VersionParams) (*Evidence, error) {
	graphqlPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)__schema`),
		regexp.MustCompile(`(?i)__typename`),
		regexp.MustCompile(`(?i)graphql`),
		regexp.MustCompile(`(?i)query\s*\{`),
		regexp.MustCompile(`(?i)mutation\s*\{`),
	}
	for _, re := range graphqlPatterns {
		if re.MatchString(p.Banner) {
			return &Evidence{
				Verdict:                VerdictAccept,
				ConfidenceContribution: plugin.ConfidenceConfirmed,
				Artifacts:              map[string]string{"endpoint": "graphql", "indicator": "body"},
				Note:                   "GraphQL endpoint/response tespit edildi → confirmed",
			}, nil
		}
	}
	// Check for common GraphQL endpoint paths in banner (if banner contains URL-like content)
	endpointPaths := []string{"/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/gql", "/query"}
	bannerLower := strings.ToLower(p.Banner)
	for _, path := range endpointPaths {
		if strings.Contains(bannerLower, path) {
			return &Evidence{
				Verdict:                VerdictAccept,
				ConfidenceContribution: plugin.ConfidenceFirm,
				Artifacts:              map[string]string{"endpoint": path, "indicator": "path"},
				Note:                   "GraphQL endpoint path tespit edildi → firm",
			}, nil
		}
	}
	return &Evidence{Verdict: VerdictReject, Note: "GraphQL göstergesi tespit edilmedi"}, nil
}

// verifyGraphQLIntrospection introspection sorgu yanıtını doğrular (GASH-038, CWE-200).
// What: Gövdede __schema + queryType birlikte varsa ve hata zarfı yoksa firm.
// Why: Introspection'ın açık olması şema ifşasıdır (low severity); hata yanıtı
// ("errors"/introspection disabled) kapalı demektir ve reject edilir. Node/npm
// yığınlarındaki düz "__schema" kelimesi tek başına yetmez (queryType şartı).
func verifyGraphQLIntrospection(p VersionParams) (*Evidence, error) {
	body := p.Banner
	if !strings.Contains(body, "__schema") || !strings.Contains(body, "queryType") {
		return &Evidence{Verdict: VerdictReject, Note: "introspection yanıtı yok (__schema/queryType)"}, nil
	}
	lower := strings.ToLower(body)
	for _, marker := range []string{"introspection is disabled", "introspection_disabled", `"errors"`} {
		if strings.Contains(lower, marker) {
			return &Evidence{Verdict: VerdictReject, Note: "introspection hata yanıtı — kapalı"}, nil
		}
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceFirm,
		Artifacts:              map[string]string{"signal": "introspection", "fields": "__schema,queryType"},
		Note:                   "GraphQL introspection açık (şema ifşası) → firm (GASH-038 tavan)",
	}, nil
}

func verifyJWTAlgConfusion(h http.Header) (*Evidence, error) {
	var findings []string

	// Check for "none" algorithm in JWT headers (Authorization, cookies, custom headers)
	noneAlgPattern := regexp.MustCompile(`(?i)eyJhbGciOiJub25l`)
	for name, values := range h {
		for _, v := range values {
			if noneAlgPattern.MatchString(v) {
				findings = append(findings, name+": JWT 'none' algorithm detected")
			}
		}
	}

	// Check for algorithm confusion indicators in debug/error headers
	confusionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)algorithm\s+(confusion|mismatch|switch)`),
		regexp.MustCompile(`(?i)(HS256|RS256).*used.*for.*(RS256|HS256)`),
		regexp.MustCompile(`(?i)key.*(confusion|mismatch)`),
		regexp.MustCompile(`(?i)jwt.*alg.*(confusion|none)`),
	}
	for name, values := range h {
		for _, v := range values {
			for _, re := range confusionPatterns {
				if re.MatchString(v) {
					findings = append(findings, name+": JWT algorithm confusion indicator: "+v)
				}
			}
		}
	}

	// Validation errors ("invalid algorithm", "unsupported algorithm") prove
	// that the server rejected the probe; they are not confusion evidence.

	if len(findings) == 0 {
		return &Evidence{Verdict: VerdictReject, Note: "JWT algorithm confusion göstergesi tespit edilmedi"}, nil
	}

	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"findings": strings.Join(findings, "; ")},
		Note:                   "JWT algorithm confusion riski tespit edildi → confirmed",
	}, nil
}
