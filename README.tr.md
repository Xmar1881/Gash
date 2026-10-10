# GASH // Vulnerability & Penetration Engine

## XSS kaniti ve yerel triage

Reflected, stored ve DOM-XSS bulgulari `core/xss_triage.py` icindeki deterministik
iki asamali yerel triage katmaniyla zenginlestirilir. Yansima veya sink,
`HTML_Text`, `HTML_Attribute`, `JS_Literal`, `JS_Block`, `URL_Attribute` ya da
`CSS_Context` olarak siniflandirilir ve sabit `XSSVulnerabilityTriageResult`
JSON sozlesmesi uretilir. Tek basina yansima calisma kaniti degildir; breakout,
browser veya OOB kaniti gerekir. Harici AI servisi kullanilmaz.

JSON/SARIF uyumlu bulgularda hedef URL, parametre, acik boolean'i, context,
source/sink/AST kaniti ve remediation alanlarini tasiyan `VulnerabilityFinding`
objesi `vulnerability_finding` altinda verilir. Eski tuketiciler icin `triage`
alanlari korunur.

`core/xss_context.py` icindeki sinirli ve calistirmayan
`double_parse_mutation()` parser-fark yardimcisi mXSS sinyali icin kullanilir;
payload calistirmez ve oturum verisi toplamaz.
Ayni context katmani JSON/import-map hydration scriptlerini ve CSS style
attribute'larini tanir; `decode_chain()` URL+HTML decode katmanlarini sinirli
olarak gosterir ama decode edilmis metni tek basina kanit saymaz.
Opsiyonel JavaScript AST context cozumu icin bu checkout'tan
`py -m pip install -e ".[jsast]"`
kurulabilir; kurulmazsa korumaci Python context fallback calisir.

`--dom` ile headless dogrulama `postMessage`, Web Storage, `history.state`,
`window.name`, URL/referrer, modern `setHTMLUnsafe`/DOMParser ve Trusted Types
politika yollarinda marker akisini kaynak -> sink olarak eslestirir. Parser ve
politika gozlemi, ekleme veya calisma bagimsizca gorulene kadar suphelidir.
Chromium TLS kontrolu `--insecure` ile uyumludur; DOM check'i bunu gizlice
atlamaz.

<p align="center"><img src="docs/logo.png" alt="GASH logo" width="220"></p>

> English version: [README.md](README.md)
>
> Not: uygulama çıktıları İngilizcedir (severity: CRITICAL/MEDIUM/LOW).

> Hızlı, modüler otomatik web zafiyet tarayıcı + pentest motoru.
>
> Konumlandırma: **heuristic güvenlik duman tarayıcısı** — recon'dan rapora
> tek komut. ZAP/Nuclei/manuel pentest yerine geçmez; bariz olanı hızlı bulur.

[![GASH CI](https://github.com/Xmar1881/Gash/actions/workflows/ci.yml/badge.svg)](https://github.com/Xmar1881/Gash/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Version](https://img.shields.io/badge/version-0.6.0-red)

```text
  ██████╗  █████╗ ███████╗██╗  ██╗
 ██╔════╝ ██╔══██╗██╔════╝██║  ██║
 ██║  ███╗███████║███████╗███████║
 ██║   ██║██╔══██║╚════██║██╔══██║
 ╚██████╔╝██║  ██║███████║██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
  [ GASH // Vulnerability & Penetration Engine ]
  v0.6.0  //  fast | modular | thorough
```

> [!WARNING]
> **Yalnızca yetkili / yasal testlerde kullan.** İzinsiz tarama suçtur. Sorumluluk kullanıcıdadır.

---

## 0.6.0 öne çıkanlar

- **56 kayıtlı kontrol:** isimleri sabit, safe/deep politikaları açıkça belirtilmiş.
- **Hibrit Python + Go worker** (`--go-worker`): sınırlı salt-okunur batch işleri,
  Python tarafında karar ve binary yoksa aynalı fallback.
- **Modern XSS kanıt hattı:** bağlam-duyarlı yansıma, opsiyonel JavaScript AST,
  DOM source/sink takibi, iki aşamalı yerel triage, mXSS parser-fark sinyali ve
  doğrulanan JSON kanıt sözleşmesi.
- **TLS chain-of-trust ve HTTP/3/QUIC kanıtı:** varsayılan trust-store kontrolü;
  `--http3` yalnızca açık opt-in ile tek salt-okunur QUIC GET çalıştırır.
- **Dürüst tarama sağlığı:** başarısız veya atlanan kontroller `SCAN DEGRADED` /
  `SCAN PARTIAL` olur; sahte temiz sonucu üretilmez.

Bu repodaki kaynak ve paket metadatası **v0.6.0**'dır. Güncel özellikler için
clone içinden kurulum yap; düz `pip install gash[...]` eski yayımlanmış paketi
getirebilir.

## Neden GASH?

- **Tek komutla full tarama:** recon + crawl + 56 güvenlik kontrolü + rapor
  (zafiyet tespiti, saldırı yüzeyi keşfi ve yapılandırma denetimi)
- **Akıllı:** tech fingerprint'e göre wordlist seçer (WordPress / PHP / Node / Java / Python)
- **Modern web:** yapay zekâyla üretilmiş sitelerin tipik hastalıkları — eksik
  başlıklar, wildcard CORS, open redirect, traversal, riskli metotlar ve
  JS'e gömülü secret'lar
- **Crawler'lı:** link + form + `sitemap.xml` + Swagger/OpenAPI + JS içinden API endpoint çıkarır (+ JS-heavy uygulamalar için opt-in `--spa` headless runtime turu)
- **Raporlama:** terminal tablosu + `JSON / HTML / TXT / SARIF / XML` + önceki taramayla **fark (YENİ/KAPANDI)** takibi
- **Dürüst çıktı:** keşif bulguları (admin sayfası, robots.txt, erişilebilir dizin)
  puansız `INFO` gözlem olarak raporlanır — bulunan `/login` sayfası asla CRITICAL değildir
- **Plugin:** yeni kontrol = 1 decorator (`core/registry.py`)

## Hızlı Başlangıç

```bash
git clone https://github.com/Xmar1881/Gash.git
cd Gash

# kurulum (Windows: `py`, Linux/macOS: `python3`)
py -m pip install -r requirements.txt
# veya: py -m pip install -e ".[test]"   (`gash` komutu + test bağımlılığı)

# tüm opsiyonel yetenekler (DOM, JS AST, OOB, HTTP/3)
py -m pip install -e ".[full]"
# DOM/browser kontrolleri için ayrıca:
py -m playwright install chromium

# full tarama (güvenli varsayılan: time-based yok, aktif POST/upload/login yok)
py gash.py -t https://target.com --full

# derin tarama (opt-in: time-based + aktif POST + upload-rce + login testi)
py gash.py -t https://target.com --full --deep

# interaktif menü (komut ezberlemeden)
py gash.py --menu

# raporlu
py gash.py -t https://target.com --full -o rapor.html -v
```

Opsiyonel (sadece `--dom` / `--spa` / `--browser-discovery` headless tarama için):

```bash
py -m pip install playwright
py -m playwright install chromium
```

## Kullanım

> **Tek komutta maksimum kapsama** (deep + thorough + browser + OOB):
>
> ```bash
> py gash.py -t https://hedef.com --full --deep --profile thorough --dom --spa --browser-discovery --http3 --go-worker --oob -o rapor.html -v
> ```
>
> `--dom/--spa/--browser-discovery` için `playwright` + Chromium, `--http3`
> için yerel `.[http3]` extra'sı ve `--oob` için `py -m pip install -e ".[oob]"`
> gerekir. Giriş arkası yüzey için
> `--cookie "session=abc"` (artı `--cookie-b` / `--cookie-admin`) ekle.

| Komut | Ne yapar |
|---|---|
| `py gash.py -t URL --full` | Recon + Scan (varsayılan) |
| `py gash.py -t URL --recon` | Sadece bilgi toplama: IP / DNS / port / header / sunucu |
| `py gash.py -t URL --scan` | Sadece zafiyet taraması |
| `py gash.py -t URL --scan --quick` | Hızlı mod: time-based + aktif POST'ları atla |
| `py gash.py -t URL --full --deep` | Derin mod (opt-in): time-based + aktif POST + upload-rce + login testi |
| `py gash.py -t URL --full --scope a.com,api.a.com` | Kapsam allowlist: kapsam dışı hedef reddedilir |
| `py gash.py -t URL --full --fail-on critical` | CI eşiği: CRITICAL bulgu varsa çıkış kodu 3 (`medium` da olur) |
| `py gash.py -t URL --full --no-color` | Renksiz çıktı (CI logları için) |
| `py gash.py -t URL --full --proxy http://127.0.0.1:8080` | Trafiği Burp/ZAP üzerinden geçir |
| `py gash.py -t URL --full --user-agent "MyScanner/1.0"` | Özel User-Agent |
| `py gash.py -t https://host/app --full` | Alt-uygulama kapsamı: path korunur (`/app`, `/app` olarak kalır) |
| `py gash.py -t URL --full --insecure` | TLS doğrulamayı kapat (yalnızca self-signed lab) |
| `py gash.py -t https://host --full --http3` | Aktif HTTP/3/QUIC kanıtı: tek salt-okunur GET; önce `py -m pip install -e ".[http3]"` kur |
| `py gash.py --list-checks` | 56 kontrolü listele |
| `py gash.py -t URL --full --skip-checks sqli-blind,ssti` | İstemediğin check'i kapat |
| `py gash.py -t URL --full --cookie "session=abc" --header "Authorization: Bearer X"` | Login arkası tarama |
| `py gash.py -t URL --full --cookie "a=1" --cookie-b "b=2"` | İkinci kullanıcıyla cross-session IDOR doğrulama |
| `py gash.py -t URL --full --cookie "a=1" --cookie-admin "adm=9"` | Yetki sınırı doğrulama için admin oturumu (sadece CLI) |
| `py gash.py -t URL --full --login-user admin --login-pass 1234` | Oto-login dene, oturumla tara |
| `py gash.py -t URL --full --max-pages 15 --depth 3` | Crawler'ı büyüt |
| `py gash.py -t URL --full --profile thorough` | Kapsam profili: quick / balanced (varsayılan) / thorough |
| `py gash.py -t URL --full --dom` | Headless Chromium ile DOM XSS doğrula (yavaş) |
| `py gash.py -t URL --full --spa --max-xss-urls 40` | SPA runtime keşfi (JS route/form/API) + büyük XSS havuzu |
| `py gash.py -t URL --full --browser-discovery` | Full browser trafik profili (istek/WS/SSE/route) havuza işlenir |
| `py gash.py -t http://127.0.0.1:8000 --full` | Loopback hedefte local audit otomatik çalışır (salt-okunur; `--local` zorlar) |
| `py gash.py -t URL --full --oob` | Otomatik OOB doğrulama (Blind XSS + SSRF), interactsh ile |
| `py gash.py -t URL --full --delay 0.2 --max-requests 500` | Kibar / bütçeli tarama |
| `py gash.py -t URL --full --go-worker` | Hibrit motor: Go worker dir-brute listesini sıralar + tüm bağımsız probları (crawl tohum/tur, dir-brute/XSS/SQLi/SSTI/SSRF/IDOR/login/LDAP/upload/API gövde) tek turda toplar; zaman/durum-bağımlı problar (time-based, OOB, stored, upload-RCE, matrix, swagger early-exit) canlı kalır; bütçe batch öncesi denetlenir; hüküm Python'da kalır (derleme: `cd go && go build -o bin/gash-worker .`; binary yoksa aynalı fallback birebir aynı sonucu verir; sıralı havuz cap altında daha iyi aday seçebilir; proxy/`--insecure`/`--delay` Python yolunu zorlar) |
| `py gash.py --target-file targets.txt --full --output-dir raporlar/` | Toplu tarama (hedef başına rapor + `bulk_summary.json`) |
| `py gash.py --target-file targets.txt --full --output-dir raporlar/ --resume` | Kaldığı yerden devam (raporu olanı atla) |

`targets.txt` formatı: satır başına 1 hedef, `#` yorum ve boş satır atlanır.

## Kontroller (56)

`py gash.py --list-checks` çıktısı:

| İsim | Açıklama |
|---|---|
| `sqli-error` | Error-based SQLi (DB hata imzası) |
| `xss-reflected` | Reflected XSS (bağlam analizi + breakout kontrolü) |
| `xss-errpage` | 404 + header yansıması |
| `upload-form` | Upload formu tespiti (pasif) |
| `robots` | robots.txt + Disallow toplama |
| `smart-dirs` | Akıllı dir-brute (tech wordlist) |
| `smart-recurse` | Bulunan yolun altı + yedek uzantılar |
| `sqli-blind` | Boolean-blind + encoding bypass + time-based |
| `nosqli` | NoSQL operatör enjeksiyonu (Mongo tarzı `$ne`/`$eq`) |
| `ssti` | SSTI şablon enjeksiyonu |
| `ssrf` | SSRF bulut metadata + yüzey notu |
| `idor` | IDOR/BOLA API obje farkı |
| `idor-param` | IDOR query parametresi (`?id=`, uuid-farkında) |
| `authz-matrix` | Anonim/kullanıcı yetki matrisi |
| `protopollution` | Prototype Pollution yansıma yüzeyi |
| `stored-xss` | Stored XSS canary + second-order render kontrolü |
| `sqli-login` | Login formu SQLi auth-bypass `[deep]` |
| `waf-detect` | WAF parmak izi (pasif) |
| `cookie-flags` | Cookie HttpOnly/Secure/SameSite denetimi |
| `upload-rce` | Upload filtre bypass (benign içerik) `[deep]` |
| `smart-tech` | Tech fingerprint + nokta-atışı yollar |
| `dom-xss` | DOM XSS headless doğrulama, sink + kaynak + oracle (`--dom`) |
| `security-headers` | Eksik güvenlik başlıkları (pasif) |
| `open-redirect` | next/redirect parametreleriyle open redirect |
| `oauth-redirect` | OAuth/OIDC `redirect_uri` open redirect (kod/token hırsızlığı sınıfı) |
| `path-traversal` | file/page parametreleriyle path traversal (+ `.properties`) |
| `cors` | Gevşek CORS politikası (evil origin probu) |
| `http-methods` | Riskli HTTP metotları (TRACE/PUT/DELETE) |
| `js-secrets` | JavaScript'e gömülü secret'lar (CI/CD token dahil) |
| `jwt-none` | alg:none / tehlikeli `kid` JWT'ler (pasif) |
| `jwt-acceptance` | Kontrollü alg:none / tehlikeli `kid` replay'i `[deep]` |
| `deserialize-surface` | İstemci tarafı Java/PHP/.NET serileştirme işaretleri (pasif) |
| `ci-workflow` | Herkese açık CI/CD workflow + tedarik zinciri risk işaretleri |
| `graphql-introspection` | GraphQL introspection + şema analizi |
| `host-header` | Yansıyan Host başlığı (cache-poison yüzeyi) |
| `security-txt` | security.txt varlığı (RFC 9116) |
| `os-command-injection` | `;id`/`\|id` ile OS komut enjeksiyonu |
| `crlf-injection` | CRLF header enjeksiyon probu |
| `csrf-surface` | Anti-CSRF kontrolsüz POST formlar |
| `firebase-open` | Herkese açık Firebase veritabanı |
| `supabase-anon` | Loginsiz okunabilen Supabase tablosu |
| `cloud-storage` | Herkese açık S3/GCS/Azure Blob listeleme (içerik kanıtı) |
| `nextjs-middleware-bypass` | Next.js middleware auth bypass |
| `wp-user-enum` | WordPress kullanıcı adı ifşası |
| `swagger-exposed` | Herkese açık API dokümanı (Swagger/OpenAPI) |
| `mass-assignment` | İstemciden kontrol edilebilen rol alanı |
| `tls-audit` | TLS sertifika/protokol + chain-of-trust; pasif veya opt-in aktif HTTP/3 |
| `vuln-components` | Bilinen zafiyetli bileşen sürümleri (CMS/eklenti/Atlassian/Denodo) |
| `atlassian-fileread` | Atlassian `::` web-resource dosya okuma (CVE-2026-21589) |
| `plugin-install-authz` | Yetkisiz plugin-install API (Hunk Companion; kurulum yok) |
| `xxe` | XML gövde entity genişletmesi ile XXE `[deep]` |
| `websocket-fuzz` | WebSocket keşif + Upgrade + canary yansıma |
| `login-enum` | Login kullanıcı adı sayımı |
| `ldap-injection` | LDAP jokerkarakter auth bypass |
| `cache-poisoning` | Host yansımasıyla cache zehirlenmesi |
| `cache-deception` | Auth içerikle suffix/normalization cache deception `[deep]` |

Her bulgu `CWE + OWASP Top 10 + tahmini CVSS + remediation` ile zenginleştirilir
(`core/knowledge.py`) ve üreten kontrolün verdiği `confidence` notunu taşır
(High/Medium/Low).

## Güvenlik Modeli

Tarama **varsayılan olarak güvenlidir**: time-based bekleme yok, aktif POST
yok, dosya yükleme yok, login denemesi yok. Bunlar sadece açık `--deep`
ile çalışır (sihirbaz zaten sorar). Stored-XSS probu password/hidden
alanlara dokunmaz, upload probları her zaman zararsız metindir.
JSON/XML/GraphQL body ve PUT/PATCH/DELETE mutasyonları da deep-only'dir
ve yapıyı korur (tek seferde bir yaprak değer); güvenli mod body mutate etmez.
TLS sertifikaları varsayılan olarak doğrulanır (`--insecure` açıkça kapatır).
JWT kabul replay'i ve cache-deception probları yalnız GET ve `[deep]` modunda
çalışır; auth içerik ve differential/cache-header kanıtı ister. Yalnız status
kodu kanıt sayılmaz.
Certificate chain-of-trust platform trust store ile kontrol edilir; private CA
veya eksik zincir MEDIUM gözlemdir, `--insecure` bu kontrolü atlar. HTTP/3
varsayılan olarak pasiftir (`Alt-Svc`); açık `--http3` ile opsiyonel `aioquic`
(`py -m pip install -e ".[http3]"`) üzerinden tek sınırlı, salt-okunur QUIC GET yapılır.
HTTP/2 fallback yapılmaz; proxy yapılandırılmışsa probe atlanır.
Check hataları asla sessiz geçilmez: çöken check tek satır yazar, kalanlar
devam eder ve tarama "Temiz" yerine **SCAN DEGRADED** biter (terminal +
tüm rapor formatları). Check bazında durum (passed/findings/skipped/error)
raporda `scan_health` altında taşınır.

## Sınırlamalar

Dürüst kapsam (Nuclei/ZAP/sqlmap ile karşılaştırma):

- **Tarayıcıdır, sömürü aracı değildir:** payload çalıştırma, oturum çalma yok.
- SSRF cloud-metadata CRITICAL sonucu somut bir AWS AMI kimliği ister; yalnızca
  yansımış çıplak `ami-` marker'ı yeterli kanıt sayılmaz. OOB callback varsa
  en güçlü bağımsız doğrulama olarak kullanılır.
- IDOR bulguları ikinci oturum (`--cookie-b`) veya anonim erişim kanıtlamadıkça
  tek-oturum sezgiseldir (başlıkta yazar).
- CVSS ve 0–100 risk skoru **sınıf bazlı statik tahminlerdir**, ortama göre
  hesaplanmaz.
- OOB doğrulama opt-in'dir — `--oob` (interactsh) Blind XSS/SSRF
  callback'lerini kapsar; dinleyici yoksa tasarım gereği blind bulgu çıkmaz.
- Aktif HTTP/3/QUIC kanıtı opsiyonel `aioquic`, hedefe UDP erişimi ve açık
  `--http3` ister; kullanılamayan/başarısız probe bulgu değildir. `tls-audit`
  chain-of-trust kanıtı için yerel trust store kullanır ve `--insecure` ile
  tutarlıdır. `jwt-none` pasif gözlemin yanında korumalı yanıt kanıtı isteyen
  ayrı bir deep-only kabul replay kontrolüne sahiptir.
- `plugin-install-authz` kurulum rotasında eksik yetkiyi **eksik**
  POST ile kanıtlar (plugin slug yok) — asla eklenti kurmaz/aktive etmez.

## Rapor Örneği

```bash
py gash.py -t https://target.com --full -o rapor.html
# rapor.json / rapor.txt / rapor.sarif / rapor.xml de olur (uzantıya göre)
```

- **Terminal:** renkli severity listesi + özet tablosu (CRITICAL / MEDIUM / LOW)
- **HTML:** severity dağılımı, risk skoru (0-100), kategori kırılımı, yönetici özeti, filtre butonları, `evidence <details>` içinde
- **SARIF / JUnit:** `rapor.sarif` (kod-tarama içe aktarma) ve `rapor.xml` (CI test geçitleri)
- **Diff:** her tarama `.gash_history/` altına kaydolur, sonraki taramada `X YENİ / Y KAPANDI` gösterir

## Proje Yapısı

```text
Gash/
├── gash.py              # giriş noktası (CLI -> recon/scan -> rapor)
├── go/                 # hibrit worker (go.mod + main.go, stdin JSON → stdout JSON)
├── core/
│   ├── goworker.py      # Go köprüsü (subprocess+JSON, opt-in, aynalı fallback)
│   ├── cli.py           # argparse bayrakları
│   ├── recon.py         # IP / DNS / port / header
│   ├── scanner.py       # import hub (scan.* re-export)
│   ├── scan/            # tarayıcı aileleri: _shared/http/discovery/injection/enumeration/engine
│   ├── advanced.py      # import hub (deep.* re-export)
│   ├── deep/            # deep aileleri: _shared/sqli/server/stored/surface
│   ├── bulk.py          # toplu tarama yardımcıları
│   ├── crawler.py       # BFS crawler (sitemap + swagger + JS)
│   ├── discovery.py     # birleşik keşif: canonicalize, JS/API/REST, profiller
│   ├── api_params.py    # recursive body parametreleri + güvenli mutate
│   ├── diff.py          # baseline/differential motoru (tüm check'ler ortak)
│   ├── xss_context.py   # reflection bağlam analizi
│   ├── xss_triage.py    # deterministik iki aşamalı XSS kanıt sözleşmesi
│   ├── xss_payloads.py  # bağlama-duyarlı payload üretici
│   ├── xss_spa.py       # SPA runtime keşfi (--spa)
│   ├── domxss.py        # Playwright DOM doğrulama (--dom)
│   ├── checks/          # kontrol ailesi başına bir modül
│   │   ├── headers.py   # güvenlik başlıkları, CORS, metotlar, host, CSRF…
│   │   ├── movement.py  # open redirect, traversal, CRLF
│   │   ├── secrets.py   # JS secret, JWT, Firebase, Supabase
│   │   └── apps.py      # komut enjeksiyonu, GraphQL, Next.js, TLS, CVE…
│   ├── webchecks.py     # import hub (checks.* re-export)
│   ├── wordlists.py     # statik wordlist'ler + FUZZ parametreleri (lojiksiz)
│   ├── authz.py         # IDOR/BOLA + yetki matris motoru
│   ├── graphql.py       # GraphQL şema analizi
│   ├── localaudit.py    # local makine profili (--local)
│   ├── cve.py           # bilinen-zafiyetli bileşen DB + sürüm eşleme
│   ├── oob.py           # interactsh bant-dışı doğrulama
│   ├── colors.py        # terminal paleti
│   ├── spinner.py       # ilerleme animasyonu
│   ├── reporter.py      # terminal + json/html/txt/sarif/xml + diff
│   ├── knowledge.py     # CWE / OWASP / CVSS / remediation
│   ├── registry.py      # plugin sistemi (@check)
│   ├── net.py           # delay / bütçe / auth
│   ├── menu.py          # interaktif tarama sihirbazı
│   └── banner.py        # ASCII banner
├── tests/
│   ├── test_unit.py         # ağ gerektirmez
│   ├── test_bulk.py         # toplu tarama (ağ gerektirmez)
│   ├── test_bench.py        # bench skorlama (ağ gerektirmez)
│   ├── test_lab.py          # lokal lab regresyonu (~25 sn)
│   ├── test_localbench.py   # lokal yüzey matrisi (ağ gerektirmez)
│   └── test_integration.py  # lokal stub sunucu (~15 sn)
├── bench/
│   ├── lab.py               # zafiyetli lab uygulaması (stdlib)
│   ├── run_bench.py         # DVWA/Juice Shop precision/recall
│   ├── score.py             # precision/recall skorlama
│   ├── cases_dvwa.json / cases_juice.json  # ground truth
│   └── docker-compose.yml   # bench hedefleri
├── docs/
│   └── logo.png             # proje logosu
└── .github/workflows/ci.yml  # ubuntu+windows × 3.12/3.13
```

Yeni kontrol eklemek:

```python
from core.registry import check

@check("benim-check", "Açıklama", order=10,
       active=False, requires_auth=False, max_requests=0)
def test_benim(session, urls, timeout, verbose=False):
    return []  # list[Finding]
```

## Test

```bash
py -m pytest tests/ -q
py -m ruff check core gash.py tests
py -m bandit -q -ll -r core gash.py
py -m pip_audit -r requirements.txt
```

`py gash.py --list-checks` her kontrolün `deep`, `active`, `auth` ve istek
limiti sözleşmesini gösterir. Atlanan kontroller `SCAN PARTIAL` olarak
raporlanır; tarama temiz kabul edilmez.

## Benchmark

DVWA + Juice Shop'a karşı XSS precision/recall (opt-in, canlı hedef —
CI'da asla çalışmaz):

```bash
docker compose -f bench/docker-compose.yml up -d
py bench/run_bench.py --target all --deep --dom --json-out bench/results.json
```

Ground truth `bench/cases_*.json` içinde (zafiyetli endpoint'ler +
negatif kontroller). Skorlama recall/precision'a **confirmed**
başlıkları sayar, unconfirmed/suspected'i ayrı raporlar (dürüstlük
istatistikleri).
Docker yoksa: `py -m pytest tests/test_lab.py -q` aynı vulnerable/fixed
regresyonunu lokal stdlib lab'e karşı koşar.

## Yol Haritası

- [x] Bulk tarama (`--target-file` + resume)
- [x] Güvenli varsayılan + `--deep` opt-in + `--scope` + `--fail-on`
- [ ] YAML profil (sessiz / kapsamlı)
- [x] Blind-XSS/OOB doğrulama (`--oob`, interactsh)
- [x] CVE eşleme (versiyon → bilinen zafiyet, `vuln-components`)
- [x] SARIF / JUnit çıktıları
- [x] 0.6.0 hibrit Go worker, TLS zincir doğrulaması, opt-in HTTP/3 kanıtı
- [x] Bağlam-duyarlı XSS/DOM kanıtı ve deterministik JSON triage sözleşmesi
- [ ] Webhook bildirimi
- [x] Modern kontrol sınıfları: traversal, open redirect, CORS, güvenlik
  başlıkları, riskli metotlar, JS secret'ları

## Katkı

PR ve issue'lara açık. Lütfen:

1. `py -m pytest tests/ -q` yeşil olsun
2. Yeni check için unit test ekle
3. Yıkıcı payload yok — sadece benign kanıt

## Lisans

Apache-2.0 — bkz. [LICENSE](LICENSE).

## Geliştirici

**[Xmar1881](https://github.com/Xmar1881)** tarafından geliştirildi.
