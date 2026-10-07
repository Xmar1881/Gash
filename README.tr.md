# GASH // Vulnerability & Penetration Engine

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
![Version](https://img.shields.io/badge/version-0.3.0-red)

```text
  ██████╗  █████╗ ███████╗██╗  ██╗
 ██╔════╝ ██╔══██╗██╔════╝██║  ██║
 ██║  ███╗███████║███████╗███████║
 ██║   ██║██╔══██║╚════██║██╔══██║
 ╚██████╔╝██║  ██║███████║██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
  [ GASH // Vulnerability & Penetration Engine ]
  v0.3.0  //  fast | modular | thorough
```

> [!WARNING]
> **Yalnızca yetkili / yasal testlerde kullan.** İzinsiz tarama suçtur. Sorumluluk kullanıcıdadır.

---

## Neden GASH?

- **Tek komutla full tarama:** recon + crawl + 39 güvenlik kontrolü + rapor
  (zafiyet tespiti, saldırı yüzeyi keşfi ve yapılandırma denetimi)
- **Akıllı:** tech fingerprint'e göre wordlist seçer (WordPress / PHP / Node / Java / Python)
- **Modern web:** yapay zekâyla üretilmiş sitelerin tipik hastalıkları — eksik
  başlıklar, wildcard CORS, open redirect, traversal, riskli metotlar ve
  JS'e gömülü secret'lar
- **Crawler'lı:** link + form + `sitemap.xml` + Swagger/OpenAPI + JS içinden API endpoint çıkarır
- **Raporlama:** terminal tablosu + `JSON / HTML / TXT` + önceki taramayla **fark (YENİ/KAPANDI)** takibi
- **Dürüst çıktı:** keşif bulguları (admin sayfası, robots.txt, erişilebilir dizin)
  puansız `INFO` gözlem olarak raporlanır — bulunan `/login` sayfası asla CRITICAL değildir
- **Plugin:** yeni kontrol = 1 decorator (`core/registry.py`)

## Hızlı Başlangıç

```bash
git clone https://github.com/Xmar1881/Gash.git
cd Gash

# kurulum (Windows: `py`, Linux/macOS: `python3`)
py -m pip install -r requirements.txt
# veya: pip install -e .   (`gash` komutunu kurar)

# full tarama (güvenli varsayılan: time-based yok, aktif POST/upload/login yok)
py gash.py -t https://target.com --full

# derin tarama (opt-in: time-based + aktif POST + upload-rce + login testi)
py gash.py -t https://target.com --full --deep

# interaktif menü (komut ezberlemeden)
py gash.py --menu

# raporlu
py gash.py -t https://target.com --full -o rapor.html -v
```

Opsiyonel (sadece `--dom` headless DOM XSS için):

```bash
py -m pip install playwright
py -m playwright install chromium
```

## Kullanım

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
| `py gash.py --list-checks` | 39 kontrolü listele |
| `py gash.py -t URL --full --skip-checks sqli-blind,ssti` | İstemediğin check'i kapat |
| `py gash.py -t URL --full --cookie "session=abc" --header "Authorization: Bearer X"` | Login arkası tarama |
| `py gash.py -t URL --full --login-user admin --login-pass 1234` | Oto-login dene, oturumla tara |
| `py gash.py -t URL --full --max-pages 15 --depth 3` | Crawler'ı büyüt |
| `py gash.py -t URL --full --dom` | Headless Chromium ile DOM XSS doğrula (yavaş) |
| `py gash.py -t URL --full --oob` | Otomatik OOB doğrulama (Blind XSS + SSRF), interactsh ile |
| `py gash.py -t URL --full --delay 0.2 --max-requests 500` | Kibar / bütçeli tarama |
| `py gash.py --target-file targets.txt --full --output-dir raporlar/` | Toplu tarama (hedef başına rapor + `bulk_summary.json`) |
| `py gash.py --target-file targets.txt --full --output-dir raporlar/ --resume` | Kaldığı yerden devam (raporu olanı atla) |

`targets.txt` formatı: satır başına 1 hedef, `#` yorum ve boş satır atlanır.

## Kontroller (39)

`py gash.py --list-checks` çıktısı:

| İsim | Açıklama |
|---|---|
| `sqli-error` | Error-based SQLi (DB hata imzası) |
| `xss-reflected` | Reflected XSS (3 bağlam + escape filtresi) |
| `xss-errpage` | 404 + header yansıması |
| `upload-form` | Upload formu tespiti (pasif) |
| `robots` | robots.txt + Disallow toplama |
| `smart-dirs` | Akıllı dir-brute (tech wordlist) |
| `smart-recurse` | Bulunan yolun altı + yedek uzantılar |
| `sqli-blind` | Boolean-blind + encoding bypass + time-based |
| `ssti` | SSTI şablon enjeksiyonu |
| `ssrf` | SSRF bulut metadata + yüzey notu |
| `idor` | IDOR/BOLA API obje farkı |
| `protopollution` | Prototype Pollution yansıma yüzeyi |
| `stored-xss` | Stored XSS canary (blind: `--blind-callback` gerekli) |
| `sqli-login` | Login formu SQLi auth-bypass `[deep]` |
| `waf-detect` | WAF parmak izi (pasif) |
| `idor-param` | IDOR query parametresi (`?id=`) |
| `cookie-flags` | Cookie HttpOnly/Secure/SameSite denetimi |
| `upload-rce` | Upload filtre bypass (benign içerik) `[deep]` |
| `smart-tech` | Tech fingerprint + nokta-atışı yollar |
| `dom-xss` | DOM XSS headless doğrulama (`--dom`) |
| `security-headers` | Eksik güvenlik başlıkları (pasif) |
| `open-redirect` | next/redirect parametreleriyle open redirect |
| `path-traversal` | file/page parametreleriyle path traversal |
| `cors` | Gevşek CORS politikası (evil origin probu) |
| `http-methods` | Riskli HTTP metotları (TRACE/PUT/DELETE) |
| `js-secrets` | JavaScript'e gömülü secret'lar |
| `jwt-none` | alg:none kullanan JWT'ler (pasif) |
| `graphql-introspection` | Açık bırakılmış GraphQL introspection |
| `host-header` | Yansıyan Host başlığı (cache-poison yüzeyi) |
| `security-txt` | security.txt varlığı (RFC 9116) |
| `os-command-injection` | `;id`/`\|id` ile OS komut enjeksiyonu |
| `crlf-injection` | CRLF header enjeksiyon probu |
| `csrf-surface` | Anti-CSRF kontrolsüz POST formlar |
| `firebase-open` | Herkese açık Firebase veritabanı |
| `supabase-anon` | Loginsiz okunabilen Supabase tablosu |
| `nextjs-middleware-bypass` | Next.js middleware auth bypass |
| `wp-user-enum` | WordPress kullanıcı adı ifşası |
| `swagger-exposed` | Herkese açık API dokümanı (Swagger/OpenAPI) |
| `mass-assignment` | İstemciden kontrol edilebilen rol alanı |

Her bulgu `CWE + OWASP Top 10 + tahmini CVSS + remediation` ile zenginleştirilir
(`core/knowledge.py`) ve üreten kontrolün verdiği `confidence` notunu taşır
(High/Medium/Low).

## Güvenlik Modeli

Tarama **varsayılan olarak güvenlidir**: time-based bekleme yok, aktif POST
yok, dosya yükleme yok, login denemesi yok. Bunlar sadece açık `--deep`
ile çalışır (sihirbaz zaten sorar). Stored-XSS probu password/hidden
alanlara dokunmaz, upload probları her zaman zararsız metindir.
TLS sertifikaları varsayılan olarak doğrulanır (`--insecure` açıkça kapatır).

## Sınırlamalar

Dürüst kapsam (Nuclei/ZAP/sqlmap ile karşılaştırma):

- **Tarayıcıdır, sömürü aracı değildir:** payload çalıştırma, oturum çalma yok.
- IDOR/SSRF bulguları tek-oturum sezgiseldir — manuel doğrulama şarttır
  (başlıkta yazar).
- CVSS ve 0–100 risk skoru **sınıf bazlı statik tahminlerdir**, ortama göre
  hesaplanmaz.
- Dahili OOB dinleyici artık var — `--oob` (interactsh) Blind XSS/SSRF
  callback'lerini kapsar; diğer OOB sınıfları hâlâ senin dinleyicini ister.
- Henüz yok: path traversal/LFI, OS komut enjeksiyonu, XXE, open redirect,
  CORS, JWT, GraphQL introspection, TLS denetimi.

## Rapor Örneği

```bash
py gash.py -t https://target.com --full -o rapor.html
# rapor.json / rapor.txt de olur (uzantıya göre)
```

- **Terminal:** renkli severity listesi + özet tablosu (CRITICAL / MEDIUM / LOW)
- **HTML:** severity dağılımı, risk skoru (0-100), kategori kırılımı, yönetici özeti, filtre butonları, `evidence <details>` içinde
- **Diff:** her tarama `.gash_history/` altına kaydolur, sonraki taramada `X YENİ / Y KAPANDI` gösterir

## Proje Yapısı

```text
Gash/
├── gash.py              # giriş noktası (CLI -> recon/scan -> rapor)
├── core/
│   ├── cli.py           # argparse bayrakları
│   ├── recon.py         # IP / DNS / port / header
│   ├── scanner.py       # SQLi / XSS / dir-brute motoru
│   ├── advanced.py      # blind / SSTI / SSRF / IDOR / upload-RCE ...
│   ├── bulk.py          # toplu tarama yardımcıları
│   ├── crawler.py       # BFS crawler (sitemap + swagger + JS)
│   ├── domxss.py        # Playwright DOM doğrulama (--dom)
│   ├── reporter.py      # terminal + json/html/txt + diff
│   ├── knowledge.py     # CWE / OWASP / CVSS / remediation
│   ├── registry.py      # plugin sistemi (@check)
│   ├── net.py           # delay / bütçe / auth
│   ├── menu.py          # interaktif tarama sihirbazı
│   └── banner.py        # ASCII banner
├── tests/
│   ├── test_unit.py         # ağ gerektirmez
│   ├── test_bulk.py         # toplu tarama (ağ gerektirmez)
│   └── test_integration.py  # lokal stub sunucu (~15 sn)
└── .github/workflows/ci.yml  # ubuntu+windows × 3.12/3.13
```

Yeni kontrol eklemek:

```python
from core.registry import check

@check("benim-check", "Açıklama", order=10)
def test_benim(session, urls, timeout, verbose=False):
    return []  # list[Finding]
```

## Test

```bash
py -m pytest tests/ -q
```

## Yol Haritası

- [x] Bulk tarama (`--target-file` + resume)
- [x] Güvenli varsayılan + `--deep` opt-in + `--scope` + `--fail-on`
- [ ] YAML profil (sessiz / kapsamlı)
- [ ] Blind-XSS callback otomasyonu
- [ ] CVE eşleme (versiyon → bilinen zafiyet)
- [ ] SARIF / JUnit + webhook bildirimi
- [x] Modern kontrol sınıfları: traversal, open redirect, CORS, güvenlik
  başlıkları, riskli metotlar, JS secret'ları

## Katkı

PR ve issue'lara açık. Lütfen:

1. `py -m pytest tests/ -q` yeşil olsun
2. Yeni check için unit test ekle
3. Yıkıcı payload yok — sadece benign kanıt

## Lisans

Apache-2.0 — bkz. [LICENSE](LICENSE).
