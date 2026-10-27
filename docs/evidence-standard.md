SPDX-License-Identifier: AGPL-3.0-only | Copyright (C) 2026 Xmar1881 / GASH contributors | Modul: github.com/Xmar1881/Gash

# Gash - Kanit Standardi (guncel, 2026-10-27)

- Durum: `v0.1.0-dev`; kod mevcut (338 plugin: 275 Tier 1 YAML + 62 Tier 2 JS + 1 Tier 3 native; 13 engine detector). Bu dokuman Faz 1'de dondurulan kanit standardini korur; guncel uygulama durumu README ve docs/architecture.md §0.2'dedir.
- Modul: github.com/Xmar1881/Gash. Lisans: AGPL-3.0-only.
- Es dosya: docs/architecture.md (oracle arayuzleri bolum 6, Finding semasi bolum 10, OOB protokolu bolum 9).
- Faz kapisi: tarihsel; onay verildi, kod ve testler mevcut. Guncel dogrulama: gofmt, go vet, go build, go test -count=1 ./...
- Faz 0'dan sapma: YOK.

## 0. Teslim formati haritasi

- (1) Ne yapildi: bolum 0.1.
- (2) Kararlar + gerekceler: her sinif basindaki Oracle karari + bolum 8'deki genel kararlar G-01..G-08, her onemli kararda gerekce + reddedilen alternatif.
- (3) B1-B11 durumu: bolum 9.
- (4) Riskler/sorular: architecture.md bolum 20'ye referans; bu dosyanin ayri acik sorusu YOK (tek soru listesi mimari dosyadaki Q1-Q5'tir).

### 0.1 Ne yapildi

benioku.txt 3.3'teki OOB tablosu her zafiyet sinifi icin su yapiya genisletildi: oracle adi + parametreleri, confirmed/firm/tentative kabul-ret kosullari, pozitif + negatif ornek senaryo, OOB kurali (zorunlu/onerilir/gecersiz) ve motorun bunu nasil zorladigi. Taksonomi GASH-XXX + CWE eslemesiyle donduruldu (Faz 0 S3 karari). Test harness eslemesi eklendi (bolum 7).

## 1. Genel kurallar (tum siniflar)

### Karar G-01 - Guven merdiveni

- confirmed: yeniden uretilebilir + kontrollu kanit (OOB callback, baglamsal yurutulebilir yansima + kontrol, tutarli differential 3/3 + kontrol, error imzasi + kontrolde yokluk, hesaplama kaniti + kontrolde yokluk, headless yurutme).
- firm: guclu ama tek-kanalli (timing istatistigi + kontrol, differential 2/3, headless'siz DOM statik analiz).
- tentative: zayif/dolayli (banner, OOB'siz blind probe). Varsayilan raporda YOK (--show-tentative gerekir).
- Kanitsiz aday elenir. Suphede tentative.

### Karar G-02 - Zorunlu on kosullar (oracle'lar atlayamaz)

1. Baseline Classify: Untrusted (WAF/blok) veya ilgili oracle'da Soft404 -> reject.
2. Taint: TaintedByPlugin etiketli yanit -> reject.
3. Kontrol istegi: confirmed gerektiren tum in-band kanitlarda temiz-kontrol zorunlu. Kontrolsuz confirmed YOK.
4. Tekrar: differential/timing'de N=3 default; 3/3 degilse dusurme.
5. Maskeleme: differential/baseline karsilastirmalarinda ayni maske profili.

### Karar G-03 - OOB zorlama disiplini (motor)

- oob required + --oob-server yok: plugin HIC calismaz, sahte tentative YOK, raporda skipped (oob-not-configured). Gerekce: blind siniflarda OOB'siz tentative gurultudur; durust skip daha iyi. Reddedilen: her blind'a tentative basma.
- oob required + --oob-server var: OOB callback gelirse confirmed, gelmezse bulgu YOK.
- oob optional + --oob-server yok: sessiz dusuk-guven modu, OOB cagrisi skipped, in-band tavana inilir.
- oob optional + --oob-server var: iki kanal denenir, OOB gelirse --oob-wait icinde yukseltilir.
- OOB gecersiz sinifta oob=required validasyon hatasidir.

### Karar G-04 - Fixture zorunlulugu

Her kural icin positive + negative fixture Faz 3'te zorunlu. Fixturesiz plugin tentative tavanli. Global negatif korpusta firm+ CI fail (B4). Lab recall olcer.

## 2. Taksonomi (GASH-ID, CWE, Oracle, OOB)

- GASH-001 Reflected XSS, CWE-79, Reflection, OOB gecersiz
- GASH-002 Stored XSS senkron, CWE-79, Reflection 2-istekli, OOB gecersiz
- GASH-003 DOM XSS, CWE-79, StaticSink/Execution, OOB gecersiz (headless yeterli)
- GASH-004 SQLi error-based, CWE-89, ErrorSignature, OOB gecersiz
- GASH-005 SQLi boolean/differential, CWE-89, Differential, OOB onerilir
- GASH-006 SQLi time-based blind, CWE-89, Timing, OOB onerilir
- GASH-007 SSRF yansiyen, CWE-918, Reflection/Header, OOB gecersiz
- GASH-008 SSRF blind, CWE-918, OOB, OOB ZORUNLU
- GASH-009 Command Injection cikti yansiyen, CWE-78, Reflection/Differential, OOB gecersiz
- GASH-010 Command Injection blind, CWE-78, Timing+OOB, OOB ZORUNLU (confirmed icin)
- GASH-011 XXE icerik yansiyen, CWE-611, Reflection, OOB gecersiz
- GASH-012 XXE blind, CWE-611, OOB, OOB ZORUNLU
- GASH-013 Blind deserialization Log4Shell-tarzi, CWE-502, OOB, OOB ZORUNLU
- GASH-014 SSTI yansiyen, CWE-1336, Reflection hesaplama, OOB gecersiz
- GASH-015 SSTI blind, CWE-1336, OOB+Timing, OOB onerilir
- GASH-016 Open Redirect, CWE-601, Redirect, OOB gecersiz
- GASH-017 Path Traversal icerik ifsa, CWE-22, Reflection icerik imzasi, OOB gecersiz
- GASH-018 Path Traversal blind, CWE-22, tespit edilemez, OOB gecersiz (uygulanamaz)
- GASH-019 Header/Misconfig, CWE-693/16, Header, OOB gecersiz
- GASH-020 CSRF, CWE-352, Mantik Header+Differential, OOB gecersiz
- GASH-021 Version/Banner, CWE-200, Version, OOB gecersiz
- GASH-068 Cok-adimli akis atlama (oturumsuz dogrudan erisim), CWE-841, Differential, OOB gecersiz
- GASH-069 Next.js middleware yetkilendirme atlama (CVE-2025-29927), CWE-288, Middleware differential, OOB gecersiz
- GASH-070 Next.js image optimizer blind SSRF, CWE-918, OOB, OOB ZORUNLU
- GASH-071 SPA embedded-state sir ifsasi, CWE-798/200, Static state extraction, OOB gecersiz
- GASH-072 Development build marker, CWE-489, Static content marker, OOB gecersiz

oob required yalnizca GASH-008/010/012/013/070'tedir (+ GASH-005/006/015'te optional). Digerlerinde required validasyon hatasidir.

## 3. Sinif kurallari

### GASH-001 Reflected XSS

Implementation note: a random canary reflection is not an execution proof.
The current oracle requires the requested context to be allowed, separates
JavaScript code from strings/comments and inert JSON script blocks, and emits
`static-execution-evidence` for a recognizable execution payload plus a clean
control and no blocking inline CSP. This is not browser execution. Only a
controlled headless run with a triggered canary and clean control may emit
`confirmed`. A bare `<script>gash_canary</script>` is at most `tentative`.

- Oracle: ReflectionOracle(canary=gash_hex8, contexts=[html,attr,script], require_executable_context=true).
- static-execution-evidence: canary script veya event-handler veya executable attr baglaminda yansiyor + parser tarafindan taninan execution call + kontrol payload'i ayni baglamda yurutulebilir degil + Untrusted yok + taint yok.
- confirmed kabul: yukaridaki kanita ek olarak kontrollu headless tarayicida canary tetiklenir ve temiz kontrolde tetiklenmez.
- firm: yansima var ama baglam HTML-text (yurutulebilir degil) -> en fazla firm degil, tentative. Kural: text-baglam tek basina firm vermez.
- tentative: encode'lu yansima (HTML-entity) -> tentative.
- ret: yansima yok, veya WAF blok sayfasi icinde yansima, veya kontrol de ayni baglamda yurutulebilir (uygulama her girdiyi script'e yaziyor -> baglam ayirt edici degil).
- Ornek (+): GET /search?q=alert(gash_a1b2c3d4) yaniti <script>alert(gash_a1b2c3d4)</script> iceriyor, kontrol q=zzz zararsizken script bos -> static-execution-evidence; headless tetiklenirse confirmed.
- Ornek (-): yanit <p>gash_a1b2c3d4</p> (text) -> tentative; yanit &lt;script&gt; (encode) -> tentative; Cloudflare blok sayfasinda canary -> reject.
- OOB: gecersiz. oob=required verilirse validate hatasi. Motor zorlamasi: R-OOB validasyonu.

### GASH-002 Stored XSS senkron gorunur

- Oracle: ReflectionOracle iki-istekli (POST store + GET render). Params: store_request, render_request, canary.
- confirmed: ikinci istekte executable baglamda canary + kontrol kaydi (temiz icerik) ayni baglamda temiz + taint kontrolu: render edilen canary baska plugin'e aitse reject.
- firm: render gecikmeli (polling ile 2. istekte yok, 3. istekte var) ama executable -> firm (senkron degil).
- tentative: text-baglamda stored yansima.
- ret: store basarili ama render'da yok (filtrelenmis) -> reject, bulgu yok.
- Ornek (+): POST /comment body=gash_hex8, GET /comments son girdide <img onerror=gash_hex8> -> confirmed.
- Ornek (-): POST basarili ama GET'te canary yok (strip edilmis) -> reject; kendi plugin'inin onceki canary'sini baska plugin kanit sayarsa taint ret.
- OOB: gecersiz.

### GASH-003 DOM XSS

- Oracle: StaticSink(source=[location.hash, postMessage], sink=[innerHTML, document.write, eval]) + ExecutionOracle (headless, --deep + dom-xss tag).
- confirmed: headless'te alert/eval tetiklenmesi (chromedp) + kontrolde tetiklenmeme. Headless yoksa confirmed YOK.
- firm: statik sink+source eslesmesi (ornek: location.hash -> innerHTML akisi) -> en fazla firm.
- tentative: sink var source supheli ama akis kurulamamis.
- ret: sink yok veya CSP trusted-types ile bloklu ve headless'te calismamis.
- Ornek (+): /page#gash_hex8 -> innerHTML icine yaziliyor, headless'te script calisti -> confirmed.
- Ornek (-): innerHTML var ama input sabit (URL'den beslenmiyor) -> reject.
- OOB: gecersiz (headless yeterli). Gerekce: DOM istemcide, ag callback'i kanit degil. Reddedilen: DOM icin OOB dayatma.

### GASH-004 SQLi error-based

- Oracle: ErrorSignatureOracle(signature_set=[MySQL, Postgres, MSSQL, Oracle, SQLite], require_absent_in_control=true).
- confirmed: DB imza regex'i hata yanitinda + kontrol istekinde (nötr payload) imza yok + Untrusted yok.
- firm: imza var ama kontrolde de zayif benzer imza (ornek: generic 500) -> firm'a duser.
- tentative: generic SQL kelimesi (ornek: "SQL error") imza setinde yok -> tentative.
- ret: kontrolde de ayni imza (uygulama her hatada ayni DB dump) veya WAF blok icinde imza.
- Ornek (+): ' AND 1=CONVERT(int,@@version)-- yanitinda "SQLServer ... conversion failed" + kontrolde normal sayfa -> confirmed.
- Ornek (-): her 500'de ayni "DB error" (kontrolde de var) -> reject.
- OOB: gecersiz.

### GASH-005 SQLi boolean/differential

- Oracle: DifferentialOracle(true_payload, false_payload, control, repeats=3, mask_profile=default).
- confirmed OOB'siz: 3/3 tutarli true/false ayrismasi + kontrol notr + maskeleme sonrasi fark stabil -> confirmed (OOB'siz mumkun).
- firm: 2/3 tutarlilik veya kucuk fark (uzunluk +/- %5'ten kucuk ama stabil) -> firm.
- tentative: 1/3 veya kararsiz -> tentative degil, reject (suphede eleme). Kural: differential kararsizsa bulgu yok.
- OOB yukseltmesi: MSSQL xp_dirtree / Oracle UTL_HTTP ile DNS callback gelirse confirmed (oob optional). OOB yokken tavan confirmed (dusmez) ama onerilir notu rapora islenir.
- Ornek (+): /item?id=1' AND '1'='1 200 uzun, /item?id=1' AND '1'='2 404 kisa, 3 tekrarda stabil, kontrolde stabil -> confirmed.
- Ornek (-): dinamik icerik (timestamp) maskesiz karsilastirilmis, her istek farkli -> reject.
- OOB: onerilir. Motor: oob optional + --oob-server yoksa dusuk-guven modu yok, in-band devam; varsa callback gelirse guven pekisir.

### GASH-006 SQLi time-based blind

- Oracle: TimingOracle(delay_payload=SLEEP(5)/pg_sleep(5), control_payload=benign, repeats>=3, alpha=0.05, min_delay=5s, strategy=mann-whitney-u).
- firm: istatistiksel ayrisma + kontrol ayismiyor + baseline jitter'dan anlamli buyuk (medyan fark > 3*stddev) -> OOB'siz maksimum firm. confirmed YOK (OOB'siz).
- confirmed: OOB callback (ornek: DB'den DNS) gelirse confirmed (oob optional + --oob-server var).
- tentative: tek olcumde gecikme ama tekrar tutarsiz -> reject (tentative bile degil). Kural: timing tek ornekle bulgu uretmez.
- ret: baseline jitter yuksek (hedef zaten yavas/dalgalı) ve ayrisma anlamsiz.
- Ornek (+): 3x delay medyan 5.2sn, 3x kontrol medyan 0.3sn, baseline stddev 0.1sn -> firm; +OOB callback -> confirmed.
- Ornek (-): tek istekte 6sn ama tekrarlarda 0.4sn (onbellek/yuk) -> reject.
- OOB: onerilir, zorunlu degil. Gerekce: timing tek basina guclu ama ag gurultusunda FP riski; OOB kesinlestirir.

### GASH-007 SSRF yansiyen

- Oracle: ReflectionOracle (hedef URL'nin yanit icine yansimasi: status/body/header) + HeaderOracle (ic ag IP'sine erisim gostergesi).
- confirmed: payload URL'si (ornek: http://169.254.169.254/ icin canary domain) yanitta icerik olarak donuyor veya ic-ag baglanti gostergesi (ornek: metadata JSON) + kontrolde yok.
- tentative: dis URL'ye istek atildigi soyleniyor ama icerik yok (ornek: "fetched" mesaji) -> tentative.
- ret: yansima yok, veya DNS cozumlemesi disariya degil (RedirectOracle cift kontrolunde oldugu gibi).
- Ornek (+): POST /fetch url=https://canary.oob -> yanitta canary domain icerigi -> confirmed.
- Ornek (-): "URL fetched" mesaji ama icerik yok, OOB de yok -> tentative.
- OOB: gecersiz (yansiyorsa gerekmez).

### GASH-008 SSRF blind (iz yok)

- Oracle: OOBOracle(channel=dns+http, namespace=scan-id, correlation_id=c_hex12).
- confirmed: OOB callback correlation+namespace eslesiyor -> confirmed. Baska kanitla confirmed YOK.
- tentative: OOB'siz en fazla tentative, ama kural geregi oob required + --oob-server yoksa plugin HIC calismaz (sahte tentative bile yok). --oob-server varken callback gelmezse bulgu YOK.
- ret: correlation eslesmiyor veya namespace disindan (baska scan) -> reject.
- Ornek (+): POST /webhook url=http://c_a1b2.oob -> 8sn sonra DNS isabeti ayni ID -> confirmed.
- Ornek (-): --oob-server verilmemis, plugin skip -> raporda skipped (oob-not-configured); OOB'siz "response time artti" -> bulgu degil.
- OOB: ZORUNLU. Motor: R-OOB-01 scheduler skip + oracle guard. Gerekce: iz yoksa kanit callback'tir. Reddedilen: timing ile confirmed.

### GASH-009 Command Injection cikti yansiyen

- Oracle: ReflectionOracle (komut ciktisi: ornek: uid=, root:) + DifferentialOracle (hesaplama: 7*7=49).
- confirmed: komut ciktisi veya hesaplama sonucu yanitta + kontrolde yok + Untrusted yok.
- tentative: komut benzeri yankı ama belirsiz (ornek: "uid" kelimesi tek basina) -> tentative.
- ret: kontrolde de ayni icerik (statik sayfa).
- Ornek (+): GET /ping?ip=127.0.0.1;id yanitinda uid=0(root) -> confirmed. GET /calc?expr=7*7 yanitinda 49 + kontrolde yok -> confirmed (SSTI ile karisiyorsa bkz GASH-014 ayrisma notu: template motoru gostergesi varsa SSTI kurali uygulanir).
- Ornek (-): yanitta "id" kelimesi ama cikti yok -> reject.
- OOB: gecersiz.

### GASH-010 Command Injection blind

- Oracle: TimingOracle (sleep 5) + OOBOracle (nslookup/curl callback).
- firm: timing ayismasi (3 tekrar + kontrol) -> OOB'siz maksimum firm.
- confirmed: OOB callback -> confirmed. OOB'siz confirmed YOK.
- ret: timing tutarsiz.
- Ornek (+): ip=127.0.0.1;sleep 5 medyan 5.1sn vs kontrol 0.2sn -> firm; + nslookup callback -> confirmed.
- Ornek (-): tek gecikme, tekrar yok -> reject.
- OOB: confirmed icin ZORUNLU (oob required). Motor R-OOB-01. Gerekce: blind RCE'de timing guclu sinyal ama tek basina kesin degil.

### GASH-011 XXE icerik yansiyen

- Oracle: ReflectionOracle (entity icerigi: /etc/passwd imzasi root:x:, veya canary entity).
- confirmed: tanimli entity icerigi yanitta + kontrolde yok.
- tentative: XML hatasi var ama icerik yok -> tentative (error-based degilse).
- ret: external entity bloklanmis (hata veriyor ama icerik yok) -> reject.
- Ornek (+): POST XML <!ENTITY xxe SYSTEM "file:///etc/passwd"> yanitinda root:x:0:0 -> confirmed.
- Ornek (-): "XML parse error" ama icerik yok -> tentative.
- OOB: gecersiz.

### GASH-012 XXE blind

- Oracle: OOBOracle (external DTD URL'si correlation ID'li).
- confirmed: DTD fetch callback -> confirmed. Baska confirmed yolu YOK.
- tentative: OOB'siz en fazla tentative ama oob required + server yoksa skip (sahte tentative yok).
- Ornek (+): XML'de <!ENTITY % xxe SYSTEM "http://c_hex.oob/evil.dtd"> -> DNS/HTTP isabeti -> confirmed.
- Ornek (-): hata mesaji var icerik yok, OOB yok -> bulgu yok (skip veya reject).
- OOB: ZORUNLU. Motor R-OOB-01.

### GASH-013 Blind deserialization Log4Shell-tarzi

- Oracle: OOBOracle (JNDI/LDAP URL'si veya benzer callback tetikleyici).
- confirmed: callback -> confirmed. In-band confirmed YOK.
- tentative: OOB'siz neredeyse imkansiz -> en fazla tentative, ama oob required + server yoksa skip.
- ret: callback yok -> bulgu yok.
- Ornek (+): header ${jndi:ldap://c_hex.oob/a} -> LDAP/DNS isabeti -> confirmed.
- Ornek (-): "loglaniyor" varsayimiyla version banner'dan Log4Shell iddiasi -> reject (banner tek basina GASH-021 bile degil bu sinifta; tentative'ye dusmez, direkt reject).
- OOB: ZORUNLU. Gerekce: deserialization gozlenemez, callback tek kanit. Reddedilen: banner + tentative.

### GASH-014 SSTI yansiyen

- Oracle: ReflectionOracle hesaplama kaniti (7*7=49, veya template UUID).
- confirmed: hesaplama sonucu yanitta (ornek: 49) + kontrolde (ornek: 7*7'nin ham hali veya farkli carpim) yok + Untrusted yok.
- tentative: template syntax yansiyor ama hesaplanmamis (ornek: {{7*7}} aynen donmus) -> tentative (yansima var, calisma yok).
- ret: hesaplama yok, syntax yok.
- Ornek (+): GET /hello?name={{7*7}} yanitinda "Hello 49" + kontrol ?name=zzz'de 49 yok -> confirmed.
- Ornek (-): yanitta "{{7*7}}" aynen -> tentative (enjekte edilebilir ama calismiyor olabilir).
- OOB: gecersiz. Ayrisma notu: hem CMDi hem SSTI hesaplama veriyorsa template gostergesi (ornek: {{ }} syntax) SSTI'yi secer; motor correlate'de cakismayi cozer (yuksek guven kazanir, digeri duplicate_of).

### GASH-015 SSTI blind

- Oracle: OOBOracle (template fonksiyonuyla DNS: ornek: Freemarker api, Twig dump) + TimingOracle (sleep enjeksiyonu).
- confirmed: OOB callback -> confirmed.
- firm: timing ayismasi (sleep calismis) + kontrol -> firm.
- tentative: syntax yansimasi ama calisma yok -> tentative.
- Ornek (+): blind template'de DNS callback -> confirmed; sleep 5 calismis -> firm.
- Ornek (-): hata mesaji var ama hesaplama/callback yok -> reject.
- OOB: onerilir (oob optional).

### GASH-016 Open Redirect

- Oracle: RedirectOracle(expect_external_host=true, resolve_dns=true).
- confirmed: Location header'i dis hosta (ornek: https://gash-canary.example/) + string eslesme + DNS cozumu cift kontrol + kontrolde (nötr param) redirect yok veya ic redirect.
- tentative: Location'da dis host string olarak var ama redirect gerceklesmiyor (ornek: JS'de disabled link) -> tentative.
- ret: relative redirect (/dashboard) veya ayni host -> reject.
- Ornek (+): GET /go?url=https://gash-canary.example/ -> 302 Location dis host + DNS cozuluyor -> confirmed.
- Ornek (-): /go?url=/profile -> 302 ic -> reject.
- OOB: n/a gecersiz. Gerekce: redirect istemcide gozlenir, callback gerekmez.

### GASH-017 Path Traversal icerik ifsa

- Oracle: ReflectionOracle icerik imzasi (ornek: root:x:, [extensions], boot.ini).
- confirmed: bilinen dosya imzasi yanitta + kontrolde (mevcut olmayan dosya) imza yok + Soft404 degil.
- tentative: dosya benzeri icerik ama imza zayif.
- ret: Soft404 catch-all icinde imza benzerligi (SPA her path'te ayni sayfa) -> reject; kontrolde de ayni imza -> reject.
- Ornek (+): GET /file?name=../../etc/passwd yanitinda root:x:0:0 + kontrol ?name=nonexistent_xyz'de yok -> confirmed.
- Ornek (-): SPA catch-all her path'te ayni HTML, icinde "root" kelimesi -> reject.
- OOB: n/a gecersiz (dosya okuma ag tetiklemez).

### GASH-018 Path Traversal blind

- Tespit edilemez sinif. Oracle YOK. En fazla tentative, pratikte bulgu uretilmez.
- Kural: bu sinifta confirmed/firm YOK. Plugin bu id'yi beyan ederse validate uyarisi + bulgulari tentative tavanli.
- OOB: gecersiz (uygulanamaz) - dosya okuma ag tetiklemez. Gerekce: OOB dayatmak yanlis olur; durust sinir.
- Ornek (-): hata suresi degisti varsayimiyla traversal iddiasi -> reject.

### GASH-019 Header/Misconfig

- Oracle: HeaderOracle(header, expect, mode=absent|weak|malformed).
- confirmed: mantik tabanli (ornek: HSTS yok, CSP yok/unsafe-inline, X-Frame-Options yok + clickjacking baglami, Cookie Secure/HttpOnly/SameSite eksik). Kontrol gerekmez (deterministik header okuma) ama tekrar (2 istek) onerilir (ara proxy varyansi).
- tentative: bu sinifta tentative YOK (header ya var ya yok); supheli ara durum (ornek: CSP var ama zayif) firm'a duser, tentative degil.
- ret: header dogru ve guclu -> reject.
- Ornek (+): HTTPS yanitinda Strict-Transport-Security yok -> confirmed (info/low severity, kurali gore).
- Ornek (-): HSTS var, max-age yeterli -> reject.
- OOB: n/a gecersiz.

### GASH-020 CSRF

- Oracle: Mantik (Header token yoklugu + Differential state-change tekrari).
- confirmed: state-changing istekte (POST) token/samesite yok + kontrolde (token'li) kabul / tokensiz kabul farki + SameSite=Lax/None analizi.
- tentative: form var token gorunmuyor ama istek test edilmemis (pasif gozlem) -> tentative.
- ret: token var veya SameSite=Strict + Preflight dogru -> reject. GET-only endpoint -> bu kuralda reject (baska kurala girmez).
- Ornek (+): POST /transfer tokensiz 200 + kontrol token'li de 200 (ayni sonuc) -> confirmed.
- Ornek (-): POST tokensiz 403, token'li 200 -> reject (korumali).
- OOB: gecersiz.

### GASH-021 Version/Banner

- Oracle: VersionOracle(banner_regex, behavior_probe opsiyonel).
- tentative: banner eslesmesi + davranissal dogrulama yok -> tentative + banner-based etiketi zorunlu. Bu sinifta confirmed/firm YOK (davranissal yoksa).
- firm: davranissal dogrulama varsa (ornek: surume ozgu endpoint/response farki differential ile) -> firm'a yukselebilir (confirmed yine YOK).
- ret: banner yok veya teknoloji eslesmiyor.
- Ornek (+): Server: Apache/2.4.49 + /cgi-bin/.%2e/.%2e davranissal fark -> firm; sadece banner -> tentative + banner-based.
- Ornek (-): Server: cloudflare (CDN, origin gizli) uzerinden version iddiasi -> reject.
- OOB: gecersiz.

### GASH-068 Cok-adimli akis atlama (oturumsuz dogrudan erisim)

Implementation note: this rule is engine-owned (`flow-replay` synthetic spec,
no plugin file) and only runs with `--active --flow-seed`. It is a heuristic
screen, not a state-machine proof: a single unauthenticated fetch of the final
workflow URL is compared to the authenticated baseline.

- Oracle: differential (normalized body similarity), N=1.
- tentative: >=2 discovered steps + fresh jar without seed cookies + final URL
  returns 2xx + body has no password field + normalized similarity >=0.95 to
  the authenticated final page. The synthetic spec has no fixtures, so R-06
  caps confidence at tentative and severity at medium regardless of oracle
  contribution.
- firm/confirmed: not emitted by this screen; a repeated multi-session
  ladder or an explicit authorization check is required and is out of scope.
- ret: final URL not reachable anonymously, non-2xx, login form present,
  similarity <0.95, or <2 steps.
- Ornek (+): /start -> /step1 -> /done; GET /done anonymously returns the same
  masked confirmation page as the authenticated run -> GASH-068 tentative.
- Ornek (-): GET /done anonymously returns 401/403 or a login form -> reject.
- OOB: gecersiz.

### GASH-069 Next.js middleware authorization bypass (CVE-2025-29927)

Implementation note: Tier 1 YAML (`nextjs-middleware-bypass`) plus the
`middleware-bypass` oracle. Read-only GET differential across five fixed
paths; the control request carries no bypass header.

- Oracle: middleware-bypass (control status/body versus
  `x-middleware-subrequest` variants).
- firm: control is access-denied (401/403 or a login/session redirect toward
  a login path) AND bypass returns 2xx with >=32 body bytes AND the masked
  body differs materially from the control AND neither response is a
  WAF/challenge page. Ceiling is firm; confirmed does not exist for this
  class.
- ret: control is already 2xx, bypass is non-2xx, body is short/identical,
  response is a block/challenge page, or the change is only header echo with
  no status change.
- Ornek (+): GET /admin -> 307 /login; GET /admin with
  `x-middleware-subrequest: middleware` -> 200 with dashboard content ->
  GASH-069 firm.
- Ornek (-): GET /admin -> 200 on the control (public route), or variant ->
  401/403 -> reject.
- OOB: gecersiz.

### GASH-070 Next.js image optimizer blind SSRF

Implementation note: Tier 1 YAML (`nextjs-image-optimizer-ssrf`) with
`oob=required`, path `/_next/image`, `url={{OOB_URL}}`, static `w`/`q`.
Internal, metadata, and cloud-metadata targets are deliberately not sent.

- Oracle: OOB callback (single-use token per payload).
- confirmed: the operator's OOB server receives the matching callback; no
  status/body in-band proof is used.
- ret: no callback within the shared bounded window; without
  `--oob-server` the plugin skips as `oob-not-configured` (no fake
  tentative).
- Ornek (+): callback for `/cb/<token>` after the optimizer fetches the
  external URL -> GASH-070 confirmed.
- Ornek (-): optimizer rejects the URL, serves from an allowlist, or
  optimization is disabled -> no callback -> reject.
- OOB: ZORUNLU.

### GASH-071 SPA embedded-state secrets

Implementation note: engine-owned (`internal/discovery/spa_state.go` +
`internal/engine/embedded_state.go`, no plugin file). Static parse of
already-fetched page bodies and external JS; no extra requests.

- Oracle: static state extraction (known containers + secret rules +
  sensitive-key match), masked literal.
- static-execution-evidence: a supported container parses AND a secret-shaped
  literal or sensitive state key with a >=12-char value is present after
  placeholder/env-reference filtering. JWT values map to CWE-200; other
  secrets map to CWE-798. Values are masked (never reported in full).
- ret: no supported container, unparseable/JS-evaluated state, placeholder
  or environment reference, low-entropy value, or duplicate already seen in
  another container/page.
- Ornek (+): `__NEXT_DATA__` contains `"apiKey": "sk_live_..."` ->
  GASH-071 static-execution-evidence with masked evidence.
- Ornek (-): `__NEXT_DATA__` contains `"apiKey": "YOUR_API_KEY"` or
  `process.env.API_KEY` -> reject.
- OOB: gecersiz.

### GASH-072 Development build markers

Implementation note: engine-owned (`internal/discovery/devbuild.go` +
`internal/engine/embedded_state.go`, no plugin file). One aggregated finding
per fetched source; static content only.

- Oracle: marker table (React development bundles/`jsxDEV(`, Vue dev global
  build, Angular debug APIs).
- firm: at least one marker from the exact table is present. Severity stays
  low; confidence is firm, not confirmed, because presence is an observation
  and does not prove an exploitable debug endpoint.
- ret: only devtools hooks, `isDevMode()`, generic warnings, or production
  bundle markers (`.prod.js`) are present; production-present noise never
  fires.
- Ornek (+): page loads `react-dom.development.js` -> GASH-072 firm with the
  matched marker and a bounded snippet.
- Ornek (-): page loads `vue.global.prod.js` or only sets
  `__REACT_DEVTOOLS_GLOBAL_HOOK__` -> reject.
- OOB: gecersiz.

## 4. OOB zorunlu/onerilir/gecersiz kurallari nasil zorlanir

1. Validasyon zamani (loader): oob=required ama R-02/R-03 ihlali (active=false veya safe=true) -> load ret. OOB gecersiz sinifta required -> ret, optional -> uyari.
2. Scheduler zamani: oob required + --oob-server yok -> plugin hic cagrilmaz, skipped (oob-not-configured). B9 testi budur.
3. Oracle zamani: --oob-server yokken OOBOracle.Verify cagrilirsa skipped doner (plugin hatasi degil). oob optional plugin dusuk-guven modunda devam eder.
4. Rapor zamani: skip sebepleri skipped_plugins listesinde sayilir; sahte tentative uretilmedigi buradan denetlenir.
5. CLI zamani: --oob-server verilirse --active zorunlu kilinir (PreRunE kapisi); --active yoksa hata + kullanim mesaji.

## 5. Severity tavanlari (bilgilendirme)

- tentative bulguda final severity tavani medium (R-SEV-01). Ornek: yazar critical yazsa da tentative -> medium.
- GASH-019/021 cogunlukla info/low; GASH-008/010/012/013 confirmed ise high/critical (baglam + auth gore).
- Final severity motor sablonundan; yazar beyanini asamaz (asagi iner, yukari cikmaz).

## 6. Maskeleme ve kontrol matrisi (ozet)

- Maskeleme profili default: CSRF token, nonce, timestamp, UUID, VIEWSTATE, JWT-benzeri. Differential + baseline ayni fonksiyon.
- Kontrol payload'i: her confirmed icin zorunlu; nötr (bos/benign) veya false-dali. Kontrolsuz confirmed yok.
- Tekrar: differential/timing N=3; headless 1 + kontrol; OOB 1 (ID kriptografik).

## 7. Test harness eslemesi

- Her GASH-XXX icin tests/Fixtures: positive/ (zafiyetli yanit) + negative/ (benzer zararsiz: WAF blok, SPA catch-all, encode eden app, dinamik icerik). Ornek: GASH-001 negative'leri: encode'lu yansima, WAF blokta canary, text-baglam.
- gash plugins test: positive'de beklenen guven, negative'de reject/tentative kontrolu.
- Global korpus: temiz app'ler + WAF + SPA + dinamik; firm+ = CI fail.
- Lab: DVWA/JuiceShop/WebGoat'ta precision/recall (gash bench lab).

## 8. Genel kararlar ozeti

- G-01 guven merdiveni: kanit-yeniden-uretilebilirlik esasi. Reddedilen: skor (0-100).
- G-02 on kosullar: baseline+taint+kontrol+tekrar+maskeleme atlanamaz. Reddedilen: oracle'a birakma.
- G-03 OOB disiplini: durust skip, sahte tentative yok. Reddedilen: gurultulu tentative, varsayilan-acik OOB.
- G-04 fixture: kanit topluluga degil kapiya dayanir. Reddedilen: fixturesiz confirmed.
- G-05 (bu dosya): GASH-XXX birincil + CWE ikincil (S3). Reddedilen: yalnizca CWE.
- G-06: tentative tavan + severity tavan (H2). Reddedilen: yazar-beyan guven.
- G-07: blind'da timing/differential tek basina confirmed vermez (OOB veya 3/3 differential haric). Reddedilen: tek-olcum confirmed.
- G-08: GASH-018 durust-sinir (tespit edilemez). Reddedilen: imkansiza bulgu.

## 9. B1-B11 durumu (Faz 1, bu dosyanin payi)

- B3: kanitsiz <= tentative + Finding uretilemez -> bu dosya guven tavanlarini, architecture A-04 mekanizmasiyla birlikte dondurur. Dogrulama Faz 2 contract test.
- B4: korpusta firm+ = 0 -> bu dosyanin ret kosullari + negative fixture listesi kapinin kurali; enforcement Faz 2 CI.
- B9: oob required + server yoksa hic calismaz -> bolum 4'teki 5-nokta zorlama; test Faz 2.
- Diger B'ler architecture.md bolum 19'dadir; bu dosya onlara ek kural koymaz.

## 10. Faz kapisi

- Ciktilar: bu dosya + docs/architecture.md + proto/gash/v1/plugin.proto. Kod yazilmadi.
- Onay sorusu: G-01..G-08 + sinif kurallari (GASH-001..021) kabul mu? Red varsa hangi kurala itiraz?
