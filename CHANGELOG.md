# Changelog

## Unreleased

- Follow-up maintenance and release candidates for the 0.6.x line.

## v0.6.0 — 2026-10-10 (hybrid worker + modern evidence pipeline)

- Release consolidation: 56 stable checks, Python/Go hybrid execution,
  deterministic XSS/DOM evidence triage, TLS chain-of-trust validation, and
  opt-in active HTTP/3/QUIC proof are now documented and packaged together.

- XSS coverage update: DOM verification now traces safe source labels through
  `postMessage`, Web Storage, `history.state`, `window.name`, URL/referrer,
  modern `setHTMLUnsafe`/DOMParser paths, and Trusted Types policy methods.
  Parser/policy observations stay suspected without insertion or execution
  proof, and Playwright now follows the global `--insecure` TLS setting.
  CSP analysis recognizes `script-src-attr`, `strict-dynamic` trust anchors,
  and Trusted Types allowlists without attempting a bypass.
- Context analysis now recognizes JSON/import-map hydration scripts and CSS
  style attributes, and exposes bounded URL+HTML decoding layers for review
  without promoting decoded text to execution proof.
- Optional local `.[jsast]` adds non-executing tree-sitter JavaScript AST context
  resolution; the dependency remains optional and the conservative fallback
  is explicit when it is unavailable.
- Findings now carry a validated `vulnerability_finding` object matching the
  requested target/parameter/source/sink/AST evidence contract; the previous
  `triage` object remains for compatibility.

- XSS evidence update: `core/xss_triage.py` enriches reflected, stored, DOM,
  and confirmed Blind-XSS findings with a deterministic two-pass result
  validated against the requested `XSSVulnerabilityTriageResult` contract.
  Contexts map to the six public enum values; reflection or a sink alone
  remains `False_Positive` until breakout, browser, or OOB execution evidence
  exists. `xss_context.double_parse_mutation()` adds a bounded,
  non-executing parser-differential signal for offline mXSS review.

- SSRF cloud-metadata kanıtı sıkılaştırıldı: URL'den yansıyabilen çıplak
  `ami-`/`meta-data` marker'ları artık CRITICAL üretmiyor; somut AMI ID veya
  daha güçlü metadata kanıtı gerekiyor. Reflection regresyon testi eklendi.

- Research slice 5 (check count **54 -> 56**): `jwt-acceptance` runs only
  with `--deep`, uses GET-only original JWT vs claim-preserving `alg:none`
  differential replay, and raises CRITICAL only when identical protected
  response fingerprints prove acceptance; a dangerous `kid` is a confirmed
  MEDIUM acceptance surface. `cache-deception` tests authenticated content on
  path suffix/normalization variants and requires cache-header/age/CDN evidence;
  status alone is not a finding. Menu, EN/TR README and offline tests updated.
  `tls-audit` now performs platform trust-store chain-of-trust validation by
  default (skipped with `--insecure`) and supports an explicit `--http3` one-
  GET QUIC proof when the optional local `.[http3]`/aioquic backend is installed;
  it never falls back to HTTP/2 and unavailable probes are not findings.
- Güvenilirlik katmanı: `core/diff.py` auth-content proof ve response fingerprint
  helper'ları JWT/cache kontrollerinde ortaklaştırıldı; registry check sözleşmesi
  `active`/`requires_auth`/`max_requests` metadata taşıyor. `tls-audit`, mevcut
  yanıt başlıklarından pasif `Alt-Svc: h3` INFO sinyali üretiyor; açık `--http3`
  ile tek salt-okunur QUIC GET ve trust-store chain kanıtı eklenmiştir. Lab
  vulnerable/fixed fixture'ları, EN/TR sayaç drift testi,
  token redaction regresyonu ve atlanan check'leri Clean göstermeyen terminal/
  TXT/HTML rapor uyarıları eklendi.

- Araştırma dilimi 4 (check sayısı **51 → 54**): `oauth-redirect`
  (OAuth/OIDC authorize `redirect_uri` → evil host = CRITICAL; kod/token
  hırsızlığı sınıfı); `deserialize-surface` (Java `rO0AB`/`aced0005`,
  PHP `O:n:`, .NET ViewState — pasif işaret, gadget yok); `ci-workflow`
  (herkese açık workflow YAML + canlı token / unpinned `tj-actions`
  tedarik zinciri işaretleri); `jwt-none` genişlemesi (path/URL `kid`
  karışıklık yüzeyi); dilim 2 için ağsız test borcu kapatıldı
  (atlassian-fileread / plugin-install-authz / websocket / xxe)
- Araştırma dilimi 3 (check sayısı **49 → 51**): `nosqli` (Mongo-tarzı
  `$ne`/`$eq` boolean fark + hata imzası; JSON gövde morph yalnızca
  `--deep`); `cloud-storage` (sayfada görünen S3/GCS/Azure Blob köklerini
  listeleme XML/JSON kanıtıyla — 403/AccessDenied bulgu değil); Denodo
  Scheduler `CVE-2025-26147` kürate DB + banner sürüm çıkarma +
  `keyTabFile` yüzey INFO (multipart traversal upload **asla** yok);
  smart-tech `denodo` yolları; sayı 51
- Araştırma dilimi 2 (check sayısı **45 → 49**): Atlassian ürün
  parmak izi (`smart-tech` + status/serverInfo sürüm) +
  `atlassian-fileread` (`::` / `%3a%3a` web-resource LFI,
  `CVE-2026-21589`, yalnızca içerik kanıtı); `plugin-install-authz`
  (Hunk Companion `themehunk-import` anonim handler — **eksik POST,
  plugin slug yok, kurulum yok**); `xxe` (`[deep]` XML entity + OOB
  drain); `websocket-fuzz` (keşif + Upgrade + canary echo)
- Araştırma entegrasyonu (2024–2026 smoke dilimi):
  Ghost SVG XSS (`CVE-2024-23724`) + Hunk Companion RCE zinciri
  (`CVE-2024-11972`) `vuln-components` kürate DB + WP plugin
  `readme.txt` Stable-tag probu (salt okuma; install API yok);
  path-traversal uygulama config LFI (`.properties` /
  `crowd.properties` içerik işaretleri + ikinci dosya onayı,
  `/etc` erişilemezse de); `js-secrets` CI/CD tokenleri
  (`ghs_` / `github_pat_` / `npm_`, maskeli) + wordlist'e
  `.github/workflows` / `crowd.properties` / Hunk Companion yolu
- Hibrit hız kaydı düzeltmesi: 0.55s→0.05s sayısı, GIL'i paylaşan
  proses-içi lab sunucusunun Python thread'lerini cezalandırmasından
  geliyordu (Go ayrı process'te etkilenmiyordu). İzole sunucuda iki motor
  başabaş; `bench/latency_curve.py` artık ayrı process'te ölçüyor
  (parite her hücrede `same`). Kalıcı değer: parite + offload mimari,
  çarpan değil; kanıtlanmamış Nagle denemesi geri alındı
- Hibrit RTT eğrisi: `bench/latency_curve.py` (gecikmeli lab; 40 prob,
  threads=workers=10, her hücrede parite `same`); sonuç: kazanç
  istek-başı overhead'den (session klon/lock), paralellikten değil —
  eşit işçide yüksek RTT'de başabaş; tablo `bench/hybrid_board.md` ekinde;
  sayı 45 sabit
- Hibrit motor (crawler): tohum (sitemap/JS/config) + BFS turları tek turda,
  scope/duvar/cap hükmü Python'da birebir (swagger early-exit bilerek
  sıralı); lab paritesi + 429 fallback testli; sayı 45 sabit
- Hibrit motor (kalıcı worker): `gash-worker --stream` (NDJSON döngü,
  satır çerçeveli — bozuk satır akışı kilitleyemez) + Python
  `WorkerSession` havuzu (tarama başına tek spawn; ölü proc düşer,
  `GASH_GO_STREAM=0` kapatır); 5 ping ölçüsü 53ms→~0ms; sayı 45 sabit
- Hibrit skor tablosu: `bench/hybrid_board.md` + `tests/test_hybrid_board.py`
  (9 satır lab ground truth: recall 9/9, FP 0, parite 9/9); burst-flake
  kapatıldı (düşen proba Python tekrarı + Go'da tek transport retry,
  yalnızca güvenli metotlar; 8/8 tam-tarama paritesi); sayı 45 sabit
- Hibrit motor (Go faz 6, hepsi): kalan tüm bağımsız halkalar tek turda
  (blind/SSRF/IDOR+param/proto/login/enum/LDAP/upload/errpage/API-gövde);
  time-based/OOB/stored/upload-RCE/matrix bilinçli canlı (sıra+zaman
  kanıtın parçası); bütçe dürüstlüğü (`pace_many`: batch öncesi fail-closed
  + sayaç; `--delay` kibarlığı Python yolunu zorlar); mock tuzağı kapatıldı
  (tüm parite testleri sayaçla batch'i kanıtlar); sayı 45 sabit
- Hibrit motor (Go faz 5): POST-SQLi + SSTI (GET+POST) fan-out; stability
  re-check ve SSTI confirm POST'u bilerek canlı kalır (art arda aynı cevap
  gerekir); Go↔Python parite + fallback testli; sayı 45 sabit
- Hibrit motor (Go faz 4, lab kanıtlı): gerçek binary + gerçek HTTP ile
  stdlib lab'e karşı parite testleri (XSS + dir-brute + POST-XSS, go on/off
  birebir aynı bulgu); tam `run_scan` paritesi
  (sabit wordlist ile 16/16 aynı bulgu); not: sıralı havuz cap-80 altında
  daha iyi aday seçebilir (ölçüldü: `/upload` kuyruk dışı kaldı), verdict
  başına hüküm asla değişmez; sayı 45 sabit
- Hibrit motor (Go faz 3): XSS stage-1 (url×prob) + filter-map (16 prob)
  tek turda Go'dan; kesik gövdeler `_get` ile tamamlanır (sıfır ıraksama),
  429/toplu ölümde Python yoluna düşer (Go↔Python birebir parite testli);
  `go/` da modüler (`protocol/tech/rank/fetch/main` + aile testleri);
  sayı 45 sabit
- Hibrit motor (Go faz 2): `fetch-batch` işi (tek turda N paralel GET,
  sıra korunur, `httptest` ile durum/redirect/kesit/limit kanıtlı) + hüküm
  ayrıştırması (`_probe_dir` getirir, `_verdict_dir` yargılar; FP kuralları
  tek sahip, iki motorda birebir) + dir-brute Go yolu (dürüstlük kapıları:
  429/toplu ölüm/proxy/`--insecure` Python yoluna düşer); sayı 45 sabit
- Hibrit motor (Go faz 1, doğrulanmış): `go/` worker v2 (ping,
  tech-fingerprint, rank-wordlist, prioritize-urls; `go vet`+`go test`
  yeşil, canlı binary protokole karşı testli) + `core/goworker.py` bridge
  (Go→Python fallback birebir, `go/testdata/*.json` iki tarafı kilitler)
  + `--go-worker` bayrağı (CLI→run_scan→ctx; dir-brute/XSS/POST-XSS
  Go'ya verir; verdict başına hüküm asla değişmez, binary yoksa aynalı
  fallback birebir aynı); CI'ye setup-go + vet/test/build;
  yeni check yok, sayı 45 sabit
- Hibrit iskelet (Go v1, opt-in): `go/` worker (stdin Job JSON →
  stdout Result JSON; `ping`, `tech-fingerprint`, ağsız) + `core/goworker.py`
  bridge (binary yoksa degrade, `Finding` kwargs-only); yeni check yok,
  sayı 45 sabit (faz 1'de v2'ye yükseldi, CI eklendi)
- Modüler yapı (faz 2): `core/scanner.py` -> `core/scan/` paketi
  (_shared/http/discovery/injection/enumeration/engine), `core/advanced.py`
  -> `core/deep/` paketi (_shared/sqli/server/stored/surface); her iki
  `.py` import hub (re-export, sıfır kırılma); `_forms`/`UNFUZZABLE_TYPES`
  tek sahip `scan/discovery` (cycle kırıldı); sayı 45 sabit
- Modüler yapı: wordlist'ler `core/wordlists.py`'da, 21 webchecks
  `core/checks/` paketinde (headers/movement/secrets/apps);
  `core/webchecks.py` import hub (re-export, sıfır kırılma)
- WAF-bypass motoru: per-char filter-map (16 prob, byte-raw canlılık),
  efficiency skoru, confirm/prompt alternates, keyword-split
  (`prompt%0a(1)`, `/**/`), object-base64 + mXSS aileleri, filterfit
  seçici, JSON CT-confusion retry; hepsi bütçe-cap'li; sayı 45 sabit
- Oturumlu crawl dürüstlüğü: login-wall tespiti (crawl + coverage),
  bozuk session'da yüksek sesli uyarı (gated alanlar anonim taranır);
  check sayısı değişmedi (45)
- CVE eşleme (zone-h sınıfı): `core/cve.py` kürate DB + versiyon
  çıkarımı (meta/?ver=/header/CHANGELOG/JS banner), yeni
  `vuln-components` check'i (jQuery/Drupalgeddon/WP-EOL/PHP-EOL…);
  check sayısı 44 -> 45
- DOM self-echo FP fix: prob dispatch'leri `__gash_dispatch` etiketli,
  hook kendi iskelesini kaydetmiyor (postMessage->eval sahte
  CONFIRMED'i kapatır); gerçek sayfa akışları aynen yakalanıyor,
  canlı regresyon testli
- Rapor soft redesign: açık tema, gradient hero, yuvarlak bulgu
  kartları, severity rozetleri, context chip'leri, sticky filtre,
  coverage bandı (eski hacker-terminal teması kalktı)
- Local health merge (M16): section-guard'lı audit (passed/partial/
  error), scan_health'te partial listesi, PARTIAL terminal uyarısı;
  kritik collector çökerse DEGRADED
- API graph pipeline (M10+M11+M12+M13): browser post_data kaydı,
  traffic→ApiTarget (privileged, swagger'dan önce), identifier_graph
  (href/URL/OpenAPI/traffic/GraphQL-vars), matrix GET cross-user +
  `--cookie-admin` ile admin confirm, GraphQL weak-contract INFO;
  check sayısı değişmedi (44)
- Coverage honesty (M9+M14+M15+M16): profil cap'leri (visits/traffic/
  routes/sockets), multi-visit SPA, discovered/tested/truncated
  sayaçları (rapor + TRUNCATED uyarısı), local-audit scan_health'te;
  balanced 12 sayfa, thorough 50 sayfa
- Secret discovery + Windows ACL (M7+M8): platform path envanteri
  (.aws/.azure/.kube/.docker/SSH/Git/.env.* glob), deep-only shape
  fingerprint (değer asla raporlanmaz), SID-tabanlı ACL denetimi
  (locale-proof broad-read/write); sayı 44 sabit
- Dev fingerprint (M6): 18 araç (Vite/webpack/Next/Nuxt/Angular/Django/
  Flask/Laravel/PHP/Express/Spring/Storybook/Jupyter/Grafana/api-docs/
  admin); strong tek başına yeter, weak 2 bağımsız ister (`admin`
  tek başına ve `invited`→vite artığı yok)
- Container/VM surface (M5): `docker ps` published-port mapping
  (host -> container + image + exposure), tek çağrılık inspect IP'leri,
  WSL portproxy forwarding; CLI yoksa graceful degrade; sayı 44 sabit
- Exposure model (M4): loopback-only / LAN-visible / all-interfaces /
  IPv6-visible / virtual-network-visible / unknown + firewall birleşimli
  verdict (CRITICAL asla otomatik değil); bağlı IP'den prob; check
  sayısı değişmedi (44)
- UDP discovery (M3): well-known port sınıflandırması (DNS/DHCP/mDNS/
  SSDP/NTP/SNMP/QUIC/oyun) + tek benign DNS probu (`.invalid`, reply
  varsa DNS kanıtlanır; version fishing yok); loopback INFO,
  LAN-visible LOW, bilinmeyen sessiz; exploit yok; sayı 44 sabit

- Windows netstat bugfix: yalnızca LISTENING satırları listener sayılır
  (ESTABLISHED/TIME_WAIT elenir), state korunur, IPv6 `[::]:port`
   desteklenir; Linux tcp6 parse (`::1`/`::` artık IPv4 gibi
   yorumlanmaz); IPv6 regression testleri

- Local enrichment (M2): listener kayıtları proto/ip/port/pid/process/
  exe/service/parent/scope/ipver/confidence/source taşır; Linux exe +
  parent + systemd/docker service (/proc), Windows PowerShell join
  (process + service + parent, netstat fallback); UDP endpointleri
  düşük confidence ile toplanır; fallback `source=connect-scan`
  damgalıdır; envanter INFO bulgusu; check sayısı değişmedi (44)

## v0.5.0 — 2026-10-08 (XSS Engine v2 + scanner hardening: 20 maddenin tamamı)

- Reporting + regression lab (öncelik-12): SARIF 2.1.0 + JUnit XML
  çıktıları (`-o` uzantıyla), Finding alanları (method/param/location/
  auth_context/fingerprint/confirm + registry check damgası), TXT
  Context satırı; `bench/lab.py` stdlib lab (20+ fixture, vulnerable/
  fixed çiftleri) + `tests/test_lab.py` regresyonu; README sync
  (stale "henüz yok" + roadmap düzeltmeleri)

- Upload expansion (öncelik-11): API JSON/base64 upload keşfi +
  served-marker kanıtı (CRITICAL), extension/content-type mismatch
  (LOW), traversal-filename reflection (LOW, yazım iddiası yok);
   hepsi deep-only benign; check sayısı değişmedi (44)

- GraphQL deep analysis (öncelik-10): `core/graphql.py` (şema parse,
  query/mutation ayrımı, required-argsız güvenli seçim kurucu, id ile
  nesne sorgusu); introspection check'i şemayı okuyor: mutasyon yüzeyi
  INFO (asla çalıştırılmaz), hassas-alan exposure MEDIUM, ikinci
   oturumla nested authz Confirmed; GET ?query= fallback; sayı 44 sabit

- Local machine audit (öncelik-9): `core/localaudit.py` salt-okunur
  profil (loopback'te otomatik, `--local` ile zorlanır); dinleyen
  portlar + süreç eşleme (/proc, netstat, connect-scan fallback),
  loopback HTTP banner sınıflama (vite/webpack/next/debug),
  secret izin denetimi (içerik asla okunmaz), firewall + container
  arayüz notları; check sayısı değişmedi (44)
- TLS audit (öncelik-8): yeni `tls-audit` check'i (read-only ≤3 handshake:
  expiry/mismatch/self-signed, TLS 1.0-1.1 teklifi, zayıf cipher);
  chain-of-trust bilerek kapsam dışı (private-CA lab FP'si); HTTP
  hedefler sessiz geçer; check sayısı 43 -> 44
- Browser traffic discovery (öncelik-7): `--browser-discovery` profili
  (request/WebSocket/response listener'ları: method + URL +
  content-type + status, SSE tespiti, route-watcher); özet saf
  `summarize_traffic()` ile havuza işlenir (socket'ler havuza girmez,
  graph'ta kalır); check sayısı değişmedi (43)
- DOM source/sink tamamlama (öncelik-6): location.assign/replace,
  window.open, iframe src/srcdoc, script src, document.domain hook'ları;
  aşamalı kaynak probu (load -> postMessage -> storage+reload ->
  referrer) ve erken çıkış; bulgular source -> sink zinciri + raw/
  filtered-or-text notu taşır; check sayısı değişmedi (43)
- IDOR/BOLA + authorization matrix (öncelik-5): `core/authz.py` motoru
  (path/query/JSON/header ref çıkarımı int/uuid/guid/slug, sibling
  N+1, canonical-JSON ownership karşılaştırma, auth-response
  sınıflandırma); idor/idor-param engine'e geçti (numeric başlıklar
  aynı); yeni `authz-matrix` check'i (anon-vs-user, uuid direct-access,
  admin-surface, cross-user confirmed); check sayısı 42 -> 43
- Baseline/differential engine (öncelik-4): `core/diff.py` ortak motor
  (status/length/normalized-HTML/canonical-JSON/title/visible-text/DOM/
  redirect/timing); IDOR `_bodies_differ`, soft-404 ve CSRF-scrub
  davranış-birebir delegasyonla geçti; timing helper'lar hazır;
  check sayısı değişmedi (42)
- API/body parameter engine (öncelik-3): `core/api_params.py`
  (recursive JSON flatten `user.role`, urlencoded/XML/GraphQL-variables/
  header/path extraction, shape-preserving leaf mutation, safe-mode
  gate); OpenAPI requestBody+parameters -> ApiTarget; deep-only JSON/XML
  body XSS probu (POST/PUT/PATCH/DELETE metodu korunur, hedef başına
  ≤2 alan, toplam ≤4 bulgu); check sayısı değişmedi (42)
- Discovery engine (öncelik-2): `core/discovery.py` birleşik pipeline
  (canonicalization, fetch/axios/XHR/WebSocket/SSE/API-client JS
  çıkarımı, `{id}/:id/[id]` REST params, api/page ayrımı, JSON config
  refs); `--profile quick|balanced|thorough` (explicit flag override'lar),
  thorough 30 sayfa + derin crawl + büyük havuzlar; havuz canonical
  dedupe'lu; check sayısı değişmedi (42)
- Check health / degraded scan (öncelik-1): `run_checks` her check için
  status kaydeder (passed/findings/skipped+reason/error+type/abort,
  elapsed_ms) ve hatayı verbose'suz da tek satır yazar; `run_scan(health=)`
  dışa taşır, terminal **SCAN DEGRADED** basar, raporlara `scan_health`
  eklenir, bulk `(degraded)` işaretler — çöken check varken "Clean" yok
- Bench: `bench/` precision/recall harness

- Bench: `bench/` precision/recall harness (DVWA + Juice Shop ground
  truth, negatif kontroller; `score.py` saf + `tests/test_bench.py`,
  `run_bench.py` canlı opt-in runner, `docker-compose.yml` hedefleri);
  scoring confirmed başlıkları sayar, unconfirmed/suspected'i honesty
  istatistiği olarak raporlar; CI'a dokunmaz (canlı hedef yok)
- P3 coverage

- P3 coverage: `core/xss_spa.py` opt-in `--spa` runtime keşfi (headless
  read-only: render link/form, Resource-Timing API endpoint'leri,
  `__NEXT_DATA__` route'ları; Playwright yoksa sessiz fallback),
  `--max-xss-urls` limitli + öncelikli havuz (form girdisi > hot param >
  API), FUZZ 16→60+ hidden/uncommon parametre, SPA/JS param adları
  fallback'a katılır; check sayısı değişmedi (42)
- P2 DOM oracle

- P2 DOM oracle: sink hook genişletme (innerHTML/outerHTML,
  insertAdjacentHTML, createContextualFragment, write/writeln, eval,
  Function, setTimeout/Interval-string, setAttribute event/URL, jQuery
  html/append) + `classify_sink()` saf kararı; sink'e ulaşmak tek başına
  confirmed değil: executable içerik `DOM XSS (confirmed — executable
  sink)` CRITICAL/High, düz marker `DOM XSS (suspected — controllable
  sink)` LOW/Medium, alert/confirm/prompt sarmalı + dialog/console
  dinleyiciler; hedef/bütçe/`--dom` sözleşmesi aynı
- P1 payload motoru

- P1 payload motoru: `core/xss_payloads.py` (context → confidence'lı
  payload, max 8; mutation: URL-encode/case/whitespace; filter probe
  listesi); `xss-reflected` stage-2 sadece unconfirmed context'te ≤4
  istek dener, bütçe korunur
- P1 stored second-order: field-unique canary, render taraması
  (action + crawl = A'da gir B'de çık), breaker probe ile karar:
  persistence-only `Stored reflection (unconfirmed)` LOW/Low,
  breakout `Possible Stored XSS` MEDIUM/Medium (eski CRITICAL/High
  düşürüldü); OOB `kind=xss` sözleşmesi aynı, şifreli form koruması aynı
- P0 reflection vs execution ayrımı

- Reflection vs execution ayrımı: `core/xss_context.py` (context tespiti:
  html-text, quoted/unquoted attribute, event-handler, url-attr, comment,
  js-string/expression/template, style, svg, json) + breaker-karakter
  kontrolü; ham yansıma tek başına XSS sayılmıyor
- `xss-reflected`/`POST XSS`: breakout yoksa `Reflected input (unconfirmed)`
  `LOW/Low`; breakout varsa `Possible Reflected XSS` `MEDIUM/Medium`
  (eski `High` confidence düşürüldü); check sayısı değişmedi (42)

## v0.4.0

- Detection depth: POST-body fuzzing for SQLi/XSS/SSTI/OS-command
  (deep only, password forms never touched); cross-session IDOR
  confirmation via `--cookie-b`/`--header-b`; UNION ORDER BY
  differential; DBMS fingerprinting; OOB-SQLi DNS exfiltration
- Proof upgrades: php://filter LFI confirmation, Azure + GCP metadata
  SSRF, MSSQL WAITFOR delay, Thymeleaf SSTI bundle, SVG upload
  verification, LDAP wildcard bypass, cache-poisoning surface
- Coverage: crawler POST forms, wider FUZZ params, dir backup mutations
  + extensions, broader JS secret sweep; CSP weakness + HSTS depth
  audit, CORS preflight + null-origin, X-Forwarded-Host fallback,
  reset-poisoning OOB proof, TRACE live confirm; 42 checks total
- Honesty hardening: dispatcher session-binding fix, 401/403 never
  exposure without content proof, PartialResults + INCOMPLETE reporting,
  429 storm caps, report-dir auto-create
- UX: live spinner + 429 countdown, modern 3-step wizard, Xmar1881
  branding in banner/menu/README/reports

## v0.3.0

- 39 security checks: injection (SQLi, OS command, CRLF, SSTI), XSS
  (reflected, stored, DOM), SSRF/IDOR, auth (login bypass, JWT, CSRF),
  modern web (CORS, open redirect, traversal, headers, methods, GraphQL,
  Firebase, Supabase, Next.js, WordPress), recon + BFS crawler
- Safe by default: aggressive checks (time-based, active POST, uploads,
  login tests) require explicit `--deep`
- Findings vs INFO observations (discovery never scores), confidence
  ratings, CWE/OWASP/CVSS enrichment
- Out-of-band verification via interactsh (`--oob`): proven Blind XSS
  and SSRF callbacks
- JSON/HTML/TXT reports with previous-scan diff, bulk scan with resume,
  scope allowlist, CI gate (`--fail-on`)
