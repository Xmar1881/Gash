# Changelog

## Unreleased

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
