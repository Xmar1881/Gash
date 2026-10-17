<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / Gash contributors
Modül: github.com/Xmar1881/Gash
Bu dosya Gash tasarım dokümanıdır; kod değildir.
Lisans metni için bkz. COPYING (Faz 2'de eklenecek) ve https://www.gnu.org/licenses/agpl-3.0.html
-->

# Gash — Mimari Tasarım (Faz 1)

- **Durum:** Faz 1 çıktısı — KOD YOK. Motor kodu, `go.mod`, Go implementasyonu yazılmadı.
- **Modül yolu (donduruldu):** `github.com/Xmar1881/Gash`
- **Lisans (donduruldu):** `AGPL-3.0-only` (SPDX). Tüm tasarım artefaktları bu lisansa tabidir.
- **Toolchain (Faz 0 D1'den devralındı):** `go1.26.8`, `go.mod` dili `go 1.26.0`, CI imajı `golang:1.26.8-bookworm`, `CGO_ENABLED=0`.
- **Kaynaklar:** `benioku.txt` (Gash spec) + `docs/design/00-scope.md` (Faz 0 kararları D1–D6, sorular S1–S5).
- **Faz kapısı:** Bu dosya + `docs/evidence-standard.md` + `proto/gash/v1/plugin.proto` sunulur, **DURULUR, onay beklenir.** Faz 2'ye geçilmez, kod yazılmaz.
- **Faz 0'dan sapma:** YOK. Tüm Faz 0 kararları (D1–D6) korunmuştur. S1–S5 varsayımları bu dosyada karara dönüştürülmüştür (detay §18); sapma değil, Faz 0'ın öngördüğü netleştirmedir. Sapma gerektiği düşünülen tek aday (modül yolundaki büyük harf `Xmar1881/Gash`) kullanıcı onayıyla aynen kabul edilmiştir — gerekçe §1.3'te.

---

## 0. Teslim formatı haritası (spec §10 uyumu)

| Teslim maddesi | Bu dosyadaki karşılığı |
|---|---|
| (1) Ne yapıldı | §0.1 |
| (2) Kararlar + gerekçeler (+ reddedilen alternatifler) | §1–§16 içindeki `Karar A-*` kutuları + özet §17 |
| (3) B1–B11 durumu | §19 |
| (4) Açık riskler / sorular | §20 (en fazla 5 soru) |

### 0.1 Ne yapıldı (Faz 1)

1. **Repo/modül/lisans tasarımı donduruldu** (§1): `github.com/Xmar1881/Gash`, AGPL-3.0-only, SPDX header konvansiyonu, `COPYING`/`NOTICE` planı, Tier 3 SDK lisans etkisi.
2. **Uçtan uca mimari donduruldu** (§2–§4): process modeli, katmanlar, engine orchestration/scheduler, Candidate→Verify→Finding hattı, confidence/severity türetimi.
3. **Baseline modeli tasarıma döküldü** (§5): soft-404/SPA, WAF/CDN/captcha, dinamik maskeleme, teknoloji parmak izi, `Untrusted` kapısı.
4. **Oracle kütüphanesi arayüzleri donduruldu** (§6): `Oracle` arayüzü sözleşmesi, 9 oracle'ın sorumluluk/params/`Evidence` yapısı, hata modeli.
5. **Plugin sistemi tasarıma döküldü** (§7): `PluginSpec` IR alan listesi + tutarlılık kuralları (rules.go tasarım karşılığı), JSON Schema tasarım notu, 3 tier loader, registry, `PolicySession` proxy, toposort, cache ≤150ms bütçesi.
6. **Tier 3 gRPC tasarımı donduruldu** (§8 + `proto/gash/v1/plugin.proto`): iki servisli sözleşme (`PluginRunner` + `HostCapabilities`), handshake, lifecycle, mTLS, multiplex, fail-closed kuralları. Generated kod YOK.
7. **OOB sunucu protokolü detayı donduruldu** (§9): self-hosted DNS+HTTP interaction, namespace, correlation ID, polling/push, `--oob-wait` penceresi, S1 kararı.
8. **Finding şeması + dedup/korelasyon + noisy-breaker + taint takibi donduruldu** (§10–§13).
9. **CLI yüzeyi donduruldu** (§14): `gash scan`, `gash plugins list|validate|test|new|trust|info`, `gash bench lab`, `gash suppress`, tüm bayraklar (safe/deep/active/auth/scope/max-requests/plugin-timeout/oob-server/oob-wait/show-tentative vb.).
10. **Reporter formatları donduruldu** (§15): json/sarif/text/html, SARIF eşlemesi (S3 kararı), tentative politikası.
11. **Config/dizin yapısı donduruldu** (§16): final ağaç, `~/.gash` layout, embed.FS, lab pinleri (S4 kararı).
12. **B1–B11'in Faz 1 karşılığı yazıldı** (§19): her kriter için tasarım karşılığı + Faz 2 doğrulama planı.
13. **Kanıt standardı ayrı dosyaya çıkarıldı:** `docs/evidence-standard.md` (§3.3'ün genişletilmiş hali). Bu dosya ona referans verir, tekrar etmez.

Kod, `go.mod`, `go.sum`, generated protobuf, JSON Schema dosyası, test — hiçbiri yazılmadı. `.proto` dosyası tasarımdır (IDL), implementasyon değildir.

---

## 1. Repo / modül / lisans tasarımı

### Karar A-01 — Modül yolu ve lisans

- **Modül:** `module github.com/Xmar1881/Gash` (büyük/küçük harf aynen; import örneklerinde hep bu yazım kullanılır).
- **Lisans:** `AGPL-3.0-only`. SPDX tanımlayıcı tüm dosyalarda: `SPDX-License-Identifier: AGPL-3.0-only`.
- **Go sürümü:** `go1.26.8` toolchain, `go 1.26.0` dil alt sınırı (Faz 0 D1 aynen).
- **Dosya header konvansiyonu (Faz 2'den itibaren zorunlu, CI grep kapısı):**
  - `.go` dosyaları: `// SPDX-License-Identifier: AGPL-3.0-only` + `// Copyright (C) 2026 Xmar1881 / GASH contributors` + `// Modül: github.com/Xmar1881/Gash`.
  - `.proto`, `.yaml`, `.js`, `.md` tasarım artefaktları: eşdeğer blok yorum (bu dosyanın başındaki HTML yorum gibi).
  - `COPYING` (AGPL-3.0 tam metni) + `NOTICE` (telif + üçüncü parti atıfları) + `REUSE.toml` (REUSE uyumu) Faz 2 repo iskeletinde eklenir.
- **Tier 3 public SDK (`pkg/gashsdk` planı):** Aynı lisans (`AGPL-3.0-only`), ayrı permissive lisans YOK.

**Gerekçe:**

1. Kullanıcı onayı (Faz 1 girdisi) org/modül + lisansı dondurdu; tartışma kapanmıştır (Faz 0 S5'in karşılığı).
2. AGPL-3.0, ağ üzerinden kullandırılan bir güvenlik tarayıcısında "SaaS olarak çalıştırıp değişikliği geri vermeme" deliğini kapatır — tarayıcıyı servis olarak sunanların da kaynak açmasını gerektirir. Topluluk katkısının tek yönlü sömürülmesini engeller; H1 (topluluk) ile tutarlıdır.
3. SDK'yı permissive (MIT/Apache) yapmak, çekirdeği AGPL tutup eklenti ekosistemini proprietary'ye açmak anlamına gelirdi — kanıt standardı (H2) lisans asimetrisiyle delinirdi (kapalı Tier 3 plugin'ler denetlenemez). Tek lisans, tek yükümlülük: sade ve dürüst.
4. SPDX + REUSE, SARIF/CI tüketicilerinin (kurumsal pentest, CI-DAST) lisans tarama araçlarıyla (FOSSA, ScanCode, GitHub dependency review) uyumludur.

**Reddedilen alternatifler:**

| Alternatif | Neden reddedildi |
|---|---|
| Apache-2.0 / MIT (permissive) | SaaS deliği açık kalır; topluluk katkısı kapalı servislere akar. Güvenlik aracında topluluk güveni için copyleft daha doğru. |
| GPL-3.0 (AGPL değil) | Ağ-kullanımı kapsamaz; CI-DAST/SaaS senaryosunda yükümlülük düşer. AGPL, GPL'in ağ karşılığıdır. |
| Dual-license (AGPL + ticari) | Faz 0 kapsam-dışı (market/imzalama altyapısı yok) ile çelişir; Faz 1'de hukuk/operasyon yükü getirir. Gelecek iş olarak not edilir, şimdi reddedilir. |
| SDK'yı MIT yapma | Lisans arbitrajı yaratır; kapalı Tier 3'lerin kanıt hattını bypass etme motivasyonu doğar. H2'ye aykırı. |
| Modül yolunu lowercase'e çevirme (`xmar1881/gash`) | GitHub URL'si `Xmar1881/Gash` iken modül yolunu farklı yazmak `go get` karışıklığı + dokümantasyon ikiliği yaratır. Go büyük harfli modül yollarını destekler (case-preserving); kullanıcı onayı varken değiştirmek için sebep yok. |

### 1.1 Dizin iskeleti kararı (özet; detay §16)

Faz 0'daki ağaç korunur; tek netleştirme: `proto/gash/v1/plugin.proto` eklenir, `pkg/gashsdk/` AGPL altında planlanır, `schemas/` Faz 2'de üretilir (Faz 1'de yalnızca tasarım notu, dosya YOK).

### 1.2 Üçüncü parti atıf politikası (tasarım)

- `cobra`, `goja`, `hashicorp/go-plugin`, `bbolt` (bkz. §7.7), `validator`, `yaml.v3`, `x/time/rate` — hepsi Faz 2'de `go.mod`'da pinlenir + `NOTICE`'ta listelenir.
- `chromedp` (ExecutionOracle, opsiyonel) build-tag arkasında tutulur (§6.8) — default binary'yi şişirmez, lisans taramasını kirletmez.

---

## 2. Genel mimari

### Karar A-02 — Process modeli ve katmanlar

- **Tek ana binary:** `gash` (`cmd/gash`). Tier 1/2 motor process'i içinde çalışır (Tier 2 goja VM sandbox'ında).
- **Ayrı process'ler:** (a) Tier 3 plugin'ler (bir plugin = bir OS process, gRPC), (b) OOB interaction sunucusu `gash-interactsh` (ayrı binary, ayrı deployment; tarama sırasında localhost veya iç ağda).
- **Ağ şeması:** Plugin → `probe.Send()` → `PolicySession` (`http.RoundTripper` sarmalayıcı) → hedef. Plugin asla ham soket açamaz (Tier 1/2'de API yok; Tier 3'te SDK `SendProbe`/`VerifyOracle` üzerinden host'a döner, bkz. §8).
- **Veri akışı tek yönlüdür:** `Plugin → Candidate → Oracle Verify → Finding → Correlate/Dedup → Reporter`. Geriye doğru akış yoktur (oracle baseline'ı değiştiremez, plugin finding yazamaz).

```
                    ┌──────────────────────────────────────────────────┐
                    │                   gash (tek binary)              │
                    │                                                  │
  ~/.gash/plugins/  │  ┌──────────┐  ┌───────────┐  ┌──────────────┐    │
  plugins/ (embed) ─┼─►│ Registry │─►│ Scheduler │─►│ Tier1/2 Exec │    │
                    │  │ +cache   │  │+toposort  │  │ +goja VM     │    │
                    │  └──────────┘  │+PolicySes.│  └──────┬───────┘    │
                    │               └─────┬─────┘         │Candidate   │
                    │                     │               ▼            │
                    │  ┌──────────┐  ┌────▼────────┐  ┌────────────┐    │
                    │  │ Baseline │◄─│Probe+Policy │◄─│Oracle lib  │    │
                    │  │ (Untrust)│  │ proxy (RT)  │  │ Verify()   │    │
                    │  └──────────┘  └─────┬───────┘  └─────┬──────┘    │
                    │                     │ hedef HTTP     │Evidence   │
                    │                     ▼                ▼            │
                    │               ┌────────────┐  ┌──────────────┐    │
                    │               │Correlate/  │◄─│Finding build │    │
                    │               │Dedup+Noisy │  │(internal)    │    │
                    │               └─────┬──────┘  └──────────────┘    │
                    │                     │ Finding[]                  │
                    │                     ▼                            │
                    │           ┌──────────────────┐                    │
                    │           │Reporter(json/    │                    │
                    │           │ sarif/text/html) │                    │
                    │           └──────────────────┘                    │
                    └──────────────────────────────────────────────────┘
                         ▲ gRPC (trust'lı)      ▲ polling/WebSocket
                         │ Tier3 process         │ OOB interaction
                    ┌────┴─────┐            ┌────┴──────────────┐
                    │Tier3 bin.│            │gash-interactsh     │
                    │(ayrı PID)│            │(DNS+HTTP, self-host)│
                    └──────────┘            └───────────────────┘
```

**Gerekçe:** Tek binary (dağıtım kolaylığı, `CGO_ENABLED=0` cross-compile) + ayrı process'lerde izolasyon (Tier 3 crash/kill, OOB ağ izolasyonu). Nuclei/ZAP/Burp mimarileriyle aynı ayrışma: çekirdek + izole eklenti + dış doğrulama kanalı.

**Reddedilen alternatifler:**

| Alternatif | Neden reddedildi |
|---|---|
| Monolit (Tier 3'ü de in-process) | Native kod host'u çökertir/kirletir; H2 ölür. |
| Mikroservis (her oracle ayrı servis) | Latency + dağıtım karmaşası; oracle'lar CPU/I/O hafif, in-process çağrı yeterlidir. |
| Plugin'in doğrudan HTTP açması | Bütçe/scope/rate-limit enforcement delinir (B6 ölür). Tüm trafik proxy'den geçer. |

---

## 3. Engine orchestration / scheduler

### Karar A-03 — Fazlar, sıralama, paralellik, bütçe

- **Fazlar (sabit sıra):** `recon → discovery → probe → deep`. `PluginSpec.Phase` bu enum'dandır. Fazlar arası barrier vardır (sonraki faz, öncekinin `provides` çıktılarını görür); faz-içi paralellik serbesttir.
- **Sıralama:** faz → `order` (küçük önce) → deterministik tie-break (`id` alfabetik). `requires`/`provides` topolojik sıralamaya girer (§7.6). Döngü = startup fail-closed (B-fail, tarama başlamaz, döngüdeki id'ler listelenir).
- **Paralellik modeli:** faz-içi worker pool (goroutine). Varsayılan paralellik: `min(2*GOMAXPROCS, 32)`; bayrak `--parallelism` ile ayarlanır (üst sınır `--max-requests-*` ve rate-limit ile çarpışırsa rate-limit kazanır — fail-closed).
- **Context yayılımı:** `context.Context` her çağrıya girer: `scanCtx (global timeout/cancel) → phaseCtx → pluginCtx (per-plugin --plugin-timeout) → probeCtx (per-request timeout)`. İptal yukarıdan aşağıya yayılır; Tier 2'de `vm.Interrupt`, Tier 3'te process kill'e çevrilir.
- **Bütçe enforcement:** `--max-requests-per-target`, `--max-requests-total` sayaçları `PolicySession`'da `atomic.Int64`; aşımda yeni `probe.Send()` reddedilir (`ErrBudgetExceeded`), plugin hata sayılmaz, `skipped (budget-exceeded)` olarak işaretlenir.
- **Sıfır plugin davranışı (B2):** registry boşsa scheduler boş döner, reporter geçerli boş rapor üretir (şema-geçerli `[]`, exit 0). Crash yok, uyarı basılır.
- **Phantom/ölü hedef:** DNS çözülmeyen / TCP açılmayan hedefte scheduler başlamadan `Unreachable` raporu üretir; plugin'ler hiç çağrılmaz (bütçe yakılmaz).

**Gerekçe:**

1. Faz-barrier + faz-içi paralel, hem determinizm (tekrar üretilebilirlik, CI-DAST) hem hız sağlar. Tam global paralel (fazsız) `provides`/`requires` yarışları yaratırdı.
2. `context` hiyerarşisi, Go'da deadline/iptalin tek doğru yoludur; Python taslağındaki thread-kill sorunu bu hiyerarşi + `Interrupt`/kill ile kapanır.
3. Bütçe sayaçlarının proxy'de atomik tutulması, kötü plugin'in `for(;;) probe.send()` ile hedefi/CI'ı yakmasını engeller (B5/B6'nın zaman boyutu).

**Reddedilen alternatifler:**

| Alternatif | Neden reddedildi |
|---|---|
| Tamamen sıralı çalıştırma | Yavaş (binlerce istek); H1'e değil ama kullanılabilirliğe aykırı. |
| Tamamen barriersız paralel | `requires` determinizmi kaybolur; aynı seed ile farklı sonuç (CI-DAST determinizmi ölür). |
| Bütçeyi plugin'e güvenme (beyan) | H2'ye aykırı; motor enforce eder. |
| Raylı sistem (her plugin'e eşit kota) | Keşif fazı ile deep faz aynı kotayı hak etmez; global + per-target + per-plugin (`MaxRequests`) üçlüsü daha adil. |

### 3.1 Scheduler lifecycle (tasarım, implementasyon değil)

```
Load → Validate(rules) → Toposort → PolicyFilter(safe/deep/auth/scope/oob) → BaselineFetch
  → for each phase: RunWorkers(pluginCtx) → Collect Candidates → Verify(oracles)
  → OOBWaitWindow (--oob-wait) → Correlate/Dedup/NoisyBreaker → Reporter → ExitCode
```

- `PolicyFilter`'da elenen plugin rapora `skipped (sebep)` olarak girer (sessiz drop YOK — denetlenebilirlik).
- `Verify` her candidate için senkron/oracle-sıralı yapılır; oracle'lar birbirini görmez (kirlenme yok).
- `OOBWaitWindow` yalnızca OOB'li candidate varsa uygulanır; yoksa 0 gecikme (CI determinizmi).

---

## 4. Candidate → Verify → Finding hattı

### Karar A-04 — Yetki ayrımı ve güven türetimi

- **Plugin yalnızca `Candidate` döner.** `Finding` struct'ının kurucusu `internal/` içindedir (küçük harf / internal alanlar); plugin API'sinde (YAML matcher, JS `host.*`, gRPC response) `confidence`/`severity` yazma alanı YOKTUR. Faz 2'de contract test (B3) bunu kilitler: yetkisiz alan set denemesi derleme/validasyon hatasıdır.
- **`Candidate` (tasarım alanları):** `plugin_id`, `target (URL)`, `injection_point`, `oracle_name`, `oracle_params_ref`, `raw_evidence_ref (response ids, OOB correlation id)`, `taint_labels`. Ağır body inline taşınmaz; response store'da id ile referanslanır (bellek şişmesi engeli).
- **`Evidence` (oracle çıktısı):** `verdict (accept/reject/inconclusive)`, `confidence_contribution`, `artifacts (maskelenmiş snippet, bağlam, timing dağılımı, kontrol karşılaştırması)`, `reproducibility (tekrar sayısı, seed)`. `Untrusted` baseline yanıtından gelen kanıt `verdict=reject`'e zorlanır (oracle bunu atlayamaz — arayüz ön adımı).
- **Güven türetimi (motor-içi, tablo):**

| Oracle sonucu | Tekrar/kontrol | Güven |
|---|---|---|
| OOB callback eşleşti (correlation ID + namespace) | 1+ (tek yeterli, kriptografik rastgele) | `confirmed` |
| Bağlamsal yürütülebilir yansıma (Reflection, script/attr bağlamı) | 1 + kontrol (temiz payload yansımıyor) | `confirmed` |
| Error imzası + kontrolde imza yok | 1 + kontrol | `confirmed` |
| Hesaplama kanıtı (SSTI `7*7=49`) + kontrolde yok | 1 + kontrol | `confirmed` |
| Differential true/false ayrışması, maskeleme sonrası | N=3, 3/3 tutarlı + kontrol | `confirmed` (OOB'siz) / `firm` (2/3 tutarlılıkta düşer) |
| Timing istatistiksel ayrışma + kontrol ayrışması | N≥3 + baseline jitter | `firm` (OOB'siz maksimum); OOB ile `confirmed` |
| DOM statik sink/source, headless yok | — | `firm` (maksimum) |
| Banner/version eşleşmesi, davranışsal doğrulama yok | — | `tentative` + `banner-based` etiketi |
| Blind probe, OOB yok, dolaylı sinyal | — | `tentative` (maksimum) |
| Kanıtsız / `Untrusted` / tutarsız | — | ret (finding yok) veya `tentative`'a düşürme yok — direkt eleme |

- **Severity türetimi:** `PluginSpec.Severity` (yazar beyanı) + oracle güveni + bağlam (örn. auth gerektiren → bir kademe notu). Yazar `critical` yazdı diye `critical/confirmed` çıkmaz; `tentative` ise severity tavanı `medium`'a iner (tasarım kuralı R-SEV-01, §7.1). Gerekçe: H2 — abartılı severity ile korku salma engeli.
- **Varsayılan rapor:** yalnızca `confirmed` + `firm`. `tentative` için `--show-tentative` gerekir (SARIF'ta `level: note` + ayrı kural, bkz. §15).

**Gerekçe:** Burp/ZAP/Nuclei'nin pasif/aktif ayrımından bir adım ileri: güven, kanıtın yeniden üretilebilirliğinden türetilir, yazarın iddiasından değil. `tentative` tavanı + severity tavanı, kötü plugin'in "kritik buldum" gürültüsünü yapısal olarak kısar.

**Reddedilen alternatifler:**

| Alternatif | Neden reddedildi |
|---|---|
| Plugin'e confidence/severity yazdırma | H2 ölür; kötü niyetli/abartılı plugin raporu kirletir. |
| Tek seviyeli (vuln/var-yok) | CI kapıları + bounty triyajı için yetersiz; `firm` ara kademesi timing/differential gerçekliğini yansıtır. |
| Skor (0-100 CVSS-benzeri) | Yanlış kesinlik hissi; GASH kanıt-odaklıdır, skor-odaklı değil. CVSS yalnızca SARIF `properties`'ta opsiyonel taşınır. |

---

## 5. Baseline modeli (`internal/baseline/` tasarımı)

### Karar A-05 — Tarama-öncesi gürültü parmak izi

Tarama başlamadan, plugin'lerden bağımsız, tek sefer çıkarılır; tüm `probe.Send()` dönüşleri otomatik `baseline.Classify()`'dan geçer:

1. **Soft-404 / SPA catch-all:** 3 rastgele path (`/__gash_<rand>__`, `/__gash_<rand>__.html`, `/api/__gash_<rand>__`) denenir. Kaydedilen imza: `status + body_hash (maskelenmiş) + uzunluk aralığı (±%10) + başlık iskeleti`. Sonraki 404-benzeri yanıtlar `Soft404: true` işaretlenir; path-traversal/dizin-keşif oracle'ları bunları kanıt sayamaz.
2. **WAF/CDN/captcha/rate-limit blok sayfası:** bilinen imza seti (örn. Cloudflare `cf-chl`, Akamai referans, Imperva/Incapsula marker'ları, reCAPTCHA/hCaptcha form iskeleti, `429` + `Retry-After`) + anormal pattern (tüm path'lerde aynı body hash). Eşleşen yanıt `Untrusted: true` — **hiçbir oracle kanıt sayamaz** (arayüz ön adımı, atlanamaz).
3. **Dinamik içerik maskeleme:** regex seti (CSRF token `name="csrf[^"]*" value="[^"]*"`, `nonce="[^"]*"`, ISO timestamp, UUID, `__VIEWSTATE`, JWT benzeri) + yapılandırılabilir ek maske (`--baseline-extra-mask`). Maskeleme hem baseline hash'inde hem Differential karşılaştırmasında aynı fonksiyonla uygulanır (tek implementasyon, iki kullanım — tutarlılık).
4. **Teknoloji parmak izi:** header (`Server`, `X-Powered-By`, `X-AspNet-Version`), favicon hash, cookie ismi, known-path (`/wp-json/`, `/_next/`, `/static/js/main.`). `requires_tech` filtresi burada uygulanır (ilgisiz plugin hiç çalışmaz — bütçe tasarrufu).
5. **Jitter baseline (TimingOracle girdisi):** N=5 kontrol isteği (aynı endpoint, zararsız), RTT dağılımı (medyan, p95, stddev). Timing kararı bu dağılıma göre verilir (§6.3).

**Gerekçe:** ZAP'ın "404'ü 200 dönen SPA" sorunu + Nuclei'nin WAF-FP sorunu, motor katmanında tek sefer çözülür; her plugin'in kendi "bu WAF mı" mantığı yazması (ve yanlış yazması) engellenir.

**Reddedilen alternatifler:**

| Alternatif | Neden reddedildi |
|---|---|
| Baseline'siz (her oracle kendi kontrolünü yapar) | N×WAF-imza maliyeti + tutarsızlık; kötü plugin kontrolü atlar. |
| ML-tabanlı blok sayfa sınıflandırıcı | Bağımlılık + determinizm kaybı; imza seti + pattern yeterlidir, açıklanabilirdir. |
| Kullanıcıdan manuel baseline isteme | H1'e aykırı (sürtünme); otomatik çıkarım varsayılan, `--baseline-override` yalnızca ileri düzey. |

---

## 6. Oracle kütüphanesi arayüzleri (`internal/oracle/` tasarımı)

### Karar A-06 — Tek `Oracle` sözleşmesi

Tasarım sözleşmesi (implementasyon değil; Faz 2'de `oracle.go`'ya dönüşecek):

- `Verify(ctx, probe, params) → (Evidence, error)`; `ctx` iptal/timeout taşır.
- Her oracle: kesin kanıt tanımı + kabul/ret koşulları (`docs/evidence-standard.md`'de sınıf başına) + birim testleri + Go arayüzü. Params `map[string]any` değil, tipli struct'tır (yanlış tip = validasyon hatası, sessiz `any` yok).
- Ortak ön adımlar (arayüz sarmalayıcıda, oracle'lar atlayamaz): (a) baseline `Classify` (`Untrusted` → `reject`), (b) taint kontrolü (`TaintedByPlugin` → ret, §13), (c) bütçe/timeout kontrolü.

| # | Oracle | Sorumluluk (özet) | Ana params (tasarım) | Güven tavanı |
|---|---|---|---|---|
| O-1 | `ReflectionOracle` | Benzersiz canary yansıması + bağlam analizi (html body / attr / script / url / encode durumu; basit HTML tokenizer, tam DOM render değil) | `canary`, `contexts[]`, `require_executable_context bool` | `confirmed` |
| O-2 | `DifferentialOracle` | true/false/kontrol üçlüsü, N=3 tekrar, maskeleme sonrası karşılaştırma; tutarsız = ret | `true_payload`, `false_payload`, `control_payload`, `repeats=3`, `mask_profile` | `confirmed` (3/3) / `firm` (kısmi) |
| O-3 | `TimingOracle` | Baseline jitter + istatistiksel test (Mann-Whitney U veya eşik+sapma; Faz 2'de testle seçilir), ≥3 tekrar, kontrol ayrışması zorunlu | `delay_payload`, `control_payload`, `repeats≥3`, `alpha=0.05`, `min_delay=5s` | `firm` (OOB'siz) |
| O-4 | `ErrorSignatureOracle` | Servis/DB imza kütüphanesi (regex seti `internal/signatures/`) + kontrolde imza yokluğu zorunlu | `signature_set`, `require_absent_in_control=true` | `confirmed` |
| O-5 | `OOBOracle` | Correlation ID + namespace üretimi, interaction polling, bekleme penceresi bağlama | `channel=dns|http`, `namespace`, `correlation_id`, `wait=--oob-wait` | `confirmed` |
| O-6 | `HeaderOracle` | Güvenlik header'larının varlığı/değeri (HSTS, CSP, X-Frame-Options vb.) | `header`, `expect`, `mode=absent|weak|malformed` | `confirmed` (mantık tabanlı) |
| O-7 | `RedirectOracle` | Gerçek `Location` parse + host karşılaştırması + DNS çözümü çift kontrolü | `payload_host`, `expect_external=true`, `resolve_dns=true` | `confirmed` |
| O-8 | `VersionOracle` | Banner + (varsa) davranışsal doğrulama; yoksa `tentative` + `banner-based` | `banner_regex`, `behavior_probe?` | `tentative` (davranışsız) |
| O-9 | `ExecutionOracle` | Headless tarayıcı (chromedp) ile gerçek JS yürütme kanıtı; yalnızca `--deep` + `dom-xss` | `sink`, `source`, `payload`, `headless_timeout` | `confirmed` |

Detaylı kabul/ret koşulları + örnek senaryolar: `docs/evidence-standard.md`.

### Karar A-06a — Timing istatistiği, HTML tokenizer, headless motoru

- **Timing:** varsayılan Mann-Whitney U (non-parametrik, jitter-dayanıklı); fallback basit eşik (`medyan_fark > 3*stddev && p95 ayrışması`). Hangisinin kullanılacağı Faz 2'de lab verisiyle seçilir; arayüz ikisini de taşır (strateji param).
- **HTML tokenizer:** `golang.org/x/net/html` tokenizer (parse ağacı değil, token stream) + bağlam makinesi (tag/attr/script/style/comment/url). Tam DOM render YOK (maliyet + determinizm).
- **ExecutionOracle motoru:** `chromedp` (saf Go CDP client). Build-tag `deep` arkasında; default build'te headless kodu derlenmez.

**Gerekçe:** Her üçünde de "yeterli doğruluk,最小 bağımlılık, determinizm" dengesi. `x/net/html` stdlib-komşu, `chromedp` cgo'suz, M-W U dağılım-varsayımsız.

**Reddedilen alternatifler:**

| Alternatif | Neden reddedildi |
|---|---|
| Timing'de sabit eşik (örn. ">2sn = vuln") | Gürültülü hedef/CI'da FP patlar; istatistik zorunlu. |
| Tam headless her XSS'te | Maliyet (saniyeler/bulgu) + CI'da tarayıcı bağımlılığı; yalnızca `dom-xss` + `--deep`. |
| Playwright/rod (ağır) | cgo/node bağımlılığı, cross-compile'ı bozar. |
| Regex ile HTML bağlamı | Kırılgan; tokenizer zorunlu (ama full DOM değil). |

---

## 7. Plugin sistemi

### 7.1 Tek doğruluk kaynağı: `PluginSpec` IR

#### Karar A-07 — Alan listesi (donduruldu)

| Alan | Tip | Zorunlu | Validasyon / enum | Açıklama |
|---|---|---|---|---|
| `id` | string | Evet | `slug` (`^[a-z0-9]+(-[a-z0-9]+)*$`, ≤64) | Global benzersiz; dosya adından bağımsız. |
| `name` | string | Evet | 3–120 karakter | İnsan-okunur ad. |
| `description` | string | Evet | 10–2000 karakter | Ne bulur, nasıl (OOB gerekiyorsa belirtir). |
| `author` | string | Hayır | serbest | Topluluk atfı. |
| `severity` | enum | Evet | `info\|low\|medium\|high\|critical` | Yazar beyanı; final severity motor tarafından tavanlanır (R-SEV-01). |
| `tags` | string[] | Evet (≥1) | küçük harf slug listesi | Örn. `xss`, `sqli`, `ssrf`, `redirect`; `dom-xss` ExecutionOracle'ı tetikler. |
| `safe` | bool | Evet | — | `true` ise yalnızca GET/HEAD/OPTIONS (proxy enforce). |
| `deep` | bool | Evet | — | `true` ise yalnızca `--deep` ile çalışır. |
| `active` | bool | Evet | — | `true` ise yalnızca `--active` ile çalışır (state-changing). |
| `requires_auth` | bool | Evet | — | `true` ise auth oturumu yoksa skip. |
| `requires_tech` | string[] | Hayır | slug listesi | Baseline tech eşleşmezse skip (bütçe dostu). |
| `max_requests` | int? | Hayır | ≥1, ≤10000 | Per-plugin kota; yoksa global bütçe geçerli. |
| `phase` | enum | Evet | `recon\|discovery\|probe\|deep` | Scheduler fazı. |
| `order` | int | Evet | 0–1000 | Faz-içi sıra (küçük önce). |
| `requires` | string[] | Hayır | mevcut `provides` id'leri | Toposort girdisi. |
| `provides` | string[] | Hayır | slug listesi | Toposort çıktısı (örn. `tech-fingerprint`). |
| `overrides` | string? | Hayır | mevcut `id` | Bilinçli built-in override (sessiz ezme yok). |
| `oob` | enum | Hayır (default `""`=yok) | `""\|optional\|required` | OOB gereksinimi; `required` + `--oob-server` yoksa hiç çalışmaz. |
| `api_version` | string | Evet | `^1\.0$` (Faz 1'de tek sürüm) | IR sürümü; uyumsuzluk = fail-closed. |
| `tests` | string? | Hayır | fixture dizin yolu | Boşsa bulgular `tentative` ile sınırlı (P6). |
| `tier` | enum (internal) | Motor set eder | `yaml\|js\|native` | Metadata'da YOK; yükleyici set eder. |

Tier-özel ek alanlar (IR dışı, loader'da): Tier 1 `request` + `oracle` blokları; Tier 2 frontmatter + `run()`; Tier 3 manifest `binary` + `protocol: grpc` + `sha256`. Bunlar IR'a derlenir; scheduler yalnızca IR görür.

#### Karar A-08 — Tutarlılık kuralları (rules.go tasarım karşılığı)

Tek kural kaynağı (`internal/plugin/rules.go` tasarım karşılığı — bu tablodur; Faz 2'de hem JSON Schema hem struct validator bundan üretilir/senkron tutulur):

| Kural | İfade | İhlalde |
|---|---|---|
| R-01 | `safe=true && active=true` → GEÇERSİZ | load-time ret + `validate` hatası |
| R-02 | `oob=required && active=false` → GEÇERSİZ | load-time ret (OOB invasive'dir) |
| R-03 | `oob=required && safe=true` → GEÇERSİZ | load-time ret |
| R-04 | `deep=true && phase != deep` → UYARI (hata değil) | `validate` uyarısı; scheduler `--deep` olmadan skip |
| R-05 | `severity=critical && safe=true` → UYARI | İnceleme önerisi (pasif kritik nadirdir; yasak değil) |
| R-06 | `tests=""` → bulgu tavanı `tentative` | Motor enforce (P6); `validate` uyarısı |
| R-07 | `id` çakışması + `overrides` yok → built-in kazanır, kullanıcı kopyası skip + stderr uyarısı | Sessiz ezme YOK |
| R-08 | `overrides` var ama hedef `id` yok → GEÇERSİZ | load-time ret (ölü override) |
| R-09 | `requires` içinde bilinmeyen `provides` → GEÇERSİZ | toposort öncesi ret |
| R-10 | `api_version != "1.0"` → GEÇERSİZ | fail-closed (POC handshake dahil) |
| R-11 | `max_requests` aralık dışı → GEÇERSİZ | load-time ret |
| R-12 | `phase=deep` ama `deep=false` → UYARI | Tutarsızlık; çalışır ama politika filtresi şaşırtır |
| R-SEV-01 | `tentative` bulguda final severity tavanı `medium` | Reporter enforce |
| R-OOB-01 | `oob=required` + `--oob-server` yok → hiç çalıştırma, sahte `tentative` YOK | Scheduler skip + sebep |
| R-OOB-02 | `oob=optional` + `--oob-server` yok → düşük-güven modu (OOB oracle çağrısı `skipped`) | Oracle guard |

**Gerekçe:** Kurallar motor-tarafı, tier-bağımsız, test-edilebilir. "Beyana güvenme" (P5) burada ete kemiğe bürünür.

**Reddedilen alternatif:** Kuralları her tier loader'a dağıtma — üç ayrı mantık, üç ayrı bug. Tek tablo, iki üretim (schema + validator).

### 7.2 JSON Schema tasarım notu

#### Karar A-09 — Single-source-of-truth yönü

- **Kaynak:** yukarıdaki alan listesi + R-kuralları (bu dosya). Faz 2'de `internal/plugin/rules.go` yazılır; `schemas/plugin.schema.json` (JSON Schema 2020-12) ondan **üretilir** (el ile çift bakım YOK). Üretim yönü tek: `rules.go → schema.json` (+ `schema_test.go` senkron kontrolü: schema ile validator aynı fixture setinde aynı kararı vermeli).
- **Tier 1 YAML/JSON** schema ile doğrulanır; **Tier 2/3** aynı kurallar Go `validator` tag'leriyle zorlanır. İki sunum, tek kural seti.
- **Sürümleme:** `api_version: "1.0"` Faz 1'de tek sürüm. Schema `$id`: `https://gash.dev/schemas/plugin-1.0.json` (dokümantasyon URL'si; fetch edilmez, offline validasyon).
- **Matcher whitelist (Tier 1):** yalnızca `status/word/regex/header` + `oracle:` referansı; kod bloğu/`eval`/`script` anahtarı schema'da `additionalProperties: false` + `not` ile yasaklanır.

**Reddedilen alternatifler:** Schema-first (önce JSON yaz, Go'yu uyarla) — Go tipleri daha katı (slug regex, enum, çapraz-alan R-01..R-03 JSON Schema'da `if/then` ile kırılgan); code-first üretim daha sağlam. Çift-el-bakımı — senkron kayması kaçınılmaz, reddedildi.

### 7.3 Keşif ve yükleme (3 tier loader tasarımı)

#### Karar A-10 — İki aşamalı keşif + lazy init

- **Aşama 1 — metadata taraması (import/execute ETMEDEN):** Tier 1: YAML/JSON metadata bloğu (`yaml.v3`); Tier 2: dosya başı sabit frontmatter (`/* --- ... --- */`), goja VM başlatılmaz; Tier 3: ayrı `.gashplugin.yaml` manifest (binary'ye dokunulmaz, çalıştırılmaz). Sabit frontmatter formatı Faz 2'de `validate` ile kilitlenir (varyant kabul edilmez — parser basitliği).
- **Aşama 2 — lazy init:** politika filtresinden geçenler yüklenir (Tier 2: goja evaluate bir kez; Tier 3: registry'ye kayıt, spawn ilk çağrıda).
- **Sıra:** built-in (`plugins/`, `embed.FS`) → `~/.gash/plugins/` → `GASH_PLUGIN_PATH` (`:`/`;` ayraçlı). Deterministik alfabetik, recursive. `overrides` yoksa built-in kazanır (§7.1 R-07).
- **Güvenlik kapıları (loader'da):** Tier 1/2 world-writable dosya/dizin reddi (`0002` bit kontrolü, uyarı + skip); Tier 3'te `trust` + `sha256` olmadan registry'ye "çalıştırılabilir" olarak girmez (yalnızca `untrusted` listeleme).

**Gerekçe:** Warm-keşif bütçesi (≤150ms) yalnızca metadata parse + cache-hit ile tutturulur; VM/process bu bütçeye dahil değildir.

**Reddedilen alternatif:** Eager-load (tüm VM'leri başlat) — 100 plugin'de saniyeler; bütçe ölür. Tek-aşamalı (metadata+execute bir arada) — güvenilmeyen kodu filtre öncesi çalıştırır; tehdit modeline aykırı.

### 7.4 Registry tasarımı

- `Registry`: `id → PluginSpec + loader_ref + trust_state + skip_reason`. Salt-okunur snapshot scheduler'a verilir (yarış yok).
- `plugins.db` cache: `path → (mtime, sha256, parsed_metadata)`. Cache-hit'te dosya okunmaz (stat dışında). Cache-bypass bayrağı `--no-plugin-cache` (debug).
- `gash plugins list/info` registry snapshot'ını okur (çalıştırma yok).

### 7.5 Politika motoru (`PolicySession` proxy tasarımı)

#### Karar A-11 — `http.RoundTripper` sarmalayıcı

Tüm `probe.Send()` bu proxy'den geçer:

- `safe=true` + `POST/PUT/PATCH/DELETE` → `ErrPolicyViolation` (`PluginResult{PolicyError}`, tarama durmaz).
- Sayaçlar: per-plugin (`MaxRequests`), per-target, total — `atomic.Int64`. Aşım → `ErrBudgetExceeded` (skip, hata değil).
- Scope: `--scope` CIDR/domain allowlist opsiyonel opt-in sıkı moddur; verilirse dışı → `ErrScopeViolation`, DNS rebinding'e karşı resolve edilen IP de allowlist'te olmalı. Verilmezse open mod: yazılımsal host engeli yok (redirect/crawl takibi serbest, operatör sorumluluğu).
- Rate-limit: `x/time/rate` token-bucket (per-target). `--rate-limit` (req/s, default 10).
- Auth: `requires_auth` Cookie/header jar yalnızca auth'lu session'da enjekte edilir; auth'suz plugin jar'ı göremez.
- Boyut/timeout: response cap (`--max-response-bytes`, default 5MB), per-request timeout (default 15s), redirect limiti (max 5, `Location` zinciri loglanır).

**Reddedilen alternatif:** Plugin'e ham `http.Client` verme — enforcement delinir. Merkezi proxy tek doğru nokta.

### 7.6 Toposort tasarımı

- Kahn algoritması (deterministik: hazır kuyruğu `order`+`id` sıralı). Girdi: `phase` grupları içinde `requires`/`provides` kenarları. Fazlar arası kenar yasak (faz-barrier ihlali) → validasyon hatası.
- Döngü tespiti zorunlu; döngü varsa motor başlamadan hata + döngüdeki id'ler + kırma önerisi (`--ignore-plugin` ile hariç tutma).

### 7.7 Cache ≤150ms tasarımı

#### Karar A-12 — Backend ve bütçe

- **Backend:** `go.etcd.io/bbolt` (eski `boltdb`; saf Go, `CGO_ENABLED=0` uyumlu, tek dosya `~/.gash/cache/plugins.db`).
- **Anahtar:** `sha256(path + mtime_ns + api_version)`. Değer: serialize edilmiş metadata + validasyon sonucu.
- **Bütçe dağılımı (warm, 100 plugin varsayımı):** stat(100 dosya) ~20ms + bbolt read ~10ms + deserialize ~30ms + conflict/topo ön-hesap ~20ms = ~80ms; kalan 70ms headroom. Cold (ilk çalıştırma) bütçeye dahil DEĞİL (dokümante).
- **Ölçüm:** `go test -bench=BenchmarkWarmDiscovery` + CI regresyon (eşik aşımı = fail).

**Gerekçe / reddedilen:** `modernc.org/sqlite` (cgo'suz SQLite) değerlendirildi — SQL esnekliği avantaj, ama bbolt'un tek-key okuma latensi + sıfır-sorgu basitliği warm-bütçe için daha uygun; SQL şema migrasyonu yükü yok. `sqlite` (cgo'lu) cross-compile'ı bozar — elendi.

### 7.8 Yürütme ve hata izolasyonu

- Her çağrı `recover()` + `context.WithTimeout(--plugin-timeout, default 30s)`. Tier 2: `vm.Interrupt` (gerçek kesme); Tier 3: `SIGTERM → grace (5s) → SIGKILL` + `Client.Kill()` her yolda.
- Yanlış dönüş (`[]Candidate` dışı), panic, timeout → `PluginResult{Error}`; scheduler devam (B7). Raporda çalıştırma özeti: `loaded / skipped(sebep) / errored(sebep)`.

---

## 8. Tier 3 gRPC tasarımı

### Karar A-13 — Tek protokol (gRPC), iki servis, fail-closed

- **Taşıma:** yalnızca gRPC (`hashicorp/go-plugin` v1.8.0 üzerinden; `net/rpc` modu yasak). `AutoMTLS` açık, loopback-only dinleme.
- **Proto:** `proto/gash/v1/plugin.proto` (bu Faz'da donduruldu; generated kod YOK). Paket `gash.v1`, Go import `github.com/Xmar1881/Gash/proto/gash/v1`.
- **İki servis (tek `.proto`):**
  - `PluginRunner` (host → plugin): `GetMetadata`, `Run`, `HealthCheck`. Plugin `Candidate` döner, `Finding` dönemez (mesajda alan YOK — B3 proto seviyesinde).
  - `HostCapabilities` (plugin → host, brokered): `SendProbe`, `VerifyOracle`, `GetBaseline`, `Log`. Plugin'in ağ/oracle erişimi yalnızca bu servistir; doğrudan soket/sandbox-dışı çağrı SDK'da YOKTUR.
- **Handshake:** `api_version ("1.0") + plugin id + sha256 (manifest pin)`; uyumsuzluk → spawn yok, fail-closed + rapor sebebi.
- **Lifecycle:** lazy spawn (ilk çağrıda), long-lived process (çoklu `Run` multiplex, HTTP/2), per-call timeout, scan sonunda `Kill`. Asılı plugin taramayı kilitleyemez (timeout→kill zinciri).
- **Trust:** `gash plugins trust <manifest>` sha256 pinler (`~/.gash/trust.db`); `--strict-plugins`'te trust'suz binary asla exec edilmez (B10). Manifestteki `binary` yolu allowlist dışıysa fail-closed.
- **Trust File Migration (S1):** default `~/.gash/trust.db`'dir; legacy `~/.gash/trust.json` varsa ilk default kullanımda otomatik okunur ve bozmadan `trust.db`'ye kopyalanır. `GASH_TRUST_FILE` / `--trust-file` override korunur ve migration tetiklemez.
- **Modül izolasyonu:** Tier 3 + gRPC bağımlılıkları build-tag `tier3` arkasında; Tier 1/2-only build şişmez (R-T3-6 karşılığı).
- **SDK (`pkg/gashsdk`, Faz 3):** Go-first; stdout yazma yasak (handshake bozulması engeli), log yalnızca `HostCapabilities.Log` üzerinden. Sözleşme dil-bağımsız (S2 kararı); Python örneği POC dışı.

**Gerekçe:** `go-plugin`'in 10 yıllık handshake/crash/mTLS birikimini yeniden icat etmemek (Faz 0 D4). İki-servisli tasarım, Tier 3'ü de `PolicySession`/oracle hattına tabi kılar — native hız, ama kanıt standardından muafiyet yok (H2).

**Reddedilen alternatifler:** Bkz. Faz 0 D4 tablosu (`.so`, el yapımı stdio-RPC, `net/rpc`, WASM) — kararlar değişmedi. Ek Faz 1 reddi: tek-yönlü (host→plugin) proto + plugin'e ham HTTP izni — B6/B5 delinirdi.

---

## 9. OOB sunucu protokolü detayı

### Karar A-14 — Self-hosted DNS+HTTP, interactsh-uyumlu client, ayrı binary Faz 3+ (S1 kararı)

Faz 0 S1'in Faz 1 karşılığı: **protokol dondurulur, sunucu Faz 3+.** Faz 2'de OOB client, self-hosted `interactsh` (ProjectDiscovery) ile uyumlu çalışır; `cmd/gash-interactsh` ayrı binary'si Faz 3+ iş olarak planlanır (tekerlek icadı yok). Protokol, iki tarafa da uyacak şekilde tanımlanır:

#### 9.1 Adresleme ve namespace

- OOB sunucusu: `--oob-server https://oob.iç-ağ.example` (TLS zorunlu; `--oob-token` ile auth). Public `interactsh.sh` varsayılan DEĞİL (kapsam/NDA riski); kullanıcı açıkça verirse uyarı basılır.
- Scan namespace: `<scan-id>.<domain>`; scan-id 128-bit kriptografik rastgele (`scan_<hex16>`). Her correlation ID bu namespace altındadır: `<corr-id>.<scan-id>.<domain>` (DNS) veya `https://<domain>/s/<scan-id>/c/<corr-id>` (HTTP).
- Correlation ID: per-candidate unique (`c_<hex12>`); payload'a enjekte edilen tek değerdir (tahmin edilemez, kaba-kuvvet dayanıklı).

#### 9.2 Interaction kaydı ve korelasyon

- Sunucu her DNS/HTTP isabeti kaydeder: `(correlation_id, namespace, timestamp, remote_ip, protocol, raw_request_headers)`.
- Motor polling yapar: `GET /api/v1/poll?scan=<scan-id>&since=<cursor>` (token auth, 5sn aralık, jitter'lı) veya WebSocket push (`/api/v1/stream`, varsa; yoksa polling'e düşer — ikisi de proto'da tanımlı, client otomatik seçer).
- Eşleşme: `correlation_id + namespace` birebir; namespace dışı isabetler yok sayılır (başka scan'in gürültüsü bulaşmaz).
- **Zorlama:** OOB callback tek başına `confirmed` için yeterlidir (ID tahmin edilemez olduğu için); ek kontrol isteği gerekmez (ama noisy-breaker/taint kontrolleri yine uygulanır).

#### 9.3 Bekleme penceresi (`--oob-wait`)

- Scan sonunda, OOB'li candidate varsa sabit pencere beklenir: `--oob-wait` (default 60s, 0–600s aralığı). Pencerede gelen interaction ilgili candidate'a bağlanıp `confirmed`'a yükseltilir; rapor bu kadar gecikmeli finalize edilir.
- OOB'siz scan'de pencere 0'dır (CI determinizmi). `--oob-wait 0` açıkça verilirse OOB'li candidate'lar `tentative`'ta kalır + raporda `oob-wait-skipped` notu (dürüstlük).
- CI-DAST profili: OOB kapalı + OOB-sınıfları kapsam dışı (determinizm); pentest: iç-ağ OOB + `--oob-wait` ayarlı; bounty: kullanıcı kendi sunucusunu kurarsa açılır (bkz. Faz 0 D5 matrisi).

#### 9.4 Güvenlik ve politika

- OOB gerektiren plugin'ler `active:true, safe:false` ZORUNLU (R-02/R-03); `--oob-server` yoksa `oob:required` hiç çalışmaz, `oob:optional` düşük-güven moduna geçer (R-OOB-01/02, B9).
- Sunucu auth'suz dinlemez; token `GASH_OOB_TOKEN` env veya `--oob-token` (flag > env; ikisi yoksa sunucu reddeder — fail-closed).
- Egress denetimi: hedefi dışarıya istek atmaya zorlamak invasive'dir; `--active` olmadan OOB payload'u gönderilemez (PolicySession enforce).

**Reddedilen alternatifler:**

| Alternatif | Neden reddedildi |
|---|---|
| Public interactsh varsayılan | Hedef verisi üçüncü partiye akar (kapsam/NDA ihlali); sessiz phone-home. |
| Sıfırdan sunucu Faz 2'de | Tekerlek icadı; interactsh olgun + self-hostable. Ayrı binary Faz 3+. |
| Push-only (WebSocket zorunlu) | Kurumsal egress/proxy'de WS kırılır; polling fallback zorunlu. |
| Sonsuz bekleme (callback gelene kadar) | CI kilitlenir; sabit pencere + dürüst `tentative` daha doğru. |

---

## 10. Finding şeması

### Karar A-15 — SARIF-uyumlu, GASH-ID birincil (S3 kararı)

Faz 0 S3'ün karşılığı: **`GASH-XXX` birincil `ruleId`, CWE ikincil (`taxa`)**. Örn. `GASH-001` (reflected XSS) ↔ `CWE-79`.

Tasarım alanları (implementasyon değil):

| Alan | Kaynak | Not |
|---|---|---|
| `id` | motor | `finding_<hex12>`; suppress anahtarı. |
| `rule_id` | motor | `GASH-XXX` (sabit taksonomi, `docs/evidence-standard.md`'de sınıf başına). |
| `cwe` | motor | `CWE-79` vb.; yoksa `null` (misconfig sınıfları). |
| `title`, `description` | motor (şablon) | Plugin `name`/`description`'dan değil, kural şablonundan (abartı engeli). |
| `severity` | motor-türetilmiş | `info/low/medium/high/critical`; `tentative` tavanı `medium` (R-SEV-01). |
| `confidence` | motor-türetilmiş | `confirmed/firm/tentative`. |
| `target`, `injection_point` | candidate | Maskelenmiş (secret sızıntısı engeli). |
| `evidence` | oracle | `Evidence` özeti (snippet maskeli, tekrar sayısı, OOB correlation id hash'i). |
| `reproducibility` | oracle | `repeats`, `seed`, `control_result`. |
| `taint`, `suppressed`, `fingerprints` | motor | §11–§13. |
| `tags`, `references` | motor | CWE URL, kural dokümantasyonu. |
| `plugin_id`, `oracle_name` | motor | İzlenebilirlik (hangi plugin/oracle üretti). |

- PII/secret maskeleme: evidence snippet'lerinde `Authorization`, `Cookie`, `Set-Cookie`, token pattern'ları redact edilir (reporter katmanında, ham store'da değil).
- `tentative` bulgular varsayılan raporda YOK (yalnızca `--show-tentative`).

**Reddedilen alternatif:** Yalnızca CWE `ruleId` — GASH-özgü sınıflar (örn. SPA-catch-all ayrımı, `banner-based` varyantları) CWE'de birebir yok; GASH-ID birincil, CWE ikincil daha dürüst.

---

## 11. Dedup / korelasyon

### Karar A-16 — Motor-tarafı normalize + fingerprint

- **Normalize:** URL (query sırası, trailing slash, default port, fragment düşürme), injection point (param adı + yöntem), evidence (maskeleme sonrası hash).
- **Fingerprint:** `sha256(rule_id + normalized_target + injection_point + evidence_hash)`. Aynı fingerprint → tek finding (çoklu plugin aynı bulguyu şişirmez).
- **Korelasyon:** aynı `(rule_id, host, path)` farklı param'larda → grup finding (`occurrences[]`); farklı `rule_id` aynı evidence → en yüksek güvenli olan kazanır, diğeri `duplicate_of` ile bastırılır.
- **SARIF:** `fingerprints` alanına yazılır; `suppressions` ile entegre (suppress fingerprint'e bağlanır, satır numarasına değil — kod değişse de suppress yaşar).

**Gerekçe:** Dedup plugin'de değil motorda (B5); fingerprint satır-bağımsız (CI stabilitesi).

**Reddedilen:** Satır-tabanlı dedup (SARIF default) — tarayıcı çıktısında satır yok; URL+kanıt daha stabil.

---

## 12. Noisy-breaker

### Karar A-17 — Eşik + demote + rapor notu

- Aynı `Evidence` hash'iyle (maskelenmiş) N>10 endpoint'te (default `--noisy-threshold 10`, 1–1000) aday üreten plugin → `demoted`: kalan adayları `tentative`'a düşer + scheduler o plugin'e yeni probe kotası vermez (mevcut faz sonunda durur).
- Raporda `noisy plugin` notu (plugin id + eşik + örnek fingerprint). Demote, diğer plugin'lerin bulgularını değiştirmez (B5).
- Eşik yapılandırılabilir; `--noisy-threshold 0` = devre dışı (önerilmez, uyarı basılır).

**Reddedilen:** Sessiz drop (uyarısız) — denetlenebilirliğe aykırı. Tam kill (plugin'i abort) — faz-içi yarışlarda determinizm bozulur; demote daha yumuşak ve deterministik.

---

## 13. Taint takibi

### Karar A-18 — Etiket + oracle-seviyesi ret

- Aktif plugin'in bıraktığı iz (stored canary, oluşturduğu kayıt, değiştirdiği state) `TaintedByPlugin: <id>` etiketlenir (motor store'unda, plugin'in göremeyeceği alan).
- Başka plugin'in oracle çağrısında tainted yanıt kanıt olarak kullanılamaz — oracle ön adımı ret verir. Kendi taint'ini kanıt saymak da yasak (self-confirm engeli).
- Taint TTL: scan-sonu temizlenir (kalıcı değil); rapor taint'li eleme sayısını gösterir (şeffaflık).

**Reddedilen:** Taint'siz (her yansıma kanıt) — stored-XSS self-confirm FP patlar. Kalıcı taint (diskte) — scan'ler arası bulaşma; TTL'siz taint reddedildi.

---

## 14. CLI yüzeyi

### Karar A-19 — cobra ağacı (Faz 0 D2'nin Faz 1 karşılığı)

```
gash
├── scan                # tarama
├── plugins
│   ├── list            # registry snapshot (çalıştırma yok)
│   ├── validate <file> # schema + rules kontrolü
│   ├── test <file>     # fixture çalıştırma (positive+negative)
│   ├── new <ad>        # iskelet üretimi (--tier yaml|js)
│   ├── trust <manifest># Tier 3 allowlist + sha256 pin
│   └── info <id>       # metadata + skip sebebi + trust durumu
├── bench
│   └── lab             # recall lab (DVWA/JuiceShop/WebGoat, §16.3)
└── suppress
    ├── add <finding-id>
    ├── list
    └── remove <finding-id>
```

- `cmd/gash/main.go` ince (yalnızca `Execute()`); tüm mantık `internal/` paketlerde (test edilebilirlik, D2).
- Completion + man: `gash completion <bash|zsh|fish|powershell>`, `gash man` (cobra out-of-the-box).
- Exit kodları: `0` temiz (bulgu olsa da 0; bulgu = hata değil), `2` validasyon/policy hatası, `3` `firm`+ bulgu (yalnızca `--fail-on firm` ile, CI kapısı), `4` iç hata (panic değil, kontrollü).

#### 14.1 Global ve komut bayrakları (donduruldu)

| Bayrak | Komut | Default | Açıklama |
|---|---|---|---|
| `--safe/--no-safe` | scan | `true` | Varsayılan safe; kapatmak açık opt-out (uyarı basılır). |
| `--deep` | scan | `false` | Deep faz + ExecutionOracle kapısı. |
| `--active` | scan | `false` | State-changing/OOB payload kapısı. |
| `--auth-session <file>` | scan | — | Cookie/header jar; `requires_auth` plugin'ler için zorunlu. |
| `--scope <cidr/domain,...>` | scan | — | Opsiyonel opt-in sıkı allowlist; verilmezse open mod (host engeli yok, operatör sorumluluğu; redirect/crawl any-host izlenir). |
| (`--scope` verilince strict) | scan | — | Allowlist + DNS-rebinding reddi; http→https upgrade izinli, https→http downgrade asla, kapsam-dışı subdomain/registrable-domain reddi. Gerekçe/etki: strict modda upgrade gizliliği korunur, downgrade MITM'e açacağı için yasak; open modda hiçbiri bloklanmaz. |
| `--max-requests-per-target` | scan | 1000 | Per-target bütçe. |
| `--max-requests-total` | scan | 10000 | Global bütçe. |
| `--plugin-timeout` | scan | 30s | Per-plugin timeout (Tier 2 Interrupt, Tier 3 kill). |
| `--request-timeout` | scan | 15s | Per-request timeout. |
| `--max-response-bytes` | scan | 5MB | Response cap (zip-bomb engeli). |
| `--rate-limit` | scan | 10/s | Per-target rate. |
| `--parallelism` | scan | auto | Worker sayısı (üst sınır). |
| `--oob-server <url>` | scan | — (kapalı) | Self-hosted interaction sunucusu; yoksa OOB kapalı. |
| `--oob-token <tok>` | scan | `$GASH_OOB_TOKEN` | Sunucu auth. |
| `--oob-wait` | scan | 60s | Scan-sonu bekleme penceresi (0–600s). |
| `--show-tentative` | scan, reporter | `false` | Tentative'i rapora dahil et. |
| `--format <json|sarif|text|html>` | scan | `text` (terminal) | Tekrarlanabilir (çoklu çıktı). |
| `--output <file>` | scan | stdout | Format başına (`-o sarif:rapor.sarif`). |
| `--fail-on <level>` | scan | — | CI kapısı (`firm`/`confirmed`). |
| `--no-plugin-cache` | scan, plugins | `false` | Cache bypass (debug). |
| `--noisy-threshold` | scan | 10 | Noisy-breaker eşiği. |
| `--strict-plugins` | scan | `false` | Yalnızca trust'lı Tier 3 (kurumsal/CI önerilir). |
| `--tier <yaml|js|native>` | plugins new | `yaml` | İskelet tipi. |
| `--ignore-plugin <id,...>` | scan | — | Döngü kırma / gürültü susturma (rapora işlenir). |

PD `goflags` konvansiyonlarıyla uyum (Faz 0 D2 notu): bayrak isimleri Nuclei/httpx kullanıcılarına tanıdık (`-target`, `-o`, `-silent` alias'ları cobra'da shim olarak tanımlanır; birincil isimler yukarıdakilerdir).

**Reddedilen alternatifler:** `--load-plugin/--enable` (H1'e aykırı; otomatik keşif varken manuel bayrak sürtünmedir). `--oob-server`'a public default (güvenlik, §9). Exit=1 her bulguda (CI'da gürültü; `--fail-on` daha hassas).

---

## 15. Reporter formatları

### Karar A-20 — SARIF birincil sözleşme, dördü de desteklenir

| Format | Hedef | İçerik politikası |
|---|---|---|
| `sarif` (v2.1.0) | CI-DAST (GitHub/GitLab code scanning) | `ruleId: GASH-XXX`, `taxa: CWE`, `level`: `confirmed→error`, `firm→warning`, `tentative→note` (yalnızca `--show-tentative`), `fingerprints`, `suppressions`, `invocations` (çalıştırma özeti). |
| `json` | Otomasyon/pipe (bounty, PD araçlarıyla birlikte çalışma) | Tam Finding[] + `scan_meta` + `skipped_plugins` + `stats`. Şema-geçerli, deterministik sıralı. |
| `text` | Terminal (bounty hızlı triyaj) | İnsan-okunur, renkli (non-TTY'de renksiz), `tentative` gizli. |
| `html` | Paydaş (pentest rapor eki) | Tek dosya, inline CSS, PII-redact'li evidence, suppress notu. |

- Sıfır plugin / sıfır bulgu: geçerli boş rapor (B2) — SARIF'ta boş `results[]`, text'te `0 findings` özeti.
- Bastırılanlar: ayrı sayaç (`suppressed: N`), detay gizli değil (denetlenebilirlik).
- `gash suppress`: yerel `.gash-suppress.yaml` (fingerprint anahtarlı); reporter bastırma uygular + sayıyı gösterir.

**Reddedilen:** Yalnızca JSON (CI entegrasyonu zayıflar). Markdown birincil (SARIF varken gereksiz; HTML paydaşı kapatır). `tentative`'i SARIF'a varsayılan yazma (CI gürültüsü; `note` + flag'li).

---

## 16. Config / dizin yapısı

### Karar A-21 — Final ağaç (Faz 1 dondurması)

```
gash/  (module github.com/Xmar1881/Gash, AGPL-3.0-only)
├── COPYING / NOTICE / REUSE.toml        # Faz 2'de eklenecek (tasarım burada)
├── cmd/
│   ├── gash/main.go                     # ince entrypoint (Execute only)
│   └── gash-interactsh/main.go          # Faz 3+ (Faz 2'de YOK; client interactsh-uyumlu)
├── internal/
│   ├── engine/                          # orchestration, scheduler, correlate.go
│   ├── baseline/                        # gürültü/WAF/soft-404 modeli
│   ├── oracle/                          # 9 oracle + Evidence tipi + signatures/
│   ├── plugin/
│   │   ├── spec.go                      # PluginSpec IR (A-07)
│   │   ├── rules.go                     # tek kural kaynağı (A-08)
│   │   ├── loader/                      # tier1_yaml.go, tier2_js.go, tier3_native.go
│   │   ├── registry.go / policy.go / toposort.go / errors.go
│   ├── probe/                           # HTTP client + canary + response store
│   ├── finding/                         # Finding builder (internal) + fingerprint
│   ├── reporter/                        # json, sarif, text, html
│   └── oob/                             # interactsh-uyumlu client + correlation
├── pkg/gashsdk/                         # Tier 3 public SDK (Go-first, AGPL; Faz 3)
├── plugins/                             # built-in (embed.FS)
├── proto/gash/v1/plugin.proto           # DONDURULDU (bu Faz; generated YOK)
├── schemas/plugin.schema.json           # Faz 2'de rules.go'dan ÜRETİLECEK (bu Faz'da YOK)
├── tests/corpus/ / tests/fixtures/ / tests/lab/
├── docs/architecture.md (bu dosya) / docs/evidence-standard.md
├── docker-compose.lab.yml               # S4 pinleri (§16.3)
└── .golangci.yml / .github/workflows/   # Faz 2'de (lint+vet+bench+corpus kapıları)
```

- **Config dosyası:** `gash.yaml` (viper, opsiyonel; flag > env > config > default). Lazy-load: yalnızca `scan`/`plugins` okur (Faz 0 D2). Secret'lar config'e yazılmaz (token env'den).
- **Ev dizini:** `~/.gash/plugins/` (drop-in), `~/.gash/cache/plugins.db` (bbolt), `~/.gash/trust.db` (Tier 3 pinleri), `.gash-suppress.yaml` (proje-yerel, versiyonlanır).
- **Trust Migration Note (S1):** legacy `~/.gash/trust.json` salt-okunur kaynaktır; default `trust.db` yoksa ve legacy varsa engine otomatik migrate eder (legacy dosya silinmez/değişmez). Explicit path (`GASH_TRUST_FILE`, `--trust-file`) migrate etmez.

### 16.3 Recall lab pinleri (S4 kararı)

`docker-compose.lab.yml` localhost-only, izole network; sürümler Faz 1'de pinlenir:

- `DVWA:2.0` (damn-vulnerable), `JuiceShop:17.1.0`, `WebGoat:2023.8`. İmaj digest'leri Faz 2'de `docker-compose.lab.yml`'e yazılır (bu Faz'da tasarım kararı; dosya Faz 2'de).
- `gash bench lab` precision/recall raporu üretir (`docs/metrics/` altında saklanır; düşüş = CI fail — P6).

**Reddedilen:** `latest` tag (tekrar üretilemezlik). Uzak lab (egress + determinizm kaybı).

---

## 17. Karar özeti (A-01 – A-21)

| # | Karar | Gerekçe (tek cümle) | Reddedilen başlıca alternatif |
|---|---|---|---|
| A-01 | AGPL-3.0-only + `github.com/Xmar1881/Gash` + SPDX | SaaS deliğini kapatır, tek lisans sadeliği | MIT/Apache, dual-license, SDK'yı permissive yapma |
| A-02 | Tek binary + ayrı Tier3/OOB process | Dağıtım kolay + gerçek izolasyon | Monolit, mikroservis, plugin'e ham soket |
| A-03 | Faz-barrier + faz-içi paralel + context hiyerarşisi | Determinizm + hız + iptal garantisi | Tam sıralı / tam barriersız, beyana-güven bütçe |
| A-04 | Plugin Candidate-only; güven/severity motor-türetilmiş | H2 yapısal garanti | Plugin'e confidence yazdırma, skor |
| A-05 | Tarama-öncesi baseline (soft404/WAF/maske/tech/jitter) | FP'yi motorda tek sefer çözme | Baseline'siz, ML sınıflandırıcı, manuel baseline |
| A-06 | Tek Oracle sözleşmesi + 9 oracle | Tek kanıt disiplini | Dağınık oracle API'leri |
| A-06a | M-W U + x/net/html tokenizer + chromedp (tag-gated) | Doğruluk + cgo'suz + determinizm | Sabit eşik, full-DOM, Playwright |
| A-07/08 | PluginSpec alanları + R-01..R-SEV-01 kuralları | Beyana-güvenmeme, test-edilebilirlik | Dağıtık kurallar |
| A-09 | rules.go → schema.json üretim yönü | Çift-bakım senkron kaymasını engelleme | Schema-first, çift-el-bakımı |
| A-10 | İki-aşamalı keşif + lazy init | ≤150ms + filtre-öncesi-execute yok | Eager-load, tek-aşamalı |
| A-11 | PolicySession RoundTripper proxy | Bütçe/scope/rate tek noktada enforce | Ham http.Client |
| A-12 | bbolt cache + bütçe dağılımı | CGO'suz + warm ≤150ms | sqlite-cgo, modernc-sqlite |
| A-13 | gRPC-only, çift servis, fail-closed | 10 yıllık birikim + H2'yi native'e de uygulama | .so, stdio-RPC, net/rpc, WASM |
| A-14 | Interactsh-uyumlu client, ayrı binary Faz 3+ | Tekerlek icadı yok + NDA güvenliği | Public default, sıfırdan Faz 2, push-only, sonsuz bekleme |
| A-15 | GASH-XXX birincil + CWE ikincil | GASH-özgü sınıflar dürüst eşlenir | Yalnızca CWE |
| A-16 | Normalize+fingerprint dedup (motorda) | B5 + CI stabilitesi | Satır-tabanlı, plugin-tarafı dedup |
| A-17 | Noisy-breaker demote (N=10) | Gürültü kısma + determinizm | Sessiz drop, hard-kill |
| A-18 | Taint etiketi + oracle ret + TTL | Self-confirm engeli, bulaşma yok | Taint'siz, kalıcı taint |
| A-19 | cobra ağacı + bayrak seti + exit kodları | D2'nin gereği + CI denetimi | --load-plugin, public OOB default, bulguda exit=1 |
| A-20 | SARIF birincil + 4 format | CI kapısı + insan + otomasyon | Yalnızca JSON, Markdown birincil |
| A-21 | Final ağaç + gash.yaml + ~/.gash + lab pinleri | Tekrar üretilebilirlik + H1 sürtünmesizliği | latest tag, uzak lab |

---

## 18. Faz 0 S1–S5'in Faz 1 karşılığı

| S | Faz 0 varsayımı | Faz 1 kararı |
|---|---|---|
| S1 (OOB sunucusu) | Protokol Faz 1'de donar; önce interactsh-uyumlu client, ayrı binary Faz 3+ | A-14 ile donduruldu (§9). Sapma yok. |
| S2 (SDK dili) | Go-first; sözleşme dil-bağımsız; Python POC dışı | A-13 ile donduruldu (§8). Sapma yok. |
| S3 (SARIF ruleId) | `GASH-XXX` birincil + CWE ikincil varsayımı | A-15 ile donduruldu (§10, evidence-standard). Sapma yok. |
| S4 (Lab pinleri) | localhost-only + sürümler Faz 1'de pinlenir | §16.3 ile donduruldu (DVWA 2.0 / JuiceShop 17.1.0 / WebGoat 2023.8). Sapma yok. |
| S5 (Org/lisans) | Placeholder; lisans Faz 1'de donar | A-01 ile donduruldu: `github.com/Xmar1881/Gash`, AGPL-3.0-only. Sapma yok (kullanıcı onayı). |

---

## 19. B1–B11 durumu (Faz 1)

Faz 1'de kod/test olmadığı için tamamı "tasarım karşılığı donduruldu / doğrulama Faz 2+" durumundadır.

| # | Kriter | Faz 1 tasarım karşılığı | Doğrulama planı (Faz 2, aksi belirtilmedikçe) |
|---|---|---|---|
| B1 | Tek-dosya Tier 1/2 plugin, çekirdek değişmez | A-07 (IR) + A-10 (drop-in keşif) + `plugins new` iskeleti (§14) | Faz 3 e2e test (yeni dosya → bulgu, çekirdek diff yok) |
| B2 | Sıfır plugin: çökmez, geçerli boş rapor | §3 (boş registry yolu) + §15 (boş rapor şeması) | Test: boş registry + 4 formatta şema geçerliliği |
| B3 | Plugin Finding üretemez; kanıtsız ≤ tentative | A-04 (internal alanlar, proto'da alan yok) + R-06/R-SEV-01 | Contract test (yetkisiz yazma denemesi + kanıtsız aday tavanı) |
| B4 | Negatif korpusta firm+ = 0 | A-05 (baseline) + evidence-standard ret koşulları + P6 | CI kapısı `TestNoFalsePositives` |
| B5 | Kötü/gürültülü plugin diğerlerini etkilemez | A-11 (proxy) + §7.4 izolasyon + A-16/A-17/A-18 | İzolasyon testi (± kötü plugin diff) |
| B6 | safe=true state-changing atamaz | A-11 (method allowlist + ErrPolicyViolation) | Proxy testi (POST denemesi → PolicyError) |
| B7 | Bozuk plugin taramayı durdurmaz | §7.8 (recover/Interrupt/kill + PluginResult) | Fault-injection (panic + timeout + invalid-return) |
| B8 | Warm keşif ≤150ms | A-12 (bbolt + bütçe ~80ms + headroom) | `go test -bench` + CI regresyon |
| B9 | oob:required + --oob-server yoksa hiç çalışmaz | R-OOB-01 + §9.4 + scheduler skip | Test (skip+sebep, sahte tentative yok) |
| B10 | Tier 3 trust'suz asla çalışmaz | A-13 (trust.db + sha256 + --strict-plugins) | Test (trust'suz exec yok) + POC kill testi |
| B11 | Sabit check sayısı/isim yok | Tasarım: sayı/isim yalnızca evidence-standard taksonomisinde (doküman), kodda aranabilir sabit listesi yasak ilkesi §1–§6 | CI grep kapısı (Faz 2'den itibaren) |

---

## 20. Açık riskler / sorular (en fazla 5 soru)

### 20.1 Açık Sorular (Faz 2'yi bloke etmeyen, Faz 2'de kapanacak)

| # | Soru | Varsayım (soruya rağmen ilerlenen) | Kapanacağı yer |
|---|---|---|---|
| Q1 | Timing istatistiği Mann-Whitney U mu, eşik+sapma mı (veya hibrit)? | Arayüz ikisini de taşır (strateji param); default M-W U | Faz 2 lab verisiyle seçim + test |
| Q2 | OOB push (WebSocket) ilk bağlantıda denensin mi, direkt polling mi? | Client otomatik seçer (WS dene → polling'e düş); polling varsayılan yol | Faz 2 OOB client testleri |
| Q3 | `x/net/html` tokenizer + bağlam makinesi hangi etiket/attr kümesini kapsayacak (SVG/MathML, `srcdoc`, `template` dahil mi)? | Çekirdek HTML + SVG `on*` dahil; MathML Faz 3'e ertelenebilir | Faz 2 ReflectionOracle testleri |
| Q4 | `chromedp` hangi sürüme pinlenecek + headless yokluğunda DOM-XSS tavanı `firm` mi kalacak? | Evet, yoksa `firm` tavanı (evidence-standard); sürüm Faz 2'de pinlenir | Faz 2 build-tag + lab |
| Q5 | SARIF `suppressions` `externalPropertyFileReferences` ile mi taşınacak, inline mı? | Inline `suppressions[]` (basit); external referans Faz 3+ | Faz 2 reporter testleri |

Küçük varsayımlar (bayrak default'ları, eşikler, `order` aralığı, suppress dosya adı, bbolt yolu) spec/Faz 0 değerleriyle devralındı, ayrıca sorulmadı.

### 20.2 Açık Riskler (Faz 1'den Faz 2'ye taşınan)

- **R1 — goja sandbox kaçışı / yanlış binding:** A-10/A-11 + contract testleriyle kilitlenir (Faz 0 R1 devamı).
- **R2 — go-plugin yaşam döngüsü takılmaları:** A-13 kill zinciri + POC kapısı (Faz 0 R2 devamı; POC geçemezse Tier 3 Faz 3'ten düşer, Tier 1/2 etkilenmez).
- **R3 — OOB korelasyon gecikmesi/FP:** §9 namespace+correlation disiplini + `--oob-wait` üst sınırı (Faz 0 R3 devamı).
- **R4 — Timing/Differential gürültüde FP:** A-05/A-06 + korpus kapısı B4 (Faz 0 R4 devamı).
- **R5 — Kapsam genişlemesi (GUI/market/imzalama):** §16 dışı talepler reddedilir; bu dosya + `00-scope.md` red gerekçesidir (Faz 0 R5 devamı).
- **R6 (yeni) — AGPL-3.0 uyumu:** bağımlılık lisansları (goja MIT, cobra Apache-2.0, go-plugin MPL-2.0, bbolt MIT, chromedp BSD) AGPL-3.0 ile uyumlu; Faz 2'de `go-licenses` taraması CI kapısı olacak. Uyumsuz bağımlılık girerse değiştirilir (fail-closed).

---

## 21. Faz kapısı

- **Çıktılar:** bu dosya + `docs/evidence-standard.md` + `proto/gash/v1/plugin.proto`. Kod, `go.mod`, generated kod, schema dosyası yazılmadı.
- **Onay için sorulan:** A-01–A-21 kararları + Q1–Q5 varsayımları kabul ediliyor mu? Red/görüş varsa hangi karar maddesine (A-01..A-21) itiraz ediliyor?
- **Onay sonrası:** Faz 2 (test-first çekirdek altyapı; henüz zafiyet plugin'i yok).

*Teslim formatı uyumu: (1) §0.1, (2) §17 (+ §1–§16'daki Karar kutuları), (3) §19, (4) §20.*
