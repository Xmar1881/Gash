<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/design/01-detector-port.md
What: Architecture decision record for the engine-owned detector port.
Why: Engine-recon logic used to be hardcoded inside the engine; this record
  freezes the port, the gates, the data-driven payload tables, and the staged
  migration of every engine-owned finding producer.
-->

# Gash — Motor-İçi Dedektör Portu (`01-detector-port.md`)

- **Durum:** Uygulandı (port + registry + 4 dedektör taşındı; kod, test, doküman)
- **Tarih:** 26 Ekim 2026 (UTC)
- **Kapsam:** `internal/detector`, `internal/smuggle`, `internal/recon`,
  `internal/discovery`, `internal/engine`
- **İlgili:** `docs/architecture.md` §7 (plugin sistemi) / §8 (Tier 3),
  `docs/js-plugin-spec.md`, `docs/native-plugin-spec.md`,
  `docs/detector-inventory.md`, `docs/plugin-coverage-matrix.md` §23

---

## 1. Problem

Motor-içi tarama mantıkları (Request Smuggling GASH-033, content discovery
GASH-028, JS recon GASH-067, embedded SPA state GASH-071, dev build GASH-072)
`internal/` içinde **Go kontrol akışı olarak** duruyordu. Kimlik, kural eşlemesi,
kapı (gate) metni, bütçe ve rapor sayaç anahtarları çağrı yerlerine dağılmıştı:

- `internal/engine/scan_exec.go` içinde her dedektör için ayrı bir `if`
  zinciri (kapı + ortam kurma + sonuç bağlama).
- Kapı metinleri iki ayrı yerde (motor `else` dalı ve dedektörün kendi
  `gate()`'i) elle yazılıydı; yeni bir varyant eklemek Go derlemesi
  gerektiriyordu.
- "Hangi motor-içi dedektörler var, hangi kuralı raporluyor?" sorusunun cevabı
  kod aramasına bağlıydı; envanter dokümanı elle güncelleniyordu.

Bu, "Plugins everywhere" felsefesiyle çelişen tek noktaydı: eklenti kataloğu
veri-güdümlü, motor-içi recon ise kontrol akışına gömülüydü.

---

## 2. Karar D2 — Motor-içi birimler için tek port + registry

### Karar

Motor-içi tarama birimleri **`internal/detector` port'una** taşınır. Port üç
parçadan oluşur:

1. **`Spec`** — kimlik + taksonomi + kapılar (`ID`, `RuleID`, `CWE`, `Oracle`,
   `Severity`, `Phase`, `Order`, `Gate`, `Requires*`, `SkipSubject`,
   `MaxRequests`, `Docs`, `DetectorVersion`).
2. **`Detector`** — `Spec()` + `Run(ctx, *Env) (Result, error)`.
3. **`Registry`** — açık (init sihri olmayan) kayıt listesi; `Specs()`
   deterministik sıralama (`Order`, sonra `ID`).

Motor ne yapar: fazı seçer, **brokered ortamı** (`Env`) kurar, bütçeyi ve
kapsamı uygular, sonucu rapora bağlar. Dedektör ne yapar: kendi kimliğini,
kapısını, payload verisini, sayaç anahtarlarını ve kanıt disiplinini taşır.

`Env` yalnızca politika-filtreli yetenekler sunar: paylaşılan `PolicySession`
üzerinden `*probe.Client`, kazınmış sayfalar (`Page`), teknoloji kümesi, kapsam
kararı (`Scope`), bayraklar (`Flags`) ve OOB bağlamı. Dedektör motora ait iç
duruma erişemez.

`Result` üç meşru çıktıyı adlandırır: `Findings`, `Stats` (nihai rapor
anahtarları), `Surface` (enjeksiyon noktası katkısı), `Paths` (keşfedilen
artefakt yolları) ve `Skipped` (dedektörün kendi dürüst skip gerekçesi).

### Neden

1. **Tek doğruluk kaynağı:** kural kimliği, CWE, oracle ve kapı artık koddaki
   bir `Spec` alanıdır; rapor, envanter ve test aynı yapıyı okur. Registry
   `validateSpec` ile eksik kimliği (boş rule/CWE/oracle/version, geçersiz
   severity/phase) **kablolama anında** reddeder.
2. **Kapı tek kaynağı:** `Spec.Evaluate(Policy)` bayrak gereksinimlerini,
   ardından profil kapısını uygular ve denetim izi metnini kanonik üretir:
   `skipped (requires --active)`,
   `skipped (smuggle-probe requires --active --aggressive)`,
   `skipped (detector smuggle disabled by profile standard)`.
   Böylece iki yerde elle yazılan skip metni sapması imkânsızlaşır.
3. **Kapsam ve bütçe motorun yetkisinde kalır:** dedektör kendi HTTP/soket
   politikasını icat edemez. Ham-TCP dedektörü kapsam kararını `Env.Scope`
   üzerinden alır; kapsam-dışı hedefte **soket açılmaz** ve bu, denetim izli
   `Skipped` olarak raporlanır.
4. **Genişleme veriye taşınır:** smuggling diferansiyel eksenleri artık
   `internal/smuggle/cases.yaml` (gomulu tablo, `go:embed`); yeni bir eksen
   (ek TE obfuscation, farklı güvenli gövde sonlandırıcı) **tablo satırıdır**.
   Tablo yükleyici bozuk veride fail-closed davranır ve altın-bayt testi tel
   formatını sabitler.

### Sonuçlar

- **Motor-içi 4 bulgu üreticisi registry'ye taşındı:** `engine-spa-state`
  (GASH-071), `engine-devbuild` (GASH-072), `engine-content-discovery`
  (GASH-028), `engine-smuggle-recon` (GASH-033).
- `internal/engine/embedded_state.go` kaldırıldı; kurallar ve testleri
  `internal/recon` altında yaşıyor. Motor yalnızca
  `runDetector(ctx, env, id)` çağırır ve `Stats`'ı rapora basar.
- Rapor sözleşmesi **birebir korundu**: sayaç anahtarları
  (`smuggle_requests`, `content_requests`, `content_findings`,
  `spa_state_pages`, `spa_state_secrets`, `devbuild_markers`) ve skip
  metinleri değişmedi; motor testleri (agresif/güvenli kapı, kapsam-dışı
  sıfır soket, GASH-071/072 rapor istatistikleri) refactor sonrası aynen geçer.
- Yeni testler: port sözleşmesi ve kapı matrisi (`internal/detector`),
  payload tablosu + tel formatı + dedektör koşumu (`internal/smuggle`),
  kural birimleri (`internal/recon`), registry bütünlüğü + profil kapıları +
  kapsam fail-closed (`internal/engine`).

### Aşamalı geçiş (durum)

| Birim | Kural | Durum | Not |
|---|---|---|---|
| `internal/smuggle` | GASH-033 | ✅ Taşındı | Payload eksenleri `cases.yaml`; ham-TCP hakkı motorda kalır (B6) |
| `internal/recon` (SPAState) | GASH-071 | ✅ Taşındı | Kazınmış gövde analizi, istek yok |
| `internal/recon` (DevBuild) | GASH-072 | ✅ Taşındı | Aynı disiplin |
| `internal/discovery` (ContentDetector) | GASH-028 | ✅ Taşındı | Motor, dönen `Paths` için geri-besleme crawl'ını yönetir (taşıyıcı rolü) |
| `internal/recon` (JSRecon) | GASH-067 | ✅ Taşındı | Motor iki yeteneği brokered eder: `Env.URLAllowed` (URL-seviyesi kapsam) ve `Env.FollowCrawl` (1 sayfa, derinlik 0). `jsReconURLAllowed` motor'da kalır (SPA yüzeyi de kullanır) |
| `internal/proto` (tls/dns/tcp/ssh/db) | GASH-024..027, 052..056 | ✅ Taşındı | 8 birim (`proto-tls-cert`, `proto-tls-deep`, `proto-dns-records`, `proto-tcp-banner`, `proto-ssh-banner`, `proto-ssh-handshake`, `proto-db-ports`, `proto-db-unauth`). Motor şunları brokered eder: `Env.Infra` (timeout, `Allow`, paylaşılan `Limiter`, `Targets`/`Hosts`/`DBPorts`, `TCPBanners`, `TLSAuditDeep`, `TLSObservation`). El sıkışma gözlemi tek dial olarak `Result.Carry` → `Env.Infra.TLSObservation` ile devredilir; birim kendi `Result.Skips` denetim izini üretir (hedef-şekli ve kapsam reddi) |

**Davranış korunumu (proto dilimi):** kapı/skip metinleri birebir korunur; motor
testleri (`TestInfraRecon*`, `TestProtoRecon*`) değiştirilmeden geçer — bunlara
"tam 1 skip", "sıfır soket", "gözlem yeniden kullanılır" (ek dial yok) ve "tüm
bayraklar kapalıyken sıfır trafik" doğrulamaları dahildir. Bilinçli tek fark:
profil bir birimi kapatırsa artık sessiz değil **denetim izli skip** yazılır
(`skipped (detector tcp disabled by profile safe)` gibi); bu "sessiz drop yok"
ilkesiyle uyumludur ve hiçbir test bu sessizliği beklemez.

**Envanter parite kapısı:** `TestDetectorInventoryParity` (`tests/contract`)
registry `Specs()` ile `docs/detector-inventory.md` tablosunu karşılaştırır;
kayıtlı bir dedektör eksikse ya da tabloda kayıtsız bir satır varsa build kırılır.

**Kapsam genişletme:** yeni bir smuggling ekseni eklerken yalnızca
`internal/smuggle/cases.yaml` + altın-bayt testi güncellenir; kod değişmez.

---

## 3. Reddedilen alternatifler

| Alternatif | Neden reddedildi |
|---|---|
| **Ham soket mantığını Tier 3 native eklentiye taşımak** | `proto/gash/v1/plugin.proto` B6: eklentinin ham soket hakkı yoktur, tüm ağ `SendProbe` üzerinden akar. Smuggling bayt-seviyesi çerçeveleme + tek keep-alive bağlantıda takip isteği gerektirir; `SendProbe` sözleşmesiyle ifade edilemez. Ham soket hakkı verilseydi B6 delinir (denetlenemeyen egress) |
| **Tier 3'e taşımak (trust bedeliyle)** | Tier 3 varsayılan güvensizdir: platform başına sha256 pinlenmesi + `gash plugins trust` gerekir. Çekirdek recon (SPA/dev build/wordlist) operatör pinlemedikçe hiç çalışmazdı; ayrıca OS/arch başına binary dağıtımı gerekirdi |
| **Mevcut hâli korumak (motor-içi if zincirleri)** | Yeni varyant = Go derlemesi; kimlik/kapı/sayaç üç ayrı yerde; envanter elle senkron tutulur |
| **`init()` zamanında otomatik kayıt** | Kayıt sırası ve "hangi birim var" sorusu görünmez olurdu; testler alt küme registry kuramazdı. Açık kayıt, kablolama hatasını (çift ID, eksik Spec) derleme/anında yakalar |
| **Dedektörlere kendi `net.Dial` / `http.Client` hakkını vermek** | Kapsam, bütçe, rate-limit ve safe-method kapıları bypass edilirdi. Ortam yalnızca paylaşılan `PolicySession` istemcisini verir |
| **Motor-içi birimleri Tier 2 JS'e taşımak** | Sandbox'ta ham soket, tarayıcı, kazınmış gövde durumu ve dosya erişimi yok; bu birimler yapısal olarak sandbox dışıdır |

---

## 4. Takip işleri

1. **js-recon (GASH-067):** `Env`'e nötr `Crawl` özeti eklenip dedektöre
   taşınacak; yüzey katkısı `Result.Surface` ile verilecek.
2. **proto recon (tls/dns/tcp/ssh/db):** aynı port'a taşınacak; `Spec.Gate`
   alanı mevcut `detectorEnabled` anahtarlarıyla birebir eşleşiyor.
3. **Envanter kapısı:** registry `Specs()` çıktısı ile
   `docs/detector-inventory.md` tablosunun uyuşmasını doğrulayan bir kapı testi
   (dosya-tabanlı parite) eklenebilir.
4. **Kapsam genişletme:** yeni bir smuggling ekseni eklerken yalnızca
   `cases.yaml` + altın-bayt testi güncellenir; kod değişmez.
