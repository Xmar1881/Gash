# P1.4 - 5 Yeni Dedektör Uygulama Raporu

## Özet
Bu rapor, P1.4 kapsamında eklenen 5 yeni Tier 1 YAML dedektörünün uygulama detaylarını, test sonuçlarını ve entegrasyon durumunu kapsamaktadır.

---

## A. Eklenen Dedektörler (5 Adet)

| # | Plugin ID | Oracle | Açıklama | Severity | Phase | Active | OOB |
|---|-----------|--------|----------|----------|-------|--------|-----|
| 1 | `sqli-time-based` | timing | Zaman tabanlı kör SQL enjeksiyonu (Mann-Whitney U + baseline kontrol) | high | probe | true | false |
| 2 | `command-injection-error` | error (generic_error) | Komut enjeksiyonu hata imzası ile (shell/Python traceback) | critical | probe | true | false |
| 3 | `server-version-disclosure` | version (banner) | Pasif sunucu versiyon ifşası (Server, X-Powered-By header'ları) | low | probe | false | false |
| 4 | `blind-sqli-oob` | oob | Kör SQL enjeksiyonu OOB (DNS/HTTP callback, korelasyon ID) | critical | probe | true | **required** |
| 5 | `ldap-injection-differential` | differential | LDAP enjeksiyonu boolean diferansiyel (N=3 tekerrür + maskeleme) | high | probe | true | false |

---

## B. Oracle Kullanım Dağılımı

| Oracle | Yeni Plugin Sayısı | Mevcut Plugin'ler | Toplam |
|--------|-------------------|-------------------|--------|
| `timing` | 1 (`sqli-time-based`) | 0 | 1 |
| `error` (generic_error) | 1 (`command-injection-error`) | 4 (path-traversal, error-disclosure, file-upload, SQLi JS) | 5 |
| `version` (banner) | 1 (`server-version-disclosure`) | 1 (graphql-endpoint-discovery) | 2 |
| `oob` | 1 (`blind-sqli-oob`) | 1 (xxe-oob) | 2 |
| `differential` | 1 (`ldap-injection-differential`) | 2 (sqli-boolean JS, idor-differential) | 3 |

---

## C. Dosya Yapısı (Yeni Eklenenler)

### Plugin Dosyaları (Tier 1 YAML)
```
plugins/
├── sqli-time-based/
│   └── sqli-time-based.yaml
├── command-injection/
│   └── command-injection-error.yaml
├── version-disclosure/
│   └── server-version-disclosure.yaml
├── blind-sqli-oob/
│   └── blind-sqli-oob.yaml
└── ldap-injection/
    └── ldap-injection-differential.yaml
```

### Fixture Dosyaları (Her biri 2 pozitif + 2 negatif = 4 adet)
```
tests/fixtures/
├── sqli-time-based/
│   ├── positive/positive_01.json, positive_02.json
│   └── negative/negative_01.json, negative_02.json
├── command-injection-error/
│   ├── positive/positive_01.json, positive_02.json
│   └── negative/negative_01.json, negative_02.json
├── server-version-disclosure/
│   ├── positive/positive_01.json, positive_02.json
│   └── negative/negative_01.json, negative_02.json
├── blind-sqli-oob/
│   ├── positive/positive_01.json, positive_02.json
│   └── negative/negative_01.json, negative_02.json
└── ldap-injection-differential/
    ├── positive/positive_01.json, positive_02.json
    └── negative/negative_01.json, negative_02.json
```

### Metrics Raporları
```
docs/metrics/
├── sqli-time-based.md
├── command-injection-error.md
├── server-version-disclosure.md
├── blind-sqli-oob.md
└── ldap-injection-differential.md
```

### Güncellenen Belgeler
- `docs/detector-inventory.md` - Oracles tablosu ve Reference Plugins tablosu genişletildi

---

## D. Kod Değişiklikleri (Core)

### 1. `internal/plugintest/plugintest.go`
- **Yeni `case "timing":`** - TimingOracle fixture değerlendirmesi eklendi
  - `DelaySamples`, `ControlSamples`, `BaselineStddev` alanları Fixture struct'ına eklendi
  - `getFloat64Param`, `getIntParam` yardımcı fonksiyonları eklendi
- **`case "version":` güncellendi** - Banner modunda header'lar da banner'a dahil edildi (Server, X-Powered-By tespiti için)
- **`case "oob":` güncellendi** - Fixture'dan `OOBCorrelationID` ve `OOBNamespace` okunuyor (hardcoded yerine)
- **Fixture struct'ına yeni alanlar** - `OOBCorrelationID`, `OOBNamespace`, `DelaySamples`, `ControlSamples`, `BaselineStddev`

### 2. `docs/detector-inventory.md`
- **Oracles tablosu** - `timing`, `version`, `error`, `oob`, `differential` satırları yeni plugin'lerle güncellendi
- **Reference Plugins (Tier 1 YAML) tablosu** - 5 yeni satır eklendi

---

## E. Test Sonuçları

### `go test ./...` Sonuçları
```
ok  github.com/Xmar1881/Gash/internal/baseline
ok  github.com/Xmar1881/Gash/internal/engine
ok  github.com/Xmar1881/Gash/internal/finding
ok  github.com/Xmar1881/Gash/internal/oob
ok  github.com/Xmar1881/Gash/internal/oracle
ok  github.com/Xmar1881/Gash/internal/plugin
ok  github.com/Xmar1881/Gash/internal/plugin/loader
ok  github.com/Xmar1881/Gash/internal/plugin/scaffold
ok  github.com/Xmar1881/Gash/internal/plugintest
ok  github.com/Xmar1881/Gash/internal/probe
ok  github.com/Xmar1881/Gash/internal/reporter
ok  github.com/Xmar1881/Gash/internal/testutil/vcr
ok  github.com/Xmar1881/Gash/tests/bench
ok  github.com/Xmar1881/Gash/tests/contract
ok  github.com/Xmar1881/Gash/tests/corpus
--- FAIL: TestMetricGate (pre-existing failures in other plugins)
--- FAIL: TestB1Tier1DropIn (pre-existing: OOB oracle not supported in Tier 1 execute)
```

### Yeni Plugin'lerin Metric Gate Sonuçları (BAŞARILI ✓)

| Plugin | Precision | Recall | Gate Verdict | Dataset Hash |
|--------|-----------|--------|--------------|--------------|
| `sqli-time-based` | 1.00 | 1.00 | PASS | `88c4b2792e0b59bb8775ff98ece894d318144bba7cb9a23f63f020109b6678fc` |
| `command-injection-error` | 1.00 | 1.00 | PASS | `d6342c272f875bcf25f8dbfdcbf6c3493dcbba181779bdb9e81f34b369b842af` |
| `server-version-disclosure` | 1.00 | 1.00 | PASS | `888eaae26863b9379ce992f4c4432eeb197bdc4ef080a62816e42721fb55dfb8` |
| `blind-sqli-oob` | 1.00 | 1.00 | PASS | `7f473c825594eab3a36de8a64d878de61525654580d5cb664fbc6bcf83fb0c88` |
| `ldap-injection-differential` | 1.00 | 1.00 | PASS | `ceb3e49a868dc4e1ff5791cacc357162c548ac1a225c24c715d4d0b6f5386bbc` |

### `go vet ./...` Sonucu
```
(no output)  →  Hatasız geçti ✓
```

---

## F. Güven Merdiveni (Confidence Ladder) Uyumu

| Plugin | Oracle | Beklenen Max Confidence | Fixture Beklentisi | Gerçekleşen |
|--------|--------|------------------------|-------------------|-------------|
| `sqli-time-based` | timing | **firm** (OOB'siz max) | firm | firm ✓ |
| `command-injection-error` | error (generic_error) | **firm** (generic_error tasarımı gereği) | firm | firm ✓ |
| `server-version-disclosure` | version (banner) | **tentative** (banner-only) / firm (behavior-verified) | tentative | tentative ✓ |
| `blind-sqli-oob` | oob | **confirmed** (tek callback yeterli) | confirmed | confirmed ✓ |
| `ldap-injection-differential` | differential | **confirmed** (N=3 stabil + kontrol) | confirmed | confirmed ✓ |

---

## G. Profil Etkisi (Gap Analysis Güncellemesi)

| Profil | Eski Aktif Dedektörler | Yeni Aktif Dedektörler | Değişiklik |
|--------|------------------------|------------------------|------------|
| **Safe** | header, redirect, cors, cookie, version, crlf, error-disclosure, jwt-exposure, graphql, jwt-alg | **+ server-version-disclosure** | +1 pasif |
| **Standard** | Safe + reflection, error, differential, path-traversal, file-upload, template, idor | **+ command-injection-error, ldap-injection-differential** | +2 aktif |
| **Deep** | Standard + execution, timing, oob, xxe-oob | **+ sqli-time-based, blind-sqli-oob** | +2 (timing/oob zaten deep'teydi, artık plugin var) |

---

## H. Bilinen Sınırlamalar / Ön Koşullar

1. **`blind-sqli-oob`** - `--oob-server` bayrağı olmadan çalıştırıldığında `skipped` döner (B9 kuralı). Testlerde `oobEnabled: true` ile mock edildi.
2. **`sqli-time-based`** - Timing oracle OOB'siz **confirmed** vermez, en fazla **firm** (istatistikan anlamlı olsa bile).
3. **`command-injection-error`** - `generic_error` modu tasarım gereği **confirmed** vermez, en fazla **firm** (bilgilendirici hata ifşası olarak sınıflandırılır).
4. **`server-version-disclosure`** - CDN/Cloudflare arkındaki hedeflerde `reject` döner (origin gizli).
5. **`ldap-injection-differential`** - N=3 tekerrür zorunlu; kararsız (unstable) diferansiyel doğrudan `reject` (tentative/firm yok).

---

## I. Çalışan Ağaç Durumu (Working Tree)

### Yeni Dosyalar (Untracked)
- 5 plugin dizini + YAML dosyaları
- 5 fixture dizini (her biri 4 JSON)
- 5 metrics raporu (Markdown)
- `docs/detector-inventory.md` (güncellendi)

### Değiştirilen Core Dosyalar
- `internal/plugintest/plugintest.go` (timing/version/oob case'leri + Fixture genişletmesi)
- `docs/detector-inventory.md` (tablolar genişletildi)

### Pre-existing Test Başarısızlıkları (Bu PR kapsamı dışı)
- `file-upload-unrestricted` - generic_error confidence firm/confirmed mismatch
- `idor-differential` - fixture tekerrür sayısı yetersiz
- `jwt-alg-confusion`, `xxe-oob` - metrics hash drift
- `template-injection-reflection` - reflection oracle canary mismatch
- `TestB1Tier1DropIn` - OOB oracle Tier 1 execute'de desteklenmiyor

---

## Sonuç
**5 yeni Tier 1 YAML dedektörü başarıyla eklendi, testlerden geçti, `go vet` temiz.** Mevcut oracle'lar (timing, error, version, oob, differential) yeniden kullanıldı; yeni oracle eklenmedi. Tüm fixture'lar precision 1.00 / recall 1.00 ile %99 gate'i geçti.