<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/user-guide-tr.md
What: Yeni başlayanlar için Türkçe kullanıcı rehberi.
Why: `gash --help` ekranından sonra ilk adımları sade dille anlatır.
-->

# GASH Kullanıcı Rehberi (Türkçe)

Bu rehber yeni başlayanlar içindir. Kısa, sade ve kopyala-yapıştır komutlarla ilerler.

## 1. GASH nedir?

GASH, Go ile yazılmış bir güvenlik tarama motorudur.

Mantık basittir:

- Plugin **aday (candidate)** üretir.
- Motorun **oracle** bileşeni adayı doğrular.
- Kanıt varsa **finding (bulgu)** oluşur.

Kısaca: `Aday -> Doğrulama -> Bulgu`.

Güven seviyeleri:

- `confirmed`: kanıt güçlü.
- `firm`: kanıt orta.
- `tentative`: kanıt zayıf, varsayılan raporda görünmez.

`tentative` bulguları görmek için `scan` komutunda `--show-tentative` gerekir.

## 2. Nasıl çalıştırılır? (Önemli)

GASH bir komut satırı aracıdır. `.exe` dosyasına çift tıklarsan pencere açılıp kapanır, tarama yapmaz.

Windows'ta **PowerShell** veya **cmd** aç ve içinden çalıştır.

Kaynak koddan çalıştırma (önerilen):

```powershell
go run ./cmd/gash --help
```

Derlenmiş exe ile çalıştırma:

```powershell
.\dist\gash-v0.1.0-dev-windows-amd64.exe --help
```

Karşına şuna benzer bir liste gelir:

```text
Available Commands:
  bench       Benchmark
  completion  Shell completion
  help        Help about any command
  plugins     Plugin yönetimi
  scan        Hedefi tara (Faz 2: schedule + boş rapor iskeleti)
  suppress    Yerel suppress yönetimi
```

> Not: Şu an `scan` Faz 2 iskelettir. Gerçek tarama motoru çağrısı henüz tamamlanmadı.

## 3. İlk 3 komut

PowerShell'i aç, `C:\dev\Gash` klasörüne geç ve sırayla dene:

```powershell
cd C:\dev\Gash
go run ./cmd/gash plugins list
go run ./cmd/gash scan --help
go run ./cmd/gash plugins --help
```

### Komut 1: `plugins list`

Yüklü pluginleri çalıştırma yapmadan listeler.

Gerçek çıktı örneği:

```text
7 plugins
- missing-security-headers [yaml] phase=probe order=10 oob= plugins\headers\missing-security-headers.yaml
- open-redirect-param [yaml] phase=probe order=30 oob= plugins\redirect\open-redirect-param.yaml
- poc-native-header-check [native] phase=deep order=70 oob= trusted=no (needs `gash plugins trust`) plugins\native\poc-native-header-check.gashplugin.yaml
- sqli-boolean-differential [js] phase=probe order=51 oob= plugins\sqli\sqli-boolean-differential.js
- sqli-error-based [js] phase=probe order=50 oob= plugins\sqli\sqli-error-based.js
- ssrf-blind-oob [js] phase=probe order=60 oob=required plugins\ssrf\ssrf-blind-oob.js
- xss-reflected-basic [js] phase=probe order=40 oob= plugins\xss\xss-reflected-basic.js
```

### Komut 2: `scan --help`

Tarama seçeneklerini gösterir. Uydurma flag kullanma, listede ne varsa o geçerlidir:

```text
Flags:
      --active                        state-changing/OOB payload kapısı
      --deep                          deep faz + ExecutionOracle kapısı
      --fail-on string                CI kapısı (firm|confirmed)
      --format strings                json|sarif|text|html (tekrarlanabilir) (default [text])
      --ignore-plugin strings         döngü kırma / susturma
      --max-requests-per-target int   per-target bütçe (default 1000)
      --max-requests-total int        global bütçe (default 10000)
      --no-plugin-cache               cache bypass (debug)
      --oob-server string             self-hosted interaction sunucusu (boş=kapalı)
      --oob-wait string               scan-sonu OOB penceresi (default "60s")
      --parallelism int               worker sayısı (default 8)
      --plugin-timeout string         per-plugin timeout (default "30s")
      --rate-limit float              per-target req/s (default 10)
      --safe                          varsayılan safe (default true)
      --scope strings                 CIDR/domain allowlist
      --show-tentative                tentative'i dahil et
      --strict-plugins                yalnızca trust'lı Tier3
      --target string                 hedef URL
```

### Komut 3: Örnek local tarama (dry-run)

> DİKKAT: İzinsiz hedefe tarama YASAKTIR. Yalnızca kendi makinen veya yazılı izinli hedefin üzerinde dene.

Güvenli deneme:

```powershell
go run ./cmd/gash scan --target http://localhost:8080
```

Şu anki gerçek çıktı:

```text
GASH scan: http://localhost:8080 (faz2 iskelet — motor çağrısı)
```

`--target` yazmazsan hata alırsın, bu normaldir:

```text
Error: scan: --target zorunlu
```

## 4. Plugin akışı: new / validate / test

Yeni plugin üretmenin en kolay yolu:

```powershell
go run ./cmd/gash plugins new my-check --tier yaml
go run ./cmd/gash plugins validate my-check.yaml
go run ./cmd/gash plugins test my-check.yaml
```

Ne işe yararlar?

- `plugins new <ad>`: iskelet + örnek fixture üretir.
  - `--tier yaml|js` (varsayılan `yaml`)
  - `--dir` çıktı klasörü (varsayılan `.`)
  - `--force` varsa üzerine yazar
- `plugins validate <dosya>`: şema + kural kontrolü yapar.
- `plugins test <dosya>`: `positive` + `negative` fixture çalıştırır, 0.99 precision kapısı uygular.

Diğer yararlı komutlar:

```powershell
go run ./cmd/gash plugins info xss-reflected-basic
go run ./cmd/gash bench --help
```

`bench` altında şu an yalnızca `lab` vardır:

```text
Available Commands:
  lab  Recall lab (DVWA/JuiceShop/WebGoat)
```

## 5. Trust (Tier 3)

Tier 3, native (çalıştırılabilir) plugin demektir. Güvenlik için otomatik çalışmaz.

`plugins list` çıktısında bunu görürsen:

```text
trusted=no (needs `gash plugins trust`)
```

Önce güven vermen gerekir:

```powershell
go run ./cmd/gash plugins trust plugins\native\poc-native-header-check.gashplugin.yaml
```

Bu komut dosyanın `sha256` özetini kontrol edip güven dosyasına (`~/.gash/trust.db`) kaydeder. Özet uymazsa işlem durur.

Kurumsal / CI ortamında ek koruma:

```powershell
go run ./cmd/gash scan --target http://localhost:8080 --strict-plugins
```

`--strict-plugins` yalnızca güven verilmiş Tier 3 çalıştırır.

## 6. Suppress

Bulgu gizlemek / geri almak için kullanılır (Faz 2'de iskelet düzeyindedir):

```powershell
go run ./cmd/gash suppress list
go run ./cmd/gash suppress add <finding-id>
go run ./cmd/gash suppress remove <finding-id>
```

Gerçek `suppress list` çıktısı şu an şudur:

```text
suppress list
```

## 7. OOB notu

OOB (Out-of-Band), kör açıklar için dış doğrulama kanalıdır.

- `--oob-server` boşsa OOB kapalıdır.
- `oob=required` bir plugin, sunucu yokken hiç çalışmaz. Sahte `tentative` üretmez, dürüstçe atlanır (skip).
- `--oob-server` verirsen `--active` de zorunludur. Çünkü OOB payload göndermek invasive sayılır.

Özet: `--oob-server` yoksa blind/OOB bulgusu bekleme, bu normaldir.

## 8. SSS

**Çift tıklayınca pencere kapanıyor, ne yapayım?**

Normaldir. Çift tıklama yalnızca yardım gösterir. PowerShell veya cmd açıp komutla çalıştır:

```powershell
go run ./cmd/gash --help
go run ./cmd/gash scan --help
go run ./cmd/gash plugins list
```

**Boş rapor ne demek?**

Hiç plugin yoksa veya hiç kanıt bulunamazsa motor boş ama geçerli rapor üretir. Bu hata değildir, exit kodu 0 olur.

**`tentative` nedir?**

Zayıf kanıtlı bulgudur. Varsayılan raporda görünmez. Görmek istersen:

```powershell
go run ./cmd/gash scan --target http://localhost:8080 --show-tentative
```

**Shell tamamlama var mı?**

Evet:

```powershell
go run ./cmd/gash completion --help
```

Altında `bash`, `zsh`, `fish`, `powershell` vardır.

## 9. Sorumlu kullanım

- Yalnızca izinli hedef tara.
- `--scope` ile kapsamı dar tut.
- Varsayılan `--safe` modda kal.
- OOB sunucusu kurmadan OOB açmaya çalışma.

Detay: `docs/SECURITY.md`, `docs/plugin-development.md`.
