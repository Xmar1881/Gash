<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / Gash contributors
Module: github.com/Xmar1881/Gash

File: docs/user-guide-tr.md
What: Yeni başlayanlar için Türkçe kullanıcı rehberi.
Why: `gash --help` ekranından sonra ilk adımları sade dille anlatır.
-->

# Gash Kullanıcı Rehberi (Türkçe)

Bu rehber yeni başlayanlar içindir. Kısa, sade ve kopyala-yapıştır komutlarla ilerler.

## 1. Gash nedir?

Gash, Go ile yazılmış bir güvenlik tarama motorudur.

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

Gash bir komut satırı aracıdır. `.exe` dosyasına çift tıklarsan pencere açılıp kapanır, tarama yapmaz.

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
  openapi     OpenAPI/Swagger spec'ten test planı üret (taramasız)
  plugins     Plugin yönetimi
  scan        Hedefi tara (Candidate→Verify→Finding hattı)
  suppress    Yerel suppress yönetimi
```

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

### Komut 2: `scan --help`

Tarama seçeneklerini gösterir. Uydurma flag kullanma, listede ne varsa o geçerlidir:

```text
      --active                        state-changing/OOB payload kapısı
      --aggressive                    tam güç ofansif tarama (active+deep+yüksek bütçe)
      --auth-header strings           kimlik header'ı 'Ad: değer' (tekrarlanabilir)
      --auth-user-a strings           BOLA matrisi kullanıcı A başlığı (--auth-user-b ile birlikte)
      --auth-user-b strings           BOLA matrisi kullanıcı B başlığı (--auth-user-a ile birlikte)
      --basic-auth string             basic kimlik 'kullanıcı:parola'
      --cookie strings                oturum cookie'si 'a=b[; c=d]' (tekrarlanabilir)
      --deep                          deep faz + ExecutionOracle kapısı
      --fail-on string                CI kapısı (firm|confirmed)
      --format strings                json|sarif|text|html|junit (tekrarlanabilir) (default [text])
      --ignore-plugin strings         döngü kırma / susturma
      --login-pass string             tek kimlik seti parolası (--login-pass-env tercih edilir)
      --login-pass-env string         parolayı ortam değişkeninden oku (örn. GASH_LOGIN_PASS)
      --login-pass-field string       parola alanı adı override'ı (boşsa ilk type=password)
      --login-url string              login formu URL'i; gerçek oturum kurar (--active + --login-user şart)
      --login-user string             tek kimlik seti kullanıcı adı (parola denemesi YOK)
      --login-user-field string       kullanıcı alanı adı override'ı (boşsa sezgisel)
      --login-verify-url string       oturum doğrulama URL'i (boşsa action target, o da yoksa --login-url)
      --max-requests-per-target int   per-target bütçe (default 1000)
      --max-requests-total int        global bütçe (default 10000)
      --no-plugin-cache               cache bypass (debug)
      --oob-server string             OOB sağlayıcısı: local | interactsh (public) | interactsh://host | self-hosted API URL (boş=kapalı)
      --oob-token string              self-hosted interactsh/API token'ı (boşsa GASH_OOB_TOKEN)
      --oob-wait string               scan-sonu OOB penceresi (default "60s")
      --parallelism int               worker sayısı (default 8)
      --plugin-timeout string         per-plugin timeout (default "60s")
      --profile string                scan profile: safe|standard|deep|aggressive (default "standard"; pasif için "safe")
      --rate-limit float              per-target req/s (default 10)
      --scope strings                 CIDR/domain allowlist
      --show-tentative                tentative'i dahil et
      --strict-plugins                yalnızca trust'lı Tier3
      --target string                 hedef URL
      --tcp-banner strings            açık TCP banner probu 'host:port' (--active şart)
      --tech strings                  bilinen teknoloji (örn. wordpress,graphql)
```

### Proxy havuzu: timeout ve IP engeli

Tek bir proxy inceleme (Burp/ZAP) için yeterlidir; ancak hedef IP'nizi
engelliyorsa veya rate-limit uyguluyorsa tek IP ile tarama timeout'a düşer ve
plugin'ler `skipped` olur. Proxy havuzu bu durumda devreye girer:

```powershell
# proxies.txt: satır başına bir proxy URL'i, # ile yorum
gash scan --target https://app.example.com --scope app.example.com `
  --proxy-file proxies.txt --proxy-rotate per-host --proxy-cooldown 45s
```

- `per-host` (varsayılan): her hedef host için tek proxy sabitlenir; oturum
  çerezleri IP'ye bağlıysa bu modu kullanın. Hata alınca yalnızca o host'un
  proxy'si değişir.
- `per-request`: her istekte sıradaki proxy; yalnızca hedef oturumu IP'ye
  bağlamıyorsa kullanın.
- Timeout, bağlantı hatası ve `403`/`407`/`429` yanıtlarında istek bir sonraki
  sağlıklı proxy üzerinden yeniden denenir (istek başına en fazla 2 blok
  rotasyonu). Başarısız/bloklu proxy `--proxy-cooldown` süresi boyunca atlanır.
- Havuzda birden fazla proxy varsa `--request-timeout` **deneme başına**
  uygulanır; böylece takılan ilk proxy tüm plugin süresini yemez ve istek gövdesi
  eksiksiz yeniden oynatılır.
- `--proxy` tek proxy olarak aynen çalışır; `--proxy-file` ile birlikte
  kullanılabilir. Kimlik bilgili URL'ler desteklenir
  (`http://kullanıcı:parola@proxy:8080`); şemalar: `http`, `https`, `socks5`,
  `socks5h`. Listeye `host:port`, `kullanıcı:parola@host:port` veya yaygın
  `host:port:kullanıcı:parola` biçiminde de yazabilirsiniz.
- `--proxy`/`--proxy-file` verilmezse çalışma dizinindeki
  `.gash/proxies/alive.txt` (yoksa `.gash/proxies/all.txt`) otomatik yüklenir;
  `GASH_PROXY_FILE` ile başka bir liste gösterebilirsiniz. Otomatik kullanımı
  kapatmak için `--no-proxy` verin. Menüdeki "HER ŞEY" profili proxy listesini
  otomatik ekler ve `per-request` + 45s cooldown kullanır.
- Kapsam, bütçe, rate-limit ve redirect kontrolleri her denemede aynen uygulanır;
  proxy rotasyonu bu kontrolleri atlamaz.

### Aynı domain taraması (varsayılan)

`--scope` verilmezse Gash hedefin kayıtlı domainini (eTLD+1) otomatik scope
yapar; crawl ve redirect'ler yalnızca bu domain ve alt alanlarında kalır.
Böylece Google, CDN veya sosyal medya gömmeleri gibi dış linkler taranmaz.
Dışarı çıkmak isterseniz `--allow-external`, belirli bir listeyi zorlamak için
`--scope` kullanın. Menüde scope boş bırakılırsa aynı otomatik kapsam uygulanır.

- `--scan-timeout` (varsayılan `30m`): discovery + pluginler dahil tüm taramanın
  süre tavanı. 338 plugin'lik taramalarda 10m çoğu plugin'i skip ettiriyordu;
  menüdeki "HER ŞEY" profili `45m` kullanır.
- `--crawl-timeout` (varsayılan `5m`, menü HER ŞEY `10m`): BFS keşif fazının
  süre tavanı; yavaş proxy havuzu tüm scan süresini yiyemez, pluginlere süre
  kalır. Rapor `crawl_ms`, `crawl_budget_exhausted`, `crawl_incomplete` taşır.
- Proxy havuzu bir host için üst üste 6 transport hatası alırsa o host doğrudan
  bağlantıya düşer (`proxy_direct_fallbacks`). Doğrudan çıkışın kabul
  edilmediği işlerde `--no-proxy` veya sabit tek proxy kullanın.
- `--proxy-timeout` (varsayılan `8s`): çoklu proxy'de tek deneme süresi; ölü
  proxy'nin 20s asılı kalmasını engeller. `0` verilirse `--request-timeout`
  kullanılır.
- İçerik keşfi 8 paralel prob kullanır ve wordlist fazı 90s, mini-crawl 60s ile
  sınırlıdır; sayaç `N/80` olarak akar. Raporda `content_discovery_ms`,
  `content_budget_exhausted` ve `content_follow_budget_exhausted` görünür.
- JS recon follow-crawl + source map fazı 90s ile sınırlıdır
  (`js_recon_budget_exhausted`); rapor `crawl_ms`, `js_recon_ms`,
  `spa_crawl_ms`, `fuzz_ms`, `form_fuzz_ms`, `flow_ms`, `matrix_ms`,
  `smuggle_ms`, `browser_verify_ms`, `plugins_ms` ve `total_ms` sürelerini,
  ayrıca `surface_points`, `crawl_failed`, `crawl_stored_bytes`,
  `crawl_urls_dropped` ve `crawl_bodies_dropped` sayaçlarını taşır. Crawl
  belleği 64 MiB gövde ve `max(1000, 20×sayfa)` URL ile sınırlıdır; analiz
  tam yanıt üzerinde çalışır, yalnızca saklanan kopya kırpılır. Bulk taramada
  login oturumu hedef başına izoledir; önceki hedefin çerezi sonrakine geçmez.

### Komut 3: Örnek local tarama

> DİKKAT: İzinsiz hedefe tarama YASAKTIR. Yalnızca kendi makinen veya yazılı izinli hedefin üzerinde dene.

Güvenli deneme:

```powershell
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost
```

`--target` yazmazsan hata alırsın, bu normaldir:

```text
Error: scan: --target zorunlu
```

### Etkileşimli menü (`gash menu`)

Komutları ezberlemek istemiyorsan menüyü aç:

```powershell
go run ./cmd/gash menu
```

Sekmeler: `1` tarama, `2` pluginler, `3` bench, `4` OpenAPI, `5` diff,
`6` suppress, `7` konsol, `8` sistem durumu, `9` yardım. Sekme adını da
yazabilirsin (`scan`, `durum`, `yardim`); `0` veya `iptal` geri döner.

Tarama sekmesinde:

- **Toplu hedef dosyası:** hedef alanına bir dosya yolu yazarsan her satır ayrı
  hedef olarak `--target-file` ile taranır; scope her hedefin kendi domainine
  otomatik uygulanır. Çıktı klasörü ve `--resume` sorulur.
- **Proxy modu:** `auto` sağlıklı listeyi otomatik kullanır, `off` doğrudan
  bağlanır (`--no-proxy`), `single` tek proxy sorar, `all` tüm proxy listesini
  `per-request` rotasyonla verir.
- **Kimlik modu:** `cookie`, `header` veya `login` seçebilirsin. `login` güvenli
  profili otomatik `standard`a yükseltir ve `--active` ekler.
- **Dış alan adları:** varsayılan kapalıdır; açarsan `--allow-external` eklenir.
- Çalıştırmadan önce komut özeti gösterilir; `--cookie`, `--auth-header`,
  `--oob-token`, `--login-pass`, `--basic-auth` ve proxy kimlik bilgileri
  `[redacted]`/`***` olarak maskelenir.
- Tarama sırasında her faz bittiğinde son detayı ve süresi sabitlenir; aktif
  faz canlı güncellenir (sayfa/endpoint/istek/bulgu/plugin sayaçları). Atlanan
  fazın gerekçesi de yazılır; örnek: `✔ [İçerik Keşfi] tamam · 82 istek ·
  1 bulgu · 45000 ms`.
- Son komutu yeniden çalıştırmak için ana menüde `r` (veya `tekrar`) tuşuna bas.

`8` sistem durumu sekmesi derleme etiketlerini, Chrome/headless durumunu, Go
sürümünü, yüklü plugin sayısını, otomatik proxy listesini ve son raporları
gösterir; `o` rapor klasörünü açar, `v` son raporu görüntüler, `p` proxy
sağlık kontrolü komutunu yazdırır. Ayrıntılı menü rehberi:
[menu.md](menu.md).

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
go run ./cmd/gash openapi --spec openapi.json
```

`openapi` komutu tarama yapmaz; OpenAPI/Swagger dosyasından test planı çıkarır.
`bench lab` recall laboratuvarıdır (DVWA/JuiceShop/WebGoat, localhost).

## 5. Tarama profilleri (P2)

Profil, hangi dedektörlerin koşacağını ve bütçeyi tek yerden seçer:

| Profil | Ne yapar | Ne zaman kullan |
|---|---|---|
| `safe` | Pasif kontroller, düşük bütçe (100 req/hedef) | CI ve üretim, izinsiz yük yok |
| `standard` | Kontrollü aktif testler (500 req/hedef) | Yetkili web uygulaması (varsayılan) |
| `deep` | Tarayıcı/OOB dahil yüksek bütçe (2000 req/hedef), `--deep` ister | Açıkça yetkilendirilmiş hedef |
| `aggressive` | Tam güç ofansif (50000 req/hedef, 100 req/s, 32 worker) | Yalnızca lab ve yazılı izinli hedef |

```powershell
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost --profile safe
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost --profile deep --deep
```

## 6. Agresif tarama (`--aggressive`)

`--aggressive` tek bayrakla tam güç açar: `active=true`, `safe=false`,
`deep=true`, profil `aggressive`, `show-tentative=true` (değiştirmediğin
sürece). Tüm dedektörler, tüm HTTP metotları, genişletilmiş bütçe.

> DİKKAT: Yalnızca kendi lab'ın veya yazılı izinli hedefin üzerinde kullan.
> Üçüncü parti sistemlere agresif payload, timing döngüsü veya OOB gönderme.

```powershell
go run ./cmd/gash scan --target http://127.0.0.1:8081 --scope 127.0.0.1 --aggressive --format json
```

WAF ile karşılaşırsan tarama durmaz: durum `waf_detected` / `waf_challenges`
sayaçlarına işlenir. Agresif modda sınıflı semantik varyantlar denenir
(header/HPP/encode/yorum/case + SQLi `/**/`/versioned comment/HEX/CHAR/CHR +
yüzde/GBK quote ve `%0b`/`%0c`/`%a0` whitespace farkları + XSS alternatif
tag/entity/Unicode + shell `${IFS}` + path encode; content-type switching
(JSON→text/plain/vendor, form→multipart, multipart duplicate field); JSON
duplicate-key/Unicode-escape parser farkları; path-normalization `//`, `/./`,
`;`; IP spoof header'ları; en fazla 16, aynı kapsam ve bütçe içinde). Cloudflare/Akamai/Imperva/DataDome/PerimeterX/AWS
WAF/Sucuri/F5/Kasada challenge sayfaları untrusted kabul edilir ve
`waf_challenges` sayacına işlenir; host-genelinde plugin skip uygulanmaz.
Proxy rotasyonu ve per-target rate limit devrede kalır. Headless Chrome challenge
sayfasını `payload_waf_challenge` / `control_waf_challenge` olarak blocked
döndürür; challenge DOM'u hedef kanıtı sayılmaz. Anti-bot stealth kapsam
dışıdır; IP engeli devam ederse `--no-proxy` veya güvenilir proxy kullanın.
Blok sayfanın kendisi asla kanıt sayılmaz. Chunked gönderim desteklenmez
(bkz. `docs/known-limits.md`).

## 7. Kimlik ve kapsam (P2)

Kimlik gerektiren sayfaları test etmek için:

```powershell
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost --active `
  --auth-header "Authorization: Bearer TOKEN" --cookie "session=abc"
```

İki kullanıcılı yetki (BOLA/IDOR) matrisi için iki kimlik birlikte verilir
(`--active` şart, bulgular daima `tentative` ve elle doğrulanır):

```powershell
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost --active `
  --auth-user-a "Authorization: Bearer AAAA" --auth-user-b "Authorization: Bearer BBBB"
```

Değerler asla loglanmaz; raporda yalnızca maskeli özet görünür.

Teknoloji kapısı (`--tech`) ve TCP probları:

```powershell
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost --tech wordpress,graphql
go run ./cmd/gash scan --target https://localhost:8443 --scope localhost --active --tcp-banner localhost:22
```

Motor ayrıca yanıttan teknolojiyi kendisi çıkarır (Server başlığı, cookie
adı, `wp-json`/`_next/`/`graphql` izleri, favicon); `--tech` vermesen bile
uygun dedektör açılır. Görülen yetenekler (`login-form`, `graphql-endpoint`)
zincir beslemesine girer. Detay: `docs/auth.md`, `docs/api-discovery.md`.

## 8. Trust (Tier 3)

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
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost --strict-plugins
```

`--strict-plugins` yalnızca güven verilmiş Tier 3 çalıştırır.

## 9. Suppress

Bulgu gizlemek / geri almak için kullanılır:

```powershell
go run ./cmd/gash suppress list
go run ./cmd/gash suppress add <finding-id>
go run ./cmd/gash suppress remove <finding-id>
```

## 10. OOB notu

OOB (Out-of-Band), kör açıklar için dış doğrulama kanalıdır.

- `--oob-server` boşsa OOB kapalıdır.
- Seçenekler:
  - `local`: dahili dinleyici; hedef bu makineye erişebiliyorsa çalışır.
  - `interactsh`: public interactsh havuzu; tak-çalıştır ama **üçüncü taraf**
    servistir, callback metadatası ağınızdan çıkar.
  - `interactsh://host`: kendi interactsh sunucunuz; hassas hedefler için
    önerilir. Token gerekiyorsa `--oob-token` veya `GASH_OOB_TOKEN`.
  - `https://...`: custom self-hosted API.
- `oob=required` bir plugin, sunucu yokken hiç çalışmaz. Sahte `tentative` üretmez, dürüstçe atlanır (skip).
- `--oob-server` verirsen `--active` de zorunludur. Çünkü OOB payload göndermek invasive sayılır.
- Interactsh kaydı başarısız olursa tarama durmaz; `oob-provider` skip kaydı
  rapora yazılır ve OOB plugin'leri kanıt üretmez.

Özet: `--oob-server` yoksa blind/OOB bulgusu bekleme, bu normaldir.

## 11. Raporlar ve CI

```powershell
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost --format sarif --output rapor.sarif
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost --format junit --output rapor.xml
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost --fail-on firm
```

`static-execution-evidence` raporlanır ancak `firm` eşiğinin altındadır.
`--fail-on firm|confirmed` CI kapısıdır: eşik ve üstü bulgu varsa çıkış kodu
1 olur. Metrik kapıları (`TestMetricGate`, korpus, bench) için
`docs/metrics/README.md` ve `docs/ci-integration.md` dosyasına bak.

## 12. SSS

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
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost --show-tentative
```

**Shell tamamlama var mı?**

Evet:

```powershell
go run ./cmd/gash completion --help
```

Altında `bash`, `zsh`, `fish`, `powershell` vardır.

**Neleri yapamaz?**

Tarayıcılı DOM doğrulama, chunked bypass, CAA kaydı ve Nuclei karşılaştırması
yoktur veya ölçülmemiştir. Bahane değil, kayıt: `docs/known-limits.md`.

## 13. Sorumlu kullanım

- Yalnızca izinli hedef tara.
- `--scope` ile kapsamı dar tut.
- Varsayılan `--safe` modda kal; `--active`/`--aggressive` yalnızca izinli lab'da.
- OOB sunucusu kurmadan OOB açmaya çalışma.
- Secret ve oturum değerlerini rapora elle yapıştırma.

Detay: `docs/SECURITY.md`, `docs/plugin-development.md`.
