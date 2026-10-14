# Gash — Faz 0 Kapsam Kararları (`00-scope.md`)

- **Durum:** Faz 0 çıktısı — kod YOK, motor kodu yazılmadı.
- **Tarih:** 12 Ekim 2026 (UTC)
- **Kaynak spec:** `benioku.txt` (Gash, sıfırdan bağımsız Go projesi; migrasyon yok, önceki kod yok, referans yok)
- **Faz kapısı:** Bu dosya sunulur, **DURULUR, onay beklenir.** Faz 1'e geçilmez, kod yazılmaz.

---

## 1. Ne yapıldı (Faz 0)

Faz 0, `benioku.txt §7`'de tanımlandığı üzere kodsuz kapsam kesinleştirmedir. Bu dosyada yapılanlar:

1. **Go sürümü kesinleştirildi:** `1.26.8` (detay §2).
2. **CLI framework kararı verildi:** `cobra` (detay §3).
3. **goja vs Starlark nihai kararı verildi:** `goja` varsayılan/nihai (detay §4).
4. **`hashicorp/go-plugin` Tier 3 POC değerlendirmesi yapıldı:** uygunluk + riskler + POC kapsamı (detay §5).
5. **Tehdit modeli + hedef kullanım ortamı tanımlandı:** bug bounty / kurumsal pentest / CI-DAST; OOB varsayılan-kapalı davranışı ve SARIF önceliğine etkisiyle birlikte (detay §6).
6. **H1/H2 geriliminin Faz 0 karşılığı donduruldu:** ilke olarak hangi garantinin hangi fazda mekanizmaya dönüşeceği (detay §7).
7. **B1–B11 durumu işaretlendi:** Faz 0 için tamamı "henüz uygulanabilir değil / planlandı" (detay §9).
8. **Açık Sorular (5) + Açık Riskler listelendi** (detay §10).

Kod, `go.mod`, proto, şema, test — hiçbiri yazılmadı. Bu bilinçli bir kapıdır: Faz 1 mimari detayları bu kararların üstüne inşa edilecek.

---

## 2. Karar D1 — Go sürümü: `1.26.8`

### Karar

- **Toolchain:** `go1.26.8`
- **`go.mod` dili:** `go 1.26.0` (dil sürümü alt sınırı; Go 1.21+ semantiğinde minimum dil sürümü)
- **CI imajı:** `golang:1.26.8-bookworm`, `GOTOOLCHAIN=go1.26.8`, `CGO_ENABLED=0`
- **Desteklenen build matrisi:** `linux,darwin,windows × amd64,arm64` (`GOOS/GOARCH` cross-compile; `windows/arm` 32-bit ölü port hariç — Go 1.25+ notu)
- **Modül yolu:** `module github.com/<org>/gash` (org adı Faz 1'de netleşir; `<org>` placeholder olarak kalır, kod yok)

### Gerekçe

1. **Destek durumu (Eylül 2026 verisi):** desteklenen hatlar yalnızca `1.26` ve `1.27`'dir (son sürümler `1.26.8` ve `1.27.1`, ~1 Eylül 2026). `1.23`, `1.24`, `1.25` hatları EOL'dur (`1.25` EOL: 19 Ağu 2026; `1.24` EOL: Şub 2026; `1.23` EOL: Ağu 2025). Spec'teki "Go 1.23+" alt sınırı bu yüzden Faz 0'da daraltılmak zorundaydı: EOL bir toolchain ile güvenlik aracı gemilenmez (stdlib güvenlik yaması alınamaz).
2. **Olgunluk vs yenilik dengesi:** `1.27.1` (19 Ağu 2026) karar tarihinde ~7 haftalıktır. Güvenlik aracı için `.0/.1` sürümü seçmek kıdemli mühendislik değildir: `golangci-lint`, `goja`, `hashicorp/go-plugin`, distro paketleri ve CI imajları geriden gelir. `1.26` hattı (Şub 2026'dan beri, 8 yama) pişmiş, tüm bağımlılıklarla doğrulanmış olandır.
3. **İhtiyaç duyulan dil/stdlib özellikleri `1.26`'da tamamdır:** generic type alias (1.24'te stabilize), `unique` paketi, `slices`/`maps`, `atomic.Int64`, `log/slog`, `net/http` yönlendirme iyileştirmeleri, `testing/synctest` olgunlaşması, range-over-func, toolchain otomatik indirme (`GOTOOLCHAIN`). `1.27`'nin getirdiği deneysel işler (örn. deneysel GC, `encoding/json/v2` deneyi) GASH çekirdeği için gerekli değildir; deneysel API'ye çekirdek bağlanmaz.
4. **Dağıtım kısıtı:** `CGO_ENABLED=0` tek statik binary + cross-compile hedefi, `1.26.8`'de tüm hedef platformlarda sorunsuzdur. `goja` (saf Go, cgo yok) ve `go-plugin` (ayrı process) bu matrisle uyumludur.
5. **Kurumsal gerçeklik:** hedef ortamlardan biri kurumsal pentest / CI-DAST'tir; Ubuntu 26.04 (`golang-defaults 1.26`), snap `1.26/stable`, Homebrew `go@1.26` yaygınlığı, `1.26` seçimini operasyonel olarak en sürtünmesiz desteklenen sürüm yapar.

### Reddedilen alternatifler

| Alternatif | Neden reddedildi |
|---|---|
| `1.23.x` / `1.24.x` (spec'in alt sınırı) | EOL; güvenlik yaması yok. Güvenlik aracının toolchain'i desteksiz olamaz. |
| `1.25.x` | 19 Ağu 2026 itibarıyla EOL; seçilemez. |
| `1.27.1` (en güncel) | ~7 haftalık; linter/CI/distro olgunluğu yetersiz, deneysel API riski. Faz 1–2'de toolchain olarak denenebilir ama taban sürüm yapılmaz. Kural: taban = desteklenen hatların olgun olanı (N-1). |
| "Her zaman latest, pin yok" (`GOTOOLCHAIN=auto` + kayan sürüm) | Tekrar üretilebilir build ve güvenlik denetimi için toolchain pinlenmelidir. Kayan sürüm, farklı makinede farklı stdlib davranışı demektir; kanıt standardı olan bir motorda kabul edilemez. |
| `1.22` altı / eski LTS takıntısı | Dil özellikleri (generic alias, `slices`, `unique`, `synctest`) kaybedilir; GASH'in scheduler/oracle kodunda net kayıp. |

### İdiomatik Go vizyonu (bu karara bağlı)

- `context.Context` deadline/iptal her katmanda (plugin yürütme dahil) birinci sınıf parametre olacak (Faz 1'de arayüzlere işlenecek, Faz 2'de enforce edilecek).
- `error` wrapping: `fmt.Errorf("…: %w", err)` zorunlu; `%v` ile yutma yok; `errors.Is/As` ile test edilebilir hata zincirleri.
- `golangci-lint` + `go vet` CI'da zorunlu kapı olacak (Faz 2'den itibaren); Faz 0'da yalnızca ilke olarak donduruldu.

---

## 3. Karar D2 — CLI framework: `cobra`

### Karar

- **Seçim:** `github.com/spf13/cobra` (+ transitive `spf13/pflag`). Config dosyası ihtiyacı için `spf13/viper` **opsiyonel, lazy**: yalnızca `scan` ve `plugins` komutları config okursa eklenir; Faz 1'de CLI yüzeyi netleşince kesinleşir. Shell completion (`bash/zsh/fish/powershell`) ve `man` üretimi cobra'dan alınır.
- **CLI yüzeyi varsayımı (Faz 1'de spec'e dönüşecek):** `gash scan`, `gash plugins list|validate|test|new|trust|info`, `gash bench lab`, `gash suppress add` — ağaç yapısı gerektirir.

### Gerekçe

1. **Alt-komut ağacı zorunluluğu:** GASH CLI'si tek bayraklı bir tarayıcı değil; `plugins trust` gibi güvenlik-duyarlı alt komutlar, `bench lab` gibi ayrı modlar içerir. Bu ağaç + bayrak kalıtımı + `PreRunE` politika kapıları (örn. `--active` olmadan active plugin çalıştırma) cobra'nın çekirdek gücüdür.
2. **Operasyonel çıktı:** completion + dokümantasyon (`GenManTree`, `GenMarkdownTree`) out-of-the-box gelir. Bug bounty (hızlı terminal kullanımı) ve kurumsal pentest (denetlenebilir CLI, man sayfası) için kritiktir.
3. **Ekosistem ve işe alım:** `kubectl`, `gh`, `hugo` ile aynı framework; topluluk katkıcısı için öğrenme maliyeti sıfıra yakındır. Windows'ta sorunsuz çalışır (Tier 3'ün Windows zorunluluğuyla uyumlu).
4. **Test edilebilirlik:** `cmd` ağacı `internal/` paketlerinden ayrılır; `cmd/gash/main.go` ince tutulur (sadece `Execute()`), tüm mantık test edilebilir paketlerde. Bu, `golangci-lint` temizliğiyle birlikte kıdemli Go standardıdır.

### Reddedilen alternatifler

| Alternatif | Neden reddedildi |
|---|---|
| `stdlib flag` (+ el yapımı subcommand) | Ağaç, completion, man, kalıtımlı bayrak için yeniden icat gerekir. H1'e aykırı: CLI sürtünmesi artar, bakım yükü çekirdeğe biner. |
| `urfave/cli v3` | Yetkin kütüphane, ancak v2→v3 API kırılması ve daha küçük ekosistem; cobra kadar completion/man/örnek birikimi yok. Güvenlik aracında "az sürpriz" kazanır. |
| `projectdiscovery/goflags` (Nuclei ailesi) | Nuclei/httpx'te kanıtlanmış, grup-bazlı bayrak UX'i güçlü. Ancak genel toplulukta bilinirliği cobra'dan düşük, completion/man üretimi zayıf, GASH'in `trust`/`bench` gibi güvenlik-ritüeli komutları için cobra'nın `PreRunE` + `ValidArgsFunction` modeli daha uygun. Not: PD araçlarıyla entegrasyon (pipe/JSON birlikte çalışma) Faz 1'de CLI bayrak isimlerinde `goflags` konvansiyonlarıyla uyumlu seçilerek telafi edilir; framework kopyalanmaz. |
| `kong` / struct-tag tabanlı CLI | Tag-magic; büyük komut ağacında okunabilirlik ve test edilebilirlik düşer. `golangci-lint` (öz. `govet`, `staticcheck`) ile daha az şeffaf. |
| `bubbletea` (TUI-first) | Kapsam dışı (spec §9: GUI yok). CI-DAST'te non-TTY zorunluluğu TUI'yi dışlar; önce non-interaktif çekirdek, TUI ancak gelecek iş. |

---

## 4. Karar D3 — Tier 2 script motoru: `goja` (nihai)

### Karar

- **Seçim:** `github.com/dop251/goja` — Tier 2 (`.js`) için nihai karar. Starlark değerlendirme dışı bırakıldı (aşağıda gerekçe).
- **Kilit güvenlik profili (Faz 1'de spec, Faz 2'de enforce):** `require` yok, dosya I/O yok, ham soket yok; host yalnızca `probe`, `ctx`, `host.oracles.*`, `host.candidate()` binding'lerini enjekte eder; `eval`/`Function` constructor host tarafında devre dışı; CPU/instruction limiti (`vm.SetMaxCallStackSize` + `vm.Interrupt()` ile execution timeout); regex yalnızca Go `regexp` (RE2, backtracking yok) üzerinden.
- **Frontmatter:** dosya başı sabit YAML frontmatter; metadata taraması goja VM başlatmadan yapılır (warm keşif bütçesi §8 ile ilişkili).

### Gerekçe

1. **Topluluk adaptasyonu (H1):** JavaScript, hedef toplulukta (bug bounty, web güvenliği) en yaygın ikinci dildir. Nuclei'nin "code protocol"ünde fiilen kullanılan motorun goja olması, yaklaşımın bu problem alanında kanıtlandığı anlamına gelir — sıfırdan ispat yükü yoktur.
2. **Gerçek iptal (H2 + operasyonel):** `vm.Interrupt()` script'i ortasında güvenilir şekilde keser. Python thread'lerinin "zorla öldürülemez" sorunu Tier 2'de bu mekanizmayla çözülür; `--plugin-timeout` (varsayılan 30sn) gerçek bir garantiye dönüşür (Faz 2'de testle kanıtlanacak).
3. **Saf Go, cgo yok:** cross-compile matrisini bozmaz; `CGO_ENABLED=0` korunur; Windows dahil her hedefte aynı sandbox.
4. **ReDoS yapısal bağışıksığı:** JS regex'i kullandırmayıp tüm regex işini Go `regexp`'e (RE2) yıkma kararı yalnızca goja ile temiz uygulanır; Starlark'ta da yapılabilir ama JS ekosisteminden kopyalanan payload/regex örnekleri goja'da birebir çalışır, Starlark'ta port ister.
5. **I/O kontrolü:** Tier 2'nin tüm ağ erişimi `probe.send()` üzerinden geçmek zorunda; doğrudan `fetch`/`net` yok. Bu, `PolicySession` (`http.RoundTripper` sarmalayıcı) ile bütçe/scope/rate-limit enforcement'ın tek noktada yapılmasını sağlar.

### Reddedilen alternatifler

| Alternatif | Neden reddedildi |
|---|---|
| `Starlark` (`go.starlark.net`) | Daha kısıtlı/deterministik ve hermetik olması teorik avantaj; pratikte üç kayıp: (a) sözdizimi topluluğa yabancı (Python-benzeri ama top-level `if`/`for` yok, global tek-atama, `recursion`/`set`/`float` flag-gated — plugin yazarına "neden çalışmadı" sürtünmesi), (b) host binding boilerplate'i daha fazla (her I/O host enjekte; goja'da da öyle ama JS'te örnek/pattern havuzu büyük), (c) Nuclei-kanıtı yok. Determinizm ihtiyacı GASH'te zaten motor katmanında (oracle + baseline + dedup) karşılanıyor; dile hermetiklik yüklemek H1'i feda eder. |
| `gopher-lua` / Lua | Teknik olarak yetkin ve hafif; ancak web-güvenliği topluluğunda Lua yazar kitlesi JS'in çok altında. H1 (sürtünmesiz katkı) kaybeder. |
| `wazero` / WASM-guest plugin | İzolasyon olarak en güçlü aday; ancak toolchain sürtünmesi (her plugin için WASM derleme), debug zorluğu ve `probe` host-fonksiyon köprüsünün olgunlaşmamışlığı, community-drop-in vizyonuyla çelişir. Gelecek iş olarak not edilir; Tier 3'ün yerini almaz. |
| `otto` (JS, bakımsız) | Bakım durumu ve `Interrupt` olgunluğu goja'nın gerisinde. |
| `yaegi` (Go interpreter) | "Go yaz, drop-in çalışsın" cazip görünür ama sandbox değildir; `import` kontrolü, kaynak limiti ve deterministik API yüzeyi goja kadar net değildir. Ayrıca Tier 1/2 vaadi "çekirdek Go bilgisi olmadan katkı"dır; Go yorumlayıcı bu vaadi tersine çevirir. |
| Native `.so` (`plugin.Open`) | Spec §2.2'de zaten elendi: Windows yok, toolchain eşleşme zorunluluğu, unload yok. Tekrar değerlendirilmedi — karar değişmedi. |

---

## 5. Karar D4 — `hashicorp/go-plugin` Tier 3 POC değerlendirmesi

### Karar

- **Değerlendirme sonucu:** Tier 3 için `hashicorp/go-plugin` **uygun, Faz 2'de POC'a değer.** Sürüm pini (POC için): `v1.8.0` (Nis 2026; `pkg.go.dev`'de görünen güncel hat). Protokol: **yalnızca gRPC**; `net/rpc` modu yasaklanır (Faz 1 proto kararıyla dondurulacak).
- **POC kapsamı (Faz 2, kod henüz yok):** minimal `VerifyRequest/VerifyResponse` echo plugin'i + `trust` kapısı + timeout-kill (`SIGTERM` → süre sonu `SIGKILL`) + sürüm handshake uyumsuzluğunda fail-closed. POC geçemezse Tier 3 Faz 3'ten düşer; Tier 1/2 etkilenmez (katmanlar bağımsız ilerler).
- **Güven ilkesi değişmedi:** Tier 3 **otomatik keşfedilmez**, `gash plugins trust <path>` + `sha256` pinleme olmadan asla çalıştırılmaz (`--strict-plugins`'te yalnızca önceden trust edilmişler).

### Uygunluk gerekçesi

1. **Savaşta kanıt:** Terraform/Nomad/Vault/Boundary/Waypoint'te yıllardır üretimde; 6k+ star, 3.7k+ bağımlı, aktif bakım (2026 sürümleri mevcut). Plugin-crash-host'u-öldürür sorununu çözer (ayrı PID).
2. **Windows sorununu çözer:** native `.so`'nun öldüğü yerde (`plugin.Open` Windows yok) process+RPC modeli çalışır — GASH'in cross-platform zorunluluğuyla uyumlu tek native yoldur.
3. **Gerçek zorla sonlandırma:** `context` iptali → process kill'e çevrilir. Önceki taslaklardaki "thread öldürülemez" sorunu Tier 3'te tamamen kapanır (Tier 2'de `vm.Interrupt`, Tier 3'te kill — iki katman, iki gerçek garanti).
4. **Dil bağımsızlığı:** Tier 3 yazarı Go'ya mahkûm değildir (herhangi bir dilde gRPC server + ince handshake boilerplate). Resmi/ileri düzey genişletmeler (özel kripto, protokol parser) için doğru kapıdır.
5. **Aynı IR, aynı hat:** Tier 3 de `PluginSpec` IR'ına derlenir ve Candidate→Verify→Finding hattından geçer; Finding üretme yetkisi yoktur. Performans/özellik için kanıt standardı esnetilmez (H1/H2 §7).

### Riskler (POC'un kapatması gerekenler)

| # | Risk | Büyüklük | Azaltma / POC kapısı |
|---|---|---|---|
| R-T3-1 | **Supply-chain / sessiz çalıştırma:** klasöre düşen binary'nin çalışması RCE demektir | Kritik | Otomatik keşif yok; `trust` + `sha256` pin; manifestteki `binary` yolu allowlist dışıysa fail-closed. POC'ta test: trust'suz spawn denemesi asla exec yapmaz. |
| R-T3-2 | **Handshake/version uyumsuzluğu:** host–plugin `api_version`/proto uyuşmazlığı sessiz yanlış davranışa dönüşebilir | Yüksek | Versioned handshake; uyumsuzlukta çalıştırma yok + raporda sebep. POC'ta negatif test. |
| R-T3-3 | **Yaşam döngüsü:** asılı plugin (broken pipe, `RPC address` bekleme, graceful-exit başarısızlığı — upstream issue'lar) taramayı kilitleyebilir | Yüksek | Lazy spawn (ilk çağrıda), per-call timeout, `SIGTERM→SIGKILL` zinciri, `Client.Kill()` her yolda (defer + `context` cancel). POC'ta kill-testi zorunlu. |
| R-T3-4 | **Taşıma güvenliği:** local RPC'nin ağa açılmaması gerekir (upstream: "yalnızca güvenilir local ağ") | Yüksek | `AutoMTLS` açık, loopback-only, `--strict-plugins`'te ek daraltma. POC'ta dinleme adresi denetimi. |
| R-T3-5 | **Maliyet:** process spawn ~10–100ms; her probe'da spawn edilirse bütçe patlar | Orta | Long-lived plugin process + çoklu çağrı multiplex (gRPC/HTTP2); spawn yalnızca policy'den geçen pluginde, ilk çağrıda. Warm-keşif bütçesine Tier 3 dahil değildir (metadata manifestten okunur, exec yok). |
| R-T3-6 | **Bağımlılık ağırlığı:** `grpc`, `hclog`, broker/multiplex kodu binary'yi büyütür | Orta | Tier 3 desteği build-tag/opsiyonel modül olarak izole edilir; Tier 1/2-only build şişmez (Faz 1'de modül sınırı çizilecek). |
| R-T3-7 | **Kaynak limiti:** OS limitleri (cgroups/rlimit/Job Objects) motor dışında, platforma özgü | Orta | Faz 1'de platform matrisi; Linux'ta ilk sınıf, Windows/macOS'ta best-effort + dokümante. POC Linux'ta, diğer OS'ler Faz 3'te. |
| R-T3-8 | **Log/stdout karışması:** plugin stdout'una yazarsa handshake bozulabilir (bilinen upstream şikâyeti) | Düşük-Orta | SDK (`pkg/gashsdk`) stdout'u yasaklar, log `hclog` stderr hattına; kontrat testiyle enforce. |

### Reddedilen alternatifler (Tier 3 taşıması)

| Alternatif | Neden reddedildi |
|---|---|
| Native `.so` (`plugin.Open`) | §2.2 + D3: Windows yok, toolchain kilidi, unload yok. Community-drop-in ile taban tabana zıt. |
| El yapımı `os/exec + JSON-RPC/stdio` | Başlangıçta hafif görünür; ancak handshake, mTLS, multiplex, broker, crash-detect yeniden icat edilir. go-plugin'in 10 yıllık hata birikimini sıfırdan ödemek kıdemli seçim değildir. |
| `net/rpc` modunda go-plugin | Eski protokol; gRPC'nin multiplex + dil-bağımsızlığı + tooling'i varken seçilmez. Tek protokol (gRPC) kuralı karmaşıklığı yarıya indirir. |
| WASI/WASM Tier 3 | D4'te değil; olgunluk ve toolchain sürtünmesi nedeniyle Tier 3 yerine geçemez (bkz. D3). İzleme maddesi olarak kalır. |
| Uzak plugin registry/market | Spec §9'da kapsam dışı. Tier 3 imzalama altyapısı da kapsam dışı (gelecek iş). POC buna dokunmaz. |

---

## 6. Karar D5 — Tehdit modeli + hedef kullanım ortamı

### 6.1 Tehdit modeli (Faz 0 dondurması; Faz 1'de `threat-model.md`'ye genişler)

**Güven sınırları:**

1. **Plugin yazarı = güvensiz (untrusted).** Tier 1: by-construction güvenli (kod yok). Tier 2: sandbox + host-binding allowlist. Tier 3: tam güvensiz native kod — yalnızca explicit `trust` ile çalışır.
2. **Hedef = güvensiz + hassas.** Yanıtlar düşmanca olabilir (header injection, sonsuz redirect, dev body, zip-bomb-vari gövde, yavaş yanıt). Motor: boyut/timeout cap, redirect limiti, `Untrusted` işaretleme, baseline-dışı kanıtı ret.
3. **OOB altyapısı = ayrıcalıklı yan kanal.** Hedefi üçüncü partiye istek atmaya zorlamak kapsam/NDA ihlalidir → varsayılan kapalı (bkz. 6.3).
4. **Rapor tüketicisi = aşağı-akış güveni.** SARIF/JSON tüketen CI, bulguya göre build kırar → FP maliyeti yüksektir; kanıt standardı + `tentative` bastırma bunun içindir.
5. **Yerel makine = korunacak varlık.** World-writable plugin dosyası/dizini yüklenmez; Tier 3'te `sha256` pin; cache (`plugins.db`) mtime+sha256 ile doğrulanır.

**Temsilci saldırı senaryoları (tasarım sürücüsü):**

- Kötü niyetli Tier 2 script: exfil (`probe` dışı ağ yok → başarısız olmalı), FS okuma (`require`/I/O yok → başarısız), sonsuz döngü (`Interrupt` → `PluginResult{Error: timeout}`), ReDoS (JS regex yok, Go RE2 → yapısal bağışık).
- Kötü niyetli Tier 3 binary: trust'suz çalıştırma denemesi (exec yok, uyarı + skip), hash uyuşmazlığı (fail-closed), panic (host etkilenmez, scheduler devam).
- Gürültülü plugin: aynı `Evidence` hash'iyle N>10 aday (varsayılan) → `demoted` + kalanı `tentative` + rapor notu (noisy-breaker).
- Hedeften gelen kirlenme: stored canary'yi başka plugin kanıt sayamaz (`TaintedByPlugin` etiketi, oracle seviyesinde ret); WAF/blok sayfası kanıt sayılmaz (baseline `Untrusted`).
- Politika ihlali: `safe=true` plugin POST/PUT denerse `ErrPolicyViolation` → `PluginResult{PolicyError}`, tarama durmaz.
- OOB suistimali: `--oob-server` verilmeden OOB çağrısı → `skipped (oob-not-configured)`, plugin hatası sayılmaz; `oob:required` plugin hiç çalışmaz (sahte `tentative` yok).

### 6.2 Hedef kullanım ortamı matrisi

| Boyut | Bug bounty (hacker) | Kurumsal pentest (denetimli) | CI-DAST (pipeline) |
|---|---|---|---|
| Tipik hedef | Kapsamlı program, vahşi hedef; rate-limit/WAF yaygın | Yetkili, tanımlı kapsam (CIDR/domain allowlist zorunlu) | Ephemeral (preview/review ortamı, localhost veya iç ağ) |
| Varsayılan politika | `safe` (pasif + güvenli probe); `--active/--deep` bilinçli opt-in | `safe` + `--scope` allowlist zorunlu; `requires_auth` oturumu desteklenir | `safe` + sıkı bütçe (`--max-requests-*`), deterministik seed; `deep` kapalı |
| OOB | Genelde **kapalı** (kendi sunucusu yoksa); `required` pluginler atlanır, rapor sebep gösterir | Self-hosted OOB **opsiyonel** (müşteri onayıyla, iç ağda); `--oob-server` + `--oob-wait` ayarlanır | Genelde **kapalı** (egress yok / determinizm); OOB gerektiren sınıflar kapsam dışı bırakılır, kapı SARIF'a dayanır |
| Rapor önceliği | İnsan-okunur `text` + `json` (hızlı triyaj) | `html` (paydaş) + `sarif`/`json` (izlenebilirlik) | **`sarif` birincil** (GitHub Code Scanning / GL SAST entegrasyonu), `json` ikincil |
| Gürültü toleransı | Düşük (programdan ban riski) → rate-limit + bütçe enforcement kritik | Çok düşük (üretim etkisi) → `safe` default + değişiklik izi | Sıfır-tolerans FP → korpus kapısı + `tentative` gizleme kritik |
| Kimlik/denetim | Tek kullanıcı, yerel suppress | Ekip, suppress dosyası versiyonlanır | Makine; suppress + SARIF `suppressions` alanı, build kararı kanıta dayanır |

### 6.3 OOB varsayılan-kapalı davranışına etkisi

Karar değişmedi, Faz 0'da operasyonel karşılığı donduruldu:

- Bayrak verilmeden (`--oob-server` yok): OOB oracle'ı çağrılamaz. `oob: optional` → sessiz düşük-güven modu; `oob: required` (blind SSRF, blind XXE, blind RCE, Log4Shell-tarzı, `confirmed`-için-OOB-isteyen blind SQLi/CMDi) → **hiç çalıştırılmaz**, raporda `skipped (oob-not-configured)`; sahte `tentative` üretilmez (gürültü yerine dürüst skip).
- Bayrak verildiğinde: self-hosted interaction sunucusu (ayrı `cmd/gash-interactsh` binary'si varsayımı; sıfırdan mı interactsh-fork mı — bkz. Açık Soru S1), scan-namespace subdomain, polling/WebSocket korelasyon, scan-sonu bekleme penceresi (varsayılan örn. 60sn, `--oob-wait`).
- Ortam eşlemesi: bounty'de kapalı (kullanıcı kendi sunucusunu kurarsa açılır); pentestte müşteri-onaylı iç OOB; CI-DAST'te kapalı + OOB-sınıfları kapsam dışı (pipeline determinizmi OOB gecikmesiyle bozulmaz).

### 6.4 SARIF önceliğine etkisi

- **SARIF v2.1.0 birincil makine-raporudur** (CI-DAST gereksinimi). Gerekçe: GitHub/GitLab code-scanning entegrasyonu, `ruleId`/`ruleIndex`, `level` (`error/warning/note` ↔ `confirmed/firm/tentative` eşlemesi Faz 1'de), `suppressions`, `fingerprints` ile dedup — JSON bunu standart sunmaz.
- Sıralama: `sarif` (CI kapısı) > `json` (otomasyon/pipe) > `text` (terminal) > `html` (paydaş). Bounty'de fiili kullanım `text/json` olsa da motorun birincil sözleşmesi SARIF'tir; bu, CI-DAST'i hedef ortam olarak ciddiye almanın sonucudur.
- Faz 1'de dondurulacaklar: `ruleId` taksonomisi (CWE eşlemesi dahil mi — bkz. S3), `confidence`→`level` eşlemesi, `tentative`'in SARIF'a yazılıp yazılmayacağı (varsayım: varsayılan yazılmaz, `--show-tentative` ile yazılır + `suppressions` değil `level: note`).

---

## 7. Karar D6 — H1/H2 geriliminin Faz 0 karşılığı

H1 (sürtünmesiz plugin: dosyayı at, çalışsın; sıfır pluginde boş geçerli rapor) ile H2 (plugin'den bağımsız doğruluk: kötü plugin bulgu kirletemez) gerilimlidir. Faz 0'da kod olmadığı için gerilim **mekanizmayla değil ilkeyle** çözülür; her ilke bir faza bağlanır:

| # | İlke (donduruldu) | Gerilimdeki rolü | Mekanizmaya dönüşeceği faz |
|---|---|---|---|
| P1 | Üç tier da aynı `PluginSpec` IR'ına derlenir, aynı Candidate→Verify→Finding hattından geçer | Sürtünmesizlik format seçiminde, doğruluk katmandan bağımsız | Faz 1 (IR + proto spec), Faz 2 (loader/registry/executor) |
| P2 | Plugin `Finding` üretemez; yalnızca `Candidate`. `Severity`/`Confidence` motor-içidir, plugin API'sinde yazma metodu yoktur | Kötü plugin "critical/confirmed" basamaz | Faz 1 (Finding şeması), Faz 2 (contract test B3) |
| P3 | Kanıt standardı oracle'ındır; kanıtsız aday ≤ `tentative`; varsayılan raporda yalnızca `confirmed`+`firm` | Şüphede `tentative`; FP ödülüyle recall şişirilmez | Faz 1 (evidence-standard), Faz 2 (oracle kütüphanesi + korpus kapısı B4) |
| P4 | Tier 1/2 otomatik keşif, Tier 3 explicit `trust` | Sürtünmesizlik güvenli olana, RCE riski allowlist'e | Faz 2 (loader + trust testi B10) |
| P5 | Politika motor tarafından zorlanır (`PolicySession` proxy, `atomic` bütçe, scope/rate-limit) | Beyana güvenilmez (`safe` diyen POST atamaz) | Faz 2 (proxy testi B6) |
| P6 | Fixture'sız plugin `tentative` ile sınırlı; korpusta `firm`+ = build fail | Doğruluk topluluğa değil kapıya dayanır | Faz 2 (harness + korpus B4), Faz 3 (referans plugin metrikleri) |
| P7 | Kirlenme önleme: namespaced `ctx.Shared`, `TaintedByPlugin`, noisy-breaker, motor-tarafı dedup/korelasyon | Kötü/gürültülü plugin diğerlerini etkileyemez | Faz 2 (izolasyon testi B5), Faz 3 (bench) |

Faz 0'da bu ilkelerden hiçbiri esnetilmedi, hiçbiri "gizlice feda edilmedi": sürtünmesizlikten feragat edilen tek yer Tier 3'tür ve bu açık bir güvenlik kararıdır (R-T3-1).

---

## 8. Kapsam ve değişmez kısıtlar (Faz 0 teyidi)

- Varsayılan tarama `safe` kalır (`--deep`, `--active` açık opt-in). Yanlış pozitif ödünüyle recall artırılmaz; şüphede `tentative`.
- OOB varsayılan kapalı, açık opt-in (`--oob-server`).
- Kapsam dışı (şimdilik): GUI, uzak plugin marketi/registry, Tier 3 otomatik imzalama altyapısı.
- `golangci-lint` + `go vet` CI'da zorunlu (Faz 2'den itibaren kapı; Faz 0'da ilke).
- Test-first sıralaması değişmedi: önce oracle/altyapı testleri (Faz 2), sonra plugin'ler (Faz 3).

---

## 9. B1–B11 durumu (Faz 0)

Faz 0'da kod/test olmadığı için **tamamı "henüz uygulanabilir değil / planlandı"** durumundadır. Tablodaki "Plan" sütunu, hangi fazda hangi kapıyla doğrulanacağını taahhüt eder.

| # | Kriter | Faz 0 durumu | Doğrulama planı |
|---|---|---|---|
| B1 | Yeni Tier 1/2 plugin = tek dosya, çekirdek değişmez | Henüz uygulanabilir değil / planlandı | Faz 3 e2e test |
| B2 | Sıfır plugin: çökmez, geçerli boş rapor | Henüz uygulanabilir değil / planlandı | Faz 2 test (boş registry + boş rapor şema geçerliliği) |
| B3 | Plugin doğrudan Finding üretemez; kanıtsız aday ≤ `tentative` | Henüz uygulanabilir değil / planlandı | Faz 2 contract test (oracle-mock + yetkisiz alan yazma denemesi) |
| B4 | Negatif korpusta `firm`+ bulgu = 0 | Henüz uygulanabilir değil / planlandı | Faz 2 CI kapısı (`TestNoFalsePositives`) |
| B5 | Kötü/gürültülü plugin diğer bulguları değiştirmez | Henüz uygulanabilir değil / planlandı | Faz 2 izolasyon testi (± kötü plugin diff) |
| B6 | `safe=true` plugin state-changing istek atamaz | Henüz uygulanabilir değil / planlandı | Faz 2 proxy testi (`ErrPolicyViolation`) |
| B7 | Bozuk plugin (panic/timeout/geçersiz dönüş) taramayı durdurmaz | Henüz uygulanabilir değil / planlandı | Faz 2 fault-injection (panic + `Interrupt` + kill) |
| B8 | Warm keşif ≤150ms | Henüz uygulanabilir değil / planlandı | Faz 2 `go test -bench` + CI regresyon |
| B9 | `oob: required` plugin, `--oob-server` yokken hiç çalışmaz | Henüz uygulanabilir değil / planlandı | Faz 2 test (skip + sebep, sahte `tentative` yok) |
| B10 | Tier 3 plugin açık `trust` olmadan asla çalıştırılmaz | Henüz uygulanabilir değil / planlandı | Faz 2 test (trust'suz exec yok) + POC kapısı |
| B11 | Kodda sabit check sayısı/isim yok | Henüz uygulanabilir değil / planlandı | Faz 2'den itibaren CI grep kapısı |

---

## 10. Açık Sorular ve Açık Riskler

### 10.1 Açık Sorular (en fazla 5 — mimari kararı etkileyenler)

| # | Soru | Varsayım (soruya rağmen ilerlenen) | Etkilediği karar / faz |
|---|---|---|---|
| S1 | OOB interaction sunucusu sıfırdan mı yazılacak (`cmd/gash-interactsh`), ProjectDiscovery `interactsh` mi fork/gömülecek, harici bağımlılık mı kalacak? | Faz 1'de protokol dondurulur; sunucu tarafı için varsayım: önce harici/self-hosted `interactsh` uyumlu client, ayrı binary Faz 3+ (tekerlek icadı yok) | D5 (OOB), Faz 1 OOB protokolü |
| S2 | Tier 3 public SDK (`pkg/gashsdk`) yalnızca Go mu destekleyecek, Faz 3 POC'u başka dil (örn. Python) içerecek mi? | Varsayım: SDK Go-first; gRPC sözleşmesi dil-bağımsız tutulur, Python örneği POC dışı | D4, Faz 3 Tier 3 örneği |
| S3 | SARIF `ruleId` taksonomisi ne olacak (GASH-özgü ID + CWE eşlemesi mi, yalnızca CWE mi)? | Varsayım: `GASH-XXX` birincil + `taxa`/CWE ikincil; Faz 1 evidence-standard ile dondurulur | D5 (SARIF önceliği), Faz 1 Finding şeması |
| S4 | Recall lab'ı hangi sürümlerde pinlenecek (DVWA / Juice Shop / WebGoat sürüm + ağ izolasyon profili)? | Varsayım: `docker-compose.lab.yml` localhost-only, izole network; sürümler Faz 1'de pinlenir | D6 (P6 metriği), Faz 2 lab |
| S5 | `go.mod` org adı (`github.com/<org>/gash`) ne olacak; lisans seçimi (örn. Apache-2.0/MIT/AGPL) Tier 3 SDK'yı etkiler mi? | Varsayım: org placeholder kalır, kod yazılmaz; lisans Faz 1'de hukuk/topluluk kararıyla dondurulur | D1 (modül yolu), Faz 1 repo iskeleti |

Küçük konulardaki varsayımlar (bayrak varsayılanları örn. `--plugin-timeout 30s`, `--oob-wait 60s`, noisy-breaker N=10; `order`/faz isimleri; suppress dosya adı) spec'teki değerlerle aynen devralındı, ayrıca sorulmadı.

### 10.2 Açık Riskler (Faz 0'dan Faz 1'e taşınan)

- **R1 — goja sandbox kaçışı (yeni CVE / yanlış binding):** binding allowlist + `eval` yasağı Faz 2'de kontrat testiyle kilitlenir; goja sürümü `go.sum`'da pinlenir, Dependabot/renovate Faz 2'de açılır.
- **R2 — go-plugin yaşam döngüsü takılmaları (R-T3-3/R-T3-8):** POC başarısız olursa Tier 3 ertelenir; çekirdek yol (Tier 1/2) etkilenmez.
- **R3 — OOB korelasyon gecikmesi ve FP:** bekleme penceresi + correlation-ID disiplini Faz 1 protokolünde; CI-DAST determinizmi için OOB'siz kapı ayrı tutulur.
- **R4 — Timing/Differential oracle'larının gürültülü hedeflerde FP üretmesi:** baseline+jitter ölçümü + N-tekrar + kontrol isteği Faz 1 kanıt standardında; korpus kapısı (B4) geri dönüş sigortasıdır.
- **R5 — Kapsam genişlemesi (GUI/market/imzalama):** spec §9 kapsam-dışılar Faz 1 tasarımında tekrar teklif edilirse reddedilir; bu dosya red gerekçesi olarak referans verilir.

---

## 11. Faz kapısı ve Faz 1'e giriş koşulu

- **Bu dosya Faz 0'ın tek çıktısıdır.** Onaylanmadan Faz 1'e geçilmez, kod yazılmaz.
- **Faz 1 girdisi (taahhüt, henüz başlanmadı):** tam mimari tasarım + her zafiyet sınıfı için Kanıt Standardı + OOB protokol detayı + `PluginSpec` ve Tier 3 `.proto` tanımları + Finding şeması + CLI yüzeyi; çıktılar `docs/architecture.md` + `docs/evidence-standard.md`; sonunda DUR + onay.
- **Onay için sorulan:** yukarıdaki D1–D6 kararları + S1–S5 varsayımları kabul ediliyor mu? Red/görüş varsa hangi karar maddesine (D1..D6) itiraz ediliyor?

*Teslim formatı uyumu: (1) §1, (2) §2–§7 (her kararda gerekçe + reddedilen alternatif), (3) §9 (B1–B11: tamamı planlandı), (4) §10 (riskler/sorular).*
