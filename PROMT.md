# GASH — 2024–2026 Web Zafiyet Araştırmasını Tarama Motoruna Entegre Etme Talimatı

## 1. ANA GÖREV

Sana sağlanan 2024–2026 dönemine ait web uygulaması güvenlik araştırmasını ve mevcut Gash kaynak kodunu birlikte incele.

Senin görevin yalnızca araştırmayı özetlemek veya teorik öneriler sunmak değil. Öncelikle mevcut kod tabanını anlayarak eksik zafiyet sınıflarını, yetersiz kontrolleri, yanlış pozitif kaynaklarını, tespit edilemeyen saldırı yüzeylerini ve mimari darboğazları belirle. Ardından kanıta dayalı iyileştirmeleri mevcut projeye entegre et.

Gash'ın mevcut mimarisini, dilini, modüllerini, çıktı formatlarını ve çalışan özelliklerini koru. Gereksiz yere sıfırdan yazma, çalışan kodu sebepsiz değiştirme ve mevcut tarama modüllerini tekrar eden yeni modüller oluşturma.

**Öncelik sırası:** Gerçek tespit kabiliyeti → düşük yanlış pozitif oranı → güvenli doğrulama → kapsamlı kanıt → performans → raporlama kalitesi.

## 2. ARAŞTIRMA BULGULARINI DOĞRULA

Araştırma belgesindeki her CVE'yi, sürüm bilgisini, CVSS değerini, yama bilgisini ve istismar iddiasını otomatik olarak doğru kabul etme.

Öncelikle şu kaynaklarla çapraz kontrol yap:

- NVD ve MITRE CVE kayıtları
- CISA Known Exploited Vulnerabilities (KEV) kataloğu
- Üreticilerin resmî güvenlik duyuruları ve yamaları
- OWASP Web Security Testing Guide ve OWASP Top 10
- OWASP API Security Top 10
- EPSS ve güvenilir araştırmacıların teknik analizleri
- İlgili projelerin GitHub depoları, düzeltme commit'leri ve sürüm notları

2026 yılı için 9 Ekim 2026 tarihine kadarki verileri değerlendir; yılın tamamlandığını varsayma. Henüz doğrulanmamış, çelişkili veya eksik kaynaklı bulguları ayrı işaretle.

Bir CVE kaydının varlığını, belirli bir hedefin o zafiyetten gerçekten etkilendiğinin kanıtı olarak görme. Ürün, sürüm, yapılandırma ve gerekli önkoşulları eşleştir.

## 3. GASH ÜZERİNDE DENETLENECEK ZAFİYET SINIFLARI

Önce mevcut tarama motorunda her sınıfın bulunup bulunmadığını, ne kadar derin test edildiğini ve hangi kanıtı ürettiğini belirle.

### A. Enjeksiyon ve istemci tarafı açıkları
- Reflected, Stored ve DOM-based XSS
- HTML bağlamı, JavaScript bağlamı, URL ve öznitelik bağlamı ayrımları
- SQL injection ve NoSQL injection
- Server-Side Template Injection (SSTI)
- OS command injection
- LDAP ve diğer bağlama özgü enjeksiyonlar
- Prototype pollution ve güvenli biçimde doğrulanabilen etkileri
- Dosya yükleme üzerinden SVG ve diğer aktif içerik riskleri

Yalnızca payload yanıtında bir kelimenin görünmesine dayanarak XSS veya enjeksiyon bulunduğu sonucuna varma. Yansıma, bağlam, kodlama, filtreleme ve gerçekten doğrulanabilen etkiyi birbirinden ayır.

### B. Yetkilendirme ve kimlik doğrulama
- IDOR ve API BOLA
- Broken Function Level Authorization
- Broken Object Property Level Authorization
- Rol ve kullanıcılar arası erişim kontrolü
- JWT doğrulama hataları
- OAuth/OIDC yönlendirme ve doğrulama hataları
- Oturum yönetimi, parola sıfırlama ve MFA akışları
- CSRF ve CORS yanlış yapılandırmaları
- GraphQL yetkilendirme ve aşırı veri erişimi

Yetkilendirme testlerinde yalnızca izinli laboratuvar hesaplarını ve sentetik kayıtları kullan. Farklı kullanıcıların birbirine ait gerçek verilerini çekme.

### C. Sunucu ve altyapı zafiyetleri
- SSRF ve güvenli biçimde doğrulanabilir iç ağ erişimi riskleri
- Path traversal ve dosya erişim kontrolleri
- Güvensiz dosya yükleme ve arşiv açma işlemleri
- Request smuggling ve proxy/backend ayrışmaları
- Web cache poisoning ve cache deception
- Deserialization kaynaklı riskler ve RCE göstergeleri
- Race condition ve time-of-check/time-of-use hataları
- WebSocket güvenlik kontrolleri
- Bilgi sızıntıları, yedek dosyalar, loglar, debug uç noktaları ve yanlış yapılandırmalar
- Bulut depolama izinleri ve hassas metadata erişimi
- CI/CD, bağımlılık zinciri ve yanlışlıkla yayımlanmış sırlar

Bu sınıflarda tehlikeli işlemleri doğrudan canlı hedeflerde gerçekleştirme. Örneğin SSRF testlerinde hassas bulut kimlik bilgilerini okuma; dosya yükleme testlerinde sunucuda çalışabilir kod bırakma; race condition testlerinde gerçek ödeme veya veri silme işlemleri çalıştırma.

### D. Nadir ve zincirleme zafiyetler
Araştırmadaki sıradışı vakaları ayrıca değerlendir:

- Güvensiz SVG işleme ile Stored XSS zincirleri
- Yetkisiz eklenti veya bileşen kurulumu üzerinden oluşan riskler
- Path traversal ile hassas yapılandırma dosyalarının açığa çıkması
- CI/CD token sızıntısı ve bağımlılıkların ele geçirilmesi
- Kimlik doğrulama veya yetkilendirme açığının başka bir zafiyetle zincirlenmesi
- Cache, reverse proxy ve uygulama davranışı arasındaki tutarsızlıklar
- Normal tarayıcıların veya basit imza tabanlı taramaların kaçırabileceği bağlama özgü açıklar

Zincirleme zafiyetlerde her halkayı ayrı değerlendir. Bir sonraki aşamanın yalnızca teorik olarak mümkün olması, tam saldırı zincirinin doğrulandığı anlamına gelmez.

## 4. MEVCUT MOTORU ANALİZ ET VE ENTEGRE ET

Kod değişikliğinden önce mevcut Gash deposunu incele ve şu soruları yanıtla:

1. Tarama akışı ve modül mimarisi nasıl çalışıyor?
2. Hangi zafiyet sınıfları mevcut, hangileri eksik?
3. Mevcut kontroller hangi durumlarda açık kaçırıyor?
4. Hangi tespitler yalnızca imzaya veya yanıt metnine dayanıyor?
5. HTTP oturumu, çerezler, kimlik bilgileri, yönlendirmeler ve içerik kodlaması nasıl yönetiliyor?
6. Tarama kapsamı, hız sınırları, eşzamanlılık ve hata yönetimi yeterli mi?
7. Bulgular için tekrarlanabilir kanıt ve güven seviyesi üretiliyor mu?

Analizden sonra önem derecesi, uygulanabilirlik ve geliştirme maliyetine göre bir öncelik planı oluştur. Ardından gerekli değişiklikleri doğrudan mevcut mimariye uygula.

Yeni bir modül gerçekten gerekiyorsa mevcut arayüzlerle uyumlu tasarla. Aynı kontrolü farklı isimlerle çoğaltma. Mevcut özelliklerin geriye dönük uyumluluğunu koru.

## 5. TESPİT KALİTESİ VE GÜVEN

Her zafiyet kontrolü mümkün olduğunca aşağıdaki aşamaları içersin:

1. **Önkoşul tespiti:** Hedefin ilgili ürünü, uç noktayı veya işlevi içerdiğini belirle.
2. **Aday oluşturma:** İlgili parametreyi, başlığı, gövde alanını veya akışı bul.
3. **Güvenli doğrulama:** Yalnızca izin verilen hedeflerde düşük etkili kontrol yap.
4. **Kanıt toplama:** İstek/yanıt ilişkisini, ilgili bağlamı ve tespit ölçütlerini sakla.
5. **Yanlış pozitif kontrolü:** Normal davranışla karşılaştır; mümkünse kontrol deneyi kullan.
6. **Derecelendirme:** Doğrulanmış, yüksek güvenli şüpheli, düşük güvenli veya doğrulanamadı olarak ayır.
7. **Raporlama:** Etkiyi, önkoşulları ve düzeltme önerisini açıkça belirt.

Her kontrol için olumlu sonuç ve olumsuz sonuç senaryolarını düşün. Zaman aşımı, HTTP 500, WAF engeli, genel hata metni veya beklenmeyen yanıtı tek başına zafiyet kanıtı kabul etme.

Mümkün olduğunda doğrulamaları gerçek kullanıcı verilerine dokunmadan, benzersiz canary değerleri, sentetik hesaplar ve kontrollü laboratuvar uç noktalarıyla gerçekleştir.

## 6. GÜVENLİ ÇALIŞMA SINIRLARI

Gash yalnızca kullanıcının sahip olduğu, açıkça test izni aldığı veya izole laboratuvar ortamında çalıştırılan varlıklarda aktif doğrulama yapmalı.

Varsayılan davranış:

- Önce kapsamı ve izin verilen hedefleri doğrula.
- Varsayılan olarak pasif ve düşük etkili kontrolleri tercih et.
- Tehlikeli testler için açık opt-in, düşük hız ve ayrı güvenlik sınırları uygula.
- Veri silme, gerçek hesap ele geçirme, kalıcılık oluşturma, gizlenme, gerçek kimlik bilgilerini dışarı çıkarma veya yetkisiz erişim üretme işlemleri gerçekleştirme.
- Bulunan sırları ve kişisel verileri raporda maskele.
- Tarama döngülerinde zaman aşımı, hız sınırı, güvenli durdurma ve hata izolasyonu kullan.
- Kanıt bulunamadıysa sonucu başarılı istismar olarak gösterme.

Bu sınırlar, güvenlik testinin kalitesini düşürmek için değil; tespitleri kontrollü ve tekrarlanabilir hale getirmek için uygulanmalıdır.

## 7. STANDART BULGU ÇIKTISI

Mevcut raporlama formatına uyumlu olacak şekilde, mümkün olduğunca her bulguda şu alanları üret:

- Bulgu kimliği ve zafiyet sınıfı
- Hedef URL ve etkilenen parametre/işlev
- İlgili CWE ve doğrulanmışsa CVE
- Şiddet seviyesi ve gerekçesi
- CVSS ve sürüm bilgisi; kaynak ve vektör mevcutsa
- Güven seviyesi ve doğrulama durumu
- Etkilenen bileşen/sürüm ve önkoşullar
- İsteğin ve yanıtın güvenli, hassas bilgilerden arındırılmış kanıtı
- Yanlış pozitif değerlendirmesi
- Potansiyel etki ve saldırı zinciri
- Üretici düzeltmesi veya uygulanabilir mitigasyon
- Tekrar test sonucu ve zaman damgası

CVE veya CVSS bilgisini doğrulayamıyorsan bunu açıkça belirt. Tahmini değerleri resmî veri gibi sunma.

## 8. KALİTE KONTROLÜ

Değişiklikleri uyguladıktan sonra mevcut test mekanizmasını incele. Gereksiz bir test altyapısı kurmadan, değişikliklerin doğru çalıştığını gösterecek en küçük yeterli testleri ekle veya mevcut testleri genişlet.

Mümkün olan her zafiyet sınıfı için şu durumları değerlendirmeye çalış:

- Kontrol edilen laboratuvar senaryosunda açık bulunması
- Aynı senaryoda güvenli uygulamanın açık vermemesi
- Eksik yetki veya eksik önkoşul nedeniyle bulgu üretilmemesi
- WAF veya ağ hatalarının zafiyet olarak raporlanmaması
- Zaman aşımı ve hatalı yanıt durumlarında motorun güvenli kalması
- Tarama çıktısının mevcut formatla uyumlu olması
- Performans ve istek sayısındaki değişiklikler

Testleri çalıştırabiliyorsan sonuçları gerçek çıktılara göre raporla. Çalıştırmadığın testleri başarılı gibi gösterme.

## 9. TAMAMLANMA RAPORU

Çalışmanın sonunda şu başlıklarla somut bir teknik rapor sun:

1. Mevcut Gash motorunun tespit edilen eksikleri
2. Araştırmadan doğrulanan ve doğrulanamayan bulgular
3. Değiştirilen veya eklenen dosyalar ve gerekçeleri
4. Her zafiyet sınıfında geliştirilen tespit kabiliyeti
5. Yanlış pozitifleri azaltmak için yapılan iyileştirmeler
6. Test edilen senaryolar ve gerçek test sonuçları
7. Bilinen sınırlamalar ve henüz uygulanmayan iyileştirmeler
8. Kalan işler için önem sıralaması

Yalnızca yapılmış değişiklikleri tamamlandı olarak işaretle.

## SON TALİMAT

Araştırmayı bir saldırı payload'ı listesi olarak ele alma. Asıl hedef, Gash'ın modern web uygulamalarındaki güvenlik açıklarını daha doğru, daha kapsamlı, daha az yanlış pozitif üreterek ve güvenli biçimde tespit etmesini sağlamaktır.

Önce mevcut kodu ve araştırma kaynaklarını incele; eksikleri kanıtla; ardından küçük, uyumlu ve ölçülebilir değişikliklerle uygula. Gereksiz teori anlatımıyla veya yalnızca öneri listesi sunarak görevi tamamlanmış sayma.