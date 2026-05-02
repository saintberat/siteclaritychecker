## Siteye ulaşmak için: https://saintberat.github.io/siteclaritychecker/
## 🔎 URL Güvenlik Analizi Nasıl Çalışır?

Bu araç, girilen bir URL’yi analiz ederek phishing, zararlı yazılım ve sosyal mühendislik risklerini tespit etmeye çalışır.  
Hem URL yapısını hem de (isteğe bağlı) sayfanın kaynak kodunu inceleyerek skor bazlı bir risk değerlendirmesi yapar.

---

### ⚙️ Genel Mantık

Kullanıcı bir URL girer:

1. URL normalize edilir (`https://` eklenir vs.)  
2. Yapısal analiz yapılır  
3. (Opsiyonel) kaynak kodu çekilir  
4. Tüm bulgulara göre risk skoru hesaplanır  
5. Sonuç kullanıcıya detaylı şekilde gösterilir  

---

### 🌐 URL Analizi

#### 🔐 Protokol Kontrolü
- `HTTPS` → Güvenli  
- `HTTP` → Risk (veriler şifrelenmez)

---

#### 🌍 Domain Kontrolü

- IP ile erişim → yüksek risk  
- Punycode / unicode → görsel aldatma riski  
- Şüpheli TLD’ler (`.xyz`, `.tk`, vs.) → ek risk  
- Güvenilir domain listesi → risk düşürülür  

---

#### 🧱 URL Yapısı

- Çok fazla subdomain → gizleme taktiği olabilir  
- Aşırı uzun path → şüpheli yönlendirme  

---

#### 🏷️ Marka Taklidi (Phishing)

- Bilinen markalar kontrol edilir (Google, PayPal, vs.)  
- Lookalike karakterler tespit edilir (`g00gle`, `paypa1` gibi)  
- Levenshtein distance ile benzerlik ölçülür  

---

#### ⚠️ Şüpheli Kelimeler

URL içinde şu tarz kelimeler aranır:

- login, verify, secure  
- bank, account, password  
- bonus, wallet, confirm  

Bunlar sosyal mühendislik ihtimalini artırır.

---

### 🧠 Strict Mode (Gelişmiş Analiz)

Açıldığında ekstra kontroller yapılır:

- Domain uzunluğu  
- Tire (-) sayısı  
- Rakam yoğunluğu  
- Entropi analizi  

Amaç: rastgele üretilmiş (malicious) domainleri yakalamak.

---

### 🧬 Kaynak Kod Analizi (Deep Scan)

Opsiyonel olarak site HTML’i çekilir ve analiz edilir.

#### 🚨 Zararlı Patternler

- Obfuscated `eval()` kullanımı  
- Base64 decode işlemleri  
- `document.write` ile gizli script  
- CharCode obfuscation  

---

#### 🔁 Yönlendirmeler

- `window.location`  
- `meta refresh`  

Çok fazla yönlendirme → şüpheli davranış

---

#### 📡 Harici Scriptler

- Farklı domainlerden script yüklenmesi incelenir  
- Çok fazla dış kaynak → risk artar  

---

#### 🧾 Form Analizi

- Form başka bir domaine veri gönderiyorsa → ciddi risk  
- Özellikle login/password içeren formlar kontrol edilir  

---

#### 🧨 Ek Tehditler

- Crypto miner imzaları  
- Keylogger patternleri  
- Gizli input yakalama mekanizmaları  

---

### 📊 Skorlama Sistemi

Toplanan tüm bulgulara göre:

- **0 – 24 → Düşük Risk**  
- **25 – 54 → Orta Risk**  
- **55+ → Yüksek Risk**  

---

### 🧾 Sonuç

Kullanıcıya:

- Risk skoru  
- Güvenlik özeti  
- Detaylı bulgular  
- (Varsa) kaynak kod analiz çıktısı  

gösterilir.

---

### 🛡️ Özet

Bu sistem:

- Phishing sitelerini tespit etmeye çalışır  
- Zararlı script davranışlarını analiz eder  
- Kullanıcıyı riskli siteler konusunda uyarır  

Kısacası:  
Linke bakıp “bu biraz garip” demek yerine, neden garip olduğunu teknik olarak açıklıyor.
