(function () {

  const translations = {
    tr: {
      
      tag: 'URL Güvenlik Analizi',
      subtitle: 'Kaynak kodu taraması, yapısal risk analizi ve bilinen tehdit kalıplarıyla URL güvenliğini kontrol eder. Google Safe Browsing API entegrasyonu destekler.',
      deepScan: 'Kaynak kodu tara',
      strictMode: 'Sıkı mod',
      scanBtn: 'Tara',
      loading: 'Analiz ediliyor...',
      scoreSub: 'Risk Puanı / 100',
      checkLayers: 'Kontrol Katmanları',
      findings: 'Bulgular',
      sourceAnalysis: 'Kaynak Kodu Analizi',
      footerTitle1: 'Yapısal analiz',
      footerDesc1: 'HTTPS, IP, Punycode, TLD, subdomain, lookalike ve entropi kontrolü.',
      footerTitle2: 'Kaynak tarama',
      footerDesc2: 'Ücretsiz CORS proxy servisleri ile kaynak kodu çekilir. Form, script ve obfuscation taranır.',
      footerTitle3: 'Sınırlar',
      footerDesc3: 'Tamamen istemci taraflı çalışır. Bazı siteler CORS proxy ile erişilemeyebilir.',

      
      verdictHigh: 'Yüksek Risk',
      verdictMid: 'Orta Risk',
      verdictLow: 'Düşük Risk',

      summaryTrusted: 'Bilinen ve güvenilir bir alan adı. Yine de dikkatli ol.',
      summaryHigh: 'Birden fazla güçlü risk faktörü tespit edildi. Bu siteyi ziyaret etmekten veya bilgi girmekten kaçın.',
      summaryMid: 'Bazı şüpheli unsurlar mevcut. Siteyi dikkatle incele, kişisel bilgi girme.',
      summaryLow: 'Belirgin bir tehdit işareti bulunamadı. Yine de beklenmedik bir linkse temkinli ol.',

      logParsing: 'URL ayrıştırılıyor...',
      logStructDone: 'Yapısal kontroller tamamlandı.',
      logFetchSrc: 'Kaynak kodu getiriliyor (CORS proxy)...',
      logAnalyzeSrc: 'Kaynak analiz ediliyor...',
      logSrcFail: 'Kaynak alınamadı: ',
      logSrcFailFinding: 'Kaynak kodu alınamadı: ',
      logReport: 'Rapor oluşturuluyor...',
      logTrying: 'Deneniyor: ',
      logDirect: 'Doğrudan bağlantı deneniyor...',
      logAllFailed: 'Tüm CORS proxy servisleri ve doğrudan bağlantı başarısız oldu. Site erişimi engelleniyor olabilir.',

      errEmpty: 'Bir URL gir.',
      errProto: 'Sadece http/https destekleniyor.',
      errInvalid: 'Geçerli bir URL gir.',

     
      lblProtocol: 'Protokol',
      lblDomain: 'Alan Adı',
      lblBrand: 'Marka Risk',
      lblKeywords: 'Kelime Risk',
      lblStructure: 'Yapı',
      lblEntropy: 'Entropi',

      
      valOff: 'Kapalı',
      valNormal: 'Normal',
      valClean: 'Temiz',
      valTrusted: 'Güvenilir',
      valIPAddr: 'IP Adresi',
      valLongPath: 'Uzun path',
      valSubdomains: 'alt alan',
      valCount: 'adet',

      
      fHttpWarn: 'Şifrelenmemiş HTTP bağlantısı. Girilen veriler açık taşınıyor.',
      fHttpsOk: 'HTTPS kullanılıyor, iletişim şifreli.',
      fIPDanger: 'Alan adı yerine doğrudan IP kullanılıyor — klasik phishing göstergesi.',
      fPunycode: 'Punycode / unicode karakter tespiti. Görsel aldatmaca riski yüksek.',
      fSuspTLD: (tld) => `Şüpheli TLD: ${tld} — kötüye kullanım oranı yüksek uzantılardan.`,
      fTrusted: 'Bilinen güvenilir alan adı listesinde yer alıyor.',
      fSubdomains: (n) => `Çok katmanlı subdomain (${n} adet). Gerçek alan adını gizleme taktiği.`,
      fLongPath: 'URL yolu olağandışı uzun — yönlendirme karmaşıklığı şüpheli.',
      fBrandFake: (b) => `"${b}" markasına benzemeye çalışan alan adı tespit edildi.`,
      fBrandOk: 'Bilinen markaları taklit eden bir pattern bulunamadı.',
      fKeywordHits: (kw) => `Sosyal mühendislik kelimeleri: ${kw}`,

      fStrictLong: 'Uzun domain',
      fStrictHyphens: 'Fazla tire',
      fStrictDigits: 'Fazla rakam',
      fStrictEntropy: (v) => `Yüksek entropi (${v})`,
      fStrictWarn: (s) => `Sıkı mod uyarıları: ${s}`,

      srcDetected: (l, n) => `⟨src⟩ ${l} tespit edildi (${n} yerde).`,
      srcRedirects: (n) => `⟨src⟩ ${n} adet yönlendirme komutu bulundu.`,
      srcExtScripts: (n) => `⟨src⟩ ${n} farklı harici script kaynağı (fazla sayıda).`,
      srcExtInfo: (h) => `⟨src⟩ Harici script kaynakları: ${h}`,
      srcFormDanger: (n) => `⟨src⟩ ${n} form başka bir alana veri gönderiyor — credential harvesting riski.`,
      srcIframes: (n) => `⟨src⟩ ${n} adet iframe bulundu.`,
      srcCrypto: '⟨src⟩ Kripto madencisi imzası tespit edildi.',
      srcKeylogger: '⟨src⟩ Keylogger pattern tespit edildi.',
      srcSensitive: '⟨src⟩ Hassas anahtar kelimeler içeren form(lar) mevcut.',
      srcClean: '⟨src⟩ Kaynak kodda bilinen zararlı pattern bulunamadı.',

      srcLabel: 'kaynak tarama',
      srcAccessFail: 'Erişilemedi',
      srcAccessDesc: 'CORS proxy servisleri aracılığıyla kaynak kodu alınamadı. Site erişimi engelliyor olabilir.',
    },

    en: {
      tag: 'URL Security Analysis',
      subtitle: 'Checks URL safety through source code scanning, structural risk analysis, and known threat patterns. Supports Google Safe Browsing API integration.',
      deepScan: 'Scan source code',
      strictMode: 'Strict mode',
      scanBtn: 'Scan',
      loading: 'Analyzing...',
      scoreSub: 'Risk Score / 100',
      checkLayers: 'Check Layers',
      findings: 'Findings',
      sourceAnalysis: 'Source Code Analysis',
      footerTitle1: 'Structural Analysis',
      footerDesc1: 'HTTPS, IP, Punycode, TLD, subdomain, lookalike, and entropy checks.',
      footerTitle2: 'Source Scanning',
      footerDesc2: 'Source code is fetched via free CORS proxy services. Forms, scripts, and obfuscation are scanned.',
      footerTitle3: 'Limitations',
      footerDesc3: 'Runs entirely client-side. Some sites may not be accessible via CORS proxy.',

      verdictHigh: 'High Risk',
      verdictMid: 'Medium Risk',
      verdictLow: 'Low Risk',

      summaryTrusted: 'A known and trusted domain. Still, stay cautious.',
      summaryHigh: 'Multiple strong risk factors detected. Avoid visiting this site or entering any information.',
      summaryMid: 'Some suspicious elements found. Examine the site carefully, do not enter personal info.',
      summaryLow: 'No clear threat indicators found. Still, be careful if it\'s an unexpected link.',

      logParsing: 'Parsing URL...',
      logStructDone: 'Structural checks completed.',
      logFetchSrc: 'Fetching source code (CORS proxy)...',
      logAnalyzeSrc: 'Analyzing source...',
      logSrcFail: 'Could not fetch source: ',
      logSrcFailFinding: 'Could not fetch source code: ',
      logReport: 'Generating report...',
      logTrying: 'Trying: ',
      logDirect: 'Trying direct connection...',
      logAllFailed: 'All CORS proxy services and direct connection failed. The site may be blocking access.',

      errEmpty: 'Enter a URL.',
      errProto: 'Only http/https is supported.',
      errInvalid: 'Enter a valid URL.',

      lblProtocol: 'Protocol',
      lblDomain: 'Domain',
      lblBrand: 'Brand Risk',
      lblKeywords: 'Keyword Risk',
      lblStructure: 'Structure',
      lblEntropy: 'Entropy',

      valOff: 'Off',
      valNormal: 'Normal',
      valClean: 'Clean',
      valTrusted: 'Trusted',
      valIPAddr: 'IP Address',
      valLongPath: 'Long path',
      valSubdomains: 'subdomains',
      valCount: 'hits',

      fHttpWarn: 'Unencrypted HTTP connection. Entered data is transmitted in plain text.',
      fHttpsOk: 'HTTPS is used, communication is encrypted.',
      fIPDanger: 'Direct IP address used instead of domain — classic phishing indicator.',
      fPunycode: 'Punycode / unicode character detected. High risk of visual spoofing.',
      fSuspTLD: (tld) => `Suspicious TLD: ${tld} — extension with high abuse rate.`,
      fTrusted: 'Listed in known trusted domain list.',
      fSubdomains: (n) => `Multi-layered subdomain (${n} levels). Domain masking tactic.`,
      fLongPath: 'URL path is unusually long — suspicious redirect complexity.',
      fBrandFake: (b) => `Domain attempting to impersonate "${b}" brand detected.`,
      fBrandOk: 'No pattern found imitating known brands.',
      fKeywordHits: (kw) => `Social engineering keywords: ${kw}`,

      fStrictLong: 'Long domain',
      fStrictHyphens: 'Excess hyphens',
      fStrictDigits: 'Excess digits',
      fStrictEntropy: (v) => `High entropy (${v})`,
      fStrictWarn: (s) => `Strict mode warnings: ${s}`,

      srcDetected: (l, n) => `⟨src⟩ ${l} detected (${n} occurrences).`,
      srcRedirects: (n) => `⟨src⟩ ${n} redirect commands found.`,
      srcExtScripts: (n) => `⟨src⟩ ${n} different external script sources (excessive).`,
      srcExtInfo: (h) => `⟨src⟩ External script sources: ${h}`,
      srcFormDanger: (n) => `⟨src⟩ ${n} form(s) sending data to another domain — credential harvesting risk.`,
      srcIframes: (n) => `⟨src⟩ ${n} iframes found.`,
      srcCrypto: '⟨src⟩ Crypto miner signature detected.',
      srcKeylogger: '⟨src⟩ Keylogger pattern detected.',
      srcSensitive: '⟨src⟩ Form(s) containing sensitive keywords found.',
      srcClean: '⟨src⟩ No known malicious pattern found in source code.',

      srcLabel: 'source scan',
      srcAccessFail: 'Unreachable',
      srcAccessDesc: 'Source code could not be fetched via CORS proxy services. The site may be blocking access.',
    },
  };

  let currentLang = 'tr';

  
  window.i18n = {
    t(key) {
      return translations[currentLang][key] || translations['tr'][key] || key;
    },
    lang() {
      return currentLang;
    },
  };

  function applyStaticTranslations() {
    document.querySelectorAll('[data-i18n]').forEach((el) => {
      const key = el.getAttribute('data-i18n');
      const val = translations[currentLang][key];
      if (val && typeof val === 'string') {
        el.textContent = val;
      }
    });

    
    if (currentLang === 'en') {
      document.title = 'IsThisSiteSafe?';
      document.querySelector('meta[name="description"]').setAttribute('content', 'URL security analysis tool — source code, DNS, and structural risk scanning.');
      document.getElementById('lang-toggle').title = 'Switch Language';
    } else {
      document.title = 'BuSiteGüvenliMi?';
      document.querySelector('meta[name="description"]').setAttribute('content', 'URL güvenlik analiz aracı — kaynak kodu, DNS ve yapısal risk taraması.');
      document.getElementById('lang-toggle').title = 'Dil Değiştir';
    }

    
    document.documentElement.lang = currentLang === 'en' ? 'en' : 'tr';
  }

  function toggleLang() {
    currentLang = currentLang === 'tr' ? 'en' : 'tr';

    
    document.querySelectorAll('.lang-option').forEach((opt) => {
      opt.classList.toggle('active', opt.getAttribute('data-lang') === currentLang);
    });

    applyStaticTranslations();

    
    try { localStorage.setItem('sitechecker-lang', currentLang); } catch {}
  }

  
  try {
    const saved = localStorage.getItem('sitechecker-lang');
    if (saved === 'en' || saved === 'tr') {
      currentLang = saved;
    }
  } catch {}

 
  if (currentLang === 'en') {
    document.querySelectorAll('.lang-option').forEach((opt) => {
      opt.classList.toggle('active', opt.getAttribute('data-lang') === 'en');
    });
  }
  applyStaticTranslations();


  document.getElementById('lang-toggle').addEventListener('click', toggleLang);

})();
