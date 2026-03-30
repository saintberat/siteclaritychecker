(function() {

const SUSPICIOUS_WORDS = ['login','verify','secure','bank','account','update','signin','confirm','bonus','wallet','suspend','recover','unlock','credential','password','auth'];
const SUSPICIOUS_TLDS  = ['.zip','.xyz','.top','.site','.online','.tk','.ml','.ga','.cf','.gq','.work','.click','.link','.pw'];
const BRAND_WORDS      = ['google','microsoft','apple','paypal','amazon','instagram','facebook','netflix','binance','coinbase','telegram','whatsapp','twitter','spotify'];
const TRUSTED_DOMAINS  = ['google.com','microsoft.com','apple.com','paypal.com','amazon.com','instagram.com','facebook.com','github.com','twitter.com','wikipedia.org','youtube.com'];
const LOOKALIKE_MAP    = {'0':'o','1':'l','3':'e','4':'a','5':'s','7':'t','@':'a'};

const PROXIES = [
  url => `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`,
  url => `https://corsproxy.io/?${encodeURIComponent(url)}`
];

const $ = id => document.getElementById(id);

const form_input   = $('url-input');
const deepScan     = $('deep-scan');
const strictMode   = $('strict-mode');
const analyzeBtn   = $('analyze-btn');
const errMsg       = $('err-msg');
const results      = $('results');
const scoreNum     = $('score-num');
const verdictBadge = $('verdict-badge');
const meterFill    = $('meter-fill');
const summaryText  = $('summary-text');
const checksGrid   = $('checks-grid');
const findingsList = $('findings-list');
const sourceSection= $('source-section');
const sourceStatus = $('source-status');
const sourceBody   = $('source-body');
const sourceFindings=$('source-findings');
const sourceUrlLabel=$('source-url-label');
const loadingOverlay=$('loading-overlay');
const loadingLog   = $('loading-log');

let logSteps = [];

function setLog(txt) {
  logSteps.push(txt);
  loadingLog.textContent = logSteps.slice(-3).join('\n');
}

analyzeBtn.addEventListener('click', async () => {
  const raw = form_input.value.trim();
  const norm = normalizeUrl(raw);
  if (!norm.ok) { showErr(norm.msg); return; }
  clearErr();
  logSteps = [];
  loadingOverlay.classList.add('active');
  analyzeBtn.disabled = true;
  results.classList.remove('visible');

  setLog('URL ayrıştırılıyor...');
  const analysis = analyzeUrl(norm.url, strictMode.checked);
  setLog('Yapısal kontroller tamamlandı.');

  let sourceResult = null;
  if (deepScan.checked) {
    setLog('Kaynak kodu getiriliyor...');
    sourceResult = await fetchSource(norm.url);
    if (sourceResult.ok) {
      setLog('Kaynak analiz ediliyor...');
      const srcAnalysis = analyzeSource(sourceResult.html, norm.url);
      analysis.score = Math.min(100, analysis.score + srcAnalysis.score);
      analysis.findings.push(...srcAnalysis.findings);
      analysis.sourceResult = sourceResult;
      analysis.srcAnalysis = srcAnalysis;
    } else {
      setLog('Kaynak alınamadı: ' + sourceResult.reason);
      analysis.findings.push({ tone:'neutral', text: 'Kaynak kodu alınamadı: ' + sourceResult.reason });
    }
  }

  analysis.score = Math.min(100, Math.round(analysis.score));
  setLog('Rapor oluşturuluyor...');

  await sleep(300);
  loadingOverlay.classList.remove('active');
  analyzeBtn.disabled = false;
  renderResult(analysis);
});

form_input.addEventListener('keydown', e => { if (e.key === 'Enter') analyzeBtn.click(); });
form_input.addEventListener('input', clearErr);

function normalizeUrl(val) {
  if (!val) return { ok:false, msg:'Bir URL gir.' };
  const withProto = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(val) ? val : `https://${val}`;
  try {
    const u = new URL(withProto);
    if (!['http:','https:'].includes(u.protocol)) return { ok:false, msg:'Sadece http/https destekleniyor.' };
    return { ok:true, url: u };
  } catch { return { ok:false, msg:'Geçerli bir URL gir.' }; }
}

function analyzeUrl(url, isStrict) {
  const hostname = url.hostname.toLowerCase();
  const fullUrl  = url.href.toLowerCase();
  const findings = [];
  let score = 0;

  const trusted = isTrusted(hostname);

  const checks = {
    protocol: { label:'Protokol', state:'neutral', value:'—' },
    domain:   { label:'Alan Adı', state:'neutral', value:'—' },
    brand:    { label:'Marka Risk', state:'neutral', value:'—' },
    keywords: { label:'Kelime Risk', state:'neutral', value:'—' },
    structure:{ label:'Yapı', state:'neutral', value:'—' },
    strict:   { label:'Entropi', state:'neutral', value: isStrict ? '—' : 'Kapalı' },
  };

  if (url.protocol === 'http:') {
    score += 25;
    checks.protocol = { label:'Protokol', state:'warn', value:'HTTP' };
    findings.push({ tone:'warn', text:'Şifrelenmemiş HTTP bağlantısı. Girilen veriler açık taşınıyor.' });
  } else {
    checks.protocol = { label:'Protokol', state:'safe', value:'HTTPS ✓' };
    findings.push({ tone:'safe', text:'HTTPS kullanılıyor, iletişim şifreli.' });
  }

  if (isIp(hostname)) {
    score += 40;
    checks.domain = { label:'Alan Adı', state:'danger', value:'IP Adresi' };
    findings.push({ tone:'danger', text:'Alan adı yerine doğrudan IP kullanılıyor — klasik phishing göstergesi.' });
  } else if (hostname.includes('xn--') || /[^\x00-\x7F]/.test(hostname)) {
    score += 38;
    checks.domain = { label:'Alan Adı', state:'danger', value:'Punycode' };
    findings.push({ tone:'danger', text:'Punycode / unicode karakter tespiti. Görsel aldatmaca riski yüksek.' });
  } else {
    const tldHit = SUSPICIOUS_TLDS.find(t => hostname.endsWith(t));
    if (tldHit && !trusted) {
      score += 18;
      checks.domain = { label:'Alan Adı', state:'warn', value:tldHit };
      findings.push({ tone:'warn', text:`Şüpheli TLD: ${tldHit} — kötüye kullanım oranı yüksek uzantılardan.` });
    } else if (trusted) {
      checks.domain = { label:'Alan Adı', state:'safe', value:'Güvenilir' };
      findings.push({ tone:'safe', text:'Bilinen güvenilir alan adı listesinde yer alıyor.' });
    } else {
      checks.domain = { label:'Alan Adı', state:'neutral', value:'Normal' };
    }
  }

  const subCount = Math.max(hostname.split('.').length - 2, 0);
  if (subCount >= 2 && !trusted) {
    score += 14;
    checks.structure = { label:'Yapı', state:'warn', value:`${subCount} alt alan` };
    findings.push({ tone:'warn', text:`Çok katmanlı subdomain (${subCount} adet). Gerçek alan adını gizleme taktiği.` });
  } else if (url.pathname.length > 120) {
    score += 8;
    checks.structure = { label:'Yapı', state:'warn', value:'Uzun path' };
    findings.push({ tone:'warn', text:'URL yolu olağandışı uzun — yönlendirme karmaşıklığı şüpheli.' });
  } else {
    checks.structure = { label:'Yapı', state:'safe', value:'Normal' };
  }

  const fakeBrand = detectBrand(hostname);
  if (fakeBrand) {
    score += 32;
    checks.brand = { label:'Marka Risk', state:'danger', value: fakeBrand };
    findings.push({ tone:'danger', text:`"${fakeBrand}" markasına benzemeye çalışan alan adı tespit edildi.` });
  } else {
    checks.brand = { label:'Marka Risk', state:'safe', value:'Temiz' };
    findings.push({ tone:'safe', text:'Bilinen markaları taklit eden bir pattern bulunamadı.' });
  }

  const kwHits = SUSPICIOUS_WORDS.filter(w => fullUrl.includes(w));
  if (kwHits.length && !trusted) {
    score += Math.min(kwHits.length * 6, 18);
    checks.keywords = { label:'Kelime Risk', state:'warn', value:`${kwHits.length} adet` };
    findings.push({ tone:'warn', text:`Sosyal mühendislik kelimeleri: ${kwHits.slice(0,5).join(', ')}` });
  } else {
    checks.keywords = { label:'Kelime Risk', state:'safe', value:'Temiz' };
  }

  if (isStrict) {
    const bare = hostname.replace(/\./g,'');
    const entropy = calcEntropy(bare);
    const hyphens = (hostname.match(/-/g)||[]).length;
    const digits  = (hostname.match(/\d/g)||[]).length;
    const strictHits = [];

    if (bare.length > 24 && !trusted) { score += 10; strictHits.push('Uzun domain'); }
    if (hyphens >= 3 && !trusted) { score += 10; strictHits.push('Fazla tire'); }
    if (digits >= 4 && !trusted) { score += 8; strictHits.push('Fazla rakam'); }
    if (entropy > 3.8 && bare.length > 14 && !trusted) {
      score += 14;
      strictHits.push(`Yüksek entropi (${entropy.toFixed(2)})`);
    }

    if (strictHits.length) {
      checks.strict = { label:'Entropi', state:'warn', value: strictHits.join(', ') };
      findings.push({ tone:'warn', text:`Sıkı mod uyarıları: ${strictHits.join(', ')}` });
    } else {
      checks.strict = { label:'Entropi', state:'safe', value:'Normal' };
    }
  }

  return { score, checks, findings, trusted };
}

function detectBrand(hostname) {
  if (isTrusted(hostname)) return null;
  const parts = hostname.split('.');
  const main  = parts.length > 1 ? parts[parts.length-2] : parts[0];
  const sub   = parts.length > 2 ? parts.slice(0,-2).join('.') : '';
  const sim   = lookalike;
  for (const b of BRAND_WORDS) {
    if (sub.includes(b) || sim(sub).includes(b)) return b;
    if (main !== b && (main.includes(b) || sim(main).includes(b))) return b;
  }
  return null;
}

function lookalike(s) {
  return Array.from(s).map(c => LOOKALIKE_MAP[c] || c).join('');
}

function isTrusted(h) {
  return TRUSTED_DOMAINS.some(d => h === d || h.endsWith('.'+d));
}
function isIp(h) { return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(h); }
function calcEntropy(s) {
  if (!s) return 0;
  const counts = {};
  for (const c of s) counts[c] = (counts[c]||0)+1;
  return Object.values(counts).reduce((t,n) => {
    const r = n/s.length; return t - r*Math.log2(r);
  }, 0);
}

async function fetchSource(url) {
  for (let i = 0; i < PROXIES.length; i++) {
    try {
      const proxyUrl = PROXIES[i](url.href);
      const resp = await fetch(proxyUrl, { signal: AbortSignal.timeout(10000) });
      if (!resp.ok) continue;
      const data = await resp.json();
      const html = data.contents || data.body || '';
      if (html && html.length > 50) {
        return { ok:true, html, proxy: i+1 };
      }
    } catch(e) {}
  }
  return { ok:false, reason:'CORS veya bağlantı hatası' };
}

function analyzeSource(html, url) {
  const findings = [];
  let score = 0;
  const lower = html.toLowerCase();

  const MALWARE_PATTERNS = [
    { re: /eval\s*\(\s*(?:unescape|atob|String\.fromCharCode)/gi, label:'Obfuscated eval()', score:30 },
    { re: /document\.write\s*\(\s*(?:unescape|atob)/gi, label:'Encoded document.write', score:25 },
    { re: /(?:window|document)\s*\[\s*['"][^'"]{1,4}['"]\s*\]/gi, label:'Property obfuscation', score:20 },
    { re: /(?:fromCharCode|charCodeAt)\s*\(/gi, label:'CharCode kullanımı', score:15 },
    { re: /base64_decode|base64decode/gi, label:'Base64 decode', score:12 },
    { re: /\bpassword\b.*\binput\b|\binput\b.*\bpassword\b/gi, label:'Password input', score:10 },
    { re: /\.onload\s*=\s*function.*setTimeout/gs, label:'Geciktirilmiş yükleme', score:8 },
  ];

  const REDIRECT_PATTERNS = [
    /window\.location(?:\.href)?\s*=\s*['"][^'"]{8,}/gi,
    /document\.location\s*=\s*['"][^'"]{8,}/gi,
    /meta\s+http-equiv\s*=\s*['"]refresh['"]/gi,
  ];

  for (const p of MALWARE_PATTERNS) {
    const matches = html.match(p.re);
    if (matches) {
      score += p.score;
      findings.push({ tone:'danger', text:`⟨src⟩ ${p.label} tespit edildi (${matches.length} yerde).` });
    }
  }

  let redirectCount = 0;
  for (const r of REDIRECT_PATTERNS) {
    const m = html.match(r);
    if (m) redirectCount += m.length;
  }
  if (redirectCount > 0) {
    score += Math.min(redirectCount * 8, 24);
    findings.push({ tone:'warn', text:`⟨src⟩ ${redirectCount} adet yönlendirme komutu bulundu.` });
  }

  const extScripts = [];
  const scriptRe = /<script[^>]+src\s*=\s*['"]([^'"]+)['"]/gi;
  let sm;
  while ((sm = scriptRe.exec(html)) !== null) {
    try {
      const su = new URL(sm[1], url.href);
      if (su.hostname !== url.hostname) extScripts.push(su.hostname);
    } catch {}
  }
  const uniqueExt = [...new Set(extScripts)];
  if (uniqueExt.length > 5) {
    score += 15;
    findings.push({ tone:'warn', text:`⟨src⟩ ${uniqueExt.length} farklı harici script kaynağı (fazla sayıda).` });
  } else if (uniqueExt.length > 0) {
    findings.push({ tone:'neutral', text:`⟨src⟩ Harici script kaynakları: ${uniqueExt.slice(0,3).join(', ')}` });
  }

  const forms = html.match(/<form[^>]*>/gi) || [];
  const suspForms = forms.filter(f => {
    const action = (f.match(/action\s*=\s*['"]([^'"]*)['"]/i)||[])[1]||'';
    if (!action) return false;
    try { const au = new URL(action, url.href); return au.hostname !== url.hostname; } catch { return false; }
  });
  if (suspForms.length > 0) {
    score += suspForms.length * 20;
    findings.push({ tone:'danger', text:`⟨src⟩ ${suspForms.length} form başka bir alana veri gönderiyor — credential harvesting riski.` });
  }

  const iframeCount = (html.match(/<iframe/gi)||[]).length;
  if (iframeCount > 2) {
    score += 10;
    findings.push({ tone:'warn', text:`⟨src⟩ ${iframeCount} adet iframe bulundu.` });
  }

  if (lower.includes('cryptominer') || lower.includes('coinhive') || lower.includes('minero.js') || lower.includes('webmr.js')) {
    score += 40;
    findings.push({ tone:'danger', text:'⟨src⟩ Kripto madencisi imzası tespit edildi.' });
  }

  if (lower.includes('keylogger') || lower.includes('document.onkeypress') || lower.includes('document.onkeydown')) {
    score += 35;
    findings.push({ tone:'danger', text:'⟨src⟩ Keylogger pattern tespit edildi.' });
  }

  const lowerHtml = lower;
  if (
    (lowerHtml.includes('bank') || lowerHtml.includes('signin') || lowerHtml.includes('password')) &&
    suspForms.length === 0 && forms.length > 0
  ) {
    score += 8;
    findings.push({ tone:'warn', text:'⟨src⟩ Hassas anahtar kelimeler içeren form(lar) mevcut.' });
  }

  if (findings.length === 0) {
    findings.push({ tone:'safe', text:'⟨src⟩ Kaynak kodda bilinen zararlı pattern bulunamadı.' });
  }

  const snippet = extractSnippet(html);

  return { score, findings, snippet };
}

function extractSnippet(html) {
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, (m) => m.slice(0,300))
    .replace(/\s+/g,' ')
    .trim()
    .slice(0, 1200);
}

function getVerdict(score) {
  if (score >= 55) return { text:'Yüksek Risk', cls:'high', color:'#ef4444' };
  if (score >= 25) return { text:'Orta Risk', cls:'mid', color:'#eab308' };
  return { text:'Düşük Risk', cls:'low', color:'#22c55e' };
}

function buildSummary(score, trusted) {
  if (trusted && score < 25) return 'Bilinen ve güvenilir bir alan adı. Yine de dikkatli ol.';
  if (score >= 55) return 'Birden fazla güçlü risk faktörü tespit edildi. Bu siteyi ziyaret etmekten veya bilgi girmekten kaçın.';
  if (score >= 25) return 'Bazı şüpheli unsurlar mevcut. Siteyi dikkatle incele, kişisel bilgi girme.';
  return 'Belirgin bir tehdit işareti bulunamadı. Yine de beklenmedik bir linkse temkinli ol.';
}

function renderResult(a) {
  const verdict = getVerdict(a.score);

  scoreNum.textContent = a.score;
  scoreNum.style.color = verdict.color;

  verdictBadge.textContent = verdict.text;
  verdictBadge.className = `verdict-badge ${verdict.cls}`;

  meterFill.style.width  = `${a.score}%`;
  meterFill.style.background = verdict.color;

  summaryText.textContent = buildSummary(a.score, a.trusted);

  checksGrid.innerHTML = '';
  for (const key of Object.keys(a.checks)) {
    const c = a.checks[key];
    const div = document.createElement('div');
    div.className = `check-card ${c.state}`;
    div.innerHTML = `<span class="check-label">${c.label}</span><span class="check-value">${c.value}</span>`;
    checksGrid.appendChild(div);
  }

  findingsList.innerHTML = '';
  for (const f of a.findings) {
    const li = document.createElement('li');
    li.className = `finding-item ${f.tone}`;
    const icon = f.tone === 'danger' ? '!' : f.tone === 'warn' ? '◆' : f.tone === 'safe' ? '+' : f.tone === 'neutral' ? '·' : 'i';
    li.innerHTML = `<span class="f-icon">${icon}</span><span>${escHtml(f.text)}</span>`;
    findingsList.appendChild(li);
  }

  if (a.sourceResult && a.sourceResult.ok) {
    sourceSection.style.display = 'block';
    sourceUrlLabel.textContent  = 'proxy-' + a.sourceResult.proxy;
    sourceStatus.textContent    = '200 OK';
    sourceStatus.className      = 'source-status ok';
    sourceBody.textContent      = a.srcAnalysis.snippet || '(boş)';

    sourceFindings.innerHTML = '';
    const highSrc = a.srcAnalysis.findings.filter(f => f.tone === 'danger' || f.tone === 'warn');
    if (highSrc.length) {
      for (const sf of highSrc) {
        const tag = document.createElement('span');
        tag.className = `src-tag ${sf.tone}`;
        tag.textContent = sf.text;
        sourceFindings.appendChild(tag);
      }
    }
  } else if (deepScan.checked) {
    sourceSection.style.display = 'block';
    sourceUrlLabel.textContent  = 'kaynak tarama';
    sourceStatus.textContent    = 'Erişilemedi';
    sourceStatus.className      = 'source-status err';
    sourceBody.textContent      = 'CORS politikası veya bağlantı hatası nedeniyle kaynak kodu alınamadı.';
    sourceFindings.innerHTML    = '';
  } else {
    sourceSection.style.display = 'none';
  }

  results.classList.add('visible');
  results.scrollIntoView({ behavior:'smooth', block:'start' });
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function showErr(msg) {
  errMsg.textContent = msg;
  errMsg.classList.add('visible');
  form_input.classList.add('error');
}

function clearErr() {
  errMsg.classList.remove('visible');
  form_input.classList.remove('error');
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

})();