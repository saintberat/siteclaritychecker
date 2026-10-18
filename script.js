(function() {

const SUSPICIOUS_WORDS = ['login','verify','secure','bank','account','update','signin','confirm','bonus','wallet','suspend','recover','unlock','credential','password','auth'];
const SUSPICIOUS_TLDS  = ['.zip','.xyz','.top','.site','.online','.tk','.ml','.ga','.cf','.gq','.work','.click','.link','.pw'];
const BRAND_WORDS      = ['google','microsoft','apple','paypal','amazon','instagram','facebook','netflix','binance','coinbase','telegram','whatsapp','twitter','spotify','trendyol','hepsiburada','ziraat','garanti','akbank','papara','sahibinden','turkiye','turkcell','vodafone','ebanking'];
const TRUSTED_DOMAINS  = ['google.com','microsoft.com','apple.com','paypal.com','amazon.com','instagram.com','facebook.com','github.com','twitter.com','wikipedia.org','youtube.com','trendyol.com','hepsiburada.com','ziraatbank.com.tr','garantibbva.com.tr','akbank.com','papara.com','sahibinden.com','turkiye.gov.tr','turkcell.com.tr','vodafone.com.tr'];
const LOOKALIKE_MAP    = {'0':'o','1':'l','3':'e','4':'a','5':'s','7':'t','8':'b','@':'a'};
const NORM_MAP         = {'rn':'m', 'vv':'w', 'cl':'d', 'ln':'m', '1v':'w', 'lv':'w'};

const CORS_PROXIES = [
  {
    name: 'allorigins',
    build: (url) => `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`,
    parse: (json) => json.contents,
  },
  {
    name: 'corsproxy.io',
    build: (url) => `https://corsproxy.io/?${encodeURIComponent(url)}`,
    parse: (text) => text,
    isText: true,
  },
  {
    name: 'cors-anywhere-test',
    build: (url) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(url)}`,
    parse: (text) => text,
    isText: true,
  },
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
let lastAnalysis = null;
let lastNormalizedUrl = null;

const t = (k, ...args) => (window.i18n ? window.i18n.t(k, ...args) : k);

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

  setLog(t('logParsing'));
  const analysis = analyzeUrl(norm.url, strictMode.checked);
  setLog(t('logStructDone'));

  let sourceResult = null;
  if (deepScan.checked) {
    setLog(t('logFetchSrc'));
    sourceResult = await fetchSource(norm.url);
    if (sourceResult.ok) {
      setLog(t('logAnalyzeSrc'));
      const srcAnalysis = analyzeSource(sourceResult.html, norm.url);
      analysis.score = Math.min(100, analysis.score + srcAnalysis.score);
      analysis.findings.push(...srcAnalysis.findings);
      analysis.sourceResult = sourceResult;
      analysis.srcAnalysis = srcAnalysis;
    } else {
      setLog(t('logSrcFail') + sourceResult.reason);
      analysis.findings.push({ tone:'neutral', text: t('logSrcFailFinding') + sourceResult.reason });
    }
  }

  analysis.score = Math.min(100, Math.round(analysis.score));
  setLog(t('logReport'));

  await sleep(300);
  loadingOverlay.classList.remove('active');
  analyzeBtn.disabled = false;
  lastAnalysis = analysis;
  lastNormalizedUrl = norm.url;
  renderResult(analysis);
});

form_input.addEventListener('keydown', e => { if (e.key === 'Enter') analyzeBtn.click(); });
form_input.addEventListener('input', clearErr);

window.addEventListener('langchange', () => {
  if (lastNormalizedUrl) {
    // Re-run analysis rendering for current URL with updated language
    const analysis = analyzeUrl(lastNormalizedUrl, strictMode.checked);
    if (lastAnalysis && lastAnalysis.srcAnalysis) {
      analysis.score = Math.min(100, analysis.score + lastAnalysis.srcAnalysis.score);
      analysis.findings.push(...lastAnalysis.srcAnalysis.findings);
      analysis.sourceResult = lastAnalysis.sourceResult;
      analysis.srcAnalysis = lastAnalysis.srcAnalysis;
    }
    analysis.score = Math.min(100, Math.round(analysis.score));
    lastAnalysis = analysis;
    renderResult(analysis);
  }
});

function normalizeUrl(val) {
  if (!val) return { ok:false, msg: t('errEmpty') };
  const withProto = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(val) ? val : `https://${val}`;
  try {
    const u = new URL(withProto);
    if (!['http:','https:'].includes(u.protocol)) return { ok:false, msg: t('errProto') };
    return { ok:true, url: u };
  } catch { return { ok:false, msg: t('errInvalid') }; }
}

function analyzeUrl(url, isStrict) {
  const hostname = url.hostname.toLowerCase();
  const fullUrl  = url.href.toLowerCase();
  const findings = [];
  let score = 0;

  const trusted = isTrusted(hostname);

  const checks = {
    protocol: { label: t('lblProtocol'), state:'neutral', value:'—' },
    domain:   { label: t('lblDomain'), state:'neutral', value:'—' },
    brand:    { label: t('lblBrand'), state:'neutral', value:'—' },
    keywords: { label: t('lblKeywords'), state:'neutral', value:'—' },
    structure:{ label: t('lblStructure'), state:'neutral', value:'—' },
    strict:   { label: t('lblEntropy'), state:'neutral', value: isStrict ? '—' : t('valOff') },
  };

  if (url.protocol === 'http:') {
    score += 25;
    checks.protocol = { label: t('lblProtocol'), state:'warn', value:'HTTP' };
    findings.push({ tone:'warn', text: t('fHttpWarn') });
  } else {
    checks.protocol = { label: t('lblProtocol'), state:'safe', value:'HTTPS ✓' };
    findings.push({ tone:'safe', text: t('fHttpsOk') });
  }

  if (isIp(hostname)) {
    score += 40;
    checks.domain = { label: t('lblDomain'), state:'danger', value: t('valIPAddr') };
    findings.push({ tone:'danger', text: t('fIPDanger') });
  } else if (hostname.includes('xn--') || /[^\x00-\x7F]/.test(hostname)) {
    score += 38;
    checks.domain = { label: t('lblDomain'), state:'danger', value:'Punycode' };
    findings.push({ tone:'danger', text: t('fPunycode') });
  } else {
    const tldHit = SUSPICIOUS_TLDS.find(t => hostname.endsWith(t));
    if (tldHit && !trusted) {
      score += 18;
      checks.domain = { label: t('lblDomain'), state:'warn', value: tldHit };
      findings.push({ tone:'warn', text: t('fSuspTLD', tldHit) });
    } else if (trusted) {
      checks.domain = { label: t('lblDomain'), state:'safe', value: t('valTrusted') };
      findings.push({ tone:'safe', text: t('fTrusted') });
    } else {
      checks.domain = { label: t('lblDomain'), state:'neutral', value: t('valNormal') };
    }
  }

  const subCount = Math.max(hostname.split('.').length - 2, 0);
  if (subCount >= 2 && !trusted) {
    score += 14;
    checks.structure = { label: t('lblStructure'), state:'warn', value:`${subCount} ${t('valSubdomains')}` };
    findings.push({ tone:'warn', text: t('fSubdomains', subCount) });
  } else if (url.pathname.length > 120) {
    score += 8;
    checks.structure = { label: t('lblStructure'), state:'warn', value: t('valLongPath') };
    findings.push({ tone:'warn', text: t('fLongPath') });
  } else {
    checks.structure = { label: t('lblStructure'), state:'safe', value: t('valNormal') };
  }

  const fakeBrand = detectBrand(hostname);
  if (fakeBrand) {
    score += 32;
    checks.brand = { label: t('lblBrand'), state:'danger', value: fakeBrand };
    findings.push({ tone:'danger', text: t('fBrandFake', fakeBrand) });
  } else {
    checks.brand = { label: t('lblBrand'), state:'safe', value: t('valClean') };
    findings.push({ tone:'safe', text: t('fBrandOk') });
  }

  const kwHits = SUSPICIOUS_WORDS.filter(w => fullUrl.includes(w));
  if (kwHits.length && !trusted) {
    score += Math.min(kwHits.length * 6, 18);
    checks.keywords = { label: t('lblKeywords'), state:'warn', value:`${kwHits.length} ${t('valCount')}` };
    findings.push({ tone:'warn', text: t('fKeywordHits', kwHits.slice(0,5).join(', ')) });
  } else {
    checks.keywords = { label: t('lblKeywords'), state:'safe', value: t('valClean') };
  }

  if (isStrict) {
    const bare = hostname.replace(/\./g,'');
    const entropy = calcEntropy(bare);
    const hyphens = (hostname.match(/-/g)||[]).length;
    const digits  = (hostname.match(/\d/g)||[]).length;
    const strictHits = [];

    if (bare.length > 24 && !trusted) { score += 10; strictHits.push(t('fStrictLong')); }
    if (hyphens >= 3 && !trusted) { score += 10; strictHits.push(t('fStrictHyphens')); }
    if (digits >= 4 && !trusted) { score += 8; strictHits.push(t('fStrictDigits')); }
    if (entropy > 3.8 && bare.length > 14 && !trusted) {
      score += 14;
      strictHits.push(t('fStrictEntropy', entropy.toFixed(2)));
    }

    if (strictHits.length) {
      checks.strict = { label: t('lblEntropy'), state:'warn', value: strictHits.join(', ') };
      findings.push({ tone:'warn', text: t('fStrictWarn', strictHits.join(', ')) });
    } else {
      checks.strict = { label: t('lblEntropy'), state:'safe', value: t('valNormal') };
    }
  }

  return { score, checks, findings, trusted };
}

function detectBrand(hostname) {
  if (isTrusted(hostname)) return null;
  const parts = hostname.split('.');
  const main  = parts.length > 1 ? parts[parts.length-2] : parts[0];
  const sub   = parts.length > 2 ? parts.slice(0,-2).join('.') : '';
  
  const normMain = normalizeVisual(main);
  const normSub  = normalizeVisual(sub);

  for (const b of BRAND_WORDS) {
    if (sub.includes(b) || normSub.includes(b)) return b;
    if (main !== b && (main.includes(b) || normMain.includes(b))) return b;

    if (b.length > 3) {
      if (levenshtein(main, b) <= 1) return b;
      if (levenshtein(normMain, b) <= 1) return b;
    }
  }
  return null;
}

function normalizeVisual(s) {
  let res = s.toLowerCase();
  res = Array.from(res).map(c => LOOKALIKE_MAP[c] || c).join('');
  for (const [key, val] of Object.entries(NORM_MAP)) {
    res = res.split(key).join(val);
  }
  return res;
}

function levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix = Array.from({ length: b.length + 1 }, (_, i) => [i]);
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      const cost = b[i - 1] === a[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost);
    }
  }
  return matrix[b.length][a.length];
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
  for (const proxy of CORS_PROXIES) {
    try {
      setLog(`${t('logTrying')}${proxy.name}...`);
      const apiUrl = proxy.build(url.href);
      const resp = await fetch(apiUrl, { signal: AbortSignal.timeout(15000) });

      if (!resp.ok) continue;

      let html;
      if (proxy.isText) {
        html = await resp.text();
      } else {
        const data = await resp.json();
        html = proxy.parse(data);
      }

      if (html && html.length > 50) {
        return { ok: true, html: html, proxy: proxy.name };
      }
    } catch (e) {
      console.warn(`Proxy "${proxy.name}" failed:`, e.message);
      continue;
    }
  }

  try {
    setLog(t('logDirect'));
    const resp = await fetch(url.href, {
      mode: 'cors',
      signal: AbortSignal.timeout(10000),
    });
    if (resp.ok) {
      const html = await resp.text();
      if (html && html.length > 50) {
        return { ok: true, html, proxy: 'direct' };
      }
    }
  } catch {}

  return {
    ok: false,
    reason: t('logAllFailed')
  };
}

function analyzeSource(html, url) {
  const findings = [];
  let score = 0;
  const lower = html.toLowerCase();

  const MALWARE_PATTERNS = [
    { re: /eval\s*\(\s*(?:unescape|atob|String\.fromCharCode)/gi, label:'Obfuscated eval()', score:30 },
    { re: /document\.write\s*\(\s*(?:unescape|atob)/gi, label:'Encoded document.write', score:25 },
    { re: /(?:window|document)\s*\[\s*['"][^'"]{1,4}['"]\s*\]/gi, label:'Property obfuscation', score:20 },
    { re: /(?:fromCharCode|charCodeAt)\s*\(/gi, label:'CharCode usage', score:15 },
    { re: /base64_decode|base64decode/gi, label:'Base64 decode', score:12 },
    { re: /\bpassword\b.*\binput\b|\binput\b.*\bpassword\b/gi, label:'Password input', score:10 },
    { re: /\.onload\s*=\s*function.*setTimeout/gs, label:'Delayed loader', score:8 },
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
      findings.push({ tone:'danger', text: t('srcDetected', p.label, matches.length) });
    }
  }

  let redirectCount = 0;
  for (const r of REDIRECT_PATTERNS) {
    const m = html.match(r);
    if (m) redirectCount += m.length;
  }
  if (redirectCount > 0) {
    score += Math.min(redirectCount * 8, 24);
    findings.push({ tone:'warn', text: t('srcRedirects', redirectCount) });
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
    findings.push({ tone:'warn', text: t('srcExtScripts', uniqueExt.length) });
  } else if (uniqueExt.length > 0) {
    findings.push({ tone:'neutral', text: t('srcExtInfo', uniqueExt.slice(0,3).join(', ')) });
  }

  const forms = html.match(/<form[^>]*>/gi) || [];
  const suspForms = forms.filter(f => {
    const action = (f.match(/action\s*=\s*['"]([^'"]*)['\"]/i)||[])[1]||'';
    if (!action) return false;
    try { const au = new URL(action, url.href); return au.hostname !== url.hostname; } catch { return false; }
  });
  if (suspForms.length > 0) {
    score += suspForms.length * 20;
    findings.push({ tone:'danger', text: t('srcFormDanger', suspForms.length) });
  }

  const iframeCount = (html.match(/<iframe/gi)||[]).length;
  if (iframeCount > 2) {
    score += 10;
    findings.push({ tone:'warn', text: t('srcIframes', iframeCount) });
  }

  if (lower.includes('cryptominer') || lower.includes('coinhive') || lower.includes('minero.js') || lower.includes('webmr.js')) {
    score += 40;
    findings.push({ tone:'danger', text: t('srcCrypto') });
  }

  if (lower.includes('keylogger') || lower.includes('document.onkeypress') || lower.includes('document.onkeydown')) {
    score += 35;
    findings.push({ tone:'danger', text: t('srcKeylogger') });
  }

  const lowerHtml = lower;
  if (
    (lowerHtml.includes('bank') || lowerHtml.includes('signin') || lowerHtml.includes('password')) &&
    suspForms.length === 0 && forms.length > 0
  ) {
    score += 8;
    findings.push({ tone:'warn', text: t('srcSensitive') });
  }

  if (findings.length === 0) {
    findings.push({ tone:'safe', text: t('srcClean') });
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
  if (score >= 55) return { text: t('verdictHigh'), cls:'high', color:'#ef4444' };
  if (score >= 25) return { text: t('verdictMid'), cls:'mid', color:'#eab308' };
  return { text: t('verdictLow'), cls:'low', color:'#22c55e' };
}

function buildSummary(score, trusted) {
  if (trusted && score < 25) return t('summaryTrusted');
  if (score >= 55) return t('summaryHigh');
  if (score >= 25) return t('summaryMid');
  return t('summaryLow');
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
    sourceBody.textContent      = a.srcAnalysis.snippet || '(empty)';

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
    sourceUrlLabel.textContent  = t('srcLabel');
    sourceStatus.textContent    = t('srcAccessFail');
    sourceStatus.className      = 'source-status err';
    sourceBody.textContent      = t('srcAccessDesc');
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
