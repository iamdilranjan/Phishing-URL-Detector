#!/usr/bin/env python3
import os, math, re, time, json
from collections import deque
from flask import Flask, request, jsonify, render_template_string, send_file
from urllib.parse import urlparse, unquote, parse_qs
import joblib, tldextract, idna
import numpy as np
from io import BytesIO
from scipy.sparse import csr_matrix, hstack

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "url_phish_model.joblib")
THRESHOLD = 3
MAX_HISTORY = 250
PORT = 5000

app = Flask(__name__)
recent = deque(maxlen=MAX_HISTORY)

SHORTENER_DOMAINS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly","adf.ly","is.gd","bitly.com","shorturl.at","trib.al","rb.gy","rebrand.ly"}
RISKY_TLDS = {"xyz","top","club","icu","pw","review","loan","win","click","date","bid","science","kim"}
COMMON_BRAND_TOKENS = {"paypal","google","amazon","apple","facebook","microsoft","bank","chase","wellsfargo","gmail","icloud","netflix","dropbox","login","secure","account","update"}

_RE_IPV4 = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
_RE_IP_ANY = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_AT = re.compile(r'@')
_RE_LONG_RANDOM = re.compile(r'[a-z0-9]{20,}', re.I)
_RE_EXCESS_HYPHENS = re.compile(r'(?:-.*-){2,}')
_RE_NON_ALNUM = re.compile(r'[^a-z0-9\-\._]', re.I)
_RE_PORT = re.compile(r':(\d+)$')

def _safe_parse(url):
    try:
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
            url2 = 'http://' + url
        else:
            url2 = url
        p = urlparse(url2)
        host = (p.hostname or '').lower()
        return p, host
    except Exception:
        return None, ''

def is_ip_hostname(url):
    _, host = _safe_parse(url); return 1 if host and _RE_IPV4.match(host) else 0
def contains_ip(url):
    return 1 if _RE_IP_ANY.search(url) else 0
def has_at_symbol(url):
    return 1 if _RE_AT.search(url) else 0
def uses_punycode(url):
    _, host = _safe_parse(url); return 1 if host and 'xn--' in host else 0
def is_shortened(url):
    _, host = _safe_parse(url)
    if not host: return 0
    try:
        ext = tldextract.extract(host); reg = (ext.domain + '.' + ext.suffix) if ext.suffix else ext.domain
        return 1 if reg in SHORTENER_DOMAINS else 0
    except:
        return 0
def has_suspicious_port(url):
    p, _ = _safe_parse(url)
    if not p: return 0
    port = getattr(p, "port", None)
    if port is None:
        m = _RE_PORT.search(p.netloc or ""); port = int(m.group(1)) if m else None
    if port:
        return 0 if port in (80,443,8080,8000,8443) else 1
    return 0
def long_hostname(url, threshold=60):
    _, host = _safe_parse(url); return 1 if host and len(host) > threshold else 0
def excessive_hyphens_digits(url):
    _, host = _safe_parse(url)
    if not host: return 0
    if _RE_EXCESS_HYPHENS.search(host): return 1
    digits = sum(c.isdigit() for c in host)
    return 1 if digits >= max(3, len(host)//6) else 0
def risky_tld(url):
    _, host = _safe_parse(url)
    if not host: return 0
    try:
        ext = tldextract.extract(host)
        last = (ext.suffix or '').split('.')[-1]
        return 1 if last in RISKY_TLDS else 0
    except:
        return 0
def long_random_path_query(url):
    try:
        p, _ = _safe_parse(url); combined = (p.path or '') + (p.query or '')
        return 1 if _RE_LONG_RANDOM.search(combined) else 0
    except:
        return 0
def brand_in_subdomain(url):
    _, host = _safe_parse(url)
    if not host: return 0
    parts = host.split('.')
    if len(parts) < 3: return 0
    for tok in parts[:-2]:
        if tok.lower() in COMMON_BRAND_TOKENS: return 1
    for tok in parts:
        for b in COMMON_BRAND_TOKENS:
            if b in tok and tok != b:
                try:
                    ext = tldextract.extract(host); reg = (ext.domain or '').lower()
                    if b != reg: return 1
                except:
                    pass
    return 0
def brand_in_path_or_query(url):
    try:
        p, _ = _safe_parse(url); s = ((p.path or '') + " " + (p.query or '')).lower()
        for b in COMMON_BRAND_TOKENS:
            if b in s: return 1
    except:
        pass
    return 0
def non_alnum_chars_in_host(url):
    _, host = _safe_parse(url); return 1 if host and _RE_NON_ALNUM.search(host) else 0
def many_subdomains(url, threshold=4):
    _, host = _safe_parse(url)
    if not host: return 0
    parts = [p for p in host.split('.') if p]; return 1 if len(parts) >= threshold else 0
def high_entropy_path(url, entropy_threshold=4.0):
    try:
        p, _ = _safe_parse(url); s = ((p.path or '') + (p.query or '')).strip()
        if not s: return 0
        freq = {}; L = len(s)
        for ch in s: freq[ch] = freq.get(ch, 0) + 1
        H = 0.0
        for v in freq.values():
            pch = v / L; H -= pch * math.log2(pch)
        return 1 if H >= entropy_threshold else 0
    except:
        return 0
def tiny_tld_like(url):
    _, host = _safe_parse(url)
    if not host: return 0
    parts = host.split('.'); return 1 if parts and len(parts[0]) <= 2 and len(parts) == 2 else 0
def suspicious_file_extension(url):
    suspicious_exts = ('.exe', '.scr', '.zip', '.rar', '.msi', '.bat', '.php', '.jsp')
    try:
        p, _ = _safe_parse(url); path = (p.path or '').lower()
        for ext in suspicious_exts:
            if path.endswith(ext): return 1
    except:
        pass
    return 0

RULES = [
    ("ip_in_hostname", is_ip_hostname, 3, "Hostname is an IP address"),
    ("contains_ip", contains_ip, 2, "URL contains raw IP"),
    ("at_symbol", has_at_symbol, 2, "Contains '@' character"),
    ("punycode", uses_punycode, 2, "Uses punycode (xn--)"),
    ("shortener", is_shortened, 1, "Known URL shortener"),
    ("suspicious_port", has_suspicious_port, 1, "Non-standard port"),
    ("long_hostname", long_hostname, 1, "Very long hostname"),
    ("excess_hyphens_digits", excessive_hyphens_digits, 1, "Many hyphens/digits"),
    ("risky_tld", risky_tld, 1, "TLD commonly abused"),
    ("long_random_path", long_random_path_query, 2, "Random token in path/query"),
    ("brand_in_subdomain", brand_in_subdomain, 2, "Brand token in subdomain"),
    ("brand_in_path", brand_in_path_or_query, 2, "Brand token in path/query"),
    ("non_alnum", non_alnum_chars_in_host, 1, "Non-alphanumeric chars in hostname"),
    ("many_subdomains", many_subdomains, 1, "Many subdomain levels"),
    ("high_entropy", high_entropy_path, 1, "High entropy in path/query"),
    ("tiny_domain", tiny_tld_like, 1, "Tiny/suspicious domain label"),
    ("suspicious_ext", suspicious_file_extension, 2, "Suspicious file extension"),
]

def analyze_url(url, threshold=THRESHOLD):
    score = 0; triggered = []; details = {}
    for name, fn, weight, msg in RULES:
        try:
            val = bool(fn(url))
        except:
            val = False
        details[name] = val
        if val:
            score += weight
            triggered.append({"rule": name, "message": msg, "weight": weight})
    label = 1 if score >= threshold else 0
    return {"url": url, "score": score, "label": label, "triggered_rules": triggered, "details": details}

MODEL = None
if os.path.exists(MODEL_PATH):
    try:
        MODEL = joblib.load(MODEL_PATH)
        app.logger.info("Loaded ML model: %s", MODEL_PATH)
    except Exception:
        app.logger.exception("Failed to load model")
        MODEL = None
else:
    app.logger.info("No ML model found at %s — heuristics only.", MODEL_PATH)

def predict_ml_prob(url):
    if not MODEL:
        return None
    try:
        feat_order = MODEL.get('rules_features'); scaler = MODEL.get('scaler'); tfidf = MODEL.get('tfidf'); model = MODEL.get('model')
        det = analyze_url(url).get('details', {})
        row = np.array([[1 if det.get(n, False) else 0 for n in feat_order]], dtype=int)
        scaled = scaler.transform(row)
        Xtf = tfidf.transform([url])
        X = hstack([csr_matrix(scaled), Xtf])
        return float(model.predict_proba(X)[:,1][0])
    except Exception:
        app.logger.exception("ML predict error")
        return None

def explain_ml(url, topk=6):
    if not MODEL:
        return None
    try:
        feat_order = MODEL.get('rules_features'); scaler = MODEL.get('scaler'); tfidf = MODEL.get('tfidf'); model = MODEL.get('model')
        det = analyze_url(url).get('details', {})
        rule_vec = np.array([[1 if det.get(n, False) else 0 for n in feat_order]], dtype=int)
        rule_vec_scaled = scaler.transform(rule_vec)
        Xtf = tfidf.transform([url])
        Xfull = hstack([csr_matrix(rule_vec_scaled), Xtf])
        coef = model.coef_.ravel(); intercept = float(model.intercept_[0]) if hasattr(model, 'intercept_') else 0.0
        n_rules = len(feat_order)
        coef_rules = coef[:n_rules]; coef_tfidf = coef[n_rules:]
        scaled_arr = rule_vec_scaled.toarray() if hasattr(rule_vec_scaled, "toarray") else np.array(rule_vec_scaled)
        rule_contribs = {}
        for i, name in enumerate(feat_order):
            val = float(scaled_arr[0, i]); contrib = float(coef_rules[i] * val)
            rule_contribs[name] = {"value": bool(rule_vec[0,i]), "contrib": contrib}
        try:
            tfidf_feature_names = tfidf.get_feature_names_out()
        except:
            tfidf_feature_names = tfidf.get_feature_names()
        Xtf_coo = Xtf.tocoo(); tfidf_contribs = []
        for col, data in zip(Xtf_coo.col, Xtf_coo.data):
            ngram = tfidf_feature_names[col]; tfidf_val = float(data); coef_val = float(coef_tfidf[col]); contrib = float(coef_val * tfidf_val)
            tfidf_contribs.append((ngram, tfidf_val, contrib, coef_val))
        tfidf_contribs_sorted = sorted(tfidf_contribs, key=lambda x: x[2], reverse=True)[:topk]
        Xarr = Xfull.toarray().ravel(); logit = float(intercept + np.dot(coef, Xarr)); prob = 1.0 / (1.0 + math.exp(-logit))
        return {"probability": float(prob), "label": int(prob >= 0.5), "logit": logit, "rule_contributions": rule_contribs, "top_tfidf_contributors": [{"ngram": t, "tfidf": v, "contrib": c} for (t, v, c, coef_val) in tfidf_contribs_sorted]}
    except Exception:
        app.logger.exception("explain_ml error")
        return None

INDEX_HTML = r'''
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>URL Detector — Premium UI (Animated Gauge)</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#f6fbff;--card:#fff;--muted:#6b7280;--accent1:#0c5bd6;--accent2:#0ea5e9;--ok:#10b981;--danger:#ef4444}
*{box-sizing:border-box}
body{font-family:Inter,system-ui,Arial,sans-serif;background:linear-gradient(180deg,#fbfdff,#f6fbff);margin:0;color:#051226;-webkit-font-smoothing:antialiased}
.container{max-width:1080px;margin:36px auto;padding:20px}
.header{display:flex;align-items:center;gap:16px;margin-bottom:18px}
.logo{width:68px;height:68px;border-radius:12px;background:linear-gradient(135deg,#eef7ff,#f0fbff);display:flex;align-items:center;justify-content:center;font-weight:900;color:#0b63b8;font-size:26px}
.title{font-size:20px;font-weight:800}
.subtitle{color:var(--muted);margin-top:6px}
.panel{background:var(--card);border-radius:12px;padding:18px;box-shadow:0 18px 60px rgba(6,18,40,0.06);border:1px solid rgba(14,90,180,0.03)}
.controls{display:flex;gap:12px;align-items:center}
.input{flex:1;padding:12px;border-radius:10px;border:1px solid #e9f4ff;font-size:15px;outline:none;transition:box-shadow .15s,transform .08s}
.input:focus{box-shadow:0 8px 24px rgba(12,91,214,0.08);transform:translateY(-2px)}
.btn{padding:10px 14px;border-radius:10px;border:0;background:linear-gradient(90deg,var(--accent1),var(--accent2));color:#fff;font-weight:800;cursor:pointer;box-shadow:0 10px 28px rgba(12,91,214,0.08)}
.btn.ghost{background:transparent;border:1px solid #eef6ff;color:#0b1220;padding:8px 12px}
.layout{display:grid;grid-template-columns:2fr 1fr;gap:18px;margin-top:18px}
@media(max-width:900px){.layout{grid-template-columns:1fr}}
.result{padding:22px;border-radius:12px;background:linear-gradient(180deg,#fff,#fbfdff);border:1px solid #eef8ff;min-height:240px;display:flex;gap:20px;align-items:center;transition:transform .12s,box-shadow .12s}
.result.enter{transform:translateY(-6px);box-shadow:0 24px 80px rgba(6,18,40,0.08)}
.left{flex:1}
.domain{font-weight:800;font-size:20px;letter-spacing:0.1px}
.path{color:var(--muted);margin-top:6px}
.verdict-block{display:flex;flex-direction:column;align-items:center;gap:12px;min-width:190px}
.pill{padding:12px 18px;border-radius:999px;font-weight:900;font-size:15px;display:inline-block}
.pill.ok{background:linear-gradient(90deg,#ecfff2,#f0fff7);color:var(--ok);border:1px solid rgba(16,185,129,0.08)}
.pill.phish{background:linear-gradient(90deg,#fff2f2,#fff7f7);color:var(--danger);border:1px solid rgba(239,68,68,0.08)}
.gauge-wrap{width:120px;height:120px;display:flex;align-items:center;justify-content:center;position:relative}
.gauge-svg{transform:rotate(-90deg)}
.gauge-center{position:absolute;width:78px;height:78px;border-radius:999px;background:linear-gradient(180deg,#fff,#fbfdff);display:flex;align-items:center;justify-content:center;font-weight:800}
.meta{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap}
.meta .tag{background:#f3f8ff;padding:8px 10px;border-radius:8px;font-weight:700}
.reasons{margin-top:14px}
.reasons .row{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px dashed #f4f8fb}
.reasons .row:last-child{border-bottom:none}
.side{padding:14px;border-radius:10px;background:#fff;border:1px solid #eef8ff}
.side h3{margin:0 0 8px 0}
.tools{display:flex;gap:8px;flex-wrap:wrap}
.tools .btn-mini{padding:8px 10px;border-radius:10px;background:transparent;border:1px solid #eef6ff;cursor:pointer}
.history{margin-top:12px}
.history .item{padding:10px;border-radius:8px;background:#fbfdff;border:1px solid #eef8ff;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;transition:transform .08s}
.history .item:hover{transform:translateX(6px)}
.small{font-size:13px;color:var(--muted)}
.footer{margin-top:18px;color:var(--muted);font-size:13px;text-align:center}
.kv{font-weight:800}
.timestamp{font-size:12px;color:#94a3b8}
svg path.animated { transition: stroke-dashoffset 900ms cubic-bezier(.16,.9,.36,1), stroke 800ms ease; }
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">U</div>
      <div style="flex:1">
        <div class="title">URL Detector — Premium</div>
        <div class="subtitle small">Clean verdict, animated confidence gauge, and concise reasons. Model used if present locally.</div>
      </div>
    </div>

    <div class="panel">
      <div class="controls">
        <input id="url" class="input" placeholder="Paste a URL or domain (e.g. https://example.com/login)" onkeydown="if(event.key==='Enter'){analyze()}">
        <button class="btn" onclick="analyze()">Analyze</button>
        <button class="btn ghost" onclick="clearInput()">Clear</button>
      </div>

      <div class="layout">
        <div>
          <div id="result" class="result" role="region" aria-live="polite">
            <div class="left">
              <div class="domain">No analysis yet</div>
              <div class="path small">Paste a URL and click Analyze</div>
              <div class="meta">
                <div class="tag">Heuristics threshold: <span class="kv">''' + str(THRESHOLD) + '''</span></div>
                <div class="tag" id="modelTag">Model: checking…</div>
              </div>
              <div class="reasons" id="reasonsArea"></div>
            </div>

            <div class="verdict-block" aria-hidden="false">
              <div id="verdictPill" class="pill ok">—</div>
              <div class="gauge-wrap" aria-hidden="false">
                <svg id="gaugeSvg" class="gauge-svg" width="120" height="120" viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Confidence gauge">
                  <defs>
                    <linearGradient id="gradA" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stop-color="#34d399"/>
                      <stop offset="50%" stop-color="#f59e0b"/>
                      <stop offset="100%" stop-color="#ef4444"/>
                    </linearGradient>
                  </defs>
                  <circle cx="60" cy="60" r="52" stroke="#eef6ff" stroke-width="12" fill="none"/>
                  <path id="arcPath" class="animated" d="" stroke="url(#gradA)" stroke-width="12" fill="none" stroke-linecap="round"></path>
                </svg>
                <div class="gauge-center" id="gaugeCenter">—</div>
              </div>
              <div class="small" id="scoreLabel">Score: —</div>
            </div>
          </div>
        </div>

        <aside class="side" aria-label="Side tools and history">
          <h3>Quick actions</h3>
          <div class="tools" style="margin-top:8px">
            <button class="btn-mini" onclick="copyLatest()">Copy last</button>
            <button class="btn-mini" onclick="openLatest()">Open last</button>
            <button class="btn-mini" onclick="downloadHistory()">Export JSON</button>
          </div>

          <div class="history" id="historyBox">
            <div class="small" style="margin-top:12px">Recent</div>
            <div id="historyList" style="margin-top:10px"></div>
          </div>
        </aside>
      </div>

      <div class="footer">Educational demo • Do not click suspicious links in your normal browser.</div>
    </div>
  </div>

<script>
const esc = s => s===undefined||s===null ? '' : String(s).replace(/[&<>"'`=\/]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','/':'&#47;','`':'&#96;','=':'&#61;'}[m]));
let lastResult = null;

function polarArc(cx, cy, r, pct){
  const angle = pct/100 * 2 * Math.PI;
  const x = cx + r * Math.cos(angle);
  const y = cy + r * Math.sin(angle);
  const large = pct > 50 ? 1 : 0;
  const sx = cx + r * Math.cos(0);
  const sy = cy + r * Math.sin(0);
  return `M ${sx} ${sy} A ${r} ${r} 0 ${large} 1 ${x} ${y}`;
}

async function init(){
  try{
    const r = await fetch('/api/health'); const j = await r.json();
    document.getElementById('modelTag').textContent = j.ml_loaded ? 'Model: loaded' : 'Model: not loaded';
    refreshHistory();
    // initialize empty arc (0%)
    setAnimatedArc(0, false);
  }catch(e){
    document.getElementById('modelTag').textContent = 'Model: check failed';
  }
}
init();

function setAnimatedArc(pct, animate=true){
  const path = document.getElementById('arcPath');
  const d = polarArc(60,60,52, pct);
  path.setAttribute('d', d);
  // compute path length and animate stroke-dashoffset
  const L = path.getTotalLength();
  path.style.strokeDasharray = L;
  if (!animate) {
    path.style.transition = 'none';
    path.style.strokeDashoffset = (1 - pct/100) * L;
    // force reflow then restore transition
    void path.getBoundingClientRect();
    path.style.transition = 'stroke-dashoffset 900ms cubic-bezier(.16,.9,.36,1), stroke 800ms ease';
  } else {
    // set starting offset fully hidden then animate to target
    path.style.transition = 'none';
    path.style.strokeDashoffset = L;
    // small timeout to ensure the browser registers the starting offset
    requestAnimationFrame(()=> {
      // allow transition defined in CSS (class 'animated') to run
      path.style.transition = 'stroke-dashoffset 900ms cubic-bezier(.16,.9,.36,1), stroke 800ms ease';
      path.style.strokeDashoffset = (1 - pct/100) * L;
    });
  }
  // color blending: change stroke to gradient (already set) - no-op here
}

function clearInput(){ document.getElementById('url').value=''; renderEmpty(); }

function renderEmpty(){
  document.getElementById('verdictPill').className = 'pill ok';
  document.getElementById('verdictPill').textContent = '—';
  setAnimatedArc(0, false);
  document.getElementById('gaugeCenter').textContent = '—';
  document.getElementById('scoreLabel').textContent = 'Score: —';
  document.querySelector('.domain').textContent = 'No analysis yet';
  document.querySelector('.path').textContent = 'Paste a URL and click Analyze';
  document.getElementById('reasonsArea').innerHTML = '';
}

function animateResult(){ const r=document.getElementById('result'); r.classList.remove('enter'); void r.offsetWidth; r.classList.add('enter'); }

async function analyze(){
  const u = document.getElementById('url').value.trim();
  if(!u){ alert('Enter a URL'); return; }
  document.querySelector('.domain').textContent = 'Analyzing…';
  document.querySelector('.path').textContent = esc(u);
  document.getElementById('reasonsArea').innerHTML = '<div class="small">Working…</div>';
  try{
    const r = await fetch('/api/predict', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url:u})});
    const j = await r.json();
    if(j.error){ alert('Error: ' + j.error); renderEmpty(); return; }
    lastResult = j;
    renderResult(j);
    refreshHistory();
  }catch(e){ alert('Network error: ' + e); renderEmpty(); }
}

function renderResult(d){
  animateResult();
  const domain = d.parsed.registered_domain || d.parsed.host || d.url;
  const path = d.parsed.path || '/';
  const ml = (typeof d.ml_probability === 'number') ? Math.round(d.ml_probability*1000)/10 : null;
  const isPhish = !!d.label;
  document.querySelector('.domain').textContent = domain;
  document.querySelector('.path').textContent = path;
  document.getElementById('scoreLabel').textContent = 'Score: ' + d.score;
  const pill = document.getElementById('verdictPill');
  pill.className = 'pill ' + (isPhish ? 'phish' : 'ok');
  pill.textContent = isPhish ? 'PHISH' : 'OK';
  const gaugePct = ml !== null ? Math.max(0, Math.min(100, ml)) : (isPhish?88:12);
  setAnimatedArc(Math.round(gaugePct), true);
  document.getElementById('gaugeCenter').textContent = ml !== null ? Math.round(gaugePct) + '%' : (isPhish? 'Likely' : 'Low');

  const reasonsEl = document.getElementById('reasonsArea'); reasonsEl.innerHTML = '';
  if(d.triggered_rules && d.triggered_rules.length){
    d.triggered_rules.slice(0,6).forEach((r,i)=>{
      const row = document.createElement('div'); row.className = 'row';
      row.innerHTML = '<div style="display:flex;gap:12px;align-items:center"><svg class="icon" width="18" height="18" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#eef8ff"/></svg><div><div style="font-weight:700">'+esc(r.message)+'</div><div class="small">'+esc(r.rule)+'</div></div></div><div style="font-weight:800;color:#ef4444">+'+r.weight+'</div>';
      reasonsEl.appendChild(row);
    });
  } else {
    const none = document.createElement('div'); none.className = 'small'; none.textContent = 'No heuristic signals';
    reasonsEl.appendChild(none);
  }

  if(d.ml_explain && d.ml_explain.top_tfidf_contributors && d.ml_explain.top_tfidf_contributors.length){
    const hr = document.createElement('div'); hr.style.marginTop='12px'; hr.innerHTML = '<div style="font-weight:700;margin-bottom:8px">ML signals</div>';
    const list = document.createElement('div');
    d.ml_explain.top_tfidf_contributors.slice(0,5).forEach(t=>{
      const it = document.createElement('div'); it.className='row';
      const sign = t.contrib >= 0 ? '+' : '';
      it.innerHTML = '<div class="small">'+esc(t.ngram)+'</div><div style="font-weight:800;color:'+(t.contrib>=0? '#ef4444':'#10b981')+'">'+sign+Number(t.contrib).toFixed(4)+'</div>';
      list.appendChild(it);
    });
    hr.appendChild(list); reasonsEl.appendChild(hr);
  }
}

async function refreshHistory(){
  try{
    const r = await fetch('/api/history'); const j = await r.json();
    const box = document.getElementById('historyList'); box.innerHTML = '';
    if(!j || !j.length){ box.innerHTML = '<div class="small">No recent analyses</div>'; return; }
    j.slice(0,8).forEach(it=>{
      const el = document.createElement('div'); el.className = 'item';
      const timeS = new Date(it.ts*1000).toLocaleString();
      el.innerHTML = '<div style="max-width:70%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><strong>'+esc(it.parsed.registered_domain || it.parsed.host || it.url)+'</strong><div class="small">'+esc(it.parsed.path||'')+'</div></div><div style="text-align:right"><div style="font-weight:800">'+(it.label? 'PHISH' : 'OK')+'</div><div class="timestamp">'+timeS+'</div></div>';
      el.onclick = ()=>{ document.getElementById('url').value = it.url; lastResult = it; renderResult(it); window.scrollTo({top:0,behavior:'smooth'}); };
      box.appendChild(el);
    });
  }catch(e){ console.error('history err', e); }
}

async function copyLatest(){
  try{
    if(!lastResult){ alert('No result yet'); return; }
    await navigator.clipboard.writeText(lastResult.url);
    alert('Copied: ' + lastResult.url);
  }catch(e){ alert('Copy failed: ' + e); }
}

async function openLatest(){
  try{
    if(!lastResult){ alert('No result yet'); return; }
    window.open(lastResult.url, '_blank', 'noopener');
  }catch(e){ alert('Open failed: ' + e); }
}

async function downloadHistory(){
  try{
    const r = await fetch('/api/export');
    if(r.status !== 200){ alert('Export failed'); return; }
    const blob = await r.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'url_detector_history.json'; document.body.appendChild(a); a.click(); a.remove(); window.URL.revokeObjectURL(url);
  }catch(e){ alert('Export failed: '+e); }
}

window.onload = ()=>{ refreshHistory(); };
</script>
</body>
</html>
'''

@app.route('/api/health', methods=['GET'])
def api_health():
    ml_loaded = False
    try:
        ml_loaded = (predict_ml_prob("example.com") is not None)
    except Exception:
        ml_loaded = False
    return jsonify({"status":"ok", "ml_loaded": bool(ml_loaded)})

@app.route('/api/predict', methods=['POST'])
def api_predict():
    data = request.get_json() or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error":"no url provided"}), 400
    try:
        heur = analyze_url(url)
        raw = url.strip()
        probe = raw if raw.startswith("http://") or raw.startswith("https://") else "http://"+raw
        p = urlparse(probe); host = (p.hostname or "")
        try:
            tx = tldextract.extract(host or "")
            registered = (tx.domain + "." + tx.suffix) if tx.domain and tx.suffix else (tx.domain or host)
        except:
            registered = host
        puny = None
        if host and "xn--" in host:
            try:
                parts = host.split("."); dec=[]
                for t in parts:
                    try: dec.append(idna.decode(t))
                    except: dec.append(t)
                puny = ".".join(dec)
            except: puny = None
        q = parse_qs(p.query or "")
        parsed = {"raw":raw,"probe":probe,"scheme":p.scheme,"host":host,"registered_domain":registered,"punycode_preview":puny,"path":unquote(p.path or ""),"query":p.query or "","query_param_count":sum(len(v) for v in q.values())}

        ml_prob = None; ml_explain = None
        try: ml_prob = predict_ml_prob(url)
        except: ml_prob = None
        try: ml_explain = explain_ml(url, topk=6) if MODEL else None
        except: ml_explain = None

        out = {"url":url,"score":int(heur.get("score",0)),"label":int(heur.get("label",0)),"triggered_rules":heur.get("triggered_rules",[]),"details":heur.get("details",{}),"parsed":parsed,"ml_probability":ml_prob,"ml_explain":ml_explain,"ts": int(time.time())}

        try:
            recent.appendleft(out)
        except Exception:
            pass

        return jsonify(out)
    except Exception as e:
        app.logger.exception("predict error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/history', methods=['GET'])
def api_history():
    return jsonify(list(recent))

@app.route('/api/export', methods=['GET'])
def api_export():
    data = list(recent)
    bio = BytesIO()
    bio.write(json.dumps(data, indent=2).encode('utf-8'))
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name='url_detector_history.json', mimetype='application/json')

@app.route('/', methods=['GET'])
def index():
    return render_template_string(INDEX_HTML)

if __name__ == "__main__":
    print("Starting premium URL Detector on port", PORT, " model loaded:", bool(MODEL))
    app.run(debug=True, port=PORT)
