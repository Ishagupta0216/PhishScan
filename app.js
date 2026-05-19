// ============================================================
// app.js — UI rendering, samples, and user interactions
// ============================================================

const SAMPLES = {
  phish: `From: security@paypa1-alerts.com
Subject: URGENT: Your PayPal account has been suspended!
SPF: FAIL
DMARC: FAIL

Dear Customer,

We have detected unauthorized access and suspicious activity on your PayPal account. Your account will be permanently disabled within 24 hours if you do not verify your identity immediately.

Click here to verify your account: http://paypal-secure-login.xyz/verify

You must provide your password and credit card details to restore access. Failure to comply will result in permanent account termination. This is your last chance to act now.

PayPal Security Team`,

  clean: `From: monica.chhetri@gla.ac.in
Subject: Infosys test Schedule - 29 March 2026
SPF: PASS
DKIM: PASS with domain gla.ac.in
DMARC: PASS

Dear Students,

Greetings!!!

Kindly attend the Infosys test link.
Date: 29 March 2026
Time: 2 to 5 PM
You all have to attempt the test.

Important Note:
The login window will remain open for 30 minutes only, students must start the test within this time frame.

Regards & Thanks,
Ms Monica Bhatt Chhetri
Vice President-Corporate Relations
Mobile: 8527823921
Email: monica.chhetri@gla.ac.in

GLA University`
};


// ─── Build analyst report ───────────────────────────────────

function buildAnalystReport(res) {
  const ctxHits = res.contextHits || [];
  const regHits = res.signals.filter(s => s.hit);

  if (ctxHits.length === 0 && regHits.length === 0 && res.score <= 10) {
    return `<p>All checks passed. No phishing indicators detected. 
    The sender domain is verified, authentication headers are clean, 
    and no suspicious content patterns were found.</p>`;
  }

  let html = '';

  if (ctxHits.length > 0) {
    html += `<p><strong>Context signals detected (${ctxHits.length}):</strong></p><ul>`;
    ctxHits.forEach(s => {
      html += `<li>${s.label} <span style="color:#f87171">(+${s.contribution} pts)</span></li>`;
    });
    html += '</ul>';
  }

  if (regHits.length > 0) {
    html += `<p style="margin-top:8px"><strong>Pattern signals detected (${regHits.length}):</strong></p><ul>`;
    regHits.forEach(s => {
      html += `<li>${s.label} <span style="color:#f87171">(+${s.contribution} pts)</span></li>`;
    });
    html += '</ul>';
  }

  return html || '<p>Low-level signals only. Treat with caution.</p>';
}


// ─── Auth badge HTML ────────────────────────────────────────

function authBadge(label, value) {
  let cls = 'auth-none';
  let display = value.toUpperCase();
  if (value === 'pass') cls = 'auth-pass';
  else if (value === 'fail') cls = 'auth-fail';
  else if (value === 'softfail') { cls = 'auth-softfail'; display = 'SOFTFAIL'; }
  else display = 'NOT FOUND';
  return `<span class="auth-badge ${cls}">${label}: ${display}</span>`;
}


// ─── Render results ─────────────────────────────────────────

function renderResults(res) {
  const hitCount = res.signals.filter(s => s.hit).length;
  const ctxCount = (res.contextHits || []).length;

  const sigHTML = res.signals.map(s => `
    <div class="sig ${s.hit ? 'hit' : 'miss'}">
      <span class="sig-icon">${s.icon}</span>
      <div class="sig-txt">
        ${s.label}
        ${s.hit ? `<div class="sig-pts">+${s.contribution} pts</div>` : ''}
      </div>
    </div>`).join('');

  const ctxHTML = (res.contextHits || []).length > 0
    ? `<div class="section-lbl">Context Analysis</div>
       <div class="context-hits">
         ${res.contextHits.map(s => `
           <div class="ctx-item">
             ⚡ ${s.label}
             <span class="ctx-pts">+${s.contribution} pts</span>
           </div>`).join('')}
       </div>`
    : '';

  const trustClass = {
    high: 'trust-high',
    medium: 'trust-medium',
    none: 'trust-none'
  }[res.trust.level];

  const trustIcon = {
    high: '✅',
    medium: '🔵',
    none: '❓'
  }[res.trust.level];

  const out = document.getElementById('out');
  out.innerHTML = `
    <div class="card ${res.level}">

      <div class="score-row">
        <div class="circle">
          <span class="circle-num">${res.score}</span>
          <span class="circle-lbl">/ 100</span>
        </div>
        <div>
          <div class="verdict">${res.verdict}</div>
          <div class="verdict-sub">${res.desc}</div>
          <div class="tally">
            ${ctxCount} context + ${hitCount} pattern signals triggered
          </div>
        </div>
      </div>

      <div class="bar-bg">
        <div class="bar-fill" id="bfill" style="width:0%"></div>
      </div>

      <div class="section-lbl">Email Authentication</div>
      <div class="auth-row">
        ${authBadge('SPF', res.auth.spf)}
        ${authBadge('DKIM', res.auth.dkim)}
        ${authBadge('DMARC', res.auth.dmarc)}
      </div>

      <div class="trust-row">
        <div class="section-lbl">Sender Trust</div>
        <span class="trust-badge ${trustClass}">
          ${trustIcon} ${res.trust.label}
          ${res.trust.reduction > 0 ? '(−' + res.trust.reduction + ' pts)' : ''}
        </span>
      </div>

      ${ctxHTML}

      <div class="section-lbl">Pattern Signals</div>
      <div class="sig-grid">${sigHTML}</div>

      <div class="divider"></div>

      <div class="section-lbl">Analyst Report</div>
      <div class="analysis-box">${buildAnalystReport(res)}</div>

      <div class="rec-box">
        🛡️ <div><strong>Recommended action:</strong> ${res.recommendation}</div>
      </div>

    </div>`;

  setTimeout(() => {
    const f = document.getElementById('bfill');
    if (f) f.style.width = res.score + '%';
  }, 60);
}


// ─── Public functions ───────────────────────────────────────

function runScan() {
  const text = document.getElementById('emailIn').value.trim();
  if (!text) { alert('Please paste an email to scan.'); return; }
  renderResults(analyzeEmail(text));
}

function loadSample(type) {
  document.getElementById('emailIn').value = SAMPLES[type];
  document.getElementById('out').innerHTML = '';
}

function clearAll() {
  document.getElementById('emailIn').value = '';
  document.getElementById('out').innerHTML = '';
}