// ============================================================
// PhishScan engine.js — 4-layer detection system
// Layer 1: Header authentication (SPF / DKIM / DMARC)
// Layer 2: Sender trust scoring
// Layer 3: Context-aware content signals
// Layer 4: Regex pattern signals (reduced weight)
// ============================================================


// ─── LAYER 1: Header Authentication ────────────────────────

function parseAuthHeaders(text) {
  const result = {
    spf: 'none',
    dkim: 'none',
    dmarc: 'none',
    score: 0,
    flags: []
  };

  // SPF
  if (/spf=pass/i.test(text)) {
    result.spf = 'pass';
    result.score -= 10;
  } else if (/spf=fail(?!ure)/i.test(text) || /spf:\s*fail(?!ure)/i.test(text)) {
    result.spf = 'fail';
    result.score += 30;
    result.flags.push('SPF hard fail — sender not authorized to send from this domain');
  } else if (/spf=softfail/i.test(text) || /spf:\s*softfail/i.test(text)) {
    result.spf = 'softfail';
    result.score += 15;
    result.flags.push('SPF soft fail — sender is questionable');
  }

  // DKIM
  if (/dkim=pass/i.test(text)) {
    result.dkim = 'pass';
    result.score -= 5;
  } else if (/dkim=fail/i.test(text)) {
    result.dkim = 'fail';
    result.score += 20;
    result.flags.push('DKIM fail — email signature invalid or tampered');
  }

  // DMARC
  if (/dmarc=pass/i.test(text)) {
    result.dmarc = 'pass';
    result.score -= 15;
    result.flags.push('DMARC pass — domain identity verified');
  } else if (/dmarc=fail/i.test(text) || /dmarc:\s*['"]?fail/i.test(text)) {
    result.dmarc = 'fail';
    result.score += 25;
    result.flags.push('DMARC fail — domain spoofing likely');
  }

  return result;
}


// ─── LAYER 2: Sender Trust ──────────────────────────────────

const TRUSTED_PATTERNS = {
  high: [
    /from:.*@.*\.ac\.in/i,
    /from:.*@.*\.edu\b/i,
    /from:.*@.*\.gov\.in/i,
    /from:.*@.*\.gov\b/i,
    /from:.*@.*\.ac\.uk/i,
    /from:.*@.*\.edu\.au/i,
    /from:.*@infosys\.com/i,
    /from:.*@tcs\.com/i,
    /from:.*@wipro\.com/i,
    /from:.*@hcltech\.com/i,
    /from:.*@microsoft\.com/i,
    /from:.*@google\.com/i,
    /from:.*@amazon\.com/i,
  ],
  medium: [
    /from:.*@.*\.org\b/i,
    /from:.*@.*\.ac\.[a-z]{2}\b/i,
    /from:.*@.*\.edu\.[a-z]{2}\b/i,
  ]
};

function getSenderTrust(text) {
  for (const pattern of TRUSTED_PATTERNS.high) {
    if (pattern.test(text)) {
      return { level: 'high', label: 'Trusted institutional sender', reduction: 30 };
    }
  }
  for (const pattern of TRUSTED_PATTERNS.medium) {
    if (pattern.test(text)) {
      return { level: 'medium', label: 'Likely trusted sender', reduction: 15 };
    }
  }
  return { level: 'none', label: 'Unknown sender domain', reduction: 0 };
}


// ─── LAYER 3: Context-Aware Signals ────────────────────────

const CONTEXT_SIGNALS = [
  {
    label: 'Credential request with verification language',
    weight: 25,
    test: (t) =>
      /password|credit card|ssn|social security|billing details|cvv/i.test(t) &&
      /verify|confirm|update|provide|enter your/i.test(t)
  },
  {
    label: 'Urgency language combined with a link',
    weight: 20,
    test: (t) =>
      /urgent|immediately|24 hours|act now|expire|last chance|final notice/i.test(t) &&
      /https?:\/\//i.test(t)
  },
  {
    label: 'Brand name present but sender domain does not match',
    weight: 25,
    test: (t) => {
      const brands = ['paypal','amazon','apple','microsoft','google','netflix','facebook','instagram'];
      const fromLine = (t.match(/from:.*$/im) || [''])[0].toLowerCase();
      return brands.some(b =>
        t.toLowerCase().includes(b) &&
        !fromLine.includes(b + '.com') &&
        !fromLine.includes(b + '.co') &&
        !fromLine.includes(b + '.in')
      );
    }
  },
  {
    label: 'IP address used directly as a URL',
    weight: 30,
    test: (t) => /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(t)
  },
  {
    label: 'Suspicious TLD in link (.xyz, .tk, .ml etc.)',
    weight: 22,
    test: (t) =>
      /https?:\/\/[^\s]*\.(xyz|tk|ml|ga|cf|gq|top|club|work|date|faith|zip|mov)[\/\s"']/i.test(t)
  },
  {
    label: 'URL shortener hiding real destination',
    weight: 15,
    test: (t) => /bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|rb\.gy/i.test(t)
  },
  {
    label: 'Fear tactic with account suspension threat',
    weight: 18,
    test: (t) =>
      /account.*(suspend|terminat|locked|disabled|closed)/i.test(t) &&
      /will be|has been|is being/i.test(t)
  },
  {
    label: 'Fake partnership claims with major brands',
    weight: 12,
    test: (t) =>
      /(microsoft|apple|meta|cisco|hcl|adobe|nasscom).*certif/i.test(t) &&
      /100.*percent|guaranteed|assured|placement/i.test(t)
  },
  {
    label: 'Google Form used for data collection by non-institution',
    weight: 8,
    test: (t) =>
      /docs\.google\.com\/forms/i.test(t) &&
      !/from:.*@.*\.ac\.in|from:.*@.*\.edu|from:.*@.*\.gov/i.test(t)
  },
  {
    label: 'Generic impersonal greeting — recipient not named',
    weight: 8,
    test: (t) =>
      /dear (customer|user|valued|account holder|sir\/madam|sir or madam)/i.test(t) &&
      !/dear [A-Z][a-z]+ [A-Z]/i.test(t)
  },
  {
    label: 'Student email address sending corporate-style offer',
    weight: 12,
    test: (t) =>
      /from:.*_\d{4}@.*\.ac\.in/i.test(t) &&
      /internship|job offer|placement|certification/i.test(t)
  },
  {
    label: 'Prize or lottery claim',
    weight: 20,
    test: (t) =>
      /you.*(won|been selected|been chosen)/i.test(t) ||
      /lottery|jackpot|sweepstakes/i.test(t) ||
      /claim.*prize|claim.*reward/i.test(t)
  },
  {
    label: 'Macro or executable attachment reference',
    weight: 22,
    test: (t) =>
      /enable (macros|content|editing)/i.test(t) ||
      /open.*attachment.*(exe|zip|js|vbs|bat|cmd)/i.test(t)
  }
];


// ─── LAYER 4: Regex Signal Patterns ────────────────────────

const SIGNALS = [
  {
    id: 'urgent',
    label: 'Urgency / deadline language',
    icon: '⏰',
    weight: 8,
    patterns: [
      /act now/i, /within \d+ hours?/i,
      /limited time/i, /last (chance|warning|notice)/i,
      /final notice/i, /expires? (today|soon)/i
    ]
  },
  {
    id: 'sender',
    label: 'Suspicious sender address',
    icon: '👤',
    weight: 15,
    patterns: [
      /from:.*@.*\.(tk|ml|ga|cf|gq)\b/i,
      /from:.*\d{5,}@/i,
      /from:.*(paypal|amazon|apple|microsoft|google|netflix|bank).*@(?!paypal\.|amazon\.|apple\.|microsoft\.|google\.|netflix\.)/i
    ]
  },
  {
    id: 'urls',
    label: 'Suspicious link patterns',
    icon: '🔗',
    weight: 15,
    patterns: [
      /https?:\/\/[^\/]*-[^\/]*-[^\/]*\.(com|net|org)\//i,
      /paypal-|amazon-secure|apple-id-|microsoft-alert/i
    ]
  },
  {
    id: 'creds',
    label: 'Credential harvesting language',
    icon: '🔑',
    weight: 15,
    patterns: [
      /enter your (password|credentials|credit card|ssn)/i,
      /provide (your )?(personal|banking|account) (info|details)/i
    ]
  },
  {
    id: 'brand',
    label: 'Brand impersonation in display name',
    icon: '🎭',
    weight: 14,
    patterns: [
      /from:\s*(paypal|apple inc|amazon|microsoft corporation|google|netflix|facebook|instagram|irs|fedex|ups|dhl)/i
    ]
  },
  {
    id: 'fear',
    label: 'Fear / threat tactics',
    icon: '⚠️',
    weight: 10,
    patterns: [
      /unauthorized (access|login|activity) (was |has been )?detected/i,
      /failure to (comply|respond|verify) (will|may) result/i,
      /we (have|'ve) (detected|noticed) (unusual|suspicious|unauthorized)/i
    ]
  },
  {
    id: 'offer',
    label: 'Too-good-to-be-true offer',
    icon: '🏆',
    weight: 10,
    patterns: [
      /\$\d{3,}[\d,]* (prize|reward|gift|bonus)/i,
      /free (iphone|laptop|vacation|macbook)/i,
      /congratulations.*winner/i
    ]
  },
  {
    id: 'grammar',
    label: 'Suspicious phrasing',
    icon: '💬',
    weight: 5,
    patterns: [
      /kindly (click|verify|update|provide|enter your|submit your password)/i,
      /do the needful/i,
      /your good self/i
    ]
  },
  {
    id: 'attach',
    label: 'Suspicious attachment reference',
    icon: '📎',
    weight: 10,
    patterns: [
      /open (the |this )?(attached|attachment)/i,
      /download.*\.(exe|zip|js|vbs|bat|cmd)/i,
      /enable (macros|content|editing)/i
    ]
  },
  {
    id: 'scarcity',
    label: 'Artificial scarcity / seat pressure',
    icon: '⏳',
    weight: 7,
    patterns: [
      /seats? (are |will be )?(filling|limited|allocated)/i,
      /portal will.*automatically close/i,
      /allocated seats are filled/i
    ]
  }
];


// ─── MAIN analyzeEmail() FUNCTION ──────────────────────────

function analyzeEmail(text) {
  let score = 0;
  const allFlags = [];

  // Layer 1 — Header auth
  const auth = parseAuthHeaders(text);
  score += auth.score;
  allFlags.push(...auth.flags);

  // Layer 2 — Sender trust
  const trust = getSenderTrust(text);
  score -= trust.reduction;
  if (trust.level !== 'none') {
    allFlags.push(trust.label + ' (−' + trust.reduction + ' pts)');
  }

  // Layer 3 — Context signals
  const contextHits = [];
  for (const signal of CONTEXT_SIGNALS) {
    if (signal.test(text)) {
      // Reduce weight if from trusted sender
      const contribution = trust.level === 'high'
        ? Math.floor(signal.weight / 3)
        : trust.level === 'medium'
        ? Math.floor(signal.weight / 1.5)
        : signal.weight;
      score += contribution;
      contextHits.push({ ...signal, contribution });
      allFlags.push(signal.label + ' (+' + contribution + ' pts)');
    }
  }

  // Layer 4 — Regex signals
  const regexResults = SIGNALS.map(s => {
    const hit = s.patterns.some(p => p.test(text));
    let contribution = 0;
    if (hit) {
      contribution = trust.level === 'high'
        ? Math.floor(s.weight / 4)
        : trust.level === 'medium'
        ? Math.floor(s.weight / 2)
        : s.weight;
      score += contribution;
    }
    return { ...s, hit, contribution };
  });

  // Hard rules
  // If all 3 auth checks pass — cap score at 20 (almost certainly legitimate)
  if (auth.spf === 'pass' && auth.dkim === 'pass' && auth.dmarc === 'pass') {
    score = Math.min(score, 20);
  }

  // If SPF hard fail + DMARC fail — minimum score is 45
  if (auth.spf === 'fail' && auth.dmarc === 'fail') {
    score = Math.max(score, 45);
  }

  // If SPF softfail + DMARC fail — minimum score is 35
  if (auth.spf === 'softfail' && auth.dmarc === 'fail') {
    score = Math.max(score, 35);
  }

  // Clamp to 0–100
  score = Math.max(0, Math.min(score, 100));

  // Verdict
  let level, verdict, desc, recommendation;

  if (score <= 10) {
    level = 'safe';
    verdict = 'Clean — Legitimate email';
    desc = 'Authentication passed and no suspicious content detected.';
    recommendation = 'Safe to open and respond normally.';
  } else if (score <= 30) {
    level = 'low';
    verdict = 'Low Risk — Verify sender';
    desc = 'Minor signals found. Likely legitimate but worth double-checking.';
    recommendation = 'Confirm sender through official channels if unsure.';
  } else if (score <= 55) {
    level = 'suspicious';
    verdict = 'Suspicious — Treat with caution';
    desc = 'Multiple indicators detected. Do not share personal information.';
    recommendation = 'Do not click links. Verify through the official website directly.';
  } else {
    level = 'dangerous';
    verdict = 'Dangerous — Likely phishing';
    desc = 'Strong phishing indicators across headers and content.';
    recommendation = 'Delete immediately. Do not click links or reply. Report to SOC team.';
  }

  return {
    score, level, verdict, desc, recommendation,
    signals: regexResults,
    contextHits,
    auth,
    trust,
    allFlags
  };
}