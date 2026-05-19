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
    // ===== EDUCATIONAL DOMAINS =====
    /from:.*@.*\.ac\.in/i,
    /from:.*@.*\.edu\b/i,
    /from:.*@.*\.ac\.uk/i,
    /from:.*@.*\.edu\.au/i,
    /from:.*@.*\.ac\.nz/i,
    /from:.*@.*\.ac\.za/i,
    /from:.*@.*\.ac\.jp/i,
    /from:.*@.*\.ac\.kr/i,
    /from:.*@.*\.ac\.cn/i,
    /from:.*@.*\.ac\.il/i,
    /from:.*@.*\.ac\.at/i,
    /from:.*@.*\.ac\.be/i,
    /from:.*@.*\.ac\.bd/i,
    /from:.*@.*\.ac\.ng/i,
    /from:.*@.*\.edu\.pk/i,
    /from:.*@.*\.edu\.cn/i,
    /from:.*@.*\.edu\.sg/i,
    /from:.*@.*\.edu\.my/i,
    /from:.*@.*\.edu\.ph/i,
    /from:.*@.*\.edu\.tr/i,
    /from:.*@.*\.edu\.eg/i,
    /from:.*@.*\.edu\.br/i,
    /from:.*@.*\.edu\.mx/i,
    /from:.*@.*\.edu\.ar/i,
    /from:.*@.*\.edu\.co/i,
    /from:.*@.*\.edu\.pe/i,
    /from:.*@.*\.edu\.vn/i,
    /from:.*@.*\.edu\.gh/i,
    /from:.*@.*\.edu\.ng/i,
    /from:.*@.*\.edu\.et/i,
    /from:.*@.*\.edu\.np/i,
    /from:.*@.*\.edu\.lk/i,
    /from:.*@.*\.edu\.kw/i,
    /from:.*@.*\.edu\.sa/i,

    // ===== GOVERNMENT DOMAINS =====
    /from:.*@.*\.gov\.in/i,
    /from:.*@.*\.gov\b/i,
    /from:.*@.*\.gov\.uk/i,
    /from:.*@.*\.gov\.au/i,
    /from:.*@.*\.gov\.nz/i,
    /from:.*@.*\.gov\.za/i,
    /from:.*@.*\.gov\.sg/i,
    /from:.*@.*\.gov\.my/i,
    /from:.*@.*\.gov\.ph/i,
    /from:.*@.*\.gov\.pk/i,
    /from:.*@.*\.gov\.bd/i,
    /from:.*@.*\.gov\.np/i,
    /from:.*@.*\.gov\.lk/i,
    /from:.*@.*\.gov\.br/i,
    /from:.*@.*\.gov\.ar/i,
    /from:.*@.*\.gov\.mx/i,
    /from:.*@.*\.gov\.co/i,
    /from:.*@.*\.gov\.eg/i,
    /from:.*@.*\.gov\.ng/i,
    /from:.*@.*\.gov\.gh/i,
    /from:.*@.*\.gov\.ke/i,
    /from:.*@.*\.gov\.et/i,
    /from:.*@.*\.gov\.tr/i,
    /from:.*@.*\.gov\.cn/i,
    /from:.*@.*\.gov\.jp/i,
    /from:.*@.*\.gov\.kr/i,
    /from:.*@.*\.go\.jp/i,         // Japan government
    /from:.*@.*\.go\.kr/i,         // Korea government
    /from:.*@.*\.go\.id/i,         // Indonesia government
    /from:.*@.*\.go\.ke/i,         // Kenya government
    /from:.*@.*\.gob\.mx/i,        // Mexico government
    /from:.*@.*\.gob\.ar/i,        // Argentina government
    /from:.*@.*\.gob\.es/i,        // Spain government
    /from:.*@.*\.gouv\.fr/i,       // France government
    /from:.*@.*\.bund\.de/i,       // Germany federal
    /from:.*@.*\.admin\.ch/i,      // Switzerland government
    /from:.*@.*\.belgium\.be/i,    // Belgium government
    /from:.*@.*\.nic\.in/i,        // India NIC

    // ===== MAJOR TECH COMPANIES =====
    /from:.*@microsoft\.com/i,
    /from:.*@google\.com/i,
    /from:.*@amazon\.com/i,
    /from:.*@apple\.com/i,
    /from:.*@meta\.com/i,
    /from:.*@facebook\.com/i,
    /from:.*@instagram\.com/i,
    /from:.*@whatsapp\.com/i,
    /from:.*@linkedin\.com/i,
    /from:.*@twitter\.com/i,
    /from:.*@x\.com/i,
    /from:.*@netflix\.com/i,
    /from:.*@adobe\.com/i,
    /from:.*@salesforce\.com/i,
    /from:.*@oracle\.com/i,
    /from:.*@ibm\.com/i,
    /from:.*@intel\.com/i,
    /from:.*@nvidia\.com/i,
    /from:.*@samsung\.com/i,
    /from:.*@sony\.com/i,
    /from:.*@cisco\.com/i,
    /from:.*@vmware\.com/i,
    /from:.*@sap\.com/i,
    /from:.*@zoom\.us/i,
    /from:.*@slack\.com/i,
    /from:.*@dropbox\.com/i,
    /from:.*@github\.com/i,
    /from:.*@gitlab\.com/i,
    /from:.*@atlassian\.com/i,
    /from:.*@shopify\.com/i,
    /from:.*@stripe\.com/i,
    /from:.*@twilio\.com/i,
    /from:.*@cloudflare\.com/i,
    /from:.*@akamai\.com/i,
    /from:.*@qualcomm\.com/i,
    /from:.*@amd\.com/i,
    /from:.*@hp\.com/i,
    /from:.*@dell\.com/i,
    /from:.*@lenovo\.com/i,
    /from:.*@asus\.com/i,
    /from:.*@lg\.com/i,
    /from:.*@huawei\.com/i,
    /from:.*@xiaomi\.com/i,
    /from:.*@oppo\.com/i,

    // ===== INDIAN IT / MAJOR COMPANIES =====
    /from:.*@infosys\.com/i,
    /from:.*@tcs\.com/i,
    /from:.*@wipro\.com/i,
    /from:.*@hcltech\.com/i,
    /from:.*@techmahindra\.com/i,
    /from:.*@ltimindtree\.com/i,
    /from:.*@mphasis\.com/i,
    /from:.*@hexaware\.com/i,
    /from:.*@cognizant\.com/i,
    /from:.*@capgemini\.com/i,
    /from:.*@accenture\.com/i,
    /from:.*@birlasoft\.com/i,
    /from:.*@kpit\.com/i,
    /from:.*@persistent\.com/i,
    /from:.*@zensar\.com/i,
    /from:.*@mindtree\.com/i,
    /from:.*@niit\.com/i,
    /from:.*@mastek\.com/i,
    /from:.*@rcom\.co\.in/i,
    /from:.*@tatamotors\.com/i,
    /from:.*@relianceretail\.com/i,
    /from:.*@jio\.com/i,
    /from:.*@airtel\.in/i,
    /from:.*@bsnl\.co\.in/i,

    // ===== BANKING & FINANCE =====
    /from:.*@sbi\.co\.in/i,
    /from:.*@hdfcbank\.com/i,
    /from:.*@icicibank\.com/i,
    /from:.*@axisbank\.com/i,
    /from:.*@kotak\.com/i,
    /from:.*@yesbank\.in/i,
    /from:.*@pnb\.co\.in/i,
    /from:.*@bankofbaroda\.co\.in/i,
    /from:.*@canarabank\.com/i,
    /from:.*@unionbankofindia\.co\.in/i,
    /from:.*@idfcfirstbank\.com/i,
    /from:.*@indusind\.com/i,
    /from:.*@rbi\.org\.in/i,
    /from:.*@sebi\.gov\.in/i,
    /from:.*@jpmorgan\.com/i,
    /from:.*@chase\.com/i,
    /from:.*@bankofamerica\.com/i,
    /from:.*@wellsfargo\.com/i,
    /from:.*@citibank\.com/i,
    /from:.*@hsbc\.com/i,
    /from:.*@barclays\.com/i,
    /from:.*@deutschebank\.com/i,
    /from:.*@ubs\.com/i,
    /from:.*@goldmansachs\.com/i,
    /from:.*@morganstanley\.com/i,
    /from:.*@standardchartered\.com/i,
    /from:.*@paypal\.com/i,
    /from:.*@razorpay\.com/i,
    /from:.*@paytm\.com/i,
    /from:.*@phonepe\.com/i,
    /from:.*@visa\.com/i,
    /from:.*@mastercard\.com/i,
    /from:.*@americanexpress\.com/i,

    // ===== EMAIL PROVIDERS =====
    /from:.*@gmail\.com/i,
    /from:.*@googlemail\.com/i,
    /from:.*@outlook\.com/i,
    /from:.*@hotmail\.com/i,
    /from:.*@live\.com/i,
    /from:.*@yahoo\.com/i,
    /from:.*@yahoo\.co\.in/i,
    /from:.*@yahoo\.co\.uk/i,
    /from:.*@protonmail\.com/i,
    /from:.*@proton\.me/i,
    /from:.*@icloud\.com/i,
    /from:.*@me\.com/i,
    /from:.*@zoho\.com/i,
    /from:.*@rediffmail\.com/i,

    // ===== HEALTHCARE =====
    /from:.*@who\.int/i,
    /from:.*@cdc\.gov/i,
    /from:.*@nih\.gov/i,
    /from:.*@icmr\.gov\.in/i,
    /from:.*@mohfw\.gov\.in/i,
    /from:.*@aiims\.edu/i,
    /from:.*@apollohospitals\.com/i,
    /from:.*@fortishealthcare\.com/i,
    /from:.*@manipalhospitals\.com/i,
    /from:.*@maxhealthcare\.in/i,

    // ===== INTERNATIONAL ORGANIZATIONS =====
    /from:.*@un\.org/i,
    /from:.*@unicef\.org/i,
    /from:.*@unesco\.org/i,
    /from:.*@worldbank\.org/i,
    /from:.*@imf\.org/i,
    /from:.*@wto\.org/i,
    /from:.*@nato\.int/i,
    /from:.*@europa\.eu/i,
    /from:.*@oecd\.org/i,
    /from:.*@icrc\.org/i,

    // ===== E-COMMERCE =====
    /from:.*@flipkart\.com/i,
    /from:.*@myntra\.com/i,
    /from:.*@meesho\.com/i,
    /from:.*@snapdeal\.com/i,
    /from:.*@nykaa\.com/i,
    /from:.*@ebay\.com/i,
    /from:.*@alibaba\.com/i,
    /from:.*@aliexpress\.com/i,
    /from:.*@walmart\.com/i,
    /from:.*@target\.com/i,

    // ===== CLOUD & DEVELOPER SERVICES =====
    /from:.*@aws\.amazon\.com/i,
    /from:.*@azure\.com/i,
    /from:.*@cloud\.google\.com/i,
    /from:.*@digitalocean\.com/i,
    /from:.*@heroku\.com/i,
    /from:.*@vercel\.com/i,
    /from:.*@netlify\.com/i,
    /from:.*@mongodb\.com/i,
    /from:.*@postgresql\.org/i,
    /from:.*@npmjs\.com/i,
    /from:.*@pypi\.org/i,
  ],

  medium: [
    // ===== GENERIC TLDS =====
    /from:.*@.*\.org\b/i,
    /from:.*@.*\.net\b/i,
    /from:.*@.*\.int\b/i,
    /from:.*@.*\.co\b/i,
    /from:.*@.*\.io\b/i,
    /from:.*@.*\.dev\b/i,
    /from:.*@.*\.app\b/i,
    /from:.*@.*\.tech\b/i,

    // ===== COUNTRY-SPECIFIC ACADEMIC =====
    /from:.*@.*\.ac\.[a-z]{2}\b/i,
    /from:.*@.*\.edu\.[a-z]{2}\b/i,
    /from:.*@.*\.sch\.[a-z]{2}\b/i,   // school domains
    /from:.*@.*\.uni\.[a-z]{2}\b/i,   // university domains

    // ===== COUNTRY-SPECIFIC BUSINESS =====
    /from:.*@.*\.co\.in\b/i,
    /from:.*@.*\.co\.uk\b/i,
    /from:.*@.*\.co\.jp\b/i,
    /from:.*@.*\.co\.nz\b/i,
    /from:.*@.*\.co\.za\b/i,
    /from:.*@.*\.co\.kr\b/i,
    /from:.*@.*\.com\.au\b/i,
    /from:.*@.*\.com\.br\b/i,
    /from:.*@.*\.com\.mx\b/i,
    /from:.*@.*\.com\.sg\b/i,
    /from:.*@.*\.com\.pk\b/i,
    /from:.*@.*\.com\.ng\b/i,
    /from:.*@.*\.com\.tr/i,

    // ===== MEDIA & NEWS =====
    /from:.*@bbc\.co\.uk/i,
    /from:.*@bbc\.com/i,
    /from:.*@reuters\.com/i,
    /from:.*@apnews\.com/i,
    /from:.*@thehindu\.com/i,
    /from:.*@hindustantimes\.com/i,
    /from:.*@timesofindia\.com/i,
    /from:.*@ndtv\.com/i,
    /from:.*@nytimes\.com/i,
    /from:.*@theguardian\.com/i,
    /from:.*@washingtonpost\.com/i,

    // ===== NONPROFITS & NGOs =====
    /from:.*@redcross\.org/i,
    /from:.*@msf\.org/i,
    /from:.*@savethechildren\.org/i,
    /from:.*@oxfam\.org/i,
    /from:.*@amnesty\.org/i,
    /from:.*@helpage\.org/i,
    /from:.*@giveindia\.org/i,
  ]
};

function getSenderTrust(text) {
  for (const pattern of TRUSTED_PATTERNS.high) {
    if (pattern.test(text)) {
      return { level: 'high', label: 'Trusted sender', reduction: 30 };
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
