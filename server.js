const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const dns = require('dns');
const net = require('net');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Too many requests. Limit: 60/min.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const bulkLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many bulk requests. Limit: 10/min.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// ─── Static data ──────────────────────────────────────────────────────────────
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com','guerrillamail.com','tempmail.com','throwaway.email',
  'yopmail.com','sharklasers.com','guerrillamailblock.com','grr.la',
  'guerrillamail.info','spam4.me','trashmail.com','trashmail.me',
  'trashmail.net','10minutemail.com','temp-mail.org','fakeinbox.com',
  'maildrop.cc','dispostable.com','spamgourmet.com','mytemp.email',
  'discard.email','mailnull.com','getairmail.com','mailexpire.com',
  'spamevader.com','jetable.org','wegwerfmail.de','mailnesia.com',
  'spamgob.com','binkmail.com','bobmail.info','dayrep.com',
  'discard.email','einrot.com','filzmail.com','fleckens.hu',
  'hmamail.com','jourrapide.com','objectmail.com','obobbo.com',
  'proxymail.eu','rcpt.at','rppkn.com','safetymail.info',
  'supergreatmail.com','suremail.info','tafmail.com','veryrealemail.com',
  'yogamaven.com','zippymail.in','spamcorptastic.com','spambog.com',
  'spambog.de','spambog.ru','spambog.com.ua','garbagemail.org',
]);

const ROLE_PREFIXES = new Set([
  'admin','info','support','contact','sales','marketing','noreply',
  'no-reply','postmaster','webmaster','abuse','root','help','hello',
  'team','hr','careers','jobs','billing','security','privacy',
  'legal','press','media','newsletter','notifications','alerts',
  'donotreply','do-not-reply','feedback','enquiries','enquiry',
  'accounts','finance','service','services','office',
]);

const COMMON_TYPOS = {
  'gamil.com':'gmail.com','gmaill.com':'gmail.com','gmial.com':'gmail.com',
  'yahooo.com':'yahoo.com','yaho.com':'yahoo.com','hotmial.com':'hotmail.com',
  'hotmale.com':'hotmail.com','outlok.com':'outlook.com','outloook.com':'outlook.com',
  'aol.con':'aol.com','gnail.com':'gmail.com','gmali.com':'gmail.com',
  'gmal.com':'gmail.com','gmailcom':'gmail.com','yahoocom':'yahoo.com',
  'hotmailcom':'hotmail.com',
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function validateFormat(email) {
  const errors = [];
  const warnings = [];

  // RFC 5322 simplified but practical regex
  const basicRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  if (!basicRx.test(email)) {
    errors.push('Malformed email address');
    return { valid: false, errors, warnings };
  }

  const atCount = (email.match(/@/g) || []).length;
  if (atCount !== 1) {
    errors.push('Must contain exactly one @ symbol');
    return { valid: false, errors, warnings };
  }

  const [local, domain] = email.split('@');

  if (local.length === 0) errors.push('Local part is empty');
  if (local.length > 64) errors.push('Local part exceeds 64 characters');
  if (domain.length > 255) errors.push('Domain exceeds 255 characters');
  if (email.length > 320) errors.push('Email exceeds 320 characters');

  if (/\.\./.test(email)) errors.push('Consecutive dots are not allowed');
  if (local.startsWith('.') || local.endsWith('.')) errors.push('Local part cannot start or end with a dot');

  const localRx = /^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+$/;
  if (!localRx.test(local)) errors.push('Invalid characters in local part');

  const domainRx = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/;
  if (!domainRx.test(domain)) errors.push('Invalid domain format');

  const tld = domain.split('.').pop();
  if (tld.length < 2) errors.push('TLD too short');
  if (!/^[a-zA-Z]+$/.test(tld)) errors.push('TLD must contain only letters');

  return { valid: errors.length === 0, errors, warnings };
}

function checkHeuristics(email) {
  const flags = [];
  const [local, domain] = email.split('@');

  if (DISPOSABLE_DOMAINS.has(domain.toLowerCase())) {
    flags.push({ type: 'disposable', message: 'Disposable/temporary email provider' });
  }

  if (ROLE_PREFIXES.has(local.toLowerCase())) {
    flags.push({ type: 'role', message: `Role-based address (${local})` });
  }

  const typo = COMMON_TYPOS[domain.toLowerCase()];
  if (typo) {
    flags.push({ type: 'typo', message: `Possible domain typo: "${domain}" → did you mean "${typo}"?` });
  }

  return flags;
}

function resolveMX(domain) {
  return new Promise((resolve) => {
    dns.promises.resolveMx(domain)
      .then(records => {
        if (!records || records.length === 0) {
          resolve({ hasMX: false, records: [], error: 'No MX records found' });
        } else {
          const sorted = records.sort((a, b) => a.priority - b.priority);
          resolve({ hasMX: true, records: sorted, error: null });
        }
      })
      .catch(err => {
        const msg = err.code === 'ENOTFOUND' ? 'Domain does not exist'
                  : err.code === 'ENODATA'   ? 'No MX records found'
                  : err.code === 'ETIMEOUT'  ? 'DNS lookup timed out'
                  : `DNS error: ${err.code}`;
        resolve({ hasMX: false, records: [], error: msg });
      });
  });
}

function smtpProbe(mxHost, email) {
  return new Promise((resolve) => {
    const TIMEOUT = 8000;
    let socket;
    let stage = 'connect';
    let log = [];
    let resolved = false;

    const done = (result) => {
      if (resolved) return;
      resolved = true;
      if (socket) { try { socket.destroy(); } catch (_) {} }
      resolve({ ...result, log });
    };

    const timer = setTimeout(() => {
      done({ deliverable: null, error: `SMTP timeout at stage: ${stage}` });
    }, TIMEOUT);

    try {
      socket = net.createConnection({ host: mxHost, port: 25, timeout: TIMEOUT });
    } catch (e) {
      clearTimeout(timer);
      return done({ deliverable: null, error: 'Cannot create socket: ' + e.message });
    }

    socket.setEncoding('utf8');

    let buffer = '';

    const send = (cmd) => {
      log.push(`> ${cmd}`);
      socket.write(cmd + '\r\n');
    };

    socket.on('error', (err) => {
      clearTimeout(timer);
      const msg = err.code === 'ECONNREFUSED' ? 'SMTP port 25 refused (server may block outbound SMTP)'
                : err.code === 'ETIMEDOUT'    ? 'Connection timed out'
                : err.message;
      done({ deliverable: null, error: msg });
    });

    socket.on('data', (data) => {
      buffer += data;
      const lines = buffer.split('\r\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line) continue;
        log.push(`< ${line}`);
        const code = parseInt(line.slice(0, 3), 10);

        if (stage === 'connect' && code === 220) {
          stage = 'ehlo';
          send(`EHLO email-validator.local`);
        } else if (stage === 'ehlo' && (code === 250 || code === 220)) {
          if (!line.startsWith('250-') && (code === 250 || code === 220)) {
            stage = 'mailfrom';
            send(`MAIL FROM:<verify@email-validator.local>`);
          }
        } else if (stage === 'mailfrom' && code === 250) {
          stage = 'rcptto';
          send(`RCPT TO:<${email}>`);
        } else if (stage === 'rcptto') {
          clearTimeout(timer);
          stage = 'quit';
          send('QUIT');
          if (code === 250 || code === 251) {
            done({ deliverable: true, error: null, smtpCode: code });
          } else if (code === 550 || code === 551 || code === 553 || code === 554) {
            done({ deliverable: false, error: `Mailbox rejected (${code})`, smtpCode: code });
          } else if (code === 450 || code === 451 || code === 452) {
            done({ deliverable: null, error: `Temporary rejection (${code}) — try again later`, smtpCode: code });
          } else if (code === 421) {
            done({ deliverable: null, error: `Server unavailable (${code})`, smtpCode: code });
          } else {
            done({ deliverable: null, error: `Unexpected SMTP response: ${code}`, smtpCode: code });
          }
        } else if (stage === 'quit') {
          clearTimeout(timer);
          done({ deliverable: null, error: 'SMTP conversation ended early' });
        }
      }
    });

    socket.on('close', () => {
      clearTimeout(timer);
      if (!resolved) done({ deliverable: null, error: 'Connection closed unexpectedly' });
    });
  });
}

// ─── Core validator ───────────────────────────────────────────────────────────
async function fullValidate(email, options = {}) {
  const start = Date.now();
  email = email.trim().toLowerCase();

  const result = {
    email,
    checks: {
      format:     { pass: false, detail: null },
      mx:         { pass: false, detail: null, records: [] },
      smtp:       { pass: null,  detail: null, skipped: false },
    },
    flags:        [],
    score:        0,      // 0-100
    status:       'unknown',  // valid | invalid | risky | unknown
    deliverable:  null,
    reason:       '',
    duration_ms:  0,
  };

  // 1. Format check
  const fmt = validateFormat(email);
  result.checks.format.pass = fmt.valid;
  result.checks.format.detail = fmt.valid ? 'Passed all syntax checks' : fmt.errors.join('; ');

  if (!fmt.valid) {
    result.status = 'invalid';
    result.reason = fmt.errors[0];
    result.duration_ms = Date.now() - start;
    return result;
  }

  // 2. Heuristic flags
  result.flags = checkHeuristics(email);

  // 3. MX check
  const [, domain] = email.split('@');
  const mx = await resolveMX(domain);
  result.checks.mx.pass = mx.hasMX;
  result.checks.mx.detail = mx.hasMX
    ? `${mx.records.length} MX record(s) found`
    : mx.error;
  result.checks.mx.records = mx.records.map(r => ({ exchange: r.exchange, priority: r.priority }));

  if (!mx.hasMX) {
    result.status = 'invalid';
    result.reason = mx.error || 'No mail server found for this domain';
    result.duration_ms = Date.now() - start;
    return result;
  }

  // 4. SMTP check (optional — skip if smtpCheck=false)
  if (options.smtpCheck === false) {
    result.checks.smtp.skipped = true;
    result.checks.smtp.detail = 'SMTP check skipped';
  } else {
    const primaryMX = mx.records[0].exchange;
    const smtp = await smtpProbe(primaryMX, email);
    result.checks.smtp.pass = smtp.deliverable;
    result.checks.smtp.detail = smtp.deliverable === true
      ? `Mailbox accepted by ${primaryMX}`
      : smtp.deliverable === false
      ? smtp.error
      : `Inconclusive: ${smtp.error}`;
    result.checks.smtp.smtpCode = smtp.smtpCode;
    result.checks.smtp.log = options.debug ? smtp.log : undefined;
    result.deliverable = smtp.deliverable;
  }

  // 5. Score & status
  let score = 0;
  if (result.checks.format.pass)            score += 30;
  if (result.checks.mx.pass)                score += 35;
  if (result.checks.smtp.pass === true)     score += 35;
  else if (result.checks.smtp.pass === null) score += 15;
  else if (result.checks.smtp.skipped)      score += 15;

  const disposable = result.flags.find(f => f.type === 'disposable');
  const typo = result.flags.find(f => f.type === 'typo');
  if (disposable) score = Math.max(0, score - 20);
  if (typo)       score = Math.max(0, score - 10);

  result.score = score;

  if (result.checks.smtp.pass === false) {
    result.status = 'invalid';
    result.reason = result.checks.smtp.detail;
  } else if (result.checks.smtp.pass === true) {
    result.status = disposable ? 'risky' : 'valid';
    result.reason = disposable
      ? 'Deliverable but from a disposable provider'
      : 'Mailbox verified and accepting mail';
  } else {
    // SMTP inconclusive
    if (disposable) {
      result.status = 'risky';
      result.reason = 'Disposable email provider';
    } else if (typo) {
      result.status = 'risky';
      result.reason = typo.message;
    } else {
      result.status = 'unknown';
      result.reason = result.checks.smtp.skipped
        ? 'Syntax and MX valid — SMTP not checked'
        : result.checks.smtp.detail;
    }
  }

  result.duration_ms = Date.now() - start;
  return result;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0', timestamp: new Date().toISOString() });
});

// Single email
app.post('/api/validate', async (req, res) => {
  const { email, smtp_check = true, debug = false } = req.body;
  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid "email" field' });
  }
  if (email.length > 320) {
    return res.status(400).json({ error: 'Email too long' });
  }
  try {
    const result = await fullValidate(email, { smtpCheck: smtp_check, debug });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Internal error', detail: err.message });
  }
});

// GET convenience
app.get('/api/validate', async (req, res) => {
  const { email, smtp_check, debug } = req.query;
  if (!email) return res.status(400).json({ error: 'Missing "email" query parameter' });
  try {
    const result = await fullValidate(email, {
      smtpCheck: smtp_check !== 'false',
      debug: debug === 'true',
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Internal error', detail: err.message });
  }
});

// Bulk
app.post('/api/validate/bulk', bulkLimiter, async (req, res) => {
  const { emails, smtp_check = true, debug = false } = req.body;

  if (!Array.isArray(emails)) {
    return res.status(400).json({ error: '"emails" must be an array' });
  }
  if (emails.length === 0) {
    return res.status(400).json({ error: 'Empty emails array' });
  }
  if (emails.length > 100) {
    return res.status(400).json({ error: 'Maximum 100 emails per bulk request' });
  }

  const invalid = emails.filter(e => typeof e !== 'string' || e.length > 320);
  if (invalid.length > 0) {
    return res.status(400).json({ error: 'All emails must be strings under 320 chars' });
  }

  try {
    // Run with concurrency cap (5 at a time) to avoid hammering DNS/SMTP
    const CONCURRENCY = 5;
    const results = [];
    for (let i = 0; i < emails.length; i += CONCURRENCY) {
      const batch = emails.slice(i, i + CONCURRENCY);
      const batchResults = await Promise.all(
        batch.map(email => fullValidate(email, { smtpCheck: smtp_check, debug }))
      );
      results.push(...batchResults);
    }

    const summary = {
      total: results.length,
      valid:   results.filter(r => r.status === 'valid').length,
      invalid: results.filter(r => r.status === 'invalid').length,
      risky:   results.filter(r => r.status === 'risky').length,
      unknown: results.filter(r => r.status === 'unknown').length,
    };

    res.json({ summary, results });
  } catch (err) {
    res.status(500).json({ error: 'Internal error', detail: err.message });
  }
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅  Email Validator API running on http://localhost:${PORT}`);
  console.log(`   POST /api/validate         — single email`);
  console.log(`   GET  /api/validate?email=  — single email (GET)`);
  console.log(`   POST /api/validate/bulk    — up to 100 emails`);
  console.log(`   GET  /health               — health check\n`);
});

module.exports = app;
