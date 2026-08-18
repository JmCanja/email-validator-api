const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const dns = require('dns');
const https = require('https');
const net = require('net');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
const path = require('path');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// ─── Serve web UI ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

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


// ─── Free email providers ─────────────────────────────────────────────────────
const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com','yahoo.com','yahoo.co.uk','yahoo.co.in','yahoo.com.au','yahoo.ca',
  'hotmail.com','hotmail.co.uk','hotmail.fr','hotmail.de','hotmail.es','hotmail.it',
  'outlook.com','outlook.co.uk','outlook.fr','outlook.de','outlook.es','outlook.com.au',
  'live.com','live.co.uk','live.fr','live.de','live.com.au','live.ca',
  'msn.com','icloud.com','me.com','mac.com','aol.com','aol.co.uk',
  'protonmail.com','protonmail.ch','proton.me',
  'zoho.com','zohomail.com',
  'yandex.com','yandex.ru','yandex.ua','yandex.by','yandex.kz',
  'mail.com','email.com','gmx.com','gmx.net','gmx.de','gmx.at','gmx.ch',
  'web.de','freenet.de','t-online.de',
  'qq.com','163.com','126.com','sina.com','sina.cn','sohu.com',
  'rediffmail.com','in.com','sify.com',
  'rocketmail.com','ymail.com','rogers.com','shaw.ca','telus.net',
  'bigpond.com','bigpond.net.au','optusnet.com.au','internode.on.net',
  'ntlworld.com','btinternet.com','virgin.net','virginmedia.com','sky.com',
  'orange.fr','wanadoo.fr','free.fr','sfr.fr','laposte.net','bbox.fr',
  'libero.it','virgilio.it','tiscali.it','alice.it',
  'terra.com.br','uol.com.br','bol.com.br','ig.com.br','globo.com','r7.com',
  'seznam.cz','atlas.cz','centrum.cz',
  'wp.pl','onet.pl','interia.pl','o2.pl',
  'rambler.ru','inbox.ru','list.ru','bk.ru','mail.ru',
  'tutanota.com','tutanota.de','tutamail.com','tuta.io',
  'fastmail.com','fastmail.fm','fastmail.net','hushmail.com',
  'lavabit.com','safe-mail.net','runbox.com',
]);

// ─── Expanded toxic/abusive domains ──────────────────────────────────────────
const TOXIC_DOMAINS = new Set([
  // Known spam/abuse domains
  'spam.la','spamgourmet.com','spamgourmet.net','spamgourmet.org',
  'spamherelots.com','spamhereplease.com','spamthisplease.com',
  'spamoff.de','spamcannon.com','spamcannon.net',
  'spaml.com','spaml.de','spamspot.com','spamstack.net',
  'spamtrail.com','spamtroll.net','spamt.net',
  // Toxic/abusive
  'anonbox.net','anonymbox.com','anonymail.dk','anonymize.com',
  'antichef.com','antichef.net','antireg.com','antispam.de',
  'antispammail.de','armyspy.com','binkmail.com','bobmail.info',
  'chammy.info','cheatmail.de','chewiemail.com','childsafemail.com',
  'clrmail.com','cmail.net','cool.fr.nf','courriel.fr.nf',
  'courrieltemporaire.com','crapmail.org','cust.in','dacoolest.com',
  'dandikmail.com','dayrep.com','dcemail.com','deadaddress.com',
  'deadletter.ga','delikkt.de','despam.it','devnullmail.com',
  'digitalsanctuary.com','dingbone.com','disposablemail.us',
  'dispostable.com','dm.w3internet.co.uk','dodgeit.com','dodgmail.de',
  'dodsi.com','domforfb1.tk','domforfb18.tk','domforfb19.tk',
  'domforfb2.tk','domforfb23.tk','domforfb27.tk','domforfb29.tk',
  'domforfb3.tk','domforfb4.tk','domforfb5.tk','domforfb6.tk',
  'domforfb7.tk','domforfb8.tk','dontreg.com','dontsendmespam.de',
  'drdrb.com','drdrb.net','dump-email.info','dumpandfuck.com',
  'dumpmail.de','dumpyemail.com','e4ward.com','easytrashmail.com',
  'einrot.com','einrot.de','emailage.cf','emailage.ga','emailage.gq',
  'emailage.ml','emailage.tk','emaildienst.de','emailgo.de',
  'emailias.com','emailinfive.com','emailisvalid.com','emailmiser.com',
  'emailproxsy.com','emailsensei.com','emailtemporanea.com',
  'emailtemporanea.net','emailtemporar.ro','emailto.de','emailwarden.com',
  'emailx.at.hm','emailxfer.com','emailz.cf','emailz.ga','emailz.gq',
  'emailz.ml','emeil.in','emeil.ir','emz.net','enterto.com',
  'ephemail.net','etranquil.com','etranquil.net','etranquil.org',
  'evopo.com','explodemail.com','express.net.ua','eyepaste.com',
  'fakeinformation.com','fansworldwide.de','fantasymail.de',
  'fightallspam.com','filzmail.com','fivemail.de','fixmail.tk',
  'fizmail.com','fleckens.hu','frapmail.com','freemail.ms',
  'fuckingdumbass.com','fudgerub.com','fux0ringduh.com',
  'garbagecollector.org','garbagemail.org','get-mail.cf',
  'get-mail.ga','get-mail.ml','get-mail.tk','get1mail.com',
  'getairmail.com','getairmail.cf','getairmail.ga','getairmail.gq',
  'getairmail.ml','getairmail.tk','getmails.eu','getonemail.com',
  'getonemail.net','gishpuppy.com','goemailgo.com','gotmail.net',
  'gotmail.org','gowikibooks.com','gowikicampus.com','gowikicars.com',
  'gowikifilms.com','gowikigames.com','gowikimusic.com',
  'gowikinetwork.com','gowikitravel.com','gowikitv.com','grandmamail.com',
  'grandmasmail.com','great-host.in','greensloth.com','gsrv.co.uk',
  'gustr.com','h8s.org','haltospam.com','harakirimail.com',
  'hartbot.de','hat-geld.de','hatespam.org','herp.in',
  'hidemail.de','hidzz.com','hmamail.com','hopemail.biz',
  'hulapla.de','ieatspam.eu','ieatspam.info','ieh-mail.de',
  'ihateyoualot.info','iheartspam.org','imails.info','inbax.tk',
  'inbox.si','inboxalias.com','inboxclean.com','inboxclean.org',
  'inboxdesign.me','inboxed.pw','inboxstore.me','incognitomail.com',
  'incognitomail.net','incognitomail.org','insorg.org','instant-mail.de',
  'ip6.li','ipoo.org','irish2me.com','iwi.net',
  'jetable.com','jetable.fr.nf','jetable.net','jetable.org',
  'jnxjn.com','jourrapide.com','jsrsolutions.com','junk.to',
  'jupimail.com','kasmail.com','kaspop.com','killmail.com',
  'killmail.net','klassmaster.com','klzlk.com','koszmail.pl',
  'kulturbetrieb.info','kurzepost.de','letthemeatspam.com',
  'lhsdv.com','lifebyfood.com','link2mail.net','litedrop.com',
  'lol.ovpn.to','lolfreak.net','lookugly.com','lortemail.dk',
  'losemymail.com','lovemeleaveme.com','lr78.com','lroid.com',
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

  // Free email provider check
  if (FREE_EMAIL_PROVIDERS.has(domain.toLowerCase())) {
    flags.push({ type: 'free_provider', message: `Free email provider (${domain}) — not a business address` });
  }

  // Toxic domain check
  if (TOXIC_DOMAINS.has(domain.toLowerCase())) {
    flags.push({ type: 'toxic', message: `Toxic/abusive domain detected — high spam risk` });
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



// ─── Mailboxlayer config ──────────────────────────────────────────────────────
const MAILBOXLAYER_KEY = process.env.MAILBOXLAYER_KEY || '206c6b33b2e7c3fa4d588640922866b8';

function mailboxlayerCheck(email) {
  return new Promise((resolve) => {
    const urlObj = new URL(`https://apilayer.net/api/check`);
    urlObj.searchParams.set('access_key', MAILBOXLAYER_KEY);
    urlObj.searchParams.set('email', email);
    urlObj.searchParams.set('smtp', '1');
    urlObj.searchParams.set('format', '1');

    const options = {
      hostname: 'apilayer.net',
      path: `/api/check?access_key=${MAILBOXLAYER_KEY}&email=${encodeURIComponent(email)}&smtp=1&format=1`,
      method: 'GET',
      timeout: 15000,
      headers: { 'User-Agent': 'EmailValidator/1.3.0' }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const result = JSON.parse(data);
          if (result.error) {
            resolve({ success: false, error: result.error.info || 'Mailboxlayer error' });
            return;
          }
          resolve({
            success: true,
            deliverable: result.smtp_check === true,
            disposable: result.disposable,
            free:        result.free,
            formatValid: result.format_valid,
            mxFound:     result.mx_found,
            score:       result.score,
            did_you_mean: result.did_you_mean || null,
          });
        } catch (e) {
          resolve({ success: false, error: 'Failed to parse Mailboxlayer response: ' + e.message });
        }
      });
    });

    req.on('error', (e) => {
      resolve({ success: false, error: 'Mailboxlayer request error: ' + e.message });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false, error: 'Mailboxlayer request timed out' });
    });

    req.end();
  });
}

// ─── Catch-all detection ──────────────────────────────────────────────────────
const catchAllCache = new Map(); // cache per domain to avoid double probing

function randomString(len = 12) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

async function isCatchAll(mxHost, domain) {
  if (catchAllCache.has(domain)) return catchAllCache.get(domain);

  const fakeEmail = `${randomString()}@${domain}`;
  const probe = await smtpProbe(mxHost, fakeEmail);

  // If the server accepts a random fake address, it is catch-all
  const result = probe.deliverable === true;
  catchAllCache.set(domain, result);

  // Expire cache after 10 minutes
  setTimeout(() => catchAllCache.delete(domain), 10 * 60 * 1000);

  return result;
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
      catch_all:  { detected: false, detail: null, skipped: false },
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

    // 4b. Catch-all detection (only if SMTP said deliverable or inconclusive)
    if (smtp.deliverable !== false) {
      try {
        const catchAll = await isCatchAll(primaryMX, domain);
        result.checks.catch_all.detected = catchAll;
        result.checks.catch_all.detail = catchAll
          ? 'Catch-all domain — server accepts all addresses, mailbox existence unverifiable'
          : 'Not catch-all — server rejects unknown addresses';
        if (catchAll) {
          result.flags.push({ type: 'catch_all', message: 'Catch-all domain detected — may cause bounces in any ESP' });
        }
      } catch (e) {
        result.checks.catch_all.skipped = true;
        result.checks.catch_all.detail = 'Catch-all probe failed: ' + e.message;
      }
    } else {
      result.checks.catch_all.skipped = true;
      result.checks.catch_all.detail = 'Skipped — mailbox already rejected';
    }
  }

  // 5. Score & status
  let score = 0;
  if (result.checks.format.pass)            score += 30;
  if (result.checks.mx.pass)                score += 35;
  if (result.checks.smtp.pass === true)     score += 35;
  else if (result.checks.smtp.pass === null) score += 15;
  else if (result.checks.smtp.skipped)      score += 15;

  const disposable    = result.flags.find(f => f.type === 'disposable');
  const typo          = result.flags.find(f => f.type === 'typo');
  const catchAll      = result.flags.find(f => f.type === 'catch_all');
  const freeProvider  = result.flags.find(f => f.type === 'free_provider');
  const toxic         = result.flags.find(f => f.type === 'toxic');
  if (disposable)   score = Math.max(0, score - 20);
  if (typo)         score = Math.max(0, score - 10);
  if (catchAll)     score = Math.max(0, score - 20);
  if (toxic)        score = Math.max(0, score - 30);
  // free_provider doesn't reduce score — it's informational only

  result.score = score;

  // GHL safe-to-send verdict
  result.safe_to_send = false;

  // Toxic domain = always invalid regardless of SMTP
  if (toxic) {
    result.status = 'invalid';
    result.reason = 'Toxic/abusive domain — do not send';
    result.safe_to_send = false;
    result.duration_ms = Date.now() - start;
    return result;
  }

  if (result.checks.smtp.pass === false) {
    result.status = 'invalid';
    result.reason = result.checks.smtp.detail;
    result.safe_to_send = false;
  } else if (result.checks.smtp.pass === true) {
    if (catchAll) {
      result.status = 'risky';
      result.reason = 'Catch-all domain — cannot confirm mailbox exists, risk of bounce in any ESP';
      result.safe_to_send = false;
    } else if (disposable) {
      result.status = 'risky';
      result.reason = 'Deliverable but from a disposable provider';
      result.safe_to_send = false;
    } else {
      result.status = 'valid';
      result.reason = 'Mailbox verified — safe to send';
      result.safe_to_send = true;
    }
  } else {
    // SMTP inconclusive
    if (catchAll) {
      result.status = 'risky';
      result.reason = 'Catch-all domain — may cause bounces in any ESP';
      result.safe_to_send = false;
    } else if (disposable) {
      result.status = 'risky';
      result.reason = 'Disposable email provider';
      result.safe_to_send = false;
    } else if (typo) {
      result.status = 'risky';
      result.reason = typo.message;
      result.safe_to_send = false;
    } else {
      result.status = 'unknown';
      result.reason = result.checks.smtp.skipped
        ? 'Syntax and MX valid — SMTP not checked'
        : result.checks.smtp.detail;
      result.safe_to_send = false;
    }
  }

  result.duration_ms = Date.now() - start;
  return result;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '1.3.1', timestamp: new Date().toISOString() });
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
