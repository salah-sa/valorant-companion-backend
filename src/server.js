// â”€â”€ ValorantCompanion â€” Production Backend Server â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Node.js + Express | MongoDB | Full license/order/update system

'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '../config/.env') });

const express    = require('express');
const mongoose   = require('mongoose');
const helmet     = require('helmet');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const crypto     = require('crypto');
const cron       = require('node-cron');
const bcrypt     = require('bcryptjs');  // FIX: import once at top, not inline per-request

const { LicenseKey, Activation, Order, SecurityLog, AppVersion } = require('./models');

const app  = express();
const PORT = process.env.PORT || 3000;

// â”€â”€ Security middleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use(helmet());
app.use(cors({ origin: false }));          // API-only, no browser CORS needed
app.use(express.json({ limit: '16kb' }));  // prevent payload bombs
app.set('trust proxy', 1);

// ── Version Gate Middleware ─────────────────────────────────────────────────
// Blocks all protected API calls from outdated clients.
// Old clients that don't send X-App-Version or send a version < MINIMUM_VERSION
// receive 426 Upgrade Required, which the client maps to the forced-update dialog.
// Exempt routes: /check-update, /ping, /health, /pricing, /admin/*
const MINIMUM_VERSION = '1.1.7';

const VERSION_EXEMPT = ['/check-update', '/health', '/pricing'];

app.use((req, res, next) => {
  // Skip exempt routes and all admin routes
  if (VERSION_EXEMPT.includes(req.path) || req.path.startsWith('/admin')) return next();

  const clientVersion = (req.headers['x-app-version'] || req.body?.app_version || '0.0.0')
    .toString().replace(/[^0-9.]/g, '');

  if (compareVersions(clientVersion, MINIMUM_VERSION) < 0) {
    return res.status(426).json({
      error:           'update_required',
      update_required: true,
      minimum_version: MINIMUM_VERSION,
      latest_version:  MINIMUM_VERSION,
      download_url:    'https://sasa120120.itch.io/valorant-companion-app/download/eyJpZCI6NDQxODI5NCwiZXhwaXJlcyI6MTc3NDQ4NjQ1MH0%3d%2ev0Oyz%2f8pnRmQ9vOGL3uSnjoTCbU%3d',
      message:         'Your version is outdated. Please download the latest version (v' + MINIMUM_VERSION + ') to continue.',
    });
  }
  next();
});
// ───────────────────────────────────────────────────────────────────────────


// â”€â”€ Global rate limiter (all routes) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const globalLimiter = rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down.' },
});
app.use(globalLimiter);

// â”€â”€ Strict limiter for key validation (5 attempts per 30 sec per IP) â”€â”€â”€â”€â”€â”€â”€â”€â”€
const validateLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 30_000,
  max:      parseInt(process.env.RATE_LIMIT_MAX)       || 5,
  keyGenerator: (req) => req.ip + ':' + (req.body?.hwid || ''),
  message: { error: 'Too many validation attempts. Wait 30 seconds.', code: 'RATE_LIMITED' },
  handler: async (req, res, next, options) => {
    await logSecurity('security', `Rate limit hit on /validate-key`, req.ip, req.body?.key?.slice(0,8), req.body?.hwid);
    res.status(429).json(options.message);
  }
});

// â”€â”€ MongoDB connect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
mongoose.connect(process.env.MONGODB_URI, {
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 30000,
})
.then(() => console.log('[DB] MongoDB connected'))
.catch(err => { console.error('[DB] Connection failed:', err.message); process.exit(1); });

// â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function getIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '';
}

function normalizeKey(raw) {
  return (raw || '').trim().toUpperCase();
}

function keyPrefix(raw) {
  return normalizeKey(raw).slice(0, 8);
}

function compareVersions(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i]||0) > (pb[i]||0)) return 1;
    if ((pa[i]||0) < (pb[i]||0)) return -1;
  }
  return 0;
}

async function logSecurity(type, message, ip = '', keyPfx = '', hwid = '', meta = {}) {
  try {
    await SecurityLog.create({ type, message, ip, key_prefix: keyPfx, hwid, metadata: meta });
  } catch (e) { console.error('[LOG]', e.message); }
}

function requireAdminKey(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.admin_key;

  // FIX: removed debug log that leaked the attempted key value to console
  if (!key || key !== process.env.ADMIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  next();
}

// â”€â”€ Telegram notification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function notifyTelegram(text) {
  const token  = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return false;
  try {
    const axios = require('axios');
    await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
      chat_id:    chatId,
      text:       text,
      parse_mode: 'HTML',
    }, { timeout: 8000 });
    return true;
  } catch (e) {
    console.error('[Telegram]', e.message);
    return false;
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// ROUTE: POST /validate-key
// Client calls this on every launch and periodically (heartbeat)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
app.post('/validate-key', validateLimiter, async (req, res) => {
  const { key: rawKey, hwid, app_version = '', is_heartbeat = false } = req.body;
  const ip = getIp(req);

  // â”€â”€ Input validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (!rawKey || typeof rawKey !== 'string' || rawKey.length < 8 || rawKey.length > 64) {
    return res.status(400).json({ valid: false, code: 'INVALID_INPUT', message: 'Invalid key format.' });
  }
  if (!hwid || typeof hwid !== 'string' || hwid.length < 8 || hwid.length > 64) {
    return res.status(400).json({ valid: false, code: 'INVALID_INPUT', message: 'Invalid HWID.' });
  }

  // ── Version gate inside validate-key (catches ALL clients including old ones) ──
  // Old clients send app_version in body; new ones also send X-App-Version header.
  const clientVer = (req.headers['x-app-version'] || app_version || '0.0.0')
    .toString().replace(/[^0-9.]/g, '');
  if (compareVersions(clientVer, MINIMUM_VERSION) < 0) {
    const latest = await AppVersion.findOne({ is_active: true }).sort({ released_at: -1 }).lean();
    return res.status(426).json({
      valid:           false,
      code:            'UPDATE_REQUIRED',
      update_required: true,
      minimum_version: MINIMUM_VERSION,
      latest_version:  latest?.version || MINIMUM_VERSION,
      download_url:    MANDATORY_DOWNLOAD_URL,
      message:         'Your version (v' + (clientVer || '?') + ') is outdated. Download v' + (latest?.version || MINIMUM_VERSION) + ' to continue.',
    });
  }
  // ─────────────────────────────────────────────────────────────────────────────

  // Sanitize
  const normalKey = normalizeKey(rawKey);
  const pfx       = keyPrefix(normalKey);
  const safeHwid  = hwid.trim().toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 32);

  try {
    // â”€â”€ Find candidates by prefix (avoids full-table bcrypt scan) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const candidates = await LicenseKey.find({ key_prefix: pfx }).lean();

    let matchedDoc = null;
    for (const doc of candidates) {
      const ok = await bcrypt.compare(normalKey, doc.key_hash);  // FIX: use top-level import
      if (ok) { matchedDoc = doc; break; }
    }

    // â”€â”€ Not found â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (!matchedDoc) {
      await logSecurity('security', `Invalid key attempt`, ip, pfx, safeHwid);
      return res.json({ valid: false, code: 'INVALID_KEY', message: 'Key not recognised.' });
    }

    // â”€â”€ Banned â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (matchedDoc.is_banned) {
      await logSecurity('security', `Banned key attempt`, ip, pfx, safeHwid);
      return res.json({ valid: false, code: 'BANNED', message: 'This key has been banned.' });
    }

    // â”€â”€ Inactive / revoked â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (!matchedDoc.is_active) {
      return res.json({ valid: false, code: 'REVOKED', message: 'This key has been revoked.' });
    }

    // â”€â”€ Expiry check using SERVER TIME (prevents clock rollback) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const now = new Date();
    if (matchedDoc.expires_at && matchedDoc.expires_at < now) {
      await logSecurity('info', `Expired key attempt`, ip, pfx, safeHwid);
      return res.json({ valid: false, code: 'EXPIRED', message: 'This key has expired.', expires_at: matchedDoc.expires_at });
    }

    // â”€â”€ HWID binding â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (!matchedDoc.hwid) {
      // First activation â€” bind
      await LicenseKey.updateOne({ _id: matchedDoc._id }, { $set: { hwid: safeHwid } });
      matchedDoc.hwid = safeHwid;
      await logSecurity('info', `Key bound to HWID ${safeHwid}`, ip, pfx, safeHwid);
    } else if (matchedDoc.hwid !== safeHwid) {
      await logSecurity('security', `HWID mismatch. Expected=${matchedDoc.hwid} Got=${safeHwid}`, ip, pfx, safeHwid);
      return res.json({
        valid:   false,
        code:    'HWID_MISMATCH',
        message: 'This key is locked to a different device. Contact support to transfer.',
        your_hwid: safeHwid,
      });
    }

    // â”€â”€ Update last_used_at â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    await LicenseKey.updateOne({ _id: matchedDoc._id }, { $set: { last_used_at: now } });

    // â”€â”€ Session / heartbeat â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (!is_heartbeat) {
      // New session
      await Activation.create({
        license_key_id: matchedDoc._id,
        hwid:           safeHwid,
        ip_address:     ip,
        app_version:    app_version,
        started_at:     now,
        last_heartbeat: now,
        is_active:      true,
      });
    } else {
      // Update existing session heartbeat
      await Activation.updateOne(
        { license_key_id: matchedDoc._id, hwid: safeHwid, is_active: true },
        { $set: { last_heartbeat: now } },
        { sort: { started_at: -1 } }
      );
    }

    // â”€â”€ Success response â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // FIX: Added session_token and hwid_match fields that LicenseService expects
    const session_token = crypto.randomBytes(32).toString('hex');
    return res.json({
      valid:         true,
      code:          'OK',
      tier:          matchedDoc.tier,
      label:         matchedDoc.label,
      expires_at:    matchedDoc.expires_at,         // null = lifetime
      server_time:   now.toISOString(),             // client uses for clock skew detection
      hwid_bound:    matchedDoc.hwid,               // the bound HWID value
      hwid_match:    true,                          // FIX: client checks this field
      session_token: session_token,                 // FIX: client stores for heartbeat auth
      message:       `${matchedDoc.tier.toUpperCase()} key accepted.`,
    });

  } catch (err) {
    console.error('[validate-key]', err);
    await logSecurity('error', `validate-key server error: ${err.message}`, ip);
    return res.status(500).json({ valid: false, code: 'SERVER_ERROR', message: 'Validation service error. Try again.' });
  }
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// ROUTE: POST /submit-order
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const orderLimiter = rateLimit({ windowMs: 60_000, max: 3, message: { error: 'Too many orders. Wait a minute.' } });

app.post('/submit-order', orderLimiter, async (req, res) => {
  const { user_name, phone_number, email, country, plan, hwid, machine_name, os_version } = req.body;
  const ip = getIp(req);

  // Validate
  if (!user_name || !phone_number || !plan) {
    return res.status(400).json({ ok: false, message: 'Name, phone, and plan are required.' });
  }
  if (!['daily','weekly','monthly'].includes(plan)) {
    return res.status(400).json({ ok: false, message: 'Invalid plan.' });
  }

  const prices = { daily: { egp: 30, usd: '~$0.6' }, weekly: { egp: 200, usd: '~$4' }, monthly: { egp: 500, usd: '~$10' } };
  const price  = prices[plan];

  try {
    const order = await Order.create({
      user_name:    user_name.trim().slice(0, 100),
      phone_number: phone_number.trim().slice(0, 30),
      email:        (email || '').trim().slice(0, 100),
      country:      (country || '').trim().slice(0, 60),
      plan,
      price_egp:    price.egp,
      price_usd:    price.usd,
      hwid:         (hwid || '').trim().slice(0, 32),
      machine_name: (machine_name || '').trim().slice(0, 60),
      os_version:   (os_version || '').trim().slice(0, 60),
      ip_address:   ip,
      status:       'pending',
    });

    // Notify admin via Telegram
    const tgText = `ðŸ›’ <b>NEW ORDER</b>\n` +
      `ðŸ“¦ Plan: <b>${plan.toUpperCase()}</b> â€” ${price.egp} EGP (${price.usd})\n` +
      `ðŸ‘¤ Name: ${user_name}\n` +
      `ðŸ“± Phone: ${phone_number}\n` +
      `ðŸŒ Country: ${country || 'N/A'}\n` +
      `ðŸ“§ Email: ${email || 'N/A'}\n` +
      `ðŸ†” Order ID: <code>${order._id}</code>\n` +
      `ðŸ’» HWID: <code>${hwid || 'N/A'}</code>\n` +
      `ðŸ• Time: ${new Date().toUTCString()}`;
    await notifyTelegram(tgText);

    await logSecurity('info', `New order submitted plan=${plan}`, ip, '', hwid || '', { order_id: order._id });

    return res.json({
      ok:       true,
      order_id: order._id,
      message:  'Order received! Admin will send your license key shortly.',
    });
  } catch (err) {
    console.error('[submit-order]', err);
    return res.status(500).json({ ok: false, message: 'Order submission failed. Please try again.' });
  }
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// ROUTE: GET /check-update?version=1.0.0
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Mandatory update download URL - always sent to client when is_mandatory=true
const MANDATORY_DOWNLOAD_URL = 'https://sasa120120.itch.io/valorant-companion-app/download/eyJpZCI6NDQxODI5NCwiZXhwaXJlcyI6MTc3NDQ4NjQ1MH0%3d%2ev0Oyz%2f8pnRmQ9vOGL3uSnjoTCbU%3d';

app.get('/check-update', async (req, res) => {
  const clientVersion = (req.query.version || '0.0.0').replace(/[^0-9.]/g, '');
  try {
    const latest = await AppVersion.findOne({ is_active: true }).sort({ released_at: -1 }).lean();
    if (!latest) return res.json({ update_available: false });

    const needsUpdate = compareVersions(latest.version, clientVersion) > 0;

    // Always use itch.io URL for mandatory updates regardless of DB value
    const downloadUrl = needsUpdate
      ? (latest.is_mandatory ? MANDATORY_DOWNLOAD_URL : (latest.download_url || MANDATORY_DOWNLOAD_URL))
      : null;

    // Build a rich message the client will display in the mandatory update dialog
    const updateMessage = (needsUpdate && latest.is_mandatory)
      ? 'New Update Available!\n\n' +
        'A mandatory update (v' + latest.version + ') is required to continue using VALORANT Companion.\n\n' +
        (latest.release_notes ? latest.release_notes + '\n\n' : '') +
        'Press \"Update\" to open the download page, or \"Exit\" to close the app.'
      : null;

    return res.json({
      update_available: needsUpdate,
      latest_version:   latest.version,
      download_url:     downloadUrl,
      release_notes:    needsUpdate ? latest.release_notes : null,
      is_mandatory:     needsUpdate ? latest.is_mandatory  : false,
      checksum_sha256:  needsUpdate ? latest.checksum_sha256 : null,
      update_message:   updateMessage,
      server_time:      new Date().toISOString(),
    });
  } catch (err) {
    console.error('[check-update]', err);
    return res.status(500).json({ update_available: false, error: 'Update check failed.' });
  }
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// ADMIN ROUTES â€” protected by x-admin-key header
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// Generate a new license key
app.post('/admin/generate-key', requireAdminKey, async (req, res) => {
  const { tier = 'standard', label = '' } = req.body;

  // FIX: ensure duration is always a valid number
  const duration_days = Math.max(0, parseInt(req.body.duration_days, 10) || 30);

  if (!['standard','pro','lifetime','admin'].includes(tier)) {
    return res.status(400).json({ error: 'Invalid tier.' });
  }

  // Generate raw key
  // FIX: key format was "VS-XXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX" (prefix 8 chars = "VS-XXXXX")
  // but key_prefix was sliced from the raw key which starts with e.g. "VS-" (3 chars) + 5 hex chars.
  // The prefix lookup on validate uses keyPrefix() which normalizes and takes first 8 chars of the
  // full key â€” this is consistent. However, the rand was 32 hex chars (16 bytes * 2) but only
  // slice(0,8) and slice(8) were used giving 8+24=32 chars total key body. This is correct.
  // FIX: ensure key_prefix is derived from the normalized key (uppercase, trimmed) for consistent lookups.
  const prefix = { standard: 'VS', pro: 'VP', lifetime: 'VL', admin: 'VA' }[tier];
  const rand   = crypto.randomBytes(16).toString('hex').toUpperCase();
  const rawKey = `${prefix}-${rand.slice(0,8)}-${rand.slice(8,24)}`;  // FIX: explicit slice end (24) for consistent 16-char body

  const key_hash   = await bcrypt.hash(rawKey, 10);  // FIX: use top-level import
  const key_prefix = rawKey.slice(0, 8).toUpperCase();  // FIX: normalize to uppercase for consistent prefix lookups
  const expires_at = (tier === 'lifetime' || tier === 'admin' || duration_days === 0)
    ? null
    : new Date(Date.now() + duration_days * 86_400_000);

  try {
    const doc = await LicenseKey.create({ key_hash, key_prefix, tier, label, expires_at });
    await logSecurity('info', `Key generated tier=${tier} prefix=${key_prefix}`, '', key_prefix);

    return res.json({ ok: true, key: rawKey, tier, label, expires_at, id: doc._id });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});
// FIX: add rate limiter to crash-report to prevent log flooding / DoS
const crashReportLimiter = rateLimit({ windowMs: 60_000, max: 5, message: { ok: false } });
app.post('/crash-report', crashReportLimiter, async (req, res) => {
  try {
    console.log('[CRASH REPORT]', req.body);

    await logSecurity(
      'error',
      'Client crash report',
      getIp(req),
      '',
      req.body?.hwid || '',
      req.body
    );

    res.json({ ok: true });
  } catch (e) {
    console.error('[crash-report]', e.message);
    res.status(500).json({ ok: false });
  }
});

// List all keys (paginated)
app.get('/admin/keys', requireAdminKey, async (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page)  || 1);
  const limit = Math.min(100, parseInt(req.query.limit) || 50);
  try {
    const total = await LicenseKey.countDocuments();
    const keys  = await LicenseKey.find()
      .sort({ created_at: -1 })
      .skip((page-1) * limit)
      .limit(limit)
      .select('-key_hash')  // never expose hash
      .lean();
    return res.json({ ok: true, total, page, limit, keys });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Revoke key
app.post('/admin/revoke-key', requireAdminKey, async (req, res) => {
  const { key_id } = req.body;
  try {
    await LicenseKey.updateOne({ _id: key_id }, { $set: { is_active: false } });
    await Activation.updateMany({ license_key_id: key_id }, { $set: { is_active: false } });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Ban key (harder than revoke)
app.post('/admin/ban-key', requireAdminKey, async (req, res) => {
  const { key_id } = req.body;
  try {
    await LicenseKey.updateOne({ _id: key_id }, { $set: { is_banned: true, is_active: false } });
    await Activation.updateMany({ license_key_id: key_id }, { $set: { is_active: false } });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Unbind HWID
app.post('/admin/unbind-hwid', requireAdminKey, async (req, res) => {
  const { key_id } = req.body;
  try {
    await LicenseKey.updateOne({ _id: key_id }, { $set: { hwid: null } });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// List orders
app.get('/admin/orders', requireAdminKey, async (req, res) => {
  const status = req.query.status;
  const filter = status ? { status } : {};
  try {
    const orders = await Order.find(filter).sort({ created_at: -1 }).limit(200).lean();
    return res.json({ ok: true, orders });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Update order status
app.post('/admin/update-order', requireAdminKey, async (req, res) => {
  const { order_id, status, admin_note, license_key_issued } = req.body;
  try {
    const upd = { status, admin_note: admin_note || '' };
    if (status === 'completed') upd.completed_at = new Date();
    if (license_key_issued)     upd.license_key_issued = license_key_issued;
    await Order.updateOne({ _id: order_id }, { $set: upd });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Publish new app version
app.post('/admin/publish-version', requireAdminKey, async (req, res) => {
  const { version, download_url, release_notes, is_mandatory, checksum_sha256 } = req.body;
  if (!version || !download_url) return res.status(400).json({ error: 'version and download_url required.' });
  try {
    await AppVersion.findOneAndUpdate(
      { version },
      { version, download_url, release_notes: release_notes || '', is_mandatory: !!is_mandatory, checksum_sha256: checksum_sha256 || '', is_active: true, released_at: new Date() },
      { upsert: true }
    );
    return res.json({ ok: true, version });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Analytics dashboard stats
app.get('/admin/stats', requireAdminKey, async (req, res) => {
  try {
    const now = new Date();
    const heartbeatThreshold = new Date(now - (parseInt(process.env.HEARTBEAT_TIMEOUT_SECONDS)||120) * 1000);
    const [totalKeys, activeKeys, activeSessions, pendingOrders, totalOrders, recentLogs, expiredKeys, revokedKeys] = await Promise.all([
      LicenseKey.countDocuments(),
      LicenseKey.countDocuments({ is_active: true, is_banned: false }),
      Activation.countDocuments({ is_active: true, last_heartbeat: { $gte: heartbeatThreshold } }),
      Order.countDocuments({ status: 'pending' }),
      Order.countDocuments(),
      SecurityLog.find({ type: 'security' }).sort({ timestamp: -1 }).limit(10).lean(),
      // FIX: Added expiredKeys and revokedKeys counts for accurate dashboard stats
      LicenseKey.countDocuments({ expires_at: { $ne: null, $lt: now }, is_active: true }),
      LicenseKey.countDocuments({ is_active: false }),
    ]);
    const tierBreakdown = await LicenseKey.aggregate([
      { $group: { _id: '$tier', count: { $sum: 1 } } }
    ]);
    return res.json({
      ok: true,
      totalKeys,
      activeKeys,
      activeSessions,
      pendingOrders,
      totalOrders,
      expiredKeys,    // FIX: new field â€” client uses for ExpiredKeyCount display
      revokedKeys,    // FIX: new field â€” client uses for RevokedKeyCount display
      tierBreakdown,
      recentSecurityEvents: recentLogs,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Health check
// â”€â”€ Pricing settings (stored in its own collection) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const PricingSettings = mongoose.models.PricingSettings || mongoose.model('PricingSettings',
  new mongoose.Schema({ key: String, value: mongoose.Schema.Types.Mixed }, { strict: false }));

// â”€â”€ Admin: Update pricing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/admin/update-pricing', requireAdminKey, async (req, res) => {
  try {
    const { daily_egp, daily_usd, weekly_egp, weekly_usd, monthly_egp, monthly_usd } = req.body;
    await PricingSettings.findOneAndUpdate(
      { key: 'pricing' },
      { key: 'pricing', value: { daily_egp, daily_usd, weekly_egp, weekly_usd, monthly_egp, monthly_usd }, updated_at: new Date() },
      { upsert: true, new: true }
    );
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// â”€â”€ Admin: Get pricing (for client sync) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/pricing', async (req, res) => {
  try {
    const doc = await PricingSettings.findOne({ key: 'pricing' }).lean();
    if (!doc) return res.json({ ok: true, pricing: null });
    return res.json({ ok: true, pricing: doc.value });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// â”€â”€ Admin: Pin/Unpin HWID â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/admin/pin-hwid', requireAdminKey, async (req, res) => {
  try {
    const { key_id, pinned } = req.body;
    if (!key_id) return res.status(400).json({ error: 'key_id required' });
    await LicenseKey.findByIdAndUpdate(key_id, { hwid_pinned: !!pinned });
    return res.json({ ok: true, pinned });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// â”€â”€ Admin: Adjust key duration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/admin/adjust-key-duration', requireAdminKey, async (req, res) => {
  try {
    const { key_id, days } = req.body;
    if (!key_id || typeof days !== 'number') return res.status(400).json({ error: 'key_id and days required' });
    const key = await LicenseKey.findById(key_id);
    if (!key) return res.status(404).json({ error: 'Key not found' });
    if (key.expires_at) {
      const base = key.expires_at > new Date() ? key.expires_at : new Date();
      key.expires_at = new Date(base.getTime() + days * 86400000);
    } else if (days < 0) {
      // Lifetime key â€” set expiry to N days from now when reducing
      key.expires_at = new Date(Date.now() + Math.abs(days) * 86400000);
    }
    await key.save();
    return res.json({ ok: true, expires_at: key.expires_at });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// â”€â”€ Admin: Hard delete key â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/admin/delete-key', requireAdminKey, async (req, res) => {
  try {
    const { key_id } = req.body;
    if (!key_id) return res.status(400).json({ error: 'key_id required' });
    await LicenseKey.findByIdAndDelete(key_id);
    await Activation.deleteMany({ key_id });
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// ROUTE: POST /complaint â€” User submits a complaint from the floating chat icon
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const { Complaint } = require('./models');

const complaintLimiter = rateLimit({ windowMs: 5 * 60_000, max: 3, message: { ok: false, message: 'Too many complaints sent. Please wait 5 minutes.' } });

app.post('/complaint', complaintLimiter, async (req, res) => {
  const { subject, message, category, hwid, app_version } = req.body;
  const ip = getIp(req);

  if (!subject || !message) {
    return res.status(400).json({ ok: false, message: 'Subject and message are required.' });
  }
  if (message.length < 10) {
    return res.status(400).json({ ok: false, message: 'Message too short.' });
  }

  try {
    const complaint = await Complaint.create({
      subject:     subject.trim().slice(0, 120),
      message:     message.trim().slice(0, 1000),
      category:    (category || 'General').slice(0, 60),
      hwid:        (hwid || '').trim().slice(0, 64),
      app_version: (app_version || '').trim().slice(0, 20),
      ip_address:  ip,
      status:      'open',
    });

    // Notify admin via Telegram
    const tgText = `ðŸ’¬ <b>NEW COMPLAINT</b>\n` +
      `ðŸ“‹ Subject: <b>${subject}</b>\n` +
      `ðŸ·ï¸ Category: ${category || 'General'}\n` +
      `ðŸ’¬ Message: ${message.slice(0, 200)}${message.length > 200 ? '...' : ''}\n` +
      `ðŸ’» HWID: <code>${hwid || 'N/A'}</code>\n` +
      `ðŸ”¢ App: v${app_version || 'N/A'}\n` +
      `ðŸ†” ID: <code>${complaint._id}</code>\n` +
      `ðŸ• Time: ${new Date().toUTCString()}`;
    await notifyTelegram(tgText);

    return res.json({ ok: true, complaint_id: complaint._id, message: 'Complaint received! We will respond soon.' });
  } catch (err) {
    console.error('[complaint]', err);
    return res.status(500).json({ ok: false, message: 'Failed to submit complaint. Try again.' });
  }
});

// â”€â”€ Admin: List complaints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/admin/complaints', requireAdminKey, async (req, res) => {
  const status = req.query.status;
  const filter = status ? { status } : {};
  try {
    const complaints = await Complaint.find(filter).sort({ created_at: -1 }).limit(200).lean();
    return res.json({ ok: true, complaints });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// â”€â”€ Admin: Update complaint status / reply â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/admin/update-complaint', requireAdminKey, async (req, res) => {
  const { complaint_id, status, admin_reply } = req.body;
  try {
    const upd = {};
    if (status)      upd.status      = status;
    if (admin_reply) upd.admin_reply = admin_reply;
    if (status === 'resolved') upd.resolved_at = new Date();
    await Complaint.updateOne({ _id: complaint_id }, { $set: upd });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// ROUTE: GET /my-orders?hwid=... â€” Returns all orders for a given HWID
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
app.get('/my-orders', async (req, res) => {
  const { hwid } = req.query;
  if (!hwid || hwid.length < 4) {
    return res.status(400).json({ ok: false, message: 'HWID required.' });
  }
  try {
    const orders = await Order.find({ hwid: hwid.trim().toUpperCase() })
      .sort({ created_at: -1 })
      .limit(50)
      .select('-ip_address -machine_name -os_version') // don't expose system info
      .lean();
    return res.json({ ok: true, orders });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// â”€â”€ Keep-alive ping endpoint (for UptimeRobot) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// UptimeRobot pings /ping every 5 minutes to prevent Replit from sleeping
app.get('/ping', (req, res) => {
  // Version-aware ping - old clients get 503 which SplashScreen treats as "Server Offline"
  const clientVer = (req.headers['x-app-version'] || req.query.version || '0.0.0')
    .toString().replace(/[^0-9.]/g, '');
  if (compareVersions(clientVer, MINIMUM_VERSION) < 0) {
    return res.status(503).json({
      ok:              false,
      update_required: true,
      minimum_version: MINIMUM_VERSION,
      download_url:    MANDATORY_DOWNLOAD_URL,
      message:         'Update required: v' + MINIMUM_VERSION,
    });
  }
  return res.json({ ok: true, ts: Date.now() });
});

// â”€â”€ Self-ping (built-in keep-alive) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Replit sleeps after ~30min of inactivity. This self-ping runs every 4 minutes
// as a backup so the server stays awake even if UptimeRobot hasn't been set up yet.
// Only runs in production to avoid noise during local development.
if (process.env.NODE_ENV === 'production') {
  const SELF_URL = process.env.REPLIT_DEV_DOMAIN
    ? `https://${process.env.REPLIT_DEV_DOMAIN}/ping`
    : null;
  if (SELF_URL) {
    setInterval(async () => {
      try {
        const http = require('https');
        http.get(SELF_URL, (r) => r.resume()).on('error', () => {});
      } catch (_) {}
    }, 4 * 60 * 1000); // every 4 minutes
    console.log(`[KEEP-ALIVE] Self-ping active â†’ ${SELF_URL}`);
  }
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString(), db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// BACKGROUND JOBS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// Every 5 minutes: mark stale sessions as inactive
cron.schedule('*/5 * * * *', async () => {
  try {
    const threshold = new Date(Date.now() - (parseInt(process.env.HEARTBEAT_TIMEOUT_SECONDS)||120) * 1000);
    const result = await Activation.updateMany(
      { is_active: true, last_heartbeat: { $lt: threshold } },
      { $set: { is_active: false } }
    );
    if (result.modifiedCount > 0)
      console.log(`[CRON] Deactivated ${result.modifiedCount} stale sessions`);
  } catch (e) { console.error('[CRON] session cleanup:', e.message); }
});

// Every hour: log stats
cron.schedule('0 * * * *', async () => {
  try {
    const active = await Activation.countDocuments({ is_active: true });
    console.log(`[CRON] Active sessions: ${active}`);
  } catch {}
});

// â”€â”€ Start server â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SERVER] ValorantCompanion Backend running on port ${PORT}`);
  console.log(`[SERVER] Environment: ${process.env.NODE_ENV}`);
});

process.on('unhandledRejection', (reason) => {
  console.error('[UNHANDLED REJECTION]', reason);
});


