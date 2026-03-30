'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '../config/.env') });

const express   = require('express');
const mongoose  = require('mongoose');
const helmet    = require('helmet');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const crypto    = require('crypto');
const cron      = require('node-cron');
const bcrypt    = require('bcryptjs');
const axios     = require('axios');

const { LicenseKey, Activation, Order, SecurityLog, AppVersion, Complaint, PerformanceMetric, ServerConfig } = require('./models');

const app  = express();
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Security middleware
// ---------------------------------------------------------------------------
app.use(helmet());
app.use(cors({ origin: false }));
app.use(express.json({ limit: '16kb' }));
app.set('trust proxy', 1);

// ---------------------------------------------------------------------------
// SSE Client Registry  (real-time push to all connected desktop clients)
// ---------------------------------------------------------------------------
const sseClients    = new Map(); // id -> { res, hwid, appVersion }
const adminSseClients = new Map(); // id -> res  (admin dashboard streams)

function broadcastToAll(eventName, payload) {
  const data = JSON.stringify(payload);
  for (const [id, client] of sseClients) {
    try { client.res.write(`event: ${eventName}\ndata: ${data}\n\n`); }
    catch { sseClients.delete(id); }
  }
}

function broadcastToAdmin(eventName, payload) {
  const data = JSON.stringify(payload);
  for (const [id, res] of adminSseClients) {
    try { res.write(`event: ${eventName}\ndata: ${data}\n\n`); }
    catch { adminSseClients.delete(id); }
  }
}

function broadcastVersionUpdate(payload) {
  broadcastToAll('version_update', payload);
}

// ---------------------------------------------------------------------------
// Version gate & Maintenance mode
// ---------------------------------------------------------------------------
let MINIMUM_VERSION = '1.1.9';
let MAINTENANCE_MODE = false;

const MANDATORY_DOWNLOAD_URL = process.env.DOWNLOAD_URL ||
  'https://sasa120120.itch.io/valorant-companion-app/download/eyJpZCI6NDQxODI5NCwiZXhwaXJlcyI6MTc3NDQ4NjQ1MH0%3d%2ev0Oyz%2f8pnRmQ9vOGL3uSnjoTCbU%3d';

async function refreshMinimumVersion() {
  try {
    const latest = await AppVersion.findOne({ is_active: true }).sort({ released_at: -1 }).lean();
    if (latest && latest.version) {
      if (MINIMUM_VERSION !== latest.version)
        console.log(`[version] MINIMUM_VERSION: ${MINIMUM_VERSION} -> ${latest.version}`);
      MINIMUM_VERSION = latest.version;
    }
  } catch (e) { console.error('[version] refresh error:', e.message); }
}

async function loadMaintenanceMode() {
  try {
    const config = await ServerConfig.findOne({ key: 'maintenance_mode' });
    MAINTENANCE_MODE = config ? config.value === true : false;
  } catch (e) { console.error('[config] maintenance_mode load error:', e.message); }
}

const VERSION_EXEMPT = ['/check-update', '/health', '/pricing', '/events', '/admin-events', 
  '/crash-report', '/admin'];

app.use((req, res, next) => {
  if (VERSION_EXEMPT.some(p => req.path.startsWith(p))) return next();
  const clientVersion = (req.headers['x-app-version'] || req.body?.app_version || '0.0.0')
    .toString().replace(/[^0-9.]/g, '');
  if (compareVersions(clientVersion, MINIMUM_VERSION) !== 0) {
    return res.status(426).json({
      error: 'update_required', update_required: true,
      minimum_version: MINIMUM_VERSION, latest_version: MINIMUM_VERSION,
      download_url: MANDATORY_DOWNLOAD_URL,
      message: `Your version is outdated. Please download the latest version (v${MINIMUM_VERSION}) to continue.`,
    });
  }
  next();
});

// ---------------------------------------------------------------------------
// Rate limiters (EXEMPTING /ping and /check-update from globalLimiter)
// ---------------------------------------------------------------------------
const globalLimiter = rateLimit({
  windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many requests, slow down.' },
  skip: (req) => req.path === '/ping' || req.path === '/check-update',
});

const validateKeyLimiter = rateLimit({
  windowMs: 60_000, max: 10, standardHeaders: false, legacyHeaders: false,
  message: { error: 'Too many validation attempts. Try again later.' },
});

const activationLimiter = rateLimit({
  windowMs: 300_000, max: 15, standardHeaders: false, legacyHeaders: false,
});

app.use(globalLimiter);

// ---------------------------------------------------------------------------
// Helper: Version comparison (semver-like)
// ---------------------------------------------------------------------------
function compareVersions(v1, v2) {
  const p1 = v1.split('.').map(Number);
  const p2 = v2.split('.').map(Number);
  for (let i = 0; i < Math.max(p1.length, p2.length); i++) {
    const a = p1[i] || 0;
    const b = p2[i] || 0;
    if (a > b) return 1;
    if (a < b) return -1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Helper: Validate admin key
// ---------------------------------------------------------------------------
async function requireAdminKey(req, res, next) {
  const key = req.headers['x-admin-key'] || req.body?.admin_key || req.query.key;
  const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'c636cf706ff8efef3920328c9248bc566e17a4313b04243ff679a4f5584d67ad';
  
  if (!key || key !== ADMIN_API_KEY) {
    return res.status(401).json({ error: 'unauthorized', message: 'Invalid Admin API Key' });
  }
  next();
}

// ===========================================================================
// PUBLIC ROUTES
// ===========================================================================

// GET /health — server health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', maintenance: MAINTENANCE_MODE, version: MINIMUM_VERSION });
});

// GET /ping — version-locked ping
app.get('/ping', (req, res) => {
  res.json({ ok: true, timestamp: Date.now(), minimum_version: MINIMUM_VERSION });
});

// GET /check-update — check if update available
app.get('/check-update', async (req, res) => {
  try {
    const clientVersion = (req.headers['x-app-version'] || req.query.v || '0.0.0')
      .toString().replace(/[^0-9.]/g, '');
    const latest = await AppVersion.findOne({ is_active: true }).sort({ released_at: -1 }).lean();
    if (!latest) return res.json({ update_available: false });
    const needsUpdate = compareVersions(clientVersion, latest.version) !== 0;
    return res.json({
      update_available: needsUpdate,
      latest_version: latest.version,
      is_mandatory: needsUpdate && latest.is_mandatory,
      download_url: latest.download_url,
      release_notes: latest.release_notes,
    });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// GET /pricing — pricing info
app.get('/pricing', async (req, res) => {
  try {
    return res.json({
      plans: [
        { name: 'Daily', duration: '24h', price_egp: 20, price_usd: '$0.50' },
        { name: 'Weekly', duration: '7d', price_egp: 100, price_usd: '$2.50' },
        { name: 'Monthly', duration: '30d', price_egp: 300, price_usd: '$7.50' },
      ]
    });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// POST /validate-key — validate license key & create activation
app.post('/validate-key', validateKeyLimiter, async (req, res) => {
  const { key, hwid, ip_address } = req.body;
  if (!key || !hwid) return res.status(400).json({ error: 'Missing key or hwid' });

  if (MAINTENANCE_MODE) {
    return res.status(503).json({ error: 'maintenance_mode', message: 'Server is under maintenance. Please try again later.' });
  }

  try {
    const keyPrefixHint = key.substring(0, 8).toUpperCase();
    const candidates = await LicenseKey.find({ 
      key_prefix: keyPrefixHint, 
      is_active: true, 
      is_banned: false 
    }).lean();

    let validKey = null;
    for (const candidate of candidates) {
      const isMatch = await bcrypt.compare(key.trim().toUpperCase(), candidate.key_hash);
      if (isMatch) {
         validKey = candidate;
         break; // Return first match only
      }
    }

    if (!validKey) {
      await SecurityLog.create({
        type: 'security', message: 'Invalid key attempted', ip: req.ip, hwid: hwid, 
        key_prefix: keyPrefixHint, timestamp: new Date(),
      });
      return res.status(401).json({ error: 'Invalid key' });
    }

    // Check expiration
    if (validKey.expires_at && new Date() > validKey.expires_at) {
      return res.status(401).json({ error: 'Key expired' });
    }

    // Check HWID binding
    if (validKey.hwid && validKey.hwid !== hwid) {
      return res.status(403).json({ error: 'Key bound to different device' });
    }

    // Update activation
    const HEARTBEAT_EXPIRY = 300; // 5 min
    const session = await Activation.findOneAndUpdate(
      { license_key_id: validKey._id, hwid: hwid },
      { 
        $set: { 
          is_active: true, 
          last_heartbeat: new Date(),
          ip_address: ip_address || req.ip,
          expires_at: new Date(Date.now() + HEARTBEAT_EXPIRY * 1000)
        }
      },
      { upsert: true, new: true }
    );

    return res.json({
      valid: true,
      tier: validKey.tier,
      label: validKey.label,
      expires_at: validKey.expires_at,
      server_time: new Date(),
    });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// ===========================================================================
// ADMIN ROUTES (Protected by requireAdminKey)
// ===========================================================================

app.get('/admin/stats', requireAdminKey, async (req, res) => {
  try {
    const totalKeys = await LicenseKey.countDocuments();
    const activeSessions = await Activation.countDocuments({ is_active: true });
    const totalOrders = await Order.countDocuments();
    const openComplaints = await Complaint.countDocuments({ status: 'open' });
    
    return res.json({
      ok: true,
      stats: {
        total_keys: totalKeys,
        active_users: activeSessions,
        total_orders: totalOrders,
        pending_reports: openComplaints,
        server_uptime: process.uptime(),
        memory_usage: process.memoryUsage().heapUsed
      }
    });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.get('/admin/keys', requireAdminKey, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const keys = await LicenseKey.find()
      .sort({ created_at: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();
    return res.json({ ok: true, keys });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.post('/admin/generate-key', requireAdminKey, async (req, res) => {
  const { tier, duration_days, label } = req.body;
  try {
    const rawKey = `VALO-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const hash = await bcrypt.hash(rawKey, 10);
    const expiresAt = duration_days > 0 ? new Date(Date.now() + duration_days * 24 * 60 * 60 * 1000) : null;
    
    await LicenseKey.create({
      key_hash: hash,
      key_prefix: rawKey.substring(0, 8),
      tier,
      label,
      expires_at: expiresAt,
      created_at: new Date()
    });
    
    return res.json({ ok: true, key: rawKey });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.post('/admin/adjust-key-duration', requireAdminKey, async (req, res) => {
  const { key_id, days } = req.body;
  try {
    const key = await LicenseKey.findById(key_id);
    if (!key) return res.status(404).json({ error: 'Key not found' });
    
    const currentExpiry = key.expires_at || new Date();
    key.expires_at = new Date(currentExpiry.getTime() + days * 24 * 60 * 60 * 1000);
    await key.save();
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.post('/admin/unbind-hwid', requireAdminKey, async (req, res) => {
  const { key_id } = req.body;
  try {
    await LicenseKey.findByIdAndUpdate(key_id, { $unset: { hwid: 1 } });
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.post('/admin/pin-hwid', requireAdminKey, async (req, res) => {
  const { key_id, hwid } = req.body;
  try {
    await LicenseKey.findByIdAndUpdate(key_id, { $set: { hwid: hwid } });
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.get('/admin/orders', requireAdminKey, async (req, res) => {
  try {
    const orders = await Order.find().sort({ created_at: -1 }).limit(100).lean();
    return res.json({ ok: true, orders });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.post('/admin/update-order', requireAdminKey, async (req, res) => {
  const { order_id, status } = req.body;
  try {
    await Order.findByIdAndUpdate(order_id, { $set: { status } });
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.get('/admin/complaints', requireAdminKey, async (req, res) => {
  try {
    const complaints = await Complaint.find().sort({ created_at: -1 }).limit(100).lean();
    return res.json({ ok: true, complaints });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.post('/admin/update-complaint', requireAdminKey, async (req, res) => {
  const { complaint_id, status } = req.body;
  try {
    await Complaint.findByIdAndUpdate(complaint_id, { $set: { status } });
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.post('/admin/update-pricing', requireAdminKey, async (req, res) => {
  const { pricing_json } = req.body;
  try {
    await ServerConfig.findOneAndUpdate({ key: 'pricing' }, { $set: { value: pricing_json } }, { upsert: true });
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.post('/admin/delete-key', requireAdminKey, async (req, res) => {
  const { key_id } = req.body;
  try {
    await LicenseKey.findByIdAndDelete(key_id);
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.get('/admin/current-version', requireAdminKey, async (req, res) => {
  return res.json({ ok: true, version: MINIMUM_VERSION });
});

// GET /admin/logs
app.get('/admin/logs', requireAdminKey, async (req, res) => {
  const limit = Math.min(200, parseInt(req.query.limit) || 50);
  const type  = req.query.type;
  try {
    const filter = type ? { type } : {};
    const logs   = await SecurityLog.find(filter).sort({ timestamp: -1 }).limit(limit).lean();
    return res.json({ ok: true, logs });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// GET /admin/sessions
app.get('/admin/sessions', requireAdminKey, async (req, res) => {
  try {
    const sessions = await Activation.find({ is_active: true })
      .sort({ last_heartbeat: -1 }).limit(100)
      .populate('license_key_id', 'tier label key_prefix').lean();
    return res.json({ ok: true, sessions });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// POST /admin/kick-session
app.post('/admin/kick-session', requireAdminKey, async (req, res) => {
  const { session_id } = req.body;
  try {
    await Activation.findByIdAndUpdate(session_id, { $set: { is_active: false } });
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// ---------------------------------------------------------------------------
// Telegram notification helper (with axios)
// ---------------------------------------------------------------------------
async function notifyTelegram(message) {
  if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID) {
    console.log('[notifyTelegram] Telegram credentials not configured');
    return;
  }

  try {
    await axios.post(
      `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        chat_id: process.env.TELEGRAM_CHAT_ID,
        text: message,
        parse_mode: 'HTML',
      },
      { timeout: 10000 }
    );
  } catch (err) {
    console.error('[notifyTelegram]', err.message);
  }
}

// ---------------------------------------------------------------------------
// KEEP-ALIVE (self-ping for Replit)
// ---------------------------------------------------------------------------
if (process.env.NODE_ENV === 'production') {
  const SELF_URL = process.env.REPLIT_DEV_DOMAIN
    ? `https://${process.env.REPLIT_DEV_DOMAIN}/ping` : null;
  if (SELF_URL) {
    setInterval(() => {
      try {
        axios.get(SELF_URL, { timeout: 10000 }).catch(() => {});
      } catch (e) {
        console.error('[KEEP-ALIVE] Error:', e.message);
      }
    }, 4 * 60 * 1000);
    console.log(`[KEEP-ALIVE] Self-ping active -> ${SELF_URL}`);
  }
}

// ---------------------------------------------------------------------------
// BACKGROUND JOBS
// ---------------------------------------------------------------------------
// Every 5 minutes: deactivate stale sessions
cron.schedule('*/5 * * * *', async () => {
  try {
    const timeoutSeconds = parseInt(process.env.HEARTBEAT_TIMEOUT_SECONDS) || 180;
    const threshold = new Date(Date.now() - (timeoutSeconds * 1000));
    const result = await Activation.updateMany(
      { is_active: true, last_heartbeat: { $lt: threshold } },
      { $set: { is_active: false } }
    );
    if (result.modifiedCount > 0) {
      console.log(`[CRON] Deactivated ${result.modifiedCount} stale sessions`);
    }
  } catch (e) { console.error('[CRON] session cleanup:', e.message); }
});

// Every hour: log active session count
cron.schedule('0 * * * *', async () => {
  try {
    const active = await Activation.countDocuments({ is_active: true });
    console.log(`[CRON] Active sessions: ${active} | SSE clients: ${sseClients.size}`);
  } catch {}
});

// On startup: load version & maintenance mode
(async () => {
  await refreshMinimumVersion();
  await loadMaintenanceMode();
})();

// ===========================================================================
// BACKWARD-COMPAT ALIASES (Replit live server uses these route names)
// ===========================================================================

// /admin/publish-version is the OLD route name -> alias to set-version handler
app.post('/admin/publish-version', requireAdminKey, async (req, res) => {
  try {
    const { version, is_mandatory = false, release_notes = '' } = req.body;
    if (!version || !/^\d+\.\d+\.\d+$/.test(version))
      return res.status(400).json({ error: 'Version must be in X.Y.Z format.' });
    const latest = await AppVersion.findOne({ is_active: true }).sort({ released_at: -1 }).lean();
    if (latest && compareVersions(version, latest.version) <= 0)
      return res.status(400).json({ error: `Version must be higher than current (${latest.version}).` });
    await AppVersion.updateMany({}, { is_active: false });
    await AppVersion.create({ version, is_mandatory, release_notes, is_active: true, released_at: new Date(), download_url: MANDATORY_DOWNLOAD_URL, checksum_sha256: '' });
    await refreshMinimumVersion();
    const updatePayload = {
      update_available: true, latest_version: version, is_mandatory, release_notes,
      download_url: MANDATORY_DOWNLOAD_URL,
      update_message: `New Update Available!\n\nVersion v${version} has been released.\n\n${release_notes ? release_notes + '\n\n' : ''}${is_mandatory ? 'This is a MANDATORY update. You must update to continue.' : 'Press "Update" to download.'}`,
    };
    broadcastVersionUpdate(updatePayload);
    broadcastToAdmin('version_changed', { version, is_mandatory, ts: Date.now() });
    console.log(`[admin/publish-version] Version raised to ${version} — broadcast to ${sseClients.size} SSE clients`);
    return res.json({ ok: true, version, is_mandatory });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// /complaint is the OLD route name -> alias to submit-complaint handler
app.post('/complaint', async (req, res) => {
  req.body.app_version = req.headers['x-app-version'] || req.body.app_version || '';
  return res.redirect(307, '/submit-complaint');
});
// ===========================================================================
// START SERVER
// ===========================================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SERVER] ValorantCompanion Backend v2 running on port ${PORT}`);
  console.log(`[SERVER] Environment: ${process.env.NODE_ENV}`);
  console.log(`[SERVER] Real-time SSE: /events | Admin SSE: /admin-events`);
});

process.on('unhandledRejection', reason => { console.error('[UNHANDLED REJECTION]', reason); });
process.on('uncaughtException',  err    => { console.error('[UNCAUGHT EXCEPTION]',  err);    });