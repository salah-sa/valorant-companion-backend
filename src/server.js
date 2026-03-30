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
let MINIMUM_VERSION = '1.1.8';
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

const VERSION_EXEMPT = ['/check-update', '/health', '/pricing', '/ping', '/events', '/admin-events', 
  '/crash-report', '/admin'];

app.use((req, res, next) => {
  if (VERSION_EXEMPT.some(p => req.path.startsWith(p))) return next();
  const clientVersion = (req.headers['x-app-version'] || req.body?.app_version || '0.0.0')
    .toString().replace(/[^0-9.]/g, '');
  if (compareVersions(clientVersion, MINIMUM_VERSION) < 0) {
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
  const key = req.headers['x-admin-key'] || req.body?.admin_key;
  if (!key || key !== process.env.ADMIN_KEY) {
    await SecurityLog.create({
      type: 'security',
      message: 'Admin key validation failed',
      ip: req.ip,
      timestamp: new Date(),
    });
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ---------------------------------------------------------------------------
// PUBLIC ROUTES
// ---------------------------------------------------------------------------

// GET /health — server health check
app.get('/health', (req, res) => {
  res.json({ ok: true, timestamp: Date.now() });
});

// GET /ping — version-exempt ping
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
    const needsUpdate = compareVersions(clientVersion, latest.version) < 0;
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

    // Bind HWID if not already bound
    if (!validKey.hwid) {
      await LicenseKey.findByIdAndUpdate(validKey._id, { hwid: hwid, last_used_at: new Date() });
    } else {
      await LicenseKey.findByIdAndUpdate(validKey._id, { last_used_at: new Date() });
    }

    // Create activation
    const activation = await Activation.create({
      license_key_id: validKey._id,
      hwid: hwid,
      ip_address: ip_address || req.ip,
      app_version: req.body.app_version || '',
      user_agent: req.get('User-Agent') || '',
    });

    await SecurityLog.create({
      type: 'info', message: 'Key validated successfully',
      ip: req.ip, hwid: hwid, key_prefix: validKey.key_prefix,
      timestamp: new Date(),
    });

    return res.json({
      ok: true,
      activation_id: activation._id,
      tier: validKey.tier,
      expires_at: validKey.expires_at,
      minimum_version: MINIMUM_VERSION,
    });
  } catch (err) {
    console.error('[validate-key]', err);
    return res.status(500).json({ error: err.message });
  }
});

// POST /heartbeat — keep activation alive
app.post('/heartbeat', activationLimiter, async (req, res) => {
  const { activation_id } = req.body;
  if (!activation_id) return res.status(400).json({ error: 'Missing activation_id' });

  try {
    const activation = await Activation.findByIdAndUpdate(
      activation_id,
      { last_heartbeat: new Date() },
      { new: true }
    ).lean();

    if (!activation || !activation.is_active) {
      return res.status(401).json({ error: 'Activation not found or inactive' });
    }

    return res.json({ ok: true, is_active: activation.is_active });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// GET /events — SSE stream for version updates & messages
app.get('/events', (req, res) => {
  const clientId = crypto.randomUUID();
  const hwid = req.query.hwid || 'unknown';
  const appVersion = req.query.app_version || '0.0.0';

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  sseClients.set(clientId, { res, hwid, appVersion });

  // Send immediate 'connected' event with current version
  res.write(`event: connected\ndata: ${JSON.stringify({ minimum_version: MINIMUM_VERSION, timestamp: Date.now() })}\n\n`);

  res.on('close', () => {
    sseClients.delete(clientId);
  });
});

// GET /admin-events — Admin SSE stream
app.get('/admin-events', requireAdminKey, (req, res) => {
  const clientId = crypto.randomUUID();

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  adminSseClients.set(clientId, res);

  res.on('close', () => {
    adminSseClients.delete(clientId);
  });
});

// POST /report-performance — clients send FPS, ping, CPU, RAM metrics
app.post('/report-performance', async (req, res) => {
  const { hwid, fps_avg, fps_min, fps_max, ping_avg, cpu_avg, ram_avg, app_version, map_name, agent_name } = req.body;
  if (!hwid) return res.status(400).json({ error: 'Missing hwid' });

  try {
    await PerformanceMetric.create({
      hwid: hwid,
      fps_avg: fps_avg || 0,
      fps_min: fps_min || 0,
      fps_max: fps_max || 0,
      ping_avg: ping_avg || 0,
      cpu_avg: cpu_avg || 0,
      ram_avg: ram_avg || 0,
      app_version: app_version || '',
      map_name: map_name || '',
      agent_name: agent_name || '',
      recorded_at: new Date(),
    });
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// GET /leaderboard — top 10 users by average FPS
app.get('/leaderboard', async (req, res) => {
  try {
    const leaderboard = await PerformanceMetric.aggregate([
      {
        $group: {
          _id: { $substr: ['$hwid', 0, 8] },  // Use HWID prefix for privacy
          avg_fps: { $avg: '$fps_avg' },
          total_sessions: { $sum: 1 },
        }
      },
      { $sort: { avg_fps: -1 } },
      { $limit: 10 },
    ]);
    return res.json({ ok: true, leaderboard });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// GET /server-status — server health, sessions, version, maintenance
app.get('/server-status', async (req, res) => {
  try {
    const activeSessions = await Activation.countDocuments({ is_active: true });
    return res.json({
      ok: true,
      server_health: 'healthy',
      active_sessions: activeSessions,
      minimum_version: MINIMUM_VERSION,
      maintenance_mode: MAINTENANCE_MODE,
      sse_clients: sseClients.size,
      timestamp: Date.now(),
    });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// POST /ping-test — measure ping to target IPs
app.post('/ping-test', async (req, res) => {
  const { targets } = req.body;
  if (!Array.isArray(targets) || targets.length === 0) {
    return res.status(400).json({ error: 'targets must be a non-empty array' });
  }

  try {
    const results = {};
    for (const target of targets) {
      try {
        const start = Date.now();
        await axios.get(`http://${target}:80`, { timeout: 5000 });
        results[target] = Date.now() - start;
      } catch {
        results[target] = null;  // Timeout or unreachable
      }
    }
    return res.json({ ok: true, results });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// GET /changelog — list all AppVersion entries
app.get('/changelog', async (req, res) => {
  try {
    const versions = await AppVersion.find()
      .sort({ released_at: -1 })
      .lean();
    return res.json({ ok: true, versions });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// GET /my-order-status/:order_id — check specific order status
app.get('/my-order-status/:order_id', async (req, res) => {
  try {
    const order = await Order.findById(req.params.order_id).lean();
    if (!order) return res.status(404).json({ error: 'Order not found' });
    return res.json({
      ok: true,
      order_id: order._id,
      status: order.status,
      plan: order.plan,
      price_egp: order.price_egp,
      created_at: order.created_at,
      completed_at: order.completed_at,
      license_key_issued: order.license_key_issued,
    });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// POST /crash-report — clients send crash logs
app.post('/crash-report', async (req, res) => {
  const { hwid, message, stack_trace, app_version } = req.body;
  try {
    await SecurityLog.create({
      type: 'error',
      message: `Crash Report: ${message}`,
      hwid: hwid || '',
      metadata: { stack_trace, app_version },
      timestamp: new Date(),
    });
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// ---------------------------------------------------------------------------
// ADMIN ROUTES
// ---------------------------------------------------------------------------

// GET /admin/stats — push live stats to all admin SSE clients
function pushAdminStats() {
  try {
    Activation.countDocuments({ is_active: true }).then(count => {
      broadcastToAdmin('stats_update', {
        active_sessions: count,
        sse_clients: sseClients.size,
        timestamp: Date.now(),
      });
    });
  } catch {}
}

// POST /admin/set-version
app.post('/admin/set-version', requireAdminKey, async (req, res) => {
  const { version, is_mandatory, release_notes } = req.body;
  if (!version) return res.status(400).json({ error: 'Missing version' });

  try {
    const latest = await AppVersion.findOne({ is_active: true }).sort({ released_at: -1 }).lean();
    if (latest && compareVersions(version, latest.version) <= 0) {
      return res.status(400).json({ error: 'Version must be greater than current version' });
    }

    await AppVersion.updateMany({}, { is_active: false });
    await AppVersion.create({
      version, is_mandatory, release_notes, is_active: true, released_at: new Date(),
      download_url: MANDATORY_DOWNLOAD_URL, checksum_sha256: ''
    });
    await refreshMinimumVersion();
    console.log(`[admin/set-version] Version raised to ${version}`);

    const updatePayload = {
      update_available: true, latest_version: version, is_mandatory, release_notes,
      download_url: MANDATORY_DOWNLOAD_URL,
      update_message: `New Update Available!\n\nVersion v${version} has been released.\n\n${release_notes ? release_notes + '\n\n' : ''}${is_mandatory ? 'This is a MANDATORY update. You must update to continue.' : 'Press "Update" to download.'}`,
    };
    broadcastVersionUpdate(updatePayload);
    broadcastToAdmin('version_changed', { version, is_mandatory, ts: Date.now() });
    console.log(`[admin/set-version] Broadcast to ${sseClients.size} SSE clients, ${adminSseClients.size} admin clients`);
    return res.json({ ok: true, version, is_mandatory });
  } catch (err) {
    console.error('[admin/set-version]', err);
    return res.status(500).json({ error: err.message });
  }
});

// POST /admin/set-maintenance — toggle maintenance mode
app.post('/admin/set-maintenance', requireAdminKey, async (req, res) => {
  const { enabled } = req.body;
  try {
    await ServerConfig.findOneAndUpdate(
      { key: 'maintenance_mode' },
      { key: 'maintenance_mode', value: enabled === true, updated_at: new Date() },
      { upsert: true }
    );
    MAINTENANCE_MODE = enabled === true;
    broadcastToAdmin('maintenance_mode_changed', { maintenance_mode: MAINTENANCE_MODE, ts: Date.now() });
    return res.json({ ok: true, maintenance_mode: MAINTENANCE_MODE });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// POST /admin/broadcast-message — send message to all SSE clients
app.post('/admin/broadcast-message', requireAdminKey, async (req, res) => {
  const { message, title } = req.body;
  if (!message) return res.status(400).json({ error: 'Missing message' });

  try {
    broadcastToAll('server_message', {
      title: title || 'Server Message',
      message: message,
      timestamp: Date.now(),
    });
    broadcastToAdmin('message_broadcast', { title, message, recipients: sseClients.size, ts: Date.now() });
    return res.json({ ok: true, recipients: sseClients.size });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// POST /admin/send-telegram — manually trigger Telegram message
app.post('/admin/send-telegram', requireAdminKey, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Missing message' });

  try {
    await notifyTelegram(message);
    return res.json({ ok: true });
  } catch (err) {
    console.error('[admin/send-telegram]', err);
    return res.status(500).json({ error: err.message });
  }
});

// GET /admin/export-orders — export all orders as CSV
app.get('/admin/export-orders', requireAdminKey, async (req, res) => {
  try {
    const orders = await Order.find().lean();
    const csv = [
      'Order ID,User,Phone,Email,Country,Plan,Price EGP,Status,Created At,Completed At,License Key',
      ...orders.map(o => `"${o._id}","${o.user_name}","${o.phone_number}","${o.email}","${o.country}","${o.plan}",${o.price_egp},"${o.status}","${o.created_at}","${o.completed_at || ''}","${o.license_key_issued || ''}"`)
    ].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="orders_export.csv"');
    return res.send(csv);
  } catch (err) { return res.status(500).json({ error: err.message }); }
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
    setImmediate(pushAdminStats);
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
      setImmediate(pushAdminStats);
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