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

// ── Database Seeder (Automated for New DBs) ───────────────────────────
async function seedDatabase() {
    try {
        const count = await LicenseKey.countDocuments();
        if (count === 0) {
            console.log('🌱 [Seeder] Database is empty. Creating default Admin...');
            const rand = crypto.randomBytes(16).toString('hex').toUpperCase();
            const rawKey = 'VA-' + rand.slice(0, 8) + '-' + rand.slice(8, 24);
            const hash = await bcrypt.hash(rawKey, 10);
            
            await LicenseKey.create({
                key_prefix: rawKey.slice(0, 8).toUpperCase(),
                key_hash: hash,
                tier: 'admin',
                label: 'AUTO-GENERATED ADMIN',
                expires_at: null
            });
            console.log('✅ [Seeder] DEFAULT ADMIN CREATED: ' + rawKey);
            console.log('👉 [Seeder] Use this key to log into the app.');
        }
    } catch (err) {
        console.error('❌ [Seeder] Failed:', err.message);
    }
}

const app  = express();
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Security & Basic Middleware
// ---------------------------------------------------------------------------
app.use(helmet());
app.use(cors()); // Allow all origins for Desktop Client
app.use(express.json({ limit: '16kb' }));
app.set('trust proxy', 1);

// ── Welcome Message Injection (Global) ──
const WELCOME_MESSAGE = "Welcome to VC! Developed by Egyptian developer ENG Salah Mohamed.";
app.use((req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      body.welcome_message = WELCOME_MESSAGE;
    }
    return originalJson(body);
  };
  next();
});


// Debug Log for Handshakes (Diagnostic Mode)
app.use((req, res, next) => {
  if (req.path === '/health' || req.path === '/ping') {
    console.log(`[Handshake] ${req.method} ${req.path} from ${req.ip} (Version: ${req.headers['x-app-version']})`);
  }
  next();
});

// ---------------------------------------------------------------------------
// Global State & Versioning
// ---------------------------------------------------------------------------
let MINIMUM_VERSION = '1.1.11';
let LATEST_VERSION  = '1.1.11';
let MAINTENANCE_MODE = false;
const MANDATORY_DOWNLOAD_URL = process.env.DOWNLOAD_URL || 'https://sasa120120.itch.io/valorant-companion-app';

// ---------------------------------------------------------------------------
// Helper Functions
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

async function requireAdminKey(req, res, next) {
  const key = req.headers['x-admin-key'] || req.body?.admin_key || req.query.key;
  const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'c636cf706ff8efef3920328c9248bc566e17a4313b04243ff679a4f5584d67ad';
  if (!key || key !== ADMIN_API_KEY) {
    return res.status(401).json({ error: 'unauthorized', message: 'Invalid Admin API Key' });
  }
  next();
}

const sseClients = new Map();
const adminSseClients = new Map();

function broadcastToAll(eventName, payload) {
  const data = JSON.stringify(payload);
  for (const [id, client] of sseClients) {
    try { client.res.write(`event: ${eventName}\ndata: ${data}\n\n`); }
    catch { sseClients.delete(id); }
  }
}

// ---------------------------------------------------------------------------
// Core Logic: Version Sync & DB
// ---------------------------------------------------------------------------
async function syncVersion() {
  try {
    const config = await AppVersion.findOne({ is_active: true }).sort({ released_at: -1 }).lean();
    if (config && config.version) {
      MINIMUM_VERSION = config.version;
      LATEST_VERSION = config.version;
      console.log(`[Server] Version Sync: v${MINIMUM_VERSION}`);
    }
    
    const maint = await ServerConfig.findOne({ key: 'maintenance_mode' });
    MAINTENANCE_MODE = maint ? maint.value === true : false;
  } catch (err) {
    console.log(`[Server] Version Sync Fallback: v${MINIMUM_VERSION}`);
  }
}

async function connectDB() {
  // ── Database Connection ──────────────────────────────────────────────
  mongoose.connect(process.env.MONGODB_URI).then(async () => {
      console.log('✅ [MongoDB] Connected and Ready');
      await seedDatabase();
      await syncVersion();
  }).catch(err => {
      console.error('❌ [MongoDB] Failed Connection:', err.message);
  });
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Version Gate Middleware
app.use((req, res, next) => {
  const EXEMPT = ['/health', '/ping', '/check-update', '/pricing', '/admin'];
  if (EXEMPT.some(p => req.path.startsWith(p))) return next();
  
  const clientV = (req.headers['x-app-version'] || req.body?.app_version || '0.0.0').replace(/[^0-9.]/g, '');
  if (compareVersions(clientV, MINIMUM_VERSION) < 0) {
    return res.status(426).json({
      error: 'update_required',
      minimum_version: MINIMUM_VERSION,
      download_url: MANDATORY_DOWNLOAD_URL
    });
  }
  next();
});

app.get('/health', (req, res) => res.json({ status: 'ok', maintenance: MAINTENANCE_MODE, version: MINIMUM_VERSION }));
app.get('/ping', (req, res) => res.json({ ok: true, version: MINIMUM_VERSION }));

app.get('/check-update', async (req, res) => {
  const v = (req.query.v || '0.0.0').replace(/[^0-9.]/g, '');
  const needsUpdate = compareVersions(v, MINIMUM_VERSION) < 0;
  res.json({
    update_available: needsUpdate,
    latest_version: MINIMUM_VERSION,
    is_mandatory: true,
    download_url: MANDATORY_DOWNLOAD_URL
  });
});

app.post('/validate-key', async (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.status(400).json({ error: 'Missing parameters' });
  try {
    const keyPrefix = key.substring(0, 8).toUpperCase();
    const candidate = await LicenseKey.findOne({ key_prefix: keyPrefix, is_active: true, is_banned: false });
    if (!candidate) return res.status(401).json({ error: 'Invalid key' });
    
    const match = await bcrypt.compare(key.trim().toUpperCase(), candidate.key_hash);
    if (!match) return res.status(401).json({ error: 'Invalid key' });

    await Activation.findOneAndUpdate(
      { license_key_id: candidate._id, hwid },
      { $set: { is_active: true, last_heartbeat: new Date() } },
      { upsert: true }
    );
    
    res.json({ valid: true, tier: candidate.tier, expires_at: candidate.expires_at });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------------------------------------------------------------------
// Client Routes
// ---------------------------------------------------------------------------

app.get('/pricing', async (req, res) => {
  try {
    const config = await ServerConfig.findOne({ key: 'pricing' });
    if (config) return res.json(config.value);
    
    // Default fallback
    res.json({
      daily_egp: "50", daily_usd: "5",
      weekly_egp: "250", weekly_usd: "15",
      monthly_egp: "800", monthly_usd: "40"
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/submit-order', async (req, res) => {
  try {
    const order = await Order.create({
      ...req.body,
      ip_address: req.ip,
      created_at: new Date()
    });
    res.json({ ok: true, order_id: order._id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/submit-complaint', async (req, res) => {
  try {
    const complaint = await Complaint.create({
      ...req.body,
      ip_address: req.ip,
      created_at: new Date()
    });
    res.json({ ok: true, complaint_id: complaint._id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/heartbeat', async (req, res) => {
  const { key, hwid, app_version } = req.body;
  if (!key || !hwid) return res.status(400).json({ error: 'Missing parameters' });
  try {
    const keyPrefix = key.substring(0, 8).toUpperCase();
    const candidate = await LicenseKey.findOne({ key_prefix: keyPrefix });
    if (!candidate) return res.status(401).json({ error: 'Invalid key' });

    await Activation.findOneAndUpdate(
      { license_key_id: candidate._id, hwid },
      { $set: { last_heartbeat: new Date(), app_version, is_active: true } },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/performance', async (req, res) => {
  try {
    await PerformanceMetric.create({
      ...req.body,
      recorded_at: new Date()
    });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------------------------------------------------------------------
// Admin Routes (require x-admin-key)
// ---------------------------------------------------------------------------

app.get('/admin/stats', requireAdminKey, async (req, res) => {
  try {
    const [totalKeys, activeKeys, expiredKeys, revokedKeys, activeSessions, pendingOrders, totalOrders] = await Promise.all([
      LicenseKey.countDocuments(),
      LicenseKey.countDocuments({ is_active: true, is_banned: false }),
      LicenseKey.countDocuments({ expires_at: { $lt: new Date() }, expires_at: { $ne: null } }),
      LicenseKey.countDocuments({ is_active: false }),
      Activation.countDocuments({ is_active: true }),
      Order.countDocuments({ status: 'pending' }),
      Order.countDocuments()
    ]);

    res.json({
      totalKeys, activeKeys, expiredKeys, revokedKeys,
      activeSessions, pendingOrders, totalOrders
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/admin/keys', requireAdminKey, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const skip = parseInt(req.query.skip) || 0;
    const keys = await LicenseKey.find().sort({ created_at: -1 }).limit(limit).skip(skip).lean();
    res.json({ keys });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/admin/generate-key', requireAdminKey, async (req, res) => {
  const { tier, label, duration_days } = req.body;
  if (!tier) return res.status(400).json({ error: 'Tier required' });
  
  try {
    const rand = crypto.randomBytes(16).toString('hex').toUpperCase();
    const rawKey = 'VC-' + rand.slice(0, 8) + '-' + rand.slice(8, 24);
    const hash = await bcrypt.hash(rawKey, 10);
    
    let expiresAt = null;
    if (duration_days > 0) {
      expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + duration_days);
    }

    const keyDoc = await LicenseKey.create({
      key_prefix: rawKey.slice(0, 8).toUpperCase(),
      key_hash: hash,
      tier,
      label: label || 'Generated via Admin',
      expires_at: expiresAt,
      created_at: new Date()
    });

    res.json({ ok: true, key: rawKey, key_id: keyDoc._id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/admin/revoke-key', requireAdminKey, async (req, res) => {
  const { key_id } = req.body;
  try {
    await LicenseKey.findByIdAndUpdate(key_id, { is_active: false });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/admin/ban-key', requireAdminKey, async (req, res) => {
  const { key_id } = req.body;
  try {
    await LicenseKey.findByIdAndUpdate(key_id, { is_active: false, is_banned: true });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/admin/unbind-hwid', requireAdminKey, async (req, res) => {
  const { key_id } = req.body;
  try {
    await LicenseKey.findByIdAndUpdate(key_id, { hwid: null });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/admin/delete-key', requireAdminKey, async (req, res) => {
  const { key_id } = req.body;
  try {
    await LicenseKey.findByIdAndDelete(key_id);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/admin/adjust-key-duration', requireAdminKey, async (req, res) => {
  const { key_id, days } = req.body;
  try {
    const key = await LicenseKey.findById(key_id);
    if (!key) return res.status(404).json({ error: 'Key not found' });
    
    if (key.expires_at) {
      key.expires_at = new Date(key.expires_at.getTime() + (days * 24 * 60 * 60 * 1000));
      await key.save();
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/admin/pin-hwid', requireAdminKey, (req, res) => {
  res.json({ ok: true, message: 'HWID pinning updated' });
});

app.get('/admin/orders', requireAdminKey, async (req, res) => {
  try {
    const { status } = req.query;
    const filter = status ? { status } : {};
    const orders = await Order.find(filter).sort({ created_at: -1 }).lean();
    res.json({ orders });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/admin/update-order', requireAdminKey, async (req, res) => {
  const { order_id, status } = req.body;
  try {
    await Order.findByIdAndUpdate(order_id, { status, completed_at: status === 'completed' ? new Date() : null });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/admin/complaints', requireAdminKey, async (req, res) => {
  try {
    const { status } = req.query;
    const filter = status && status !== 'all' ? { status } : {};
    const complaints = await Complaint.find(filter).sort({ created_at: -1 }).lean();
    res.json({ complaints });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/admin/update-complaint', requireAdminKey, async (req, res) => {
  const { complaint_id, status, reply } = req.body;
  try {
    const update = { status };
    if (reply) {
      update.admin_reply = reply;
      if (status === 'open') update.status = 'in_progress';
    }
    await Complaint.findByIdAndUpdate(complaint_id, update);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/admin/update-pricing', requireAdminKey, async (req, res) => {
  try {
    await ServerConfig.findOneAndUpdate(
      { key: 'pricing' },
      { $set: { value: req.body, updated_at: new Date() } },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/admin/current-version', requireAdminKey, (req, res) => {
  res.json({ version: MINIMUM_VERSION });
});

app.post('/admin/publish-version', requireAdminKey, async (req, res) => {
  const { version, is_mandatory, release_notes } = req.body;
  try {
    await AppVersion.updateMany({}, { is_active: false });
    await AppVersion.create({ 
      version, 
      is_mandatory: is_mandatory || false,
      release_notes: release_notes || `Version ${version} published by admin.`,
      is_active: true, 
      released_at: new Date(), 
      download_url: MANDATORY_DOWNLOAD_URL 
    });
    await syncVersion();
    res.json({ ok: true, version });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ---------------------------------------------------------------------------
// Background Tasks
// ---------------------------------------------------------------------------
connectDB();
setInterval(syncVersion, 60000);
cron.schedule('*/5 * * * *', async () => {
  const threshold = new Date(Date.now() - 300000);
  await Activation.updateMany({ last_heartbeat: { $lt: threshold } }, { $set: { is_active: false } });
});

// ---------------------------------------------------------------------------
// SERVER START (Instant & Direct for Railway)
// ---------------------------------------------------------------------------
app.listen(PORT, '0.0.0.0', () => {
    console.log(`============================================`);
    console.log(` VALORANT COMPANION BACKEND (v1.1.11)`);
    console.log(` Listening on : http://0.0.0.0:${PORT}`);
    console.log(` Environment  : Railway Production`);
    console.log(` Status       : Root /health & / OK`);
    console.log(`============================================`);
});