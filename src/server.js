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
let MINIMUM_VERSION = '1.1.9';
let LATEST_VERSION  = '1.1.9';
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

// Admin Routes Aliases
app.post('/admin/publish-version', requireAdminKey, async (req, res) => {
  const { version } = req.body;
  await AppVersion.updateMany({}, { is_active: false });
  await AppVersion.create({ version, is_active: true, released_at: new Date(), download_url: MANDATORY_DOWNLOAD_URL });
  await syncVersion();
  res.json({ ok: true, version });
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
    console.log(` VALORANT COMPANION BACKEND (v1.1.9)`);
    console.log(` Listening on : http://0.0.0.0:${PORT}`);
    console.log(` Environment  : Railway Production`);
    console.log(` Status       : Root /health & / OK`);
    console.log(`============================================`);
});