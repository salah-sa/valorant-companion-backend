'use strict';
// ── ValorantCompanion Backend — Production Server v1.1.12 ───────────────────
// Refactored: modular routes, timing-safe auth, input validation, error handling

require('dotenv').config({ path: require('path').join(__dirname, '../config/.env') });

const express   = require('express');
const mongoose  = require('mongoose');
const helmet    = require('helmet');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const crypto    = require('crypto');
const cron      = require('node-cron');
const bcrypt    = require('bcryptjs');

const { LicenseKey, Activation, AppVersion, ServerConfig } = require('./models');
const { createVersionGate } = require('./middleware/versionGate');
const { notFoundHandler, errorHandler } = require('./middleware/errorHandler');
const clientRoutes = require('./routes/client');
const adminRoutes  = require('./routes/admin');

// ── Application Instance ──────────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3000;

// ── Server State (shared via app.locals for routes) ──────────────────────────
let MINIMUM_VERSION   = '1.1.12';
let LATEST_VERSION    = '1.1.12';
let MAINTENANCE_MODE  = false;
let WELCOME_MESSAGE   = 'Welcome to Valorant Companion — Built by ENG Salah Mohamed.';
const DOWNLOAD_URL    = process.env.DOWNLOAD_URL || 'https://sasa120120.itch.io/valorant-companion-app';

// Expose getters via app.locals (used by route modules)
app.locals.getMinVersion  = () => MINIMUM_VERSION;
app.locals.getDownloadUrl = () => DOWNLOAD_URL;

// ── Security Middleware ───────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // Desktop client API — no browser CSP needed
}));

// CORS: Restrict to known origins in production
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : null;

app.use(cors({
  origin: (origin, callback) => {
    // Desktop app sends no Origin header — allow null/undefined
    if (!origin) return callback(null, true);
    if (!allowedOrigins || allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: Origin ${origin} not allowed`));
  },
  methods: ['GET', 'POST'],
}));

app.use(express.json({ limit: '16kb' }));
app.set('trust proxy', 1);

// ── Global Rate Limiter (fallback) ────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 30_000,
  max:      parseInt(process.env.RATE_LIMIT_MAX) || 60,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: 'rate_limited', message: 'Too many requests. Please slow down.' },
});
app.use(globalLimiter);

// ── Request Logger (health/ping only) ────────────────────────────────────────
app.use((req, res, next) => {
  if (req.path === '/health' || req.path === '/ping') {
    const v = req.headers['x-app-version'] || 'unknown';
    console.log(`[Handshake] ${req.method} ${req.path} — IP: ${req.ip} — v${v}`);
  }
  next();
});

// ── Welcome Message Injection ─────────────────────────────────────────────────
// Only inject on non-error, non-binary responses
app.use((req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    if (body && typeof body === 'object' && !Array.isArray(body) && res.statusCode < 400) {
      body.welcome_message = WELCOME_MESSAGE;
    }
    return originalJson(body);
  };
  next();
});

// ── Maintenance Mode Gate ─────────────────────────────────────────────────────
app.use((req, res, next) => {
  if (MAINTENANCE_MODE && req.path !== '/health' && req.path !== '/ping') {
    return res.status(503).json({
      error:   'maintenance',
      message: 'Server is under maintenance. Please try again later.',
    });
  }
  next();
});

// ── Version Gate Middleware ───────────────────────────────────────────────────
app.use(createVersionGate(() => MINIMUM_VERSION, () => DOWNLOAD_URL));

// ── Health / Ping ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStatus = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };
  res.json({
    status:      'ok',
    db:          dbStatus[dbState] || 'unknown',
    maintenance: MAINTENANCE_MODE,
    version:     MINIMUM_VERSION,
    uptime:      Math.floor(process.uptime()),
  });
});

app.get('/ping', (req, res) => {
  res.json({ ok: true, version: MINIMUM_VERSION, ts: Date.now() });
});

// ── Route Modules ─────────────────────────────────────────────────────────────
app.use('/', clientRoutes);     // /pricing, /check-update, /validate-key, /heartbeat, etc.
app.use('/admin', adminRoutes); // /admin/stats, /admin/keys, etc.

// ── 404 & Error Handlers ──────────────────────────────────────────────────────
app.use(notFoundHandler);
app.use(errorHandler);

// ── Database Seeder ───────────────────────────────────────────────────────────
async function seedDatabase() {
  try {
    const count = await LicenseKey.countDocuments();
    if (count === 0) {
      console.log('[Seeder] Empty DB — creating default admin key...');
      const rand   = crypto.randomBytes(16).toString('hex').toUpperCase();
      const rawKey = 'VA-' + rand.slice(0, 8) + '-' + rand.slice(8, 24);
      const hash   = await bcrypt.hash(rawKey, 10);

      await LicenseKey.create({
        key_prefix: rawKey.slice(0, 8).toUpperCase(),
        key_hash:   hash,
        tier:       'admin',
        label:      'AUTO-GENERATED ADMIN',
        expires_at: null,
      });

      console.log('[Seeder] ===================================');
      console.log('[Seeder] DEFAULT ADMIN KEY: ' + rawKey);
      console.log('[Seeder] Save this — it will NOT be shown again.');
      console.log('[Seeder] ===================================');
    }
  } catch (err) {
    console.error('[Seeder] Failed:', err.message);
  }
}

// ── Version Sync ──────────────────────────────────────────────────────────────
async function syncVersion() {
  try {
    const config = await AppVersion.findOne({ is_active: true }).sort({ released_at: -1 }).lean();
    if (config?.version) {
      MINIMUM_VERSION = config.version;
      LATEST_VERSION  = config.version;
    }

    const welcome = await ServerConfig.findOne({ key: 'welcome_message' }).lean();
    if (welcome?.value) {
      WELCOME_MESSAGE = welcome.value;
      app.locals.welcomeMessage = welcome.value;
    }

    const maint = await ServerConfig.findOne({ key: 'maintenance_mode' }).lean();
    MAINTENANCE_MODE = maint?.value === true;

  } catch (err) {
    console.warn('[SyncVersion] Fallback — using in-memory version:', MINIMUM_VERSION);
  }
}

// Expose syncVersion for admin routes
app.locals.syncVersion = syncVersion;

// ── Database Connection ───────────────────────────────────────────────────────
async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
    });
    console.log('[MongoDB] Connected');
    await seedDatabase();
    await syncVersion();
  } catch (err) {
    console.error('[MongoDB] Connection failed:', err.message);
    // Non-fatal: server still responds; DB ops will fail gracefully
  }
}

// ── Background Jobs ───────────────────────────────────────────────────────────
// Session cleanup: mark stale sessions inactive
const HEARTBEAT_TIMEOUT = parseInt(process.env.HEARTBEAT_TIMEOUT_SECONDS || '180') * 1000;

cron.schedule('*/5 * * * *', async () => {
  try {
    const threshold = new Date(Date.now() - HEARTBEAT_TIMEOUT);
    const result = await Activation.updateMany(
      { last_heartbeat: { $lt: threshold }, is_active: true },
      { $set: { is_active: false } }
    );
    if (result.modifiedCount > 0) {
      console.log(`[Cron] Deactivated ${result.modifiedCount} stale sessions`);
    }
  } catch (err) {
    console.error('[Cron] Session cleanup error:', err.message);
  }
});

// Version sync every 60 seconds
const versionSyncInterval = setInterval(syncVersion, 60_000);

// ── Graceful Shutdown ─────────────────────────────────────────────────────────
process.on('SIGTERM', async () => {
  console.log('[Server] SIGTERM received — shutting down gracefully...');
  clearInterval(versionSyncInterval);
  await mongoose.connection.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('[Server] SIGINT received — shutting down...');
  clearInterval(versionSyncInterval);
  await mongoose.connection.close();
  process.exit(0);
});

// ── Start Server ──────────────────────────────────────────────────────────────
connectDB();

app.listen(PORT, '0.0.0.0', () => {
  console.log('============================================');
  console.log(` VALORANT COMPANION BACKEND  v${MINIMUM_VERSION}`);
  console.log(` Port       : ${PORT}`);
  console.log(` Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(` Routes     : /health /ping /validate-key /admin/*`);
  console.log('============================================');
});