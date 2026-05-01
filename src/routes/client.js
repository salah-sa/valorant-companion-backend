'use strict';
// ── ValorantCompanion — Client Routes ────────────────────────────────────────

const express  = require('express');
const rateLimit = require('express-rate-limit');
const router   = express.Router();

const { LicenseKey, Activation, Order, Complaint, PerformanceMetric, ServerConfig } = require('../models');
const { asyncHandler } = require('../middleware/errorHandler');
const { validateKeyRequest, validateHeartbeat, validateOrder, validateComplaint } = require('../middleware/validation');
const bcrypt = require('bcryptjs');

// ── Per-endpoint rate limits ──────────────────────────────────────────────────
const keyValidationLimit = rateLimit({
  windowMs: 5 * 60 * 1000,  // 5 minutes
  max: 10,                    // 10 attempts per 5 min
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'rate_limited', message: 'Too many validation attempts. Please wait 5 minutes.' },
  skipSuccessfulRequests: true, // Only count failed attempts
});

const heartbeatLimit = rateLimit({
  windowMs: 2 * 60 * 1000,  // 2 minutes
  max: 60,                    // 60 heartbeats per 2 min (one every ~2s max)
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'rate_limited', message: 'Heartbeat rate limit exceeded.' },
});

const orderLimit = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5,                    // 5 orders per 10 min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'rate_limited', message: 'Too many order submissions. Please wait.' },
});

const complaintLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,                   // 10 complaints per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'rate_limited', message: 'Too many complaint submissions. Please wait.' },
});

// ── GET /pricing ──────────────────────────────────────────────────────────────
router.get('/pricing', asyncHandler(async (req, res) => {
  const config = await ServerConfig.findOne({ key: 'pricing' }).lean();
  if (config?.value) return res.json(config.value);

  res.json({
    daily_egp:   '50',  daily_usd:   '5',
    weekly_egp:  '250', weekly_usd:  '15',
    monthly_egp: '800', monthly_usd: '40',
  });
}));

// ── GET /check-update ─────────────────────────────────────────────────────────
router.get('/check-update', asyncHandler(async (req, res) => {
  // getMinVersion injected by server.js via req.app.locals
  const minV = req.app.locals.getMinVersion();
  const downloadUrl = req.app.locals.getDownloadUrl();
  const v = (req.query.v || '0.0.0').replace(/[^0-9.]/g, '');

  const { compareVersions } = require('../middleware/versionGate');
  const needsUpdate = compareVersions(v, minV) < 0;

  res.json({
    update_available: needsUpdate,
    latest_version:   minV,
    your_version:     v,
    is_mandatory:     true,
    download_url:     downloadUrl,
  });
}));

// ── POST /validate-key ────────────────────────────────────────────────────────
router.post('/validate-key', keyValidationLimit, validateKeyRequest, asyncHandler(async (req, res) => {
  const { key, hwid } = req.body;

  const keyPrefix = key.substring(0, 8).toUpperCase();
  const candidate = await LicenseKey.findOne({
    key_prefix: keyPrefix,
    is_active:  true,
    is_banned:  false,
  });

  if (!candidate) {
    return res.status(401).json({ error: 'invalid_key', message: 'Invalid license key' });
  }

  // Check expiry
  if (candidate.expires_at && candidate.expires_at < new Date()) {
    return res.status(401).json({ error: 'key_expired', message: 'License key has expired' });
  }

  const match = await bcrypt.compare(key.trim().toUpperCase(), candidate.key_hash);
  if (!match) {
    return res.status(401).json({ error: 'invalid_key', message: 'Invalid license key' });
  }

  // Upsert activation
  await Activation.findOneAndUpdate(
    { license_key_id: candidate._id, hwid },
    { $set: { is_active: true, last_heartbeat: new Date(), ip_address: req.ip, app_version: req.headers['x-app-version'] || '' } },
    { upsert: true }
  );

  // Update last_used_at on key
  await LicenseKey.findByIdAndUpdate(candidate._id, { $set: { last_used_at: new Date() } });

  res.json({
    valid:      true,
    tier:       candidate.tier,
    label:      candidate.label,
    expires_at: candidate.expires_at,
  });
}));

// ── POST /heartbeat ───────────────────────────────────────────────────────────
router.post('/heartbeat', heartbeatLimit, validateHeartbeat, asyncHandler(async (req, res) => {
  const { key, hwid } = req.body;
  const appVersion = req.body.app_version || req.headers['x-app-version'] || '';

  const keyPrefix = key.substring(0, 8).toUpperCase();
  const candidate = await LicenseKey.findOne({ key_prefix: keyPrefix });
  if (!candidate) {
    return res.status(401).json({ error: 'invalid_key', message: 'Invalid license key' });
  }

  await Activation.findOneAndUpdate(
    { license_key_id: candidate._id, hwid },
    { $set: { last_heartbeat: new Date(), app_version: appVersion, is_active: true } },
    { upsert: true }
  );

  res.json({ ok: true });
}));

// ── GET /changelog ────────────────────────────────────────────────────────────
// Returns version history — served from DB config or built-in fallback
router.get('/changelog', asyncHandler(async (req, res) => {
  const config = await ServerConfig.findOne({ key: 'changelog' }).lean();
  if (config?.value) return res.json(config.value);

  // Fallback static changelog
  res.json([
    {
      version:      '1.1.12',
      releasedAt:   '2026-05-01T00:00:00Z',
      title:        'Production Overhaul',
      releaseNotes: 'Complete backend modularization. Security hardening with rate limiting, timing-safe auth, mass-assignment protection. 8 new services: Auto-Update, Notification Center, NQS, Config Snapshots, Quick Profiles, Server Status, Heat Map, Changelog.',
      tags:         ['Major', 'Security', 'Features'],
    },
    {
      version:      '1.1.11',
      releasedAt:   '2026-04-15T00:00:00Z',
      title:        'Stability Release',
      releaseNotes: 'Fixed heartbeat timeout logic. Improved admin dashboard performance. Resolved complaint submission validation errors.',
      tags:         ['Fix', 'Performance'],
    },
    {
      version:      '1.1.10',
      releasedAt:   '2026-04-01T00:00:00Z',
      title:        'Network Optimizer Update',
      releaseNotes: 'Added DNS flush automation. Improved route optimization algorithm. Added per-server ping monitoring.',
      tags:         ['Feature', 'Network'],
    },
  ]);
}));

// ── GET /server-status ────────────────────────────────────────────────────────
// Returns quick backend health for the client status dashboard
router.get('/server-status', asyncHandler(async (req, res) => {
  const dbState = require('mongoose').connection.readyState;
  const dbStatus = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };

  res.json({
    status:      'ok',
    version:     req.app.locals.getMinVersion(),
    db:          dbStatus[dbState] || 'unknown',
    uptime:      Math.floor(process.uptime()),
    maintenance: false,
    timestamp:   Date.now(),
  });
}));

// ── POST /submit-order ────────────────────────────────────────────────────────
router.post('/submit-order', orderLimit, validateOrder, asyncHandler(async (req, res) => {
  const PRICING_DEFAULTS = {
    daily_egp: '50', weekly_egp: '250', monthly_egp: '800',
    daily_usd: '5',  weekly_usd: '15',  monthly_usd: '40',
  };

  const config = await ServerConfig.findOne({ key: 'pricing' }).lean();
  const pricing = config?.value || PRICING_DEFAULTS;

  const plan = req.sanitizedOrder.plan;
  const priceEgp = parseInt(pricing[`${plan}_egp`]) || 0;
  const priceUsd = pricing[`${plan}_usd`] || '';

  const order = await Order.create({
    ...req.sanitizedOrder,
    price_egp:  priceEgp,
    price_usd:  priceUsd,
    ip_address: req.ip,
    created_at: new Date(),
  });

  res.json({ ok: true, order_id: order._id });
}));

// ── POST /submit-complaint ────────────────────────────────────────────────────
router.post('/submit-complaint', complaintLimit, validateComplaint, asyncHandler(async (req, res) => {
  const complaint = await Complaint.create({
    ...req.sanitizedComplaint,
    ip_address: req.ip,
    created_at: new Date(),
  });

  res.json({ ok: true, complaint_id: complaint._id });
}));

// ── POST /performance ─────────────────────────────────────────────────────────
router.post('/performance', asyncHandler(async (req, res) => {
  // Whitelist performance fields
  const { hwid, fps_avg, fps_min, fps_max, ping_avg, cpu_avg, ram_avg, app_version, map_name, agent_name } = req.body;

  if (!hwid || typeof hwid !== 'string') {
    return res.status(400).json({ error: 'invalid_request', message: 'HWID is required' });
  }

  await PerformanceMetric.create({
    hwid:        String(hwid).trim().slice(0, 128),
    fps_avg:     Number(fps_avg) || 0,
    fps_min:     Number(fps_min) || 0,
    fps_max:     Number(fps_max) || 0,
    ping_avg:    Number(ping_avg) || 0,
    cpu_avg:     Number(cpu_avg) || 0,
    ram_avg:     Number(ram_avg) || 0,
    app_version: String(app_version || '').slice(0, 20),
    map_name:    String(map_name || '').slice(0, 60),
    agent_name:  String(agent_name || '').slice(0, 60),
    recorded_at: new Date(),
  });

  res.json({ ok: true });
}));

module.exports = router;
