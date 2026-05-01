'use strict';
// ── ValorantCompanion — Admin Routes ─────────────────────────────────────────

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');
const bcrypt  = require('bcryptjs');

const { LicenseKey, Activation, Order, Complaint, AppVersion, ServerConfig, PerformanceMetric } = require('../models');
const { requireAdminKey } = require('../middleware/auth');
const { asyncHandler }    = require('../middleware/errorHandler');
const { validateGenerateKey, sanitize } = require('../middleware/validation');

// Apply admin auth to ALL routes in this router
router.use(requireAdminKey);

// ── GET /admin/stats ──────────────────────────────────────────────────────────
router.get('/stats', asyncHandler(async (req, res) => {
  const now = new Date();
  const [
    totalKeys,
    activeKeys,
    expiredKeys,
    revokedKeys,
    activeSessions,
    pendingOrders,
    totalOrders,
    openComplaints,
  ] = await Promise.all([
    LicenseKey.countDocuments(),
    LicenseKey.countDocuments({ is_active: true, is_banned: false }),
    LicenseKey.countDocuments({
      expires_at: { $lt: now, $ne: null },
      is_active:  true,
    }),
    LicenseKey.countDocuments({ is_active: false }),
    Activation.countDocuments({ is_active: true }),
    Order.countDocuments({ status: 'pending' }),
    Order.countDocuments(),
    Complaint.countDocuments({ status: 'open' }),
  ]);

  res.json({
    totalKeys, activeKeys, expiredKeys, revokedKeys,
    activeSessions, pendingOrders, totalOrders, openComplaints,
  });
}));

// ── GET /admin/keys ───────────────────────────────────────────────────────────
router.get('/keys', asyncHandler(async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit) || 50, 200);
  const skip   = parseInt(req.query.skip) || 0;
  const search = sanitize(req.query.search, 50);

  const filter = search
    ? { $or: [{ label: new RegExp(search, 'i') }, { key_prefix: new RegExp(search, 'i') }] }
    : {};

  const [keys, total] = await Promise.all([
    LicenseKey.find(filter)
      .select('-key_hash')  // Never expose hash
      .sort({ created_at: -1 })
      .limit(limit)
      .skip(skip)
      .lean(),
    LicenseKey.countDocuments(filter),
  ]);

  res.json({ keys, total, limit, skip });
}));

// ── POST /admin/generate-key ──────────────────────────────────────────────────
router.post('/generate-key', validateGenerateKey, asyncHandler(async (req, res) => {
  const { tier, label, duration_days } = req.body;

  const rand   = crypto.randomBytes(16).toString('hex').toUpperCase();
  const rawKey = 'VC-' + rand.slice(0, 8) + '-' + rand.slice(8, 24);
  const hash   = await bcrypt.hash(rawKey, 10);

  let expiresAt = null;
  const days = parseInt(duration_days);
  if (!isNaN(days) && days > 0) {
    expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + days);
  }

  const keyDoc = await LicenseKey.create({
    key_prefix:  rawKey.slice(0, 8).toUpperCase(),
    key_hash:    hash,
    tier:        tier.toLowerCase(),
    label:       label,
    expires_at:  expiresAt,
    created_at:  new Date(),
  });

  res.json({ ok: true, key: rawKey, key_id: keyDoc._id, expires_at: expiresAt });
}));

// ── POST /admin/revoke-key ────────────────────────────────────────────────────
router.post('/revoke-key', asyncHandler(async (req, res) => {
  const { key_id } = req.body;
  if (!key_id) return res.status(400).json({ error: 'invalid_request', message: 'key_id required' });
  await LicenseKey.findByIdAndUpdate(key_id, { $set: { is_active: false } });
  res.json({ ok: true });
}));

// ── POST /admin/ban-key ───────────────────────────────────────────────────────
router.post('/ban-key', asyncHandler(async (req, res) => {
  const { key_id } = req.body;
  if (!key_id) return res.status(400).json({ error: 'invalid_request', message: 'key_id required' });
  await LicenseKey.findByIdAndUpdate(key_id, { $set: { is_active: false, is_banned: true } });
  res.json({ ok: true });
}));

// ── POST /admin/unban-key ─────────────────────────────────────────────────────
router.post('/unban-key', asyncHandler(async (req, res) => {
  const { key_id } = req.body;
  if (!key_id) return res.status(400).json({ error: 'invalid_request', message: 'key_id required' });
  await LicenseKey.findByIdAndUpdate(key_id, { $set: { is_active: true, is_banned: false } });
  res.json({ ok: true });
}));

// ── POST /admin/unbind-hwid ───────────────────────────────────────────────────
router.post('/unbind-hwid', asyncHandler(async (req, res) => {
  const { key_id } = req.body;
  if (!key_id) return res.status(400).json({ error: 'invalid_request', message: 'key_id required' });
  await LicenseKey.findByIdAndUpdate(key_id, { $set: { hwid: null } });
  await Activation.updateMany({ license_key_id: key_id }, { $set: { is_active: false } });
  res.json({ ok: true });
}));

// ── POST /admin/delete-key ────────────────────────────────────────────────────
router.post('/delete-key', asyncHandler(async (req, res) => {
  const { key_id } = req.body;
  if (!key_id) return res.status(400).json({ error: 'invalid_request', message: 'key_id required' });
  await LicenseKey.findByIdAndDelete(key_id);
  await Activation.deleteMany({ license_key_id: key_id });
  res.json({ ok: true });
}));

// ── POST /admin/adjust-key-duration ──────────────────────────────────────────
router.post('/adjust-key-duration', asyncHandler(async (req, res) => {
  const { key_id, days } = req.body;
  if (!key_id) return res.status(400).json({ error: 'invalid_request', message: 'key_id required' });

  const d = parseInt(days);
  if (isNaN(d) || Math.abs(d) > 3650) {
    return res.status(400).json({ error: 'invalid_request', message: 'days must be within ±3650' });
  }

  const key = await LicenseKey.findById(key_id);
  if (!key) return res.status(404).json({ error: 'not_found', message: 'Key not found' });

  if (key.expires_at) {
    key.expires_at = new Date(key.expires_at.getTime() + (d * 24 * 60 * 60 * 1000));
    await key.save();
  }

  res.json({ ok: true, new_expires_at: key.expires_at });
}));

// ── GET /admin/orders ─────────────────────────────────────────────────────────
router.get('/orders', asyncHandler(async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit) || 100, 500);
  const skip   = parseInt(req.query.skip) || 0;
  const status = sanitize(req.query.status, 20);
  const filter = (status && status !== 'all') ? { status } : {};

  const [orders, total] = await Promise.all([
    Order.find(filter).sort({ created_at: -1 }).limit(limit).skip(skip).lean(),
    Order.countDocuments(filter),
  ]);

  res.json({ orders, total });
}));

// ── POST /admin/update-order ──────────────────────────────────────────────────
router.post('/update-order', asyncHandler(async (req, res) => {
  const { order_id, status, admin_note, license_key_issued } = req.body;
  if (!order_id) return res.status(400).json({ error: 'invalid_request', message: 'order_id required' });

  const VALID_STATUSES = ['pending', 'completed', 'failed', 'refunded'];
  if (status && !VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: 'invalid_request', message: 'Invalid status' });
  }

  const update = {};
  if (status) {
    update.status = status;
    if (status === 'completed') update.completed_at = new Date();
  }
  if (admin_note !== undefined) update.admin_note = sanitize(admin_note, 500);
  if (license_key_issued !== undefined) update.license_key_issued = sanitize(license_key_issued, 100);

  await Order.findByIdAndUpdate(order_id, { $set: update });
  res.json({ ok: true });
}));

// ── GET /admin/complaints ─────────────────────────────────────────────────────
router.get('/complaints', asyncHandler(async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit) || 100, 500);
  const skip   = parseInt(req.query.skip) || 0;
  const status = sanitize(req.query.status, 20);
  const filter = (status && status !== 'all') ? { status } : {};

  const [complaints, total] = await Promise.all([
    Complaint.find(filter).sort({ created_at: -1 }).limit(limit).skip(skip).lean(),
    Complaint.countDocuments(filter),
  ]);

  res.json({ complaints, total });
}));

// ── POST /admin/update-complaint ──────────────────────────────────────────────
router.post('/update-complaint', asyncHandler(async (req, res) => {
  const { complaint_id, status, reply } = req.body;
  if (!complaint_id) return res.status(400).json({ error: 'invalid_request', message: 'complaint_id required' });

  const VALID_STATUSES = ['open', 'in_progress', 'resolved', 'closed'];
  if (status && !VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: 'invalid_request', message: 'Invalid status' });
  }

  const update = {};
  if (status) update.status = status;
  if (reply) {
    update.admin_reply = sanitize(reply, 2000);
    if (status === 'open') update.status = 'in_progress';
  }
  if (status === 'resolved') update.resolved_at = new Date();

  await Complaint.findByIdAndUpdate(complaint_id, { $set: update });
  res.json({ ok: true });
}));

// ── GET /admin/activations ────────────────────────────────────────────────────
router.get('/activations', asyncHandler(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const skip  = parseInt(req.query.skip) || 0;

  const activations = await Activation.find()
    .populate('license_key_id', 'key_prefix tier label')
    .sort({ last_heartbeat: -1 })
    .limit(limit)
    .skip(skip)
    .lean();

  res.json({ activations });
}));

// ── POST /admin/update-pricing ────────────────────────────────────────────────
router.post('/update-pricing', asyncHandler(async (req, res) => {
  const allowed = ['daily_egp', 'daily_usd', 'weekly_egp', 'weekly_usd', 'monthly_egp', 'monthly_usd'];
  const value = {};
  for (const field of allowed) {
    if (req.body[field] !== undefined) value[field] = String(req.body[field]).slice(0, 20);
  }

  await ServerConfig.findOneAndUpdate(
    { key: 'pricing' },
    { $set: { value, updated_at: new Date() } },
    { upsert: true }
  );
  res.json({ ok: true });
}));

// ── GET /admin/current-version ────────────────────────────────────────────────
router.get('/current-version', (req, res) => {
  res.json({ version: req.app.locals.getMinVersion() });
});

// ── POST /admin/publish-version ───────────────────────────────────────────────
router.post('/publish-version', asyncHandler(async (req, res) => {
  const { version, is_mandatory, release_notes } = req.body;
  if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
    return res.status(400).json({ error: 'invalid_request', message: 'Valid semver version required (e.g. 1.2.3)' });
  }

  await AppVersion.updateMany({}, { $set: { is_active: false } });
  await AppVersion.findOneAndUpdate(
    { version },
    {
      $set: {
        version,
        is_mandatory:  is_mandatory === true,
        release_notes: sanitize(release_notes, 2000) || `Version ${version} published by admin.`,
        is_active:     true,
        released_at:   new Date(),
        download_url:  process.env.DOWNLOAD_URL || 'https://sasa120120.itch.io/valorant-companion-app',
      },
    },
    { upsert: true }
  );

  // Trigger version sync
  await req.app.locals.syncVersion();

  res.json({ ok: true, version });
}));

// ── POST /admin/set-welcome-message ──────────────────────────────────────────
router.post('/set-welcome-message', asyncHandler(async (req, res) => {
  const { message } = req.body;
  const clean = sanitize(message, 500);
  await ServerConfig.findOneAndUpdate(
    { key: 'welcome_message' },
    { $set: { value: clean, updated_at: new Date() } },
    { upsert: true }
  );
  req.app.locals.welcomeMessage = clean;
  res.json({ ok: true });
}));

// ── GET /admin/performance ────────────────────────────────────────────────────
router.get('/performance', asyncHandler(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const hwid  = sanitize(req.query.hwid, 128);
  const filter = hwid ? { hwid } : {};

  const metrics = await PerformanceMetric.find(filter)
    .sort({ recorded_at: -1 })
    .limit(limit)
    .lean();

  res.json({ metrics });
}));

// ── POST /admin/pin-hwid (stub) ───────────────────────────────────────────────
router.post('/pin-hwid', (req, res) => {
  res.json({ ok: true, message: 'HWID pinning updated' });
});

module.exports = router;
