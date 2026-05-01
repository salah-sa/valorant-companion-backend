'use strict';
// ── ValorantCompanion — Input Validation Middleware ──────────────────────────

const crypto = require('crypto');

// ── Sanitize string fields ──
function sanitize(val, maxLen = 500) {
  if (val === null || val === undefined) return '';
  return String(val).trim().slice(0, maxLen);
}

// ── Validate key format ──
function isValidKeyFormat(key) {
  if (!key || typeof key !== 'string') return false;
  const clean = key.trim().toUpperCase();
  // Formats: VC-XXXXXXXX-XXXXXXXXXXXXXXXX or VA-XXXXXXXX-XXXXXXXXXXXXXXXX
  return /^(VC|VA)-[A-F0-9]{8}-[A-F0-9]{16}$/.test(clean);
}

// ── Validate HWID format ──
function isValidHwid(hwid) {
  if (!hwid || typeof hwid !== 'string') return false;
  const clean = hwid.trim();
  return clean.length >= 10 && clean.length <= 128;
}

// ── Validate version format ──
function isValidVersion(ver) {
  if (!ver || typeof ver !== 'string') return false;
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ver.replace(/^v/, ''));
}

// ── Validate tier ──
const VALID_TIERS = ['standard', 'pro', 'lifetime', 'admin'];
function isValidTier(tier) {
  return VALID_TIERS.includes(String(tier).toLowerCase());
}

// ── Middleware: validate /validate-key ──
function validateKeyRequest(req, res, next) {
  const { key, hwid } = req.body;
  if (!key || typeof key !== 'string') {
    return res.status(400).json({ error: 'invalid_request', message: 'License key is required' });
  }
  if (!isValidKeyFormat(key)) {
    return res.status(400).json({ error: 'invalid_format', message: 'Invalid license key format' });
  }
  if (!hwid || !isValidHwid(hwid)) {
    return res.status(400).json({ error: 'invalid_request', message: 'Valid HWID is required' });
  }
  req.body.key = key.trim().toUpperCase();
  req.body.hwid = hwid.trim();
  next();
}

// ── Middleware: validate /heartbeat ──
function validateHeartbeat(req, res, next) {
  const { key, hwid } = req.body;
  if (!key || !isValidKeyFormat(key)) {
    return res.status(400).json({ error: 'invalid_request', message: 'Valid license key required' });
  }
  if (!hwid || !isValidHwid(hwid)) {
    return res.status(400).json({ error: 'invalid_request', message: 'Valid HWID required' });
  }
  req.body.key = key.trim().toUpperCase();
  req.body.hwid = hwid.trim();
  next();
}

// ── Middleware: validate /submit-order ──
function validateOrder(req, res, next) {
  const { user_name, phone_number, plan } = req.body;
  if (!user_name || sanitize(user_name).length < 2) {
    return res.status(400).json({ error: 'invalid_request', message: 'Valid name is required' });
  }
  if (!phone_number || sanitize(phone_number).length < 6) {
    return res.status(400).json({ error: 'invalid_request', message: 'Valid phone number is required' });
  }
  const validPlans = ['daily', 'weekly', 'monthly'];
  if (!plan || !validPlans.includes(plan)) {
    return res.status(400).json({ error: 'invalid_request', message: 'Plan must be daily, weekly, or monthly' });
  }
  // Whitelist allowed fields — prevent mass assignment
  req.sanitizedOrder = {
    user_name:    sanitize(user_name, 100),
    phone_number: sanitize(phone_number, 20),
    email:        sanitize(req.body.email, 100),
    country:      sanitize(req.body.country, 60),
    plan:         plan,
    hwid:         sanitize(req.body.hwid, 128),
    machine_name: sanitize(req.body.machine_name, 100),
    os_version:   sanitize(req.body.os_version, 100),
  };
  next();
}

// ── Middleware: validate /submit-complaint ──
function validateComplaint(req, res, next) {
  const { subject, message } = req.body;
  if (!subject || sanitize(subject).length < 3) {
    return res.status(400).json({ error: 'invalid_request', message: 'Subject is required (min 3 chars)' });
  }
  if (!message || sanitize(message).length < 10) {
    return res.status(400).json({ error: 'invalid_request', message: 'Message is required (min 10 chars)' });
  }
  // Whitelist allowed fields
  req.sanitizedComplaint = {
    subject:     sanitize(subject, 200),
    message:     sanitize(message, 2000),
    category:    sanitize(req.body.category, 60) || 'General',
    hwid:        sanitize(req.body.hwid, 128),
    app_version: sanitize(req.body.app_version, 20),
  };
  next();
}

// ── Admin: validate generate-key ──
function validateGenerateKey(req, res, next) {
  const { tier, label, duration_days } = req.body;
  if (!tier || !isValidTier(tier)) {
    return res.status(400).json({ error: 'invalid_request', message: 'Valid tier required (standard, pro, lifetime, admin)' });
  }
  if (duration_days !== undefined && duration_days !== null) {
    const days = parseInt(duration_days);
    if (isNaN(days) || days < 0 || days > 3650) {
      return res.status(400).json({ error: 'invalid_request', message: 'duration_days must be 0–3650' });
    }
    req.body.duration_days = days;
  }
  req.body.label = sanitize(label, 200) || 'Generated via Admin';
  next();
}

module.exports = {
  validateKeyRequest,
  validateHeartbeat,
  validateOrder,
  validateComplaint,
  validateGenerateKey,
  sanitize,
  isValidKeyFormat,
  isValidHwid,
  isValidVersion,
};
