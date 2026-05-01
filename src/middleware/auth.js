'use strict';
// ── ValorantCompanion — Auth Middleware ──────────────────────────────────────
const crypto = require('crypto');

/**
 * Timing-safe admin key comparison using crypto.timingSafeEqual.
 * Prevents timing-attack enumeration of the admin key.
 */
function timingSafeCompare(a, b) {
  try {
    const bufA = Buffer.from(String(a), 'utf8');
    const bufB = Buffer.from(String(b), 'utf8');
    if (bufA.length !== bufB.length) {
      // Still do a comparison to consume constant time
      crypto.timingSafeEqual(bufA, bufA);
      return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Express middleware — validates x-admin-key header using timing-safe comparison.
 * Falls back to body.admin_key and query.key.
 */
function requireAdminKey(req, res, next) {
  const provided = req.headers['x-admin-key'] || req.body?.admin_key || req.query.key;
  const expected = process.env.ADMIN_API_KEY;

  if (!expected) {
    console.error('[Auth] ADMIN_API_KEY not set in environment!');
    return res.status(500).json({ error: 'server_misconfigured', message: 'Admin key not configured' });
  }

  if (!provided || !timingSafeCompare(provided, expected)) {
    // Log failed attempt (sanitize IP)
    console.warn(`[Auth] Admin auth failure from ${req.ip} — path: ${req.path}`);
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Invalid or missing Admin API Key',
    });
  }

  next();
}

module.exports = { requireAdminKey, timingSafeCompare };
