'use strict';
// ── ValorantCompanion — Version Gate Middleware ──────────────────────────────

const EXEMPT_PATHS = ['/health', '/ping', '/check-update', '/pricing', '/admin'];

/**
 * Compares two semver strings.
 * Returns: 1 if v1 > v2, -1 if v1 < v2, 0 if equal.
 */
function compareVersions(v1, v2) {
  const p1 = v1.replace(/^v/, '').split('.').map(Number);
  const p2 = v2.replace(/^v/, '').split('.').map(Number);
  for (let i = 0; i < Math.max(p1.length, p2.length); i++) {
    const a = p1[i] || 0;
    const b = p2[i] || 0;
    if (a > b) return 1;
    if (a < b) return -1;
  }
  return 0;
}

/**
 * Creates version gate middleware with a getter for the current minimum version.
 * Rejects clients below the minimum version with HTTP 426 Upgrade Required.
 */
function createVersionGate(getMinVersion, getDownloadUrl) {
  return (req, res, next) => {
    if (EXEMPT_PATHS.some(p => req.path.startsWith(p))) return next();

    const clientV = (req.headers['x-app-version'] || req.body?.app_version || '0.0.0')
      .replace(/[^0-9.]/g, '');
    const minV = getMinVersion();

    if (compareVersions(clientV, minV) < 0) {
      return res.status(426).json({
        error: 'update_required',
        code:  'VERSION_OUTDATED',
        message: `Your app version (${clientV || '0.0.0'}) is outdated. Please update to v${minV}.`,
        your_version:   clientV || '0.0.0',
        minimum_version: minV,
        download_url:   getDownloadUrl(),
      });
    }
    next();
  };
}

module.exports = { compareVersions, createVersionGate };
