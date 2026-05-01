'use strict';
// ── ValorantCompanion — Error Handling Middleware ────────────────────────────

/**
 * 404 handler — must be registered after all routes.
 */
function notFoundHandler(req, res) {
  res.status(404).json({
    error: 'not_found',
    message: `Route ${req.method} ${req.path} not found`,
  });
}

/**
 * Global error handler — must be registered last with 4 parameters.
 */
function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  const status  = err.status || err.statusCode || 500;
  const message = err.message || 'Internal server error';

  // Don't leak stack traces in production
  const isDev = process.env.NODE_ENV !== 'production';

  console.error(`[Error] ${status} ${req.method} ${req.path} — ${message}`);
  if (isDev && err.stack) console.error(err.stack);

  res.status(status).json({
    error:   err.code || 'server_error',
    message: isDev ? message : (status >= 500 ? 'Internal server error' : message),
    ...(isDev && { stack: err.stack }),
  });
}

/**
 * Async route wrapper — catches rejected promises and forwards to error handler.
 * Usage: router.get('/path', asyncHandler(async (req, res) => { ... }));
 */
function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

module.exports = { notFoundHandler, errorHandler, asyncHandler };
