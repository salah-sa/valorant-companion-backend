// ── ValorantCompanion — Production Database Models ───────────────────────────
// MongoDB / Mongoose schemas — production-grade, fully indexed

const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');

// ══════════════════════════════════════════════════════════════════════════════
// LICENSE KEYS
// ══════════════════════════════════════════════════════════════════════════════
const licenseKeySchema = new mongoose.Schema({
  key_hash:    { type: String, required: true, unique: true, index: true }, // bcrypt hash of the raw key
  key_prefix:  { type: String, required: true, index: true },               // first 8 chars for lookup hints
  tier:        { type: String, enum: ['standard', 'pro', 'lifetime', 'admin'], required: true },
  label:       { type: String, default: '' },
  hwid:        { type: String, default: null,  index: true },               // null = unbound
  created_at:  { type: Date,   default: Date.now },
  expires_at:  { type: Date,   default: null,  index: true },               // null = lifetime
  is_active:   { type: Boolean, default: true, index: true },
  is_banned:   { type: Boolean, default: false },
  last_used_at:{ type: Date,   default: null },
  note:        { type: String, default: '' },
}, { versionKey: false });

// Compound index — fast validation path
licenseKeySchema.index({ key_prefix: 1, is_active: 1, is_banned: 1 });
licenseKeySchema.index({ expires_at: 1, is_active: 1 });

licenseKeySchema.statics.hashKey = async function(rawKey) {
  return bcrypt.hash(rawKey.trim().toUpperCase(), 10);
};
licenseKeySchema.statics.verifyKey = async function(rawKey, hash) {
  return bcrypt.compare(rawKey.trim().toUpperCase(), hash);
};

const LicenseKey = mongoose.model('LicenseKey', licenseKeySchema);

// ══════════════════════════════════════════════════════════════════════════════
// ACTIVATIONS / SESSIONS
// ══════════════════════════════════════════════════════════════════════════════
const activationSchema = new mongoose.Schema({
  license_key_id: { type: mongoose.Schema.Types.ObjectId, ref: 'LicenseKey', required: true, index: true },
  hwid:           { type: String, required: true, index: true },
  ip_address:     { type: String, required: true },
  started_at:     { type: Date,   default: Date.now },
  last_heartbeat: { type: Date,   default: Date.now, index: true },
  is_active:      { type: Boolean, default: true, index: true },
  user_agent:     { type: String, default: '' },
  app_version:    { type: String, default: '' },
}, { versionKey: false });

activationSchema.index({ license_key_id: 1, is_active: 1 });
activationSchema.index({ last_heartbeat: 1, is_active: 1 }); // for cleanup job

const Activation = mongoose.model('Activation', activationSchema);

// ══════════════════════════════════════════════════════════════════════════════
// ORDERS
// ══════════════════════════════════════════════════════════════════════════════
const orderSchema = new mongoose.Schema({
  user_name:    { type: String, required: true },
  phone_number: { type: String, required: true },
  email:        { type: String, default: '' },
  country:      { type: String, default: '' },
  plan:         { type: String, enum: ['daily', 'weekly', 'monthly'], required: true },
  price_egp:    { type: Number, required: true },
  price_usd:    { type: String, default: '' },
  status:       { type: String, enum: ['pending', 'completed', 'failed', 'refunded'], default: 'pending', index: true },
  hwid:         { type: String, default: '' },
  machine_name: { type: String, default: '' },
  os_version:   { type: String, default: '' },
  ip_address:   { type: String, default: '' },
  created_at:   { type: Date, default: Date.now, index: true },
  completed_at: { type: Date, default: null },
  admin_note:   { type: String, default: '' },
  license_key_issued: { type: String, default: null }, // key given after payment
}, { versionKey: false });

orderSchema.index({ status: 1, created_at: -1 });
orderSchema.index({ phone_number: 1 });

const Order = mongoose.model('Order', orderSchema);

// ══════════════════════════════════════════════════════════════════════════════
// SECURITY LOGS
// ══════════════════════════════════════════════════════════════════════════════
const securityLogSchema = new mongoose.Schema({
  type:      { type: String, enum: ['error', 'info', 'security', 'warn'], required: true, index: true },
  message:   { type: String, required: true },
  ip:        { type: String, default: '' },
  hwid:      { type: String, default: '' },
  key_prefix:{ type: String, default: '' },
  timestamp: { type: Date, default: Date.now, index: true },
  metadata:  { type: mongoose.Schema.Types.Mixed, default: {} },
}, { versionKey: false });

// TTL: auto-delete logs older than 90 days
securityLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: 7776000 });

const SecurityLog = mongoose.model('SecurityLog', securityLogSchema);

// ══════════════════════════════════════════════════════════════════════════════
// APP VERSIONS (Update System)
// ══════════════════════════════════════════════════════════════════════════════
const appVersionSchema = new mongoose.Schema({
  version:       { type: String, required: true, unique: true },  // e.g. "1.5.0"
  download_url:  { type: String, required: true },
  release_notes: { type: String, default: '' },
  is_mandatory:  { type: Boolean, default: false },
  min_version:   { type: String, default: '0.0.0' },              // minimum version to upgrade from
  checksum_sha256: { type: String, default: '' },                  // SHA-256 of the installer
  released_at:   { type: Date, default: Date.now },
  is_active:     { type: Boolean, default: true },
}, { versionKey: false });

appVersionSchema.index({ released_at: -1 });

const AppVersion = mongoose.model('AppVersion', appVersionSchema);

// ══════════════════════════════════════════════════════════════════════════════
// RATE LIMIT TRACKING (in-memory via Map is fine; DB for persistence)
// ══════════════════════════════════════════════════════════════════════════════
const rateLimitSchema = new mongoose.Schema({
  ip:        { type: String, required: true, index: true },
  endpoint:  { type: String, required: true },
  attempts:  { type: Number, default: 0 },
  window_start: { type: Date, default: Date.now },
  locked_until: { type: Date, default: null },
}, { versionKey: false });

rateLimitSchema.index({ ip: 1, endpoint: 1 }, { unique: true });
// TTL — auto-clean after 1 hour
rateLimitSchema.index({ window_start: 1 }, { expireAfterSeconds: 3600 });

const RateLimit = mongoose.model('RateLimit', rateLimitSchema);

// ══════════════════════════════════════════════════════════════════════════════
// COMPLAINTS (User → Admin support messages)
// ══════════════════════════════════════════════════════════════════════════════
const complaintSchema = new mongoose.Schema({
  subject:     { type: String, required: true },
  message:     { type: String, required: true },
  category:    { type: String, default: 'General' },
  hwid:        { type: String, default: '', index: true },
  ip_address:  { type: String, default: '' },
  app_version: { type: String, default: '' },
  status:      { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open', index: true },
  admin_reply: { type: String, default: '' },
  created_at:  { type: Date, default: Date.now, index: true },
  resolved_at: { type: Date, default: null },
}, { versionKey: false });

complaintSchema.index({ status: 1, created_at: -1 });
// TTL: auto-delete resolved complaints after 6 months
complaintSchema.index({ resolved_at: 1 }, { expireAfterSeconds: 15552000, partialFilterExpression: { resolved_at: { $ne: null } } });

const Complaint = mongoose.model('Complaint', complaintSchema);

module.exports = { LicenseKey, Activation, Order, SecurityLog, AppVersion, RateLimit, Complaint };
