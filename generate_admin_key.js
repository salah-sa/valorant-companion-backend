'use strict';
// Run: node generate_admin_key.js
// Generates a new admin license key and inserts it into the database.

require('dotenv').config({ path: './config/.env' });
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');

const LicenseKeySchema = new mongoose.Schema({
  key_prefix: String,
  key_hash:   String,
  tier:       String,
  label:      String,
  expires_at: Date,
});
const LicenseKey = mongoose.model('LicenseKey', LicenseKeySchema);

async function main() {
  await mongoose.connect(process.env.MONGODB_URI);
  console.log('[DB] Connected');

  const rand   = crypto.randomBytes(16).toString('hex').toUpperCase();
  const rawKey = 'VA-' + rand.slice(0, 8) + '-' + rand.slice(8, 24);
  const hash   = await bcrypt.hash(rawKey, 10);

  await LicenseKey.create({
    key_prefix: rawKey.slice(0, 8).toUpperCase(),
    key_hash:   hash,
    tier:       'admin',
    label:      'MANUAL-ADMIN-' + Date.now(),
    expires_at: null,
  });

  console.log('========================================');
  console.log(' NEW ADMIN KEY: ' + rawKey);
  console.log(' Save this - it will NOT be shown again.');
  console.log('========================================');

  await mongoose.disconnect();
}

main().catch(e => { console.error(e); process.exit(1); });