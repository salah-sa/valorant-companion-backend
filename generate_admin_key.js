const crypto   = require('crypto');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
require('dotenv').config({ path: 'config/.env' });

const schema = new mongoose.Schema({
  key_prefix: String,
  key_hash:   String,
  tier:       String,
  label:      String,
  is_active:  { type: Boolean, default: true },
  is_banned:  { type: Boolean, default: false },
  expires_at: Date,
  created_at: { type: Date, default: Date.now }
});
const Key = mongoose.model('LicenseKey', schema);

mongoose.connect(process.env.MONGODB_URI).then(async () => {
  const rand   = crypto.randomBytes(16).toString('hex').toUpperCase();
  const rawKey = 'VA-' + rand.slice(0, 8) + '-' + rand.slice(8, 24);
  const hash   = await bcrypt.hash(rawKey, 10);
  await Key.create({
    key_prefix: rawKey.slice(0, 8).toUpperCase(),
    key_hash:   hash,
    tier:       'admin',
    label:      'Admin Key',
    expires_at: null
  });
  console.log('\n✅ ADMIN KEY GENERATED:');
  console.log(rawKey);
  console.log('\nEnter this key in the License window of the app.\n');
  mongoose.disconnect();
}).catch(err => {
  console.error('❌ Error:', err.message);
  process.exit(1);
});
