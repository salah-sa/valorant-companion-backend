// Run this in MongoDB shell or Compass to register v1.1.7 as the latest version
// Command: node update_version.js

require('dotenv').config({ path: './config/.env' });
const mongoose = require('mongoose');

const AppVersionSchema = new mongoose.Schema({
  version:        String,
  is_active:      Boolean,
  is_mandatory:   Boolean,
  download_url:   String,
  release_notes:  String,
  checksum_sha256:String,
  released_at:    Date,
});
const AppVersion = mongoose.model('AppVersion', AppVersionSchema);

async function main() {
  await mongoose.connect(process.env.MONGODB_URI);
  console.log('[DB] Connected');

  // Deactivate all previous versions
  await AppVersion.updateMany({}, { $set: { is_active: false } });
  console.log('[DB] Old versions deactivated');

  // Insert new v1.1.7
  await AppVersion.findOneAndUpdate(
    { version: '1.1.7' },
    { $set: {
      is_active:     true,
      is_mandatory:  true,
      download_url:  'https://sasa120120.itch.io/valorant-companion-app/download/eyJpZCI6NDQxODI5NCwiZXhwaXJlcyI6MTc3NDQ4NjQ1MH0%3d%2ev0Oyz%2f8pnRmQ9vOGL3uSnjoTCbU%3d',
      release_notes: 'Version 1.1.7 - Latest release with improvements and bug fixes.',
      released_at:   new Date(),
    }},
    { upsert: true, new: true }
  );
  console.log('[DB] ✅ Version 1.1.7 registered as latest active version');

  await mongoose.disconnect();
}

main().catch(e => { console.error(e); process.exit(1); });

