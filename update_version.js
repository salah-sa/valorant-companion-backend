// Run: node update_version.js
// Seeds the DB with the current minimum version — run after every version raise.

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

const NEW_VERSION   = '1.1.8';
const IS_MANDATORY  = true;
const DOWNLOAD_URL  = 'https://sasa120120.itch.io/valorant-companion-app';
const RELEASE_NOTES = 'Version 1.1.8 — Performance improvements, icon fixes, admin version control.';

async function main() {
  await mongoose.connect(process.env.MONGODB_URI);
  console.log('[DB] Connected');

  // Deactivate all previous versions
  await AppVersion.updateMany({}, { $set: { is_active: false } });
  console.log('[DB] Old versions deactivated');

  // Insert/update new version
  const doc = await AppVersion.findOneAndUpdate(
    { version: NEW_VERSION },
    { $set: {
      is_active:      true,
      is_mandatory:   IS_MANDATORY,
      download_url:   DOWNLOAD_URL,
      release_notes:  RELEASE_NOTES,
      released_at:    new Date(),
      checksum_sha256: '',
    }},
    { upsert: true, new: true }
  );
  console.log('[DB] Version registered:', doc.version, '| mandatory:', doc.is_mandatory);
  console.log('[DB] Done — /check-update will now return update_available=true for clients < v' + NEW_VERSION);

  await mongoose.disconnect();
}

main().catch(e => { console.error(e); process.exit(1); });
