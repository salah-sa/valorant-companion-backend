// ── ValorantCompanion — MongoDB Atlas Setup Script ───────────────────────────
// Run this in MongoDB Atlas > Data Explorer > Shell OR via mongosh

// ── 1. Create collections with validation ────────────────────────────────────

db.createCollection("licensekeys", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["key_hash", "key_prefix", "tier"],
      properties: {
        key_hash:     { bsonType: "string", description: "bcrypt hash of the raw key" },
        key_prefix:   { bsonType: "string", description: "First 8 chars for lookup" },
        tier:         { bsonType: "string", enum: ["standard","pro","lifetime","admin"] },
        hwid:         { bsonType: ["string", "null"] },
        is_active:    { bsonType: "bool" },
        is_banned:    { bsonType: "bool" },
        expires_at:   { bsonType: ["date", "null"] },
      }
    }
  }
});

db.createCollection("activations", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["license_key_id", "hwid", "ip_address"],
      properties: {
        license_key_id: { bsonType: "objectId" },
        hwid:           { bsonType: "string" },
        ip_address:     { bsonType: "string" },
        last_heartbeat: { bsonType: "date" },
        is_active:      { bsonType: "bool" },
      }
    }
  }
});

db.createCollection("orders");
db.createCollection("securitylogs");
db.createCollection("appversions");

// ── 2. Indexes ────────────────────────────────────────────────────────────────

// licensekeys
db.licensekeys.createIndex({ key_hash: 1 }, { unique: true });
db.licensekeys.createIndex({ key_prefix: 1, is_active: 1, is_banned: 1 });
db.licensekeys.createIndex({ hwid: 1 });
db.licensekeys.createIndex({ expires_at: 1, is_active: 1 });
db.licensekeys.createIndex({ created_at: -1 });

// activations
db.activations.createIndex({ license_key_id: 1, is_active: 1 });
db.activations.createIndex({ hwid: 1 });
db.activations.createIndex({ last_heartbeat: 1, is_active: 1 });
// TTL index: auto-expire abandoned sessions after 7 days
db.activations.createIndex(
  { last_heartbeat: 1 },
  { expireAfterSeconds: 604800 }
);

// orders
db.orders.createIndex({ status: 1, created_at: -1 });
db.orders.createIndex({ phone_number: 1 });
db.orders.createIndex({ created_at: -1 });

// securitylogs (TTL: delete after 90 days)
db.securitylogs.createIndex({ type: 1 });
db.securitylogs.createIndex({ timestamp: 1 }, { expireAfterSeconds: 7776000 });
db.securitylogs.createIndex({ ip: 1, timestamp: -1 });

// appversions
db.appversions.createIndex({ version: 1 }, { unique: true });
db.appversions.createIndex({ released_at: -1 });
db.appversions.createIndex({ is_active: 1, released_at: -1 });

print("✅ All collections and indexes created successfully.");

// ── 3. Insert first app version ───────────────────────────────────────────────
db.appversions.insertOne({
  version:        "15.0.0",
  download_url:   "https://YOUR_CDN/ValorantCompanion_v15_Setup.exe",
  release_notes:  "Production release: server-side licensing, auto-updater, crash reporting.",
  is_mandatory:   false,
  checksum_sha256:"",           // Fill in after building installer
  is_active:      true,
  released_at:    new Date(),
});

print("✅ Initial app version record inserted.");
print("");
print("NEXT STEPS:");
print("1. Edit config/.env with your MONGODB_URI and secrets");
print("2. Run: npm install && node src/server.js");
print("3. Generate your first license key via POST /admin/generate-key");
print("4. Update ApiBase in all Client service files to your backend URL");
