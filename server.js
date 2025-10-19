// ... keep your existing imports and setup

// === DB MIGRATION (no terminal needed) ===
async function migrate() {
  // CREATE EXTENSION may need superuser on some hosts; it's allowed on Render PG.
  await sql(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

  await sql(`
    CREATE TABLE IF NOT EXISTS families (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);

  await sql(`
    CREATE TABLE IF NOT EXISTS children (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      family_id UUID REFERENCES families(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      yob INT,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);

  await sql(`
    CREATE TABLE IF NOT EXISTS rules (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      family_id UUID REFERENCES families(id) ON DELETE CASCADE,
      platform TEXT NOT NULL,
      daily_minutes INT NOT NULL,
      bedtime TEXT NOT NULL,
      whitelist JSONB DEFAULT '[]',
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );
  `);

  await sql(`
    CREATE TABLE IF NOT EXISTS usage_events (
      id BIGSERIAL PRIMARY KEY,
      family_id UUID REFERENCES families(id) ON DELETE CASCADE,
      child_id UUID REFERENCES children(id) ON DELETE SET NULL,
      platform TEXT NOT NULL,
      kind TEXT NOT NULL,
      payload JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);

  console.log("✅ Database migrated");
}

// call migration before starting the server
migrate().catch(err => {
  console.error("DB migration failed:", err?.message || err);
  process.exit(1);
});
