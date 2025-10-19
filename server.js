// server.js — Bloomly backend (Node/Express + Postgres) with auto-migration
// Runs DB migrations on boot so you can deploy from GitHub/Render only.

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pkg from 'pg';
const { Pool } = pkg;

// --- Config
const PORT = process.env.PORT || 8080;
const ORIGIN = process.env.CORS_ORIGIN || '*';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

// --- DB
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
const sql = (text, params = []) => pool.query(text, params);

// --- App
const app = express();
app.use(helmet());
app.use(express.json());
app.use(cors({ origin: ORIGIN, credentials: true }));

// --- Helpers (auth)
function signToken(family) {
  return jwt.sign({ fid: family.id, email: family.email }, JWT_SECRET, { expiresIn: '7d' });
}

function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'invalid token' });
  }
}

// --- Health
app.get('/health', (_, res) => res.json({ ok: true }));

// --- Auto-migration (idempotent; safe to run every boot)
async function migrate() {
  // Try to enable pgcrypto for gen_random_uuid()
  try {
    await sql(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);
  } catch (e) {
    console.warn('⚠️ Could not enable pgcrypto extension:', e?.message || e);
    // If your DB provider disallows extensions on your plan, remove the DEFAULTs below
    // and let IDs be provided app-side, or upgrade DB plan to enable pgcrypto.
  }

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
      platform TEXT NOT NULL,            -- 'youtube' | 'roblox'
      daily_minutes INT NOT NULL,        -- e.g., 45
      bedtime TEXT NOT NULL,             -- '21:00'
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
      kind TEXT NOT NULL,                -- 'start'|'stop'|'blocked'|'intent' etc.
      payload JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);

  console.log('✅ Database migrated / verified');
}

// --- Auth routes
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email & password required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await sql(
      `INSERT INTO families(email, password_hash) VALUES($1,$2) RETURNING id,email`,
      [String(email).toLowerCase(), hash]
    );
    return res.json({ token: signToken(rows[0]) });
  } catch (e) {
    // duplicate email or other db error
    return res.status(400).json({ error: 'email exists?' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const { rows } = await sql(
    `SELECT id,email,password_hash FROM families WHERE email=$1`,
    [String(email || '').toLowerCase()]
  );
  const fam = rows[0];
  if (!fam) return res.status(401).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(password, fam.password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  return res.json({ token: signToken(fam) });
});

// --- Children
app.post('/children', requireAuth, async (req, res) => {
  const { name, yob } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const { rows } = await sql(
    `INSERT INTO children(family_id,name,yob) VALUES($1,$2,$3) RETURNING id,name,yob`,
    [req.user.fid, name, yob || null]
  );
  res.json(rows[0]);
});

app.get('/children', requireAuth, async (req, res) => {
  const { rows } = await sql(
    `SELECT id,name,yob FROM children WHERE family_id=$1 ORDER BY created_at`,
    [req.user.fid]
  );
  res.json(rows);
});

// --- Rules (per platform)
app.get('/rules', requireAuth, async (req, res) => {
  const { rows } = await sql(
    `SELECT id,platform,daily_minutes,bedtime,whitelist,updated_at 
     FROM rules WHERE family_id=$1`,
    [req.user.fid]
  );
  res.json(rows);
});

app.post('/rules', requireAuth, async (req, res) => {
  const { platform, daily_minutes, bedtime, whitelist } = req.body || {};
  if (!platform || !daily_minutes || !bedtime) {
    return res.status(400).json({ error: 'platform, daily_minutes, bedtime required' });
  }

  // try insert; if conflict, update (emulate upsert for per-family+platform)
  const tryInsert = await sql(
    `INSERT INTO rules(family_id,platform,daily_minutes,bedtime,whitelist)
     VALUES($1,$2,$3,$4,$5)
     ON CONFLICT DO NOTHING
     RETURNING id,platform,daily_minutes,bedtime,whitelist`,
    [req.user.fid, platform, daily_minutes, bedtime, JSON.stringify(whitelist || [])]
  );

  if (tryInsert.rows[0]) return res.json(tryInsert.rows[0]);

  const up = await sql(
    `UPDATE rules SET daily_minutes=$3, bedtime=$4, whitelist=$5, updated_at=now()
     WHERE family_id=$1 AND platform=$2
     RETURNING id,platform,daily_minutes,bedtime,whitelist`,
    [req.user.fid, platform, daily_minutes, bedtime, JSON.stringify(whitelist || [])]
  );
  res.json(up.rows[0]);
});

// --- Events / telemetry
app.post('/events', requireAuth, async (req, res) => {
  const { platform, kind, payload, child_id } = req.body || {};
  if (!platform || !kind) return res.status(400).json({ error: 'platform & kind required' });
  await sql(
    `INSERT INTO usage_events(family_id, child_id, platform, kind, payload)
     VALUES($1,$2,$3,$4,$5)`,
    [req.user.fid, child_id || null, platform, kind, payload || {}]
  );
  res.json({ ok: true });
});

// --- Lightweight policy endpoint for extensions/clients
app.get('/policy', requireAuth, async (req, res) => {
  const platform = req.query.platform || 'youtube';
  const { rows } = await sql(
    `SELECT daily_minutes, bedtime, whitelist 
     FROM rules 
     WHERE family_id=$1 AND platform=$2`,
    [req.user.fid, platform]
  );
  res.json(rows[0] || { daily_minutes: 45, bedtime: '21:00', whitelist: [] });
});

// --- Start
async function start() {
  await migrate();          // ensure DB is ready
  app.listen(PORT, () => {
    console.log(`🌿 Bloomly backend running on port ${PORT}`);
  });
}

start().catch(err => {
  console.error('Fatal startup error:', err?.message || err);
  process.exit(1);
});