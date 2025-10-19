import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pkg from 'pg';
const { Pool } = pkg;

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
const PORT = process.env.PORT || 8080;
const ORIGIN = process.env.CORS_ORIGIN || '*';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

app.use(helmet());
app.use(express.json());
app.use(cors({ origin: ORIGIN, credentials: true }));

const sql = (text, params = []) => pool.query(text, params);

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

app.get('/health', (_, res) => res.json({ ok: true }));

// AUTH
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email & password required' });
  const hash = await bcrypt.hash(password, 10);
  try {
    const { rows } = await sql(
      `insert into families(email, password_hash) values($1,$2) returning id,email`,
      [email.toLowerCase(), hash]
    );
    return res.json({ token: signToken(rows[0]) });
  } catch {
    return res.status(400).json({ error: 'email exists?' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const { rows } = await sql(`select id,email,password_hash from families where email=$1`, [email?.toLowerCase()]);
  if (!rows[0]) return res.status(401).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(password, rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  return res.json({ token: signToken(rows[0]) });
});

// CHILDREN
app.post('/children', requireAuth, async (req, res) => {
  const { name, yob } = req.body || {};
  const { rows } = await sql(
    `insert into children(family_id,name,yob) values($1,$2,$3) returning id,name,yob`,
    [req.user.fid, name, yob || null]
  );
  res.json(rows[0]);
});

app.get('/children', requireAuth, async (req, res) => {
  const { rows } = await sql(`select id,name,yob from children where family_id=$1 order by created_at`, [req.user.fid]);
  res.json(rows);
});

// RULES
app.get('/rules', requireAuth, async (req, res) => {
  const { rows } = await sql(
    `select id,platform,daily_minutes,bedtime,whitelist,updated_at from rules where family_id=$1`,
    [req.user.fid]
  );
  res.json(rows);
});

app.post('/rules', requireAuth, async (req, res) => {
  const { platform, daily_minutes, bedtime, whitelist } = req.body || {};
  const { rows } = await sql(
    `insert into rules(family_id,platform,daily_minutes,bedtime,whitelist) 
     values($1,$2,$3,$4,$5) 
     on conflict do nothing returning id,platform,daily_minutes,bedtime,whitelist`,
    [req.user.fid, platform, daily_minutes, bedtime, JSON.stringify(whitelist || [])]
  );
  if (rows[0]) return res.json(rows[0]);
  const up = await sql(
    `update rules set daily_minutes=$3, bedtime=$4, whitelist=$5, updated_at=now()
     where family_id=$1 and platform=$2
     returning id,platform,daily_minutes,bedtime,whitelist`,
    [req.user.fid, platform, daily_minutes, bedtime, JSON.stringify(whitelist || [])]
  );
  res.json(up.rows[0]);
});

// EVENTS
app.post('/events', requireAuth, async (req, res) => {
  const { platform, kind, payload, child_id } = req.body || {};
  await sql(
    `insert into usage_events(family_id, child_id, platform, kind, payload)
     values($1,$2,$3,$4,$5)`,
    [req.user.fid, child_id || null, platform, kind, payload || {}]
  );
  res.json({ ok: true });
});

app.get('/policy', requireAuth, async (req, res) => {
  const platform = req.query.platform || 'youtube';
  const { rows } = await sql(
    `select daily_minutes, bedtime, whitelist from rules where family_id=$1 and platform=$2`,
    [req.user.fid, platform]
  );
  res.json(rows[0] || { daily_minutes: 45, bedtime: '21:00', whitelist: [] });
});

app.listen(PORT, () => console.log(`Guardian backend running on port ${PORT}`));
