// auth.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
app.use(bodyParser.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.warn('WARNING: JWT_SECRET not set. Generate one and set it in .env for production security.');
}

// --- Helper: generate JWT ---
function issueToken(payload) {
  // short-lived token for MVP; adjust expiry as needed
  return jwt.sign(payload, JWT_SECRET || 'dev-secret', { algorithm: 'HS256', expiresIn: '1h' });
}

// --- Middleware: protect routes ---
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'missing authorization header' });
  const parts = header.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'malformed authorization header' });
  const token = parts[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET || 'dev-secret');
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid or expired token' });
  }
}

// --- Register (email + password) ---
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    const q = `
      INSERT INTO users (email, password_hash)
      VALUES ($1, $2)
      ON CONFLICT (email) DO UPDATE
        SET password_hash = EXCLUDED.password_hash
      RETURNING id, email, created_at
    `;
    const { rows } = await pool.query(q, [email, hashed]);
    const user = rows[0];
    const token = issueToken({ userId: user.id });
    return res.json({ user, token });
  } catch (err) {
    console.error('register error', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// --- Login ---
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  try {
    const { rows } = await pool.query('SELECT id, password_hash FROM users WHERE email = $1', [email]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash || '');
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    const token = issueToken({ userId: user.id });
    return res.json({ token });
  } catch (err) {
    console.error('login error', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// --- Protected route example ---
app.get('/me', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, email, created_at FROM users WHERE id = $1', [req.user.userId]);
    if (!rows[0]) return res.status(404).json({ error: 'user not found' });
    return res.json({ user: rows[0] });
  } catch (err) {
    console.error('me error', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// --- Optional: token refresh (simple example) ---
app.post('/refresh', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'token required' });

  try {
    const payload = jwt.verify(token, JWT_SECRET || 'dev-secret', { ignoreExpiration: true });
    // keep logic simple: if token expired, you might want to verify with a refresh token flow.
    const newToken = issueToken({ userId: payload.userId });
    return res.json({ token: newToken });
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' });
  }
});

// --- Start server ---
const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Auth server listening on ${port}`);
});
