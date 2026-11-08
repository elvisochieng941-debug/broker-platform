require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Server } = require('socket.io');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: process.env.BASE_URL, methods: ['GET', 'POST'] },
});
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
  console.warn('Missing DATABASE_URL or SESSION_SECRET in .env');
}

// --- Security headers ---
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://unpkg.com'],
        styleSrc: ["'self'", "'unsafe-inline'"],
        connectSrc: ["'self'", 'wss:', 'https:'],
        imgSrc: ["'self'", 'data:', 'https:'],
      },
    },
  })
);
app.set('trust proxy', 1);

// Raw body ONLY for webhook (needed for signature verification)
app.use(
  '/api/webhook/tuma',
  express.raw({ type: 'application/json', limit: '20kb' })
);

app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: true, limit: '20kb' }));
app.use(express.static(__dirname));

// --- Rate limiters ---
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many auth attempts, try again in 15 min' },
  standardHeaders: true,
});
const strictLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many requests, slow down' },
});
const tradeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Too many trades' },
});
const depositLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  message: { error: 'Too many deposit attempts' },
});
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many OTP requests' },
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false,
  max: 20,
});

app.use(
  session({
    store: new PgSession({
      pool,
      tableName: 'session',
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

// ---------- Validation helpers ----------
function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return res.status(400).json({ error: errors.array()[0].msg });
  next();
}
const validateEmail = body('email')
  .trim()
  .isEmail()
  .withMessage('Valid email required')
  .normalizeEmail();
const validatePassword = body('password')
  .isLength({ min: 8, max: 128 })
  .withMessage('Password must be 8-128 chars');
const validatePhone = body('phone')
  .trim()
  .matches(/^07\d{8}$/)
  .withMessage('Phone must be 07XXXXXXXX');
const validateAmountUSD = body('amount')
  .isFloat({ min: 1, max: 100000 })
  .withMessage('Amount must be 1 - 100000 USD');
const validateAmountKES = body('amountKes')
  .isFloat({ min: 10, max: 10000000 })
  .withMessage('Amount must be 10 - 10,000,000 KES');

// ---------- Audit Log ----------
async function audit(
  req,
  { userId, actorId, action, entityType, entityId, metadata = {} }
) {
  try {
    await pool.query(
      `INSERT INTO audit_logs (user_id, actor_id, action, entity_type, entity_id, ip, user_agent, metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        userId || null,
        actorId || userId || null,
        action,
        entityType || null,
        entityId ? String(entityId) : null,
        req?.ip || req?.headers?.['x-forwarded-for'] || null,
        req?.headers?.['user-agent']?.slice(0, 500) || null,
        JSON.stringify(metadata),
      ]
    );
  } catch (e) {
    console.error('Audit failed', e.message);
  }
}

function isAdminEmail(email) {
  const list = (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return list.includes((email || '').toLowerCase());
}

// ---------- DB auto-migration ----------
async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      phone TEXT,
      balance NUMERIC(14,2) DEFAULT 1000.00 CHECK (balance >= 0),
      is_verified BOOLEAN DEFAULT FALSE,
      verification_code TEXT,
      google_id TEXT,
      role TEXT DEFAULT 'user' CHECK (role IN ('user','admin')),
      is_frozen BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL, expires_at TIMESTAMPTZ NOT NULL, used BOOLEAN DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS deposits (
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE,
      phone TEXT, amount_kes NUMERIC(14,2), amount_usd NUMERIC(14,2),
      checkout_request_id TEXT UNIQUE, status TEXT DEFAULT 'pending',
      idempotency_key TEXT UNIQUE, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS withdrawals (
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE,
      phone TEXT, amount_usd NUMERIC(14,2), amount_kes NUMERIC(14,2),
      status TEXT DEFAULT 'pending', tuma_ref TEXT, idempotency_key TEXT UNIQUE,
      two_fa_verified BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS trades (
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE,
      asset TEXT NOT NULL, type TEXT NOT NULL CHECK (type IN ('HIGHER','LOWER')),
      amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
      entry_price NUMERIC(18,6) NOT NULL, exit_price NUMERIC(18,6),
      payout NUMERIC(14,2), status TEXT DEFAULT 'ACTIVE',
      created_at TIMESTAMPTZ DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id) ON DELETE SET NULL,
      actor_id INT REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id TEXT,
      ip TEXT,
      user_agent TEXT,
      metadata JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action, created_at DESC);
    CREATE TABLE IF NOT EXISTS withdrawal_otps (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id) ON DELETE CASCADE,
      withdrawal_id INT REFERENCES withdrawals(id) ON DELETE CASCADE,
      code_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INT DEFAULT 0,
      used BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_withdrawal_otps_user ON withdrawal_otps(user_id, used, expires_at);
    CREATE INDEX IF NOT EXISTS idx_trades_active ON trades(status, expires_at);
    CREATE INDEX IF NOT EXISTS idx_deposits_checkout ON deposits(checkout_request_id);
  `);
  console.log('Migration OK');
}

// ---------- Market simulation ----------
const prices = { 'EUR/USD': 1.0842, 'GBP/USD': 1.2715, 'BTC/USD': 67420 };
const candles = {};
for (const k of Object.keys(prices)) candles[k] = [];
function tick() {
  for (const asset of Object.keys(prices)) {
    const vol = asset.includes('BTC') ? 0.0015 : 0.0004;
    prices[asset] *= 1 + (Math.random() - 0.5) * vol * 2;
    prices[asset] = Number(
      prices[asset].toFixed(asset.includes('BTC') ? 2 : 5)
    );
    const now = Math.floor(Date.now() / 1000);
    const last = candles[asset][candles[asset].length - 1];
    if (!last || last.time !== now)
      candles[asset].push({
        time: now,
        open: prices[asset],
        high: prices[asset],
        low: prices[asset],
        close: prices[asset],
      });
    else {
      last.high = Math.max(last.high, prices[asset]);
      last.low = Math.min(last.low, prices[asset]);
      last.close = prices[asset];
    }
    if (candles[asset].length > 200) candles[asset].shift();
  }
  io.emit('prices', prices);
}
setInterval(tick, 1000);

// ---------- Settlement loop (60s, transactional) ----------
setInterval(async () => {
  const client = await pool.connect();
  try {
    const { rows } = await client.query(
      `SELECT * FROM trades WHERE status='ACTIVE' AND expires_at <= NOW() FOR UPDATE SKIP LOCKED`
    );
    for (const t of rows) {
      const exit = prices[t.asset];
      const won =
        (t.type === 'HIGHER' && exit > Number(t.entry_price)) ||
        (t.type === 'LOWER' && exit < Number(t.entry_price));
      const payout = won ? Number(t.amount) * 1.92 : 0;
      await client.query('BEGIN');
      await client.query(
        `UPDATE trades SET exit_price=$1, payout=$2, status=$3 WHERE id=$4`,
        [exit, payout, won ? 'WON' : 'LOST', t.id]
      );
      if (won)
        await client.query(
          `UPDATE users SET balance = balance + $1 WHERE id=$2`,
          [payout, t.user_id]
        );
      await client.query('COMMIT');
      await audit(
        { ip: 'system', headers: {} },
        {
          userId: t.user_id,
          action: won ? 'TRADE_WON' : 'TRADE_LOST',
          entityType: 'trade',
          entityId: t.id,
          metadata: { asset: t.asset, amount: t.amount, payout, exit },
        }
      );
    }
  } catch (e) {
    console.error('Settlement error', e.message);
    try {
      await client.query('ROLLBACK');
    } catch {}
  } finally {
    client.release();
  }
}, 2000);

// ---------- Passport ----------
passport.serializeUser((u, cb) => cb(null, u.id));
passport.deserializeUser(async (id, cb) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM users WHERE id=$1`, [id]);
    cb(null, rows[0] || false);
  } catch (e) {
    cb(e);
  }
});
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.CALLBACK_URL || '/auth/google/callback',
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value;
          const role = isAdminEmail(email) ? 'admin' : 'user';
          let { rows } = await pool.query(
            `SELECT * FROM users WHERE google_id=$1 OR email=$2`,
            [profile.id, email]
          );
          let user = rows[0];
          if (!user) {
            const ins = await pool.query(
              `INSERT INTO users (email, google_id, is_verified, role) VALUES ($1,$2,TRUE,$3) RETURNING *`,
              [email, profile.id, role]
            );
            user = ins.rows[0];
          } else {
            if (!user.google_id)
              await pool.query(
                `UPDATE users SET google_id=$1, is_verified=TRUE WHERE id=$2`,
                [profile.id, user.id]
              );
            if (user.role !== 'admin' && role === 'admin') {
              await pool.query(`UPDATE users SET role='admin' WHERE id=$1`, [
                user.id,
              ]);
              user.role = 'admin';
            }
          }
          done(null, user);
        } catch (e) {
          done(e);
        }
      }
    )
  );
}

const requireAuth = (req, res, next) =>
  req.isAuthenticated()
    ? next()
    : res.status(401).json({ error: 'Not authenticated' });
const requireAdmin = (req, res, next) => {
  if (!req.isAuthenticated())
    return res.status(401).json({ error: 'Not authenticated' });
  if (req.user.role !== 'admin')
    return res.status(403).json({ error: 'Admin only' });
  next();
};
const blockFrozen = (req, res, next) => {
  if (req.user?.is_frozen)
    return res.status(403).json({ error: 'Account frozen. Contact support.' });
  next();
};

// ---------- Tuma helpers ----------
let tumaTokenCache = { token: null, expiresAt: 0 };
async function getTumaToken() {
  if (tumaTokenCache.token && Date.now() < tumaTokenCache.expiresAt)
    return tumaTokenCache.token;
  const r = await fetch(`${process.env.TUMA_BASE_URL}/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: process.env.TUMA_BUSINESS_EMAIL,
      api_key: process.env.TUMA_API_KEY,
    }),
  });
  if (!r.ok) throw new Error('Tuma auth failed: ' + r.status);
  const j = await r.json();
  const token = j.token || j.access_token;
  if (!token) throw new Error('No Tuma token returned');
  tumaTokenCache = { token, expiresAt: Date.now() + 50 * 60 * 1000 };
  return token;
}
function verifyTumaWebhook(req, rawBody) {
  const secret = process.env.TUMA_WEBHOOK_SECRET;
  if (!secret) {
    console.warn('TUMA_WEBHOOK_SECRET not set - skipping webhook verification');
    return true;
  }
  const sig = req.headers['x-tuma-signature'] || req.headers['x-signature'];
  if (!sig) return false;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

// ---------- Auth routes ----------
app.post(
  '/api/auth/signup',
  authLimiter,
  validateEmail,
  validatePassword,
  validatePhone,
  handleValidation,
  async (req, res) => {
    const { email, password, phone } = req.body;
    const code = String(Math.floor(100000 + Math.random() * 900000));
    try {
      const hash = await bcrypt.hash(password, 12);
      const role = isAdminEmail(email) ? 'admin' : 'user';
      const { rows } = await pool.query(
        `INSERT INTO users (email, password_hash, phone, verification_code, role) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
        [email, hash, phone, code, role]
      );
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'TradeNova verification code',
        text: `Your TradeNova code is ${code}`,
      });
      await audit(req, {
        userId: rows[0].id,
        action: 'USER_SIGNUP',
        entityType: 'user',
        entityId: rows[0].id,
        metadata: { email, phone },
      });
      res.json({ ok: true, userId: rows[0].id });
    } catch (e) {
      res.status(400).json({ error: 'Email already exists' });
    }
  }
);

app.post(
  '/api/auth/verify',
  authLimiter,
  validateEmail,
  body('code')
    .trim()
    .isLength({ min: 6, max: 6 })
    .withMessage('6-digit code required'),
  handleValidation,
  async (req, res) => {
    const { email, code } = req.body;
    const { rows } = await pool.query(
      `SELECT * FROM users WHERE email=$1 AND verification_code=$2`,
      [email, code]
    );
    if (!rows.length) return res.status(400).json({ error: 'Invalid code' });
    await pool.query(
      `UPDATE users SET is_verified=TRUE, verification_code=NULL WHERE id=$1`,
      [rows[0].id]
    );
    await audit(req, {
      userId: rows[0].id,
      action: 'USER_VERIFIED',
      entityType: 'user',
      entityId: rows[0].id,
    });
    res.json({ ok: true });
  }
);

app.post(
  '/api/auth/login-local',
  authLimiter,
  validateEmail,
  body('password').notEmpty().withMessage('Password required'),
  handleValidation,
  async (req, res) => {
    const { email, password, remember } = req.body;
    const { rows } = await pool.query(`SELECT * FROM users WHERE email=$1`, [
      email,
    ]);
    const user = rows[0];
    const hashToCheck =
      user?.password_hash ||
      '$2b$12$invalidinvalidinvalidinvalidinvalidinvalidinvalid12';
    const ok = await bcrypt.compare(password, hashToCheck);
    if (!user || !ok)
      return res.status(401).json({ error: 'Invalid credentials' });
    if (!user.is_verified)
      return res.status(403).json({ error: 'Verify your email first' });
    if (user.is_frozen)
      return res
        .status(403)
        .json({ error: 'Account frozen. Contact support.' });
    req.login(user, async (err) => {
      if (err) return res.status(500).json({ error: 'Login failed' });
      if (remember) req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
      await audit(req, {
        userId: user.id,
        action: 'USER_LOGIN',
        entityType: 'user',
        entityId: user.id,
      });
      res.json({
        ok: true,
        user: { email: user.email, balance: user.balance },
      });
    });
  }
);

app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);
app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/?error=google' }),
  async (req, res) => {
    await audit(req, {
      userId: req.user.id,
      action: 'USER_LOGIN_GOOGLE',
      entityType: 'user',
      entityId: req.user.id,
    });
    res.redirect('/');
  }
);

app.post(
  '/api/auth/forgot',
  authLimiter,
  validateEmail,
  handleValidation,
  async (req, res) => {
    const { email } = req.body;
    const { rows } = await pool.query(`SELECT id FROM users WHERE email=$1`, [
      email,
    ]);
    if (rows.length) {
      const token = crypto.randomBytes(32).toString('hex');
      await pool.query(
        `INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1,$2,NOW() + INTERVAL '1 hour')`,
        [rows[0].id, token]
      );
      const link = `${process.env.BASE_URL || ''}/?reset=${token}`;
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'TradeNova password reset',
        text: `Reset here: ${link}`,
      });
      await audit(req, {
        userId: rows[0].id,
        action: 'PASSWORD_RESET_REQUESTED',
        entityType: 'user',
        entityId: rows[0].id,
      });
    }
    res.json({
      ok: true,
      message: 'If that email exists, a reset link was sent',
    });
  }
);

app.post(
  '/api/auth/reset',
  authLimiter,
  body('token').notEmpty(),
  validatePassword,
  handleValidation,
  async (req, res) => {
    const { token, password } = req.body;
    const { rows } = await pool.query(
      `SELECT * FROM password_resets WHERE token=$1 AND expires_at > NOW() AND used=FALSE`,
      [token]
    );
    if (!rows.length)
      return res.status(400).json({ error: 'Invalid or expired token' });
    const hash = await bcrypt.hash(password, 12);
    await pool.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [
      hash,
      rows[0].user_id,
    ]);
    await pool.query(`UPDATE password_resets SET used=TRUE WHERE id=$1`, [
      rows[0].id,
    ]);
    await audit(req, {
      userId: rows[0].user_id,
      action: 'PASSWORD_RESET_COMPLETED',
      entityType: 'user',
      entityId: rows[0].user_id,
    });
    res.json({ ok: true });
  }
);

app.get('/api/me', requireAuth, (req, res) =>
  res.json({
    email: req.user.email,
    balance: req.user.balance,
    phone: req.user.phone,
    role: req.user.role,
    is_frozen: req.user.is_frozen,
  })
);
app.post('/api/auth/logout', (req, res) =>
  req.logout(() => {
    req.session.destroy(() => res.json({ ok: true }));
  })
);

// ---------- Trading ----------
app.post(
  '/api/trades',
  requireAuth,
  blockFrozen,
  tradeLimiter,
  body('asset')
    .isIn(['EUR/USD', 'GBP/USD', 'BTC/USD'])
    .withMessage('Invalid asset'),
  body('type').isIn(['HIGHER', 'LOWER']).withMessage('Invalid type'),
  validateAmountUSD,
  handleValidation,
  async (req, res) => {
    const { asset, type, amount } = req.body;
    const amt = Number(amount);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        `SELECT balance FROM users WHERE id=$1 FOR UPDATE`,
        [req.user.id]
      );
      if (Number(rows[0].balance) < amt) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Insufficient funds' });
      }
      await client.query(
        `UPDATE users SET balance = balance - $1 WHERE id=$2`,
        [amt, req.user.id]
      );
      const ins = await client.query(
        `INSERT INTO trades (user_id, asset, type, amount, entry_price, expires_at) VALUES ($1,$2,$3,$4,$5,NOW() + INTERVAL '60 seconds') RETURNING *`,
        [req.user.id, asset, type, amt, prices[asset]]
      );
      await client.query('COMMIT');
      await audit(req, {
        userId: req.user.id,
        action: 'TRADE_PLACED',
        entityType: 'trade',
        entityId: ins.rows[0].id,
        metadata: { asset, type, amount: amt, entry_price: prices[asset] },
      });
      res.json(ins.rows[0]);
    } catch (e) {
      await client.query('ROLLBACK');
      res.status(500).json({ error: 'Trade failed' });
    } finally {
      client.release();
    }
  }
);
app.get('/api/trades', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM trades WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,
    [req.user.id]
  );
  res.json(rows);
});

// ---------- Deposits via Tuma ----------
app.post(
  '/api/deposit',
  requireAuth,
  blockFrozen,
  depositLimiter,
  validatePhone,
  validateAmountKES,
  handleValidation,
  async (req, res) => {
    const { phone, amountKes } = req.body;
    const kes = Number(amountKes);
    const usd = Number((kes / 130).toFixed(2));
    const idempotencyKey =
      req.headers['idempotency-key'] || crypto.randomUUID();
    try {
      const existing = await pool.query(
        `SELECT * FROM deposits WHERE idempotency_key=$1`,
        [idempotencyKey]
      );
      if (existing.rows.length)
        return res.json({
          ok: true,
          message: 'Deposit already initiated',
          checkoutId: existing.rows[0].checkout_request_id,
        });
      const token = await getTumaToken();
      const r = await fetch(`${process.env.TUMA_BASE_URL}/payment/stk-push`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          phone,
          amount: kes,
          email: req.user.email,
          callback_url: `${process.env.BASE_URL}/api/webhook/tuma`,
        }),
      });
      const data = await r.json();
      if (!r.ok)
        return res
          .status(400)
          .json({ error: data.message || 'STK push failed' });
      const checkoutId =
        data.CheckoutRequestID || data.checkout_request_id || null;
      await pool.query(
        `INSERT INTO deposits (user_id, phone, amount_kes, amount_usd, checkout_request_id, idempotency_key) VALUES ($1,$2,$3,$4,$5,$6)`,
        [req.user.id, phone, kes, usd, checkoutId, idempotencyKey]
      );
      await audit(req, {
        userId: req.user.id,
        action: 'DEPOSIT_INITIATED',
        entityType: 'deposit',
        entityId: checkoutId,
        metadata: { amount_kes: kes, amount_usd: usd, phone },
      });
      res.json({
        ok: true,
        message: 'STK push sent. Complete payment on your phone.',
        checkoutId,
      });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Deposit failed to start' });
    }
  }
);

// ---------- Webhook ----------
app.post('/api/webhook/tuma', async (req, res) => {
  try {
    const raw = req.body;
    const body = JSON.parse(raw.toString());
    if (!verifyTumaWebhook(req, raw))
      return res.status(401).json({ ok: false, error: 'Invalid signature' });
    const resultCode =
      body.ResultCode ?? body.resultCode ?? body?.Body?.stkCallback?.ResultCode;
    const checkoutId =
      body.CheckoutRequestID ||
      body.checkout_request_id ||
      body?.Body?.stkCallback?.CheckoutRequestID;
    if (!checkoutId) return res.json({ ok: true });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        `SELECT * FROM deposits WHERE checkout_request_id=$1 FOR UPDATE`,
        [checkoutId]
      );
      if (!rows.length || rows[0].status !== 'pending') {
        await client.query('COMMIT');
        return res.json({ ok: true });
      }
      if (Number(resultCode) === 0) {
        await client.query(
          `UPDATE deposits SET status='completed' WHERE id=$1`,
          [rows[0].id]
        );
        await client.query(
          `UPDATE users SET balance = balance + $1 WHERE id=$2`,
          [rows[0].amount_usd, rows[0].user_id]
        );
      } else {
        await client.query(`UPDATE deposits SET status='failed' WHERE id=$1`, [
          rows[0].id,
        ]);
      }
      await client.query('COMMIT');
      if (Number(resultCode) === 0) {
        await audit(
          { ip: 'webhook', headers: {} },
          {
            userId: rows[0].user_id,
            action: 'DEPOSIT_COMPLETED',
            entityType: 'deposit',
            entityId: rows[0].id,
            metadata: { amount_usd: rows[0].amount_usd, checkoutId },
          }
        );
      }
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('Webhook error', e);
    res.status(500).json({ ok: false });
  }
});

// ---------- Withdrawals with 2FA > $100 ----------
app.post(
  '/api/withdraw',
  requireAuth,
  blockFrozen,
  strictLimiter,
  body('phone')
    .trim()
    .matches(/^07\d{8}$/)
    .withMessage('Phone must be 07XXXXXXXX'),
  validateAmountUSD,
  handleValidation,
  async (req, res) => {
    const { amount, phone } = req.body;
    const amt = Number(amount);
    const kes = Math.floor(amt * 130);
    const idempotencyKey =
      req.headers['idempotency-key'] || crypto.randomUUID();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const existing = await client.query(
        `SELECT * FROM withdrawals WHERE idempotency_key=$1`,
        [idempotencyKey]
      );
      if (existing.rows.length) {
        await client.query('COMMIT');
        const wd = existing.rows[0];
        if (wd.two_fa_verified)
          return res.json({
            ok: true,
            message: 'Withdrawal already processed',
            id: wd.id,
          });
        return res.json({
          ok: true,
          requires2FA: amt > 100,
          withdrawalId: wd.id,
          message: 'OTP sent - verify to continue',
        });
      }
      const { rows } = await client.query(
        `SELECT balance FROM users WHERE id=$1 FOR UPDATE`,
        [req.user.id]
      );
      if (Number(rows[0].balance) < amt) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Insufficient funds' });
      }
      const needs2FA = amt > 100;
      const wd = await client.query(
        `INSERT INTO withdrawals (user_id, phone, amount_usd, amount_kes, idempotency_key, status, two_fa_verified) VALUES ($1,$2,$3,$4,$5,'pending',$6) RETURNING *`,
        [req.user.id, phone, amt, kes, idempotencyKey, !needs2FA]
      );
      await client.query('COMMIT');
      if (!needs2FA) return processWithdrawal(req, res, wd.rows[0]);
      const code = String(Math.floor(100000 + Math.random() * 900000));
      const codeHash = await bcrypt.hash(code, 10);
      await pool.query(
        `UPDATE withdrawal_otps SET used=TRUE WHERE user_id=$1 AND used=FALSE`,
        [req.user.id]
      );
      await pool.query(
        `INSERT INTO withdrawal_otps (user_id, withdrawal_id, code_hash, expires_at) VALUES ($1,$2,$3,NOW() + INTERVAL '5 minutes')`,
        [req.user.id, wd.rows[0].id, codeHash]
      );
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: req.user.email,
        subject: 'TradeNova Withdrawal Verification',
        text: `Your withdrawal OTP for $${amt.toFixed(2)} to ${phone} is ${code}. Valid for 5 minutes. If you didn't request this, contact support immediately.`,
      });
      await audit(req, {
        userId: req.user.id,
        action: 'WITHDRAWAL_OTP_SENT',
        entityType: 'withdrawal',
        entityId: wd.rows[0].id,
        metadata: { amount_usd: amt, phone },
      });
      res.json({
        ok: true,
        requires2FA: true,
        withdrawalId: wd.rows[0].id,
        message: 'OTP sent to your email. Enter code to confirm withdrawal.',
      });
    } catch (e) {
      await client.query('ROLLBACK');
      console.error(e);
      res.status(500).json({ error: 'Withdrawal failed' });
    } finally {
      client.release();
    }
  }
);

app.post(
  '/api/withdraw/verify-otp',
  requireAuth,
  blockFrozen,
  otpLimiter,
  body('withdrawalId').isInt().withMessage('Invalid withdrawal'),
  body('code')
    .trim()
    .isLength({ min: 6, max: 6 })
    .withMessage('6-digit code required'),
  handleValidation,
  async (req, res) => {
    const { withdrawalId, code } = req.body;
    const { rows } = await pool.query(
      `SELECT * FROM withdrawals WHERE id=$1 AND user_id=$2`,
      [withdrawalId, req.user.id]
    );
    const wd = rows[0];
    if (!wd) return res.status(404).json({ error: 'Withdrawal not found' });
    if (wd.two_fa_verified)
      return res.json({ ok: true, message: 'Already verified' });
    if (wd.status === 'cancelled')
      return res.status(400).json({ error: 'Withdrawal cancelled' });
    const { rows: otpRows } = await pool.query(
      `SELECT * FROM withdrawal_otps WHERE withdrawal_id=$1 AND used=FALSE ORDER BY created_at DESC LIMIT 1`,
      [withdrawalId]
    );
    const otp = otpRows[0];
    if (!otp)
      return res
        .status(400)
        .json({ error: 'No OTP found. Request withdrawal again.' });
    if (new Date(otp.expires_at) < new Date())
      return res
        .status(400)
        .json({ error: 'OTP expired. Request withdrawal again.' });
    if (otp.attempts >= 3) {
      await pool.query(`UPDATE withdrawal_otps SET used=TRUE WHERE id=$1`, [
        otp.id,
      ]);
      return res
        .status(429)
        .json({ error: 'Too many attempts. Withdrawal locked.' });
    }
    const ok = await bcrypt.compare(code, otp.code_hash);
    if (!ok) {
      await pool.query(
        `UPDATE withdrawal_otps SET attempts = attempts + 1 WHERE id=$1`,
        [otp.id]
      );
      await audit(req, {
        userId: req.user.id,
        action: 'WITHDRAWAL_OTP_FAILED',
        entityType: 'withdrawal',
        entityId: withdrawalId,
        metadata: { attempts: otp.attempts + 1 },
      });
      return res.status(400).json({ error: 'Invalid OTP' });
    }
    await pool.query(`UPDATE withdrawal_otps SET used=TRUE WHERE id=$1`, [
      otp.id,
    ]);
    await pool.query(
      `UPDATE withdrawals SET two_fa_verified=TRUE WHERE id=$1`,
      [withdrawalId]
    );
    await audit(req, {
      userId: req.user.id,
      action: 'WITHDRAWAL_OTP_VERIFIED',
      entityType: 'withdrawal',
      entityId: withdrawalId,
    });
    return processWithdrawal(req, res, wd);
  }
);

async function processWithdrawal(req, res, wd) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `SELECT balance FROM users WHERE id=$1 FOR UPDATE`,
      [wd.user_id]
    );
    if (Number(rows[0].balance) < Number(wd.amount_usd)) {
      await client.query('ROLLBACK');
      await pool.query(`UPDATE withdrawals SET status='failed' WHERE id=$1`, [
        wd.id,
      ]);
      return res
        .status(400)
        .json({ error: 'Insufficient funds at payout time' });
    }
    await client.query(`UPDATE users SET balance = balance - $1 WHERE id=$2`, [
      wd.amount_usd,
      wd.user_id,
    ]);
    let payoutOk = false,
      tumaRef = null;
    try {
      const token = await getTumaToken();
      const r = await fetch(`${process.env.TUMA_BASE_URL}/payment/payout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          phone: wd.phone,
          amount: wd.amount_kes,
          email: req.user.email,
          reference: `WD-${wd.id}`,
          callback_url: `${process.env.BASE_URL}/api/webhook/tuma`,
        }),
      });
      const data = await r.json();
      payoutOk = r.ok;
      tumaRef =
        data.TransactionID || data.reference || data.CheckoutRequestID || null;
      if (!payoutOk) console.error('Tuma payout failed', data);
    } catch (e) {
      console.error('Payout network error', e);
      payoutOk = false;
    }
    if (!payoutOk) {
      await client.query('ROLLBACK');
      await pool.query(`UPDATE withdrawals SET status='failed' WHERE id=$1`, [
        wd.id,
      ]);
      return res
        .status(502)
        .json({
          error: 'Payout provider failed, funds not debited. Try again.',
        });
    }
    await client.query(
      `UPDATE withdrawals SET status='processing', tuma_ref=$1 WHERE id=$2`,
      [tumaRef, wd.id]
    );
    await client.query('COMMIT');
    await audit(req, {
      userId: wd.user_id,
      action: 'WITHDRAWAL_INITIATED',
      entityType: 'withdrawal',
      entityId: wd.id,
      metadata: { amount_usd: wd.amount_usd, phone: wd.phone, tumaRef },
    });
    res.json({
      ok: true,
      message: `Withdrawal of $${Number(wd.amount_usd).toFixed(2)} (${wd.amount_kes} KES) to ${wd.phone} initiated`,
      ref: tumaRef,
    });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Withdrawal failed' });
  } finally {
    client.release();
  }
}

app.post(
  '/api/withdraw/cancel',
  requireAuth,
  body('withdrawalId').isInt(),
  handleValidation,
  async (req, res) => {
    const { rows } = await pool.query(
      `UPDATE withdrawals SET status='cancelled' WHERE id=$1 AND user_id=$2 AND status='pending' RETURNING *`,
      [req.body.withdrawalId, req.user.id]
    );
    if (!rows.length)
      return res.status(404).json({ error: 'Not found or already processed' });
    await pool.query(
      `UPDATE withdrawal_otps SET used=TRUE WHERE withdrawal_id=$1`,
      [req.body.withdrawalId]
    );
    await audit(req, {
      userId: req.user.id,
      action: 'WITHDRAWAL_CANCELLED',
      entityType: 'withdrawal',
      entityId: req.body.withdrawalId,
    });
    res.json({ ok: true });
  }
);

// ---------- ADMIN ----------
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const [users, trades, dep, wd] = await Promise.all([
    pool.query(
      `SELECT COUNT(*) c, COALESCE(SUM(balance),0) total_balance FROM users`
    ),
    pool.query(
      `SELECT COUNT(*) c, COUNT(*) FILTER (WHERE status='WON') won, COUNT(*) FILTER (WHERE status='LOST') lost FROM trades`
    ),
    pool.query(
      `SELECT COUNT(*) c, COALESCE(SUM(amount_usd),0) total FROM deposits WHERE status='completed'`
    ),
    pool.query(
      `SELECT COUNT(*) c, COALESCE(SUM(amount_usd),0) total FROM withdrawals WHERE status IN ('processing','completed')`
    ),
  ]);
  res.json({
    users: users.rows[0],
    trades: trades.rows[0],
    deposits: dep.rows[0],
    withdrawals: wd.rows[0],
  });
});
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const q = (req.query.q || '').trim();
  const { rows } = await pool.query(
    `SELECT id, email, phone, balance, role, is_verified, is_frozen, created_at FROM users WHERE email ILIKE $1 OR phone ILIKE $1 ORDER BY created_at DESC LIMIT 100`,
    [`%${q}%`]
  );
  res.json(rows);
});
app.get('/api/admin/trades', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT t.*, u.email FROM trades t JOIN users u ON u.id=t.user_id ORDER BY t.created_at DESC LIMIT 100`
  );
  res.json(rows);
});
app.get('/api/admin/deposits', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT d.*, u.email FROM deposits d JOIN users u ON u.id=d.user_id ORDER BY d.created_at DESC LIMIT 100`
  );
  res.json(rows);
});
app.get('/api/admin/withdrawals', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT w.*, u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.created_at DESC LIMIT 100`
  );
  res.json(rows);
});
app.get('/api/admin/audit', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT a.*, u.email as user_email, au.email as actor_email FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN users au ON au.id=a.actor_id ORDER BY a.created_at DESC LIMIT 200`
  );
  res.json(rows);
});
app.post('/api/admin/users/:id/freeze', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE users SET is_frozen=TRUE WHERE id=$1 RETURNING *`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'User not found' });
  await audit(req, {
    userId: Number(req.params.id),
    actorId: req.user.id,
    action: 'ADMIN_FREEZE_USER',
    entityType: 'user',
    entityId: req.params.id,
  });
  res.json({ ok: true });
});
app.post('/api/admin/users/:id/unfreeze', requireAdmin, async (req, res) => {
  await pool.query(`UPDATE users SET is_frozen=FALSE WHERE id=$1`, [
    req.params.id,
  ]);
  await audit(req, {
    userId: Number(req.params.id),
    actorId: req.user.id,
    action: 'ADMIN_UNFREEZE_USER',
    entityType: 'user',
    entityId: req.params.id,
  });
  res.json({ ok: true });
});
app.post(
  '/api/admin/adjust-balance',
  requireAdmin,
  body('userId').isInt(),
  body('amount').isFloat({ min: -1000000, max: 1000000 }),
  body('reason').trim().isLength({ min: 5, max: 500 }),
  handleValidation,
  async (req, res) => {
    const { userId, amount, reason } = req.body;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        `SELECT balance FROM users WHERE id=$1 FOR UPDATE`,
        [userId]
      );
      if (!rows.length) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'User not found' });
      }
      if (Number(rows[0].balance) + Number(amount) < 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Would make balance negative' });
      }
      await client.query(
        `UPDATE users SET balance = balance + $1 WHERE id=$2`,
        [amount, userId]
      );
      await client.query('COMMIT');
      await audit(req, {
        userId: Number(userId),
        actorId: req.user.id,
        action: 'ADMIN_BALANCE_ADJUST',
        entityType: 'user',
        entityId: userId,
        metadata: { amount: Number(amount), reason, admin: req.user.email },
      });
      res.json({ ok: true });
    } catch (e) {
      await client.query('ROLLBACK');
      res.status(500).json({ error: 'Adjust failed' });
    } finally {
      client.release();
    }
  }
);

app.get('/api/candles/:asset', (req, res) =>
  res.json(candles[req.params.asset] || [])
);
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

migrate().then(() =>
  server.listen(PORT, () => console.log(`TradeNova on ${PORT}`))
);
