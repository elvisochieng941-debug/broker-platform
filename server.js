const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool, Client } = require('pg');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const nodemailer = require('nodemailer');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

app.use(
  cors({
    origin: [
      'https://broker-platform-3alf.onrender.com',
      'http://localhost:3000',
      'http://127.0.0.1:3000',
    ],
    credentials: true,
  })
);

const io = new Server(server, {
  cors: {
    origin: [
      'https://broker-platform-3alf.onrender.com',
      'http://localhost:3000',
      'http://127.0.0.1:3000',
    ],
    credentials: true,
  },
});

const PORT = process.env.PORT || 3000;
const targetDbUrl =
  process.env.DATABASE_URL ||
  'postgresql://postgres:password@localhost:5432/tradenova_db';
const urlParts = targetDbUrl.split('/');
const dbName = urlParts[urlParts.length - 1];
const baseServerUrl = urlParts.slice(0, urlParts.length - 1).join('/');

async function ensureDatabaseExists() {
  const defaultClient = new Client({
    connectionString: `${baseServerUrl}/postgres`,
    ssl:
      process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false,
  });
  try {
    await defaultClient.connect();
    const res = await defaultClient.query(
      `SELECT 1 FROM pg_database WHERE datname = $1`,
      [dbName]
    );
    if (res.rows.length === 0) {
      await defaultClient.query(`CREATE DATABASE "${dbName}"`);
      console.log(`✅ Database "${dbName}" created successfully!`);
    }
  } catch (err) {
    console.error('⚠️ DB creation notice:', err.message);
  } finally {
    await defaultClient.end();
  }
}

let pool;

async function startServer() {
  await ensureDatabaseExists();
  pool = new Pool({
    connectionString: targetDbUrl,
    ssl:
      process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false,
  });

  await pool
    .query(
      `
    CREATE TABLE IF NOT EXISTS session (
      sid VARCHAR NOT NULL COLLATE "default",
      sess JSON NOT NULL,
      expire TIMESTAMP(6) NOT NULL
    );
    ALTER TABLE session DROP CONSTRAINT IF EXISTS session_pkey;
    ALTER TABLE session ADD CONSTRAINT session_pkey PRIMARY KEY (sid);
    CREATE INDEX IF NOT EXISTS IDX_session_expire ON session (expire);

    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255),
      phone VARCHAR(20),
      balance NUMERIC(12,2) DEFAULT 1000.00,
      verified BOOLEAN DEFAULT FALSE,
      verification_code VARCHAR(6),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) NOT NULL,
      token VARCHAR(255) NOT NULL,
      expires_at TIMESTAMP NOT NULL
    );

    CREATE TABLE IF NOT EXISTS trades (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id),
      asset VARCHAR(20),
      amount NUMERIC(10,2),
      direction VARCHAR(10),
      entry_price NUMERIC(10,4),
      exit_price NUMERIC(10,4),
      status VARCHAR(20) DEFAULT 'active',
      payout NUMERIC(10,2),
      expires_at TIMESTAMP
    );
  `
    )
    .catch((err) => console.error('DB Table Init Error:', err.message));

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(express.static(path.join(__dirname)));

  app.use(
    session({
      store: new PgSession({ pool: pool, tableName: 'session' }),
      secret:
        process.env.SESSION_SECRET || 'super_secret_trading_session_key_2026',
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      },
    })
  );

  app.use(passport.initialize());
  app.use(passport.session());

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });

  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL:
          process.env.CALLBACK_URL ||
          'https://broker-platform-3alf.onrender.com/auth/google/callback',
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails[0].value;
          let result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
          );
          let user;
          if (result.rows.length === 0) {
            const insertRes = await pool.query(
              'INSERT INTO users (email, balance, verified) VALUES ($1, 1000.00, TRUE) RETURNING id, email, phone, balance',
              [email]
            );
            user = insertRes.rows[0];
          } else {
            user = result.rows[0];
          }
          return done(null, user);
        } catch (err) {
          return done(err, null);
        }
      }
    )
  );

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const res = await pool.query(
        'SELECT id, email, phone, balance FROM users WHERE id = $1',
        [id]
      );
      done(null, res.rows[0]);
    } catch (err) {
      done(err, null);
    }
  });

  app.get('/api/auth/status', (req, res) => {
    if (req.isAuthenticated && req.isAuthenticated()) {
      res.json({ authenticated: true, user: req.user });
    } else if (req.session && req.session.userId) {
      res.json({ authenticated: true, user: req.session.user });
    } else {
      res.json({ authenticated: false });
    }
  });

  app.post('/api/auth/signup', async (req, res) => {
    try {
      const { email, password, phone } = req.body;
      if (!email || !email.includes('@'))
        return res
          .status(400)
          .json({ success: false, error: 'Invalid email.' });
      if (!password || password.length < 8)
        return res
          .status(400)
          .json({
            success: false,
            error: 'Password must be at least 8 chars.',
          });

      const phoneRegex = /^(?:254|\+254|0)?([17][0-9]{8})$/;
      if (!phoneRegex.test(phone))
        return res
          .status(400)
          .json({ success: false, error: 'Invalid phone number.' });

      const emailCheck = await pool.query(
        'SELECT * FROM users WHERE email = $1',
        [email]
      );
      if (emailCheck.rows.length > 0 && emailCheck.rows[0].verified) {
        return res
          .status(400)
          .json({ success: false, error: 'Email already registered.' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const verificationCode = Math.floor(
        100000 + Math.random() * 900000
      ).toString();

      if (emailCheck.rows.length > 0) {
        await pool.query(
          'UPDATE users SET password_hash = $1, phone = $2, verification_code = $3 WHERE email = $4',
          [hashedPassword, phone, verificationCode, email]
        );
      } else {
        await pool.query(
          'INSERT INTO users (email, password_hash, phone, balance, verified, verification_code) VALUES ($1, $2, $3, 1000.00, FALSE, $4)',
          [email, hashedPassword, phone, verificationCode]
        );
      }

      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'TradeNova - Verification Code',
        text: `Your verification code is: ${verificationCode}`,
      });

      res.json({
        success: true,
        requiresVerification: true,
        email,
        message: 'Verification code sent to your email!',
      });
    } catch (err) {
      res
        .status(500)
        .json({ success: false, error: 'Server error during signup.' });
    }
  });

  app.post('/api/auth/verify-code', async (req, res) => {
    try {
      const { email, code, remember } = req.body;
      const result = await pool.query('SELECT * FROM users WHERE email = $1', [
        email,
      ]);
      if (result.rows.length === 0)
        return res
          .status(400)
          .json({ success: false, error: 'User not found.' });

      const user = result.rows[0];
      if (user.verification_code !== code.toString().trim()) {
        return res
          .status(400)
          .json({ success: false, error: 'Invalid verification code.' });
      }

      await pool.query(
        'UPDATE users SET verified = TRUE, verification_code = NULL WHERE email = $1',
        [email]
      );
      req.session.userId = user.id;
      req.session.user = {
        email: user.email,
        phone: user.phone,
        balance: user.balance,
      };
      if (remember) req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;

      res.json({
        success: true,
        message: 'Email verified successfully!',
        user: req.session.user,
      });
    } catch (err) {
      res.status(500).json({ success: false, error: 'Verification failed.' });
    }
  });

  app.post('/api/auth/signin', async (req, res) => {
    try {
      const { email, password, remember } = req.body;
      const result = await pool.query('SELECT * FROM users WHERE email = $1', [
        email,
      ]);
      if (result.rows.length === 0)
        return res
          .status(401)
          .json({ success: false, error: 'Account not found.' });

      const user = result.rows[0];
      if (!user.verified)
        return res
          .status(401)
          .json({ success: false, error: 'Please verify your email first.' });

      const match = await bcrypt.compare(password, user.password_hash);
      if (!match)
        return res
          .status(401)
          .json({ success: false, error: 'Incorrect password.' });

      req.session.userId = user.id;
      req.session.user = {
        email: user.email,
        phone: user.phone,
        balance: user.balance,
      };
      if (remember) req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;

      res.json({
        success: true,
        message: 'Signed in successfully!',
        user: req.session.user,
      });
    } catch (err) {
      res
        .status(500)
        .json({ success: false, error: 'Authentication failure.' });
    }
  });

  app.post('/api/auth/forgot-password', async (req, res) => {
    try {
      const { email } = req.body;
      const result = await pool.query('SELECT * FROM users WHERE email = $1', [
        email,
      ]);
      if (result.rows.length === 0)
        return res
          .status(404)
          .json({ success: false, error: 'Email not registered.' });

      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 3600000);
      await pool.query('DELETE FROM password_resets WHERE email = $1', [email]);
      await pool.query(
        'INSERT INTO password_resets (email, token, expires_at) VALUES ($1, $2, $3)',
        [email, token, expiresAt]
      );

      const resetLink = `${process.env.BASE_URL}/reset-password.html?token=${token}&email=${email}`;
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'TradeNova - Password Reset',
        text: `Reset link: ${resetLink}`,
      });

      res.json({ success: true, message: 'Recovery email sent.' });
    } catch (err) {
      res.status(500).json({ success: false, error: 'Failed.' });
    }
  });

  app.get(
    '/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
  );
  app.get(
    '/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
      req.session.userId = req.user.id;
      req.session.user = req.user;
      res.redirect('/');
    }
  );

  app.post('/api/auth/logout', (req, res) => {
    req.logout(() => {
      req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.json({ success: true, message: 'Logged out.' });
      });
    });
  });

  const TUMA_BASE_URL = process.env.TUMA_BASE_URL || 'https://api.tuma.co.ke';
  async function getTumaToken() {
    const response = await axios.post(`${TUMA_BASE_URL}/auth/token`, {
      email: process.env.TUMA_BUSINESS_EMAIL,
      api_key: process.env.TUMA_API_KEY,
    });
    return response.data.data.token || response.data.token;
  }

  app.post('/api/deposit', async (req, res) => {
    if (!req.session?.userId)
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    try {
      const { amount, phone } = req.body;
      const token = await getTumaToken();
      let fmtPhone = phone.startsWith('0') ? '254' + phone.slice(1) : phone;

      const paymentRes = await axios.post(
        `${TUMA_BASE_URL}/payment/stk-push`,
        {
          amount: Number(amount),
          phone: fmtPhone,
          callback_url: `${process.env.BASE_URL}/api/webhook/tuma`,
          description: `TradeNova Deposit #${req.session.userId}`,
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      res.json({
        success: true,
        message: 'STK Push sent!',
        data: paymentRes.data,
      });
    } catch (err) {
      res
        .status(500)
        .json({
          success: false,
          error: err.response?.data?.message || 'Deposit failed.',
        });
    }
  });

  app.post('/api/withdraw', async (req, res) => {
    if (!req.session?.userId)
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    const { amount, phone } = req.body;
    try {
      const userRes = await pool.query(
        'SELECT balance FROM users WHERE id = $1',
        [req.session.userId]
      );
      const balance = Number(userRes.rows[0].balance);
      if (balance < amount)
        return res
          .status(400)
          .json({ success: false, error: 'Insufficient funds.' });

      await pool.query(
        'UPDATE users SET balance = balance - $1 WHERE id = $2',
        [amount, req.session.userId]
      );
      req.session.user.balance = balance - Number(amount);
      res.json({
        success: true,
        message: `Withdrew $${amount} to ${phone}`,
        newBalance: req.session.user.balance,
      });
    } catch (err) {
      res.status(500).json({ success: false, error: 'Withdrawal failed.' });
    }
  });

  app.post('/api/webhook/tuma', (req, res) =>
    res.status(200).json({ received: true })
  );

  app.post('/api/trade/place', async (req, res) => {
    if (!req.session?.userId)
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    const { asset, amount, direction, entryPrice } = req.body;
    try {
      const userRes = await pool.query(
        'SELECT balance FROM users WHERE id = $1',
        [req.session.userId]
      );
      const balance = Number(userRes.rows[0].balance);
      if (balance < amount)
        return res
          .status(400)
          .json({ success: false, error: 'Insufficient balance.' });

      const expiresAt = new Date(Date.now() + 60000);
      await pool.query(
        'UPDATE users SET balance = balance - $1 WHERE id = $2',
        [amount, req.session.userId]
      );
      const tradeRes = await pool.query(
        'INSERT INTO trades (user_id, asset, amount, direction, entry_price, expires_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
        [req.session.userId, asset, amount, direction, entryPrice, expiresAt]
      );
      req.session.user.balance = balance - amount;
      res.json({
        success: true,
        trade: tradeRes.rows[0],
        newBalance: req.session.user.balance,
      });
    } catch (err) {
      res.status(500).json({ success: false, error: 'Trade failed.' });
    }
  });

  app.get('/api/trade/history', async (req, res) => {
    if (!req.session?.userId) return res.status(401).json({ success: false });
    const trades = await pool.query(
      'SELECT * FROM trades WHERE user_id = $1 ORDER BY id DESC',
      [req.session.userId]
    );
    res.json({ success: true, trades: trades.rows });
  });

  let currentPrice = 1.0925;
  setInterval(() => {
    currentPrice = Number(
      (currentPrice + (Math.random() - 0.49) * 0.0008).toFixed(4)
    );
    io.emit('priceTick', { time: Date.now(), price: currentPrice });
  }, 1000);

  setInterval(async () => {
    try {
      const expiredTrades = await pool.query(
        "SELECT * FROM trades WHERE status = 'active' AND expires_at <= NOW()"
      );
      for (let trade of expiredTrades.rows) {
        const won =
          (trade.direction === 'higher' && currentPrice > trade.entry_price) ||
          (trade.direction === 'lower' && currentPrice < trade.entry_price);
        const payout = won ? Number(trade.amount) * 1.92 : 0;
        await pool.query(
          'UPDATE trades SET status = $1, exit_price = $2, payout = $3 WHERE id = $4',
          [won ? 'won' : 'lost', currentPrice, payout, trade.id]
        );
        if (won)
          await pool.query(
            'UPDATE users SET balance = balance + $1 WHERE id = $2',
            [payout, trade.user_id]
          );
      }
    } catch (err) {}
  }, 1000);

  app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
  server.listen(PORT, () => console.log(`🚀 TradeNova live at port ${PORT}`));
}

startServer().catch((err) => console.error(err));
