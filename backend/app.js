/**
 * app.js - Express application entry point
 * Security Demo: Weak Passwords & 2FA
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const session = require('express-session');

const { router: authRoutes } = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-KEY'],
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'session_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 2 * 60 * 60 * 1000 },
}));

// ─── Static Frontend ──────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, '../frontend')));

// ─── API Routes ───────────────────────────────────────────────────────────────

app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);

// ─── Health Check ─────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Password Security Demo API is running',
    timestamp: new Date().toISOString(),
    features: [
      'Password Strength Analysis (zxcvbn)',
      'Strong Password Generator',
      'Passphrase Generator',
      'TOTP 2FA (otpauth)',
      'QR Code Generation',
      'Brute-force Time Estimation',
      'Credential Stuffing Simulation',
      'Account Lockout Protection',
    ],
  });
});

// ─── Frontend Routing ─────────────────────────────────────────────────────────

app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../frontend/pages/login.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, '../frontend/pages/login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, '../frontend/pages/register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, '../frontend/pages/dashboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, '../frontend/pages/admin.html')));
app.get('/attack-lab', (req, res) => res.sendFile(path.join(__dirname, '../frontend/pages/attack-lab.html')));

// ─── 404 ─────────────────────────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// ─── Error Handler ────────────────────────────────────────────────────────────

app.use((err, req, res, _next) => {
  console.error('[Server Error]', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────────────────────

const User = require('./models/userModel');
User.init().then(async () => {
  await User.ensureSeedUsers();
  console.log('✅ Database initialized');
  
  const server = app.listen(PORT, () => {
    console.log(`\n🔐 Password Security Demo`);
    console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    console.log(`🚀 Server running at: http://localhost:${PORT}`);
    console.log(`📊 API health:        http://localhost:${PORT}/api/health`);
    console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`\n⚠️  Port ${PORT} đang bị chiếm dụng — đang tự động giải phóng...`);
      try {
        const { execSync } = require('child_process');
        // Windows: find PID listening on port and kill it
        const result = execSync(`netstat -ano | findstr ":${PORT}.*LISTENING"`, { encoding: 'utf8' });
        const lines = result.trim().split('\n');
        const killedPids = new Set();
        for (const line of lines) {
          const parts = line.trim().split(/\s+/);
          const pid = parts[parts.length - 1];
          if (pid && !isNaN(pid) && pid !== '0' && !killedPids.has(pid)) {
            killedPids.add(pid);
            try {
              execSync(`taskkill /PID ${pid} /F`, { encoding: 'utf8' });
              console.log(`✅ Đã kill process PID ${pid} đang chiếm port ${PORT}`);
            } catch (e) { /* already dead */ }
          }
        }
        // Retry after a short delay
        setTimeout(() => {
          server.listen(PORT);
        }, 1000);
      } catch (e) {
        console.error(`❌ Không thể tự giải phóng port ${PORT}.`);
        console.error(`   Chạy thủ công: netstat -ano | findstr :${PORT}  →  taskkill /PID <số> /F\n`);
        process.exit(1);
      }
    }
  });

}).catch(err => {
  console.error('❌ DB init failed:', err);
  process.exit(1);
});

module.exports = app;

