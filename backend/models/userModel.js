/**
 * userModel.js - SQLite database model using sql.js (pure JS, no native binaries)
 * Table: users (id, email, password_hash, is_2fa_enabled, secret_2fa)
 */

const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const DB_DIR  = path.join(__dirname, '../../data');
const DB_PATH = path.join(DB_DIR, 'security_demo.db');

if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

// We'll use synchronous-style by initializing once at startup
let db;
let initialized = false;

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id               TEXT PRIMARY KEY,
    email            TEXT UNIQUE NOT NULL,
    password_hash    TEXT NOT NULL,
    is_2fa_enabled   INTEGER NOT NULL DEFAULT 0,
    secret_2fa       TEXT,
    display_name     TEXT,
    token_version    INTEGER NOT NULL DEFAULT 0,
    backup_codes     TEXT, -- Store hashed backup codes
    last_known_ip    TEXT,
    last_known_ua    TEXT,
    role             TEXT NOT NULL DEFAULT 'user', -- 'user', 'admin'
    is_locked        INTEGER NOT NULL DEFAULT 0,
    api_key          TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    last_login       TEXT
  );

  CREATE TABLE IF NOT EXISTS security_alerts (
    id            TEXT PRIMARY KEY,
    user_id       TEXT,
    alert_type    TEXT NOT NULL, -- BRUTE_FORCE, CREDENTIAL_STUFFING, UNUSUAL_LOGIN
    severity      TEXT DEFAULT 'MEDIUM',
    ip_address    TEXT,
    details       TEXT,
    status        TEXT DEFAULT 'NEW',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS password_history (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id         TEXT PRIMARY KEY,
    user_id    TEXT,
    action     TEXT NOT NULL,
    ip_address TEXT,
    details    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS login_attempts (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    last_attempt  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS active_sessions (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    refresh_token TEXT UNIQUE NOT NULL,
    user_agent    TEXT,
    ip_address    TEXT,
    device_id     TEXT,
    trusted       INTEGER NOT NULL DEFAULT 0,
    expires_at    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS trusted_devices (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    device_name   TEXT,
    user_agent    TEXT,
    ip_address    TEXT,
    trusted_until TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at  TEXT
  );

  CREATE TABLE IF NOT EXISTS login_behavior_history (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL,
    ip_address       TEXT,
    user_agent       TEXT,
    device           TEXT,
    login_hour       INTEGER,
    location_country  TEXT,
    location_city    TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
  );
`;

// Persist DB to disk
function saveDb() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

async function ensureInit() {
  if (initialized) return;
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  // Ensure tables exist
  db.run(SCHEMA);

  // MIGRATION: Ensure all columns exist for 'users'
  // (CREATE TABLE IF NOT EXISTS doesn't add missing columns to an existing table)
  try {
    const tableInfo = [];
    const stmt = db.prepare('PRAGMA table_info(users)');
    while (stmt.step()) tableInfo.push(stmt.getAsObject().name);
    stmt.free();

    if (!tableInfo.includes('backup_codes')) {
      db.run('ALTER TABLE users ADD COLUMN backup_codes TEXT');
    }
    if (!tableInfo.includes('token_version')) {
      db.run('ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0');
    }
    if (!tableInfo.includes('last_known_ip')) {
      db.run('ALTER TABLE users ADD COLUMN last_known_ip TEXT');
    }
    if (!tableInfo.includes('last_known_ua')) {
      db.run('ALTER TABLE users ADD COLUMN last_known_ua TEXT');
    }
    if (!tableInfo.includes('role')) {
      db.run("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
    }
    if (!tableInfo.includes('is_locked')) {
      db.run('ALTER TABLE users ADD COLUMN is_locked INTEGER NOT NULL DEFAULT 0');
    }
    if (!tableInfo.includes('api_key')) {
      db.run('ALTER TABLE users ADD COLUMN api_key TEXT');
    }

    const sessionInfo = [];
    const stmtSession = db.prepare('PRAGMA table_info(active_sessions)');
    while (stmtSession.step()) sessionInfo.push(stmtSession.getAsObject().name);
    stmtSession.free();
    if (!sessionInfo.includes('device_id')) db.run('ALTER TABLE active_sessions ADD COLUMN device_id TEXT');
    if (!sessionInfo.includes('trusted')) db.run('ALTER TABLE active_sessions ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0');

    const trustedInfo = [];
    const stmtTrusted = db.prepare('PRAGMA table_info(trusted_devices)');
    while (stmtTrusted.step()) trustedInfo.push(stmtTrusted.getAsObject().name);
    stmtTrusted.free();
    if (trustedInfo.length === 0) {
      db.run(`CREATE TABLE IF NOT EXISTS trusted_devices (
        id            TEXT PRIMARY KEY,
        user_id       TEXT NOT NULL,
        device_id     TEXT NOT NULL,
        device_name   TEXT,
        user_agent    TEXT,
        ip_address    TEXT,
        trusted_until TEXT,
        created_at    TEXT NOT NULL DEFAULT (datetime('now')),
        last_used_at  TEXT
      )`);
    }

    const behaviorInfo = [];
    const stmtBehavior = db.prepare('PRAGMA table_info(login_behavior_history)');
    while (stmtBehavior.step()) behaviorInfo.push(stmtBehavior.getAsObject().name);
    stmtBehavior.free();
    if (behaviorInfo.length > 0) {
      if (!behaviorInfo.includes('location_country')) db.run('ALTER TABLE login_behavior_history ADD COLUMN location_country TEXT');
      if (!behaviorInfo.includes('location_city')) db.run('ALTER TABLE login_behavior_history ADD COLUMN location_city TEXT');
    }
  } catch (err) {
    console.error('[Migration Error]', err);
  }

  saveDb();
  initialized = true;
}

// Helper: run INSERT/UPDATE/DELETE
function run(sql, params = []) {
  db.run(sql, params);
  saveDb();
}

// Helper: get single row
function get(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

// Helper: get all rows
function all(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ─── Public API (all async for consistency) ───────────────────────────────────

module.exports = {
  init: ensureInit,

  findByEmail: (email) => get(
    'SELECT * FROM users WHERE email = ?', [email]
  ),
  findById: (id) => get(
    'SELECT * FROM users WHERE id = ?', [id]
  ),
  create: ({ id, email, password_hash, is_2fa_enabled = 0, secret_2fa = null, role = 'user' }) => {
    run(
      'INSERT INTO users (id, email, password_hash, is_2fa_enabled, secret_2fa, role, display_name) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [id, email, password_hash, is_2fa_enabled, secret_2fa, role, role === 'admin' ? 'Administrator' : 'General User']
    );
  },
  listAll: () => all('SELECT * FROM users ORDER BY created_at DESC'),
  lockAccount: (id) => run('UPDATE users SET is_locked = 1 WHERE id = ?', [id]),
  unlockAccount: (id) => run('UPDATE users SET is_locked = 0 WHERE id = ?', [id]),

  /**
   * Hard-delete a user and ALL their associated data
   * Called only by Admin — irreversible
   */
  deleteUserData: (userId, email) => {
    run('DELETE FROM active_sessions WHERE user_id = ?', [userId]);
    run('DELETE FROM security_alerts WHERE user_id = ?', [userId]);
    run('DELETE FROM audit_logs WHERE user_id = ?', [userId]);
    run('DELETE FROM login_attempts WHERE email = ?', [email]);
    run('DELETE FROM password_history WHERE user_id = ?', [userId]);
    run('DELETE FROM trusted_devices WHERE user_id = ?', [userId]);
    run('DELETE FROM login_behavior_history WHERE user_id = ?', [userId]);
    run('DELETE FROM users WHERE id = ?', [userId]);
  },

  ensureSeedUsers: async () => {
    const adminEmail = 'admin.security@gmail.com';
    const userEmail = 'testuser.demo@gmail.com';
    const superAdminEmail = 'superadmin.pro@gmail.com';

    // 1. Core Seed users
    if (!get('SELECT id FROM users WHERE email = ?', [adminEmail])) {
      const adminHash = await bcrypt.hash('Admin@12345', 12);
      module.exports.create({ id: require('uuid').v4(), email: adminEmail, password_hash: adminHash, role: 'admin' });
    }
    if (!get('SELECT id FROM users WHERE email = ?', [userEmail])) {
      // Mật khẩu yếu — dễ bị brute force
      const userHash = await bcrypt.hash('User@123456', 12);
      module.exports.create({ id: require('uuid').v4(), email: userEmail, password_hash: userHash, role: 'user' });
    }
    if (!get('SELECT id FROM users WHERE email = ?', [superAdminEmail])) {
      const superAdminHash = await bcrypt.hash('SuperAdmin@123', 12);
      module.exports.create({ id: require('uuid').v4(), email: superAdminEmail, password_hash: superAdminHash, role: 'admin' });
    }

    // 2. Extra demo users for attack simulation scenarios
    const demoUsers = [
      { email: 'alice.weak@gmail.com',   password: '123456',       role: 'user' },
      { email: 'bob.common@gmail.com',   password: 'password',     role: 'user' },
      { email: 'carol.hr@gmail.com',     password: 'User@12345',   role: 'user' },
      { email: 'dave.dev@gmail.com',     password: 'Test@123456',  role: 'user' },
      { email: 'eve.finance@gmail.com',  password: 'Admin@123456', role: 'user' },
    ];
    // Cleanup: remove old demo accounts if they exist in DB
    for (const u of demoUsers) {
      const existing = get('SELECT id, email FROM users WHERE email = ?', [u.email]);
      if (existing) {
        run('DELETE FROM active_sessions WHERE user_id = ?', [existing.id]);
        run('DELETE FROM security_alerts WHERE user_id = ?', [existing.id]);
        run('DELETE FROM audit_logs WHERE user_id = ?', [existing.id]);
        run('DELETE FROM login_attempts WHERE email = ?', [existing.email]);
        run('DELETE FROM password_history WHERE user_id = ?', [existing.id]);
        run('DELETE FROM trusted_devices WHERE user_id = ?', [existing.id]);
        run('DELETE FROM login_behavior_history WHERE user_id = ?', [existing.id]);
        run('DELETE FROM users WHERE id = ?', [existing.id]);
        console.log(`[Seed] Removed old demo account: ${u.email}`);
      }
    }

    // 3. FORCE Roles upgrade (Safeguard for existing DB rows)
    run("UPDATE users SET role = 'admin' WHERE email IN (?, ?)", [adminEmail, superAdminEmail]);
    run("UPDATE users SET role = 'user' WHERE email = ?", [userEmail]);

    // 4. FORCE update testuser password in case DB already existed with old hash
    const testUser = get('SELECT id FROM users WHERE email = ?', [userEmail]);
    if (testUser) {
      const newHash = await bcrypt.hash('User@123456', 12);
      run('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, testUser.id]);
    }
  },
  updatePasswordHash: (id, hash) => run(
    'UPDATE users SET password_hash = ? WHERE id = ?', [hash, id]
  ),
  updateProfile: (id, { display_name, email }) => run(
    'UPDATE users SET display_name = ?, email = ? WHERE id = ?',
    [display_name, email, id]
  ),
  updateApiKey: (id, apiKey) => run(
    'UPDATE users SET api_key = ? WHERE id = ?', [apiKey, id]
  ),
  findByApiKey: (apiKey) => get(
    'SELECT * FROM users WHERE api_key = ?', [apiKey]
  ),
  enable2FA: (id, secret) => run(
    'UPDATE users SET is_2fa_enabled = 1, secret_2fa = ? WHERE id = ?', [secret, id]
  ),
  disable2FA: (id) => run(
    'UPDATE users SET is_2fa_enabled = 0, secret_2fa = NULL WHERE id = ?', [id]
  ),
  // Mark secret stored but not yet enabled (pending verification)
  storeSecret: (id, secret) => run(
    'UPDATE users SET secret_2fa = ?, is_2fa_enabled = 0 WHERE id = ?', [secret, id]
  ),
  setLastLogin: (id) => run(
    "UPDATE users SET last_login = datetime('now') WHERE id = ?", [id]
  ),
  getLoginAttempts: (email) => get(
    'SELECT * FROM login_attempts WHERE email = ?', [email]
  ),
  recordFailedAttempt: (id, email) => run(
    "INSERT INTO login_attempts (id, email, attempt_count, last_attempt) VALUES (?, ?, 1, datetime('now')) ON CONFLICT(email) DO UPDATE SET attempt_count = attempt_count + 1, last_attempt = datetime('now')",
    [id, email]
  ),
  resetLoginAttempts: (email) => run(
    'DELETE FROM login_attempts WHERE email = ?', [email]
  ),
  savePasswordHistory: (id, userId, hash) => run(
    'INSERT INTO password_history (id, user_id, password_hash) VALUES (?, ?, ?)',
    [id, userId, hash]
  ),
  getPasswordHistory: (userId) => all(
    'SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
    [userId]
  ),

  logAudit: (id, userId, action, ip, details = null) => run(
    'INSERT INTO audit_logs (id, user_id, action, ip_address, details) VALUES (?, ?, ?, ?, ?)',
    [id, userId, action, ip, details]
  ),
  getUserAuditLogs: (userId) => all(
    'SELECT action, ip_address, details, created_at FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
    [userId]
  ),
  getGlobalAuditLogs: () => all(
    'SELECT user_id, action, ip_address, details, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100'
  ),

  // ─── Session Management (JWT Refresh) ───────────────────────────────────────
  incrementTokenVersion: (userId) => run(
    'UPDATE users SET token_version = token_version + 1 WHERE id = ?', [userId]
  ),
  storeSession: (id, userId, refreshToken, userAgent, ipAddress, expiresAt, deviceId = null, trusted = 0) => run(
    'INSERT INTO active_sessions (id, user_id, refresh_token, user_agent, ip_address, device_id, trusted, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [id, userId, refreshToken, userAgent, ipAddress, deviceId, trusted ? 1 : 0, expiresAt]
  ),
  findSession: (refreshToken) => get(
    'SELECT * FROM active_sessions WHERE refresh_token = ?', [refreshToken]
  ),
  deleteSession: (refreshToken) => run(
    'DELETE FROM active_sessions WHERE refresh_token = ?', [refreshToken]
  ),
  revokeSessionById: (sessionId, userId) => run(
    'DELETE FROM active_sessions WHERE id = ? AND user_id = ?', [sessionId, userId]
  ),
  revokeAllSessions: (userId) => {
    run('DELETE FROM active_sessions WHERE user_id = ?', [userId]);
    run('DELETE FROM trusted_devices WHERE user_id = ?', [userId]);
    run('UPDATE users SET token_version = token_version + 1 WHERE id = ?', [userId]);
  },
  getUserSessions: (userId) => all(
    'SELECT id, user_id, ip_address, user_agent, device_id, trusted, created_at, expires_at FROM active_sessions WHERE user_id = ? ORDER BY created_at DESC',
    [userId]
  ),
  addTrustedDevice: (id, userId, deviceId, deviceName, userAgent, ipAddress, trustedUntil) => run(
    'INSERT INTO trusted_devices (id, user_id, device_id, device_name, user_agent, ip_address, trusted_until, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime(\'now\'))',
    [id, userId, deviceId, deviceName, userAgent, ipAddress, trustedUntil]
  ),
  findTrustedDevice: (userId, deviceId) => get(
    'SELECT * FROM trusted_devices WHERE user_id = ? AND device_id = ?', [userId, deviceId]
  ),
  listTrustedDevices: (userId) => all(
    'SELECT * FROM trusted_devices WHERE user_id = ? ORDER BY created_at DESC',
    [userId]
  ),
  revokeTrustedDevice: (userId, deviceId) => run(
    'DELETE FROM trusted_devices WHERE user_id = ? AND device_id = ?', [userId, deviceId]
  ),
  lockUser: (userId) => run(
    'UPDATE users SET token_version = token_version + 1 WHERE id = ?', [userId]
  ),
  resetPasswordAdmin: async (userId, newPassword) => {
    const newPasswordHash = await bcrypt.hash(newPassword, 12);
    run('UPDATE users SET password_hash = ? WHERE id = ?', [newPasswordHash, userId]);
    run('DELETE FROM active_sessions WHERE user_id = ?', [userId]);
    run('UPDATE users SET token_version = token_version + 1 WHERE id = ?', [userId]);
  },
  getRiskSummary: (userId) => {
    const user = get('SELECT * FROM users WHERE id = ?', [userId]);
    if (!user) return null;
    const attempts = get('SELECT * FROM login_attempts WHERE email = ?', [user.email]);
    const alerts = all('SELECT * FROM security_alerts WHERE user_id = ? ORDER BY created_at DESC LIMIT 20', [userId]);
    const behavior = all('SELECT * FROM login_behavior_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', [userId]);
    const sessions = all('SELECT * FROM active_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', [userId]);
    const lockCount = attempts ? attempts.attempt_count : 0;
    return { user, attempts, alerts, behavior, sessions, lockCount };
  },

  // ─── Security Detection & Advanced 2FA ──────────────────────────────────────
  saveBackupCodes: (userId, hashedCodesJson) => run(
    'UPDATE users SET backup_codes = ? WHERE id = ?', [hashedCodesJson, userId]
  ),
  updateUserIdentity: (userId, ip, ua) => run(
    'UPDATE users SET last_known_ip = ?, last_known_ua = ? WHERE id = ?', [ip, ua, userId]
  ),
  recordLoginBehavior: (userId, { ip, ua, device, hour, location_country = null, location_city = null }) => run(
    'INSERT INTO login_behavior_history (id, user_id, ip_address, user_agent, device, login_hour, location_country, location_city) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [require('uuid').v4(), userId, ip, ua, device, hour, location_country, location_city]
  ),
  getLoginBehaviorHistory: (userId, limit = 20) => all(
    'SELECT ip_address, user_agent, device, login_hour, location_country, location_city, created_at FROM login_behavior_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
    [userId, limit]
  ),
  createAlert: (id, userId, type, severity, ip, details) => run(
    'INSERT INTO security_alerts (id, user_id, alert_type, severity, ip_address, details) VALUES (?, ?, ?, ?, ?, ?)',
    [id, userId, type, severity, ip, details]
  ),
  getUserAlerts: (userId) => all(
    'SELECT * FROM security_alerts WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', [userId]
  ),
  resolveAllAlerts: (userId) => run(
    'DELETE FROM security_alerts WHERE user_id = ?', [userId]
  ),
  getGlobalAlerts: () => all(
    'SELECT s.*, u.email FROM security_alerts s LEFT JOIN users u ON s.user_id = u.id ORDER BY s.created_at DESC LIMIT 50'
  ),
  getSecurityMetrics: (userId = null) => {
    let filterAudit = '';
    let filterAlerts = '';
    let params = [];
    if (userId) {
      filterAudit = ' AND user_id = ?';
      filterAlerts = ' AND user_id = ?';
      params = [userId];
    }

    const loginSuccess = get(`SELECT COUNT(*) AS total FROM audit_logs WHERE action = 'LOGIN_SUCCESS'${filterAudit}`, params)?.total || 0;
    const loginFail = get(`SELECT COUNT(*) AS total FROM audit_logs WHERE action IN ('LOGIN_FAILED', 'LOGIN_BLOCKED', 'ACCOUNT_LOCKED')${filterAudit}`, params)?.total || 0;
    const suspicious = get(`SELECT COUNT(*) AS total FROM security_alerts WHERE alert_type IN ('SUSPICIOUS_LOGIN', 'IMPOSSIBLE_TRAVEL', 'RISK_BLOCK', 'CREDENTIAL_STUFFING', 'BRUTE_FORCE')${filterAlerts}`, params)?.total || 0;
    const topIpRows = all(
      `SELECT ip_address AS ip, COUNT(*) AS count
       FROM security_alerts
       WHERE ip_address IS NOT NULL AND ip_address != ''${filterAlerts}
       GROUP BY ip_address
       ORDER BY count DESC
       LIMIT 5`, params
    );
    return {
      loginSuccess: Number(loginSuccess),
      loginFail: Number(loginFail),
      suspicious: Number(suspicious),
      topIpAttackers: topIpRows,
    };
  }
};
