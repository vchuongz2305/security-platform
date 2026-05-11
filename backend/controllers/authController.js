/**
 * authController.js
 * Handles registration, login, 2FA setup/verify, password tools
 */

const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const { hashPassword, comparePassword } = require('../utils/hash');
const { analyzePassword, generateStrongPassword, generatePassphrase: genPassphrase, isPasswordReused } = require('../services/passwordService');
const { validatePolicy, getPolicySpec, POLICY } = require('../services/passwordPolicy');
const { generateTOTPSecret, generateQRCode, verifyTOTP, generateCurrentToken } = require('../services/otpService');
const { simulateCredentialStuffing, getBruteForceEstimate, assessReuseRisk, BREACH_STATS } = require('../services/securityService');
const { detectThreats, getBehaviorProfile } = require('../services/attackDetectionEngine');
const { sendSecurityAlert } = require('../services/emailService');
const bcrypt = require('bcryptjs');


const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';
const MAX_ATTEMPTS = 5;

// ─── Helpers ────────────────────────────────────────────────────────────────

function logEvent(req, userId, action, details = null) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || 'unknown';
  try {
    User.logAudit(uuidv4(), userId, action, ip, details);
  } catch (err) {
    console.error('[Audit Log Error]', err);
  }
}

const crypto = require('crypto');

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, tokenVersion: user.token_version, twoFAPending: false },
    JWT_SECRET,
    { expiresIn: '15m' } // Giảm xuống 15 phút, yêu cầu Refresh
  );
}

function signPendingToken(user, meta = {}) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      tokenVersion: user.token_version,
      twoFAPending: true,
      trustDevice: !!meta.trustDevice,
      deviceId: meta.deviceId || null,
      deviceName: meta.deviceName || null,
    },
    JWT_SECRET,
    { expiresIn: '5m' }
  );
}

function generateRefreshToken() {
  return crypto.randomBytes(40).toString('hex');
}

function buildSuspiciousLoginResponse(behavior, threats = []) {
  return {
    suspicious: true,
    riskScore: behavior.score,
    reasons: behavior.suspiciousReasons,
    profile: {
      ip: behavior.ip,
      device: behavior.device,
      loginHour: behavior.hour,
    },
    threats,
  };
}

function getDeviceId(req) {
  const ua = req.headers['user-agent'] || 'Unknown';
  const platform = req.headers['sec-ch-ua-platform'] || '';
  const mobile = req.headers['sec-ch-ua-mobile'] || '';
  return Buffer.from(`${ua}|${platform}|${mobile}`).toString('base64').replace(/=+$/g, '');
}

// ─── Register ────────────────────────────────────────────────────────────────

exports.register = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Vui lòng điền email và mật khẩu.' });
    }

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,10}$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Định dạng email không hợp lệ.' });
    }

    const cleanEmail = email.trim().toLowerCase();

    // ── FR2: Enterprise Password Policy ──────────────────────────
    const policy = validatePolicy(password);
    if (!policy.valid) {
      return res.status(400).json({
        success: false,
        message: 'Mật khẩu không đáp ứng chính sách bảo mật.',
        violations: policy.violations,
        passed: policy.passed,
      });
    }

    // Check existing user
    if (User.findByEmail(cleanEmail)) {
      return res.status(409).json({ success: false, message: 'Email này đã được đăng ký' });
    }

    // Analyze password strength (zxcvbn — enterprise threshold = 3)
    const analysis = analyzePassword(password);
    if (analysis.score < POLICY.MIN_ZXCVBN_SCORE) {
      return res.status(400).json({
        success: false,
        message: `Mật khẩu chưa đủ mạnh (score ${analysis.score}/4, cần ít nhất ${POLICY.MIN_ZXCVBN_SCORE}). ${analysis.feedback.warning || ''}`,
        analysis,
      });
    }

    if (analysis.isCommon) {
      return res.status(400).json({
        success: false,
        message: 'Mật khẩu này có trong danh sách mật khẩu phổ biến và không được phép.',
        analysis,
      });
    }

    const password_hash = await hashPassword(password);
    const id = uuidv4();

    const isAdmin = cleanEmail === 'admin@local.test';
    User.create({ id, email: cleanEmail, password_hash, is_2fa_enabled: 0, secret_2fa: null, role: isAdmin ? 'admin' : 'user' });
    User.savePasswordHistory(uuidv4(), id, password_hash);

    const token = signToken({ id, email: cleanEmail });

    return res.status(201).json({
      success: true,
      message: 'Tài khoản được tạo thành công!',
      token,
      user: { id, email: cleanEmail, is_2fa_enabled: false, role: isAdmin ? 'admin' : 'user' },
      passwordAnalysis: analysis,
    });
  } catch (err) {
    console.error('[Register Error]', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─── Login ───────────────────────────────────────────────────────────────────

exports.login = async (req, res) => {
  try {
    const { email, password, trustDevice = false, deviceName = null } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Vui lòng điền email và mật khẩu.' });
    }

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,10}$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Định dạng email không hợp lệ.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = User.findByEmail(cleanEmail);

    if (user && user.is_locked) {
      logEvent(req, user.id, 'LOGIN_BLOCKED', 'Account manually locked by admin');
      return res.status(403).json({ success: false, message: 'Tài khoản của bạn đã bị khóa bởi người quản trị.', locked: true });
    }

    const attempts = User.getLoginAttempts(cleanEmail);
    let isLocked = false;

    if (attempts) {
      const lastAttemptTime = new Date(attempts.last_attempt);
      const timeDiff = new Date() - lastAttemptTime;
      // Lock for 15 minutes if attempts >= MAX_ATTEMPTS
      if (attempts.attempt_count >= MAX_ATTEMPTS && timeDiff < 15 * 60000) {
        isLocked = true;
        const remainingMinutes = Math.ceil((15 * 60000 - timeDiff) / 60000);
        const logId = user ? user.id : 'unknown_user';
        logEvent(req, logId, 'LOGIN_BLOCKED', `Account locked. Time remaining: ${remainingMinutes}m`);
        return res.status(429).json({
          success: false,
          message: `Account locked due to too many failed attempts. Try again in ${remainingMinutes} minutes.`,
          locked: true,
        });
      }
    }

    if (!user) {
      User.recordFailedAttempt(uuidv4(), cleanEmail);
      logEvent(req, null, 'LOGIN_FAILED', `Invalid email/account does not exist: ${cleanEmail}`);
      // Lộ danh tính tài khoản (không bảo mật lắm nhưng đáp ứng yêu cầu user "có tồn tại")
      return res.status(401).json({ success: false, message: 'Lỗi: Email này chưa được đăng ký trong hệ thống.' });
    }

    const valid = await comparePassword(password, user.password_hash);
    if (!valid) {
      User.recordFailedAttempt(uuidv4(), email);
      const newCount = attempts ? attempts.attempt_count + 1 : 1;
      if (newCount >= MAX_ATTEMPTS) {
        logEvent(req, user.id, 'ACCOUNT_LOCKED', 'Exceeded MAX_ATTEMPTS');
        return res.status(429).json({
          success: false,
          message: 'Too many failed attempts. Account locked for 15 minutes.',
          locked: true,
        });
      }
      logEvent(req, user.id, 'LOGIN_FAILED', 'Invalid password');
      return res.status(401).json({
        success: false,
        message: `Invalid credentials. ${MAX_ATTEMPTS - newCount} attempts remaining.`,
      });
    }

    // Login success, clean up attempts
    User.resetLoginAttempts(cleanEmail);

    // Behavioral profile computed before finalizing login
    const behavior = getBehaviorProfile(user, req);

    if (behavior.blocked) {
      logEvent(req, user.id, 'LOGIN_BLOCKED', `Risk score ${behavior.score} exceeded block threshold`);
      return res.status(403).json({
        success: false,
        blocked: true,
        suspicious: true,
        riskScore: behavior.score,
        reasons: behavior.suspiciousReasons,
        message: 'Login bị chặn do risk score vượt ngưỡng.',
      });
    }

    const deviceId = getDeviceId(req);
    const trustedDevice = User.findTrustedDevice(user.id, deviceId);
    const isTrustedDevice = !!trustedDevice || !!trustDevice;
    let shouldBlock = behavior.score >= 80;
    let require2FA = false;

    // Enforce 2FA rules
    if (user.is_2fa_enabled) {
      if (!isTrustedDevice) {
        require2FA = true; // Bắt buộc 2FA nếu thiết bị chưa được tin cậy
      } else if (behavior.score > 50 && behavior.score < 80) {
        require2FA = true; // Bắt buộc 2FA do phát hiện rủi ro (dù thiết bị đã lưu)
      }
    } else if (behavior.score > 50 && behavior.score < 80) {
      // Nếu rủi ro cao mà KHÔNG có 2FA -> Khóa luôn để an toàn (Zero Trust)
      shouldBlock = true;
    }

    if (shouldBlock) {
      logEvent(req, user.id, 'LOGIN_BLOCKED', `Risk score ${behavior.score} exceeded block threshold`);
      return res.status(403).json({
        success: false,
        blocked: true,
        suspicious: true,
        riskScore: behavior.score,
        reasons: behavior.suspiciousReasons,
        message: 'Login bị chặn do risk score quá cao.',
      });
    }

    // Risk-based authentication: 51-79 requires 2FA; 80+ is blocked.
    if (require2FA) {
      const pendingToken = signPendingToken(user);
      const suspiciousPayload = behavior.suspicious ? buildSuspiciousLoginResponse(behavior) : null;
      return res.json({
        success: true,
        requires2FA: true,
        pendingToken,
        suspiciousLogin: suspiciousPayload,
        riskScore: behavior.score,
        deviceTrusted: isTrustedDevice,
        message: 'Đăng nhập có rủi ro. Vui lòng xác thực 2FA.',
      });
    }

    User.setLastLogin(user.id);
    const token = signToken(user);
    const refreshToken = generateRefreshToken();
    
    // Attack Detection Engine integration
    const threats = detectThreats(req, user, cleanEmail);

    // Store session (7 days)
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    const ip = behavior.ip;
    const ua = behavior.ua;
    User.storeSession(uuidv4(), user.id, refreshToken, ua, ip, expiresAt, deviceId, isTrustedDevice);

    if (trustDevice || req.body.trustDevice === true) {
      User.addTrustedDevice(uuidv4(), user.id, deviceId, deviceName || ua, ua, ip, new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString());
    }

    logEvent(req, user.id, 'LOGIN_SUCCESS', 'Standard login');

    const suspiciousThreat = threats.find((t) => t.type === 'SUSPICIOUS_LOGIN');
    if (suspiciousThreat) {
      sendSecurityAlert(user.email, {
        type: 'UNUSUAL_LOGIN',
        details: suspiciousThreat.details,
        ip: behavior.ip,
        device: behavior.device
      }).catch(console.error);
    }

    return res.json({
      success: true,
      requires2FA: false,
      token,
      refreshToken,
      deviceTrusted: isTrustedDevice || !!trustDevice,
      threats: threats.length > 0 ? threats : null,
      suspiciousLogin: suspiciousThreat ? {
        suspicious: true,
        riskScore: suspiciousThreat.score,
        reasons: suspiciousThreat.details.split(' | '),
      } : null,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        display_name: user.display_name,
        is_2fa_enabled: !!user.is_2fa_enabled,
        last_login: user.last_login,
      },
    });
  } catch (err) {
    console.error('[Login Error]', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─── 2FA Setup ───────────────────────────────────────────────────────────────

exports.setup2FA = async (req, res) => {
  try {
    const userId = req.user.id;
    const user = User.findById(userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const { secret, totp: _ } = generateTOTPSecret(user.email);
    const { qrDataUrl, manualKey } = await generateQRCode(user.email, secret);

    // Store secret temporarily (not enabled until verified)
    User.storeSecret(userId, secret);

    return res.json({
      success: true,
      secret,
      qrCode: qrDataUrl,
      manualKey,
      instructions: [
        '1. Install Google Authenticator, Authy, or Microsoft Authenticator',
        '2. Tap "+" → "Scan QR code" and scan the QR code above',
        '3. Or manually enter the key shown below',
        '4. Enter the 6-digit code to confirm and enable 2FA',
      ],
    });
  } catch (err) {
    console.error('[Setup 2FA Error]', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─── 2FA Verify & Enable ─────────────────────────────────────────────────────

exports.verify2FASetup = async (req, res) => {
  try {
    const { token } = req.body;
    const userId = req.user.id;
    const user = User.findById(userId);

    if (!user || !user.secret_2fa) {
      return res.status(400).json({ success: false, message: '2FA not initialized. Please start setup first.' });
    }

    const valid = verifyTOTP(user.secret_2fa, token);
    if (!valid) {
      return res.status(400).json({ success: false, message: 'Invalid or expired token. Please try again.' });
    }

    // Gmail Style: Generate 10 Backup Codes
    const backupCodes = Array.from({ length: 10 }, () => crypto.randomBytes(4).toString('hex')); // 8 chars
    const hashedBackupCodes = await Promise.all(backupCodes.map(code => bcrypt.hash(code, 10)));
    
    User.enable2FA(userId, user.secret_2fa);
    User.saveBackupCodes(userId, JSON.stringify(hashedBackupCodes));
    logEvent(req, userId, '2FA_ENABLED', 'Enabled via App');
    
    sendSecurityAlert(user.email, {
      type: '2FA_ENABLED',
      details: 'Tính năng xác thực 2 bước (2FA) đã được kích hoạt thành công.',
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || 'unknown',
      device: req.headers['user-agent'] || 'Unknown'
    }).catch(console.error);

    return res.json({
      success: true,
      message: '🎉 Two-Factor Authentication enabled successfully!',
      is_2fa_enabled: true,
      backupCodes,
      securityReport: {
        scoreBoard: [
          { label: 'Password Strength', status: 'Passed', color: 'var(--accent-green)' },
          { label: 'Two-Factor Auth', status: 'Secured', color: 'var(--accent-green)' },
          { label: 'Recovery Method', status: 'Available', color: 'var(--accent-green)' }
        ],
        newRiskLevel: 'LOW',
        riskMessage: 'Tài khoản của bạn hiện đạt mức bảo mật CAO NHẤT (Enterprise-Grade).'
      }
    });
  } catch (err) {
    console.error('[Verify 2FA Error]', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─── 2FA Login Verify ────────────────────────────────────────────────────────

exports.verifyLogin2FA = async (req, res) => {
  try {
    const { token, pendingToken } = req.body;

    let payload;
    try {
      payload = jwt.verify(pendingToken, JWT_SECRET);
    } catch {
      return res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
    }

    if (!payload.twoFAPending) {
      return res.status(400).json({ success: false, message: 'Invalid session state.' });
    }

    const user = User.findById(payload.id);
    if (!user) {
      return res.status(400).json({ success: false, message: 'Account not found.' });
    }

    let valid = verifyTOTP(user.secret_2fa, token);
    let usedBackup = false;
    const behavior = getBehaviorProfile(user, req);
    const deviceId = getDeviceId(req);
    const trustedDevice = User.findTrustedDevice(user.id, deviceId);
    const isTrustedDevice = !!trustedDevice || !!payload.trustDevice;
    const allowByTrust = isTrustedDevice && behavior.score <= 50;

    if (behavior.blocked) {
      logEvent(req, user.id, 'LOGIN_BLOCKED', `Risk score ${behavior.score} exceeded block threshold during 2FA`);
      return res.status(403).json({
        success: false,
        blocked: true,
        suspicious: true,
        riskScore: behavior.score,
        reasons: behavior.suspiciousReasons,
        message: '2FA login bị chặn do risk score vượt ngưỡng.',
      });
    }

    // Trusted device can bypass OTP on repeat login when risk is normal
    if (allowByTrust) {
      valid = true;
    }

    // Advanced 2FA: Check backup codes if TOTP fails
    if (!valid && user.backup_codes) {
      const hashedCodes = JSON.parse(user.backup_codes);
      const matchIndex = (await Promise.all(hashedCodes.map(h => bcrypt.compare(token, h)))).indexOf(true);
      
      if (matchIndex !== -1) {
        valid = true;
        usedBackup = true;
        // Remove used code
        hashedCodes.splice(matchIndex, 1);
        User.saveBackupCodes(user.id, JSON.stringify(hashedCodes));
        logEvent(req, user.id, '2FA_BACKUP_USED', 'Used a recovery code');
      }
    }

    if (!valid) {
      return res.status(400).json({ success: false, message: 'Invalid or expired 2FA code.' });
    }

    User.setLastLogin(user.id);
    // Real-world recovery: Successful 2FA "clears" the previous attack state
    User.resetLoginAttempts(user.email);
    User.resolveAllAlerts(user.id);
    
    // Identity update
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || 'unknown';
    const ua = req.headers['user-agent'] || 'Unknown';

    // Auto-trust this device context after successful 2FA to prevent repetitive prompts
    if (!isTrustedDevice) {
      User.addTrustedDevice(
        uuidv4(),
        user.id,
        deviceId,
        'Device verified via 2FA',
        ua,
        ip,
        new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
      );
    }

    const authToken = signToken(user);
    const refreshToken = generateRefreshToken();
    User.updateUserIdentity(user.id, ip, ua);
    User.recordLoginBehavior(user.id, {
      ip,
      ua,
      device: behavior.device,
      hour: behavior.hour,
      location_country: null,
      location_city: null,
    });

    if (isTrustedDevice) {
      User.addTrustedDevice(uuidv4(), user.id, deviceId, req.body.deviceName || ua, ua, ip, new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString());
    }

    const suspiciousLogin = behavior.suspicious
      ? buildSuspiciousLoginResponse(behavior)
      : null;

    // Store session (7 days)
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    User.storeSession(uuidv4(), user.id, refreshToken, ua, ip, expiresAt, deviceId, isTrustedDevice);

    const threats = detectThreats(req, user, user.email);

    logEvent(req, user.id, 'LOGIN_SUCCESS', usedBackup ? '2FA backup success' : '2FA login success');

    if (behavior.suspicious) {
      sendSecurityAlert(user.email, {
        type: 'UNUSUAL_LOGIN',
        details: behavior.suspiciousReasons.join(' | '),
        ip: ip,
        device: behavior.device
      }).catch(console.error);
    }

    return res.json({
      success: true,
      token: authToken,
      refreshToken,
      deviceTrusted: isTrustedDevice,
      threats: threats.length > 0 ? threats : null,
      suspiciousLogin,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        display_name: user.display_name,
        is_2fa_enabled: true,
        last_login: user.last_login,
      },
    });
  } catch (err) {
    console.error('[Verify Login 2FA Error]', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─── Disable 2FA ─────────────────────────────────────────────────────────────

exports.disable2FA = async (req, res) => {
  try {
    const { token } = req.body;
    const userId = req.user.id;
    const user = User.findById(userId);

    if (!user.is_2fa_enabled || !user.secret_2fa) {
      return res.status(400).json({ success: false, message: '2FA is not enabled.' });
    }

    const valid = verifyTOTP(user.secret_2fa, token);
    if (!valid) {
      return res.status(400).json({ success: false, message: 'Invalid 2FA token. Cannot disable 2FA.' });
    }

    User.disable2FA(userId);
    logEvent(req, userId, '2FA_DISABLED', 'Disabled by user');
    
    sendSecurityAlert(user.email, {
      type: '2FA_DISABLED',
      details: 'Tính năng xác thực 2 bước (2FA) đã bị vô hiệu hóa.',
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || 'unknown',
      device: req.headers['user-agent'] || 'Unknown'
    }).catch(console.error);
    return res.json({ success: true, message: '2FA has been disabled.' });
  } catch (err) {
    console.error('[Disable 2FA Error]', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─── Password Tools (API) ─────────────────────────────────────────────────────

exports.analyzePassword = (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ success: false, message: 'Password required' });
  const result = analyzePassword(password);
  const bruteForce = getBruteForceEstimate(password);
  return res.json({
    success: true,
    analysis: result,
    bruteForce,
    breachCheck: result.breach,
    entropy: result.entropy,
  });
};

exports.generatePassword = (req, res) => {
  const { length = 20, uppercase = true, lowercase = true, numbers = true, symbols = true } = req.query;
  const result = generateStrongPassword({
    length: parseInt(length),
    uppercase: uppercase !== 'false',
    lowercase: lowercase !== 'false',
    numbers:   numbers   !== 'false',
    symbols:   symbols   !== 'false',
  });
  return res.json({ success: true, ...result });
};

exports.generatePassphrase = (req, res) => {
  const { words = 4, separator = '-' } = req.query;
  const result = genPassphrase(parseInt(words), separator);
  return res.json({ success: true, ...result });
};

exports.simulateAttack = (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
  const result = simulateCredentialStuffing(email, password);
  return res.json({ success: true, ...result });
};

exports.simulateMultiSystemAttack = (req, res) => {
  try {
    const { victimEmail, leakedPassword, systems = ['A', 'C'] } = req.body;
    if (!victimEmail || !leakedPassword) {
      return res.status(400).json({ success: false, message: 'victimEmail and leakedPassword are required' });
    }

    const targetSystems = Array.isArray(systems) && systems.length ? systems : ['A', 'C'];
    const scenarioId = require('uuid').v4();
    const fakeBreachSource = {
      system: 'B',
      type: 'FAKE_SERVICE_LEAK',
      details: 'Dữ liệu rò rỉ từ System B (fake service) gồm email/password tái sử dụng.',
      leakedEmail: victimEmail,
    };

    const outcomes = [];
    const attackSignals = [];
    const user = User.findByEmail(victimEmail.toLowerCase());
    const reused = !!user;

    if (targetSystems.includes('A')) {
      attackSignals.push({ system: 'A', action: 'LOGIN_ATTEMPT', status: reused ? 'SUCCESS_OR_2FA' : 'FAILED' });
      if (user) {
        const reqLike = { headers: req.headers, socket: req.socket, ip: req.ip };
        const threats = require('../services/attackDetectionEngine').detectThreats(reqLike, user, victimEmail);
        outcomes.push({ system: 'A', result: 'attacker_reached_main_app', threats });
      } else {
        outcomes.push({ system: 'A', result: 'main_app_login_failed' });
      }
    }

    if (targetSystems.includes('C')) {
      attackSignals.push({ system: 'C', action: 'ADMIN_PORTAL_LOGIN_ATTEMPT', status: reused ? 'BLOCKED_OR_2FA' : 'FAILED' });
      outcomes.push({ system: 'C', result: reused ? 'admin_portal_triggered_risk' : 'admin_portal_failed' });
    }

    User.createAlert(scenarioId, user ? user.id : null, 'CREDENTIAL_STUFFING', 'CRITICAL', req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || 'unknown', `Multi-system attack simulation: leaked password from System B reused on ${targetSystems.join(', ')}`);

    if (user) {
      // Real-world response: Send alert & Kick user out of all devices
      sendSecurityAlert(user.email, {
        type: 'UNUSUAL_LOGIN',
        details: '⚠️ CẢNH BÁO: Tài khoản của bạn đang bị tấn công Multi-System! Mật khẩu bị rò rỉ từ Hệ thống B đã được sử dụng để truy cập Hệ thống A và C.',
        ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || 'unknown',
        device: 'Attacker Machine (Simulated)'
      }).catch(console.error);

      // Logout the user everywhere
      User.revokeAllSessions(user.id);
    }

    return res.json({
      success: true,
      scenarioId,
      flow: {
        systemA: { name: 'Main App', target: 'A', outcome: outcomes.find(o => o.system === 'A') || null },
        systemB: fakeBreachSource,
        systemC: { name: 'Admin Portal', target: 'C', outcome: outcomes.find(o => o.system === 'C') || null },
      },
      attackSignals,
      detection: {
        suspicious: true,
        riskScore: user ? 85 : 65,
        action: user ? '2FA_REQUIRED' : 'BLOCK_OR_2FA',
        reasons: [
          'Password reuse detected from fake breach source',
          'Cross-system login attempt observed',
          'Credential stuffing pattern matched',
        ],
      },
      message: 'Multi-system attack simulation executed successfully.',
    });
  } catch (err) {
    console.error('[Multi-System Attack Simulation Error]', err);
    return res.status(500).json({ success: false, message: 'Simulation failed.' });
  }
};

exports.getBreachStats = (_req, res) => {
  return res.json({ success: true, stats: BREACH_STATS });
};

exports.getProfile = (req, res) => {
  const user = User.findById(req.user.id);
  if (!user) return res.status(404).json({ success: false, message: 'User not found' });
  return res.json({
    success: true,
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
      display_name: user.display_name || '',
      is_2fa_enabled: !!user.is_2fa_enabled,
      created_at: user.created_at,
      last_login: user.last_login,
    },
  });
};

// ─── Update Profile ───────────────────────────────────────────────────────────

exports.updateProfile = async (req, res) => {
  try {
    const userId = req.user.id;
    const { display_name, email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: 'Email là bắt buộc.' });
    }

    // Basic email format check
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Email không hợp lệ.' });
    }

    // Check if email already used by another user
    const existing = User.findByEmail(email);
    if (existing && existing.id !== userId) {
      return res.status(409).json({ success: false, message: 'Email này đã được sử dụng bởi tài khoản khác.' });
    }

    User.updateProfile(userId, {
      display_name: display_name ? display_name.trim() : null,
      email: email.trim().toLowerCase(),
    });

    const updated = User.findById(userId);
    return res.json({
      success: true,
      message: 'Cập nhật hồ sơ thành công!',
      user: {
        id: updated.id,
        email: updated.email,
        display_name: updated.display_name || '',
        is_2fa_enabled: !!updated.is_2fa_enabled,
        created_at: updated.created_at,
        last_login: updated.last_login,
      },
    });
  } catch (err) {
    console.error('[UpdateProfile Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi server.' });
  }
};

// ─── Change Password ──────────────────────────────────────────────────────────

exports.changePassword = async (req, res) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ success: false, message: 'Vui lòng điền đầy đủ các trường.' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Mật khẩu xác nhận không khớp.' });
    }

    const user = User.findById(userId);
    if (!user) return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng.' });

    // Verify current password
    const isValid = await comparePassword(currentPassword, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Mật khẩu hiện tại không đúng.' });
    }

    // ── FR2: Enterprise Password Policy ──────────────────────────
    const policy = validatePolicy(newPassword);
    if (!policy.valid) {
      return res.status(400).json({
        success: false,
        message: 'Mật khẩu mới không đáp ứng chính sách bảo mật.',
        violations: policy.violations,
        passed: policy.passed,
      });
    }

    // zxcvbn strength check (enterprise: score >= 3)
    const analysis = analyzePassword(newPassword);
    if (analysis.score < POLICY.MIN_ZXCVBN_SCORE) {
      return res.status(400).json({
        success: false,
        message: `Mật khẩu chưa đủ mạnh (score ${analysis.score}/4). ${analysis.feedback.warning || ''}`,
        analysis,
      });
    }

    // New password must not be same as current
    const isSame = await comparePassword(newPassword, user.password_hash);
    if (isSame) {
      return res.status(400).json({ success: false, message: 'Mật khẩu mới phải khác mật khẩu hiện tại.' });
    }

    // FR2: Check password reuse (last N passwords)
    const history = User.getPasswordHistory(userId);
    const reused = await isPasswordReused(newPassword, history);
    if (reused) {
      return res.status(400).json({
        success: false,
        message: `Bạn đã dùng mật khẩu này trước đây. Không được tái sử dụng trong ${POLICY.HISTORY_DEPTH} mật khẩu gần nhất.`,
      });
    }

    const newHash = await hashPassword(newPassword);
    User.updatePasswordHash(userId, newHash);
    User.savePasswordHistory(uuidv4(), userId, newHash);
    
    // Revoke all existing sessions globally (M365 style)
    User.revokeAllSessions(userId);

    logEvent(req, userId, 'PASSWORD_CHANGED');

    sendSecurityAlert(user.email, {
      type: 'PASSWORD_CHANGED',
      details: 'Mật khẩu của bạn đã được thay đổi thành công.',
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || 'unknown',
      device: req.headers['user-agent'] || 'Unknown'
    }).catch(console.error);

    return res.json({
      success: true,
      message: '✅ Đổi mật khẩu thành công! Vui lòng đăng nhập lại.',
      passwordStrength: analysis.label,
    });
  } catch (err) {
    console.error('[ChangePassword Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi server.' });
  }
};

// ─── Logout (invalidate client token and specific refresh session) ──────────────

exports.logout = (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    User.deleteSession(refreshToken);
  }
  return res.json({
    success: true,
    message: 'Đăng xuất thành công. Session đã bị thu hồi khỏi Server.',
  });
};

exports.logoutAll = (req, res) => {
  try {
    const userId = req.user.id;
    User.revokeAllSessions(userId);
    logEvent(req, userId, 'LOGOUT_ALL', 'Revoked all active sessions globally.');
    return res.json({ success: true, message: 'Đã đăng xuất khỏi mọi thiết bị.' });
  } catch(err) {
    return res.status(500).json({ success: false, message: 'Lỗi server' });
  }
};

exports.refreshTokenApi = (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ success: false, message: 'No refresh token provided' });

    const session = User.findSession(refreshToken);
    if (!session) return res.status(401).json({ success: false, message: 'Invalid refresh token' });

    if (new Date(session.expires_at) < new Date()) {
      User.deleteSession(refreshToken);
      return res.status(401).json({ success: false, message: 'Refresh token expired' });
    }

    const user = User.findById(session.user_id);
    if (!user) return res.status(401).json({ success: false, message: 'User not found' });

    const newToken = signToken(user);
    return res.json({ success: true, token: newToken });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Lỗi server' });
  }
};

exports.getSessions = async (req, res) => {
  try {
    const sessions = User.getUserSessions(req.user.id) || [];
    return res.json({ success: true, sessions });
  } catch (err) {
    console.error('[Get Sessions Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi lấy danh sách thiết bị.' });
  }
};

exports.logoutSession = async (req, res) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) return res.status(400).json({ success: false, message: 'Session ID is required' });

    User.revokeSessionById(sessionId, req.user.id);
    logEvent(req, req.user.id, 'LOGOUT_DEVICE', `Revoked session ${sessionId}`);
    return res.json({ success: true, message: 'Thiết bị đã được đăng xuất.' });
  } catch (err) {
    console.error('[Logout Session Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi đăng xuất thiết bị.' });
  }
};

exports.trustCurrentDevice = async (req, res) => {
  try {
    const deviceId = getDeviceId(req);
    const deviceName = req.body.deviceName || req.headers['user-agent'] || 'Unknown Device';
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || 'unknown';
    const trustedUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

    User.addTrustedDevice(uuidv4(), req.user.id, deviceId, deviceName, req.headers['user-agent'] || 'Unknown', ip, trustedUntil);
    logEvent(req, req.user.id, 'DEVICE_TRUSTED', `Trusted device ${deviceId}`);

    return res.json({ success: true, message: 'Thiết bị này đã được tin cậy.', deviceId, trustedUntil });
  } catch (err) {
    console.error('[Trust Device Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi tin cậy thiết bị.' });
  }
};

exports.getTrustedDevices = async (req, res) => {
  try {
    const devices = User.listTrustedDevices(req.user.id) || [];
    return res.json({ success: true, devices });
  } catch (err) {
    console.error('[Get Trusted Devices Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi lấy danh sách thiết bị tin cậy.' });
  }
};

exports.revokeTrustedDevice = async (req, res) => {
  try {
    const { deviceId } = req.body;
    if (!deviceId) return res.status(400).json({ success: false, message: 'Device ID is required' });

    User.revokeTrustedDevice(req.user.id, deviceId);
    logEvent(req, req.user.id, 'TRUST_DEVICE_REVOKED', `Revoked trusted device ${deviceId}`);
    return res.json({ success: true, message: 'Đã gỡ tin cậy thiết bị.' });
  } catch (err) {
    console.error('[Revoke Trusted Device Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi gỡ tin cậy thiết bị.' });
  }
};

// ─── Get Password Policy (FR2) ────────────────────────────────────────────────

exports.getPolicy = (_req, res) => {
  return res.json({ success: true, policy: getPolicySpec() });
};

// ─── Security Platform Features ───────────────────────────────────────────────

exports.getSecurityLogs = async (req, res) => {
  try {
    const userId = req.user.id;
    const logs = User.getUserAuditLogs(userId);
    return res.json({ success: true, logs });
  } catch (err) {
    console.error('[Get Security Logs Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi máy chủ.' });
  }
};

exports.getSecurityScore = async (req, res) => {
  try {
    const userId = req.user.id;
    const user = User.findById(userId);
    const logs = User.getUserAuditLogs(userId) || [];
    const alerts = User.getUserAlerts(userId) || [];

    let score = 100;
    const issues = [];

    // 1) 2FA protection
    if (!user.is_2fa_enabled) {
      score -= 20;
      issues.push({ type: 'danger', message: 'Tài khoản chưa bật 2FA.' });
    }

    // 2) Dynamic penalty from CURRENT failed attempts counter (changes every failed login)
    const attempts = User.getLoginAttempts(user.email);
    const failedCount = attempts ? Number(attempts.attempt_count || 0) : 0;
    if (failedCount > 0) {
      const failedPenalty = Math.min(40, failedCount * 8); // 1 fail=-8, 5 fail=-40
      score -= failedPenalty;
      issues.push({
        type: failedCount >= 4 ? 'danger' : 'warning',
        message: `Có ${failedCount} lần nhập sai gần đây (trừ ${failedPenalty} điểm).`,
      });
    }

    // 3) Additional penalty from recent suspicious events (last 24h)
    const last24h = Date.now() - 24 * 60 * 60 * 1000;
    const recentSuspicious = logs.filter((l) => {
      const t = new Date(l.created_at).getTime();
      return t >= last24h && (l.action === 'LOGIN_FAILED' || l.action === 'LOGIN_BLOCKED' || l.action === 'ACCOUNT_LOCKED');
    });
    if (recentSuspicious.length > 0) {
      const recentPenalty = Math.min(20, recentSuspicious.length * 2);
      score -= recentPenalty;
      issues.push({
        type: 'warning',
        message: `Phát hiện ${recentSuspicious.length} sự kiện rủi ro trong 24h (trừ ${recentPenalty} điểm).`,
      });
    }

    // 3.5) Penalty for Critical Security Alerts (Credential Stuffing, Hijacking)
    const recentAlerts = alerts.filter(a => new Date(a.created_at).getTime() >= last24h);
    if (recentAlerts.length > 0) {
      const alertPenalty = Math.min(30, recentAlerts.length * 10); // Mỗi alert trừ 10, tối đa 30
      score -= alertPenalty;
      issues.push({
        type: 'danger',
        message: `Có ${recentAlerts.length} Cảnh báo Xâm nhập (Alerts) chưa xử lý (trừ ${alertPenalty} điểm).`,
      });
    }

    // 4) Hard penalty when account is locked in current window
    if (attempts) {
      const lastAttemptTime = new Date(attempts.last_attempt).getTime();
      const inLockWindow = attempts.attempt_count >= MAX_ATTEMPTS && (Date.now() - lastAttemptTime) < 15 * 60 * 1000;
      if (inLockWindow) {
        score -= 20;
        issues.push({ type: 'danger', message: 'Tài khoản đang trong trạng thái lockout 15 phút.' });
      }
    }

    if (score > 95) {
      issues.push({ type: 'success', message: 'Tài khoản của bạn đang ở trạng thái an toàn cao.' });
    }

    if (score < 0) score = 0;

    return res.json({
      success: true,
      score,
      issues,
      status2FA: !!user.is_2fa_enabled,
      pwdStrength: 'Rất mạnh',
      failedAttemptsCurrent: failedCount,
    });
  } catch (err) {
    console.error('[Get Security Score Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi máy chủ.' });
  }
};

exports.getSecurityAlerts = async (req, res) => {
  try {
    const userId = req.user.id;
    const alerts = User.getUserAlerts(userId);
    return res.json({ success: true, alerts });
  } catch (err) {
    console.error('[Get Alerts Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi máy chủ.' });
  }
};

exports.getMonitoringData = async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const metrics = User.getSecurityMetrics(isAdmin ? null : req.user.id);
    return res.json({ success: true, metrics });
  } catch (err) {
    console.error('[Get Monitoring Data Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi lấy dữ liệu giám sát.' });
  }
};


exports.getApiKey = (req, res) => {
    return res.json({ success: true, apiKey: req.user.api_key });
};

exports.rotateApiKey = (req, res) => {
    const newKey = require('crypto').randomBytes(32).toString('hex');
    User.updateApiKey(req.user.id, newKey);
    logEvent(req, req.user.id, 'API_KEY_ROTATE', 'Regenerated system API Key');
    return res.json({ success: true, apiKey: newKey });
};

