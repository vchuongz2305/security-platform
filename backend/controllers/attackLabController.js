/**
 * attackLabController.js
 * Specialized controller for simulating security attacks for educational purposes.
 */

const User = require('../models/userModel');
const { v4: uuidv4 } = require('uuid');
const { comparePassword } = require('../utils/hash');
const { sendSecurityAlert } = require('../services/emailService');

/**
 * Helper: Enforce post-attack response based on 2FA status
 * - No 2FA  → Lock account + revoke sessions (must contact Admin to unlock)
 * - Has 2FA → Revoke sessions only (user re-verifies with 2FA on next login)
 */
function enforcePostAttack(user, ip, attackType) {
  User.revokeAllSessions(user.id);

  if (!user.is_2fa_enabled) {
    // No 2FA → Lock account, user must contact Admin
    User.lockAccount(user.id);
    User.logAudit(
      uuidv4(), user.id,
      'AUTO_LOCK_NO_2FA', ip,
      `Tài khoản bị khóa tự động sau ${attackType} vì chưa bật 2FA. Liên hệ Admin để mở khóa.`
    );
    return {
      action: 'LOCKED',
      message: '🔒 Tài khoản bị khóa tự động. Người dùng phải liên hệ Admin để mở khóa.'
    };
  } else {
    // Has 2FA → Force logout only, next login requires 2FA verification
    User.logAudit(
      uuidv4(), user.id,
      'FORCE_LOGOUT_2FA_REQUIRED', ip,
      `Buộc đăng xuất sau ${attackType}. Yêu cầu xác thực lại bằng 2FA.`
    );
    return {
      action: 'FORCE_LOGOUT',
      message: '🔐 Đã đăng xuất khỏi tất cả thiết bị. Đăng nhập lại yêu cầu xác thực 2FA.'
    };
  }
}

/**
 * Simulate Brute Force Attack
 * Rapidly attempts multiple passwords for a single email
 */
exports.simulateBruteForce = async (req, res) => {
  const { email, passwordList } = req.body;
  if (!email || !passwordList || !Array.isArray(passwordList)) {
    return res.status(400).json({ success: false, message: 'Email and password list are required.' });
  }

  const user = User.findByEmail(email.toLowerCase());
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found for simulation.' });
  }

  // ⚠️ SIMULATION MODE: Reset login attempts so the full dictionary can run
  // Real consequences only applied if password is actually cracked
  User.resetLoginAttempts(email.toLowerCase());

  const results = [];
  let attackOutcome = null;

  for (const pwd of passwordList) {
    const isValid = await comparePassword(pwd, user.password_hash);

    if (isValid) {
      results.push({ password: pwd, status: 'CRACKED', color: 'red' });
      User.createAlert(uuidv4(), user.id, 'BRUTE_FORCE', 'CRITICAL', req.ip, `Phát hiện bẻ khóa mật khẩu thành công: ${pwd}`);

      // Apply real consequences based on 2FA status
      attackOutcome = enforcePostAttack(user, req.ip, 'BRUTE_FORCE');

      const alertDetails = user.is_2fa_enabled
        ? '⚠️ Tài khoản bị đăng xuất toàn bộ thiết bị. Hãy đăng nhập lại và xác thực bằng 2FA.'
        : '🔒 Tài khoản bị KHÓA do chưa bật 2FA. Liên hệ Admin để mở khóa.';

      sendSecurityAlert(user.email, {
        type: 'ACCOUNT_LOCKED',
        details: alertDetails,
        ip: req.ip,
        device: 'Unknown Attacker'
      }).catch(() => {});

      break;
    } else {
      // In simulation mode: just record the attempt result, no real lockout
      results.push({ password: pwd, status: 'FAILED', color: 'gray' });
    }
  }

  const cracked = results.some(r => r.status === 'CRACKED');

  // If not cracked after exhausting dictionary: simulate lockout
  if (!cracked) {
    // Apply 5 real failed attempts so lockout is realistic post-simulation
    for (let i = 0; i < 5; i++) {
      User.recordFailedAttempt(uuidv4(), email.toLowerCase());
    }
    if (results.length > 0) {
      results[results.length - 1].status = 'LOCKED';
    }
  }

  return res.json({
    success: true,
    target: email,
    attempts: results.length,
    results,
    cracked,
    has2FA: !!user.is_2fa_enabled,
    attackOutcome,
    explanation: 'Tấn công Brute Force thử nghiệm hàng nghìn tổ hợp mật khẩu cho đến khi tìm thấy mật khẩu đúng.'
  });
};

/**
 * Simulate Credential Stuffing
 * Attempts a single leaked password against multiple "known" emails
 */
exports.simulateCredentialStuffing = async (req, res) => {
  const { leakedPassword, targetEmails } = req.body;
  if (!leakedPassword || !targetEmails || !Array.isArray(targetEmails)) {
    return res.status(400).json({ success: false, message: 'Leaked password and target emails are required.' });
  }

  const results = [];
  for (const email of targetEmails) {
    const user = User.findByEmail(email.toLowerCase());
    if (user) {
      const isValid = await comparePassword(leakedPassword, user.password_hash);
      if (isValid) {
        User.createAlert(uuidv4(), user.id, 'CREDENTIAL_STUFFING', 'CRITICAL', req.ip, `Phát hiện sử dụng mật khẩu bị lộ từ Breach database.`);

        // Enforce post-attack response
        const outcome = enforcePostAttack(user, req.ip, 'CREDENTIAL_STUFFING');

        const alertDetails = user.is_2fa_enabled
          ? '⚠️ PHÁT HIỆN RÒ RỈ: Mật khẩu đã bị lộ. Đã đăng xuất toàn bộ, hãy đăng nhập lại và xác thực 2FA.'
          : '🔒 PHÁT HIỆN RÒ RỈ: Tài khoản bị KHÓA do chưa bật 2FA. Liên hệ Admin để mở khóa.';

        sendSecurityAlert(user.email, {
          type: 'UNUSUAL_LOGIN',
          details: alertDetails,
          ip: req.ip,
          device: 'Credential Stuffing Bot'
        }).catch(() => {});

        results.push({
          email,
          status: 'SUCCESS (REUSED)',
          color: 'red',
          outcome: outcome.action,
          outcomeMessage: outcome.message
        });
      } else {
        results.push({ email, status: 'FAILED (UNIQUE)', color: 'green' });
      }
    } else {
      results.push({ email, status: 'NOT FOUND', color: 'gray' });
    }
  }

  return res.json({
    success: true,
    leakedPassword,
    results,
    reusedCount: results.filter(r => r.status.includes('REUSED')).length,
    explanation: 'Credential Stuffing tận dụng việc người dùng dùng chung một mật khẩu cho nhiều dịch vụ.'
  });
};

/**
 * Simulate Session Hijacking
 * Demonstrates how stealing a session token allows access without a password
 */
exports.simulateSessionHijack = (req, res) => {
  const { userEmail, userId } = req.body;

  let user;

  // Priority: look up by email (new), fall back to userId (legacy)
  if (userEmail) {
    user = User.findByEmail(userEmail.toLowerCase());
  } else if (userId === 'admin-id' || userId === 'admin') {
    user = User.findByEmail('admin@local.test');
  } else if (userId) {
    user = User.findById(userId);
  }

  if (!user) {
    return res.status(404).json({
      success: false,
      message: `Không tìm thấy tài khoản "${userEmail || userId}". Kiểm tra lại email.`
    });
  }

  // Generate a fake "captured" session token for demonstration
  const expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();
  const fakeToken = require('jsonwebtoken').sign(
    { id: user.id, email: user.email, tokenVersion: user.token_version, role: user.role },
    process.env.JWT_SECRET || 'fallback_secret',
    { expiresIn: '1h' }
  );

  // Record the hijack alert (nhưng chưa revoke để demo việc hacker vào được)
  User.createAlert(uuidv4(), user.id, 'SESSION_HIJACK', 'CRITICAL', req.ip, `Phát hiện JWT Token bị đánh cắp cho tài khoản ${user.email} (Simulated)`);

  return res.json({
    success: true,
    capturedToken: fakeToken,
    capturedUser: user.email,
    expiresAt,
    risk: 'EXTREME',
    hijackOutcome: { action: 'NONE', message: 'Hacker đang giữ Token hợp lệ!' },
    mitigation: 'Sử dụng Token ngắn hạn (Short-lived JWT), IP Binding, và Token Versioning để vô hiệu hóa Token bị đánh cắp.',
    explanation: 'Vì Token đại diện cho trạng thái ĐÃ XÁC THỰC (bao gồm cả 2FA), hacker có thể dùng nó để vào thẳng hệ thống mà không cần mật khẩu hay mã OTP.'
  });
};

/**
 * Get all available targets for attack simulation
 */
exports.getTargets = (req, res) => {
  try {
    const users = User.listAll() || [];
    const emails = users.map(u => u.email);
    return res.json({ success: true, targets: emails });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to fetch targets.' });
  }
};
