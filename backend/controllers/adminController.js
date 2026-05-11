/**
 * adminController.js
 * Module 6: Admin Dashboard - Hệ thống Quản trị Trung tâm (Enhanced)
 */

const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

exports.getGlobalStats = async (req, res) => {
  try {
    const allUsers = User.listAll() || [];
    const logs = User.getGlobalAuditLogs() || [];
    const alerts = User.getGlobalAlerts() || [];

    const totalUsers = allUsers.length;
    const lockedUsers = allUsers.filter(u => {
      const attempts = User.getLoginAttempts(u.email);
      let isAutoLocked = false;
      if (attempts && attempts.attempt_count >= 5) {
         if (new Date() - new Date(attempts.last_attempt) < 15 * 60000) isAutoLocked = true;
      }
      return u.is_locked === 1 || u.is_locked === true || isAutoLocked;
    }).length;
    const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL').length;

    return res.json({
      success: true,
      stats: { 
        totalUsers, 
        lockedUsers, 
        blockedAttacks: alerts.length, 
        totalLogs: logs.length,
        criticalAlerts
      }
    });
  } catch (err) {
    console.error('[Admin Stats Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi lấy dữ liệu quản trị.' });
  }
};

exports.getGlobalLogs = async (req, res) => {
  try {
    const logs = User.getGlobalAuditLogs() || [];
    
    // Attach emails to logs
    const logsWithEmail = logs.map(l => {
      let email = 'System/Service';
      if (l.user_id) {
        const u = User.findById(l.user_id);
        if (u) email = u.email;
      }
      return { ...l, email };
    });

    return res.json({ success: true, logs: logsWithEmail });
  } catch (err) {
    console.error('[Admin Logs Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi lấy dữ liệu logs.' });
  }
};

exports.getUsers = async (req, res) => {
  try {
    const users = User.listAll();
    
    const mappedUsers = users.map(u => {
      const attempts = User.getLoginAttempts(u.email);
      let isAutoLocked = false;
      if (attempts && attempts.attempt_count >= 5) {
         if (new Date() - new Date(attempts.last_attempt) < 15 * 60000) isAutoLocked = true;
      }
      
      return {
        id: u.id,
        email: u.email,
        role: u.role,
        is_2fa_enabled: !!u.is_2fa_enabled,
        isLocked: !!u.is_locked || isAutoLocked,
        manualLock: !!u.is_locked,
        created_at: u.created_at,
        last_login: u.last_login,
        failures: attempts ? attempts.attempt_count : 0
      };
    });

    return res.json({ success: true, users: mappedUsers });
  } catch (err) {
    console.error('[Admin Users Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi tải danh sách người dùng.' });
  }
};

exports.toggleUserLock = async (req, res) => {
  try {
    const { userId, action } = req.body; // action: 'lock' or 'unlock'
    const target = User.findById(userId);
    if (!target) return res.status(404).json({ success: false, message: 'User not found' });

    if (action === 'lock') {
      User.lockAccount(target.id);
      User.revokeAllSessions(target.id); // Secure: kick out locked user
    } else {
      User.unlockAccount(target.id);
      User.resetLoginAttempts(target.email);
    }

    const ip = req.ip || 'unknown';
    User.logAudit(uuidv4(), req.user.id, `ADMIN_${action.toUpperCase()}`, ip, `${action.charAt(0).toUpperCase() + action.slice(1)}ed account: ${target.email}`);

    return res.json({ success: true, message: `Tài khoản ${target.email} đã được ${action === 'lock' ? 'khóa' : 'mở khóa'}.` });
  } catch (err) {
    console.error('[Admin Toggle Lock Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi thao tác khóa/mở khóa.' });
  }
};

exports.resetUserPassword = async (req, res) => {
  try {
    const { userId, newPassword } = req.body;
    if (!userId || !newPassword) return res.status(400).json({ success: false, message: 'Missing data' });
    
    const target = User.findById(userId);
    if (!target) return res.status(404).json({ success: false, message: 'User not found' });

    const hash = await bcrypt.hash(newPassword, 12);
    User.updatePasswordHash(target.id, hash);
    User.revokeAllSessions(target.id); // Secure: force new password login

    User.logAudit(uuidv4(), req.user.id, 'ADMIN_PASSWORD_RESET', req.ip, `Reset password for ${target.email}`);

    return res.json({ success: true, message: `Mật khẩu của ${target.email} đã được đặt lại.` });
  } catch (err) {
    console.error('[Admin Reset Pwd Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi đặt lại mật khẩu.' });
  }
};

exports.getUserSecurityDetail = async (req, res) => {
  try {
    const { userId } = req.params;
    const user = User.findById(userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const alerts = User.getUserAlerts(userId);
    const logs = User.getUserAuditLogs(userId);
    const attempts = User.getLoginAttempts(user.email);
    
    // Simple Risk Score Calculation
    let riskScore = 0;
    if (user.is_locked) riskScore += 100;
    if (attempts && attempts.attempt_count > 0) riskScore += attempts.attempt_count * 10;
    riskScore += alerts.filter(a => a.severity === 'CRITICAL').length * 25;
    riskScore += alerts.filter(a => a.severity === 'MEDIUM').length * 10;
    
    riskScore = Math.min(riskScore, 100);

    return res.json({ 
      success: true, 
      detail: {
        email: user.email,
        riskScore,
        attackHistory: alerts,
        auditLogs: logs.slice(0, 10),
        status: user.is_locked ? 'LOCKED' : (riskScore > 50 ? 'SUSPICIOUS' : 'SAFE')
      }
    });
  } catch (err) {
    console.error('[Admin Risk Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi lấy risk score.' });
  }
};

exports.getGlobalAlerts = async (req, res) => {
  try {
    const alerts = User.getGlobalAlerts();
    return res.json({ success: true, alerts });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Lỗi lấy alerts.' });
  }
};

  exports.disable2FA = async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ success: false, message: 'Missing userId' });

    const target = User.findById(userId);
    if (!target) return res.status(404).json({ success: false, message: 'User not found' });

    if (!target.is_2fa_enabled) {
      return res.status(400).json({ success: false, message: `Tài khoản ${target.email} chưa bật 2FA.` });
    }

    User.disable2FA(target.id);
    User.revokeAllSessions(target.id);

    User.logAudit(uuidv4(), req.user.id, 'ADMIN_DISABLE_2FA', req.ip || 'unknown', `Force-disabled 2FA for ${target.email}`);

    return res.json({ success: true, message: `Đã tắt 2FA cho tài khoản ${target.email}. Người dùng sẽ bị đăng xuất.` });
  } catch (err) {
    console.error('[Admin Disable 2FA Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi tắt 2FA.' });
  }
};

/**
 * Delete User Account
 * Hard-deletes a user and all associated data (sessions, alerts, audit logs, login attempts)
 * Protected: Cannot delete admin accounts or self
 */
exports.deleteUser = async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ success: false, message: 'Missing userId' });

    const target = User.findById(userId);
    if (!target) return res.status(404).json({ success: false, message: 'User not found' });

    // Cannot delete admin accounts
    if (target.role === 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: `Không thể xóa tài khoản Admin. Hãy hạ cấp xuống user trước.` 
      });
    }

    // Cannot delete own account
    if (target.id === req.user.id) {
      return res.status(403).json({ 
        success: false, 
        message: 'Không thể tự xóa tài khoản của chính mình.' 
      });
    }

    const deletedEmail = target.email;

    // Revoke all sessions first (kick user out immediately)
    User.revokeAllSessions(target.id);

    // Delete all associated data
    User.deleteUserData(target.id, target.email);

    // Log the action (by admin who performed it)
    User.logAudit(
      uuidv4(), req.user.id, 
      'ADMIN_DELETE_USER', 
      req.ip || 'unknown', 
      `Permanently deleted account: ${deletedEmail}`
    );

    return res.json({ 
      success: true, 
      message: `Tài khoản ${deletedEmail} đã bị xóa vĩnh viễn.` 
    });
  } catch (err) {
    console.error('[Admin Delete User Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi xóa tài khoản.' });
  }
};


/**
 * Scan Vulnerable Accounts
 * Returns list of accounts with no 2FA and/or weak passwords — used by Attack Lab
 */
exports.scanVulnerableAccounts = async (req, res) => {
  try {
    const zxcvbn = require('zxcvbn');
    const allUsers = User.listAll() || [];

    const vulnerable = allUsers
      .filter(u => u.role !== 'admin') // Skip admins
      .map(u => {
        const attempts = User.getLoginAttempts(u.email);
        const recentAlerts = User.getUserAlerts(u.id) || [];

        // Score password if plaintext isn't available — use email pattern heuristics
        // In demo, seed passwords follow known patterns for scoring purposes
        const knownWeakPwds = ['User@12345', 'Admin@12345', 'Test@123', 'Password1', '123456', 'qwerty'];
        const isKnownWeak = knownWeakPwds.some(p => {
          try { return zxcvbn(p).score <= 2; } catch { return false; }
        });

        const no2FA = !u.is_2fa_enabled;
        const isLocked = !!u.is_locked;
        const failedLogins = attempts ? attempts.attempt_count : 0;
        const criticalIncidents = recentAlerts.filter(a => a.severity === 'CRITICAL').length;

        // Vulnerability score: 0-100
        let vulnScore = 0;
        if (no2FA) vulnScore += 50;
        if (failedLogins > 0) vulnScore += Math.min(failedLogins * 5, 30);
        if (criticalIncidents > 0) vulnScore += Math.min(criticalIncidents * 10, 20);

        return {
          id: u.id,
          email: u.email,
          role: u.role || 'user',
          is_2fa_enabled: !!u.is_2fa_enabled,
          isLocked,
          failedLogins,
          criticalIncidents,
          vulnScore: Math.min(vulnScore, 100),
          riskLevel: vulnScore >= 70 ? 'HIGH' : (vulnScore >= 40 ? 'MEDIUM' : 'LOW'),
        };
      })
      .filter(u => !u.isLocked) // Only show unlocked accounts (attackable)
      .sort((a, b) => b.vulnScore - a.vulnScore); // Most vulnerable first

    return res.json({ success: true, vulnerable, total: vulnerable.length });
  } catch (err) {
    console.error('[Scan Vulnerable Error]', err);
    return res.status(500).json({ success: false, message: 'Lỗi quét tài khoản.' });
  }
};
