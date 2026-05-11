/**
 * attackDetectionEngine.js
 * Core engine for detecting security threats: Brute Force, Credential Stuffing,
 * and behavioral anomalies based on login time, IP, and device history.
 */

const User = require('../models/userModel');
const { v4: uuidv4 } = require('uuid');

const DETECTION_CONFIG = {
  STUFFING_THRESHOLD: 10,
  STUFFING_WINDOW: 600000,
  NORMAL_LOGIN_HOURS: [5, 23],
  TIME_ANOMALY_SCORE: 2,
  IP_ANOMALY_SCORE: 30,
  DEVICE_ANOMALY_SCORE: 20,
  FAILED_ATTEMPTS_SCORE: 40,
  LOCATION_ANOMALY_SCORE: 50,
  SUSPICIOUS_THRESHOLD: 50,
  BLOCK_THRESHOLD: 80,
};

// In-memory cache for fast detection of stuffing (would use Redis in prod)
const recentFailuresByIP = new Map();

function normalizeIp(ip) {
  if (!ip) return 'unknown';
  return String(ip).replace(/^::ffff:/, '').trim();
}

function extractDeviceSignature(req) {
  const ua = req.headers['user-agent'] || 'Unknown';
  const platform = req.headers['sec-ch-ua-platform'] || '';
  const mobile = req.headers['sec-ch-ua-mobile'] || '';
  return `${ua} | ${platform} | ${mobile}`.trim();
}

function buildDeviceId(req) {
  return Buffer.from(extractDeviceSignature(req)).toString('base64').replace(/=+$/g, '');
}

function extractLocation(req) {
  const country = req.headers['x-vercel-ip-country'] || req.headers['x-country'] || req.headers['cf-ipcountry'] || 'UNKNOWN';
  const city = req.headers['x-vercel-ip-city'] || req.headers['x-city'] || req.headers['cf-ipcity'] || 'UNKNOWN';
  return {
    country: String(country).toUpperCase(),
    city: String(city).toUpperCase(),
  };
}

function getLoginHour(date = new Date()) {
  return date.getHours();
}

function getBehaviorProfile(user, req) {
  const ip = normalizeIp(req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || 'unknown');
  const ua = req.headers['user-agent'] || 'Unknown';
  const device = extractDeviceSignature(req);
  const hour = getLoginHour(new Date());
  const suspiciousReasons = [];
  let score = 0;
  let failedAttempts = 0;

  if (user && user.last_login) {
    const lastLoginDate = new Date(user.last_login);
    const lastLoginHour = lastLoginDate.getHours();

    const [start, end] = DETECTION_CONFIG.NORMAL_LOGIN_HOURS;
    const isNightLogin = hour < start || hour > end;
    const wasDayLogin = lastLoginHour >= start && lastLoginHour <= end;

    if (isNightLogin && wasDayLogin) {
      score += DETECTION_CONFIG.TIME_ANOMALY_SCORE;
      suspiciousReasons.push(`Thời gian đăng nhập bất thường: ${hour}h (lịch sử gần nhất: ${lastLoginHour}h)`);
    }
  }

  if (user && user.last_known_ip && user.last_known_ip !== ip) {
    score += DETECTION_CONFIG.IP_ANOMALY_SCORE;
    suspiciousReasons.push(`IP mới: ${ip} (IP đã biết: ${user.last_known_ip})`);
  }

  if (user && user.last_known_ua && user.last_known_ua !== ua) {
    score += DETECTION_CONFIG.DEVICE_ANOMALY_SCORE;
    suspiciousReasons.push('Device / User-Agent thay đổi');
  }

  if (user) {
    const recentAttempts = User.getLoginAttempts(user.email);
    failedAttempts = recentAttempts ? Number(recentAttempts.attempt_count || 0) : 0;
    if (failedAttempts > 0) {
      score += DETECTION_CONFIG.FAILED_ATTEMPTS_SCORE;
      suspiciousReasons.push(`Có ${failedAttempts} lần đăng nhập thất bại gần đây`);
    }

    // New: Check for recent critical alerts
    const alerts = User.getUserAlerts(user.id);
    if (alerts && alerts.some(a => a.severity === 'CRITICAL')) {
      score += 45; // Increase score to ensure 2FA is triggered
      suspiciousReasons.push('Phát hiện dấu hiệu tài khoản đang bị tấn công Multi-System');
    }
  }

  let history = [];
  try {
    history = User.getLoginBehaviorHistory(user ? user.id : '', 5) || [];
  } catch {
    history = [];
  }
  if (history.length > 0) {
    const knownCountries = new Set(history.map((h) => h.location_country).filter(Boolean));
    const currentCountry = extractLocation(req).country;
    if (knownCountries.size > 0 && currentCountry && currentCountry !== 'UNKNOWN' && !knownCountries.has(currentCountry)) {
      score += DETECTION_CONFIG.LOCATION_ANOMALY_SCORE;
      suspiciousReasons.push(`Location mới: ${currentCountry}`);
    }
  }

  return {
    ip,
    ua,
    device,
    hour,
    score,
    failedAttempts,
    suspiciousReasons,
    suspicious: score >= DETECTION_CONFIG.SUSPICIOUS_THRESHOLD,
    blocked: user?.role === 'admin' ? false : (score > DETECTION_CONFIG.BLOCK_THRESHOLD),
  };
}

function recordBehaviorSnapshot(userId, req) {
  const ip = normalizeIp(req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || 'unknown');
  const ua = req.headers['user-agent'] || 'Unknown';
  const device = extractDeviceSignature(req);
  const hour = getLoginHour(new Date());
  const location = extractLocation(req);

  User.updateUserIdentity(userId, ip, ua);
  User.recordLoginBehavior(userId, { ip, ua, device, hour, location_country: location.country, location_city: location.city });
}

function getRecentLoginHistory(userId) {
  return User.getLoginBehaviorHistory(userId, 10);
}

function detectImpossibleTravel(user, currentLocation) {
  if (!user) return null;
  const history = getRecentLoginHistory(user.id);
  if (!history || history.length === 0) return null;

  const latest = history[0];
  if (!latest || !latest.location_country || !currentLocation.location_country) return null;

  if (latest.location_country === currentLocation.location_country) return null;

  const latestTime = new Date(latest.created_at).getTime();
  const currentTime = Date.now();
  const diffMinutes = Math.abs(currentTime - latestTime) / 60000;

  if (diffMinutes <= 60 && latest.location_country !== currentLocation.location_country) {
    return {
      type: 'IMPOSSIBLE_TRAVEL',
      severity: 'HIGH',
      details: `Đăng nhập liên tiếp từ ${latest.location_country} → ${currentLocation.location_country} trong ${Math.round(diffMinutes)} phút`,
      score: DETECTION_CONFIG.LOCATION_ANOMALY_SCORE,
    };
  }

  return null;
}

function detectThreats(req, user, email) {
  const ip = normalizeIp(req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || 'unknown');
  const ua = req.headers['user-agent'] || 'Unknown';
  const threats = [];

  const behavior = getBehaviorProfile(user, req);
  const location = extractLocation(req);
  const impossibleTravel = detectImpossibleTravel(user, location);

  if (behavior.suspicious) {
    threats.push({
      type: 'SUSPICIOUS_LOGIN',
      severity: 'MEDIUM',
      details: behavior.suspiciousReasons.join(' | '),
      score: behavior.score,
      ip,
      device: behavior.device,
      hour: behavior.hour,
    });
  }

  if (impossibleTravel) {
    behavior.score += impossibleTravel.score;
    behavior.suspiciousReasons.push(impossibleTravel.details);
    threats.push(impossibleTravel);
  }

  if (behavior.score > DETECTION_CONFIG.BLOCK_THRESHOLD) {
    threats.push({
      type: 'RISK_BLOCK',
      severity: 'CRITICAL',
      details: `Risk score ${behavior.score} vượt ngưỡng block (${DETECTION_CONFIG.BLOCK_THRESHOLD})`,
      score: behavior.score,
    });
  }

  // Track login history regardless of suspiciousness, so future comparisons have data
  if (user) {
    recordBehaviorSnapshot(user.id, req);
  }

  // 2. Track for Credential Stuffing (Logic: Multiple different emails failing from same IP)
  const ipData = recentFailuresByIP.get(ip) || { failures: [], emails: new Set() };
  const now = Date.now();
  ipData.failures = ipData.failures.filter(f => now - f < DETECTION_CONFIG.STUFFING_WINDOW);

  if (!user) {
    ipData.failures.push(now);
    ipData.emails.add(email);
    recentFailuresByIP.set(ip, ipData);

    if (ipData.emails.size >= 5 && ipData.failures.length >= DETECTION_CONFIG.STUFFING_THRESHOLD) {
      threats.push({
        type: 'CREDENTIAL_STUFFING',
        severity: 'CRITICAL',
        details: `Phát hiện tấn công dò email quy mô lớn từ IP này (${ipData.emails.size} tài khoản bị nhắm tới).`
      });
    }
  }

  // Persist alerts to DB
  threats.forEach(t => {
    User.createAlert(uuidv4(), user ? user.id : null, t.type, t.severity, ip, t.details);
  });

  return threats;
}

module.exports = { detectThreats, getBehaviorProfile, detectImpossibleTravel };
