const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const rateLimit = require('express-rate-limit');

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

/**
 * Standard JWT Authentication Middleware
 */
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authentication required' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({ success: false, message: 'User no longer exists' });
    }

    if (user.is_locked) {
      return res.status(403).json({ success: false, message: 'Tài khoản của bạn đã bị khóa bởi Admin.', locked: true });
    }

    // Check token version for global logout support
    if (decoded.tokenVersion !== undefined && decoded.tokenVersion < user.token_version) {
       return res.status(401).json({ success: false, message: 'Phiên đăng nhập đã hết hạn (Revoked)', requireRelogin: true });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
};

/**
 * Role-Based Access Control (RBAC) middleware
 */
const authorize = (roles = []) => {
  if (typeof roles === 'string') roles = [roles];
  
  return (req, res, next) => {
    if (!req.user || (roles.length && !roles.includes(req.user.role))) {
      return res.status(403).json({ 
        success: false, 
        message: `Quyền truy cập bị từ chối. Yêu cầu quyền: ${roles.join(' or ')}` 
      });
    }
    next();
  };
};

/**
 * API Key Middleware for internal/service calls
 */
const requireApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
        return res.status(401).json({ success: false, message: 'X-API-KEY header is required' });
    }

    const user = User.findByApiKey(apiKey);
    if (!user) {
        return res.status(403).json({ success: false, message: 'Invalid API Key' });
    }

    req.user = user; // Service-to-service identifies as this user
    next();
};

/**
 * Enhanced Rate Limiter
 */
const createLimiter = (minutes, max, message) => rateLimit({
    windowMs: minutes * 60 * 1000,
    max,
    message: { success: false, message: message || 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

module.exports = {
  authenticate,
  authorize,
  requireApiKey,
  apiLimiter: createLimiter(15, 100),
  authLimiter: createLimiter(1, 10, 'Quá nhiều nỗ lực đăng nhập. Vui lòng thử lại sau 1 phút.')
};
