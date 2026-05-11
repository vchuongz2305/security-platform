/**
 * authRoutes.js - All authentication and security API routes (IAM Enabled)
 */

const express = require('express');
const router = express.Router();
const ctrl = require('../controllers/authController');
const attackLabCtrl = require('../controllers/attackLabController');
const { authenticate, authorize, apiLimiter, authLimiter, requireApiKey } = require('../middlewares/authMiddleware');

// ─── Public Routes ────────────────────────────────────────────────────────────
router.post('/register', authLimiter, ctrl.register);
router.post('/login',    authLimiter, ctrl.login);
router.post('/login/verify-2fa',      ctrl.verifyLogin2FA);

// Password tools (public for demo)
router.post('/tools/analyze',   apiLimiter, ctrl.analyzePassword);
router.get('/tools/generate',   apiLimiter, ctrl.generatePassword);
router.get('/tools/passphrase', apiLimiter, ctrl.generatePassphrase);
router.post('/tools/simulate-attack', apiLimiter, ctrl.simulateAttack);
router.post('/tools/simulate-multi-system-attack', apiLimiter, ctrl.simulateMultiSystemAttack);
router.get('/security/breach-stats',  apiLimiter, ctrl.getBreachStats);
router.get('/policy',                  apiLimiter, ctrl.getPolicy);

// Layer 9: Attack Lab Simulations
router.get('/attack-lab/targets',             apiLimiter, attackLabCtrl.getTargets);
router.post('/attack-lab/brute-force',        apiLimiter, attackLabCtrl.simulateBruteForce);
router.post('/attack-lab/credential-stuffing', apiLimiter, attackLabCtrl.simulateCredentialStuffing);
router.post('/attack-lab/session-hijack',      apiLimiter, attackLabCtrl.simulateSessionHijack);

// Advanced Auth
router.post('/refresh-token',           apiLimiter, ctrl.refreshTokenApi);

// ─── Protected Routes (JWT required) ────────────────────────────────────
router.get('/profile',           authenticate, ctrl.getProfile);
router.put('/profile',           authenticate, ctrl.updateProfile);
router.post('/change-password',  authenticate, ctrl.changePassword);
router.post('/logout',           authenticate, ctrl.logout);
router.post('/logout-all',       authenticate, ctrl.logoutAll);
router.get('/security-logs',     authenticate, ctrl.getSecurityLogs);
router.get('/security-score',    authenticate, ctrl.getSecurityScore);
router.get('/security-alerts',   authenticate, ctrl.getSecurityAlerts);
router.get('/monitoring',        authenticate, ctrl.getMonitoringData);
router.get('/sessions',          authenticate, ctrl.getSessions);
router.post('/sessions/logout',  authenticate, ctrl.logoutSession);
router.get('/trusted-devices',   authenticate, ctrl.getTrustedDevices);
router.post('/trusted-devices/trust-current', authenticate, ctrl.trustCurrentDevice);
router.post('/trusted-devices/revoke', authenticate, ctrl.revokeTrustedDevice);

router.post('/2fa/setup',        authenticate, ctrl.setup2FA);
router.post('/2fa/verify-setup', authenticate, ctrl.verify2FASetup);
router.post('/2fa/disable',      authenticate, ctrl.disable2FA);

// API Key Example (For Layer 1.3)
router.get('/api-key/me', authenticate, ctrl.getApiKey);
router.post('/api-key/rotate', authenticate, ctrl.rotateApiKey);

// Example of purely API-Key protected service
router.get('/service/health-check', requireApiKey, (req, res) => {
    res.json({ success: true, service: 'IAM Security Engine', identified_as: req.user.email });
});

module.exports = { 
    router, 
    requireAuth: authenticate // Backward compatibility
};
