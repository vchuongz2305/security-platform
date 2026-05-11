const express = require('express');
const router = express.Router();
const adminCtrl = require('../controllers/adminController');
const { authenticate, authorize } = require('../middlewares/authMiddleware');

const adminGuard = [authenticate, authorize(['admin'])];

router.get('/stats', adminGuard, adminCtrl.getGlobalStats);
router.get('/logs', adminGuard, adminCtrl.getGlobalLogs);
router.get('/alerts', adminGuard, adminCtrl.getGlobalAlerts);
router.get('/users', adminGuard, adminCtrl.getUsers);
router.get('/users/:userId/security', adminGuard, adminCtrl.getUserSecurityDetail);

router.post('/toggle-lock', adminGuard, adminCtrl.toggleUserLock);
router.post('/reset-password', adminGuard, adminCtrl.resetUserPassword);
router.post('/disable-2fa', adminGuard, adminCtrl.disable2FA);
router.post('/delete-user', adminGuard, adminCtrl.deleteUser);
router.get('/scan-vulnerable', adminGuard, adminCtrl.scanVulnerableAccounts);

module.exports = router;
