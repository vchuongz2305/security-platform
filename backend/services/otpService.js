/**
 * otpService.js
 * TOTP-based Two-Factor Authentication using otpauth library.
 * Compatible with Google Authenticator, Authy, Microsoft Authenticator.
 */

const { TOTP, URI } = require('otpauth');
const QRCode = require('qrcode');

const APP_NAME = 'SecurityDemo';
const ISSUER   = 'Password Security Lab';

/**
 * Generate a new TOTP secret for a user
 * @param {string} email - User's email (label for authenticator app)
 * @returns {{ secret: string, totp: TOTP }}
 */
function generateTOTPSecret(email) {
  const totp = new TOTP({
    issuer: ISSUER,
    label:  email,
    algorithm: 'SHA1',
    digits:    6,
    period:    30,
  });

  return {
    secret: totp.secret.base32, // Store this in DB (secret_2fa)
    totp,
  };
}

/**
 * Build TOTP URI and generate QR code as data URL
 * @param {string} email
 * @param {string} secret - base32 secret
 * @returns {Promise<string>} QR code data URL
 */
async function generateQRCode(email, secret) {
  const totp = new TOTP({
    issuer: ISSUER,
    label:  email,
    algorithm: 'SHA1',
    digits:    6,
    period:    30,
    secret,
  });

  const uri = totp.toString(); // otpauth:// URI

  const qrDataUrl = await QRCode.toDataURL(uri, {
    width: 256,
    margin: 2,
    color: { dark: '#1e293b', light: '#f8fafc' },
  });

  return { qrDataUrl, uri, manualKey: secret };
}

/**
 * Verify a TOTP token
 * @param {string} secret - base32 secret stored in DB
 * @param {string} token  - 6-digit token from authenticator app
 * @returns {boolean}
 */
function verifyTOTP(secret, token) {
  try {
    const totp = new TOTP({
      issuer: ISSUER,
      algorithm: 'SHA1',
      digits:    6,
      period:    30,
      secret,
    });

    // delta allows ±1 window (30 seconds tolerance)
    const delta = totp.validate({ token: String(token).trim(), window: 1 });
    return delta !== null;
  } catch {
    return false;
  }
}

/**
 * Generate a current TOTP token (for demo/testing purposes only)
 */
function generateCurrentToken(secret) {
  const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret });
  return totp.generate();
}

module.exports = {
  generateTOTPSecret,
  generateQRCode,
  verifyTOTP,
  generateCurrentToken,
};
