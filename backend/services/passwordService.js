/**
 * passwordService.js
 * Demonstrates password strength analysis and secure password generation.
 * Educational: Shows what makes a password weak vs strong.
 */

const zxcvbn = require('zxcvbn');
const { validatePolicy, POLICY } = require('./passwordPolicy');

// Common weak passwords list (subset for demo - simulate a small leak DB)
const COMMON_PASSWORDS = [
  '123456', 'password', '12345678', 'qwerty', '123456789', '12345',
  '1234', '111111', '1234567', 'dragon', '123123', 'baseball',
  'abc123', 'football', 'monkey', 'letmein', 'shadow', 'master',
  '666666', 'qwertyuiop', '123321', 'mustang', '1234567890',
  'michael', 'superman', 'batman', 'trustno1', 'hello', 'charlie',
  'donald', 'password1', 'qwerty123', 'iloveyou', 'admin', 'welcome',
  'login', 'pass', 'test', 'password123', 'p@ssword', 'qwertyuiop',
  'user@12345', 'admin@12345', 'letmein123', 'welcome123', 'summer2024',
  'winter2024', 'spring2024', 'fall2024'
];

/**
 * Calculate password entropy bits
 * Entropy = log2(charset^length) = length * log2(charset)
 */
function calculateEntropy(password) {
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^A-Za-z0-9]/.test(password)) charsetSize += 33; // Approx special chars

  if (charsetSize === 0) return 0;
  return Math.floor(password.length * Math.log2(charsetSize));
}

/**
 * Evaluate Risk Level (Bitwarden style)
 */
function getRiskLevel(score, entropy, isCommon) {
  if (isCommon) return { level: 'CRITICAL', color: '#ef4444', message: 'Tài khoản cực kỳ rủi ro: Mật khẩu này đã bị rò rỉ!' };
  if (score <= 1 || entropy < 40) return { level: 'HIGH', color: '#f97316', message: 'Rủi ro rò rỉ cao: Mật khẩu quá dễ đoán.' };
  if (score === 2 || entropy < 60) return { level: 'MEDIUM', color: '#eab308', message: 'Rủi ro trung bình: Nên nâng cấp mật khẩu dài hơn.' };
  return { level: 'LOW', color: '#10b981', message: 'Rủi ro thấp: Mật khẩu đạt chuẩn an toàn.' };
}

/**
 * Analyze a password for strength using zxcvbn
 * Returns score (0-4), feedback, crack time estimates
 */
function analyzePassword(password) {
  const result  = zxcvbn(password);
  const isCommon = COMMON_PASSWORDS.includes(password.toLowerCase());
  const policy  = validatePolicy(password);
  const entropy = calculateEntropy(password);
  const risk    = getRiskLevel(result.score, entropy, isCommon);
  const breach = checkPasswordBreach(password);

  const scoreLabels = ['Very Weak 🔴', 'Weak 🟠', 'Fair 🟡', 'Strong 🟢', 'Very Strong 💪'];
  const scoreColors = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#10b981'];

  return {
    score:     result.score,
    label:     scoreLabels[result.score],
    color:     scoreColors[result.score],
    isCommon,
    breach,
    entropy,
    risk,
    // FR2 policy result
    policyValid:      policy.valid,
    policyViolations: policy.violations,
    policyPassed:     policy.passed,
    // Crack time
    crackTimeDisplay: result.crack_times_display.offline_slow_hashing_1e4_per_second,
    crackTimeSeconds: result.crack_times_seconds.offline_slow_hashing_1e4_per_second,
    feedback: {
      warning:     result.feedback.warning || null,
      suggestions: result.feedback.suggestions || [],
    },
    length:       password.length,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumbers:   /[0-9]/.test(password),
    hasSymbols:   /[^A-Za-z0-9]/.test(password),
    guesses:      result.guesses,
    meetsEnterprise: policy.valid && result.score >= POLICY.MIN_ZXCVBN_SCORE,
  };
}

function checkPasswordBreach(password) {
  const normalized = String(password || '').toLowerCase();
  const leaked = COMMON_PASSWORDS.includes(normalized);
  const exactMatches = leaked ? [normalized] : [];
  const reason = leaked
    ? 'Mật khẩu nằm trong danh sách leaked/common passwords.'
    : 'Không khớp với danh sách leak demo.';

  return {
    breached: leaked,
    exactMatches,
    source: 'demo_leak_list',
    checkedAgainst: COMMON_PASSWORDS.length,
    reason,
  };
}

/**
 * Generate a cryptographically strong password
 * @param {object} options
 */
function generateStrongPassword(options = {}) {
  const {
    length = 20,
    uppercase = true,
    lowercase = true,
    numbers = true,
    symbols = true,
  } = options;

  const chars = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    numbers:   '0123456789',
    symbols:   '!@#$%^&*()_+-=[]{}|;:,.<>?',
  };

  let pool = '';
  const required = [];

  if (uppercase) { pool += chars.uppercase; required.push(chars.uppercase); }
  if (lowercase) { pool += chars.lowercase; required.push(chars.lowercase); }
  if (numbers)   { pool += chars.numbers;   required.push(chars.numbers);   }
  if (symbols)   { pool += chars.symbols;   required.push(chars.symbols);   }

  if (!pool) throw new Error('At least one character type must be selected');

  // Ensure at least one character from each required set
  const passwordChars = required.map((set) =>
    set[Math.floor(Math.random() * set.length)]
  );

  // Fill remaining length with random characters from pool
  for (let i = passwordChars.length; i < length; i++) {
    passwordChars.push(pool[Math.floor(Math.random() * pool.length)]);
  }

  // Fisher-Yates shuffle
  for (let i = passwordChars.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [passwordChars[i], passwordChars[j]] = [passwordChars[j], passwordChars[i]];
  }

  const password = passwordChars.join('');
  return {
    password,
    analysis: analyzePassword(password),
  };
}

/**
 * Generate a memorable passphrase (like Bitwarden's passphrase mode)
 */
const WORD_LIST = [
  'correct','horse','battery','staple','tiger','purple','ocean','forest',
  'mountain','river','thunder','silver','golden','crystal','bright','swift',
  'fierce','gentle','clever','brave','ancient','cosmic','digital','vivid',
  'mystic','stellar','lunar','solar','arctic','tropical','electric','phantom',
  'dragon','falcon','eagle','wolf','bear','lion','panther','cobra',
  'maple','cedar','willow','birch','jasmine','violet','amber','jade',
  'stone','iron','steel','copper','bronze','marble','obsidian','quartz',
];

function generatePassphrase(wordCount = 4, separator = '-', capitalize = true) {
  const words = [];
  for (let i = 0; i < wordCount; i++) {
    let w = WORD_LIST[Math.floor(Math.random() * WORD_LIST.length)];
    if (capitalize) w = w.charAt(0).toUpperCase() + w.slice(1);
    words.push(w);
  }
  // Add a number for extra entropy
  words.push(Math.floor(Math.random() * 900 + 100).toString());
  const passphrase = words.join(separator);
  return {
    passphrase,
    analysis: analyzePassword(passphrase),
  };
}

/**
 * Check if a password has been reused (compare against history hashes)
 */
const bcrypt = require('bcryptjs');
async function isPasswordReused(plainPassword, historyHashes) {
  for (const hash of historyHashes) {
    const match = await bcrypt.compare(plainPassword, hash.password_hash);
    if (match) return true;
  }
  return false;
}

module.exports = {
  analyzePassword,
  generateStrongPassword,
  generatePassphrase,
  isPasswordReused,
  COMMON_PASSWORDS,
};
