/**
 * passwordPolicy.js — Enterprise Password Security Policy (FR2)
 *
 * Single source of truth for all password rules.
 * Used by: passwordService, authController (register + changePassword)
 * Exposed to frontend via: GET /api/auth/policy
 */

// ─── Policy Constants ─────────────────────────────────────────────────────────

const POLICY = {
  MIN_LENGTH:         12,      // NIST SP 800-63B minimum
  MAX_LENGTH:         128,     // Prevent DoS via bcrypt
  REQUIRE_UPPERCASE:  true,    // At least 1 A-Z
  REQUIRE_LOWERCASE:  true,    // At least 1 a-z
  REQUIRE_NUMBER:     true,    // At least 1 0-9
  REQUIRE_SPECIAL:    true,    // At least 1 special char
  SPECIAL_CHARS:      '!@#$%^&*()_+-=[]{}|;:,.<>?/~`',
  MIN_ZXCVBN_SCORE:   3,       // 0-4; 3 = "Strong" (enterprise standard)
  HISTORY_DEPTH:      5,       // Reject last N passwords
  MAX_CONSECUTIVE:    3,       // e.g. "aaa", "111" not allowed
};

// ─── Validation Engine ────────────────────────────────────────────────────────

/**
 * Validate a password against FR2 policy rules.
 * Returns { valid: boolean, violations: string[], passed: string[] }
 */
function validatePolicy(password) {
  const violations = [];
  const passed     = [];

  if (typeof password !== 'string' || password.length === 0) {
    return { valid: false, violations: ['Mật khẩu không được để trống.'], passed: [] };
  }

  // 1. Min length
  if (password.length < POLICY.MIN_LENGTH) {
    violations.push(`Độ dài tối thiểu ${POLICY.MIN_LENGTH} ký tự (hiện tại: ${password.length}).`);
  } else {
    passed.push(`Độ dài ≥ ${POLICY.MIN_LENGTH} ký tự ✓`);
  }

  // 2. Max length (DoS prevention)
  if (password.length > POLICY.MAX_LENGTH) {
    violations.push(`Mật khẩu quá dài (tối đa ${POLICY.MAX_LENGTH} ký tự).`);
  }

  // 3. Uppercase
  if (POLICY.REQUIRE_UPPERCASE && !/[A-Z]/.test(password)) {
    violations.push('Phải có ít nhất 1 chữ hoa (A-Z).');
  } else if (POLICY.REQUIRE_UPPERCASE) {
    passed.push('Có chữ hoa ✓');
  }

  // 4. Lowercase
  if (POLICY.REQUIRE_LOWERCASE && !/[a-z]/.test(password)) {
    violations.push('Phải có ít nhất 1 chữ thường (a-z).');
  } else if (POLICY.REQUIRE_LOWERCASE) {
    passed.push('Có chữ thường ✓');
  }

  // 5. Number
  if (POLICY.REQUIRE_NUMBER && !/[0-9]/.test(password)) {
    violations.push('Phải có ít nhất 1 chữ số (0-9).');
  } else if (POLICY.REQUIRE_NUMBER) {
    passed.push('Có chữ số ✓');
  }

  // 6. Special character
  const specialRegex = new RegExp(`[${POLICY.SPECIAL_CHARS.replace(/[\]\\^-]/g, '\\$&')}]`);
  if (POLICY.REQUIRE_SPECIAL && !specialRegex.test(password)) {
    violations.push(`Phải có ít nhất 1 ký tự đặc biệt (!@#$%^&* ...).`);
  } else if (POLICY.REQUIRE_SPECIAL) {
    passed.push('Có ký tự đặc biệt ✓');
  }

  // 7. No consecutive repeated characters (e.g. "aaa", "111")
  const consecRegex = new RegExp(`(.)\\1{${POLICY.MAX_CONSECUTIVE},}`);
  if (consecRegex.test(password)) {
    violations.push(`Không được có ${POLICY.MAX_CONSECUTIVE + 1}+ ký tự giống nhau liên tiếp (vd: "aaaa").`);
  } else {
    passed.push('Không lặp liên tiếp ✓');
  }

  // 8. No sequential patterns (keyboard walks)
  const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
  let hasSequence = false;
  const lp = password.toLowerCase();
  for (const seq of SEQUENCES) {
    for (let i = 0; i <= seq.length - 4; i++) {
      const chunk = seq.slice(i, i + 4);
      if (lp.includes(chunk) || lp.includes(chunk.split('').reverse().join(''))) {
        hasSequence = true;
        break;
      }
    }
    if (hasSequence) break;
  }
  if (hasSequence) {
    violations.push('Không được chứa chuỗi tuần tự (vd: "abcd", "1234", "qwerty").');
  } else {
    passed.push('Không có chuỗi tuần tự ✓');
  }

  return {
    valid: violations.length === 0,
    violations,
    passed,
  };
}

/**
 * Get policy as a readable object for the frontend
 */
function getPolicySpec() {
  return {
    minLength:        POLICY.MIN_LENGTH,
    maxLength:        POLICY.MAX_LENGTH,
    requireUppercase: POLICY.REQUIRE_UPPERCASE,
    requireLowercase: POLICY.REQUIRE_LOWERCASE,
    requireNumber:    POLICY.REQUIRE_NUMBER,
    requireSpecial:   POLICY.REQUIRE_SPECIAL,
    specialChars:     POLICY.SPECIAL_CHARS,
    minZxcvbnScore:   POLICY.MIN_ZXCVBN_SCORE,
    historyDepth:     POLICY.HISTORY_DEPTH,
    rules: [
      `Tối thiểu ${POLICY.MIN_LENGTH} ký tự`,
      'Ít nhất 1 chữ hoa (A-Z)',
      'Ít nhất 1 chữ thường (a-z)',
      'Ít nhất 1 chữ số (0-9)',
      'Ít nhất 1 ký tự đặc biệt (!@#$%^&*...)',
      `Không lặp ký tự liên tiếp (≥ ${POLICY.MAX_CONSECUTIVE + 1} lần)`,
      'Không có chuỗi tuần tự (abcd, 1234, qwerty)',
      `Không trùng ${POLICY.HISTORY_DEPTH} mật khẩu gần nhất`,
      `Độ mạnh zxcvbn ≥ ${POLICY.MIN_ZXCVBN_SCORE}/4 (Strong)`,
    ],
  };
}

module.exports = { POLICY, validatePolicy, getPolicySpec };
