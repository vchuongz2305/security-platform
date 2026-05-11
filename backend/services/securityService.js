/**
 * securityService.js
 * Educational security analysis service.
 * Demonstrates: threats from weak passwords, reuse attacks, brute force.
 */

/**
 * Real-world breach statistics for educational display
 */
const BREACH_STATS = {
  weakPasswordRisk: '81% of data breaches involve weak or stolen passwords (Verizon DBIR)',
  reuseRisk: '65% of people reuse passwords across multiple sites',
  crackedIn: {
    '6chars_lower': '< 1 second',
    '8chars_lower': '22 minutes',
    '8chars_mixed': '8 hours',
    '10chars_mixed': '5 years',
    '12chars_all':  '2 centuries',
    '16chars_all':  '1 trillion years',
  },
  topBreaches: [
    { company: 'RockYou', year: 2009, records: '32 million', notes: 'Passwords stored in plain text' },
    { company: 'LinkedIn', year: 2012, records: '117 million', notes: 'Unsalted SHA1 hashes' },
    { company: 'Adobe', year: 2013, records: '153 million', notes: 'Weak encryption, hints exposed' },
    { company: 'Yahoo', year: 2016, records: '3 billion', notes: 'MD5 hashes, no salting' },
    { company: 'Zynga', year: 2019, records: '218 million', notes: 'SHA1 without salt' },
  ],
};

/**
 * Simulate a credential stuffing attack
 * (Educational demo only - shows how attackers exploit password reuse)
 */
function simulateCredentialStuffing(email, password) {
  const services = [
    { name: 'Gmail', domain: 'gmail.com' },
    { name: 'GitHub', domain: 'github.com' },
    { name: 'Netflix', domain: 'netflix.com' },
    { name: 'Amazon', domain: 'amazon.com' },
    { name: 'PayPal', domain: 'paypal.com' },
    { name: 'Instagram', domain: 'instagram.com' },
  ];

  // Simulate: if user used same weak password, attacker can try all services
  const hasWeakPassword = password.length < 8 || !/[A-Z]/.test(password) || !/[^A-Za-z0-9]/.test(password);

  return {
    scenario: 'Credential Stuffing Attack Simulation',
    email,
    riskLevel: hasWeakPassword ? 'CRITICAL' : 'MODERATE',
    explanation: hasWeakPassword
      ? `Your password "${password.substring(0, 2)}***" appears in common breach databases. An automated bot could attempt it on all these services within seconds.`
      : 'Your password appears unique and strong. Credential stuffing would fail even if this site were breached.',
    targetedServices: services.map((s) => ({
      ...s,
      vulnerable: hasWeakPassword,
      estimatedTime: hasWeakPassword ? '< 1 second per site' : 'Would require brute force (years)',
    })),
    recommendations: [
      'Use a unique password for every service',
      'Enable 2FA on all important accounts',
      'Use a password manager like Bitwarden or 1Password',
      'Check haveibeenpwned.com for breach exposure',
    ],
  };
}

/**
 * Get brute-force time estimate based on password characteristics
 */
function getBruteForceEstimate(password) {
  const length = password.length;
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^A-Za-z0-9]/.test(password)) charsetSize += 32;

  const combinations = Math.pow(charsetSize, length);
  // Assuming 1 billion guesses/second (offline GPU attack)
  const secondsTocrack = combinations / 1e9;

  let estimate;
  if (secondsTocrack < 1)          estimate = 'Less than 1 second';
  else if (secondsTocrack < 60)    estimate = `${Math.round(secondsTocrack)} seconds`;
  else if (secondsTocrack < 3600)  estimate = `${Math.round(secondsTocrack / 60)} minutes`;
  else if (secondsTocrack < 86400) estimate = `${Math.round(secondsTocrack / 3600)} hours`;
  else if (secondsTocrack < 31536000) estimate = `${Math.round(secondsTocrack / 86400)} days`;
  else if (secondsTocrack < 3.15e10)  estimate = `${Math.round(secondsTocrack / 31536000)} years`;
  else estimate = 'Centuries (effectively uncrackable)';

  return {
    password: password.substring(0, 2) + '*'.repeat(Math.max(0, password.length - 2)),
    length,
    charsetSize,
    combinations: combinations.toExponential(2),
    estimatedCrackTime: estimate,
    attackType: 'Offline brute-force (1 billion guesses/sec GPU)',
  };
}

/**
 * Password reuse risk assessment
 */
function assessReuseRisk(password, services = []) {
  const risks = [];
  if (services.length > 1) {
    risks.push(`Used on ${services.length} sites → one breach exposes ALL accounts`);
  }
  if (password.length < 12) {
    risks.push('Short password → high probability it appears in leaked databases');
  }

  return {
    reuseCount: services.length,
    riskScore: Math.min(100, services.length * 20 + (12 - Math.min(12, password.length)) * 5),
    risks,
    impact: services.length > 2 ? 'HIGH' : services.length > 0 ? 'MEDIUM' : 'LOW',
  };
}

module.exports = {
  BREACH_STATS,
  simulateCredentialStuffing,
  getBruteForceEstimate,
  assessReuseRisk,
};
