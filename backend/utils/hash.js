/**
 * hash.js - Utility for password hashing and comparison using bcrypt
 * Demonstrates: Salting, work factor, and secure password storage
 */

const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 12; // Higher = slower but more secure (10-12 recommended)

/**
 * Hash a plain-text password (with salt)
 * @param {string} plainPassword
 * @returns {Promise<string>} bcrypt hash
 */
async function hashPassword(plainPassword) {
  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  return bcrypt.hash(plainPassword, salt);
}

/**
 * Compare a plain-text password with a stored hash
 * @param {string} plainPassword
 * @param {string} hashedPassword
 * @returns {Promise<boolean>}
 */
async function comparePassword(plainPassword, hashedPassword) {
  return bcrypt.compare(plainPassword, hashedPassword);
}

/**
 * Get info about a hash (rounds used)
 * @param {string} hash
 * @returns {number}
 */
function getHashRounds(hash) {
  return bcrypt.getRounds(hash);
}

module.exports = { hashPassword, comparePassword, getHashRounds, SALT_ROUNDS };
