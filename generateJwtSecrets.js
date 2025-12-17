const crypto = require("crypto");

/**
 * Generate a secure random secret
 * @param {number} length - number of bytes (32+ recommended)
 */
function generateSecret(length = 64) {
  return crypto.randomBytes(length).toString("hex");
}

const JWT_ACCESS_SECRET = generateSecret(64);
const JWT_REFRESH_SECRET = generateSecret(64);

console.log("JWT_ACCESS_SECRET =", JWT_ACCESS_SECRET);
console.log("JWT_REFRESH_SECRET =", JWT_REFRESH_SECRET);
