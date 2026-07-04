/**
 * Backend contract definition - all backends must implement this interface
 * @typedef {Object} Backend
 * @property {function(string, Object): Promise<string>} hash - Hash a password with params
 * @property {function(string, string, Object): Promise<boolean>} verify - Verify password against hash
 * @property {function(): Object} defaultParams - Get default parameters for this backend
 * @property {function(number): Promise<Object>} calibrate - Calibrate parameters for target time
 */

/**
 * Hash function parameters
 * @typedef {Object} HashParams
 * @property {number} [memoryCost] - Memory cost (for argon2/scrypt)
 * @property {number} [timeCost] - Time cost (for argon2/scrypt)
 * @property {number} [parallelism] - Parallelism (for argon2/scrypt)
 * @property {number} [N] - CPU/memory cost parameter (for scrypt)
 * @property {number} [r] - Block size parameter (for scrypt)
 * @property {number} [p] - Parallelization parameter (for scrypt)
 * @property {number} [cost] - Log cost factor (for bcrypt)
 */

/**
 * Hasher options
 * @typedef {Object} HasherOptions
 * @property {'argon2id'|'bcrypt'|'scrypt'} [backend='argon2id'] - which hashing algorithm to use
 * @property {string} [pepper] - optional server-side secret, stored outside the DB
 * @property {number} [targetMs=250] - target hash duration in ms, used by calibrate()
 * @property {number} [bcryptCost] - manual bcrypt cost override
 * @property {{memoryCost?: number, timeCost?: number, parallelism?: number}} [argon2Options]
 * @property {{N?: number, r?: number, p?: number}} [scryptOptions]
 */