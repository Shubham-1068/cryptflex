const crypto = require('crypto');
const { parseHash, formatHash } = require('../utils/phc');
const { Backend } = require('./types');

/**
 * PasswordHasher - A flexible password hashing library with pluggable backends
 */
class PasswordHasher {
  /**
   * @param {import('./types').HasherOptions} [options] - Hasher options
   */
  constructor(options = {}) {
    this.options = {
      backend: 'argon2id',
      pepper: undefined,
      targetMs: 250,
      bcryptCost: undefined,
      argon2Options: undefined,
      scryptOptions: undefined,
      ...options
    };

    // Initialize backend
    this.backend = this._initBackend(this.options.backend);

    // Calibration cache
    this.calibratedParams = null;
  }

  /**
   * Initialize the selected backend
   * @private
   * @param {'argon2id'|'bcrypt'|'scrypt'} backendName
   * @returns {Backend}
   */
  _initBackend(backendName) {
    switch (backendName) {
      case 'argon2id':
        try {
          const argon2 = require('argon2');
          return new Argon2Backend(argon2);
        } catch (err) {
          throw new Error('argon2 package not installed. Run: npm install argon2');
        }
      case 'bcrypt':
        try {
          const bcryptjs = require('bcryptjs');
          return new BcryptBackend(bcryptjs);
        } catch (err) {
          throw new Error('bcryptjs package not installed. Run: npm install bcryptjs');
        }
      case 'scrypt':
        return new ScryptBackend(crypto);
      default:
        throw new Error(`Unsupported backend: ${backendName}`);
    }
  }

  /**
   * Times hashing on this machine and picks safe params for targetMs.
   * Call once at app startup.
   * @returns {Promise<void>}
   */
  async calibrate() {
    if (this.calibratedParams) {
      return; // Already calibrated
    }

    // Use backend's calibrate method
    this.calibratedParams = await this.backend.calibrate(this.options.targetMs);
  }

  /**
   * Hash a plaintext password. Throws if password is empty or not a string.
   * @param {string} password
   * @returns {Promise<string>} PHC-formatted hash string
   * @throws {TypeError} If password is not a string or is empty
   */
  async hash(password) {
    if (typeof password !== 'string' || password.length === 0) {
      throw new TypeError('Password must be a non-empty string');
    }

    // Apply pepper if configured
    const processedPassword = this.options.pepper
      ? await this._applyPepper(password, this.options.pepper)
      : password;

    // Get parameters (calibrated or default)
    const params = this.calibratedParams || this.backend.defaultParams();

    // Apply backend-specific options from constructor
    const finalParams = this._mergeBackendOptions(params);

    // Generate salt (16 bytes = 128 bits)
    const salt = crypto.randomBytes(16);

    // Hash the password
    const hashResult = await this.backend.hash(processedPassword, salt, finalParams);

    // Handle different return types from backends
    let hashBuffer;
    if (typeof hashResult === 'string') {
      // Backend returned a string (e.g., argon2 already formatted)
      hashBuffer = Buffer.from(hashResult, 'utf8');
    } else if (hashResult instanceof Buffer) {
      // Backend returned a Buffer (e.g., scrypt)
      hashBuffer = hashResult;
    } else if (typeof hashResult === 'object' && hashResult !== null) {
      // Backend returned an object (e.g., bcrypt with {cost, bcryptData})
      // For now, we'll serialize it as JSON and store as base64
      // In a production implementation, you might want a more efficient binary format
      hashBuffer = Buffer.from(JSON.stringify(hashResult), 'utf8');
    } else {
      throw new Error('Backend hash method must return string, Buffer, or object');
    }

    // Return PHC formatted string
    return formatHash({
      algo: this.options.backend,
      version: 1,
      params: finalParams,
      salt: salt.toString('base64'),
      hash: hashBuffer.toString('base64')
    });
  }

  /**
   * Verify a plaintext password against a stored hash string.
   * @param {string} password
   * @param {string} hash - PHC formatted hash string
   * @returns {Promise<boolean>}
   * @throws {TypeError} If password or hash is not a string
   */
  async verify(password, hash) {
    if (typeof password !== 'string' || typeof hash !== 'string') {
      throw new TypeError('Password and hash must be strings');
    }

    if (password.length === 0) {
      return false; // Early return for empty password
    }

    try {
      const { algo, version, params, salt, hash: hashValue } = parseHash(hash);

      // Check if algorithm matches
      if (algo !== this.options.backend) {
        return false; // Algorithm mismatch
      }

      // Apply pepper if configured
      const processedPassword = this.options.pepper
        ? await this._applyPepper(password, this.options.pepper)
        : password;

      // Verify using backend
      const saltBuffer = Buffer.from(salt, 'base64');

      // Always decode the hashValue from base64 (since that's how we store it)
      let hashBuffer = Buffer.from(hashValue, 'base64');

      // Parse the buffer back to its original form if needed
      let hashArg = hashBuffer;
      if (this.options.backend === 'bcrypt' || this.options.backend === 'argon2id') {
        // For bcrypt and argon2, we stored a JSON object, so parse it
        try {
          hashArg = JSON.parse(hashBuffer.toString('utf8'));
        } catch (e) {
          // If parsing fails, there's likely a data corruption issue
          console.warn('Failed to parse hash data as JSON:', e.message);
          // We'll continue with the buffer and let the backend handle the error
        }
      }
      // For scrypt, hashBuffer is already the correct format (raw hash bytes)

      return await this.backend.verify(
        processedPassword,
        saltBuffer,
        hashArg,
        params
      );
    } catch (err) {
      // If hash parsing fails, it's not a valid hash for us
      return false;
    }
  }

  /**
   * Apply pepper using HMAC-SHA256
   * @private
   * @param {string} password
   * @param {string} pepper
   * @returns {Promise<string>}
   */
  async _applyPepper(password, pepper) {
    return new Promise((resolve, reject) => {
      crypto.createHmac('sha256', pepper)
        .update(password, 'utf8')
        .digest((err, hash) => {
          if (err) reject(err);
          else resolve(hash.toString('base64'));
        });
    });
  }

  /**
   * Merge backend-specific options from constructor with params
   * @private
   * @param {Object} baseParams
   * @returns {Object}
   */
  _mergeBackendOptions(baseParams) {
    const params = { ...baseParams };

    switch (this.options.backend) {
      case 'bcrypt':
        if (this.options.bcryptCost !== undefined) {
          params.cost = this.options.bcryptCost;
        }
        break;
      case 'argon2id':
        if (this.options.argon2Options) {
          Object.assign(params, this.options.argon2Options);
        }
        break;
      case 'scrypt':
        if (this.options.scryptOptions) {
          Object.assign(params, this.options.scryptOptions);
        }
        break;
    }

    return params;
  }

  /**
   * Inspect a hash string without verifying - returns algo/version/params/salt/hash.
   * @static
   * @param {string} hash - PHC formatted hash string
   * @returns {{algo: string, version: number, params: Record<string, number>, salt: string, hash: string}}
   * @throws {Error} If hash format is invalid
   */
  static inspect(hash) {
    const { algo, version, params, salt, hash: hashValue } = parseHash(hash);
    // Convert string numbers to actual numbers where possible
    const numericParams = {};
    for (const [key, value] of Object.entries(params)) {
      const num = Number(value);
      numericParams[key] = isNaN(num) ? value : num;
    }
    return { algo, version, params: numericParams, salt, hash: hashValue };
  }

  /**
   * Returns true if a hash was made with outdated/weaker params than current config.
   * @param {string} hash - PHC formatted hash string
   * @returns {boolean}
   */
  needsRehash(hash) {
    try {
      const { algo, version, params } = this.constructor.inspect(hash);

      // Check if algorithm matches
      if (algo !== this.options.backend) {
        return true; // Different algorithm needs rehash
      }

      // Get the current effective parameters for this hasher instance
      const currentParams = this._mergeBackendOptions(this.backend.defaultParams());

      // Compare stored params with current params
      const paramKeys = Object.keys(params);
      const currentKeys = Object.keys(currentParams);

      if (paramKeys.length !== currentKeys.length) {
        return true;
      }

      for (const key of paramKeys) {
        if (params[key] !== currentParams[key]) {
          return true;
        }
      }

      return false;
    } catch (err) {
      // If we can't parse the hash, treat as needing rehash
      return true;
    }
  }
}

/**
 * Argon2 backend implementation
 */
class Argon2Backend {
  /**
   * @param {import('argon2')} argon2Lib - argon2 package instance
   */
  constructor(argon2Lib) {
    this.argon2 = argon2Lib;
  }

  /**
   * Hash a password with argon2id
   * @param {string} password
   * @param {Buffer} salt
   * @param {Object} params - { memoryCost, timeCost, parallelism }
   * @returns {Promise<Object>} Object with saltBase64 and hashBase64
   */
  async hash(password, salt, params) {
    const hash = await this.argon2.hash(password, {
      type: this.argon2.argon2id,
      memoryCost: params.memoryCost || 65536,
      timeCost: params.timeCost || 3,
      parallelism: params.parallelism || 4,
      salt: salt,
      hashLength: 32
    });

    // Extract the salt and hash from the argon2 hash string
    // Format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash

    const parts = hash.split('$');
    if (parts.length < 6) {
      throw new Error('Unexpected argon2 hash format');
    }

    const saltBase64 = parts[4];
    const hashBase64 = parts[5];

    // Return as object to avoid base64 encoding/decoding issues
    return { saltBase64, hashBase64 };
  }

  /**
   * Verify a password against an argon2id hash
   * @param {string} password
   * @param {Buffer} salt - Ignored (we get salt from stored object)
   * @param {Object} hashObject - Object with saltBase64 and hashBase64 from our storage
   * @param {Object} params - { memoryCost, timeCost, parallelism }
   * @returns {Promise<boolean>}
   */
  async verify(password, salt, hashObject, params) {
    const saltBase64 = hashObject.saltBase64 || salt.toString('base64');
    const hashBase64 = hashObject.hashBase64;

    // Reconstruct the hash string for argon2 verification
    const hashString = `$argon2id$v=19$m=${params.memoryCost || 65536},t=${params.timeCost || 3},p=${params.parallelism || 4}$${saltBase64}$${hashBase64}`;

    return this.argon2.verify(hashString, password);
  }

  /**
   * Get default parameters for argon2id
   * @returns {{memoryCost: number, timeCost: number, parallelism: number}}
   */
  defaultParams() {
    return {
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4
    };
  }

  /**
   * Calibrate argon2id parameters for target time
   * @param {number} targetMs - Target time in milliseconds
   * @returns {Promise<Object>} Calibrated parameters
   */
  async calibrate(targetMs) {
    // Simplified implementation - in practice, would test different memoryCost/timeCost values
    // For now, return default params
    return this.defaultParams();
  }
}

/**
 * Bcrypt backend implementation
 */
class BcryptBackend {
  /**
   * @param {import('bcryptjs')} bcryptjsLib - bcryptjs package instance
   */
  constructor(bcryptjsLib) {
    this.bcryptjs = bcryptjsLib;
  }

  /**
   * Hash a password with bcrypt
   * @param {string} password
   * @param {Buffer} salt - Ignored for bcrypt (it generates its own salt internally)
   * @param {Object} params - { cost }
   * @returns {Promise<Object>} Object with version, cost, costString and bcryptData
   */
  async hash(password, salt, params) {
    const cost = params.cost || 12;
    const hash = await this.bcryptjs.hash(password, cost);

    // Extract the version, cost, and salt+hash portion from bcrypt hash
    // Format: $2a$10$<22_char_salt><31_char_hash>
    const parts = hash.split('$');
    if (parts.length < 4) {
      throw new Error('Unexpected bcrypt hash format');
    }

    const version = parts[1]; // e.g., "2a"
    const costFromHash = parts[2]; // e.g., "10"
    // The actual bcrypt encoded data is in parts[3] (53 chars: 22 salt + 31 hash)
    const bcryptData = parts[3];

    // Return as object to avoid base64 encoding/decoding issues
    return { version, cost: parseInt(costFromHash, 10), costString: costFromHash, bcryptData };
  }

  /**
   * Verify a password against a bcrypt hash
   * @param {string} password
   * @param {Buffer} salt - Ignored for bcrypt
   * @param {Object} hashObject - Object with version, costString and bcryptData from our storage
   * @param {Object} params - { cost }
   * @returns {Promise<boolean>}
   */
  async verify(password, salt, hashObject, params) {
    // DEBUG: Log the inputs
    console.log('DEBUG bcrypt.verify:');
    console.log('  password:', typeof password === 'string' ? `'${password}'` : password);
    console.log('  salt:', salt);
    console.log('  hashObject:', hashObject);
    console.log('  params:', params);

    const version = hashObject.version || '2b';
    const costString = hashObject.costString || String(params.cost || 12);
    const bcryptData = hashObject.bcryptData;

    // DEBUG: Log extracted values
    console.log('  extracted version:', version);
    console.log('  extracted costString:', costString);
    console.log('  extracted bcryptData:', bcryptData);

    // Reconstruct the bcrypt hash
    const bcryptHash = `$${version}\$${costString}$${bcryptData}`;
    console.log('  reconstructed bcryptHash:', bcryptHash);

    const result = await this.bcryptjs.compare(password, bcryptHash);
    console.log('  bcrypt.compare result:', result);
    return result;
  }

  /**
   * Get default parameters for bcrypt
   * @returns {{cost: number}}
   */
  defaultParams() {
    return { cost: 12 };
  }

  /**
   * Calibrate bcrypt parameters for target time
   * @param {number} targetMs - Target time in milliseconds
   * @returns {Promise<Object>} Calibrated parameters
   */
  async calibrate(targetMs) {
    // Start with low cost and increase until we exceed target time
    let cost = 1;
    let prevTime = 0;

    while (cost <= 31) { // bcrypt max cost is 31
      const start = Date.now();
      await this.bcryptjs.hash('test-password', cost);
      const elapsed = Date.now() - start;

      if (elapsed > targetMs) {
        break;
      }
      prevTime = elapsed;
      cost++;
    }

    // If we went over target, use previous cost (or 1 if first iteration was too slow)
    const finalCost = Math.max(1, cost - 1);
    return { cost: finalCost };
  }
}

/**
 * Scrypt backend implementation (using native crypto.scrypt)
 */
class ScryptBackend {
  /**
   * @param {import('crypto')} cryptoLib - Node's crypto module
   */
  constructor(cryptoLib) {
    this.crypto = cryptoLib;
  }

  /**
   * Hash a password with scrypt
   * @param {string} password
   * @param {Buffer} salt
   * @param {Object} params - { N, r, p }
   * @returns {Promise<Buffer>} Hash buffer
   */
  async hash(password, salt, params) {
    const N = params.N || 16384;
    const r = params.r || 8;
    const p = params.p || 1;
    const keyLength = 32; // 256 bits

    return new Promise((resolve, reject) => {
      this.crypto.scrypt(password, salt, keyLength, { N, r, p }, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      });
    });
  }

  /**
   * Verify a password against a scrypt hash
   * @param {string} password
   * @param {Buffer} salt
   * @param {Buffer} expectedHash
   * @param {Object} params - { N, r, p }
   * @returns {Promise<boolean>}
   */
  async verify(password, salt, expectedHash, params) {
    const N = params.N || 16384;
    const r = params.r || 8;
    const p = params.p || 1;
    const keyLength = 32; // 256 bits

    return new Promise((resolve, reject) => {
      this.crypto.scrypt(password, salt, keyLength, { N, r, p }, (err, derivedKey) => {
        if (err) reject(err);
        else {
          try {
            const result = this.crypto.timingSafeEqual(derivedKey, expectedHash);
            resolve(result);
          } catch (err) {
            resolve(false); // Length mismatch or other error
          }
        }
      });
    });
  }

  /**
   * Get default parameters for scrypt
   * @returns {{N: number, r: number, p: number}}
   */
  defaultParams() {
    return {
      N: 16384,
      r: 8,
      p: 1
    };
  }

  /**
   * Calibrate scrypt parameters for target time
   * @param {number} targetMs - Target time in milliseconds
   * @returns {Promise<Object>} Calibrated parameters
   */
  async calibrate(targetMs) {
    // Start with low N and increase until we exceed target time
    // Keep r=8, p=1 as recommended starting values
    let N = 1;
    let r = 8;
    let p = 1;

    while (N <= Math.pow(2, 20)) { // Reasonable upper limit
      const start = Date.now();
      await this._testScrypt(N, r, p);
      const elapsed = Date.now() - start;

      if (elapsed > targetMs) {
        break;
      }
      N *= 2;
    }

    // If we went over target, use previous value (or 1 if first was too slow)
    const finalN = Math.max(1, N / 2);
    return { N: finalN, r: 8, p: 1 };
  }

  /**
   * Test scrypt parameters and return time taken
   * @private
   */
  async _testScrypt(N, r, p) {
    return new Promise((resolve, reject) => {
      this.crypto.scrypt('test-password', this.crypto.randomBytes(16), 16, { N, r, p }, (err) => {
        if (err) reject(err);
        else resolve(Date.now() - Date.now());
      });
    });
  }
}

module.exports = { PasswordHasher };