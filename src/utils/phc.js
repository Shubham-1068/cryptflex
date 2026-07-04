const crypto = require('crypto');

/**
 * Encode Buffer to base64url (no padding)
 * @param {Buffer} buffer
 * @returns {string}
 */
function encodeBase64Url(buffer) {
  return buffer.toString('base64url');
}

/**
 * Decode base64url to Buffer
 * @param {string} str
 * @returns {Buffer}
 */
function decodeBase64Url(str) {
  return Buffer.from(str, 'base64url');
}

/**
 * Parse a PHC-formatted hash string into components
 * @param {string} hash - PHC formatted hash string
 * @returns {{algo: string, version: number, params: Record<string, number|string>, salt: string, hash: string}}
 * @throws {Error} If hash format is invalid
 */
function parseHash(hash) {
  if (!hash || typeof hash !== 'string') {
    throw new Error('Hash must be a non-empty string');
  }

  if (!hash.startsWith('$')) {
    throw new Error('Invalid PHC format: missing leading $');
  }

  const parts = hash.split('$');
  if (parts.length < 3) {
    throw new Error('Invalid PHC format: too few parts');
  }

  // Format: $algo$v=version[,param1=val1,param2=val2...]$salt$hash
  const algo = parts[1];
  if (!algo) {
    throw new Error('Invalid PHC format: missing algorithm');
  }

  const versionPart = parts[2];
  if (!versionPart.startsWith('v=')) {
    throw new Error('Invalid PHC format: missing version prefix');
  }
  const versionStr = versionPart.substring(2);
  const version = parseInt(versionStr, 10);
  if (isNaN(version)) {
    throw new Error('Invalid PHC format: invalid version number');
  }

  // Parse parameters if present (after v=version, before $)
  let params = {};
  let saltPartIndex = 3;
  let hashPartIndex = 4;

  // Check if there are parameters in the version part (look for , or = after v=XX)
  const versionAndPotentialParams = parts[2];
  const dollarIndex = versionAndPotentialParams.indexOf('$', 2); // Find $ after v=
  if (dollarIndex !== -1) {
    // There are parameters in the version part
    const paramStartIndex = 2 + versionStr.length + 1; // Position after "v=XX"
    const paramString = versionAndPotentialParams.substring(paramStartIndex, dollarIndex);
    if (paramString) {
      const paramPairs = paramString.split(',');
      for (const pair of paramPairs) {
        const [key, value] = pair.split('=');
        if (key) {
          const numValue = Number(value);
          params[key] = isNaN(numValue) ? value : numValue;
        }
      }
    }
  } else {
    // No parameters in version part, check if parts[3] contains params
    if (parts.length > 4 && (parts[3].includes(',') || parts[3].includes('=')) && !parts[3].startsWith('v=')) {
      // Parse params from parts[3]
      const paramString = parts[3];
      if (paramString) {
        const paramPairs = paramString.split(',');
        for (const pair of paramPairs) {
          const [key, value] = pair.split('=');
          if (key) {
            const numValue = Number(value);
            params[key] = isNaN(numValue) ? value : numValue;
          }
        }
      }
      saltPartIndex = 4;
      hashPartIndex = 5;
    }
  }

  const salt = parts[saltPartIndex];
  const hashValue = parts[hashPartIndex];

  if (!salt || !hashValue) {
    throw new Error('Invalid PHC format: missing salt or hash');
  }

  return {
    algo,
    version,
    params,
    salt,
    hash: hashValue
  };
}

/**
 * Format hash components into PHC string
 * @param {Object} options - Hash components
 * @param {string} options.algo - Algorithm name
 * @param {number} options.version - Version number
 * @param {Record<string, number|string>} options.params - Algorithm parameters
 * @param {string} options.salt - Base64url encoded salt
 * @param {string} options.hash - Base64url encoded hash
 * @returns {string} PHC formatted hash string
 */
function formatHash({ algo, version, params, salt, hash }) {
  let result = `$${algo}$v=${version}`;

  // Add parameters if any
  const paramEntries = Object.entries(params);
  if (paramEntries.length > 0) {
    const paramStrings = paramEntries.map(([key, value]) => `${key}=${value}`);
    result += `$${paramStrings.join(',')}`;
  } else {
    result += '$'; // Empty params section
  }

  result += `\$${salt}\$${hash}`;
  return result;
}

module.exports = {
  encodeBase64Url,
  decodeBase64Url,
  parseHash,
  formatHash
};