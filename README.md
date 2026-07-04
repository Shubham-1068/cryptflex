# cryptflex

[GitHub Repository](https://github.com/Shubham-1068/cryptflex)

[![npm version](https://img.shields.io/npm/v/cryptflex.svg)](https://www.npmjs.com/package/cryptflex)
[![License: MIT](https://img.shields.io/npm/l/cryptflex.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/node/v/cryptflex.svg)](https://nodejs.org)

A flexible, modern password hashing library for Node.js with pluggable backends (bcrypt, scrypt, Argon2id) and Password Hashing Competition (PHC) format support.

## Features

- 🔌 **Pluggable Backends**: Choose between bcrypt (via bcryptjs), scrypt (native crypto), and Argon2id (via argon2 package)
- 📜 **PHC Compliant**: Generates and verifies Password Hashing Competition format strings (`$algo$v=version$param1=val1,...$salt$hash`)
- 🌶️ **Pepper Support**: Optional HMAC-SHA256 peppering for additional security (store pepper separately from your data)
- ⚡ **Fully Async**: All operations return Promises for seamless async/await integration
- ⚙️ **Highly Configurable**: Per-backend parameter tuning (cost factors, memory, parallelism, etc.)
- 🔒 **Security Focused**: Cryptographically secure salts (16 bytes), timing-safe comparisons where available
- 🧩 **Zero Runtime Dependencies**: Only requires the backend package you choose (argon2, bcryptjs)
- 📚 **Well Documented**: Comprehensive JSDoc comments and clear TypeScript-like definitions via JSDoc

## Installation

```bash
npm install cryptflex
```

### Peer Dependencies (install one based on your preferred backend)

```bash
# For Argon2id (default backend)
npm install argon2

# For Bcrypt
npm install bcryptjs

# For Scrypt (uses Node's built-in crypto - no additional install needed)
```

## Quick Start

```javascript
const { PasswordHasher } = require('cryptflex');

// Using default Argon2id backend
async function example() {
  const hasher = new PasswordHasher();
  const hash = await hasher.hash('mySecurePassword');
  console.log('Generated hash:', hash);
  
  const isValid = await hasher.verify('mySecurePassword', hash);
  console.log('Password valid:', isValid); // true
  
  const isInvalid = await hasher.verify('wrongPassword', hash);
  console.log('Wrong password rejected:', !isInvalid); // true
}

example().catch(console.error);

// Using bcrypt with custom configuration
const bcryptHasher = new PasswordHasher({
  backend: 'bcrypt',
  bcryptCost: 12,
  pepper: process.env.PEPPER_SECRET // Store securely in environment variables!
});

const bcryptHash = await bcryptHasher.hash('mySecurePassword');
// ... verify as above
```

## API

### `new PasswordHasher(options)`

Create a new password hasher instance.

**Options:**
- `backend`: `'argon2id' | 'bcrypt' | 'scrypt'` (default: `'argon2id'`)
- `pepper`: `string` - Secret pepper for HMAC-SHA256 pre-processing (optional, but recommended for production)
- `targetMs`: `number` - Target hash time in milliseconds for calibration (default: `250`)
- `bcryptCost`: `number` - Cost factor for bcrypt (default: `12`)
- `argon2Options`: `Object` - Argon2 options:
  - `memoryCost`: `number` - Memory cost (default: `65536`)
  - `timeCost`: `number` - Time cost (default: `3`)
  - `parallelism`: `number` - Parallelism (default: `4`)
- `scryptOptions`: `Object` - Scrypt options:
  - `N`: `number` - CPU/memory cost parameter (must be power of 2, default: `16384`)
  - `r`: `number` - Block size (default: `8`)
  - `p`: `number` - Parallelization parameter (default: `1`)

### `async hash(password)`

Hash a password.

**Parameters:**
- `password`: `string` - The password to hash

**Returns:** `Promise<string>` - PHC formatted hash string

### `async verify(password, hash)`

Verify a password against a stored hash.

**Parameters:**
- `password`: `string` - The password to verify
- `hash`: `string` - PHC formatted hash to verify against

**Returns:** `Promise<boolean>` - `true` if password matches, `false` otherwise

### `needsRehash(hash)`

Check if a hash was made with outdated/weaker parameters compared to current configuration.

**Parameters:**
- `hash`: `string` - PHC formatted hash to check

**Returns:** `boolean` - `true` if hash needs rehashing, `false` otherwise

### `static inspect(hash)`

Extract algorithm, version, params, salt, and hash from a PHC string.

**Parameters:**
- `hash`: `string` - PHC formatted hash string

**Returns:** `Object` - `{algo, version, params, salt, hash}`

### `async calibrate()`

Auto-tune parameters to hit target hash time. Call once at application startup.

**Returns:** `Promise<void>`

## Examples

### Basic Usage (Argon2id - Default)
```javascript
const { PasswordHasher } = require('cryptflex');

async function example() {
  const hasher = new PasswordHasher();
  const hash = await hasher.hash('password123');
  
  console.log('Hash:', hash);
  // Example: $argon2id$v=1$memoryCost=65536,timeCost=3,parallelism=4$...$...
  
  const valid = await hasher.verify('password123', hash);
  console.log('Valid password:', valid); // true
  
  const invalid = await hasher.verify('wrongpass', hash);
  console.log('Wrong password rejected:', !invalid); // true
}

example().catch(console.error);
```

### Custom Backend Configuration
```javascript
// Bcrypt with custom cost and pepper
const bcryptHasher = new PasswordHasher({
  backend: 'bcrypt',
  bcryptCost: 12,
  pepper: process.env.PEPPER_SECRET
});

// Scrypt with low parameters for testing (use higher in production!)
const scryptHasher = new PasswordHasher({
  backend: 'scrypt',
  scryptOptions: { N: 64, r: 1, p: 1 }
});

// Argon2id with custom parameters
const argon2Hasher = new PasswordHasher({
  backend: 'argon2id',
  argon2Options: {
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4
  }
});
```

### Rehash Detection
```javascript
const weakHasher = new PasswordHasher({ backend: 'bcrypt', bcryptCost: 4 });
const strongHasher = new PasswordHasher({ backend: 'bcrypt', bcryptCost: 12 });

const oldHash = await weakHasher.hash('password123');

if (strongHasher.needsRehash(oldHash)) {
  const newHash = await strongHasher.hash('password123');
  // Store newHash instead of oldHash
}
```

### Hash Inspection
```javascript
const { PasswordHasher } = require('cryptflex');
const hash = await new PasswordHasher().hash('test123');
const info = PasswordHasher.inspect(hash);

console.log('Algorithm:', info.algo); // 'argon2id' (default)
console.log('Version:', info.version); // 1
console.log('Parameters:', info.params);
// { memoryCost: 65536, timeCost: 3, parallelism: 4 }
console.log('Salt length:', info.salt.length); // 24 characters
console.log('Hash length:', info.hash.length); // Varies by backend
```

## Security Best Practices

1. **Always use a pepper**: Store your pepper in an environment variable or secure vault, never in your codebase.
2. **Rotate pepper periodically**: When rotating passwords, consider generating a new pepper and re-hashing all passwords.
3. **Use appropriate work factors**: Adjust bcrypt cost, Argon2 parameters, or scrypt N/r/p based on your security/performance requirements.
4. **Never log passwords or hashes**: Avoid accidentally logging sensitive information.
5. **Use HTTPS**: Always transmit passwords over encrypted connections.
6. **Consider breach detection**: Services like HaveIBeenPwned can help check if passwords have been exposed in breaches.

## Why cryptflex?

- **Flexibility**: Switch between backends without changing your application code
- **Standards Compliant**: Uses the widely-adopted PHC format for interoperability
- **Modern**: Supports the latest password hashing algorithms (Argon2id won the Password Hashing Competition)
- **Simple**: Clean API with sensible defaults
- **Secure**: Built with security best practices in mind

## License

MIT © 2026 Shubham

## Support

If you find this library useful, please consider:
- Giving it a ⭐️ on GitHub: https://github.com/Shubham-1068/cryptflex
- Sharing it with colleagues
- Contributing improvements or reporting issues: https://github.com/Shubham-1068/cryptflex/issues

---

**Note**: This library is designed for server-side Node.js applications. For browser-based cryptography, consider using the Web Crypto API or specialized libraries.