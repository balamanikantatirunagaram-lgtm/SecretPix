/**
 * SecretPix — Cryptographic Engine (Web Crypto API)
 *
 * Implements:
 * - PBKDF2 key derivation (SHA-256, 600,000 iterations)
 * - AES-256-GCM authenticated encryption and decryption
 * - CSPRNG salt (16 bytes) and IV (12 bytes) generation
 * - AEAD (Authenticated Encryption with Associated Data) header binding
 * - PKCS#7 length padding to eliminate plaintext length leakage side-channels
 * - Sanitized domain error handling
 */

import { CONFIG } from './config.js';

/**
 * Custom Cryptographic Errors
 */
export class CryptoError extends Error {
  constructor(message, code = 'CRYPTO_ERROR') {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
  }
}

export class InvalidPasswordError extends CryptoError {
  constructor(message = 'Incorrect password or corrupted data. Decryption authentication failed.') {
    super(message, 'INVALID_PASSWORD');
    this.name = 'InvalidPasswordError';
  }
}

/**
 * Generate cryptographically secure random bytes
 * @param {number} length - Number of bytes
 * @returns {Uint8Array}
 */
export function getRandomBytes(length) {
  if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
    throw new CryptoError('Web Crypto API is not supported in this environment.');
  }
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Apply PKCS#7 padding to align buffer to block boundary
 * Mitigates plaintext length leak side-channel
 * @param {Uint8Array} data
 * @param {number} blockSize
 * @returns {Uint8Array}
 */
export function padBytes(data, blockSize = CONFIG.CRYPTO.PADDING_BLOCK_SIZE || 64) {
  const padLen = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data, 0);
  padded.fill(padLen, data.length);
  return padded;
}

/**
 * Strip and validate PKCS#7 padding
 * @param {Uint8Array} padded
 * @param {number} blockSize
 * @returns {Uint8Array}
 */
export function unpadBytes(padded, blockSize = CONFIG.CRYPTO.PADDING_BLOCK_SIZE || 64) {
  if (!padded || padded.length === 0 || padded.length % blockSize !== 0) {
    throw new CryptoError('Invalid padded buffer length.');
  }
  const padLen = padded[padded.length - 1];
  if (padLen <= 0 || padLen > blockSize) {
    throw new CryptoError('Invalid padding value.');
  }
  for (let i = padded.length - padLen; i < padded.length; i++) {
    if (padded[i] !== padLen) {
      throw new CryptoError('Corrupted padding bytes.');
    }
  }
  return padded.slice(0, padded.length - padLen);
}

/**
 * Derive an AES-256-GCM CryptoKey from a password and salt using PBKDF2
 * @param {string} password - User-provided password
 * @param {Uint8Array} salt - 16-byte random salt
 * @param {number} iterations - PBKDF2 iteration count (default 600,000)
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKey(
  password,
  salt,
  iterations = CONFIG.CRYPTO.PBKDF2_ITERATIONS
) {
  if (!password || typeof password !== 'string') {
    throw new CryptoError('A valid password string is required for key derivation.');
  }
  if (!salt || !(salt instanceof Uint8Array) || salt.length !== CONFIG.CRYPTO.SALT_LENGTH_BYTES) {
    throw new CryptoError(`Salt must be a Uint8Array of exactly ${CONFIG.CRYPTO.SALT_LENGTH_BYTES} bytes.`);
  }

  const textEncoder = new TextEncoder();
  const passwordBytes = textEncoder.encode(password);

  // 1. Import raw password bytes as a PBKDF2 master key
  const baseKey = await crypto.subtle.importKey(
    'raw',
    passwordBytes,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  // 2. Derive 256-bit AES-GCM encryption key
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: CONFIG.CRYPTO.PBKDF2_HASH,
    },
    baseKey,
    {
      name: CONFIG.CRYPTO.ALGORITHM,
      length: CONFIG.CRYPTO.KEY_LENGTH,
    },
    false, // Key is non-extractable for memory security
    ['encrypt', 'decrypt']
  );

  return derivedKey;
}

/**
 * Encrypt a plaintext message using AES-256-GCM with length padding and optional AAD
 * @param {string} plaintext - Plaintext message to encrypt
 * @param {string} password - User password
 * @param {object} options - Optional { salt, iv, additionalData }
 * @returns {Promise<{ ciphertext: Uint8Array, salt: Uint8Array, iv: Uint8Array }>}
 */
export async function encryptMessage(plaintext, password, options = {}) {
  if (typeof plaintext !== 'string' || plaintext.length === 0) {
    throw new CryptoError('Cannot encrypt empty or invalid message.');
  }
  if (!password || typeof password !== 'string') {
    throw new CryptoError('Password cannot be empty.');
  }

  // 1. Generate fresh CSPRNG salt and IV if not pre-provided
  const salt = options.salt || getRandomBytes(CONFIG.CRYPTO.SALT_LENGTH_BYTES);
  const iv = options.iv || getRandomBytes(CONFIG.CRYPTO.IV_LENGTH_BYTES);

  // 2. Derive AES key via PBKDF2 (600,000 rounds)
  const key = await deriveKey(password, salt);

  // 3. Encode plaintext to UTF-8 bytes and apply PKCS#7 block padding
  const textEncoder = new TextEncoder();
  const plaintextBytes = textEncoder.encode(plaintext);
  const paddedBytes = padBytes(plaintextBytes);

  // 4. Configure GCM algorithm parameters with optional AEAD additionalData
  const gcmParams = {
    name: CONFIG.CRYPTO.ALGORITHM,
    iv: iv,
    tagLength: CONFIG.CRYPTO.TAG_LENGTH_BITS,
  };

  if (options.additionalData && options.additionalData instanceof Uint8Array) {
    gcmParams.additionalData = options.additionalData;
  }

  // 5. Encrypt with AES-GCM (128-bit authentication tag appended automatically)
  let encryptedBuffer;
  try {
    encryptedBuffer = await crypto.subtle.encrypt(
      gcmParams,
      key,
      paddedBytes
    );
  } catch (err) {
    throw new CryptoError(`Encryption operation failed: ${err.message}`);
  }

  return {
    ciphertext: new Uint8Array(encryptedBuffer),
    salt,
    iv,
  };
}

/**
 * Decrypt a ciphertext buffer using AES-256-GCM with unpadding and optional AAD verification
 * @param {Uint8Array} ciphertext - Encrypted ciphertext with appended 128-bit auth tag
 * @param {Uint8Array} salt - 16-byte PBKDF2 salt
 * @param {Uint8Array} iv - 12-byte AES-GCM initialization vector
 * @param {string} password - User-provided password
 * @param {Uint8Array|null} additionalData - Optional AEAD additional authenticated data
 * @returns {Promise<string>} - Decrypted plaintext string
 */
export async function decryptMessage(ciphertext, salt, iv, password, additionalData = null) {
  if (!ciphertext || !(ciphertext instanceof Uint8Array) || ciphertext.length === 0) {
    throw new CryptoError('Invalid ciphertext buffer.');
  }
  if (!salt || !(salt instanceof Uint8Array) || salt.length !== CONFIG.CRYPTO.SALT_LENGTH_BYTES) {
    throw new CryptoError('Invalid cryptographic salt.');
  }
  if (!iv || !(iv instanceof Uint8Array) || iv.length !== CONFIG.CRYPTO.IV_LENGTH_BYTES) {
    throw new CryptoError('Invalid initialization vector (IV).');
  }
  if (!password || typeof password !== 'string') {
    throw new CryptoError('Password is required for decryption.');
  }

  // 1. Re-derive key using identical parameters and salt
  const key = await deriveKey(password, salt);

  // 2. Configure GCM params with optional AAD
  const gcmParams = {
    name: CONFIG.CRYPTO.ALGORITHM,
    iv: iv,
    tagLength: CONFIG.CRYPTO.TAG_LENGTH_BITS,
  };

  if (additionalData && additionalData instanceof Uint8Array) {
    gcmParams.additionalData = additionalData;
  }

  // 3. Decrypt with AES-GCM (authenticates ciphertext, tag, and additionalData)
  let decryptedBuffer;
  try {
    decryptedBuffer = await crypto.subtle.decrypt(
      gcmParams,
      key,
      ciphertext
    );
  } catch (err) {
    // If decryption fails (authentication tag mismatch or tampered AAD), Web Crypto throws OperationError
    throw new InvalidPasswordError();
  }

  // 4. Strip PKCS#7 padding
  let unpaddedBytes;
  try {
    unpaddedBytes = unpadBytes(new Uint8Array(decryptedBuffer));
  } catch (padErr) {
    throw new InvalidPasswordError();
  }

  // 5. Decode UTF-8 bytes to plaintext string
  const textDecoder = new TextDecoder('utf-8', { fatal: true });
  try {
    return textDecoder.decode(unpaddedBytes);
  } catch (decodeErr) {
    throw new CryptoError('Decrypted payload contains invalid UTF-8 characters.');
  }
}
