/**
 * SecretPix — Dedicated Web Worker for Cryptography & Steganography
 *
 * Runs off the main UI thread to prevent UI freezing during:
 * - PBKDF2 key derivation (600,000 SHA-256 iterations)
 * - Intensive pixel traversal across multi-megapixel images
 * - AEAD header integrity binding and PKCS#7 length padding
 */

import { CONFIG } from './config.js';
import { encryptMessage, decryptMessage, getRandomBytes, InvalidPasswordError } from './crypto.js';
import {
  createHeader,
  packPayload,
  embedPayloadInImageData,
  extractPayloadFromImageData,
  NoSecretPixDataError,
  CapacityExceededError
} from './steganography.js';

self.onmessage = async (e) => {
  const { type, payload } = e.data;

  try {
    if (type === 'ENCRYPT_AND_EMBED') {
      const { imageData, message, password } = payload;

      // Stage 1: Deriving key and encrypting with AEAD header binding
      self.postMessage({
        status: 'PROGRESS',
        stage: 'Deriving key with PBKDF2 (600k rounds) & encrypting...',
        percent: 25,
      });

      // 1. Calculate padded ciphertext length for header AAD
      const plaintextBytes = new TextEncoder().encode(message);
      const blockSize = CONFIG.CRYPTO.PADDING_BLOCK_SIZE || 64;
      const padLen = blockSize - (plaintextBytes.length % blockSize);
      const paddedLength = plaintextBytes.length + padLen;
      const ciphertextLength = paddedLength + (CONFIG.CRYPTO.TAG_LENGTH_BITS / 8);

      const salt = getRandomBytes(CONFIG.CRYPTO.SALT_LENGTH_BYTES);
      const iv = getRandomBytes(CONFIG.CRYPTO.IV_LENGTH_BYTES);
      const header = createHeader(salt, iv, ciphertextLength);

      const { ciphertext } = await encryptMessage(message, password, { salt, iv, additionalData: header });

      // Stage 2: Packaging binary payload
      self.postMessage({
        status: 'PROGRESS',
        stage: 'Packing binary steganographic protocol with AEAD integrity...',
        percent: 50,
      });

      const binaryPayload = packPayload(salt, iv, ciphertext);

      // Stage 3: Embedding bits into pixels
      self.postMessage({
        status: 'PROGRESS',
        stage: 'Embedding encrypted bits into image pixels...',
        percent: 75,
      });

      embedPayloadInImageData(imageData, binaryPayload);

      // Success
      self.postMessage({
        status: 'SUCCESS',
        type: 'ENCRYPT_AND_EMBED',
        result: { imageData },
      });
    } else if (type === 'EXTRACT_AND_DECRYPT') {
      const { imageData, password } = payload;

      // Stage 1: Extracting payload from pixels
      self.postMessage({
        status: 'PROGRESS',
        stage: 'Extracting hidden payload from pixels...',
        percent: 30,
      });

      const { salt, iv, ciphertext, header } = extractPayloadFromImageData(imageData);

      // Stage 2: Deriving key and decrypting with AAD verification
      self.postMessage({
        status: 'PROGRESS',
        stage: 'Deriving key & verifying AEAD integrity...',
        percent: 70,
      });

      const decryptedText = await decryptMessage(ciphertext, salt, iv, password, header);

      // Success
      self.postMessage({
        status: 'SUCCESS',
        type: 'EXTRACT_AND_DECRYPT',
        result: { decryptedText },
      });
    } else {
      throw new Error(`Unknown worker message type: "${type}"`);
    }
  } catch (err) {
    let errorCode = 'WORKER_ERROR';
    if (err instanceof InvalidPasswordError) errorCode = 'INVALID_PASSWORD';
    if (err instanceof NoSecretPixDataError) errorCode = 'NO_PAYLOAD_DETECTED';
    if (err instanceof CapacityExceededError) errorCode = 'CAPACITY_EXCEEDED';

    self.postMessage({
      status: 'ERROR',
      type,
      error: {
        message: err.message,
        code: errorCode,
      },
    });
  }
};
