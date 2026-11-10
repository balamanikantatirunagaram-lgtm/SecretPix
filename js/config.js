/**
 * SecretPix — Global Configuration & Security Constants
 */

export const CONFIG = {
  APP_NAME: 'SecretPix',
  TAGLINE: 'Hide in Plain Sight. Share with Confidence.',
  VERSION: '1.1.0',

  // Binary Protocol Constants
  PROTOCOL: {
    MAGIC_BYTES: new Uint8Array([0x53, 0x50, 0x49, 0x58]), // 'SPIX'
    MAGIC_STRING: 'SPIX',
    VERSION: 0x01,
    PAYLOAD_TYPES: {
      TEXT: 0x01,
      FILE: 0x02,
    },
    // Overhead = Magic(4) + Version(1) + Type(1) + Salt(16) + IV(12) + Length(4) + GCM_Tag(16) = 54 bytes
    HEADER_SIZE_BYTES: 38,
    TAG_SIZE_BYTES: 16,
    TOTAL_OVERHEAD_BYTES: 54,
  },

  // Cryptographic Parameters
  CRYPTO: {
    ALGORITHM: 'AES-GCM',
    KEY_LENGTH: 256,
    TAG_LENGTH_BITS: 128,
    SALT_LENGTH_BYTES: 16,
    IV_LENGTH_BYTES: 12,
    PBKDF2_HASH: 'SHA-256',
    PBKDF2_ITERATIONS: 600000, // NIST Recommended baseline
    MIN_PASSWORD_LENGTH: 8,
    PADDING_BLOCK_SIZE: 64, // Mitigate plaintext length side-channel
  },

  // Image & File Constraints
  LIMITS: {
    MAX_IMAGE_FILE_SIZE_BYTES: 25 * 1024 * 1024, // 25 MB
    MAX_IMAGE_PIXELS: 25000000, // 25 Megapixels (~100 MB uncompressed ImageData)
    SUPPORTED_INPUT_MIME_TYPES: [
      'image/png',
      'image/jpeg',
      'image/jpg',
      'image/webp'
    ],
    OUTPUT_FORMAT: 'image/png',
  }
};
