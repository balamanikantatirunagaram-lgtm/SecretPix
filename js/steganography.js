/**
 * SecretPix — Steganography Engine & Binary Protocol (LSB Image Steganography)
 *
 * Implements:
 * - Versioned binary payload protocol (Magic 'SPIX', Version 0x01, Type, Salt, IV, Length, Ciphertext)
 * - Deterministic RGB channel bit embedding (Least Significant Bit)
 * - Alpha channel preservation (100% untouched)
 * - Fast header detection without scanning full image buffers
 * - Bounds checking and memory exhaustion guards
 */

import { CONFIG } from './config.js';

export class SteganographyError extends Error {
  constructor(message, code = 'STEGANOGRAPHY_ERROR') {
    super(message);
    this.name = 'SteganographyError';
    this.code = code;
  }
}

export class NoSecretPixDataError extends SteganographyError {
  constructor(message = 'No SecretPix data detected in this image.') {
    super(message, 'NO_PAYLOAD_DETECTED');
    this.name = 'NoSecretPixDataError';
  }
}

export class CapacityExceededError extends SteganographyError {
  constructor(message = 'Message payload exceeds image pixel capacity.') {
    super(message, 'CAPACITY_EXCEEDED');
    this.name = 'CapacityExceededError';
  }
}

/**
 * Create a 38-byte standardized binary protocol header
 * @param {Uint8Array} salt
 * @param {Uint8Array} iv
 * @param {number} ciphertextLength
 * @param {number} payloadType
 * @returns {Uint8Array}
 */
export function createHeader(
  salt,
  iv,
  ciphertextLength,
  payloadType = CONFIG.PROTOCOL.PAYLOAD_TYPES.TEXT
) {
  if (!(salt instanceof Uint8Array) || salt.length !== CONFIG.CRYPTO.SALT_LENGTH_BYTES) {
    throw new SteganographyError('Invalid salt length for header creation.');
  }
  if (!(iv instanceof Uint8Array) || iv.length !== CONFIG.CRYPTO.IV_LENGTH_BYTES) {
    throw new SteganographyError('Invalid IV length for header creation.');
  }

  const header = new Uint8Array(CONFIG.PROTOCOL.HEADER_SIZE_BYTES);
  const view = new DataView(header.buffer);

  // 1. Magic bytes 'SPIX'
  header.set(CONFIG.PROTOCOL.MAGIC_BYTES, 0);

  // 2. Version byte (0x01)
  header[4] = CONFIG.PROTOCOL.VERSION;

  // 3. Payload type (0x01 for TEXT)
  header[5] = payloadType;

  // 4. Salt (16 bytes)
  header.set(salt, 6);

  // 5. IV (12 bytes)
  header.set(iv, 22);

  // 6. Ciphertext length (4 bytes Uint32 Big-Endian)
  view.setUint32(34, ciphertextLength, false);

  return header;
}

/**
 * Pack security parameters and ciphertext into a serialized binary payload buffer
 *
 * Layout:
 * [0..3]   : Magic Header (4 bytes: 'S','P','I','X')
 * [4]      : Version (1 byte: 0x01)
 * [5]      : Payload Type (1 byte: 0x01 = TEXT, 0x02 = FILE)
 * [6..21]  : Salt (16 bytes)
 * [22..33] : IV (12 bytes)
 * [34..37] : Ciphertext Length (4 bytes: Uint32 Big-Endian)
 * [38..N]  : Ciphertext + Auth Tag (N bytes)
 *
 * @param {Uint8Array} salt - 16-byte PBKDF2 salt
 * @param {Uint8Array} iv - 12-byte AES-GCM IV
 * @param {Uint8Array} ciphertext - Encrypted data with authentication tag
 * @param {number} payloadType - 0x01 for TEXT, 0x02 for FILE
 * @returns {Uint8Array}
 */
export function packPayload(
  salt,
  iv,
  ciphertext,
  payloadType = CONFIG.PROTOCOL.PAYLOAD_TYPES.TEXT
) {
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length === 0) {
    throw new SteganographyError('Invalid ciphertext buffer for serialization.');
  }

  const header = createHeader(salt, iv, ciphertext.length, payloadType);
  const totalLength = header.length + ciphertext.length;
  const buffer = new Uint8Array(totalLength);

  buffer.set(header, 0);
  buffer.set(ciphertext, header.length);

  return buffer;
}

/**
 * Unpack a serialized binary payload buffer into constituent fields
 * @param {Uint8Array} payloadBytes
 * @returns {{
 *   version: number,
 *   payloadType: number,
 *   salt: Uint8Array,
 *   iv: Uint8Array,
 *   ciphertext: Uint8Array
 * }}
 */
export function unpackPayload(payloadBytes) {
  const headerSize = CONFIG.PROTOCOL.HEADER_SIZE_BYTES;
  if (!payloadBytes || payloadBytes.length < headerSize) {
    throw new SteganographyError('Payload buffer is too short to contain a valid header.');
  }

  // 1. Validate Magic bytes
  for (let i = 0; i < 4; i++) {
    if (payloadBytes[i] !== CONFIG.PROTOCOL.MAGIC_BYTES[i]) {
      throw new NoSecretPixDataError();
    }
  }

  // 2. Validate Version
  const version = payloadBytes[4];
  if (version !== CONFIG.PROTOCOL.VERSION) {
    throw new SteganographyError(`Unsupported SecretPix version 0x0${version}.`);
  }

  // 3. Payload Type
  const payloadType = payloadBytes[5];

  // 4. Extract Salt (16 bytes)
  const salt = payloadBytes.slice(6, 22);

  // 5. Extract IV (12 bytes)
  const iv = payloadBytes.slice(22, 34);

  // 6. Extract Ciphertext Length
  const view = new DataView(payloadBytes.buffer, payloadBytes.byteOffset, payloadBytes.byteLength);
  const declaredLength = view.getUint32(34, false);

  // 7. Validate Length Bounds
  if (headerSize + declaredLength > payloadBytes.length) {
    throw new SteganographyError('Declared payload length exceeds buffer length. Data may be truncated.');
  }

  // 8. Extract Ciphertext and full Header
  const header = payloadBytes.slice(0, headerSize);
  const ciphertext = payloadBytes.slice(headerSize, headerSize + declaredLength);

  return {
    version,
    payloadType,
    salt,
    iv,
    ciphertext,
    header,
  };
}

/**
 * Embed a binary payload into an ImageData buffer using Least Significant Bit (LSB) steganography
 *
 * Pixel Traversal:
 * - Each pixel has 4 channels: [R, G, B, A]
 * - R: data[i * 4 + 0] LSB
 * - G: data[i * 4 + 1] LSB
 * - B: data[i * 4 + 2] LSB
 * - A: data[i * 4 + 3] (Alpha channel is strictly preserved!)
 *
 * @param {ImageData} imageData - Target canvas pixel buffer (will be modified in-place)
 * @param {Uint8Array} payloadBytes - Serialized binary payload
 * @returns {ImageData} - Modified pixel buffer
 */
export function embedPayloadInImageData(imageData, payloadBytes) {
  const width = imageData.width;
  const height = imageData.height;
  const totalPixels = width * height;
  const totalAvailableBits = totalPixels * 3;
  const totalRequiredBits = payloadBytes.length * 8;

  if (totalRequiredBits > totalAvailableBits) {
    throw new CapacityExceededError(
      `Image capacity (${Math.floor(totalAvailableBits / 8)} bytes) is too small for payload (${payloadBytes.length} bytes).`
    );
  }

  const data = imageData.data;
  let byteIndex = 0;
  let bitIndex = 0; // 0 (MSB) to 7 (LSB)

  // Traverse pixels
  for (let i = 0; i < totalPixels; i++) {
    const pixelOffset = i * 4;

    // Traverse RGB channels (channel 0 = R, 1 = G, 2 = B)
    for (let c = 0; c < 3; c++) {
      if (byteIndex >= payloadBytes.length) {
        // All bits embedded successfully
        return imageData;
      }

      const currentByte = payloadBytes[byteIndex];
      // Extract bit MSB-first: bit 0 is (byte >> 7) & 1, bit 7 is (byte >> 0) & 1
      const bit = (currentByte >> (7 - bitIndex)) & 1;

      // Replace the least significant bit of the channel
      const channelIndex = pixelOffset + c;
      data[channelIndex] = (data[channelIndex] & 0xfe) | bit;

      bitIndex++;
      if (bitIndex === 8) {
        bitIndex = 0;
        byteIndex++;
      }
    }
  }

  return imageData;
}

/**
 * Quick Header Scanner: Checks whether an ImageData buffer starts with 'SPIX' magic bytes
 * Requires reading only 32 bits (the first 11 pixels)
 * @param {ImageData} imageData
 * @returns {boolean}
 */
export function detectSecretPixHeader(imageData) {
  if (!imageData || !imageData.data || imageData.width * imageData.height < 11) {
    return false;
  }

  const data = imageData.data;
  const magic = CONFIG.PROTOCOL.MAGIC_BYTES;
  let byteIndex = 0;
  let bitIndex = 0;
  let currentByte = 0;

  for (let i = 0; i < 11; i++) {
    const pixelOffset = i * 4;
    for (let c = 0; c < 3; c++) {
      const bit = data[pixelOffset + c] & 1;
      currentByte = (currentByte << 1) | bit;
      bitIndex++;

      if (bitIndex === 8) {
        if (currentByte !== magic[byteIndex]) {
          return false;
        }
        byteIndex++;
        bitIndex = 0;
        currentByte = 0;
        if (byteIndex === 4) {
          return true; // All 4 magic bytes matched!
        }
      }
    }
  }

  return false;
}

/**
 * Extract embedded payload bytes from an ImageData pixel buffer
 * @param {ImageData} imageData
 * @returns {{
 *   version: number,
 *   payloadType: number,
 *   salt: Uint8Array,
 *   iv: Uint8Array,
 *   ciphertext: Uint8Array
 * }}
 */
export function extractPayloadFromImageData(imageData) {
  const width = imageData.width;
  const height = imageData.height;
  const totalPixels = width * height;
  const totalAvailableBytes = Math.floor((totalPixels * 3) / 8);

  const headerSize = CONFIG.PROTOCOL.HEADER_SIZE_BYTES; // 38 bytes
  if (totalAvailableBytes < headerSize) {
    throw new NoSecretPixDataError('Image is too small to contain a SecretPix payload.');
  }

  const data = imageData.data;

  // Helper to extract N bytes from pixel stream
  let pixelIndex = 0;
  let channelIndex = 0;

  function readNextBytes(count) {
    const output = new Uint8Array(count);
    let currentByte = 0;
    let bitIndex = 0;
    let bytesRead = 0;

    while (bytesRead < count && pixelIndex < totalPixels) {
      const bit = data[pixelIndex * 4 + channelIndex] & 1;
      currentByte = (currentByte << 1) | bit;
      bitIndex++;

      // Advance channel and pixel
      channelIndex++;
      if (channelIndex === 3) {
        channelIndex = 0;
        pixelIndex++;
      }

      if (bitIndex === 8) {
        output[bytesRead] = currentByte;
        bytesRead++;
        bitIndex = 0;
        currentByte = 0;
      }
    }

    if (bytesRead < count) {
      throw new SteganographyError('Premature end of pixel data during extraction.');
    }

    return output;
  }

  // 1. Read Magic Header (4 bytes)
  const magic = readNextBytes(4);
  for (let i = 0; i < 4; i++) {
    if (magic[i] !== CONFIG.PROTOCOL.MAGIC_BYTES[i]) {
      throw new NoSecretPixDataError('No SecretPix data detected in this image.');
    }
  }

  // 2. Read Version and Payload Type (2 bytes)
  const verAndType = readNextBytes(2);
  const version = verAndType[0];
  const payloadType = verAndType[1];

  if (version !== CONFIG.PROTOCOL.VERSION) {
    throw new SteganographyError(`Unsupported SecretPix payload version (0x0${version}).`);
  }

  // 3. Read Salt (16 bytes)
  const salt = readNextBytes(CONFIG.CRYPTO.SALT_LENGTH_BYTES);

  // 4. Read IV (12 bytes)
  const iv = readNextBytes(CONFIG.CRYPTO.IV_LENGTH_BYTES);

  // 5. Read Payload Length (4 bytes Uint32)
  const lengthBytes = readNextBytes(4);
  const view = new DataView(lengthBytes.buffer, lengthBytes.byteOffset, lengthBytes.byteLength);
  const ciphertextLength = view.getUint32(0, false);

  // Bounds check: Protect against buffer memory exhaustion attacks
  const remainingMaxBytes = totalAvailableBytes - headerSize;
  if (ciphertextLength === 0 || ciphertextLength > remainingMaxBytes) {
    throw new SteganographyError(
      `Invalid declared payload length (${ciphertextLength} bytes). Image capacity is ${remainingMaxBytes} bytes. Image may be corrupted.`
    );
  }

  // Assemble the exact 38-byte header slice for AEAD verification
  const header = new Uint8Array(headerSize);
  header.set(magic, 0);
  header.set(verAndType, 4);
  header.set(salt, 6);
  header.set(iv, 22);
  header.set(lengthBytes, 34);

  // 6. Read Ciphertext bytes
  const ciphertext = readNextBytes(ciphertextLength);

  return {
    version,
    payloadType,
    salt,
    iv,
    ciphertext,
    header,
  };
}
