/**
 * Integration Test: End-to-End Crypto + Steganography Engine Round-Trip with AEAD Header Integrity
 */

import { encryptMessage, decryptMessage, getRandomBytes, InvalidPasswordError } from '../js/crypto.js';
import { createHeader, packPayload, embedPayloadInImageData, extractPayloadFromImageData } from '../js/steganography.js';
import { CONFIG } from '../js/config.js';

async function runRoundtripTest() {
  console.log('--- Testing Integrated Crypto + Stego Engine (AEAD & Length Padding) ---');

  const secretMessage = '🚀 SecretPix Confidential Message: Operation Green Mint is GO! \nCoordinates: 37.7749° N, 122.4194° W';
  const password = 'SuperSecretP@ssw0rd!2026';

  // Calculate padded ciphertext length for header AAD
  const plaintextBytes = new TextEncoder().encode(secretMessage);
  const blockSize = CONFIG.CRYPTO.PADDING_BLOCK_SIZE || 64;
  const padLen = blockSize - (plaintextBytes.length % blockSize);
  const paddedLength = plaintextBytes.length + padLen;
  const ciphertextLength = paddedLength + 16; // 128-bit tag

  const salt = getRandomBytes(16);
  const iv = getRandomBytes(12);
  const header = createHeader(salt, iv, ciphertextLength);

  console.log('1. Encrypting message using AES-256-GCM + PBKDF2 (600k rounds) with AEAD Header binding...');
  const { ciphertext } = await encryptMessage(secretMessage, password, { salt, iv, additionalData: header });
  console.log(`   Ciphertext produced: ${ciphertext.length} bytes (padded to multiple of ${blockSize} + 16B tag)`);

  console.log('2. Packing into versioned binary payload...');
  const payload = packPayload(salt, iv, ciphertext);
  console.log(`   Packed binary payload: ${payload.length} bytes (38B header + ${ciphertext.length}B ciphertext)`);

  console.log('3. Generating synthetic 200x200 pixel image...');
  const width = 200;
  const height = 200;
  const pixelData = new Uint8Array(width * height * 4);
  for (let i = 0; i < width * height; i++) {
    pixelData[i * 4 + 0] = (i * 3) % 256;
    pixelData[i * 4 + 1] = (i * 5) % 256;
    pixelData[i * 4 + 2] = (i * 7) % 256;
    pixelData[i * 4 + 3] = 255;
  }
  const imageData = { width, height, data: pixelData };

  console.log('4. Embedding payload bits into RGB LSBs...');
  embedPayloadInImageData(imageData, payload);
  console.log('   Embedding complete.');

  console.log('5. Extracting payload from image pixels...');
  const extracted = extractPayloadFromImageData(imageData);
  console.log(`   Extracted salt: ${extracted.salt.length}B, IV: ${extracted.iv.length}B, Ciphertext: ${extracted.ciphertext.length}B, Header: ${extracted.header.length}B`);

  console.log('6. Decrypting extracted ciphertext with password and verifying AEAD header integrity...');
  const decryptedMessage = await decryptMessage(extracted.ciphertext, extracted.salt, extracted.iv, password, extracted.header);

  if (decryptedMessage === secretMessage) {
    console.log('\n🎉 SUCCESS: Decrypted message matches original secret with 100% fidelity!');
    console.log(`Recovered message:\n"${decryptedMessage}"\n`);
  } else {
    throw new Error('Decrypted message does NOT match original secret!');
  }

  // 7. Verify Header Tampering Rejection
  console.log('7. Verifying Header Tampering Detection (flipping 1 bit in extracted salt)...');
  let headerTamperCaught = false;
  const tamperedSalt = new Uint8Array(extracted.salt);
  tamperedSalt[0] ^= 0x01; // flip 1 bit in salt
  try {
    await decryptMessage(extracted.ciphertext, tamperedSalt, extracted.iv, password, extracted.header);
  } catch (err) {
    if (err instanceof InvalidPasswordError) headerTamperCaught = true;
  }
  if (!headerTamperCaught) {
    throw new Error('Header salt tampering was NOT detected!');
  }
  console.log('   ✅ Header tampering was correctly detected and rejected by AES-GCM AEAD.');
}

runRoundtripTest().catch(err => {
  console.error('Roundtrip failed:', err);
  process.exit(1);
});
