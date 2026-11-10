/**
 * Unit Test Suite for SecretPix Cryptographic Engine
 */

import { encryptMessage, decryptMessage, getRandomBytes, padBytes, unpadBytes, InvalidPasswordError, CryptoError } from '../js/crypto.js';
import { CONFIG } from '../js/config.js';

async function runTests() {
  console.log('--- Starting SecretPix Crypto Engine Tests ---');
  let passed = 0;
  let total = 0;

  function assert(condition, message) {
    total++;
    if (!condition) {
      console.error(`❌ FAILED: ${message}`);
      throw new Error(message);
    } else {
      passed++;
      console.log(`✅ PASSED: ${message}`);
    }
  }

  // Test 1: CSPRNG generation
  console.log('\n[Test 1] Random Bytes Generation');
  const salt1 = getRandomBytes(16);
  const salt2 = getRandomBytes(16);
  assert(salt1.length === 16, 'Salt 1 is 16 bytes');
  assert(salt2.length === 16, 'Salt 2 is 16 bytes');
  assert(salt1.some((b, i) => b !== salt2[i]), 'Successive salts are distinct random bytes');

  // Test 2: Basic Encryption & Decryption Round-Trip
  console.log('\n[Test 2] Encryption & Decryption Round-Trip (ASCII)');
  const secretText = 'This is a top-secret message for testing SecretPix!';
  const password = 'CorrectHorseBatteryStaple123!';

  // For testing speed, we use the standard 600k iterations or test with default
  console.log('Deriving key and encrypting (600,000 PBKDF2 rounds)...');
  const encResult = await encryptMessage(secretText, password);
  assert(encResult.ciphertext instanceof Uint8Array, 'Ciphertext is Uint8Array');
  assert(encResult.salt.length === 16, 'Salt is 16 bytes');
  assert(encResult.iv.length === 12, 'IV is 12 bytes');
  assert(encResult.ciphertext.length > secretText.length, 'Ciphertext includes 128-bit authentication tag');

  console.log('Decrypting with correct password...');
  const decrypted = await decryptMessage(encResult.ciphertext, encResult.salt, encResult.iv, password);
  assert(decrypted === secretText, 'Decrypted text exactly matches original secret');

  // Test 3: Uniqueness of Salt and IV across repeated encryptions
  console.log('\n[Test 3] Encryption Nonce/Salt Freshness');
  const encResult2 = await encryptMessage(secretText, password);
  assert(encResult.salt.some((b, i) => b !== encResult2.salt[i]), 'Different encryption produces different salt');
  assert(encResult.iv.some((b, i) => b !== encResult2.iv[i]), 'Different encryption produces different IV');
  assert(encResult.ciphertext.some((b, i) => b !== encResult2.ciphertext[i]), 'Different encryption produces different ciphertext');

  // Test 4: Unicode, Emojis, Punctuation and Multiline Text
  console.log('\n[Test 4] Unicode and Multiline Text');
  const unicodeText = '🔒 SecretPix: 秘密メッセージ! Äpfel & café — \nLine 2 with emojis: 🌟🚀🛡️';
  const encUnicode = await encryptMessage(unicodeText, 'MasterP@ssw0rd!');
  const decUnicode = await decryptMessage(encUnicode.ciphertext, encUnicode.salt, encUnicode.iv, 'MasterP@ssw0rd!');
  assert(decUnicode === unicodeText, 'Decrypted Unicode and emojis match perfectly');

  // Test 5: Rejection of Incorrect Password
  console.log('\n[Test 5] Rejection of Incorrect Password');
  let rejected = false;
  try {
    await decryptMessage(encResult.ciphertext, encResult.salt, encResult.iv, 'WrongPassword456!');
  } catch (err) {
    if (err instanceof InvalidPasswordError) {
      rejected = true;
    }
  }
  assert(rejected, 'Incorrect password throws InvalidPasswordError');

  // Test 6: Tampering Detection (Authentication Tag Verification)
  console.log('\n[Test 6] Ciphertext Tampering Detection');
  let tamperDetected = false;
  const tamperedCiphertext = new Uint8Array(encResult.ciphertext);
  tamperedCiphertext[0] ^= 0x01; // flip 1 bit

  try {
    await decryptMessage(tamperedCiphertext, encResult.salt, encResult.iv, password);
  } catch (err) {
    if (err instanceof InvalidPasswordError) {
      tamperDetected = true;
    }
  }
  assert(tamperDetected, 'Flipping a single ciphertext bit triggers GCM authentication failure');

  // Test 7: Validation against empty inputs
  console.log('\n[Test 7] Input Validation');
  let emptyRejected = false;
  try {
    await encryptMessage('', password);
  } catch (err) {
    if (err instanceof CryptoError) emptyRejected = true;
  }
  assert(emptyRejected, 'Empty plaintext throws CryptoError');

  // Test 8: PKCS#7 Length Padding
  console.log('\n[Test 8] PKCS#7 Length Padding & Unpadding');
  const shortBytes = new Uint8Array([65, 66, 67]); // 3 bytes
  const padded = padBytes(shortBytes, 64);
  assert(padded.length === 64, 'Padded length aligns to 64 bytes');
  assert(padded[63] === 61, 'Pad length value is 61');
  const unpadded = unpadBytes(padded, 64);
  assert(unpadded.length === 3 && unpadded[0] === 65 && unpadded[1] === 66 && unpadded[2] === 67, 'Unpadded matches original');

  // Test 9: AEAD Associated Data (Header Tampering Detection)
  console.log('\n[Test 9] AEAD Header Integrity Binding');
  const mockHeader = new Uint8Array([0x53, 0x50, 0x49, 0x58, 0x01, 0x01]);
  const encAead = await encryptMessage('AEAD Test Message', 'TestPassword123!', { additionalData: mockHeader });
  const decAead = await decryptMessage(encAead.ciphertext, encAead.salt, encAead.iv, 'TestPassword123!', mockHeader);
  assert(decAead === 'AEAD Test Message', 'AEAD roundtrip succeeds with matching additionalData');

  let aeadTamperDetected = false;
  const tamperedHeader = new Uint8Array(mockHeader);
  tamperedHeader[0] ^= 0x01; // flip 1 bit in header
  try {
    await decryptMessage(encAead.ciphertext, encAead.salt, encAead.iv, 'TestPassword123!', tamperedHeader);
  } catch (err) {
    if (err instanceof InvalidPasswordError) aeadTamperDetected = true;
  }
  assert(aeadTamperDetected, 'Tampering with even 1 bit of header AAD triggers GCM authentication failure');

  console.log(`\n========================================`);
  console.log(`All ${passed}/${total} Crypto Engine tests PASSED successfully!`);
  console.log(`========================================\n`);
}

runTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
