/**
 * SecretPix — Master Application Controller (Phase 6: Web Worker & Security Hardening)
 */

import { switchView, showToast, evaluatePasswordStrength, formatBytes, ICONS } from './ui.js';
import { CONFIG } from './config.js';
import { encryptMessage, decryptMessage, getRandomBytes, InvalidPasswordError } from './crypto.js';
import {
  validateImageFile,
  loadImageElement,
  revokeImageElement,
  extractImageDataFromImage,
  calculateCapacity,
  exportImageDataToPngBlob,
  triggerFileDownload,
} from './image.js';
import {
  createHeader,
  packPayload,
  embedPayloadInImageData,
  extractPayloadFromImageData,
  detectSecretPixHeader,
  NoSecretPixDataError,
  CapacityExceededError,
} from './steganography.js';

// Application State Store (Kept strictly in volatile memory; zero persistence)
const state = {
  hide: {
    file: null,
    imageElement: null,
    imageData: null,
    width: 0,
    height: 0,
    encodedBlob: null,
    modalPreviewUrl: null,
  },
  reveal: {
    file: null,
    imageElement: null,
    imageData: null,
    hasPayload: false,
    recoveredText: '',
  },
};

/* ==========================================================================
   WEB WORKER SERVICE WITH SEAMLESS SYNCHRONOUS FALLBACK
   ========================================================================== */

class StegoWorkerClient {
  constructor() {
    this.worker = null;
    this.initWorker();
  }

  initWorker() {
    try {
      // Attempt to instantiate Web Worker (supported in modern browsers over HTTP/HTTPS)
      this.worker = new Worker('js/worker.js', { type: 'module' });
      console.log('SecretPix: Dedicated Web Worker successfully initialized.');
    } catch (e) {
      console.warn('SecretPix: Web Worker restricted or unavailable (e.g. file:// origin). Using in-thread engine.', e);
      this.worker = null;
    }
  }

  /**
   * Run Encrypt & Embed task
   * @param {{ imageData: ImageData, message: string, password: string }} params
   * @param {(stage: string, percent: number) => void} onProgress
   * @returns {Promise<{ imageData: ImageData }>}
   */
  async encryptAndEmbed(params, onProgress) {
    if (this.worker) {
      return new Promise((resolve, reject) => {
        const handler = (e) => {
          const { status, type, stage, percent, result, error } = e.data;
          if (type && type !== 'ENCRYPT_AND_EMBED') return;

          if (status === 'PROGRESS') {
            if (onProgress) onProgress(stage, percent);
          } else if (status === 'SUCCESS') {
            this.worker.removeEventListener('message', handler);
            resolve(result);
          } else if (status === 'ERROR') {
            this.worker.removeEventListener('message', handler);
            reject(new Error(error.message));
          }
        };

        this.worker.addEventListener('message', handler);
        this.worker.postMessage({
          type: 'ENCRYPT_AND_EMBED',
          payload: params,
        });
      });
    } else {
      // Graceful in-thread execution fallback
      const plaintextBytes = new TextEncoder().encode(params.message);
      const blockSize = CONFIG.CRYPTO.PADDING_BLOCK_SIZE || 64;
      const padLen = blockSize - (plaintextBytes.length % blockSize);
      const paddedLength = plaintextBytes.length + padLen;
      const ciphertextLength = paddedLength + (CONFIG.CRYPTO.TAG_LENGTH_BITS / 8);

      const salt = getRandomBytes(CONFIG.CRYPTO.SALT_LENGTH_BYTES);
      const iv = getRandomBytes(CONFIG.CRYPTO.IV_LENGTH_BYTES);
      const header = createHeader(salt, iv, ciphertextLength);

      if (onProgress) onProgress('Deriving key with PBKDF2 (600k rounds) & encrypting...', 30);
      const { ciphertext } = await encryptMessage(params.message, params.password, { salt, iv, additionalData: header });

      if (onProgress) onProgress('Packing binary steganographic protocol with AEAD integrity...', 60);
      const binaryPayload = packPayload(salt, iv, ciphertext);

      if (onProgress) onProgress('Embedding encrypted bits into image pixels...', 85);
      embedPayloadInImageData(params.imageData, binaryPayload);

      return { imageData: params.imageData };
    }
  }

  /**
   * Run Extract & Decrypt task
   * @param {{ imageData: ImageData, password: string }} params
   * @param {(stage: string, percent: number) => void} onProgress
   * @returns {Promise<{ decryptedText: string }>}
   */
  async extractAndDecrypt(params, onProgress) {
    if (this.worker) {
      return new Promise((resolve, reject) => {
        const handler = (e) => {
          const { status, type, stage, percent, result, error } = e.data;
          if (type && type !== 'EXTRACT_AND_DECRYPT') return;

          if (status === 'PROGRESS') {
            if (onProgress) onProgress(stage, percent);
          } else if (status === 'SUCCESS') {
            this.worker.removeEventListener('message', handler);
            resolve(result);
          } else if (status === 'ERROR') {
            this.worker.removeEventListener('message', handler);
            if (error.code === 'INVALID_PASSWORD') {
              reject(new InvalidPasswordError(error.message));
            } else if (error.code === 'NO_PAYLOAD_DETECTED') {
              reject(new NoSecretPixDataError(error.message));
            } else {
              reject(new Error(error.message));
            }
          }
        };

        this.worker.addEventListener('message', handler);
        this.worker.postMessage({
          type: 'EXTRACT_AND_DECRYPT',
          payload: params,
        });
      });
    } else {
      // Graceful in-thread execution fallback
      if (onProgress) onProgress('Extracting hidden payload from pixels...', 35);
      const { salt, iv, ciphertext, header } = extractPayloadFromImageData(params.imageData);

      if (onProgress) onProgress('Deriving key & verifying AEAD integrity...', 75);
      const decryptedText = await decryptMessage(ciphertext, salt, iv, params.password, header);

      return { decryptedText };
    }
  }
}

const workerClient = new StegoWorkerClient();

/* ==========================================================================
   APPLICATION ENTRY & NAVIGATION
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  console.log(`${CONFIG.APP_NAME} v${CONFIG.VERSION} — Initializing Client.`);

  // Navigation Links
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      const targetView = e.currentTarget.getAttribute('data-view');
      if (targetView) switchView(targetView);
    });
  });

  const logoBtn = document.getElementById('logoBtn');
  if (logoBtn) {
    logoBtn.addEventListener('click', () => switchView('viewDashboard'));
  }

  // Quick Action CTAs
  const heroHideBtn = document.getElementById('heroHideBtn');
  const heroRevealBtn = document.getElementById('heroRevealBtn');
  const cardHide = document.getElementById('cardHide');
  const cardReveal = document.getElementById('cardReveal');

  if (heroHideBtn) heroHideBtn.addEventListener('click', () => switchView('viewHide'));
  if (heroRevealBtn) heroRevealBtn.addEventListener('click', () => switchView('viewReveal'));
  if (cardHide) cardHide.addEventListener('click', () => switchView('viewHide'));
  if (cardReveal) cardReveal.addEventListener('click', () => switchView('viewReveal'));

  // Footer Navigation Link
  const footerAboutLink = document.getElementById('footerAboutLink');
  if (footerAboutLink) {
    footerAboutLink.addEventListener('click', (e) => {
      e.preventDefault();
      switchView('viewAbout');
    });
  }

  // Password Visibility Toggles
  setupPasswordToggle('toggleHidePassword', 'hidePasswordInput');
  setupPasswordToggle('toggleRevealPassword', 'revealPasswordInput');

  // Initialize Workspaces & Settings
  initHideWorkspace();
  initRevealWorkspace();
  initSettingsWorkspace();
  initPwaAndUpdates();
});

/* ==========================================================================
   HIDE MESSAGE WORKSPACE
   ========================================================================== */

function initHideWorkspace() {
  const dropzone = document.getElementById('hideDropzone');
  const fileInput = document.getElementById('hideFileInput');
  const browseBtn = document.getElementById('hideBrowseBtn');
  const previewBox = document.getElementById('hideImagePreviewBox');
  const previewImg = document.getElementById('hideImagePreview');
  const fileNameText = document.getElementById('hideImageFileName');
  const dimensionsText = document.getElementById('hideImageDimensions');
  const removeBtn = document.getElementById('hideRemoveImageBtn');

  if (browseBtn) {
    browseBtn.addEventListener('click', () => fileInput.click());
  }

  const messageInput = document.getElementById('hideMessageInput');
  const charCountLabel = document.getElementById('charCountLabel');
  const passwordInput = document.getElementById('hidePasswordInput');
  const confirmPasswordInput = document.getElementById('hideConfirmPasswordInput');
  const strengthFill = document.getElementById('hideStrengthFill');
  const strengthText = document.getElementById('hideStrengthText');
  const passwordMatchBadge = document.getElementById('passwordMatchBadge');
  const encryptBtn = document.getElementById('encryptAndHideBtn');

  const capacityContainer = document.getElementById('capacityContainer');
  const capacityPercentBadge = document.getElementById('capacityPercentBadge');
  const capacityFill = document.getElementById('capacityFill');
  const capacityUsedText = document.getElementById('capacityUsedText');
  const capacityMaxText = document.getElementById('capacityMaxText');

  // File Upload
  fileInput.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (file) await handleHideImageSelection(file);
    fileInput.value = '';
  });

  setupDropzone(dropzone, async (file) => {
    await handleHideImageSelection(file);
  });

  async function handleHideImageSelection(file) {
    try {
      validateImageFile(file);
      const img = await loadImageElement(file);
      const { imageData, width, height } = extractImageDataFromImage(img);

      // Clean up previous image element object URL if any
      revokeImageElement(state.hide.imageElement);

      state.hide.file = file;
      state.hide.imageElement = img;
      state.hide.imageData = imageData;
      state.hide.width = width;
      state.hide.height = height;

      previewImg.src = img.src;
      fileNameText.textContent = file.name;
      dimensionsText.textContent = `(${width.toLocaleString()} × ${height.toLocaleString()})`;

      dropzone.classList.add('hidden');
      previewBox.classList.remove('hidden');
      capacityContainer.classList.remove('hidden');

      updateHideCapacityAndValidation();
      showToast('Image loaded successfully.', 'info', 2000);
    } catch (err) {
      console.error(err);
      showToast(err.message, 'error', 4500);
    }
  }

  // Remove Image & Scrub State
  removeBtn.addEventListener('click', () => {
    revokeImageElement(state.hide.imageElement);

    if (state.hide.modalPreviewUrl) {
      try { URL.revokeObjectURL(state.hide.modalPreviewUrl); } catch (e) {}
      state.hide.modalPreviewUrl = null;
    }

    state.hide.file = null;
    state.hide.imageElement = null;
    state.hide.imageData = null;
    state.hide.width = 0;
    state.hide.height = 0;
    state.hide.encodedBlob = null;

    previewImg.src = '';
    previewBox.classList.add('hidden');
    capacityContainer.classList.add('hidden');
    dropzone.classList.remove('hidden');

    updateHideCapacityAndValidation();
  });

  // Inputs
  messageInput.addEventListener('input', () => {
    const length = messageInput.value.length;
    charCountLabel.textContent = `${length.toLocaleString()} chars`;
    updateHideCapacityAndValidation();
  });

  passwordInput.addEventListener('input', () => {
    const val = passwordInput.value;
    const strength = evaluatePasswordStrength(val);
    strengthFill.className = `strength-fill ${strength.className}`;
    strengthText.textContent = val ? `Password strength: ${strength.label}` : 'Password strength';
    checkPasswordsMatch();
    updateHideCapacityAndValidation();
  });

  confirmPasswordInput.addEventListener('input', () => {
    checkPasswordsMatch();
    updateHideCapacityAndValidation();
  });

  const MIN_PASSWORD_LENGTH = CONFIG.CRYPTO.MIN_PASSWORD_LENGTH || 8;

  function checkPasswordsMatch() {
    const pwd = passwordInput.value;
    const confirm = confirmPasswordInput.value;
    if (!confirm && !pwd) {
      passwordMatchBadge.textContent = '';
      return false;
    }
    if (pwd.length < MIN_PASSWORD_LENGTH) {
      passwordMatchBadge.textContent = `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
      passwordMatchBadge.style.color = 'var(--color-error)';
      return false;
    }
    if (!confirm) {
      passwordMatchBadge.textContent = '';
      return false;
    }
    if (pwd === confirm) {
      passwordMatchBadge.textContent = 'Passwords match';
      passwordMatchBadge.style.color = 'var(--color-success)';
      return true;
    } else {
      passwordMatchBadge.textContent = 'Passwords do not match';
      passwordMatchBadge.style.color = 'var(--color-error)';
      return false;
    }
  }

  function updateHideCapacityAndValidation() {
    const hasImage = !!state.hide.imageData;
    const message = messageInput.value.trim();
    const password = passwordInput.value;
    const confirm = confirmPasswordInput.value;
    const passwordsMatch = password.length >= MIN_PASSWORD_LENGTH && password === confirm;

    if (hasImage) {
      const textBytesLength = new TextEncoder().encode(message).length;
      const blockSize = CONFIG.CRYPTO.PADDING_BLOCK_SIZE || 64;
      const padLen = textBytesLength > 0 ? (blockSize - (textBytesLength % blockSize)) : 0;
      const paddedBytesLength = textBytesLength + padLen;
      const estimatedPayloadBytes = message.length > 0 ? paddedBytesLength + CONFIG.PROTOCOL.TOTAL_OVERHEAD_BYTES : 0;
      const capacity = calculateCapacity(state.hide.width, state.hide.height, estimatedPayloadBytes);

      const visualPercent = Math.min(100, Math.max(0, capacity.usagePercentage));
      capacityFill.style.width = `${visualPercent}%`;
      capacityPercentBadge.textContent = `${capacity.usagePercentage}%`;
      capacityUsedText.textContent = `Payload: ${formatBytes(capacity.usedBytes)}`;
      capacityMaxText.textContent = `Available: ${formatBytes(capacity.usableCapacityBytes)}`;

      if (capacity.isOverCapacity) {
        capacityFill.className = 'capacity-fill danger';
        capacityPercentBadge.className = 'badge badge-error font-mono';
      } else if (capacity.usagePercentage > 75) {
        capacityFill.className = 'capacity-fill warning';
        capacityPercentBadge.className = 'badge badge-pistachio font-mono';
      } else {
        capacityFill.className = 'capacity-fill';
        capacityPercentBadge.className = 'badge badge-mint font-mono';
      }

      const isValid = hasImage && message.length > 0 && passwordsMatch && !capacity.isOverCapacity;
      encryptBtn.disabled = !isValid;
    } else {
      encryptBtn.disabled = true;
    }
  }

  // Encrypt & Hide Button
  encryptBtn.addEventListener('click', async () => {
    const message = messageInput.value.trim();
    const password = passwordInput.value;

    if (!state.hide.imageData || !message || !password) return;

    encryptBtn.disabled = true;
    const originalBtnContent = encryptBtn.innerHTML;

    try {
      // 1. Fresh pixel extraction from original cover image
      const { imageData } = extractImageDataFromImage(state.hide.imageElement);

      // 2. Execute via Worker (or graceful synchronous fallback) with live stage telemetry
      const { imageData: encodedImageData } = await workerClient.encryptAndEmbed(
        { imageData, message, password },
        (stage) => {
          encryptBtn.innerHTML = `<span class="spinner spinner-primary" style="margin-right: 8px;"></span> ${stage}`;
        }
      );

      // 3. Export PNG
      encryptBtn.innerHTML = `<span class="spinner spinner-primary" style="margin-right: 8px;"></span> Generating PNG image...`;
      const pngBlob = await exportImageDataToPngBlob(encodedImageData);
      state.hide.encodedBlob = pngBlob;

      // 4. Show Success Modal (revoke previous modal preview URL if existing)
      if (state.hide.modalPreviewUrl) {
        try { URL.revokeObjectURL(state.hide.modalPreviewUrl); } catch (e) {}
        state.hide.modalPreviewUrl = null;
      }
      state.hide.modalPreviewUrl = URL.createObjectURL(pngBlob);

      const modal = document.getElementById('encodeSuccessModal');
      const modalPreview = document.getElementById('modalSuccessPreview');
      modalPreview.src = state.hide.modalPreviewUrl;
      modal.classList.add('active');

      showToast('Image successfully encrypted and embedded!', 'success', 3500);
    } catch (err) {
      console.error(err);
      showToast(`Encoding failed: ${err.message}`, 'error', 5000);
    } finally {
      encryptBtn.disabled = false;
      encryptBtn.innerHTML = originalBtnContent;
      updateHideCapacityAndValidation();
    }
  });

  // Modal Download Button
  const downloadBtn = document.getElementById('downloadEncodedImageBtn');
  if (downloadBtn) {
    downloadBtn.addEventListener('click', () => {
      if (state.hide.encodedBlob) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        triggerFileDownload(state.hide.encodedBlob, `secretpix-${timestamp}.png`);
        showToast('PNG image downloaded.', 'success', 2500);
      }
    });
  }

  // Modal Close ("Done") Button & Click Outside
  const closeSuccessModalBtn = document.getElementById('closeSuccessModalBtn');
  const encodeSuccessModal = document.getElementById('encodeSuccessModal');
  if (closeSuccessModalBtn && encodeSuccessModal) {
    closeSuccessModalBtn.addEventListener('click', () => {
      encodeSuccessModal.classList.remove('active');
      if (state.hide.modalPreviewUrl) {
        try { URL.revokeObjectURL(state.hide.modalPreviewUrl); } catch (e) {}
        state.hide.modalPreviewUrl = null;
      }
    });
  }
}

/* ==========================================================================
   REVEAL MESSAGE WORKSPACE
   ========================================================================== */

function initRevealWorkspace() {
  const dropzone = document.getElementById('revealDropzone');
  const fileInput = document.getElementById('revealFileInput');
  const browseBtn = document.getElementById('revealBrowseBtn');
  const previewBox = document.getElementById('revealImagePreviewBox');
  const previewImg = document.getElementById('revealImagePreview');
  const fileNameText = document.getElementById('revealImageFileName');
  const removeBtn = document.getElementById('revealRemoveImageBtn');

  if (browseBtn) {
    browseBtn.addEventListener('click', () => fileInput.click());
  }

  const detectionBadge = document.getElementById('revealDetectionBadge');
  const detectionIcon = document.getElementById('revealDetectionIcon');
  const detectionTitle = document.getElementById('revealDetectionTitle');
  const detectionDesc = document.getElementById('revealDetectionDesc');

  const passwordInput = document.getElementById('revealPasswordInput');
  const decryptBtn = document.getElementById('decryptBtn');

  const recoveredBox = document.getElementById('recoveredMessageBox');
  const recoveredText = document.getElementById('recoveredMessageText');
  const copyBtn = document.getElementById('copyRecoveredBtn');
  const clearBtn = document.getElementById('clearRecoveredBtn');

  fileInput.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (file) await handleRevealImageSelection(file);
    fileInput.value = '';
  });

  setupDropzone(dropzone, async (file) => {
    await handleRevealImageSelection(file);
  });

  async function handleRevealImageSelection(file) {
    try {
      validateImageFile(file);
      const img = await loadImageElement(file);
      const { imageData } = extractImageDataFromImage(img);

      // Clean up previous image element object URL if any
      revokeImageElement(state.reveal.imageElement);

      state.reveal.file = file;
      state.reveal.imageElement = img;
      state.reveal.imageData = imageData;

      previewImg.src = img.src;
      fileNameText.textContent = file.name;

      dropzone.classList.add('hidden');
      previewBox.classList.remove('hidden');

      // Fast Header Detection Scan
      const hasHeader = detectSecretPixHeader(imageData);
      state.reveal.hasPayload = hasHeader;

      detectionBadge.style.display = 'block';
      if (hasHeader) {
        detectionBadge.className = 'card card-mint';
        detectionIcon.innerHTML = `<span style="color: var(--color-primary);">${ICONS.CHECK}</span>`;
        detectionTitle.textContent = 'SecretPix Encrypted Payload Detected';
        detectionDesc.textContent = 'Valid SecretPix identifier found. Enter your password to decrypt.';
        decryptBtn.disabled = !passwordInput.value.trim();
        showToast('SecretPix encrypted payload detected!', 'info', 3000);
      } else {
        detectionBadge.className = 'card card-surface';
        detectionIcon.innerHTML = `<span style="color: var(--color-error);">${ICONS.ALERT}</span>`;
        detectionTitle.textContent = 'No SecretPix Payload Detected';
        detectionDesc.textContent = 'This image does not contain a SecretPix payload or was re-compressed by another service.';
        decryptBtn.disabled = true;
      }
    } catch (err) {
      console.error(err);
      showToast(err.message, 'error', 4500);
    }
  }

  // Remove Image & Scrub State
  removeBtn.addEventListener('click', () => {
    revokeImageElement(state.reveal.imageElement);

    state.reveal.file = null;
    state.reveal.imageElement = null;
    state.reveal.imageData = null;
    state.reveal.hasPayload = false;
    state.reveal.recoveredText = '';

    previewImg.src = '';
    previewBox.classList.add('hidden');
    dropzone.classList.remove('hidden');
    detectionBadge.style.display = 'none';
    recoveredBox.classList.add('hidden');
    recoveredText.textContent = '';
    passwordInput.value = '';
    decryptBtn.disabled = true;
  });

  passwordInput.addEventListener('input', () => {
    const hasPassword = passwordInput.value.trim().length > 0;
    decryptBtn.disabled = !(state.reveal.hasPayload && hasPassword);
  });

  // Decrypt Button
  decryptBtn.addEventListener('click', async () => {
    const password = passwordInput.value;
    if (!state.reveal.imageData || !password) return;

    decryptBtn.disabled = true;
    const originalBtnContent = decryptBtn.innerHTML;

    try {
      // Execute decryption through WorkerClient (or fallback) with stage feedback
      const { decryptedText } = await workerClient.extractAndDecrypt(
        { imageData: state.reveal.imageData, password },
        (stage) => {
          decryptBtn.innerHTML = `<span class="spinner spinner-primary" style="margin-right: 8px;"></span> ${stage}`;
        }
      );

      // Render recovered text strictly as plain text (XSS defense)
      state.reveal.recoveredText = decryptedText;
      recoveredText.textContent = decryptedText;
      recoveredBox.classList.remove('hidden');

      showToast('Message decrypted successfully!', 'success', 3500);
    } catch (err) {
      console.error(err);
      if (err instanceof InvalidPasswordError) {
        showToast('Decryption failed: Incorrect password or damaged payload.', 'error', 5000);
      } else if (err instanceof NoSecretPixDataError) {
        showToast('No valid SecretPix payload found in this image.', 'error', 5000);
      } else {
        showToast(`Decryption error: ${err.message}`, 'error', 5000);
      }
    } finally {
      decryptBtn.disabled = false;
      decryptBtn.innerHTML = originalBtnContent;
    }
  });

  // Copy Message to Clipboard
  copyBtn.addEventListener('click', async () => {
    if (!state.reveal.recoveredText) return;
    try {
      await navigator.clipboard.writeText(state.reveal.recoveredText);
      showToast('Message copied to clipboard!', 'success', 2500);
    } catch (err) {
      const textarea = document.createElement('textarea');
      textarea.value = state.reveal.recoveredText;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      showToast('Message copied to clipboard!', 'success', 2500);
    }
  });

  // Clear Message & Scrub Memory
  clearBtn.addEventListener('click', () => {
    state.reveal.recoveredText = '';
    recoveredText.textContent = '';
    recoveredBox.classList.add('hidden');
    passwordInput.value = '';
    decryptBtn.disabled = true;
    showToast('Decrypted message cleared from memory.', 'info', 2000);
  });
}

/* ==========================================================================
   UI UTILITY BINDINGS
   ========================================================================== */

function setupPasswordToggle(btnId, inputId) {
  const btn = document.getElementById(btnId);
  const input = document.getElementById(inputId);
  if (!btn || !input) return;

  btn.addEventListener('click', () => {
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    btn.innerHTML = isPassword ? ICONS.EYE_OFF : ICONS.EYE;
  });
}

function setupDropzone(dropzone, onFileSelected) {
  if (!dropzone) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      onFileSelected(files[0]);
    }
  });
}

/* ==========================================================================
   SETTINGS WORKSPACE & DIAGNOSTICS
   ========================================================================== */

function initSettingsWorkspace() {
  const purgeBtn = document.getElementById('purgeMemoryBtn');
  if (purgeBtn) {
    purgeBtn.addEventListener('click', () => {
      // 1. Revoke loaded images
      revokeImageElement(state.hide.imageElement);
      revokeImageElement(state.reveal.imageElement);
      if (state.hide.modalPreviewUrl) {
        try { URL.revokeObjectURL(state.hide.modalPreviewUrl); } catch (e) {}
      }

      // 2. Wipe memory states
      state.hide = {
        file: null,
        imageElement: null,
        imageData: null,
        width: 0,
        height: 0,
        encodedBlob: null,
        modalPreviewUrl: null,
      };
      state.reveal = {
        file: null,
        imageElement: null,
        imageData: null,
        hasPayload: false,
        recoveredText: '',
      };

      // 3. Clear DOM inputs
      const hideMessageInput = document.getElementById('hideMessageInput');
      const hidePasswordInput = document.getElementById('hidePasswordInput');
      const hideConfirmPasswordInput = document.getElementById('hideConfirmPasswordInput');
      const revealPasswordInput = document.getElementById('revealPasswordInput');

      if (hideMessageInput) hideMessageInput.value = '';
      if (hidePasswordInput) hidePasswordInput.value = '';
      if (hideConfirmPasswordInput) hideConfirmPasswordInput.value = '';
      if (revealPasswordInput) revealPasswordInput.value = '';

      // 4. Reset UI displays
      const hidePreviewBox = document.getElementById('hideImagePreviewBox');
      const hideDropzone = document.getElementById('hideDropzone');
      const capacityContainer = document.getElementById('capacityContainer');
      const revealPreviewBox = document.getElementById('revealImagePreviewBox');
      const revealDropzone = document.getElementById('revealDropzone');
      const revealDetectionBadge = document.getElementById('revealDetectionBadge');
      const recoveredBox = document.getElementById('recoveredMessageBox');

      if (hidePreviewBox) hidePreviewBox.classList.add('hidden');
      if (hideDropzone) hideDropzone.classList.remove('hidden');
      if (capacityContainer) capacityContainer.classList.add('hidden');
      if (revealPreviewBox) revealPreviewBox.classList.add('hidden');
      if (revealDropzone) revealDropzone.classList.remove('hidden');
      if (revealDetectionBadge) revealDetectionBadge.style.display = 'none';
      if (recoveredBox) recoveredBox.classList.add('hidden');

      showToast('All volatile memory and image buffers have been purged.', 'success', 3500);
    });
  }

  // Diagnostics check
  const diagCrypto = document.getElementById('diagCrypto');
  const diagCanvas = document.getElementById('diagCanvas');
  const diagWorker = document.getElementById('diagWorker');

  if (diagCrypto) {
    const hasCrypto = typeof window !== 'undefined' && window.crypto && window.crypto.subtle;
    diagCrypto.textContent = hasCrypto ? 'Active (AES-GCM/PBKDF2) ✅' : 'Unavailable ❌';
    diagCrypto.style.color = hasCrypto ? 'var(--color-success)' : 'var(--color-error)';
  }

  if (diagCanvas) {
    const hasCanvas = typeof document !== 'undefined' && !!document.createElement('canvas').getContext;
    diagCanvas.textContent = hasCanvas ? 'Active (ImageData 2D) ✅' : 'Unavailable ❌';
    diagCanvas.style.color = hasCanvas ? 'var(--color-success)' : 'var(--color-error)';
  }

  if (diagWorker) {
    const hasWorker = typeof Worker !== 'undefined';
    diagWorker.textContent = hasWorker ? 'Active (Dedicated Background) ✅' : 'Fallback Mode ⚠️';
    diagWorker.style.color = hasWorker ? 'var(--color-success)' : 'var(--color-warning)';
  }
}

/* ==========================================================================
   PWA & AUTO-UPDATE LIFECYCLE MANAGEMENT
   ========================================================================== */

let deferredInstallPrompt = null;
let swRegistration = null;

function initPwaAndUpdates() {
  const diagSW = document.getElementById('diagSW');
  const checkUpdatesBtn = document.getElementById('checkUpdatesBtn');
  const lastUpdateCheckText = document.getElementById('lastUpdateCheckText');
  const updateBanner = document.getElementById('updateBanner');
  const updateNowBtn = document.getElementById('updateNowBtn');
  const dismissUpdateBtn = document.getElementById('dismissUpdateBtn');
  const installPwaBtn = document.getElementById('installPwaBtn');
  const settingsInstallDesc = document.getElementById('settingsInstallDesc');

  // 1. Online / Offline Real-time Monitoring
  function updateNetworkStatus() {
    const isOnline = navigator.onLine;
    const headerBadge = document.getElementById('networkStatusBadge');
    const settingsBadge = document.getElementById('settingsNetworkBadge');

    const badgeHtml = isOnline
      ? `<span style="display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--color-success); margin-right:4px;"></span> Online`
      : `<span style="display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--color-warning); margin-right:4px;"></span> Air-Gapped (Offline)`;

    const badgeClass = isOnline ? 'badge badge-mint' : 'badge badge-pistachio';

    if (headerBadge) {
      headerBadge.innerHTML = badgeHtml;
      headerBadge.className = badgeClass;
    }
    if (settingsBadge) {
      settingsBadge.innerHTML = badgeHtml;
      settingsBadge.className = badgeClass;
    }
  }

  window.addEventListener('online', () => {
    updateNetworkStatus();
    showToast('Internet restored. Checking for SecretPix updates...', 'info', 3000);
    checkForServiceWorkerUpdates(false);
  });

  window.addEventListener('offline', () => {
    updateNetworkStatus();
    showToast('Air-gapped mode active: SecretPix is completely offline.', 'info', 4000);
  });

  updateNetworkStatus();

  // 2. Capture PWA Installation Prompt
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredInstallPrompt = e;

    if (installPwaBtn) {
      installPwaBtn.disabled = false;
      installPwaBtn.classList.remove('btn-secondary');
      installPwaBtn.classList.add('btn-primary');
    }
    if (settingsInstallDesc) {
      settingsInstallDesc.textContent = 'Ready to install as standalone desktop/mobile app';
    }
  });

  if (installPwaBtn) {
    installPwaBtn.addEventListener('click', async () => {
      if (!deferredInstallPrompt) return;
      deferredInstallPrompt.prompt();
      const choiceResult = await deferredInstallPrompt.userChoice;
      if (choiceResult.outcome === 'accepted') {
        showToast('SecretPix installation confirmed!', 'success', 3000);
        installPwaBtn.disabled = true;
        installPwaBtn.textContent = 'Installed ✅';
      }
      deferredInstallPrompt = null;
    });
  }

  window.addEventListener('appinstalled', () => {
    if (settingsInstallDesc) settingsInstallDesc.textContent = 'Installed as standalone desktop/mobile app ✅';
    if (installPwaBtn) {
      installPwaBtn.disabled = true;
      installPwaBtn.textContent = 'Installed ✅';
    }
    showToast('SecretPix successfully installed as a PWA!', 'success', 3500);
  });

  // Check if already running in standalone display mode
  if (window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true) {
    if (settingsInstallDesc) settingsInstallDesc.textContent = 'Running in standalone native window ✅';
    if (installPwaBtn) {
      installPwaBtn.disabled = true;
      installPwaBtn.textContent = 'Installed ✅';
    }
  }

  // 3. Register Service Worker (over HTTP/HTTPS)
  if ('serviceWorker' in navigator && (window.location.protocol.startsWith('http') || window.location.hostname === 'localhost')) {
    navigator.serviceWorker.register('./sw.js')
      .then((registration) => {
        swRegistration = registration;
        if (diagSW) {
          diagSW.textContent = 'Active (Offline Ready) ✅';
          diagSW.style.color = 'var(--color-success)';
        }

        // Listen for new worker versions installing
        registration.addEventListener('updatefound', () => {
          const installingWorker = registration.installing;
          if (!installingWorker) return;

          installingWorker.addEventListener('statechange', () => {
            if (installingWorker.state === 'installed' && navigator.serviceWorker.controller) {
              // A new version has been found and cached!
              promptUserForUpdate();
            }
          });
        });

        // Periodic check when tab is focused
        document.addEventListener('visibilitychange', () => {
          if (document.visibilityState === 'visible' && navigator.onLine) {
            registration.update().catch(() => {});
          }
        });
      })
      .catch((err) => {
        console.warn('SecretPix: Service worker registration error:', err);
        if (diagSW) {
          diagSW.textContent = 'Unavailable ⚠️';
          diagSW.style.color = 'var(--color-warning)';
        }
      });

    // Reload page once new controller activates
    let refreshing = false;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (!refreshing) {
        refreshing = true;
        window.location.reload();
      }
    });
  } else {
    if (diagSW) {
      diagSW.textContent = 'Inactive (file:// origin) ⚠️';
      diagSW.style.color = 'var(--color-warning)';
    }
  }

  // 4. Update Notifications & Actions
  function promptUserForUpdate() {
    if (updateBanner) updateBanner.style.display = 'flex';
    showToast('A new update is available! Click Update Now to refresh.', 'info', 6000);
  }

  if (updateNowBtn) {
    updateNowBtn.addEventListener('click', () => {
      if (swRegistration && swRegistration.waiting) {
        swRegistration.waiting.postMessage({ type: 'SKIP_WAITING' });
      } else {
        window.location.reload();
      }
    });
  }

  if (dismissUpdateBtn) {
    dismissUpdateBtn.addEventListener('click', () => {
      if (updateBanner) updateBanner.style.display = 'none';
    });
  }

  // 5. Manual Check for Updates Button on Settings Page
  async function checkForServiceWorkerUpdates(isManual = true) {
    if (!swRegistration) {
      if (isManual) showToast('Service worker is not active in this environment.', 'info', 3000);
      return;
    }

    if (!navigator.onLine) {
      if (isManual) showToast('Cannot check for updates: device is offline.', 'error', 3000);
      return;
    }

    if (checkUpdatesBtn && isManual) {
      checkUpdatesBtn.disabled = true;
      checkUpdatesBtn.innerHTML = `<span class="spinner spinner-primary" style="margin-right: 6px;"></span> Checking...`;
    }

    try {
      await swRegistration.update();
      const timestamp = new Date().toLocaleTimeString();
      if (lastUpdateCheckText) {
        lastUpdateCheckText.textContent = `Last checked at ${timestamp} (Online)`;
      }

      if (swRegistration.waiting) {
        promptUserForUpdate();
      } else if (isManual) {
        showToast('SecretPix is up to date! (v' + CONFIG.VERSION + ')', 'success', 3000);
      }
    } catch (err) {
      console.warn('Update check failed:', err);
      if (isManual) showToast('Update check failed: ' + err.message, 'error', 3000);
    } finally {
      if (checkUpdatesBtn && isManual) {
        checkUpdatesBtn.disabled = false;
        checkUpdatesBtn.innerHTML = `
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
          Check Updates
        `;
      }
    }
  }

  if (checkUpdatesBtn) {
    checkUpdatesBtn.addEventListener('click', () => checkForServiceWorkerUpdates(true));
  }
}
