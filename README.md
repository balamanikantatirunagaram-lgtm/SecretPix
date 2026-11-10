# SecretPix — Hide in Plain Sight

> **A privacy-first client-side image steganography and encryption web application.**  
> Built strictly using standard web technologies: **Pure HTML5, CSS3, and Modern JavaScript (ES6 Modules)** with **zero dependencies** and **zero build tools**.

---

## 🔒 Security Architecture

SecretPix combines military-grade authenticated encryption with pixel-level steganography to conceal private messages inside ordinary images:

```
+-----------------------------------------------------------------------------------------+
|                                    SecretPix Pipeline                                   |
|                                                                                         |
|  [Plaintext Message]                                                                    |
|           │                                                                             |
|           ▼                                                                             |
|  [PBKDF2 Key Derivation]  ◄── Password + 16-byte Random Salt (SHA-256, 600,000 rounds)  |
|           │                                                                             |
|           ▼                                                                             |
|  [AES-256-GCM Encryption] ◄── 12-byte Unique IV + 128-bit Authentication Tag            |
|           │                                                                             |
|           ▼                                                                             |
|  [Binary Protocol Packing] (SPIX Header + Version + Salt + IV + Length + Ciphertext)     |
|           │                                                                             |
|           ▼                                                                             |
|  [LSB Pixel Embedding]    ──► RGB Channels Modified (Alpha Channel 100% Preserved)      |
|           │                                                                             |
|           ▼                                                                             |
|  [Lossless PNG Export]    ──► Downloadable Encrypted Image                             |
+-----------------------------------------------------------------------------------------+
```

### 1. Cryptography
* **Algorithm:** AES-256-GCM (Galois/Counter Mode) with 128-bit authentication tags.
* **Key Derivation:** PBKDF2 using SHA-256 and **600,000 iterations** (strictly aligning with NIST SP 800-63B).
* **Salt & Nonce:** Fresh 16-byte random salt and 12-byte initialization vector (IV) generated for every single encryption using `crypto.getRandomValues()`. Zero IV reuse.
* **Integrity Guarantee:** Any alteration to the ciphertext or pixel data triggers an immediate authentication rejection.

### 2. Steganography Engine
* **Technique:** Least Significant Bit (LSB) substitution across Red, Green, and Blue color channels.
* **Alpha Channel Protection:** The Alpha channel (`data[i * 4 + 3]`) remains 100% unaltered, preventing transparency visual artifacts.
* **Capacity Formula:**
  $$\text{Raw Bytes} = \lfloor (\text{width} \times \text{height} \times 3) / 8 \rfloor$$
  $$\text{Usable Capacity} = \text{Raw Bytes} - 54 \text{ bytes overhead}$$
* **Lossless PNG Export:** Always exported strictly as uncompressed PNG to prevent lossy compression algorithms from destroying embedded bits.

### 3. Binary Packet Layout
```
[0..3]   : Magic Identifier (4 bytes: 'S','P','I','X' -> 0x53, 0x50, 0x49, 0x58)
[4]      : Version (1 byte: 0x01)
[5]      : Payload Type (1 byte: 0x01 = TEXT, 0x02 = FILE)
[6..21]  : Salt (16 bytes: PBKDF2 random salt)
[22..33] : IV (12 bytes: AES-GCM random initialization vector)
[34..37] : Length (4 bytes: Uint32 Big-Endian ciphertext size)
[38..N]  : Ciphertext + Auth Tag (Variable size)
```

---

## 📱 Progressive Web App (PWA) & Offline Air-Gapping

SecretPix is a fully-featured **Progressive Web App (PWA)**:
* **True Air-Gapped Mode:** Automatically pre-caches all code and assets via [`sw.js`](sw.js). Once loaded or installed, you can disconnect from Wi-Fi/Internet entirely and SecretPix remains 100% functional.
* **Installable:** Install as a standalone native-like desktop app (macOS, Windows, Linux) or mobile app (iOS, Android) via the "Install App" button in Settings or browser prompt.
* **Auto-Update Detection:** When online, the service worker checks for updates in the background. A notification banner alerts you when a new release is available with a 1-click "Update Now" action.
* **Settings & Diagnostics Page:** Includes real-time internet connectivity indicators, runtime hardware diagnostics (Web Crypto, Canvas, Worker, Service Worker), and an **Emergency Memory Purge** button to immediately scrub volatile memory.

---

## 🎨 Design System

SecretPix features a premium, minimalist mint, sage, and pistachio color scheme:

| Token | Hex Value | Role |
|---|---|---|
| Primary | `#52796F` | Brand primary, action buttons, active states |
| Primary Dark | `#354F46` | Button hover states, dark text contrast |
| Secondary | `#84A98C` | Secondary accents, borders |
| Mint | `#CADFD1` | Badges, card backgrounds, subtle pills |
| Pistachio | `#DCE8C8` | Information banners, feature highlights |
| Background | `#F7F9F6` | Main application background |
| Surface | `#FFFFFF` | Card containers, dropzones, inputs |
| Text | `#202923` | Charcoal primary typography |

---

## 🚀 Quick Start & Running Locally

Because SecretPix has **zero dependencies** and requires **no compilation**, you can run it immediately using any local web server:

### Option 1: Python HTTP Server (Recommended)
```bash
python3 -m http.server 8000
```
Then open `http://localhost:8000` in your web browser.

### Option 2: Node.js (npx serve)
```bash
npx serve .
```

### Option 3: Double-Click Directly
You can also open `index.html` directly in your browser. SecretPix includes an automatic fallback that switches from Web Workers to an in-thread engine when running under the `file://` protocol.

---

## 🧪 Testing & Automated Verification

### 1. In-Browser Test Suite
Open `test.html` in your browser (or visit `http://localhost:8000/test.html`) to execute the interactive 10-point test runner:
* ✅ CSPRNG Salt & IV generation
* ✅ AES-256-GCM + PBKDF2 (600,000 iterations) round-trip
* ✅ Wrong password authentication failure
* ✅ Single-bit tampering detection
* ✅ Multi-byte Unicode, accents, Asian characters, and emojis
* ✅ Capacity calculation accuracy (Full HD 1080p, boundary limits)
* ✅ Binary protocol serialization & deserialization
* ✅ LSB embedding & Alpha channel immutability
* ✅ Fast header detection scanner
* ✅ Full end-to-end synthetic image encryption and recovery

### 2. Command Line Unit Tests (Node.js)
```bash
node tests/test_crypto.js
node tests/test_image.js
node tests/test_steganography.js
node tests/test_crypto_stego_roundtrip.js
```

---

## ⚠️ Important Operational Security Guidelines

1. **Share as Documents / Uncompressed Files:**
   * Social messaging apps (WhatsApp, Messenger, Instagram, Discord, Twitter) re-encode and compress images into lossy JPEGs. **Lossy compression destroys steganographic bits.**
   * Always transmit encoded PNG images as **"Files" / "Documents"**, via AirDrop, email attachment, or private cloud storage.
2. **Steganography vs Cryptography:**
   * Steganography conceals the existence of communication, but statistical steganalysis can detect LSB modifications.
   * Even if the presence of hidden data is detected, the **AES-256-GCM encryption with 600k PBKDF2 rounds** ensures that the contents cannot be decrypted without the password.
3. **Zero Persistence:**
   * SecretPix stores **nothing** in `localStorage`, cookies, or remote databases. Once you refresh or clear the tab, all keys, plaintexts, and image buffers are permanently wiped from memory.

---

## 📄 License
MIT License. Created for private, secure communication.
