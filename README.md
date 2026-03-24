# 🔐 VAULT

### Advanced Quantum-Resistant Encrypted File Safe

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg">
  <img src="https://img.shields.io/badge/security-AES--256%20%7C%20ChaCha20-critical">
  <img src="https://img.shields.io/badge/KDF-scrypt%20128MB-purple">
  <img src="https://img.shields.io/badge/UI-CustomTkinter-modern">
  <img src="https://img.shields.io/badge/license-MIT-green.svg">
</p>

<p align="center">
  <b>Military-grade encryption. Modern UI. Self-destructing security.</b><br>
  Built for privacy, engineered for resilience.
</p>

---

## 🚀 Overview

**VAULT** is a **high-security desktop encryption suite** that allows you to lock, unlock, and manage sensitive data using **modern authenticated cryptography and memory-hard key derivation**.

It combines:

* **AES-256-GCM** & **ChaCha20-Poly1305**
* **scrypt (128MB memory-hard KDF)**
* **SHA3-based key separation + HMAC integrity**

with a **fully featured GUI**, encrypted notes system, and self-destructing executables.

---

## ✨ Core Features

### 🔐 File & Folder Encryption

* Encrypt files OR entire directories
* Automatically packs folders into compressed archives
* Outputs a secure `.vault` container

### 🧠 Quantum-Resistant Key Derivation

* scrypt (N=131072, ~128MB RAM usage)
* Auto memory fallback (adaptive degradation)
* HKDF-SHA3-256 for key separation

### 🔑 Dual-Factor Security (Optional)

* 512-bit keyfile support
* Password + keyfile required for decryption
* Enforced at file level

### 🧾 Metadata Encryption

* File name, size, timestamps encrypted
* Prevents information leakage

### 🗑️ Secure File Wiping

* 3-pass overwrite (random + zero)
* Works for files AND directories

---

## 💻 Advanced Capabilities

### ⚡ Self-Decrypting Executables

* Generates standalone `.exe`
* Contains encrypted payload internally
* No VAULT app required
* Deletes itself after execution

### 💣 Self-Destruct Protection

* Limited password attempts
* Auto-deletes executable after failures
* Anti-bruteforce mechanism

### 🔍 Vault Inspection

* Detects:

  * version
  * cipher used
  * keyfile requirement

---

## 🖥️ GUI Features (CustomTkinter)

### 🎛️ Modern Interface

* Sidebar navigation
* Card-based layout
* Real-time progress updates
* Status feedback + logs

### 🎨 Theme System

* Dark / Light modes
* Fully layered UI system
* High contrast design

### 🔐 Password Strength Meter

* Real-time evaluation
* Visual strength bar

---

## ✏️ Encrypted Notes System

A built-in secure editor with:

* 🔒 AES-encrypted notes vault
* 🧠 Password-protected access
* 📁 File-tree style editing
* 🎨 Multiple editor themes:

  * VS Dark
  * Monokai
  * Dracula
  * Solarized
  * GitHub Light
  * CRT modes (Green / Amber)

### 🔤 Advanced Editor Controls

* Font selector (IDLE-style panel)
* Font size + bold control
* Live preview system
* Syntax-style text rendering

---

## 🛡️ Cryptographic Architecture

| Component      | Implementation                  |
| -------------- | ------------------------------- |
| Encryption     | AES-256-GCM / ChaCha20-Poly1305 |
| KDF            | scrypt (128MB) + HKDF-SHA3-256  |
| Integrity      | HMAC-SHA3-256                   |
| Key Separation | HKDF (enc_key + mac_key)        |
| Metadata       | AES-GCM encrypted               |
| Randomness     | `secrets` (CSPRNG)              |

---

## ⚙️ File Format

```
[VLT MAGIC][VERSION][FLAGS][KDF PARAMS][SALT]
[ENCRYPTED METADATA]
[ENCRYPTED PAYLOAD]
[HMAC-SHA3-256 TAG]
```

* Fully authenticated (Encrypt-then-MAC)
* Tamper-proof structure
* Backward compatibility (v5, v6 supported)

---

## ⚡ Performance Design

* Adaptive scrypt (auto memory fallback)
* Threaded encryption/decryption
* Efficient ZIP packing for folders
* Low UI latency via background workers

---

## 📦 Installation

```bash
pip install customtkinter cryptography
```

Run:

```bash
python vault.py
```

---

## 🚀 Usage

### 🔐 Encrypt

* Select file/folder
* Enter password (+ optional keyfile)
* Click **LOCK & ENCRYPT**

### 🔓 Decrypt

* Select `.vault`
* Enter credentials
* Restore original data

### ⚡ Generate Executable

* Creates standalone decryptor
* Auto-deletes after use

---

## 📁 Storage Locations

| Item        | Location             |
| ----------- | -------------------- |
| Notes Vault | `~/.vault_notes.enc` |
| Config      | `~/.vault5.json`     |

---

## ⚠️ Security Notes

* Weak passwords compromise security
* Lost password = **irrecoverable data**
* Keyfile loss = permanent lockout
* No backdoors, no recovery system (by design)

---

## 🧩 Roadmap

* [ ] Hardware key support (YubiKey)
* [ ] CLI version
* [ ] Secure cloud sync
* [ ] Mobile companion app

---

## 🤝 Contributing

Pull requests and ideas are welcome.

---

## 📄 License

MIT License

---

<p align="center">
  <b>Privacy is not optional.</b><br>
  🔐 Built for those who understand security.
</p>
