```markdown
# 🔐 VAULT 8.0 — Quantum‑Resistant Encrypted File Safe

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

**VAULT** is a cross‑platform desktop application that lets you encrypt files and folders with **military‑grade security** while also providing an **encrypted notes editor**. It uses modern cryptography (AES‑256‑GCM, ChaCha20‑Poly1305, scrypt, HMAC‑SHA3‑256) and includes features like secure wiping, keyfile two‑factor authentication, and a standalone self‑destructing decryptor.

---

## 📦 Download & Installation

### Pre‑compiled Executable (Windows)
- Download the latest `VAULT.exe` from the [**Releases**](../../releases) page.
- Run the executable – no installation required.
- On first launch, the **Editor** tab will ask you to create a password for your encrypted notes vault.
- The vault file is stored in your home directory (`%USERPROFILE%\.vault_notes.enc`).


## ✨ Features

- **Encrypt Files & Folders** – Create `.vault` containers with AES‑256‑GCM or ChaCha20‑Poly1305.
- **Quantum‑Resistant KDF** – Memory‑hard scrypt (128 MB) with HKDF‑SHA3‑256 key derivation.
- **Integrity Protection** – HMAC‑SHA3‑256 ensures tamper‑proof vaults.
- **Standalone Decryptor** – Optionally generate a single‑file `.exe` that decrypts itself and self‑destructs after wrong attempts.
- **Keyfile Support** – Add a second factor (a 512‑bit keyfile) for two‑factor encryption.
- **Secure Wiping** – 3‑pass overwrite (random → random → zeros) before deletion.
- **Encrypted Notes Editor** – Built‑in, password‑protected editor (AES‑256‑GCM + scrypt) with syntax highlighting, themes, and a file‑tree explorer.
- **Dark/Light Theme** – Fully customizable UI with multiple editor themes (VS Dark, Monokai, Dracula, etc.).
- **File Association** – Register `.vault` files to open directly with VAULT (Windows only).

---

## 🛡️ Security Details

| Component            | Algorithm / Method           | Purpose                                   |
|----------------------|------------------------------|-------------------------------------------|
| Ciphers              | AES‑256‑GCM, ChaCha20‑Poly1305 | Authenticated encryption for data and metadata |
| Key Derivation (KDF) | scrypt (N=131072, r=8, p=1) + HKDF‑SHA3‑256 | Memory‑hard, quantum‑resistant key stretching |
| Integrity            | HMAC‑SHA3‑256                | Encrypt‑then‑MAC – rejects tampered vaults |
| Keyfile              | 512‑bit random + SHA3‑256    | Optional second factor                    |
| Wipe                 | 3‑pass overwrite             | Prevents file recovery                     |

> **Note:** All cryptographic operations rely on the well‑audited `cryptography` library and the standard `hashlib` module.

---

## 📖 How to Use

### 🔒 Locking Files / Folders
1. In the **Lock** tab, choose a file or folder.
2. Enter and confirm a strong password (a strength bar helps).
3. Optionally:
   - Select a different cipher (AES‑256‑GCM or ChaCha20‑Poly1305).
   - Adjust the KDF strength (scrypt memory is fixed for security).
   - Enable **keyfile protection** (generate or pick an existing keyfile).
   - Choose to generate a **self‑decrypting .exe** instead of a `.vault` file.
4. Click **LOCK & ENCRYPT**. The `.vault` file (or `.exe`) is created. You can choose to securely wipe the original.

### 🔓 Unlocking Vaults
1. In the **Unlock** tab, select a `.vault` file (or drag‑and‑drop).
2. Enter the password. If a keyfile was used, select it.
3. Choose an output folder (default is the vault’s location).
4. Decide whether to delete the vault after decryption.
5. Click **DECRYPT & RESTORE**. The original files/folders are restored, and the vault is verified for integrity.

### ✏️ Encrypted Notes Editor
- The editor stores all notes encrypted in a file located in your home directory:  
  - Windows: `%USERPROFILE%\.vault_notes.enc`  
  - macOS/Linux: `~/.vault_notes.enc`
- **First use:** Set a password to create a new encrypted vault.
- **Subsequent uses:** Enter the same password to unlock.
- Manage files with the left explorer (right‑click for context menus). Use `Ctrl+S` to save, `Ctrl+N` for new file.
- Change fonts and themes via the toolbar button **🔤 FONT & THEME**.

### ⚙️ Additional Features
- **Security Tab:** View cryptographic details, switch app theme, and register `.vault` file association (Windows).
- **Standalone Decryptor:** When locking, choose *“Self‑decrypting .exe”*. The resulting `.exe` contains the vault and asks for the password. After successful decryption (or after too many wrong attempts), it deletes itself.

---

> **Note:** The built‑in “Self‑decrypting .exe” feature (under Lock options) also uses PyInstaller. Ensure PyInstaller is installed when using that feature.

---

## 📁 File Locations

| Item                  | Default Location (Windows)                   | Default Location (Linux/macOS)            |
|-----------------------|----------------------------------------------|-------------------------------------------|
| Encrypted Notes Vault | `%USERPROFILE%\.vault_notes.enc`             | `~/.vault_notes.enc`                      |
| Configuration         | `%USERPROFILE%\.vault5.json`                 | `~/.vault5.json`                          |

To change the notes vault location, edit the `NOTES_FILE` variable in the source code.  
Example: `NOTES_FILE = Path(__file__).parent / "notes.vault"` makes it portable with the app.

---

## 🧪 Testing

The application has been tested on:
- Windows 10 / 11
- Ubuntu 22.04 LTS
- macOS Monterey (Intel and Apple Silicon)

---

## 📄 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or pull request for any bug fixes, improvements, or new features.

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

---

## 📧 Support

If you encounter any issues, please [open an issue](../../issues) on GitHub.

---

**Made with 🔒 for privacy.**
```
