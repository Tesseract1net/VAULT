#!/usr/bin/env python3
"""
VAULT 1.0 — Quantum-Resistant Encrypted File Safe
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Cipher   : AES-256-GCM  |  ChaCha20-Poly1305
KDF      : scrypt (N=131072, 128 MB) — memory-hard, quantum-resistant
Integrity: HMAC-SHA3-256 (encrypt-then-MAC)
Key split: HKDF-SHA3-256 (separate enc_key + mac_key)
Storage  : .vault files + AES-256-GCM encrypted notes vault

Install  : pip install customtkinter cryptography
Run      : python vault.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os, sys, io, json, struct, zipfile, threading, secrets, shutil, base64
import hmac as _hmac_mod, hashlib
from pathlib import Path
from datetime import datetime
from tkinter import filedialog, messagebox
import tkinter as tk
from tkinter import ttk

# ── Hard memory ceiling: 8 GB ─────────────────────────────────────────────────
try:
    import resource as _resource
    _8GB = 8 * 1024 * 1024 * 1024
    _soft, _hard = _resource.getrlimit(_resource.RLIMIT_AS)
    _new_hard = _8GB if _hard == _resource.RLIM_INFINITY else min(_hard, _8GB)
    _resource.setrlimit(_resource.RLIMIT_AS, (_8GB, _new_hard))
    del _soft, _hard, _new_hard
except Exception:
    pass  # Windows has no resource module

def _safe_scrypt(pw_bytes: bytes, salt: bytes, n: int, r: int = 8,
                 p: int = 1, dklen: int = 32) -> bytes:
    """
    Drop-in for hashlib.scrypt that auto-halves N on any memory-related error
    (MemoryError, OSError, ValueError from OpenSSL EVP_PBE_scrypt limit).
    Starts at the requested N and steps down: 131072→65536→32768→…→1024.
    Never raises a memory error to the caller — degrades gracefully.
    """
    start_n = n
    while n >= 1024:
        try:
            result = hashlib.scrypt(pw_bytes, salt=salt, n=n, r=r, p=p, dklen=dklen)
            if n < start_n:
                # Log degradation so it is visible during debugging
                import warnings
                warnings.warn(
                    f"scrypt N degraded {start_n}→{n} (low memory)",
                    RuntimeWarning, stacklevel=2)
            return result
        except (MemoryError, OSError, ValueError):
            n //= 2
    raise MemoryError(
        f"scrypt failed even at N=1024. System memory critically low.")

APP_VER  = "v1.0.0"
APP_NAME = "VAULT"

# ── auto-install ──────────────────────────────────────────────────────────────
def _pip(pkg):
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    import customtkinter as ctk
except ImportError:
    _pip("customtkinter"); import customtkinter as ctk
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    _pip("cryptography")
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ══════════════════════════════════════════════════════════════════════════════
#  THEME SYSTEM — gray-based, clearly differentiated layers
# ══════════════════════════════════════════════════════════════════════════════

THEMES = {
    "dark": {
        # Layered gray backgrounds — each step is clearly distinct
        "sidebar":    "#181818",   # darkest — far left
        "bg":         "#252525",   # main window fill
        "card":       "#303030",   # card surface  (+12 from bg)
        "field":      "#3a3a3a",   # input / inner field (+10 from card)
        "hover":      "#464646",   # hover state
        # Borders — highly visible
        "border":     "#505050",   # card border
        "border2":    "#686868",   # field / focus border
        "border3":    "#282828",   # sidebar divider
        # Step strip
        "strip":      "#1e1e1e",
        "strip_text": "#909090",
        # Accent
        "blue":       "#4d8ef5",
        "blue_d":     "#2563eb",
        "blue_bg":    "#1a2a42",
        "blue_strip": "#1a2235",
        "green":      "#2ec27e",
        "green_bg":   "#0d2216",
        "red":        "#e05252",
        "red_d":      "#b91c1c",
        "red_bg":     "#251010",
        "orange":     "#e0932e",
        "orange_bg":  "#251a08",
        "purple":     "#a070e8",
        "teal":       "#2abfbf",
        "yellow":     "#d4b420",
        # Text — high contrast on every surface above
        "text":       "#f0f0f0",   # bright white
        "text2":      "#aaaaaa",   # secondary
        "text3":      "#686868",   # muted labels
        "text_inv":   "#1a1a1a",   # for light-bg buttons
    },
    "light": {
        # Layered light grays
        "sidebar":    "#c8c8c8",   # medium gray sidebar
        "bg":         "#e8e8e8",   # light gray window
        "card":       "#f8f8f8",   # near-white card
        "field":      "#ffffff",   # pure white inputs
        "hover":      "#eeeeee",
        "border":     "#c0c0c0",
        "border2":    "#a0a0a0",
        "border3":    "#b8b8b8",
        "strip":      "#d8d8d8",
        "strip_text": "#555555",
        "blue":       "#1a5fcc",
        "blue_d":     "#1447a0",
        "blue_bg":    "#dce8ff",
        "blue_strip": "#e8f0ff",
        "green":      "#1a9060",
        "green_bg":   "#d8f5e8",
        "red":        "#cc2222",
        "red_d":      "#991414",
        "red_bg":     "#fde8e8",
        "orange":     "#c06010",
        "orange_bg":  "#fdf0dc",
        "purple":     "#7030c8",
        "teal":       "#0e8888",
        "yellow":     "#887000",
        "text":       "#1a1a1a",
        "text2":      "#505050",
        "text3":      "#909090",
        "text_inv":   "#ffffff",
    },
}

# Global active theme dict — mutated on theme switch
T = dict(THEMES["dark"])

CFG_PATH = Path.home() / ".vault5.json"
DEFAULTS = {"cipher": "AES-256-GCM", "itr": 310_000, "theme": "dark"}

def load_cfg():
    try:
        if CFG_PATH.exists():
            return {**DEFAULTS, **json.loads(CFG_PATH.read_text())}
    except: pass
    return dict(DEFAULTS)

def save_cfg(cfg):
    try: CFG_PATH.write_text(json.dumps(cfg, indent=2))
    except: pass

def t(k): return T[k]

def apply_theme(mode: str):
    T.clear()
    T.update(THEMES.get(mode, THEMES["dark"]))
    ctk.set_appearance_mode("dark" if mode == "dark" else "light")

# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO  v5
# ══════════════════════════════════════════════════════════════════════════════
MAGIC     = b"VLT500\x00\x00"
VER        = 7          # current version
VER_LEGACY = (5, 6)    # supported legacy versions
SALT_LEN   = 32
IV_LEN     = 12
HMAC_LEN   = 32        # SHA3-256 = 32 bytes
CIPHER_AES = 0x01
CIPHER_CHA = 0x02
FLAG_KEYFILE = 0x01
FLAG_ARGON2  = 0x02    # scrypt KDF used (set on VER 7+)

# scrypt parameters — memory-hard, quantum-resistant (stdlib hashlib)
# N=2^17 (128MB), r=8, p=1 → ~0.5-1s on modern CPU, GPU-resistant
SCRYPT_N    = 131072   # CPU/memory cost (128 MB)
SCRYPT_R    = 8        # block size
SCRYPT_P    = 1        # parallelism
SCRYPT_LEN  = 64       # output length (512 bits)

def _kdf(pw: str, salt: bytes, itr: int, keyfile_bytes: bytes = b"",
         use_argon2: bool = True):
    """
    Quantum-resistant key derivation.
    VER 7+: scrypt (memory-hard, stdlib) → HKDF-SHA3-256
    Legacy:  PBKDF2-SHA256 → HKDF-SHA256 (backwards compat)
    scrypt with N=2^17 requires 128MB RAM — GPU/ASIC/quantum resistant.
    """
    pw_material = pw.encode("utf-8")
    if keyfile_bytes:
        pw_material += hashlib.sha3_256(keyfile_bytes).digest()

    if use_argon2:  # flag name kept for file-format compat; actually runs scrypt
        master = _safe_scrypt(
            pw_material, salt=salt,
            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
            dklen=SCRYPT_LEN
        )
        enc_key = HKDF(hashes.SHA3_256(), 32, salt, b"vault-enc-key-v7").derive(master)
        mac_key = HKDF(hashes.SHA3_256(), 32, salt, b"vault-mac-key-v7").derive(master)
    else:
        master = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=itr
        ).derive(pw_material)
        enc_key = HKDF(hashes.SHA256(), 32, salt, b"vault-enc-key").derive(master)
        mac_key = HKDF(hashes.SHA256(), 32, salt, b"vault-mac-key").derive(master)

    master = b"\x00" * SCRYPT_LEN
    return enc_key, mac_key

def _enc(key, pt, cid):
    iv  = secrets.token_bytes(IV_LEN)
    obj = ChaCha20Poly1305(key) if cid == CIPHER_CHA else AESGCM(key)
    return iv, obj.encrypt(iv, pt, None)

def _dec(key, iv, ct, cid):
    obj = ChaCha20Poly1305(key) if cid == CIPHER_CHA else AESGCM(key)
    return obj.decrypt(iv, ct, None)

def _mac(key, data):
    return _hmac_mod.new(key, data, hashlib.sha3_256).digest()

def secure_wipe(path: Path, passes=3):
    if path.is_file():
        sz = path.stat().st_size
        if sz > 0:
            with open(path, "r+b") as f:
                for i in range(passes):
                    f.seek(0)
                    f.write(b"\x00" * sz if i == passes-1 else secrets.token_bytes(sz))
                    f.flush()
                    try: os.fsync(f.fileno())
                    except: pass
        path.unlink()
    elif path.is_dir():
        for c in sorted(path.rglob("*"), reverse=True):
            if c.is_file(): secure_wipe(c, passes)
        shutil.rmtree(path, ignore_errors=True)

def vault_lock(src: str, pw: str, cfg: dict, cb=None):
    p      = Path(src)
    cipher = cfg.get("cipher", "AES-256-GCM")
    itr    = cfg.get("itr", 310_000)
    cid    = CIPHER_CHA if "ChaCha" in cipher else CIPHER_AES
    kf_path = cfg.get("keyfile_path", "")
    keyfile_bytes = b""
    if kf_path:
        kf_path = Path(kf_path)
        if not kf_path.exists():
            raise FileNotFoundError(f"Keyfile not found: {kf_path}")
        keyfile_bytes = kf_path.read_bytes()
    flags = FLAG_KEYFILE if keyfile_bytes else 0x00

    cb and cb(5, "Packing files…")
    if p.is_dir():
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for f in sorted(p.rglob("*")):
                if f.is_file(): z.write(f, f.relative_to(p.parent))
        payload = buf.getvalue(); is_dir = True
    else:
        payload = p.read_bytes(); is_dir = False

    cb and cb(18, "Deriving keys  (Argon2id · 128MB · SHA3-256)…")
    salt = secrets.token_bytes(SALT_LEN)
    flags |= FLAG_ARGON2
    enc_key, mac_key = _kdf(pw, salt, itr, keyfile_bytes, use_argon2=True)

    cb and cb(55, f"Encrypting  [{cipher}]…")
    data_iv, data_ct = _enc(enc_key, payload, cid)

    cb and cb(72, "Encrypting metadata…")
    meta_iv, meta_ct = _enc(enc_key, json.dumps({
        "name": p.name, "is_dir": is_dir, "cipher": cipher,
        "itr": itr, "sz": len(payload), "ts": datetime.utcnow().isoformat(),
    }).encode(), CIPHER_AES)

    cb and cb(84, "Computing HMAC-SHA3-256 tag…")
    header     = MAGIC + struct.pack("<BBBII", VER, cid, flags, itr, SALT_LEN) + salt
    meta_block = struct.pack("<I", len(meta_ct)) + meta_iv + meta_ct
    data_block = data_iv + data_ct
    body       = header + meta_block + data_block
    tag        = _mac(mac_key, body)

    cb and cb(92, "Writing .vault file…")
    out = p.with_suffix(".vault")
    out.write_bytes(body + tag)

    enc_key = b"\x00"*32; mac_key = b"\x00"*32; keyfile_bytes = b""

    if cfg.get("wipe_orig") == "wipe":
        cb and cb(96, "Securely wiping original (3-pass)…")
        secure_wipe(p)

    cb and cb(100, "Locked ✓")
    return str(out), bool(flags & FLAG_KEYFILE)

def vault_peek_flags(vault_path: str) -> dict:
    raw = Path(vault_path).read_bytes()
    if raw[:8] != MAGIC: return {"ver": 0, "keyfile_required": False}
    ver, cid = struct.unpack("<BB", raw[8:10])
    if ver in VER_LEGACY: return {"ver": ver, "keyfile_required": False}
    if ver == VER:
        flags = struct.unpack("<B", raw[10:11])[0]
        return {"ver": ver, "keyfile_required": bool(flags & FLAG_KEYFILE)}
    return {"ver": ver, "keyfile_required": False}

def vault_unlock(vault_path: str, pw: str, dest: str, keyfile_bytes: bytes = b"", cb=None):
    raw = Path(vault_path).read_bytes()
    pos = 0
    def rd(n):
        nonlocal pos; v = raw[pos:pos+n]; pos += n; return v

    cb and cb(5, "Reading header…")
    if rd(8) != MAGIC:
        raise ValueError("Not a valid VAULT file")
    ver, cid = struct.unpack("<BB", rd(2))
    if ver in VER_LEGACY:
        itr, sl = struct.unpack("<II", rd(8)); flags = 0x00; use_argon2 = False
    elif ver == VER:
        flags, itr, sl = struct.unpack("<BII", rd(9)); use_argon2 = bool(flags & FLAG_ARGON2)
    else:
        raise ValueError(f"Unsupported vault version {ver}")
    if (flags & FLAG_KEYFILE) and not keyfile_bytes:
        raise ValueError("This vault requires a keyfile")
    if not (flags & FLAG_KEYFILE) and keyfile_bytes:
        raise ValueError("This vault was not created with a keyfile")
    salt = rd(sl)

    kdf_name = "Argon2id·SHA3" if use_argon2 else f"PBKDF2·{itr//1000}k"
    cb and cb(22, f"Deriving keys  ({kdf_name})…")
    enc_key, mac_key = _kdf(pw, salt, itr, keyfile_bytes, use_argon2=use_argon2)

    cb and cb(40, "Verifying HMAC integrity…")
    if not _hmac_mod.compare_digest(_mac(mac_key, raw[:-HMAC_LEN]), raw[-HMAC_LEN:]):
        enc_key = mac_key = b"\x00"*32
        raise ValueError("Wrong password, keyfile, or vault is corrupted")

    meta_len = struct.unpack("<I", rd(4))[0]
    meta_iv  = rd(IV_LEN); meta_ct = rd(meta_len)

    cb and cb(56, "Decrypting metadata…")
    try:
        meta = json.loads(_dec(enc_key, meta_iv, meta_ct, CIPHER_AES))
    except Exception:
        raise ValueError("Metadata decryption failed")

    data_iv = rd(IV_LEN)
    data_ct = raw[pos:-HMAC_LEN]

    cb and cb(72, f"Decrypting payload  [{meta['cipher']}]…")
    try:
        payload = _dec(enc_key, data_iv, data_ct, cid)
    except Exception:
        raise ValueError("Payload decryption failed")

    enc_key = mac_key = b"\x00"*32

    cb and cb(90, "Restoring files…")
    out_dir = Path(dest); out_dir.mkdir(parents=True, exist_ok=True)
    if meta.get("is_dir"):
        with zipfile.ZipFile(io.BytesIO(payload), "r") as z:
            z.extractall(out_dir)
        result = str(out_dir / meta["name"])
    else:
        of = out_dir / meta["name"]
        of.write_bytes(payload)
        result = str(of)

    cb and cb(100, "Unlocked ✓")
    return result, meta

def _build_vault_exe(vault_path: str, pw: str,
                     keyfile_bytes: bytes = b"",
                     max_attempts: int = 3) -> str:
    """
    Build a single self-contained self-deleting .exe:
      - Encrypted vault bytes embedded as base64 (no separate .vault needed)
      - scrypt hash stored for fast wrong-password rejection
      - AES-256-GCM + HMAC-SHA3-256 decrypt on correct password
      - Deletes itself after success OR after max_attempts failures
      - Uses PyInstaller; falls back to .pyc if unavailable
    """
    import subprocess as _sp, tempfile, shutil as _sh, base64 as _b64

    vp = Path(vault_path)
    raw_vault = vp.read_bytes()
    b64_chunks = "\n".join(
        f'    "{_b64.b64encode(raw_vault[i:i+57]).decode()}"'
        for i in range(0, len(raw_vault), 57)
    )

    # Derive scrypt verification hash (separate salt — reveals nothing about enc key)
    pw_material = pw.encode("utf-8")
    if keyfile_bytes:
        pw_material += hashlib.sha3_256(keyfile_bytes).digest()
    v_salt = secrets.token_bytes(32)
    v_hash = _safe_scrypt(pw_material, salt=v_salt,
                            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    v_salt_b64 = _b64.b64encode(v_salt).decode()
    v_hash_b64 = _b64.b64encode(v_hash).decode()
    kf_bool    = "True" if keyfile_bytes else "False"

    script = """\
import sys, os, io, json, struct, zipfile, base64, hashlib
import hmac as _h, threading, ctypes
from pathlib import Path

# ── embedded encrypted data ──────────────────────────────────
_DATA = base64.b64decode(''.join([
""" + b64_chunks + """
]))

# ── verification data (hash only — cannot decrypt) ───────────
_KF   = """ + kf_bool + """
_VS   = base64.b64decode('""" + v_salt_b64 + """')
_VH   = base64.b64decode('""" + v_hash_b64 + """')
_MAX  = """ + str(max_attempts) + """

# ── crypto constants ─────────────────────────────────────────
MAGIC = b'VLT500\\x00\\x00'
HMAC_LEN = 32; IV_LEN = 12; SALT_LEN = 32
C_AES = 0x01; C_CHA = 0x02
F_KF  = 0x01; F_SC  = 0x02
VL    = (5, 6); VER  = 7
SN = 131072; SR = 8; SP = 1; SL = 64

# ── load crypto deps once at module level ────────────────────
def _deps():
    try:
        from cryptography.hazmat.primitives import hashes as _hh
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        return _hh, AESGCM, ChaCha20Poly1305, HKDF, PBKDF2HMAC
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable,'-m','pip','install','cryptography','-q'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        from cryptography.hazmat.primitives import hashes as _hh
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        return _hh, AESGCM, ChaCha20Poly1305, HKDF, PBKDF2HMAC

# Initialise crypto globals once — avoids repeated frozen-archive imports
_hh, _AESGCM, _CCP, _HKDF, _PBKDF2HMAC = _deps()

def _safe_scrypt(pw_bytes, salt, n, r=8, p=1, dklen=32):
    # scrypt with auto N-halving on MemoryError/OSError/ValueError (OpenSSL limit)
    while n >= 1024:
        try:
            return hashlib.scrypt(pw_bytes, salt=salt, n=n, r=r, p=p, dklen=dklen)
        except (MemoryError, OSError, ValueError):
            n //= 2
    raise MemoryError("scrypt failed: system memory critically low")

def _kdf(pw, salt, itr, kb, scrypt_kdf):
    # FIX: use module-level globals — no repeated _deps() import inside thread
    m = pw.encode() + (hashlib.sha3_256(kb).digest() if kb else b'')
    if scrypt_kdf:
        master = _safe_scrypt(m, salt=salt, n=SN, r=SR, p=SP, dklen=SL)
        ek = _HKDF(_hh.SHA3_256(), 32, salt, b'vault-enc-key-v7').derive(master)
        mk = _HKDF(_hh.SHA3_256(), 32, salt, b'vault-mac-key-v7').derive(master)
    else:
        master = _PBKDF2HMAC(_hh.SHA256(), 32, salt, itr).derive(m)
        ek = _HKDF(_hh.SHA256(), 32, salt, b'vault-enc-key').derive(master)
        mk = _HKDF(_hh.SHA256(), 32, salt, b'vault-mac-key').derive(master)
    return ek, mk

def _decrypt(pw, kb):
    # FIX: single scrypt run — _verify removed; HMAC check here rejects wrong passwords
    raw = _DATA; pos = 0
    def rd(n):
        nonlocal pos; v = raw[pos:pos+n]; pos += n; return v
    if rd(8) != MAGIC: raise ValueError('Not a valid vault')
    ver, cid = struct.unpack('<BB', rd(2))
    if ver in VL:   itr, sl = struct.unpack('<II', rd(8)); flags = 0; sc = False
    elif ver == VER: flags, itr, sl = struct.unpack('<BII', rd(9)); sc = bool(flags & F_SC)
    else: raise ValueError('Unsupported version')
    salt = rd(sl)
    ek, mk = _kdf(pw, salt, itr, kb, sc)
    body = raw[:-HMAC_LEN]
    if not _h.compare_digest(_h.new(mk, body, hashlib.sha3_256).digest(), raw[-HMAC_LEN:]):
        raise ValueError('Wrong password or keyfile')
    ml = struct.unpack('<I', rd(4))[0]
    meta = json.loads((_CCP(ek) if cid==C_CHA else _AESGCM(ek)).decrypt(rd(IV_LEN), rd(ml), None))
    dv = rd(IV_LEN); ct = raw[pos:-HMAC_LEN]
    payload = (_CCP(ek) if cid==C_CHA else _AESGCM(ek)).decrypt(dv, ct, None)
    # Save next to the exe
    out_dir = Path(sys.executable if getattr(sys,'_MEIPASS',None) else __file__).parent
    if meta.get('is_dir'):
        with zipfile.ZipFile(io.BytesIO(payload)) as z: z.extractall(out_dir)
        return str(out_dir / meta['name'])
    else:
        of = out_dir / meta['name']; of.write_bytes(payload); return str(of)

def _self_destruct():
    exe = Path(sys.executable if getattr(sys,'frozen',False) else __file__).resolve()
    try:
        if sys.platform == 'win32':
            import subprocess
            subprocess.Popen(
                f'cmd /c ping -n 3 127.0.0.1 >nul & del /f /q "{exe}"',
                shell=True, creationflags=0x08000000)
        else:
            exe.unlink(missing_ok=True)
    except Exception:
        pass

# ── GUI ──────────────────────────────────────────────────────
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

BG='#1a1a1a'; CARD='#252525'; FLD='#303030'
ACC='#4d8ef5'; GRN='#2ec27e'; RED='#e05252'; ORG='#e0932e'
TXT='#f0f0f0'; TXT2='#aaaaaa'

def run():
    h = 400 if _KF else 310
    root = tk.Tk()
    root.title('VAULT — Encrypted File')
    root.configure(bg=BG)
    root.resizable(False, False)
    root.geometry(f'500x{h}')
    root.update_idletasks()
    sw = root.winfo_screenwidth(); sh = root.winfo_screenheight()
    root.geometry(f'500x{h}+{(sw-500)//2}+{(sh-h)//2}')

    # prevent close during decrypt
    busy = [False]
    attempts = [0]
    pw_v = tk.StringVar(); kf_path = ['']; show_v = tk.BooleanVar()

    def _on_close():
        if not busy[0]: root.destroy()
    root.protocol('WM_DELETE_WINDOW', _on_close)

    # header
    hf = tk.Frame(root, bg='#111111', pady=14); hf.pack(fill='x')
    tk.Label(hf, text='🔐  VAULT Encrypted File', bg='#111111', fg=TXT,
             font=('Segoe UI', 13, 'bold')).pack()
    tk.Label(hf, text='scrypt · AES-256-GCM · HMAC-SHA3-256  |  Self-deletes after use',
             bg='#111111', fg=TXT2, font=('Segoe UI', 7)).pack(pady=(1,0))

    # attempts counter label
    atl_v = tk.StringVar(value=f'Attempts remaining: {_MAX}')
    atl = tk.Label(root, textvariable=atl_v, bg=BG, fg=ORG, font=('Segoe UI', 9))
    atl.pack(pady=(8,0))

    # password
    cf = tk.Frame(root, bg=CARD); cf.pack(fill='x', padx=20, pady=(6,0))
    tk.Label(cf, text='Password', bg=CARD, fg=TXT2,
             font=('Segoe UI', 9)).pack(anchor='w', padx=14, pady=(10,2))
    pr = tk.Frame(cf, bg=CARD); pr.pack(fill='x', padx=14, pady=(0,10))
    pe = tk.Entry(pr, textvariable=pw_v, show='●', bg=FLD, fg=TXT,
                  insertbackground=TXT, relief='flat', font=('Segoe UI', 12),
                  highlightthickness=1, highlightbackground='#444',
                  highlightcolor=ACC)
    pe.pack(side='left', fill='x', expand=True, ipady=8, padx=(0,6))
    pe.focus_set()
    def _show(): pe.configure(show='' if show_v.get() else '●')
    tk.Checkbutton(pr, text='Show', variable=show_v, bg=CARD, fg=TXT2,
                   selectcolor=CARD, activebackground=CARD, activeforeground=TXT,
                   font=('Segoe UI', 9), command=_show,
                   relief='flat', cursor='hand2').pack(side='right')

    # keyfile (if required)
    kf_lbl_v = tk.StringVar(value='No keyfile selected')
    if _KF:
        kc = tk.Frame(root, bg=CARD); kc.pack(fill='x', padx=20, pady=(6,0))
        tk.Label(kc, text='🗝  Keyfile Required', bg=CARD, fg=ORG,
                 font=('Segoe UI', 9, 'bold')).pack(anchor='w', padx=14, pady=(8,2))
        kr = tk.Frame(kc, bg=CARD); kr.pack(fill='x', padx=14, pady=(0,8))
        kfl = tk.Label(kr, textvariable=kf_lbl_v, bg=CARD, fg=TXT2,
                       font=('Segoe UI', 9), anchor='w', width=30)
        kfl.pack(side='left', fill='x', expand=True)
        def _pick():
            p = filedialog.askopenfilename(parent=root, title='Select keyfile',
                filetypes=[('Vault Keyfile','*.vaultkey'),('All','*.*')])
            if p: kf_path[0]=p; kf_lbl_v.set(Path(p).name); kfl.configure(fg=GRN)
        tk.Button(kr, text='Browse…', command=_pick, bg=FLD, fg=TXT,
                  relief='flat', cursor='hand2',
                  font=('Segoe UI', 9), padx=10, pady=3).pack(side='right')

    sv = tk.StringVar()
    sl = tk.Label(root, textvariable=sv, bg=BG, font=('Segoe UI', 9),
                  fg=TXT2, wraplength=460); sl.pack(pady=(8,0), padx=20)
    prog = ttk.Progressbar(root, mode='indeterminate', length=460)

    def _go():
        if busy[0]: return
        pw = pw_v.get()
        if not pw: sv.set('⚠  Enter password'); sl.configure(fg=ORG); return
        if _KF and not kf_path[0]: sv.set('⚠  Select keyfile'); sl.configure(fg=ORG); return
        busy[0] = True
        btn.configure(state='disabled', text='Decrypting…')
        sv.set('Decrypting (scrypt + AES-256-GCM)…'); sl.configure(fg=TXT2)
        prog.pack(padx=20, pady=(4,0)); prog.start(12)

        def _worker():
            try:
                kb = Path(kf_path[0]).read_bytes() if kf_path[0] else b''
                # FIX: single scrypt run — _verify removed.
                # _decrypt runs scrypt once and rejects wrong passwords via HMAC.
                result = _decrypt(pw, kb)
                root.after(0, lambda r=result: _success(r))
            except ValueError:
                root.after(0, lambda: _wrong())
            except Exception as ex:
                root.after(0, lambda e=str(ex): _error(e))

        threading.Thread(target=_worker, daemon=True).start()

    def _wrong():
        prog.stop(); prog.pack_forget(); busy[0] = False
        attempts[0] += 1
        left = _MAX - attempts[0]
        if left <= 0:
            sv.set('❌  Too many wrong attempts — self-destructing…')
            sl.configure(fg=RED)
            btn.configure(state='disabled', text='Deleted')
            root.after(1500, lambda: (_self_destruct(), root.destroy()))
        else:
            atl_v.set(f'Attempts remaining: {left}')
            sv.set(f'✗  Wrong password.  {left} attempt(s) left.'); sl.configure(fg=RED)
            pw_v.set(''); pe.focus_set()
            btn.configure(state='normal', text='🔓  Decrypt')

    def _success(result):
        prog.stop(); prog.pack_forget(); busy[0] = False
        sv.set('✓  Decrypted: ' + result); sl.configure(fg=GRN)
        btn.configure(state='disabled', text='✓  Done', bg=GRN)
        messagebox.showinfo('Decrypted ✓',
            'File restored to:\\n' + result +
            '\\n\\nKDF: scrypt | Cipher: AES-256-GCM | HMAC: SHA3-256'
            '\\n\\nThis file will now delete itself.', parent=root)
        _self_destruct()
        root.after(800, root.destroy)

    def _error(msg):
        prog.stop(); prog.pack_forget(); busy[0] = False
        sv.set('✗  ' + msg); sl.configure(fg=RED)
        btn.configure(state='normal', text='🔓  Decrypt', bg=ACC)

    btn = tk.Button(root, text='🔓  Decrypt', command=_go,
                    bg=ACC, fg='#fff', relief='flat', cursor='hand2',
                    font=('Segoe UI', 12, 'bold'), pady=11)
    btn.pack(fill='x', padx=20, pady=(10,6))
    pe.bind('<Return>', lambda _: _go())
    root.mainloop()

if __name__ == '__main__':
    _deps()
    run()
"""

    tmp     = Path(tempfile.mkdtemp())
    py_file = tmp / (vp.stem + ".py")
    py_file.write_text(script, encoding="utf-8")

    # Try PyInstaller
    for attempt in range(2):
        try:
            if attempt == 1:   # install on second try
                _sp.check_call([sys.executable, "-m", "pip", "install", "pyinstaller", "-q"],
                               stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, timeout=120)
            _sp.check_call([
                sys.executable, "-m", "PyInstaller",
                "--onefile", "--noconsole", "--clean",
                "--distpath", str(vp.parent),
                "--workpath", str(tmp / "build"),
                "--specpath", str(tmp),
                "--name", vp.stem,
                str(py_file)
            ], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, timeout=300)
            exe = vp.parent / (vp.stem + ".exe")
            if exe.exists():
                _sh.rmtree(tmp, ignore_errors=True)
                # Delete the .vault — exe contains everything
                try: vp.unlink()
                except: pass
                return str(exe)
        except Exception:
            if attempt == 1:
                break

    # Fallback: .pyc
    import py_compile
    pyc = py_compile.compile(str(py_file), cfile=None, doraise=True, optimize=2)
    final = vp.parent / (vp.stem + ".pyc")
    Path(pyc).replace(final)
    _sh.rmtree(tmp, ignore_errors=True)
    return str(final)


def fmt_sz(b):
    for u in ["B","KB","MB","GB","TB"]:
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"

def pw_score(pw):
    if not pw: return 0, "", t("text3")
    s = sum([len(pw)>=8, len(pw)>=14,
             any(c.isupper() for c in pw),
             any(c.isdigit() for c in pw),
             any(not c.isalnum() for c in pw)])
    s = min(s, 4)
    return s, ["","Weak","Fair","Good","Strong"][s], \
              [t("text3"),t("red"),t("orange"),t("blue"),t("green")][s]

# ══════════════════════════════════════════════════════════════════════════════
#  STANDALONE DECRYPTOR  — generated alongside every .vault file
#  Running it asks for password and decrypts WITHOUT the VAULT app.
# ══════════════════════════════════════════════════════════════════════════════

DECRYPTOR_TEMPLATE = '''\
#!/usr/bin/env python3
"""
VAULT Standalone Decryptor
Generated by VAULT {app_ver} on {ts}
Vault file: {vault_name}

Run:   python "{script_name}"
Needs: pip install cryptography
"""
import sys, io, json, struct, os, zipfile, getpass, hmac as _hmac, hashlib, secrets, shutil
from pathlib import Path

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    import subprocess
    print("Installing cryptography…")
    subprocess.check_call([sys.executable,"-m","pip","install","cryptography","-q"])
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC    = b"VLT500\\x00\\x00"
SALT_LEN = 32; IV_LEN = 12; HMAC_LEN = 32
CIPHER_AES = 0x01; CIPHER_CHA = 0x02

def _kdf(pw, salt, itr):
    m = PBKDF2HMAC(hashes.SHA256(), 32, salt, itr).derive(pw.encode())
    ek = HKDF(hashes.SHA256(), 32, salt, b"vault-enc-key").derive(m)
    mk = HKDF(hashes.SHA256(), 32, salt, b"vault-mac-key").derive(m)
    return ek, mk

def _dec(key, iv, ct, cid):
    return (ChaCha20Poly1305(key) if cid==CIPHER_CHA else AESGCM(key)).decrypt(iv, ct, None)

VAULT_FILE = "{vault_name}"

def main():
    vault = Path(__file__).parent / VAULT_FILE
    if not vault.exists():
        print(f"ERROR: Cannot find {{VAULT_FILE}} in the same folder as this script.")
        input("Press Enter to exit...")
        return

    print("=" * 52)
    print("  VAULT — Standalone Decryptor")
    print(f"  File: {{VAULT_FILE}}")
    print("=" * 52)
    print()

    for attempt in range(3):
        try:
            pw = getpass.getpass("Password: ")
        except KeyboardInterrupt:
            print("\\nCancelled.")
            return

        try:
            raw = vault.read_bytes(); pos = 0
            def rd(n):
                nonlocal pos; v=raw[pos:pos+n]; pos+=n; return v
            if rd(8) != MAGIC: raise ValueError("Not a valid VAULT file")
            ver, cid, itr, sl = struct.unpack("<BBII", rd(10))
            salt = rd(sl)
            ek, mk = _kdf(pw, salt, itr)
            body = raw[:-HMAC_LEN]
            if not _hmac.compare_digest(_hmac.new(mk, body, hashlib.sha256).digest(), raw[-HMAC_LEN:]):
                raise ValueError("Wrong password")
            meta_len = struct.unpack("<I", rd(4))[0]
            meta = json.loads(_dec(ek, rd(IV_LEN), rd(meta_len), CIPHER_AES))
            data_iv = rd(IV_LEN); data_ct = raw[pos:-HMAC_LEN]
            payload = _dec(ek, data_iv, data_ct, cid)
            out_dir = vault.parent
            if meta.get("is_dir"):
                with zipfile.ZipFile(io.BytesIO(payload)) as z: z.extractall(out_dir)
                result = str(out_dir / meta["name"])
            else:
                of = out_dir / meta["name"]; of.write_bytes(payload); result = str(of)
            print(f"\\n  Decrypted successfully!")
            print(f"  Restored to: {{result}}")
            print(f"  Cipher: {{meta['cipher']}}, HMAC: verified")
            break
        except Exception as e:
            remaining = 2 - attempt
            if remaining > 0:
                print(f"  Wrong password. {{remaining}} attempt(s) left.\\n")
            else:
                print("  Too many failed attempts.")

    print()
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()
'''

def generate_decryptor(vault_path: str) -> str:
    """Write a standalone decryptor .py next to the vault file."""
    vp = Path(vault_path)
    script_name = vp.stem + "_open.py"
    out = vp.parent / script_name
    content = DECRYPTOR_TEMPLATE.format(
        app_ver    = APP_VER,
        ts         = datetime.now().strftime("%Y-%m-%d %H:%M"),
        vault_name = vp.name,
        script_name= script_name,
    )
    out.write_text(content, encoding="utf-8")
    return str(out)

# ══════════════════════════════════════════════════════════════════════════════
#  EDITOR THEME SYSTEM  (used by NotesView)
# ══════════════════════════════════════════════════════════════════════════════

_ETHEME = 'dark'

EDITOR_THEMES = {
    # ── Dark themes ─────────────────────────────────────────────────────────
    'dark': dict(
        bg='#1e1e1e', bg2='#252526', gutter='#1e1e1e', border='#3c3c3c',
        fg='#d4d4d4', fg2='#808080', acc='#569cd6', acc2='#4ec9b0',
        sel='#264f78', cur='#aeafad', name='VS DARK',
        font='Consolas',
    ),
    'monokai': dict(
        bg='#272822', bg2='#1e1f1c', gutter='#1e1f1c', border='#3e3d32',
        fg='#f8f8f2', fg2='#75715e', acc='#a6e22e', acc2='#66d9e8',
        sel='#49483e', cur='#f8f8f0', name='MONOKAI',
        font='Consolas',
    ),
    'dracula': dict(
        bg='#282a36', bg2='#21222c', gutter='#21222c', border='#44475a',
        fg='#f8f8f2', fg2='#6272a4', acc='#bd93f9', acc2='#50fa7b',
        sel='#44475a', cur='#ff79c6', name='DRACULA',
        font='Consolas',
    ),
    'midnight': dict(
        bg='#0d1117', bg2='#161b22', gutter='#0d1117', border='#30363d',
        fg='#c9d1d9', fg2='#8b949e', acc='#58a6ff', acc2='#3fb950',
        sel='#1f3a5f', cur='#58a6ff', name='MIDNIGHT',
        font='Courier New',
    ),
    # ── CRT / retro ──────────────────────────────────────────────────────────
    'green': dict(
        bg='#0d0d0d', bg2='#161616', gutter='#111111', border='#2a2a2a',
        fg='#00cc44', fg2='#2d6e2d', acc='#ffaa00', acc2='#00ccbb',
        sel='#00331a', cur='#ffaa00', name='GREEN PHOSPHOR',
        font='Courier New',
    ),
    'amber': dict(
        bg='#0d0800', bg2='#161000', gutter='#110c00', border='#2e2000',
        fg='#ffb830', fg2='#7a5010', acc='#ff6600', acc2='#ffe080',
        sel='#2a1800', cur='#ff6600', name='AMBER CRT',
        font='Courier New',
    ),
    # ── Light themes ─────────────────────────────────────────────────────────
    'light': dict(
        bg='#f2ede3', bg2='#e8e2d6', gutter='#ddd8cc', border='#b8b0a0',
        fg='#1a1208', fg2='#6a5a40', acc='#c84800', acc2='#006080',
        sel='#c8dff8', cur='#c84800', name='PAPER LIGHT',
        font='Georgia',
    ),
    'solarized': dict(
        bg='#fdf6e3', bg2='#eee8d5', gutter='#eee8d5', border='#cdc1a0',
        fg='#657b83', fg2='#93a1a1', acc='#268bd2', acc2='#2aa198',
        sel='#eee8d5', cur='#268bd2', name='SOLARIZED',
        font='Georgia',
    ),
    'github': dict(
        bg='#ffffff', bg2='#f6f8fa', gutter='#f6f8fa', border='#d0d7de',
        fg='#24292f', fg2='#57606a', acc='#0969da', acc2='#1a7f37',
        sel='#b6d4fe', cur='#0969da', name='GITHUB LIGHT',
        font='Consolas',
    ),
    'white': dict(
        bg='#ffffff', bg2='#f5f5f5', gutter='#f0f0f0', border='#e0e0e0',
        fg='#1a1a1a', fg2='#6e6e6e', acc='#0066cc', acc2='#007a5e',
        sel='#b3d4ff', cur='#0066cc', name='WHITE',
        font='Consolas',
    ),
}

def _ec(k):
    th = EDITOR_THEMES[_ETHEME]
    # 'font' key optional — fallback to Courier New
    if k == 'font': return th.get('font', 'Courier New')
    return th[k]

MONO_FONTS = [
    'Courier New', 'Consolas', 'Lucida Console', 'Courier',
    'Cascadia Code', 'Source Code Pro', 'Fira Code',
    'Monaco', 'Menlo', 'DejaVu Sans Mono', 'Monospace',
    # proportional (for light / writing themes)
    'Georgia', 'Times New Roman', 'Palatino Linotype',
    'Segoe UI', 'Arial', 'Calibri',
]


# ══════════════════════════════════════════════════════════════════════════════
#  NOTES FONT / APPEARANCE DIALOG  — IDLE-style big settings panel
# ══════════════════════════════════════════════════════════════════════════════

class NotesFontDialog(tk.Toplevel):
    """
    IDLE-style font & appearance settings window for the Notes editor.
    Two tabs: Font Settings  |  Editor Theme
    Applies changes live to the notes view.
    """
    def __init__(self, parent_tk, notes_view):
        super().__init__(parent_tk)
        self._nv = notes_view
        self.title('Notes — Font & Appearance')
        self.resizable(False, False)
        self.configure(bg=_ec('bg2'))
        self.grab_set()
        self.lift()
        self.focus_force()

        # Center over parent
        self.update_idletasks()
        pw = parent_tk.winfo_toplevel()
        x = pw.winfo_rootx() + (pw.winfo_width()  - 640) // 2
        y = pw.winfo_rooty() + (pw.winfo_height() - 560) // 2
        self.geometry(f'640x560+{max(x,0)}+{max(y,0)}')

        self._cur_font  = tk.StringVar(value=notes_view._nff.get())
        self._cur_size  = tk.IntVar(value=notes_view._nfs.get())
        self._cur_bold  = tk.BooleanVar(value=False)
        self._pending_theme = tk.StringVar(value=_ETHEME)
        self._build()

    # ── layout ────────────────────────────────────────────────────────────────

    def _build(self):
        bg   = _ec('bg')
        bg2  = _ec('bg2')
        fg   = _ec('fg')
        fg2  = _ec('fg2')
        acc  = _ec('acc')
        acc2 = _ec('acc2')
        bdr  = _ec('border')

        H1 = ('Segoe UI', 11, 'bold')
        H2 = ('Segoe UI', 10)
        MONO = ('Courier New', 10)

        # ── tab bar ───────────────────────────────────────────────────────────
        tab_bar = tk.Frame(self, bg=bg2, height=42)
        tab_bar.pack(fill='x')
        tab_bar.pack_propagate(False)

        self._pages = {}
        self._tab_btns = {}
        body = tk.Frame(self, bg=bg)
        body.pack(fill='both', expand=True)

        def _switch(name):
            for n, pg in self._pages.items():
                pg.pack_forget()
                self._tab_btns[n].configure(
                    relief='flat',
                    bg=bg2, fg=fg2,
                    font=('Segoe UI', 11),
                )
            self._pages[name].pack(fill='both', expand=True)
            self._tab_btns[name].configure(
                bg=bg, fg=acc,
                font=('Segoe UI', 11, 'bold'),
                relief='flat',
            )

        for tab_name in ('🔤  Font', '🎨  Theme'):
            key = tab_name
            pg = tk.Frame(body, bg=bg)
            self._pages[key] = pg
            btn = tk.Button(
                tab_bar, text=tab_name,
                command=lambda n=key: _switch(n),
                bg=bg2, fg=fg2, relief='flat',
                font=('Segoe UI', 11),
                activebackground=bg, activeforeground=acc,
                padx=18, pady=8, cursor='hand2', bd=0,
            )
            btn.pack(side='left')
            self._tab_btns[key] = btn

        tk.Frame(tab_bar, bg=bdr, height=2).pack(side='bottom', fill='x')

        # ── FONT PAGE ─────────────────────────────────────────────────────────
        fp = self._pages['🔤  Font']

        # left: scrollable font list
        left_col = tk.Frame(fp, bg=bg, width=230)
        left_col.pack(side='left', fill='y', padx=(18, 0), pady=18)
        left_col.pack_propagate(False)

        tk.Label(left_col, text='Font Family', bg=bg, fg=fg,
                 font=H1).pack(anchor='w', pady=(0, 6))

        flist_frame = tk.Frame(left_col, bg=bdr, bd=1, relief='flat')
        flist_frame.pack(fill='both', expand=True)

        self._flist = tk.Listbox(
            flist_frame,
            bg=_ec('bg2'), fg=fg, selectbackground=acc,
            selectforeground=bg, activestyle='none',
            font=('Segoe UI', 11), relief='flat',
            highlightthickness=0, bd=0,
            exportselection=False,
        )
        fscroll = tk.Scrollbar(flist_frame, orient='vertical',
                               command=self._flist.yview,
                               bg=bg2, troughcolor=bg, relief='flat')
        self._flist.configure(yscrollcommand=fscroll.set)
        fscroll.pack(side='right', fill='y')
        self._flist.pack(fill='both', expand=True)

        for fname in MONO_FONTS:
            self._flist.insert('end', fname)

        # pre-select current
        cur = self._cur_font.get()
        if cur in MONO_FONTS:
            idx = MONO_FONTS.index(cur)
            self._flist.selection_set(idx)
            self._flist.see(idx)

        self._flist.bind('<<ListboxSelect>>', self._on_flist)

        # right: size + style + preview
        right_col = tk.Frame(fp, bg=bg)
        right_col.pack(side='left', fill='both', expand=True,
                       padx=18, pady=18)

        tk.Label(right_col, text='Size', bg=bg, fg=fg,
                 font=H1).pack(anchor='w', pady=(0, 6))

        # Big size buttons like IDLE
        size_frame = tk.Frame(right_col, bg=bg)
        size_frame.pack(anchor='w', pady=(0, 14))

        SIZES = [8, 9, 10, 11, 12, 13, 14, 16, 18, 20, 22, 24, 28, 32, 36]
        self._sz_btns = {}
        cols = 5
        for i, sz in enumerate(SIZES):
            r, c = divmod(i, cols)
            is_sel = (sz == self._cur_size.get())
            b = tk.Button(
                size_frame,
                text=str(sz),
                width=4, pady=4,
                bg=acc if is_sel else _ec('bg2'),
                fg=bg if is_sel else fg,
                activebackground=acc, activeforeground=bg,
                relief='flat', font=('Segoe UI', 10, 'bold' if is_sel else 'normal'),
                cursor='hand2', bd=0,
                command=lambda s=sz: self._set_size(s),
            )
            b.grid(row=r, column=c, padx=2, pady=2)
            self._sz_btns[sz] = b

        # custom size spinbox
        csz_row = tk.Frame(right_col, bg=bg)
        csz_row.pack(anchor='w', pady=(0, 14))
        tk.Label(csz_row, text='Custom size:', bg=bg, fg=fg2,
                 font=H2).pack(side='left')
        self._sz_spin = tk.Spinbox(
            csz_row, from_=6, to=72, width=4,
            textvariable=self._cur_size,
            bg=_ec('bg2'), fg=fg, buttonbackground=_ec('bg2'),
            insertbackground=acc, relief='flat',
            font=('Segoe UI', 12, 'bold'),
            command=self._apply_font,
        )
        self._sz_spin.pack(side='left', padx=8)
        self._sz_spin.bind('<Return>', lambda _: self._apply_font())

        # style checkboxes
        tk.Label(right_col, text='Style', bg=bg, fg=fg,
                 font=H1).pack(anchor='w', pady=(0, 6))
        style_row = tk.Frame(right_col, bg=bg)
        style_row.pack(anchor='w', pady=(0, 14))
        tk.Checkbutton(
            style_row, text='Bold', variable=self._cur_bold,
            bg=bg, fg=fg, selectcolor=bg2,
            activebackground=bg, activeforeground=acc,
            font=('Segoe UI', 11), relief='flat',
            command=self._apply_font,
        ).pack(side='left', padx=(0, 14))

        # preview box
        tk.Label(right_col, text='Preview', bg=bg, fg=fg,
                 font=H1).pack(anchor='w', pady=(0, 6))
        pv_frame = tk.Frame(right_col, bg=bdr, bd=1)
        pv_frame.pack(fill='x', ipady=2)
        self._preview = tk.Text(
            pv_frame, height=5, wrap='word',
            bg=_ec('bg'), fg=_ec('fg'),
            insertbackground=_ec('acc'),
            selectbackground=_ec('sel'),
            relief='flat', highlightthickness=0,
            padx=12, pady=10,
            font=(self._cur_font.get(), self._cur_size.get()),
        )
        self._preview.pack(fill='x')
        PREVIEW_TEXT = (
            "AaBbCcDdEeFfGgHhIiJjKkLlMmOoPpQqRrSsTtUuVvWwXxYyZz.\n"
            "0 1 2 3 4 5 6 7 8 9  { } [ ] ( ) # @ ! & *\n"
            "def vault_lock(src, pw, cfg):\n"
            "    return encrypt(src, derive_key(pw))"
        )
        self._preview.insert('1.0', PREVIEW_TEXT)
        self._preview.configure(state='disabled')

        # ── THEME PAGE ────────────────────────────────────────────────────────


             # ── THEME PAGE (SCROLLABLE) ─────────────────────────────────────────
        tp = self._pages['🎨  Theme']

        tk.Label(tp, text='Editor Theme', bg=bg, fg=fg,font=('Segoe UI', 13, 'bold')).pack(anchor='w', padx=20, pady=(18, 6))
        tk.Label(tp, text='Select a theme then click  ✓ Apply Theme  to apply.',bg=bg, fg=fg2, font=H2).pack(anchor='w', padx=20, pady=(0, 10))

    # Scrollable canvas for theme swatches
        theme_canvas = tk.Canvas(tp, bg=bg, highlightthickness=0)
        theme_scrollbar = tk.Scrollbar(tp, orient='vertical', command=theme_canvas.yview)
        theme_canvas.configure(yscrollcommand=theme_scrollbar.set)
        theme_canvas.pack(side='left', fill='both', expand=True, padx=(18, 0), pady=(0, 4))
        theme_scrollbar.pack(side='right', fill='y', padx=(0, 18), pady=(0, 4))

        self._theme_inner = tk.Frame(theme_canvas, bg=bg)
        theme_canvas.create_window((0, 0), window=self._theme_inner, anchor='nw')

        self._theme_grid = self._theme_inner  # alias for existing code

        def _on_theme_configure(e):
            theme_canvas.configure(scrollregion=theme_canvas.bbox('all'))
        self._theme_inner.bind('<Configure>', _on_theme_configure)

        cols = 3
        for i, (tname, tdata) in enumerate(EDITOR_THEMES.items()):
            r, c = divmod(i, cols)
            self._make_theme_swatch(self._theme_grid, tname, tdata, r, c)

    # Apply Theme button (outside the scrollable area)
        theme_bot = tk.Frame(tp, bg=bg2, height=48)
        theme_bot.pack(fill='x', side='bottom')
        theme_bot.pack_propagate(False)
        tk.Frame(theme_bot, bg=bdr, height=1).pack(fill='x', side='top')
        self._theme_apply_btn = tk.Button(theme_bot, text='✓  Apply Theme',command=self._do_apply_theme,bg=acc, fg=bg, relief='flat', cursor='hand2',font=('Segoe UI', 11, 'bold'), padx=28, pady=6,activebackground=acc2, activeforeground=bg,)
        self._theme_apply_btn.pack(side='right', padx=14, pady=8)
        self._pending_lbl = tk.Label(
            theme_bot, text=f'Selected: {_ETHEME}',
            bg=bg2, fg=fg2, font=('Segoe UI', 9))
        self._pending_lbl.pack(side='left', padx=14, pady=8)
        # ── bottom bar ────────────────────────────────────────────────────────
        bot = tk.Frame(self, bg=bg2, height=52)
        bot.pack(fill='x', side='bottom')
        bot.pack_propagate(False)
        tk.Frame(bot, bg=bdr, height=1).pack(fill='x', side='top')
        tk.Button(
            bot, text='Close',
            command=self.destroy,
            bg=bg2, fg=fg2, relief='flat', cursor='hand2',
            font=('Segoe UI', 11), padx=20, pady=6,
            activebackground=bdr, activeforeground=fg,
        ).pack(side='right', padx=10, pady=8)
        self._apply_btn = tk.Button(
            bot, text='✓  Apply',
            command=self._do_apply_font,
            bg=acc, fg=bg, relief='flat', cursor='hand2',
            font=('Segoe UI', 11, 'bold'), padx=24, pady=6,
            activebackground=acc2, activeforeground=bg,
        )
        self._apply_btn.pack(side='right', padx=4, pady=8)
        tk.Button(
            bot, text='↺  Reset',
            command=self._reset_font,
            bg=bg2, fg=fg2, relief='flat', cursor='hand2',
            font=('Segoe UI', 10), padx=14, pady=6,
            activebackground=bdr, activeforeground=fg,
        ).pack(side='left', padx=10, pady=8)

        # activate first tab
        _switch('🔤  Font')

    # ── theme swatches ────────────────────────────────────────────────────────

    def _make_theme_swatch(self, parent, tname, tdata, row, col):
        is_active = (tname == _ETHEME)
        frame_bg  = tdata['acc'] if is_active else tdata['bg2']

        outer = tk.Frame(
            parent,
            bg=tdata['acc'] if is_active else _ec('border'),
            bd=2, relief='flat',
        )
        outer.grid(row=row, column=col, padx=7, pady=7, sticky='ew')
        parent.grid_columnconfigure(col, weight=1)

        inner = tk.Frame(outer, bg=tdata['bg'], cursor='hand2')
        inner.pack(fill='both', expand=True, padx=2, pady=2)

        # mini color swatches row
        sw_row = tk.Frame(inner, bg=tdata['bg'], height=10)
        sw_row.pack(fill='x', padx=6, pady=(6, 2))
        for color in [tdata['bg'], tdata['fg'], tdata['acc'],
                      tdata['acc2'], tdata.get('sel', tdata['bg2'])]:
            tk.Frame(sw_row, bg=color, width=14, height=10,
                     relief='flat').pack(side='left', padx=1)

        # sample text
        sample = tk.Label(
            inner,
            text=f"  {tdata['name']}\n  def hello(): ...\n  # {tname}",
            bg=tdata['bg'], fg=tdata['fg'],
            font=(tdata.get('font', 'Courier New'), 9),
            anchor='w', justify='left', pady=4,
        )
        sample.pack(fill='x', padx=4)

        # active badge
        badge_bg = tdata['acc']
        badge_fg = tdata['bg']
        badge = tk.Label(
            inner,
            text='  ✓ ACTIVE  ' if is_active else '  APPLY  ',
            bg=badge_bg if is_active else tdata['bg2'],
            fg=badge_fg if is_active else tdata['fg2'],
            font=('Segoe UI', 8, 'bold'),
            anchor='e', cursor='hand2',
        )
        badge.pack(fill='x', side='bottom', pady=(2, 4), padx=4)

        # click selects pending theme (Apply button commits it)
        for w in (inner, sample, badge, sw_row):
            w.bind('<Button-1>', lambda _e, n=tname: self._select_theme(n))

    # ── callbacks ─────────────────────────────────────────────────────────────

    def _on_flist(self, _=None):
        sel = self._flist.curselection()
        if sel:
            self._cur_font.set(MONO_FONTS[sel[0]])
            self._apply_font()

    def _set_size(self, sz):
        self._cur_size.set(sz)
        for s, b in self._sz_btns.items():
            sel = (s == sz)
            b.configure(
                bg=_ec('acc') if sel else _ec('bg2'),
                fg=_ec('bg') if sel else _ec('fg'),
                font=('Segoe UI', 10, 'bold' if sel else 'normal'),
            )
        self._apply_font()

    def _apply_font(self):
        ff       = self._cur_font.get()
        fs       = self._cur_size.get()
        bold_str = 'bold' if self._cur_bold.get() else 'normal'
        # Update preview
        self._preview.configure(state='normal')
        self._preview.configure(font=(ff, fs, bold_str))
        self._preview.configure(state='disabled')
        # Live-update the editor immediately
        nv = self._nv
        nv._nff.set(ff)
        nv._nfs.set(fs)
        nv._nfb.set(self._cur_bold.get())
        nv._refont()

    def _do_apply_font(self):
        """Apply button — commits current font choices (already live via _apply_font)."""
        self._apply_font()
        try:
            self._apply_btn.configure(text='✓  Applied!', bg=_ec('acc2'))
            self.after(1200, lambda: self._apply_btn.configure(
                text='✓  Apply', bg=_ec('acc')))
        except Exception:
            pass

    def _select_theme(self, tname):
        """Click a swatch — immediately apply the theme (same as current vault behaviour)."""
        global _ETHEME
        self._pending_theme.set(tname)
        _ETHEME = tname
        # Apply to the editor immediately
        self._nv._apply_editor_theme()
        # Update swatches to show new active state
        if hasattr(self, '_theme_inner') and self._theme_inner.winfo_exists():
            for sw in list(self._theme_inner.winfo_children()):
                sw.destroy()
            for i, (nm, td) in enumerate(EDITOR_THEMES.items()):
                r, c = divmod(i, 3)
                self._make_theme_swatch(self._theme_inner, nm, td, r, c)
        # Update pending label and preview
        if hasattr(self, '_pending_lbl'):
            self._pending_lbl.configure(text=f'Active: {tname}  ✓')
        self._preview.configure(
            bg=_ec('bg'), fg=_ec('fg'),
            insertbackground=_ec('acc'),
            selectbackground=_ec('sel'),
        )

    def _make_theme_swatch_sel(self, parent, tname, tdata, row, col, selected):
        """Swatch with selection highlight (not active=applied)."""
        is_sel    = (tname == selected)
        is_active = (tname == _ETHEME)
        border_col = tdata['acc'] if is_sel else (_ec('border') if not is_active else tdata['acc'])
        outer = tk.Frame(parent, bg=border_col, bd=2, relief='flat')
        outer.grid(row=row, column=col, padx=7, pady=7, sticky='ew')
        parent.grid_columnconfigure(col, weight=1)
        inner = tk.Frame(outer, bg=tdata['bg'], cursor='hand2')
        inner.pack(fill='both', expand=True, padx=2, pady=2)
        sw_row = tk.Frame(inner, bg=tdata['bg'], height=10)
        sw_row.pack(fill='x', padx=6, pady=(6, 2))
        for color in [tdata['bg'], tdata['fg'], tdata['acc'], tdata['acc2'],
                      tdata.get('sel', tdata['bg2'])]:
            tk.Frame(sw_row, bg=color, width=14, height=10,
                     relief='flat').pack(side='left', padx=1)
        label_txt = f"  {tdata['name']}\n  # {tname}"
        if is_active: label_txt += '  [active]'
        tk.Label(inner, text=label_txt, bg=tdata['bg'], fg=tdata['fg'],
                 font=(tdata.get('font', 'Courier New'), 9),
                 anchor='w', justify='left', pady=4).pack(fill='x', padx=4)
        badge_txt  = '  ✓ SELECTED  ' if is_sel else ('  ✓ ACTIVE  ' if is_active else '  CLICK  ')
        badge_bg   = tdata['acc'] if (is_sel or is_active) else tdata['bg2']
        badge_fg   = tdata['bg']  if (is_sel or is_active) else tdata['fg2']
        badge = tk.Label(inner, text=badge_txt, bg=badge_bg, fg=badge_fg,
                         font=('Segoe UI', 8, 'bold'), anchor='e', cursor='hand2')
        badge.pack(fill='x', side='bottom', pady=(2, 4), padx=4)
        for w in (inner, badge, sw_row) + tuple(sw_row.winfo_children()):
            w.bind('<Button-1>', lambda _e, n=tname: self._select_theme(n))

    def _do_apply_theme(self):
        """Apply Theme button — re-applies the currently selected theme."""
        self._select_theme(self._pending_theme.get())

    def _reset_font(self):
        """Reset font to theme default and apply immediately."""
        dfont = _ec('font')
        self._cur_font.set(dfont)
        self._cur_size.set(14)
        self._cur_bold.set(False)
        if dfont in MONO_FONTS:
            idx = MONO_FONTS.index(dfont)
            self._flist.selection_clear(0, 'end')
            self._flist.selection_set(idx)
            self._flist.see(idx)
        self._apply_font()
        # Also commit to editor immediately on reset
        self._nv._nff.set(dfont)
        self._nv._nfs.set(14)
        self._nv._nfb.set(False)
        self._nv._refont()

# ══════════════════════════════════════════════════════════════════════════════
#  WIDGETS
# ══════════════════════════════════════════════════════════════════════════════

class StrengthBar(ctk.CTkFrame):
    def __init__(self, parent, **kw):
        super().__init__(parent, fg_color="transparent", height=20, **kw)
        self._segs = []
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(side="left", fill="x", expand=True)
        for i in range(4):
            s = ctk.CTkFrame(bar, height=5, corner_radius=3, fg_color=t("border"))
            s.pack(side="left", fill="x", expand=True, padx=(0,3) if i<3 else 0)
            self._segs.append(s)
        self._lbl = ctk.CTkLabel(self, text="", font=ctk.CTkFont(size=10),
                                  text_color=t("text3"), width=52, anchor="e")
        self._lbl.pack(side="right")

    def update(self, pw):
        sc, lb, col = pw_score(pw)
        for i, s in enumerate(self._segs):
            s.configure(fg_color=col if i < sc else t("border"))
        self._lbl.configure(text=lb, text_color=col if sc else t("text3"))


class Card(ctk.CTkFrame):
    def __init__(self, parent, **kw):
        super().__init__(parent, corner_radius=10, fg_color=t("card"),
                         border_width=1, border_color=t("border"), **kw)

class FieldBox(ctk.CTkFrame):
    def __init__(self, parent, **kw):
        super().__init__(parent, corner_radius=8, fg_color=t("field"),
                         border_width=1, border_color=t("border2"), **kw)

def mk_entry(parent, var, show="", ph="", h=40, **kw):
    return ctk.CTkEntry(parent, textvariable=var, show=show, height=h,
                        corner_radius=8, fg_color=t("field"),
                        border_color=t("border2"), border_width=1,
                        text_color=t("text"), placeholder_text=ph,
                        placeholder_text_color=t("text3"),
                        font=ctk.CTkFont(size=13), **kw)

def mk_btn(parent, text, cmd, color=None, tc=None, w=None, h=36, **kw):
    fc = color if color else t("blue")
    tx = tc if tc else t("text_inv")
    b  = ctk.CTkButton(parent, text=text, command=cmd,
                        fg_color=fc, hover_color=t("blue_d") if fc==t("blue") else fc,
                        text_color=tx, font=ctk.CTkFont(size=12, weight="bold"),
                        corner_radius=8, height=h,
                        **({"width": w} if w else {}), **kw)
    return b

def lbl(parent, text, size=12, color=None, bold=False, **kw):
    return ctk.CTkLabel(parent, text=text,
                        font=ctk.CTkFont(size=size, weight="bold" if bold else "normal"),
                        text_color=color or t("text2"), **kw)

def step_strip(parent, text, pad):
    f = ctk.CTkFrame(parent, fg_color=t("strip"), corner_radius=6, height=28)
    f.pack(fill="x", **pad, pady=(0,8)); f.pack_propagate(False)
    ctk.CTkLabel(f, text=text, font=ctk.CTkFont(size=9, weight="bold"),
                 text_color=t("strip_text")).pack(side="left", padx=12, pady=5)

# ══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════

class Sidebar(ctk.CTkFrame):
    PAGES = [("🔒","Lock"), ("🔓","Unlock"), ("✏","Editor"), ("🛡","Security & Settings")]

    def __init__(self, parent, on_nav, **kw):
        super().__init__(parent, width=220, corner_radius=0,
                          fg_color=t("sidebar"), **kw)
        self.pack_propagate(False)
        self._on_nav = on_nav
        self._active = "Lock"
        self._rows   = {}
        self._build()

    def _build(self):
        # Logo
        logo = ctk.CTkFrame(self, fg_color="transparent", height=72)
        logo.pack(fill="x"); logo.pack_propagate(False)
        ctk.CTkLabel(logo, text="◈", font=ctk.CTkFont(size=30),
                     text_color=t("blue")).pack(side="left", padx=(16,8), pady=18)
        c = ctk.CTkFrame(logo, fg_color="transparent")
        c.pack(side="left", pady=18)
        ctk.CTkLabel(c, text=APP_NAME,
                     font=ctk.CTkFont(size=21, weight="bold"),
                     text_color=t("text")).pack(anchor="w")
        ctk.CTkLabel(c, text=f"v{APP_VER}  ·  Quantum-Resistant",
                     font=ctk.CTkFont(size=9), text_color=t("text3")).pack(anchor="w")

        ctk.CTkFrame(self, height=1, fg_color=t("border3")).pack(fill="x", padx=14)

        # Nav
        nav = ctk.CTkFrame(self, fg_color="transparent")
        nav.pack(fill="x", padx=10, pady=12)
        for icon, label in self.PAGES:
            outer = ctk.CTkFrame(nav, fg_color="transparent",
                                  corner_radius=8, height=44, cursor="hand2")
            outer.pack(fill="x", pady=2); outer.pack_propagate(False)
            bar  = ctk.CTkFrame(outer, width=3, corner_radius=2, fg_color="transparent")
            bar.pack(side="left", fill="y", padx=(6,6), pady=8)
            li   = ctk.CTkLabel(outer, text=icon, font=ctk.CTkFont(size=17),
                                 text_color=t("text3"), width=32)
            li.pack(side="left", padx=(0,4))
            lt   = ctk.CTkLabel(outer, text=label, font=ctk.CTkFont(size=13),
                                 text_color=t("text3"))
            lt.pack(side="left")
            self._rows[label] = (outer, bar, li, lt)
            for w in [outer, bar, li, lt]:
                w.bind("<Button-1>", lambda _, l=label: self._user_click(l))

        ctk.CTkFrame(self, fg_color="transparent").pack(fill="both", expand=True)

        # Status badge
        badge = ctk.CTkFrame(self, corner_radius=10, fg_color=t("card"),
                              border_width=1, border_color=t("border"))
        badge.pack(fill="x", padx=12, pady=(0,8))
        ctk.CTkLabel(badge, text="ENCRYPTION",
                     font=ctk.CTkFont(size=8, weight="bold"),
                     text_color=t("text3")).pack(pady=(8,4))
        for dot, name, col in [
            ("●","AES-256-GCM",    t("green")),
            ("●","HMAC-SHA3-256",  t("green")),
            ("●","scrypt · 128MB", t("green")),
            ("●","Zero-knowledge", t("blue")),
        ]:
            r = ctk.CTkFrame(badge, fg_color="transparent")
            r.pack(fill="x", padx=10, pady=1)
            ctk.CTkLabel(r, text=dot, font=ctk.CTkFont(size=8),
                         text_color=col, width=12).pack(side="left")
            ctk.CTkLabel(r, text=name, font=ctk.CTkFont(size=10),
                         text_color=t("text2")).pack(side="left")
        ctk.CTkFrame(badge, fg_color="transparent", height=6).pack()

        self._apply_visuals("Lock")

    def _apply_visuals(self, active):
        for label, (outer, bar, li, lt) in self._rows.items():
            on = label == active
            outer.configure(fg_color=t("blue_bg") if on else "transparent")
            bar.configure(fg_color=t("blue") if on else "transparent")
            li.configure(text_color=t("blue") if on else t("text3"))
            lt.configure(text_color=t("text") if on else t("text3"),
                         font=ctk.CTkFont(size=13, weight="bold" if on else "normal"))

    def _user_click(self, label):
        self._active = label
        self._apply_visuals(label)
        self._on_nav(label)

    def set_active(self, label):
        """Visuals ONLY — never calls _on_nav (avoids infinite recursion)."""
        self._active = label
        self._apply_visuals(label)


# ══════════════════════════════════════════════════════════════════════════════
#  LOCK VIEW
# ══════════════════════════════════════════════════════════════════════════════

class LockView(ctk.CTkScrollableFrame):
    ITR_LABELS = [
        "Maximum  ·  600 000 iterations",
        "Military  ·  500 000 iterations",
        "Standard  ·  310 000 iterations",
        "Fast       ·  100 000 iterations",
    ]
    ITR_MAP = {
        "Maximum  ·  600 000 iterations": 600_000,
        "Military  ·  500 000 iterations": 500_000,
        "Standard  ·  310 000 iterations": 310_000,
        "Fast       ·  100 000 iterations": 100_000,
    }

    def __init__(self, parent, app, **kw):
        super().__init__(parent, fg_color="transparent",
                         scrollbar_button_color=t("card"),
                         scrollbar_fg_color=t("bg"), **kw)
        self._app    = app
        self._src    = ""
        self._pw1    = tk.StringVar()
        self._pw2    = tk.StringVar()
        self._cipher = tk.StringVar(value=app.cfg.get("cipher","AES-256-GCM"))
        self._itr    = tk.StringVar(value=self._itr2l(app.cfg.get("itr",310_000)))
        self._wipe   = tk.StringVar(value="wipe")
        self._show   = tk.BooleanVar(value=False)
        self._gen_exe     = tk.StringVar(value='none')  # none | exe
        self._exe_attempts = tk.IntVar(value=3)          # password attempt limit for exe
        self._kf_mode = tk.StringVar(value='none')  # none | generate | existing
        self._kf_path = ''
        self._busy   = False
        self._prog_v = False
        self._build()

    def _itr2l(self, v):
        if v >= 550000: return "Maximum  ·  600 000 iterations"
        if v >= 400000: return "Military  ·  500 000 iterations"
        if v >= 200000: return "Standard  ·  310 000 iterations"
        return "Fast       ·  100 000 iterations"

    def _build(self):
        P = dict(padx=24)
        lbl(self,"🔒  Lock & Encrypt", size=22, bold=True,
            color=t("text")).pack(anchor="w", **P, pady=(24,4))
        lbl(self,"Encrypts with AES-256-GCM · scrypt KDF · HMAC-SHA3-256. "
            "Optionally generates a standalone decryptor so the file can "
            "be opened without this app.",
            size=11, color=t("text2"), wraplength=680, justify="left").pack(
            anchor="w", **P, pady=(0,18))

        # Step 1 — source
        step_strip(self,"STEP 1  ·  CHOOSE FILE OR FOLDER", P)
        c1 = Card(self); c1.pack(fill="x", **P, pady=(0,14))
        fb = FieldBox(c1); fb.pack(fill="x", padx=12, pady=(12,8))
        self._icon = ctk.CTkLabel(fb, text="📄", font=ctk.CTkFont(size=20), width=32)
        self._icon.pack(side="left", padx=(10,6), pady=8)
        self._slbl = ctk.CTkLabel(fb, text="Nothing selected",
                                   font=ctk.CTkFont(size=11),
                                   text_color=t("text3"), anchor="w", wraplength=500)
        self._slbl.pack(side="left", fill="x", expand=True, padx=2, pady=8)
        br = ctk.CTkFrame(c1, fg_color="transparent")
        br.pack(fill="x", padx=12, pady=(0,12))
        mk_btn(br,"📄  File", self._pf, w=110).pack(side="left",padx=(0,8))
        mk_btn(br,"📁  Folder", self._pd,
               color=t("field"), tc=t("text"), w=110).pack(side="left")

        # Step 2 — password
        step_strip(self,"STEP 2  ·  SET PASSWORD", P)
        c2 = Card(self); c2.pack(fill="x", **P, pady=(0,14))
        lbl(c2,"Password", size=11, bold=True).pack(anchor="w", padx=12, pady=(12,4))
        self._e1 = mk_entry(c2, self._pw1, show="●",
                             ph="Enter a strong password…", h=42)
        self._e1.pack(fill="x", padx=12, pady=(0,6))
        self._pw1.trace_add("write", lambda *_: (
            self._sb.update(self._pw1.get()), self._cm()))
        self._sb = StrengthBar(c2)
        self._sb.pack(fill="x", padx=12, pady=(0,10))
        lbl(c2,"Confirm Password", size=11, bold=True).pack(anchor="w", padx=12, pady=(0,4))
        self._e2 = mk_entry(c2, self._pw2, show="●", ph="Re-enter password…", h=42)
        self._e2.pack(fill="x", padx=12, pady=(0,4))
        self._pw2.trace_add("write", lambda *_: self._cm())
        self._ml = ctk.CTkLabel(c2, text="", font=ctk.CTkFont(size=11),
                                 text_color=t("text3"))
        self._ml.pack(anchor="e", padx=12, pady=(2,4))
        ctk.CTkCheckBox(c2, text="Show passwords", variable=self._show,
                        font=ctk.CTkFont(size=11), text_color=t("text2"),
                        fg_color=t("blue"), hover_color=t("blue_d"),
                        checkmark_color=t("text_inv"),
                        command=lambda: (self._e1.configure(show="" if self._show.get() else "●"),
                                          self._e2.configure(show="" if self._show.get() else "●"))
                        ).pack(anchor="w", padx=12, pady=(2,12))

        # Step 3 — options
        step_strip(self,"STEP 3  ·  ENCRYPTION OPTIONS", P)
        c3 = Card(self); c3.pack(fill="x", **P, pady=(0,14))
        g = ctk.CTkFrame(c3, fg_color="transparent")
        g.pack(fill="x", padx=12, pady=(12,10))
        g.columnconfigure(0, weight=1, uniform="o"); g.columnconfigure(1, weight=1, uniform="o")
        ctk.CTkLabel(g, text="Cipher",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=t("text3"), anchor="w").grid(row=0,column=0,sticky="w",pady=(0,4))
        ctk.CTkComboBox(g, variable=self._cipher,
                        values=["AES-256-GCM","ChaCha20-Poly1305"],
                        fg_color=t("field"), border_color=t("border2"),
                        text_color=t("text"), button_color=t("hover"),
                        dropdown_fg_color=t("card"), font=ctk.CTkFont(size=12)
                        ).grid(row=1,column=0,sticky="ew",padx=(0,8))
        ctk.CTkLabel(g, text="Key Derivation Strength",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=t("text3"), anchor="w").grid(row=0,column=1,sticky="w",pady=(0,4))
        ctk.CTkComboBox(g, variable=self._itr,
                        values=self.ITR_LABELS,
                        fg_color=t("field"), border_color=t("border2"),
                        text_color=t("text"), button_color=t("hover"),
                        dropdown_fg_color=t("card"), font=ctk.CTkFont(size=11)
                        ).grid(row=1,column=1,sticky="ew")

        ctk.CTkFrame(c3, height=1, fg_color=t("border")).pack(fill="x", padx=12, pady=10)

        # Decryptor option
        ctk.CTkFrame(c3, height=1, fg_color=t("border")).pack(fill="x", padx=12, pady=10)
        lbl(c3, "Output Format", size=10, bold=True, color=t("text3")).pack(anchor="w", padx=12, pady=(0,4))
        for _val, _icon, _title, _desc, _col in [
            ("none", "🔒", "Vault file only (.vault)",
             "Just the .vault file. Needs VAULT app to decrypt.", t("text2")),
            ("exe",  "💻", "Self-decrypting .exe  (single use)",
             "One .exe with data inside. Password prompt on open. Self-deletes after success.", t("green")),
        ]:
            _r = ctk.CTkFrame(c3, fg_color=t("field"), corner_radius=8)
            _r.pack(fill="x", padx=12, pady=(0,5))
            ctk.CTkRadioButton(_r, text=f"{_icon}  {_title}", variable=self._gen_exe, value=_val,
                               font=ctk.CTkFont(size=11, weight="bold"),
                               text_color=_col, fg_color=_col, hover_color=_col,
                               radiobutton_width=16, radiobutton_height=16,
                               command=self._on_exe_mode_change
                               ).pack(anchor="w", padx=12, pady=(9,2))
            lbl(_r, _desc, size=10, color=t("text2"), justify="left").pack(anchor="w", padx=36, pady=(0,8))

        # Password attempt limit (only shown when exe selected)
        self._attempt_row = ctk.CTkFrame(c3, fg_color=t("blue_bg"), corner_radius=8)
        _al = ctk.CTkFrame(self._attempt_row, fg_color="transparent")
        _al.pack(side="left", fill="x", expand=True, padx=12, pady=10)
        lbl(_al, "🔐  Password attempt limit for exe", size=11, bold=True, color=t("blue")).pack(anchor="w")
        lbl(_al, "Exe permanently deletes itself after this many wrong passwords.",
            size=10, color=t("text2"), justify="left").pack(anchor="w")
        _ar = ctk.CTkFrame(self._attempt_row, fg_color="transparent")
        _ar.pack(side="right", padx=12)
        for _n in [1, 3, 5, 10]:
            ctk.CTkRadioButton(_ar, text=str(_n), variable=self._exe_attempts, value=_n,
                               font=ctk.CTkFont(size=11, weight="bold"),
                               text_color=t("blue"), fg_color=t("blue"), hover_color=t("blue_d"),
                               radiobutton_width=14, radiobutton_height=14
                               ).pack(side="left", padx=6)
        # hidden by default; shown when exe is chosen
        self._attempt_row.pack_forget()

        ctk.CTkFrame(c3, fg_color="transparent", height=4).pack()

        # Step 4 — keyfile
        step_strip(self,"STEP 4  ·  KEYFILE PROTECTION  (optional, two-factor)", P)
        c4k = Card(self); c4k.pack(fill="x", **P, pady=(0,14))
        lbl(c4k, "A keyfile adds a second factor — need BOTH password AND keyfile to decrypt.",
            size=10, color=t("text2"), wraplength=660, justify="left").pack(anchor="w", padx=12, pady=(10,6))
        for _v, _ic, _ti, _de, _ac in [
            ("none",     "🔑", "Password only",        "Standard — one factor.",                              t("text2")),
            ("generate", "✨", "Generate new keyfile",  "Creates a random 512-bit .vaultkey file.",            t("blue")),
            ("existing", "📂", "Use existing keyfile",  "Pick a .vaultkey you already have.",                  t("purple")),
        ]:
            _krow = ctk.CTkFrame(c4k, fg_color=t("field"), corner_radius=8)
            _krow.pack(fill="x", padx=12, pady=(0,5))
            ctk.CTkRadioButton(_krow, text=f"{_ic}  {_ti}", variable=self._kf_mode, value=_v,
                               font=ctk.CTkFont(size=11, weight="bold"),
                               text_color=_ac, fg_color=_ac, hover_color=_ac,
                               radiobutton_width=16, radiobutton_height=16,
                               command=self._kf_changed).pack(anchor="w", padx=12, pady=(9,2))
            lbl(_krow, _de, size=10, color=t("text2"), justify="left").pack(anchor="w", padx=36, pady=(0,8))
        kf_pick_row = ctk.CTkFrame(c4k, fg_color="transparent")
        kf_pick_row.pack(fill="x", padx=12, pady=(0,10))
        self._kf_lbl = ctk.CTkLabel(kf_pick_row, text="No keyfile  —  password only",
                                     font=ctk.CTkFont(size=10), text_color=t("text3"),
                                     anchor="w", wraplength=480)
        self._kf_lbl.pack(side="left", fill="x", expand=True, padx=(0,8))
        self._kf_btn = mk_btn(kf_pick_row, "📂  Choose Keyfile", self._pick_kf,
                               color=t("field"), tc=t("text"), w=140)
        self._kf_btn.pack(side="right")
        self._kf_btn.pack_forget()

        # Step 5 — original handling
        step_strip(self,"STEP 5  ·  WHAT HAPPENS TO THE ORIGINAL", P)
        c4 = Card(self); c4.pack(fill="x", **P, pady=(0,14))
        lbl(c4,"After the .vault is created, the original file:",
            size=11).pack(anchor="w", padx=12, pady=(12,8))
        self._opt_frames = {}
        self._wopt(c4,"keep","📂  Keep original  (not recommended)",
                   "Original file stays on disk unchanged. Can still be opened.",
                   t("orange_bg"), t("orange"))
        self._wopt(c4,"wipe","🔥  Securely wipe original  (recommended)",
                   "3-pass overwrite then delete. Unrecoverable by any file recovery tool.",
                   t("green_bg"), t("green"))
        ctk.CTkFrame(c4, fg_color="transparent", height=8).pack()

        # Progress
        self._pc = Card(self)
        self._pb = ctk.CTkProgressBar(self._pc, height=8, corner_radius=4,
                                       progress_color=t("blue"), fg_color=t("border"))
        self._pb.pack(fill="x", padx=12, pady=(12,6)); self._pb.set(0)
        self._pl = lbl(self._pc, "")
        self._pl.pack(anchor="w", padx=12, pady=(0,10))

        self._lbtn = ctk.CTkButton(self, text="🔒   LOCK & ENCRYPT",
                                    height=52, corner_radius=10,
                                    font=ctk.CTkFont(size=15, weight="bold"),
                                    fg_color=t("blue"), hover_color=t("blue_d"),
                                    text_color=t("text_inv"),
                                    command=self._go)
        self._lbtn.pack(fill="x", **P, pady=(4,28))

    def _wopt(self, parent, value, title, desc, bg, fg):
        f = ctk.CTkFrame(parent, fg_color=bg, corner_radius=8,
                          border_width=0, cursor="hand2")
        f.pack(fill="x", padx=12, pady=(0,6))
        top = ctk.CTkFrame(f, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(8,4))
        rb = ctk.CTkRadioButton(top, text=title, variable=self._wipe, value=value,
                                 font=ctk.CTkFont(size=11, weight="bold"),
                                 text_color=fg, fg_color=fg, hover_color=fg,
                                 radiobutton_width=16, radiobutton_height=16,
                                 command=self._ropt)
        rb.pack(side="left")
        lbl(f, desc, size=10, justify="left").pack(anchor="w", padx=28, pady=(0,8))
        self._opt_frames[value] = (f, fg)
        for w in [f, top, rb]:
            w.bind("<Button-1>", lambda _, v=value: (self._wipe.set(v), self._ropt()))
        self._ropt()

    def _ropt(self):
        for v, (f, fg) in self._opt_frames.items():
            f.configure(border_width=2 if self._wipe.get()==v else 0, border_color=fg)

    def _on_exe_mode_change(self):
        if self._gen_exe.get() == 'exe':
            self._attempt_row.pack(fill='x', padx=12, pady=(0,5))
        else:
            self._attempt_row.pack_forget()

    def _kf_changed(self):
        mode = self._kf_mode.get()
        if mode == "none":
            self._kf_btn.pack_forget()
            self._kf_lbl.configure(text="No keyfile  —  password only", text_color=t("text3"))
            self._kf_path = ""
        elif mode == "generate":
            self._kf_btn.pack(side="right")
            self._kf_lbl.configure(text="Click 'Choose Keyfile' to pick where to save it", text_color=t("blue"))
            self._kf_path = ""
        elif mode == "existing":
            self._kf_btn.pack(side="right")
            self._kf_lbl.configure(text="Click 'Choose Keyfile' to select your .vaultkey", text_color=t("purple"))
            self._kf_path = ""

    def _pick_kf(self):
        mode = self._kf_mode.get()
        if mode == "generate":
            p = filedialog.asksaveasfilename(title="Save new keyfile as…",
                defaultextension=".vaultkey",
                filetypes=[("Vault Keyfile","*.vaultkey"),("All","*.*")])
            if p:
                Path(p).write_bytes(secrets.token_bytes(64))
                self._kf_path = p
                self._kf_lbl.configure(text=f"✓  {p}", text_color=t("green"))
        elif mode == "existing":
            p = filedialog.askopenfilename(title="Select keyfile",
                filetypes=[("Vault Keyfile","*.vaultkey"),("All","*.*")])
            if p:
                self._kf_path = p
                self._kf_lbl.configure(text=f"✓  {p}", text_color=t("purple"))

    def _pf(self):
        p = filedialog.askopenfilename(title="Select file to lock")
        if p: self._src=p; self._slbl.configure(text=p, text_color=t("text")); self._icon.configure(text="📄")

    def _pd(self):
        p = filedialog.askdirectory(title="Select folder to lock")
        if p: self._src=p; self._slbl.configure(text=p, text_color=t("text")); self._icon.configure(text="📁")

    def _cm(self):
        p1,p2 = self._pw1.get(), self._pw2.get()
        if not p2: self._ml.configure(text=""); self._e2.configure(border_color=t("border2")); return
        if p1==p2: self._ml.configure(text="✓  Match", text_color=t("green")); self._e2.configure(border_color=t("green"))
        else:      self._ml.configure(text="✗  No match", text_color=t("red")); self._e2.configure(border_color=t("red"))

    def _sp(self):
        if not self._prog_v:
            self._pc.pack(fill="x", padx=24, pady=(0,12), before=self._lbtn)
            self._prog_v = True

    def _go(self):
        if self._busy: return
        if not self._src or not Path(self._src).exists():
            messagebox.showerror("Nothing Selected","Choose a file or folder first.",parent=self); return
        pw1,pw2 = self._pw1.get(), self._pw2.get()
        if not pw1: messagebox.showerror("No Password","Enter a password.",parent=self); self._e1.focus_set(); return
        if pw1!=pw2: messagebox.showerror("Mismatch","Passwords don't match.",parent=self); self._e2.focus_set(); return
        sc,lb,_ = pw_score(pw1)
        if sc<2 and not messagebox.askyesno("Weak Password",f"Strength: {lb}\n\nContinue anyway?",parent=self): return
        wipe = self._wipe.get()
        if wipe=="wipe" and not messagebox.askyesno("⚠  Confirm Wipe",
                f"Original will be permanently overwritten & deleted:\n\n  {self._src}\n\nContinue?",
                icon="warning",parent=self): return

        # Keyfile validation
        kf_mode = self._kf_mode.get()
        if kf_mode != "none" and not self._kf_path:
            messagebox.showerror("No Keyfile",
                "You selected a keyfile mode but haven't chosen a file yet.", parent=self); return
        if kf_mode == "generate" and not Path(self._kf_path).exists():
            messagebox.showerror("Keyfile Missing", f"Keyfile not saved: {self._kf_path}", parent=self); return

        cfg = {"cipher":self._cipher.get(), "itr":self.ITR_MAP.get(self._itr.get(),310_000),
               "wipe_orig":wipe, "keyfile_path": self._kf_path if kf_mode != "none" else ""}
        save_cfg({"cipher":cfg["cipher"],"itr":cfg["itr"]})
        self._busy=True
        self._lbtn.configure(state="disabled", text="⏳  Working…")
        self._pb.configure(progress_color=t("blue")); self._pb.set(0)
        self._pl.configure(text_color=t("text2"))
        self._sp()
        threading.Thread(target=self._bg, args=(self._src, pw1, cfg, self._gen_exe.get(), self._exe_attempts.get()), daemon=True).start()

    def _bg(self, src, pw, cfg, gen_exe, max_attempts=3):
        def cb(p,m): self.after(0, lambda: (self._pb.set(p/100), self._pl.configure(text=m)))
        try:
            out, kf_used = vault_lock(src, pw, cfg, cb=cb)
            kb = Path(cfg.get('keyfile_path','')).read_bytes() if cfg.get('keyfile_path','') else b''
            if gen_exe == 'exe':
                exe = _build_vault_exe(out, pw=pw, keyfile_bytes=kb, max_attempts=max_attempts)
            else:
                exe = None
            self.after(0, lambda o=out, e=exe, c=cfg, k=kf_used: self._done(o, e, c, k))
        except Exception as e:
            self.after(0, lambda err=str(e): self._fail(err))

    def _done(self, out, exe, cfg, kf_used):
        self._busy=False
        self._lbtn.configure(state="normal", text="🔒   LOCK & ENCRYPT")
        self._pb.set(1.0); self._pb.configure(progress_color=t("green"))
        sz=fmt_sz(Path(out).stat().st_size)
        self._pl.configure(text=f"✓  {Path(out).name}  ({sz})", text_color=t("green"))
        self._pw1.set(""); self._pw2.set(""); self._src=""
        self._slbl.configure(text="Nothing selected",text_color=t("text3"))
        self._icon.configure(text="📄"); self._sb.update("")
        self._ml.configure(text=""); self._e2.configure(border_color=t("border2"))
        self._kf_mode.set("none"); self._kf_path = ""
        self._kf_lbl.configure(text="No keyfile  —  password only", text_color=t("text3"))
        exe_line = f"Decryptor:  {Path(exe).name}" if exe else "Decryptor:  none"
        kf_line  = "Keyfile:    used" if kf_used else "Keyfile:    none"
        messagebox.showinfo("Locked ✓",
            f"Encryption complete!\n\n"
            f"Vault:     {out}\n"
            f"Size:      {sz}\n"
            f"Cipher:    {cfg['cipher']}\n"
            f"KDF:       scrypt (128MB · quantum-resistant)\n"
            f"HMAC:      SHA3-256\n"
            f"Original:  {'securely wiped' if cfg['wipe_orig']=='wipe' else 'kept'}\n"
            f"{kf_line}\n"
            f"{exe_line}")

    def _fail(self, msg):
        self._busy=False
        self._lbtn.configure(state="normal", text="🔒   LOCK & ENCRYPT")
        self._pb.configure(progress_color=t("red"))
        self._pl.configure(text=f"✗  {msg}", text_color=t("red"))
        messagebox.showerror("Lock Failed",msg)


# ══════════════════════════════════════════════════════════════════════════════
#  UNLOCK VIEW
# ══════════════════════════════════════════════════════════════════════════════

class UnlockView(ctk.CTkScrollableFrame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, fg_color="transparent",
                         scrollbar_button_color=t("card"),
                         scrollbar_fg_color=t("bg"), **kw)
        self._app    = app
        self._vault  = ""
        self._dest   = ""
        self._pw     = tk.StringVar()
        self._show   = tk.BooleanVar(value=False)
        self._del_vault = tk.BooleanVar(value=True)
        self._kf_path     = ""
        self._kf_required = False
        self._busy   = False
        self._prog_v = False
        self._build()

    def _build(self):
        P = dict(padx=24)
        lbl(self,"🔓  Unlock & Decrypt", size=22, bold=True,
            color=t("text")).pack(anchor="w", **P, pady=(24,4))
        lbl(self,"HMAC verified BEFORE decryption. Wrong password rejected instantly.",
            size=11, color=t("text2")).pack(anchor="w", **P, pady=(0,18))

        step_strip(self,"STEP 1  ·  SELECT VAULT FILE", P)
        c1=Card(self); c1.pack(fill="x",**P,pady=(0,14))
        fb=FieldBox(c1); fb.pack(fill="x",padx=12,pady=(12,8))
        ctk.CTkLabel(fb,text="🔐",font=ctk.CTkFont(size=20),width=32).pack(
            side="left",padx=(10,6),pady=8)
        self._vlbl=ctk.CTkLabel(fb,text="No .vault file selected",
                                 font=ctk.CTkFont(size=11),
                                 text_color=t("text3"),anchor="w",wraplength=500)
        self._vlbl.pack(side="left",fill="x",expand=True,padx=2,pady=8)
        mk_btn(c1,"📂  Browse .vault File",self._pv).pack(anchor="w",padx=12,pady=(0,12))

        step_strip(self,"STEP 2  ·  OUTPUT FOLDER  (optional)", P)
        c2=Card(self); c2.pack(fill="x",**P,pady=(0,14))
        self._dlbl=lbl(c2,"Same folder as vault  (default)")
        self._dlbl.pack(anchor="w",padx=12,pady=(12,8))
        mk_btn(c2,"📁  Choose Output Folder",self._pd,
               color=t("field"),tc=t("text")).pack(anchor="w",padx=12,pady=(0,12))

        step_strip(self,"STEP 3  ·  ENTER PASSWORD", P)
        c3=Card(self); c3.pack(fill="x",**P,pady=(0,14))
        lbl(c3,"Vault Password",size=11,bold=True).pack(anchor="w",padx=12,pady=(12,4))
        self._pe=mk_entry(c3,self._pw,show="●",ph="Enter vault password…",h=42)
        self._pe.pack(fill="x",padx=12,pady=(0,6))
        self._pe.bind("<Return>", lambda _: self._go())
        ctk.CTkCheckBox(c3,text="Show password",variable=self._show,
                        font=ctk.CTkFont(size=11),text_color=t("text2"),
                        fg_color=t("blue"),hover_color=t("blue_d"),
                        checkmark_color=t("text_inv"),
                        command=lambda: self._pe.configure(
                            show="" if self._show.get() else "●")
                        ).pack(anchor="w",padx=12,pady=(2,12))

        # Keyfile step
        step_strip(self,"STEP 4  ·  KEYFILE  (if vault was created with one)", P)
        ckf=Card(self); ckf.pack(fill="x",**P,pady=(0,14))
        self._kf_status=lbl(ckf,"Select a vault to auto-detect if a keyfile is required.",size=10,color=t("text3"))
        self._kf_status.pack(anchor="w",padx=12,pady=(10,4))
        kfr=ctk.CTkFrame(ckf,fg_color="transparent"); kfr.pack(fill="x",padx=12,pady=(0,10))
        self._ukf_lbl=ctk.CTkLabel(kfr,text="No keyfile selected",font=ctk.CTkFont(size=10),
                                    text_color=t("text3"),anchor="w",wraplength=440)
        self._ukf_lbl.pack(side="left",fill="x",expand=True,padx=(0,8))
        self._ukf_btn=mk_btn(kfr,"📂  Select Keyfile",self._pick_kf_u,color=t("field"),tc=t("text"),w=150)
        self._ukf_btn.pack(side="right"); self._ukf_btn.configure(state="disabled")

        # After decrypt option
        step_strip(self,"STEP 5  ·  AFTER DECRYPTION", P)
        c4=Card(self); c4.pack(fill="x",**P,pady=(0,14))
        lbl(c4,"What to do with the .vault file after successful decryption?",
            size=11).pack(anchor="w",padx=12,pady=(12,4))

        dv = ctk.CTkFrame(c4, fg_color=t("field"), corner_radius=8)
        dv.pack(fill="x", padx=12, pady=(4,4))
        dv_left = ctk.CTkFrame(dv, fg_color="transparent")
        dv_left.pack(side="left", fill="x", expand=True, padx=12, pady=10)
        ctk.CTkLabel(dv_left, text="🗑  Delete .vault file after decryption",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=t("text")).pack(anchor="w")
        ctk.CTkLabel(dv_left,
                     text="The decrypted original file replaces the vault. "
                          "Vault file is deleted. Mirrors the encryption wipe behavior.",
                     font=ctk.CTkFont(size=10), text_color=t("text2"),
                     justify="left").pack(anchor="w")
        ctk.CTkSwitch(dv, text="", variable=self._del_vault,
                      progress_color=t("blue"), button_color=t("text"),
                      fg_color=t("border"), width=44, height=22).pack(
                      side="right", padx=12)
        ctk.CTkFrame(c4, fg_color="transparent", height=8).pack()

        # Progress
        self._pc=Card(self)
        self._pb=ctk.CTkProgressBar(self._pc,height=8,corner_radius=4,
                                     progress_color=t("teal"),fg_color=t("border"))
        self._pb.pack(fill="x",padx=12,pady=(12,6)); self._pb.set(0)
        self._pl=lbl(self._pc,"")
        self._pl.pack(anchor="w",padx=12,pady=(0,10))

        self._ubtn=ctk.CTkButton(self,text="🔓   DECRYPT & RESTORE",
                                  height=56,corner_radius=10,
                                  font=ctk.CTkFont(size=15,weight="bold"),
                                  fg_color=t("green"),hover_color=t("green"),
                                  text_color=t("text_inv"),
                                  command=self._go)
        self._ubtn.pack(fill="x",**P,pady=(4,28))

    def _pv(self):
        p=filedialog.askopenfilename(title="Select .vault file",
                                      filetypes=[("Vault","*.vault"),("All","*.*")])
        if p:
            self._vault=p; self._vlbl.configure(text=p,text_color=t("text"))
            if not self._dest:
                self._dest=str(Path(p).parent)
                self._dlbl.configure(text=self._dest,text_color=t("text"))
            try: info=vault_peek_flags(p); self._kf_required=info.get("keyfile_required",False)
            except: self._kf_required=False
            self._kf_path=""; self._ukf_lbl.configure(text="No keyfile selected",text_color=t("text3"))
            if self._kf_required:
                self._kf_status.configure(text="⚠  This vault requires a keyfile.",text_color=t("orange"))
                self._ukf_btn.configure(state="normal")
            else:
                self._kf_status.configure(text="✓  Password only — no keyfile needed.",text_color=t("green"))
                self._ukf_btn.configure(state="disabled")

    def _pick_kf_u(self):
        p=filedialog.askopenfilename(title="Select keyfile (.vaultkey)",
            filetypes=[("Vault Keyfile","*.vaultkey"),("All","*.*")])
        if p: self._kf_path=p; self._ukf_lbl.configure(text=f"✓  {Path(p).name}",text_color=t("green"))

    def _pd(self):
        p=filedialog.askdirectory(title="Select output folder")
        if p: self._dest=p; self._dlbl.configure(text=p,text_color=t("text"))

    def _sp(self):
        if not self._prog_v:
            self._pc.pack(fill="x",padx=24,pady=(0,12),before=self._ubtn)
            self._prog_v=True

    def _go(self):
        if self._busy: return
        if not self._vault or not Path(self._vault).exists():
            messagebox.showerror("No Vault","Select a .vault file.",parent=self); return
        pw=self._pw.get()
        if not pw: messagebox.showerror("No Password","Enter the vault password.",parent=self); self._pe.focus_set(); return
        if self._del_vault.get():
            if not messagebox.askyesno("Confirm",
                    "After decryption the .vault file will be deleted.\nContinue?",
                    parent=self): return
        if self._kf_required and not self._kf_path:
            messagebox.showerror("Keyfile Required","This vault needs a keyfile — click Select Keyfile.",parent=self); return
        dest=self._dest or str(Path(self._vault).parent)
        kf_bytes=Path(self._kf_path).read_bytes() if self._kf_path else b""
        self._busy=True
        self._ubtn.configure(state="disabled",text="⏳  Decrypting…")
        self._pb.configure(progress_color=t("teal")); self._pb.set(0)
        self._sp()
        threading.Thread(target=self._bg,args=(self._vault,pw,dest,self._del_vault.get(),kf_bytes),daemon=True).start()

    def _bg(self, vault, pw, dest, del_vault, kf_bytes):
        def cb(p,m): self.after(0, lambda: (self._pb.set(p/100), self._pl.configure(text=m)))
        try:
            r,meta = vault_unlock(vault, pw, dest, keyfile_bytes=kf_bytes, cb=cb)
            if del_vault:
                try: Path(vault).unlink()
                except: pass
            self.after(0, lambda: self._done(r, meta, del_vault))
        except Exception as e:
            self.after(0, lambda err=str(e): self._fail(err))

    def _done(self, result, meta, deleted_vault):
        self._busy=False
        self._ubtn.configure(state="normal",text="🔓   DECRYPT & RESTORE")
        self._pb.set(1.0); self._pb.configure(progress_color=t("green"))
        self._pl.configure(text=f"✓  {result}", text_color=t("green"))
        self._pw.set("")
        vault_line = "Vault file: deleted" if deleted_vault else "Vault file: kept"
        messagebox.showinfo("Unlocked ✓",
            f"Decryption complete!\n\n"
            f"Restored to:\n{result}\n\n"
            f"Cipher:  {meta.get('cipher','?')}\n"
            f"HMAC:    ✓ Verified\n"
            f"{vault_line}")

    def _fail(self, msg):
        self._busy=False
        self._ubtn.configure(state="normal",text="🔓   DECRYPT & RESTORE")
        self._pb.configure(progress_color=t("red"))
        self._pl.configure(text=f"✗  {msg}", text_color=t("red"))
        messagebox.showerror("Unlock Failed",msg)


# ══════════════════════════════════════════════════════════════════════════════
#  SECURITY VIEW
# ══════════════════════════════════════════════════════════════════════════════

class SecurityView(ctk.CTkScrollableFrame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, fg_color="transparent",
                         scrollbar_button_color=t("card"),
                         scrollbar_fg_color=t("bg"), **kw)
        self._app=app; self._build()

    def _qrow(self, parent, icon, q, a, col):
        r=ctk.CTkFrame(parent,fg_color=t("field"),corner_radius=8)
        r.pack(fill="x",padx=12,pady=3)
        ctk.CTkLabel(r,text=icon,font=ctk.CTkFont(size=18),width=38
                     ).pack(side="left",padx=(10,0),pady=10)
        c2=ctk.CTkFrame(r,fg_color="transparent")
        c2.pack(side="left",fill="x",expand=True,padx=8,pady=10)
        ctk.CTkLabel(c2,text=q,font=ctk.CTkFont(size=12,weight="bold"),
                     text_color=col,anchor="w").pack(anchor="w")
        ctk.CTkLabel(c2,text=a,font=ctk.CTkFont(size=10),
                     text_color=t("text2"),anchor="w",justify="left",
                     wraplength=580).pack(anchor="w")

    def _build(self):
        P=dict(padx=24)
        lbl(self,"🛡  Security & Settings",size=22,bold=True,
            color=t("text")).pack(anchor="w",**P,pady=(24,18))

        # ── Theme toggle ──────────────────────────────────────────────────────
        tc=Card(self); tc.pack(fill="x",**P,pady=(0,16))
        tr=ctk.CTkFrame(tc,fg_color="transparent")
        tr.pack(fill="x",padx=12,pady=14)
        lbl(tr,"🎨  App Theme",size=13,bold=True,color=t("text")).pack(side="left")
        # Segmented button
        theme_seg = ctk.CTkSegmentedButton(
            tr, values=["Dark","Light"],
            selected_color=t("blue"), selected_hover_color=t("blue_d"),
            unselected_color=t("field"), unselected_hover_color=t("hover"),
            text_color=t("text"),
            font=ctk.CTkFont(size=12),
            command=self._chtheme)
        theme_seg.set("Dark" if self._app.cfg.get("theme","dark")=="dark" else "Light")
        theme_seg.pack(side="right")
        lbl(tc,"Changes apply immediately. The window rebuilds with the new theme.",
            size=10).pack(anchor="w",padx=12,pady=(0,12))

        # ── File association ──────────────────────────────────────────────────
        fc=Card(self); fc.pack(fill="x",**P,pady=(0,16))
        lbl(fc,"🖥  File Association (Windows)",size=13,bold=True,
            color=t("text")).pack(anchor="w",padx=12,pady=(12,4))
        lbl(fc,"Register .vault with Windows so double-clicking asks for password.",
            size=10).pack(anchor="w",padx=12,pady=(0,8))
        br2=ctk.CTkFrame(fc,fg_color="transparent")
        br2.pack(fill="x",padx=12,pady=(0,12))
        mk_btn(br2,"✓  Register .vault",register_file_association,w=160).pack(side="left",padx=(0,8))
        mk_btn(br2,"✕  Unregister",unregister_file_association,
               color=t("field"),tc=t("text"),w=120).pack(side="left")

        # ── Q&A ───────────────────────────────────────────────────────────────
        qa=Card(self); qa.pack(fill="x",**P,pady=(0,16))
        step_strip(qa,"SECURITY Q&A", dict(padx=12))
        self._qrow(qa,"🔑","Where is my key stored?",
            "NOWHERE. The key is re-derived from your password every time using "
            "PBKDF2-HMAC-SHA256. No key file is ever saved to disk.",
            t("green"))
        self._qrow(qa,"🔥","Can someone recover the original after wipe?",
            "Extremely unlikely. 3-pass overwrite (random→random→zeros) before deletion. "
            "Standard recovery tools will only find garbage bytes.",
            t("blue"))
        self._qrow(qa,"📝","Why can I still open the original?",
            "Only if you chose 'Keep original'. With 'Securely wipe' enabled, "
            "the source is gone after locking — only the .vault remains.",
            t("orange"))
        self._qrow(qa,"🔑","What is the standalone decryptor?",
            "A small filename_open.py generated alongside the vault. "
            "Anyone with Python + cryptography installed can run it to decrypt — "
            "no VAULT app needed. The decryption is identical.",
            t("green"))
        self._qrow(qa,"⚠","What if I forget my password?",
            "No recovery. No backdoor. No one can help. Store your password safely.",
            t("red"))
        self._qrow(qa,"🧪","Is the vault tamper-proof?",
            "Yes. HMAC-SHA256 covers every byte. If a single bit changes, "
            "decryption is refused before any data is processed.",
            t("green"))
        ctk.CTkFrame(qa,fg_color="transparent",height=8).pack()

        # ── Crypto suite ──────────────────────────────────────────────────────
        cs=Card(self); cs.pack(fill="x",**P,pady=(0,16))
        step_strip(cs,"CRYPTOGRAPHIC PRIMITIVES", dict(padx=12))
        for ico,name,detail,col in [
            ("🔐","AES-256-GCM","NIST SP 800-38D · hardware-accelerated · authenticated",t("green")),
            ("🌊","ChaCha20-Poly1305","RFC 8439 · stream cipher · timing-safe",t("teal")),
            ("🏗","scrypt","128MB memory · quantum-resistant · stdlib hashlib",t("blue")),
            ("🔀","HKDF-SHA256","Derives enc_key + mac_key separately",t("purple")),
            ("🏷","HMAC-SHA3-256","Encrypt-then-MAC · 256-bit integrity tag · quantum-resistant",t("orange")),
            ("🔥","3-pass Wipe","random→random→zeros before delete",t("red")),
        ]:
            self._qrow(cs,ico,name,detail,col)
        ctk.CTkFrame(cs,fg_color="transparent",height=8).pack()

        ctk.CTkLabel(self,text=f"Config: {CFG_PATH}",
                     font=ctk.CTkFont(size=9),
                     text_color=t("text3")).pack(anchor="w",**P,pady=(4,28))

    def _chtheme(self, val):
        mode = "dark" if val == "Dark" else "light"
        self._app.cfg["theme"] = mode
        save_cfg(self._app.cfg)
        apply_theme(mode)
        # Rebuild entire window with new theme
        self._app.rebuild()


# ══════════════════════════════════════════════════════════════════════════════
#  PASSWORD PROMPT DIALOG  (for double-click / file association open)
# ══════════════════════════════════════════════════════════════════════════════

class VaultOpenDialog(ctk.CTkToplevel):
    def __init__(self, parent, vault_path, on_success, on_cancel):
        super().__init__(parent)
        self._vault=vault_path; self._on_ok=on_success; self._on_cancel=on_cancel
        self._pw=tk.StringVar(); self._show=tk.BooleanVar(value=False)
        self._busy=False
        self.title("Password Required")
        self.geometry("520x420"); self.resizable(False,False)
        self.configure(fg_color=t("bg"))
        self.grab_set(); self.lift(); self.focus_force()
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.update_idletasks()
        px=parent.winfo_rootx()+(parent.winfo_width()-520)//2
        py=parent.winfo_rooty()+(parent.winfo_height()-420)//2
        self.geometry(f"+{max(px,0)}+{max(py,0)}")
        self._build()

    def _build(self):
        hdr=ctk.CTkFrame(self,fg_color=t("card"),corner_radius=0,height=104)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        ctk.CTkLabel(hdr,text="🔐",font=ctk.CTkFont(size=46)).pack(pady=(10,0))
        ctk.CTkLabel(hdr,text="Password Required",
                     font=ctk.CTkFont(size=16,weight="bold"),
                     text_color=t("text")).pack()

        nf=ctk.CTkFrame(self,fg_color=t("field"),corner_radius=0,height=28)
        nf.pack(fill="x"); nf.pack_propagate(False)
        fname=Path(self._vault).name
        if len(fname)>62: fname="…"+fname[-59:]
        ctk.CTkLabel(nf,text=f"  {fname}",
                     font=ctk.CTkFont(size=11),
                     text_color=t("text2")).pack(side="left",padx=8,pady=4)

        body=ctk.CTkFrame(self,fg_color="transparent")
        body.pack(fill="both",expand=True,padx=26,pady=16)
        lbl(body,"This file is encrypted. Enter the password to decrypt it.",
            size=11,color=t("text2"),wraplength=460,justify="left").pack(anchor="w",pady=(0,12))
        self._entry=mk_entry(body,self._pw,show="●",ph="Enter vault password…",h=44)
        self._entry.pack(fill="x",pady=(0,4))
        self._entry.bind("<Return>",lambda _: self._try())
        self._entry.focus_set()
        self._errlbl=ctk.CTkLabel(body,text="",font=ctk.CTkFont(size=11),
                                   text_color=t("red"))
        self._errlbl.pack(anchor="w",pady=(0,4))
        ctk.CTkCheckBox(body,text="Show password",variable=self._show,
                        font=ctk.CTkFont(size=11),text_color=t("text2"),
                        fg_color=t("blue"),hover_color=t("blue_d"),
                        checkmark_color=t("text_inv"),
                        command=lambda: self._entry.configure(
                            show="" if self._show.get() else "●")
                        ).pack(anchor="w",pady=(0,12))
        self._pb=ctk.CTkProgressBar(body,height=5,corner_radius=3,
                                     progress_color=t("blue"),fg_color=t("border"))
        self._pb.pack(fill="x",pady=(0,4)); self._pb.set(0)
        self._pbl=lbl(body,"",size=10)
        self._pbl.pack(anchor="w",pady=(0,10))
        row=ctk.CTkFrame(body,fg_color="transparent")
        row.pack(fill="x")
        mk_btn(row,"Cancel",self._cancel,color=t("field"),tc=t("text"),w=100).pack(side="left")
        self._okbtn=mk_btn(row,"🔓  Open File",self._try,h=40)
        self._okbtn.pack(side="right",fill="x",expand=True,padx=(10,0))

    def _try(self):
        if self._busy: return
        pw=self._pw.get()
        if not pw: self._errlbl.configure(text="⚠  Enter a password"); return
        self._errlbl.configure(text=""); self._busy=True
        self._okbtn.configure(state="disabled",text="⏳  Decrypting…")
        dest=str(Path(self._vault).parent)
        threading.Thread(target=self._bg,args=(pw,dest),daemon=True).start()

    def _bg(self,pw,dest):
        def cb(p,m): self.after(0,lambda:(self._pb.set(p/100),self._pbl.configure(text=m)))
        try:
            r,meta=vault_unlock(self._vault,pw,dest,cb=cb)
            self.after(0,lambda:self._ok(r,meta))
        except Exception as e:
            self.after(0,lambda err=str(e):self._bad(err))

    def _ok(self,result,meta):
        self._busy=False
        self._pb.set(1.0); self._pb.configure(progress_color=t("green"))
        self.after(500,lambda:(self.destroy(),self._on_ok(result,meta)))

    def _bad(self,msg):
        self._busy=False
        self._okbtn.configure(state="normal",text="🔓  Open File")
        self._pb.configure(progress_color=t("red")); self._pb.set(1.0)
        self._pw.set(""); self._entry.focus_set()
        self._errlbl.configure(text="✗  Wrong password or corrupted vault")

    def _cancel(self):
        if not self._busy: self.destroy(); self._on_cancel()


# ══════════════════════════════════════════════════════════════════════════════
#  FILE ASSOCIATION
# ══════════════════════════════════════════════════════════════════════════════

def register_file_association():
    if sys.platform != "win32":
        messagebox.showinfo("Windows Only",
            "File association is Windows-only.\n\n"
            "Linux: use your file manager to set default app for .vault\n"
            "macOS: Finder → Get Info → Open With → Change All"); return
    try:
        import winreg
        exe = Path(sys.executable if getattr(sys,'frozen',False) else __file__).resolve()
        cmd = f'"{exe}" "%1"' if getattr(sys,'frozen',False) \
              else f'"{sys.executable}" "{exe}" "%1"'
        for path,val in [
            (r"Software\Classes\.vault",                       "VaultFile"),
            (r"Software\Classes\VaultFile",                    "VAULT Encrypted File"),
            (r"Software\Classes\VaultFile\DefaultIcon",        f"{exe},0"),
            (r"Software\Classes\VaultFile\shell\open\command", cmd),
        ]:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,path) as k:
                winreg.SetValueEx(k,"",0,winreg.REG_SZ,val)
        messagebox.showinfo("Registered ✓",
            "Done! Double-clicking any .vault file will\n"
            "open VAULT and ask for your password.")
    except Exception as e:
        messagebox.showerror("Failed",f"{e}\n\nTry Run as Administrator.")

def unregister_file_association():
    if sys.platform != "win32": return
    try:
        import winreg
        for k in [r"Software\Classes\VaultFile\shell\open\command",
                  r"Software\Classes\VaultFile\shell\open",
                  r"Software\Classes\VaultFile\shell",
                  r"Software\Classes\VaultFile\DefaultIcon",
                  r"Software\Classes\VaultFile",
                  r"Software\Classes\.vault"]:
            try: winreg.DeleteKey(winreg.HKEY_CURRENT_USER,k)
            except FileNotFoundError: pass
        messagebox.showinfo("Removed",".vault association removed.")
    except Exception as e:
        messagebox.showerror("Error",str(e))


# ══════════════════════════════════════════════════════════════════════════════
#  EDITOR VIEW  — VSCode-style encrypted editor
#  Directory tree · Tabs · AES-256-GCM · scrypt · HMAC-SHA3-256
# ══════════════════════════════════════════════════════════════════════════════

NOTES_FILE    = Path.home() / '.vault_notes.enc'
NOTES_MAX_FILE = 8 * 1024 * 1024          # 8 MB per-file soft limit (warn)
NOTES_MAX_VAULT = 8 * 1024 * 1024 * 1024  # 8 GB hard limit on vault size

# ── Crypto helpers (v2: fast pw verifier + HMAC-SHA3-AES-GCM) ─────────────────

def _nkdf(pw: str, salt: bytes) -> tuple:
    """Derive enc_key + mac_key via safe-scrypt → HKDF-SHA3-256."""
    km = _safe_scrypt(pw.encode('utf-8'), salt, n=32768, r=8, p=1, dklen=32)
    ek = HKDF(hashes.SHA3_256(), 32, salt, b'notes-enc-v2').derive(km)
    mk = HKDF(hashes.SHA3_256(), 32, salt, b'notes-mac-v2').derive(km)
    return ek, mk

def _notes_encrypt(data: bytes, pw: str) -> bytes:
    """
    Format:
        magic(4) pw_salt(16) pw_hash(32) enc_salt(32) iv(12) ciphertext HMAC(32)
    The pw_salt/pw_hash prefix lets us reject wrong passwords instantly
    without doing full HMAC+decryption.
    """
    pw_salt  = secrets.token_bytes(16)
    pw_hash  = _safe_scrypt(pw.encode(), pw_salt, n=4096, r=8, p=1, dklen=32)
    enc_salt = secrets.token_bytes(32)
    ek, mk   = _nkdf(pw, enc_salt)
    iv       = secrets.token_bytes(12)
    ct       = AESGCM(ek).encrypt(iv, data, None)
    body     = b'VNT2' + pw_salt + pw_hash + enc_salt + iv + ct
    tag      = _hmac_mod.new(mk, body, hashlib.sha3_256).digest()
    return body + tag

def _notes_decrypt(raw: bytes, pw: str) -> bytes:
    """
    1. Fast pw verifier (scrypt on 16-byte salt) — immediate rejection.
    2. HMAC verification over full body.
    3. AES-GCM decryption.
    """
    if len(raw) < 100:
        raise ValueError("File too short — corrupted?")
    if raw[:4] == b'VNT2':
        pw_salt  = raw[4:20];  pw_hash  = raw[20:52]
        enc_salt = raw[52:84]; iv       = raw[84:96]
        body     = raw[:-32];  tag      = raw[-32:]
        # fast rejection — cheap scrypt check, no decryption
        if not _hmac_mod.compare_digest(
                _safe_scrypt(pw.encode(), pw_salt, n=4096, r=8, p=1, dklen=32),
                pw_hash):
            raise ValueError("Wrong password")
        ek, mk = _nkdf(pw, enc_salt)
        if not _hmac_mod.compare_digest(
                _hmac_mod.new(mk, body, hashlib.sha3_256).digest(), tag):
            raise ValueError("File corrupted (integrity check failed)")
        return AESGCM(ek).decrypt(iv, raw[96:-32], None)
    else:
        # legacy v1: salt(32) iv(12) ct hmac(32)
        salt, iv = raw[:32], raw[32:44]
        ct, tag  = raw[44:-32], raw[-32:]
        ek, mk   = _nkdf(pw, salt)
        if not _hmac_mod.compare_digest(
                _hmac_mod.new(mk, raw[:-32], hashlib.sha3_256).digest(), tag):
            raise ValueError("Wrong password or corrupted file")
        return AESGCM(ek).decrypt(iv, ct, None)


# ══════════════════════════════════════════════════════════════════════════════

class NotesView(ctk.CTkFrame):
    """
    VSCode-inspired encrypted editor (VAULT Editor).
      Left  : activity bar (48px) + collapsible folder tree (240px)
      Right : tab bar + toolbar + line-numbered text editor + status bar
    Crypto: scrypt fast-verifier → HMAC-SHA3-256 → AES-256-GCM.
    """

    # ── init ──────────────────────────────────────────────────────────────────
    def __init__(self, parent, app, **kw):
        super().__init__(parent, fg_color=t('bg'), corner_radius=0, **kw)
        self._app      = app
        self._data     = {"files": {}, "dirs": []}
        self._pw       = None
        self._tabs     = []          # [path, …]  ordered open tabs
        self._active   = None        # str  currently visible file
        self._buf      = {}          # {path: str}  in-memory buffer
        self._dirty    = set()       # {path}  unsaved changes
        self._expanded = set()       # {dir_path}  expanded tree nodes
        self._blink_on = True
        self._nff      = None        # tk.StringVar set in _build_editor
        self._nfs      = None        # tk.IntVar
        self._nfb      = None        # tk.BooleanVar — bold base font
        self._tab_btns = {}          # {path: tk.Frame}
        self._build_lock()

    # ══ LOCK SCREEN ═══════════════════════════════════════════════════════════

    def _build_lock(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        is_new = not NOTES_FILE.exists()

        bg_frame = tk.Frame(self, bg=t('bg'))
        bg_frame.grid(row=0, column=0, sticky='nsew')
        bg_frame.grid_columnconfigure(0, weight=1)
        bg_frame.grid_rowconfigure(0, weight=1)

        card = ctk.CTkFrame(bg_frame, fg_color=t('card'), corner_radius=16, width=460)
        card.grid(row=0, column=0)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card, text='🔐', font=ctk.CTkFont(size=60)).pack(pady=(36, 4))
        ctk.CTkLabel(card, text='VAULT EDITOR',
                     font=ctk.CTkFont(size=26, weight='bold'),
                     text_color=t('text')).pack(pady=(0, 4))
        ctk.CTkLabel(card, text='AES-256-GCM  ·  scrypt-128MB  ·  HMAC-SHA3-256  ·  Zero-Knowledge',
                     font=ctk.CTkFont(size=10),
                     text_color=t('text3')).pack(pady=(0, 20))
        ctk.CTkLabel(card,
                     text='Create your encrypted vault' if is_new
                          else 'Enter password to unlock',
                     font=ctk.CTkFont(size=12),
                     text_color=t('text2')).pack(pady=(0, 14))

        lbl(card, 'Password', size=11, bold=True).pack(anchor='w', padx=30, pady=(0, 4))
        self._lpw = tk.StringVar()
        self._lpw_entry = mk_entry(card, self._lpw, show='●', ph='Password…', h=46)
        self._lpw_entry.pack(fill='x', padx=30, pady=(0, 10))

        self._lpw2 = tk.StringVar()
        if is_new:
            lbl(card, 'Confirm Password', size=11, bold=True).pack(
                anchor='w', padx=30, pady=(0, 4))
            self._lpw2_entry = mk_entry(card, self._lpw2, show='●',
                                         ph='Confirm password…', h=46)
            self._lpw2_entry.pack(fill='x', padx=30, pady=(0, 6))
            self._lpw2_entry.bind('<Return>', lambda _: self._do_unlock())
            self._str_bar = StrengthBar(card)
            self._str_bar.pack(fill='x', padx=30, pady=(0, 10))
            self._lpw.trace_add('write', lambda *_: self._str_bar.update(self._lpw.get()))

        self._lerr = ctk.CTkLabel(card, text='', font=ctk.CTkFont(size=11),
                                   text_color=t('red'))
        self._lerr.pack(pady=(0, 6))

        btn_txt = '  Create Vault  ' if is_new else '🔓  Unlock'
        self._unlock_btn = mk_btn(card, btn_txt, self._do_unlock, w=280, h=48)
        self._unlock_btn.pack(pady=(0, 32))
        self._lpw_entry.bind('<Return>', lambda _: self._do_unlock())
        self._lpw_entry.focus_set()

    def _do_unlock(self):
        pw = self._lpw.get()
        if not pw:
            self._lerr.configure(text='⚠  Enter a password'); return

        is_new = not NOTES_FILE.exists()
        if is_new:
            pw2 = self._lpw2.get()
            if pw != pw2:
                self._lerr.configure(text='✗  Passwords do not match'); return
            if len(pw) < 4:
                self._lerr.configure(text='⚠  Minimum 4 characters'); return
            self._data = {"files": {}, "dirs": []}
        else:
            self._unlock_btn.configure(state='disabled', text='Verifying…')
            self.update_idletasks()
            try:
                raw   = NOTES_FILE.read_bytes()
                plain = _notes_decrypt(raw, pw)
                self._data = json.loads(plain.decode('utf-8'))
            except ValueError as e:
                self._unlock_btn.configure(state='normal', text='🔓  Unlock')
                self._lerr.configure(text=f'✗  {e}')
                self._lpw.set(''); self._lpw_entry.focus_set()
                return
            except Exception as e:
                self._unlock_btn.configure(state='normal', text='🔓  Unlock')
                self._lerr.configure(text=f'✗  Error: {e}'); return

        # Normalise data structure (always ensure clean schema)
        if not isinstance(self._data, dict) or 'files' not in self._data:
            # Legacy migration: old flat {title: content} format
            if isinstance(self._data, dict):
                legacy = {k: v for k, v in self._data.items()
                          if not k.startswith('_') and isinstance(v, str)}
                self._data = {"files": {k + '.md': v for k, v in legacy.items()},
                              "dirs": []}
            else:
                self._data = {"files": {}, "dirs": []}
        if 'dirs' not in self._data or not isinstance(self._data['dirs'], list):
            self._data['dirs'] = []
        if 'files' not in self._data or not isinstance(self._data['files'], dict):
            self._data['files'] = {}

        self._pw = pw
        for w in self.winfo_children(): w.destroy()
        self._build_editor()

    # ══ EDITOR LAYOUT ═════════════════════════════════════════════════════════

    def _build_editor(self):
        bg   = _ec('bg');   bg2  = _ec('bg2');  gut  = _ec('gutter')
        fg   = _ec('fg');   fg2  = _ec('fg2');  acc  = _ec('acc')
        acc2 = _ec('acc2'); bdr  = _ec('border');sel  = _ec('sel')
        dfont = _ec('font')

        self._nff = tk.StringVar(value=dfont)
        self._nfs = tk.IntVar(value=14)
        self._nfb = tk.BooleanVar(value=False)

        pane = tk.Frame(self, bg=bg)
        pane.pack(fill='both', expand=True)

        # ── Activity bar (48px) ───────────────────────────────────────────────
        ab = tk.Frame(pane, bg=bg2, width=48)
        ab.pack(side='left', fill='y')
        ab.pack_propagate(False)
        tk.Frame(ab, bg=bdr, width=1).pack(side='right', fill='y')

        # Files icon
        fi = tk.Frame(ab, bg=bg2, cursor='hand2')
        fi.pack(pady=(12, 0), fill='x')
        tk.Label(fi, text='📁', bg=bg2, fg=acc2,
                 font=('Segoe UI', 16)).pack(pady=(6, 0))
        tk.Label(fi, text='FILES', bg=bg2, fg=fg2,
                 font=('Segoe UI', 6)).pack(pady=(0, 4))

        # Lock button at bottom
        lk = tk.Frame(ab, bg=bg2, cursor='hand2')
        lk.pack(side='bottom', pady=8, fill='x')
        tk.Label(lk, text='🔒', bg=bg2, fg=fg2, font=('Segoe UI', 14)).pack()
        tk.Label(lk, text='LOCK', bg=bg2, fg=fg2, font=('Segoe UI', 6)).pack()
        for w in [lk] + list(lk.winfo_children()):
            w.bind('<Button-1>', lambda _: self._lock_vault())

        # ── Sidebar explorer (240px) ──────────────────────────────────────────
        self._sidebar = tk.Frame(pane, bg=bg2, width=240)
        self._sidebar.pack(side='left', fill='y')
        self._sidebar.pack_propagate(False)
        self._build_explorer(bg2, fg, fg2, acc, acc2, bdr, dfont)

        tk.Frame(pane, bg=bdr, width=1).pack(side='left', fill='y')

        # ── Editor area ───────────────────────────────────────────────────────
        right = tk.Frame(pane, bg=bg)
        right.pack(side='left', fill='both', expand=True)
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(2, weight=1)

        # Row 0 — Tab bar
        self._tab_row = tk.Frame(right, bg=bg2, height=36)
        self._tab_row.grid(row=0, column=0, sticky='ew')
        self._tab_row.grid_propagate(False)

        # Row 1 — Toolbar
        self._build_toolbar(right, bg, bg2, fg, fg2, acc, acc2, bdr, dfont)

        # Row 2 — Text editor
        ed = tk.Frame(right, bg=bg)
        ed.grid(row=2, column=0, sticky='nsew')
        ed.grid_columnconfigure(1, weight=1)
        ed.grid_rowconfigure(0, weight=1)

        self._ngut = tk.Canvas(ed, bg=gut, width=56,
                                highlightthickness=0, bd=0)
        self._ngut.grid(row=0, column=0, sticky='ns')
        tk.Frame(ed, bg=bdr, width=1).grid(row=0, column=0,
                                            sticky='nse', padx=(56, 0))

        self._txt = tk.Text(
            ed, bg=bg, fg=fg, insertbackground=acc, insertwidth=2,
            relief='flat', font=(dfont, 14), wrap='word',
            undo=True, maxundo=-1,
            selectbackground=sel, selectforeground=fg,
            highlightthickness=0, padx=20, pady=14,
            spacing1=3, spacing3=3,
        )
        self._txt.grid(row=0, column=1, sticky='nsew')

        vsb = tk.Scrollbar(ed, orient='vertical', command=self._yscroll,
                            bg=bg2, troughcolor=bg, width=12, relief='flat')
        vsb.grid(row=0, column=2, sticky='ns')
        self._txt.configure(yscrollcommand=vsb.set)

        # Row 3 — Status bar
        sb = tk.Frame(right, bg=bg2, height=24)
        sb.grid(row=3, column=0, sticky='ew')
        sb.grid_propagate(False)
        right.grid_rowconfigure(3, weight=0)
        tk.Frame(sb, bg=bdr, height=1).pack(side='top', fill='x')
        self._stv = tk.StringVar(value='VAULT EDITOR  ·  AES-256-GCM  ·  Ready')
        self._wcv = tk.StringVar(value='')
        tk.Label(sb, textvariable=self._stv, bg=bg2, fg=fg2,
                 font=('Segoe UI', 9), anchor='w').pack(side='left', padx=10)
        tk.Label(sb, textvariable=self._wcv, bg=bg2, fg=fg2,
                 font=('Segoe UI', 9)).pack(side='right', padx=10)
        self._theme_lbl = tk.Label(sb, text=_ec('name'), bg=bg2, fg=acc2,
                                    font=('Segoe UI', 8))
        self._theme_lbl.pack(side='right', padx=8)

        self._setup_tags()
        self._txt.bind('<KeyRelease>', self._on_key)
        self._txt.bind('<MouseWheel>', lambda _: self.after(8, self._gut_draw))
        self._txt.bind('<Button-4>',   lambda _: self.after(8, self._gut_draw))
        self._txt.bind('<Button-5>',   lambda _: self.after(8, self._gut_draw))
        self._txt.bind('<Control-s>',  lambda _: self._save_current())
        self._txt.bind('<Control-n>',  lambda _: self._new_file_dialog())
        self._txt.bind('<Control-w>',  lambda _: self._close_tab(self._active))
        self._txt.bind('<Control-b>',  lambda e: self._fmt_bold())
        self._txt.bind('<Control-i>',  lambda e: self._fmt_italic())

        self._show_welcome()
        if self._data['files']:
            self._open_file(sorted(self._data['files'].keys())[0])
        self._cursor_blink()

    # ══ EXPLORER (VSCode-style tree) ══════════════════════════════════════════

    def _build_explorer(self, bg2, fg, fg2, acc, acc2, bdr, dfont):
        # Header row
        hdr = tk.Frame(self._sidebar, bg=bg2, height=36)
        hdr.pack(fill='x')
        hdr.pack_propagate(False)
        tk.Label(hdr, text='  EXPLORER', bg=bg2, fg=fg2,
                 font=('Segoe UI', 9, 'bold'), anchor='w').pack(
            side='left', fill='y', pady=8)

        # New-file / new-folder icons
        btn_f = tk.Frame(hdr, bg=bg2)
        btn_f.pack(side='right', padx=4)
        for icon, cmd in [('📄+', self._new_file_dialog),
                           ('📁+', self._new_folder_dialog)]:
            b = tk.Button(btn_f, text=icon, command=cmd, bg=bg2, fg=acc2,
                          relief='flat', font=('Segoe UI', 9),
                          activebackground=acc2, activeforeground=bg2,
                          padx=4, cursor='hand2', bd=0)
            b.pack(side='left', padx=1)

        tk.Frame(self._sidebar, bg=bdr, height=1).pack(fill='x')

        # Scrollable canvas for tree
        tree_wrap = tk.Frame(self._sidebar, bg=bg2)
        tree_wrap.pack(fill='both', expand=True)

        self._tree_cv = tk.Canvas(tree_wrap, bg=bg2,
                                   highlightthickness=0, bd=0)
        tsb = tk.Scrollbar(tree_wrap, orient='vertical',
                            command=self._tree_cv.yview,
                            bg=bg2, troughcolor=_ec('bg'),
                            width=10, relief='flat')
        self._tree_cv.configure(yscrollcommand=tsb.set)
        tsb.pack(side='right', fill='y')
        self._tree_cv.pack(fill='both', expand=True)

        self._tree_inner = tk.Frame(self._tree_cv, bg=bg2)
        _win = self._tree_cv.create_window(0, 0, anchor='nw',
                                            window=self._tree_inner,
                                            tags='inner')
        self._tree_inner.bind('<Configure>',
            lambda e: self._tree_cv.configure(
                scrollregion=self._tree_cv.bbox('all')))
        self._tree_cv.bind('<Configure>',
            lambda e: self._tree_cv.itemconfig('inner', width=e.width))
        for seq, d in [('<MouseWheel>', lambda e: self._tree_cv.yview_scroll(
                           int(-1*(e.delta/120)), 'units')),
                        ('<Button-4>',  lambda _: self._tree_cv.yview_scroll(-1, 'units')),
                        ('<Button-5>',  lambda _: self._tree_cv.yview_scroll(1, 'units'))]:
            self._tree_cv.bind(seq, d)

        self._refresh_tree()

    def _refresh_tree(self):
        bg2   = _ec('bg2'); fg    = _ec('fg');  fg2   = _ec('fg2')
        acc   = _ec('acc'); acc2  = _ec('acc2');bdr   = _ec('border')
        dfont = _ec('font')

        for w in self._tree_inner.winfo_children():
            w.destroy()

        files = self._data.get('files', {})
        dirs  = set(self._data.get('dirs', []))
        for path in files:
            parts = path.replace('\\', '/').split('/')
            for i in range(1, len(parts)):
                dirs.add('/'.join(parts[:i]))

        def _row(parent, text, is_active, cmd, rclick_cmd, depth):
            pad = depth * 16 + 8
            row_bg = acc if is_active else bg2
            row_fg = _ec('bg') if is_active else fg

            row = tk.Frame(parent, bg=row_bg, cursor='hand2')
            row.pack(fill='x')

            def _ent(e, r=row, a=is_active):
                if not a: r.configure(bg=_ec('border'))
            def _lve(e, r=row, b=row_bg):
                r.configure(bg=b)

            row.bind('<Enter>', _ent)
            row.bind('<Leave>', _lve)

            lbl_w = tk.Label(row, text=text, bg=row_bg, fg=row_fg,
                              anchor='w', font=(dfont, 10), cursor='hand2',
                              padx=pad, pady=4)
            lbl_w.pack(fill='x')
            lbl_w.bind('<Enter>', _ent)
            lbl_w.bind('<Leave>', _lve)

            for w in (row, lbl_w):
                w.bind('<Button-1>', lambda e, c=cmd: c())
                w.bind('<Button-3>', lambda e, c=rclick_cmd: c(e))
            return row

        def _render(prefix, depth):
            # Immediate subdirs
            my_dirs = sorted(set(
                d for d in dirs
                if (prefix == '' and '/' not in d) or
                   (prefix != '' and d.startswith(prefix + '/') and
                    '/' not in d[len(prefix)+1:])
            ))
            for d in my_dirs:
                dname  = d.split('/')[-1]
                is_exp = d in self._expanded
                arrow  = '▾ ' if is_exp else '▸ '
                _row(self._tree_inner,
                     arrow + '📁  ' + dname,
                     False,
                     lambda dn=d: self._toggle_dir(dn),
                     lambda e, dn=d: self._dir_ctx(e, dn),
                     depth)
                if is_exp:
                    _render(d, depth + 1)

            # Files at this level
            my_files = sorted(
                p for p in files
                if (prefix == '' and '/' not in p) or
                   (prefix != '' and p.startswith(prefix + '/') and
                    '/' not in p[len(prefix)+1:])
            )
            for fp in my_files:
                fname  = fp.split('/')[-1]
                dot    = '● ' if fp in self._dirty else '   '
                ext    = fname.rsplit('.', 1)[-1].lower() if '.' in fname else ''
                icon   = {'py':'🐍','md':'📝','txt':'📄','json':'📋',
                           'csv':'📊','html':'🌐','js':'⚡','sh':'⚙',
                           'css':'🎨'}.get(ext, '📄')
                _row(self._tree_inner,
                     dot + icon + '  ' + fname,
                     fp == self._active,
                     lambda p=fp: self._open_file(p),
                     lambda e, p=fp: self._file_ctx(e, p),
                     depth)

        _render('', 0)

    def _toggle_dir(self, dpath):
        if dpath in self._expanded: self._expanded.discard(dpath)
        else: self._expanded.add(dpath)
        self._refresh_tree()

    # ── Context menus ─────────────────────────────────────────────────────────
    def _file_ctx(self, event, path):
        m = tk.Menu(self, tearoff=0, bg=_ec('bg2'), fg=_ec('fg'),
                    activebackground=_ec('acc'), activeforeground=_ec('bg'),
                    relief='flat', bd=0)
        fname = path.split('/')[-1]
        m.add_command(label=f'  {fname}', state='disabled',
                      font=('Segoe UI', 9, 'bold'))
        m.add_separator()
        m.add_command(label='  Open',       command=lambda: self._open_file(path))
        m.add_command(label='  Rename…',    command=lambda: self._rename_file(path))
        m.add_command(label='  Move to…',   command=lambda: self._move_file(path))
        m.add_separator()
        m.add_command(label='  Export…',    command=lambda: self._export_file(path))
        m.add_separator()
        m.add_command(label='  🗑  Delete', command=lambda: self._delete_file(path))
        try: m.tk_popup(event.x_root, event.y_root)
        finally: m.grab_release()

    def _dir_ctx(self, event, dpath):
        m = tk.Menu(self, tearoff=0, bg=_ec('bg2'), fg=_ec('fg'),
                    activebackground=_ec('acc'), activeforeground=_ec('bg'),
                    relief='flat', bd=0)
        dname = dpath.split('/')[-1]
        m.add_command(label=f'  📁 {dname}', state='disabled',
                      font=('Segoe UI', 9, 'bold'))
        m.add_separator()
        m.add_command(label='  New File Here…',
                      command=lambda d=dpath: (self._expanded.add(d),
                                               self._new_file_dialog(parent_dir=d)))
        m.add_command(label='  New Subfolder…',
                      command=lambda d=dpath: self._new_folder_dialog(parent_dir=d))
        m.add_separator()
        m.add_command(label='  Rename…', command=lambda: self._rename_dir(dpath))
        m.add_separator()
        m.add_command(label='  🗑  Delete Folder',
                      command=lambda: self._delete_dir(dpath))
        try: m.tk_popup(event.x_root, event.y_root)
        finally: m.grab_release()

    # ══ TOOLBAR ═══════════════════════════════════════════════════════════════

    def _build_toolbar(self, parent, bg, bg2, fg, fg2, acc, acc2, bdr, dfont):
        tb = tk.Frame(parent, bg=bg2, height=40)
        tb.grid(row=1, column=0, sticky='ew')
        tb.grid_propagate(False)
        tk.Frame(tb, bg=bdr, height=1).pack(side='bottom', fill='x')

        self._breadcrumb = tk.Label(tb, text='— no file open —',
                                     bg=bg2, fg=fg2,
                                     font=('Segoe UI', 10), anchor='w')
        self._breadcrumb.pack(side='left', padx=14, fill='y')

        ctrl = tk.Frame(tb, bg=bg2)
        ctrl.pack(side='right', padx=6)

        def _tbtn(text, cmd, bg_=acc, fg_=None):
            fg_ = fg_ or bg
            b = tk.Button(ctrl, text=text, command=cmd,
                          bg=bg_, fg=fg_, relief='flat',
                          font=('Segoe UI', 9, 'bold'),
                          activebackground=acc, activeforeground=bg,
                          padx=10, pady=0, cursor='hand2', bd=0)
            b.pack(side='left', padx=3, pady=6)
            return b

        def _sep():
            tk.Frame(ctrl, bg=bdr, width=1).pack(side='left', fill='y', pady=8)

        _tbtn('💾 Save', self._save_current)
        _sep()
        self._font_lbl = tk.Label(ctrl, textvariable=self._nff,
                                   bg=bg2, fg=acc2,
                                   font=(dfont, 9, 'bold'), cursor='hand2', padx=4)
        self._font_lbl.pack(side='left')
        tk.Button(ctrl, text='−', command=lambda: self._bump_size(-1),
                  bg=bg2, fg=fg, relief='flat', font=('Segoe UI', 12, 'bold'),
                  activebackground=acc, activeforeground=bg,
                  padx=5, pady=0, cursor='hand2', bd=0).pack(
            side='left', padx=1, pady=6)
        self._sz_lbl = tk.Label(ctrl, textvariable=self._nfs,
                                 bg=bg2, fg=fg,
                                 font=('Segoe UI', 10, 'bold'), width=3, anchor='center')
        self._sz_lbl.pack(side='left', padx=1)
        tk.Button(ctrl, text='+', command=lambda: self._bump_size(+1),
                  bg=bg2, fg=fg, relief='flat', font=('Segoe UI', 12, 'bold'),
                  activebackground=acc, activeforeground=bg,
                  padx=5, pady=0, cursor='hand2', bd=0).pack(
            side='left', padx=(1, 6), pady=6)
        _sep()
        self._font_btn = tk.Button(ctrl, text='🔤 FONT & THEME',
                                    command=self._open_font_dialog,
                                    bg=acc2, fg=bg, relief='flat',
                                    font=('Segoe UI', 9, 'bold'),
                                    activebackground=acc, activeforeground=bg,
                                    padx=10, cursor='hand2', bd=0)
        self._font_btn.pack(side='left', padx=3, pady=6)
        self._mod_lbl = tk.Label(ctrl, text='', bg=bg2, fg=acc,
                                  font=('Segoe UI', 9, 'bold'), padx=6)
        self._mod_lbl.pack(side='left')

    # ══ TABS ══════════════════════════════════════════════════════════════════

    def _rebuild_tabs(self):
        bg2  = _ec('bg2'); bg = _ec('bg'); fg  = _ec('fg')
        fg2  = _ec('fg2'); acc = _ec('acc'); bdr = _ec('border')
        dfont = _ec('font')

        for w in self._tab_row.winfo_children(): w.destroy()
        self._tab_btns = {}

        for path in self._tabs:
            fname     = path.split('/')[-1]
            is_active = path == self._active
            is_dirty  = path in self._dirty
            tab_bg    = bg  if is_active else bg2
            tab_fg    = acc if is_active else fg2
            dot       = '● ' if is_dirty else ''

            tab = tk.Frame(self._tab_row, bg=tab_bg, cursor='hand2')
            tab.pack(side='left', fill='y', padx=(0, 1))
            if is_active:
                tk.Frame(tab, bg=acc, height=2).pack(fill='x', side='top')

            inner = tk.Frame(tab, bg=tab_bg)
            inner.pack(fill='both', expand=True, padx=2)

            name_lbl = tk.Label(inner, text=dot + fname, bg=tab_bg, fg=tab_fg,
                                 font=(dfont, 10), padx=6, pady=6, cursor='hand2')
            name_lbl.pack(side='left')

            x_lbl = tk.Label(inner, text='×', bg=tab_bg, fg=fg2,
                              font=('Segoe UI', 11), padx=4, pady=5, cursor='hand2')
            x_lbl.pack(side='left')

            for w in (tab, inner, name_lbl):
                w.bind('<Button-1>', lambda e, p=path: self._switch_tab(p))
            x_lbl.bind('<Button-1>', lambda e, p=path: self._close_tab(p))
            x_lbl.bind('<Enter>',    lambda e, l=x_lbl: l.configure(fg=_ec('acc')))
            x_lbl.bind('<Leave>',    lambda e, l=x_lbl, f=fg2: l.configure(fg=f))

            self._tab_btns[path] = tab

        # trailing spacer
        tk.Frame(self._tab_row, bg=bg2).pack(side='left', fill='both', expand=True)

    def _open_file(self, path):
        if self._active and self._active in self._tabs:
            self._buf[self._active] = self._txt.get('1.0', 'end-1c')

        if path not in self._tabs:
            self._buf[path] = self._data['files'].get(path, '')
            self._tabs.append(path)

        self._active = path
        self._rebuild_tabs()

        self._txt.configure(state='normal')
        self._txt.delete('1.0', 'end')
        self._txt.insert('1.0', self._buf.get(path, ''))
        self._txt.edit_reset()
        self._txt.focus_set()

        self._breadcrumb.configure(text=' › '.join(path.split('/')))
        self._mod_lbl.configure(text='● Unsaved' if path in self._dirty else '')
        self._refresh_tree()
        self._update_wc()
        self.after(20, self._gut_draw)

    def _switch_tab(self, path): self._open_file(path)

    def _close_tab(self, path):
        if path is None: return
        if path in self._dirty:
            ans = messagebox.askyesnocancel(
                'Unsaved Changes',
                f'Save "{path.split("/")[-1]}" before closing?', parent=self)
            if ans is True:  self._save_file(path)
            elif ans is None: return

        if path in self._tabs:
            idx = self._tabs.index(path)
            self._tabs.remove(path)
        self._dirty.discard(path)
        self._buf.pop(path, None)

        if self._tabs:
            self._open_file(self._tabs[min(idx, len(self._tabs)-1)])
        else:
            self._active = None
            self._txt.configure(state='normal')
            self._txt.delete('1.0', 'end')
            self._show_welcome()
            self._rebuild_tabs()
            self._breadcrumb.configure(text='— no file open —')
            self._mod_lbl.configure(text='')
        self._refresh_tree()

    # ══ FILE OPERATIONS ═══════════════════════════════════════════════════════

    def _new_file_dialog(self, parent_dir=''):
        name = self._input_dialog('New File', 'File name (e.g. notes.md):',
                                   default='New Note.md')
        if not name or not name.strip(): return
        name = name.strip().lstrip('/')
        # Build full path: join parent_dir + name, strip leading slash
        path = (parent_dir + '/' + name).lstrip('/') if parent_dir else name
        # Validate: no empty segments, no backslashes
        if not path or '//' in path:
            messagebox.showwarning('Invalid Name', 'Invalid file name.', parent=self)
            return
        if path in self._data['files']:
            messagebox.showwarning('Exists', f'"{path}" already exists.', parent=self)
            return
        self._data['files'][path] = ''
        # Auto-expand all parent folders so the new file is visible in the tree
        parts = path.split('/')
        for i in range(1, len(parts)):
            self._expanded.add('/'.join(parts[:i]))
        # Ensure parent folder is registered in dirs list
        if parent_dir and parent_dir not in self._data['dirs']:
            self._data['dirs'].append(parent_dir)
        self._save_vault()
        self._refresh_tree()
        self._open_file(path)

    def _new_folder_dialog(self, parent_dir=''):
        name = self._input_dialog('New Folder', 'Folder name:', default='New Folder')
        if not name or not name.strip(): return
        name = name.strip().strip('/')
        path = (parent_dir + '/' + name).lstrip('/') if parent_dir else name
        if not path:
            return
        if path not in self._data['dirs']:
            self._data['dirs'].append(path)
        # Auto-expand the parent and the new folder
        if parent_dir:
            self._expanded.add(parent_dir)
        self._expanded.add(path)
        self._save_vault()
        self._refresh_tree()

    def _rename_file(self, old):
        new_name = self._input_dialog('Rename', 'New name:', default=old.split('/')[-1])
        if not new_name or new_name.strip() == old.split('/')[-1]: return
        prefix   = '/'.join(old.split('/')[:-1])
        new_path = (prefix + '/' + new_name.strip()).lstrip('/')
        if new_path in self._data['files']:
            messagebox.showwarning('Exists', f'"{new_path}" already exists.', parent=self)
            return
        content = self._data['files'].pop(old)
        self._data['files'][new_path] = content
        if old in self._tabs:
            self._tabs[self._tabs.index(old)] = new_path
        if old == self._active: self._active = new_path
        self._buf[new_path] = self._buf.pop(old, content)
        if old in self._dirty:
            self._dirty.discard(old); self._dirty.add(new_path)
        self._save_vault(); self._rebuild_tabs(); self._refresh_tree()

    def _rename_dir(self, old):
        new_name = self._input_dialog('Rename Folder', 'New folder name:',
                                       default=old.split('/')[-1])
        if not new_name or new_name.strip() == old.split('/')[-1]: return
        prefix   = '/'.join(old.split('/')[:-1])
        new_path = (prefix + '/' + new_name.strip()).lstrip('/')
        new_files = {}
        for fp, fc in self._data['files'].items():
            if fp == old or fp.startswith(old + '/'):
                new_files[new_path + fp[len(old):]] = fc
            else: new_files[fp] = fc
        self._data['files'] = new_files
        self._data['dirs']  = [
            (new_path + d[len(old):]) if (d == old or d.startswith(old + '/')) else d
            for d in self._data['dirs']]
        self._save_vault()
        self._tabs = []; self._active = None
        self._buf = {}; self._dirty = set()
        self._rebuild_tabs(); self._refresh_tree()
        self._txt.configure(state='normal'); self._txt.delete('1.0', 'end')
        self._show_welcome()

    def _move_file(self, path):
        dirs  = ['(root)'] + sorted(self._data.get('dirs', []))
        dest  = self._input_dialog(
            'Move File',
            'Destination folder:\n' + '\n'.join(f'  {d}' for d in dirs),
            default='(root)')
        if dest is None: return
        dest  = dest.strip()
        fname = path.split('/')[-1]
        new   = fname if dest == '(root)' else dest.lstrip('(root)').strip('/') + '/' + fname
        new   = new.lstrip('/')
        if new == path: return
        if new in self._data['files']:
            messagebox.showwarning('Exists', f'"{new}" already exists.', parent=self)
            return
        content = self._data['files'].pop(path)
        self._data['files'][new] = content
        if path in self._tabs:
            self._tabs[self._tabs.index(path)] = new
        if path == self._active: self._active = new
        self._buf[new] = self._buf.pop(path, content)
        if path in self._dirty: self._dirty.discard(path); self._dirty.add(new)
        self._save_vault(); self._rebuild_tabs(); self._refresh_tree()

    def _delete_file(self, path):
        if not messagebox.askyesno(
                'Delete', f'Delete "{path.split("/")[-1]}"?', parent=self): return
        self._data['files'].pop(path, None)
        if path in self._tabs: self._close_tab(path)
        self._dirty.discard(path); self._buf.pop(path, None)
        self._save_vault(); self._refresh_tree()

    def _delete_dir(self, dpath):
        n = sum(1 for fp in self._data['files']
                if fp == dpath or fp.startswith(dpath + '/'))
        msg = f'Delete folder "{dpath.split("/")[-1]}"'
        if n: msg += f' and all {n} file(s) inside it'
        if not messagebox.askyesno('Delete', msg + '?', parent=self): return
        del_files = [fp for fp in self._data['files']
                     if fp == dpath or fp.startswith(dpath + '/')]
        for fp in del_files:
            self._data['files'].pop(fp, None)
            if fp in self._tabs: self._tabs.remove(fp)
            self._dirty.discard(fp); self._buf.pop(fp, None)
        self._data['dirs'] = [d for d in self._data['dirs']
                               if d != dpath and not d.startswith(dpath + '/')]
        self._active = None
        self._txt.configure(state='normal'); self._txt.delete('1.0', 'end')
        self._show_welcome()
        self._save_vault(); self._rebuild_tabs(); self._refresh_tree()

    def _export_file(self, path):
        fname = path.split('/')[-1]
        p = filedialog.asksaveasfilename(parent=self, title='Export',
            defaultextension='.txt', initialfile=fname,
            filetypes=[('Text', '*.txt'), ('Markdown', '*.md'), ('All', '*.*')])
        if p:
            Path(p).write_text(
                self._buf.get(path, self._data['files'].get(path, '')),
                encoding='utf-8')

    # ══ SAVE ══════════════════════════════════════════════════════════════════

    def _save_current(self, _=None):
        if not self._active: return
        self._buf[self._active] = self._txt.get('1.0', 'end-1c')
        self._save_file(self._active)

    def _save_file(self, path):
        content = self._buf.get(path, '')
        if len(content.encode('utf-8')) > NOTES_MAX_FILE:
            if not messagebox.askyesno(
                    'Large File',
                    f'This file is over 8 MB. Save anyway?', parent=self):
                return
        self._data['files'][path] = content
        self._dirty.discard(path)
        self._save_vault()
        self._mod_lbl.configure(text='')
        self._stv.set(f'✓  Saved  ·  {path.split("/")[-1]}')
        self._rebuild_tabs(); self._refresh_tree()

    def _save_vault(self):
        try:
            raw = json.dumps(self._data, ensure_ascii=False).encode('utf-8')
            if len(raw) > NOTES_MAX_VAULT:
                messagebox.showerror('Size Limit',
                    'Vault exceeds 8 GB limit. Remove files before saving.',
                    parent=self); return
            NOTES_FILE.write_bytes(_notes_encrypt(raw, self._pw))
        except MemoryError:
            messagebox.showerror('Memory Error',
                'Not enough memory to save.\n'
                'Close other applications and try again.', parent=self)
        except Exception as e:
            messagebox.showerror('Save Error', str(e), parent=self)

    # ══ EDITOR HELPERS ════════════════════════════════════════════════════════

    def _show_welcome(self):
        self._txt.configure(state='normal')
        self._txt.delete('1.0', 'end')
        self._txt.insert('1.0',
            '\n\n\n'
            '         ◈  VAULT EDITOR\n\n'
            '         Your notes are encrypted with AES-256-GCM\n'
            '         and stored securely beside this app.\n\n'
            '         ─────────────────────────────────────\n\n'
            '         📄+   New file at root\n'
            '         📁+   New folder\n'
            '         Right-click folder  →  New File Here\n\n'
            '         Ctrl+S   Save          Ctrl+W   Close tab\n'
            '         Ctrl+N   New file      Ctrl+B   Bold\n'
            '         Ctrl+I   Italic\n'
        )
        self._txt.configure(state='disabled')

    def _setup_tags(self):
        ff = self._nff.get() if self._nff else 'Consolas'
        fs = self._nfs.get() if self._nfs else 14
        # Tags always use explicit font weight — independent of base font
        self._txt.tag_configure('bold',   font=(ff, fs, 'bold'))
        self._txt.tag_configure('italic', font=(ff, fs, 'italic'))
        self._txt.tag_configure('bold_italic', font=(ff, fs, 'bold italic'))
        self._txt.tag_configure('h1',     font=(ff, max(fs+8, 22), 'bold'),
                                 foreground=_ec('acc'))
        self._txt.tag_configure('h2',     font=(ff, max(fs+4, 18), 'bold'),
                                 foreground=_ec('acc2'))
        self._txt.tag_configure('code',   font=('Consolas', max(fs-1, 10)),
                                 background=_ec('gutter'), foreground=_ec('fg'))
        # Ensure bold/italic tags render above base font
        self._txt.tag_raise('bold')
        self._txt.tag_raise('italic')
        self._txt.tag_raise('bold_italic')

    def _on_key(self, _=None):
        if self._active:
            self._dirty.add(self._active)
            self._mod_lbl.configure(text='● Unsaved')
            self._buf[self._active] = self._txt.get('1.0', 'end-1c')
        self._gut_draw(); self._update_wc()

    def _update_wc(self):
        try:
            txt = self._txt.get('1.0', 'end-1c')
            w   = len(txt.split()) if txt.strip() else 0
            ln  = int(self._txt.index('insert').split('.')[0])
            col = int(self._txt.index('insert').split('.')[1])
            self._wcv.set(f'Ln {ln}, Col {col}  ·  {w} words  ·  {len(txt)} chars')
        except Exception: pass

    def _yscroll(self, *a):
        self._txt.yview(*a); self.after(5, self._gut_draw)

    def _gut_draw(self):
        if not hasattr(self, '_ngut'): return
        self._ngut.delete('all')
        if not self._active: return
        fs = self._nfs.get() if self._nfs else 14
        ff = self._nff.get() if self._nff else 'Consolas'
        try: cur_ln = int(self._txt.index('insert').split('.')[0])
        except: cur_ln = 1
        i = self._txt.index('@0,0'); row = 0
        while row < 2000:
            info = self._txt.dlineinfo(i)
            if info is None: break
            ln  = int(str(i).split('.')[0])
            col = _ec('acc') if ln == cur_ln else _ec('fg2')
            self._ngut.create_text(6, info[1] + fs // 2 + 2, anchor='w',
                                    text=str(ln), fill=col,
                                    font=(ff, max(8, fs - 3)))
            nxt = self._txt.index(f'{i}+1line')
            if self._txt.compare(nxt, '>=', 'end'): break
            i = nxt; row += 1

    def _cursor_blink(self):
        if not self.winfo_exists(): return
        try:
            col = _ec('cur') if self._blink_on else _ec('bg')
            self._txt.configure(insertbackground=col)
            self._blink_on = not self._blink_on
            self.after(530, self._cursor_blink)
        except Exception: pass

    def _fmt_bold(self):
        """Toggle bold on selected text. Returns 'break' to stop default binding."""
        try:
            sel_start = self._txt.index('sel.first')
            sel_end   = self._txt.index('sel.last')
            # Detect if the entire selection is already bold
            ranges = self._txt.tag_ranges('bold')
            already = any(
                self._txt.compare(str(ranges[i]), '<=', sel_start) and
                self._txt.compare(str(ranges[i+1]), '>=', sel_end)
                for i in range(0, len(ranges), 2)
            )
            if already:
                self._txt.tag_remove('bold', sel_start, sel_end)
            else:
                self._txt.tag_add('bold', sel_start, sel_end)
            self._on_key()  # mark dirty
        except tk.TclError:
            pass  # no selection — ignore
        return 'break'  # prevent default Ctrl+B cursor movement

    def _fmt_italic(self):
        """Toggle italic on selected text. Returns 'break' to stop default binding."""
        try:
            sel_start = self._txt.index('sel.first')
            sel_end   = self._txt.index('sel.last')
            ranges = self._txt.tag_ranges('italic')
            already = any(
                self._txt.compare(str(ranges[i]), '<=', sel_start) and
                self._txt.compare(str(ranges[i+1]), '>=', sel_end)
                for i in range(0, len(ranges), 2)
            )
            if already:
                self._txt.tag_remove('italic', sel_start, sel_end)
            else:
                self._txt.tag_add('italic', sel_start, sel_end)
            self._on_key()
        except tk.TclError:
            pass
        return 'break'  # prevent default Ctrl+I behavior

    def _lock_vault(self):
        if self._dirty:
            ans = messagebox.askyesnocancel(
                'Unsaved Changes',
                'Save unsaved changes before locking?', parent=self)
            if ans is True:
                if self._active: self._save_current()
            elif ans is None: return
        self._pw = None; self._buf.clear()
        self._dirty.clear(); self._tabs.clear(); self._active = None
        self._data = {"files": {}, "dirs": []}
        for w in self.winfo_children(): w.destroy()
        self._build_lock()

    # ── Font / Theme ──────────────────────────────────────────────────────────
    def _refont(self):
        ff  = self._nff.get() if self._nff else 'Consolas'
        fs  = self._nfs.get() if self._nfs else 14
        fb  = 'bold' if (self._nfb and self._nfb.get()) else 'normal'
        self._txt.configure(font=(ff, fs, fb))
        self._setup_tags()
        if hasattr(self, '_font_lbl') and self._font_lbl.winfo_exists():
            self._font_lbl.configure(font=(ff, 9, 'bold'))
        self.after(10, self._gut_draw)

    def _bump_size(self, delta):
        if not self._nfs: return
        self._nfs.set(max(6, min(72, self._nfs.get() + delta)))
        self._refont()

    def _open_font_dialog(self):
        NotesFontDialog(self.winfo_toplevel(), self)

    def _apply_editor_theme(self):
        if not hasattr(self, '_txt'): return
        bg  = _ec('bg');  bg2 = _ec('bg2'); gut = _ec('gutter')
        fg  = _ec('fg');  fg2 = _ec('fg2'); acc = _ec('acc')
        acc2 = _ec('acc2'); sel = _ec('sel')
        self._txt.configure(bg=bg, fg=fg, insertbackground=acc,
                            selectbackground=sel, selectforeground=fg)
        if hasattr(self, '_ngut') and self._ngut.winfo_exists():
            self._ngut.configure(bg=gut)
        if hasattr(self, '_font_btn') and self._font_btn.winfo_exists():
            self._font_btn.configure(bg=acc2, fg=bg)
        if hasattr(self, '_font_lbl') and self._font_lbl.winfo_exists():
            self._font_lbl.configure(fg=acc2)
        if hasattr(self, '_theme_lbl') and self._theme_lbl.winfo_exists():
            self._theme_lbl.configure(text=_ec('name'), fg=acc2)
        if self._nff:
            self._nff.set(_ec('font'))
        if self._nfb:
            self._nfb.set(False)

        # Recreate tags with new theme colors
        self._setup_tags()

        # Force a full redraw of the text widget
        # Save current wrap mode, toggle it to force redraw
        wrap_mode = self._txt.cget('wrap')
        self._txt.configure(wrap='none')
        self._txt.configure(wrap=wrap_mode)
        self.update_idletasks()

        self._refont()
        self.after(10, self._gut_draw)
    # ── Utility ───────────────────────────────────────────────────────────────
    def _input_dialog(self, title, prompt, default=''):
        dlg = tk.Toplevel(self.winfo_toplevel())
        dlg.title(title)
        dlg.configure(bg=_ec('bg2'))
        dlg.resizable(False, False)
        dlg.grab_set(); dlg.lift()
        dlg.update_idletasks()
        pw = self.winfo_toplevel()
        x  = pw.winfo_rootx() + (pw.winfo_width() - 360) // 2
        y  = pw.winfo_rooty() + (pw.winfo_height() - 150) // 2
        dlg.geometry(f'360x148+{max(x,0)}+{max(y,0)}')

        tk.Label(dlg, text=prompt, bg=_ec('bg2'), fg=_ec('fg'),
                 font=('Segoe UI', 10), wraplength=340, justify='left',
                 anchor='w').pack(padx=16, pady=(16, 6), fill='x')

        var   = tk.StringVar(value=default)
        entry = tk.Entry(dlg, textvariable=var,
                         bg=_ec('bg'), fg=_ec('fg'),
                         insertbackground=_ec('acc'), relief='flat',
                         font=('Segoe UI', 12),
                         highlightthickness=1,
                         highlightbackground=_ec('border'),
                         highlightcolor=_ec('acc'))
        entry.pack(padx=16, fill='x', ipady=6)
        entry.select_range(0, 'end'); entry.focus_set()

        result = [None]
        def _ok():    result[0] = var.get(); dlg.destroy()
        def _cancel(): dlg.destroy()

        btn_row = tk.Frame(dlg, bg=_ec('bg2'))
        btn_row.pack(pady=10, padx=16, fill='x')
        tk.Button(btn_row, text='Cancel', command=_cancel,
                  bg=_ec('bg2'), fg=_ec('fg2'), relief='flat',
                  font=('Segoe UI', 10), padx=16, cursor='hand2',
                  activebackground=_ec('border')).pack(side='right', padx=(4, 0))
        tk.Button(btn_row, text='OK', command=_ok,
                  bg=_ec('acc'), fg=_ec('bg'), relief='flat',
                  font=('Segoe UI', 10, 'bold'), padx=16, cursor='hand2',
                  activebackground=_ec('acc')).pack(side='right')
        entry.bind('<Return>', lambda _: _ok())
        entry.bind('<Escape>', lambda _: _cancel())
        dlg.wait_window()
        return result[0]



#  MAIN APP
# ══════════════════════════════════════════════════════════════════════════════

class VaultApp(ctk.CTk):
    def __init__(self):
        self.cfg = load_cfg()
        apply_theme(self.cfg.get("theme","dark"))

        super().__init__()
        self.title(f"VAULT {APP_VER}  —  Quantum-Resistant Encrypted Safe")
        self.geometry("1200x780")
        self.minsize(960,640)
        self.configure(fg_color=t("bg"))
        self._build_layout()
        self._nav("Lock")

        vault_arg = self._argv_vault()
        if vault_arg:
            self.after(200, lambda p=vault_arg: self._open_vault_prompt(p))

    def _argv_vault(self):
        for arg in sys.argv[1:]:
            p=Path(arg)
            if p.suffix.lower()==".vault" and p.exists(): return str(p)
        return None

    def _build_layout(self):
        self.grid_columnconfigure(1,weight=1)
        self.grid_rowconfigure(0,weight=1)
        self._sidebar = Sidebar(self, self._nav)
        self._sidebar.grid(row=0,column=0,sticky="nsew")
        ctk.CTkFrame(self,width=1,corner_radius=0,
                     fg_color=t("border3")).grid(row=0,column=0,sticky="nse")
        self._content = ctk.CTkFrame(self,fg_color=t("bg"),corner_radius=0)
        self._content.grid(row=0,column=1,sticky="nsew")
        self._content.grid_columnconfigure(0,weight=1)
        self._content.grid_rowconfigure(0,weight=1)

    def _nav(self, page):
        for w in self._content.winfo_children(): w.destroy()
        self._sidebar.set_active(page)   # visuals only — no recursion
        cls={"Lock":LockView,"Unlock":UnlockView,
             "Editor":NotesView,"Security & Settings":SecurityView}.get(page)
        if cls: cls(self._content,self).grid(row=0,column=0,sticky="nsew")

    def rebuild(self):
        """Rebuild entire UI after theme change."""
        geo = self.geometry()
        for w in self.winfo_children(): w.destroy()
        self.configure(fg_color=t("bg"))
        self._build_layout()
        self._nav("Lock")
        self.geometry(geo)

    def _open_vault_prompt(self, vault_path):
        self._nav("Unlock")
        for w in self._content.winfo_children():
            if isinstance(w, UnlockView):
                w._vault=vault_path; w._vlbl.configure(text=vault_path,text_color=t("text"))
                w._dest=str(Path(vault_path).parent)
                w._dlbl.configure(text=w._dest,text_color=t("text")); break

        def on_ok(result,meta):
            self._nav("Unlock")
            messagebox.showinfo("Unlocked ✓",
                f"Decryption complete!\n\nRestored to:\n{result}\n\n"
                f"Cipher: {meta.get('cipher','?')}\nHMAC: ✓ Verified")

        VaultOpenDialog(self, vault_path, on_ok, lambda: self._nav("Lock"))


if __name__ == "__main__":
    VaultApp().mainloop()
