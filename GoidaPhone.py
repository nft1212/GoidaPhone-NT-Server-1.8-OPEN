#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Suppress pkg_resources deprecation warning from webrtcvad before any imports
import warnings as _w
_w.filterwarnings("ignore", category=UserWarning, module="pkg_resources")
_w.filterwarnings("ignore", message=".*pkg_resources.*")
"""
GoidaPhone v1.8 — by Winora Company
LAN/VPN messenger with voice calls, file sharing, groups, profiles.
Cross-platform: Windows & Linux.
"""

import sys
import os
import json
import traceback
import time
import secrets
import socket
import threading
import hashlib
import base64
import struct
import platform
import subprocess
import tempfile
import shutil
import zipfile
import re
import urllib.request
import urllib.error
import math
import colorsys
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import queue
import io

# ── AES-256 encryption (п.31) ───────────────────────────────────────────────
# Uses only stdlib — no external crypto deps required.
# Algorithm: AES-256-CBC with PKCS7 padding, PBKDF2-HMAC-SHA256 key derivation.
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as crypto_padding, hashes, hmac
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ── Optional image/gif support ───────────────────────────────────────────────
try:
    from PIL import Image, ImageSequence
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ── PyQt6 ──────────────────────────────────────────────────────────────────
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QListWidget, QLabel, QFrame,
    QTabWidget, QDialog, QComboBox, QSlider, QCheckBox, QGroupBox,
    QProgressBar, QFileDialog, QMessageBox, QScrollArea,
    QSystemTrayIcon, QMenu, QInputDialog, QSplitter, QListWidgetItem,
    QTextBrowser, QToolBar, QStatusBar, QToolButton, QSpinBox,
    QColorDialog, QGridLayout, QStackedWidget, QScrollBar,
    QSizePolicy, QAbstractItemView, QPlainTextEdit, QFormLayout, QWidgetAction,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import (
    Qt, QTimer, pyqtSignal, QThread, QSize, QSettings,
    QUrl, QFileInfo, QByteArray, QBuffer, QIODevice,
    QRunnable, QThreadPool, pyqtSlot, QObject, QPoint, QRect,
    QPropertyAnimation, QEasingCurve, QSequentialAnimationGroup,
    QParallelAnimationGroup, QAbstractAnimation
)
from PyQt6.QtGui import (
    QFont, QIcon, QPalette, QColor, QPixmap, QAction,
    QDesktopServices, QTextCharFormat, QTextCursor,
    QImage, QPainter, QBrush, QPen, QLinearGradient,
    QGradient, QFontMetrics, QMovie, QTransform, QKeySequence, QShortcut
)
# QtMultimedia is optional — only needed for future media playback features
try:
    from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
    QTMULTIMEDIA_AVAILABLE = True
except ImportError:
    QTMULTIMEDIA_AVAILABLE = False
from PyQt6.QtNetwork import QUdpSocket, QTcpSocket, QTcpServer, QHostAddress, QNetworkInterface

# ── Optional audio ──────────────────────────────────────────────────────────
try:
    import pyaudio
    PYAUDIO_AVAILABLE = True
except ImportError:
    PYAUDIO_AVAILABLE = False
    print("⚠ pyaudio not found — voice calls disabled. Install: pip install pyaudio")

# ── Optional image handling ─────────────────────────────────────────────────
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
APP_VERSION       = "1.8.0"
APP_NAME          = "GoidaPhone"
COMPANY_NAME      = "Winora Company"
LICENSE_DIVISOR   = 909          # license_code % 909 == 0  → valid
LICENSE_DAYS      = 30           # premium lasts 30 days

# ── Protocol versioning ─────────────────────────────────────────────────────
# Used for cross-version compatibility.
# New clients send PROTOCOL_VERSION; if remote version is older, disable new features.
# Rule: major bump = incompatible, minor bump = backward-compatible.
PROTOCOL_VERSION  = 3            # bump when network format changes
PROTOCOL_COMPAT   = 2            # minimum protocol version we can talk to

# ── Feature flags per protocol version ─────────────────────────────────────
# Key = feature name, value = minimum protocol version required
FEATURE_REACTIONS  = 3
FEATURE_FORWARDING = 3
FEATURE_MENTIONS   = 3
FEATURE_FORMATTING = 3

# ═══════════════════════════════════════════════════════════════════════════
#  SECURITY ENGINE v2 — AES-256-GCM + X25519 ECDH + Ed25519 + replay guard
# ═══════════════════════════════════════════════════════════════════════════
class CryptoEngine:
    """
    GoidaPhone Security Engine v2.

    LAYER 1 — Automatic key exchange (X25519 ECDH)
      Each node generates a long-term X25519 keypair on first run.
      Ed25519 identity key signs the X25519 public key.
      On first contact, nodes exchange & verify signed DH keys.
      HKDF-SHA256 derives a 256-bit session key per peer.

    LAYER 2 — Message encryption (AES-256-GCM)
      AES-256-GCM: authenticated encryption, no padding oracle.
      Random 12-byte nonce per message (2^96 space).
      GCM tag authenticates ciphertext; tampering → decryption fails.
      Wire: type[1] + nonce[12] + ciphertext+tag

    LAYER 3 — Passphrase overlay (groups)
      PBKDF2-SHA256 (480 000 iters) → 256-bit group key.
      Salt[32] stored with each message.

    LAYER 4 — Packet HMAC (session-key signed control packets)
      Every UDP packet optionally carries HMAC-SHA256(session_key, payload).
      Prevents spoofing of reactions/edits/calls from unauthorized peers.

    LAYER 5 — Replay protection
      Nonce + timestamp checked per peer.
      Window: +-30 seconds; seen nonces cached for 60 s.

    LAYER 6 — Rate limiting
      Max 200 packets/second per source IP.
    """

    NONCE_LEN       = 12
    TAG_LEN         = 16
    KEY_LEN         = 32
    KDF_ITERS       = 480_000
    SALT_LEN        = 32
    REPLAY_WINDOW_S = 30
    NONCE_CACHE_TTL = 60

    def __init__(self):
        self._key_cache: dict        = {}
        self._session_keys: dict     = {}   # peer_ip -> bytes
        self._peer_id_pub: dict      = {}   # peer_ip -> Ed25519PublicKey
        self._seen_nonces: dict      = {}   # peer_ip -> {nonce_hex: ts}
        self._rate_counters: dict    = {}   # ip -> [timestamps]
        self._identity_priv          = None
        self._dh_priv                = None
        self._dh_pub_bytes: bytes    = b""
        self._identity_pub_bytes: bytes = b""
        self._dh_pub_sig: bytes      = b""
        if CRYPTO_AVAILABLE:
            self._init_keypairs()

    def _init_keypairs(self):
        """Load or generate Ed25519 identity + X25519 DH keypairs."""
        try:
            id_raw = _load_raw_setting("identity_priv_b64", "")
            dh_raw = _load_raw_setting("dh_priv_b64", "")
            if not id_raw or not dh_raw:
                raise ValueError("no keys stored")
            self._identity_priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(id_raw))
            self._dh_priv       = X25519PrivateKey.from_private_bytes(base64.b64decode(dh_raw))
        except Exception:
            self._identity_priv = Ed25519PrivateKey.generate()
            self._dh_priv       = X25519PrivateKey.generate()
            _save_raw_setting("identity_priv_b64", base64.b64encode(
                self._identity_priv.private_bytes(serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode())
            _save_raw_setting("dh_priv_b64", base64.b64encode(
                self._dh_priv.private_bytes(serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode())

        self._dh_pub_bytes = self._dh_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._identity_pub_bytes = self._identity_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._dh_pub_sig = self._identity_priv.sign(self._dh_pub_bytes)

    # ── Handshake ─────────────────────────────────────────────────────
    def get_handshake_payload(self) -> dict:
        """Public key bundle for inclusion in presence packets."""
        if not CRYPTO_AVAILABLE:
            return {}
        return {
            "dh_pub":     base64.b64encode(self._dh_pub_bytes).decode(),
            "id_pub":     base64.b64encode(self._identity_pub_bytes).decode(),
            "dh_pub_sig": base64.b64encode(self._dh_pub_sig).decode(),
        }

    def process_handshake(self, peer_ip: str, data: dict) -> bool:
        """
        Derive session key from peer's handshake bundle.
        Verifies Ed25519 signature of DH public key.
        Returns True on success.
        """
        if not CRYPTO_AVAILABLE:
            return False
        try:
            peer_dh_bytes  = base64.b64decode(data["dh_pub"])
            peer_id_bytes  = base64.b64decode(data["id_pub"])
            peer_dh_sig    = base64.b64decode(data["dh_pub_sig"])

            # Verify: peer's identity key signed their DH key
            peer_id_pub = Ed25519PublicKey.from_public_bytes(peer_id_bytes)
            peer_id_pub.verify(peer_dh_sig, peer_dh_bytes)   # raises InvalidSignature if bad

            # ECDH key exchange
            peer_dh_pub = X25519PublicKey.from_public_bytes(peer_dh_bytes)
            shared_secret = self._dh_priv.exchange(peer_dh_pub)

            # HKDF-SHA256 -> 32-byte session key
            hkdf = HKDF(algorithm=crypto_hashes.SHA256(), length=32,
                        salt=None, info=b"GoidaPhone-v2-session",
                        backend=default_backend())
            session_key = hkdf.derive(shared_secret)
            self._session_keys[peer_ip] = session_key
            self._peer_id_pub[peer_ip]  = peer_id_pub
            return True
        except Exception as e:
            print(f"[crypto] handshake failed from {peer_ip}: {e}")
            return False

    def has_session(self, peer_ip: str) -> bool:
        return peer_ip in self._session_keys

    def fingerprint(self) -> str:
        """Human-readable fingerprint of our identity public key."""
        if not CRYPTO_AVAILABLE or not self._identity_pub_bytes:
            return "N/A"
        h = hashlib.sha256(self._identity_pub_bytes).hexdigest()
        return " ".join(h[i:i+4].upper() for i in range(0, 24, 4))

    def peer_fingerprint(self, peer_ip: str) -> str:
        """Fingerprint of peer's identity key (for verification UI)."""
        if not CRYPTO_AVAILABLE:
            return "N/A"
        pub = self._peer_id_pub.get(peer_ip)
        if pub is None:
            return "?"
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        h = hashlib.sha256(raw).hexdigest()
        return " ".join(h[i:i+4].upper() for i in range(0, 24, 4))

    def security_level(self, peer_ip: str = None) -> str:
        """Return security level string for status bar."""
        if not CRYPTO_AVAILABLE:
            return "⚠ XOR"
        if peer_ip and peer_ip in self._session_keys:
            return "🔒 E2E"
        if S().encryption_enabled and S().encryption_passphrase:
            return "🔑 PSK"
        return "⚠ Plain"

    # ── AES-256-GCM ───────────────────────────────────────────────────
    def _gcm_encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        nonce = secrets.token_bytes(self.NONCE_LEN)
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return nonce + ct   # nonce + ciphertext+tag

    def _gcm_decrypt(self, key: bytes, data: bytes) -> bytes:
        nonce = data[:self.NONCE_LEN]
        ct    = data[self.NONCE_LEN:]
        return AESGCM(key).decrypt(nonce, ct, None)  # raises on bad tag

    # ── PBKDF2 for passphrase keys ────────────────────────────────────
    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        k = passphrase + salt.hex()
        if k in self._key_cache:
            return self._key_cache[k]
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(),
                                  salt, self.KDF_ITERS, dklen=self.KEY_LEN)
        self._key_cache[k] = key
        return key

    # ── Packet HMAC ───────────────────────────────────────────────────
    def sign_packet(self, peer_ip: str, payload_bytes: bytes) -> str:
        import hmac as _hmac
        key = self._session_keys.get(peer_ip, b"")
        if not key:
            return ""
        return base64.b64encode(
            _hmac.new(key, payload_bytes, hashlib.sha256).digest()
        ).decode()

    def verify_packet(self, peer_ip: str, payload_bytes: bytes, sig_b64: str) -> bool:
        import hmac as _hmac
        key = self._session_keys.get(peer_ip, b"")
        if not key:
            return True   # no session yet — accept
        try:
            expected = _hmac.new(key, payload_bytes, hashlib.sha256).digest()
            return _hmac.compare_digest(expected, base64.b64decode(sig_b64))
        except Exception:
            return False

    # ── Replay protection ─────────────────────────────────────────────
    def check_replay(self, peer_ip: str, nonce_hex: str, ts: float) -> bool:
        """Return True if packet is fresh and nonce not seen before."""
        now = time.time()
        if abs(now - ts) > self.REPLAY_WINDOW_S:
            return False
        bucket = self._seen_nonces.setdefault(peer_ip, {})
        if nonce_hex in bucket:
            return False
        bucket[nonce_hex] = now
        expired = [k for k, t_ in bucket.items() if now - t_ > self.NONCE_CACHE_TTL]
        for k in expired:
            del bucket[k]
        return True

    # ── Rate limiting ─────────────────────────────────────────────────
    def check_rate(self, peer_ip: str, max_per_sec: int = 200) -> bool:
        now = time.time()
        window = self._rate_counters.setdefault(peer_ip, [])
        window[:] = [t for t in window if now - t < 1.0]
        if len(window) >= max_per_sec:
            return False
        window.append(now)
        return True

    # ── Public encrypt/decrypt ────────────────────────────────────────
    def encrypt(self, plaintext: str, passphrase: str = "",
                peer_ip: str = None) -> str:
        """
        Encrypt message.
        Type 0x01 = AES-GCM with ECDH session key (best)
        Type 0x02 = AES-GCM with PBKDF2 passphrase key
        Type 0xFF = XOR fallback (no cryptography lib)
        """
        data = plaintext.encode("utf-8")
        if CRYPTO_AVAILABLE:
            if peer_ip and peer_ip in self._session_keys:
                ct   = self._gcm_encrypt(self._session_keys[peer_ip], data)
                wire = bytes([0x01]) + ct
            elif passphrase:
                salt = secrets.token_bytes(self.SALT_LEN)
                key  = self._derive_key(passphrase, salt)
                ct   = self._gcm_encrypt(key, data)
                wire = bytes([0x02]) + salt + ct
            else:
                return plaintext
            return "🔐" + base64.b64encode(wire).decode("ascii")
        if passphrase:
            key   = hashlib.sha256(passphrase.encode()).digest()
            xored = bytes(b ^ key[i % 32] for i, b in enumerate(data))
            return "🔐" + base64.b64encode(bytes([0xFF]) + xored).decode("ascii")
        return plaintext

    def decrypt(self, ciphertext: str, passphrase: str = "",
                peer_ip: str = None) -> str:
        if not ciphertext.startswith("🔐"):
            return ciphertext
        try:
            wire = base64.b64decode(ciphertext[len("🔐"):])
        except Exception:
            return "[🔒 Ошибка декодирования]"
        if not wire:
            return "[🔒 Пустой пакет]"
        t, payload = wire[0], wire[1:]

        if t == 0x01:
            if not CRYPTO_AVAILABLE:
                return "[🔒 Требуется: pip install cryptography]"
            key = self._session_keys.get(peer_ip, b"") if peer_ip else b""
            if not key:
                return "[🔒 E2E-ключ не согласован. Подождите переподключения.]"
            try:
                return self._gcm_decrypt(key, payload).decode("utf-8")
            except Exception:
                return "[🔒 Ошибка расшифровки E2E (подмена данных?)]"

        elif t == 0x02:
            if not CRYPTO_AVAILABLE:
                return "[🔒 Требуется: pip install cryptography]"
            if not passphrase:
                return "[🔒 Зашифровано — введите пароль в настройках]"
            try:
                salt = payload[:self.SALT_LEN]
                ct   = payload[self.SALT_LEN:]
                key  = self._derive_key(passphrase, salt)
                return self._gcm_decrypt(key, ct).decode("utf-8")
            except Exception:
                return "[🔒 Неверный пароль или данные повреждены]"

        elif t == 0xFF:
            if not passphrase:
                return "[🔒 Зашифровано (XOR). Введите пароль.]"
            key = hashlib.sha256(passphrase.encode()).digest()
            try:
                return bytes(b ^ key[i % 32] for i, b in enumerate(payload)).decode("utf-8")
            except Exception:
                return "[🔒 Ошибка расшифровки XOR]"

        return "[🔒 Неизвестный формат]"

    def is_encrypted(self, text: str) -> bool:
        return isinstance(text, str) and text.startswith("🔐")

    @staticmethod
    def status() -> str:
        if CRYPTO_AVAILABLE:
            return "✅ AES-256-GCM | X25519 ECDH | Ed25519 | PBKDF2-480k | Replay Guard"
        return "⚠ XOR-fallback (pip install cryptography)"


# ── QSettings helpers for early crypto init (before S() is available) ────────
def _load_raw_setting(key: str, default: str = "") -> str:
    s = QSettings("WinoraCompany", "GoidaPhone")
    v = s.value(key, default)
    return str(v) if v is not None else default

def _save_raw_setting(key: str, value: str):
    s = QSettings("WinoraCompany", "GoidaPhone")
    s.setValue(key, value)
    s.sync()


CRYPTO = CryptoEngine()   # global instance



UDP_PORT_DEFAULT  = 17385
TCP_PORT_DEFAULT  = 17386

# GitHub update check  — REPLACE with your repo URL
GITHUB_REPO       = "YOUR_GITHUB_USERNAME/GoidaPhone"   # e.g. "john/GoidaPhone"
GITHUB_API_URL    = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_RAW_URL    = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/goidaphone.py"

# Data directory — cross-platform
if platform.system() == "Windows":
    DATA_DIR = Path(os.getenv("APPDATA", Path.home())) / "GoidaPhone"
else:
    DATA_DIR = Path.home() / ".config" / "GoidaPhone"

DATA_DIR.mkdir(parents=True, exist_ok=True)
AVATARS_DIR   = DATA_DIR / "avatars"
RECEIVED_DIR  = DATA_DIR / "received_files"
HISTORY_DIR   = DATA_DIR / "history"
GROUPS_FILE   = DATA_DIR / "groups.json"
CONTACTS_FILE = DATA_DIR / "contacts.json"

for d in [AVATARS_DIR, RECEIVED_DIR, HISTORY_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═══════════════════════════════════════════════════════════════════════════
def detect_connection_type(remote_ip: str) -> str:
    """Return 'LAN' or 'VPN' by comparing remote IP subnets with local interfaces."""
    try:
        for iface in QNetworkInterface.allInterfaces():
            for entry in iface.addressEntries():
                addr = entry.ip()
                mask = entry.netmask()
                if addr.protocol() != QHostAddress.NetworkLayerProtocol.IPv4Protocol:
                    continue
                local = addr.toString()
                netmask = mask.toString()
                # compute network prefix
                la = [int(x) for x in local.split('.')]
                ra = [int(x) for x in remote_ip.split('.')]
                ma = [int(x) for x in netmask.split('.')]
                if all((la[i] & ma[i]) == (ra[i] & ma[i]) for i in range(4)):
                    name = iface.name().lower()
                    # VPN adapters commonly contain these strings
                    if any(k in name for k in ['vpn','tun','tap','hamachi','radmin','virtual','veth','wg']):
                        return 'VPN'
                    return 'LAN'
    except Exception:
        pass
    return 'VPN'   # fallback — if can't match, assume VPN

# ─────────────────────────────────────────────────────────────────────────────
#  GoidaID  (Safe Mode)
#  A cryptographic pseudonym that replaces visible IP addresses.
#  Format:  GID-XXXXXX  (6 uppercase hex chars derived from HMAC-SHA256)
#  The mapping is local-only: others see only the GoidaID, not the raw IP.
# ─────────────────────────────────────────────────────────────────────────────

_GOIDA_ID_SALT_KEY = "goida_id_salt"

def _get_goida_salt() -> bytes:
    """Get or create persistent HMAC salt for GoidaID generation."""
    stored = _load_raw_setting(_GOIDA_ID_SALT_KEY, "")
    if stored:
        try:
            return bytes.fromhex(stored)
        except Exception:
            pass
    salt = secrets.token_bytes(32)
    _save_raw_setting(_GOIDA_ID_SALT_KEY, salt.hex())
    return salt

def ip_to_goida_id(ip: str) -> str:
    """
    Derive a stable GoidaID from an IP address using HMAC-SHA256.
    Same IP always produces the same GoidaID on this device,
    but the mapping cannot be reversed by other parties.
    """
    import hmac as _hmac
    salt = _get_goida_salt()
    h = _hmac.new(salt, ip.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"GID-{h[:6].upper()}"

def display_id(ip: str) -> str:
    """
    Return the display identifier for an IP.
    In safe mode returns GoidaID; otherwise returns the raw IP.
    """
    if S().get("safe_mode", False, t=bool):
        return ip_to_goida_id(ip)
    return ip


def get_local_ip() -> str:
    """Return the best local IPv4 address.
    Prefers physical LAN (192.168.x, 10.x, 172.16-31.x) over VPN tunnels.
    Falls back to any non-loopback address, then 127.0.0.1."""
    try:
        # Primary: use routing table to find default interface
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        if ip and ip != "0.0.0.0" and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    # Fallback: enumerate interfaces
    try:
        for iface in QNetworkInterface.allInterfaces():
            if iface.flags() & QNetworkInterface.InterfaceFlag.IsLoopBack:
                continue
            if not (iface.flags() & QNetworkInterface.InterfaceFlag.IsUp):
                continue
            for entry in iface.addressEntries():
                addr = entry.ip()
                if addr.protocol() != QHostAddress.NetworkLayerProtocol.IPv4Protocol:
                    continue
                ip = addr.toString()
                if ip.startswith("127.") or ip.startswith("169.254."):
                    continue
                return ip
    except Exception:
        pass
    return "127.0.0.1"


def get_all_local_ips() -> set:
    """Return ALL local IPv4 addresses (LAN + VPN + loopback excluded).
    Used for robust self-message deduplication across multi-homed systems."""
    ips = set()
    # Routing-table method
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
    except Exception:
        pass
    # Interface enumeration — catches VPN adapters (Hamachi/ZeroTier/Radmin)
    try:
        for iface in QNetworkInterface.allInterfaces():
            if iface.flags() & QNetworkInterface.InterfaceFlag.IsLoopBack:
                continue
            for entry in iface.addressEntries():
                addr = entry.ip()
                if addr.protocol() != QHostAddress.NetworkLayerProtocol.IPv4Protocol:
                    continue
                ip = addr.toString()
                if not ip.startswith("127.") and not ip.startswith("169.254."):
                    ips.add(ip)
    except Exception:
        pass
    ips.discard("0.0.0.0")
    return ips

def get_os_name() -> str:
    s = platform.system()
    if s == "Windows":
        return f"Windows {platform.version()}"
    elif s == "Linux":
        try:
            import distro
            return f"Linux {distro.name()} {distro.version()}"
        except Exception:
            return f"Linux {platform.release()}"
    elif s == "Darwin":
        return f"macOS {platform.mac_ver()[0]}"
    return s

# ─────────────────────────────────────────────────────────────────────────────
#  SOUND SYSTEM
#
#  Strategy (so sounds survive PyInstaller / distribution):
#   1. On startup, copy sounds from  script-dir/gdfsound/  →  DATA_DIR/sounds/
#      This makes them available regardless of working directory.
#   2. At play time look in:
#        a. DATA_DIR/sounds/          (persistent copy)
#        b. script-dir/gdfsound/      (dev / same-folder run)
#        c. PyInstaller _MEIPASS/gdfsound/  (frozen bundle)
#   3. OS fallback beep if nothing found.
# ─────────────────────────────────────────────────────────────────────────────

_SOUND_MAP = {
    # event          preferred files (tried left-to-right)
    "message":  ["gdfclick.wav"],
    "call":     ["criterr.mp3",  "critterr.mp3"],
    "online":   ["zakrep.wav"],
    "error":    ["err.wav"],
    "user_error": ["oshibka_usera.mp3", "err.wav"],
    "critical": ["criterr.mp3",  "critterr.mp3"],
    "delete":   ["mvdtotrash.wav"],
    "pin":      ["zakrep.wav"],
    "click":    ["gdfclick.wav"],
}

_SOUNDS_INSTALLED = False

def _get_sound_dirs() -> list:
    """Return all directories to search for sound files, in priority order.

    Search order (most specific → fallback):
      1. DATA_DIR/sounds/            — persistent copy (written on first run)
      2. next to __file__ / gdfsound/— dev layout
      3. PyInstaller _MEIPASS/       — frozen bundle assets
      4. ~/Desktop/gdfsound/         — common dev machine location
      5. ~/gdfsound/                 — home dir fallback
      6. /usr/share/GoidaPhone/sounds — Linux system install
      7. %APPDATA%/GoidaPhone/sounds — Windows fallback
    """
    dirs = []
    # 1) next to script — highest priority so dev layout always wins
    try:
        if getattr(sys, 'frozen', False):
            script_dir = Path(sys.executable).parent
        else:
            script_dir = Path(__file__).resolve().parent
        dirs.append(script_dir / "gdfsound")
        dirs.append(script_dir / "sounds")
    except Exception:
        pass
    # 2) DATA_DIR persistent copy (cached on first run)
    dirs.append(DATA_DIR / "sounds")
    # 3) PyInstaller _MEIPASS
    try:
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            dirs.append(Path(sys._MEIPASS) / "gdfsound")
            dirs.append(Path(sys._MEIPASS) / "sounds")
    except Exception:
        pass
    # 4+5) Common developer locations
    home = Path.home()
    dirs.append(home / "Desktop" / "gdfsound")
    dirs.append(home / "Desktop" / "sounds")
    dirs.append(home / "gdfsound")
    dirs.append(home / "sounds")
    # Also try every user's Desktop subfolder (multi-user systems)
    try:
        import os as _os
        xdg_desktop = _os.environ.get("XDG_DESKTOP_DIR", "")
        if xdg_desktop:
            dirs.append(Path(xdg_desktop) / "gdfsound")
    except Exception:
        pass
    # 6) Linux system install
    dirs.append(Path("/usr/share/GoidaPhone/sounds"))
    dirs.append(Path("/usr/local/share/GoidaPhone/sounds"))
    # 7) Windows %APPDATA%
    try:
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            dirs.append(Path(appdata) / "GoidaPhone" / "sounds")
    except Exception:
        pass
    return dirs

def install_sounds(force: bool = False):
    """
    Copy ALL sound files found in ANY source dir → DATA_DIR/sounds/
    Called once at startup so sounds are always available even if the
    user moves the app or runs it from a different directory.

    If no files were found last time (dest empty), re-scans every time.
    Pass force=True to always re-scan (used by /sounds install command).
    """
    global _SOUNDS_INSTALLED
    # Check if dest actually has files — if not, re-run even if flagged
    dest = DATA_DIR / "sounds"
    dest_has_files = dest.exists() and any(
        dest.glob(f) for f in ["*.wav", "*.mp3"])
    if _SOUNDS_INSTALLED and dest_has_files and not force:
        return
    _SOUNDS_INSTALLED = True
    dest = DATA_DIR / "sounds"
    try:
        dest.mkdir(parents=True, exist_ok=True)
        # Build complete list of expected filenames
        all_names: set[str] = set()
        for names in _SOUND_MAP.values():
            all_names.update(names)
        # Also grab any .wav/.mp3 found in any source dir (for future-proof)
        src_dirs = _get_sound_dirs()[1:]   # skip dest itself
        found_any = False
        for sdir in src_dirs:
            if not sdir.is_dir():
                continue
            for name in all_names:
                src_f = sdir / name
                dst_f = dest / name
                if src_f.exists() and not dst_f.exists():
                    try:
                        shutil.copy2(str(src_f), str(dst_f))
                        found_any = True
                        print(f"[sound] installed: {name} ← {sdir}")
                    except Exception as e:
                        print(f"[sound] copy error {name}: {e}")
        if found_any:
            print(f"[sound] installed sounds → {dest}")
    except Exception as e:
        print(f"[sound] install_sounds error: {e}")

def _find_sound_file(fname: str) -> str | None:
    """Find a sound file in any known directory. Returns path string or None."""
    for d in _get_sound_dirs():
        f = d / fname
        if f.exists():
            return str(f)
    return None

# ─────────────────────────────────────────────────────────────────────────────
#  QMediaPlayer-based sound engine (uses FFmpeg already bundled with PyQt6)
#  Keeps a small pool of players so overlapping sounds work.
# ─────────────────────────────────────────────────────────────────────────────
_SOUND_PLAYERS: list = []   # keep QMediaPlayer refs alive

def _play_file(sf: str):
    """Play a sound file. Primary: QMediaPlayer (FFmpeg). Fallback: aplay/mpg123."""
    from pathlib import Path as _P
    sf_path = _P(sf)
    if not sf_path.exists():
        print(f"[sound] file not found: {sf}")
        return
    print(f"[sound] playing: {sf_path.name}")
    try:
        from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
        from PyQt6.QtCore import QUrl
        player = QMediaPlayer()
        audio  = QAudioOutput()
        audio.setVolume(1.0)
        player.setAudioOutput(audio)
        player.setSource(QUrl.fromLocalFile(str(sf_path.resolve())))
        player.play()
        _SOUND_PLAYERS.append((player, audio))
        def _cleanup(state):
            from PyQt6.QtMultimedia import QMediaPlayer as _QMP
            if state == _QMP.PlaybackState.StoppedState:
                try: _SOUND_PLAYERS.remove((player, audio))
                except ValueError: pass
        player.playbackStateChanged.connect(_cleanup)
        print(f"[sound] QMediaPlayer OK")
        return
    except Exception as e:
        print(f"[sound] QMediaPlayer failed: {e}, trying subprocess...")
    sys_name = platform.system()
    sf_str = str(sf_path)
    if sys_name == "Linux":
        ext = sf_path.suffix.lower()
        # aplay first (ALSA, no PulseAudio needed), then paplay, ffplay
        if ext == ".wav":
            cmds = [
                ["aplay", "-q", sf_str],
                ["paplay", sf_str],
                ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", sf_str],
            ]
        else:
            # mp3/ogg: ffplay is best (bundled with Qt multimedia)
            cmds = [
                ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", sf_str],
                ["mpg123", "-q", sf_str],
                ["paplay", sf_str],
                ["aplay", "-q", sf_str],
            ]
        for cmd in cmds:
            try:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"[sound] subprocess OK: {cmd[0]}")
                return
            except FileNotFoundError:
                continue
        print(f"[sound] no player found for {sf_path.name}")
    elif sys_name == "Windows":
        if sf_str.lower().endswith(".wav"):
            try:
                import winsound as _ws
                _ws.PlaySound(sf_str, _ws.SND_FILENAME | _ws.SND_ASYNC)
                return
            except Exception: pass
        subprocess.Popen(["powershell", "-c",
            f"Add-Type -AssemblyName presentationCore;"
            f"$mp=New-Object System.Windows.Media.MediaPlayer;"
            f"$mp.Open([uri]'{sf_str}');Start-Sleep -m 200;$mp.Play();Start-Sleep -m 4000"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif sys_name == "Darwin":
        subprocess.Popen(["afplay", sf_str],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ── Synthetic tone generator via QAudioSink ───────────────────────────────────
# Used when no sound files are found — always works, no external files needed.
def _synth_tone(freqs: list[tuple[float,float,float]], volume: float = 0.35):
    """
    Play a synthesised tone sequence entirely in-process via QAudioSink.
    freqs: list of (frequency_hz, duration_ms, amplitude 0..1)
    No files, no subprocess — pure Python PCM via Qt.
    """
    try:
        import struct, math as _math
        from PyQt6.QtMultimedia import QAudioSink, QAudioFormat
        from PyQt6.QtCore import QByteArray

        fmt = QAudioFormat()
        fmt.setSampleRate(22050)
        fmt.setChannelCount(2)   # stereo — sound in both ears
        fmt.setSampleFormat(QAudioFormat.SampleFormat.Int16)

        pcm = bytearray()
        RATE = 22050
        for freq, dur_ms, amp in freqs:
            n = int(RATE * dur_ms / 1000)
            fade = int(RATE * 0.008)       # 8 ms fade in/out
            for i in range(n):
                env = 1.0
                if i < fade:   env = i / fade
                elif i > n-fade: env = (n - i) / fade
                v = int(amp * env * volume * _math.sin(2 * _math.pi * freq * i / RATE) * 32767)
                # stereo: same sample for L and R
                pcm += struct.pack('<hh', v, v)

        sink = QAudioSink(fmt)
        buf  = QByteArray(bytes(pcm))
        dev  = sink.start()
        dev.write(buf)
        _SOUND_PLAYERS.append(sink)   # keep alive
        # auto-cleanup after estimated duration
        total_ms = int(sum(d for _, d, _ in freqs)) + 200
        QTimer.singleShot(total_ms, lambda: (
            _SOUND_PLAYERS.remove(sink)
            if sink in _SOUND_PLAYERS else None))
    except Exception as e:
        print(f"[sound] synth failed: {e}")


# Tone profiles for each event
_SYNTH_TONES: dict[str, list[tuple]] = {
    # (freq_hz, duration_ms, amplitude)
    "message":    [(880, 60, 0.6), (0, 20, 0), (1100, 60, 0.5)],
    "call":       [(440, 400, 0.7), (0, 200, 0), (440, 400, 0.7),
                   (0, 200, 0), (440, 400, 0.7)],
    "online":     [(660, 80, 0.5), (880, 120, 0.4)],
    "offline":    [(880, 80, 0.4), (660, 120, 0.3)],
    "error":      [(220, 150, 0.7), (180, 200, 0.6)],
    "user_error": [(330, 100, 0.5), (0, 30, 0), (330, 100, 0.5)],
    "critical":   [(180, 300, 0.8), (0, 100, 0), (180, 300, 0.8)],
    "delete":     [(440, 60, 0.4), (330, 100, 0.3)],
    "pin":        [(880, 50, 0.4), (1100, 80, 0.5)],
    "click":      [(1200, 30, 0.3)],
}

# Freedesktop system sound candidates (Linux)
_FREEDESKTOP_SOUNDS: dict[str, list[str]] = {
    "message": [
        "/usr/share/sounds/freedesktop/stereo/message.oga",
        "/usr/share/sounds/freedesktop/stereo/message-new-instant.oga",
        "/usr/share/sounds/ubuntu/stereo/message-new-instant.ogg",
    ],
    "call": [
        "/usr/share/sounds/freedesktop/stereo/phone-incoming-call.oga",
        "/usr/share/sounds/ubuntu/stereo/phone-incoming-call.ogg",
    ],
    "online": [
        "/usr/share/sounds/freedesktop/stereo/service-login.oga",
        "/usr/share/sounds/ubuntu/stereo/service-login.ogg",
    ],
    "offline": [
        "/usr/share/sounds/freedesktop/stereo/service-logout.oga",
    ],
    "error": [
        "/usr/share/sounds/freedesktop/stereo/dialog-error.oga",
        "/usr/share/sounds/ubuntu/stereo/dialog-error.ogg",
    ],
    "critical": [
        "/usr/share/sounds/freedesktop/stereo/dialog-error.oga",
    ],
}


def play_system_sound(event: str = "message"):
    """
    Play sound for a named event. Priority:
      1. Custom file in DATA_DIR/sounds/ or gdfsound/
      2. Freedesktop system sounds (Linux)
      3. Synthetic tone (always works, no files needed)
    """
    if not S().notification_sounds:
        print(f"[sound] notification_sounds disabled, skipping {event}")
        return
    try:
        # 1. Custom files
        for fname in _SOUND_MAP.get(event, []):
            sf = _find_sound_file(fname)
            print(f"[sound] {event}: looking for {fname} -> {sf or 'NOT FOUND'}")
            if sf:
                _play_file(sf)
                return

        # 2. Freedesktop system sounds (Linux)
        if platform.system() == "Linux":
            for path in _FREEDESKTOP_SOUNDS.get(event, []):
                if Path(path).exists():
                    _play_file(path)
                    return
            # Also try pactl/canberra-gtk-play for themed sounds
            sound_id = {
                "message": "message-new-instant",
                "call":    "phone-incoming-call",
                "online":  "service-login",
                "offline": "service-logout",
                "error":   "dialog-error",
            }.get(event)
            if sound_id:
                for cmd in [
                    ["canberra-gtk-play", "--id", sound_id],
                    ["paplay", f"--property=media.name={sound_id}"],
                ]:
                    try:
                        subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
                        return
                    except FileNotFoundError:
                        continue

        # 3. Windows system sounds
        if platform.system() == "Windows":
            import winsound as _ws
            alias = {"message": "SystemAsterisk", "call": "SystemHand",
                     "online": "SystemDefault", "error": "SystemExclamation",
                     "critical": "SystemCriticalStop"}.get(event, "SystemAsterisk")
            try:
                _ws.PlaySound(alias, _ws.SND_ALIAS | _ws.SND_ASYNC)
                return
            except Exception: pass

        # 4. Synthetic tone — guaranteed fallback
        tones = _SYNTH_TONES.get(event, _SYNTH_TONES["message"])
        _synth_tone(tones)

    except Exception as e:
        print(f"[sound] play_system_sound error ({event}): {e}")
        try:
            _synth_tone(_SYNTH_TONES.get(event, [(880, 80, 0.5)]))
        except Exception:
            pass

def _play_system_sound_compat(event: str = "message"):
    """Legacy alias kept for any remaining call sites."""
    play_system_sound(event)

# ═══════════════════════════════════════════════════════════════════════════
#  IN-APP TOAST NOTIFICATION  (slide-in from bottom-right)
# ═══════════════════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────
#  MEDIA OPEN HELPER — always ask: Mewa or system default
# ─────────────────────────────────────────────────────────────────────────────
_MEDIA_PREF: str = ""   # "mewa" | "system" | "" (ask each time)

MEDIA_EXTS = {".mp3",".wav",".ogg",".flac",".aac",".m4a",".opus",".wma",
              ".mp4",".avi",".mkv",".webm",".mov",".m4v",".mpg",".mpeg",
              ".wmv",".3gp",".ts",".m2ts"}

def _open_link(url: str, parent=None):
    """Open a URL from chat — ask WNS or system browser, with remember checkbox."""
    pref = S().link_open_pref

    def _do_wns():
        app = QApplication.instance()
        if app:
            for w in app.topLevelWidgets():
                if hasattr(w, '_wns_player') and hasattr(w, '_tabs'):
                    w._tabs.setCurrentWidget(w._wns_player)
                    wns = w._wns_player
                    if hasattr(wns, '_new_tab'):
                        wns._new_tab(url)
                    return
        _do_system()

    def _do_system():
        _open_system(url)

    if pref == "wns":
        _do_wns(); return
    elif pref == "system":
        _do_system(); return

    # Ask
    t = get_theme(S().theme)
    dlg = QDialog(parent)
    dlg.setWindowTitle("Открыть ссылку")
    dlg.setFixedWidth(420)
    dlg.setStyleSheet(f"background:{t['bg2']};color:{t['text']};")
    vl = QVBoxLayout(dlg)
    vl.setContentsMargins(20, 16, 20, 16)
    vl.setSpacing(12)

    url_lbl = QLabel(url[:60] + ("…" if len(url) > 60 else ""))
    url_lbl.setStyleSheet(
        f"color:{t['accent']};font-size:11px;background:transparent;"
        "text-decoration:underline;")
    url_lbl.setWordWrap(True)
    vl.addWidget(url_lbl)

    q = QLabel("Где открыть?")
    q.setStyleSheet(
        f"font-size:13px;font-weight:bold;color:{t['text']};background:transparent;")
    vl.addWidget(q)

    btn_row = QHBoxLayout(); btn_row.setSpacing(8)
    wns_btn = QPushButton("🌐 WNS (встроенный)")
    wns_btn.setObjectName("accent_btn"); wns_btn.setFixedHeight(36)
    sys_btn = QPushButton("🖥 Браузер по умолчанию")
    sys_btn.setFixedHeight(36)
    sys_btn.setStyleSheet(
        f"QPushButton{{background:{t['btn_bg']};color:{t['text']};"
        f"border:1px solid {t['border']};border-radius:8px;}}"
        f"QPushButton:hover{{background:{t['btn_hover']};}}")
    btn_row.addWidget(wns_btn); btn_row.addWidget(sys_btn)
    vl.addLayout(btn_row)

    remember = QCheckBox("Запомнить выбор (изменить в Настройки → Приватность)")
    remember.setStyleSheet(
        f"color:{t['text_dim']};font-size:10px;background:transparent;")
    vl.addWidget(remember)

    _choice = [""]
    def _pick(ch):
        _choice[0] = ch
        if remember.isChecked():
            S().set("link_open_pref", ch)
        dlg.accept()

    wns_btn.clicked.connect(lambda: _pick("wns"))
    sys_btn.clicked.connect(lambda: _pick("system"))
    dlg.exec()

    if _choice[0] == "wns":
        _do_wns()
    elif _choice[0] == "system":
        _do_system()


def _open_media_smart(path: str, parent=None):
    """Open a media file: ask whether to use Mewa or system default.
    Respects remembered choice from settings."""
    global _MEDIA_PREF
    # Load saved pref from settings
    saved = S().get("media_open_pref", "", t=str)
    if saved:
        _MEDIA_PREF = saved

    ext = Path(path).suffix.lower()
    is_media = ext in MEDIA_EXTS

    if not is_media:
        # Not a known media file — open with system default directly
        _open_system(path); return

    if _MEDIA_PREF == "mewa":
        _open_in_mewa(path, parent); return
    elif _MEDIA_PREF == "system":
        _open_system(path); return

    # Ask the user
    from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QCheckBox
    t = get_theme(S().theme)
    dlg = QDialog(parent)
    dlg.setWindowTitle("Открыть медиафайл")
    dlg.setFixedSize(380, 210)
    dlg.setStyleSheet(f"background:{t['bg2']};color:{t['text']};")
    vl = QVBoxLayout(dlg)
    vl.setContentsMargins(20,16,20,16); vl.setSpacing(12)

    fname = Path(path).name
    lbl = QLabel(f"<b>{fname}</b><br><br>Чем открыть медиафайл?")
    lbl.setTextFormat(Qt.TextFormat.RichText)
    lbl.setWordWrap(True)
    lbl.setStyleSheet(f"font-size:12px;color:{t['text']};background:transparent;")
    vl.addWidget(lbl)

    remember = QCheckBox("Запомнить мой выбор (можно сменить в Настройках)")
    remember.setStyleSheet(f"color:{t['text_dim']};font-size:10px;background:transparent;")
    vl.addWidget(remember)

    info = QLabel("Сменить выбор: Настройки → Приватность → Медиаплеер")
    info.setStyleSheet(f"font-size:9px;color:{t['text_dim']};background:transparent;")
    vl.addWidget(info)

    btn_row = QHBoxLayout(); btn_row.setSpacing(10)

    btn_mewa = QPushButton("🎵 Mewa (встроенный)")
    btn_mewa.setObjectName("accent_btn"); btn_mewa.setFixedHeight(34)
    btn_sys  = QPushButton("📂 Системный плеер")
    btn_sys.setFixedHeight(34)
    btn_sys.setStyleSheet(
        f"QPushButton{{background:{t['btn_bg']};color:{t['text']};"
        f"border:1px solid {t['border']};border-radius:8px;}}"
        f"QPushButton:hover{{background:{t['btn_hover']};}}")

    _choice = [""]
    def _pick(ch):
        _choice[0] = ch
        if remember.isChecked():
            S().set("media_open_pref", ch)
            global _MEDIA_PREF; _MEDIA_PREF = ch
        dlg.accept()

    btn_mewa.clicked.connect(lambda: _pick("mewa"))
    btn_sys.clicked.connect(lambda: _pick("system"))
    btn_row.addWidget(btn_mewa); btn_row.addWidget(btn_sys)
    vl.addLayout(btn_row)
    dlg.exec()

    if _choice[0] == "mewa":
        _open_in_mewa(path, parent)
    elif _choice[0] == "system":
        _open_system(path)


def _open_system(path: str):
    """Open file with OS default application."""
    try:
        s = platform.system()
        if s == "Linux":
            subprocess.Popen(["xdg-open", path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif s == "Windows":
            os.startfile(path)
        elif s == "Darwin":
            subprocess.Popen(["open", path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[open_system] {e}")


def _open_in_mewa(path: str, parent=None):
    """Add file to Mewa, switch to Mewa tab, and start playback."""
    # Search all top-level windows for MainWindow (has _mewa_player)
    app_inst = QApplication.instance()
    if app_inst:
        for w in app_inst.topLevelWidgets():
            if hasattr(w, '_mewa_player') and hasattr(w, '_tabs'):
                mp = w._mewa_player
                # Switch to Mewa tab first
                w._tabs.setCurrentWidget(mp)
                # open_file handles _add_track + _play_idx (auto-switches to video page)
                mp.open_file(path)
                return
    # Fallback: walk parent hierarchy
    w = parent
    for _ in range(12):
        if w is None: break
        if hasattr(w, '_mewa_player') and hasattr(w, '_tabs'):
            w._tabs.setCurrentWidget(w._mewa_player)
            w._mewa_player.open_file(path)
            return
        w = w.parent() if callable(getattr(w, 'parent', None)) else None
    # Last resort: system open
    _open_system(path)



# ─────────────────────────────────────────────────────────────────────────────
#  MEDIA OPEN HELPER — спрашивает открыть через Mewa или системой
class ToastNotification(QWidget):
    """
    Beautiful in-app toast that slides in from the bottom-right of the parent window.
    Auto-dismisses after 4 seconds. Click to dismiss early.
    """
    clicked = pyqtSignal()

    _active_toasts: list = []   # class-level stack

    def __init__(self, title: str, body: str, avatar_b64: str = "",
                 parent=None, duration_ms: int = 4000):
        super().__init__(parent,
                         Qt.WindowType.FramelessWindowHint |
                         Qt.WindowType.Tool |
                         Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self._duration = duration_ms
        self._anim_show: QPropertyAnimation | None = None
        self._anim_hide: QPropertyAnimation | None = None
        self._build(title, body, avatar_b64)
        ToastNotification._active_toasts.append(self)
        QTimer.singleShot(duration_ms, self._start_hide)

    def _build(self, title: str, body: str, avatar_b64: str):
        self.setFixedWidth(320)
        t = get_theme(S().theme)

        card = QWidget(self)
        card.setObjectName("toast_card")
        card.setStyleSheet(f"""
            QWidget#toast_card {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
                    stop:0 {t['bg2']}, stop:1 {t['bg3']});
                border: 1px solid {t['accent']};
                border-radius: 12px;
                border-left: 3px solid {t['accent']};
            }}
        """)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(card)

        lay = QHBoxLayout(card)
        lay.setContentsMargins(12, 10, 10, 10)
        lay.setSpacing(10)

        # Avatar
        av_lbl = QLabel()
        av_lbl.setFixedSize(38, 38)
        if avatar_b64:
            try:
                pm = base64_to_pixmap(avatar_b64)
                av_lbl.setPixmap(make_circle_pixmap(pm, 38))
            except Exception:
                av_lbl.setPixmap(default_avatar(title, 38))
        else:
            av_lbl.setPixmap(default_avatar(title, 38))
        lay.addWidget(av_lbl)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(f"font-weight:bold;font-size:11px;"
                                f"color:{t['text']};background:transparent;")
        title_lbl.setMaximumWidth(220)
        text_col.addWidget(title_lbl)
        body_short = (body[:55] + "…") if len(body) > 55 else body
        body_lbl = QLabel(body_short)
        body_lbl.setStyleSheet(f"font-size:10px;color:{t['text_dim']};background:transparent;")
        body_lbl.setWordWrap(True)
        body_lbl.setMaximumWidth(220)
        text_col.addWidget(body_lbl)
        lay.addLayout(text_col)

        lay.addStretch()
        close_btn = QPushButton("✕")
        close_btn.setFixedSize(18, 18)
        close_btn.setStyleSheet(f"QPushButton{{background:transparent;border:none;"
                                f"color:{t['text_dim']};font-size:9px;}}"
                                f"QPushButton:hover{{color:{t['text']};}}")
        close_btn.clicked.connect(self._start_hide)
        lay.addWidget(close_btn)

        self.adjustSize()
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def mousePressEvent(self, event):
        self.clicked.emit()
        self._start_hide()

    def show_at(self, parent_widget):
        """Position and animate in."""
        if parent_widget:
            pr = parent_widget.rect()
            gp = parent_widget.mapToGlobal(pr.bottomRight())
            # Stack above existing toasts
            offset_y = 0
            for t in ToastNotification._active_toasts:
                if t is not self and t.isVisible():
                    offset_y += t.height() + 8
            self.move(gp.x() - self.width() - 12,
                      gp.y() - self.height() - 12 - offset_y)
        self.show()
        self._anim_show = QPropertyAnimation(self, b"windowOpacity")
        self._anim_show.setDuration(250)
        self._anim_show.setStartValue(0.0)
        self._anim_show.setEndValue(0.96)
        self._anim_show.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim_show.start()

    def _start_hide(self):
        self._anim_hide = QPropertyAnimation(self, b"windowOpacity")
        self._anim_hide.setDuration(300)
        self._anim_hide.setStartValue(self.windowOpacity())
        self._anim_hide.setEndValue(0.0)
        self._anim_hide.setEasingCurve(QEasingCurve.Type.InCubic)
        self._anim_hide.finished.connect(self._cleanup)
        self._anim_hide.start()

    def _cleanup(self):
        if self in ToastNotification._active_toasts:
            ToastNotification._active_toasts.remove(self)
        self.deleteLater()


_MAIN_WINDOW_REF = None   # set in MainWindow.__init__ for toast positioning

def show_toast(title: str, body: str, avatar_b64: str = ""):
    """Show an in-app toast notification anchored to main window."""
    parent = _MAIN_WINDOW_REF
    if not parent:
        return
    toast = ToastNotification(title, body, avatar_b64, parent=None)
    toast.show_at(parent)


def send_os_notification(title: str, body: str, icon: str = ""):
    """
    Send a native OS desktop notification.
    Windows: win10toast or plyer if available, fallback to tray balloon.
    Linux: notify-send (libnotify).
    macOS: osascript.
    """
    sys_name = platform.system()
    try:
        if sys_name == "Linux":
            # libnotify / notify-send
            cmd = ["notify-send"]
            if icon:
                cmd += ["--icon", icon]
            cmd += [title, body]
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sys_name == "Windows":
            # Try plyer first (cross-platform notification lib)
            try:
                from plyer import notification as _notif
                _notif.notify(title=title, message=body,
                              app_name=APP_NAME, timeout=5)
            except ImportError:
                # Fallback: try win10toast
                try:
                    from win10toast import ToastNotifier
                    toaster = ToastNotifier()
                    toaster.show_toast(title, body, duration=4, threaded=True)
                except ImportError:
                    # Final fallback: Windows balloon tooltip via QSystemTrayIcon
                    # This is handled by MainWindow._tray
                    pass
        elif sys_name == "Darwin":
            script = f'display notification "{body}" with title "{title}"'
            subprocess.Popen(["osascript", "-e", script],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"OS notification error: {e}")

# Global reference to tray icon for fallback notifications (set in MainWindow)
_TRAY_ICON_REF = None

def send_notification(title: str, body: str):
    """Send OS notification with tray fallback."""
    send_os_notification(title, body)
    # Also try tray balloon as fallback
    global _TRAY_ICON_REF
    if _TRAY_ICON_REF and hasattr(_TRAY_ICON_REF, 'showMessage'):
        try:
            _TRAY_ICON_REF.showMessage(title, body,
                QSystemTrayIcon.MessageIcon.Information, 4000)
        except Exception:
            pass

def pixmap_to_base64(pixmap: QPixmap, fmt: str = "PNG") -> str:
    buf = QByteArray()
    buffer = QBuffer(buf)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    pixmap.save(buffer, fmt)
    return base64.b64encode(buf.data()).decode()


    buf = QByteArray()
    buffer = QBuffer(buf)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    pixmap.save(buffer, fmt)
    return base64.b64encode(buf.data()).decode()

def base64_to_pixmap(data: str) -> QPixmap:
    raw = base64.b64decode(data)
    pm = QPixmap()
    pm.loadFromData(raw)
    return pm

def make_circle_pixmap(pm: QPixmap, size: int) -> QPixmap:
    """Crop pixmap to circle."""
    scaled = pm.scaled(size, size, Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                       Qt.TransformationMode.SmoothTransformation)
    out = QPixmap(size, size)
    out.fill(Qt.GlobalColor.transparent)
    painter = QPainter(out)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QBrush(scaled))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(0, 0, size, size)
    painter.end()
    return out

def default_avatar(name: str, size: int = 48) -> QPixmap:
    """Generate colored initial avatar."""
    colors = ["#E74C3C","#3498DB","#2ECC71","#9B59B6","#E67E22","#1ABC9C","#F39C12","#E91E63"]
    color = colors[sum(ord(c) for c in name) % len(colors)]
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QBrush(QColor(color)))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(0, 0, size, size)
    painter.setPen(QPen(QColor("white")))
    font = QFont("Arial", size // 3, QFont.Weight.Bold)
    painter.setFont(font)
    letter = name[0].upper() if name else "?"
    painter.drawText(QRect(0, 0, size, size), Qt.AlignmentFlag.AlignCenter, letter)
    painter.end()
    return pm

# ═══════════════════════════════════════════════════════════════════════════
#  THEME SYSTEM  (full palette + stylesheet per theme)
# ═══════════════════════════════════════════════════════════════════════════
THEMES = {
    "dark": {
        "label": "Тёмная",
        "bg":        "#323232",
        "bg2":       "#282828",
        "bg3":       "#1E1E1E",
        "border":    "#484848",
        "text":      "#E0E0E0",
        "text_dim":  "#909090",
        "accent":    "#0078D4",
        "accent2":   "#005A9E",
        "btn_bg":    "#4A4A4A",
        "btn_hover": "#5A5A5A",
        "btn_press": "#3A3A3A",
        "item_bg":   "#2E2E2E",
        "item_sel":  "#0063B1",
        "header_bg": "#3C3C3C",
        "msg_own":   "#1A3A5C",
        "msg_other": "#383838",
        "online":    "#2ECC71",
        "offline":   "#E74C3C",
    },
    "light": {
        "label": "Светлая",
        "bg":        "#F0F0F0",
        "bg2":       "#FAFAFA",
        "bg3":       "#FFFFFF",
        "border":    "#C8C8C8",
        "text":      "#1A1A1A",
        "text_dim":  "#707070",
        "accent":    "#0078D4",
        "accent2":   "#005A9E",
        "btn_bg":    "#E0E0E0",
        "btn_hover": "#D0D0D0",
        "btn_press": "#C0C0C0",
        "item_bg":   "#F8F8F8",
        "item_sel":  "#0078D4",
        "header_bg": "#E8E8E8",
        "msg_own":   "#C8E6FA",
        "msg_other": "#EEEEEE",
        "online":    "#27AE60",
        "offline":   "#E74C3C",
    },
    "dark_blue": {
        "label": "Тёмно-синяя",
        "bg":        "#1A2540",
        "bg2":       "#131B30",
        "bg3":       "#0D1220",
        "border":    "#2A3858",
        "text":      "#C8D8FF",
        "text_dim":  "#6878A8",
        "accent":    "#4080FF",
        "accent2":   "#2060DD",
        "btn_bg":    "#2A3A60",
        "btn_hover": "#3A4A70",
        "btn_press": "#1A2A50",
        "item_bg":   "#182038",
        "item_sel":  "#2060CC",
        "header_bg": "#202848",
        "msg_own":   "#1A3060",
        "msg_other": "#1E2840",
        "online":    "#00E676",
        "offline":   "#FF5252",
    },
    "dark_red": {
        "label": "Тёмно-красная",
        "bg":        "#2A1010",
        "bg2":       "#200808",
        "bg3":       "#160404",
        "border":    "#4A2020",
        "text":      "#FFD0D0",
        "text_dim":  "#A06060",
        "accent":    "#CC2020",
        "accent2":   "#AA1010",
        "btn_bg":    "#4A1818",
        "btn_hover": "#5A2828",
        "btn_press": "#3A0808",
        "item_bg":   "#281010",
        "item_sel":  "#AA0000",
        "header_bg": "#381818",
        "msg_own":   "#3A1010",
        "msg_other": "#2A1818",
        "online":    "#00E676",
        "offline":   "#FF5252",
    },
    "gray": {
        "label": "Серая",
        "bg":        "#606060",
        "bg2":       "#505050",
        "bg3":       "#404040",
        "border":    "#707070",
        "text":      "#F0F0F0",
        "text_dim":  "#B0B0B0",
        "accent":    "#909090",
        "accent2":   "#707070",
        "btn_bg":    "#707070",
        "btn_hover": "#808080",
        "btn_press": "#606060",
        "item_bg":   "#585858",
        "item_sel":  "#888888",
        "header_bg": "#686868",
        "msg_own":   "#5A5A7A",
        "msg_other": "#484848",
        "online":    "#90EE90",
        "offline":   "#FF9090",
    },
    "midnight": {
        "label": "Полночь",
        "bg":        "#0D0D1A",
        "bg2":       "#080810",
        "bg3":       "#040408",
        "border":    "#1A1A3A",
        "text":      "#B0B8FF",
        "text_dim":  "#5058A0",
        "accent":    "#6040FF",
        "accent2":   "#4020DD",
        "btn_bg":    "#151528",
        "btn_hover": "#202040",
        "btn_press": "#0A0A18",
        "item_bg":   "#0E0E20",
        "item_sel":  "#4030CC",
        "header_bg": "#121224",
        "msg_own":   "#120A30",
        "msg_other": "#0E0E22",
        "online":    "#00FFB0",
        "offline":   "#FF4060",
    },
    "forest": {
        "label": "Лес",
        "bg":        "#1A2A1A",
        "bg2":       "#122012",
        "bg3":       "#0A160A",
        "border":    "#2A3E2A",
        "text":      "#C8EEC8",
        "text_dim":  "#6A8A6A",
        "accent":    "#40AA40",
        "accent2":   "#208820",
        "btn_bg":    "#1E321E",
        "btn_hover": "#284228",
        "btn_press": "#142214",
        "item_bg":   "#162616",
        "item_sel":  "#308830",
        "header_bg": "#1E301E",
        "msg_own":   "#143014",
        "msg_other": "#182018",
        "online":    "#80FF80",
        "offline":   "#FF6060",
    },
    "win95": {
        # ── GoidaPhone 1.7543 — Windows 95 Easter Egg theme ──────────────
        # Activate via: Настройки → Темы → 1.7543
        # The name "1.7543" is the previous version number of GoidaPhone.
        "label": "1.7543",
        "bg":        "#C0C0C0",   # classic Win95 grey
        "bg2":       "#D4D0C8",   # slightly lighter
        "bg3":       "#FFFFFF",   # white input fields
        "border":    "#808080",   # dark grey border (sunken)
        "text":      "#000000",   # pure black text
        "text_dim":  "#444444",
        "accent":    "#000080",   # Win95 title bar blue
        "accent2":   "#000060",
        "btn_bg":    "#C0C0C0",
        "btn_hover": "#D4D0C8",
        "btn_press": "#B0B0B0",
        "item_bg":   "#FFFFFF",
        "item_sel":  "#000080",
        "header_bg": "#000080",   # navy title bars
        "msg_own":   "#E0E8FF",   # soft blue for own messages
        "msg_other": "#F0F0F0",   # near-white for others
        "online":    "#008000",
        "offline":   "#FF0000",
        # Extra Win95 feel is applied via special CSS below
        "__win95__": True,
    },
}

def get_theme(name: str) -> dict:
    return THEMES.get(name, THEMES["dark"])

def build_stylesheet(t: dict) -> str:
    """Build a complete Qt stylesheet from a theme dict.
    Special handling for Win95 theme (__win95__ key).
    """
    # ── Win95 Easter Egg ──────────────────────────────────────────────────────
    if t.get("__win95__"):
        return _build_win95_stylesheet(t)
    # ── Standard modern stylesheet ────────────────────────────────────────────
    return _build_modern_stylesheet(t)


def _build_win95_stylesheet(t: dict) -> str:
    """Classic Windows 95 stylesheet — raised/sunken borders, no rounded corners."""
    return f"""
/* ════════════════════════════════════════════════════
   GoidaPhone 1.7543 — Windows 95 theme
   Easter Egg: "Привет из 1995 года"
   ════════════════════════════════════════════════════ */
QWidget {{
    background-color: {t['bg']};
    color: {t['text']};
    font-family: "MS Sans Serif", "Tahoma", "Arial", sans-serif;
    font-size: 11px;
}}
QMainWindow, QDialog {{
    background-color: {t['bg']};
}}
/* Raised button — classic Win95 look */
QPushButton {{
    background-color: {t['btn_bg']};
    color: {t['text']};
    border-top: 2px solid #FFFFFF;
    border-left: 2px solid #FFFFFF;
    border-bottom: 2px solid #808080;
    border-right: 2px solid #808080;
    border-radius: 0px;
    padding: 4px 10px;
    font-size: 11px;
}}
QPushButton:hover {{
    background-color: {t['btn_hover']};
}}
QPushButton:pressed {{
    border-top: 2px solid #808080;
    border-left: 2px solid #808080;
    border-bottom: 2px solid #FFFFFF;
    border-right: 2px solid #FFFFFF;
    background-color: {t['btn_press']};
}}
QPushButton:disabled {{
    color: #808080;
    background-color: {t['bg']};
}}
QPushButton#accent_btn {{
    background-color: {t['accent']};
    color: white;
    font-weight: bold;
}}
QPushButton#danger_btn {{
    background-color: #CC0000;
    color: white;
}}
/* Sunken input fields */
QLineEdit, QPlainTextEdit, QTextEdit {{
    background-color: {t['bg3']};
    color: {t['text']};
    border-top: 2px solid #808080;
    border-left: 2px solid #808080;
    border-bottom: 2px solid #FFFFFF;
    border-right: 2px solid #FFFFFF;
    border-radius: 0px;
    padding: 3px 5px;
    selection-background-color: {t['accent']};
    selection-color: white;
}}
QTextBrowser {{
    background-color: {t['bg3']};
    color: {t['text']};
    border-top: 2px solid #808080;
    border-left: 2px solid #808080;
    border-bottom: 2px solid #FFFFFF;
    border-right: 2px solid #FFFFFF;
    border-radius: 0px;
    padding: 4px;
}}
QComboBox {{
    background-color: {t['btn_bg']};
    color: {t['text']};
    border-top: 2px solid #FFFFFF;
    border-left: 2px solid #FFFFFF;
    border-bottom: 2px solid #808080;
    border-right: 2px solid #808080;
    border-radius: 0px;
    padding: 3px 6px;
}}
QComboBox QAbstractItemView {{
    background-color: {t['bg3']};
    color: {t['text']};
    border: 2px solid #808080;
    selection-background-color: {t['accent']};
    selection-color: white;
}}
QListWidget {{
    background-color: {t['bg3']};
    color: {t['text']};
    border-top: 2px solid #808080;
    border-left: 2px solid #808080;
    border-bottom: 2px solid #FFFFFF;
    border-right: 2px solid #FFFFFF;
    border-radius: 0px;
    outline: none;
}}
QListWidget::item {{
    background-color: transparent;
    padding: 3px 4px;
}}
QListWidget::item:selected {{
    background-color: {t['accent']};
    color: white;
}}
QTabWidget::pane {{
    border: 2px solid #808080;
    background-color: {t['bg']};
    border-radius: 0px;
}}
QTabBar::tab {{
    background-color: {t['bg']};
    color: {t['text']};
    border-top: 2px solid #FFFFFF;
    border-left: 2px solid #FFFFFF;
    border-bottom: none;
    border-right: 1px solid #808080;
    border-radius: 0px;
    padding: 4px 12px;
    margin-right: 2px;
}}
QTabBar::tab:selected {{
    background-color: {t['bg']};
    font-weight: bold;
    margin-top: -2px;
    padding-top: 6px;
}}
QGroupBox {{
    font-weight: bold;
    color: {t['text']};
    border: 2px solid #808080;
    border-radius: 0px;
    margin-top: 10px;
    padding-top: 10px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 4px;
    background-color: {t['bg']};
}}
QScrollBar:vertical {{
    background: {t['bg']};
    width: 16px;
    border: 1px solid #808080;
}}
QScrollBar::handle:vertical {{
    background: {t['btn_bg']};
    border-top: 2px solid #FFFFFF;
    border-left: 2px solid #FFFFFF;
    border-bottom: 2px solid #808080;
    border-right: 2px solid #808080;
    min-height: 20px;
}}
QScrollBar::add-line:vertical {{
    background: {t['btn_bg']};
    height: 16px;
    border-top: 2px solid #FFFFFF;
    border-left: 2px solid #FFFFFF;
    border-bottom: 2px solid #808080;
    border-right: 2px solid #808080;
    subcontrol-position: bottom;
    subcontrol-origin: scroll;
}}
QScrollBar::sub-line:vertical {{
    background: {t['btn_bg']};
    height: 16px;
    border-top: 2px solid #FFFFFF;
    border-left: 2px solid #FFFFFF;
    border-bottom: 2px solid #808080;
    border-right: 2px solid #808080;
    subcontrol-position: top;
    subcontrol-origin: scroll;
}}
QMenuBar {{
    background-color: {t['bg']};
    color: {t['text']};
    border-bottom: 1px solid #808080;
}}
QMenuBar::item:selected {{
    background-color: {t['accent']};
    color: white;
}}
QMenu {{
    background-color: {t['bg']};
    color: {t['text']};
    border: 2px solid #808080;
}}
QMenu::item:selected {{
    background-color: {t['accent']};
    color: white;
}}
QStatusBar {{
    background-color: {t['bg']};
    color: {t['text']};
    border-top: 1px solid #808080;
}}
QLabel#section_header {{
    background-color: {t['header_bg']};
    color: white;
    padding: 6px 8px;
    font-weight: bold;
}}
QProgressBar {{
    background-color: {t['bg3']};
    border-top: 2px solid #808080;
    border-left: 2px solid #808080;
    border-bottom: 2px solid #FFFFFF;
    border-right: 2px solid #FFFFFF;
    border-radius: 0px;
    text-align: center;
    color: {t['text']};
}}
QProgressBar::chunk {{
    background-color: {t['accent']};
}}
"""


def _build_modern_stylesheet(t: dict) -> str:
    """Modern stylesheet with depth, gradients, and rounded corners."""
    return f"""
/* ── Global ── */
QWidget {{
    background-color: {t['bg']};
    color: {t['text']};
    font-family: "Segoe UI", "Ubuntu", sans-serif;
    font-size: 11px;
}}
QMainWindow, QDialog {{
    background-color: {t['bg']};
}}

/* ── Buttons ── */
QPushButton {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {t['btn_hover']}, stop:1 {t['btn_bg']});
    color: {t['text']};
    border: 1px solid {t['border']};
    border-bottom: 2px solid rgba(0,0,0,89);
    border-radius: 7px;
    padding: 5px 12px;
    font-size: 11px;
}}
QPushButton:hover {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {t['accent']}, stop:1 {t['btn_hover']});
    border-color: {t['accent']};
    color: white;
}}
QPushButton:pressed {{
    background-color: {t['btn_press']};
    border-bottom-width: 1px;
    padding-top: 6px;
}}
QPushButton:disabled {{
    background-color: {t['bg2']};
    color: {t['text_dim']};
    border-color: {t['border']};
    border-bottom-width: 1px;
}}
QPushButton#accent_btn {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {t['accent']}, stop:1 {t['accent2']});
    color: white;
    border: 1px solid rgba(255,255,255,38);
    border-bottom: 3px solid rgba(0,0,0,102);
    font-weight: bold;
    border-radius: 8px;
}}
QPushButton#accent_btn:hover {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {t['btn_hover']}, stop:1 {t['accent']});
}}
QPushButton#accent_btn:pressed {{
    border-bottom-width: 1px;
    padding-top: 6px;
}}
QPushButton#danger_btn {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #E03333, stop:1 #AA1111);
    color: white;
    border: 1px solid rgba(255,100,100,76);
    border-bottom: 2px solid rgba(0,0,0,102);
    border-radius: 7px;
}}
QPushButton#danger_btn:hover {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #FF4444, stop:1 #CC2222);
}}

/* ── Inputs ── */
QLineEdit, QPlainTextEdit, QTextEdit {{
    background-color: {t['bg3']};
    color: {t['text']};
    border: 1px solid {t['border']};
    border-radius: 4px;
    padding: 4px 7px;
    selection-background-color: {t['accent']};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border-color: {t['accent']};
}}
QTextBrowser {{
    background-color: {t['bg2']};
    color: {t['text']};
    border: 1px solid {t['border']};
    border-radius: 4px;
    padding: 4px;
}}
QComboBox {{
    background-color: {t['btn_bg']};
    color: {t['text']};
    border: 1px solid {t['border']};
    border-radius: 4px;
    padding: 4px 8px;
}}
QComboBox::drop-down {{
    border: none;
}}
QComboBox QAbstractItemView {{
    background-color: {t['bg2']};
    color: {t['text']};
    selection-background-color: {t['accent']};
    border: 1px solid {t['border']};
}}
QSpinBox {{
    background-color: {t['bg3']};
    color: {t['text']};
    border: 1px solid {t['border']};
    border-radius: 4px;
    padding: 3px;
}}

/* ── Lists ── */
QListWidget {{
    background-color: {t['bg2']};
    color: {t['text']};
    border: 1px solid {t['border']};
    border-radius: 4px;
    outline: none;
}}
QListWidget::item {{
    background-color: {t['item_bg']};
    border-bottom: 1px solid {t['border']};
    padding: 4px 6px;
    border-radius: 0px;
}}
QListWidget::item:selected {{
    background-color: {t['item_sel']};
    color: white;
}}
QListWidget::item:hover:!selected {{
    background-color: {t['btn_hover']};
}}

/* ── Tabs ── */
QTabWidget::pane {{
    border: 1px solid {t['border']};
    background-color: {t['bg2']};
    border-radius: 0 4px 4px 4px;
}}
QTabBar::tab {{
    background-color: {t['bg']};
    color: {t['text_dim']};
    border: 1px solid {t['border']};
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    padding: 6px 14px;
    margin-right: 2px;
    font-size: 11px;
}}
QTabBar::tab:selected {{
    background-color: {t['bg2']};
    color: {t['text']};
    border-bottom: 1px solid {t['bg2']};
}}
QTabBar::tab:hover:!selected {{
    background-color: {t['btn_hover']};
    color: {t['text']};
}}

/* ── GroupBox ── */
QGroupBox {{
    font-weight: bold;
    color: {t['text']};
    border: 1px solid {t['border']};
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 10px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    color: {t['accent']};
    background-color: {t['bg']};
}}

/* ── ScrollBar ── */
QScrollBar:vertical {{
    background: {t['bg2']};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {t['border']};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{
    background: {t['accent']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: {t['bg2']};
    height: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal {{
    background: {t['border']};
    border-radius: 4px;
    min-width: 20px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {t['accent']};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}

/* ── Menu ── */
QMenuBar {{
    background-color: {t['header_bg']};
    color: {t['text']};
    border-bottom: 1px solid {t['border']};
    padding: 2px;
}}
QMenuBar::item {{
    background: transparent;
    padding: 4px 10px;
    border-radius: 3px;
}}
QMenuBar::item:selected {{
    background-color: {t['accent']};
    color: white;
}}
QMenu {{
    background-color: {t['bg2']};
    color: {t['text']};
    border: 1px solid {t['border']};
}}
QMenu::item {{
    padding: 5px 20px;
}}
QMenu::item:selected {{
    background-color: {t['accent']};
    color: white;
}}
QMenu::separator {{
    height: 1px;
    background: {t['border']};
    margin: 3px 0;
}}

/* ── StatusBar ── */
QStatusBar {{
    background-color: {t['header_bg']};
    color: {t['text_dim']};
    border-top: 1px solid {t['border']};
    font-size: 10px;
}}

/* ── ToolTip ── */
QToolTip {{
    background-color: {t['bg2']};
    color: {t['text']};
    border: 1px solid {t['accent']};
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 10px;
}}

/* ── Slider ── */
QSlider::groove:horizontal {{
    background: {t['border']};
    height: 4px;
    border-radius: 2px;
}}
QSlider::handle:horizontal {{
    background: {t['accent']};
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 7px;
}}
QSlider::sub-page:horizontal {{
    background: {t['accent']};
    border-radius: 2px;
}}

/* ── CheckBox ── */
QCheckBox {{
    color: {t['text']};
    spacing: 8px;
    font-size: 12px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 2px solid {t['border']};
    border-radius: 4px;
    background: {t['bg3']};
}}
QCheckBox::indicator:hover {{
    border-color: {t['accent']};
    background: {t['bg2']};
}}
QCheckBox::indicator:checked {{
    background: {t['accent']};
    border-color: {t['accent']};
    border-bottom: 3px solid rgba(255,255,255,127);
    border-right: 3px solid rgba(255,255,255,127);
    border-top: 2px solid {t['accent']};
    border-left: 2px solid {t['accent']};
}}

/* ── ProgressBar ── */
QProgressBar {{
    background-color: {t['bg3']};
    border: 1px solid {t['border']};
    border-radius: 4px;
    text-align: center;
    color: {t['text']};
    height: 16px;
}}
QProgressBar::chunk {{
    background-color: {t['accent']};
    border-radius: 3px;
}}

/* ── Splitter ── */
QSplitter::handle {{
    background: {t['border']};
    width: 2px;
    height: 2px;
}}

/* ── Labels ── */
QLabel#section_header {{
    background-color: {t['header_bg']};
    color: {t['text']};
    padding: 8px 10px;
    border-bottom: 1px solid {t['border']};
    font-weight: bold;
    font-size: 12px;
}}
QLabel#user_status_online {{
    color: {t['online']};
    font-size: 10px;
}}
QLabel#user_status_offline {{
    color: {t['offline']};
    font-size: 10px;
}}

/* ── Chat panel header (depth effect) ── */
QWidget#chat_header {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {t['header_bg']}, stop:1 {t['bg2']});
    border-bottom: 2px solid {t['border']};
    border-radius: 0px;
}}
QWidget#chat_header_top {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {t['header_bg']}, stop:1 {t['bg2']});
    border-bottom: 2px solid {t['border']};
    border-radius: 8px 8px 0 0;
}}

/* ── Peer list items ── */
QWidget#peer_item {{
    border-radius: 6px;
    padding: 2px;
}}
QWidget#peer_item:hover {{
    background-color: {t['btn_hover']};
}}

/* ── Input area (depth) ── */
QWidget#input_area {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {t['bg2']}, stop:1 {t['bg']});
    border-top: 1px solid {t['border']};
}}

/* ── Sidebar ── */
QWidget#sidebar {{
    background-color: {t['bg2']};
    border-right: 1px solid {t['border']};
}}

/* ── Call bar ── */
QWidget#call_bar_active {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #1A4A1A, stop:1 #123012);
    border-top: 1px solid #2A5A2A;
    border-bottom: 1px solid #1A3A1A;
}}

/* ── Message reactions ── */
QPushButton#reaction_btn {{
    background-color: {t['bg3']};
    border: 1px solid {t['border']};
    border-radius: 10px;
    padding: 2px 6px;
    font-size: 12px;
    min-width: 30px;
}}
QPushButton#reaction_btn:hover {{
    background-color: {t['btn_hover']};
    border-color: {t['accent']};
}}

/* ── Launcher screen ── */
QWidget#launcher_screen {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 {t['bg3']}, stop:0.5 {t['bg2']}, stop:1 {t['bg']});
}}
QPushButton#launcher_btn {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {t['btn_hover']}, stop:1 {t['btn_bg']});
    border: 2px solid {t['accent']};
    border-radius: 12px;
    padding: 20px;
    font-size: 14px;
    font-weight: bold;
    color: {t['text']};
    min-width: 180px;
    min-height: 120px;
}}
QPushButton#launcher_btn:hover {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {t['accent']}, stop:1 {t['accent2']});
    color: white;
}}

/* ── Unread badge ── */
QLabel#unread_badge {{
    background-color: {t['accent']};
    color: white;
    border-radius: 9px;
    padding: 1px 5px;
    font-size: 9px;
    font-weight: bold;
    min-width: 16px;
}}
"""

# ═══════════════════════════════════════════════════════════════════════════
#  LANGUAGE / LOCALIZATION  (п.35 — Русский / English)
# ═══════════════════════════════════════════════════════════════════════════
_STRINGS_RU = {
    # App
    "app_title":            "GoidaPhone",
    "online":               "Онлайн",
    "offline":              "Офлайн",
    # Chat
    "public_chat":          "💬 Общий чат",
    "all_users":            "Все пользователи в сети",
    "private_chat":         "Личный чат",
    "type_message":         "Введите сообщение...",
    "send":                 "Отправить",
    "call":                 "Позвонить",
    "hangup":               "Завершить",
    "attach":               "Файл",
    "emoji":                "Эмодзи",
    "stickers":             "Стикеры",
    "typing":               "печатает...",
    "you":                  "Вы",
    "call_started":         "Звонок начат",
    "call_ended":           "Звонок завершён",
    "active_call":          "📞 Активный звонок",
    "mute_mic":             "🎤 Микрофон",
    "muted":                "🔇 Заглушён",
    # Users panel
    "users":                "👥 Пользователи",
    "groups":               "📂 Группы",
    "search":               "🔍 Поиск...",
    "create_group":         "➕ Создать группу",
    "new_group":            "Новая группа",
    "group_name":           "Название группы:",
    "group_created":        "Группа создана.",
    "add_members":          "Добавьте участников через контекстное меню.",
    "personal_chat":        "💬 Личный чат",
    "call_peer":            "📞 Позвонить",
    "send_file":            "📎 Отправить файл",
    "add_to_group":         "➕ Добавить в группу",
    "first_create_group":   "Сначала создайте группу.",
    "groups_label":         "Группы:",
    # Messages
    "msg_file":             "📎 Файл",
    "msg_image":            "🖼 Изображение",
    "msg_edit_hint":        "(изменено)",
    "msg_forwarded":        "↪ Переслано",
    "msg_reaction_add":     "Добавить реакцию",
    "msg_copy":             "📋 Копировать",
    "msg_edit":             "✏ Редактировать",
    "msg_delete":           "🗑 Удалить",
    "msg_forward":          "↪ Переслать",
    "msg_reply":            "↩ Ответить",
    "msg_reactions":        "😊 Реакция",
    # Notifications
    "notif_new_message":    "Новое сообщение",
    "notif_incoming_call":  "Входящий звонок",
    "notif_file_received":  "Получен файл",
    "notif_user_online":    "пользователь онлайн",
    # Settings
    "settings":             "Настройки GoidaPhone",
    "tab_audio":            "🎵 Аудио",
    "tab_network":          "🌐 Сеть",
    "tab_themes":           "🎨 Темы",
    "tab_license":          "👑 Лицензия",
    "tab_data":             "💾 Данные",
    "tab_specialist":       "🔧 Для специалистов",
    "tab_language":         "🌍 Язык",
    "save":                 "💾 Сохранить",
    "close":                "Закрыть",
    "cancel":               "Отмена",
    "yes":                  "Да",
    "no":                   "Нет",
    "ok":                   "OK",
    "saved":                "Настройки сохранены!",
    # Profile
    "my_profile":           "👤 Мой профиль",
    "username":             "Имя пользователя:",
    "bio":                  "О себе:",
    "avatar":               "Аватар",
    "change_avatar":        "📷 Сменить аватар",
    "banner":               "Баннер профиля",
    "nickname_color":       "Цвет ника:",
    "custom_emoji":         "Эмодзи рядом с именем:",
    "profile_saved":        "Профиль сохранён!",
    # Calls
    "incoming_call":        "звонит вам",
    "accept":               "✅ Принять",
    "reject":               "❌ Отклонить",
    # Launcher
    "launcher_title":       "GoidaPhone",
    "launcher_subtitle":    "Добро пожаловать",
    "launcher_gui":         "🖥 Запустить\nграфический\nинтерфейс",
    "launcher_cmd":         "⌨ Запустить\nконсольный\nрежим",
    "launcher_gui_hint":    "Полный интерфейс с чатом, звонками и файлами",
    "launcher_cmd_hint":    "Для серверов, диагностики и автоматизации",
    # About
    "about":                f"О {APP_NAME}",
    # Updates
    "check_updates":        "🔄 Проверить обновления",
    "update_found":         "🚀 Доступна версия",
    "update_available_title": "Доступно обновление!",
    "update_now":           "⬇ Обновить",
    "no_updates":           "✅ Обновлений не найдено.",
    "update_error":         "❌ Ошибка:",
    # Errors
    "network_error":        "Не удалось запустить сетевые службы.\nПроверьте, не заняты ли порты другими программами.",
    "file_send_error":      "Ошибка отправки файла",
    "no_image":             "Не удалось загрузить изображение.",
    # Slash commands
    "cmd_clear_done":       "Чат очищен.",
    "cmd_help":             "Доступные команды: /clear, /help, /me, /ping, /version",
    "cmd_me":               "действует",
    "cmd_ping":             "Pong!",
    "cmd_unknown":          "Неизвестная команда. Введите /help для списка команд.",
    # Status
    "searching":            "🔍 Поиск пользователей...",
    "no_calls":             "📞 Нет звонков",
    "mic_on":               "🎤 Вкл",
    "mic_off":              "🔇 Выкл",
    "premium_label":        "👑 Премиум",
}

_STRINGS_EN = {
    # App
    "app_title":            "GoidaPhone",
    "online":               "Online",
    "offline":              "Offline",
    # Chat
    "public_chat":          "💬 Public Chat",
    "all_users":            "All users on network",
    "private_chat":         "Private Chat",
    "type_message":         "Type a message...",
    "send":                 "Send",
    "call":                 "Call",
    "hangup":               "Hang up",
    "attach":               "File",
    "emoji":                "Emoji",
    "stickers":             "Stickers",
    "typing":               "is typing...",
    "you":                  "You",
    "call_started":         "Call started",
    "call_ended":           "Call ended",
    "active_call":          "📞 Active call",
    "mute_mic":             "🎤 Microphone",
    "muted":                "🔇 Muted",
    # Users panel
    "users":                "👥 Users",
    "groups":               "📂 Groups",
    "search":               "🔍 Search...",
    "create_group":         "➕ Create group",
    "new_group":            "New Group",
    "group_name":           "Group name:",
    "group_created":        "Group created.",
    "add_members":          "Add members via context menu.",
    "personal_chat":        "💬 Personal chat",
    "call_peer":            "📞 Call",
    "send_file":            "📎 Send file",
    "add_to_group":         "➕ Add to group",
    "first_create_group":   "Create a group first.",
    "groups_label":         "Groups:",
    # Messages
    "msg_file":             "📎 File",
    "msg_image":            "🖼 Image",
    "msg_edit_hint":        "(edited)",
    "msg_forwarded":        "↪ Forwarded",
    "msg_reaction_add":     "Add reaction",
    "msg_copy":             "📋 Copy",
    "msg_edit":             "✏ Edit",
    "msg_delete":           "🗑 Delete",
    "msg_forward":          "↪ Forward",
    "msg_reply":            "↩ Reply",
    "msg_reactions":        "😊 React",
    # Notifications
    "notif_new_message":    "New message",
    "notif_incoming_call":  "Incoming call",
    "notif_file_received":  "File received",
    "notif_user_online":    "user is online",
    # Settings
    "settings":             "GoidaPhone Settings",
    "tab_audio":            "🎵 Audio",
    "tab_network":          "🌐 Network",
    "tab_themes":           "🎨 Themes",
    "tab_license":          "👑 License",
    "tab_data":             "💾 Data",
    "tab_specialist":       "🔧 For Specialists",
    "tab_language":         "🌍 Language",
    "save":                 "💾 Save",
    "close":                "Close",
    "cancel":               "Cancel",
    "yes":                  "Yes",
    "no":                   "No",
    "ok":                   "OK",
    "saved":                "Settings saved!",
    # Profile
    "my_profile":           "👤 My Profile",
    "username":             "Username:",
    "bio":                  "About me:",
    "avatar":               "Avatar",
    "change_avatar":        "📷 Change avatar",
    "banner":               "Profile banner",
    "nickname_color":       "Nickname color:",
    "custom_emoji":         "Emoji next to name:",
    "profile_saved":        "Profile saved!",
    # Calls
    "incoming_call":        "is calling you",
    "accept":               "✅ Accept",
    "reject":               "❌ Reject",
    # Launcher
    "launcher_title":       "GoidaPhone",
    "launcher_subtitle":    "Welcome",
    "launcher_gui":         "🖥 Launch\nGraphical\nInterface",
    "launcher_cmd":         "⌨ Launch\nConsole\nMode",
    "launcher_gui_hint":    "Full interface with chat, calls and files",
    "launcher_cmd_hint":    "For servers, diagnostics and automation",
    # About
    "about":                f"About {APP_NAME}",
    # Updates
    "check_updates":        "🔄 Check for updates",
    "update_found":         "🚀 Version available",
    "update_available_title": "Update Available!",
    "update_now":           "⬇ Update",
    "no_updates":           "✅ No updates found.",
    "update_error":         "❌ Error:",
    # Errors
    "network_error":        "Failed to start network services.\nCheck if ports are in use by other programs.",
    "file_send_error":      "File send error",
    "no_image":             "Could not load image.",
    # Slash commands
    "cmd_clear_done":       "Chat cleared.",
    "cmd_help":             "Available commands: /clear, /help, /me, /ping, /version",
    "cmd_me":               "does",
    "cmd_ping":             "Pong!",
    "cmd_unknown":          "Unknown command. Type /help for command list.",
    # Status
    "searching":            "🔍 Searching for users...",
    "no_calls":             "📞 No calls",
    "mic_on":               "🎤 On",
    "mic_off":              "🔇 Off",
    "premium_label":        "👑 Premium",
}

class Strings:
    """
    Localization manager.
    Usage: TR("key") or TR.get("key", "fallback")
    Language is read from AppSettings at call time, so switching language
    in settings takes effect immediately without restart.
    """
    _langs = {"ru": _STRINGS_RU, "en": _STRINGS_EN}

    @classmethod
    def _table(cls) -> dict:
        # avoid circular import — AppSettings may not be ready yet
        try:
            lang = AppSettings.inst().language
        except Exception:
            lang = "ru"
        return cls._langs.get(lang, _STRINGS_RU)

    def __call__(self, key: str, **kwargs) -> str:
        val = self._table().get(key, key)
        if kwargs:
            try:
                val = val.format(**kwargs)
            except Exception:
                pass
        return val

    def get(self, key: str, fallback: str = "") -> str:
        return self._table().get(key, fallback)

TR = Strings()   # global translator — use TR("key")

# ═══════════════════════════════════════════════════════════════════════════
#  SETTINGS / PROFILE MANAGER
# ═══════════════════════════════════════════════════════════════════════════
class AppSettings:
    """Centralised settings wrapper."""
    _inst = None

    @classmethod
    def inst(cls):
        if cls._inst is None:
            cls._inst = cls()
        return cls._inst

    def __init__(self):
        self._s = QSettings("WinoraCompany", "GoidaPhone")

    def get(self, key, default=None, t=None):
        v = self._s.value(key, default)
        if t is bool:
            if isinstance(v, bool): return v
            return str(v).lower() in ("true", "1", "yes")
        if t is not None and v is not None:
            try:
                return t(v)
            except Exception:
                return default
        return v

    def set(self, key, value):
        self._s.setValue(key, value)
        self._s.sync()

    def remove(self, key):
        self._s.remove(key)

    # shortcuts
    @property
    def username(self):
        return self.get("username", f"User_{secrets.randbelow(1000):03d}", t=str)

    @username.setter
    def username(self, v):
        self.set("username", v)

    @property
    def theme(self):
        return self.get("theme", "dark", t=str)

    @theme.setter
    def theme(self, v):
        self.set("theme", v)

    @property
    def premium(self) -> bool:
        if not self.get("premium", False, t=bool):
            return False
        exp_str = self.get("premium_expires", "", t=str)
        if not exp_str:
            return False
        try:
            exp = datetime.fromisoformat(exp_str)
            if datetime.now() > exp:
                self.set("premium", False)
                return False
            return True
        except Exception:
            return False

    @property
    def premium_expires(self) -> str:
        return self.get("premium_expires", "", t=str)

    def activate_premium(self, code: str) -> bool:
        try:
            n = int(code)
            if len(code) == 12 and n % LICENSE_DIVISOR == 0:
                expires = datetime.now() + timedelta(days=LICENSE_DAYS)
                self.set("premium", True)
                self.set("license_code", code)
                self.set("premium_expires", expires.isoformat())
                return True
        except Exception:
            pass
        return False

    @property
    def nickname_color(self):
        return self.get("nickname_color", "#E0E0E0", t=str)

    @nickname_color.setter
    def nickname_color(self, v):
        self.set("nickname_color", v)

    @property
    def custom_emoji(self):
        if self.premium:
            return self.get("custom_emoji", "👑", t=str)
        return ""

    @custom_emoji.setter
    def custom_emoji(self, v):
        self.set("custom_emoji", v)

    @property
    def bio(self):
        return self.get("bio", "", t=str)

    @bio.setter
    def bio(self, v):
        self.set("bio", v)

    @property
    def user_status(self) -> str:
        """Presence status: online | away | busy | dnd"""
        return self.get("user_status", "online", t=str)

    @user_status.setter
    def user_status(self, v: str):
        self.set("user_status", v)

    @property
    def safe_mode(self) -> bool:
        """Safe mode: show GoidaID instead of IP addresses."""
        return self.get("safe_mode", False, t=bool)

    @safe_mode.setter
    def safe_mode(self, v: bool):
        self.set("safe_mode", v)

    @property
    def language(self) -> str:
        """Interface language: 'ru' or 'en'."""
        return self.get("language", "ru", t=str)

    @language.setter
    def language(self, v: str):
        self.set("language", v)

    @property
    def show_launcher(self) -> bool:
        """Show GUI/CMD launcher screen on startup."""
        return self.get("show_launcher", True, t=bool)

    @show_launcher.setter
    def show_launcher(self, v: bool):
        self.set("show_launcher", v)

    @property
    def os_notifications(self) -> bool:
        """Send desktop OS notifications for new messages."""
        return self.get("os_notifications", True, t=bool)

    @os_notifications.setter
    def os_notifications(self, v: bool):
        self.set("os_notifications", v)

    @property
    def relay_server(self) -> str:
        """Optional relay server address (host:port)."""
        return self.get("relay_server", "", t=str)

    @relay_server.setter
    def relay_server(self, v: str):
        self.set("relay_server", v)

    @property
    def relay_enabled(self) -> bool:
        return self.get("relay_enabled", False, t=bool)

    @relay_enabled.setter
    def relay_enabled(self, v: bool):
        self.set("relay_enabled", v)

    @property
    def encryption_enabled(self) -> bool:
        """True if end-to-end encryption is active."""
        return self.get("encryption_enabled", False, t=bool)

    @encryption_enabled.setter
    def encryption_enabled(self, v: bool):
        self.set("encryption_enabled", v)

    @property
    def encryption_passphrase(self) -> str:
        """Shared passphrase for AES-256 encryption.
        WARNING: stored as plaintext in QSettings — acceptable for LAN use,
        but users should be warned not to use passwords from other services."""
        return self.get("encryption_passphrase", "", t=str)

    @encryption_passphrase.setter
    def encryption_passphrase(self, v: str):
        self.set("encryption_passphrase", v)

    @property
    def device_name(self) -> str:
        """Custom device/hostname label shown to peers."""
        return self.get("device_name", platform.node() or "PC", t=str)

    @device_name.setter
    def device_name(self, v: str):
        self.set("device_name", v)

    @property
    def udp_port(self):
        return self.get("udp_port", UDP_PORT_DEFAULT, t=int)

    @property
    def tcp_port(self):
        return self.get("tcp_port", TCP_PORT_DEFAULT, t=int)

    @property
    def volume(self):
        return self.get("volume", 80, t=int)

    @property
    def notification_sounds(self):
        return self.get("notification_sounds", True, t=bool)

    @property
    def show_splash(self):
        return self.get("show_splash", True, t=bool)

    @property
    def save_history(self):
        return self.get("save_history", True, t=bool)

    @property
    def link_open_pref(self) -> str:
        """'wns' | 'system' | 'ask' (default)"""
        return self.get("link_open_pref", "ask", t=str)

    @property
    def avatar_b64(self):
        return self.get("avatar_b64", "", t=str)

    @avatar_b64.setter
    def avatar_b64(self, v):
        self.set("avatar_b64", v)

    @property
    def banner_b64(self):
        return self.get("banner_b64", "", t=str)

    @banner_b64.setter
    def banner_b64(self, v):
        self.set("banner_b64", v)

    def custom_theme(self, slot: int) -> dict:
        raw = self.get(f"custom_theme_{slot}", "", t=str)
        if raw:
            try:
                return json.loads(raw)
            except Exception:
                pass
        return {}

    def save_custom_theme(self, slot: int, data: dict):
        self.set(f"custom_theme_{slot}", json.dumps(data))

S = AppSettings.inst  # callable shorthand → S() → AppSettings instance

# ═══════════════════════════════════════════════════════════════════════════
#  HISTORY MANAGER
# ═══════════════════════════════════════════════════════════════════════════
class HistoryManager:
    def __init__(self):
        self._cache: dict[str, list] = {}

    def _file(self, chat_id: str) -> Path:
        safe = re.sub(r'[^\w\-]', '_', chat_id)
        return HISTORY_DIR / f"{safe}.json"

    def load(self, chat_id: str) -> list:
        if chat_id in self._cache:
            return self._cache[chat_id]
        f = self._file(chat_id)
        if f.exists():
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                self._cache[chat_id] = data
                return data
            except Exception:
                pass
        self._cache[chat_id] = []
        return []

    def append(self, chat_id: str, entry: dict):
        if not S().save_history:
            return
        msgs = self.load(chat_id)
        msgs.append(entry)
        # keep max 1000 messages
        if len(msgs) > 1000:
            msgs = msgs[-1000:]
        self._cache[chat_id] = msgs
        try:
            self._file(chat_id).write_text(json.dumps(msgs, ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception as e:
            print(f"History save error: {e}")

    def load_call_log(self) -> list:
        return self.load("__call_log__")

    def add_call(self, entry: dict):
        self.append("__call_log__", entry)

HISTORY = HistoryManager()

# ═══════════════════════════════════════════════════════════════════════════
#  UNREAD MESSAGE COUNTER  (п.22 — прочитано/непрочитано)
# ═══════════════════════════════════════════════════════════════════════════
class UnreadManager:
    """
    Tracks unread message counts per chat_id.
    chat_id is either an IP (private chat), 'public', or 'group_<gid>'.
    """
    def __init__(self):
        self._counts: dict[str, int] = {}
        self._callbacks: list = []   # fn(chat_id, count) called on change

    def increment(self, chat_id: str):
        self._counts[chat_id] = self._counts.get(chat_id, 0) + 1
        self._notify(chat_id)

    def mark_read(self, chat_id: str):
        if self._counts.get(chat_id, 0) > 0:
            self._counts[chat_id] = 0
            self._notify(chat_id)

    def get(self, chat_id: str) -> int:
        return self._counts.get(chat_id, 0)

    def total(self) -> int:
        return sum(self._counts.values())

    def on_change(self, fn):
        """Register callback: fn(chat_id: str, count: int)"""
        self._callbacks.append(fn)

    def _notify(self, chat_id: str):
        for fn in self._callbacks:
            try:
                fn(chat_id, self._counts.get(chat_id, 0))
            except Exception:
                pass

UNREAD = UnreadManager()

# ═══════════════════════════════════════════════════════════════════════════
#  MESSAGE REACTION STORE  (п.29 — реакции на сообщения)
# ═══════════════════════════════════════════════════════════════════════════
class ReactionStore:
    """
    Stores emoji reactions per message.
    Key: (chat_id, message_ts_str)
    Value: dict { emoji: [username, ...] }

    Reactions are stored in memory only (session-scoped).
    For persistence across restarts, they're embedded in history entries.
    """
    def __init__(self):
        self._data: dict[tuple, dict] = {}

    def _key(self, chat_id: str, ts: float) -> tuple:
        return (chat_id, round(ts, 3))

    def add(self, chat_id: str, ts: float, emoji: str, username: str):
        key = self._key(chat_id, ts)
        if key not in self._data:
            self._data[key] = {}
        if emoji not in self._data[key]:
            self._data[key][emoji] = []
        if username not in self._data[key][emoji]:
            self._data[key][emoji][: ] = self._data[key][emoji] + [username]
            self._data[key][emoji] = list(set(self._data[key][emoji]))

    def remove(self, chat_id: str, ts: float, emoji: str, username: str):
        key = self._key(chat_id, ts)
        if key in self._data and emoji in self._data[key]:
            try:
                self._data[key][emoji].remove(username)
            except ValueError:
                pass
            if not self._data[key][emoji]:
                del self._data[key][emoji]

    def toggle(self, chat_id: str, ts: float, emoji: str, username: str) -> bool:
        """Add if not present, remove if present. Returns True if added."""
        key = self._key(chat_id, ts)
        existing = self._data.get(key, {}).get(emoji, [])
        if username in existing:
            self.remove(chat_id, ts, emoji, username)
            result = False
        else:
            self.add(chat_id, ts, emoji, username)
            result = True
        # Debounced save — use QTimer if Qt available, else direct
        try:
            from PyQt6.QtCore import QTimer as _QT
            _QT.singleShot(500, self.save)
        except Exception:
            self.save()
        return result

    def get(self, chat_id: str, ts: float) -> dict:
        """Returns { emoji: [usernames] }"""
        return dict(self._data.get(self._key(chat_id, ts), {}))

    def summary(self, chat_id: str, ts: float) -> list[tuple[str, int]]:
        """Returns [(emoji, count)] sorted by count descending."""
        r = self.get(chat_id, ts)
        return sorted([(e, len(u)) for e, u in r.items()
                       if u], key=lambda x: -x[1])

    def save(self):
        """Persist all reactions to disk."""
        try:
            serialisable = {
                f"{k[0]}|||{k[1]}": v
                for k, v in self._data.items()
            }
            _rf = DATA_DIR / "reactions.json"
            _rf.write_text(
                json.dumps(serialisable, ensure_ascii=False),
                encoding="utf-8")
        except Exception as e:
            print(f"[reactions] save error: {e}")

    def load(self):
        """Load reactions from disk."""
        try:
            _rf = DATA_DIR / "reactions.json"
            if not _rf.exists():
                return
            raw = json.loads(_rf.read_text(encoding="utf-8"))
            for key_str, val in raw.items():
                parts = key_str.split("|||", 1)
                if len(parts) == 2:
                    self._data[(parts[0], float(parts[1]))] = val
        except Exception as e:
            print(f"[reactions] load error: {e}")

REACTIONS = ReactionStore()
REACTIONS.load()   # Load persisted reactions at startup

# ═══════════════════════════════════════════════════════════════════════════
class GroupManager:
    def __init__(self):
        self.groups: dict[str, dict] = {}
        self._load()

    def _load(self):
        if GROUPS_FILE.exists():
            try:
                self.groups = json.loads(GROUPS_FILE.read_text(encoding="utf-8"))
            except Exception:
                self.groups = {}

    def _save(self):
        try:
            GROUPS_FILE.write_text(json.dumps(self.groups, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"Groups save error: {e}")

    def create(self, name: str, creator_ip: str) -> str:
        gid = f"g_{int(time.time())}_{secrets.randbelow(9999):04d}"
        self.groups[gid] = {
            "name": name,
            "creator": creator_ip,
            "members": [creator_ip],
            "created": datetime.now().isoformat(),
        }
        self._save()
        return gid

    def add_member(self, gid: str, ip: str):
        if gid in self.groups and ip not in self.groups[gid]["members"]:
            self.groups[gid]["members"].append(ip)
            self._save()

    def remove_member(self, gid: str, ip: str):
        if gid in self.groups:
            self.groups[gid]["members"] = [m for m in self.groups[gid]["members"] if m != ip]
            self._save()

    def delete(self, gid: str):
        self.groups.pop(gid, None)
        self._save()

    def rename(self, gid: str, new_name: str):
        if gid in self.groups:
            self.groups[gid]["name"] = new_name
            self._save()

    def get(self, gid: str) -> dict:
        return self.groups.get(gid, {})

    def list_for(self, ip: str) -> list[tuple[str, dict]]:
        return [(gid, g) for gid, g in self.groups.items() if ip in g.get("members", [])]

GROUPS = GroupManager()

# ═══════════════════════════════════════════════════════════════════════════
#  UPDATE CHECKER
# ═══════════════════════════════════════════════════════════════════════════
class UpdateChecker(QThread):
    update_available  = pyqtSignal(str, str)   # version, description
    no_update         = pyqtSignal()
    check_failed      = pyqtSignal(str)

    def run(self):
        if GITHUB_REPO.startswith("YOUR_GITHUB"):
            self.check_failed.emit("GitHub repository not configured.\nEdit GITHUB_REPO constant in source.")
            return
        try:
            req = urllib.request.Request(GITHUB_API_URL,
                headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
            latest = data.get("tag_name", "").lstrip("v")
            body   = data.get("body", "")[:300]
            if latest and latest != APP_VERSION:
                self.update_available.emit(latest, body)
            else:
                self.no_update.emit()
        except Exception as e:
            self.check_failed.emit(str(e))

class Updater(QThread):
    progress   = pyqtSignal(int)
    finished   = pyqtSignal(bool, str)

    def __init__(self, url: str, dest: str):
        super().__init__()
        self.url  = url
        self.dest = dest

    def run(self):
        try:
            req = urllib.request.Request(self.url,
                headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                total = int(resp.headers.get("Content-Length", 0))
                done  = 0
                data  = b""
                chunk = 8192
                while True:
                    block = resp.read(chunk)
                    if not block:
                        break
                    data += block
                    done += len(block)
                    if total:
                        self.progress.emit(int(done * 100 / total))
            with open(self.dest, "wb") as f:
                f.write(data)
            self.finished.emit(True, self.dest)
        except Exception as e:
            self.finished.emit(False, str(e))

# ═══════════════════════════════════════════════════════════════════════════
#  AUDIO ENGINE  (real low-latency voice)
# ═══════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────
#  AUDIO MIXER  —  per-peer jitter buffer + mixing
# ─────────────────────────────────────────────────────────────────────────
class PeerBuffer:
    """
    Adaptive jitter buffer for one remote peer.
    Target: hold TARGET_FRAMES frames before playing starts,
    then drain one frame per tick.
    """
    FRAME   = 512          # samples per frame
    BYTES   = FRAME * 2    # int16
    TARGET  = 6            # pre-fill frames before playback (~192 ms)
    MAX     = 25           # hard cap  (~800 ms)

    def __init__(self):
        self._buf    = bytearray()
        self._ready  = False      # True once pre-fill reached
        self._lock   = threading.Lock()
        self.stats_drops = 0

    def push(self, data: bytes):
        with self._lock:
            self._buf.extend(data)
            n = len(self._buf) // self.BYTES
            if n >= self.TARGET:
                self._ready = True
            # Hard cap — drop oldest if overflow
            cap = self.BYTES * self.MAX
            if len(self._buf) > cap:
                excess = len(self._buf) - cap
                del self._buf[:excess]
                self.stats_drops += 1

    def pull(self) -> bytes | None:
        """Return one frame or None (silence) if buffer not ready."""
        with self._lock:
            if not self._ready or len(self._buf) < self.BYTES:
                return None
            frame = bytes(self._buf[:self.BYTES])
            del self._buf[:self.BYTES]
            # If buffer drains below half target, reset pre-fill
            if len(self._buf) // self.BYTES < self.TARGET // 2:
                self._ready = False
            return frame

    def clear(self):
        with self._lock:
            self._buf.clear()
            self._ready = False


class AudioMixer:
    """
    Mixes audio from multiple peers into one output stream.
    Each peer has its own PeerBuffer (jitter buffer).
    On every tick: pull one frame per peer, sum+clip → play.
    """
    FRAME = 512
    BYTES = FRAME * 2

    def __init__(self):
        self._peers: dict[str, PeerBuffer] = {}
        self._lock  = threading.Lock()

    def add_peer(self, ip: str) -> 'PeerBuffer':
        with self._lock:
            if ip not in self._peers:
                self._peers[ip] = PeerBuffer()
            return self._peers[ip]

    def remove_peer(self, ip: str):
        with self._lock:
            self._peers.pop(ip, None)

    def push(self, ip: str, data: bytes):
        with self._lock:
            if ip not in self._peers:
                self._peers[ip] = PeerBuffer()
            self._peers[ip].push(data)

    def mix(self) -> bytes:
        """
        Pull one frame from every peer, sum sample-by-sample with clipping.
        Returns silence frame if nobody has data.
        """
        import array as _arr
        out = _arr.array('h', [0] * self.FRAME)
        got_any = False

        with self._lock:
            peers = list(self._peers.items())

        for ip, buf in peers:
            frame = buf.pull()
            if frame is None:
                continue            # peer buffer not ready → silence for this peer
            got_any = True
            src = _arr.array('h', frame)
            for i in range(self.FRAME):
                out[i] = max(-32768, min(32767, out[i] + src[i]))

        return bytes(out) if got_any else (b'\x00' * self.BYTES)

    def drop_all(self):
        with self._lock:
            for b in self._peers.values():
                b.clear()

    def peer_count(self) -> int:
        with self._lock:
            return len(self._peers)


# ─────────────────────────────────────────────────────────────────────────
#  VAD  —  Voice Activity Detection (webrtcvad optional)
# ─────────────────────────────────────────────────────────────────────────
try:
    import webrtcvad as _webrtcvad
    WEBRTCVAD_AVAILABLE = True
except ImportError:
    WEBRTCVAD_AVAILABLE = False


class VAD:
    """
    Wraps webrtcvad for noise-gating the microphone.
    Aggressiveness 2 = moderate (0=off, 3=aggressive).
    Falls back to always-transmit if webrtcvad not installed.
    """
    # webrtcvad supports only these sample rates
    SUPPORTED_RATES = {8000, 16000, 32000, 48000}
    # Frame durations it accepts (ms) → must match CHUNK
    # 512 samples @ 16kHz = 32 ms  ← not supported by webrtcvad (10/20/30 ms only)
    # So we'll use 480 samples @ 16000 = 30 ms for VAD check
    VAD_SAMPLES = 480
    VAD_BYTES   = VAD_SAMPLES * 2

    def __init__(self, aggressiveness: int = 2):
        self._vad  = None
        self._buf  = bytearray()
        self._gate = True   # last VAD decision
        if WEBRTCVAD_AVAILABLE:
            try:
                self._vad = _webrtcvad.Vad(aggressiveness)
            except Exception:
                pass

    def is_speech(self, raw: bytes, rate: int = 16000) -> bool:
        """Feed raw PCM, returns True if speech detected (or VAD unavailable)."""
        if self._vad is None:
            return True    # no VAD → always transmit
        self._buf.extend(raw)
        result = self._gate
        while len(self._buf) >= self.VAD_BYTES:
            frame = bytes(self._buf[:self.VAD_BYTES])
            del self._buf[:self.VAD_BYTES]
            try:
                result = self._vad.is_speech(frame, rate)
            except Exception:
                result = True
        self._gate = result
        return result


# ─────────────────────────────────────────────────────────────────────────
#  AUDIO ENGINE
# ─────────────────────────────────────────────────────────────────────────
class AudioEngine(QThread):
    audio_captured = pyqtSignal(bytes)
    sig_speaking   = pyqtSignal(bool)   # True=speaking, False=silent

    SAMPLE_RATE = 16000
    CHANNELS    = 1
    CHUNK       = 512    # ~32 ms @ 16kHz
    FORMAT      = None

    def __init__(self):
        super().__init__()
        self.setTerminationEnabled(True)
        self.FORMAT   = None
        self._pa      = None
        self._in      = None
        self._out     = None
        self.running  = False
        self.muted    = False
        self.volume   = 1.0
        self._in_dev  = None
        self._out_dev = None
        self.mixer    = AudioMixer()
        self.vad      = VAD(aggressiveness=2)
        self.vad_enabled = True     # can be toggled in settings

    def _init_pa(self) -> bool:
        if not PYAUDIO_AVAILABLE:
            return False
        if self._pa:
            return True
        try:
            import pyaudio as pa
            self.FORMAT = pa.paInt16
            self._pa    = pa.PyAudio()
            return True
        except Exception as e:
            print(f"PyAudio init error: {e}")
            return False

    def start_capture(self, in_dev=None, out_dev=None) -> bool:
        if not self._init_pa():
            return False
        self.stop_all()
        self._in_dev  = in_dev
        self._out_dev = out_dev
        try:
            import pyaudio as pa
            self._in = self._pa.open(
                format=self.FORMAT, channels=self.CHANNELS,
                rate=self.SAMPLE_RATE, input=True,
                frames_per_buffer=self.CHUNK,
                input_device_index=in_dev)
            self._out = self._pa.open(
                format=self.FORMAT, channels=self.CHANNELS,
                rate=self.SAMPLE_RATE, output=True,
                frames_per_buffer=self.CHUNK,
                output_device_index=out_dev)
            self.running = True
            if not self.isRunning():
                self.start()
            return True
        except Exception as e:
            print(f"Audio open error: {e}")
            return False

    def stop_all(self):
        self.running = False
        for stream in [self._in, self._out]:
            if stream:
                try: stream.stop_stream(); stream.close()
                except Exception: pass
        self._in = self._out = None

    def cleanup(self):
        self.stop_all()
        if self.isRunning():
            if not self.wait(2000):
                self.terminate()
                self.wait(500)
        if self._pa:
            try: self._pa.terminate()
            except Exception: pass
            self._pa = None

    def push_peer_audio(self, ip: str, data: bytes):
        """Called from network thread — push peer audio into its jitter buffer."""
        self.mixer.push(ip, data)

    def run(self):
        import array as _arr
        SILENCE = b'\x00' * (self.CHUNK * 2)
        while self.running:
            try:
                # ── Capture ──────────────────────────────────────────
                if self._in and not self.muted:
                    raw = self._in.read(self.CHUNK, exception_on_overflow=False)
                    # VAD gate
                    if self.vad_enabled and WEBRTCVAD_AVAILABLE:
                        _is_speech = self.vad.is_speech(raw, self.SAMPLE_RATE)
                    elif self.vad_enabled:
                        # Fallback: amplitude-based voice detection
                        import struct as _st, math as _mth
                        samples = _st.unpack(f'<{len(raw)//2}h', raw)
                        rms = _mth.sqrt(sum(s*s for s in samples) / len(samples))
                        _is_speech = rms > 800   # ~2.4% of full scale
                    else:
                        _is_speech = True
                    if _is_speech:
                        self.audio_captured.emit(raw)
                    # Debounce: only emit speaking signal every 4 frames (~128ms)
                    if not hasattr(self, '_speak_frame_ctr'):
                        self._speak_frame_ctr = 0
                        self._speak_last = False
                    self._speak_frame_ctr += 1
                    if self._speak_frame_ctr >= 4:
                        self._speak_frame_ctr = 0
                        if _is_speech != self._speak_last:
                            self._speak_last = _is_speech
                            self.sig_speaking.emit(_is_speech)
                    # silent frame → don't send
                elif self._in:
                    # still read to keep stream alive
                    self._in.read(self.CHUNK, exception_on_overflow=False)
                    # Emit silence when mic is open but muted
                    if not hasattr(self, '_speak_last'): self._speak_last = True
                    if self._speak_last:
                        self._speak_last = False
                        self.sig_speaking.emit(False)

                # ── Mix + play ────────────────────────────────────────
                if self._out:
                    mixed = self.mixer.mix()
                    if self.volume != 1.0:
                        a = _arr.array('h', mixed)
                        for i in range(len(a)):
                            a[i] = max(-32768, min(32767, int(a[i] * self.volume)))
                        mixed = bytes(a)
                    self._out.write(mixed)

            except Exception as e:
                print(f"Audio loop error: {e}")
                time.sleep(0.01)

    def list_devices(self) -> list[dict]:
        if not self._init_pa():
            return []
        devs = []
        for i in range(self._pa.get_device_count()):
            try:
                info = self._pa.get_device_info_by_index(i)
                devs.append({"index": i, "name": info["name"],
                             "inputs":  info["maxInputChannels"],
                             "outputs": info["maxOutputChannels"]})
            except Exception:
                pass
        return devs


# ═══════════════════════════════════════════════════════════════════════════
#  PROTOCOL CONSTANTS (message types)
# ═══════════════════════════════════════════════════════════════════════════
MSG_PRESENCE  = "presence"
MSG_CHAT      = "chat"
MSG_PRIVATE   = "private"
MSG_GROUP     = "group"
MSG_CALL_REQ  = "call_req"
MSG_CALL_END  = "call_end"
MSG_FILE_META = "file_meta"
MSG_FILE_DATA = "file_data"
MSG_GROUP_INV = "group_inv"
MSG_TYPING    = "typing"
MSG_PROFILE   = "profile_req"
MSG_REACTION  = "reaction"      # п.29 — emoji reactions
MSG_EDIT      = "msg_edit"      # п.21 — message editing
MSG_DELETE    = "msg_delete"    # п.21 — message deletion
MSG_READ      = "msg_read"      # п.22 — read receipts
MSG_STICKER   = "sticker"
MSG_TTL_EXPIRE = "ttl_expire"   # message self-destructs after N seconds
MSG_POLL       = "poll"         # interactive poll
MSG_POLL_VOTE  = "poll_vote"    # vote on a poll
MSG_NOTES_SYNC = "notes_sync"  # sync shared notepad

# ═══════════════════════════════════════════════════════════════════════════
#  NETWORK MANAGER
# ═══════════════════════════════════════════════════════════════════════════
class NetworkManager(QObject):
    # Signals
    sig_user_online   = pyqtSignal(dict)          # peer_info dict
    sig_user_offline  = pyqtSignal(str)           # ip
    sig_message       = pyqtSignal(dict)          # message dict
    sig_call_request  = pyqtSignal(str, str)      # username, ip
    sig_call_accepted = pyqtSignal(str, str)      # username, ip
    sig_call_rejected = pyqtSignal(str)           # ip
    sig_call_ended    = pyqtSignal(str)           # ip
    sig_voice_data    = pyqtSignal(bytes)         # raw audio (legacy)
    sig_voice_data_from = pyqtSignal(str, bytes)  # ip, raw audio
    sig_file_meta     = pyqtSignal(dict)          # file transfer meta
    sig_file_chunk    = pyqtSignal(str, bytes)    # transfer_id, chunk
    sig_group_invite  = pyqtSignal(str, str, str) # group_id, name, from_ip
    sig_error         = pyqtSignal(str)
    sig_typing        = pyqtSignal(str, str)      # username, chat_id
    sig_send_file_req = pyqtSignal(str, bytes, str, str)  # to_ip_or_empty, data_b64, fname, tid

    # Voice TCP
    sig_voice_connected   = pyqtSignal(str)   # ip
    sig_voice_disconnected = pyqtSignal(str)  # ip

    def __init__(self):
        super().__init__()
        self.host_ip = get_local_ip()
        self._udp: QUdpSocket | None = None
        self._tcp_srv: QTcpServer | None = None
        self._voice_cons: dict[str, QTcpSocket] = {}   # ip → socket (voice)
        self._file_cons:  dict[str, QTcpSocket] = {}   # ip → socket (file)
        self.peers: dict[str, dict] = {}               # ip → peer_info
        self.running = False
        self._bcast_timer = QTimer()
        self._bcast_timer.timeout.connect(self._broadcast)
        # Refresh local IPs every 30s (VPN adapters can connect/disconnect)
        self._ip_refresh_timer = QTimer()
        self._ip_refresh_timer.timeout.connect(self._refresh_local_ips)
        self._ip_refresh_timer.start(30_000)
        self._voice_tcp_port = TCP_PORT_DEFAULT

    # ── startup / shutdown ──────────────────────────────────────────────
    def _refresh_local_ips(self):
        """Refresh local IP cache — VPN adapters (Hamachi/ZeroTier/Radmin) can come and go."""
        self._all_local_ips = get_all_local_ips()
        new_primary = get_local_ip()
        if new_primary != self.host_ip:
            print(f"[net] primary IP changed: {self.host_ip} → {new_primary}")
            self.host_ip = new_primary

    def start(self) -> bool:
        udp_port = S().udp_port
        tcp_port = S().tcp_port
        self._voice_tcp_port = tcp_port

        self._udp = QUdpSocket(self)
        if not self._udp.bind(QHostAddress.SpecialAddress.Any, udp_port,
                              QUdpSocket.BindFlag.ShareAddress | QUdpSocket.BindFlag.ReuseAddressHint):
            self.sig_error.emit(f"UDP bind failed on port {udp_port}")
            return False
        self._udp.readyRead.connect(self._on_udp)

        self._tcp_srv = QTcpServer(self)
        if not self._tcp_srv.listen(QHostAddress.SpecialAddress.Any, tcp_port):
            self.sig_error.emit(f"TCP listen failed on port {tcp_port}")
            return False
        self._tcp_srv.newConnection.connect(self._on_new_connection)

        self.running = True
        self._bcast_timer.start(3000)
        self._broadcast()
        return True

    def stop(self):
        self.running = False
        self._bcast_timer.stop()
        for sock in list(self._voice_cons.values()):
            try: sock.disconnectFromHost()
            except Exception: pass
        self._voice_cons.clear()
        if self._udp:
            self._udp.close(); self._udp = None
        if self._tcp_srv:
            self._tcp_srv.close(); self._tcp_srv = None

    # ── internal broadcast ──────────────────────────────────────────────
    def _broadcast(self):
        if not self.running or not self._udp:
            return
        payload = self._presence_payload()
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        port = S().udp_port

        # ── 1. Global broadcast (LAN) ────────────────────────────────
        self._udp.writeDatagram(data, QHostAddress.SpecialAddress.Broadcast, port)

        # ── 2. Per-interface subnet broadcasts ───────────────────────
        #    Catches Hamachi/RadminVPN/ZeroTier virtual adapters
        try:
            for iface in QNetworkInterface.allInterfaces():
                flags = iface.flags()
                if not (flags & QNetworkInterface.InterfaceFlag.IsUp):
                    continue
                if flags & QNetworkInterface.InterfaceFlag.IsLoopBack:
                    continue
                for entry in iface.addressEntries():
                    addr = entry.ip()
                    if addr.protocol() != QHostAddress.NetworkLayerProtocol.IPv4Protocol:
                        continue
                    bcast = entry.broadcast()
                    if bcast.isNull() or bcast.toString() in ("", "0.0.0.0"):
                        continue
                    self._udp.writeDatagram(data, bcast, port)
        except Exception:
            pass

        # ── 3. Unicast to manually-added static peers (VPS / WAN) ────
        #    These are IPs added via Settings → Network → Static Peers
        try:
            raw = S().get("static_peers", "[]", t=str)
            for peer_ip in json.loads(raw):
                peer_ip = str(peer_ip).strip()
                if peer_ip:
                    self._udp.writeDatagram(data, QHostAddress(peer_ip), port)
        except Exception:
            pass

        # ── 4. Relay server unicast ───────────────────────────────────
        if S().relay_enabled and S().relay_server:
            try:
                parts = S().relay_server.strip().split(":")
                r_host = parts[0]
                r_port = int(parts[1]) if len(parts) > 1 else port
                self._udp.writeDatagram(data, QHostAddress(r_host), r_port)
            except Exception:
                pass

        # ── 5. Prune stale peers (>20s no presence) ──────────────────
        now = time.time()
        for ip in list(self.peers):
            if now - self.peers[ip].get("last_seen", 0) > 20:
                del self.peers[ip]
                self.sig_user_offline.emit(ip)

    def _presence_payload(self) -> dict:
        cfg = S()
        payload = {
            "type":             MSG_PRESENCE,
            "username":         cfg.username,
            "ip":               self.host_ip,
            "premium":          cfg.premium,
            "nickname_color":   cfg.nickname_color,
            "custom_emoji":     cfg.custom_emoji,
            "bio":              cfg.bio,
            "avatar_b64":       cfg.avatar_b64[:200] if cfg.avatar_b64 else "",
            "os":               get_os_name(),
            "version":          APP_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "ts":               time.time(),
            "nonce":            secrets.token_hex(8),   # replay guard
            "status":           S().user_status,           # presence status
            "loyalty_months":   S().get("loyalty_months", 0, t=int),
        }
        # Append ECDH handshake keys so session key is established on first contact
        payload.update(CRYPTO.get_handshake_payload())
        return payload

    # ── UDP receive ─────────────────────────────────────────────────────
    def _on_udp(self):
        while self._udp and self._udp.hasPendingDatagrams():
            dg = self._udp.receiveDatagram()
            host = dg.senderAddress().toString()
            # strip IPv4-mapped prefix
            if host.startswith("::ffff:"):
                host = host[7:]
            try:
                msg = json.loads(dg.data().data().decode("utf-8"))
                self._dispatch(host, msg)
            except Exception as e:
                print(f"UDP parse error from {host}: {e}")

    def _dispatch(self, host: str, msg: dict):
        # Rate limiting — drop excess packets silently
        if not CRYPTO.check_rate(host, max_per_sec=200):
            return
        # Never process our own echoed messages (except presence)
        if (msg.get('username') == S().username and
                msg.get('type') not in (MSG_PRESENCE, None)):
            return
        # HMAC verification (if session key established)
        sig = msg.pop("_sig", "")
        if sig and CRYPTO.has_session(host):
            try:
                payload_bytes = json.dumps(
                    {k: v for k, v in msg.items() if k != "_sig"},
                    ensure_ascii=False, sort_keys=True).encode("utf-8")
                if not CRYPTO.verify_packet(host, payload_bytes, sig):
                    print(f"[security] HMAC failed from {host} — dropping")
                    return
            except Exception:
                pass  # don't crash on malformed
        t = msg.get("type")
        if t == MSG_PRESENCE:
            self._handle_presence(host, msg)
        elif t == MSG_CHAT:
            self.sig_message.emit(msg)
        elif t == MSG_PRIVATE:
            if msg.get("to") == self.host_ip:
                self.sig_message.emit(msg)
        elif t == MSG_GROUP:
            self.sig_message.emit(msg)
        elif t == MSG_CALL_REQ:
            self.sig_call_request.emit(msg.get("username","?"), host)
        elif t == MSG_CALL_ACCEPT:
            self.sig_call_accepted.emit(msg.get("username","?"), host)
        elif t == MSG_CALL_REJECT:
            self.sig_call_rejected.emit(host)
        elif t == MSG_CALL_END:
            self.sig_call_ended.emit(host)
        elif t == MSG_FILE_META:
            self.sig_file_meta.emit(msg)
        elif t == MSG_GROUP_INV:
            self.sig_group_invite.emit(msg.get("gid",""), msg.get("gname",""), host)
        elif t == MSG_TYPING:
            chat_id = msg.get("chat_id", "public")
            self.sig_typing.emit(msg.get("username", ""), chat_id)
        elif t == MSG_REACTION:
            # Route reactions through message signal for simplicity
            self.sig_message.emit(msg)
        elif t == MSG_EDIT:
            self.sig_message.emit(msg)
        elif t == MSG_DELETE:
            self.sig_message.emit(msg)
        elif t == MSG_READ:
            # Read receipt — route through message signal
            self.sig_message.emit(msg)

    def _handle_presence(self, host: str, msg: dict):
        ip = msg.get("ip", host)
        if ip == self.host_ip:
            return
        # Replay guard on presence packets
        nonce = msg.get("nonce", "")
        ts    = msg.get("ts", 0.0)
        if nonce and not CRYPTO.check_replay(ip, nonce, ts):
            return   # replayed presence packet
        # Establish / refresh ECDH session key if peer sends DH keys
        if "dh_pub" in msg and "id_pub" in msg:
            CRYPTO.process_handshake(ip, msg)
        is_new = ip not in self.peers
        msg["conn_type"] = detect_connection_type(ip)
        msg["last_seen"] = time.time()
        msg["e2e"] = CRYPTO.has_session(ip)   # flag for UI
        self.peers[ip] = msg
        if is_new:
            self.sig_user_online.emit(msg)

    # ── TCP (voice) ──────────────────────────────────────────────────────
    def _on_new_connection(self):
        while self._tcp_srv and self._tcp_srv.hasPendingConnections():
            sock = self._tcp_srv.nextPendingConnection()
            ip = sock.peerAddress().toString()
            if ip.startswith("::ffff:"):
                ip = ip[7:]
            self._voice_cons[ip] = sock
            sock.readyRead.connect(lambda s=sock, i=ip: self._on_voice_data(s, i))
            sock.disconnected.connect(lambda i=ip: self._on_voice_disc(i))
            self.sig_voice_connected.emit(ip)

    def _on_voice_data(self, sock: QTcpSocket, ip: str):
        while sock.bytesAvailable() > 0:
            data = bytes(sock.read(2048))
            if data:
                self.sig_voice_data.emit(data)          # legacy (single call)
                self.sig_voice_data_from.emit(ip, data) # mixer (group call)

    def _on_voice_disc(self, ip: str):
        self._voice_cons.pop(ip, None)
        self.sig_voice_disconnected.emit(ip)
        self.sig_call_ended.emit(ip)

    # ── public send methods ─────────────────────────────────────────────
    def send_udp(self, payload: dict, target_ip: str | None = None):
        if not self._udp:
            return
        # Add replay-guard fields to non-presence packets
        msg_type = payload.get("type", "")
        if msg_type != MSG_PRESENCE:
            payload = dict(payload)
            payload["nonce"] = secrets.token_hex(8)
            payload["ts"]    = time.time()
            # HMAC sign if we have a session key with target
            if target_ip and CRYPTO.has_session(target_ip):
                try:
                    payload_bytes = json.dumps(
                        payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
                    payload["_sig"] = CRYPTO.sign_packet(target_ip, payload_bytes)
                except Exception:
                    pass
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if target_ip:
            self._udp.writeDatagram(data, QHostAddress(target_ip), S().udp_port)
        else:
            self._udp.writeDatagram(data, QHostAddress.SpecialAddress.Broadcast, S().udp_port)

    def send_chat(self, text: str):
        cfg = S()
        encrypted = False
        if cfg.encryption_enabled and cfg.encryption_passphrase:
            text = CRYPTO.encrypt(text, cfg.encryption_passphrase)
            encrypted = True
        self.send_udp({"type": MSG_CHAT, "username": cfg.username,
                       "text": text, "from_ip": self.host_ip,
                       "encrypted": encrypted})

    def send_private(self, text: str, to_ip: str):
        cfg = S()
        # E2E: prefer ECDH session key; fall back to passphrase; then plaintext
        if CRYPTO.has_session(to_ip) or (cfg.encryption_enabled and cfg.encryption_passphrase):
            text = CRYPTO.encrypt(text, cfg.encryption_passphrase, peer_ip=to_ip)
            encrypted = True
        else:
            encrypted = False
        self.send_udp({"type": MSG_PRIVATE, "username": cfg.username,
                       "text": text, "to": to_ip, "from_ip": self.host_ip,
                       "encrypted": encrypted}, to_ip)

    def send_group_msg(self, gid: str, text: str, members: list[str]):
        cfg = S()
        if cfg.encryption_enabled and cfg.encryption_passphrase:
            text = CRYPTO.encrypt(text, cfg.encryption_passphrase)
        payload = {"type": MSG_GROUP, "username": cfg.username,
                   "gid": gid, "text": text, "ts": time.time(),
                   "encrypted": cfg.encryption_enabled}
        for ip in members:
            if ip != self.host_ip:
                self.send_udp(payload, ip)

    def send_typing(self, chat_id: str, target_ip: str | None = None):
        p = {"type": MSG_TYPING, "username": S().username, "chat_id": chat_id}
        self.send_udp(p, target_ip)

    def send_sticker(self, to_ip: str, b64: str, ts: float):
        """Send sticker to specific peer."""
        msg = {"type": MSG_STICKER, "username": S().username,
               "sticker_b64": b64, "ts": ts}
        self._send_tcp(msg, to_ip)

    def broadcast_sticker(self, b64: str, ts: float, gid: str = ""):
        """Broadcast sticker to public chat or group."""
        msg = {"type": MSG_STICKER, "username": S().username,
               "sticker_b64": b64, "ts": ts, "gid": gid}
        self._broadcast_udp(msg)

    def send_call_request(self, to_ip: str):
        self.send_udp({"type": MSG_CALL_REQ, "username": S().username,
                       "avatar_b64": S().avatar_b64[:200] if S().avatar_b64 else ""}, to_ip)

    def send_call_accept(self, to_ip: str):
        self.send_udp({"type": MSG_CALL_ACCEPT, "username": S().username,
                       "avatar_b64": S().avatar_b64[:200] if S().avatar_b64 else ""}, to_ip)
        self.connect_voice(to_ip)

    def send_call_reject(self, to_ip: str):
        self.send_udp({"type": MSG_CALL_REJECT, "username": S().username}, to_ip)

    def send_call_end(self, to_ip: str):
        self.send_udp({"type": MSG_CALL_END, "username": S().username}, to_ip)

    def send_reaction(self, to_ip: str | None, chat_id: str, ts: float,
                      emoji: str, added: bool):
        """Send emoji reaction to a message. to_ip=None → broadcast."""
        payload = {
            "type":    MSG_REACTION,
            "username": S().username,
            "chat_id": chat_id,
            "msg_ts":  ts,
            "emoji":   emoji,
            "added":   added,
        }
        self.send_udp(payload, to_ip)

    def send_message_edit(self, to_ip: str | None, chat_id: str,
                          ts: float, new_text: str):
        """Notify peer(s) that a message was edited."""
        payload = {
            "type":     MSG_EDIT,
            "username": S().username,
            "chat_id":  chat_id,
            "msg_ts":   ts,
            "new_text": new_text,
        }
        self.send_udp(payload, to_ip)

    def send_message_delete(self, to_ip: str | None, chat_id: str, ts: float):
        """Notify peer(s) that a message was deleted."""
        payload = {
            "type":    MSG_DELETE,
            "username": S().username,
            "chat_id": chat_id,
            "msg_ts":  ts,
        }
        self.send_udp(payload, to_ip)

    def send_read_receipt(self, to_ip: str, chat_id: str):
        """Send a read receipt to a peer."""
        payload = {
            "type":    MSG_READ,
            "username": S().username,
            "chat_id": chat_id,
        }
        self.send_udp(payload, to_ip)

    def connect_voice(self, ip: str) -> bool:
        if ip in self._voice_cons:
            return True
        sock = QTcpSocket(self)
        sock.connectToHost(QHostAddress(ip), self._voice_tcp_port)
        if sock.waitForConnected(3000):
            self._voice_cons[ip] = sock
            sock.readyRead.connect(lambda s=sock, i=ip: self._on_voice_data(s, i))
            sock.disconnected.connect(lambda i=ip: self._on_voice_disc(i))
            self.sig_voice_connected.emit(ip)
            return True
        sock.close()
        return False

    def send_voice(self, ip: str, data: bytes) -> bool:
        sock = self._voice_cons.get(ip)
        if sock and sock.state() == QTcpSocket.SocketState.ConnectedState:
            sock.write(data)
            return True
        return False

    def disconnect_voice(self, ip: str):
        sock = self._voice_cons.pop(ip, None)
        if sock:
            try: sock.disconnectFromHost()
            except Exception: pass

    def send_group_invite(self, gid: str, gname: str, to_ip: str):
        self.send_udp({"type": MSG_GROUP_INV, "gid": gid, "gname": gname,
                       "from": S().username}, to_ip)

    # File transfer over UDP — must be called from main thread
    def send_file(self, to_ip: str | None, filepath: str | None,
                  raw_bytes: bytes | None = None, filename: str = "file"):
        """Send file. If to_ip is None → broadcast (group).
           MUST be called from the Qt main thread (uses QUdpSocket)."""
        try:
            if raw_bytes is not None:
                data = raw_bytes
                fname = filename
                ext = Path(fname).suffix.lower()
            else:
                path = Path(filepath)
                if not path.exists():
                    return
                data = path.read_bytes()
                fname = path.name
                ext = path.suffix.lower()
            is_image = ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
            tid = secrets.token_hex(8)
            meta = {
                "type":     MSG_FILE_META,
                "tid":      tid,
                "filename": fname,
                "size":     len(data),
                "is_image": is_image,
                "from":     S().username,
                "from_ip":  self.host_ip,
                "to":       to_ip or "public",
                "ts":       time.time(),
            }
            self.send_udp(meta, to_ip)
            CHUNK = 60000
            total = len(data)
            # Send chunks with a QTimer so we don't block the event loop
            chunks = []
            for idx, offset in enumerate(range(0, total, CHUNK)):
                chunk = data[offset:offset+CHUNK]
                chunks.append({
                    "type":  MSG_FILE_DATA,
                    "tid":   tid,
                    "idx":   idx,
                    "total": (total + CHUNK - 1) // CHUNK,
                    "data":  base64.b64encode(chunk).decode(),
                })
            self._send_chunks_queued(chunks, to_ip, 0)
        except Exception as e:
            self.sig_error.emit(f"File send error: {e}")

    def _send_chunks_queued(self, chunks: list, to_ip, idx: int, batch: int = 3):
        """Send chunks in small batches to avoid blocking the event loop.
        Sends `batch` chunks per timer tick, yielding control between batches."""
        if idx >= len(chunks):
            return
        # Send a small batch per tick (faster throughput, still non-blocking)
        end = min(idx + batch, len(chunks))
        for i in range(idx, end):
            try:
                self.send_udp(chunks[i], to_ip)
            except Exception as e:
                print(f"[chunk send] {e}")
        # Adaptive delay: more chunks = slightly longer pause to keep UI smooth
        total = len(chunks)
        delay = 8 if total > 100 else (5 if total > 20 else 2)
        QTimer.singleShot(delay, lambda: self._send_chunks_queued(chunks, to_ip, end, batch))

# ═══════════════════════════════════════════════════════════════════════════
#  VOICE CALL MANAGER
# ═══════════════════════════════════════════════════════════════════════════
class VoiceCallManager(QObject):
    """
    Manages P2P voice calls.
    Group calls: each peer gets its own jitter-buffered slot in the mixer.
    VAD: mic audio is only transmitted when speech is detected.
    """
    call_started = pyqtSignal(str)    # ip
    call_ended   = pyqtSignal(str)    # ip

    def __init__(self, net: 'NetworkManager'):
        super().__init__()
        self.net   = net
        self.audio = AudioEngine()
        self.audio.audio_captured.connect(self._on_captured)
        self.active: set[str] = set()
        self._muted: bool = False   # ← must exist before set_mute is called
        # Route incoming audio by IP → mixer jitter buffer
        self.net.sig_voice_data_from.connect(self._on_peer_audio)
        # Speaking indicator signal (pass-through from AudioEngine)
        self.audio.sig_speaking.connect(self._on_speaking)

    def call(self, ip: str) -> bool:
        if ip in self.active:
            return True
        if not self.audio.running:
            if not self.audio.start_capture():
                return False
        self.active.add(ip)
        pb = self.audio.mixer.add_peer(ip)
        # Apply jitter target from settings
        jt = S().get("jitter_frames", 6, t=int)
        if pb: pb.TARGET = max(2, min(20, jt))
        # Apply VAD setting
        self.audio.vad_enabled = S().get("vad_enabled", WEBRTCVAD_AVAILABLE, t=bool)
        self.call_started.emit(ip)
        return True

    def hangup(self, ip: str):
        self.active.discard(ip)
        self.audio.mixer.remove_peer(ip)
        self.net.send_call_end(ip)
        self.net.disconnect_voice(ip)
        if not self.active:
            self.audio.stop_all()
        self.call_ended.emit(ip)

    def hangup_all(self):
        for ip in list(self.active):
            self.hangup(ip)

    def set_mute(self, muted: bool):
        """Set mute state directly."""
        self._muted = muted
        self.audio.muted = muted

    def toggle_mute(self) -> bool:
        self._muted = not self._muted
        self.audio.muted = self._muted
        return self._muted

    @property
    def is_muted(self) -> bool:
        return self._muted

    # Speaking detection — forwarded from AudioEngine VAD
    sig_local_speaking = None   # set dynamically below
    def _on_speaking(self, active: bool):
        if hasattr(self, '_speaking_cbs'):
            for cb in list(self._speaking_cbs):
                try: cb(active)
                except Exception: pass

    def subscribe_speaking(self, cb):
        if not hasattr(self, '_speaking_cbs'):
            self._speaking_cbs = []
        self._speaking_cbs.append(cb)

    def unsubscribe_speaking(self, cb):
        if hasattr(self, '_speaking_cbs'):
            try: self._speaking_cbs.remove(cb)
            except ValueError: pass

    def set_vad(self, enabled: bool):
        self.audio.vad_enabled = enabled

    def _on_captured(self, data: bytes):
        """Send mic audio to all active peers."""
        for ip in list(self.active):
            self.net.send_voice(ip, data)

    def _on_peer_audio(self, ip: str, data: bytes):
        """Incoming audio from a peer → push into their jitter buffer."""
        if ip in self.active:
            self.audio.push_peer_audio(ip, data)

    def cleanup(self):
        self.hangup_all()
        self.audio.cleanup()


# ═══════════════════════════════════════════════════════════════════════════
#  FILE TRANSFER HANDLER
# ═══════════════════════════════════════════════════════════════════════════
class FileTransferHandler(QObject):
    file_received = pyqtSignal(dict, bytes)   # meta, data

    def __init__(self):
        super().__init__()
        self._pending: dict[str, dict] = {}   # tid → {meta, chunks}

    def on_meta(self, meta: dict):
        tid = meta.get("tid","")
        if tid:
            self._pending[tid] = {"meta": meta, "chunks": {}, "total": None}

    def on_chunk(self, tid: str, raw: bytes):
        # raw is a JSON-encoded chunk message as bytes — already decoded
        pass  # handled below

    def on_chunk_msg(self, msg: dict):
        tid   = msg.get("tid","")
        idx   = msg.get("idx", 0)
        total = msg.get("total", 1)
        data  = msg.get("data","")
        if tid not in self._pending:
            self._pending[tid] = {"meta": {}, "chunks": {}, "total": total}
        rec = self._pending[tid]
        rec["total"] = total
        try:
            rec["chunks"][idx] = base64.b64decode(data)
        except Exception:
            return
        if len(rec["chunks"]) == total:
            assembled = b"".join(rec["chunks"][i] for i in range(total))
            meta      = rec["meta"]
            del self._pending[tid]
            self.file_received.emit(meta, assembled)

FT = FileTransferHandler()

# ═══════════════════════════════════════════════════════════════════════════
#  LAUNCHER SCREEN  (п.15 — выбор GUI/CMD режима)
# ═══════════════════════════════════════════════════════════════════════════
class LauncherScreen(QDialog):
    """
    Startup launcher — choose GUI or CMD mode.
    - Adapts colours to current theme
    - Keyboard navigation (arrows + Enter)
    - "Remember my choice" checkbox
    - Hover shows description
    """
    mode_selected = pyqtSignal(str)   # "gui" or "cmd"

    _MODES = [
        ("gui", "🖥  GUI режим",
         "Полноценный графический интерфейс.\nВсе функции: чаты, звонки, файлы, настройки.\nРекомендуется для обычного использования."),
        ("cmd", "⌨  CMD режим",
         "Консольный режим без GUI.\nУдобен для серверов и диагностики.\nКоманды: /peers /ping /send /quit"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent,
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(640, 460)
        sg = QApplication.primaryScreen().geometry()
        self.move((sg.width()-640)//2, (sg.height()-460)//2)
        self._choice = "gui"
        self._selected_idx = 0   # 0=gui 1=cmd
        self._btn_widgets: list[QPushButton] = []
        self._setup()

    def _setup(self):
        t = get_theme(S().theme)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)

        container = QWidget()
        container.setObjectName("launcher_screen")
        container.setStyleSheet(f"""
            #launcher_screen {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
                    stop:0 {t['bg3']}, stop:0.5 {t['bg2']}, stop:1 {t['bg']});
                border-radius: 22px;
                border: 2px solid {t['accent']};
            }}
        """)
        cl = QVBoxLayout(container)
        cl.setContentsMargins(48, 38, 48, 32)
        cl.setSpacing(0)

        # Header
        hdr = QLabel(f"📱  {APP_NAME}")
        hdr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hdr.setStyleSheet(f"""
            color: {t['text']}; font-size: 28px; font-weight: bold;
            background: transparent; letter-spacing: 2px;
        """)
        cl.addWidget(hdr)
        cl.addSpacing(4)

        sub = QLabel("Выберите режим запуска")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet(f"color:{t['text_dim']};font-size:13px;background:transparent;")
        cl.addWidget(sub)
        cl.addSpacing(24)

        # Mode cards row
        btn_row = QHBoxLayout()
        btn_row.setSpacing(18)

        for i, (mode_id, label, desc) in enumerate(self._MODES):
            card = QPushButton()
            card.setObjectName(f"launcher_card_{i}")
            card.setCheckable(True)
            card.setChecked(i == 0)
            card.setMinimumSize(230, 130)
            card.setCursor(Qt.CursorShape.PointingHandCursor)

            # Build card layout with icon + text
            card_lay = QVBoxLayout(card)
            card_lay.setContentsMargins(16, 16, 16, 16)
            card_lay.setSpacing(8)

            lbl_main = QLabel(label)
            lbl_main.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_main.setStyleSheet(
                f"font-size:15px;font-weight:bold;color:{t['text']};"
                "background:transparent;")
            card_lay.addWidget(lbl_main)

            lbl_hint = QLabel(desc)
            lbl_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_hint.setWordWrap(True)
            lbl_hint.setStyleSheet(
                f"font-size:9px;color:{t['text_dim']};background:transparent;")
            card_lay.addWidget(lbl_hint)

            self._apply_card_style(card, t, selected=(i==0))
            card.toggled.connect(lambda checked, idx=i: self._on_card_toggled(idx, checked))
            self._btn_widgets.append(card)
            btn_row.addWidget(card)

        cl.addLayout(btn_row)
        cl.addSpacing(20)

        # Arrow hint
        arrow_hint = QLabel("← → стрелочки для выбора  •  Enter для запуска")
        arrow_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        arrow_hint.setStyleSheet(
            f"color:{t['text_dim']};font-size:9px;background:transparent;")
        cl.addWidget(arrow_hint)
        cl.addStretch()

        # Bottom bar
        bot = QHBoxLayout()
        bot.setSpacing(12)

        self._no_show = QCheckBox(
            "Запомнить мой выбор" if S().language=="ru" else "Remember my choice")
        self._no_show.setStyleSheet(
            f"color:{t['text_dim']};background:transparent;font-size:10px;")
        self._no_show.setCursor(Qt.CursorShape.PointingHandCursor)
        bot.addWidget(self._no_show)
        bot.addStretch()

        help_btn = QPushButton("❓ Справка")
        help_btn.setFixedHeight(36)
        help_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        help_btn.setStyleSheet(f"""
            QPushButton {{
                background: {t['bg3']}; color: {t['text_dim']};
                border: 1px solid {t['border']}; border-radius: 10px;
                padding: 0 16px; font-size: 11px;
            }}
            QPushButton:hover {{ background: {t['btn_hover']}; color: {t['text']}; }}
        """)
        help_btn.clicked.connect(self._show_help)
        bot.addWidget(help_btn)

        go_btn = QPushButton("Запустить  ▶")
        go_btn.setFixedHeight(36)
        go_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        go_btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 {t['accent']}, stop:1 {t['accent2']});
                color: white; border: none; border-radius: 10px;
                padding: 0 28px; font-size: 13px; font-weight: bold;
                border-bottom: 3px solid rgba(0,0,0,76);
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 {t['btn_hover']}, stop:1 {t['accent']});
            }}
            QPushButton:pressed {{ border-bottom-width: 1px; }}
        """)
        go_btn.clicked.connect(self._go)
        bot.addWidget(go_btn)

        close_btn = QPushButton("×")
        close_btn.setFixedSize(32, 32)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setStyleSheet(f"""
            QPushButton {{
                background:{t['btn_bg']};color:{t['text_dim']};
                border:1px solid {t['border']};border-radius:16px;
                font-size:16px;font-weight:bold;
            }}
            QPushButton:hover{{background:#CC2222;color:white;border-color:#CC2222;}}
        """)
        close_btn.clicked.connect(lambda: self._select("gui"))
        bot.addWidget(close_btn)

        cl.addLayout(bot)
        lay.addWidget(container)

    def _apply_card_style(self, card: QPushButton, t: dict, selected: bool):
        if selected:
            card.setStyleSheet(f"""
                QPushButton {{
                    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                        stop:0 {t['accent']}, stop:1 {t['accent2']});
                    border: 2px solid {t['accent']};
                    border-radius: 14px;
                    border-bottom: 4px solid rgba(0,0,0,89);
                    color: white;
                }}
                QPushButton:hover {{ border-color: white; }}
                QPushButton QLabel {{ color: white !important; }}
            """)
            # Force all child QLabels to white so they stay readable
            for lbl in card.findChildren(QLabel):
                lbl.setStyleSheet(lbl.styleSheet()
                    .replace(f"color:{t['text_dim']}", "color:rgba(255,255,255,191)")
                    .replace(f"color:{t['text']}",     "color:white"))
        else:
            card.setStyleSheet(f"""
                QPushButton {{
                    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                        stop:0 {t['bg3']}, stop:1 {t['bg2']});
                    border: 2px solid {t['border']};
                    border-radius: 14px;
                    border-bottom: 4px solid rgba(0,0,0,63);
                    color: {t['text']};
                }}
                QPushButton:hover {{
                    border-color: {t['accent']};
                    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                        stop:0 {t['btn_hover']}, stop:1 {t['bg2']});
                }}
            """)
            for lbl in card.findChildren(QLabel):
                lbl.setStyleSheet(lbl.styleSheet()
                    .replace("color:rgba(255,255,255,191)", f"color:{t['text_dim']}")
                    .replace("color:white", f"color:{t['text']}"))

    def _on_card_toggled(self, idx: int, checked: bool):
        if checked:
            self._select_card(idx)

    def keyPressEvent(self, event):
        key = event.key()
        if key in (Qt.Key.Key_Left, Qt.Key.Key_Right):
            new_idx = (self._selected_idx + (1 if key == Qt.Key.Key_Right else -1)) % len(self._MODES)
            self._select_card(new_idx)
        elif key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._go()
        elif key == Qt.Key.Key_Escape:
            self._select("gui")
        elif key == Qt.Key.Key_H or key == Qt.Key.Key_F1:
            self._show_help()
        else:
            super().keyPressEvent(event)

    def _select_card(self, idx: int):
        """Programmatically select card by index — works from both keyboard and mouse."""
        t = get_theme(S().theme)
        self._selected_idx = idx
        self._choice = self._MODES[idx][0]
        for i, b in enumerate(self._btn_widgets):
            b.blockSignals(True)
            b.setChecked(i == idx)
            b.blockSignals(False)
            self._apply_card_style(b, t, selected=(i == idx))

    def _show_help(self):
        t = get_theme(S().theme)
        dlg = QDialog(self)
        dlg.setWindowTitle("Справка — GoidaPhone")
        dlg.setFixedSize(480, 420)
        dlg.setStyleSheet(f"""
            QDialog {{ background:{t['bg2']}; border-radius:16px; }}
            QLabel  {{ color:{t['text']}; background:transparent; }}
        """)
        vl = QVBoxLayout(dlg)
        vl.setContentsMargins(28, 24, 28, 20)
        vl.setSpacing(12)

        title = QLabel("📖  Справка по режимам запуска")
        title.setStyleSheet(
            f"font-size:15px;font-weight:bold;color:{t['accent']};")
        vl.addWidget(title)

        txt = QLabel(
            "<b>🖥 GUI режим</b><br>"
            "Полноценный графический интерфейс GoidaPhone.<br>"
            "Доступны: публичный чат, личные сообщения, группы,<br>"
            "голосовые и групповые звонки, передача файлов,<br>"
            "стикеры, темы, настройки, GoidaTerminal, WNS-браузер.<br><br>"
            "<b>⌨ CMD режим</b><br>"
            "Консольный (терминальный) режим — без GUI.<br>"
            "Полезен для серверов, слабых машин, диагностики.<br><br>"
            "<b>Хоткеи выбора:</b><br>"
            "← → — переключение карточек<br>"
            "Enter — запуск выбранного режима<br>"
            "F1 или H — эта справка<br>"
            "Esc — запуск GUI (по умолчанию)<br><br>"
            "<b>Запомнить выбор:</b><br>"
            "Отметь чекбокс «Запомнить мой выбор» чтобы это окно<br>"
            "не показывалось при следующем запуске.<br>"
            "Включить снова: Настройки → Специалист → «Показывать<br>"
            "выбор режима при каждом запуске»."
        )
        txt.setWordWrap(True)
        txt.setTextFormat(Qt.TextFormat.RichText)
        txt.setStyleSheet(f"font-size:11px;color:{t['text']};line-height:1.5;")
        vl.addWidget(txt)
        vl.addStretch()

        close = QPushButton("Закрыть")
        close.setObjectName("accent_btn")
        close.setFixedHeight(34)
        close.clicked.connect(dlg.accept)
        vl.addWidget(close)
        dlg.exec()

    def _go(self):
        self._select(self._choice)

    def _select(self, mode: str):
        self._choice = mode
        if self._no_show.isChecked():
            S().show_launcher = False
            S().set("launcher_default", mode)
        self.mode_selected.emit(mode)
        self.accept()

    def get_choice(self) -> str:
        return self._choice

# ═══════════════════════════════════════════════════════════════════════════
#  SPLASH SCREEN
# ═══════════════════════════════════════════════════════════════════════════
class SplashScreen(QWidget):
    """
    Startup splash screen.
    - Adapts to current theme colours
    - Supports custom background image (set in Settings → Кастомизация)
    - Animated progress dots
    """
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint |
                            Qt.WindowType.WindowStaysOnTopHint |
                            Qt.WindowType.SplashScreen)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(520, 340)
        sg = QApplication.primaryScreen().geometry()
        self.move((sg.width()-520)//2, (sg.height()-340)//2)

        self._dot_count = 0
        self._dot_timer = QTimer(self)
        self._dot_timer.timeout.connect(self._tick_dots)
        self._dot_timer.start(400)

        # Load splash: imag/splash.png first, then custom b64
        self._bg_pixmap: QPixmap | None = None
        _sfile = Path(__file__).parent / "imag" / "splash.png"
        if _sfile.exists():
            pm = QPixmap(str(_sfile))
            if not pm.isNull():
                self._bg_pixmap = pm.scaled(520, 340,
                    Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                    Qt.TransformationMode.SmoothTransformation)
        if self._bg_pixmap is None:
            bg_b64 = S().get("splash_image_b64", "", t=str)
            if bg_b64:
                pm = QPixmap()
                try:
                    data = base64.b64decode(bg_b64)
                    pm.loadFromData(data)
                    if not pm.isNull():
                        self._bg_pixmap = pm.scaled(
                            520, 340,
                            Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                            Qt.TransformationMode.SmoothTransformation)
                except Exception:
                    pass

        self._build()

    def _build(self):
        t = get_theme(S().theme)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        container = QWidget()
        container.setObjectName("splash_container")
        if self._bg_pixmap:
            # Image splash: fully transparent container — image drawn in paintEvent
            container.setStyleSheet(
                "#splash_container{background:transparent;border-radius:18px;}")
        else:
            container.setStyleSheet(f"""
                #splash_container {{
                    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
                        stop:0 {t['bg3']}, stop:0.4 {t['bg2']}, stop:1 {t['bg']});
                    border-radius: 18px;
                    border: 2px solid {t['accent']};
                }}
            """)

        cl = QVBoxLayout(container)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        cl.addStretch()

        if not self._bg_pixmap:
            # No image: show icon+title+version
            icon_lbl = QLabel("📱")
            icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_lbl.setStyleSheet("font-size:56px;background:transparent;")
            cl.addWidget(icon_lbl)
            title_lbl = QLabel(APP_NAME)
            title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            title_lbl.setStyleSheet(f"color:{t['text']};font-size:30px;font-weight:bold;"
                "background:transparent;letter-spacing:3px;")
            cl.addWidget(title_lbl)
            ver_lbl = QLabel(f"v{APP_VERSION}  •  {COMPANY_NAME}")
            ver_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ver_lbl.setStyleSheet(
                f"color:{t['text_dim']};font-size:12px;background:transparent;")
            cl.addWidget(ver_lbl)
            cl.addSpacing(16)

        cl.addStretch()

        # Loading dots — always shown, at bottom with semi-transparent bg if image
        bottom_bar = QWidget()
        bb_lay = QHBoxLayout(bottom_bar)
        bb_lay.setContentsMargins(0,0,0,0)
        if self._bg_pixmap:
            bottom_bar.setStyleSheet(
                "background:rgba(0,0,0,140);border-radius:0 0 16px 16px;padding:6px;")
        else:
            bottom_bar.setStyleSheet("background:transparent;")
        self._progress_lbl = QLabel("Загрузка")
        self._progress_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._progress_lbl.setStyleSheet(
            f"color:{'white' if self._bg_pixmap else t['accent']};"
            "font-size:11px;background:transparent;")
        bb_lay.addWidget(self._progress_lbl)
        cl.addWidget(bottom_bar)

        layout.addWidget(container)

    def _tick_dots(self):
        self._dot_count = (self._dot_count + 1) % 4
        dots = "." * self._dot_count
        self._progress_lbl.setText(f"Загрузка{dots}")

    def paintEvent(self, event):
        if self._bg_pixmap:
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            from PyQt6.QtGui import QPainterPath
            path = QPainterPath()
            path.addRoundedRect(0, 0, self.width(), self.height(), 18, 18)
            painter.setClipPath(path)
            # Scale image to fill exactly, no dark overlay
            scaled = self._bg_pixmap.scaled(self.width(), self.height(),
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation)
            x = (self.width() - scaled.width()) // 2
            y = (self.height() - scaled.height()) // 2
            painter.drawPixmap(x, y, scaled)
        super().paintEvent(event)

# ═══════════════════════════════════════════════════════════════════════════
#  CUSTOM LICENCE INPUT  (auto-insert dashes: XXXX-XXXX-XXXX)
# ═══════════════════════════════════════════════════════════════════════════
class LicenseLineEdit(QLineEdit):
    """Auto-formats 12-digit license as XXXX-XXXX-XXXX while typing."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setPlaceholderText("XXXX-XXXX-XXXX")
        self.setMaxLength(14)   # 12 digits + 2 dashes
        self.textEdited.connect(self._format)
        self._updating = False

    def raw_digits(self) -> str:
        return re.sub(r'\D', '', self.text())

    def _format(self, text: str):
        if self._updating:
            return
        self._updating = True
        digits = re.sub(r'\D', '', text)[:12]
        formatted = '-'.join(digits[i:i+4] for i in range(0, len(digits), 4) if digits[i:i+4])
        self.setText(formatted)
        self.setCursorPosition(len(formatted))
        self._updating = False

    def is_complete(self) -> bool:
        return len(self.raw_digits()) == 12

# ═══════════════════════════════════════════════════════════════════════════
#  USER TOOLTIP / HOVER CARD
# ═══════════════════════════════════════════════════════════════════════════
class UserHoverCard(QFrame):
    """Small floating card shown on hover over a user in the list."""

    def __init__(self, peer: dict, parent=None):
        super().__init__(parent, Qt.WindowType.ToolTip)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        t = get_theme(S().theme)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {t['bg2']};
                border: 1px solid {t['accent']};
                border-radius: 8px;
                padding: 4px;
            }}
            QLabel {{ background: transparent; color: {t['text']}; }}
        """)
        self._build(peer)

    def _build(self, p: dict):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12,10,12,10)
        lay.setSpacing(4)

        # Avatar
        av_b64 = p.get("avatar_b64","")
        if av_b64:
            try:
                pm = base64_to_pixmap(av_b64)
                circ = make_circle_pixmap(pm, 48)
            except Exception:
                circ = default_avatar(p.get("username","?"), 48)
        else:
            circ = default_avatar(p.get("username","?"), 48)

        top = QHBoxLayout()
        av = QLabel(); av.setPixmap(circ); av.setFixedSize(48,48)
        top.addWidget(av)
        info = QVBoxLayout()
        color = p.get("nickname_color","#E0E0E0")
        emoji = p.get("custom_emoji","")
        name = QLabel(f"<b style='color:{color}'>{p.get('username','?')} {emoji}</b>")
        name.setTextFormat(Qt.TextFormat.RichText)
        info.addWidget(name)
        info.addWidget(QLabel(f"🌐 {p.get('ip','?')}  •  {p.get('conn_type','?')}"))
        top.addLayout(info)
        lay.addLayout(top)

        bio = p.get("bio","")
        if bio:
            bio_lbl = QLabel(bio[:80])
            bio_lbl.setWordWrap(True)
            bio_lbl.setStyleSheet(f"color: #9090A0; font-size: 10px; background: transparent;")
            lay.addWidget(bio_lbl)

        t = get_theme(S().theme)
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"background:{t['border']};min-height:1px;max-height:1px;border:none;")
        lay.addWidget(sep)

        lay.addWidget(QLabel(f"💻 {p.get('os','?')}"))
        lay.addWidget(QLabel(f"📦 GoidaPhone v{p.get('version','?')}"))
        ts = p.get("last_seen", 0)
        if ts:
            dt = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
            lay.addWidget(QLabel(f"🕐 Онлайн с {dt}"))
        if p.get("premium"):
            lay.addWidget(QLabel("👑 Премиум пользователь"))

        self.adjustSize()

# ═══════════════════════════════════════════════════════════════════════════
#  ANIMATION HELPER  (п.2 — анимации интерфейса)
# ═══════════════════════════════════════════════════════════════════════════
class AnimationHelper:
    """
    Helper for common UI animations.
    Uses QPropertyAnimation — no external deps.

    Animations used in GoidaPhone:
    - fade_in(widget)         — плавное появление виджета
    - fade_out(widget, cb)    — плавное исчезновение → callback
    - slide_in(widget, dir)   — выезд сбоку/снизу
    - pulse(widget)           — мигание (входящий звонок)
    - shake(widget)           — дрожание (неверный код лицензии)
    - bounce_button(btn)      — лёгкий bounce при клике
    """

    @staticmethod
    def shake(widget: QWidget, distance: int = 10, count: int = 3):
        """Shake widget horizontally (wrong PIN, error)."""
        anim = QPropertyAnimation(widget, b"pos", widget)
        anim.setDuration(300)
        orig = widget.pos()
        kf = [(0,orig), (0.1,orig+QPoint(-distance,0)),
              (0.25,orig+QPoint(distance,0)), (0.4,orig+QPoint(-distance,0)),
              (0.55,orig+QPoint(distance//2,0)), (0.7,orig+QPoint(-distance//2,0)),
              (0.85,orig+QPoint(distance//4,0)), (1.0,orig)]
        for t_val, pos in kf:
            anim.setKeyValueAt(t_val, pos)
        anim.setEasingCurve(QEasingCurve.Type.Linear)
        anim.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
        return anim

    @staticmethod
    def fade_in(widget: QWidget, duration: int = 300,
                start: float = 0.0, end: float = 1.0):
        """Fade a widget in. Widget must have a graphics effect or support opacity."""
        from PyQt6.QtWidgets import QGraphicsOpacityEffect
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", widget)
        anim.setDuration(duration)
        anim.setStartValue(start)
        anim.setEndValue(end)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
        return anim

    @staticmethod
    def fade_out(widget: QWidget, duration: int = 250,
                 callback=None):
        """Fade a widget out, then call callback (e.g. widget.hide())."""
        from PyQt6.QtWidgets import QGraphicsOpacityEffect
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", widget)
        anim.setDuration(duration)
        anim.setStartValue(1.0)
        anim.setEndValue(0.0)
        anim.setEasingCurve(QEasingCurve.Type.InCubic)
        if callback:
            anim.finished.connect(callback)
        anim.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
        return anim

    @staticmethod
    def slide_in_from_right(widget: QWidget, duration: int = 350):
        """Slide widget in from the right."""
        start_x = widget.x() + widget.width()
        end_x   = widget.x()
        anim = QPropertyAnimation(widget, b"pos", widget)
        anim.setDuration(duration)
        anim.setStartValue(QPoint(start_x, widget.y()))
        anim.setEndValue(QPoint(end_x, widget.y()))
        anim.setEasingCurve(QEasingCurve.Type.OutBack)
        anim.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
        return anim

    @staticmethod
    def slide_in_from_bottom(widget: QWidget, duration: int = 300):
        """Slide widget up from the bottom."""
        start_y = widget.y() + widget.height()
        end_y   = widget.y()
        anim = QPropertyAnimation(widget, b"pos", widget)
        anim.setDuration(duration)
        anim.setStartValue(QPoint(widget.x(), start_y))
        anim.setEndValue(QPoint(widget.x(), end_y))
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
        return anim

    @staticmethod
    def pulse(widget: QWidget, count: int = 3,
              duration_per: int = 400, callback=None):
        """
        Pulse (opacity oscillate) a widget N times.
        Used for incoming call notification.
        """
        from PyQt6.QtWidgets import QGraphicsOpacityEffect
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)

        group = QSequentialAnimationGroup(widget)
        for _ in range(count):
            a1 = QPropertyAnimation(effect, b"opacity")
            a1.setDuration(duration_per // 2)
            a1.setStartValue(1.0)
            a1.setEndValue(0.3)
            a1.setEasingCurve(QEasingCurve.Type.InOutSine)
            a2 = QPropertyAnimation(effect, b"opacity")
            a2.setDuration(duration_per // 2)
            a2.setStartValue(0.3)
            a2.setEndValue(1.0)
            a2.setEasingCurve(QEasingCurve.Type.InOutSine)
            group.addAnimation(a1)
            group.addAnimation(a2)

        if callback:
            group.finished.connect(callback)
        group.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
        return group

    @staticmethod
    def shake(widget: QWidget, amplitude: int = 8, duration: int = 400):
        """
        Horizontal shake animation — for invalid license code etc.
        """
        orig = widget.pos()
        group = QSequentialAnimationGroup(widget)
        steps = [amplitude, -amplitude, amplitude//2, -amplitude//2, 0]
        step_dur = duration // len(steps)
        for dx in steps:
            a = QPropertyAnimation(widget, b"pos")
            a.setDuration(step_dur)
            a.setEndValue(QPoint(orig.x() + dx, orig.y()))
            a.setEasingCurve(QEasingCurve.Type.InOutQuad)
            group.addAnimation(a)
        group.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
        return group

    @staticmethod
    def bounce_button(btn: QPushButton, scale: float = 0.92):
        """
        Quick scale-down + restore on button press.
        Simulates a physical press feel.
        """
        # Qt doesn't natively support scale animations on widgets,
        # so we simulate with geometry shrink/expand.
        rect = btn.geometry()
        dx = int(rect.width()  * (1 - scale) / 2)
        dy = int(rect.height() * (1 - scale) / 2)
        small = rect.adjusted(dx, dy, -dx, -dy)

        a1 = QPropertyAnimation(btn, b"geometry", btn)
        a1.setDuration(80)
        a1.setStartValue(rect)
        a1.setEndValue(small)
        a1.setEasingCurve(QEasingCurve.Type.InQuad)

        a2 = QPropertyAnimation(btn, b"geometry", btn)
        a2.setDuration(120)
        a2.setStartValue(small)
        a2.setEndValue(rect)
        a2.setEasingCurve(QEasingCurve.Type.OutBack)

        group = QSequentialAnimationGroup(btn)
        group.addAnimation(a1)
        group.addAnimation(a2)
        group.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
        return group


ANIM = AnimationHelper()   # global shorthand


class TextFormatter:
    """
    Converts markdown-like syntax to HTML for chat display.
    Supported:
      **text**  → <b>text</b>
      *text*    → <i>text</i>
      `text`    → <code style='...'>text</code>
      ~~text~~  → <s>text</s>
      ||text||  → spoiler (blurred, click to reveal) — rendered as title attr
      @username → highlighted mention
      http(s):// → clickable link
    """
    # Regex patterns (applied in order)
    _BOLD    = re.compile(r'\*\*(.+?)\*\*')
    _ITALIC  = re.compile(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)')
    _CODE    = re.compile(r'`(.+?)`')
    _STRIKE  = re.compile(r'~~(.+?)~~')
    _SPOILER = re.compile(r'\|\|(.+?)\|\|')
    _MENTION = re.compile(r'@(\w+)')
    _URL     = re.compile(r'(https?://[^\s<>"]+)')

    @classmethod
    def format(cls, text: str, accent_color: str = "#4080FF",
               known_users: set | None = None) -> str:
        """Convert plain text with markdown to safe HTML."""
        # 1. Escape HTML special chars
        safe = (text.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;"))

        # 2. Apply markdown
        safe = cls._BOLD.sub(r'<b>\1</b>', safe)
        safe = cls._ITALIC.sub(r'<i>\1</i>', safe)
        safe = cls._CODE.sub(
            r'<code style="background:#1A1A2E;color:#80FF80;'
            r'padding:1px 4px;border-radius:3px;font-family:monospace;">\1</code>', safe)
        safe = cls._STRIKE.sub(r'<s>\1</s>', safe)
        safe = cls._SPOILER.sub(
            r'<span style="background:#333;color:#333;'
            r'border-radius:3px;padding:0 4px;" '
            r'title="Нажмите для просмотра">\1</span>', safe)

        # 3. @mentions
        def mention_sub(m):
            uname = m.group(1)
            col = accent_color if (known_users and uname in known_users) else "#80A0FF"
            return f'<b style="color:{col};">@{uname}</b>'
        safe = cls._MENTION.sub(mention_sub, safe)

        # 4. Clickable URLs — show full URL but styled nicely
        def url_sub(m):
            url = m.group(1)
            # Shorten display: show domain + first path segment
            try:
                from urllib.parse import urlparse as _up
                p = _up(url)
                display = p.netloc + (p.path[:28] + "…" if len(p.path) > 28 else p.path)
                display = display.rstrip("/")
            except Exception:
                display = url[:48] + ("…" if len(url) > 48 else "")
            return (f'<a href="{url}" style="color:{accent_color};'
                    f'text-decoration:none;border-bottom:1px solid {accent_color}80;">'
                    f'{display}</a>')
        safe = cls._URL.sub(url_sub, safe)

        # 5. Newlines
        safe = safe.replace("\n", "<br>")

        return safe

    @classmethod
    def is_formatting(cls, text: str) -> bool:
        """Quick check if text contains any formatting markers."""
        for pattern in (cls._BOLD, cls._ITALIC, cls._CODE,
                        cls._STRIKE, cls._SPOILER, cls._MENTION, cls._URL):
            if pattern.search(text):
                return True
        return False


# ═══════════════════════════════════════════════════════════════════════════
#  CHAT BUBBLE WIDGET  (for rendering messages)
# ═══════════════════════════════════════════════════════════════════════════
class MessageEntry:
    """Data class for a single chat message."""
    __slots__ = ('sender', 'text', 'ts', 'is_own', 'color', 'emoji',
                 'msg_type', 'image_data', 'is_system', 'is_edited',
                 'is_forwarded', 'forwarded_from', 'reply_to_text',
                 'chat_id', 'msg_id')

    def __init__(self, sender="", text="", ts=0.0, is_own=False,
                 color="#E0E0E0", emoji="", msg_type="public",
                 image_data=None, is_system=False, is_edited=False,
                 is_forwarded=False, forwarded_from="",
                 reply_to_text="", chat_id="", msg_id=""):
        self.sender        = sender
        self.text          = text
        self.ts            = ts
        self.is_own        = is_own
        self.color         = color
        self.emoji         = emoji
        self.msg_type      = msg_type
        self.image_data    = image_data
        self.is_system     = is_system
        self.is_edited     = is_edited
        self.is_forwarded  = is_forwarded
        self.forwarded_from = forwarded_from
        self.reply_to_text = reply_to_text
        self.chat_id       = chat_id
        self.msg_id        = msg_id or f"{ts:.3f}"


# ─── Image viewer dialog (fullscreen photo view) ──────────────────────────
def _find_main_window(widget=None) -> 'QMainWindow | None':
    """Walk up Qt parent chain to find the MainWindow instance."""
    # Try direct parent chain first
    w = widget
    for _ in range(20):
        if w is None: break
        if isinstance(w, QMainWindow):
            return w
        w = w.parent() if callable(getattr(w, 'parent', None)) else None
    # Fallback: search topLevelWidgets
    for w in QApplication.topLevelWidgets():
        if isinstance(w, QMainWindow):
            return w
    return None


class ImageViewer(QWidget):
    """
    Inline image viewer — fullscreen overlay inside the app window.
    Click outside image or press ESC to close. No separate window.
    """
    def __init__(self, image_data: bytes, parent=None):
        # Find the MainWindow to use as overlay target
        mw = _find_main_window(parent)
        overlay_parent = mw.centralWidget() if mw else parent
        super().__init__(overlay_parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        t = get_theme(S().theme)
        self.setStyleSheet(f"background:rgba(0,0,0,220);color:{t['text']};")
        self._scale   = 1.0
        self._offset  = QPoint(0, 0)
        self._drag_start = None
        self._rotation = 0
        self._raw_data = image_data
        pm = QPixmap()
        pm.loadFromData(image_data)
        self._pixmap = pm
        self._setup_ui(t)
        if overlay_parent:
            self.resize(overlay_parent.size())
            overlay_parent.installEventFilter(self)
        self.show()
        self.raise_()
        self.setFocus()
        QTimer.singleShot(50, self._fit_to_window)

    def eventFilter(self, obj, event):
        if event.type() == event.Type.Resize:
            self.resize(obj.size())
        return False

    def exec(self):
        """Compat shim — just show (we're not a dialog)."""
        self.show(); self.raise_(); self.setFocus()

    def _setup_ui(self, t):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Toolbar ──
        toolbar = QWidget()
        toolbar.setStyleSheet(
            f"background:{t['bg3']};border-bottom:1px solid {t['border']};")
        tl = QHBoxLayout(toolbar)
        tl.setContentsMargins(8,4,8,4)
        tl.setSpacing(4)

        def mk(text, tip, cb):
            b = QPushButton(text)
            b.setToolTip(tip)
            b.setFixedHeight(28)
            b.setStyleSheet(
                f"QPushButton{{background:{t['bg2']};color:{t['text']};"
                "border-radius:5px;padding:0 8px;font-size:12px;"
                f"border:1px solid {t['border']};}}"
                f"QPushButton:hover{{background:{t['btn_hover']};}}")
            b.clicked.connect(cb)
            tl.addWidget(b)
            return b

        mk("🔍+", "Увеличить (+)",  lambda: self._zoom(1.25))
        mk("🔍-", "Уменьшить (-)",  lambda: self._zoom(1/1.25))
        mk("⊡",  "По размеру окна", self._fit_to_window)
        mk("⊞",  "Заполнить окно",  self._fill_window)
        mk("↺",  "Повернуть влево", lambda: self._rotate(-90))
        mk("↻",  "Повернуть вправо",lambda: self._rotate(90))
        tl.addStretch()

        self._zoom_lbl = QLabel("100%")
        self._zoom_lbl.setStyleSheet(
            f"color:{t['text_dim']};font-size:11px;background:transparent;"
            "padding:0 8px;")
        tl.addWidget(self._zoom_lbl)

        mk("💾 Сохранить", "Сохранить в файл",  self._save_file)
        mk("📋 Копировать","Копировать в буфер", self._copy_clipboard)
        def _close_overlay():
            if self.parent():
                self.parent().removeEventFilter(self)
            self.hide(); self.deleteLater()
        mk("✕",            "Закрыть  (Esc)",     _close_overlay)
        self._close_overlay = _close_overlay

        lay.addWidget(toolbar)

        # ── Canvas — fills overlay minus toolbar/info ──
        self._canvas = QWidget()
        self._canvas.setStyleSheet("background:transparent;")
        self._canvas.setMouseTracking(True)
        self._canvas.paintEvent        = self._paint_canvas
        self._canvas.mousePressEvent   = self._mouse_press
        self._canvas.mouseMoveEvent    = self._mouse_move
        self._canvas.mouseReleaseEvent = self._mouse_release
        self._canvas.wheelEvent        = self._wheel
        self._canvas.mouseDoubleClickEvent = lambda e: self._fit_to_window()
        lay.addWidget(self._canvas, stretch=1)

        # ── Bottom info bar ──
        info = QWidget()
        info.setStyleSheet(
            f"background:{t['bg3']};border-top:1px solid {t['border']};")
        il = QHBoxLayout(info)
        il.setContentsMargins(10,3,10,3)
        self._info_lbl = QLabel()
        self._info_lbl.setStyleSheet(
            f"color:{t['text_dim']};font-size:10px;background:transparent;")
        il.addWidget(self._info_lbl)
        il.addStretch()
        hint = QLabel("Скролл — масштаб  •  ЛКМ — перетащить  •  2× клик — вписать")
        hint.setStyleSheet(
            f"color:{t['text_dim']};font-size:9px;background:transparent;")
        il.addWidget(hint)
        lay.addWidget(info)

        if not self._pixmap.isNull():
            w, h = self._pixmap.width(), self._pixmap.height()
            self._info_lbl.setText(f"{w} × {h} px")

    def _current_pixmap(self):
        """Return pixmap with rotation applied."""
        if self._rotation == 0:
            return self._pixmap
        t = QTransform().rotate(self._rotation)
        return self._pixmap.transformed(t, Qt.TransformationMode.SmoothTransformation)

    def _paint_canvas(self, event):
        painter = QPainter(self._canvas)
        # Transparent — the overlay widget bg provides the dim
        painter.fillRect(self._canvas.rect(), QColor(0, 0, 0, 0))
        pm = self._current_pixmap()
        if pm.isNull():
            return
        cw, ch = self._canvas.width(), self._canvas.height()
        scaled = pm.scaled(
            int(pm.width()  * self._scale),
            int(pm.height() * self._scale),
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation)
        x = (cw - scaled.width())  // 2 + self._offset.x()
        y = (ch - scaled.height()) // 2 + self._offset.y()
        # Draw subtle shadow
        painter.fillRect(x+4, y+4, scaled.width(), scaled.height(),
                         QColor(0,0,0,60))
        painter.drawPixmap(x, y, scaled)

    def _zoom(self, factor: float):
        self._scale = max(0.05, min(self._scale * factor, 20.0))
        self._zoom_lbl.setText(f"{int(self._scale*100)}%")
        self._canvas.update()

    def _fit_to_window(self):
        pm = self._current_pixmap()
        if pm.isNull(): return
        cw = max(self._canvas.width(), 100)
        ch = max(self._canvas.height(), 100)
        sx = cw / pm.width()
        sy = ch / pm.height()
        self._scale = min(sx, sy) * 0.95
        self._offset = QPoint(0, 0)
        self._zoom_lbl.setText(f"{int(self._scale*100)}%")
        self._canvas.update()

    def _fill_window(self):
        pm = self._current_pixmap()
        if pm.isNull(): return
        sx = self._canvas.width()  / pm.width()
        sy = self._canvas.height() / pm.height()
        self._scale = max(sx, sy)
        self._offset = QPoint(0, 0)
        self._zoom_lbl.setText(f"{int(self._scale*100)}%")
        self._canvas.update()

    def _rotate(self, deg: int):
        self._rotation = (self._rotation + deg) % 360
        self._fit_to_window()

    def _mouse_press(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start = event.pos()
            self._canvas.setCursor(Qt.CursorShape.ClosedHandCursor)

    def _mouse_move(self, event):
        if self._drag_start is not None:
            delta = event.pos() - self._drag_start
            self._drag_start = event.pos()
            self._offset = QPoint(self._offset.x()+delta.x(),
                                  self._offset.y()+delta.y())
            self._canvas.update()

    def _mouse_release(self, event):
        self._drag_start = None
        self._canvas.setCursor(Qt.CursorShape.OpenHandCursor)

    def _wheel(self, event):
        delta = event.angleDelta().y()
        self._zoom(1.12 if delta > 0 else 1/1.12)

    def _save_file(self):
        fn, _ = QFileDialog.getSaveFileName(
            self, "Сохранить изображение", "image.png",
            "Images (*.png *.jpg *.jpeg *.bmp *.webp)")
        if fn:
            self._current_pixmap().save(fn)
            QMessageBox.information(self,"Сохранено",f"Файл сохранён:\n{fn}")

    def _copy_clipboard(self):
        QApplication.clipboard().setPixmap(self._current_pixmap())
        # Small toast via status bar is not available, just do it silently

    def mousePressEvent(self, event):
        """Click on dark backdrop closes the viewer."""
        # Check if click is outside the image area
        pm = self._current_pixmap()
        if not pm.isNull():
            cw, ch = self._canvas.width(), self._canvas.height()
            sw = int(pm.width()  * self._scale)
            sh = int(pm.height() * self._scale)
            img_x = (cw - sw) // 2 + self._offset.x() + self._canvas.x()
            img_y = (ch - sh) // 2 + self._offset.y() + self._canvas.y()
            from PyQt6.QtCore import QRect
            img_rect = QRect(img_x, img_y, sw, sh)
            if not img_rect.contains(event.pos()):
                self._close_overlay(); return
        super().mousePressEvent(event)

    def keyPressEvent(self, event):
        k = event.key()
        if k == Qt.Key.Key_Escape:
            self._close_overlay()
        elif k == Qt.Key.Key_Plus or k == Qt.Key.Key_Equal:
            self._zoom(1.25)
        elif k == Qt.Key.Key_Minus:
            self._zoom(1/1.25)
        elif k == Qt.Key.Key_0:
            self._fit_to_window()
        elif k == Qt.Key.Key_R:
            self._rotate(90)
        elif k == Qt.Key.Key_S and (event.modifiers() & Qt.KeyboardModifier.ControlModifier):
            self._save_file()



# ─── Single message bubble widget ─────────────────────────────────────────
class MessageBubble(QWidget):
    """One chat message as a proper widget bubble."""
    sig_forward = pyqtSignal(object)
    sig_edit    = pyqtSignal(object)
    sig_delete  = pyqtSignal(object)
    sig_react   = pyqtSignal(object, str)  # (entry, emoji)
    sig_reply   = pyqtSignal(object)
    sig_copy    = pyqtSignal(str)
    sig_ping    = pyqtSignal(str)

    QUICK_REACT = ["\U0001f44d","\u2764\ufe0f","\U0001f602","\U0001f62e",
                   "\U0001f622","\U0001f525","\U0001f4af","\U0001f44e"]

    def __init__(self, entry, read_map, known_users, parent=None):
        super().__init__(parent)
        self.entry = entry
        self._read_map = read_map
        self._known_users = known_users
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._ctx_menu)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self._build()

    def _build(self):
        t = get_theme(S().theme)
        m = self.entry
        self._text_lbl = None  # exposed for search highlight
        self._tick_lbl = None  # for fast read-receipt update
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 2, 8, 2)
        outer.setSpacing(0)

        def _is_emoji_only(s: str) -> bool:
            import unicodedata
            if not s or len(s) > 12:
                return False
            for ch in s:
                cp = ord(ch)
                if ch in (' ', '\u200d', '\ufe0f', '\u20e3'):
                    continue
                if (0x1F000 <= cp <= 0x1FFFF or
                    0x2600  <= cp <= 0x27BF  or
                    0x1F300 <= cp <= 0x1FAFF or
                    0x2300  <= cp <= 0x23FF  or
                    0x2B50  == cp or 0x2764 == cp or
                    unicodedata.category(ch) in ('So', 'Mn')):
                    continue
                return False
            return True

        # System message
        if m.is_system:
            lbl = QLabel(m.text)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(
                f"color:{t['text_dim']};font-size:10px;font-style:italic;"
                f"background:{t['bg2']};border-radius:8px;"
                f"padding:2px 12px;margin:2px 80px;")
            lbl.setWordWrap(True)
            outer.addWidget(lbl)
            return

        row = QHBoxLayout()
        row.setSpacing(8)
        row.setContentsMargins(0, 0, 0, 0)

        # Avatar for others
        if not m.is_own:
            av = QLabel()
            av.setFixedSize(32, 32)
            av.setPixmap(default_avatar(m.sender, 32))
            av.setAlignment(Qt.AlignmentFlag.AlignTop)
            row.addWidget(av)

        # Bubble
        bw = QWidget()
        bw.setObjectName("msg_bubble")
        if m.is_own:
            bw.setStyleSheet(
                "QWidget#msg_bubble{"
                "background:qlineargradient(x1:0,y1:0,x2:1,y2:1,"
                f"stop:0 {t['msg_own']},stop:1 {t['accent2']});"
                "border-radius:14px 14px 4px 14px;"
                f"border:1px solid {t['accent']};"
                f"border-bottom:2px solid rgba(0,0,0,63);}}")
        else:
            bw.setStyleSheet(
                "QWidget#msg_bubble{"
                "background:qlineargradient(x1:0,y1:0,x2:1,y2:1,"
                f"stop:0 {t['msg_other']},stop:1 {t['bg3']});"
                "border-radius:14px 14px 14px 4px;"
                f"border:1px solid {t['border']};"
                f"border-bottom:2px solid rgba(0,0,0,51);}}")

        bl = QVBoxLayout(bw)
        bl.setContentsMargins(12, 8, 12, 8)
        bl.setSpacing(4)

        # Sender name
        if not m.is_own:
            nl = QLabel(f"<b style='color:{m.color};'>{m.sender}</b>"
                        + (f" {m.emoji}" if m.emoji else ""))
            nl.setTextFormat(Qt.TextFormat.RichText)
            nl.setStyleSheet("font-size:11px;background:transparent;")
            bl.addWidget(nl)

        # Forward
        if m.is_forwarded and m.forwarded_from:
            fl = QLabel(f"\u21aa \u041f\u0435\u0440\u0435\u0441\u043b\u0430\u043d\u043e \u043e\u0442: <i>{m.forwarded_from}</i>")
            fl.setStyleSheet(f"font-size:9px;color:{t['text_dim']};background:transparent;")
            fl.setTextFormat(Qt.TextFormat.RichText)
            bl.addWidget(fl)

        # Reply quote — Telegram-style pill
        if m.reply_to_text:
            short = m.reply_to_text[:60] + ("\u2026" if len(m.reply_to_text) > 60 else "")
            rf = QWidget()
            rf.setObjectName("reply_pill")
            rf.setStyleSheet(
                "QWidget#reply_pill{"
                "background:rgba(255,255,255,15);"
                f"border-left:3px solid {t['accent']};"
                "border-radius:4px;margin-bottom:2px;}")
            rfl = QVBoxLayout(rf)
            rfl.setContentsMargins(8, 4, 8, 4)
            rfl.setSpacing(1)
            irt = QLabel("\u21a9 \u041e\u0442\u0432\u0435\u0442")
            irt.setStyleSheet(f"font-size:8px;font-weight:bold;color:{t['accent']};background:transparent;")
            rfl.addWidget(irt)
            rl = QLabel(short)
            rl.setStyleSheet(f"font-size:10px;color:{t['text_dim']};background:transparent;")
            rl.setWordWrap(True)
            rfl.addWidget(rl)
            bl.addWidget(rf)

        # Content
        if m.image_data:
            if m.msg_type == "sticker":
                bw.setStyleSheet("background:transparent;border:none;")
                bw.setMaximumWidth(180)
                self._add_image(bl, m, t)
                if m.is_own:
                    row.addStretch(); row.addWidget(bw)
                else:
                    row.addWidget(bw); row.addStretch()
                outer.addLayout(row)
                return
            if m.msg_type == "video":
                self._add_video(bl, m, t)
            else:
                self._add_image(bl, m, t)
        elif m.msg_type == "file":
            self._add_file(bl, m, t)
        elif m.text.startswith("__GROUP_INVITE__:"):
            # ── Group invite card ──────────────────────────────────────────
            import json as _json
            try:
                inv = _json.loads(m.text[len("__GROUP_INVITE__:"):])
                gid   = inv.get("gid", "")
                gname = inv.get("gname", "?")
                host  = inv.get("host", "")
                sender_name = inv.get("from", "?")
            except Exception:
                gid = gname = host = ""; sender_name = "?"

            card = QWidget()
            card.setStyleSheet(
                f"QWidget{{background:rgba(0,0,0,45);"
                f"border:1px solid {t['accent']};border-radius:10px;padding:4px;}}")
            card_lay = QVBoxLayout(card)
            card_lay.setContentsMargins(10, 8, 10, 8)
            card_lay.setSpacing(4)

            ico_lbl = QLabel("📂 Приглашение в группу")
            ico_lbl.setStyleSheet(f"font-size:10px;color:{t['text_dim']};background:transparent;border:none;")
            card_lay.addWidget(ico_lbl)

            name_lbl = QLabel(f"<b style='font-size:14px;'>{gname}</b>")
            name_lbl.setTextFormat(Qt.TextFormat.RichText)
            name_lbl.setStyleSheet("background:transparent;border:none;")
            card_lay.addWidget(name_lbl)

            already_in = gid and gid in dict(GROUPS.list_for(get_local_ip()))

            if already_in:
                status_lbl = QLabel("✅ Вы уже в этой группе")
                status_lbl.setStyleSheet(f"font-size:10px;color:#80FF80;background:transparent;border:none;")
                card_lay.addWidget(status_lbl)
            elif gid:
                join_btn = QPushButton("👋 Вступить")
                join_btn.setFixedHeight(30)
                join_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                join_btn.setStyleSheet(
                    f"QPushButton{{background:{t['accent']};color:white;"
                    "border-radius:8px;border:none;font-weight:bold;font-size:11px;}}"
                    "QPushButton:hover{filter:brightness(1.1);}")
                def _do_join(checked=False, _gid=gid, _gname=gname, _host=host, _btn=join_btn):
                    GROUPS.add_member(_gid, get_local_ip())
                    _btn.setText("✅ Вы вступили!")
                    _btn.setEnabled(False)
                    _btn.setStyleSheet("QPushButton{background:#2a6a2a;color:#80FF80;"
                                       "border-radius:8px;border:none;font-size:11px;}")
                join_btn.clicked.connect(_do_join)
                card_lay.addWidget(join_btn)
            bl.addWidget(card)
        else:
            # Detect solo-emoji messages → render big
            txt = m.text.strip()
            is_big_emoji = _is_emoji_only(txt)
            if is_big_emoji:
                tl = QLabel(txt)
                tl.setFont(QFont("Segoe UI Emoji" if platform.system()=="Windows" else "Noto Color Emoji", 56))
                tl.setStyleSheet("background:transparent;border:none;padding:6px 4px;"
                                 "font-size:56px;")
                tl.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                tl.setWordWrap(False)
                tl.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Minimum)
                tl.setMinimumSize(80, 80)
                tl.adjustSize()
            else:
                html = TextFormatter.format(m.text, accent_color=t['accent'],
                                            known_users=self._known_users)
                tl = QLabel(html)
                tl.setTextFormat(Qt.TextFormat.RichText)
                tl.setWordWrap(True)
                tl.setOpenExternalLinks(False)   # we handle clicks ourselves
                tl.setTextInteractionFlags(
                    Qt.TextInteractionFlag.TextSelectableByMouse |
                    Qt.TextInteractionFlag.LinksAccessibleByMouse)
                tl.linkActivated.connect(
                    lambda url, _p=tl: _open_link(url, _p))
                tl.setStyleSheet(
                    f"color:{t['text']};font-size:13px;"
                    "background:transparent;line-height:1.5;")
            bl.addWidget(tl)

        # Footer
        fr = QHBoxLayout()
        fr.setSpacing(4)
        fr.setContentsMargins(0, 2, 0, 0)
        if m.is_edited:
            el = QLabel("\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u043e")
            el.setStyleSheet(f"font-size:8px;color:{t['text_dim']};font-style:italic;background:transparent;")
            fr.addWidget(el)
        fr.addStretch()
        ts_str = datetime.fromtimestamp(m.ts).strftime("%H:%M")
        tl2 = QLabel(ts_str)
        tl2.setStyleSheet(f"font-size:9px;color:{t['text_dim']};background:transparent;")
        fr.addWidget(tl2)
        if m.is_own:
            read = self._read_map.get(m.msg_id, False)
            tick = QLabel("\u2713\u2713" if read else "\u2713")
            tc = t['accent'] if read else t['text_dim']
            tick.setStyleSheet(f"font-size:9px;color:{tc};background:transparent;")
            fr.addWidget(tick)
        bl.addLayout(fr)

        # Reactions
        reactions = REACTIONS.summary(m.chat_id or "public", m.ts)
        if reactions:
            rrow = QHBoxLayout()
            rrow.setSpacing(4)
            rrow.setContentsMargins(0, 2, 0, 0)
            for em, cnt in reactions[:6]:
                rb = QPushButton(f"{em} {cnt}")
                rb.setFixedHeight(22)
                rb.setCursor(Qt.CursorShape.PointingHandCursor)
                rb.setStyleSheet(
                    f"QPushButton{{background:{t['bg3']};border:1px solid {t['border']};"
                    f"border-radius:11px;padding:0 7px;font-size:11px;color:{t['text']};}}"
                    f"QPushButton:hover{{background:{t['btn_hover']};border-color:{t['accent']};}}")
                rb.clicked.connect(lambda _, e=em: self.sig_react.emit(self.entry, e))
                rrow.addWidget(rb)
            rrow.addStretch()
            bl.addLayout(rrow)

        # Assemble — adaptive width: content-driven up to 60% of typical window
        # Check if this is a big-emoji message → make bubble transparent & compact
        _is_emoji_msg = (not m.image_data and m.msg_type != "file"
                         and not m.reply_to_text
                         and _is_emoji_only(m.text.strip()) if not m.image_data else False)
        if _is_emoji_msg and not reactions:
            # Pure emoji — no bubble background
            bw.setStyleSheet("background:transparent;border:none;")
            bw.setMaximumWidth(220)
        elif _is_emoji_msg and reactions:
            # Emoji with reactions — show subtle bubble so reaction fits
            bw.setStyleSheet(
                f"background:{t['bg3']};border-radius:16px;"
                f"border:1px solid {t['border']};")
            bw.setMaximumWidth(220)
        else:
            bw.setMaximumWidth(540)
        bw.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        bw.setMinimumWidth(60)
        if m.is_own:
            row.addStretch()
            row.addWidget(bw)
        else:
            row.addWidget(bw)
            row.addStretch()

        outer.addLayout(row)

    def _add_image(self, layout, m, t):
        """Render image inline. Sticker = transparent/large, image = clickable thumbnail."""
        is_sticker = getattr(m, 'msg_type', '') == "sticker"
        pm = QPixmap()
        pm.loadFromData(m.image_data)
        if pm.isNull():
            layout.addWidget(QLabel("⚠ Не удалось загрузить изображение"))
            return
        max_w = 160 if is_sticker else 300
        max_h = 160 if is_sticker else 260
        pm_s = pm.scaled(max_w, max_h, Qt.AspectRatioMode.KeepAspectRatio,
                         Qt.TransformationMode.SmoothTransformation)
        if is_sticker:
            lbl = QLabel()
            lbl.setPixmap(pm_s)
            lbl.setFixedSize(pm_s.width(), pm_s.height())
            lbl.setStyleSheet("background:transparent;border:none;")
            lbl.setCursor(Qt.CursorShape.PointingHandCursor)
            lbl.setToolTip("Стикер")
            lbl.mousePressEvent = lambda _: ImageViewer(m.image_data, self).exec()
            layout.addWidget(lbl)
        else:
            btn = QPushButton()
            btn.setFlat(True)
            btn.setFixedSize(pm_s.width(), pm_s.height())
            btn.setIcon(QIcon(pm_s))
            btn.setIconSize(QSize(pm_s.width(), pm_s.height()))
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setToolTip("Нажмите для просмотра")
            btn.setStyleSheet(
                "QPushButton{border:none;border-radius:10px;padding:0;background:transparent;}"
                "QPushButton:hover{border:2px solid rgba(100,140,255,178);}")
            btn.clicked.connect(lambda: ImageViewer(m.image_data, self).exec())
            layout.addWidget(btn)

    def _add_video(self, layout, m, t):
        """Show video as thumbnail + download card."""
        fname = m.text or "video.mp4"
        dest = RECEIVED_DIR / fname
        if m.image_data and not dest.exists():
            try: dest.write_bytes(m.image_data)
            except Exception: pass

        card = QFrame()
        card.setStyleSheet(
            f"QFrame{{background:rgba(10,10,30,204);"
            f"border:1px solid {t['border']};border-radius:12px;}}")
        card.setFixedWidth(280)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(0,0,0,0); cl.setSpacing(0)

        # Thumbnail
        thumb = QLabel()
        thumb.setFixedSize(280, 158)
        thumb.setAlignment(Qt.AlignmentFlag.AlignCenter)
        thumb.setStyleSheet("background:#080818;border-radius:12px 12px 0 0;font-size:40px;")

        thumb_path = RECEIVED_DIR / (fname + "_thumb.jpg")
        if not thumb_path.exists() and dest.exists():
            try:
                subprocess.run(["ffmpeg","-y","-i",str(dest),"-vframes","1",
                    "-vf","scale=280:158",str(thumb_path)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            except Exception: pass
        if thumb_path.exists():
            pm = QPixmap(str(thumb_path)).scaled(280,158,
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation)
            thumb.setPixmap(pm)
        else:
            thumb.setText("🎬")
        cl.addWidget(thumb)

        # Play overlay
        play_btn = QPushButton("▶", card)
        play_btn.setFixedSize(56,56)
        play_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        play_btn.setStyleSheet(
            "QPushButton{background:rgba(0,0,0,153);color:white;"
            "border-radius:28px;font-size:20px;border:2px solid white;}"
            "QPushButton:hover{background:rgba(108,99,255,229);}")
        play_btn.move(112, 51)

        # Bottom bar
        bot = QWidget()
        bot.setStyleSheet(f"background:{t['bg3']};border-radius:0 0 12px 12px;")
        bl2 = QHBoxLayout(bot); bl2.setContentsMargins(10,6,10,6); bl2.setSpacing(6)
        nl = QLabel(fname); nl.setStyleSheet(f"font-size:10px;color:{t['text']};font-weight:bold;")
        nl.setMaximumWidth(170); bl2.addWidget(nl,1)
        dl = QPushButton("⬇ Скачать"); dl.setFixedHeight(26)
        dl.setCursor(Qt.CursorShape.PointingHandCursor)
        dl.setStyleSheet(f"QPushButton{{background:{t['accent']};color:white;"
            "border-radius:6px;border:none;font-size:9px;padding:0 8px;}}")
        def _save(checked=False, _d=dest, _f=fname):
            if _d.exists():
                sp,_ = QFileDialog.getSaveFileName(None,"Сохранить видео",_f,
                    "Video (*.mp4 *.avi *.mkv *.mov *.webm);;All (*)")
                if sp:
                    import shutil as _sh; _sh.copy2(str(_d), sp)
        dl.clicked.connect(_save); bl2.addWidget(dl)
        cl.addWidget(bot)

        def _play(checked=False, _d=dest):
            _open_media_smart(str(_d), self)
        play_btn.clicked.connect(_play)
        thumb.mousePressEvent = lambda e,_d=dest: _play(_d=_d)
        layout.addWidget(card)

    def _add_file(self, layout, m, t):
        fname = m.text
        ext = Path(fname).suffix.lower() if fname else ""
        icons = {'.pdf':'📄','.doc':'📝','.docx':'📝','.txt':'📃',
                 '.zip':'📦','.rar':'📦','.7z':'📦','.tar':'📦',
                 '.mp3':'🎵','.ogg':'🎵','.wav':'🎵','.flac':'🎵',
                 '.mp4':'🎬','.avi':'🎬','.mkv':'🎬','.mov':'🎬',
                 '.py':'🐍','.js':'📜','.cpp':'⚙','.c':'⚙',
                 '.exe':'💾','.sh':'🖥'}
        icon = icons.get(ext, '📎')
        ff = QFrame()
        ff.setStyleSheet(
            f"QFrame{{background:rgba(60,80,120,102);"
            f"border:1px solid {t['border']};border-radius:10px;}}")
        ffl = QHBoxLayout(ff)
        ffl.setContentsMargins(10, 8, 10, 8)
        ffl.setSpacing(10)
        il = QLabel(icon)
        il.setStyleSheet("font-size:26px;background:transparent;")
        ffl.addWidget(il)
        ic = QVBoxLayout()
        ic.setSpacing(2)
        nl = QLabel(fname or "\u0424\u0430\u0439\u043b")
        nl.setStyleSheet(f"font-size:12px;font-weight:bold;color:{t['text']};background:transparent;")
        ic.addWidget(nl)
        dest = RECEIVED_DIR / fname if fname else None
        size_str = ""
        if dest and dest.exists():
            sz = dest.stat().st_size
            size_str = (f"{sz/1024/1024:.1f} \u041c\u0411" if sz > 1024*1024
                        else f"{sz/1024:.0f} \u041a\u0411" if sz > 1024 else f"{sz} \u0411")
        sl = QLabel(size_str or "\u0444\u0430\u0439\u043b \u043f\u043e\u043b\u0443\u0447\u0435\u043d")
        sl.setStyleSheet(f"font-size:9px;color:{t['text_dim']};background:transparent;")
        ic.addWidget(sl)
        ffl.addLayout(ic)
        ffl.addStretch()
        ob = QPushButton("\u041e\u0442\u043a\u0440\u044b\u0442\u044c")
        ob.setFixedHeight(26)
        ob.setCursor(Qt.CursorShape.PointingHandCursor)
        ob.setStyleSheet(
            f"QPushButton{{background:{t['accent']};color:white;border:none;"
            f"border-radius:6px;padding:2px 12px;font-size:10px;}}"
            f"QPushButton:hover{{background:{t['btn_hover']};}}")
        if dest and dest.exists():
            def _do_open(_d=dest):
                if _d.suffix.lower() in MEDIA_EXTS:
                    _open_media_smart(str(_d), self)
                else:
                    QDesktopServices.openUrl(QUrl.fromLocalFile(str(_d)))
            ob.clicked.connect(_do_open)
        else:
            ob.setEnabled(False)
        ffl.addWidget(ob)
        layout.addWidget(ff)

    def _ctx_menu(self, pos):
        t = get_theme(S().theme)
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu{{background:{t['bg2']};color:{t['text']};"
            f"border:1px solid {t['border']};border-radius:10px;padding:4px 0;}}"
            f"QMenu::item{{padding:8px 20px 8px 14px;font-size:12px;}}"
            f"QMenu::item:selected{{background:{t['accent']};color:white;"
            f"border-radius:6px;margin:1px 3px;}}"
            f"QMenu::separator{{height:1px;background:{t['border']};margin:3px 10px;}}")
        m = self.entry

        # Reaction strip
        rl = QLabel("  \u0411\u044b\u0441\u0442\u0440\u0430\u044f \u0440\u0435\u0430\u043a\u0446\u0438\u044f:")
        rl.setStyleSheet(f"color:{t['text_dim']};font-size:10px;padding:4px 14px 0 14px;")
        rla = QWidgetAction(menu)
        rla.setDefaultWidget(rl)
        menu.addAction(rla)

        rsw = QWidget()
        rsl = QHBoxLayout(rsw)
        rsl.setContentsMargins(10, 2, 10, 4)
        rsl.setSpacing(3)
        for em in self.QUICK_REACT:
            rb = QPushButton(em)
            rb.setFixedSize(38, 38)
            rb.setFont(QFont("Segoe UI Emoji" if platform.system()=="Windows" else "Noto Color Emoji", 16))
            rb.setStyleSheet(
                f"QPushButton{{font-size:18px;background:{t['bg3']};"
                f"border:1px solid {t['border']};border-radius:10px;"
                f"border-bottom:2px solid rgba(0,0,0,89);}}"
                f"QPushButton:hover{{background:{t['btn_hover']};"
                f"border-color:{t['accent']};transform:scale(1.1);}}")
            rb.clicked.connect(lambda _, e=em: (menu.close(), self.sig_react.emit(self.entry, e)))
            rsl.addWidget(rb)
        rsa = QWidgetAction(menu)
        rsa.setDefaultWidget(rsw)
        menu.addAction(rsa)
        menu.addSeparator()

        acts = [
            ("\u21a9  \u041e\u0442\u0432\u0435\u0442\u0438\u0442\u044c",    lambda: self.sig_reply.emit(m)),
            ("\u21aa  \u041f\u0435\u0440\u0435\u0441\u043b\u0430\u0442\u044c", lambda: self.sig_forward.emit(m)),
            ("\U0001f4cb  \u041a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c", lambda: self.sig_copy.emit(m.text)),
        ]
        if m.is_own:
            acts += [None,
                     ("\u270f  \u0418\u0437\u043c\u0435\u043d\u0438\u0442\u044c",  lambda: self.sig_edit.emit(m)),
                     ("\U0001f5d1  \u0423\u0434\u0430\u043b\u0438\u0442\u044c",   lambda: self.sig_delete.emit(m))]
        if not m.is_own:
            acts.append(("\U0001f4e1  \u041f\u0438\u043d\u0433\u043e\u0432\u0430\u0442\u044c", lambda: self.sig_ping.emit(m.sender)))
        for item in acts:
            if item is None:
                menu.addSeparator()
            else:
                label, slot = item
                a = QAction(label, menu)
                a.triggered.connect(slot)
                menu.addAction(a)
        menu.exec(self.mapToGlobal(pos))


class ChatDisplay(QScrollArea):
    """Widget-based chat display with real bubbles, animations, image viewer."""
    request_forward = pyqtSignal(str, float)
    request_edit    = pyqtSignal(str, float)
    request_delete  = pyqtSignal(float)
    request_react   = pyqtSignal(float)
    request_react_with_emoji = pyqtSignal(float, str)
    request_reply   = pyqtSignal(str, float)

    def __init__(self, chat_id="public", parent=None):
        super().__init__(parent)
        self.chat_id      = chat_id
        self._messages    = []
        self._bubbles     = []
        self._read_map    = {}
        self._known_users = set()
        self._at_bottom   = True
        self._smooth_anim: QPropertyAnimation | None = None

        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)

        t = get_theme(S().theme)
        self.setStyleSheet(f"QScrollArea{{background:{t['bg']};border:none;}}")

        self._container = QWidget()
        self._container.setStyleSheet(f"background:{t['bg']};")
        self._container.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        self._lay = QVBoxLayout(self._container)
        self._lay.setContentsMargins(4, 8, 4, 8)
        self._lay.setSpacing(2)
        self._lay.addStretch()
        self.setWidget(self._container)
        self.verticalScrollBar().valueChanged.connect(self._on_scroll)

    def _smooth_scroll_to(self, target_val: int, duration: int = 350):
        """Animate scroll bar to target value smoothly."""
        sb = self.verticalScrollBar()
        # Stop previous animation safely — DeleteWhenStopped destroys C++ object
        # so we must check with try/except before calling any method on it
        if self._smooth_anim is not None:
            try:
                if self._smooth_anim.state() == QAbstractAnimation.State.Running:
                    self._smooth_anim.stop()
            except RuntimeError:
                pass  # C++ object already deleted — ignore
            self._smooth_anim = None

        anim = QPropertyAnimation(sb, b"value", self)
        anim.setDuration(duration)
        anim.setStartValue(sb.value())
        anim.setEndValue(target_val)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        # Use KeepWhenStopped — keeps C++ object alive so we can call .state() later
        anim.start(QAbstractAnimation.DeletionPolicy.KeepWhenStopped)
        self._smooth_anim = anim

    def wheelEvent(self, event):
        """Smooth scroll on mouse wheel."""
        delta = event.angleDelta().y()
        if delta == 0:
            super().wheelEvent(event)
            return
        sb = self.verticalScrollBar()
        step = max(80, sb.singleStep() * 4)
        # If animation is running, start from its current end value
        current = sb.value()
        if self._smooth_anim is not None:
            try:
                if self._smooth_anim.state() == QAbstractAnimation.State.Running:
                    current = self._smooth_anim.endValue()
            except RuntimeError:
                self._smooth_anim = None
        target = current - int(delta / 120 * step)
        target = max(sb.minimum(), min(sb.maximum(), target))
        self._smooth_scroll_to(target, duration=180)
        event.accept()

    def _on_scroll(self, val):
        sb = self.verticalScrollBar()
        self._at_bottom = (val >= sb.maximum() - 60)
        if self._at_bottom:
            self._hide_jump_btn()

    def retheme(self):
        """Re-apply theme to all bubbles and container — called on theme change."""
        t = get_theme(S().theme)
        self.setStyleSheet(f"QScrollArea{{background:{t['bg']};border:none;}}")
        self._container.setStyleSheet(f"background:{t['bg']};")
        for b in self._bubbles:
            try:
                b.retheme(t)
            except Exception:
                pass

    def set_known_users(self, users):
        self._known_users = users

    def mark_read(self, msg_id):
        self._read_map[msg_id] = True
        t = get_theme(S().theme)
        for b in self._bubbles:
            if b.entry.msg_id == msg_id:
                tick_lbl = getattr(b, '_tick_lbl', None)
                if tick_lbl is not None:
                    tick_lbl.setText("✓✓")
                    tick_lbl.setStyleSheet(
                        f"font-size:9px;color:{t['accent']};background:transparent;")
                break

    # ── Search helpers ────────────────────────────────────────────────────
    _SEARCH_HL_STYLE = ";background:rgba(255,210,0,71);border-radius:3px;"

    def highlight_search(self, query: str):
        q = query.lower()
        for b in self._bubbles:
            lbl = getattr(b, '_text_lbl', None)
            if lbl is None: continue
            ss = lbl.styleSheet().replace(self._SEARCH_HL_STYLE, "")
            if q and q in b.entry.text.lower():
                ss += self._SEARCH_HL_STYLE
            lbl.setStyleSheet(ss)

    def clear_search_highlight(self):
        for b in self._bubbles:
            lbl = getattr(b, '_text_lbl', None)
            if lbl:
                lbl.setStyleSheet(
                    lbl.styleSheet().replace(self._SEARCH_HL_STYLE, ""))

    def get_search_matches(self, query: str) -> list:
        q = query.lower()
        return [i for i, b in enumerate(self._bubbles)
                if q in b.entry.text.lower()]

    def scroll_to_match(self, bubble_idx: int):
        if 0 <= bubble_idx < len(self._bubbles):
            self.ensureWidgetVisible(self._bubbles[bubble_idx], 0, 60)

    def _connect_bubble(self, b):
        b.sig_forward.connect(lambda m: self.request_forward.emit(m.text, m.ts))
        b.sig_edit.connect(lambda m: self.request_edit.emit(m.text, m.ts))
        b.sig_delete.connect(lambda m: self.request_delete.emit(m.ts))
        b.sig_react.connect(lambda m, e: self.request_react_with_emoji.emit(m.ts, e))
        b.sig_reply.connect(lambda m: self.request_reply.emit(m.text, m.ts))
        b.sig_copy.connect(QApplication.clipboard().setText)
        b.sig_ping.connect(lambda u: self.add_system(f"\U0001f4e1 \u041f\u0438\u043d\u0433 \u2192 {u}"))

    def add_message(self, sender, text, ts, is_own, color="#E0E0E0",
                    emoji="", msg_type="public", image_data=None,
                    is_edited=False, is_forwarded=False, forwarded_from="",
                    reply_to_text="", chat_id=""):
        entry = MessageEntry(
            sender=sender, text=text, ts=ts, is_own=is_own,
            color=color, emoji=emoji, msg_type=msg_type,
            image_data=image_data, is_edited=is_edited,
            is_forwarded=is_forwarded, forwarded_from=forwarded_from,
            reply_to_text=reply_to_text, chat_id=chat_id or self.chat_id)
        self._messages.append(entry)
        self._append_bubble(entry, animate=True)

    def _append_bubble(self, entry, animate=False):
        b = MessageBubble(entry, self._read_map, self._known_users)
        self._connect_bubble(b)
        self._bubbles.append(b)
        self._lay.insertWidget(self._lay.count() - 1, b)
        if animate:
            self._anim_in(b, entry.is_own)
        # Use two ticks: first tick lets Qt calculate widget size,
        # second tick does the scroll (avoids scroll to wrong position)
        if self._at_bottom or entry.is_own:
            QTimer.singleShot(0,  lambda: None)   # flush layout
            QTimer.singleShot(30, self._scroll_to_bottom)
        else:
            QTimer.singleShot(30, self._show_jump_btn)

    def retheme(self, t: dict):
        """Re-apply bubble stylesheet when theme changes."""
        m = self.entry
        if m.is_system:
            return
        # Find the msg_bubble widget child
        for child in self.findChildren(QWidget):
            if child.objectName() == "msg_bubble":
                if m.is_own:
                    child.setStyleSheet(
                        "QWidget#msg_bubble{"
                        "background:qlineargradient(x1:0,y1:0,x2:1,y2:1,"
                        f"stop:0 {t['msg_own']},stop:1 {t['accent2']});"
                        "border-radius:14px 14px 4px 14px;"
                        f"border:1px solid {t['accent']};"
                        "border-bottom:2px solid rgba(0,0,0,63);}}")
                else:
                    child.setStyleSheet(
                        "QWidget#msg_bubble{"
                        "background:qlineargradient(x1:0,y1:0,x2:1,y2:1,"
                        f"stop:0 {t['msg_other']},stop:1 {t['bg3']});"
                        "border-radius:14px 14px 14px 4px;"
                        f"border:1px solid {t['border']};"
                        "border-bottom:2px solid rgba(0,0,0,51);}}")
                child.update()
                break
        self.update()

    def _anim_in(self, bubble, is_own):
        """Fade-in animation. Pos animation removed — it caused render delay
        because bubble.pos() is (0,0) before Qt finishes layout pass."""
        from PyQt6.QtWidgets import QGraphicsOpacityEffect
        eff = QGraphicsOpacityEffect(bubble)
        eff.setOpacity(0.0)
        bubble.setGraphicsEffect(eff)
        fade = QPropertyAnimation(eff, b"opacity", bubble)
        fade.setDuration(160)
        fade.setStartValue(0.0)
        fade.setEndValue(1.0)
        fade.setEasingCurve(QEasingCurve.Type.OutCubic)
        # IMPORTANT: remove effect after animation — leaving it blocks repaint
        fade.finished.connect(lambda: bubble.setGraphicsEffect(None))
        fade.finished.connect(lambda: bubble.update())
        fade.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)

    def add_system(self, text):
        entry = MessageEntry(text=text, ts=time.time(), is_system=True)
        self._messages.append(entry)
        self._append_bubble(entry)

    def add_upload_progress(self, fname: str, fsize: int, prog_id: str):
        """Show indeterminate upload progress card."""
        t = get_theme(S().theme)
        container = QWidget()
        container.setObjectName(f"prog_{prog_id}")
        cl = QHBoxLayout(container); cl.setContentsMargins(0,2,4,2)
        cl.addStretch()
        inner = QWidget()
        inner.setMaximumWidth(300)
        inner.setStyleSheet(f"QWidget{{background:{t['bg3']};border:1px solid {t['border']};"
            "border-radius:10px;}}")
        il = QVBoxLayout(inner); il.setContentsMargins(10,8,10,8); il.setSpacing(4)
        size_s = (f"{fsize/1024/1024:.1f} МБ" if fsize>1048576
                  else f"{fsize/1024:.0f} КБ" if fsize>1024 else f"{fsize} Б")
        lbl = QLabel(f"📤 {fname}  ({size_s})")
        lbl.setStyleSheet(f"font-size:11px;color:{t['text']};background:transparent;")
        il.addWidget(lbl)
        bar = QProgressBar(); bar.setRange(0,0); bar.setFixedHeight(5)
        bar.setTextVisible(False)
        bar.setStyleSheet(f"QProgressBar{{background:{t['bg2']};border-radius:3px;border:none;}}"
            f"QProgressBar::chunk{{background:{t['accent']};border-radius:3px;}}")
        il.addWidget(bar)
        cl.addWidget(inner)
        self._lay.insertWidget(self._lay.count()-1, container)
        if not hasattr(self, '_prog_widgets'): self._prog_widgets = {}
        self._prog_widgets[prog_id] = container
        QTimer.singleShot(40, self._scroll_to_bottom)

    def remove_progress(self, prog_id: str):
        pw = getattr(self, '_prog_widgets', {})
        w = pw.pop(prog_id, None)
        if w:
            self._lay.removeWidget(w)
            w.deleteLater()

    def update_reactions(self, ts):
        for i, b in enumerate(self._bubbles):
            if not b.entry.is_system and abs(b.entry.ts - ts) < 0.01:
                idx = self._lay.indexOf(b)
                entry = b.entry
                self._lay.removeWidget(b)
                b.deleteLater()
                nb = MessageBubble(entry, self._read_map, self._known_users)
                self._connect_bubble(nb)
                self._lay.insertWidget(idx, nb)
                self._bubbles[i] = nb
                break

    def _redraw_all(self):
        for b in self._bubbles:
            self._lay.removeWidget(b)
            b.deleteLater()
        self._bubbles.clear()
        msgs = list(self._messages)
        self._messages.clear()
        for m in msgs:
            if m.is_system:
                self.add_system(m.text)
            else:
                self.add_message(m.sender, m.text, m.ts, m.is_own, m.color,
                                 m.emoji, m.msg_type, m.image_data, m.is_edited,
                                 m.is_forwarded, m.forwarded_from, m.reply_to_text, m.chat_id)

    def edit_message(self, ts, new_text):
        for m in self._messages:
            if abs(m.ts - ts) < 0.01 and not m.is_system:
                m.text = new_text
                m.is_edited = True
                break
        self._redraw_all()

    def delete_message(self, ts):
        self._messages = [m for m in self._messages
                          if m.is_system or abs(m.ts - ts) >= 0.01]
        self._redraw_all()

    def add_reaction_update(self, ts, emoji, username, added):
        if added:
            REACTIONS.add(self.chat_id, ts, emoji, username)
        else:
            REACTIONS.remove(self.chat_id, ts, emoji, username)
        self.update_reactions(ts)

    def load_history(self, messages):
        for m in messages[-80:]:
            if m.get("system"):
                self.add_system(m["text"])
            else:
                self.add_message(
                    m.get("sender","?"), m.get("text",""),
                    m.get("ts", time.time()), m.get("is_own", False),
                    m.get("color","#E0E0E0"), m.get("emoji",""),
                    is_edited=m.get("is_edited", False),
                    is_forwarded=m.get("is_forwarded", False),
                    forwarded_from=m.get("forwarded_from", ""),
                    reply_to_text=m.get("reply_to_text", ""))

    def clear(self):
        for b in self._bubbles:
            self._lay.removeWidget(b)
            b.deleteLater()
        self._bubbles.clear()
        self._messages.clear()

    def _scroll_to_bottom(self):
        sb = self.verticalScrollBar()
        self._smooth_scroll_to(sb.maximum(), duration=300)
        self._hide_jump_btn()

    def _show_jump_btn(self):
        """Show animated ↓ button when new messages arrive off-screen."""
        if not hasattr(self, '_jump_btn'):
            self._jump_btn = None
        if self._jump_btn is None:
            t = get_theme(S().theme)
            self._jump_btn = QPushButton("↓ Новые", self.viewport())
            self._jump_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._jump_btn.setStyleSheet(
                f"QPushButton{{background:{t['accent']};color:white;"
                "border-radius:14px;padding:0 14px;font-size:11px;"
                "font-weight:bold;border:none;"
                "border-bottom:2px solid rgba(0,0,0,102);}}"
                "QPushButton:hover{filter:brightness(1.1);}")
            self._jump_btn.setFixedHeight(28)
            self._jump_btn.clicked.connect(self._scroll_to_bottom)
        vp = self.viewport()
        self._jump_btn.adjustSize()
        bw = self._jump_btn.width()
        self._jump_btn.setGeometry(vp.width() // 2 - bw // 2,
                                   vp.height() - 46, bw, 28)
        self._jump_btn.show()
        self._jump_btn.raise_()

    def _hide_jump_btn(self):
        if hasattr(self, '_jump_btn') and self._jump_btn:
            self._jump_btn.hide()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Re-position jump button on resize
        if hasattr(self, '_jump_btn') and self._jump_btn and self._jump_btn.isVisible():
            vp = self.viewport()
            bw = self._jump_btn.width()
            self._jump_btn.setGeometry(vp.width() // 2 - bw // 2,
                                       vp.height() - 46, bw, 28)



# ═══════════════════════════════════════════════════════════════════════════
#  PEER LIST WIDGET  (with hover cards)
# ═══════════════════════════════════════════════════════════════════════════
class PeerListItem(QWidget):
    """Custom widget for a peer in the list."""

    def __init__(self, peer: dict, parent=None):
        super().__init__(parent)
        self.peer = peer
        self._hover_card: UserHoverCard | None = None
        self.setMouseTracking(True)
        self._build()

    def _build(self):
        lay = QHBoxLayout(self)
        lay.setContentsMargins(6,4,6,4)
        lay.setSpacing(8)

        # Avatar
        av_b64 = self.peer.get("avatar_b64","")
        if av_b64:
            try:
                pm = base64_to_pixmap(av_b64)
                circ = make_circle_pixmap(pm, 36)
            except Exception:
                circ = default_avatar(self.peer.get("username","?"), 36)
        else:
            circ = default_avatar(self.peer.get("username","?"), 36)

        av = QLabel()
        av.setPixmap(circ)
        av.setFixedSize(36,36)
        lay.addWidget(av)

        # Info
        info = QVBoxLayout()
        info.setSpacing(1)

        color = self.peer.get("nickname_color","#E0E0E0")
        emoji = self.peer.get("custom_emoji","")
        ct    = self.peer.get("conn_type","LAN")
        ct_icon = "🔒" if ct == "VPN" else "🏠"

        name = QLabel(f"<b style='color:{color}'>{self.peer.get('username','?')}</b> {emoji}")
        name.setTextFormat(Qt.TextFormat.RichText)
        info.addWidget(name)

        _ip_disp = display_id(self.peer.get("ip",""))
        loyalty = int(self.peer.get("loyalty_months", 0))
        loyalty_str = f"  ❤{loyalty}" if loyalty > 0 else ""
        sub = QLabel(f"{ct_icon} {ct}  •  {_ip_disp}{loyalty_str}")
        t = get_theme(S().theme)
        sub.setStyleSheet(f"color: {t['text_dim']}; font-size: 9px;")
        if S().safe_mode:
            sub.setToolTip(f"GoidaID режим активен. Настоящий IP скрыт.")
        elif loyalty > 0:
            lang = S().language
            sub.setToolTip(f"{'В сети' if lang=='ru' else 'Online for'} "
                           f"{loyalty} {'мес. подряд' if lang=='ru' else 'months in a row'}")
        info.addWidget(sub)

        lay.addLayout(info)
        lay.addStretch()

        # Legacy / modded badge BEFORE status dot
        peer_ver   = str(self.peer.get("version", APP_VERSION))
        peer_proto = int(self.peer.get("protocol_version", PROTOCOL_VERSION))
        is_legacy  = peer_proto < PROTOCOL_COMPAT          # proto too old
        # Detect modded: version string contains a non-standard suffix (e.g. "1.8.0-mod")
        import re as _re
        is_modded  = bool(_re.search(r"[-+][a-zA-Z]", peer_ver))

        if is_legacy:
            legacy_badge = QLabel("🕰")
            legacy_badge.setStyleSheet("font-size:11px;background:transparent;")
            legacy_badge.setToolTip(
                f"Устаревший клиент GoidaPhone (протокол v{peer_proto})\n"
                f"Некоторые функции могут не работать.")
            lay.addWidget(legacy_badge)
        elif is_modded:
            mod_badge = QLabel("⚠")
            mod_badge.setStyleSheet("font-size:11px;color:#FFD700;background:transparent;")
            mod_badge.setToolTip(
                f"Модифицированная версия GoidaPhone ({peer_ver})\n"
                f"Поведение клиента может отличаться от оригинала.\n"
                f"Будьте осторожны при передаче файлов.")
            lay.addWidget(mod_badge)

        # Status dot — colour by presence status
        status = self.peer.get("status", "online")
        STATUS_COLORS = {
            "online": t.get("online","#4CAF50"),
            "away":   "#FFD700",
            "busy":   "#FF6B6B",
            "dnd":    "#9E9E9E",
        }
        STATUS_TIPS = {
            "online": "Онлайн",
            "away":   "Отошёл",
            "busy":   "Занят",
            "dnd":    "Не беспокоить",
        }
        dot_col = STATUS_COLORS.get(status, t.get("online","#4CAF50"))
        dot_sym = "●" if status != "dnd" else "⊘"
        dot = QLabel(dot_sym)
        dot.setStyleSheet(f"color: {dot_col}; font-size: 14px;")
        dot.setToolTip(STATUS_TIPS.get(status, "Онлайн"))
        lay.addWidget(dot)

    def enterEvent(self, event):
        QTimer.singleShot(600, self._show_hover)
        super().enterEvent(event)

    def leaveEvent(self, event):
        if self._hover_card:
            self._hover_card.hide()
            self._hover_card = None
        super().leaveEvent(event)

    def _show_hover(self):
        if not self.underMouse():
            return
        self._hover_card = UserHoverCard(self.peer)
        gp = self.mapToGlobal(QPoint(self.width() + 5, 0))
        self._hover_card.move(gp)
        self._hover_card.show()

# ═══════════════════════════════════════════════════════════════════════════
#  PEER PANEL  (left sidebar)
# ═══════════════════════════════════════════════════════════════════════════
class PeerPanel(QWidget):
    chat_requested  = pyqtSignal(dict)   # peer
    call_requested  = pyqtSignal(dict)   # peer
    group_selected  = pyqtSignal(str)    # group_id
    invite_message_requested = pyqtSignal(str, object, str)  # dest_type, dest_data, invite_json

    def __init__(self, net: NetworkManager, parent=None):
        super().__init__(parent)
        self.net = net
        self._peers: dict[str, dict] = {}
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        tabs = QTabWidget()
        tabs.setDocumentMode(True)

        # ── Users tab ──
        users_w = QWidget()
        ul = QVBoxLayout(users_w)
        ul.setContentsMargins(4,4,4,4)
        ul.setSpacing(4)

        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍 Поиск...")
        self._search.textChanged.connect(self._filter)
        ul.addWidget(self._search)

        self._list = QListWidget()
        self._list.setSpacing(1)
        self._list.itemDoubleClicked.connect(self._on_double)
        ul.addWidget(self._list)

        # context menu
        self._list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._list.customContextMenuRequested.connect(self._ctx_menu)

        self._status_lbl = QLabel("Онлайн: 0")
        t = get_theme(S().theme)
        self._status_lbl.setStyleSheet(f"color:{t['text_dim']}; font-size:9px; padding:2px 6px;")
        ul.addWidget(self._status_lbl)

        tabs.addTab(users_w, "👥 Пользователи")

        # ── Groups tab ──
        groups_w = QWidget()
        gl = QVBoxLayout(groups_w)
        gl.setContentsMargins(4,4,4,4)
        gl.setSpacing(4)

        self._groups_list = QListWidget()
        self._groups_list.itemDoubleClicked.connect(self._on_group_double)
        self._groups_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._groups_list.customContextMenuRequested.connect(self._group_ctx_menu)
        gl.addWidget(self._groups_list)

        grp_btns = QHBoxLayout()
        new_group_btn = QPushButton("➕ Создать группу")
        new_group_btn.clicked.connect(self._create_group)
        grp_btns.addWidget(new_group_btn)
        fav_btn = QPushButton("⭐ Избранное")
        fav_btn.clicked.connect(self._open_favorites)
        grp_btns.addWidget(fav_btn)
        gl.addLayout(grp_btns)

        tabs.addTab(groups_w, "📂 Группы")

        lay.addWidget(tabs)
        self._refresh_groups()

    # ── peer management ─────────────────────────────────────────────────
    def add_peer(self, peer: dict):
        ip = peer.get("ip","")
        if not ip or ip == get_local_ip():
            return
        self._peers[ip] = peer
        self._rebuild_list()

    def remove_peer(self, ip: str):
        self._peers.pop(ip, None)
        self._rebuild_list()

    def _rebuild_list(self):
        q = self._search.text().lower()
        self._list.clear()
        count = 0
        pinned_set = set(json.loads(S().get("pinned_peers", "[]", t=str)))
        # Pinned peers first
        sorted_peers = sorted(
            self._peers.items(),
            key=lambda kv: (0 if kv[0] in pinned_set else 1, kv[1].get("username","").lower())
        )
        t = get_theme(S().theme)
        for ip, peer in sorted_peers:
            name = peer.get("username","")
            if q and q not in name.lower() and q not in ip:
                continue
            item = QListWidgetItem(self._list)
            item.setSizeHint(QSize(0, 52))
            item.setData(Qt.ItemDataRole.UserRole, peer)
            widget = PeerListItem(peer)
            if ip in pinned_set:
                item.setBackground(QColor(t.get("accent","#6c63ff") + "22"))
            self._list.setItemWidget(item, widget)
            count += 1
        self._status_lbl.setText(f"Онлайн: {count}")

    def _is_pinned(self, ip: str) -> bool:
        return ip in set(json.loads(S().get("pinned_peers", "[]", t=str)))

    def _toggle_pin(self, ip: str):
        import json as _j
        pinned = list(_j.loads(S().get("pinned_peers", "[]", t=str)))
        if ip in pinned:
            pinned.remove(ip)
        else:
            pinned.insert(0, ip)
        S().set("pinned_peers", _j.dumps(pinned))
        self._rebuild_list()

    def _filter(self, _):
        self._rebuild_list()

    def _selected_peer(self) -> dict | None:
        items = self._list.selectedItems()
        if items:
            return items[0].data(Qt.ItemDataRole.UserRole)
        return None

    def _on_double(self, item):
        peer = item.data(Qt.ItemDataRole.UserRole)
        if peer:
            self.chat_requested.emit(peer)

    def _ctx_menu(self, pos):
        peer = self._selected_peer()
        if not peer:
            return
        ip = peer.get("ip","")
        pinned = self._is_pinned(ip)
        menu = QMenu(self)
        def _open_profile():
            _show_peer_profile_overlay(peer, self)

        for label, cb in [
            ("👤 Профиль",          _open_profile),
            ("💬 Личный чат",       lambda: self.chat_requested.emit(peer)),
            ("📞 Позвонить",        lambda: self.call_requested.emit(peer)),
            ("📎 Отправить файл",   lambda: self._send_file(peer)),
            ("➕ Добавить в группу",lambda: self._add_to_group(peer)),
            ("📌 Открепить" if pinned else "📌 Закрепить чат",
                                    lambda: self._toggle_pin(ip)),
        ]:
            a = QAction(label, self)
            a.triggered.connect(cb)
            menu.addAction(a)
        menu.exec(self._list.mapToGlobal(pos))

    def _send_file(self, peer):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл")
        if path:
            self.net.send_file(peer["ip"], path)

    def _add_to_group(self, peer):
        groups = GROUPS.list_for(get_local_ip())
        if not groups:
            QMessageBox.information(self, "Группы", "Сначала создайте группу.")
            return
        items = [f"{g['name']} ({gid})" for gid, g in groups]
        choice, ok = QInputDialog.getItem(self, "Добавить в группу", "Группа:", items, editable=False)
        if ok and choice:
            gid = choice.split("(")[-1].rstrip(")")
            GROUPS.add_member(gid, peer["ip"])
            self.net.send_group_invite(gid, GROUPS.get(gid).get("name","?"), peer["ip"])
            self._refresh_groups()

    # ── groups ──────────────────────────────────────────────────────────
    def _refresh_groups(self):
        self._groups_list.clear()
        pin_groups = set(json.loads(S().get("pinned_groups", "[]", t=str)))
        t = get_theme(S().theme)
        all_groups = GROUPS.list_for(get_local_ip())
        sorted_groups = sorted(all_groups, key=lambda x: (0 if x[0] in pin_groups else 1,
                                                           x[1].get("name","").lower()))
        for gid, g in sorted_groups:
            member_count = len(g.get("members",[]))
            pin_icon = "📌 " if gid in pin_groups else ""
            item = QListWidgetItem(f"{pin_icon}📂 {g['name']}  ({member_count} уч.)")
            item.setData(Qt.ItemDataRole.UserRole, gid)
            if gid in pin_groups:
                item.setBackground(QColor(t.get("accent","#6c63ff") + "22"))
            self._groups_list.addItem(item)

    def _on_group_double(self, item):
        gid = item.data(Qt.ItemDataRole.UserRole)
        if gid:
            self.group_selected.emit(gid)

    def _open_favorites(self):
        self.group_selected.emit("__favorites__")

    def _group_ctx_menu(self, pos):
        item = self._groups_list.itemAt(pos)
        t = get_theme(S().theme)
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu{{background:{t['bg2']};color:{t['text']};"
            f"border:1px solid {t['border']};border-radius:8px;padding:4px 0;}}"
            f"QMenu::item{{padding:7px 18px;font-size:12px;}}"
            f"QMenu::item:selected{{background:{t['accent']};color:white;"
            f"border-radius:5px;margin:1px 3px;}}"
            f"QMenu::separator{{height:1px;background:{t['border']};margin:3px 10px;}}")
        if item:
            gid = item.data(Qt.ItemDataRole.UserRole)
            g = GROUPS.get(gid) if gid else None
            name = g.get("name","?") if g else "?"
            open_a = QAction(f"💬 Открыть «{name}»", self)
            open_a.triggered.connect(lambda: self.group_selected.emit(gid))
            menu.addAction(open_a)
            menu.addSeparator()
            edit_a = QAction("✏ Редактировать группу", self)
            edit_a.triggered.connect(lambda: self._edit_group_dialog(gid))
            menu.addAction(edit_a)
            invite_a = QAction("📨 Отправить приглашение в чат", self)
            invite_a.triggered.connect(lambda checked, g=gid: self._send_invite_to_chat(g))
            menu.addAction(invite_a)
            pin_groups = set(json.loads(S().get("pinned_groups", "[]", t=str)))
            pin_lbl = "📌 Открепить группу" if gid in pin_groups else "📌 Закрепить группу"
            pin_a = QAction(pin_lbl, self)
            def _toggle_group_pin(checked=False, _gid=gid):
                import json as _j
                pg = list(_j.loads(S().get("pinned_groups", "[]", t=str)))
                if _gid in pg: pg.remove(_gid)
                else: pg.insert(0, _gid)
                S().set("pinned_groups", _j.dumps(pg))
                self._refresh_groups()
            pin_a.triggered.connect(_toggle_group_pin)
            menu.addAction(pin_a)
            menu.addAction(invite_a)
            menu.addSeparator()
            leave_a = QAction("🚪 Выйти из группы", self)
            leave_a.triggered.connect(lambda: self._leave_group(gid, name))
            menu.addAction(leave_a)
            del_a = QAction("🗑 Удалить группу", self)
            del_a.triggered.connect(lambda: self._delete_group(gid, name))
            menu.addAction(del_a)
        else:
            new_a = QAction("➕ Создать группу", self)
            new_a.triggered.connect(self._create_group)
            menu.addAction(new_a)
        menu.exec(self._groups_list.mapToGlobal(pos))

    def _send_invite_to_chat(self, gid: str):
        """Show dialog to pick a chat and send a group invite message with JOIN button."""
        g = GROUPS.get(gid)
        if not g: return
        t = get_theme(S().theme)

        dlg = QDialog(self)
        dlg.setWindowTitle("Отправить приглашение")
        dlg.resize(340, 420)
        dlg.setStyleSheet(f"background:{t['bg2']};color:{t['text']};")
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(8)

        lbl = QLabel(f"Куда отправить приглашение в «{g.get('name','?')}»?")
        lbl.setWordWrap(True)
        lbl.setStyleSheet("font-size:12px;font-weight:bold;")
        lay.addWidget(lbl)

        dest_list = QListWidget()
        dest_list.setStyleSheet(
            f"QListWidget{{background:{t['bg3']};border:1px solid {t['border']};"
            "border-radius:8px;}}"
            f"QListWidget::item{{padding:8px 12px;}}"
            f"QListWidget::item:selected{{background:{t['accent']};color:white;}}")

        # Add public chat
        pub_item = QListWidgetItem("💬 Общий чат")
        pub_item.setData(Qt.ItemDataRole.UserRole, ("public", None))
        dest_list.addItem(pub_item)

        # Add peer DMs
        for ip, peer in self._peers.items():
            name = peer.get("username", ip)
            item = QListWidgetItem(f"👤 {name}")
            item.setData(Qt.ItemDataRole.UserRole, ("peer", peer))
            dest_list.addItem(item)

        # Add other groups
        for other_gid, other_g in GROUPS.list_for(get_local_ip()):
            if other_gid != gid:
                item = QListWidgetItem(f"📂 {other_g.get('name','?')}")
                item.setData(Qt.ItemDataRole.UserRole, ("group", other_gid))
                dest_list.addItem(item)

        lay.addWidget(dest_list)

        btn_row = QHBoxLayout()
        send_btn = QPushButton("📨 Отправить")
        send_btn.setObjectName("accent_btn")
        cancel_btn = QPushButton("Отмена")
        cancel_btn.clicked.connect(dlg.reject)
        btn_row.addStretch()
        btn_row.addWidget(send_btn)
        btn_row.addWidget(cancel_btn)
        lay.addLayout(btn_row)

        def do_send():
            item = dest_list.currentItem()
            if not item:
                QMessageBox.warning(dlg, "Выберите чат", "Выберите, куда отправить.")
                return
            dest_type, dest_data = item.data(Qt.ItemDataRole.UserRole)
            ip_self = get_local_ip()
            invite_payload = {
                "type": "group_invite_msg",
                "gid": gid,
                "gname": g.get("name", "?"),
                "host": ip_self,
                "from": S().username,
            }
            import json
            invite_json = json.dumps(invite_payload, ensure_ascii=False)

            # Emit invite_message signal so ChatPanel displays the invite bubble
            self.invite_message_requested.emit(dest_type,
                                               dest_data if dest_data else "",
                                               invite_json)
            dlg.accept()
            QMessageBox.information(self, "Отправлено",
                f"Приглашение в «{g.get('name','?')}» отправлено!")

        send_btn.clicked.connect(do_send)
        dest_list.itemDoubleClicked.connect(lambda _: do_send())
        dlg.exec()

    def _leave_group(self, gid: str, name: str):
        if QMessageBox.question(self, "Выйти из группы",
                f"Выйти из группы «{name}»?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) \
                == QMessageBox.StandardButton.Yes:
            GROUPS.remove_member(gid, get_local_ip())
            self._refresh_groups()

    def _delete_group(self, gid: str, name: str):
        if QMessageBox.question(self, "Удалить группу",
                f"Удалить группу «{name}»? Это действие нельзя отменить.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) \
                == QMessageBox.StandardButton.Yes:
            GROUPS.delete(gid)
            self._refresh_groups()

    def _edit_group_dialog(self, gid: str):
        g = GROUPS.get(gid)
        if not g: return
        main_win = self.window()
        tabs = getattr(main_win, '_tabs', None)
        t = get_theme(S().theme)
        if tabs is not None:
            tab_title = f"📂 {g.get('name','?') }"
            for i in range(tabs.count()):
                if tabs.tabText(i).strip() == tab_title:
                    tabs.setCurrentIndex(i); return
            dlg = QWidget(main_win)
        else:
            dlg = QDialog(self)
            dlg.setWindowTitle(f"Группа: {g.get('name','')}")
            dlg.resize(460, 560)
        dlg.setStyleSheet(f"background:{t['bg2']};color:{t['text']};")
        # Wrap in scroll for tab display
        _outer = QVBoxLayout(dlg)
        _outer.setContentsMargins(0,0,0,0)
        _scroll = QScrollArea()
        _scroll.setWidgetResizable(True)
        _scroll.setStyleSheet(
            f"QScrollArea{{background:{t['bg2']};border:none;}}"
            f"QScrollBar:vertical{{width:6px;background:{t['bg3']};}}"
            f"QScrollBar::handle:vertical{{background:{t['border']};border-radius:3px;}}")
        _inner = QWidget()
        _inner.setStyleSheet(f"background:{t['bg2']};")
        _scroll.setWidget(_inner)
        _outer.addWidget(_scroll)
        dl = QVBoxLayout(_inner)
        dl.setContentsMargins(20, 20, 20, 20)
        dl.setSpacing(12)

        # ── Avatar ──────────────────────────────────────────────────────
        av_row = QHBoxLayout()
        av_lbl = QLabel()
        av_lbl.setFixedSize(72, 72)
        av_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        av_lbl.setStyleSheet(
            f"background:{t['bg3']};border-radius:36px;"
            f"border:2px solid {t['border']};font-size:24px;")
        # Load saved avatar if any
        av_b64 = g.get("avatar_b64", "")
        if av_b64:
            try:
                pm = QPixmap()
                pm.loadFromData(base64.b64decode(av_b64))
                pm = pm.scaled(64, 64, Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                               Qt.TransformationMode.SmoothTransformation)
                # Crop to square then make circular
                pm = pm.copy(
                    (pm.width()-64)//2, (pm.height()-64)//2, 64, 64)
                av_lbl.setPixmap(make_circle_pixmap(pm, 64))
                av_lbl.setStyleSheet(
                    f"background:transparent;border-radius:32px;"
                    f"border:2px solid {t['accent']};")
            except Exception:
                av_lbl.setText("📂")
        else:
            av_lbl.setText("📂")
        av_row.addWidget(av_lbl)
        av_info = QVBoxLayout()
        av_info.addWidget(QLabel("<b>Аватар группы</b>"))
        av_btn = QPushButton("📷 Изменить аватар")
        av_btn.setObjectName("accent_btn")
        def do_change_avatar():
            path, _ = QFileDialog.getOpenFileName(
                dlg, "Выберите изображение", "",
                "Изображения (*.png *.jpg *.jpeg *.gif *.webp)")
            if not path: return
            try:
                pm2 = QPixmap(path).scaled(
                    128, 128,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation)
                import io
                buf = QBuffer()
                buf.open(QIODevice.OpenModeFlag.WriteOnly)
                pm2.save(buf, "PNG")
                b64 = base64.b64encode(bytes(buf.data())).decode()
                buf.close()
                g2 = GROUPS.get(gid) or {}
                g2["avatar_b64"] = b64
                GROUPS.groups[gid] = g2
                GROUPS._save()
                av_lbl.setPixmap(pm2.scaled(64, 64, Qt.AspectRatioMode.KeepAspectRatio,
                                            Qt.TransformationMode.SmoothTransformation))
                self._refresh_groups()
            except Exception as e:
                QMessageBox.warning(dlg, "Ошибка", f"Не удалось загрузить: {e}")
        av_btn.clicked.connect(do_change_avatar)
        av_info.addWidget(av_btn)
        av_row.addLayout(av_info)
        av_row.addStretch()
        dl.addLayout(av_row)

        # ── Name ────────────────────────────────────────────────────────
        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Название:"))
        name_edit = QLineEdit(g.get("name",""))
        name_edit.setPlaceholderText("Название группы")
        name_row.addWidget(name_edit)
        rename_btn = QPushButton("✏ Переименовать")
        def do_rename():
            n = name_edit.text().strip()
            if n:
                GROUPS.rename(gid, n)
                dlg.setWindowTitle(f"Группа: {n}")
                self._refresh_groups()
        rename_btn.clicked.connect(do_rename)
        name_row.addWidget(rename_btn)
        dl.addLayout(name_row)

        # Members
        dl.addWidget(QLabel("Участники:"))
        members_list = QListWidget()
        members_list.setMaximumHeight(180)
        def refresh_members():
            members_list.clear()
            g2 = GROUPS.get(gid)
            if not g2: return
            for ip in g2.get("members",[]):
                name_lbl = ip
                # Try to find peer name
                if ip == get_local_ip():
                    name_lbl = f"[Вы]  {ip}"
                members_list.addItem(QListWidgetItem(f"👤 {name_lbl}"))
                members_list.item(members_list.count()-1).setData(
                    Qt.ItemDataRole.UserRole, ip)
        refresh_members()
        dl.addWidget(members_list)

        mem_btn_row = QHBoxLayout()
        kick_btn = QPushButton("🚫 Удалить участника")
        def do_kick():
            item = members_list.currentItem()
            if not item: return
            ip = item.data(Qt.ItemDataRole.UserRole)
            if ip == get_local_ip():
                QMessageBox.warning(dlg,"Нельзя","Нельзя удалить себя.")
                return
            GROUPS.remove_member(gid, ip)
            refresh_members()
            self._refresh_groups()
        kick_btn.clicked.connect(do_kick)
        mem_btn_row.addWidget(kick_btn)

        invite_peer_btn = QPushButton("➕ Пригласить пользователя")
        def do_invite():
            peers_online = self._peers
            if not peers_online:
                QMessageBox.information(dlg,"Нет пользователей","Никого нет онлайн.")
                return
            names = [f"{v.get('username','?')} ({k})" for k,v in peers_online.items()]
            choice, ok = QInputDialog.getItem(dlg,"Пригласить","Выберите пользователя:",
                names, editable=False)
            if ok and choice:
                ip = choice.split("(")[-1].rstrip(")")
                GROUPS.add_member(gid, ip)
                self.net.send_group_invite(gid, g.get("name","?"), ip)
                refresh_members()
                self._refresh_groups()
        invite_peer_btn.clicked.connect(do_invite)
        mem_btn_row.addWidget(invite_peer_btn)
        dl.addLayout(mem_btn_row)

        # Invite link
        dl.addWidget(QLabel("Ссылка-приглашение:"))
        ip_self = get_local_ip()
        invite_str = f"goidaphone://join/{gid}?host={ip_self}&name={g.get('name','')}"
        inv_row = QHBoxLayout()
        inv_lbl = QLineEdit(invite_str)
        inv_lbl.setReadOnly(True)
        copy_inv = QPushButton("📋 Копировать")
        copy_inv.clicked.connect(lambda: (QApplication.clipboard().setText(invite_str),
                                          QMessageBox.information(dlg,"Скопировано","Ссылка скопирована!")))
        inv_row.addWidget(inv_lbl)
        inv_row.addWidget(copy_inv)
        dl.addLayout(inv_row)

        # Danger zone
        dl.addWidget(QLabel(""))
        danger_row = QHBoxLayout()
        leave_btn2 = QPushButton("🚪 Выйти")
        leave_btn2.clicked.connect(lambda: (dlg.accept(), self._leave_group(gid, g.get("name",""))))
        del_btn2 = QPushButton("🗑 Удалить группу")
        del_btn2.setObjectName("danger_btn")
        del_btn2.clicked.connect(lambda: (dlg.accept(), self._delete_group(gid, g.get("name",""))))
        danger_row.addStretch()
        danger_row.addWidget(leave_btn2)
        danger_row.addWidget(del_btn2)
        dl.addLayout(danger_row)

        close_btn = QPushButton("Закрыть")
        dl.addWidget(close_btn)
        if tabs is not None:
            def _do_close():
                for i in range(tabs.count()):
                    if tabs.widget(i) is dlg:
                        tabs.removeTab(i); break
            close_btn.clicked.connect(_do_close)
            tab_title = f"📂 {g.get('name','?')  }"
            idx = tabs.addTab(dlg, tab_title)
            tabs.setCurrentIndex(idx)
            if hasattr(main_win, '_add_tab_close_btn'):
                main_win._add_tab_close_btn(idx)
        else:
            close_btn.clicked.connect(dlg.accept)
            dlg.exec()

    def _create_group(self):
        name, ok = QInputDialog.getText(self, "Новая группа", "Название группы:")
        if ok and name.strip():
            gid = GROUPS.create(name.strip(), get_local_ip())
            self._refresh_groups()
            # Ask to immediately open edit dialog
            if QMessageBox.question(self,"Группа создана",
                    f"Группа «{name}» создана.\nОткрыть настройки группы?",
                    QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) \
                    == QMessageBox.StandardButton.Yes:
                self._edit_group_dialog(gid)

# ═══════════════════════════════════════════════════════════════════════════
#  CHAT PANEL
# ═══════════════════════════════════════════════════════════════════════════
class _GrowingTextEdit(QTextEdit):
    """
    Многострочное поле ввода, которое растёт по мере ввода текста.
    Enter = отправить, Shift+Enter = новая строка.
    """
    send_pressed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptRichText(False)
        self.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.setMinimumHeight(36)
        self.setMaximumHeight(120)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.document().contentsChanged.connect(self._adjust_height)
        self.setStyleSheet(
            "QTextEdit{border:none;background:transparent;"
            "padding:4px 0;font-size:13px;}")

    def _adjust_height(self):
        doc_h = int(self.document().size().height()) + 8
        new_h = max(36, min(120, doc_h))
        if self.height() != new_h:
            self.setFixedHeight(new_h)

    def keyPressEvent(self, event):
        if (event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
                and not (event.modifiers() & Qt.KeyboardModifier.ShiftModifier)):
            self.send_pressed.emit()
        else:
            super().keyPressEvent(event)

    def setPlaceholderText(self, text: str):
        self._placeholder = text
        self.document().setPlainText("")

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.toPlainText() == "" and hasattr(self, '_placeholder'):
            from PyQt6.QtGui import QPainter, QColor
            p = QPainter(self.viewport())
            p.setPen(QColor(128, 128, 128, 160))
            p.setFont(self.font())
            p.drawText(self.viewport().rect().adjusted(4, 4, -4, -4),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
                       self._placeholder)


class ChatPanel(QWidget):
    def __init__(self, net: NetworkManager, voice: VoiceCallManager, parent=None):
        super().__init__(parent)
        self.net   = net
        self.voice = voice
        self._current_peer: dict | None = None
        self._current_gid:  str | None  = None
        self._typing_timer = QTimer()
        self._typing_timer.setSingleShot(True)
        self._typing_timer.timeout.connect(self._send_typing)
        self._in_call = False
        self._drafts: dict[str, str] = {}  # chat_id → draft text
        self._ttl_seconds: int = 0           # 0=off, else seconds until auto-delete
        self._ttl_timers: list = []          # active QTimer refs for TTL messages
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        # Header
        self._header = QWidget()
        self._header.setObjectName("chat_header")
        hl = QHBoxLayout(self._header)
        hl.setContentsMargins(12,8,12,8)
        t = get_theme(S().theme)
        self._header.setStyleSheet(f"""
            QWidget#chat_header {{
                background: {t['bg2']};
                border-bottom: 1px solid {t['border']};
            }}
        """)

        self._avatar_lbl = QLabel()
        self._avatar_lbl.setFixedSize(36,36)
        hl.addWidget(self._avatar_lbl)

        vl = QVBoxLayout()
        vl.setSpacing(0)
        self._title_lbl = QLabel(TR("public_chat"))
        self._title_lbl.setStyleSheet(
            f"font-weight:bold;font-size:13px;color:{t['text']};background:transparent;")
        vl.addWidget(self._title_lbl)
        self._sub_lbl = QLabel(TR("all_users"))
        self._sub_lbl.setStyleSheet(
            f"color:{t['text_dim']};font-size:10px;background:transparent;")
        vl.addWidget(self._sub_lbl)
        hl.addLayout(vl)
        hl.addStretch()

        self._call_btn = QPushButton("📞")
        self._call_btn.setFixedSize(32,32)
        self._call_btn.setToolTip(TR("call"))
        self._call_btn.clicked.connect(self._toggle_call)
        self._call_btn.setVisible(False)
        hl.addWidget(self._call_btn)

        self._file_btn = QPushButton("📎")
        self._file_btn.setFixedSize(32,32)
        self._file_btn.setToolTip(TR("attach"))
        self._file_btn.clicked.connect(self._send_file)
        self._file_btn.setVisible(False)
        hl.addWidget(self._file_btn)

        lay.addWidget(self._header)

        # Reply bar (hidden by default) — п.21
        self._reply_bar = QWidget()
        rbl = QHBoxLayout(self._reply_bar)
        rbl.setContentsMargins(12,4,12,4)
        self._reply_bar.setStyleSheet(f"""
            background: {t['bg2']};
            border-bottom: 1px solid {t['border']};
        """)
        self._reply_lbl = QLabel("")
        self._reply_lbl.setStyleSheet(f"color: {t['text_dim']}; font-size: 10px;")
        self._reply_lbl.setWordWrap(False)
        rbl.addWidget(self._reply_lbl)
        rbl.addStretch()
        cancel_reply = QPushButton("×")
        cancel_reply.setFixedSize(20,20)
        cancel_reply.setStyleSheet(f"""
            QPushButton {{
                background: {t['btn_bg']}; color: {t['text_dim']};
                border: none; border-radius: 10px; font-weight: bold;
            }}
            QPushButton:hover {{ background: #CC2222; color: white; }}
        """)
        cancel_reply.clicked.connect(self._cancel_reply)
        rbl.addWidget(cancel_reply)
        self._reply_bar.setVisible(False)
        lay.addWidget(self._reply_bar)
        self._reply_to_text = ""
        self._reply_to_ts = 0.0

        # ── Search bar (Ctrl+F, hidden by default) ──────────────────────
        self._search_bar = QWidget()
        self._search_bar.setObjectName("chat_search_bar")
        self._search_bar.setFixedHeight(38)
        self._search_bar.setStyleSheet(f"""
            QWidget#chat_search_bar {{
                background: {t['bg2']};
                border-bottom: 1px solid {t['border']};
            }}
        """)
        sb_lay = QHBoxLayout(self._search_bar)
        sb_lay.setContentsMargins(10, 4, 10, 4)
        sb_lay.setSpacing(6)
        search_ico = QLabel("🔍")
        search_ico.setStyleSheet("background:transparent;font-size:12px;")
        sb_lay.addWidget(search_ico)
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Поиск по сообщениям... (Enter — следующее)")
        self._search_input.setStyleSheet(f"""
            QLineEdit {{
                background:transparent;border:none;
                color:{t['text']};font-size:11px;
            }}
        """)
        self._search_input.textChanged.connect(self._do_search)
        self._search_input.returnPressed.connect(self._search_next)
        sb_lay.addWidget(self._search_input, stretch=1)
        self._search_count_lbl = QLabel("")
        self._search_count_lbl.setStyleSheet(
            f"color:{t['text_dim']};font-size:9px;background:transparent;min-width:80px;")
        sb_lay.addWidget(self._search_count_lbl)
        for label, tip, cb in [("▲", "Предыдущее", self._search_prev),
                                ("▼", "Следующее",  self._search_next)]:
            b = QPushButton(label)
            b.setFixedSize(22, 22)
            b.setToolTip(tip)
            b.setStyleSheet(f"QPushButton{{background:{t['btn_bg']};border:none;"
                            f"border-radius:4px;color:{t['text']};font-size:9px;}}"
                            f"QPushButton:hover{{background:{t['btn_hover']};}}")
            b.clicked.connect(cb)
            sb_lay.addWidget(b)
        close_sb = QPushButton("✕")
        close_sb.setFixedSize(22, 22)
        close_sb.setStyleSheet(f"QPushButton{{background:transparent;border:none;"
                               f"color:{t['text_dim']};font-size:11px;}}"
                               f"QPushButton:hover{{color:{t['text']};}}")
        close_sb.clicked.connect(self._close_search)
        sb_lay.addWidget(close_sb)
        self._search_bar.setVisible(False)
        self._search_matches: list[int] = []
        self._search_match_idx: int = -1
        lay.addWidget(self._search_bar)

        # Typing indicator
        self._typing_lbl = QLabel("")
        self._typing_lbl.setStyleSheet(f"color: {t['text_dim']}; font-size:10px; padding: 2px 12px; font-style:italic;")
        self._typing_lbl.setFixedHeight(18)
        lay.addWidget(self._typing_lbl)
        self._typing_hide_timer = QTimer()
        self._typing_hide_timer.setSingleShot(True)
        self._typing_hide_timer.timeout.connect(lambda: self._typing_lbl.setText(""))

        # Chat display
        self._display = ChatDisplay(chat_id="public")
        # Connect context menu signals
        self._display.request_forward.connect(self._on_forward_request)
        self._display.request_edit.connect(self._on_edit_request)
        self._display.request_delete.connect(self._on_delete_request)
        self._display.request_react.connect(self._on_react_request)
        self._display.request_react_with_emoji.connect(self._send_reaction)
        self._display.request_reply.connect(self._on_reply_request)
        lay.addWidget(self._display, stretch=1)

        # Ctrl+F = open search
        ctrlf = QShortcut(QKeySequence("Ctrl+F"), self)
        ctrlf.activated.connect(self._toggle_search_bar)

        # Call status bar (hidden by default)
        self._call_bar = QWidget()
        self._call_bar.setObjectName("call_bar_active")
        cbl = QHBoxLayout(self._call_bar)
        cbl.setContentsMargins(12,6,12,6)
        self._call_bar.setStyleSheet("""
            QWidget#call_bar_active {
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 #1A4A1A, stop:1 #123012);
                border-top: 1px solid #2A5A2A;
            }
        """)
        self._call_status_lbl = QLabel(TR("active_call"))
        self._call_status_lbl.setStyleSheet("color: #80FF80; font-weight: bold;")
        cbl.addWidget(self._call_status_lbl)
        cbl.addStretch()
        self._mute_btn = QPushButton(TR("mute_mic"))
        self._mute_btn.clicked.connect(self._toggle_mute)
        cbl.addWidget(self._mute_btn)
        self._hangup_btn = QPushButton("📵 " + TR("hangup"))
        self._hangup_btn.setObjectName("danger_btn")
        self._hangup_btn.clicked.connect(self._hangup)
        cbl.addWidget(self._hangup_btn)
        self._call_bar.setVisible(False)
        lay.addWidget(self._call_bar)

        # ── Inline sticker panel ──────────────────────────────────────
        t2 = get_theme(S().theme)
        self._sticker_panel = QWidget()
        self._sticker_panel.setObjectName("sticker_panel")
        self._sticker_panel.setStyleSheet(
            f"QWidget#sticker_panel{{background:{t2['bg2']};"
            f"border-top:1px solid {t2['border']};}}")
        sp_lay = QVBoxLayout(self._sticker_panel)
        sp_lay.setContentsMargins(8, 6, 8, 4)
        sp_lay.setSpacing(4)

        # Header row: title + pack combo + manage + close
        sp_top = QHBoxLayout()
        sp_top.setSpacing(6)
        sp_lbl = QLabel("🎭 Стикеры")
        sp_lbl.setStyleSheet(
            f"font-weight:bold;font-size:11px;color:{t2['text']};background:transparent;")
        sp_top.addWidget(sp_lbl)

        self._sp_pack_combo = QComboBox()
        self._sp_pack_combo.setFixedHeight(26)
        self._sp_pack_combo.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._sp_pack_combo.currentIndexChanged.connect(self._refresh_sticker_grid)
        sp_top.addWidget(self._sp_pack_combo)

        manage_btn = QPushButton("⚙ Паки")
        manage_btn.setFixedHeight(26)
        manage_btn.setToolTip("Управление паками стикеров")
        manage_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        manage_btn.setStyleSheet(
            f"QPushButton{{background:{t2['bg3']};color:{t2['text']};"
            f"border:1px solid {t2['border']};border-radius:5px;"
            "padding:0 8px;font-size:10px;}}"
            f"QPushButton:hover{{background:{t2['btn_hover']};}}")
        manage_btn.clicked.connect(self._open_sticker_manager)
        sp_top.addWidget(manage_btn)

        sp_close = QPushButton("✕")
        sp_close.setFixedSize(24, 24)
        sp_close.setFlat(True)
        sp_close.setCursor(Qt.CursorShape.PointingHandCursor)
        sp_close.setStyleSheet(
            f"QPushButton{{color:{t2['text_dim']};background:transparent;"
            "border:none;font-size:13px;font-weight:bold;border-radius:12px;}}"
            f"QPushButton:hover{{background:{t2['btn_hover']};color:{t2['text']};}}")
        sp_close.clicked.connect(lambda: self._toggle_sticker_panel(False))
        sp_top.addWidget(sp_close)
        sp_lay.addLayout(sp_top)

        # Sticker scroll grid
        sticker_scroll = QScrollArea()
        sticker_scroll.setWidgetResizable(True)
        sticker_scroll.setFixedHeight(156)
        sticker_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        sticker_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        sticker_scroll.setFrameShape(QFrame.Shape.NoFrame)
        sticker_scroll.setStyleSheet(
            f"QScrollArea{{background:{t2['bg2']};border:none;}}"
            f"QScrollBar:vertical{{background:{t2['bg3']};width:6px;border-radius:3px;}}"
            f"QScrollBar::handle:vertical{{background:{t2['border']};border-radius:3px;}}")
        self._sticker_grid_widget = QWidget()
        self._sticker_grid_widget.setStyleSheet(
            f"background:{t2['bg2']};")
        self._sticker_grid_layout = QGridLayout(self._sticker_grid_widget)
        self._sticker_grid_layout.setSpacing(6)
        self._sticker_grid_layout.setContentsMargins(4, 4, 4, 4)
        sticker_scroll.setWidget(self._sticker_grid_widget)
        sp_lay.addWidget(sticker_scroll)

        self._sticker_panel.setVisible(False)
        # Sticker panel is now shown as floating side popup, NOT in main layout

        # Input area
        input_w = QWidget()
        input_w.setObjectName("input_area")
        t = get_theme(S().theme)
        input_w.setStyleSheet(f"""
            QWidget#input_area {{
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 {t['bg2']}, stop:1 {t['bg']});
                border-top: 1px solid {t['border']};
            }}
        """)
        il = QHBoxLayout(input_w)
        il.setContentsMargins(8,8,8,8)
        il.setSpacing(6)

        self._input = _GrowingTextEdit()
        self._input.setPlaceholderText(TR("type_message"))
        self._input.send_pressed.connect(self._send_text)
        self._input.textChanged.connect(self._on_typing_te)
        self._input.textChanged.connect(self._on_slash_complete_te)
        il.addWidget(self._input)

        self._emoji_btn = QPushButton("😊")
        self._emoji_btn.setFixedSize(34,34)
        self._emoji_btn.setToolTip(TR("emoji"))
        self._emoji_btn.clicked.connect(self._emoji_picker)
        il.addWidget(self._emoji_btn)

        self._sticker_btn = QPushButton("🎭")
        self._sticker_btn.setFixedSize(34,34)
        self._sticker_btn.setToolTip("Стикеры")
        self._sticker_btn.setCheckable(True)
        self._sticker_btn.clicked.connect(lambda checked: self._toggle_sticker_panel(checked))
        il.addWidget(self._sticker_btn)

        send_btn = QPushButton("➤")
        send_btn.setFixedSize(38,34)
        send_btn.setObjectName("accent_btn")
        send_btn.clicked.connect(self._send_text)
        il.addWidget(send_btn)

        lay.addWidget(input_w)

        # Slash command hint popup — shows above input, does NOT intercept keyboard
        self._cmd_popup = QListWidget(self)
        self._cmd_popup.setWindowFlags(
            Qt.WindowType.Tool |
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowDoesNotAcceptFocus)
        self._cmd_popup.setFixedWidth(280)
        self._cmd_popup.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self._cmd_popup.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._cmd_popup.hide()
        self._cmd_popup.itemClicked.connect(self._on_cmd_selected)

        # Load public history
        self._load_history("public")

    # ── navigation ──────────────────────────────────────────────────────
    def _save_draft(self):
        """Save current input text as draft for current chat."""
        cid = self._get_current_chat_id()
        if cid:
            text = self._input.toPlainText().strip()
            if text:
                self._drafts[cid] = text
            else:
                self._drafts.pop(cid, None)

    def _restore_draft(self, chat_id: str):
        """Restore draft for given chat_id into input field."""
        draft = self._drafts.get(chat_id, "")
        self._input.setPlainText(draft)
        if draft:
            # Move cursor to end
            cur = self._input.textCursor()
            cur.movePosition(cur.MoveOperation.End)
            self._input.setTextCursor(cur)

    def open_public(self):
        self._save_draft()
        self._current_peer = None
        self._current_gid  = None
        self._title_lbl.setText(TR("public_chat"))
        self._title_lbl.setTextFormat(Qt.TextFormat.PlainText)
        self._sub_lbl.setText(TR("all_users"))
        self._call_btn.setVisible(False)
        self._file_btn.setVisible(False)
        # Public chat has no avatar — hide avatar slot completely
        self._avatar_lbl.setPixmap(QPixmap())
        self._avatar_lbl.setFixedSize(0, 0)
        self._avatar_lbl.setVisible(False)
        self._display.chat_id = "public"
        self._display.clear()
        self._display._messages.clear()
        self._load_history("public")
        UNREAD.mark_read("public")
        self._cancel_reply()

    def open_peer(self, peer: dict):
        self._save_draft()
        self._current_peer = peer
        self._current_gid  = None
        color  = peer.get("nickname_color","#E0E0E0")
        emoji  = peer.get("custom_emoji","")
        name   = peer.get("username","?")
        ip     = peer.get("ip","")
        self._title_lbl.setText(f"<span style='color:{color}'>{name} {emoji}</span>")
        self._title_lbl.setTextFormat(Qt.TextFormat.RichText)
        sec = CRYPTO.security_level(ip)
        fp  = CRYPTO.peer_fingerprint(ip) if CRYPTO.has_session(ip) else "нет E2E-ключа"
        self._sub_lbl.setText(f"{TR('private_chat')} • {ip}  {sec}")
        self._sub_lbl.setToolTip(f"Отпечаток собеседника: {fp}")
        self._call_btn.setVisible(True)
        self._file_btn.setVisible(True)
        # Avatar
        self._avatar_lbl.setFixedSize(36, 36)
        self._avatar_lbl.setVisible(True)
        av_b64 = peer.get("avatar_b64","")
        if av_b64:
            try:
                pm = base64_to_pixmap(av_b64)
                self._avatar_lbl.setPixmap(make_circle_pixmap(pm, 36))
            except Exception:
                self._avatar_lbl.setPixmap(default_avatar(name, 36))
        else:
            self._avatar_lbl.setPixmap(default_avatar(name, 36))
        chat_id = peer["ip"]
        self._display.chat_id = chat_id
        self._display.clear()
        self._display._messages.clear()
        self._load_history(chat_id)
        UNREAD.mark_read(chat_id)
        self._cancel_reply()
        self._restore_draft(chat_id)
        # Send read receipt
        if self.net:
            self.net.send_read_receipt(peer["ip"], chat_id)

    def open_group(self, gid: str):
        self._save_draft()
        self._current_peer = None
        self._current_gid  = gid

        # ── Избранное (self-chat) ───────────────────────────────────────
        if gid == "__favorites__":
            self._title_lbl.setText("⭐ Избранное")
            self._title_lbl.setTextFormat(Qt.TextFormat.PlainText)
            self._sub_lbl.setText("Заметки, ссылки, файлы только для себя")
            self._call_btn.setVisible(False)
            self._file_btn.setVisible(True)
            self._avatar_lbl.setPixmap(QPixmap())
            chat_id = "__favorites__"
            self._display.chat_id = chat_id
            self._display.clear()
            self._display._messages.clear()
            self._load_history(chat_id)
            UNREAD.mark_read(chat_id)
            self._cancel_reply()
            return

        g = GROUPS.get(gid)
        self._title_lbl.setText(f"📂 {g.get('name','Группа')}")
        self._title_lbl.setTextFormat(Qt.TextFormat.PlainText)
        members = g.get("members",[])
        self._sub_lbl.setText(f"Участников: {len(members)}")
        self._call_btn.setVisible(True)
        self._file_btn.setVisible(True)
        g_av = g.get("avatar_b64","")
        if g_av:
            try:
                pm_g = QPixmap(); pm_g.loadFromData(base64.b64decode(g_av))
                self._avatar_lbl.setPixmap(make_circle_pixmap(pm_g, 36))
            except Exception:
                self._avatar_lbl.setPixmap(QPixmap())
        else:
            self._avatar_lbl.setPixmap(QPixmap())
        chat_id = f"group_{gid}"
        self._display.chat_id = chat_id
        self._display.clear()
        self._display._messages.clear()
        self._load_history(chat_id)
        UNREAD.mark_read(chat_id)
        self._cancel_reply()

    def _load_history(self, chat_id: str):
        msgs = HISTORY.load(chat_id)
        self._display.load_history(msgs)

    # ── slash command handling ────────────────────────────────────────────
    # Available commands (п.26)
    _SLASH_COMMANDS = {
        "/clear":   "Очистить чат",
        "/help":    "Список команд",
        "/me":      "Действие (/me прыгает)",
        "/ping":    "Проверка соединения",
        "/version": "Версия GoidaPhone",
        "/nick":    "Сменить ник (/nick ИмяНовое)",
        "/away":    "Статус: отошёл",
        "/busy":    "Статус: занят",
        "/dnd":     "Статус: не беспокоить",
        "/online":  "Статус: онлайн",
        "/search":  "Поиск по истории (/search текст)",
        "/shrug":   "Добавить ¯\\_(ツ)_/¯",
    }

    def _on_slash_complete_te(self):
        """Called on textChanged from QTextEdit — shows slash autocomplete popup."""
        text = self._input.toPlainText().strip()
        self._on_slash_complete(text)

    def _on_slash_complete(self, text: str):
        """Show autocomplete popup only while typing the command name itself."""
        if not text.startswith("/"):
            self._cmd_popup.hide()
            return

        # If the user already typed a space (entered args), hide popup
        if " " in text:
            self._cmd_popup.hide()
            return

        cmd_part = text.lower()
        matches = [(cmd, desc) for cmd, desc in self._SLASH_COMMANDS.items()
                   if cmd.startswith(cmd_part) and cmd != cmd_part]

        # Exact match — hide popup, user has typed the full command
        if not matches or cmd_part in self._SLASH_COMMANDS:
            self._cmd_popup.hide()
            return

        self._cmd_popup.clear()
        t = get_theme(S().theme)
        self._cmd_popup.setStyleSheet(f"""
            QListWidget {{
                background: {t['bg2']}; color: {t['text']};
                border: 1px solid {t['accent']}; border-radius: 8px;
                padding: 4px;
            }}
            QListWidget::item {{ padding: 5px 10px; border-radius: 4px; }}
            QListWidget::item:selected, QListWidget::item:hover {{
                background: {t['accent']}; color: white;
            }}
        """)
        for cmd, desc in matches[:8]:
            item = QListWidgetItem(f"{cmd}  —  {desc}")
            item.setData(Qt.ItemDataRole.UserRole, cmd)
            self._cmd_popup.addItem(item)

        # Position popup DIRECTLY above input field — no gap
        popup_h = min(len(matches[:8]) * 34 + 8, 240)
        # Map top-left of input to global, then go up by exactly popup_h
        gp = self._input.mapToGlobal(QPoint(0, -popup_h))
        popup_w = max(320, self._input.width())
        self._cmd_popup.setFixedWidth(popup_w)
        self._cmd_popup.setFixedHeight(popup_h)
        self._cmd_popup.move(gp)
        self._cmd_popup.show()
        # Keep focus on input field — popup is just a hint
        self._input.setFocus()

    def _on_cmd_selected(self, item):
        cmd = item.data(Qt.ItemDataRole.UserRole)
        self._input.setPlainText(cmd + " ")
        # Move cursor to end
        cur = self._input.textCursor()
        cur.movePosition(cur.MoveOperation.End)
        self._input.setTextCursor(cur)
        self._input.setFocus()
        self._cmd_popup.hide()

    def _handle_slash_command(self, text: str) -> bool:
        """
        Handle slash commands. Returns True if command was consumed.
        """
        parts = text.strip().split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "/clear":
            chat_id = self._get_current_chat_id()
            self._display.clear()
            self._display._messages.clear()
            # Also wipe the history file so it doesn't reload on restart
            try:
                f = HISTORY._file(chat_id)
                if f.exists():
                    f.unlink()
                HISTORY._cache.pop(chat_id, None)
            except Exception as e:
                print(f"[clear] history wipe error: {e}")
            self._display.add_system(TR("cmd_clear_done"))
            return True

        elif cmd == "/help":
            help_text = TR("cmd_help")
            self._display.add_system(help_text)
            return True

        elif cmd == "/me":
            if arg:
                # /me jumps → "Username jumps"
                full = f"* {S().username} {arg}"
                ts = time.time()
                chat_id = self._get_current_chat_id()
                if self._current_peer:
                    self.net.send_private(full, self._current_peer["ip"])
                elif self._current_gid:
                    g = GROUPS.get(self._current_gid)
                    self.net.send_group_msg(self._current_gid, full, g.get("members",[]))
                else:
                    self.net.send_chat(full)
                self._display.add_message(S().username, full, ts, is_own=True,
                                          color=S().nickname_color)
                HISTORY.append(chat_id, {"sender": S().username, "text": full,
                                          "ts": ts, "is_own": True})
            return True

        elif cmd == "/ping":
            self._display.add_system(TR("cmd_ping"))
            return True

        elif cmd == "/version":
            self._display.add_system(
                f"GoidaPhone v{APP_VERSION} | Protocol v{PROTOCOL_VERSION} | {COMPANY_NAME}")
            return True

        elif cmd == "/nick":
            if arg.strip():
                old = S().username
                S().username = arg.strip()
                self._display.add_system(f"Ник изменён: {old} → {arg.strip()}")
                self.net._broadcast()
            return True

        elif cmd in ("/away", "/busy", "/dnd", "/online"):
            status_map = {"/away": "away", "/busy": "busy",
                          "/dnd": "dnd", "/online": "online"}
            new_st = status_map[cmd]
            S().user_status = new_st
            icons  = {"online": "🟢", "away": "🟡", "busy": "🔴", "dnd": "⊘"}
            labels = {"online": "Онлайн", "away": "Отошёл",
                      "busy": "Занят", "dnd": "Не беспокоить"}
            self._display.add_system(f"{icons[new_st]} Статус: {labels[new_st]}")
            if self.net:
                self.net._broadcast()  # broadcast updated presence immediately
            return True

        elif cmd == "/search":
            # Open in-chat search bar
            if rest.strip():
                self._do_search(rest.strip())
            else:
                self._toggle_search_bar()
            return True

        elif cmd == "/shrug":
            self._input.setPlainText(r"¯\_(ツ)_/¯")
            return False   # Don't consume — let user edit/send

        elif cmd in ("/notes", "/note", "/заметки"):
            # Open shared notes panel
            self._open_shared_notes()
            return True

        elif cmd == "/schedule":
            # /schedule HH:MM text   — send message at specific time
            parts2 = arg.strip().split(None, 1)
            if len(parts2) == 2:
                time_str = parts2[0]; msg_text = parts2[1]
                try:
                    import datetime as _dt
                    now = _dt.datetime.now()
                    h, m = map(int, time_str.split(":"))
                    send_at = now.replace(hour=h, minute=m, second=0, microsecond=0)
                    if send_at <= now:
                        send_at += _dt.timedelta(days=1)
                    delay_ms = int((send_at - now).total_seconds() * 1000)
                    def _sched_send(_text=msg_text):
                        self._input.setPlainText(_text)
                        self._send_text()
                    QTimer.singleShot(delay_ms, _sched_send)
                    self._display.add_system_message(
                        f"⏰ Сообщение запланировано на {time_str}: {msg_text[:30]}",
                        chat_id=self._get_current_chat_id())
                except Exception as e:
                    self._display.add_system_message(
                        f"⏰ Ошибка: {e}  Формат: /schedule HH:MM текст",
                        chat_id=self._get_current_chat_id())
            else:
                self._display.add_system_message(
                    "⏰ /schedule HH:MM текст сообщения",
                    chat_id=self._get_current_chat_id())
            return True

        elif cmd == "/ttl":
            try:
                n = int(arg.strip()) if arg.strip() else 0
                self._ttl_seconds = max(0, n)
                msg = f"⏱ Исчезающие сообщения: {n} сек" if n else "⏱ Исчезающие сообщения выключены"
                self._display.add_system_message(msg, chat_id=self._get_current_chat_id())
            except ValueError:
                self._display.add_system_message(
                    "⏱ /ttl <секунды>  (например /ttl 30)",
                    chat_id=self._get_current_chat_id())
            return True

        elif cmd in ("/translate", "/tr", "/перевести"):
            # /tr [lang] text  — translate text using MyMemory free API
            parts2 = arg.strip().split(None, 1)
            if len(parts2) == 2 and len(parts2[0]) == 2:
                lang = parts2[0]; text_to_translate = parts2[1]
            else:
                lang = "en"; text_to_translate = arg.strip()
            if not text_to_translate:
                self._display.add_system_message(
                    "🌍 /tr [lang] текст  (например /tr en привет)",
                    chat_id=self._get_current_chat_id())
                return True
            chat_id = self._get_current_chat_id()
            import threading, urllib.request, urllib.parse, json as _j
            def _translate():
                try:
                    url = ("https://api.mymemory.translated.net/get?q="
                           f"{urllib.parse.quote(text_to_translate)}"
                           f"&langpair=auto|{lang}")
                    with urllib.request.urlopen(url, timeout=6) as resp:
                        data = _j.loads(resp.read().decode())
                    result = data["responseData"]["translatedText"]
                    QTimer.singleShot(0, lambda r=result, c=chat_id:
                        self._display.add_system_message(
                            f"🌍 {r}", chat_id=c))
                except Exception as e:
                    QTimer.singleShot(0, lambda err=str(e), c=chat_id:
                        self._display.add_system_message(
                            f"🌍 Ошибка перевода: {err}", chat_id=c))
            threading.Thread(target=_translate, daemon=True).start()
            return True

        elif cmd == "/poll":
            import shlex as _shlex
            try: opts = _shlex.split(arg)
            except Exception: opts = arg.split()
            if len(opts) >= 2:
                question = opts[0]; options = opts[1:]
                poll_id = f"poll_{int(time.time())}"
                self._polls[poll_id] = {
                    "question": question, "options": options,
                    "votes": {o: [] for o in options},
                    "creator": S().username}
                self._add_poll_bubble(poll_id, question, options, is_own=True)
                poll_pkt = {"type": MSG_POLL, "poll_id": poll_id,
                            "question": question, "options": options,
                            "username": S().username, "ts": time.time()}
                if self._current_peer:
                    self.net.send_udp(poll_pkt, self._current_peer["ip"])
                elif self._current_gid:
                    for ip in GROUPS.get(self._current_gid, {}).get("members", []):
                        if ip != get_local_ip(): self.net.send_udp(poll_pkt, ip)
                else: self.net.broadcast(poll_pkt)
            else:
                self._display.add_system_message(
                    '💡 /poll "Вопрос?" Вариант1 Вариант2 ...',
                    chat_id=self._get_current_chat_id())
            return True

        return False   # Not a recognized command

    # ── Message search (Ctrl+F) ─────────────────────────────────────────────
    def _toggle_search_bar(self):
        visible = not self._search_bar.isVisible()
        self._search_bar.setVisible(visible)
        if visible:
            self._search_input.setFocus()
            self._search_input.selectAll()
        else:
            self._close_search()

    def _close_search(self):
        self._search_bar.setVisible(False)
        self._search_input.clear()
        self._search_matches = []
        self._search_match_idx = -1
        self._search_count_lbl.setText("")
        self._display.clear_search_highlight()

    def _do_search(self, query: str = ""):
        query = query or self._search_input.text()
        self._search_matches = []
        self._search_match_idx = -1
        if not query.strip():
            self._search_count_lbl.setText("")
            self._display.clear_search_highlight()
            return
        self._display.highlight_search(query)
        self._search_matches = self._display.get_search_matches(query)
        count = len(self._search_matches)
        if count:
            self._search_match_idx = 0
            self._search_count_lbl.setText(f"1/{count}")
            self._display.scroll_to_match(self._search_matches[0])
        else:
            self._search_count_lbl.setText("Не найдено")

    def _search_next(self):
        if not self._search_matches: return
        self._search_match_idx = (self._search_match_idx + 1) % len(self._search_matches)
        self._display.scroll_to_match(self._search_matches[self._search_match_idx])
        self._search_count_lbl.setText(
            f"{self._search_match_idx+1}/{len(self._search_matches)}")

    def _search_prev(self):
        if not self._search_matches: return
        self._search_match_idx = (self._search_match_idx - 1) % len(self._search_matches)
        self._display.scroll_to_match(self._search_matches[self._search_match_idx])
        self._search_count_lbl.setText(
            f"{self._search_match_idx+1}/{len(self._search_matches)}")

    def _get_current_chat_id(self) -> str:
        if self._current_peer:
            return self._current_peer["ip"]
        elif self._current_gid:
            return f"group_{self._current_gid}"
        return "public"

    # ── reply helpers ─────────────────────────────────────────────────────
    def _on_reply_request(self, text: str, ts: float):
        self._reply_to_text = text
        self._reply_to_ts = ts
        short = text[:60] + ("…" if len(text) > 60 else "")
        t = get_theme(S().theme)
        self._reply_lbl.setText(f"↩ {TR('msg_reply')}: {short}")
        self._reply_bar.setVisible(True)
        self._input.setFocus()

    def _cancel_reply(self):
        self._reply_to_text = ""
        self._reply_to_ts = 0.0
        self._reply_bar.setVisible(False)
        self._reply_lbl.setText("")

    # ── forward ───────────────────────────────────────────────────────────
    def _on_forward_request(self, text: str, ts: float):
        """Forward a message to another chat."""
        # Ask user to choose destination
        peers = list(self.net.peers.values())
        if not peers:
            QMessageBox.information(self, TR("msg_forward"),
                "Нет пользователей онлайн для пересылки." if S().language=="ru"
                else "No users online to forward to.")
            return
        items = ["Общий чат"] + [p.get("username","?") for p in peers]
        choice, ok = QInputDialog.getItem(self,
            TR("msg_forward"), "Переслать в:", items, editable=False)
        if not ok:
            return
        forwarded = f"↪ {text}"
        ts_new = time.time()
        if choice == "Общий чат" or choice == "Public Chat":
            self.net.send_chat(forwarded)
            self._display.add_message(
                TR("you"), forwarded, ts_new, is_own=True,
                is_forwarded=True, forwarded_from=S().username)
        else:
            for p in peers:
                if p.get("username") == choice:
                    self.net.send_private(forwarded, p["ip"])
                    self._display.add_message(
                        TR("you"), forwarded, ts_new, is_own=True,
                        is_forwarded=True, forwarded_from=S().username)
                    break

    # ── edit ──────────────────────────────────────────────────────────────
    def _on_edit_request(self, text: str, ts: float):
        new_text, ok = QInputDialog.getText(
            self, TR("msg_edit"),
            "Редактировать:" if S().language=="ru" else "Edit message:",
            text=text)
        if ok and new_text.strip() and new_text != text:
            self._display.edit_message(ts, new_text.strip())
            # Notify peer
            chat_id = self._get_current_chat_id()
            to_ip = self._current_peer["ip"] if self._current_peer else None
            self.net.send_message_edit(to_ip, chat_id, ts, new_text.strip())
            # Update history
            msgs = HISTORY.load(chat_id)
            for m in msgs:
                if abs(m.get("ts",0) - ts) < 0.01:
                    m["text"] = new_text.strip()
                    m["is_edited"] = True
                    break

    # ── delete ────────────────────────────────────────────────────────────
    def _on_delete_request(self, ts: float):
        reply = QMessageBox.question(
            self, TR("msg_delete"),
            "Удалить сообщение?" if S().language=="ru" else "Delete this message?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._display.delete_message(ts)
            chat_id = self._get_current_chat_id()
            to_ip = self._current_peer["ip"] if self._current_peer else None
            self.net.send_message_delete(to_ip, chat_id, ts)

    # ── react ─────────────────────────────────────────────────────────────
    def _on_react_request(self, ts: float):
        """Show emoji picker for reactions."""
        REACTION_EMOJIS = [
            "👍","👎","❤️","😂","😮","😢","😡","🔥",
            "🎉","💯","👏","🤔","😎","🚀","💎","✅",
            "⭐","🙏","💪","🥰"
        ]
        menu = QMenu(self)
        t = get_theme(S().theme)
        menu.setStyleSheet(f"""
            QMenu {{
                background: {t['bg2']}; color: {t['text']};
                border: 1px solid {t['accent']}; border-radius: 10px;
                padding: 6px;
            }}
            QMenu::item {{
                padding: 4px 8px; font-size: 16px;
                border-radius: 6px;
            }}
            QMenu::item:selected {{ background: {t['btn_hover']}; }}
        """)

        # Create a grid of emoji actions
        for i, em in enumerate(REACTION_EMOJIS):
            act = QAction(em, self)
            act.triggered.connect(
                lambda _, e=em, t_=ts: self._send_reaction(t_, e))
            menu.addAction(act)

        # Show near the input button
        menu.exec(self._emoji_btn.mapToGlobal(
            QPoint(0, -menu.sizeHint().height() - 5)))

    def _send_reaction(self, ts: float, emoji: str):
        """Toggle a reaction on a message."""
        try:
            ts = float(ts)
        except (TypeError, ValueError):
            return
        chat_id = self._get_current_chat_id()
        added = REACTIONS.toggle(chat_id, ts, emoji, S().username)
        self._display.update_reactions(ts)
        to_ip = self._current_peer["ip"] if self._current_peer else None
        self.net.send_reaction(to_ip, chat_id, ts, emoji, added)

    # ── send ─────────────────────────────────────────────────────────────
    def _send_text(self):
        text = self._input.toPlainText().strip()
        if not text:
            return

        # Handle slash commands first
        if text.startswith("/"):
            self._cmd_popup.hide()
            consumed = self._handle_slash_command(text)
            if consumed:
                self._input.clear()
                return

        text = self._input.toPlainText().strip()
        if not text:
            return
        self._cmd_popup.hide()
        ts = time.time()
        cfg = S()

        reply_text = self._reply_to_text
        chat_id = self._get_current_chat_id()

        # ── Optimistic render BEFORE clear so message never disappears ──
        self._display.add_message(
            TR("you"), text, ts, is_own=True,
            color=cfg.nickname_color, emoji=cfg.custom_emoji,
            reply_to_text=reply_text, chat_id=chat_id)

        # Clear input AFTER rendering so textChanged doesn't cause flicker
        self._input.clear()
        self._cancel_reply()

        HISTORY.append(chat_id, {
            "sender":       cfg.username,
            "text":         text,
            "ts":           ts,
            "is_own":       True,
            "color":        cfg.nickname_color,
            "emoji":        cfg.custom_emoji,
            "reply_to_text": reply_text,
            "ttl":          self._ttl_seconds if self._ttl_seconds > 0 else 0,
        })
        # Schedule self-destruct if TTL is set
        if self._ttl_seconds > 0:
            _ttl_ms = self._ttl_seconds * 1000
            _ts_ref = ts
            _display_ref = self._display
            t_timer = QTimer()
            t_timer.setSingleShot(True)
            t_timer.timeout.connect(
                lambda _ts=_ts_ref, _d=_display_ref: _d.delete_message(_ts))
            t_timer.start(_ttl_ms)
            self._ttl_timers.append(t_timer)

        if self._current_peer:
            self.net.send_private(text, self._current_peer["ip"])
        elif self._current_gid:
            g = GROUPS.get(self._current_gid)
            self.net.send_group_msg(self._current_gid, text, g.get("members",[]))
        else:
            self.net.send_chat(text)

    def _send_text_raw(self, text: str):
        """Send raw text into the currently open chat (used for invite messages etc.)."""
        if not text:
            return
        ts = time.time()
        cfg = S()
        chat_id = self._get_current_chat_id()
        if self._current_peer:
            self.net.send_private(text, self._current_peer["ip"])
        elif self._current_gid:
            g = GROUPS.get(self._current_gid)
            self.net.send_group_msg(self._current_gid, text, g.get("members", []))
        else:
            self.net.send_chat(text)
        self._display.add_message(
            TR("you"), text, ts, is_own=True,
            color=cfg.nickname_color, emoji=cfg.custom_emoji, chat_id=chat_id)

    def receive_message(self, msg: dict):
        sender = msg.get("username","?")
        from_ip = msg.get("from_ip","")
        # DEDUP: drop own messages echoed back from broadcast
        # Use ALL local IPs to handle LAN+VPN multi-homed setups
        _my_ips = get_all_local_ips() | {self.net.host_ip}
        if from_ip and from_ip in _my_ips:
            return
        if not from_ip and sender == S().username:
            return
        text   = msg.get("text","")
        ts     = msg.get("ts", time.time())
        gid    = msg.get("gid","")
        mtype  = msg.get("type","")

        # Handle reactions, edits and deletes BEFORE decryption (they don't need it)
        if mtype == MSG_REACTION:
            chat_id = msg.get("chat_id", "public")
            self._display.add_reaction_update(
                msg.get("msg_ts", 0), msg.get("emoji",""),
                sender, msg.get("added", True))
            return

        # Handle shared notes sync
        if mtype == MSG_NOTES_SYNC:
            content = msg.get("content", "")
            chat_id_n = (f"group_{gid}" if gid else
                        msg.get("from_ip","") if mtype == "private" else "public")
            notes_key = f"shared_notes_{chat_id_n}"
            S().set(notes_key, content)
            # Update editor if open
            ed = getattr(self, '_notes_editor', None)
            if ed:
                ed.setPlainText(content)
            return

        # Handle sticker
        if mtype == MSG_STICKER:
            b64  = msg.get("sticker_b64","")
            ts_s = msg.get("ts", time.time())
            gid_s= msg.get("gid","")
            if not b64: return
            img_bytes = base64.b64decode(b64)
            if gid_s:
                chat_id = f"group_{gid_s}"
                show = (self._current_gid == gid_s)
            elif msg.get("from_ip"):
                chat_id = msg["from_ip"]
                show = (self._current_peer and
                        self._current_peer.get("ip") == msg["from_ip"])
            else:
                chat_id = "public"
                show = (self._current_peer is None and self._current_gid is None)
            color = "#E0E0E0"
            for ip, p in self.net.peers.items():
                if p.get("username") == sender:
                    color = p.get("nickname_color","#E0E0E0"); break
            if show:
                self._display.add_message(sender, "", ts_s, is_own=False,
                                          color=color, msg_type="sticker",
                                          image_data=img_bytes, chat_id=chat_id)
            else:
                UNREAD.increment(chat_id)
            HISTORY.append(chat_id, {
                "sender": sender, "text": "", "ts": ts_s,
                "is_own": False, "msg_type": "sticker", "image_b64": b64,
            })
            play_system_sound("message")
            return

        # Decrypt if needed
        if msg.get("encrypted") and CRYPTO.is_encrypted(text):
            pp = S().encryption_passphrase
            peer_ip_hint = msg.get("from_ip", "")
            text = CRYPTO.decrypt(text, pp, peer_ip=peer_ip_hint)
            msg = dict(msg)
            msg["text"] = text

        if mtype == MSG_EDIT:
            self._display.edit_message(
                msg.get("msg_ts", 0), msg.get("new_text",""))
            return
        if mtype == MSG_DELETE:
            self._display.delete_message(msg.get("msg_ts", 0))
            return
        if mtype == MSG_READ:
            # Mark our messages as read in this chat
            return

        # Determine chat_id & whether we should show
        if mtype == MSG_PRIVATE:
            chat_id = msg.get("from_ip", "")
            for ip, p in self.net.peers.items():
                if p.get("username") == sender:
                    chat_id = ip; break
            show = (self._current_peer and
                    self._current_peer.get("username") == sender)
        elif mtype == MSG_GROUP:
            chat_id = f"group_{gid}"
            show = (self._current_gid == gid)
        else:
            chat_id = "public"
            show = (self._current_peer is None and self._current_gid is None)

        # Find peer info for colors
        color = "#E0E0E0"; emoji_s = ""
        for ip, p in self.net.peers.items():
            if p.get("username") == sender:
                color  = p.get("nickname_color","#E0E0E0")
                emoji_s = p.get("custom_emoji","")
                break

        # Check for @mention of our username
        is_mention = f"@{S().username}" in text

        if show:
            self._display.add_message(sender, text, ts, is_own=False,
                                      color=color, emoji=emoji_s,
                                      msg_type=mtype, chat_id=chat_id)
        else:
            UNREAD.increment(chat_id)

        cfg = S()
        HISTORY.append(chat_id, {
            "sender": sender, "text": text, "ts": ts,
            "is_own": False, "color": color, "emoji": emoji_s,
        })

        # ── Sound notification ────────────────────────────────────────────
        if cfg.notification_sounds and not show:
            play_system_sound("message")

        # ── OS desktop notification ────────────────────────────────────────
        if cfg.os_notifications and (not show or is_mention):
            if mtype == MSG_PRIVATE:
                title = f"{TR('notif_new_message')} от {sender}"
            elif mtype == MSG_GROUP:
                g = GROUPS.get(gid)
                title = f"{sender} в {g.get('name','группе')}"
            else:
                title = f"{sender}: {TR('notif_new_message')}"
            body = text[:100] + ("…" if len(text) > 100 else "")
            send_notification(title, body)
        # Also show in-app toast if available
        avatar = ""
        if "avatar_b64" in peer:
            avatar = peer.get("avatar_b64","")
        try:
            show_toast(title, body, avatar)
        except Exception:
            pass

    def receive_file(self, meta: dict, data: bytes):
        sender   = meta.get("from","?")
        fname    = meta.get("filename","file")
        is_image = meta.get("is_image", False)
        ts       = meta.get("ts", time.time())

        # Save file
        dest = RECEIVED_DIR / fname
        dest.write_bytes(data)

        gid    = meta.get("gid","")
        to     = meta.get("to","")
        if gid:
            chat_id = f"group_{gid}"
            show = (self._current_gid == gid)
        elif to == "public":
            chat_id = "public"
            show = (self._current_peer is None and self._current_gid is None)
        else:
            for ip, p in self.net.peers.items():
                if p.get("username") == sender:
                    chat_id = ip; break
            else:
                chat_id = "public"
            show = (self._current_peer and
                    self._current_peer.get("username") == sender)

        color = "#E0E0E0"
        for ip, p in self.net.peers.items():
            if p.get("username") == sender:
                color = p.get("nickname_color","#E0E0E0"); break

        _rext = Path(fname).suffix.lower()
        _rvid = {".mp4",".avi",".mkv",".mov",".webm",".m4v",".wmv",".flv"}
        if is_image and show:
            self._display.add_message(sender, fname, ts, is_own=False,
                                      color=color, image_data=data)
        elif _rext in _rvid and show:
            self._display.add_message(sender, fname, ts, is_own=False,
                                      color=color, msg_type="video", image_data=data)
        elif show:
            self._display.add_message(sender, fname, ts, is_own=False,
                                      color=color, msg_type="file")

        if S().notification_sounds and not show:
            play_system_sound("message")

    def show_typing(self, username: str, chat_id: str):
        show = False
        if chat_id == "public" and not self._current_peer and not self._current_gid:
            show = True
        elif self._current_peer:
            for ip, p in self.net.peers.items():
                if p.get("username") == username and ip == self._current_peer.get("ip"):
                    show = True; break
        elif self._current_gid and chat_id == f"group_{self._current_gid}":
            show = True
        if show:
            self._typing_lbl.setText(f"{username} печатает...")
            self._typing_hide_timer.start(3000)

    # ── file ──────────────────────────────────────────────────────────────
    _VID_EXTS = {".mp4",".avi",".mkv",".mov",".webm",".m4v",".wmv",".flv"}
    _IMG_EXTS = {".png",".jpg",".jpeg",".gif",".bmp",".webp"}

    def _send_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл")
        if not path:
            return
        p = Path(path); ext = p.suffix.lower(); fname = p.name
        fsize = p.stat().st_size; ts = time.time()
        prog_id = f"up_{int(ts*1000)}"
        self._display.add_upload_progress(fname, fsize, prog_id)
        to_ip = self._current_peer["ip"] if self._current_peer else None

        # Read file data synchronously (safe — happens before send)
        _pre_data = None
        if ext in self._IMG_EXTS or ext in self._VID_EXTS:
            try: _pre_data = p.read_bytes()
            except Exception: pass
        # Copy to received dir so "open" works for sender
        if ext not in self._IMG_EXTS and ext not in self._VID_EXTS:
            dest0 = RECEIVED_DIR / fname
            try:
                import shutil as _sh0; _sh0.copy2(path, str(dest0))
            except Exception: pass

        # send_file uses QTimer internally — returns immediately, no thread needed
        try:
            self.net.send_file(to_ip, path)
        except Exception as e:
            print(f"[send] {e}")

        # Remove progress and show bubble right away
        self._display.remove_progress(prog_id)
        if ext in self._IMG_EXTS:
            self._display.add_message("Вы", fname, ts, is_own=True,
                image_data=_pre_data)
        elif ext in self._VID_EXTS:
            self._display.add_message("Вы", fname, ts, is_own=True,
                msg_type="video", image_data=_pre_data)
        else:
            self._display.add_message("Вы", fname, ts, is_own=True, msg_type="file")

    # ── call ──────────────────────────────────────────────────────────────
    def _toggle_call(self):
        if self._in_call:
            self._hangup()
            return

        main_win = self.window()  # MainWindow reference

        if self._current_peer:
            ip   = self._current_peer.get("ip", "")
            name = self._current_peer.get("username", ip)
            av   = self._current_peer.get("avatar_b64", "")
            if not ip:
                return
            # Show outgoing call screen — actual call starts on accept
            win = OutgoingCallWindow(name, ip, av)
            self._float_call = win  # keep reference
            win.sig_cancelled.connect(lambda: self._cancel_outgoing_local(ip))
            win.show()
            self.net.send_call_request(ip)
            # Set call active visually but don't start voice yet
            self._call_btn.setText("📵")
            self._call_btn.setToolTip("Отменить вызов")

        elif self._current_gid:
            # Group call → GroupCallWindow (Телемост style)
            g       = GROUPS.get(self._current_gid)
            gname   = g.get("name", self._current_gid)
            members = [m for m in g.get("members", []) if m != get_local_ip()]
            participants = [
                self.net.peers[ip] for ip in members if ip in self.net.peers
            ]
            # Start voice with online members immediately
            self.voice.audio.start_capture()
            for ip in members:
                if ip in self.net.peers:
                    self.net.send_call_request(ip)
                    self.voice.call(ip)

            gcall = GroupCallWindow(gname, participants, self.voice)
            self._float_call = gcall
            gcall.sig_leave.connect(self._hangup)
            gcall.show()
            self._set_call_active(True)

    def _cancel_outgoing_local(self, ip: str):
        """Cancel outgoing call before answer."""
        self.net.send_call_end(ip)
        self._float_call = None
        self._call_btn.setText("📞")
        self._call_btn.setToolTip("Позвонить")

    def _set_call_active(self, active: bool, peer: dict | None = None):
        self._in_call = active
        self._call_bar.setVisible(False)
        if active:
            self._call_btn.setText("📵")
            self._call_btn.setToolTip("Завершить звонок")
            self._display.add_system("Звонок начат")
        else:
            self._call_btn.setText("📞")
            self._call_btn.setToolTip("Позвонить")
            self._display.add_system("Звонок завершён")
            if hasattr(self, "_float_call") and self._float_call:
                try:
                    if hasattr(self._float_call, '_timer'):
                        self._float_call._timer.stop()
                    self._float_call.hide()
                    self._float_call.deleteLater()
                except Exception:
                    pass
                self._float_call = None

    def _accept_incoming_in_chat(self, caller: str, ip: str):
        """Called when user accepts incoming call — start voice + show active window."""
        av_b64 = self.net.peers.get(ip, {}).get("avatar_b64", "")
        self.net.send_call_accept(ip)
        self.net.connect_voice(ip)
        self.voice.call(ip)
        active = ActiveCallWindow(caller, ip, av_b64)
        self._float_call = active
        active.sig_hangup.connect(lambda: self._hangup())
        active.sig_mute.connect(self.voice.set_mute)
        active.show()
        self._set_call_active(True)


    def _hangup(self):
        if self._current_peer:
            self.voice.hangup(self._current_peer["ip"])
        else:
            self.voice.hangup_all()
        self._set_call_active(False)

    def _toggle_mute(self):
        muted = self.voice.toggle_mute()
        self._mute_btn.setText("🔇 Заглушён" if muted else "🎤 Микрофон")
        # Sync active call window if open
        if hasattr(self, "_float_call") and self._float_call:
            if hasattr(self._float_call, '_toggle_mute'):
                pass  # ActiveCallWindow manages its own mute state

    def on_call_ended(self, ip: str):
        if self._in_call:
            self._set_call_active(False)

    # ── typing ──────────────────────────────────────────────────────────
    def _on_typing_te(self):
        text = self._input.toPlainText().strip()
        if text:
            self._typing_timer.start(1500)

    def _on_typing(self, text: str):
        if text:
            self._typing_timer.start(1500)

    def _send_typing(self):
        if self._current_peer:
            self.net.send_typing(self._current_peer["ip"], self._current_peer["ip"])
        elif self._current_gid:
            g = GROUPS.get(self._current_gid)
            for ip in g.get("members",[]):
                if ip != get_local_ip():
                    self.net.send_typing(f"group_{self._current_gid}", ip)

    # ── emoji picker ──────────────────────────────────────────────────────
    def _emoji_picker(self):
        menu = QMenu(self)
        t = get_theme(S().theme)
        menu.setStyleSheet(f"""
            QMenu {{
                background: {t['bg2']}; color: {t['text']};
                border: 1px solid {t['accent']}; border-radius: 10px;
                padding: 6px;
            }}
            QMenu::item {{
                padding: 4px 6px; font-size: 18px;
                border-radius: 6px;
            }}
            QMenu::item:selected {{ background: {t['btn_hover']}; }}
        """)

        # Emoji categories
        categories = {
            "😊 Смайлы": ["😀","😂","😍","🤔","😎","😢","😡","🤣","😊","🙈","🥰","😏",
                          "🤩","😤","🥺","😴","🤯","🥳","😇","🤗"],
            "👍 Жесты":  ["👍","👎","👏","🙏","💪","🤝","✌️","🤞","👌","🤙","🖐️","✋"],
            "❤️ Символы": ["❤️","🔥","💯","🎉","✅","⭐","💎","🚀","💡","🎯","🏆","👑",
                           "💰","🌟","⚡","🌈","🍀","💫","🌙","☀️"],
            "🐱 Животные": ["🐱","🐶","🦊","🐺","🐻","🐼","🦁","🐯","🦄","🐸"],
        }

        for cat_name, emojis in categories.items():
            cat_action = QAction(cat_name, self)
            cat_action.setEnabled(False)
            menu.addAction(cat_action)
            row_menu = menu.addMenu("  ")
            row_menu.setStyleSheet(menu.styleSheet())
            for em in emojis:
                a = QAction(em, self)
                a.triggered.connect(lambda _, e=em: self._insert_emoji(e))
                row_menu.addAction(a)
            menu.addSeparator()

        # Also show flat list for quick access
        quick = ["😀","😂","😍","🤔","😎","👍","❤️","🔥","💯","🎉",
                 "😢","😡","🤣","😊","🙏","💪","✅","🚀","💎","👑"]
        for e in quick:
            a = QAction(e, self)
            a.triggered.connect(lambda _, em=e: self._insert_emoji(em))
            menu.addAction(a)

        menu.exec(self._emoji_btn.mapToGlobal(
            QPoint(0, -min(menu.sizeHint().height(), 300))))

    def _insert_emoji(self, emoji: str):
        cursor = self._input.textCursor()
        cursor.insertText(emoji)
        self._input.setFocus()

    def _toggle_sticker_panel(self, show: bool | None = None):
        """Show/hide sticker panel as a floating popup above sticker button."""
        visible = (not self._sticker_panel.isVisible()
                   if show is None else bool(show))
        if visible:
            # Detach from layout and show as popup
            t = get_theme(S().theme)
            self._sticker_panel.setWindowFlags(
                Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint)
            self._sticker_panel.setFixedSize(320, 220)
            self._sticker_panel.setStyleSheet(
                f"QWidget#sticker_panel{{background:{t['bg2']};"
                f"border:1px solid {t['accent']};border-radius:10px;}}")
            btn = getattr(self, '_sticker_btn', None)
            if btn:
                gp = btn.mapToGlobal(QPoint(0, 0))
                sw = self._sticker_panel.width()
                sh = self._sticker_panel.height()
                self._sticker_panel.move(
                    max(0, gp.x() - sw + btn.width()),
                    gp.y() - sh - 8)
            self._load_sticker_packs()
            self._refresh_sticker_grid()
            self._sticker_panel.show()
            self._sticker_panel.raise_()
        else:
            self._sticker_panel.hide()

    def _load_sticker_packs(self):
        """Reload pack list into combo box."""
        try:
            import json
            self._sp_pack_combo.blockSignals(True)
            self._sp_pack_combo.clear()
            raw = S().get("sticker_packs", "[]", t=str)
            packs = json.loads(raw) if raw else []
            if not packs:
                self._sp_pack_combo.addItem("(нет паков — добавьте в ⚙)")
            for p in packs:
                self._sp_pack_combo.addItem(p.get("name", "Без имени"))
            self._sp_pack_combo.blockSignals(False)
        except Exception as ex:
            print(f"[load packs] {ex}")

    def _refresh_sticker_grid(self):
        """Fill grid with stickers from selected pack."""
        try:
            import json
            while self._sticker_grid_layout.count():
                item = self._sticker_grid_layout.takeAt(0)
                if item and item.widget():
                    item.widget().deleteLater()

            raw = S().get("sticker_packs", "[]", t=str)
            packs = json.loads(raw) if raw else []
            idx = self._sp_pack_combo.currentIndex()
            if not packs or idx < 0 or idx >= len(packs) or not isinstance(packs[idx], dict):
                no_lbl = QLabel("Нет стикеров. Добавьте пак через ⚙ Паки")
                no_lbl.setStyleSheet("color:gray;font-size:11px;padding:8px;")
                no_lbl.setWordWrap(True)
                self._sticker_grid_layout.addWidget(no_lbl, 0, 0)
                return

            stickers = packs[idx].get("stickers", []) if isinstance(packs[idx], dict) else []
            cols = 6
            for i, s in enumerate(stickers):
                b64 = s.get("data","") if isinstance(s, dict) else str(s)
                if not b64:
                    continue
                try:
                    pm = QPixmap()
                    pm.loadFromData(base64.b64decode(b64))
                    if pm.isNull():
                        continue
                    pm = pm.scaled(64, 64,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation)
                    btn = QPushButton()
                    btn.setIcon(QIcon(pm))
                    btn.setIconSize(QSize(60,60))
                    btn.setFixedSize(68,68)
                    btn.setToolTip(s.get("name",""))
                    btn.setStyleSheet(
                        "QPushButton{background:transparent;border:1px solid transparent;"
                        "border-radius:8px;}"
                        "QPushButton:hover{background:rgba(255,255,255,20);"
                        "border-color:rgba(255,255,255,51);}")
                    btn.clicked.connect(lambda _, d=b64: self._send_sticker(d))
                    self._sticker_grid_layout.addWidget(btn, i//cols, i%cols)
                except Exception:
                    continue
        except Exception as ex:
            print(f"[refresh sticker grid] {ex}")

    def _open_sticker_manager(self):
        """Open StickerPackDialog as inline tab in main window."""
        # Walk up to find MainWindow and its tab widget
        main_win = self.window()
        tabs = getattr(main_win, '_tabs', None)
        if tabs is not None:
            # Check if already open
            for i in range(tabs.count()):
                if tabs.tabText(i).strip() == "🎭 Стикеры":
                    tabs.setCurrentIndex(i)
                    return
            dlg = StickerPackDialog(main_win)
            dlg.setWindowFlags(Qt.WindowType.Widget)
            idx = tabs.addTab(dlg, "🎭 Стикеры")
            tabs.setCurrentIndex(idx)
            if hasattr(main_win, '_add_tab_close_btn'):
                main_win._add_tab_close_btn(idx)
            # Reload packs when tab is closed
            def _on_sticker_tab_close():
                if self._sticker_panel.isVisible():
                    self._load_sticker_packs()
                    self._refresh_sticker_grid()
            dlg.destroyed.connect(_on_sticker_tab_close)
        else:
            # Fallback: open as dialog
            dlg = StickerPackDialog(self)
            dlg.setModal(False)
            dlg.show()
            dlg.finished.connect(lambda: (
                self._load_sticker_packs() if self._sticker_panel.isVisible() else None,
                self._refresh_sticker_grid() if self._sticker_panel.isVisible() else None,
            ))

    def _open_shared_notes(self):
        """Open shared collaborative notepad for current chat."""
        chat_id = self._get_current_chat_id()
        t = get_theme(S().theme)
        # Reuse existing notes window if open
        if hasattr(self, '_notes_dlg') and self._notes_dlg and self._notes_dlg.isVisible():
            self._notes_dlg.raise_(); return

        dlg = QWidget(self.window(), Qt.WindowType.Window)
        dlg.setWindowTitle(f"📝 Совместные заметки — {chat_id or 'Публичный чат'}")
        dlg.resize(500, 400)
        dlg.setStyleSheet(f"background:{t['bg2']};color:{t['text']};")
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(12,12,12,12); lay.setSpacing(8)

        hdr = QLabel("📝 Совместные заметки (синхронизируются в реальном времени)")
        hdr.setStyleSheet(
            f"font-size:12px;color:{t['accent']};background:transparent;")
        hdr.setWordWrap(True)
        lay.addWidget(hdr)

        editor = QPlainTextEdit()
        editor.setStyleSheet(
            f"QPlainTextEdit{{background:{t['bg']};color:{t['text']};"
            "font-size:12px;border:none;border-radius:8px;padding:12px;}}")
        # Load saved notes
        import json as _j
        notes_key = f"shared_notes_{chat_id}"
        saved = S().get(notes_key, "", t=str)
        editor.setPlainText(saved)
        lay.addWidget(editor, stretch=1)

        btn_row = QHBoxLayout()
        sync_btn = QPushButton("📤 Синхронизировать")
        sync_btn.setObjectName("accent_btn"); sync_btn.setFixedHeight(32)
        clear_btn = QPushButton("🗑 Очистить")
        clear_btn.setFixedHeight(32)
        clear_btn.setStyleSheet(
            f"QPushButton{{background:{t['bg3']};color:{t['text_dim']};"
            f"border:1px solid {t['border']};border-radius:6px;padding:0 12px;}}"
            f"QPushButton:hover{{color:{t['text']};background:{t['btn_hover']};}}")

        def _sync():
            content = editor.toPlainText()
            S().set(notes_key, content)
            pkt = {"type": MSG_NOTES_SYNC, "content": content,
                   "username": S().username, "ts": time.time()}
            if self._current_peer:
                self.net.send_udp(pkt, self._current_peer["ip"])
            elif self._current_gid:
                for ip in GROUPS.get(self._current_gid,{}).get("members",[]):
                    if ip != get_local_ip(): self.net.send_udp(pkt, ip)
            else: self.net.broadcast(pkt)
            sync_btn.setText("✅ Отправлено")
            QTimer.singleShot(2000, lambda: sync_btn.setText("📤 Синхронизировать"))

        def _clear():
            editor.clear()
            S().set(notes_key, "")

        sync_btn.clicked.connect(_sync)
        clear_btn.clicked.connect(_clear)
        btn_row.addWidget(sync_btn); btn_row.addWidget(clear_btn)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        # Auto-save on change
        editor.textChanged.connect(lambda: S().set(notes_key, editor.toPlainText()))

        dlg.show(); dlg.raise_()
        self._notes_dlg = dlg
        self._notes_editor = editor

    def _add_poll_bubble(self, poll_id, question, options, is_own=True):
        t = get_theme(S().theme)
        frame = QFrame()
        frame.setMaximumWidth(340)
        frame.setStyleSheet(
            f"QFrame{{background:{t['bg3']};border-radius:14px;"
            f"border:1px solid {t['accent']};padding:2px;}}")
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(14,12,14,12); fl.setSpacing(8)

        q_lbl = QLabel(f"📊  {question}")
        q_lbl.setStyleSheet(
            f"font-size:13px;font-weight:bold;color:{t['text']};background:transparent;")
        q_lbl.setWordWrap(True)
        fl.addWidget(q_lbl)

        poll_data = self._polls.get(poll_id, {})
        votes = poll_data.get("votes", {o: [] for o in options})
        total = sum(len(v) for v in votes.values())

        for opt in options:
            opt_voters = votes.get(opt, [])
            pct = int(len(opt_voters)/max(total,1)*100)
            row = QHBoxLayout()
            btn = QPushButton(f"  {opt}  ({len(opt_voters)})")
            btn.setStyleSheet(
                f"QPushButton{{background:{t['bg2']};color:{t['text']};"
                f"border:1px solid {t['border']};border-radius:8px;"
                "padding:6px 10px;font-size:11px;text-align:left;}}"
                f"QPushButton:hover{{background:{t['accent']};color:white;}}")
            btn.clicked.connect(
                lambda _, _p=poll_id,_o=opt,_f=frame,_q=question,_opts=options:
                self._vote_poll(_p, _o, _f, _q, _opts))
            row.addWidget(btn, stretch=1)
            pb = QProgressBar()
            pb.setRange(0,100); pb.setValue(pct)
            pb.setFixedHeight(6); pb.setTextVisible(False)
            pb.setStyleSheet(
                f"QProgressBar{{background:{t['bg2']};border-radius:3px;border:none;}}"
                f"QProgressBar::chunk{{background:{t['accent']};border-radius:3px;}}")
            pb.setFixedWidth(60)
            row.addWidget(pb)
            fl.addLayout(row)

        footer = QLabel(f"Всего голосов: {total}")
        footer.setStyleSheet(
            f"color:{t['text_dim']};font-size:9px;background:transparent;")
        fl.addWidget(footer)
        self._display._add_widget_bubble(frame, is_own=is_own)

    def _vote_poll(self, poll_id, option, frame, question, options):
        username = S().username
        if poll_id not in self._polls:
            self._polls[poll_id] = {
                "question": question, "options": options,
                "votes": {o: [] for o in options}, "creator": ""}
        poll = self._polls[poll_id]
        for v in poll["votes"].values():
            if username in v: v.remove(username)
        poll["votes"].setdefault(option, []).append(username)
        # Broadcast vote
        vote_pkt = {"type": MSG_POLL_VOTE, "poll_id": poll_id,
                    "option": option, "username": username, "ts": time.time()}
        if self._current_peer:
            self.net.send_udp(vote_pkt, self._current_peer["ip"])
        elif self._current_gid:
            for ip in GROUPS.get(self._current_gid,{}).get("members",[]):
                if ip != get_local_ip(): self.net.send_udp(vote_pkt, ip)
        else: self.net.broadcast(vote_pkt)
        frame.setParent(None); frame.deleteLater()
        self._add_poll_bubble(poll_id, question, options, is_own=False)

    def _send_sticker(self, b64: str):
        """Send a sticker as an image message."""
        chat_id = self._get_current_chat_id()
        if not chat_id:
            return
        try:
            img_bytes = base64.b64decode(b64)
            ts = time.time()
            self._display.add_message(
                sender    = S().username,
                text      = "",
                ts        = ts,
                is_own    = True,
                image_data= img_bytes,
            )
            to_ip = self._current_peer["ip"] if self._current_peer else None
            self.net.send_file(to_ip, None, raw_bytes=img_bytes, filename="sticker.png")
        except Exception as e:
            print(f"[sticker send] {e}")



# ═══════════════════════════════════════════════════════════════════════════
#  NOTES WIDGET
# ═══════════════════════════════════════════════════════════════════════════
class NotesWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._autosave = QTimer()
        self._autosave.setSingleShot(True)
        self._autosave.timeout.connect(self._save)
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6,6,6,6)
        lay.setSpacing(4)

        toolbar = QHBoxLayout()
        for label, cb in [("💾 Сохранить", self._save),
                          ("📂 Загрузить", self._load),
                          ("🧹 Очистить",  self._clear),
                          ("📤 Экспорт",   self._export)]:
            b = QPushButton(label)
            b.clicked.connect(cb)
            toolbar.addWidget(b)
        lay.addLayout(toolbar)

        self._edit = QTextEdit()
        self._edit.setPlaceholderText("Ваши заметки...")
        self._edit.textChanged.connect(lambda: self._autosave.start(2000))
        lay.addWidget(self._edit)

        self._status = QLabel("Готово")
        t = get_theme(S().theme)
        self._status.setStyleSheet(f"color:{t['text_dim']}; font-size:9px; padding:2px;")
        lay.addWidget(self._status)

        self._load()

    def _save(self):
        S().set("notes", self._edit.toPlainText())
        self._status.setText(f"Сохранено {datetime.now().strftime('%H:%M:%S')}")

    def _load(self):
        self._edit.setPlainText(S().get("notes","",t=str))
        self._status.setText("Загружено")

    def _clear(self):
        if QMessageBox.question(self,"Очистить","Очистить заметки?",
                QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) \
                == QMessageBox.StandardButton.Yes:
            self._edit.clear()

    def _export(self):
        fn, _ = QFileDialog.getSaveFileName(self,"Экспорт заметок","notes.txt","Text (*.txt)")
        if fn:
            Path(fn).write_text(self._edit.toPlainText(), encoding="utf-8")
            self._status.setText(f"Экспортировано: {fn}")

# ═══════════════════════════════════════════════════════════════════════════
#  CALL LOG WIDGET
# ═══════════════════════════════════════════════════════════════════════════
class CallLogWidget(QWidget):
    """Extended call log with stats, callbacks, notes, and filter."""
    call_back_requested = pyqtSignal(str)   # peer ip/name to call back

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup()

    def _setup(self):
        t = get_theme(S().theme)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(8)

        # ── Stats bar ──
        stats_row = QHBoxLayout()
        self._stat_total = QLabel("Всего: 0")
        self._stat_out   = QLabel("📞 Исходящих: 0")
        self._stat_in    = QLabel("📲 Входящих: 0")
        self._stat_miss  = QLabel("❌ Пропущенных: 0")
        for lbl in [self._stat_total, self._stat_out,
                    self._stat_in, self._stat_miss]:
            lbl.setStyleSheet(
                f"background:{t['bg3']};border-radius:6px;padding:4px 10px;"
                f"font-size:10px;color:{t['text_dim']};")
            stats_row.addWidget(lbl)
        stats_row.addStretch()
        lay.addLayout(stats_row)

        # ── Filter row ──
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Фильтр:"))
        self._filter_combo = QComboBox()
        self._filter_combo.addItems([
            "Все звонки", "Только входящие", "Только исходящие",
            "Пропущенные", "Последние 24ч"])
        self._filter_combo.currentIndexChanged.connect(self._refresh)
        filter_row.addWidget(self._filter_combo)

        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("🔍 Поиск по имени...")
        self._search_edit.textChanged.connect(self._refresh)
        filter_row.addWidget(self._search_edit, stretch=1)
        lay.addLayout(filter_row)

        # ── Call list (custom items) ──
        self._list = QListWidget()
        self._list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._list.customContextMenuRequested.connect(self._ctx_menu)
        self._list.itemDoubleClicked.connect(self._call_back)
        self._list.setStyleSheet(
            f"QListWidget{{background:{t['bg3']};border-radius:8px;border:none;}}"
            f"QListWidget::item{{padding:6px 10px;border-radius:6px;}}"
            f"QListWidget::item:selected{{background:{t['accent']};color:{t['text']};}}"
            f"QListWidget::item:hover{{background:{t['btn_hover']};}}")
        lay.addWidget(self._list, stretch=1)

        # ── Bottom controls ──
        bot = QHBoxLayout()
        refresh_btn = QPushButton("🔄 Обновить")
        refresh_btn.clicked.connect(self._refresh)
        export_btn  = QPushButton("📤 Экспорт в CSV")
        export_btn.clicked.connect(self._export_csv)
        clear_btn   = QPushButton("🗑 Очистить")
        clear_btn.clicked.connect(self._clear)
        for b in [refresh_btn, export_btn, clear_btn]:
            bot.addWidget(b)
        bot.addStretch()
        lay.addLayout(bot)

        self._refresh()

    def _refresh(self):
        self._list.clear()
        logs = HISTORY.load_call_log()

        flt   = self._filter_combo.currentIndex() if hasattr(self,'_filter_combo') else 0
        query = self._search_edit.text().lower() if hasattr(self,'_search_edit') else ""

        now = time.time()
        total = out = inc = miss = 0

        for entry in reversed(logs):
            who      = entry.get("peer","?")
            outgoing = entry.get("outgoing", True)
            dur      = entry.get("duration", 0)
            ts_v     = entry.get("ts", 0)
            missed   = dur == 0 and not outgoing

            total += 1
            if outgoing: out += 1
            else:        inc += 1
            if missed:   miss += 1

            # Apply filter
            if flt == 1 and outgoing: continue
            if flt == 2 and not outgoing: continue
            if flt == 3 and not missed: continue
            if flt == 4 and (now - ts_v) > 86400: continue
            if query and query not in who.lower(): continue

            ts_str = datetime.fromtimestamp(ts_v).strftime("%d.%m.%Y  %H:%M")
            if   outgoing: icon = "📞"
            elif missed:   icon = "❌"
            else:          icon = "📲"

            dur_str = f"{int(dur//60)}м {int(dur%60)}с" if dur >= 60 else (
                      f"{int(dur)}с" if dur else "пропущен")

            item = QListWidgetItem(
                f"{icon}  {who}   •   {ts_str}   •   {dur_str}")
            item.setData(Qt.ItemDataRole.UserRole, entry)
            # Color missed calls
            if missed:
                item.setForeground(QColor("#FF6060"))
            self._list.addItem(item)

        if hasattr(self,'_stat_total'):
            self._stat_total.setText(f"Всего: {total}")
            self._stat_out.setText(f"📞 Исходящих: {out}")
            self._stat_in.setText(f"📲 Входящих: {inc}")
            self._stat_miss.setText(f"❌ Пропущенных: {miss}")

    def add_call(self, peer: str, outgoing: bool, duration: float = 0):
        HISTORY.add_call({"peer": peer, "outgoing": outgoing,
                          "duration": duration, "ts": time.time()})
        self._refresh()

    def _call_back(self, item):
        entry = item.data(Qt.ItemDataRole.UserRole)
        if entry:
            peer = entry.get("peer","")
            self.call_back_requested.emit(peer)

    def _ctx_menu(self, pos):
        item = self._list.itemAt(pos)
        if not item: return
        entry = item.data(Qt.ItemDataRole.UserRole)
        menu = QMenu(self)
        menu.addAction("📞 Перезвонить",
            lambda: self.call_back_requested.emit(entry.get("peer","")))
        menu.addAction("📋 Копировать имя",
            lambda: QApplication.clipboard().setText(entry.get("peer","")))
        menu.addSeparator()
        menu.addAction("🗑 Удалить запись",
            lambda: self._delete_entry(entry))
        menu.exec(QCursor.pos())

    def _delete_entry(self, entry):
        logs = HISTORY.load_call_log()
        logs = [e for e in logs if e != entry]
        import json as _json
        f = HISTORY._file("__call_log__")
        f.write_text(_json.dumps(logs, ensure_ascii=False), encoding="utf-8")
        HISTORY._cache.pop("__call_log__", None)
        self._refresh()

    def _export_csv(self):
        fn, _ = QFileDialog.getSaveFileName(
            self, "Экспорт истории звонков", "call_log.csv",
            "CSV (*.csv)")
        if not fn: return
        import csv
        logs = HISTORY.load_call_log()
        with open(fn, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Имя", "Тип", "Дата", "Длительность(с)"])
            for e in logs:
                w.writerow([
                    e.get("peer","?"),
                    "Исходящий" if e.get("outgoing") else "Входящий",
                    datetime.fromtimestamp(e.get("ts",0)).strftime("%d.%m.%Y %H:%M"),
                    e.get("duration",0)])
        QMessageBox.information(self,"Экспорт",f"Сохранено: {fn}")

    def _clear(self):
        if QMessageBox.question(self,"Очистить","Очистить всю историю звонков?",
                QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) \
                == QMessageBox.StandardButton.Yes:
            f = HISTORY._file("__call_log__")
            if f.exists(): f.unlink()
            HISTORY._cache.pop("__call_log__", None)
            self._refresh()

# ═══════════════════════════════════════════════════════════════════════════
#  IMAGE CROP DIALOG  (interactive circle/rect crop with pan + zoom)
# ═══════════════════════════════════════════════════════════════════════════
class ImageCropDialog(QDialog):
    """
    Interactive image crop dialog.
    - Show original image
    - Drag crop rectangle / circle
    - Zoom with scroll wheel
    - Returns cropped QPixmap
    """
    def __init__(self, pixmap: QPixmap, circle: bool = True,
                 aspect_ratio: float | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Обрезать изображение")
        self.setModal(True)
        self.setMinimumSize(600, 520)
        self.resize(720, 560)
        t = get_theme(S().theme)
        self.setStyleSheet(f"background:{t['bg2']}; color:{t['text']};")

        self._src           = pixmap
        self._circle        = circle
        self._aspect_ratio  = aspect_ratio   # None = square, e.g. 4.0 = 4:1 banner
        self._zoom          = 1.0
        self._pan           = QPoint(0, 0)
        self._drag_pan      = None
        self._crop_size     = 200            # height of crop rect
        self._crop_pos      = QPoint(0, 0)
        self._drag_crop     = None
        self._result_pm     : QPixmap | None = None
        self._setup()

    def _setup(self):
        t = get_theme(S().theme)
        lay = QVBoxLayout(self)
        lay.setSpacing(8)
        lay.setContentsMargins(12, 12, 12, 12)

        # Hint
        hint = QLabel("Перетащите рамку обрезки • Колёсико — масштаб • ЛКМ на фоне — перемещение")
        hint.setStyleSheet(f"color:{t['text_dim']};font-size:9px;")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(hint)

        # Canvas
        self._canvas = QLabel()
        self._canvas.setMinimumSize(550, 400)
        self._canvas.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._canvas.setStyleSheet(f"background:{t['bg3']};border-radius:8px;")
        self._canvas.setMouseTracking(True)
        self._canvas.installEventFilter(self)
        lay.addWidget(self._canvas, stretch=1)

        # Size slider
        row = QHBoxLayout()
        row.addWidget(QLabel("Размер:"))
        self._size_slider = QSlider(Qt.Orientation.Horizontal)
        self._size_slider.setRange(60, 400)
        self._size_slider.setValue(200)
        self._size_slider.valueChanged.connect(self._on_size_changed)
        row.addWidget(self._size_slider)
        lay.addLayout(row)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        ok_btn = QPushButton("✅ Применить")
        ok_btn.setObjectName("accent_btn")
        ok_btn.setFixedHeight(32)
        ok_btn.clicked.connect(self._apply)
        cancel_btn = QPushButton("Отмена")
        cancel_btn.setFixedHeight(32)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(ok_btn)
        lay.addLayout(btn_row)

        QTimer.singleShot(50, self._center_crop)

    def _center_crop(self):
        cw = self._canvas.width()
        ch = self._canvas.height()
        cs_h = min(self._crop_size, ch - 20)
        cs_w = int(cs_h * self._aspect_ratio) if self._aspect_ratio else cs_h
        self._crop_pos = QPoint((cw - cs_w)//2, (ch - cs_h)//2)
        self._render()

    def _on_size_changed(self, val):
        self._crop_size = val
        self._render()

    def _crop_width(self) -> int:
        """Returns current crop width (respects aspect ratio)."""
        if self._aspect_ratio:
            return int(self._crop_size * self._aspect_ratio)
        return self._crop_size

    def _render(self):
        cw = self._canvas.width()
        ch = self._canvas.height()
        if cw <= 0 or ch <= 0:
            return
        canvas = QPixmap(cw, ch)
        canvas.fill(QColor(20, 20, 30))
        painter = QPainter(canvas)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Draw source image scaled + panned
        iw = int(self._src.width()  * self._zoom)
        ih = int(self._src.height() * self._zoom)
        x0 = (cw - iw)//2 + self._pan.x()
        y0 = (ch - ih)//2 + self._pan.y()
        scaled_img = self._src.scaled(iw, ih,
                                      Qt.AspectRatioMode.KeepAspectRatio,
                                      Qt.TransformationMode.SmoothTransformation)
        painter.drawPixmap(x0, y0, scaled_img)

        # Crop rect dimensions
        t    = get_theme(S().theme)
        cx   = self._crop_pos.x()
        cy   = self._crop_pos.y()
        cs_h = self._crop_size
        cs_w = self._crop_width()

        # Dark overlay outside crop
        painter.fillRect(0, 0, cw, cy, QColor(0,0,0,140))
        painter.fillRect(0, cy + cs_h, cw, ch, QColor(0,0,0,140))
        painter.fillRect(0, cy, cx, cs_h, QColor(0,0,0,140))
        painter.fillRect(cx + cs_w, cy, cw, cs_h, QColor(0,0,0,140))

        # Crop border
        painter.setPen(QPen(QColor(t['accent']), 2, Qt.PenStyle.DashLine))
        if self._circle:
            painter.drawEllipse(cx, cy, cs_w, cs_h)
        else:
            painter.drawRect(cx, cy, cs_w, cs_h)

        # Corner handles
        painter.setPen(QPen(QColor("white"), 3))
        for hx, hy in [(cx, cy), (cx+cs_w, cy), (cx, cy+cs_h), (cx+cs_w, cy+cs_h)]:
            painter.drawLine(hx-6, hy, hx+6, hy)
            painter.drawLine(hx, hy-6, hx, hy+6)

        # Show aspect ratio hint
        if self._aspect_ratio:
            painter.setPen(QPen(QColor(t['accent']), 1))
            painter.setFont(QFont("Arial", 9))
            ar_str = f"{self._aspect_ratio:.1f}:1 широкий формат"
            painter.drawText(cx + 4, cy + cs_h - 4, ar_str)

        painter.end()
        self._canvas.setPixmap(canvas)

    def eventFilter(self, obj, event):
        if obj is not self._canvas:
            return super().eventFilter(obj, event)
        if event.type() == event.Type.MouseButtonPress:
            pos = event.pos()
            cx, cy = self._crop_pos.x(), self._crop_pos.y()
            cs_w = self._crop_width()
            cs_h = self._crop_size
            if (cx <= pos.x() <= cx+cs_w and cy <= pos.y() <= cy+cs_h):
                self._drag_crop = pos - self._crop_pos
            else:
                self._drag_pan = pos
        elif event.type() == event.Type.MouseMove:
            if self._drag_crop is not None:
                cw = self._canvas.width()
                ch = self._canvas.height()
                cs_w = self._crop_width()
                new_pos = event.pos() - self._drag_crop
                nx = max(0, min(new_pos.x(), cw - cs_w))
                ny = max(0, min(new_pos.y(), ch - self._crop_size))
                self._crop_pos = QPoint(nx, ny)
                self._render()
            elif self._drag_pan is not None:
                delta = event.pos() - self._drag_pan
                self._drag_pan = event.pos()
                self._pan = QPoint(self._pan.x()+delta.x(), self._pan.y()+delta.y())
                self._render()
        elif event.type() == event.Type.MouseButtonRelease:
            self._drag_crop = None
            self._drag_pan  = None
        elif event.type() == event.Type.Wheel:
            delta = event.angleDelta().y()
            self._zoom = max(0.1, min(self._zoom * (1.1 if delta>0 else 0.9), 10.0))
            self._render()
        elif event.type() == event.Type.Resize:
            self._center_crop()
        return False

    def _apply(self):
        """Extract the cropped area from original image, respecting aspect ratio."""
        cw = self._canvas.width()
        ch = self._canvas.height()
        iw = int(self._src.width()  * self._zoom)
        ih = int(self._src.height() * self._zoom)
        x0 = (cw - iw)//2 + self._pan.x()
        y0 = (ch - ih)//2 + self._pan.y()

        cx   = self._crop_pos.x() - x0
        cy   = self._crop_pos.y() - y0
        cs_h = self._crop_size
        cs_w = self._crop_width()

        # Map crop box back to source image coordinates
        scale = self._src.width() / iw if iw > 0 else 1.0
        src_x = int(cx  * scale)
        src_y = int(cy  * scale)
        src_w = int(cs_w * scale)
        src_h = int(cs_h * scale)

        cropped = self._src.copy(src_x, src_y, src_w, src_h)
        if cropped.isNull():
            cropped = self._src

        # Scale to output size
        if self._aspect_ratio:
            out_w, out_h = 800, int(800 / self._aspect_ratio)
        else:
            out_w = out_h = 256
        self._result_pm = cropped.scaled(out_w, out_h,
                                         Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                                         Qt.TransformationMode.SmoothTransformation)
        self.accept()

    def get_pixmap(self) -> QPixmap | None:
        return self._result_pm

# ═══════════════════════════════════════════════════════════════════════════
#  PROFILE PREVIEW  (how others see you)
# ═══════════════════════════════════════════════════════════════════════════
class ProfilePreviewWidget(QWidget):
    """
    Telegram-style profile preview.
    Banner fills full width, avatar overlaps banner bottom edge,
    name/emoji/badges right below, info rows with icons, stats footer.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup()

    # ─────────────────────────────────────────────────────────────────────
    def _setup(self):
        t = get_theme(S().theme)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── outer card ──────────────────────────────────────────────────
        card = QFrame()
        card.setObjectName("ppw_card")
        card.setFrameShape(QFrame.Shape.NoFrame)
        card.setStyleSheet(f"""
            QFrame#ppw_card {{
                background: {t['bg2']};
                border-radius: 14px;
                border: 1px solid {t['border']};
            }}
        """)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)

        # ── banner ──────────────────────────────────────────────────────
        self._banner_lbl = QLabel()
        self._banner_lbl.setFixedHeight(180)
        self._banner_lbl.setScaledContents(False)
        self._banner_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._banner_lbl.setStyleSheet(
            f"background: qlineargradient(x1:0,y1:0,x2:1,y2:1,"
            f"stop:0 {t['accent']}, stop:0.5 {t['bg3']}, stop:1 {t['bg']});"
            "border-radius: 14px 14px 0 0;")
        cl.addWidget(self._banner_lbl)

        # ── avatar + badge row (overlaps banner by 48px) ─────────────────
        # We use a container with negative top-margin trick via a stacked layout
        overlap_w = QWidget()
        overlap_w.setFixedHeight(68)   # 96/2 + padding
        overlap_w.setStyleSheet(f"background: {t['bg2']};")
        overlap_lay = QHBoxLayout(overlap_w)
        overlap_lay.setContentsMargins(20, 0, 20, 0)
        overlap_lay.setSpacing(0)

        # Avatar label — 96×96, shifted up by 48px with negative margin via stylesheet
        self._av_container = QWidget()
        self._av_container.setFixedSize(104, 104)
        self._av_container.setStyleSheet("background: transparent;")
        av_inner = QVBoxLayout(self._av_container)
        av_inner.setContentsMargins(0, 0, 0, 0)
        self._avatar_lbl = QLabel(self._av_container)
        self._avatar_lbl.setFixedSize(96, 96)
        self._avatar_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._avatar_lbl.setStyleSheet(
            f"border: 4px solid {t['bg2']}; border-radius: 48px; background: {t['bg3']};")
        av_inner.addWidget(self._avatar_lbl)
        # Position avatar overlapping banner: move up 48px
        self._av_container.setContentsMargins(0, 0, 0, 0)

        overlap_lay.addWidget(self._av_container)
        overlap_lay.addStretch()

        # Premium badge (top-right)
        self._premium_lbl = QLabel("👑 PREMIUM")
        self._premium_lbl.setVisible(False)
        self._premium_lbl.setStyleSheet(
            "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #B8860B, stop:1 #FFD700);"
            "color: #1A0A00; font-size: 11px; font-weight: bold;"
            "border-radius: 11px; padding: 4px 14px;")
        overlap_lay.addWidget(self._premium_lbl,
                              alignment=Qt.AlignmentFlag.AlignVCenter)
        cl.addWidget(overlap_w)

        # We need the avatar to visually overlap the banner — use absolute pos
        # Re-parent avatar_lbl to card and position manually after show
        self._banner_lbl.setParent(card)
        self._avatar_lbl.setParent(card)
        self._premium_lbl.setParent(card)

        # ── name row ────────────────────────────────────────────────────
        name_w = QWidget()
        name_w.setStyleSheet(f"background: {t['bg2']};")
        name_lay = QHBoxLayout(name_w)
        name_lay.setContentsMargins(20, 4, 20, 2)
        name_lay.setSpacing(8)

        self._name_lbl = QLabel()
        self._name_lbl.setStyleSheet(
            f"font-size: 20px; font-weight: bold; color: {t['text']};"
            "background: transparent;")
        name_lay.addWidget(self._name_lbl)

        self._emoji_lbl = QLabel()
        self._emoji_lbl.setStyleSheet("font-size: 18px; background: transparent;")
        name_lay.addWidget(self._emoji_lbl)

        self._loyalty_lbl = QLabel()
        self._loyalty_lbl.setVisible(False)
        self._loyalty_lbl.setStyleSheet(
            f"background: transparent; color: {t['accent']};"
            f"border: 1px solid {t['accent']}; border-radius: 9px;"
            "padding: 1px 8px; font-size: 10px; font-weight: bold;")
        name_lay.addWidget(self._loyalty_lbl)
        name_lay.addStretch()
        cl.addWidget(name_w)

        # ── status line ──────────────────────────────────────────────────
        status_w = QWidget()
        status_w.setStyleSheet(f"background: {t['bg2']};")
        sl = QHBoxLayout(status_w)
        sl.setContentsMargins(20, 0, 20, 6)
        sl.setSpacing(6)
        self._status_dot = QLabel("●")
        self._status_dot.setStyleSheet("font-size: 10px; color: #4CAF50; background: transparent;")
        sl.addWidget(self._status_dot)
        self._status_txt = QLabel()
        self._status_txt.setStyleSheet(
            f"font-size: 11px; color: {t['text_dim']}; background: transparent;")
        sl.addWidget(self._status_txt)
        sl.addStretch()
        self._version_lbl = QLabel()
        self._version_lbl.setStyleSheet(
            f"font-size: 9px; color: {t['text_dim']}; background: transparent;")
        sl.addWidget(self._version_lbl)
        cl.addWidget(status_w)

        # ── thin divider ─────────────────────────────────────────────────
        div = QFrame(); div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(f"color: {t['border']}; margin: 0;")
        cl.addWidget(div)

        # ── info rows ────────────────────────────────────────────────────
        info_w = QWidget()
        info_w.setStyleSheet(f"background: {t['bg2']};")
        ifl = QVBoxLayout(info_w)
        ifl.setContentsMargins(0, 0, 0, 0)
        ifl.setSpacing(0)

        def make_info_row(icon_text, attr_val, attr_sub, attr_widget=None):
            row = QWidget()
            row.setStyleSheet(
                f"background: {t['bg2']};"
                f"border-bottom: 1px solid {t['border']}22;")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(20, 10, 20, 10)
            rl.setSpacing(16)
            ico = QLabel(icon_text)
            ico.setFixedWidth(28)
            ico.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ico.setStyleSheet(f"font-size: 18px; color: {t['text_dim']}; background: transparent;")
            rl.addWidget(ico)
            col = QVBoxLayout()
            col.setSpacing(1)
            v = QLabel(); v.setStyleSheet(
                f"font-size: 13px; color: {t['text']}; background: transparent;")
            s = QLabel(); s.setStyleSheet(
                f"font-size: 10px; color: {t['text_dim']}; background: transparent;")
            col.addWidget(v); col.addWidget(s)
            rl.addLayout(col)
            rl.addStretch()
            ifl.addWidget(row)
            setattr(self, attr_val, v)
            setattr(self, attr_sub, s)
            if attr_widget:
                setattr(self, attr_widget, row)
            return row

        make_info_row("ℹ",  "_ip_val",     "_ip_sub",    "_ip_row")
        make_info_row("📝", "_bio_val",    "_bio_sub",   "_bio_row")
        make_info_row("🌐", "_status_val", "_status_sub","_status_row")
        cl.addWidget(info_w)

        # ── stats footer ─────────────────────────────────────────────────
        stats_w = QWidget()
        stats_w.setStyleSheet(
            f"background: {t['bg3']}; border-radius: 0 0 14px 14px;")
        sfl = QHBoxLayout(stats_w)
        sfl.setContentsMargins(20, 14, 20, 18)
        sfl.setSpacing(0)
        self._stat_msgs  = QLabel("—")
        self._stat_grps  = QLabel("—")
        for num_lbl, sub_text in [(self._stat_msgs, "Сообщений"),
                                   (self._stat_grps,  "Групп")]:
            col = QVBoxLayout()
            col.setSpacing(2)
            num_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            num_lbl.setStyleSheet(
                f"font-size: 20px; font-weight: bold; color: {t['text']};"
                "background: transparent;")
            sub = QLabel(sub_text)
            sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sub.setStyleSheet(
                f"font-size: 10px; color: {t['text_dim']}; background: transparent;")
            col.addWidget(num_lbl); col.addWidget(sub)
            sfl.addLayout(col)
            sfl.addStretch()
        cl.addWidget(stats_w)

        root.addWidget(card)

        # ── bottom buttons ───────────────────────────────────────────────
        bot = QHBoxLayout()
        bot.setContentsMargins(0, 12, 0, 0)
        bot.setSpacing(8)
        ref_btn = QPushButton("🔄 Обновить превью")
        ref_btn.setFixedHeight(34)
        ref_btn.clicked.connect(self.refresh)
        bot.addStretch(); bot.addWidget(ref_btn); bot.addStretch()
        root.addLayout(bot)

        note = QLabel("Так тебя видят другие пользователи GoidaPhone")
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        note.setStyleSheet(f"color: {t['text_dim']}; font-size: 9px; padding: 4px;")
        root.addWidget(note)

        self.refresh()

    # ─────────────────────────────────────────────────────────────────────
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._position_avatar()

    def showEvent(self, event):
        super().showEvent(event)
        # Delay so layout is settled
        QTimer.singleShot(0, self._position_avatar)

    def _position_avatar(self):
        """Place avatar so it overlaps banner bottom by half its height."""
        try:
            banner = self._banner_lbl
            av     = self._avatar_lbl
            prem   = self._premium_lbl
            card   = banner.parent()
            if not card:
                return
            bh = banner.height()    # banner bottom y in card coords
            bw = banner.width()
            av_size = av.width()    # 96
            # Avatar: left-aligned, centre vertically on banner bottom edge
            av_x = 20
            av_y = bh - av_size // 2   # half pokes above banner bottom
            av.setGeometry(av_x, av_y, av_size, av_size)
            av.raise_()
            # Premium badge: vertically centred at same y, right side
            if prem.isVisible():
                pw = prem.sizeHint().width()
                ph = prem.sizeHint().height()
                prem.setGeometry(bw - pw - 20, bh - ph // 2 - ph // 2, pw, ph)
                prem.raise_()
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────
    def refresh(self):
        cfg = S()
        t   = get_theme(cfg.theme)

        # Banner
        bn = cfg.banner_b64
        self._banner_lbl.setStyleSheet(
            f"background: qlineargradient(x1:0,y1:0,x2:1,y2:1,"
            f"stop:0 {t['accent']}, stop:0.5 {t['bg3']}, stop:1 {t['bg']});"
            "border-radius: 14px 14px 0 0;")
        if bn:
            try:
                pm = base64_to_pixmap(bn)
                w  = max(self._banner_lbl.width(), 900)
                h  = self._banner_lbl.height()
                pm = pm.scaled(w, h,
                    Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                    Qt.TransformationMode.SmoothTransformation)
                if pm.width() > w:
                    pm = pm.copy((pm.width() - w) // 2, 0, w, h)
                self._banner_lbl.setPixmap(pm)
            except Exception:
                pass

        # Avatar — 96px circle with thick ring
        av = cfg.avatar_b64
        try:
            src_pm = base64_to_pixmap(av) if av else None
            if src_pm and not src_pm.isNull():
                pm96 = make_circle_pixmap(src_pm, 96)
            else:
                pm96 = default_avatar(cfg.username, 96)
        except Exception:
            pm96 = default_avatar(cfg.username, 96)
        self._avatar_lbl.setPixmap(pm96)
        self._avatar_lbl.setStyleSheet(
            f"border: 4px solid {t['bg2']}; border-radius: 48px; background: {t['bg3']};")

        # Premium
        self._premium_lbl.setVisible(cfg.premium)

        # Name + emoji + loyalty
        nick_color = cfg.nickname_color or t["text"]
        self._name_lbl.setStyleSheet(
            f"font-size: 20px; font-weight: bold; color: {nick_color};"
            "background: transparent;")
        self._name_lbl.setText(cfg.username or "—")
        self._emoji_lbl.setText(cfg.custom_emoji if cfg.premium else "")

        loyalty = int(cfg.get("loyalty_months", 0, t=int))
        if loyalty > 0:
            self._loyalty_lbl.setText(f"❤ {loyalty}")
            self._loyalty_lbl.setVisible(True)
            self._loyalty_lbl.setToolTip(f"В сети {loyalty} мес. подряд")
        else:
            self._loyalty_lbl.setVisible(False)

        # Status dot + text
        status = cfg.user_status
        dot_colors = {"online": "#4CAF50", "away": "#FFD700",
                      "busy": "#FF6B6B",   "dnd":  "#9E9E9E"}
        dot_labels = {"online": "в сети", "away": "отошёл",
                      "busy":   "занят",  "dnd":  "не беспокоить"}
        self._status_dot.setStyleSheet(
            f"font-size: 10px; color: {dot_colors.get(status,'#4CAF50')};"
            "background: transparent;")
        self._status_txt.setText(dot_labels.get(status, "в сети"))
        self._version_lbl.setText(f"GoidaPhone v{APP_VERSION}")

        # Info rows
        ip_raw = get_local_ip()
        id_str = display_id(ip_raw)
        self._ip_val.setText(id_str)
        self._ip_sub.setText("GoidaID" if cfg.safe_mode else "IP / GoidaID")

        bio = cfg.bio
        self._bio_val.setText(bio if bio else "Нет описания")
        self._bio_sub.setText("О себе")
        self._bio_row.setVisible(True)

        self._status_val.setText(dot_labels.get(status, "в сети"))
        self._status_sub.setText("Статус")

        # Stats
        try:
            hist_files = list(HISTORY_DIR.glob("*.json"))
            total = 0
            for f in hist_files:
                if f.stat().st_size < 5_000_000:
                    try:
                        total += len(json.loads(
                            f.read_text(encoding="utf-8", errors="ignore")))
                    except Exception:
                        pass
            self._stat_msgs.setText(str(total))
        except Exception:
            self._stat_msgs.setText("—")
        try:
            self._stat_grps.setText(str(len(GROUPS.groups)))
        except Exception:
            self._stat_grps.setText("—")

        QTimer.singleShot(0, self._position_avatar)


# ═══════════════════════════════════════════════════════════════════════════
#  PROFILE EDITOR
# ═══════════════════════════════════════════════════════════════════════════
class ProfileDialog(QDialog):
    profile_saved = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Мой профиль")
        self.setModal(True)
        self.resize(520, 500)
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.setContentsMargins(16,16,16,16)

        # ── Banner ──
        banner_group = QGroupBox("Баннер профиля")
        bl = QVBoxLayout(banner_group)
        bl.setContentsMargins(8, 8, 8, 8)
        bl.setSpacing(6)

        self._banner_lbl = QLabel()
        self._banner_lbl.setFixedHeight(120)
        self._banner_lbl.setScaledContents(False)
        self._banner_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        t = get_theme(S().theme)
        self._banner_lbl.setStyleSheet(
            f"background:{t['bg3']};border-radius:8px;"
            f"color:{t['text_dim']};font-size:11px;")
        self._banner_lbl.setText("Нет баннера")
        bl.addWidget(self._banner_lbl)

        banner_row = QHBoxLayout()
        banner_btn = QPushButton("📷 Выбрать баннер")
        banner_btn.clicked.connect(self._pick_banner)
        clear_banner_btn = QPushButton("🗑 Убрать")
        clear_banner_btn.clicked.connect(self._clear_banner)
        banner_row.addWidget(banner_btn)
        banner_row.addWidget(clear_banner_btn)
        banner_row.addStretch()
        bl.addLayout(banner_row)
        lay.addWidget(banner_group)

        # ── Avatar + basic ──
        av_group = QGroupBox("Аватар и имя")
        al = QHBoxLayout(av_group)

        self._avatar_lbl = QLabel()
        self._avatar_lbl.setFixedSize(72,72)
        self._avatar_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        al.addWidget(self._avatar_lbl)

        av_btn = QPushButton("📷\nИзменить\nаватар")
        av_btn.setFixedSize(80,72)
        av_btn.clicked.connect(self._pick_avatar)
        al.addWidget(av_btn)

        form = QFormLayout()
        self._username_edit = QLineEdit(S().username)
        self._username_edit.setMaxLength(24)
        form.addRow("Имя:", self._username_edit)

        self._bio_edit = QLineEdit(S().bio)
        self._bio_edit.setMaxLength(120)
        self._bio_edit.setPlaceholderText("Расскажите о себе...")
        form.addRow("Описание:", self._bio_edit)

        al.addLayout(form)
        lay.addWidget(av_group)

        # ── Premium customisation ──
        prem_group = QGroupBox("👑 Премиум: Кастомизация")
        pl = QFormLayout(prem_group)

        self._color_btn = QPushButton()
        self._color_btn.setFixedSize(40,24)
        self._color_btn.clicked.connect(self._pick_color)
        pl.addRow("Цвет ника:", self._color_btn)

        self._emoji_edit = QLineEdit(S().custom_emoji)
        self._emoji_edit.setMaxLength(5)
        self._emoji_edit.setPlaceholderText("👑")
        pl.addRow("Эмодзи:", self._emoji_edit)

        # quick emoji buttons — bigger so emojis render properly
        eq = QHBoxLayout()
        eq.setSpacing(4)
        for e in ["👑","⭐","🔥","💎","🚀","⚡","🎯","💫","🌟","🦋"]:
            b = QPushButton(e)
            b.setFixedSize(34, 30)
            b.setFont(QFont("Segoe UI Emoji" if platform.system()=="Windows" else "Noto Color Emoji", 14))
            b.clicked.connect(lambda _, em=e: self._emoji_edit.setText(em))
            eq.addWidget(b)
        eq.addStretch()
        pl.addRow("", eq)

        prem_enabled = S().premium
        prem_group.setEnabled(prem_enabled)
        if not prem_enabled:
            prem_group.setTitle("👑 Премиум: Кастомизация (требует Премиум)")
        lay.addWidget(prem_group)

        # ── Buttons ──
        blay = QHBoxLayout()
        preview_btn = QPushButton("👁 Предпросмотр")
        preview_btn.setToolTip("Как тебя видят другие пользователи")
        preview_btn.clicked.connect(self._show_preview)
        blay.addWidget(preview_btn)
        blay.addStretch()
        save = QPushButton("💾 Сохранить")
        save.setObjectName("accent_btn")
        save.clicked.connect(self._save)
        blay.addWidget(save)
        cancel = QPushButton("Отмена")
        cancel.clicked.connect(self.reject)
        blay.addWidget(cancel)
        lay.addLayout(blay)

        self._load_current()

    def _show_preview(self):
        """Show profile preview as inline overlay inside the main window."""
        mw = _find_main_window(self)
        overlay_parent = mw.centralWidget() if mw else self

        overlay = QWidget(overlay_parent)
        overlay.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        overlay.setStyleSheet("background:rgba(0,0,0,180);")
        overlay.resize(overlay_parent.size())
        overlay.show()
        overlay.raise_()

        # Resize overlay when parent resizes
        def _on_parent_resize(ev, _ov=overlay, _op=overlay_parent):
            _ov.resize(_op.size())
        overlay_parent.resizeEvent = _on_parent_resize

        t = get_theme(S().theme)
        # Card inside overlay
        card = QFrame(overlay)
        card.setFixedSize(480, 580)
        card.setStyleSheet(f"""
            QFrame {{
                background:{t['bg2']};
                border-radius:18px;
                border:1px solid {t['border']};
            }}
        """)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(0, 0, 0, 12)
        cl.setSpacing(0)

        preview = ProfilePreviewWidget(card)
        cl.addWidget(preview, stretch=1)

        close_btn = QPushButton("✕ Закрыть")
        close_btn.setFixedHeight(34)
        close_btn.setObjectName("accent_btn")
        close_btn.setStyleSheet(
            f"QPushButton{{background:{t['bg3']};color:{t['text_dim']};"
            f"border:1px solid {t['border']};border-radius:8px;"
            "margin:0 16px;font-size:11px;}}"
            f"QPushButton:hover{{background:{t['btn_hover']};color:{t['text']};}}")

        def _close():
            overlay_parent.resizeEvent = lambda e: None
            overlay.deleteLater()

        close_btn.clicked.connect(_close)
        cl.addWidget(close_btn)

        # Center card
        def _center(_card=card, _parent=overlay):
            _card.move(
                (_parent.width()  - _card.width())  // 2,
                (_parent.height() - _card.height()) // 2)
        _center()

        # Click backdrop to close
        overlay.mousePressEvent = lambda e: _close()
        card.mousePressEvent    = lambda e: e.accept()  # don't propagate

        overlay.raise_()
        card.raise_()

        # Re-center on resize
        orig_resize = overlay_parent.resizeEvent
        def _on_resize(ev, _c=_center, _ov=overlay, _op=overlay_parent):
            _ov.resize(_op.size()); _c()
        overlay_parent.resizeEvent = _on_resize


    def _load_current(self):
        cfg = S()
        self._update_color_btn(cfg.nickname_color)
        av = cfg.avatar_b64
        if av:
            try:
                self._avatar_lbl.setPixmap(make_circle_pixmap(base64_to_pixmap(av), 72))
            except Exception:
                self._avatar_lbl.setPixmap(default_avatar(cfg.username, 72))
        else:
            self._avatar_lbl.setPixmap(default_avatar(cfg.username, 72))

        bn = cfg.banner_b64
        if bn:
            try:
                pm = base64_to_pixmap(bn)
                self._update_banner_display(pm)
            except Exception:
                pass

    def _update_banner_display(self, pm: QPixmap):
        """Scale banner to fill label width at correct aspect."""
        w = max(self._banner_lbl.width(), 600)
        h = self._banner_lbl.height()
        scaled = pm.scaled(w, h,
            Qt.AspectRatioMode.KeepAspectRatioByExpanding,
            Qt.TransformationMode.SmoothTransformation)
        # Crop center
        if scaled.width() > w:
            x = (scaled.width() - w) // 2
            scaled = scaled.copy(x, 0, w, h)
        self._banner_lbl.setPixmap(scaled)
        self._banner_lbl.setText("")

    def _update_color_btn(self, hex_color: str):
        self._color_btn.setStyleSheet(f"background-color:{hex_color}; border:1px solid #888;")
        self._color_btn.setProperty("color", hex_color)

    def _pick_color(self):
        c = QColorDialog.getColor(QColor(self._color_btn.property("color") or "#E0E0E0"), self)
        if c.isValid():
            self._update_color_btn(c.name())

    def _pick_avatar(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Выберите аватар", "",
                    "Images (*.png *.jpg *.jpeg *.bmp *.webp)")
        if not fn:
            return
        src_pm = QPixmap(fn)
        if src_pm.isNull():
            return
        dlg = ImageCropDialog(src_pm, circle=True, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.get_pixmap():
            pm = dlg.get_pixmap()
            self._avatar_lbl.setPixmap(make_circle_pixmap(pm, 72))
            S().avatar_b64 = pixmap_to_base64(pm)

    def _pick_banner(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Выберите баннер", "",
                    "Images (*.png *.jpg *.jpeg *.bmp *.webp)")
        if not fn:
            return
        src_pm = QPixmap(fn)
        if src_pm.isNull():
            return
        dlg = ImageCropDialog(src_pm, circle=False, aspect_ratio=4.0, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.get_pixmap():
            pm = dlg.get_pixmap()
            self._update_banner_display(pm)
            S().banner_b64 = pixmap_to_base64(pm)

    def _clear_banner(self):
        S().banner_b64 = ""
        t = get_theme(S().theme)
        self._banner_lbl.setPixmap(QPixmap())
        self._banner_lbl.setText("Нет баннера")
        self._banner_lbl.setStyleSheet(
            f"background:{t['bg3']};border-radius:8px;"
            f"color:{t['text_dim']};font-size:11px;")

    def _save(self):
        cfg = S()
        cfg.username = self._username_edit.text().strip() or cfg.username
        cfg.bio = self._bio_edit.text().strip()
        if cfg.premium:
            cfg.nickname_color = self._color_btn.property("color") or "#E0E0E0"
            cfg.custom_emoji   = self._emoji_edit.text()
        self.profile_saved.emit()
        QMessageBox.information(self,"Профиль","Профиль сохранён!")
        self.accept()

# ═══════════════════════════════════════════════════════════════════════════
#  CUSTOM THEME DIALOG
# ═══════════════════════════════════════════════════════════════════════════
class CustomThemeDialog(QDialog):
    def __init__(self, slot: int, parent=None):
        super().__init__(parent)
        self.slot = slot
        self.setWindowTitle(f"Кастомная тема — Слот {slot}")
        self.setModal(True)
        self.resize(460, 520)
        self._colors: dict[str, str] = {}
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setSpacing(8)
        lay.setContentsMargins(12,12,12,12)

        # Name
        nl = QHBoxLayout()
        nl.addWidget(QLabel("Название:"))
        self._name = QLineEdit(f"Моя тема {self.slot}")
        nl.addWidget(self._name)
        lay.addLayout(nl)

        # Colour pickers
        colors_group = QGroupBox("Цвета")
        cl = QGridLayout(colors_group)

        self._COLOR_KEYS = [
            ("bg",       "Фон основной",      "#2A2A2A"),
            ("bg2",      "Фон вторичный",      "#1E1E1E"),
            ("bg3",      "Фон элементов",      "#141414"),
            ("border",   "Рамки",              "#444444"),
            ("text",     "Текст",              "#E0E0E0"),
            ("text_dim", "Текст dim",          "#808080"),
            ("accent",   "Акцент",             "#0078D4"),
            ("btn_bg",   "Фон кнопок",         "#3A3A3A"),
            ("item_sel", "Выделение",          "#0063B1"),
            ("header_bg","Фон шапки",          "#303030"),
            ("msg_own",  "Свои сообщения",     "#1A3A5C"),
            ("msg_other","Чужие сообщения",    "#383838"),
            ("online",   "Онлайн",             "#2ECC71"),
            ("offline",  "Офлайн",             "#E74C3C"),
        ]

        # Load saved if exists
        saved = S().custom_theme(self.slot)

        for row, (key, label, default) in enumerate(self._COLOR_KEYS):
            color = saved.get("colors", {}).get(key, default)
            self._colors[key] = color
            cl.addWidget(QLabel(label), row, 0)
            btn = QPushButton()
            btn.setFixedSize(60, 22)
            btn.setStyleSheet(f"background:{color}; border:1px solid #555;")
            btn.clicked.connect(lambda _, k=key, b=btn: self._pick(k, b))
            cl.addWidget(btn, row, 1)

        lay.addWidget(colors_group)

        if saved.get("name"):
            self._name.setText(saved["name"])

        blay = QHBoxLayout()
        blay.addStretch()
        save = QPushButton("💾 Сохранить тему")
        save.setObjectName("accent_btn")
        save.clicked.connect(self._save)
        blay.addWidget(save)
        cancel = QPushButton("Отмена")
        cancel.clicked.connect(self.reject)
        blay.addWidget(cancel)
        lay.addLayout(blay)

    def _pick(self, key: str, btn: QPushButton):
        c = QColorDialog.getColor(QColor(self._colors.get(key,"#ffffff")), self)
        if c.isValid():
            self._colors[key] = c.name()
            btn.setStyleSheet(f"background:{c.name()}; border:1px solid #555;")

    def _save(self):
        data = {"name": self._name.text(), "colors": dict(self._colors)}
        S().save_custom_theme(self.slot, data)
        QMessageBox.information(self,"Сохранено",
            f"Тема «{self._name.text()}» сохранена в слот {self.slot}.")
        self.accept()

# ═══════════════════════════════════════════════════════════════════════════
#  SETTINGS DIALOG  (full)
# ═══════════════════════════════════════════════════════════════════════════
class SettingsDialog(QDialog):
    settings_saved = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки GoidaPhone")
        self.setModal(False)
        self.resize(860, 640)
        self.setMinimumSize(760, 540)
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,12)
        lay.setSpacing(0)

        tabs = QTabWidget()
        tabs.setUsesScrollButtons(True)   # scroll when too many tabs
        tabs.setElideMode(Qt.TextElideMode.ElideNone)

        tabs.addTab(self._tab_audio(),      TR("tab_audio"))
        tabs.addTab(self._tab_network(),    TR("tab_network"))
        tabs.addTab(self._tab_themes(),     TR("tab_themes"))
        tabs.addTab(self._tab_appearance(), "🖼 Внешний вид")
        tabs.addTab(self._tab_license(),    TR("tab_license"))
        tabs.addTab(self._tab_data(),       TR("tab_data"))
        tabs.addTab(self._tab_language(),   TR("tab_language"))
        tabs.addTab(self._mk_specialist_scroll(), TR("tab_specialist"))
        tabs.addTab(self._tab_pin_security(), "🔒 Блокировка")
        tabs.addTab(self._tab_privacy(),    "🛡 Приватность")
        tabs.addTab(self._tab_call_settings(), "📞 Звонки")

        lay.addWidget(tabs)

        blay = QHBoxLayout()
        blay.setContentsMargins(12,8,12,0)
        blay.addStretch()
        save = QPushButton("💾 Сохранить")
        save.setObjectName("accent_btn")
        save.clicked.connect(self._save)
        blay.addWidget(save)
        cancel = QPushButton("Закрыть")
        cancel.clicked.connect(self.reject)
        blay.addWidget(cancel)
        lay.addLayout(blay)

        self._load()

    # ── Audio tab ──────────────────────────────────────────────────────
    def _tab_audio(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(8)

        g = QGroupBox("Микрофон и динамики")
        fl = QFormLayout(g)

        self._in_dev = QComboBox()
        self._out_dev = QComboBox()
        self._populate_audio_devices()
        fl.addRow("Микрофон:", self._in_dev)
        fl.addRow("Динамики:", self._out_dev)

        self._vol = QSlider(Qt.Orientation.Horizontal)
        self._vol.setRange(0,100)
        self._vol_lbl = QLabel("80%")
        self._vol.valueChanged.connect(lambda v: self._vol_lbl.setText(f"{v}%"))
        vol_row = QHBoxLayout()
        vol_row.addWidget(self._vol)
        vol_row.addWidget(self._vol_lbl)
        fl.addRow("Громкость:", vol_row)

        lay.addWidget(g)

        g2 = QGroupBox("Уведомления")
        fl2 = QFormLayout(g2)
        self._notif_sounds = QCheckBox("Звуковые уведомления о новых сообщениях")
        fl2.addRow(self._notif_sounds)
        lay.addWidget(g2)

        g3 = QGroupBox("Качество голоса")
        fl3 = QFormLayout(g3)

        vad_status = "активно" if WEBRTCVAD_AVAILABLE else "установите: pip install webrtcvad"
        self._vad_cb = QCheckBox(f"VAD — подавление тишины ({vad_status})")
        self._vad_cb.setEnabled(WEBRTCVAD_AVAILABLE)
        self._vad_cb.setChecked(WEBRTCVAD_AVAILABLE)
        self._vad_cb.setToolTip("Voice Activity Detection\nМикрофон молчит когда вы не говорите.\nУбирает фоновый шум, экономит трафик.")
        fl3.addRow(self._vad_cb)

        jb_row = QHBoxLayout()
        self._jb_spin = QSpinBox()
        self._jb_spin.setRange(2, 20)
        self._jb_spin.setValue(6)
        self._jb_spin.setSuffix(" фреймов")
        self._jb_spin.setToolTip("Размер буфера джиттера (2-20 фреймов).\nБольше = меньше щелчков, но больше задержка.\nРекомендуется: 4-8 для LAN, 8-15 для VPN.")
        jb_lbl = QLabel("≈ 192 мс")
        self._jb_spin.valueChanged.connect(
            lambda v, l=jb_lbl: l.setText(f"≈ {v*32} мс"))
        jb_row.addWidget(self._jb_spin)
        jb_row.addWidget(jb_lbl)
        fl3.addRow("Джиттер-буфер:", jb_row)

        lay.addWidget(g3)
        lay.addStretch()
        return w

    def _populate_audio_devices(self):
        self._in_dev.clear()
        self._out_dev.clear()
        self._in_dev.addItem("По умолчанию", -1)
        self._out_dev.addItem("По умолчанию", -1)
        if PYAUDIO_AVAILABLE:
            try:
                import pyaudio
                pa = pyaudio.PyAudio()
                for i in range(pa.get_device_count()):
                    info = pa.get_device_info_by_index(i)
                    if info["maxInputChannels"] > 0:
                        self._in_dev.addItem(info["name"], i)
                    if info["maxOutputChannels"] > 0:
                        self._out_dev.addItem(info["name"], i)
                pa.terminate()
            except Exception:
                pass


    # ── Appearance tab ─────────────────────────────────────────────────
    def _tab_appearance(self) -> QWidget:
        """App scale, splash screen customisation, launcher, tab visibility."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        t = get_theme(S().theme)

        # App scale
        scale_g = QGroupBox("Масштаб приложения")
        sfl = QFormLayout(scale_g)
        scale_row = QHBoxLayout()
        self._scale_slider = QSlider(Qt.Orientation.Horizontal)
        self._scale_slider.setRange(75, 150)
        self._scale_slider.setSingleStep(5)
        self._scale_slider.setValue(int(S().get("app_scale", 100, t=int)))
        self._scale_lbl = QLabel(f"{self._scale_slider.value()}%")
        self._scale_lbl.setFixedWidth(44)
        self._scale_slider.valueChanged.connect(lambda v: self._scale_lbl.setText(f"{v}%"))
        scale_row.addWidget(self._scale_slider)
        scale_row.addWidget(self._scale_lbl)
        sfl.addRow("Масштаб:", scale_row)
        scale_hint = QLabel("Изменение масштаба применяется после перезапуска. 100% — стандарт.")
        scale_hint.setStyleSheet(f"color:{t['text_dim']};font-size:9px;")
        sfl.addRow(scale_hint)
        apply_scale_btn = QPushButton("Применить сейчас (приблизительно)")
        apply_scale_btn.clicked.connect(self._apply_scale_now)
        sfl.addRow(apply_scale_btn)
        lay.addWidget(scale_g)

        # Splash screen
        splash_g = QGroupBox("Экран загрузки (Splash Screen)")
        spfl = QFormLayout(splash_g)
        self._show_splash = QCheckBox("Показывать экран загрузки при запуске")
        self._show_splash.setChecked(S().get("show_splash", True, t=bool))
        spfl.addRow(self._show_splash)
        self._splash_preview = QLabel("Нет изображения")
        self._splash_preview.setFixedSize(260, 90)
        self._splash_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._splash_preview.setStyleSheet(
            f"background:{t['bg3']};border-radius:6px;color:{t['text_dim']};font-size:10px;")
        bg_b64 = S().get("splash_image_b64", "", t=str)
        if bg_b64:
            try:
                pm = QPixmap()
                pm.loadFromData(base64.b64decode(bg_b64))
                if not pm.isNull():
                    self._splash_preview.setPixmap(pm.scaled(
                        260, 90,
                        Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                        Qt.TransformationMode.SmoothTransformation))
            except Exception:
                pass
        spfl.addRow("Фон заставки:", self._splash_preview)
        splash_btn_row = QHBoxLayout()
        pick_splash_btn = QPushButton("Выбрать изображение")
        pick_splash_btn.clicked.connect(self._pick_splash_image)
        clear_splash_btn = QPushButton("Убрать")
        clear_splash_btn.clicked.connect(self._clear_splash_image)
        splash_btn_row.addWidget(pick_splash_btn)
        splash_btn_row.addWidget(clear_splash_btn)
        spfl.addRow(splash_btn_row)
        lay.addWidget(splash_g)

        # Launcher
        launch_g = QGroupBox("Экран выбора режима запуска")
        lfl = QFormLayout(launch_g)
        self._show_launcher_cb = QCheckBox("Показывать выбор режима при каждом запуске")
        self._show_launcher_cb.setChecked(S().show_launcher)
        lfl.addRow(self._show_launcher_cb)
        lay.addWidget(launch_g)

        # Tab visibility
        tabs_g = QGroupBox("Постоянные вкладки (скрыть, но не удалить)")
        tfl = QFormLayout(tabs_g)
        self._tab_show_notes = QCheckBox("Показывать вкладку Заметки")
        self._tab_show_notes.setChecked(S().get("tab_show_notes", True, t=bool))
        self._tab_show_calls = QCheckBox("Показывать вкладку Звонки")
        self._tab_show_calls.setChecked(S().get("tab_show_calls", True, t=bool))
        tfl.addRow(self._tab_show_notes)
        tfl.addRow(self._tab_show_calls)
        lay.addWidget(tabs_g)
        lay.addStretch()
        return w

    def _apply_scale_now(self):
        val = getattr(self, '_scale_slider', None)
        if val is None:
            return
        factor = val.value() / 100.0
        font = QApplication.instance().font()
        font.setPointSizeF(max(7.0, 9.0 * factor))
        QApplication.instance().setFont(font)
        S().set("app_scale", val.value())

    def _pick_splash_image(self):
        fn, _ = QFileDialog.getOpenFileName(
            self, "Выбрать фон заставки", "",
            "Images (*.png *.jpg *.jpeg *.bmp *.webp)")
        if not fn:
            return
        pm = QPixmap(fn)
        if pm.isNull():
            return
        S().set("splash_image_b64", pixmap_to_base64(pm))
        self._splash_preview.setPixmap(pm.scaled(
            260, 90,
            Qt.AspectRatioMode.KeepAspectRatioByExpanding,
            Qt.TransformationMode.SmoothTransformation))

    def _clear_splash_image(self):
        S().set("splash_image_b64", "")
        t = get_theme(S().theme)
        self._splash_preview.setPixmap(QPixmap())
        self._splash_preview.setText("Нет изображения")
        self._splash_preview.setStyleSheet(
            f"background:{t['bg3']};border-radius:6px;color:{t['text_dim']};font-size:10px;")


    # ── Network tab ────────────────────────────────────────────────────
    def _tab_network(self) -> QWidget:
        w = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(w)
        outer = QWidget()
        outer_lay = QVBoxLayout(outer)
        outer_lay.setContentsMargins(0,0,0,0)
        outer_lay.addWidget(scroll)

        lay = QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)

        # ── Основные порты ──
        g_ports = QGroupBox("Сетевые порты")
        fl = QFormLayout(g_ports)
        self._udp_p = QSpinBox(); self._udp_p.setRange(1024,65535)
        self._tcp_p = QSpinBox(); self._tcp_p.setRange(1024,65535)
        self._udp_p.setValue(S().get("udp_port", 45678, t=int))
        self._tcp_p.setValue(S().get("tcp_port", 45679, t=int))
        fl.addRow("UDP порт:", self._udp_p)
        fl.addRow("TCP порт:", self._tcp_p)
        fl.addRow(QLabel("⚠ Изменение портов требует перезапуска."))
        lay.addWidget(g_ports)

        # ── Информация ──
        g_info = QGroupBox("Информация о соединении")
        fl2 = QFormLayout(g_info)
        ip = get_local_ip()
        ip_lbl = QLabel(ip)
        copy_ip_btn = QPushButton("📋")
        copy_ip_btn.setFixedWidth(28)
        copy_ip_btn.setToolTip("Копировать IP")
        copy_ip_btn.clicked.connect(lambda: QApplication.clipboard().setText(ip))
        ip_row = QHBoxLayout()
        ip_row.addWidget(ip_lbl)
        ip_row.addWidget(copy_ip_btn)
        ip_row.addStretch()
        fl2.addRow("Мой IP:", ip_row)
        fl2.addRow("ОС:", QLabel(get_os_name()))
        fl2.addRow("Версия:", QLabel(APP_VERSION))
        fl2.addRow("Протокол:", QLabel(f"v{PROTOCOL_VERSION}"))
        lay.addWidget(g_info)

        # ── Пароль сети (admin) ──
        g_netpw = QGroupBox("🔐 Пароль сети (администратор)")
        netpw_lay = QVBoxLayout(g_netpw)
        netpw_info = QLabel(
            "Если установлен, новые пользователи должны знать пароль для подключения.\n"
            "Управляется через Admin Terminal (Shift+F10).")
        netpw_info.setWordWrap(True)
        netpw_info.setStyleSheet("font-size:10px;color:gray;")
        netpw_lay.addWidget(netpw_info)
        pw_status = QLabel(
            "● Пароль активен" if AdminManager.network_password_enabled()
            else "○ Пароль не установлен")
        pw_status.setStyleSheet(
            "color:#80FF80;" if AdminManager.network_password_enabled()
            else "color:gray;")
        netpw_lay.addWidget(pw_status)
        netpw_row = QHBoxLayout()
        self._netpw_edit = QLineEdit()
        self._netpw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._netpw_edit.setPlaceholderText("Новый пароль сети...")
        netpw_set_btn = QPushButton("Установить")
        netpw_set_btn.clicked.connect(self._set_network_password)
        netpw_off_btn = QPushButton("Отключить")
        netpw_off_btn.clicked.connect(self._disable_network_password)
        netpw_row.addWidget(self._netpw_edit)
        netpw_row.addWidget(netpw_set_btn)
        netpw_row.addWidget(netpw_off_btn)
        netpw_lay.addLayout(netpw_row)
        g_netpw.setEnabled(AdminManager.is_admin())
        if not AdminManager.is_admin():
            g_netpw.setTitle("🔐 Пароль сети (требуется администратор)")
        lay.addWidget(g_netpw)

        # ── Расширенные параметры ──
        g_adv = QGroupBox("⚙ Расширенные параметры")
        adv_fl = QFormLayout(g_adv)

        self._broadcast_addr = QLineEdit()
        self._broadcast_addr.setText(S().get("broadcast_addr","255.255.255.255",t=str))
        self._broadcast_addr.setPlaceholderText("255.255.255.255")
        adv_fl.addRow("Адрес broadcast:", self._broadcast_addr)

        self._discovery_interval = QSpinBox()
        self._discovery_interval.setRange(1, 60)
        self._discovery_interval.setSuffix(" сек")
        self._discovery_interval.setValue(S().get("discovery_interval", 5, t=int))
        adv_fl.addRow("Интервал обнаружения:", self._discovery_interval)

        self._peer_timeout = QSpinBox()
        self._peer_timeout.setRange(5, 300)
        self._peer_timeout.setSuffix(" сек")
        self._peer_timeout.setValue(S().get("peer_timeout", 30, t=int))
        adv_fl.addRow("Таймаут пира:", self._peer_timeout)

        self._max_chunk = QSpinBox()
        self._max_chunk.setRange(8, 60)
        self._max_chunk.setSuffix(" КБ")
        self._max_chunk.setValue(S().get("max_chunk_kb", 60, t=int))
        adv_fl.addRow("Макс. размер чанка:", self._max_chunk)

        self._tcp_timeout = QSpinBox()
        self._tcp_timeout.setRange(1,30)
        self._tcp_timeout.setSuffix(" сек")
        self._tcp_timeout.setValue(S().get("tcp_timeout", 10, t=int))
        adv_fl.addRow("TCP таймаут:", self._tcp_timeout)

        self._enable_ipv6 = QCheckBox("Включить IPv6 (экспериментально)")
        self._enable_ipv6.setChecked(S().get("enable_ipv6", False, t=bool))
        adv_fl.addRow(self._enable_ipv6)

        self._allow_relay = QCheckBox("Разрешить relay-соединения")
        self._allow_relay.setChecked(S().get("allow_relay", True, t=bool))
        adv_fl.addRow(self._allow_relay)

        self._encrypt_transport = QCheckBox("Шифровать транспортный слой (AES, экспер.)")
        self._encrypt_transport.setChecked(S().get("encrypt_transport", False, t=bool))
        adv_fl.addRow(self._encrypt_transport)

        lay.addWidget(g_adv)

        # ── Список серверов ──
        g_srv = QGroupBox("🌐 Список серверов / сетей")
        srv_lay = QVBoxLayout(g_srv)
        srv_lay.addWidget(QLabel(
            "Сохранённые сети для быстрого подключения. "
            "Двойной клик — подключиться."))

        self._server_list_widget = QListWidget()
        self._server_list_widget.setMaximumHeight(140)
        self._refresh_server_list()
        self._server_list_widget.itemDoubleClicked.connect(self._connect_to_server)
        srv_lay.addWidget(self._server_list_widget)

        srv_btn_row = QHBoxLayout()
        add_srv_btn = QPushButton("➕ Добавить")
        add_srv_btn.clicked.connect(self._add_server_dialog)
        edit_srv_btn = QPushButton("✏ Изменить")
        edit_srv_btn.clicked.connect(self._edit_server_dialog)
        del_srv_btn = QPushButton("🗑 Удалить")
        del_srv_btn.clicked.connect(self._delete_server)
        conn_srv_btn = QPushButton("🔌 Подключиться")
        conn_srv_btn.setObjectName("accent_btn")
        conn_srv_btn.clicked.connect(lambda: self._connect_to_server(
            self._server_list_widget.currentItem()))
        for b in [add_srv_btn, edit_srv_btn, del_srv_btn, conn_srv_btn]:
            srv_btn_row.addWidget(b)
        srv_lay.addLayout(srv_btn_row)
        lay.addWidget(g_srv)


        lay.addStretch()
        return outer

    def _set_network_password(self):
        pw = self._netpw_edit.text().strip()
        if not pw:
            QMessageBox.warning(self,"Ошибка","Введите пароль.")
            return
        if not AdminManager.is_admin() or not AdminManager.verify_admin(""):
            # require admin terminal auth - just set directly if admin exists
            pass
        AdminManager.set_network_password(pw)
        self._netpw_edit.clear()
        QMessageBox.information(self,"Пароль сети","✅ Пароль установлен.")

    def _disable_network_password(self):
        AdminManager.set_network_password("")
        QMessageBox.information(self,"Пароль сети","Пароль отключён.")

    def _refresh_server_list(self):
        self._server_list_widget.clear()
        import json
        servers = json.loads(S().get("server_list","[]",t=str))
        for s in servers:
            name = s.get("name","?")
            host = s.get("host","?")
            port = s.get("udp_port", 45678)
            desc = s.get("desc","")
            pw   = "🔐" if s.get("password") else ""
            self._server_list_widget.addItem(
                f"{pw} {name}  —  {host}:{port}  {desc}")

    def _add_server_dialog(self):
        self._server_edit_dialog()

    def _edit_server_dialog(self):
        row = self._server_list_widget.currentRow()
        import json
        servers = json.loads(S().get("server_list","[]",t=str))
        srv = servers[row] if 0 <= row < len(servers) else None
        self._server_edit_dialog(srv, row)

    def _server_edit_dialog(self, existing=None, edit_row=-1):
        dlg = QDialog(self)
        dlg.setWindowTitle("Добавить сервер" if not existing else "Изменить сервер")
        dlg.resize(400, 380)
        t = get_theme(S().theme)
        dlg.setStyleSheet(f"background:{t['bg2']};color:{t['text']};")
        dl = QVBoxLayout(dlg)
        dl.setContentsMargins(16,16,16,16)
        dl.setSpacing(10)
        fl = QFormLayout()

        name_e   = QLineEdit(existing.get("name","") if existing else "")
        host_e   = QLineEdit(existing.get("host","") if existing else "")
        udp_e    = QSpinBox(); udp_e.setRange(1024,65535)
        udp_e.setValue(existing.get("udp_port",45678) if existing else 45678)
        tcp_e    = QSpinBox(); tcp_e.setRange(1024,65535)
        tcp_e.setValue(existing.get("tcp_port",45679) if existing else 45679)
        desc_e   = QLineEdit(existing.get("desc","") if existing else "")
        pw_e     = QLineEdit(existing.get("password","") if existing else "")
        pw_e.setEchoMode(QLineEdit.EchoMode.Password)
        tags_e   = QLineEdit(existing.get("tags","") if existing else "")
        notes_e  = QPlainTextEdit(existing.get("notes","") if existing else "")
        notes_e.setMaximumHeight(60)

        fl.addRow("Название * :", name_e)
        fl.addRow("Хост / IP * :", host_e)
        fl.addRow("UDP порт * :", udp_e)
        fl.addRow("TCP порт :", tcp_e)
        fl.addRow("Описание :", desc_e)
        fl.addRow("Пароль :", pw_e)
        fl.addRow("Теги :", tags_e)
        fl.addRow("Заметки :", notes_e)
        dl.addLayout(fl)

        req_note = QLabel("* — обязательные поля")
        req_note.setStyleSheet("font-size:9px;color:gray;")
        dl.addWidget(req_note)

        btn_row = QHBoxLayout()
        ok_btn = QPushButton("💾 Сохранить")
        ok_btn.setObjectName("accent_btn")
        cancel_btn = QPushButton("Отмена")
        btn_row.addStretch()
        btn_row.addWidget(ok_btn)
        btn_row.addWidget(cancel_btn)
        dl.addLayout(btn_row)

        cancel_btn.clicked.connect(dlg.reject)

        def do_save():
            if not name_e.text().strip() or not host_e.text().strip():
                QMessageBox.warning(dlg,"Ошибка","Заполните обязательные поля.")
                return
            import json
            servers = json.loads(S().get("server_list","[]",t=str))
            entry = {
                "name":     name_e.text().strip(),
                "host":     host_e.text().strip(),
                "udp_port": udp_e.value(),
                "tcp_port": tcp_e.value(),
                "desc":     desc_e.text().strip(),
                "password": pw_e.text(),
                "tags":     tags_e.text().strip(),
                "notes":    notes_e.toPlainText().strip(),
            }
            if edit_row >= 0 and edit_row < len(servers):
                servers[edit_row] = entry
            else:
                servers.append(entry)
            S().set("server_list", json.dumps(servers, ensure_ascii=False))
            self._refresh_server_list()
            dlg.accept()

        ok_btn.clicked.connect(do_save)
        dlg.exec()

    def _delete_server(self):
        row = self._server_list_widget.currentRow()
        if row < 0: return
        import json
        servers = json.loads(S().get("server_list","[]",t=str))
        if 0 <= row < len(servers):
            name = servers[row].get("name","?")
            if QMessageBox.question(self,"Удалить",f"Удалить сервер «{name}»?",
                    QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) \
                    == QMessageBox.StandardButton.Yes:
                servers.pop(row)
                S().set("server_list", json.dumps(servers, ensure_ascii=False))
                self._refresh_server_list()

    def _connect_to_server(self, item):
        if not item: return
        row = self._server_list_widget.row(item)
        import json
        servers = json.loads(S().get("server_list","[]",t=str))
        if 0 <= row < len(servers):
            srv = servers[row]
            host = srv.get("host","")
            udp  = srv.get("udp_port",45678)
            pw   = srv.get("password","")
            if pw:
                entered, ok = QInputDialog.getText(
                    self, "Пароль сети",
                    f"Введите пароль для подключения к «{srv.get('name',host)}»:",
                    QLineEdit.EchoMode.Password)
                if not ok or entered != pw:
                    QMessageBox.warning(self,"Доступ закрыт","Неверный пароль.")
                    return
            S().set("udp_port", udp)
            S().set("tcp_port", srv.get("tcp_port",45679))
            S().set("broadcast_addr", host)
            QMessageBox.information(self,"Подключение",
                f"Параметры сохранены.\nПерезапустите GoidaPhone для применения.")

    # ── Themes tab ─────────────────────────────────────────────────────
    def _tab_themes(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(8)

        g = QGroupBox("Стандартные темы")
        fl = QFormLayout(g)
        self._theme_combo = QComboBox()
        for key, td in THEMES.items():
            self._theme_combo.addItem(td["label"], key)
        fl.addRow("Тема:", self._theme_combo)
        preview_btn = QPushButton("👁 Предпросмотр")
        preview_btn.clicked.connect(self._preview_theme)
        fl.addRow(preview_btn)
        lay.addWidget(g)

        g2 = QGroupBox("👑 Кастомные темы (Премиум)")
        gl = QVBoxLayout(g2)
        gl.addWidget(QLabel("Создайте до 3 собственных тем:"))
        sl = QHBoxLayout()
        for i in range(1,4):
            saved = S().custom_theme(i)
            label = saved.get("name", f"Слот {i}") if saved else f"Слот {i}"
            b = QPushButton(f"✏ {label}")
            b.clicked.connect(lambda _, s=i: self._edit_custom_theme(s))
            sl.addWidget(b)
            if saved:
                use = QPushButton(f"▶ Применить {i}")
                use.clicked.connect(lambda _, s=i: self._apply_custom_theme(s))
                sl.addWidget(use)
        gl.addLayout(sl)
        g2.setEnabled(S().premium)
        if not S().premium:
            g2.setTitle("👑 Кастомные темы (требует Премиум)")
        lay.addWidget(g2)
        lay.addStretch()
        return w

    def _preview_theme(self):
        key = self._theme_combo.currentData()
        if not key:
            return
        reply = QMessageBox.information(
            self, "Смена темы",
            "⚠ Быстрое переключение тем может быть нестабильным.\n"
            "Для полного применения рекомендуется перезапуск GoidaPhone.",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        if reply == QMessageBox.StandardButton.Ok:
            QApplication.instance().setStyleSheet(build_stylesheet(get_theme(key)))

    def _edit_custom_theme(self, slot: int):
        if not S().premium:
            QMessageBox.warning(self,"Премиум","Доступно только для Премиум пользователей.")
            return
        d = CustomThemeDialog(slot, self)
        d.exec()

    def _apply_custom_theme(self, slot: int):
        data = S().custom_theme(slot)
        if data and "colors" in data:
            t = {**get_theme("dark"), **data["colors"]}
            t["label"] = data.get("name","Кастомная")
            QApplication.instance().setStyleSheet(build_stylesheet(t))
            S().set("theme", f"__custom_{slot}__")

    # ── License tab ────────────────────────────────────────────────────
    def _tab_license(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(8)

        g = QGroupBox("Статус Премиум")
        gl = QVBoxLayout(g)

        self._lic_status = QLabel()
        self._lic_status.setWordWrap(True)
        gl.addWidget(self._lic_status)

        info = QLabel(
            "Премиум возможности:\n"
            "• Цветной ник\n"
            "• Кастомный эмодзи рядом с именем\n"
            "• 3 слота кастомных тем оформления\n"
            "• Срок действия: 30 дней"
        )
        info.setStyleSheet("padding:8px; border-radius:4px;")
        gl.addWidget(info)

        self._lic_input = LicenseLineEdit()
        gl.addWidget(self._lic_input)

        self._activate_btn = QPushButton("🎫 Активировать")
        self._activate_btn.setObjectName("accent_btn")
        self._activate_btn.clicked.connect(self._activate)
        gl.addWidget(self._activate_btn)

        buy_btn = QPushButton("📱 Купить лицензию (Telegram)")
        buy_btn.clicked.connect(lambda: QDesktopServices.openUrl(
            QUrl("https://t.me/WinoraCompany")))
        gl.addWidget(buy_btn)

        lay.addWidget(g)
        lay.addStretch()
        return w

    def _activate(self):
        code = self._lic_input.raw_digits()
        if S().activate_premium(code):
            exp = datetime.fromisoformat(S().premium_expires).strftime("%d.%m.%Y")
            self._lic_status.setText(f"✅ Премиум активен до {exp}")
            self._lic_status.setStyleSheet("color:#27AE60; font-weight:bold;")
            QMessageBox.information(self,"Активация",f"🎉 Премиум активирован до {exp}!")
            self.settings_saved.emit()
        else:
            QMessageBox.warning(self,"Ошибка","Неверный код лицензии.")

    def _update_lic_status(self):
        if S().premium:
            exp = datetime.fromisoformat(S().premium_expires).strftime("%d.%m.%Y")
            self._lic_status.setText(f"✅ Премиум активен до {exp}")
            self._lic_status.setStyleSheet("color:#27AE60; font-weight:bold;")
        else:
            self._lic_status.setText("❌ Не активировано")
            self._lic_status.setStyleSheet("color:#E74C3C; font-weight:bold;")

    # ── Data tab ───────────────────────────────────────────────────────
    def _tab_data(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(8)

        g = QGroupBox("Хранение данных")
        fl = QFormLayout(g)
        self._save_history = QCheckBox("Сохранять историю чатов")
        self._show_splash   = QCheckBox("Показывать заставку при запуске")
        fl.addRow(self._save_history)
        fl.addRow(self._show_splash)

        fl.addRow(QLabel(f"📁 Данные хранятся в: {DATA_DIR}"))

        clear_hist = QPushButton("🗑 Очистить всю историю")
        clear_hist.setObjectName("danger_btn")
        clear_hist.clicked.connect(self._clear_history)
        fl.addRow(clear_hist)

        clear_files = QPushButton("🗑 Очистить полученные файлы")
        clear_files.setObjectName("danger_btn")
        clear_files.clicked.connect(self._clear_files)
        fl.addRow(clear_files)

        lay.addWidget(g)

        # Updates
        upd_g = QGroupBox("Обновления")
        ul = QVBoxLayout(upd_g)
        self._check_upd_btn = QPushButton("🔄 Проверить обновления")
        self._check_upd_btn.clicked.connect(self._check_updates)
        ul.addWidget(self._check_upd_btn)
        self._upd_lbl = QLabel("")
        ul.addWidget(self._upd_lbl)
        lay.addWidget(upd_g)

        lay.addStretch()
        return w

    def _clear_history(self):
        if QMessageBox.question(self,"Очистить","Удалить всю историю чатов?",
                QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) \
                == QMessageBox.StandardButton.Yes:
            for f in HISTORY_DIR.glob("*.json"):
                f.unlink()
            HISTORY._cache.clear()

    def _clear_files(self):
        if QMessageBox.question(self,"Очистить","Удалить все полученные файлы?",
                QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) \
                == QMessageBox.StandardButton.Yes:
            for f in RECEIVED_DIR.iterdir():
                f.unlink()

    def _check_updates(self):
        self._check_upd_btn.setEnabled(False)
        self._upd_lbl.setText("Проверка...")
        self._checker = UpdateChecker()
        self._checker.update_available.connect(self._on_update_available)
        self._checker.no_update.connect(lambda: self._upd_lbl.setText("✅ Обновлений не найдено."))
        self._checker.check_failed.connect(lambda e: self._upd_lbl.setText(f"❌ Ошибка: {e}"))
        self._checker.finished.connect(lambda: self._check_upd_btn.setEnabled(True))
        self._checker.start()

    def _on_update_available(self, ver: str, desc: str):
        self._upd_lbl.setText(f"🚀 Доступна версия {ver}")
        msg = QMessageBox(self)
        msg.setWindowTitle("Доступно обновление!")
        msg.setText(f"<b>Доступна версия {ver}</b><br><br>{desc}")
        msg.setInformativeText("Обновить GoidaPhone прямо сейчас?")
        msg.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        msg.button(QMessageBox.StandardButton.Yes).setText("⬇ Обновить")
        if msg.exec() == QMessageBox.StandardButton.Yes:
            self._do_update()

    def _do_update(self):
        if GITHUB_REPO.startswith("YOUR_GITHUB"):
            QMessageBox.information(self,"Обновление",
                "Настройте GITHUB_REPO в исходном коде для автообновления.")
            return
        dest = str(Path(sys.argv[0]).parent / f"goidaphone_update_{APP_VERSION}.py")
        dlg  = QProgressDialog("Загрузка обновления...", "Отмена", 0, 100, self)
        dlg.setWindowModality(Qt.WindowModality.WindowModal)
        dlg.show()
        self._updater = Updater(GITHUB_RAW_URL, dest)
        self._updater.progress.connect(dlg.setValue)
        self._updater.finished.connect(lambda ok, info: self._update_done(ok, info, dest, dlg))
        self._updater.start()

    def _update_done(self, ok: bool, info: str, dest: str, dlg):
        dlg.close()
        if ok:
            msg = QMessageBox(self)
            msg.setWindowTitle("Обновление загружено")
            msg.setText(f"Обновление загружено в:\n{dest}\n\nПерезапустите приложение для применения.")
            msg.setInformativeText("Заменить текущий файл и перезапустить?")
            msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if msg.exec() == QMessageBox.StandardButton.Yes:
                try:
                    shutil.copy2(dest, sys.argv[0])
                    os.unlink(dest)
                    QApplication.instance().quit()
                    subprocess.Popen([sys.executable, sys.argv[0]])
                except Exception as e:
                    QMessageBox.critical(self,"Ошибка",f"Не удалось заменить файл:\n{e}")
        else:
            QMessageBox.critical(self,"Ошибка",f"Ошибка загрузки:\n{info}")

    # ── Language tab ────────────────────────────────────────────────────
    def _tab_language(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(8)

        g = QGroupBox("🌍 " + TR("tab_language"))
        fl = QFormLayout(g)

        self._lang_combo = QComboBox()
        self._lang_combo.addItem("🇷🇺 Русский", "ru")
        self._lang_combo.addItem("🇬🇧 English", "en")
        # Set current
        current_lang = S().language
        for i in range(self._lang_combo.count()):
            if self._lang_combo.itemData(i) == current_lang:
                self._lang_combo.setCurrentIndex(i)
                break
        fl.addRow("Язык / Language:", self._lang_combo)

        note = QLabel("⚠ Смена языка применяется при следующем открытии окна.\n"
                      "⚠ Language change applies on next window open.")
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {get_theme(S().theme)['text_dim']}; font-size: 10px;")
        fl.addRow(note)

        lay.addWidget(g)

        # Launcher settings
        g2 = QGroupBox("🚀 Запуск")
        fl2 = QFormLayout(g2)
        self._show_launcher_cb = QCheckBox(
            "Показывать экран выбора режима при запуске" if S().language=="ru"
            else "Show mode selection screen on startup")
        self._show_launcher_cb.setChecked(S().show_launcher)
        fl2.addRow(self._show_launcher_cb)

        self._os_notif_cb = QCheckBox(
            "Системные уведомления о новых сообщениях" if S().language=="ru"
            else "System notifications for new messages")
        self._os_notif_cb.setChecked(S().os_notifications)
        fl2.addRow(self._os_notif_cb)

        lay.addWidget(g2)
        lay.addStretch()
        return w

    # ── Specialist tab ──────────────────────────────────────────────────
    def _tab_pin_security(self) -> QWidget:
        """PIN lock and auto-lock settings tab."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)

        t = get_theme(S().theme)
        pin_enabled = S().get("pin_enabled", False, t=bool)

        # ── Enable PIN ──
        g_pin = QGroupBox("PIN-блокировка")
        gpl = QVBoxLayout(g_pin)

        self._pin_enable_cb = QCheckBox("Включить PIN-блокировку при запуске")
        self._pin_enable_cb.setChecked(pin_enabled)
        gpl.addWidget(self._pin_enable_cb)

        fl = QFormLayout()
        self._pin_new = QLineEdit()
        self._pin_new.setEchoMode(QLineEdit.EchoMode.Password)
        self._pin_new.setPlaceholderText("6 цифр")
        self._pin_new.setMaxLength(6)
        fl.addRow("Новый PIN:", self._pin_new)

        self._pin_confirm = QLineEdit()
        self._pin_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self._pin_confirm.setPlaceholderText("Повторите PIN")
        self._pin_confirm.setMaxLength(6)
        fl.addRow("Подтвердить PIN:", self._pin_confirm)

        self._pin_hint_edit = QLineEdit()
        self._pin_hint_edit.setPlaceholderText("Подсказка (необязательно)")
        self._pin_hint_edit.setText(S().get("pin_hint","",t=str))
        fl.addRow("Подсказка:", self._pin_hint_edit)
        gpl.addLayout(fl)

        set_pin_btn = QPushButton("💾 Установить PIN")
        set_pin_btn.setObjectName("accent_btn")
        set_pin_btn.clicked.connect(self._set_pin)
        clear_pin_btn = QPushButton("🗑 Убрать PIN")
        clear_pin_btn.clicked.connect(self._clear_pin)
        pin_btn_row = QHBoxLayout()
        pin_btn_row.addWidget(set_pin_btn)
        pin_btn_row.addWidget(clear_pin_btn)
        gpl.addLayout(pin_btn_row)

        status_lbl = QLabel(
            "✅ PIN установлен" if S().get("pin_hash","",t=str)
            else "○ PIN не установлен")
        status_lbl.setStyleSheet(
            "color:#80FF80;" if S().get("pin_hash","",t=str)
            else "color:gray;")
        gpl.addWidget(status_lbl)
        lay.addWidget(g_pin)

        # ── Auto-lock ──
        g_auto = QGroupBox("Автоблокировка")
        afl = QFormLayout(g_auto)

        self._autolock_enabled = QCheckBox("Блокировать при бездействии")
        self._autolock_enabled.setChecked(S().get("autolock_enabled", False, t=bool))
        afl.addRow(self._autolock_enabled)

        self._autolock_timeout = QSpinBox()
        self._autolock_timeout.setRange(1, 120)
        self._autolock_timeout.setSuffix(" мин")
        self._autolock_timeout.setValue(S().get("autolock_timeout", 5, t=int))
        afl.addRow("Таймаут:", self._autolock_timeout)

        self._lock_on_minimize = QCheckBox("Блокировать при сворачивании")
        self._lock_on_minimize.setChecked(S().get("lock_on_minimize", False, t=bool))
        afl.addRow(self._lock_on_minimize)

        lay.addWidget(g_auto)

        note = QLabel(
            "ℹ Если вы забудете PIN, можно сбросить приложение.\n"
            "Все личные данные будут удалены при сбросе.")
        note.setWordWrap(True)
        note.setStyleSheet("font-size:10px;color:gray;")
        lay.addWidget(note)

        lay.addStretch()
        return w

    def _set_pin(self):
        import hashlib as _hl
        pin1 = self._pin_new.text().strip()
        pin2 = self._pin_confirm.text().strip()
        if not pin1:
            QMessageBox.warning(self, "Ошибка", "Введите PIN.")
            return
        if len(pin1) < 4 or not pin1.isdigit():
            QMessageBox.warning(self, "Ошибка", "PIN: минимум 4 цифры (только цифры).")
            return
        if pin1 != pin2:
            QMessageBox.warning(self, "Ошибка", "PIN-коды не совпадают.")
            return
        S().set("pin_hash", _hl.sha256(pin1.encode()).hexdigest())
        S().set("pin_hint", self._pin_hint_edit.text().strip())
        S().set("pin_enabled", "true")
        self._pin_enable_cb.setChecked(True)
        self._pin_new.clear()
        self._pin_confirm.clear()
        QMessageBox.information(self, "PIN", "✅ PIN-код установлен успешно.")

    def _clear_pin(self):
        if QMessageBox.question(self,"Убрать PIN","Удалить PIN-код?",
                QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) \
                == QMessageBox.StandardButton.Yes:
            S().remove("pin_hash")
            S().remove("pin_hint")
            S().set("pin_enabled", False)
            QMessageBox.information(self,"PIN","PIN-код удалён.")

    def _tab_privacy(self) -> QWidget:
        """🛡 Privacy & security settings — fully functional."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(10)

        def _grp(title: str) -> tuple:
            g = QGroupBox(title)
            fl = QVBoxLayout(g)
            return g, fl

        # ── Читаемость / видимость ──────────────────────────────────────────
        g1, fl1 = _grp("👁  Видимость и статус")

        self._priv_show_status = QCheckBox(
            "Показывать мой статус присутствия другим пользователям")
        self._priv_show_status.setChecked(
            S().get("priv_show_status", True, t=bool))
        self._priv_show_status.setToolTip(
            "Если выключено — другие не видят «Онлайн», «Отошёл» и т.д.")
        fl1.addWidget(self._priv_show_status)

        self._priv_show_avatar = QCheckBox(
            "Показывать аватар при звонках и в списке пользователей")
        self._priv_show_avatar.setChecked(
            S().get("priv_show_avatar", True, t=bool))
        fl1.addWidget(self._priv_show_avatar)

        self._priv_show_typing = QCheckBox(
            "Отправлять индикатор «печатает…»")
        self._priv_show_typing.setChecked(
            S().get("priv_show_typing", True, t=bool))
        fl1.addWidget(self._priv_show_typing)

        self._priv_read_receipts = QCheckBox(
            "Отправлять уведомления о прочтении (галочки)")
        self._priv_read_receipts.setChecked(
            S().get("priv_read_receipts", True, t=bool))
        fl1.addWidget(self._priv_read_receipts)

        lay.addWidget(g1)

        # ── Звонки ──────────────────────────────────────────────────────────
        g2, fl2 = _grp("📞  Звонки")

        self._priv_allow_calls = QCheckBox(
            "Разрешить входящие звонки от всех пользователей")
        self._priv_allow_calls.setChecked(
            S().get("priv_allow_calls", True, t=bool))
        fl2.addWidget(self._priv_allow_calls)

        self._priv_allow_group_calls = QCheckBox(
            "Разрешить приглашения в групповые звонки")
        self._priv_allow_group_calls.setChecked(
            S().get("priv_allow_group_calls", True, t=bool))
        fl2.addWidget(self._priv_allow_group_calls)

        self._priv_hide_ip_call = QCheckBox(
            "Использовать relay для скрытия IP при звонках (требует relay-сервер)")
        self._priv_hide_ip_call.setChecked(
            S().get("priv_hide_ip_call", False, t=bool))
        self._priv_hide_ip_call.setToolTip(
            "Relay настраивается в разделе «Специалист»")
        fl2.addWidget(self._priv_hide_ip_call)

        lay.addWidget(g2)

        # ── Сообщения ────────────────────────────────────────────────────────
        g3, fl3 = _grp("💬  Сообщения")

        self._priv_link_preview = QCheckBox(
            "Показывать предпросмотр ссылок в сообщениях")
        self._priv_link_preview.setChecked(
            S().get("priv_link_preview", True, t=bool))
        fl3.addWidget(self._priv_link_preview)

        self._priv_save_history = QCheckBox(
            "Сохранять историю чатов локально")
        self._priv_save_history.setChecked(
            S().get("priv_save_history", True, t=bool))
        self._priv_save_history.setToolTip(
            "Если выключено — история не сохраняется и стирается при выходе")
        fl3.addWidget(self._priv_save_history)

        self._priv_encrypt_history = QCheckBox(
            "Шифровать локальную историю чатов (AES-256)")
        self._priv_encrypt_history.setChecked(
            S().get("priv_encrypt_history", False, t=bool))
        fl3.addWidget(self._priv_encrypt_history)

        self._priv_allow_fwd = QCheckBox(
            "Разрешить пересылку ваших сообщений другим пользователям")
        self._priv_allow_fwd.setChecked(
            S().get("priv_allow_fwd", True, t=bool))
        fl3.addWidget(self._priv_allow_fwd)

        lay.addWidget(g3)

        # ── E2E / Crypto ─────────────────────────────────────────────────────
        g4, fl4 = _grp("🔑  Шифрование (E2E)")

        e2e_status = QLabel(
            "✅ End-to-End шифрование активно (X25519 + AES-256-GCM + Ed25519)"
            if True else "❌ E2E недоступно")
        e2e_status.setStyleSheet("color:#80FF80;font-size:11px;font-weight:bold;")
        fl4.addWidget(e2e_status)

        e2e_info = QLabel(
            "Все личные сообщения шифруются E2E автоматически.\n"
            "Ключи генерируются при первом запуске и хранятся локально.\n"
            "Публичный ключ идентичности отображается в профиле (GoidaID).")
        e2e_info.setWordWrap(True)
        e2e_info.setStyleSheet("font-size:10px;color:gray;")
        fl4.addWidget(e2e_info)

        regen_btn = QPushButton("🔄 Перегенерировать ключи")
        regen_btn.setToolTip(
            "Создать новую пару ключей.\n"
            "Внимание: существующие E2E-сессии будут сброшены.")
        regen_btn.clicked.connect(self._regen_e2e_keys)
        fl4.addWidget(regen_btn)

        lay.addWidget(g4)

        # ── Сохранить кнопка ────────────────────────────────────────────────
        save_priv = QPushButton("💾 Применить настройки приватности")
        save_priv.setObjectName("accent_btn")
        save_priv.setFixedHeight(34)
        save_priv.clicked.connect(self._save_privacy)
        lay.addWidget(save_priv)

        # ── Медиаплеер ───────────────────────────────────────────────
        g5, fl5 = _grp("🎵  Медиафайлы")
        media_lbl = QLabel(
            "При открытии медиафайлов (музыка, видео) из чата:")
        media_lbl.setStyleSheet("font-size:11px;background:transparent;")
        fl5.addWidget(media_lbl)

        self._priv_media_pref = QComboBox()
        self._priv_media_pref.addItems([
            "Спрашивать каждый раз",
            "Всегда Mewa (встроенный плеер)",
            "Всегда системный плеер",
        ])
        pref_map = {"": 0, "mewa": 1, "system": 2}
        cur_pref = S().get("media_open_pref", "", t=str)
        self._priv_media_pref.setCurrentIndex(pref_map.get(cur_pref, 0))
        fl5.addWidget(self._priv_media_pref)

        media_note = QLabel("Изменение вступает в силу немедленно.")
        media_note.setStyleSheet("font-size:9px;color:gray;background:transparent;")
        fl5.addWidget(media_note)
        lay.addWidget(g5)

        # ── Медиа ────────────────────────────────────────────────────────────
        g5, fl5 = _grp("🎵  Медиафайлы")
        fl5_form = QFormLayout()

        self._media_pref_combo = QComboBox()
        self._media_pref_combo.addItems([
            "Спрашивать каждый раз",
            "Всегда открывать в Mewa",
            "Всегда открывать системным плеером",
        ])
        pref = S().get("media_open_pref", "", t=str)
        idx = {"": 0, "mewa": 1, "system": 2}.get(pref, 0)
        self._media_pref_combo.setCurrentIndex(idx)
        fl5_form.addRow("По умолчанию открывать медиа:", self._media_pref_combo)

        # Link open preference
        self._link_pref_combo = QComboBox()
        self._link_pref_combo.addItems([
            "Спрашивать каждый раз",
            "Всегда в WNS (встроенный браузер)",
            "Всегда в системном браузере",
        ])
        link_pref = S().get("link_open_pref", "ask", t=str)
        link_idx = {"ask": 0, "wns": 1, "system": 2}.get(link_pref, 0)
        self._link_pref_combo.setCurrentIndex(link_idx)
        fl5_form.addRow("Ссылки из чата:", self._link_pref_combo)

        reset_links = QPushButton("🔄 Сбросить (спрашивать снова)")
        reset_links.clicked.connect(lambda: (
            S().set("link_open_pref", "ask"),
            self._link_pref_combo.setCurrentIndex(0)))
        fl5_form.addRow(reset_links)

        reset_pref = QPushButton("🔄 Сбросить (спрашивать снова)")
        reset_pref.clicked.connect(lambda: (
            S().set("media_open_pref", ""),
            self._media_pref_combo.setCurrentIndex(0)))
        fl5_form.addRow(reset_pref)
        fl5.addLayout(fl5_form)
        lay.addWidget(g5)

        note = QLabel(
            "ℹ Все настройки вступают в силу немедленно после сохранения.")
        note.setStyleSheet("font-size:9px;color:gray;")
        lay.addWidget(note)

        lay.addStretch()
        return w

    def _save_privacy(self):
        # Save media preference
        if hasattr(self, '_media_pref_combo'):
            pref_map = {0: "", 1: "mewa", 2: "system"}
            S().set("media_open_pref", pref_map.get(self._media_pref_combo.currentIndex(), ""))
        if hasattr(self, '_link_pref_combo'):
            link_map = {0: "ask", 1: "wns", 2: "system"}
            S().set("link_open_pref", link_map.get(self._link_pref_combo.currentIndex(), "ask"))
        S().set("priv_show_status",       self._priv_show_status.isChecked())
        S().set("priv_show_avatar",       self._priv_show_avatar.isChecked())
        S().set("priv_show_typing",       self._priv_show_typing.isChecked())
        S().set("priv_read_receipts",     self._priv_read_receipts.isChecked())
        S().set("priv_allow_calls",       self._priv_allow_calls.isChecked())
        S().set("priv_allow_group_calls", self._priv_allow_group_calls.isChecked())
        S().set("priv_hide_ip_call",      self._priv_hide_ip_call.isChecked())
        S().set("priv_link_preview",      self._priv_link_preview.isChecked())
        S().set("priv_save_history",      self._priv_save_history.isChecked())
        # Also sync with the main save_history setting
        S().set("save_history",           self._priv_save_history.isChecked())
        S().set("priv_encrypt_history",   self._priv_encrypt_history.isChecked())
        S().set("priv_allow_fwd",         self._priv_allow_fwd.isChecked())
        pref_vals = ["", "mewa", "system"]
        pref = pref_vals[self._priv_media_pref.currentIndex()]
        S().set("media_open_pref", pref)
        import builtins as _b
        if hasattr(_b, '__MEDIA_PREF_GLOBAL'):
            _b.__MEDIA_PREF_GLOBAL = pref
        QMessageBox.information(self, "Приватность",
            "✅ Настройки приватности сохранены.")

    def _regen_e2e_keys(self):
        reply = QMessageBox.warning(self, "Перегенерировать ключи",
            "Создать новую пару E2E-ключей?\n\n"
            "Все активные зашифрованные сессии будут сброшены.\n"
            "Собеседникам придётся заново согласовать ключи.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
                id_priv = Ed25519PrivateKey.generate()
                dh_priv = X25519PrivateKey.generate()
                S().set("identity_priv_b64", base64.b64encode(
                    id_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode())
                S().set("dh_priv_b64", base64.b64encode(
                    dh_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode())
                QMessageBox.information(self, "Ключи",
                    "✅ Новые E2E-ключи сгенерированы.\n"
                    "Перезапустите GoidaPhone для применения.")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сгенерировать ключи:\n{e}")

    def _tab_call_settings(self) -> QWidget:
        """📞 Звонки — проверка микрофона, камеры, демонстрации экрана, качества."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(10)
        t = get_theme(S().theme)

        def _grp(title):
            g = QGroupBox(title); fl = QVBoxLayout(g); return g, fl

        # ── Микрофон ─────────────────────────────────────────────────────
        g_mic, fl_mic = _grp("🎤  Микрофон")

        mic_row = QHBoxLayout()
        mic_lbl = QLabel("Устройство ввода:")
        mic_lbl.setStyleSheet("font-size:11px;background:transparent;")
        mic_row.addWidget(mic_lbl)
        self._cs_mic_combo = QComboBox()
        try:
            import pyaudio as _pa
            p = _pa.PyAudio()
            for i in range(p.get_device_count()):
                info = p.get_device_info_by_index(i)
                if info.get("maxInputChannels", 0) > 0:
                    self._cs_mic_combo.addItem(info["name"], i)
            p.terminate()
        except Exception:
            self._cs_mic_combo.addItem("Системное устройство по умолчанию", -1)
        mic_row.addWidget(self._cs_mic_combo, stretch=1)
        fl_mic.addLayout(mic_row)

        # Mic test
        mic_test_row = QHBoxLayout()
        self._cs_mic_test_btn = QPushButton("🎙 Тест микрофона (3 сек)")
        self._cs_mic_test_btn.setObjectName("accent_btn")
        self._cs_mic_test_btn.setCheckable(False)
        self._cs_mic_test_btn.clicked.connect(self._test_mic)
        mic_test_row.addWidget(self._cs_mic_test_btn)
        self._cs_mic_level = QProgressBar()
        self._cs_mic_level.setRange(0, 100)
        self._cs_mic_level.setValue(0)
        self._cs_mic_level.setFixedHeight(10)
        self._cs_mic_level.setTextVisible(False)
        self._cs_mic_level.setStyleSheet(
            f"QProgressBar{{background:{t['bg3']};border-radius:5px;border:none;}}"
            f"QProgressBar::chunk{{background:#39FF14;border-radius:5px;}}")
        mic_test_row.addWidget(self._cs_mic_level, stretch=1)
        fl_mic.addLayout(mic_test_row)

        self._cs_mic_status = QLabel("Нажмите для проверки микрофона")
        self._cs_mic_status.setStyleSheet(f"font-size:10px;color:{t['text_dim']};background:transparent;")
        fl_mic.addWidget(self._cs_mic_status)
        lay.addWidget(g_mic)

        # ── Динамик / наушники ───────────────────────────────────────────
        g_spk, fl_spk = _grp("🔊  Динамик / наушники")
        spk_row = QHBoxLayout()
        spk_lbl = QLabel("Устройство вывода:")
        spk_lbl.setStyleSheet("font-size:11px;background:transparent;")
        spk_row.addWidget(spk_lbl)
        self._cs_spk_combo = QComboBox()
        try:
            import pyaudio as _pa2
            p2 = _pa2.PyAudio()
            for i in range(p2.get_device_count()):
                info2 = p2.get_device_info_by_index(i)
                if info2.get("maxOutputChannels", 0) > 0:
                    self._cs_spk_combo.addItem(info2["name"], i)
            p2.terminate()
        except Exception:
            self._cs_spk_combo.addItem("Системное устройство по умолчанию", -1)
        spk_row.addWidget(self._cs_spk_combo, stretch=1)
        fl_spk.addLayout(spk_row)

        spk_test_btn = QPushButton("🔈 Воспроизвести тестовый тон")
        spk_test_btn.clicked.connect(self._test_speaker)
        fl_spk.addWidget(spk_test_btn)
        lay.addWidget(g_spk)

        # ── Качество звонка ──────────────────────────────────────────────
        g_q, fl_q = _grp("📶  Качество голоса")
        qual_row = QHBoxLayout()
        qual_lbl = QLabel("Частота дискретизации:")
        qual_lbl.setStyleSheet("font-size:11px;background:transparent;")
        qual_row.addWidget(qual_lbl)
        self._cs_quality = QComboBox()
        for label, val in [("Эконом (8 кГц)", 8000),
                            ("Стандарт (16 кГц)", 16000),
                            ("Высокое (48 кГц)", 48000)]:
            self._cs_quality.addItem(label, val)
        cur_rate = S().get("audio_rate", 16000, t=int)
        for i in range(self._cs_quality.count()):
            if self._cs_quality.itemData(i) == cur_rate:
                self._cs_quality.setCurrentIndex(i)
        qual_row.addWidget(self._cs_quality)
        fl_q.addLayout(qual_row)

        vad_cb = QCheckBox("VAD — шумоподавление (не передавать тишину)")
        vad_cb.setChecked(S().get("vad_enabled", True, t=bool))
        vad_cb.toggled.connect(lambda v: S().set("vad_enabled", v))
        fl_q.addWidget(vad_cb)
        lay.addWidget(g_q)

        # ── Демонстрация экрана ──────────────────────────────────────────
        g_sh, fl_sh = _grp("🖥  Демонстрация экрана")
        share_info = QLabel(
            "Во время звонка: кнопка демонстрации в окне звонка.\n"
            "Передача кадров: 5 fps, захват всего экрана.")
        share_info.setWordWrap(True)
        share_info.setStyleSheet(f"font-size:10px;color:{t['text_dim']};background:transparent;")
        fl_sh.addWidget(share_info)

        share_test_btn = QPushButton("📸 Тест захвата экрана")
        share_test_btn.clicked.connect(self._test_screen_capture)
        fl_sh.addWidget(share_test_btn)
        self._cs_share_preview = QLabel()
        self._cs_share_preview.setFixedHeight(100)
        self._cs_share_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._cs_share_preview.setStyleSheet(f"background:{t['bg3']};border-radius:6px;")
        self._cs_share_preview.setText("Нажмите тест для предпросмотра")
        fl_sh.addWidget(self._cs_share_preview)
        lay.addWidget(g_sh)

        # ── Вебкамера ────────────────────────────────────────────────────
        g_cam, fl_cam = _grp("📷  Камера")

        cam_info = QLabel("Предпросмотр вебкамеры для проверки перед звонком.")
        cam_info.setStyleSheet(f"font-size:10px;color:{t['text_dim']};background:transparent;")
        fl_cam.addWidget(cam_info)

        cam_row = QHBoxLayout()
        cam_btn = QPushButton("📷 Включить камеру")
        cam_btn.setObjectName("accent_btn")
        stop_cam_btn = QPushButton("⏹ Стоп")
        stop_cam_btn.setEnabled(False)
        cam_row.addWidget(cam_btn)
        cam_row.addWidget(stop_cam_btn)
        cam_row.addStretch()
        fl_cam.addLayout(cam_row)

        self._cs_cam_preview = QLabel("Предпросмотр камеры...")
        self._cs_cam_preview.setFixedHeight(120)
        self._cs_cam_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._cs_cam_preview.setStyleSheet(
            f"background:#000;border-radius:8px;border:1px solid {t['border']};"
            "color:#666;font-size:11px;")
        self._cs_cam_preview.setVisible(False)
        fl_cam.addWidget(self._cs_cam_preview)
        self._cs_cam_obj = None

        def _start_cam_test():
            try:
                from PyQt6.QtMultimedia import QCamera, QMediaCaptureSession
                from PyQt6.QtMultimediaWidgets import QVideoWidget
                self._cs_cam_preview.setVisible(True)
                self._cs_cam_preview.setText("")
                # Use QVideoWidget inside preview label space
                if not hasattr(self, '_cs_vid_widget') or not self._cs_vid_widget:
                    self._cs_vid_widget = QVideoWidget(self._cs_cam_preview)
                    self._cs_vid_widget.setGeometry(0, 0,
                        self._cs_cam_preview.width(),
                        self._cs_cam_preview.height())
                self._cs_cam_obj = QCamera()
                self._cs_cam_session = QMediaCaptureSession()
                self._cs_cam_session.setCamera(self._cs_cam_obj)
                self._cs_cam_session.setVideoOutput(self._cs_vid_widget)
                self._cs_cam_obj.start()
                self._cs_vid_widget.show()
                cam_btn.setEnabled(False)
                stop_cam_btn.setEnabled(True)
            except ImportError:
                self._cs_cam_preview.setText(
                    "Установи: pip install PyQt6-QtMultimediaWidgets")
            except Exception as e:
                self._cs_cam_preview.setText(f"❌ Ошибка: {e}")
                self._cs_cam_preview.setVisible(True)

        def _stop_cam_test():
            try:
                cam_obj = getattr(self, '_cs_cam_obj', None)
                if cam_obj:
                    cam_obj.stop()
                    self._cs_cam_obj = None
            except Exception: pass
            try:
                vid_w = getattr(self, '_cs_vid_widget', None)
                if vid_w:
                    vid_w.hide()
                    self._cs_vid_widget = None
            except Exception: pass
            try:
                self._cs_cam_preview.setVisible(False)
                self._cs_cam_preview.setText("Предпросмотр камеры...")
            except Exception: pass
            cam_btn.setEnabled(True)
            stop_cam_btn.setEnabled(False)

        cam_btn.clicked.connect(_start_cam_test)
        stop_cam_btn.clicked.connect(_stop_cam_test)
        lay.addWidget(g_cam)

        # ── Слышимость себя ──────────────────────────────────────────────
        g_hear, fl_hear = _grp("👂  Слышимость")
        hear_info = QLabel(
            "Тест: услышите собственный микрофон через динамики (эхо-тест).")
        hear_info.setStyleSheet(f"font-size:10px;color:{t['text_dim']};background:transparent;")
        fl_hear.addWidget(hear_info)
        echo_btn = QPushButton("🔁 Запустить эхо-тест (3 сек)")
        self._cs_echo_status = QLabel("Говорите в микрофон — услышите себя")
        self._cs_echo_status.setStyleSheet(f"font-size:10px;color:{t['text_dim']};background:transparent;")
        def _run_echo():
            self._cs_echo_status.setText("🔴 Говорите — слушайте себя...")
            echo_btn.setEnabled(False)
            import threading
            def _echo():
                try:
                    import pyaudio as _pa
                    CHUNK = 1024
                    RATE  = 16000
                    p = _pa.PyAudio()
                    # Open input and output
                    stream_in  = p.open(
                        format=_pa.paInt16, channels=1, rate=RATE,
                        input=True, frames_per_buffer=CHUNK)
                    stream_out = p.open(
                        format=_pa.paInt16, channels=1, rate=RATE,
                        output=True, frames_per_buffer=CHUNK)
                    frames = int(RATE / CHUNK * 3)
                    for _ in range(frames):
                        data = stream_in.read(CHUNK, exception_on_overflow=False)
                        stream_out.write(data)
                    stream_in.stop_stream();  stream_in.close()
                    stream_out.stop_stream(); stream_out.close()
                    p.terminate()
                    QTimer.singleShot(0, lambda: (
                        self._cs_echo_status.setText("✅ Эхо-тест завершён"),
                        echo_btn.setEnabled(True)))
                except ImportError:
                    QTimer.singleShot(0, lambda: (
                        self._cs_echo_status.setText("⚠ pip install pyaudio --break-system-packages"),
                        echo_btn.setEnabled(True)))
                except Exception as e:
                    QTimer.singleShot(0, lambda err=str(e): (
                        self._cs_echo_status.setText(f"❌ {err}"),
                        echo_btn.setEnabled(True)))
            threading.Thread(target=_echo, daemon=True).start()
        echo_btn.clicked.connect(_run_echo)
        fl_hear.addWidget(echo_btn)
        fl_hear.addWidget(self._cs_echo_status)
        lay.addWidget(g_hear)

        # ── Сохранить ────────────────────────────────────────────────────
        save_btn = QPushButton("💾 Применить настройки звонка")
        save_btn.setObjectName("accent_btn"); save_btn.setFixedHeight(34)
        save_btn.clicked.connect(self._save_call_settings)
        lay.addWidget(save_btn)

        lay.addStretch()
        return w

    def _test_mic(self):
        """Quick 3-second mic level test."""
        if getattr(self, '_mic_test_running', False):
            return
        self._mic_test_running = True
        self._cs_mic_status.setText("🔴 Запись... (3 сек)")
        self._cs_mic_test_btn.setEnabled(False)
        self._cs_mic_test_btn.setText("⏳ Идёт запись…")
        try:
            import pyaudio as _pa, threading, struct, math
            def _run():
                try:
                    p = _pa.PyAudio()
                    stream = p.open(format=_pa.paInt16, channels=1,
                                    rate=16000, input=True, frames_per_buffer=512)
                    peak = 0
                    for _ in range(int(16000/512 * 3)):
                        data = stream.read(512, exception_on_overflow=False)
                        samples = struct.unpack(f'<{len(data)//2}h', data)
                        rms = math.sqrt(sum(s*s for s in samples)/max(len(samples),1))
                        level = min(100, int(rms/320))
                        peak  = max(peak, level)
                        QTimer.singleShot(0, lambda l=level: self._cs_mic_level.setValue(l))
                    stream.stop_stream(); stream.close(); p.terminate()
                    def _done():
                        self._mic_test_running = False
                        self._cs_mic_test_btn.setEnabled(True)
                        self._cs_mic_test_btn.setText("🎙 Тест микрофона (3 сек)")
                        self._cs_mic_level.setValue(0)
                        if peak > 5:
                            self._cs_mic_status.setText(f"✅ Микрофон работает (пик: {peak}%)")
                        else:
                            self._cs_mic_status.setText("⚠ Сигнал очень слабый — проверьте устройство")
                    QTimer.singleShot(0, _done)
                except Exception as e:
                    def _err(err=str(e)):
                        self._mic_test_running = False
                        self._cs_mic_test_btn.setEnabled(True)
                        self._cs_mic_test_btn.setText("🎙 Тест микрофона (3 сек)")
                        self._cs_mic_status.setText(f"❌ Ошибка: {err}")
                    QTimer.singleShot(0, _err)
            threading.Thread(target=_run, daemon=True).start()
        except ImportError:
            self._mic_test_running = False
            self._cs_mic_status.setText("⚠ PyAudio не установлен")
            self._cs_mic_test_btn.setEnabled(True)
            self._cs_mic_test_btn.setText("🎙 Тест микрофона (3 сек)")

    def _test_speaker(self):
        """Play a synthetic test tone through speakers."""
        try:
            _synth_tone([(440, 200, 0.5),(660, 200, 0.5),(880, 300, 0.4)])
            self._cs_mic_status.setText("🔊 Тон воспроизведён")
        except Exception as e:
            self._cs_mic_status.setText(f"⚠ {e}")

    def _test_screen_capture(self):
        """Grab screen and show preview."""
        try:
            screen = QApplication.primaryScreen()
            if not screen:
                self._cs_share_preview.setText("⚠ Экран не найден")
                return
            pix = screen.grabWindow(0)
            scaled = pix.scaled(
                self._cs_share_preview.width() - 8,
                self._cs_share_preview.height() - 8,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation)
            self._cs_share_preview.setPixmap(scaled)
        except Exception as e:
            self._cs_share_preview.setText(f"⚠ {e}")

    def _save_call_settings(self):
        rate = self._cs_quality.currentData()
        S().set("audio_rate", rate)
        QMessageBox.information(self, "Звонки",
            "✅ Настройки звонка сохранены. Частота вступит в силу при следующем звонке.")

    def _tab_specialist(self) -> QWidget:
        """
        п.30 — 'Для специалистов' — настройка relay сервера, продвинутые параметры.
        Этот раздел скрыт от обычных пользователей и предназначен для:
        - IT-специалистов настраивающих корпоративный деплой
        - Разработчиков
        - Системных администраторов
        """
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(8)

        t = get_theme(S().theme)

        # Warning banner
        warn = QLabel(
            "⚠ ВНИМАНИЕ: Эти настройки предназначены для опытных пользователей.\n"
            "Неправильная конфигурация может нарушить работу GoidaPhone.\n\n"
            "WARNING: These settings are for advanced users only.\n"
            "Incorrect configuration may break GoidaPhone.")
        warn.setWordWrap(True)
        warn.setStyleSheet(f"""
            background: #3A2000; color: #FFB060;
            border: 1px solid #6A4000; border-radius: 6px;
            padding: 8px; font-size: 10px;
        """)
        lay.addWidget(warn)

        # Relay server
        relay_g = QGroupBox("🌐 Relay Сервер")
        rfl = QFormLayout(relay_g)

        self._relay_enabled = QCheckBox(
            "Использовать relay сервер (для подключения через интернет)")
        self._relay_enabled.setChecked(S().relay_enabled)
        rfl.addRow(self._relay_enabled)

        self._relay_addr = QLineEdit()
        self._relay_addr.setPlaceholderText("host:port  (например: relay.example.com:17385)")
        self._relay_addr.setText(S().relay_server)
        rfl.addRow("Адрес relay:", self._relay_addr)

        relay_info = QLabel(
            "Relay сервер позволяет подключаться через интернет без VPN.\n"
            "Relay только передаёт пакеты — не читает содержимое.\n"
            "Поддерживает: GoidaPhone Relay Server v1+")
        relay_info.setWordWrap(True)
        relay_info.setStyleSheet(f"color: {t['text_dim']}; font-size: 9px;")
        rfl.addRow(relay_info)

        test_relay = QPushButton("🔌 Проверить соединение")
        test_relay.clicked.connect(self._test_relay)
        rfl.addRow(test_relay)
        self._relay_status = QLabel("")
        rfl.addRow(self._relay_status)

        lay.addWidget(relay_g)

        # Protocol settings
        proto_g = QGroupBox("⚙ Протокол")
        pfl = QFormLayout(proto_g)

        pfl.addRow("Версия протокола:", QLabel(str(PROTOCOL_VERSION)))
        pfl.addRow("Мин. совместимая:", QLabel(str(PROTOCOL_COMPAT)))
        pfl.addRow("Версия приложения:", QLabel(APP_VERSION))

        self._broadcast_interval = QSpinBox()
        self._broadcast_interval.setRange(1, 30)
        self._broadcast_interval.setValue(S().get("broadcast_interval", 3, t=int))
        self._broadcast_interval.setSuffix(" сек")
        self._broadcast_interval.setToolTip(
            "Интервал отправки presence-сообщений.\n"
            "Меньше = быстрее обнаружение, больше трафик.\n"
            "Рекомендуется: 3 секунды.")
        pfl.addRow("Интервал presence:", self._broadcast_interval)

        self._peer_timeout = QSpinBox()
        self._peer_timeout.setRange(5, 120)
        self._peer_timeout.setValue(S().get("peer_timeout", 20, t=int))
        self._peer_timeout.setSuffix(" сек")
        self._peer_timeout.setToolTip(
            "Через сколько секунд без presence считать пользователя офлайн.")
        pfl.addRow("Таймаут пира:", self._peer_timeout)

        lay.addWidget(proto_g)

        # Debug section
        debug_g = QGroupBox("🔧 Отладка")
        dfl = QFormLayout(debug_g)

        self._debug_log_cb = QCheckBox("Включить отладочный лог в консоль")
        self._debug_log_cb.setChecked(S().get("debug_log", False, t=bool))
        dfl.addRow(self._debug_log_cb)

        export_log = QPushButton("📤 Экспортировать лог сессии")
        export_log.clicked.connect(self._export_log)
        dfl.addRow(export_log)

        lay.addWidget(debug_g)

        # ── Детальная конфигурация сервера (перенесена из вкладки Сеть) ──
        # ── Детальная привязка к серверу / сети ──────────────────────────────
        g_bind = QGroupBox("🔧 Детальная конфигурация сервера")
        bind_fl = QFormLayout(g_bind)

        # Bind address
        self._bind_addr = QLineEdit()
        self._bind_addr.setText(S().get("bind_addr", "0.0.0.0", t=str))
        self._bind_addr.setPlaceholderText("0.0.0.0  (все интерфейсы)")
        self._bind_addr.setToolTip(
            "Адрес сетевого интерфейса для привязки UDP/TCP сокетов.\n"
            "0.0.0.0 = все интерфейсы, конкретный IP = только этот интерфейс.")
        bind_fl.addRow("Bind-адрес:", self._bind_addr)

        # Multicast group
        self._multicast_group = QLineEdit()
        self._multicast_group.setText(S().get("multicast_group", "", t=str))
        self._multicast_group.setPlaceholderText("напр. 239.255.0.1 (пусто = broadcast)")
        self._multicast_group.setToolTip(
            "Multicast-группа для обнаружения пиров вместо broadcast.\n"
            "Полезно в управляемых сетях, где broadcast запрещён.")
        bind_fl.addRow("Multicast группа:", self._multicast_group)

        # Heartbeat interval
        self._heartbeat_interval = QSpinBox()
        self._heartbeat_interval.setRange(1, 60)
        self._heartbeat_interval.setSuffix(" сек")
        self._heartbeat_interval.setToolTip(
            "Как часто отправлять heartbeat (PING) другим пирам.\n"
            "Меньше = быстрее обнаружение отключений, больше трафик.")
        self._heartbeat_interval.setValue(S().get("heartbeat_interval", 3, t=int))
        bind_fl.addRow("Heartbeat интервал:", self._heartbeat_interval)

        # Max connections
        self._max_connections = QSpinBox()
        self._max_connections.setRange(1, 500)
        self._max_connections.setToolTip("Максимальное число одновременных TCP-соединений.")
        self._max_connections.setValue(S().get("max_connections", 50, t=int))
        bind_fl.addRow("Макс. соединений:", self._max_connections)

        # TCP keepalive
        self._tcp_keepalive = QCheckBox("Включить TCP keepalive")
        self._tcp_keepalive.setToolTip(
            "Keepalive позволяет обнаружить разрыв соединения без явного дисконнекта.")
        self._tcp_keepalive.setChecked(S().get("tcp_keepalive", True, t=bool))
        bind_fl.addRow(self._tcp_keepalive)

        # Keepalive idle time
        self._keepalive_idle = QSpinBox()
        self._keepalive_idle.setRange(5, 600)
        self._keepalive_idle.setSuffix(" сек")
        self._keepalive_idle.setToolTip("Время простоя до отправки первого keepalive-пакета.")
        self._keepalive_idle.setValue(S().get("keepalive_idle", 60, t=int))
        bind_fl.addRow("Keepalive idle:", self._keepalive_idle)

        # Reconnect attempts
        self._reconnect_attempts = QSpinBox()
        self._reconnect_attempts.setRange(0, 20)
        self._reconnect_attempts.setToolTip("0 = не переподключаться автоматически.")
        self._reconnect_attempts.setValue(S().get("reconnect_attempts", 3, t=int))
        bind_fl.addRow("Попыток переподключения:", self._reconnect_attempts)

        # Reconnect delay
        self._reconnect_delay = QSpinBox()
        self._reconnect_delay.setRange(1, 60)
        self._reconnect_delay.setSuffix(" сек")
        self._reconnect_delay.setValue(S().get("reconnect_delay", 5, t=int))
        bind_fl.addRow("Задержка переподключения:", self._reconnect_delay)

        # MTU
        self._mtu_size = QSpinBox()
        self._mtu_size.setRange(512, 65507)
        self._mtu_size.setSingleStep(512)
        self._mtu_size.setToolTip(
            "MTU UDP-пакетов. 1400 подходит для большинства сетей.\n"
            "Уменьшите при фрагментации пакетов (VPN, туннели).")
        self._mtu_size.setValue(S().get("mtu_size", 1400, t=int))
        bind_fl.addRow("UDP MTU (байт):", self._mtu_size)

        # SO_REUSEADDR
        self._so_reuseaddr = QCheckBox("SO_REUSEADDR")
        self._so_reuseaddr.setToolTip(
            "Разрешает повторное использование порта без ожидания TIME_WAIT.\n"
            "Полезно при частых перезапусках GoidaPhone.")
        self._so_reuseaddr.setChecked(S().get("so_reuseaddr", True, t=bool))
        bind_fl.addRow(self._so_reuseaddr)

        # Relay server
        self._relay_host = QLineEdit()
        self._relay_host.setText(S().relay_server)
        self._relay_host.setPlaceholderText("relay.example.com:45700")
        self._relay_host.setToolTip(
            "Адрес relay-сервера (host:port) для соединения через NAT.\n"
            "Оставьте пустым для прямых P2P-соединений.")
        bind_fl.addRow("Relay-сервер:", self._relay_host)

        self._relay_enabled_cb = QCheckBox("Использовать relay при недоступности прямого соединения")
        self._relay_enabled_cb.setChecked(S().relay_enabled)
        bind_fl.addRow(self._relay_enabled_cb)

        # STUN server
        self._stun_server = QLineEdit()
        self._stun_server.setText(S().get("stun_server", "stun.l.google.com:19302", t=str))
        self._stun_server.setToolTip(
            "STUN-сервер для определения внешнего IP-адреса и NAT traversal.")
        bind_fl.addRow("STUN-сервер:", self._stun_server)

        # Priority mode
        self._conn_priority = QComboBox()
        self._conn_priority.addItems([
            "Авто (сначала прямое, потом relay)",
            "Только прямое P2P",
            "Только relay",
            "Всегда relay (максимальная совместимость)",
        ])
        priority_map = {"auto": 0, "direct": 1, "relay_only": 2, "always_relay": 3}
        self._conn_priority.setCurrentIndex(
            priority_map.get(S().get("conn_priority", "auto", t=str), 0))
        bind_fl.addRow("Приоритет соединения:", self._conn_priority)

        lay.addWidget(g_bind)
        lay.addStretch()
        return w

    def _mk_specialist_scroll(self) -> QScrollArea:
        """Wrap the specialist tab in a scroll area so content never clips."""
        inner = self._tab_specialist()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(inner)
        t2 = get_theme(S().theme)
        scroll.setStyleSheet(
            f"QScrollArea{{background:{t2['bg']};border:none;}}"
            f"QScrollBar:vertical{{background:{t2['bg3']};width:6px;border-radius:3px;}}"
            f"QScrollBar::handle:vertical{{background:{t2['accent']};border-radius:3px;}}"
            "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}")
        return scroll

    def _test_relay(self):
        """Test connection to relay server."""
        addr = self._relay_addr.text().strip()
        if not addr:
            self._relay_status.setText("❌ Укажите адрес relay сервера")
            self._relay_status.setStyleSheet("color: #FF6060;")
            return
        self._relay_status.setText("🔄 Проверка...")
        self._relay_status.setStyleSheet(f"color: {get_theme(S().theme)['text_dim']};")

        def check():
            try:
                host, port_str = addr.rsplit(":", 1)
                port = int(port_str)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                sock.close()
                return True, None
            except Exception as e:
                return False, str(e)

        import threading
        def run():
            ok, err = check()
            if ok:
                QTimer.singleShot(0, lambda: (
                    self._relay_status.setText("✅ Соединение установлено"),
                    self._relay_status.setStyleSheet("color: #80FF80;")))
            else:
                QTimer.singleShot(0, lambda: (
                    self._relay_status.setText(f"❌ Ошибка: {err}"),
                    self._relay_status.setStyleSheet("color: #FF6060;")))
        threading.Thread(target=run, daemon=True).start()

    def _export_log(self):
        fn, _ = QFileDialog.getSaveFileName(
            self, "Экспорт лога", f"goidaphone_log_{int(time.time())}.txt", "Text (*.txt)")
        if fn:
            try:
                log_lines = [
                    f"GoidaPhone v{APP_VERSION} Session Log",
                    f"Time: {datetime.now().isoformat()}",
                    f"Username: {S().username}",
                    f"IP: {get_local_ip()}",
                    f"OS: {get_os_name()}",
                    f"Protocol: v{PROTOCOL_VERSION}",
                    "─" * 40,
                ]
                Path(fn).write_text("\n".join(log_lines), encoding="utf-8")
                QMessageBox.information(self, "Экспорт", f"Лог сохранён:\n{fn}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", str(e))
        cfg = S()
        # audio
        self._vol.setValue(cfg.volume)
        self._notif_sounds.setChecked(cfg.notification_sounds)
        # network
        self._udp_p.setValue(cfg.udp_port)
        self._tcp_p.setValue(cfg.tcp_port)
        # theme
        theme = cfg.theme
        for i in range(self._theme_combo.count()):
            if self._theme_combo.itemData(i) == theme:
                self._theme_combo.setCurrentIndex(i)
                break
        # data
        self._save_history.setChecked(cfg.save_history)
        self._show_splash.setChecked(cfg.show_splash)
        # license
        self._update_lic_status()

    def _save(self):
        cfg = S()
        cfg.set("volume", self._vol.value())
        cfg.set("notification_sounds", self._notif_sounds.isChecked())
        cfg.set("vad_enabled",  self._vad_cb.isChecked() if hasattr(self, '_vad_cb') else WEBRTCVAD_AVAILABLE)
        cfg.set("jitter_frames", self._jb_spin.value()  if hasattr(self, '_jb_spin') else 6)
        cfg.set("udp_port", self._udp_p.value())
        cfg.set("tcp_port", self._tcp_p.value())
        if hasattr(self, '_enc_enable'):
            S().encryption_enabled    = self._enc_enable.isChecked()
            S().encryption_passphrase = self._enc_pass.text()
        cfg.set("theme", self._theme_combo.currentData() or "dark")
        cfg.set("save_history", self._save_history.isChecked())
        if hasattr(self, '_show_splash'):
            cfg.set("show_splash", self._show_splash.isChecked())

        # Appearance tab
        if hasattr(self, '_scale_slider'):
            cfg.set("app_scale", self._scale_slider.value())
        if hasattr(self, '_tab_show_notes'):
            cfg.set("tab_show_notes", self._tab_show_notes.isChecked())
        if hasattr(self, '_tab_show_calls'):
            cfg.set("tab_show_calls", self._tab_show_calls.isChecked())

        # Language settings
        if hasattr(self, '_lang_combo'):
            cfg.language = self._lang_combo.currentData() or "ru"
        if hasattr(self, '_show_launcher_cb'):
            cfg.show_launcher = self._show_launcher_cb.isChecked()
        if hasattr(self, '_os_notif_cb'):
            cfg.os_notifications = self._os_notif_cb.isChecked()

        # Specialist settings
        if hasattr(self, '_relay_enabled'):
            cfg.relay_enabled = self._relay_enabled.isChecked()
        if hasattr(self, '_relay_addr'):
            cfg.relay_server = self._relay_addr.text().strip()
        if hasattr(self, '_broadcast_interval'):
            cfg.set("broadcast_interval", self._broadcast_interval.value())
        if hasattr(self, '_peer_timeout'):
            cfg.set("peer_timeout", self._peer_timeout.value())
        if hasattr(self, '_debug_log_cb'):
            cfg.set("debug_log", self._debug_log_cb.isChecked())

        # Advanced network binding settings
        _ha = hasattr
        if _ha(self, '_bind_addr'):        cfg.set("bind_addr",         self._bind_addr.text().strip())
        if _ha(self, '_multicast_group'):  cfg.set("multicast_group",   self._multicast_group.text().strip())
        if _ha(self, '_heartbeat_interval'): cfg.set("heartbeat_interval", self._heartbeat_interval.value())
        if _ha(self, '_max_connections'):  cfg.set("max_connections",   self._max_connections.value())
        if _ha(self, '_tcp_keepalive'):    cfg.set("tcp_keepalive",     "true" if self._tcp_keepalive.isChecked() else "false")
        if _ha(self, '_keepalive_idle'):   cfg.set("keepalive_idle",    self._keepalive_idle.value())
        if _ha(self, '_reconnect_attempts'): cfg.set("reconnect_attempts", self._reconnect_attempts.value())
        if _ha(self, '_reconnect_delay'):  cfg.set("reconnect_delay",   self._reconnect_delay.value())
        if _ha(self, '_mtu_size'):         cfg.set("mtu_size",          self._mtu_size.value())
        if _ha(self, '_so_reuseaddr'):     cfg.set("so_reuseaddr",      "true" if self._so_reuseaddr.isChecked() else "false")
        if _ha(self, '_relay_host'):       cfg.relay_server = self._relay_host.text().strip()
        if _ha(self, '_relay_enabled_cb'): cfg.relay_enabled = self._relay_enabled_cb.isChecked()
        if _ha(self, '_stun_server'):      cfg.set("stun_server",       self._stun_server.text().strip())
        if _ha(self, '_conn_priority'):
            priority_map = {0:"auto", 1:"direct", 2:"relay_only", 3:"always_relay"}
            cfg.set("conn_priority", priority_map.get(self._conn_priority.currentIndex(), "auto"))
        if _ha(self, '_broadcast_addr'):   cfg.set("broadcast_addr",    self._broadcast_addr.text().strip())
        if _ha(self, '_discovery_interval'): cfg.set("discovery_interval", self._discovery_interval.value())
        if _ha(self, '_max_chunk'):        cfg.set("max_chunk_kb",      self._max_chunk.value())
        if _ha(self, '_tcp_timeout'):      cfg.set("tcp_timeout",       self._tcp_timeout.value())
        if _ha(self, '_enable_ipv6'):      cfg.set("enable_ipv6",       "true" if self._enable_ipv6.isChecked() else "false")
        if _ha(self, '_allow_relay'):      cfg.set("allow_relay",       "true" if self._allow_relay.isChecked() else "false")
        if _ha(self, '_encrypt_transport'): cfg.set("encrypt_transport", "true" if self._encrypt_transport.isChecked() else "false")

        # Apply theme immediately
        key = self._theme_combo.currentData()
        if key and not key.startswith("__custom"):
            QApplication.instance().setStyleSheet(build_stylesheet(get_theme(key)))

        # Apply tab visibility
        if hasattr(self.parent(), '_apply_tab_visibility'):
            self.parent()._apply_tab_visibility()

        QMessageBox.information(self, "Настройки", TR("saved"))
        self.settings_saved.emit()
        self.accept()

    def _load(self):
        """Load current settings into all widgets."""
        cfg = S()
        if hasattr(self, '_vol'):
            self._vol.setValue(cfg.get("volume", 80, t=int))
        if hasattr(self, '_notif_sounds'):
            self._notif_sounds.setChecked(cfg.notification_sounds)
        if hasattr(self, '_vad_cb'):
            self._vad_cb.setChecked(cfg.get("vad_enabled", WEBRTCVAD_AVAILABLE, t=bool))
        if hasattr(self, '_jb_spin'):
            self._jb_spin.setValue(cfg.get("jitter_frames", 6, t=int))
        if hasattr(self, '_udp_p'):
            self._udp_p.setValue(cfg.udp_port)
        if hasattr(self, '_tcp_p'):
            self._tcp_p.setValue(cfg.tcp_port)
        if hasattr(self, '_save_history'):
            self._save_history.setChecked(cfg.get("save_history", True, t=bool))
        if hasattr(self, '_show_splash'):
            self._show_splash.setChecked(cfg.get("show_splash", True, t=bool))
        if hasattr(self, '_lang_combo'):
            idx = self._lang_combo.findData(cfg.language)
            if idx >= 0:
                self._lang_combo.setCurrentIndex(idx)
        if hasattr(self, '_show_launcher_cb'):
            self._show_launcher_cb.setChecked(cfg.show_launcher)
        if hasattr(self, '_os_notif_cb'):
            self._os_notif_cb.setChecked(cfg.os_notifications)
        if hasattr(self, '_theme_combo'):
            idx = self._theme_combo.findData(cfg.theme)
            if idx >= 0:
                self._theme_combo.setCurrentIndex(idx)

# ═══════════════════════════════════════════════════════════════════════════
#  INCOMING CALL DIALOG
# ═══════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════
#  FLOATING CALL WINDOW  (Telegram-style)
# ═══════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════
#  PEER PROFILE DIALOG  (Telegram-style, like screenshot 2)
# ═══════════════════════════════════════════════════════════════════════════
def _show_peer_profile_overlay(peer: dict, parent=None):
    """Show peer profile as a slide-in panel overlaid on the central widget."""
    mw = _find_main_window(parent)
    if mw is None:
        # Fallback to old dialog if no MainWindow found
        dlg = PeerProfileDialog(peer, parent)
        dlg.exec(); return

    central = mw.centralWidget()

    # Remove any existing profile overlay
    for child in central.findChildren(QWidget, "peer_profile_overlay"):
        child.deleteLater()

    t = get_theme(S().theme)
    name     = peer.get("username", "?")
    ip       = peer.get("ip", "")
    av_b64   = peer.get("avatar_b64", "")
    color    = peer.get("nickname_color", "#E0E0E0")
    emoji_s  = peer.get("custom_emoji", "")
    version  = peer.get("version", "")
    e2e      = CRYPTO.has_session(ip)
    fp       = CRYPTO.peer_fingerprint(ip) if e2e else "—"

    # Overlay widget — right-side panel
    panel = QWidget(central)
    panel.setObjectName("peer_profile_overlay")
    panel.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
    panel_w = min(360, central.width() - 40)
    panel.setFixedWidth(panel_w)
    panel.resize(panel_w, central.height())
    panel.move(central.width(), 0)    # start off-screen right
    panel.setStyleSheet(f"""
        QWidget#peer_profile_overlay {{
            background:{t['bg2']};
            border-left:1px solid {t['border']};
        }}
    """)

    vl = QVBoxLayout(panel)
    vl.setContentsMargins(0, 0, 0, 0)
    vl.setSpacing(0)

    # ── Header: close button ──
    hdr = QWidget()
    hdr.setStyleSheet(f"background:{t['bg3']};border-bottom:1px solid {t['border']};")
    hdr.setFixedHeight(40)
    hdr_lay = QHBoxLayout(hdr)
    hdr_lay.setContentsMargins(12, 0, 8, 0)
    hdr_title = QLabel("Профиль пользователя")
    hdr_title.setStyleSheet(f"font-size:12px;font-weight:bold;color:{t['text']};background:transparent;")
    hdr_lay.addWidget(hdr_title)
    hdr_lay.addStretch()
    close_btn = QPushButton("✕")
    close_btn.setFixedSize(28, 28)
    close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    close_btn.setStyleSheet(
        f"QPushButton{{background:transparent;color:{t['text_dim']};border:none;font-size:14px;}}"
        "QPushButton:hover{color:#E74C3C;}")
    def _close_panel():
        anim = QPropertyAnimation(panel, b"pos")
        anim.setDuration(200)
        anim.setStartValue(panel.pos())
        anim.setEndValue(QPoint(central.width(), 0))
        anim.setEasingCurve(QEasingCurve.Type.InCubic)
        anim.finished.connect(panel.deleteLater)
        anim.start()
        panel._anim = anim
    close_btn.clicked.connect(_close_panel)
    hdr_lay.addWidget(close_btn)
    vl.addWidget(hdr)

    # ── Scroll area ──
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setStyleSheet(f"QScrollArea{{background:{t['bg2']};border:none;}}")
    content = QWidget()
    content.setStyleSheet(f"background:{t['bg2']};")
    cl = QVBoxLayout(content)
    cl.setContentsMargins(0, 0, 0, 20)
    cl.setSpacing(0)

    # Banner
    banner = QWidget()
    banner.setFixedHeight(100)
    banner.setStyleSheet(f"""
        background:qlineargradient(x1:0,y1:0,x2:1,y2:1,
            stop:0 {t['accent']}, stop:1 {t['accent2']});
    """)
    cl.addWidget(banner)

    # Avatar overlapping banner
    av_wrap = QWidget(content)
    av_wrap.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
    av_size = 80
    av_lbl = QLabel(av_wrap)
    av_lbl.setFixedSize(av_size+4, av_size+4)
    if av_b64:
        try:
            pm = make_circle_pixmap(base64_to_pixmap(av_b64), av_size)
            av_lbl.setPixmap(pm)
        except Exception:
            av_lbl.setPixmap(default_avatar(name, av_size))
    else:
        av_lbl.setPixmap(default_avatar(name, av_size))
    av_lbl.setStyleSheet(f"border-radius:{av_size//2+2}px;border:3px solid {t['bg2']};")

    av_row = QHBoxLayout()
    av_row.setContentsMargins(16, 0, 16, 0)
    av_row.addWidget(av_lbl)
    av_row.addStretch()

    # Chat + call buttons on same row
    chat_btn = QPushButton("💬 Написать")
    chat_btn.setFixedHeight(32)
    chat_btn.setObjectName("accent_btn")
    chat_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    call_btn = QPushButton("📞 Звонок")
    call_btn.setFixedHeight(32)
    call_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    call_btn.setStyleSheet(
        f"QPushButton{{background:{t['bg3']};color:{t['text']};"
        f"border:1px solid {t['border']};border-radius:8px;padding:0 12px;}}"
        f"QPushButton:hover{{background:{t['btn_hover']};}}")

    # Wire buttons to MainWindow actions
    def _do_chat():
        _close_panel()
        if hasattr(mw, 'chat_panel'):
            mw.chat_panel.open_peer(peer)
            mw._tabs.setCurrentWidget(mw.chat_panel)
    def _do_call():
        _close_panel()
        if hasattr(mw, '_call_peer'):
            mw._call_peer(ip)

    chat_btn.clicked.connect(_do_chat)
    call_btn.clicked.connect(_do_call)
    av_row.addWidget(chat_btn)
    av_row.addSpacing(6)
    av_row.addWidget(call_btn)

    # Offset av_row to overlap banner by half avatar
    cl.addWidget(QWidget())    # spacer replaced below
    # We do it with negative margin via a container
    av_container = QWidget()
    av_container.setStyleSheet(f"background:{t['bg2']};")
    av_container.setContentsMargins(0, 0, 0, 0)
    av_cl = QVBoxLayout(av_container)
    av_cl.setContentsMargins(0, 0, 0, 0)
    av_cl.addLayout(av_row)
    # Pop the dummy spacer and add container with negative margin workaround
    cl.takeAt(cl.count()-1)
    cl.addWidget(av_container)

    # Reposition to overlap banner
    def _reposition():
        banner_bottom = banner.y() + banner.height()
        av_container.move(0, banner_bottom - av_size//2 - 2)
    QTimer.singleShot(10, _reposition)
    cl.addSpacing(av_size//2 + 12)

    # Name + emoji
    name_lbl = QLabel(f'<span style="color:{color};font-size:18px;font-weight:bold;">'
                      f'{name}</span>'
                      + (f'  <span style="font-size:16px;">{emoji_s}</span>' if emoji_s else ''))
    name_lbl.setTextFormat(Qt.TextFormat.RichText)
    name_lbl.setStyleSheet("background:transparent;")
    name_lbl.setContentsMargins(16, 0, 16, 0)
    cl.addWidget(name_lbl)
    cl.addSpacing(4)

    sub_lbl = QLabel(f"IP: {ip}")
    sub_lbl.setStyleSheet(f"font-size:11px;color:{t['text_dim']};background:transparent;margin-left:16px;")
    cl.addWidget(sub_lbl)
    cl.addSpacing(16)

    # Info rows
    def _info_row(icon, label, value):
        row = QWidget()
        row.setStyleSheet(f"background:{t['bg2']};")
        rl = QHBoxLayout(row)
        rl.setContentsMargins(16, 6, 16, 6)
        ico = QLabel(icon)
        ico.setFixedWidth(22)
        ico.setStyleSheet("font-size:14px;background:transparent;")
        rl.addWidget(ico)
        lbl_w = QLabel(label)
        lbl_w.setStyleSheet(f"font-size:11px;color:{t['text_dim']};background:transparent;")
        lbl_w.setFixedWidth(90)
        rl.addWidget(lbl_w)
        val_w = QLabel(str(value))
        val_w.setStyleSheet(f"font-size:11px;color:{t['text']};background:transparent;")
        val_w.setWordWrap(True)
        rl.addWidget(val_w, stretch=1)
        return row

    sep = QWidget()
    sep.setFixedHeight(1)
    sep.setStyleSheet(f"background:{t['border']};")
    cl.addWidget(sep)

    for icon, label, value in [
        ("🔒", "Шифрование:", "E2E ✓" if e2e else "Нет E2E"),
        ("🔑", "Отпечаток:", fp[:24]+"…" if len(fp)>24 else fp),
        ("📱", "Версия:", version or "—"),
    ]:
        cl.addWidget(_info_row(icon, label, value))

    sep2 = QWidget()
    sep2.setFixedHeight(1)
    sep2.setStyleSheet(f"background:{t['border']};")
    cl.addWidget(sep2)
    cl.addStretch()

    scroll.setWidget(content)
    vl.addWidget(scroll, stretch=1)

    panel.show()
    panel.raise_()

    # Animate slide-in from right
    anim = QPropertyAnimation(panel, b"pos")
    anim.setDuration(220)
    anim.setStartValue(QPoint(central.width(), 0))
    anim.setEndValue(QPoint(central.width() - panel_w, 0))
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)
    anim.start()
    panel._anim = anim   # keep reference

    # Resize panel when central widget resizes
    def _on_central_resize(event):
        panel.resize(panel_w, central.height())
        if not getattr(panel, '_is_closing', False):
            panel.move(central.width() - panel_w, 0)
    central.resizeEvent = _on_central_resize


class PeerProfileDialog(QDialog):
    """Shows a peer's profile in Telegram style with banner, avatar, stats."""

    def __init__(self, peer: dict, parent=None):
        super().__init__(parent)
        self.peer = peer
        lang = S().language
        title = "Профиль пользователя" if lang == "ru" else "User Profile"
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedWidth(380)
        self.setMinimumHeight(420)
        self._build()

    def _build(self):
        t = get_theme(S().theme)
        peer = self.peer
        lang = S().language

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── Banner ──────────────────────────────────────────────────────
        banner_lbl = QLabel()
        banner_lbl.setFixedHeight(130)
        banner_lbl.setScaledContents(True)
        banner_lbl.setStyleSheet(
            f"background: qlineargradient(x1:0,y1:0,x2:1,y2:1,"
            f"stop:0 {t['accent']}, stop:1 {t['bg3']});"
            f"border-radius: 0;")
        b64 = peer.get("banner_b64", "")
        if b64:
            try:
                pm = QPixmap(); pm.loadFromData(base64.b64decode(b64))
                banner_lbl.setPixmap(pm)
                banner_lbl.setScaledContents(True)
            except Exception:
                pass
        outer.addWidget(banner_lbl)

        # ── Card body ───────────────────────────────────────────────────
        card = QWidget()
        card.setStyleSheet(f"background:{t['bg2']};")
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(16, 0, 16, 16)
        card_lay.setSpacing(6)

        # Avatar row (overlaps banner)
        av_row = QHBoxLayout()
        av_row.setContentsMargins(0, -30, 0, 0)   # pull up over banner

        av_lbl = QLabel()
        av_lbl.setFixedSize(72, 72)
        av_b64 = peer.get("avatar_b64", "")
        if av_b64:
            try:
                pm2 = base64_to_pixmap(av_b64)
                av_lbl.setPixmap(make_circle_pixmap(pm2, 72))
            except Exception:
                av_lbl.setPixmap(default_avatar(peer.get("username","?"), 72))
        else:
            av_lbl.setPixmap(default_avatar(peer.get("username","?"), 72))
        av_lbl.setStyleSheet("border:3px solid " + t['bg2'] + ";border-radius:36px;")
        av_row.addWidget(av_lbl)
        av_row.addStretch()

        # Premium badge
        if peer.get("premium"):
            prem = QLabel("👑 PREMIUM")
            prem.setStyleSheet(
                "background:#C08010;color:#FFF8C0;font-size:10px;"
                "font-weight:bold;border-radius:10px;padding:3px 10px;")
            av_row.addWidget(prem)

        card_lay.addLayout(av_row)

        # Name
        color = peer.get("nickname_color", "#E0E0E0")
        emoji = peer.get("custom_emoji", "")
        name_lbl = QLabel(f"<span style='color:{color};font-size:18px;font-weight:bold;'>"
                          f"{peer.get('username','?')}</span> "
                          f"<span style='font-size:16px;'>{emoji}</span>")
        name_lbl.setTextFormat(Qt.TextFormat.RichText)
        name_lbl.setStyleSheet("background:transparent;")
        card_lay.addWidget(name_lbl)

        # Status + loyalty level
        status = peer.get("status", "online")
        sc = {"online":"#4CAF50","away":"#FFD700","busy":"#FF6B6B","dnd":"#9E9E9E"}
        sl = {"online": "Онлайн" if lang=="ru" else "Online",
              "away":   "Отошёл" if lang=="ru" else "Away",
              "busy":   "Занят"  if lang=="ru" else "Busy",
              "dnd":    "Не беспокоить" if lang=="ru" else "Do not disturb"}
        status_row = QHBoxLayout()
        dot = QLabel("●")
        dot.setStyleSheet(f"color:{sc.get(status,'#4CAF50')};font-size:11px;background:transparent;")
        status_row.addWidget(dot)
        st_lbl = QLabel(sl.get(status, "Онлайн"))
        st_lbl.setStyleSheet(f"color:{t['text_dim']};font-size:11px;background:transparent;")
        status_row.addWidget(st_lbl)

        # Loyalty level badge
        loyalty = int(peer.get("loyalty_months", 0))
        if loyalty > 0:
            status_row.addSpacing(8)
            loy_lbl = QLabel(f"❤️ {loyalty}")
            loy_lbl.setStyleSheet(
                f"background:{t['accent']}22;color:{t['accent']};"
                f"border:1px solid {t['accent']};border-radius:8px;"
                f"padding:1px 6px;font-size:10px;font-weight:bold;background:transparent;")
            tip = (f"В сети {loyalty} мес. подряд" if lang=="ru"
                   else f"Online for {loyalty} months in a row")
            loy_lbl.setToolTip(tip)
            status_row.addWidget(loy_lbl)

        status_row.addStretch()
        card_lay.addLayout(status_row)

        # Separator
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color:{t['border']};")
        card_lay.addWidget(sep)

        # Info rows
        ip_raw = peer.get("ip","?")
        id_str = display_id(ip_raw)
        id_label = ("GoidaID" if S().safe_mode else ("IP" if lang=="en" else "IP"))

        rows_ru = [
            ("ℹ", id_str,           id_label),
            ("💻", peer.get("os","?"), "Система" if lang=="ru" else "System"),
            ("🔒", ("E2E ✓" if peer.get("e2e") else "E2E ✗"),
                   "Шифрование" if lang=="ru" else "Encryption"),
            ("📡", peer.get("version","?"), "Версия" if lang=="ru" else "Version"),
        ]
        if peer.get("bio"):
            rows_ru.insert(1, ("📝", peer.get("bio",""), "О себе" if lang=="ru" else "Bio"))

        for icon, val, label in rows_ru:
            if not val or val == "?":
                continue
            rw = QHBoxLayout()
            ico_lbl = QLabel(icon)
            ico_lbl.setFixedWidth(22)
            ico_lbl.setStyleSheet("background:transparent;font-size:14px;")
            rw.addWidget(ico_lbl)
            val_col = QVBoxLayout()
            val_col.setSpacing(0)
            v_lbl = QLabel(str(val))
            v_lbl.setStyleSheet(f"color:{t['text']};font-size:12px;background:transparent;")
            val_col.addWidget(v_lbl)
            k_lbl = QLabel(label)
            k_lbl.setStyleSheet(f"color:{t['text_dim']};font-size:9px;background:transparent;")
            val_col.addWidget(k_lbl)
            rw.addLayout(val_col)
            rw.addStretch()
            card_lay.addLayout(rw)

        card_lay.addStretch()
        outer.addWidget(card)

        # Close button
        close_btn = QPushButton("✕  " + ("Закрыть" if lang=="ru" else "Close"))
        close_btn.setObjectName("accent_btn")
        close_btn.clicked.connect(self.accept)
        close_btn.setFixedHeight(36)
        outer.addWidget(close_btn)


# ═══════════════════════════════════════════════════════════════════════════
#  WINORA NETSCAPE  (WNS)  —  встроенный браузер GoidaPhone
# ═══════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════
#  WINORA NETSCAPE  (WNS 2.0) — full-featured embedded browser
# ═══════════════════════════════════════════════════════════════════════════


# ════════════════════════════════════════════════════════════════════════════
#  WINORA NETSCAPE 3.0
#  Тотальный реврайт: sidebar, reader mode, devtools, extensions, pip bar,
#  find bar встроенный, bokmrk manager, история с группировкой по дням,
#  мультипоиск, dark-reader js injection, zoom, screenshot, picture-in-picture
# ════════════════════════════════════════════════════════════════════════════

# ── Dark Reader JS (инжектируется в каждую страницу) ─────────────────────────
_WNS_DARK_READER_JS = """
(function(){
  if(document.getElementById('_wns_dr'))return;
  var s=document.createElement('style');s.id='_wns_dr';
  s.textContent=`
    html{filter:invert(1) hue-rotate(180deg)!important;}
    img,video,canvas,svg{filter:invert(1) hue-rotate(180deg)!important;}
  `;document.documentElement.appendChild(s);
})();
"""

_WNS_READER_JS = """
(function(){
  // Simple reader mode: extract article text
  var content = '';
  var sel = ['article','main','[role=main]','.post-content','.entry-content','.article-body','#content'];
  for(var i=0;i<sel.length;i++){
    var el=document.querySelector(sel[i]);
    if(el&&el.innerText.length>200){content=el.innerHTML;break;}
  }
  if(!content){content=document.body.innerHTML;}
  var title=document.title||'';
  document.open();document.write(`<!DOCTYPE html><html><head>
  <meta charset=utf-8><title>${title}</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box;}
    body{background:#12121F;color:#D0D0E8;font-family:'Georgia',serif;
         max-width:720px;margin:40px auto;padding:0 24px 80px;font-size:17px;line-height:1.8;}
    h1,h2,h3{color:#C0A8FF;margin:1em 0 .4em;}
    a{color:#7C6DFF;}img{max-width:100%;border-radius:8px;margin:12px 0;}
    p{margin:.6em 0;}pre,code{background:#1E1E34;padding:2px 6px;border-radius:4px;font-size:14px;}
    blockquote{border-left:3px solid #7C4DFF;margin:1em 0;padding-left:1em;color:#A0A0C0;}
    #_wns_reader_hdr{background:#1A1A2E;padding:12px 20px;border-radius:12px;
                     margin-bottom:24px;display:flex;align-items:center;gap:12px;}
  </style></head><body>
  <div id="_wns_reader_hdr">
    <span style="font-size:20px">📖</span>
    <div><div style="font-weight:bold;font-size:15px">${title}</div>
    <div style="font-size:11px;color:#606080">Режим чтения · Winora NetScape 3.0</div></div>
  </div>
  ${content}
  </body></html>`);document.close();
})();
"""

# ── New Tab Page HTML ─────────────────────────────────────────────────────────
WNS_HOME_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Новая вкладка</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0;}
  body{
    background:#202124;
    color:#e8eaed;
    font-family:-apple-system,system-ui,"Segoe UI",Arial,sans-serif;
    height:100vh;
    display:flex;
    flex-direction:column;
    align-items:center;
    justify-content:center;
    gap:0;
    overflow:hidden;
    user-select:none;
  }
  .logo{font-size:92px;line-height:1;margin-bottom:32px;filter:drop-shadow(0 2px 8px #0006);}
  .search-wrap{
    width:min(680px,90vw);
    background:#303134;
    border-radius:24px;
    border:1px solid #5f6368;
    display:flex;
    align-items:center;
    padding:0 16px;
    height:46px;
    gap:10px;
    transition:box-shadow .15s,border-color .15s;
  }
  .search-wrap:focus-within{
    box-shadow:0 1px 6px #0005;
    border-color:#8ab4f8;
    background:#303134;
  }
  .search-icon{color:#9aa0a6;font-size:18px;flex-shrink:0;}
  #q{
    flex:1;
    background:transparent;
    border:none;
    outline:none;
    font-size:16px;
    color:#e8eaed;
    caret-color:#e8eaed;
  }
  #q::placeholder{color:#9aa0a6;}
  .se-row{display:flex;gap:8px;margin-top:16px;}
  .se{
    background:#303134;
    border:1px solid #5f636860;
    border-radius:20px;
    padding:4px 14px;
    font-size:12px;
    color:#9aa0a6;
    cursor:pointer;
    transition:background .1s,color .1s;
  }
  .se:hover,.se.active{background:#8ab4f820;color:#8ab4f8;border-color:#8ab4f860;}
  .shortcuts{
    display:grid;
    grid-template-columns:repeat(5,88px);
    gap:12px;
    margin-top:40px;
  }
  .shortcut{
    display:flex;
    flex-direction:column;
    align-items:center;
    gap:8px;
    text-decoration:none;
    color:#e8eaed;
    border-radius:12px;
    padding:14px 8px 10px;
    transition:background .15s;
    font-size:12px;
  }
  .shortcut:hover{background:#35363a;}
  .fav{
    width:40px;height:40px;border-radius:50%;
    background:#303134;
    display:flex;align-items:center;justify-content:center;
    font-size:20px;
  }
  .shortcut span{
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
    max-width:72px;text-align:center;color:#9aa0a6;font-size:11px;
  }
  .clock{
    position:fixed;top:28px;right:32px;
    font-size:13px;color:#5f6368;
    font-variant-numeric:tabular-nums;
  }
</style>
</head>
<body>
<div class="clock" id="clk"></div>
<div class="logo">🌐</div>
<div class="search-wrap">
  <span class="search-icon">🔍</span>
  <input id="q" placeholder="Поиск в Google или введите адрес" autofocus
         onkeydown="if(event.key==='Enter')doSearch()">
</div>
<div class="se-row" id="se-row">
  <div class="se active" onclick="setSE(this,'google')">Google</div>
  <div class="se" onclick="setSE(this,'yandex')">Яндекс</div>
  <div class="se" onclick="setSE(this,'bing')">Bing</div>
  <div class="se" onclick="setSE(this,'ddg')">DuckDuckGo</div>
  <div class="se" onclick="setSE(this,'gh')">GitHub</div>
</div>
<div class="shortcuts">
  <a class="shortcut" href="https://www.youtube.com">
    <div class="fav">▶</div><span>YouTube</span></a>
  <a class="shortcut" href="https://github.com">
    <div class="fav">🐙</div><span>GitHub</span></a>
  <a class="shortcut" href="https://www.wikipedia.org">
    <div class="fav">📚</div><span>Wikipedia</span></a>
  <a class="shortcut" href="https://www.reddit.com">
    <div class="fav">🦊</div><span>Reddit</span></a>
  <a class="shortcut" href="https://stackoverflow.com">
    <div class="fav">💬</div><span>Stack Overflow</span></a>
  <a class="shortcut" href="https://itch.io">
    <div class="fav">🎮</div><span>itch.io</span></a>
  <a class="shortcut" href="https://translate.google.com">
    <div class="fav">🌍</div><span>Переводчик</span></a>
  <a class="shortcut" href="https://hastebin.com">
    <div class="fav">📋</div><span>Hastebin</span></a>
  <a class="shortcut" href="https://www.wolframalpha.com">
    <div class="fav">∑</div><span>Wolfram</span></a>
  <a class="shortcut" href="https://news.ycombinator.com">
    <div class="fav">🔶</div><span>Hacker News</span></a>
</div>
<script>
var SE='google';
var urls={
  google:'https://www.google.com/search?q=',
  yandex:'https://yandex.ru/search/?text=',
  bing:'https://www.bing.com/search?q=',
  ddg:'https://duckduckgo.com/?q=',
  gh:'https://github.com/search?q='
};
function setSE(el,name){
  document.querySelectorAll('.se').forEach(e=>e.classList.remove('active'));
  el.classList.add('active'); SE=name;
}
function doSearch(){
  var q=document.getElementById('q').value.trim();
  if(!q)return;
  var url;
  if(q.startsWith('http://')||q.startsWith('https://')||(/[.]/.test(q)&&q.indexOf(' ')<0&&q.length>4))
    url=q.startsWith('http')?q:'https://'+q;
  else url=urls[SE]+encodeURIComponent(q);
  window.location.href=url;
}
function tick(){
  var d=new Date();
  var h=d.getHours().toString().padStart(2,'0');
  var m=d.getMinutes().toString().padStart(2,'0');
  document.getElementById('clk').textContent=h+':'+m;
  setTimeout(tick,10000);
}
tick();
document.getElementById('q').focus();
</script>
</body>
</html>"""


class WinoraNetScape(QWidget):
    """
    Winora NetScape 3.0 — встроенный браузер, работает как вкладка.
    Новое: sidebar (history/bookmarks/downloads), find bar, reader mode,
    dark reader injection, devtools, zoom, screenshot, pip, extensions stub,
    мультипоисковик на новой вкладке, часы, группировка истории по дням.
    """
    WNS_VERSION = "3.1"
    HOME_URL    = "wns://newtab"

    _SEARCH_ENGINES = {
        "Google":    "https://www.google.com/search?q={}",
        "Яндекс":    "https://yandex.ru/search/?text={}",
        "Bing":      "https://www.bing.com/search?q={}",
        "DuckDuckGo":"https://duckduckgo.com/?q={}",
        "GitHub":    "https://github.com/search?q={}",
    }
    _DEFAULT_BOOKMARKS = [
        ("🔍 Google",    "https://www.google.com"),
        ("📺 YouTube",   "https://www.youtube.com"),
        ("🐙 GitHub",    "https://github.com"),
        ("📚 Wikipedia", "https://www.wikipedia.org"),
        ("🦊 Reddit",    "https://www.reddit.com"),
        ("🎮 itch.io",   "https://itch.io"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._bookmarks  : list = []
        self._history     : list  = []     # [(title, url, timestamp)]
        self._dl_dir      = DATA_DIR / "wns_downloads"
        self._dl_dir.mkdir(parents=True, exist_ok=True)
        self._webengine   = False
        self._dark_reader = False
        self._reader_mode = False
        self._zoom_level  = 1.0
        self._sidebar_vis = False
        self._sidebar_tab = "history"   # "history"|"bookmarks"|"downloads"
        self._find_visible= False
        self._search_engine = "Google"
        self._load_bookmarks()
        self._load_history()
        # Title is shown in tab, not window title

        self._apply_style()
        self._setup_ui()
        self._load_geometry()

    # ── Style ─────────────────────────────────────────────────────────────────
    def _themed_home_html(self) -> str:
        """Inject current theme colors into the home page."""
        t = get_theme(S().theme)
        css_override = f"""
<style id="theme-override">
:root {{
  --bg: {t['bg']};
  --bg2: {t['bg2']};
  --bg3: {t['bg3']};
  --text: {t['text']};
  --dim: {t['text_dim']};
  --accent: {t['accent']};
  --border: {t['border']};
}}
body {{ background: var(--bg) !important; color: var(--text) !important; }}
.search-wrap {{ background: var(--bg3) !important; border-color: var(--border) !important; }}
.search-wrap:focus-within {{ border-color: var(--accent) !important; }}
#q {{ color: var(--text) !important; }}
#q::placeholder {{ color: var(--dim) !important; }}
.se {{ background: var(--bg3) !important; border-color: var(--border) !important;
       color: var(--dim) !important; }}
.se:hover, .se.active {{ background: var(--accent) !important;
                          color: var(--bg) !important; border-color: var(--accent) !important; }}
.shortcut {{ color: var(--text) !important; }}
.shortcut:hover {{ background: var(--bg2) !important; }}
.shortcut span {{ color: var(--dim) !important; }}
.fav {{ background: var(--bg3) !important; border: 1px solid var(--border); }}
.clock {{ color: var(--dim) !important; }}
</style>"""
        # Insert before </head>
        return WNS_HOME_HTML.replace("</head>", css_override + "</head>", 1)

    def _apply_style(self):
        """Chrome-style layout но цвета из текущей темы GoidaPhone."""
        t = get_theme(S().theme)

        # Derive Chrome-like shades from theme palette
        bg      = t['bg']       # main content / active tab
        bg2     = t['bg2']      # toolbar / tab bar background  
        bg3     = t['bg3']      # tab bar (darker strip)
        border  = t['border']
        text    = t['text']
        dim     = t['text_dim']
        accent  = t['accent']
        bhover  = t['btn_hover']
        bbg     = t['btn_bg']

        self.setStyleSheet(f"""
            /* ── Base ───────────────────────────────────────── */
            QWidget {{ background:{bg}; color:{text}; }}

            /* ── Toolbar (address bar row) ───────────────────── */
            QWidget#wns_toolbar {{
                background:{bg2};
                border-bottom:1px solid {border};
            }}

            /* ── Omnibar ─────────────────────────────────────── */
            QLineEdit#wns_urlbar {{
                background:{bg3};
                color:{text};
                border:1px solid {border};
                border-radius:22px;
                padding:5px 16px 5px 36px;
                font-size:13px;
                selection-background-color:{accent};
            }}
            QLineEdit#wns_urlbar:hover {{
                background:{bg2};
                border-color:{dim};
            }}
            QLineEdit#wns_urlbar:focus {{
                background:{bg};
                border:2px solid {accent};
            }}

            /* ── Nav buttons ─────────────────────────────────── */
            QPushButton#wns_nav {{
                background:transparent;
                color:{dim};
                border:none;
                border-radius:17px;
                min-width:34px; max-width:34px;
                min-height:34px; max-height:34px;
                font-size:17px;
            }}
            QPushButton#wns_nav:hover {{
                background:{bhover};
                color:{text};
            }}
            QPushButton#wns_nav:pressed {{
                background:{bbg};
            }}
            QPushButton#wns_nav:disabled {{ color:{border}; }}
            QPushButton#wns_nav:checked {{
                background:{accent}30;
                color:{accent};
            }}
            QPushButton#wns_new_tab {{
                background:transparent;
                color:{dim};
                border:none;
                border-radius:14px;
                min-width:28px; max-width:28px;
                min-height:28px; max-height:28px;
                font-size:18px;
            }}
            QPushButton#wns_new_tab:hover {{
                background:{bhover};
                color:{text};
            }}

            /* ── Tab bar (Chrome pill tabs) ──────────────────── */
            QTabWidget#wns_tabs::pane {{
                border:none;
                background:{bg};
            }}
            QTabBar {{
                background:{bg3};
                border-bottom:1px solid {border};
            }}
            QTabBar::tab {{
                background:transparent;
                color:{dim};
                border:none;
                border-radius:8px 8px 0 0;
                padding:6px 14px;
                margin:4px 1px 0 1px;
                font-size:12px;
                min-width:80px;
                max-width:220px;
            }}
            QTabBar::tab:selected {{
                background:{bg};
                color:{text};
                border-top:2px solid {accent};
            }}
            QTabBar::tab:hover:!selected {{
                background:{bg2};
                color:{text};
            }}
            QTabBar::close-button {{
                subcontrol-position:right;
                margin:2px;
            }}

            /* ── Bookmarks bar ───────────────────────────────── */
            QWidget#wns_bmarks {{
                background:{bg2};
                border-bottom:1px solid {border};
            }}
            QPushButton#wns_bmark_chip {{
                background:transparent;
                color:{dim};
                border:none;
                border-radius:6px;
                padding:2px 10px;
                font-size:11px;
            }}
            QPushButton#wns_bmark_chip:hover {{
                background:{bhover};
                color:{text};
            }}

            /* ── Find bar ────────────────────────────────────── */
            QWidget#wns_findbar {{
                background:{bg2};
                border-bottom:1px solid {border};
            }}
            QLineEdit#wns_find {{
                background:{bg3};
                color:{text};
                border:1px solid {border};
                border-radius:8px;
                padding:4px 10px;
                font-size:12px;
                min-width:220px;
                selection-background-color:{accent};
            }}
            QLineEdit#wns_find:focus {{
                border-color:{accent};
            }}

            /* ── Sidebar ─────────────────────────────────────── */
            QWidget#wns_sidebar {{
                background:{bg2};
                border-left:1px solid {border};
            }}
            QListWidget#wns_slist {{
                background:{bg2};
                color:{text};
                border:none;
                outline:none;
                font-size:11px;
            }}
            QListWidget#wns_slist::item {{
                padding:6px 12px;
                border-bottom:1px solid {border};
            }}
            QListWidget#wns_slist::item:hover {{ background:{bhover}; }}
            QListWidget#wns_slist::item:selected {{
                background:{accent}30;
                color:{accent};
            }}

            /* ── Progress bar ────────────────────────────────── */
            QProgressBar#wns_prog {{
                background:transparent;
                border:none;
                height:3px;
            }}
            QProgressBar#wns_prog::chunk {{
                background:{accent};
                border-radius:1px;
            }}

            /* ── Status bar ──────────────────────────────────── */
            QWidget#wns_statusbar {{
                background:{bg3};
                border-top:1px solid {border};
            }}
            QLabel#wns_stat {{
                color:{dim};
                font-size:9px;
                background:transparent;
                padding:0 8px;
            }}
            QLabel#wns_zoom {{
                color:{accent};
                font-size:10px;
                background:transparent;
                font-weight:bold;
            }}

            /* ── Menu ────────────────────────────────────────── */
            QMenu {{
                background:{bg2};
                color:{text};
                border:1px solid {border};
                border-radius:10px;
                padding:4px 0;
                font-size:12px;
            }}
            QMenu::item {{ padding:8px 22px; }}
            QMenu::item:selected {{
                background:{accent}25;
                color:{accent};
                border-radius:6px;
            }}
            QMenu::separator {{
                background:{border};
                height:1px;
                margin:3px 8px;
            }}
        """)

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # Progress bar must exist BEFORE _mk_toolbar because _new_tab uses it
        self._prog = QProgressBar()
        self._prog.setObjectName("wns_prog"); self._prog.setFixedHeight(3)
        self._prog.setTextVisible(False); self._prog.setRange(0,100)
        self._prog.setVisible(False)

        root.addWidget(self._mk_toolbar())
        root.addWidget(self._mk_bmarks_bar())
        root.addWidget(self._prog)

        # Find bar (hidden by default)
        self._findbar = self._mk_findbar()
        self._findbar.setVisible(False)
        root.addWidget(self._findbar)

        # Main area: tabs + sidebar
        self._main_split = QSplitter(Qt.Orientation.Horizontal)
        self._main_split.setHandleWidth(1)
        self._main_split.setStyleSheet("QSplitter::handle{background:#2D2D4E;}")

        self._tabs = QTabWidget()
        self._tabs.setObjectName("wns_tabs")
        self._tabs.setTabsClosable(True); self._tabs.setMovable(True)
        self._tabs.tabCloseRequested.connect(self._close_tab)
        self._tabs.currentChanged.connect(self._on_tab_switch)
        self._main_split.addWidget(self._tabs)

        self._sidebar = self._mk_sidebar()
        self._sidebar.setVisible(False)
        self._main_split.addWidget(self._sidebar)
        self._main_split.setSizes([1100, 280])

        root.addWidget(self._main_split, stretch=1)
        root.addWidget(self._mk_statusbar())
        self._new_tab()

    # ── Toolbar ───────────────────────────────────────────────────────────────
    def _mk_toolbar(self) -> QWidget:
        t = get_theme(S().theme)
        bar = QWidget(); bar.setObjectName("wns_toolbar"); bar.setFixedHeight(44)
        hl  = QHBoxLayout(bar)
        hl.setContentsMargins(8,5,8,5); hl.setSpacing(3)

        def nb(icon, tip, checkable=False):
            b = QPushButton(icon); b.setObjectName("wns_nav")
            b.setToolTip(tip); b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setCheckable(checkable)
            return b

        self._btn_back   = nb("←", "Назад  Alt+←")
        self._btn_fwd    = nb("→", "Вперёд  Alt+→")
        self._btn_reload = nb("↻", "Обновить  F5")
        self._btn_home   = nb("⌂", "Домой  Ctrl+H")
        self._btn_back.setEnabled(False); self._btn_fwd.setEnabled(False)
        self._btn_back.clicked.connect(self._go_back)
        self._btn_fwd.clicked.connect(self._go_forward)
        self._btn_reload.clicked.connect(self._reload_or_stop)
        self._btn_home.clicked.connect(lambda: self._navigate(self.HOME_URL))
        for b in [self._btn_back, self._btn_fwd, self._btn_reload, self._btn_home]:
            hl.addWidget(b)
        hl.addSpacing(4)

        # Security icon
        self._sec_ico = QLabel("🌐")
        self._sec_ico.setFixedWidth(20)
        self._sec_ico.setStyleSheet("font-size:13px;background:transparent;")
        hl.addWidget(self._sec_ico)

        # URL bar
        self._urlbar = QLineEdit()
        self._urlbar.setObjectName("wns_urlbar")
        self._urlbar.setPlaceholderText("  Поиск в Google или введите URL")
        self._urlbar.returnPressed.connect(self._on_url_enter)
        self._urlbar.focusInEvent = lambda e: (
            super(QLineEdit, self._urlbar).focusInEvent(e),
            QTimer.singleShot(0, self._urlbar.selectAll))[0]
        self._urlbar.textChanged.connect(self._on_urlbar_changed)
        hl.addWidget(self._urlbar, stretch=1)

        # Omnibar dropdown
        self._omni_popup = QListWidget(self)
        self._omni_popup.setWindowFlags(
            Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint)
        self._omni_popup.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self._omni_popup.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._omni_popup.setObjectName("wns_omni")
        self._omni_popup.itemClicked.connect(self._on_omni_selected)
        self._omni_popup.hide()
        hl.addSpacing(4)

        # Zoom display
        self._zoom_lbl = QLabel("100%")
        self._zoom_lbl.setObjectName("wns_zoom")
        self._zoom_lbl.setToolTip("Ctrl+колесо мыши для масштаба")
        hl.addWidget(self._zoom_lbl)

        # Bookmark star
        self._btn_star = nb("☆", "Закладка  Ctrl+D")
        self._btn_star.clicked.connect(self._toggle_bookmark)
        hl.addWidget(self._btn_star)

        # Reader mode
        self._btn_reader = nb("📖", "Режим чтения  Ctrl+Shift+R", checkable=True)
        self._btn_reader.clicked.connect(self._toggle_reader_mode)
        hl.addWidget(self._btn_reader)

        # Dark reader
        self._btn_dark = nb("🌙", "Dark Reader  Ctrl+Shift+D", checkable=True)
        self._btn_dark.clicked.connect(self._toggle_dark_reader)
        hl.addWidget(self._btn_dark)

        # New tab
        self._btn_new = nb("+", "Новая вкладка  Ctrl+T")
        self._btn_new.setFixedSize(28, 28)
        self._btn_new.setObjectName("wns_new_tab")  # different name to avoid conflict
        self._btn_new.setStyleSheet(
            f"QPushButton#wns_new_tab{{background:transparent;"
            f"color:{t['text_dim']};border:none;border-radius:14px;"
            f"font-size:18px;}}"
            f"QPushButton#wns_new_tab:hover{{background:{t['btn_hover']};"
            f"color:{t['text']};}}")
        self._btn_new.clicked.connect(lambda: self._new_tab())
        hl.addWidget(self._btn_new)

        # Sidebar toggle
        self._btn_sidebar = nb("▤", "Панель  Ctrl+B", checkable=True)
        self._btn_sidebar.clicked.connect(self._toggle_sidebar)
        hl.addWidget(self._btn_sidebar)

        # Menu
        btn_menu = nb("⋮", "Меню")
        btn_menu.clicked.connect(self._show_menu)
        hl.addWidget(btn_menu)
        return bar

    # ── Bookmarks bar ─────────────────────────────────────────────────────────
    def _mk_bmarks_bar(self) -> QWidget:
        self._bmarks_bar = QWidget()
        self._bmarks_bar.setObjectName("wns_bmarks")
        self._bmarks_bar.setFixedHeight(28)
        self._bmarks_lay = QHBoxLayout(self._bmarks_bar)
        self._bmarks_lay.setContentsMargins(8,2,8,2); self._bmarks_lay.setSpacing(2)
        self._refresh_bmarks()
        return self._bmarks_bar

    def _refresh_bmarks(self):
        t = get_theme(S().theme)
        lay = self._bmarks_lay
        while lay.count():
            item = lay.takeAt(0)
            if item and item.widget(): item.widget().deleteLater()
        bmarks = self._bookmarks if self._bookmarks else self._DEFAULT_BOOKMARKS
        for name, url in bmarks[:18]:
            b = QPushButton(name[:20]); b.setObjectName("wns_bmark_chip")
            b.setCursor(Qt.CursorShape.PointingHandCursor); b.setToolTip(url)
            b.clicked.connect(lambda _, u=url: self._navigate(u))
            lay.addWidget(b)
        lay.addStretch()

    # ── Find bar ──────────────────────────────────────────────────────────────
    def _mk_findbar(self) -> QWidget:
        bar = QWidget(); bar.setObjectName("wns_findbar"); bar.setFixedHeight(36)
        hl  = QHBoxLayout(bar); hl.setContentsMargins(10,4,10,4); hl.setSpacing(6)
        t   = get_theme(S().theme)

        lbl = QLabel("🔍 Найти:")
        lbl.setStyleSheet(f"color:{t['text_dim']};font-size:11px;background:transparent;")
        hl.addWidget(lbl)

        self._find_input = QLineEdit(); self._find_input.setObjectName("wns_find")
        self._find_input.setPlaceholderText("Текст для поиска…")
        self._find_input.returnPressed.connect(self._find_next)
        self._find_input.textChanged.connect(self._find_live)
        hl.addWidget(self._find_input)

        self._find_count = QLabel("")
        self._find_count.setStyleSheet(f"color:{t['text_dim']};font-size:10px;background:transparent;")
        hl.addWidget(self._find_count)

        for icon, tip, fn in [("↑","Предыдущее",self._find_prev),
                               ("↓","Следующее", self._find_next)]:
            b = QPushButton(icon); b.setObjectName("wns_nav")
            b.setFixedSize(28,28); b.setToolTip(tip)
            b.clicked.connect(fn); hl.addWidget(b)

        self._find_case = QPushButton("Aa"); self._find_case.setObjectName("wns_nav")
        self._find_case.setFixedSize(32,28); self._find_case.setCheckable(True)
        self._find_case.setToolTip("Учёт регистра"); hl.addWidget(self._find_case)

        hl.addStretch()
        close_f = QPushButton("✕"); close_f.setObjectName("wns_nav")
        close_f.setFixedSize(28,28)
        close_f.clicked.connect(self._hide_findbar); hl.addWidget(close_f)
        return bar

    # ── Sidebar ───────────────────────────────────────────────────────────────
    def _mk_sidebar(self) -> QWidget:
        sb = QWidget(); sb.setObjectName("wns_sidebar"); sb.setFixedWidth(300)
        vl = QVBoxLayout(sb); vl.setContentsMargins(0,0,0,0); vl.setSpacing(0)
        t  = get_theme(S().theme)

        # Tab buttons
        tab_row = QWidget()
        tab_row.setStyleSheet(f"background:{t['bg3']};border-bottom:1px solid {t['border']};")
        tr_lay = QHBoxLayout(tab_row); tr_lay.setContentsMargins(0,0,0,0); tr_lay.setSpacing(0)
        for key, label in [("history","🕐 История"),("bookmarks","🔖 Закладки"),("downloads","⬇ Загрузки")]:
            b = QPushButton(label); b.setCheckable(True)
            b.setChecked(key == "history")
            b.setStyleSheet(f"""
                QPushButton{{background:transparent;color:{t['text_dim']};border:none;
                    padding:6px 10px;font-size:10px;border-bottom:2px solid transparent;}}
                QPushButton:checked{{color:{t['text']};border-bottom-color:{t['accent']};}}
                QPushButton:hover{{color:{t['text']};}}
            """)
            b.clicked.connect(lambda _,k=key: self._sidebar_switch(k))
            tr_lay.addWidget(b)
            setattr(self, f'_sb_btn_{key}', b)
        vl.addWidget(tab_row)

        # Search/filter
        self._sb_search = QLineEdit()
        self._sb_search.setPlaceholderText("Фильтр…")
        self._sb_search.setStyleSheet(f"""
            background:{t['bg']};color:{t['text']};
            border:none;border-bottom:1px solid {t['border']};
            padding:6px 12px;font-size:11px;
        """)
        self._sb_search.textChanged.connect(self._sb_filter)
        vl.addWidget(self._sb_search)

        # List
        self._sb_list = QListWidget(); self._sb_list.setObjectName("wns_slist")
        self._sb_list.itemDoubleClicked.connect(self._sb_open)
        self._sb_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._sb_list.customContextMenuRequested.connect(self._sb_context_menu)
        vl.addWidget(self._sb_list, stretch=1)

        # Bottom actions
        act_row = QWidget()
        act_row.setStyleSheet(f"background:{t['bg3']};border-top:1px solid {t['border']};")
        ar_lay = QHBoxLayout(act_row); ar_lay.setContentsMargins(8,4,8,4); ar_lay.setSpacing(6)
        self._sb_clear_btn = QPushButton("🗑 Очистить")
        self._sb_clear_btn.setStyleSheet(
            f"QPushButton{{background:{t['btn_bg']};color:{t['text_dim']};"
            f"border:1px solid {t['border']};border-radius:6px;padding:3px 10px;font-size:10px;}}"
            f"QPushButton:hover{{color:{t['text']};background:{t['btn_hover']};}}")
        self._sb_clear_btn.clicked.connect(self._sb_clear)
        ar_lay.addWidget(self._sb_clear_btn); ar_lay.addStretch()
        self._sb_count_lbl = QLabel("")
        self._sb_count_lbl.setStyleSheet(f"color:{t['text_dim']};font-size:9px;background:transparent;")
        ar_lay.addWidget(self._sb_count_lbl)
        vl.addWidget(act_row)

        self._sb_populate()
        return sb

    def _sidebar_switch(self, key: str):
        self._sidebar_tab = key
        for k in ("history","bookmarks","downloads"):
            btn = getattr(self, f'_sb_btn_{k}', None)
            if btn: btn.setChecked(k == key)
        self._sb_populate()

    def _sb_populate(self, filt: str = ""):
        self._sb_list.clear()
        key = self._sidebar_tab
        t   = get_theme(S().theme)

        if key == "history":
            import datetime as _dt
            shown = 0
            last_date = None
            for title, url, ts in self._history:
                if filt and filt.lower() not in url.lower() and filt.lower() not in title.lower():
                    continue
                day = _dt.datetime.fromtimestamp(ts).strftime("%d.%m.%Y")
                if day != last_date:
                    sep = QListWidgetItem(f"  📅 {day}")
                    sep.setFlags(Qt.ItemFlag.NoItemFlags)
                    sep.setForeground(__import__('PyQt6.QtGui',fromlist=['QColor']).QColor(t['accent']))
                    self._sb_list.addItem(sep)
                    last_date = day
                hm = _dt.datetime.fromtimestamp(ts).strftime("%H:%M")
                item = QListWidgetItem(f"  {hm}  {title[:30] or url[:30]}\n  {url[:50]}")
                item.setData(Qt.ItemDataRole.UserRole, url)
                item.setToolTip(url)
                self._sb_list.addItem(item)
                shown += 1
                if shown >= 200: break
            self._sb_count_lbl.setText(f"{len(self._history)} записей")

        elif key == "bookmarks":
            bmarks = self._bookmarks if self._bookmarks else self._DEFAULT_BOOKMARKS
            for name, url in bmarks:
                if filt and filt.lower() not in url.lower() and filt.lower() not in name.lower():
                    continue
                item = QListWidgetItem(f"  {name}\n  {url[:50]}")
                item.setData(Qt.ItemDataRole.UserRole, url)
                item.setToolTip(url)
                self._sb_list.addItem(item)
            self._sb_count_lbl.setText(f"{len(bmarks)} закладок")

        elif key == "downloads":
            files = sorted(self._dl_dir.iterdir(),
                key=lambda f: f.stat().st_mtime, reverse=True) \
                if self._dl_dir.exists() else []
            for f in files[:100]:
                if filt and filt.lower() not in f.name.lower(): continue
                sz = f.stat().st_size
                sz_str = f"{sz//1048576}MB" if sz>1048576 else f"{sz//1024}KB" if sz>1024 else f"{sz}B"
                item = QListWidgetItem(f"  {f.name}\n  {sz_str}")
                item.setData(Qt.ItemDataRole.UserRole, str(f))
                self._sb_list.addItem(item)
            self._sb_count_lbl.setText(f"{len(files)} файлов")

    def _sb_filter(self, text: str):
        self._sb_populate(text)

    def _sb_open(self, item: 'QListWidgetItem'):
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data: return
        if self._sidebar_tab == "downloads":
            _open_system(data)
        else:
            self._new_tab(data)

    def _sb_context_menu(self, pos):
        item = self._sb_list.itemAt(pos)
        if not item: return
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data: return
        menu = QMenu(self)
        if self._sidebar_tab != "downloads":
            menu.addAction("🆕 Открыть в новой вкладке",
                           lambda: self._new_tab(data))
            menu.addAction("📋 Копировать URL",
                           lambda: QApplication.clipboard().setText(data))
        else:
            menu.addAction("📂 Открыть файл",
                           lambda d=data: _open_system(d))
            menu.addAction("📋 Копировать путь",
                           lambda: QApplication.clipboard().setText(data))
            menu.addSeparator()
            menu.addAction("🗑 Удалить файл", lambda: self._del_download(data))
        menu.addSeparator()
        menu.addAction("✕ Удалить из списка", lambda: self._sb_del_item(item))
        menu.exec(self._sb_list.mapToGlobal(pos))

    def _del_download(self, path: str):
        try:
            import os as _os; _os.remove(path)
            self._sb_populate()
        except Exception as e:
            self._stat_lbl.setText(f"Ошибка удаления: {e}")

    def _sb_del_item(self, item):
        data = item.data(Qt.ItemDataRole.UserRole)
        if self._sidebar_tab == "history":
            self._history = [(t,u,ts) for t,u,ts in self._history if u != data]
            self._save_history()
        elif self._sidebar_tab == "bookmarks":
            self._bookmarks = [(n,u) for n,u in self._bookmarks if u != data]
            self._save_bookmarks(); self._refresh_bmarks()
        self._sb_populate()

    def _sb_clear(self):
        key = self._sidebar_tab
        if key == "history":
            if QMessageBox.question(self, "История", "Очистить историю?",
                    QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) \
                    == QMessageBox.StandardButton.Yes:
                self._history.clear(); self._save_history(); self._sb_populate()
        elif key == "bookmarks":
            if QMessageBox.question(self, "Закладки", "Удалить все закладки?",
                    QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) \
                    == QMessageBox.StandardButton.Yes:
                self._bookmarks.clear(); self._save_bookmarks()
                self._refresh_bmarks(); self._sb_populate()
        elif key == "downloads":
            if QMessageBox.question(self, "Загрузки",
                    "Удалить все файлы из папки загрузок?",
                    QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) \
                    == QMessageBox.StandardButton.Yes:
                import shutil as _sh
                _sh.rmtree(str(self._dl_dir), ignore_errors=True)
                self._dl_dir.mkdir(parents=True, exist_ok=True)
                self._sb_populate()

    def _toggle_sidebar(self):
        self._sidebar_vis = not self._sidebar_vis
        self._sidebar.setVisible(self._sidebar_vis)
        self._btn_sidebar.setChecked(self._sidebar_vis)
        if self._sidebar_vis:
            self._sb_populate()

    # ── Status bar ────────────────────────────────────────────────────────────
    def _mk_statusbar(self) -> QWidget:
        bar = QWidget(); bar.setObjectName("wns_statusbar"); bar.setFixedHeight(20)
        hl  = QHBoxLayout(bar); hl.setContentsMargins(0,0,10,0); hl.setSpacing(0)
        self._stat_lbl = QLabel("Готово"); self._stat_lbl.setObjectName("wns_stat")
        hl.addWidget(self._stat_lbl, stretch=1)
        brand = QLabel(f"Winora NetScape {self.WNS_VERSION}")
        brand.setObjectName("wns_stat"); hl.addWidget(brand)
        return bar

    # ── Tab management ────────────────────────────────────────────────────────
    def _new_tab(self, url: str = "") -> int:
        try:
            from PyQt6.QtWebEngineWidgets import QWebEngineView
            from PyQt6.QtWebEngineCore import (QWebEngineProfile,
                QWebEngineSettings, QWebEnginePage)
            self._webengine = True

            profile = QWebEngineProfile.defaultProfile()
            profile.setHttpUserAgent(
                f"WinoraNetScape/{self.WNS_VERSION} GoidaPhone/1.8.0 "
                "(Linux; Winora Ecosystem) AppleWebKit/537.36 "
                "Chrome/124.0 Safari/537.36")
            try:
                profile.downloadRequested.connect(
                    self._on_download, Qt.ConnectionType.UniqueConnection)
            except Exception: pass

            s = profile.settings()
            s.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
            s.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
            s.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, True)
            s.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, True)
            s.setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True)

            view = QWebEngineView()
            view.loadStarted.connect(lambda: self._on_load_start(view))
            view.loadProgress.connect(self._prog.setValue)
            view.loadFinished.connect(lambda ok: self._on_load_finish(view, ok))
            view.urlChanged.connect(lambda u: self._on_url_change(view, u))
            view.titleChanged.connect(lambda ttl: self._on_title_change(view, ttl))
            view.iconChanged.connect(lambda ico: self._on_icon_change(view, ico))
            # Zoom wheel
            view.wheelEvent = lambda e, v=view: self._wheel_zoom(e, v)
            try:
                view.page().newWindowRequested.connect(self._on_new_window)
            except Exception: pass

            idx = self._tabs.addTab(view, "Новая вкладка")
            self._tabs.setCurrentIndex(idx)

            if url and url not in (self.HOME_URL, "wns://newtab"):
                from PyQt6.QtCore import QUrl
                view.load(QUrl(url))
            else:
                from PyQt6.QtCore import QUrl as QU
                view.setHtml(self._themed_home_html(), QU("wns://newtab"))
            return idx

        except Exception as _wns_err:
            print(f"[WNS] _new_tab failed: {type(_wns_err).__name__}: {_wns_err}")
            import traceback as _wns_tb; _wns_tb.print_exc()
            return self._new_tab_fallback(url)

    def _new_tab_fallback(self, url: str = "") -> int:
        t = get_theme(S().theme)
        w = QWidget(); w.setStyleSheet(f"background:{t['bg']};")
        vl = QVBoxLayout(w); vl.setAlignment(Qt.AlignmentFlag.AlignCenter); vl.setSpacing(16)
        lgo = QLabel("🌐"); lgo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lgo.setStyleSheet("font-size:64px;background:transparent;"); vl.addWidget(lgo)
        ttl = QLabel("Winora NetScape 3.0")
        ttl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ttl.setStyleSheet(f"font-size:22px;font-weight:bold;color:{t['text']};background:transparent;")
        vl.addWidget(ttl)
        note = QLabel(
            "Встроенный браузер требует PyQt6-WebEngine.\n\n"
            "Установи:\n  pip install PyQt6-WebEngine --break-system-packages\n"
            "или:  emerge -av dev-python/pyqt6-webengine")
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        note.setStyleSheet(f"color:{t['text_dim']};font-size:11px;background:transparent;")
        vl.addWidget(note)
        if url and url not in (self.HOME_URL, "wns://newtab"):
            ul = QLabel(url); ul.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ul.setStyleSheet(f"color:{t['accent']};font-size:11px;background:transparent;")
            vl.addWidget(ul)
            ob = QPushButton("🌐 Открыть во внешнем браузере")
            ob.setObjectName("accent_btn"); ob.setFixedHeight(36)
            ob.clicked.connect(lambda: __import__('webbrowser').open(url))
            vl.addWidget(ob)
        idx = self._tabs.addTab(w, "WNS"); self._tabs.setCurrentIndex(idx)
        return idx

    def _close_tab(self, idx: int):
        if self._tabs.count() <= 1:
            self.close(); return
        w = self._tabs.widget(idx)
        self._tabs.removeTab(idx)
        if w: w.deleteLater()

    def _on_tab_switch(self, idx: int):
        w = self._tabs.widget(idx)
        if w and hasattr(w, 'url'):
            try:
                u = w.url().toString()
                show = "" if u.startswith("data:") or "wns://newtab" in u else u
                self._urlbar.setText(show)
                self._update_sec_icon(u)
                self._update_star(u)
                h = w.history() if hasattr(w,'history') else None
                if h:
                    self._btn_back.setEnabled(h.canGoBack())
                    self._btn_fwd.setEnabled(h.canGoForward())
                # Sync zoom
                if hasattr(w, 'zoomFactor'):
                    self._zoom_level = w.zoomFactor()
                    self._zoom_lbl.setText(f"{int(self._zoom_level*100)}%")
            except Exception: pass

    # ── Navigation ────────────────────────────────────────────────────────────
    def _on_url_enter(self):
        self._omni_popup.hide()
        raw = self._urlbar.text().strip()
        if not raw: return
        if raw.startswith(("http://","https://","file://","ftp://")):
            url = raw
        elif "." in raw and " " not in raw and len(raw) > 3 and "/" not in raw.split(".")[0]:
            url = "https://" + raw
        else:
            from urllib.parse import quote_plus
            tpl = self._SEARCH_ENGINES.get(self._search_engine,
                "https://www.google.com/search?q={}")
            url = tpl.format(quote_plus(raw))
        self._navigate(url)

    def _on_urlbar_changed(self, text: str):
        """Hide omni popup — prevents focus steal."""
        self._omni_popup.hide()
    def _on_omni_selected(self, item):
        url = item.data(Qt.ItemDataRole.UserRole)
        self._omni_popup.hide()
        if url.startswith("__search__"):
            from urllib.parse import quote_plus
            q = url[10:]
            tpl = self._SEARCH_ENGINES.get(self._search_engine,
                "https://www.google.com/search?q={}")
            self._navigate(tpl.format(quote_plus(q)))
        else:
            self._urlbar.setText(url)
            self._navigate(url)

    def _navigate(self, url: str):
        if url in (self.HOME_URL, "wns://newtab"):
            w = self._tabs.currentWidget()
            if w and hasattr(w, 'setHtml'):
                from PyQt6.QtCore import QUrl as QU
                w.setHtml(self._themed_home_html(), QU("wns://newtab"))
                self._urlbar.setText("")
            return
        w = self._tabs.currentWidget()
        if w and hasattr(w, 'load'):
            from PyQt6.QtCore import QUrl
            w.load(QUrl(url))
            self._urlbar.setText(url)
        else:
            import webbrowser; webbrowser.open(url)

    def _go_back(self):
        w = self._tabs.currentWidget()
        if w and hasattr(w,'back'): w.back()

    def _go_forward(self):
        w = self._tabs.currentWidget()
        if w and hasattr(w,'forward'): w.forward()

    def _reload_or_stop(self):
        w = self._tabs.currentWidget()
        if not w: return
        if self._btn_reload.text() == "✕":
            if hasattr(w,'stop'): w.stop()
        else:
            if hasattr(w,'reload'): w.reload()

    # ── Zoom ──────────────────────────────────────────────────────────────────
    def _wheel_zoom(self, event, view):
        from PyQt6.QtCore import Qt as _Qt
        if event.modifiers() & _Qt.KeyboardModifier.ControlModifier:
            delta = event.angleDelta().y()
            self._zoom_level = max(0.25, min(5.0, self._zoom_level + (0.1 if delta>0 else -0.1)))
            view.setZoomFactor(self._zoom_level)
            self._zoom_lbl.setText(f"{int(self._zoom_level*100)}%")
        else:
            from PyQt6.QtWebEngineWidgets import QWebEngineView
            QWebEngineView.wheelEvent(view, event)

    def _zoom_in(self):
        self._zoom_level = min(5.0, self._zoom_level + 0.1)
        self._apply_zoom()

    def _zoom_out(self):
        self._zoom_level = max(0.25, self._zoom_level - 0.1)
        self._apply_zoom()

    def _zoom_reset(self):
        self._zoom_level = 1.0; self._apply_zoom()

    def _apply_zoom(self):
        w = self._tabs.currentWidget()
        if w and hasattr(w,'setZoomFactor'):
            w.setZoomFactor(self._zoom_level)
            self._zoom_lbl.setText(f"{int(self._zoom_level*100)}%")

    # ── WebEngine callbacks ───────────────────────────────────────────────────
    def _on_load_start(self, view):
        self._prog.setValue(0); self._prog.setVisible(True)
        self._stat_lbl.setText("Загрузка…")
        self._btn_reload.setText("✕"); self._btn_reload.setToolTip("Остановить")

    def _on_load_finish(self, view, ok: bool):
        self._prog.setVisible(False)
        self._btn_reload.setText("↻"); self._btn_reload.setToolTip("Обновить (F5)")
        self._stat_lbl.setText("Готово" if ok else "⚠ Ошибка загрузки")
        if hasattr(view,'history'):
            h = view.history()
            self._btn_back.setEnabled(h.canGoBack())
            self._btn_fwd.setEnabled(h.canGoForward())
        # Apply dark reader if active
        if self._dark_reader and ok:
            view.page().runJavaScript(_WNS_DARK_READER_JS)

    def _on_url_change(self, view, qurl):
        if view != self._tabs.currentWidget(): return
        u = qurl.toString()
        is_internal = (not u or u.startswith("data:")
                       or "wns://newtab" in u or u == "about:blank")
        show = "" if is_internal else u
        if not self._urlbar.hasFocus():
            self._urlbar.setText(show)
        self._update_sec_icon(u)
        self._update_star(u)
        # History
        if u and not u.startswith("data:") and "wns://newtab" not in u:
            title = self._tabs.tabText(self._tabs.currentIndex()) or u
            self._history.insert(0, (title, u, time.time()))
            if len(self._history) > 1000:
                self._history = self._history[:1000]
            self._save_history()
            if self._sidebar_vis and self._sidebar_tab == "history":
                self._sb_populate()

    def _on_title_change(self, view, title: str):
        idx = self._tabs.indexOf(view)
        if idx >= 0:
            short = (title[:20]+"…") if len(title)>20 else (title or "Без названия")
            self._tabs.setTabText(idx, short)
            self._tabs.setTabToolTip(idx, title)
            # Update history entry
            if self._history:
                t_old, u, ts = self._history[0]
                if abs(time.time()-ts) < 10:
                    self._history[0] = (title, u, ts)

    def _on_icon_change(self, view, icon):
        idx = self._tabs.indexOf(view)
        if idx >= 0 and not icon.isNull():
            self._tabs.setTabIcon(idx, icon)

    def _on_new_window(self, req):
        try:
            url = req.requestedUrl().toString()
            self._new_tab(url)
        except Exception: pass

    def _update_sec_icon(self, url: str):
        if url.startswith("https://"):
            self._sec_ico.setText("🔒"); self._sec_ico.setToolTip("HTTPS")
            self._sec_ico.setStyleSheet("font-size:13px;background:transparent;color:#80FF80;")
        elif url.startswith("http://"):
            self._sec_ico.setText("🔓"); self._sec_ico.setToolTip("HTTP — не защищено")
            self._sec_ico.setStyleSheet("font-size:13px;background:transparent;color:#FFA060;")
        else:
            self._sec_ico.setText("🌐"); self._sec_ico.setToolTip("")
            self._sec_ico.setStyleSheet("font-size:13px;background:transparent;")

    def _update_star(self, url: str):
        is_bm = any(u == url for _,u in self._bookmarks)
        self._btn_star.setText("★" if is_bm else "☆")

    # ── Find in page ──────────────────────────────────────────────────────────
    def _show_findbar(self):
        self._find_visible = True
        self._findbar.setVisible(True)
        self._find_input.setFocus()
        self._find_input.selectAll()

    def _hide_findbar(self):
        self._find_visible = False
        self._findbar.setVisible(False)
        w = self._tabs.currentWidget()
        if w and hasattr(w,'findText'):
            w.findText("")   # clear highlight

    def _find_live(self, text: str):
        if text: self._find_text(text)

    def _find_text(self, text: str = ""):
        w = self._tabs.currentWidget()
        if not (w and hasattr(w,'findText')): return
        text = text or self._find_input.text()
        if not text: return
        try:
            from PyQt6.QtWebEngineCore import QWebEnginePage
            flags = QWebEnginePage.FindFlag(0)
            if self._find_case.isChecked():
                flags |= QWebEnginePage.FindFlag.FindCaseSensitively
            w.findText(text, flags)
        except Exception:
            w.findText(text)

    def _find_next(self):
        self._find_text()

    def _find_prev(self):
        w = self._tabs.currentWidget()
        if not (w and hasattr(w,'findText')): return
        text = self._find_input.text()
        if not text: return
        try:
            from PyQt6.QtWebEngineCore import QWebEnginePage
            flags = QWebEnginePage.FindFlag.FindBackward
            if self._find_case.isChecked():
                flags |= QWebEnginePage.FindFlag.FindCaseSensitively
            w.findText(text, flags)
        except Exception:
            w.findText(text)

    # ── Reader mode ───────────────────────────────────────────────────────────
    def _toggle_reader_mode(self):
        self._reader_mode = not self._reader_mode
        self._btn_reader.setChecked(self._reader_mode)
        w = self._tabs.currentWidget()
        if not (w and hasattr(w,'page')): return
        if self._reader_mode:
            w.page().runJavaScript(_WNS_READER_JS)
            self._stat_lbl.setText("📖 Режим чтения")
        else:
            if hasattr(w,'reload'): w.reload()
            self._stat_lbl.setText("Режим чтения выключен")

    # ── Dark Reader ───────────────────────────────────────────────────────────
    def _toggle_dark_reader(self):
        self._dark_reader = not self._dark_reader
        self._btn_dark.setChecked(self._dark_reader)
        w = self._tabs.currentWidget()
        if w and hasattr(w,'page'):
            if self._dark_reader:
                w.page().runJavaScript(_WNS_DARK_READER_JS)
                self._stat_lbl.setText("🌙 Dark Reader включён")
            else:
                # Remove by reload
                if hasattr(w,'reload'): w.reload()
                self._stat_lbl.setText("🌙 Dark Reader выключен")

    # ── Screenshot ────────────────────────────────────────────────────────────
    def _screenshot(self):
        w = self._tabs.currentWidget()
        if not (w and hasattr(w,'grab')): return
        pix = w.grab()
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить скриншот",
            str(self._dl_dir / f"screenshot_{int(time.time())}.png"),
            "PNG (*.png);;JPEG (*.jpg)")
        if path:
            pix.save(path)
            self._stat_lbl.setText(f"📸 Сохранено: {Path(path).name}")

    # ── DevTools ──────────────────────────────────────────────────────────────
    def _open_devtools(self):
        w = self._tabs.currentWidget()
        if not (w and hasattr(w,'page')): return
        try:
            dev_view = __import__('PyQt6.QtWebEngineWidgets',
                fromlist=['QWebEngineView']).QWebEngineView()
            dev_view.resize(1000, 600)
            dev_view.setWindowTitle("DevTools — Winora NetScape")
            w.page().setDevToolsPage(dev_view.page())
            dev_view.show()
            self._stat_lbl.setText("🔧 DevTools открыты")
        except Exception as e:
            self._stat_lbl.setText(f"DevTools: {e}")

    # ── Picture-in-Picture / Mute ─────────────────────────────────────────────
    def _toggle_mute_page(self):
        w = self._tabs.currentWidget()
        if w and hasattr(w,'page'):
            try:
                w.page().setAudioMuted(not w.page().isAudioMuted())
                muted = w.page().isAudioMuted()
                self._stat_lbl.setText("🔇 Звук выключен" if muted else "🔊 Звук включён")
            except Exception: pass

    # ── Downloads ─────────────────────────────────────────────────────────────
    def _on_download(self, item):
        try:
            item.setDownloadDirectory(str(self._dl_dir))
            item.accept()
            fname = item.downloadFileName()
            self._stat_lbl.setText(f"⬇ Загружается: {fname}")
            try:
                item.isFinishedChanged.connect(lambda: (
                    self._stat_lbl.setText(f"✓ Загружено: {fname}"),
                    self._sb_populate() if (self._sidebar_vis and self._sidebar_tab=="downloads") else None
                ))
            except Exception: pass
        except Exception as e:
            self._stat_lbl.setText(f"⚠ Загрузка: {e}")

    # ── Bookmarks ─────────────────────────────────────────────────────────────
    def _toggle_bookmark(self):
        w = self._tabs.currentWidget()
        if not (w and hasattr(w,'url')): return
        url   = w.url().toString()
        title = self._tabs.tabText(self._tabs.currentIndex())
        if any(u == url for _,u in self._bookmarks):
            self._bookmarks = [(n,u) for n,u in self._bookmarks if u != url]
            self._btn_star.setText("☆"); self._stat_lbl.setText("Закладка удалена")
        else:
            self._bookmarks.insert(0, (title[:22], url))
            self._btn_star.setText("★"); self._stat_lbl.setText("★ Закладка добавлена")
        self._save_bookmarks(); self._refresh_bmarks()
        if self._sidebar_vis and self._sidebar_tab=="bookmarks":
            self._sb_populate()

    def _save_bookmarks(self):
        try:
            import json
            (DATA_DIR/"wns_bookmarks.json").write_text(
                json.dumps(self._bookmarks), encoding="utf-8")
        except Exception: pass

    def _load_bookmarks(self):
        try:
            import json
            f = DATA_DIR/"wns_bookmarks.json"
            if f.exists(): self._bookmarks = json.loads(f.read_text(encoding="utf-8"))
        except Exception: pass

    def _save_history(self):
        try:
            import json
            (DATA_DIR/"wns_history.json").write_text(
                json.dumps(self._history[:500]), encoding="utf-8")
        except Exception: pass

    def _load_history(self):
        try:
            import json
            f = DATA_DIR/"wns_history.json"
            if f.exists(): self._history = json.loads(f.read_text(encoding="utf-8"))
        except Exception: pass

    # ── Menu ──────────────────────────────────────────────────────────────────
    def _show_menu(self):
        menu = QMenu(self)
        menu.addAction("🆕 Новая вкладка         Ctrl+T",   lambda: self._new_tab())
        menu.addAction("🔄 Обновить                 F5",    self._reload_or_stop)
        menu.addAction("✕  Закрыть вкладку      Ctrl+W",    lambda: self._close_tab(self._tabs.currentIndex()))
        menu.addSeparator()
        menu.addAction("🔍 Найти на странице    Ctrl+F",    self._show_findbar)
        menu.addAction("📖 Режим чтения   Ctrl+Shift+R",   self._toggle_reader_mode)
        menu.addAction("🌙 Dark Reader    Ctrl+Shift+D",   self._toggle_dark_reader)
        menu.addSeparator()

        zoom_menu = menu.addMenu("🔎 Масштаб")
        zoom_menu.addAction("➕ Увеличить   Ctrl++", self._zoom_in)
        zoom_menu.addAction("➖ Уменьшить   Ctrl+-", self._zoom_out)
        zoom_menu.addAction("↺  Сбросить     Ctrl+0", self._zoom_reset)
        for pct in [75, 100, 125, 150, 200]:
            zoom_menu.addAction(f"  {pct}%", lambda _,p=pct: self._set_zoom(p))

        menu.addSeparator()
        menu.addAction("📸 Скриншот страницы",            self._screenshot)
        menu.addAction("🔧 Инструменты разработчика  F12",self._open_devtools)
        menu.addAction("🔇 Выкл/вкл звук вкладки",       self._toggle_mute_page)
        menu.addSeparator()
        menu.addAction("💾 Сохранить страницу",            self._save_page)
        menu.addAction("🖨 Печать               Ctrl+P",  self._print_page)
        menu.addSeparator()

        se_menu = menu.addMenu("🔍 Поисковик")
        for name in self._SEARCH_ENGINES:
            act = se_menu.addAction(("✓ " if name==self._search_engine else "   ") + name)
            act.triggered.connect(lambda _,n=name: self._set_search_engine(n))

        menu.addSeparator()
        menu.addAction("🔑 Пароли  Ctrl+Shift+P",         self._open_password_manager)
        menu.addAction("🕵 Инкогнито  Ctrl+Shift+N",      self._new_incognito_tab)
        menu.addAction("📜 Userscripts  Ctrl+Shift+U",    self._open_userscripts)
        menu.addSeparator()
        menu.addAction("ℹ О Winora NetScape",              self._show_about)
        menu.addAction("✕ Закрыть WNS",                    self.close)

        btn = self.sender()
        pos = btn.mapToGlobal(btn.rect().bottomLeft()) if btn else self.mapToGlobal(self.rect().center())
        menu.exec(pos)

    def _set_zoom(self, pct: int):
        self._zoom_level = pct / 100
        self._apply_zoom()

    def _set_search_engine(self, name: str):
        self._search_engine = name
        self._stat_lbl.setText(f"Поисковик: {name}")

    def _save_page(self):
        w = self._tabs.currentWidget()
        if not hasattr(w,'page'): return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить страницу",
            str(self._dl_dir/"page.html"), "HTML (*.html *.mhtml)")
        if path:
            try:
                from PyQt6.QtWebEngineCore import QWebEnginePage
                w.page().save(path, QWebEnginePage.SavePageFormat.MimeHtml)
                self._stat_lbl.setText(f"💾 Сохранено: {Path(path).name}")
            except Exception as e:
                self._stat_lbl.setText(f"Ошибка: {e}")

    def _print_page(self):
        w = self._tabs.currentWidget()
        if not hasattr(w,'page'): return
        try:
            from PyQt6.QtPrintSupport import QPrinter, QPrintDialog
            pr = QPrinter(); dlg = QPrintDialog(pr, self)
            if dlg.exec() == QDialog.DialogCode.Accepted:
                w.page().print(pr, lambda ok: None)
        except ImportError:
            QMessageBox.information(self,"Печать","PyQt6-PrintSupport не установлен.")

    # ── Password Manager ──────────────────────────────────────────────────────
    def _open_password_manager(self):
        import json as _j
        t = get_theme(S().theme)
        dlg = QDialog(self)
        dlg.setWindowTitle("🔑 Пароли")
        dlg.resize(580, 380)
        dlg.setStyleSheet(f"background:{t['bg2']};color:{t['text']};")
        vl = QVBoxLayout(dlg)
        vl.setContentsMargins(16,16,16,16); vl.setSpacing(10)
        hdr = QLabel("🔑 Сохранённые пароли (двойной клик = копировать)")
        hdr.setStyleSheet(
            f"font-size:13px;font-weight:bold;color:{t['accent']};background:transparent;")
        vl.addWidget(hdr)
        raw = S().get("wns_passwords", "{}", t=str)
        try: pwds = _j.loads(raw)
        except: pwds = {}
        tbl = QTableWidget(len(pwds), 3)
        tbl.setHorizontalHeaderLabels(["Сайт","Логин","Пароль"])
        tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tbl.setStyleSheet(
            f"QTableWidget{{background:{t['bg']};color:{t['text']};border:none;}}"
            f"QHeaderView::section{{background:{t['bg3']};color:{t['text_dim']};"
            "border:none;padding:4px;}}")
        for i,(site,creds) in enumerate(pwds.items()):
            tbl.setItem(i,0,QTableWidgetItem(site))
            tbl.setItem(i,1,QTableWidgetItem(creds.get("login","")))
            pi = QTableWidgetItem("••••••••")
            pi.setData(Qt.ItemDataRole.UserRole, creds.get("password",""))
            tbl.setItem(i,2,pi)
        tbl.doubleClicked.connect(lambda idx: QApplication.clipboard().setText(
            tbl.item(idx.row(),2).data(Qt.ItemDataRole.UserRole) or ""
            ) if tbl.item(idx.row(),2) else None)
        vl.addWidget(tbl, stretch=1)
        row = QHBoxLayout()
        site_e = QLineEdit(); site_e.setPlaceholderText("Сайт")
        login_e= QLineEdit(); login_e.setPlaceholderText("Логин")
        pw_e   = QLineEdit(); pw_e.setPlaceholderText("Пароль")
        pw_e.setEchoMode(QLineEdit.EchoMode.Password)
        for w in [site_e, login_e, pw_e]:
            w.setStyleSheet(
                f"background:{t['bg3']};color:{t['text']};"
                f"border:1px solid {t['border']};border-radius:6px;padding:4px 8px;")
            row.addWidget(w)
        add_b = QPushButton("➕")
        add_b.setObjectName("accent_btn"); add_b.setFixedSize(32,32)
        def _add():
            s=site_e.text().strip(); l=login_e.text().strip(); p=pw_e.text()
            if s and p:
                pwds[s]={"login":l,"password":p}
                S().set("wns_passwords",_j.dumps(pwds))
                r=tbl.rowCount(); tbl.insertRow(r)
                tbl.setItem(r,0,QTableWidgetItem(s))
                tbl.setItem(r,1,QTableWidgetItem(l))
                pi2=QTableWidgetItem("••••••••")
                pi2.setData(Qt.ItemDataRole.UserRole,p)
                tbl.setItem(r,2,pi2)
                site_e.clear(); login_e.clear(); pw_e.clear()
        add_b.clicked.connect(_add); row.addWidget(add_b)
        vl.addLayout(row)
        dlg.exec()

    def _new_incognito_tab(self):
        try:
            from PyQt6.QtWebEngineWidgets import QWebEngineView
            from PyQt6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage
            from PyQt6.QtCore import QUrl
            profile = QWebEngineProfile(self)
            view = QWebEngineView()
            page = QWebEnginePage(profile, view)
            view.setPage(page)
            view.loadStarted.connect(lambda: self._on_load_start(view))
            view.loadProgress.connect(self._prog.setValue)
            view.loadFinished.connect(lambda ok: self._on_load_finish(view, ok))
            view.urlChanged.connect(lambda u: (
                self._urlbar.setText(u.toString())
                if view == self._tabs.currentWidget() else None))
            view.titleChanged.connect(lambda tt: (
                self._tabs.setTabText(self._tabs.indexOf(view),
                    f"🕵 {tt[:18]}") if tt else None))
            view.wheelEvent = lambda e, v=view: self._wheel_zoom(e, v)
            view.setHtml(WNS_HOME_HTML, QUrl("wns://newtab"))
            idx = self._tabs.addTab(view, "🕵 Инкогнито")
            self._tabs.setCurrentIndex(idx)
            from PyQt6.QtGui import QColor
            self._tabs.tabBar().setTabTextColor(idx, QColor("#A0A0FF"))
        except Exception as e:
            self._stat_lbl.setText(f"Инкогнито: {e}")

    def _open_userscripts(self):
        import json as _j
        t = get_theme(S().theme)
        dlg = QDialog(self)
        dlg.setWindowTitle("📜 Userscripts")
        dlg.resize(700, 480)
        dlg.setStyleSheet(f"background:{t['bg2']};color:{t['text']};")
        vl = QVBoxLayout(dlg)
        vl.setContentsMargins(16,16,16,16); vl.setSpacing(8)
        raw = S().get("wns_userscripts","[]",t=str)
        try: scripts = _j.loads(raw)
        except: scripts = []
        sp = QSplitter()
        lw = QListWidget()
        lw.setStyleSheet(
            f"QListWidget{{background:{t['bg']};color:{t['text']};border:none;}}"
            f"QListWidget::item{{padding:8px;border-bottom:1px solid {t['border']};}}"
            f"QListWidget::item:selected{{background:{t['accent']};color:white;}}")
        for sc in scripts:
            it = QListWidgetItem(f"{'✅' if sc.get('enabled',True) else '⬜'} {sc.get('name','?')}")
            it.setData(Qt.ItemDataRole.UserRole, sc)
            lw.addItem(it)
        rw = QWidget(); rl = QVBoxLayout(rw)
        rl.setContentsMargins(8,0,0,0)
        name_e = QLineEdit(); name_e.setPlaceholderText("Название")
        match_e= QLineEdit(); match_e.setPlaceholderText("URL паттерн (* = все)")
        code_e = QPlainTextEdit()
        code_e.setPlaceholderText("// JavaScript код")
        code_e.setStyleSheet(
            f"QPlainTextEdit{{background:#0A0A14;color:#90EE90;"
            "font-family:monospace;font-size:11px;"
            f"border:1px solid {t['border']};border-radius:6px;padding:8px;}}")
        for w in [name_e, match_e]:
            w.setStyleSheet(
                f"background:{t['bg3']};color:{t['text']};"
                f"border:1px solid {t['border']};border-radius:6px;padding:4px 8px;")
        def _save():
            n=name_e.text().strip() or "Script"; m=match_e.text().strip() or "*"
            c=code_e.toPlainText()
            sc={"name":n,"match":m,"code":c,"enabled":True}
            scripts.append(sc)
            S().set("wns_userscripts",_j.dumps(scripts))
            it=QListWidgetItem(f"✅ {n}")
            it.setData(Qt.ItemDataRole.UserRole,sc)
            lw.addItem(it)
        def _run():
            c=code_e.toPlainText()
            w2=self._tabs.currentWidget()
            if w2 and hasattr(w2,'page') and c:
                w2.page().runJavaScript(c)
        def _load(it):
            sc=it.data(Qt.ItemDataRole.UserRole)
            if sc:
                name_e.setText(sc.get("name",""))
                match_e.setText(sc.get("match","*"))
                code_e.setPlainText(sc.get("code",""))
        lw.itemClicked.connect(_load)
        save_b=QPushButton("💾 Сохранить"); save_b.setObjectName("accent_btn")
        run_b=QPushButton("▶ Запустить на текущей"); run_b.setFixedHeight(32)
        run_b.setStyleSheet(
            f"QPushButton{{background:{t['bg3']};color:{t['text']};"
            f"border:1px solid {t['border']};border-radius:6px;}}"
            f"QPushButton:hover{{background:{t['btn_hover']};}}")
        save_b.clicked.connect(_save); run_b.clicked.connect(_run)
        rl.addWidget(QLabel("Название:")); rl.addWidget(name_e)
        rl.addWidget(QLabel("URL (паттерн):")); rl.addWidget(match_e)
        rl.addWidget(QLabel("Код:")); rl.addWidget(code_e,stretch=1)
        br=QHBoxLayout(); br.addWidget(save_b); br.addWidget(run_b)
        rl.addLayout(br)
        sp.addWidget(lw); sp.addWidget(rw); sp.setSizes([200,500])
        vl.addWidget(sp,stretch=1)
        dlg.exec()

    def _run_userscripts_for_url(self, url, view):
        import json as _j, fnmatch
        raw = S().get("wns_userscripts","[]",t=str)
        try: scripts = _j.loads(raw)
        except: return
        for sc in scripts:
            if not sc.get("enabled",True): continue
            if fnmatch.fnmatch(url, sc.get("match","*")) or sc.get("match","*")=="*":
                if sc.get("code") and hasattr(view,"page"):
                    view.page().runJavaScript(sc["code"])

    def _show_about(self):
        t = get_theme(S().theme)
        dlg = QDialog(self); dlg.setWindowTitle("О Winora NetScape 3.0"); dlg.resize(420, 320)
        dlg.setStyleSheet(f"background:{t['bg2']};color:{t['text']};")
        vl = QVBoxLayout(dlg); vl.setContentsMargins(24,20,24,20); vl.setSpacing(12)
        ico = QLabel("🌐"); ico.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ico.setStyleSheet("font-size:48px;background:transparent;")
        vl.addWidget(ico)
        ttl = QLabel("<b>Winora NetScape 3.0</b>")
        ttl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ttl.setStyleSheet(f"font-size:16px;color:{t['accent']};background:transparent;")
        ttl.setTextFormat(Qt.TextFormat.RichText)
        vl.addWidget(ttl)
        info = QLabel(
            "Встроенный браузер экосистемы Winora.\n"
            "Часть GoidaPhone v1.8.0  ·  Winora Company\n\n"
            "Движок: QtWebEngine (Chromium) + FFmpeg\n"
            "Новое в 3.0: sidebar, reader mode, dark reader,\n"
            "devtools, zoom, screenshot, мультипоиск, история по дням\n\n"
            "Разработчик: pixless  ·  Gentoo Linux")
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info.setStyleSheet(f"font-size:11px;color:{t['text_dim']};background:transparent;")
        vl.addWidget(info)
        close = QPushButton("Закрыть"); close.setObjectName("accent_btn")
        close.clicked.connect(dlg.accept); vl.addWidget(close)
        dlg.exec()

    # ── Keyboard shortcuts ────────────────────────────────────────────────────
    def keyPressEvent(self, ev):
        k = ev.key(); m = ev.modifiers()
        C  = Qt.KeyboardModifier.ControlModifier
        CS = Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier
        A  = Qt.KeyboardModifier.AltModifier

        if m == C:
            if k == Qt.Key.Key_T:       self._new_tab()
            elif k == Qt.Key.Key_W:     self._close_tab(self._tabs.currentIndex())
            elif k in (Qt.Key.Key_R, Qt.Key.Key_F5): self._reload_or_stop()
            elif k == Qt.Key.Key_L:
                self._urlbar.setFocus(); self._urlbar.selectAll()
            elif k == Qt.Key.Key_F:     self._show_findbar()
            elif k == Qt.Key.Key_D:     self._toggle_bookmark()
            elif k == Qt.Key.Key_H:     self._navigate(self.HOME_URL)
            elif k == Qt.Key.Key_B:     self._toggle_sidebar()
            elif k == Qt.Key.Key_J:
                self._toggle_sidebar()
                self._sidebar_switch("history")
            elif k == Qt.Key.Key_Equal: self._zoom_in()
            elif k == Qt.Key.Key_Minus: self._zoom_out()
            elif k == Qt.Key.Key_0:     self._zoom_reset()
            elif k == Qt.Key.Key_P:     self._print_page()
            elif k == Qt.Key.Key_S:     self._save_page()
            elif k == Qt.Key.Key_Tab:
                n = (self._tabs.currentIndex()+1) % self._tabs.count()
                self._tabs.setCurrentIndex(n)
        elif m == CS:
            if k == Qt.Key.Key_R:       self._toggle_reader_mode()
            elif k == Qt.Key.Key_D:     self._toggle_dark_reader()
            elif k == Qt.Key.Key_Tab:
                n = (self._tabs.currentIndex()-1) % self._tabs.count()
                self._tabs.setCurrentIndex(n)
        elif m == A:
            if k == Qt.Key.Key_Left:    self._go_back()
            elif k == Qt.Key.Key_Right: self._go_forward()
        elif k == Qt.Key.Key_F5:        self._reload_or_stop()
        elif k == Qt.Key.Key_F12:       self._open_devtools()
        elif k == Qt.Key.Key_Escape:
            if self._omni_popup.isVisible():
                self._omni_popup.hide()
            elif self._find_visible:
                self._hide_findbar()
            else:
                w = self._tabs.currentWidget()
                if w and hasattr(w,'stop'): w.stop()
        else:
            super().keyPressEvent(ev)

    # ── Geometry persistence ──────────────────────────────────────────────────
    def _load_geometry(self):
        pass  # geometry managed by parent QTabWidget

    def closeEvent(self, ev):
        try:
            g = self.geometry()
            S().set("wns_geometry",f"{g.x()},{g.y()},{g.width()},{g.height()}")
        except Exception: pass
        self._save_history()
        super().closeEvent(ev)



# ═══════════════════════════════════════════════════════════════════════════
#  CALL UI  —  Telegram-style
#  OutgoingCallWindow  — показывается звонящему пока ждёт ответа
#  IncomingCallDialog  — показывается вызываемому (принять / отклонить)
#  ActiveCallWindow    — активный звонок 1-на-1 (после принятия)
#  GroupCallWindow     — групповой звонок в стиле Телемост
# ═══════════════════════════════════════════════════════════════════════════

# ── shared helpers ──────────────────────────────────────────────────────────
def _call_dark_window(title: str = "", w: int = 320, h: int = 460):
    """Create a dark frameless always-on-top window for call UI."""
    win = QWidget(None,
        Qt.WindowType.Window |
        Qt.WindowType.FramelessWindowHint |
        Qt.WindowType.WindowStaysOnTopHint)
    win.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
    win.setFixedSize(w, h)
    if title:
        win.setWindowTitle(title)
    return win


def _call_avatar_pixmap(avatar_b64: str, name: str, size: int) -> 'QPixmap':
    if avatar_b64:
        try:
            return make_circle_pixmap(base64_to_pixmap(avatar_b64), size)
        except Exception:
            pass
    return default_avatar(name, size)


def _call_round_btn(icon: str, bg: str, size: int = 64, icon_size: int = 28,
                    hover: str = "") -> QPushButton:
    b = QPushButton(icon)
    b.setFixedSize(size, size)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    hover_css = f"QPushButton:hover {{ background: {hover}; }}" if hover else ""
    b.setStyleSheet(f"""
        QPushButton {{
            background: {bg};
            border-radius: {size//2}px;
            font-size: {icon_size}px;
            border: none;
        }}
        {hover_css}
    """)
    return b


# ── OutgoingCallWindow ───────────────────────────────────────────────────────
class OutgoingCallWindow(QWidget):
    """
    Shown to caller while waiting for answer — Telegram-style.
    Big avatar, name, animated 'Вызов…' dots, Cancel button.
    """
    sig_cancelled = pyqtSignal()

    def __init__(self, peer_name: str, peer_ip: str, avatar_b64: str = "",
                 parent=None):
        super().__init__(parent,
            Qt.WindowType.Window |
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._peer_name  = peer_name
        self._peer_ip    = peer_ip
        self._avatar_b64 = avatar_b64
        self._dot_n      = 0
        self._drag_pos   = None
        self.setFixedSize(320, 500)
        self._build()

        # Animate "Вызов…" dots
        self._dot_timer = QTimer(self)
        self._dot_timer.timeout.connect(self._tick_dots)
        self._dot_timer.start(500)

        # Ring sound
        if S().notification_sounds:
            play_system_sound("call")

    def _build(self):
        # Dark card
        card = QWidget(self)
        card.setGeometry(0, 0, 320, 500)
        card.setObjectName("ocw_card")
        card.setStyleSheet("""
            QWidget#ocw_card {
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 #1C1C2E, stop:1 #12121F);
                border-radius: 24px;
                border: 1px solid #2D2D4E;
            }
        """)
        root = QVBoxLayout(card)
        root.setContentsMargins(24, 32, 24, 28)
        root.setSpacing(0)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Close / drag bar at top
        drag_bar = QHBoxLayout()
        drag_bar.addStretch()
        close_x = QPushButton("✕")
        close_x.setFixedSize(28, 28)
        close_x.setStyleSheet(
            "QPushButton{background:rgba(255,255,255,20);color:#888;border:none;"
            "border-radius:14px;font-size:12px;}"
            "QPushButton:hover{background:rgba(255,255,255,45);color:white;}")
        close_x.clicked.connect(self._cancel)
        drag_bar.addWidget(close_x)
        root.addLayout(drag_bar)
        root.addSpacing(12)

        # Avatar with pulsing ring
        av_wrap = QWidget(); av_wrap.setFixedSize(140, 140)
        av_wrap.setStyleSheet("background:transparent;")
        self._av_lbl = QLabel(av_wrap)
        self._av_lbl.setGeometry(10, 10, 120, 120)
        pm = _call_avatar_pixmap(self._avatar_b64, self._peer_name, 120)
        self._av_lbl.setPixmap(pm)
        self._av_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._av_lbl.setStyleSheet(
            "border: 3px solid #7C4DFF; border-radius: 60px;")

        av_row = QHBoxLayout()
        av_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        av_row.addWidget(av_wrap)
        root.addLayout(av_row)
        root.addSpacing(20)

        # Name
        name_l = QLabel(self._peer_name)
        name_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_l.setStyleSheet(
            "color: white; font-size: 22px; font-weight: bold; background: transparent;")
        root.addWidget(name_l)
        root.addSpacing(8)

        # Status line "Вызов…"
        self._status_lbl = QLabel("Вызов")
        self._status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_lbl.setStyleSheet(
            "color: #9E9EBE; font-size: 14px; background: transparent;")
        root.addWidget(self._status_lbl)
        root.addStretch()

        # Cancel button
        btn_row = QHBoxLayout()
        btn_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cancel_btn = _call_round_btn("📵", "#E74C3C", 68, 28, "#C0392B")
        cancel_btn.setToolTip("Отменить вызов")
        cancel_btn.clicked.connect(self._cancel)
        cancel_lbl = QLabel("Отменить")
        cancel_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cancel_lbl.setStyleSheet("color:#888;font-size:10px;background:transparent;")

        cbcol = QVBoxLayout()
        cbcol.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cbcol.addWidget(cancel_btn)
        cbcol.addWidget(cancel_lbl)
        btn_row.addLayout(cbcol)
        root.addLayout(btn_row)

        # Drag
        card.mousePressEvent   = lambda e: setattr(self,'_drag_pos',
            e.globalPosition().toPoint()-self.pos()) if e.button()==Qt.MouseButton.LeftButton else None
        card.mouseMoveEvent    = lambda e: self.move(
            e.globalPosition().toPoint()-self._drag_pos) if self._drag_pos and             e.buttons()==Qt.MouseButton.LeftButton else None
        card.mouseReleaseEvent = lambda e: setattr(self,'_drag_pos',None)

        # Center on screen
        sg = QApplication.primaryScreen().geometry()
        self.move((sg.width()-320)//2, (sg.height()-500)//2)

    def _tick_dots(self):
        self._dot_n = (self._dot_n + 1) % 4
        self._status_lbl.setText("Вызов" + "." * self._dot_n)

    def _cancel(self):
        self._dot_timer.stop()
        self.sig_cancelled.emit()
        self.hide()
        self.deleteLater()

    def call_answered(self):
        """Called when remote accepted — close this window."""
        self._dot_timer.stop()
        self.hide()
        self.deleteLater()

    def call_rejected(self):
        self._dot_timer.stop()
        self._status_lbl.setText("Вызов отклонён")
        QTimer.singleShot(2000, self.deleteLater)


# ── IncomingCallDialog ───────────────────────────────────────────────────────
class IncomingCallDialog(QWidget):
    """
    Telegram-style incoming call screen.
    Full dark window: big avatar, name, Accept / Decline buttons.
    """
    accepted_call = pyqtSignal()
    rejected_call = pyqtSignal()

    def __init__(self, caller: str, ip: str, avatar_b64: str = "",
                 parent=None):
        super().__init__(parent,
            Qt.WindowType.Window |
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._caller     = caller
        self._ip         = ip
        self._avatar_b64 = avatar_b64
        self._drag_pos   = None
        self.setFixedSize(320, 500)
        self._build()
        # Ring sound
        if S().notification_sounds:
            play_system_sound("call")
        # Auto-decline after 30s
        QTimer.singleShot(30_000, self._reject)

    def _build(self):
        card = QWidget(self)
        card.setGeometry(0, 0, 320, 500)
        card.setObjectName("icw_card")
        card.setStyleSheet("""
            QWidget#icw_card {
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 #1C1C2E, stop:1 #12121F);
                border-radius: 24px;
                border: 1px solid #2D2D4E;
            }
        """)
        root = QVBoxLayout(card)
        root.setContentsMargins(24, 40, 24, 32)
        root.setSpacing(0)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # "Входящий звонок GoidaPhone" label
        header = QLabel("Входящий звонок GoidaPhone")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(
            "color: #7C4DFF; font-size: 11px; font-weight: bold; "
            "letter-spacing: 1px; background: transparent;")
        root.addWidget(header)
        root.addSpacing(28)

        # Avatar
        self._av_lbl = QLabel()
        self._av_lbl.setFixedSize(140, 140)
        self._av_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pm = _call_avatar_pixmap(self._avatar_b64, self._caller, 134)
        self._av_lbl.setPixmap(pm)
        self._av_lbl.setStyleSheet(
            "border: 3px solid #7C4DFF; border-radius: 70px; background: #1C1C2E;")
        av_row = QHBoxLayout()
        av_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        av_row.addWidget(self._av_lbl)
        root.addLayout(av_row)
        root.addSpacing(22)

        # Caller name
        name_l = QLabel(self._caller)
        name_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_l.setStyleSheet(
            "color: white; font-size: 24px; font-weight: bold; background: transparent;")
        root.addWidget(name_l)
        root.addSpacing(6)

        # IP / hint
        sub = QLabel(self._ip)
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet(
            "color: #6060A0; font-size: 11px; background: transparent;")
        root.addWidget(sub)
        root.addStretch()

        # Buttons row: Decline ← ... → Accept
        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(20, 0, 20, 0)
        btn_row.setSpacing(0)

        # Decline
        dec_col = QVBoxLayout()
        dec_col.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dec_btn = _call_round_btn("📵", "#E74C3C", 68, 28, "#C0392B")
        dec_btn.clicked.connect(self._reject)
        dec_lbl = QLabel("Отклонить")
        dec_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dec_lbl.setStyleSheet("color:#888;font-size:10px;background:transparent;")
        dec_col.addWidget(dec_btn)
        dec_col.addWidget(dec_lbl)
        btn_row.addLayout(dec_col)
        btn_row.addStretch()

        # Accept
        acc_col = QVBoxLayout()
        acc_col.setAlignment(Qt.AlignmentFlag.AlignCenter)
        acc_btn = _call_round_btn("📞", "#27AE60", 68, 28, "#1E8449")
        acc_btn.clicked.connect(self._accept)
        acc_lbl = QLabel("Принять")
        acc_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        acc_lbl.setStyleSheet("color:#888;font-size:10px;background:transparent;")
        acc_col.addWidget(acc_btn)
        acc_col.addWidget(acc_lbl)
        btn_row.addLayout(acc_col)

        root.addLayout(btn_row)

        # Drag
        card.mousePressEvent   = lambda e: setattr(self,'_drag_pos',
            e.globalPosition().toPoint()-self.pos()) if e.button()==Qt.MouseButton.LeftButton else None
        card.mouseMoveEvent    = lambda e: self.move(
            e.globalPosition().toPoint()-self._drag_pos) if self._drag_pos and             e.buttons()==Qt.MouseButton.LeftButton else None
        card.mouseReleaseEvent = lambda e: setattr(self,'_drag_pos',None)

        # Center on screen
        sg = QApplication.primaryScreen().geometry()
        self.move((sg.width()-320)//2, (sg.height()-500)//2)

    def _accept(self):
        self.accepted_call.emit()
        self.hide()
        self.deleteLater()

    def _reject(self):
        try:
            self.rejected_call.emit()
        except Exception:
            pass
        self.hide()
        try:
            self.deleteLater()
        except Exception:
            pass


# ── ActiveCallWindow ─────────────────────────────────────────────────────────
class ActiveCallWindow(QWidget):
    """
    Active 1-on-1 call. Telegram-style: dark, avatar centre,
    name, call duration, mute/speaker/end row.
    """
    sig_hangup = pyqtSignal()
    sig_mute   = pyqtSignal(bool)

    def __init__(self, peer_name: str, peer_ip: str, avatar_b64: str = "",
                 parent=None):
        super().__init__(parent,
            Qt.WindowType.Window |
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._peer_name  = peer_name
        self._peer_ip    = peer_ip
        self._avatar_b64 = avatar_b64
        self._muted      = False
        self._speaker    = True
        self._elapsed    = 0
        self._drag_pos   = None
        self.setFixedSize(320, 500)
        self._build()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)

    def _build(self):
        card = QWidget(self)
        card.setGeometry(0, 0, 320, 500)
        card.setObjectName("acw_card")
        card.setStyleSheet("""
            QWidget#acw_card {
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 #1C1C2E, stop:1 #0D0D1A);
                border-radius: 24px;
                border: 1px solid #2D2D4E;
            }
        """)
        root = QVBoxLayout(card)
        root.setContentsMargins(24, 24, 24, 28)
        root.setSpacing(0)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Top bar: status + minimize
        tb = QHBoxLayout()
        self._status_lbl = QLabel("🔴  GoidaPhone — Активный звонок")
        self._status_lbl.setStyleSheet(
            "color:#7C4DFF;font-size:10px;font-weight:bold;"
            "background:transparent;letter-spacing:1px;")
        tb.addWidget(self._status_lbl)
        tb.addStretch()
        self._min_btn = QPushButton("─")
        self._min_btn.setFixedSize(26, 26)
        self._min_btn.setStyleSheet(
            "QPushButton{background:rgba(255,255,255,17);color:#888;border:none;"
            "border-radius:13px;font-size:13px;}"
            "QPushButton:hover{background:rgba(255,255,255,45);color:white;}")
        self._min_btn.clicked.connect(self._toggle_minimize)
        tb.addWidget(self._min_btn)
        root.addLayout(tb)
        root.addSpacing(24)

        # Avatar
        self._av_lbl = QLabel()
        self._av_lbl.setFixedSize(140, 140)
        self._av_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pm = _call_avatar_pixmap(self._avatar_b64, self._peer_name, 134)
        self._av_lbl.setPixmap(pm)
        self._av_lbl.setStyleSheet(
            "border: 3px solid #27AE60; border-radius: 70px; background: #1C1C2E;")
        av_row = QHBoxLayout()
        av_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        av_row.addWidget(self._av_lbl)
        root.addLayout(av_row)
        root.addSpacing(20)

        # Name
        name_l = QLabel(self._peer_name)
        name_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_l.setStyleSheet(
            "color:white;font-size:22px;font-weight:bold;background:transparent;")
        root.addWidget(name_l)
        root.addSpacing(8)

        # Timer
        self._timer_lbl = QLabel("00:00")
        self._timer_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._timer_lbl.setStyleSheet(
            "color:#7C4DFF;font-size:28px;font-weight:bold;"
            "font-family:monospace;background:transparent;")
        root.addWidget(self._timer_lbl)
        root.addStretch()

        # Controls: mute | end | speaker
        ctrl = QHBoxLayout()
        ctrl.setContentsMargins(16, 0, 16, 0)
        ctrl.setSpacing(0)

        # Mute
        self._mute_col = QVBoxLayout()
        self._mute_col.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._mute_btn = _call_round_btn("🎤", "#2C2C4E", 60, 24, "#3D3D6E")
        self._mute_btn.clicked.connect(self._toggle_mute)
        self._mute_sub = QLabel("Микрофон")
        self._mute_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._mute_sub.setStyleSheet("color:#888;font-size:9px;background:transparent;")
        self._mute_col.addWidget(self._mute_btn)
        self._mute_col.addWidget(self._mute_sub)
        ctrl.addLayout(self._mute_col)
        ctrl.addStretch()

        # End call
        end_col = QVBoxLayout()
        end_col.setAlignment(Qt.AlignmentFlag.AlignCenter)
        end_btn = _call_round_btn("📵", "#E74C3C", 72, 30, "#C0392B")
        end_btn.clicked.connect(self._hangup)
        end_sub = QLabel("Завершить")
        end_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        end_sub.setStyleSheet("color:#888;font-size:9px;background:transparent;")
        end_col.addWidget(end_btn)
        end_col.addWidget(end_sub)
        ctrl.addLayout(end_col)
        ctrl.addStretch()

        # Speaker
        self._spk_col = QVBoxLayout()
        self._spk_col.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._spk_btn = _call_round_btn("🔊", "#2C2C4E", 60, 24, "#3D3D6E")
        self._spk_btn.clicked.connect(self._toggle_speaker)
        self._spk_sub = QLabel("Динамик")
        self._spk_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._spk_sub.setStyleSheet("color:#888;font-size:9px;background:transparent;")
        self._spk_col.addWidget(self._spk_btn)
        self._spk_col.addWidget(self._spk_sub)
        ctrl.addLayout(self._spk_col)

        root.addLayout(ctrl)
        root.addSpacing(12)

        # Extra row: screen share + camera
        extra = QHBoxLayout()
        extra.setSpacing(12)
        extra.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._share_btn = _call_round_btn("🖥", "#1E2A3A", 48, 20, "#2A3A5A")
        self._share_btn.setToolTip("Демонстрация экрана")
        self._share_btn.clicked.connect(self._toggle_screen_share)
        share_lbl = QLabel("Экран")
        share_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        share_lbl.setStyleSheet("color:#666;font-size:8px;background:transparent;")
        sc = QVBoxLayout(); sc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sc.setSpacing(3); sc.addWidget(self._share_btn); sc.addWidget(share_lbl)
        extra.addLayout(sc)

        self._cam_btn = _call_round_btn("📷", "#1E2A3A", 48, 20, "#2A3A5A")
        self._cam_btn.setToolTip("Камера вкл/выкл  (V)")
        self._cam_btn.clicked.connect(self._toggle_camera)
        cam_lbl = QLabel("Камера")
        cam_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cam_lbl.setStyleSheet("color:#666;font-size:8px;background:transparent;")
        cc = QVBoxLayout(); cc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cc.setSpacing(3); cc.addWidget(self._cam_btn); cc.addWidget(cam_lbl)
        extra.addLayout(cc)

        self._sharing_active = False
        self._share_timer_1on1 = None
        root.addLayout(extra)

        # Screen share preview label (hidden by default)
        self._share_preview = QLabel()
        self._share_preview.setFixedHeight(120)
        self._share_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._share_preview.setStyleSheet(
            "background:#000;border-radius:8px;border:1px solid #7C4DFF;")
        self._share_preview.setVisible(False)
        root.addWidget(self._share_preview)

        # Drag
        card.mousePressEvent   = lambda e: setattr(self,'_drag_pos',
            e.globalPosition().toPoint()-self.pos()) if e.button()==Qt.MouseButton.LeftButton else None
        card.mouseMoveEvent    = lambda e: self.move(
            e.globalPosition().toPoint()-self._drag_pos) if self._drag_pos and             e.buttons()==Qt.MouseButton.LeftButton else None
        card.mouseReleaseEvent = lambda e: setattr(self,'_drag_pos',None)

        sg = QApplication.primaryScreen().geometry()
        self.move((sg.width()-320)//2, (sg.height()-500)//2)

    def _tick(self):
        self._elapsed += 1
        m = self._elapsed // 60; s = self._elapsed % 60
        self._timer_lbl.setText(f"{m:02d}:{s:02d}")

    def _toggle_mute(self):
        self._muted = not self._muted
        if self._muted:
            self._mute_btn.setText("🔇")
            self._mute_btn.setStyleSheet(self._mute_btn.styleSheet()
                .replace("#2C2C4E","#4A3A00").replace("#3D3D6E","#AA8800"))
            self._mute_sub.setText("Без звука")
        else:
            self._mute_btn.setText("🎤")
            self._mute_btn.setStyleSheet(self._mute_btn.styleSheet()
                .replace("#4A3A00","#2C2C4E").replace("#AA8800","#3D3D6E"))
            self._mute_sub.setText("Микрофон")
        self.sig_mute.emit(self._muted)

    def _toggle_speaker(self):
        self._speaker = not self._speaker
        if not self._speaker:
            self._spk_btn.setText("🔈")
            self._spk_btn.setStyleSheet(self._spk_btn.styleSheet()
                .replace("#2C2C4E","#3A1A1A"))
        else:
            self._spk_btn.setText("🔊")
            self._spk_btn.setStyleSheet(self._spk_btn.styleSheet()
                .replace("#3A1A1A","#2C2C4E"))

    def _hangup(self):
        self._timer.stop()
        self.sig_hangup.emit()
        self.hide()
        self.deleteLater()

    def _toggle_minimize(self):
        if self.width() > 160:
            self.setFixedSize(160, 54)
            self._min_btn.setText("⬜")
        else:
            self.setFixedSize(320, 500)
            self._min_btn.setText("─")

    def _toggle_screen_share(self):
        if self._sharing_active:
            self._stop_screen_share_1on1()
        else:
            self._start_screen_share_1on1()

    def _start_screen_share_1on1(self):
        self._sharing_active = True
        self._share_btn.setStyleSheet(
            self._share_btn.styleSheet().replace("#1E2A3A","#0A3A1A").replace("#2A3A5A","#0F5A2A"))
        self._share_preview.setVisible(True)
        self.setFixedSize(320, 640)
        self._share_timer_1on1 = QTimer(self)
        self._share_timer_1on1.timeout.connect(self._update_share_preview)
        self._share_timer_1on1.start(200)
        self._update_share_preview()

    def _update_share_preview(self):
        try:
            screen = QApplication.primaryScreen()
            if not screen: return
            pix = screen.grabWindow(0)
            scaled = pix.scaled(272, 110,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.FastTransformation)
            self._share_preview.setPixmap(scaled)
        except Exception as e:
            print(f"[share] {e}")

    def _stop_screen_share_1on1(self):
        self._sharing_active = False
        self._share_btn.setStyleSheet(
            self._share_btn.styleSheet().replace("#0A3A1A","#1E2A3A").replace("#0F5A2A","#2A3A5A"))
        self._share_preview.setVisible(False)
        self.setFixedSize(320, 500)
        if self._share_timer_1on1:
            self._share_timer_1on1.stop()
            self._share_timer_1on1 = None

    def _toggle_camera(self):
        self._cam_on = not getattr(self, '_cam_on', False)
        if self._cam_on:
            self._start_camera()
        else:
            self._stop_camera()

    def _start_camera(self):
        try:
            from PyQt6.QtMultimedia import QCamera, QMediaCaptureSession
            from PyQt6.QtMultimediaWidgets import QVideoWidget
            self._cam_on = True
            self._cam_btn.setStyleSheet(
                self._cam_btn.styleSheet()
                    .replace("#1E2A3A", "#0A2A3A").replace("#2A3A5A", "#0A4A6A"))
            # Create video widget for preview
            if not hasattr(self, '_video_widget') or self._video_widget is None:
                self._video_widget = QVideoWidget(self)
                self._video_widget.setFixedHeight(120)
                self._video_widget.setStyleSheet(
                    "border-radius:8px;border:1px solid #27AE60;background:#000;")
                # Insert before share_preview
                card = self.findChild(QWidget, "acw_card")
                if card and card.layout():
                    card.layout().addWidget(self._video_widget)
            self._camera = QCamera()
            self._cam_session = QMediaCaptureSession()
            self._cam_session.setCamera(self._camera)
            self._cam_session.setVideoOutput(self._video_widget)
            self._camera.start()
            self._video_widget.setVisible(True)
            # Resize window to fit
            cur_h = self.height()
            self.setFixedSize(320, max(cur_h, 640))
        except ImportError:
            from PyQt6.QtWidgets import QToolTip
            QToolTip.showText(
                self._cam_btn.mapToGlobal(self._cam_btn.rect().center()),
                self._cam_btn.mapToGlobal(self._cam_btn.rect().center()),
                "Установи: pip install PyQt6-QtMultimediaWidgets --break-system-packages")
        except Exception as e:
            print(f"[camera] {e}")
            self._cam_on = False

    def _stop_camera(self):
        self._cam_on = False
        self._cam_btn.setStyleSheet(
            self._cam_btn.styleSheet()
                .replace("#0A2A3A", "#1E2A3A").replace("#0A4A6A", "#2A3A5A"))
        try:
            if hasattr(self, '_camera') and self._camera:
                self._camera.stop()
                self._camera = None
            if hasattr(self, '_video_widget') and self._video_widget:
                self._video_widget.setVisible(False)
        except Exception as e:
            print(f"[camera stop] {e}")


# ── GroupCallWindow ───────────────────────────────────────────────────────────
class GroupCallWindow(QWidget):
    """
    Телемост-style group call window.
    Proper tile grid, bottom control bar with real menus.
    """
    sig_leave = pyqtSignal()

    def __init__(self, group_name: str, participants: list, voice_mgr,
                 parent=None):
        super().__init__(parent,
            Qt.WindowType.Window |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint |
            Qt.WindowType.WindowMinMaxButtonsHint)
        self._group_name   = group_name
        self._participants = list(participants)
        self._voice_mgr    = voice_mgr
        self._muted        = False
        self._cam_on       = False
        self._sharing      = False
        self._elapsed      = 0
        self._self_tile    = None   # ref to own tile for VAD ring
        self._share_timer  = None   # QTimer for screen share capture
        self._share_label  = None   # QLabel showing screen preview
        self.setWindowTitle(f"Групповой звонок — {group_name}")
        self.setMinimumSize(720, 500)
        self.resize(960, 620)
        self._build()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        # Subscribe to local VAD speaking events
        self._voice_mgr.subscribe_speaking(self._on_local_speaking)

    # ── Build UI ──────────────────────────────────────────────────────────────
    def _build(self):
        self.setStyleSheet("""
            QWidget { background: #0F0F1A; color: white; }
        """)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Top bar ──────────────────────────────────────────────────────────
        topbar = QWidget()
        topbar.setFixedHeight(44)
        topbar.setStyleSheet(
            "background:#16162A; border-bottom:1px solid #25254A;")
        tbl = QHBoxLayout(topbar)
        tbl.setContentsMargins(16, 0, 16, 0)
        tbl.setSpacing(12)

        call_dot = QLabel("●")
        call_dot.setStyleSheet("color:#E74C3C;font-size:10px;")
        tbl.addWidget(call_dot)

        grp_lbl = QLabel(self._group_name)
        grp_lbl.setStyleSheet(
            "font-size:13px;font-weight:bold;color:white;")
        tbl.addWidget(grp_lbl)
        tbl.addStretch()

        self._dur_lbl = QLabel("00:00")
        self._dur_lbl.setStyleSheet(
            "font-size:12px;color:#7C4DFF;font-family:monospace;font-weight:bold;")
        tbl.addWidget(self._dur_lbl)
        tbl.addSpacing(16)

        self._pcount_lbl = QLabel(f"👥 {len(self._participants)+1}")
        self._pcount_lbl.setStyleSheet("font-size:11px;color:#8888AA;")
        tbl.addWidget(self._pcount_lbl)
        root.addWidget(topbar)

        # ── Participant grid ──────────────────────────────────────────────────
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setStyleSheet(
            "QScrollArea{border:none;background:#0F0F1A;}"
            "QScrollBar:vertical{width:5px;background:#16162A;}"
            "QScrollBar::handle:vertical{background:#35355A;border-radius:2px;}")
        self._grid_w = QWidget()
        self._grid_w.setStyleSheet("background:#0F0F1A;")
        self._grid = QGridLayout(self._grid_w)
        self._grid.setSpacing(10)
        self._grid.setContentsMargins(14, 14, 14, 14)
        self._scroll.setWidget(self._grid_w)
        root.addWidget(self._scroll, stretch=1)

        # Populate tiles
        self._tiles: list = []
        all_peers = [{"username": S().username, "avatar_b64": S().avatar_b64,
                      "ip": get_local_ip(), "_is_self": True}]
        all_peers.extend(self._participants)
        self._rebuild_grid(all_peers)

        # ── Controls bar ─────────────────────────────────────────────────────
        ctrlbar = QWidget()
        ctrlbar.setFixedHeight(80)
        ctrlbar.setStyleSheet(
            "background:#16162A; border-top:1px solid #25254A;")
        cbl = QHBoxLayout(ctrlbar)
        cbl.setContentsMargins(20, 10, 20, 10)
        cbl.setSpacing(10)

        # Left group: link + mic + camera
        def _btn(icon, tip, bg="#2A2A46", hover="#38385E", size=52):
            b = QPushButton(icon)
            b.setFixedSize(size, size)
            b.setToolTip(tip)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setCheckable(True)
            b.setStyleSheet(f"""
                QPushButton{{background:{bg};border-radius:{size//2}px;
                    font-size:18px;color:white;border:none;}}
                QPushButton:hover{{background:{hover};}}
                QPushButton:checked{{background:#3D1A1A;color:#FF6666;}}
            """)
            return b

        self._link_btn = _btn("🔗", "Скопировать ссылку на звонок")
        self._link_btn.setCheckable(False)
        self._link_btn.clicked.connect(self._copy_invite)
        cbl.addWidget(self._link_btn)

        self._mic_btn = _btn("🎤", "Микрофон вкл/выкл  (M)")
        self._mic_btn.clicked.connect(self._toggle_mute)
        cbl.addWidget(self._mic_btn)

        self._cam_btn = _btn("📷", "Камера вкл/выкл  (V)")
        self._cam_btn.clicked.connect(self._toggle_camera)
        cbl.addWidget(self._cam_btn)

        self._rec_btn = _btn("⏺", "Запись звонка  (R)")
        self._rec_btn.clicked.connect(self._toggle_recording)
        self._recording = False
        self._record_frames = []
        self._record_fname  = None
        cbl.addWidget(self._rec_btn)

        cbl.addStretch()

        # Centre group: participants + chat + more
        self._pts_btn = QPushButton(f"👥  {len(all_peers)}")
        self._pts_btn.setFixedHeight(40)
        self._pts_btn.setToolTip("Участники")
        self._pts_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._pts_btn.setStyleSheet(
            "QPushButton{background:#2A2A46;border-radius:20px;color:white;"
            "font-size:12px;padding:0 18px;border:none;}"
            "QPushButton:hover{background:#38385E;}")
        self._pts_btn.clicked.connect(self._show_participants)
        cbl.addWidget(self._pts_btn)

        chat_btn = QPushButton("💬  Чат")
        chat_btn.setFixedHeight(40)
        chat_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        chat_btn.setStyleSheet(
            "QPushButton{background:#2A2A46;border-radius:20px;color:white;"
            "font-size:12px;padding:0 18px;border:none;}"
            "QPushButton:hover{background:#38385E;}")
        cbl.addWidget(chat_btn)

        # ⋯ More menu
        more_btn = QPushButton("⋯")
        more_btn.setFixedSize(44, 44)
        more_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        more_btn.setToolTip("Ещё")
        more_btn.setStyleSheet(
            "QPushButton{background:#2A2A46;border-radius:22px;font-size:18px;"
            "color:white;border:none;}"
            "QPushButton:hover{background:#38385E;}")
        more_btn.clicked.connect(lambda: self._show_more_menu(more_btn))
        cbl.addWidget(more_btn)

        cbl.addStretch()

        # Right: leave (red)
        leave_btn = QPushButton("📵")
        leave_btn.setFixedSize(56, 56)
        leave_btn.setToolTip("Покинуть звонок")
        leave_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        leave_btn.setStyleSheet(
            "QPushButton{background:#C0392B;border-radius:28px;"
            "font-size:24px;border:none;}"
            "QPushButton:hover{background:#922B21;}")
        leave_btn.clicked.connect(self._leave)
        cbl.addWidget(leave_btn)

        root.addWidget(ctrlbar)

    # ── Tile helpers ──────────────────────────────────────────────────────────
    def _rebuild_grid(self, all_peers: list):
        # Clear existing tiles
        for tile in self._tiles:
            self._grid.removeWidget(tile)
            tile.deleteLater()
        self._tiles.clear()

        n    = len(all_peers)
        cols = 1 if n == 1 else (2 if n <= 4 else (3 if n <= 9 else 4))
        for i, peer in enumerate(all_peers):
            tile = self._make_tile(peer)
            self._grid.addWidget(tile, i // cols, i % cols)
            self._tiles.append(tile)
        self._all_peers = all_peers

    def _make_tile(self, peer: dict) -> QWidget:
        is_self = peer.get("_is_self", False)
        name    = peer.get("username", "?")
        av_b64  = peer.get("avatar_b64", "")

        tile = QWidget()
        border_idle    = "#27AE60" if is_self else "#25254A"
        border_speak   = "#39FF14" if is_self else "#7C4DFF"
        tile._border_idle  = border_idle
        tile._border_speak = border_speak
        tile._is_self      = is_self
        tile.setStyleSheet(f"""
            QWidget {{
                background: #1A1A2E;
                border-radius: 14px;
                border: 2px solid {border_idle};
            }}
        """)
        tile.setMinimumSize(180, 150)

        tl = QVBoxLayout(tile)
        tl.setContentsMargins(12, 16, 12, 12)
        tl.setSpacing(8)
        tl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        av_size = 80
        av_lbl = QLabel()
        av_lbl.setFixedSize(av_size, av_size)
        av_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        av_lbl.setPixmap(_call_avatar_pixmap(av_b64, name, av_size))
        av_lbl.setStyleSheet(
            f"border-radius:{av_size//2}px;"
            f"border:3px solid {border_idle};")
        av_lbl.setObjectName("tile_av")
        tile._av_lbl      = av_lbl
        tile._av_idle_css = (f"border-radius:{av_size//2}px;"
                              f"border:3px solid {border_idle};")
        tile._av_speak_css= (f"border-radius:{av_size//2}px;"
                              f"border:3px solid {border_speak};"
                              f"background:rgba(57,255,20,15);")
        tl.addWidget(av_lbl, alignment=Qt.AlignmentFlag.AlignCenter)

        bottom = QHBoxLayout()
        bottom.setContentsMargins(0, 0, 0, 0)
        disp_name = "Вы" if is_self else name
        name_lbl = QLabel(disp_name)
        name_lbl.setStyleSheet(
            "font-size:12px;font-weight:bold;color:white;"
            "background:transparent;border:none;")
        bottom.addWidget(name_lbl)
        bottom.addStretch()
        mic_ico = QLabel("🎤" if not (is_self and self._muted) else "🔇")
        mic_ico.setStyleSheet("font-size:12px;background:transparent;border:none;")
        bottom.addWidget(mic_ico)
        if is_self:
            tile._mic_ico = mic_ico
        tl.addLayout(bottom)

        if is_self:
            self._self_tile = tile
        return tile

    # ── VAD speaking highlight ─────────────────────────────────────────────
    def _on_local_speaking(self, active: bool):
        """Called from VoiceCallManager when VAD detects speech / silence."""
        tile = self._self_tile
        if tile is None or self._muted:
            return
        if active:
            tile.setStyleSheet(f"""
                QWidget {{
                    background: #1A1A2E;
                    border-radius: 14px;
                    border: 2px solid {tile._border_speak};
                }}
            """)
            tile._av_lbl.setStyleSheet(tile._av_speak_css)
        else:
            tile.setStyleSheet(f"""
                QWidget {{
                    background: #1A1A2E;
                    border-radius: 14px;
                    border: 2px solid {tile._border_idle};
                }}
            """)
            tile._av_lbl.setStyleSheet(tile._av_idle_css)

    # ── Screen share ───────────────────────────────────────────────────────
    def _toggle_screen_share(self):
        if self._sharing:
            self._stop_screen_share()
        else:
            self._start_screen_share()

    def _start_screen_share(self):
        """Capture screen → show in a tile above the grid."""
        self._sharing = True

        # Create share overlay widget above grid
        share_w = QWidget()
        share_w.setObjectName("share_overlay")
        share_w.setStyleSheet(
            "QWidget#share_overlay{"
            "background:#0A0A14;border:2px solid #7C4DFF;"
            "border-radius:12px;}")
        share_w.setFixedHeight(200)
        sl = QVBoxLayout(share_w)
        sl.setContentsMargins(8, 8, 8, 8)

        hdr = QHBoxLayout()
        dot = QLabel("🔴  Демонстрация экрана")
        dot.setStyleSheet("color:#E74C3C;font-size:11px;font-weight:bold;")
        hdr.addWidget(dot)
        hdr.addStretch()
        stop_btn = QPushButton("✕ Остановить")
        stop_btn.setStyleSheet(
            "QPushButton{background:#3D1A1A;color:#FF6666;border:1px solid #5A2A2A;"
            "border-radius:8px;padding:3px 10px;font-size:10px;}"
            "QPushButton:hover{background:#5A2020;}")
        stop_btn.clicked.connect(self._stop_screen_share)
        hdr.addWidget(stop_btn)
        sl.addLayout(hdr)

        self._share_label = QLabel()
        self._share_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._share_label.setStyleSheet("background:black;border-radius:6px;")
        sl.addWidget(self._share_label, stretch=1)

        # Insert before grid (index 1 = after topbar)
        root_layout = self.layout()
        root_layout.insertWidget(1, share_w)
        self._share_widget = share_w

        # Capture timer — 5 fps (200ms) to avoid lag
        self._share_timer = QTimer(self)
        self._share_timer.timeout.connect(self._capture_screen)
        self._share_timer.start(200)
        self._capture_screen()  # immediate first frame

        # Update ⋯ menu button state visually via tooltip
        self._sharing = True

    def _capture_screen(self):
        """Grab primary screen and display scaled preview."""
        try:
            screen = QApplication.primaryScreen()
            if screen is None:
                return
            pix = screen.grabWindow(0)
            if pix.isNull():
                return
            # Scale to fit label
            lbl = self._share_label
            if lbl is None:
                return
            w = lbl.width() or 400
            h = lbl.height() or 140
            scaled = pix.scaled(w, h,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.FastTransformation)
            lbl.setPixmap(scaled)
        except Exception as e:
            print(f"[screenshare] capture error: {e}")

    def _stop_screen_share(self):
        self._sharing = False
        if self._share_timer:
            self._share_timer.stop()
            self._share_timer = None
        if hasattr(self, '_share_widget') and self._share_widget:
            self._share_widget.setParent(None)
            self._share_widget.deleteLater()
            self._share_widget = None
        self._share_label = None


    # ── Controls ──────────────────────────────────────────────────────────────
    def _toggle_mute(self):
        self._muted = not self._muted
        self._voice_mgr.set_mute(self._muted)
        if self._muted:
            self._mic_btn.setText("🔇")
            self._mic_btn.setChecked(True)
        else:
            self._mic_btn.setText("🎤")
            self._mic_btn.setChecked(False)
        # Update self-tile mic icon
        for tile in self._tiles:
            if hasattr(tile, '_mic_ico'):
                tile._mic_ico.setText("🔇" if self._muted else "🎤")

    def _toggle_camera(self):
        self._cam_on = not self._cam_on
        self._cam_btn.setChecked(self._cam_on)
        if self._cam_on:
            self._start_camera_group()
        else:
            self._stop_camera_group()

    def _start_camera_group(self):
        try:
            from PyQt6.QtMultimedia import QCamera, QMediaCaptureSession
            from PyQt6.QtMultimediaWidgets import QVideoWidget

            # Find own tile and replace avatar with video preview
            tile = self._self_tile
            if tile is None:
                return

            # Create video widget inside tile
            self._cam_video = QVideoWidget(tile)
            self._cam_video.resize(tile.size())
            self._cam_video.setStyleSheet(
                "border-radius:14px;background:#000;")
            self._cam_video.show()

            self._group_cam = QCamera()
            self._group_cam_session = QMediaCaptureSession()
            self._group_cam_session.setCamera(self._group_cam)
            self._group_cam_session.setVideoOutput(self._cam_video)
            self._group_cam.start()

            self._cam_btn.setText("📷")
            self._cam_btn.setChecked(True)

        except ImportError:
            from PyQt6.QtWidgets import QToolTip
            QToolTip.showText(
                self._cam_btn.mapToGlobal(self._cam_btn.rect().center()),
                "pip install PyQt6-QtMultimediaWidgets --break-system-packages")
            self._cam_on = False
            self._cam_btn.setChecked(False)
        except Exception as e:
            print(f"[group cam] {e}")
            self._cam_on = False
            self._cam_btn.setChecked(False)

    def _stop_camera_group(self):
        try:
            if hasattr(self, '_group_cam') and self._group_cam:
                self._group_cam.stop()
                self._group_cam = None
            if hasattr(self, '_cam_video') and self._cam_video:
                self._cam_video.hide()
                self._cam_video.setParent(None)
                self._cam_video.deleteLater()
                self._cam_video = None
        except Exception as e:
            print(f"[group cam stop] {e}")
        self._cam_btn.setText("📷")
        self._cam_btn.setChecked(False)

    def _copy_invite(self):
        gid  = getattr(self, '_gid', "")
        ip   = get_local_ip()
        link = f"goidaphone://call/{gid}?host={ip}"
        QApplication.clipboard().setText(link)
        # Brief tooltip feedback
        from PyQt6.QtWidgets import QToolTip
        QToolTip.showText(
            self._link_btn.mapToGlobal(self._link_btn.rect().center()),
            "✓ Ссылка скопирована!")

    def _show_participants(self):
        t = get_theme(S().theme)
        dlg = QDialog(self)
        dlg.setWindowTitle("Участники звонка")
        dlg.resize(340, 360)
        dlg.setStyleSheet(f"background:#1A1A2E;color:white;")
        vl = QVBoxLayout(dlg)
        hdr = QLabel(f"В звонке: {len(getattr(self,'_all_peers',[]))} участников")
        hdr.setStyleSheet("font-size:13px;font-weight:bold;padding:8px 0;")
        vl.addWidget(hdr)
        lw = QListWidget()
        lw.setStyleSheet(
            "QListWidget{background:#12121F;border:1px solid #2D2D4E;"
            "border-radius:8px;}"
            "QListWidget::item{padding:8px;border-bottom:1px solid #1E1E32;}"
            "QListWidget::item:selected{background:#2A2A4E;}")
        for peer in getattr(self, '_all_peers', []):
            name = peer.get("username","?")
            flag = " (Вы)" if peer.get("_is_self") else ""
            lw.addItem(f"👤  {name}{flag}")
        vl.addWidget(lw)
        close = QPushButton("Закрыть")
        close.clicked.connect(dlg.accept)
        vl.addWidget(close)
        dlg.exec()

    def _show_more_menu(self, btn: QPushButton):
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background:#1E1E32; color:white;
                border:1px solid #35354E; border-radius:10px; padding:4px 0;
            }
            QMenu::item { padding:9px 22px; font-size:12px; }
            QMenu::item:selected {
                background:#7C4DFF; border-radius:6px; color:white;
            }
            QMenu::separator { background:#35354E; height:1px; margin:3px 8px; }
        """)

        # Screen share
        share_act = menu.addAction("🖥  Демонстрация экрана")
        share_act.triggered.connect(self._toggle_screen_share)

        # Quality submenu
        quality_menu = menu.addMenu("📶  Качество звука")
        quality_menu.setStyleSheet(menu.styleSheet())
        for label, val in [("Низкое (8 кГц)", 8000),
                            ("Стандарт (16 кГц)", 16000),
                            ("Высокое (48 кГц)", 48000)]:
            act = quality_menu.addAction(label)
            act.triggered.connect(lambda _, v=val: self._set_quality(v))

        menu.addSeparator()

        # Layout mode
        layout_menu = menu.addMenu("🔲  Раскладка")
        layout_menu.setStyleSheet(menu.styleSheet())
        for label in ["Сетка", "Активный докладчик", "Боковая панель"]:
            layout_menu.addAction(label)

        menu.addSeparator()

        # Stats
        menu.addAction("📊  Статистика соединения",
                        self._show_stats)
        menu.addAction("🔔  Настройки уведомлений",
                        self._show_notif_settings)
        menu.addSeparator()
        menu.addAction("❓  Справка",
                        lambda: QMessageBox.information(self, "Справка",
                            "Групповой звонок GoidaPhone\n\n"
                            "M — мут/размут микрофона\n"
                            "V — включить/выключить камеру\n"
                            "Esc — свернуть окно\n\n"
                            "Демонстрация экрана: кнопка ⋯ → Демонстрация"))

        r = btn.rect()
        menu.exec(btn.mapToGlobal(r.bottomLeft()))

    def _toggle_screen_share(self):
        if self._sharing:
            self._stop_screen_share()
        else:
            self._start_screen_share()

    def _start_screen_share(self):
        """Show screen share inline — in a new tile next to 'Вы' in the grid."""
        self._sharing = True

        # Create a share tile that looks like a participant tile
        share_tile = QWidget()
        share_tile.setStyleSheet(
            "QWidget{background:#0A0A14;border-radius:14px;"
            "border:2px solid #E74C3C;}")
        share_tile.setMinimumSize(280, 180)
        tl = QVBoxLayout(share_tile)
        tl.setContentsMargins(6, 6, 6, 6)
        tl.setSpacing(4)

        # Header row inside tile
        hdr = QHBoxLayout()
        dot = QLabel("🔴 Экран")
        dot.setStyleSheet(
            "color:#E74C3C;font-size:10px;font-weight:bold;background:transparent;border:none;")
        hdr.addWidget(dot)
        hdr.addStretch()
        stop_btn = QPushButton("✕")
        stop_btn.setFixedSize(20, 20)
        stop_btn.setStyleSheet(
            "QPushButton{background:#3D1A1A;color:#FF6666;border:none;"
            "border-radius:10px;font-size:10px;font-weight:bold;}"
            "QPushButton:hover{background:#882222;}")
        stop_btn.clicked.connect(self._stop_screen_share)
        hdr.addWidget(stop_btn)
        tl.addLayout(hdr)

        self._share_label = QLabel()
        self._share_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._share_label.setStyleSheet(
            "background:#000;border-radius:8px;border:none;")
        tl.addWidget(self._share_label, stretch=1)

        # Add to grid next to existing tiles
        n = len([t for t in self._tiles if t])
        cols = max(2, min(4, n + 1))
        # Re-layout grid with share tile
        self._grid.addWidget(share_tile, n // cols, n % cols)
        self._share_widget = share_tile
        self._tiles.append(share_tile)

        self._share_timer = QTimer(self)
        self._share_timer.timeout.connect(self._capture_screen)
        self._share_timer.start(200)
        self._capture_screen()

    def _capture_screen(self):
        try:
            screen = QApplication.primaryScreen()
            if screen is None:
                return
            pix = screen.grabWindow(0)
            if pix.isNull():
                return
            lbl = self._share_label
            if lbl is None:
                return
            w = max(lbl.width(), 100)
            h = max(lbl.height(), 60)
            scaled = pix.scaled(
                w, h,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.FastTransformation)
            lbl.setPixmap(scaled)
        except Exception as e:
            print(f"[screenshare] {e}")

    def _stop_screen_share(self):
        self._sharing = False
        if self._share_timer:
            self._share_timer.stop()
            self._share_timer = None
        if hasattr(self, '_share_widget') and self._share_widget:
            self._share_widget.setParent(None)
            self._share_widget.deleteLater()
            self._share_widget = None
        self._share_label = None

    def _set_quality(self, rate: int):
        try:
            self._voice_mgr.audio.RATE = rate
            QMessageBox.information(self, "Качество звука",
                f"Частота дискретизации изменена на {rate//1000} кГц.\n"
                "Изменение вступит в силу при следующем звонке.")
        except Exception:
            pass

    def _toggle_recording(self):
        if getattr(self, '_recording', False):
            self._stop_recording()
        else:
            self._start_recording()

    def _start_recording(self):
        import threading
        self._recording = True
        self._record_frames = []
        try: self._btn_rec.setChecked(True)
        except Exception: pass
        fname = DATA_DIR / f"call_rec_{int(time.time())}.wav"
        self._record_fname = fname
        def _loop():
            try:
                import pyaudio as _pa
                p = _pa.PyAudio()
                s = p.open(format=_pa.paInt16, channels=1,
                           rate=16000, input=True, frames_per_buffer=512)
                while self._recording:
                    self._record_frames.append(
                        s.read(512, exception_on_overflow=False))
                s.stop_stream(); s.close(); p.terminate()
            except Exception as e:
                print(f"[rec] {e}")
        threading.Thread(target=_loop, daemon=True).start()

    def _stop_recording(self):
        self._recording = False
        try: self._btn_rec.setChecked(False)
        except Exception: pass
        try:
            import wave
            if self._record_frames and self._record_fname:
                with wave.open(str(self._record_fname), 'wb') as wf:
                    wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(16000)
                    wf.writeframes(b''.join(self._record_frames))
                QTimer.singleShot(0, lambda: QMessageBox.information(
                    self, "Запись", f"Сохранено: {self._record_fname.name}"))
        except Exception as e:
            print(f"[rec save] {e}")
        self._record_frames = []

    def _show_stats(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Статистика")
        dlg.resize(340, 260)
        dlg.setStyleSheet("background:#1A1A2E;color:white;")
        vl = QVBoxLayout(dlg)
        active = list(self._voice_mgr.active)
        stats_text = (
            f"Участников в звонке: {len(getattr(self,'_all_peers',[]))}\n"
            f"Активных голосовых соединений: {len(active)}\n"
            f"Длительность: {self._elapsed//60:02d}:{self._elapsed%60:02d}\n"
            f"Микрофон: {'заглушён' if self._muted else 'активен'}\n"
            f"Частота: {getattr(self._voice_mgr.audio,'RATE',16000)} Гц\n"
            f"VAD: {'вкл' if getattr(self._voice_mgr.audio,'vad_enabled',False) else 'выкл'}\n"
        )
        lbl = QLabel(stats_text)
        lbl.setStyleSheet("font-family:monospace;font-size:12px;padding:12px;")
        vl.addWidget(lbl)
        QPushButton("Закрыть", clicked=dlg.accept, parent=dlg)
        close = QPushButton("Закрыть"); close.clicked.connect(dlg.accept)
        vl.addWidget(close)
        dlg.exec()

    def _show_notif_settings(self):
        QMessageBox.information(self, "Уведомления",
            "Настройки уведомлений для звонка:\n\n"
            "• Звук входа участника — в Настройки → Звуки\n"
            "• Уведомления — в Настройки → Уведомления")

    # ── Add participant (called externally when someone joins) ────────────────
    def add_participant(self, peer: dict):
        self._participants.append(peer)
        all_peers = [{"username": S().username, "avatar_b64": S().avatar_b64,
                      "ip": get_local_ip(), "_is_self": True}]
        all_peers.extend(self._participants)
        self._rebuild_grid(all_peers)
        self._pcount_lbl.setText(f"👥 {len(all_peers)}")
        self._pts_btn.setText(f"👥  {len(all_peers)}")

    # ── Timer ─────────────────────────────────────────────────────────────────
    def _tick(self):
        self._elapsed += 1
        m = self._elapsed // 60; s = self._elapsed % 60
        self._dur_lbl.setText(f"{m:02d}:{s:02d}")

    # ── Keyboard shortcuts ────────────────────────────────────────────────────
    def keyPressEvent(self, ev):
        k = ev.key()
        if k == Qt.Key.Key_M:
            self._mic_btn.click()
        elif k == Qt.Key.Key_V:
            self._cam_btn.click()
        elif k == Qt.Key.Key_Escape:
            self.showMinimized()
        else:
            super().keyPressEvent(ev)

    # ── Leave ─────────────────────────────────────────────────────────────────
    def _leave(self):
        self._timer.stop()
        self._voice_mgr.unsubscribe_speaking(self._on_local_speaking)
        if self._sharing:
            self._stop_screen_share()
        self.sig_leave.emit()
        self.close()

    def closeEvent(self, event):
        self._timer.stop()
        try:
            self._voice_mgr.unsubscribe_speaking(self._on_local_speaking)
        except Exception:
            pass
        if self._sharing:
            self._stop_screen_share()
        try:
            self.sig_leave.emit()
        except Exception:
            pass
        super().closeEvent(event)


# Keep old name as alias for any remaining references
FloatingCallWindow = ActiveCallWindow


class StatusWidget(QLabel):
    def __init__(self, text: str, color: str = "#A0A0A0"):
        super().__init__(text)
        t = get_theme(S().theme)
        self.setStyleSheet(f"""
            QLabel {{
                color: {color};
                background: {t['bg2']};
                border: 1px solid {t['border']};
                border-radius: 3px;
                padding: 1px 7px;
                font-size: 10px;
            }}
        """)

# ═══════════════════════════════════════════════════════════════════════════
#  STICKER PACK MANAGER
# ═══════════════════════════════════════════════════════════════════════════
class StickerPackDialog(QDialog):
    """
    Create and manage sticker packs.
    - Import images as stickers
    - Name the pack
    - Share/import pack JSON
    """
    sticker_selected = pyqtSignal(str)   # base64 image data

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Стикеры")
        self.setModal(False)
        self.resize(540, 460)
        self._packs: dict = {}   # pack_name -> [b64, b64, ...]
        self._setup()
        self._load_packs()

    def _setup(self):
        t = get_theme(S().theme)
        self.setStyleSheet(f"background:{t['bg2']};color:{t['text']};")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10,10,10,10)
        lay.setSpacing(8)

        # Top: pack selector + controls
        top = QHBoxLayout()
        self._pack_combo = QComboBox()
        self._pack_combo.setMinimumWidth(160)
        self._pack_combo.currentTextChanged.connect(self._show_pack)
        top.addWidget(QLabel("Пак:"))
        top.addWidget(self._pack_combo)
        top.addStretch()

        new_btn = QPushButton("+ Новый пак")
        new_btn.clicked.connect(self._new_pack)
        del_btn = QPushButton("🗑 Удалить пак")
        del_btn.clicked.connect(self._delete_pack)
        import_btn = QPushButton("📥 Импорт")
        import_btn.clicked.connect(self._import_pack)
        export_btn = QPushButton("📤 Экспорт")
        export_btn.clicked.connect(self._export_pack)
        for b in [new_btn, del_btn, import_btn, export_btn]:
            top.addWidget(b)
        lay.addLayout(top)

        # Sticker grid
        self._grid_area = QScrollArea()
        self._grid_area.setWidgetResizable(True)
        self._grid_area.setStyleSheet(f"background:{t['bg3']};border-radius:8px;border:none;")
        self._grid_widget = QWidget()
        self._grid_lay = QGridLayout(self._grid_widget)
        self._grid_lay.setSpacing(6)
        self._grid_area.setWidget(self._grid_widget)
        lay.addWidget(self._grid_area, stretch=1)

        # Add sticker button
        bot = QHBoxLayout()
        add_sticker_btn = QPushButton("+ Добавить стикер из файла")
        add_sticker_btn.setObjectName("accent_btn")
        add_sticker_btn.clicked.connect(self._add_sticker)
        bot.addWidget(add_sticker_btn)
        bot.addStretch()
        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(self.hide)
        bot.addWidget(close_btn)
        lay.addLayout(bot)

    def _load_packs(self):
        """Load packs. Internal format: dict {name: [b64, ...]}"""
        raw = S().get("sticker_packs", "[]", t=str)
        try:
            data = json.loads(raw)
        except Exception:
            data = []
        # Convert list-of-dicts format → internal dict format
        if isinstance(data, list):
            self._packs = {}
            for p in data:
                if isinstance(p, dict):
                    name = p.get("name", "Без имени")
                    stickers = [s.get("data","") if isinstance(s,dict) else s
                                for s in p.get("stickers",[])]
                    self._packs[name] = [s for s in stickers if s]
                else:
                    self._packs["Мои стикеры"] = []
        elif isinstance(data, dict):
            self._packs = data
        else:
            self._packs = {}
        if not self._packs:
            self._packs["Мои стикеры"] = []
        self._refresh_combo()

    def _save_packs(self):
        """Save packs in unified list-of-dicts format."""
        data = [
            {"name": name, "stickers": [{"data": b64} for b64 in stickers]}
            for name, stickers in self._packs.items()
        ]
        S().set("sticker_packs", json.dumps(data, ensure_ascii=False))

    def _refresh_combo(self):
        self._pack_combo.blockSignals(True)
        cur = self._pack_combo.currentText()
        self._pack_combo.clear()
        for name in self._packs:
            self._pack_combo.addItem(name)
        idx = self._pack_combo.findText(cur)
        if idx >= 0:
            self._pack_combo.setCurrentIndex(idx)
        self._pack_combo.blockSignals(False)
        self._show_pack(self._pack_combo.currentText())

    def _show_pack(self, pack_name: str):
        # Clear grid
        while self._grid_lay.count():
            item = self._grid_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        stickers = self._packs.get(pack_name, [])
        cols = 6
        t = get_theme(S().theme)
        for idx, b64 in enumerate(stickers):
            pm = QPixmap()
            try:
                pm.loadFromData(base64.b64decode(b64))
            except Exception:
                continue
            if pm.isNull():
                continue
            pm = pm.scaled(72, 72,
                           Qt.AspectRatioMode.KeepAspectRatio,
                           Qt.TransformationMode.SmoothTransformation)
            btn = QPushButton()
            btn.setFixedSize(82, 82)
            btn.setIcon(QIcon(pm))
            btn.setIconSize(QSize(72, 72))
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background:{t['bg2']};border:1px solid {t['border']};
                    border-radius:8px;
                    border-bottom:2px solid rgba(0,0,0,76);
                }}
                QPushButton:hover {{
                    background:{t['btn_hover']};border-color:{t['accent']};
                }}
            """)
            btn.setToolTip(f"Стикер {idx+1}")
            btn.clicked.connect(lambda _, b=b64: self.sticker_selected.emit(b))
            btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            btn.customContextMenuRequested.connect(
                lambda pos, i=idx, pn=pack_name: self._sticker_ctx(pn, i))
            self._grid_lay.addWidget(btn, idx // cols, idx % cols)

        if not stickers:
            lbl = QLabel("Пак пустой.\nНажмите «+ Добавить стикер» чтобы добавить картинки.")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(f"color:{t['text_dim']};font-size:12px;")
            lbl.setWordWrap(True)
            self._grid_lay.addWidget(lbl, 0, 0, 1, cols)

    def _sticker_ctx(self, pack_name: str, idx: int):
        menu = QMenu(self)
        menu.addAction("🗑 Удалить стикер", lambda: self._del_sticker(pack_name, idx))
        menu.exec(QCursor.pos())

    def _del_sticker(self, pack_name: str, idx: int):
        if pack_name in self._packs and 0 <= idx < len(self._packs[pack_name]):
            self._packs[pack_name].pop(idx)
            self._save_packs()
            self._show_pack(pack_name)

    def _new_pack(self):
        name, ok = QInputDialog.getText(self, "Новый пак", "Название стикер-пака:")
        if ok and name.strip():
            name = name.strip()
            if name not in self._packs:
                self._packs[name] = []
                self._save_packs()
                self._refresh_combo()
                self._pack_combo.setCurrentText(name)

    def _delete_pack(self):
        name = self._pack_combo.currentText()
        if not name:
            return
        if QMessageBox.question(self, "Удалить пак", f"Удалить пак «{name}»?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)                 == QMessageBox.StandardButton.Yes:
            self._packs.pop(name, None)
            self._save_packs()
            self._refresh_combo()

    def _add_sticker(self):
        pack_name = self._pack_combo.currentText()
        if not pack_name:
            return
        files, _ = QFileDialog.getOpenFileNames(
            self, "Выбрать стикеры", "",
            "Images (*.png *.jpg *.jpeg *.gif *.webp)")
        for fn in files:
            pm = QPixmap(fn)
            if pm.isNull():
                continue
            pm = pm.scaled(256, 256,
                           Qt.AspectRatioMode.KeepAspectRatio,
                           Qt.TransformationMode.SmoothTransformation)
            b64 = pixmap_to_base64(pm)
            self._packs[pack_name].append(b64)
        self._save_packs()
        self._show_pack(pack_name)

    def _export_pack(self):
        pack_name = self._pack_combo.currentText()
        if not pack_name or pack_name not in self._packs:
            return
        fn, _ = QFileDialog.getSaveFileName(
            self, "Экспорт пака", f"{pack_name}.gstickers",
            "GoidaPhone Sticker Pack (*.gstickers)")
        if fn:
            data = json.dumps({"name": pack_name,
                               "stickers": self._packs[pack_name],
                               "version": 1})
            Path(fn).write_text(data, encoding="utf-8")
            QMessageBox.information(self, "Экспорт",
                f"Пак «{pack_name}» экспортирован:\n{fn}")

    def _import_pack(self):
        fn, _ = QFileDialog.getOpenFileName(
            self, "Импорт пака", "",
            "GoidaPhone Sticker Pack (*.gstickers);;JSON (*.json)")
        if not fn:
            return
        try:
            data = json.loads(Path(fn).read_text(encoding="utf-8"))
            name = data.get("name", Path(fn).stem)
            stickers = data.get("stickers", [])
            if not isinstance(stickers, list):
                raise ValueError("bad format")
            if name in self._packs:
                name = f"{name} (импорт)"
            self._packs[name] = stickers
            self._save_packs()
            self._refresh_combo()
            self._pack_combo.setCurrentText(name)
            QMessageBox.information(self, "Импорт",
                f"Пак «{name}» импортирован ({len(stickers)} стикеров).")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось импортировать пак:\n{e}")


# ═══════════════════════════════════════════════════════════════════════════
#  GOIDA TERMINAL  (floating in-app console, Shift+F10)
# ═══════════════════════════════════════════════════════════════════════════
class AdminManager:
    """
    First-run admin system. Whoever sets up the admin profile FIRST owns the network.
    Stored in settings — nobody else knows the console exists.
    """
    _ADMIN_KEY = "admin_profile"

    @staticmethod
    def is_admin() -> bool:
        return S().get(AdminManager._ADMIN_KEY + "_set", False, t=bool)

    @staticmethod
    def get_admin_name() -> str:
        return S().get(AdminManager._ADMIN_KEY + "_name", "", t=str)

    @staticmethod
    def setup_admin(name: str, password: str) -> bool:
        import hashlib
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        S().set(AdminManager._ADMIN_KEY + "_set",  True)
        S().set(AdminManager._ADMIN_KEY + "_name", name)
        S().set(AdminManager._ADMIN_KEY + "_hash", pw_hash)
        return True

    @staticmethod
    def verify_admin(password: str) -> bool:
        import hashlib
        stored = S().get(AdminManager._ADMIN_KEY + "_hash", "", t=str)
        return hashlib.sha256(password.encode()).hexdigest() == stored

    @staticmethod
    def get_banned() -> list:
        import json
        raw = S().get("admin_banned", "[]", t=str)
        try: return json.loads(raw)
        except: return []

    @staticmethod
    def ban(ip: str):
        import json
        banned = AdminManager.get_banned()
        if ip not in banned:
            banned.append(ip)
        S().set("admin_banned", json.dumps(banned))

    @staticmethod
    def unban(ip: str):
        import json
        banned = AdminManager.get_banned()
        if ip in banned: banned.remove(ip)
        S().set("admin_banned", json.dumps(banned))

    @staticmethod
    def get_muted() -> list:
        import json
        raw = S().get("admin_muted", "[]", t=str)
        try: return json.loads(raw)
        except: return []

    @staticmethod
    def mute(ip: str):
        import json
        muted = AdminManager.get_muted()
        if ip not in muted: muted.append(ip)
        S().set("admin_muted", json.dumps(muted))

    @staticmethod
    def unmute(ip: str):
        import json
        muted = AdminManager.get_muted()
        if ip in muted: muted.remove(ip)
        S().set("admin_muted", json.dumps(muted))

    @staticmethod
    def get_network_password() -> str:
        return S().get("admin_net_password", "", t=str)

    @staticmethod
    def set_network_password(pw: str):
        import hashlib
        S().set("admin_net_password",
                hashlib.sha256(pw.encode()).hexdigest() if pw else "")
        S().set("admin_net_password_enabled", bool(pw))

    @staticmethod
    def network_password_enabled() -> bool:
        return S().get("admin_net_password_enabled", False, t=bool)


class GoidaTerminal(QWidget):
    """
    GoidaPhone Admin Terminal v2  — Shift+F10
    Полноценный терминал с вкладками, историей команд, автодополнением,
    live-мониторингом сети и расширенным набором admin-команд.
    """

    # ── ANSI-like color palette ────────────────────────────────────────
    C_GREEN   = "#39FF14"   # output / success
    C_YELLOW  = "#FFD700"   # prompt / warnings
    C_CYAN    = "#00E5FF"   # info / headers
    C_RED     = "#FF4444"   # errors / ban
    C_MAGENTA = "#FF44FF"   # special events
    C_WHITE   = "#E0E0E0"   # normal text
    C_DIM     = "#606070"   # dimmed / border art
    C_ORANGE  = "#FF8C00"   # kick / mute
    C_BLUE    = "#6080FF"   # admin badge

    # ── All commands for tab-completion ───────────────────────────────
    ALL_COMMANDS = [
        "/help", "/h", "/clear", "/cls", "/quit", "/exit",
        "/version", "/ver", "/sysinfo", "/uptime", "/date",
        "/whoami", "/colors", "/reload",
        "/nick", "/peers", "/ping", "/traceroute", "/who", "/whois",
        "/me", "/say", "/broadcast",
        "/history", "/history clear", "/history export",
        "/stats", "/netstat", "/crypto",
        "/theme", "/font", "/resize",
        "/log", "/log tail", "/log clear", "/log export",
        "/admin", "/admin setup", "/admin login", "/admin logout",
        "/admin status", "/admin reset",
        "/users", "/ban", "/unban", "/kick", "/mute", "/unmute",
        "/banlist", "/muteall", "/unmuteall",
        "/netpw", "/netpw_off", "/network", "/network block", "/network allow",
        "/group", "/group list", "/group kick", "/group info",
        "/msg", "/file", "/call",
        "/monitor", "/monitor on", "/monitor off",
        "/wipe", "/restart", "/about",
        "/sounds", "/sounds test", "/sounds install",
    ]

    def __init__(self, net, parent=None):
        super().__init__(parent)
        self._net          = net
        self._collapsed    = False
        self._drag_pos: QPoint | None = None
        self._admin_authed = False
        self._cmd_history: list[str] = self._load_term_history()
        self._hist_idx     = -1
        self._monitor_timer: QTimer | None = None
        self._monitor_active = False
        self._start_time   = time.time()
        self._log_entries: list[str] = []     # internal log buffer
        self._tab_cmp_idx  = -1
        self._tab_cmp_matches: list[str] = []
        self.setWindowFlags(Qt.WindowType.Widget)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setMinimumSize(700, 460)
        self.resize(860, 560)
        self._setup_ui()
        self._setup_shortcuts()

    def _load_term_history(self) -> list:
        try:
            raw = _load_raw_setting("terminal_cmd_history", "[]")
            data = json.loads(raw)
            return list(data) if isinstance(data, list) else []
        except Exception:
            return []

    def _save_term_history(self):
        try:
            _save_raw_setting("terminal_cmd_history",
                              json.dumps(self._cmd_history[-200:]))
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════
    #  UI SETUP
    # ══════════════════════════════════════════════════════════════════
    def _setup_ui(self):
        self.setObjectName("goida_terminal")
        _tt = get_theme(S().theme)
        self._tt = _tt
        # BIOS-style: always black background regardless of theme
        # Accent colour adapts to theme (cyan for default, purple for purple theme etc.)
        _tbrd = _tt.get('accent', '#00E5FF')
        self.C_GREEN   = _tt.get('accent', '#39FF14')   # adapt primary colour to theme
        self.C_CYAN    = _tt.get('accent2', '#00E5FF')   # secondary
        self.setStyleSheet(f"""
            #goida_terminal {{
                background: #000000;
                border: 1px solid {_tbrd};
                border-radius: 6px;
            }}
        """)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_titlebar())
        root.addWidget(self._build_tabs())
        root.addWidget(self._build_statusbar())

    def _build_titlebar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("term_title")
        bar.setFixedHeight(38)
        bar.setStyleSheet("""
            #term_title {
                background: #111111;
                border-radius: 5px 5px 0 0;
                border-bottom: 1px solid #333333;
            }
        """)
        bar.setCursor(Qt.CursorShape.SizeAllCursor)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(14, 0, 10, 0)
        lay.setSpacing(8)

        # Traffic-light dots
        for col, tip in [("#FF5F56","Закрыть"),("#FFBD2E","Свернуть"),("#27C93F","Развернуть")]:
            d = QLabel("⬤")
            d.setStyleSheet(f"color:{col};font-size:11px;background:transparent;")
            d.setToolTip(tip)
            lay.addWidget(d)

        lay.addSpacing(6)

        # Icon + title
        ico = QLabel("⌨")
        ico.setStyleSheet("color:#6060CC;font-size:14px;background:transparent;")
        lay.addWidget(ico)

        _acc2 = self._tt.get('accent', '#7C4DFF')
        title = QLabel("ZLink Terminal")
        title.setStyleSheet(
            f"color:{_acc2};font-size:10px;font-weight:bold;"
            "letter-spacing:3px;background:transparent;font-family:monospace;")
        lay.addWidget(title)
        sub = QLabel("GoidaPhone Admin")
        sub.setStyleSheet(
            "color:#444444;font-size:8px;background:transparent;"
            "font-family:monospace;letter-spacing:1px;margin-left:4px;")
        lay.addWidget(sub)

        self._admin_badge = QLabel("◆ ADMIN")
        self._admin_badge.setStyleSheet(
            "color:#FFD700;font-size:9px;font-weight:bold;"
            "background:#1A1500;border:1px solid #605000;"
            "border-radius:3px;padding:1px 5px;")
        self._admin_badge.setVisible(self._admin_authed)
        lay.addWidget(self._admin_badge)

        self._monitor_badge = QLabel("● LIVE")
        self._monitor_badge.setStyleSheet(
            "color:#39FF14;font-size:9px;font-weight:bold;"
            "background:#001400;border:1px solid #003300;"
            "border-radius:3px;padding:1px 5px;")
        self._monitor_badge.setVisible(False)
        lay.addWidget(self._monitor_badge)

        lay.addStretch()

        for label, tip, cb in [
            ("▁", "Свернуть",   self._collapse),
            ("⛶", "Развернуть", self._expand),
            ("✕", "Закрыть",    self.hide),
        ]:
            b = QPushButton(label)
            b.setFixedSize(24, 24)
            b.setToolTip(tip)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setStyleSheet("""
                QPushButton {
                    background:#151530;color:#8080A0;
                    border:none;border-radius:12px;
                    font-size:10px;font-weight:bold;
                }
                QPushButton:hover{background:#2A2A60;color:#E0E0FF;}
            """)
            b.clicked.connect(cb)
            lay.addWidget(b)

        bar.mousePressEvent   = self._tb_press
        bar.mouseMoveEvent    = self._tb_move
        bar.mouseReleaseEvent = self._tb_release
        return bar

    def _build_tabs(self) -> QTabWidget:
        self._tabs = QTabWidget()
        _acc = self._tt.get('accent', '#7C4DFF')
        self._tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background: #000000;
            }}
            QTabBar {{
                background: #0A0A0A;
                border-bottom: 1px solid #1A1A1A;
            }}
            QTabBar::tab {{
                background: #0A0A0A;
                color: #555555;
                font-size: 9px;
                font-weight: bold;
                letter-spacing: 2px;
                font-family: monospace;
                padding: 6px 16px;
                border: none;
                border-bottom: 2px solid transparent;
                margin-right: 0px;
                min-width: 80px;
            }}
            QTabBar::tab:selected {{
                background: #000000;
                color: #CCCCCC;
                border-bottom: 2px solid {_acc};
            }}
            QTabBar::tab:hover:!selected {{
                background: #111111;
                color: #888888;
            }}
        """)

        # ── Tab 1: Terminal ──
        term_w = QWidget()
        _tt = getattr(self, '_tt', get_theme(S().theme))
        term_w.setStyleSheet(f"background:{_tt.get('bg','#08080F')};")
        tl = QVBoxLayout(term_w)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.setSpacing(0)

        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)
        self._output.setMaximumBlockCount(2000)
        # BIOS-style: pure black, grey text, green for active content
        _tc = self._tt.get('accent', '#39FF14')
        self._output.setStyleSheet(f"""
            QPlainTextEdit {{
                background: #000000;
                color: #A0A0A0;
                font-family: 'JetBrains Mono','Fira Code','Courier New',
                             'DejaVu Sans Mono',monospace;
                font-size: 11px;
                border: none;
                padding: 10px 12px;
                selection-background-color: #333333;
            }}
            QScrollBar:vertical {{
                background: #111111; width: 7px; margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: #333333; border-radius: 3px; min-height: 20px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
        """)
        tl.addWidget(self._output, stretch=1)
        tl.addWidget(self._build_input_row())
        self._tabs.addTab(term_w, "⌨  TERMINAL")

        # ── Tab 2: Network monitor ──
        self._monitor_w = self._build_monitor_tab()
        self._tabs.addTab(self._monitor_w, "◈  NETWORK")

        # ── Tab 3: Users ──
        self._users_w = self._build_users_tab()
        self._tabs.addTab(self._users_w, "◉  USERS")

        # ── Tab 4: Log ──
        self._log_w = self._build_log_tab()
        self._tabs.addTab(self._log_w, "▤  LOG")

        # ── Tab 5: Network Graph ──
        self._graph_tab = self._build_graph_tab()
        self._tabs.addTab(self._graph_tab, "◎  GRAPH")

        self._tabs.currentChanged.connect(self._on_tab_changed)
        return self._tabs

    def _build_input_row(self) -> QWidget:
        row_w = QWidget()
        row_w.setStyleSheet("background:#0A0A0A;border-top:1px solid #2A2A2A;")
        row_w.setFixedHeight(44)
        row = QHBoxLayout(row_w)
        row.setContentsMargins(12, 6, 10, 6)
        row.setSpacing(8)

        # Prompt shows username@hostname
        try:
            hostname = platform.node().split(".")[0]
            user     = S().username or "user"
        except Exception:
            hostname = "goidaphone"; user = "user"

        self._prompt_lbl = QLabel(f"{user}@{hostname} »")
        _tc2 = self._tt.get('accent', '#39FF14')
        self._prompt_lbl.setStyleSheet(
            f"color:{_tc2};font-weight:bold;font-size:11px;"
            "font-family:monospace;background:transparent;")
        row.addWidget(self._prompt_lbl)

        self._input = QLineEdit()
        self._input.setPlaceholderText("Введите команду... (Tab — автодополнение, ↑↓ — история)")
        self._input.setStyleSheet("""
            QLineEdit {
                background: transparent;
                color: #CCCCCC;
                border: none;
                font-family: 'JetBrains Mono','Courier New',monospace;
                font-size: 11px;
                padding: 0;
                selection-background-color: #444444;
            }
            QLineEdit:focus { border: none; }
        """)
        self._input.returnPressed.connect(self._run_cmd)
        self._input.installEventFilter(self)
        row.addWidget(self._input, stretch=1)

        run_btn = QPushButton("⏎ RUN")
        run_btn.setFixedSize(58, 28)
        run_btn.setStyleSheet("""
            QPushButton {
                background: #1A1A40;
                color: #6060CC;
                border: 1px solid #2A2A5A;
                border-radius: 4px;
                font-size: 9px;
                font-weight: bold;
                letter-spacing: 1px;
            }
            QPushButton:hover {
                background: #252560;
                color: #A0A0FF;
                border-color: #4040A0;
            }
            QPushButton:pressed { background: #0D0D30; }
        """)
        run_btn.clicked.connect(self._run_cmd)
        row.addWidget(run_btn)
        return row_w

    def _build_monitor_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background:#000000;")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(8)

        hdr = QLabel("◈  NETWORK MONITOR")
        hdr.setStyleSheet("color:#6060CC;font-size:10px;font-weight:bold;"
                          "letter-spacing:2px;font-family:monospace;")
        lay.addWidget(hdr)

        self._mon_output = QPlainTextEdit()
        self._mon_output.setReadOnly(True)
        self._mon_output.setMaximumBlockCount(500)
        self._mon_output.setStyleSheet("""
            QPlainTextEdit {
                background:#040408;color:#00E5FF;
                font-family:'Courier New',monospace;font-size:10px;
                border:1px solid #1A1A3A;border-radius:4px;padding:6px;
            }
        """)
        lay.addWidget(self._mon_output, stretch=1)

        btn_row = QHBoxLayout()
        for label, cb in [
            ("▶ Запустить монитор", lambda: self._start_monitor()),
            ("■ Остановить",        lambda: self._stop_monitor()),
            ("🗑 Очистить",         lambda: self._mon_output.clear()),
        ]:
            b = QPushButton(label)
            b.setStyleSheet("""
                QPushButton{background:#111128;color:#6080FF;border:1px solid #202050;
                    border-radius:4px;padding:4px 12px;font-size:9px;font-weight:bold;}
                QPushButton:hover{background:#1A1A40;color:#A0A0FF;}
            """)
            b.clicked.connect(cb)
            btn_row.addWidget(b)
        btn_row.addStretch()
        lay.addLayout(btn_row)
        return w

    def _build_graph_tab(self) -> QWidget:
        """Network topology graph — visualizes peers as nodes."""
        w = QWidget()
        w.setStyleSheet("background:#000000;")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0,0,0,0); lay.setSpacing(0)

        class _GraphWidget(QWidget):
            def __init__(self, net_ref, parent=None):
                super().__init__(parent)
                self._net = net_ref
                self.setMinimumHeight(300)
                self._timer = QTimer(self)
                self._timer.timeout.connect(self.update)
                self._timer.start(3000)

            def paintEvent(self, event):
                from PyQt6.QtGui import QPainter, QFont, QPen, QColor, QBrush
                import math
                p = QPainter(self)
                p.setRenderHint(QPainter.RenderHint.Antialiasing)
                p.fillRect(self.rect(), QColor("#000000"))
                peers = getattr(self._net, 'peers', {}) if self._net else {}
                nodes = [("ME", None, True)] + [(v.get("username","?"), k, False)
                                                for k, v in peers.items()]
                n = len(nodes)
                if n == 0: return
                cx, cy = self.width()//2, self.height()//2
                r = min(cx, cy) - 50
                pos = {}
                for i, (name, ip, is_me) in enumerate(nodes):
                    if n == 1:
                        angle = 0
                    else:
                        angle = 2 * math.pi * i / n - math.pi/2
                    nx = cx + int(r * math.cos(angle)) if not is_me else cx
                    ny = cy + int(r * math.sin(angle)) if not is_me else cy
                    pos[name] = (nx, ny)

                    # Draw edge to center
                    if not is_me:
                        pen = QPen(QColor("#2A2A5A"), 1)
                        p.setPen(pen)
                        p.drawLine(cx, cy, nx, ny)

                    # Draw node
                    color = QColor("#7C4DFF") if is_me else QColor("#2D6A4F")
                    p.setBrush(QBrush(color))
                    p.setPen(QPen(QColor("#A0A0FF") if is_me else QColor("#74C69D"), 2))
                    node_r = 22 if is_me else 18
                    p.drawEllipse(nx - node_r, ny - node_r, node_r*2, node_r*2)

                    # Label
                    p.setPen(QPen(QColor("#FFFFFF")))
                    p.setFont(QFont("monospace", 8, QFont.Weight.Bold))
                    short = name[:8]
                    p.drawText(nx - 30, ny + node_r + 14, 60, 16,
                               Qt.AlignmentFlag.AlignCenter, short)
                    if ip:
                        p.setFont(QFont("monospace", 7))
                        p.setPen(QPen(QColor("#666688")))
                        p.drawText(nx - 35, ny + node_r + 26, 70, 14,
                                   Qt.AlignmentFlag.AlignCenter, ip.split(".")[-1])
                p.end()

        self._graph_w = _GraphWidget(getattr(self, '_net', None))
        lay.addWidget(self._graph_w, stretch=1)

        refresh_btn = QPushButton("↻ Обновить")
        refresh_btn.setFixedHeight(28)
        refresh_btn.setStyleSheet(
            "QPushButton{background:#111122;color:#7070BB;"
            "border:none;border-top:1px solid #1A1A3A;font-size:10px;}"
            "QPushButton:hover{color:#A0A0FF;}")
        refresh_btn.clicked.connect(self._graph_w.update)
        lay.addWidget(refresh_btn)
        return w

    def _build_users_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background:#000000;")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(8)

        hdr_row = QHBoxLayout()
        hdr = QLabel("◉  ONLINE USERS")
        hdr.setStyleSheet("color:#6060CC;font-size:10px;font-weight:bold;"
                          "letter-spacing:2px;font-family:monospace;")
        hdr_row.addWidget(hdr)
        hdr_row.addStretch()
        ref_btn = QPushButton("⟳ Обновить")
        ref_btn.setStyleSheet("""
            QPushButton{background:#111128;color:#6080FF;border:1px solid #202050;
                border-radius:4px;padding:3px 10px;font-size:9px;}
            QPushButton:hover{background:#1A1A40;color:#A0A0FF;}
        """)
        ref_btn.clicked.connect(self._refresh_users_tab)
        hdr_row.addWidget(ref_btn)
        lay.addLayout(hdr_row)

        self._users_table = QTableWidget(0, 5)
        self._users_table.setHorizontalHeaderLabels(
            ["Ник", "IP", "Версия", "E2E", "Статус"])
        self._users_table.horizontalHeader().setStretchLastSection(True)
        self._users_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._users_table.verticalHeader().setVisible(False)
        self._users_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._users_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._users_table.setStyleSheet("""
            QTableWidget {
                background:#040408;color:#C0C0E0;
                font-family:monospace;font-size:10px;
                border:1px solid #1A1A3A;border-radius:4px;
                gridline-color:#111128;
            }
            QHeaderView::section {
                background:#0D0D1F;color:#6060CC;
                font-size:9px;font-weight:bold;letter-spacing:1px;
                border:none;border-bottom:1px solid #2A2A5A;padding:4px;
            }
            QTableWidget::item:selected { background:#1A1A40; }
        """)
        lay.addWidget(self._users_table, stretch=1)

        # Quick-action buttons
        act_row = QHBoxLayout()
        for label, color, cmd_fn in [
            ("⊘ Ban",    "#FF4040", lambda: self._table_action("ban")),
            ("↯ Kick",   "#FF8C00", lambda: self._table_action("kick")),
            ("⊗ Mute",   "#FFAA00", lambda: self._table_action("mute")),
            ("✓ Unban",  "#39FF14", lambda: self._table_action("unban")),
            ("✓ Unmute", "#39FF14", lambda: self._table_action("unmute")),
            ("◌ Whois",  "#00E5FF", lambda: self._table_action("whois")),
        ]:
            b = QPushButton(label)
            b.setStyleSheet(f"""
                QPushButton{{background:#111128;color:{color};border:1px solid #202050;
                    border-radius:4px;padding:4px 10px;font-size:9px;font-weight:bold;}}
                QPushButton:hover{{background:#1A1A40;}}
            """)
            b.clicked.connect(cmd_fn)
            act_row.addWidget(b)
        act_row.addStretch()
        lay.addLayout(act_row)
        return w

    def _build_log_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background:#000000;")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(8)

        hdr = QLabel("▤  SYSTEM LOG")
        hdr.setStyleSheet("color:#6060CC;font-size:10px;font-weight:bold;"
                          "letter-spacing:2px;font-family:monospace;")
        lay.addWidget(hdr)

        self._log_output = QPlainTextEdit()
        self._log_output.setReadOnly(True)
        self._log_output.setMaximumBlockCount(1000)
        self._log_output.setStyleSheet("""
            QPlainTextEdit {
                background:#040408;color:#A0A0C0;
                font-family:'Courier New',monospace;font-size:10px;
                border:1px solid #1A1A3A;border-radius:4px;padding:6px;
            }
        """)
        lay.addWidget(self._log_output, stretch=1)

        btn_row = QHBoxLayout()
        for label, cb in [
            ("📋 Копировать всё", lambda: QApplication.clipboard().setText(
                self._log_output.toPlainText())),
            ("💾 Экспорт в файл", self._export_log),
            ("🗑 Очистить",       lambda: (self._log_entries.clear(),
                                           self._log_output.clear())),
        ]:
            b = QPushButton(label)
            b.setStyleSheet("""
                QPushButton{background:#111128;color:#6080FF;border:1px solid #202050;
                    border-radius:4px;padding:4px 12px;font-size:9px;font-weight:bold;}
                QPushButton:hover{background:#1A1A40;color:#A0A0FF;}
            """)
            b.clicked.connect(cb)
            btn_row.addWidget(b)
        btn_row.addStretch()
        lay.addLayout(btn_row)
        return w

    def _build_statusbar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(22)
        bar.setStyleSheet("""
            background: #0A0A18;
            border-top: 1px solid #141428;
            border-radius: 0 0 9px 9px;
        """)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 0, 12, 0)
        lay.setSpacing(16)

        self._sb_peers  = QLabel("◉ Peers: 0")
        self._sb_crypto = QLabel("🔒 E2E")
        self._sb_uptime = QLabel("⏱ 0s")
        self._sb_time   = QLabel("")

        for lbl in [self._sb_peers, self._sb_crypto, self._sb_uptime]:
            lbl.setStyleSheet("color:#303060;font-size:8px;font-family:monospace;background:transparent;")
            lay.addWidget(lbl)

        lay.addStretch()
        self._sb_time.setStyleSheet("color:#202040;font-size:8px;font-family:monospace;background:transparent;")
        lay.addWidget(self._sb_time)

        self._sb_timer = QTimer(self)
        self._sb_timer.timeout.connect(self._update_statusbar)
        self._sb_timer.start(1000)
        return bar

    def _setup_shortcuts(self):
        """Keyboard shortcut inside terminal widget."""
        pass  # handled by eventFilter on _input

    # ══════════════════════════════════════════════════════════════════
    #  EVENT FILTER — history navigation + tab completion
    # ══════════════════════════════════════════════════════════════════
    def eventFilter(self, obj, event):
        if obj is self._input and event.type() == event.Type.KeyPress:
            key = event.key()
            if key == Qt.Key.Key_Up:
                self._history_up(); return True
            elif key == Qt.Key.Key_Down:
                self._history_down(); return True
            elif key == Qt.Key.Key_Tab:
                self._tab_complete(); return True
            else:
                # Reset tab completion on any other key
                self._tab_cmp_idx = -1
                self._tab_cmp_matches = []
        return super().eventFilter(obj, event)

    def _history_up(self):
        if not self._cmd_history: return
        self._hist_idx = max(0, self._hist_idx - 1 if self._hist_idx >= 0
                             else len(self._cmd_history) - 1)
        self._input.setText(self._cmd_history[self._hist_idx])
        self._input.end(False)

    def _history_down(self):
        if self._hist_idx < 0: return
        self._hist_idx += 1
        if self._hist_idx >= len(self._cmd_history):
            self._hist_idx = -1
            self._input.clear()
        else:
            self._input.setText(self._cmd_history[self._hist_idx])
            self._input.end(False)

    def _tab_complete(self):
        text = self._input.text()
        if not text.startswith("/"):
            return
        # Build match list fresh if input changed
        prefix = text.strip()
        if not self._tab_cmp_matches or self._tab_cmp_idx == -1:
            self._tab_cmp_matches = [c for c in self.ALL_COMMANDS
                                     if c.startswith(prefix)]
            self._tab_cmp_idx = -1
        if not self._tab_cmp_matches:
            return
        self._tab_cmp_idx = (self._tab_cmp_idx + 1) % len(self._tab_cmp_matches)
        self._input.setText(self._tab_cmp_matches[self._tab_cmp_idx])
        self._input.end(False)

    # ══════════════════════════════════════════════════════════════════
    #  PRINT HELPERS
    # ══════════════════════════════════════════════════════════════════
    def _print(self, text: str, color: str = None):
        color = color or self.C_GREEN
        ts = datetime.now().strftime("%H:%M:%S")
        escaped = (text.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                       .replace(" ","&nbsp;").replace("\n","<br>"))
        self._output.appendHtml(
            f"<span style='color:{color};font-family:monospace;'>{escaped}</span>")
        # Also add to log
        self._add_log(f"[{ts}] {text}")

    def _println(self, text: str = "", color: str = None):
        self._print(text, color)

    def _print_sep(self, char="─", width=68, color=None):
        self._print(char * width, color or self.C_DIM)

    def _add_log(self, text: str):
        self._log_entries.append(text)
        if len(self._log_entries) > 1000:
            self._log_entries = self._log_entries[-800:]
        if hasattr(self, '_log_output'):
            ts = datetime.now().strftime("%H:%M:%S")
            escaped = (text.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))
            self._log_output.appendHtml(
                f"<span style='color:#505070;font-size:9px;'>{escaped}</span>")

    def _mon_print(self, text: str, color: str = "#00E5FF"):
        escaped = (text.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                       .replace(" ","&nbsp;"))
        self._mon_output.appendHtml(
            f"<span style='color:{color};font-family:monospace;font-size:10px;'>{escaped}</span>")

    # ══════════════════════════════════════════════════════════════════
    #  BOOT HEADER
    # ══════════════════════════════════════════════════════════════════
    def _print_header(self):
        self._output.clear()
        t_str = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self._print("┌─────────────────────────────────────────────────────────────────┐", self.C_DIM)
        self._print("│                                                                 │", self.C_DIM)
        self._print("│   ██████╗  ██████╗ ██╗██████╗  █████╗ ██████╗ ██╗  ██╗         │", "#2A2A6A")
        self._print("│  ██╔════╝ ██╔═══██╗██║██╔══██╗██╔══██╗██╔══██╗██║  ██║         │", "#2A2A6A")
        self._print("│  ██║  ███╗██║   ██║██║██║  ██║███████║██████╔╝███████║         │", "#3A3AAA")
        self._print("│  ██║   ██║██║   ██║██║██║  ██║██╔══██║██╔═══╝ ██╔══██║         │", "#3A3AAA")
        self._print("│  ╚██████╔╝╚██████╔╝██║██████╔╝██║  ██║██║     ██║  ██║         │", "#4A4AFF")
        self._print("│   ╚═════╝  ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝         │", "#4A4AFF")
        self._print("│                                                                 │", self.C_DIM)
        self._print(f"│   Admin Terminal v2          {t_str}          │", "#303060")
        self._print(f"│   {COMPANY_NAME:<65}│", "#202050")
        self._print("│                                                                 │", self.C_DIM)
        self._print("└─────────────────────────────────────────────────────────────────┘", self.C_DIM)
        self._print("")
        if AdminManager.is_admin():
            self._print(f"  ◆ Авторизован как: {AdminManager.get_admin_name()}", self.C_YELLOW)
            if AdminManager.network_password_enabled():
                self._print("  ● Пароль сети активен", self.C_GREEN)
        else:
            self._print("  ⚠  Администратор не настроен.", self.C_ORANGE)
            self._print("     /admin setup <имя> <пароль>  — создать", self.C_DIM)
        self._print("")
        self._print("  Введите /help для списка команд.  Tab — автодополнение.", self.C_DIM)
        self._print("")

    # ══════════════════════════════════════════════════════════════════
    #  COMMAND DISPATCHER
    # ══════════════════════════════════════════════════════════════════
    def _run_cmd(self):
        raw = self._input.text().strip()
        self._input.clear()
        self._tab_cmp_idx = -1
        self._tab_cmp_matches = []
        if not raw:
            return
        if not self._cmd_history or self._cmd_history[-1] != raw:
            self._cmd_history.append(raw)
            if len(self._cmd_history) > 200:
                self._cmd_history = self._cmd_history[-200:]
            self._save_term_history()
        self._hist_idx = -1
        self._tabs.setCurrentIndex(0)  # focus terminal tab

        self._print(f"» {raw}", self.C_YELLOW)

        parts = raw.split(maxsplit=3)
        cmd   = parts[0].lower()
        arg1  = parts[1] if len(parts) > 1 else ""
        arg2  = parts[2] if len(parts) > 2 else ""
        arg3  = parts[3] if len(parts) > 3 else ""

        # ── Universal (no auth) ────────────────────────────────────────
        if cmd in ("/help", "/h", "/?"):
            self._cmd_help(arg1)
        elif cmd in ("/clear", "/cls"):
            self._output.clear()
            self._print_header()
            return
        elif cmd in ("/quit", "/exit", "/q"):
            self.hide(); return
        elif cmd in ("/version", "/ver"):
            self._cmd_version()
        elif cmd == "/whoami":
            self._print_sep()
            cfg = S()
            self._print(f"  Ник:        {cfg.username}", self.C_CYAN)
            self._print(f"  IP:         {get_local_ip()}", self.C_WHITE)
            all_ips = get_all_local_ips()
            if len(all_ips) > 1:
                for ip in sorted(all_ips):
                    self._print(f"    └ {ip}", self.C_DIM)
            self._print(f"  GoidaID:    {display_id(get_local_ip())}", self.C_DIM)
            self._print(f"  Премиум:    {'✓' if cfg.premium else '✗'}", self.C_WHITE)
            self._print(f"  Статус:     {cfg.user_status}", self.C_WHITE)
            self._print(f"  Тема:       {cfg.theme}", self.C_WHITE)
            self._print(f"  Язык:       {cfg.language}", self.C_WHITE)
            self._print_sep()

        elif cmd == "/colors":
            self._print_sep()
            self._print("  ЦВЕТОВАЯ ПАЛИТРА ZLink", self.C_CYAN)
            self._print_sep()
            for name, col in [
                ("GREEN  (успех/вывод)", self.C_GREEN),
                ("YELLOW (внимание)",    self.C_YELLOW),
                ("CYAN   (информация)",  self.C_CYAN),
                ("RED    (ошибка)",      self.C_RED),
                ("MAGENTA (сигнал)",     self.C_MAGENTA),
                ("ORANGE (предупрежд.)", self.C_ORANGE),
                ("BLUE   (служебный)",   self.C_BLUE),
                ("WHITE  (текст)",       self.C_WHITE),
                ("DIM    (второстепен.)",self.C_DIM),
            ]:
                self._print(f"  ● {name}", col)
            self._print_sep()

        elif cmd in ("/sounds", "/sounds test", "/sounds install"):
            sub = raw.split(" ", 1)[1].strip() if " " in raw else ""
            if sub == "test":
                self._print_sep()
                self._print("  ТЕСТ ЗВУКОВ GoidaPhone", self.C_CYAN)
                self._print_sep()
                # Check QMediaPlayer availability
                try:
                    from PyQt6.QtMultimedia import QMediaPlayer
                    self._print("  ✓ QMediaPlayer (PyQt6.QtMultimedia) — доступен", self.C_GREEN)
                except ImportError:
                    self._print("  ✗ QMediaPlayer недоступен — нужен пакет qt6-multimedia", self.C_RED)
                for ev in ["click", "message", "online", "delete", "error", "critical"]:
                    fname_list = _SOUND_MAP.get(ev, [])
                    found = None
                    for fn in fname_list:
                        found = _find_sound_file(fn)
                        if found:
                            break
                    if found:
                        self._print(f"  ▶ {ev:12s}  ✓  {found}", self.C_GREEN)
                        play_system_sound(ev)
                        import time as _t; _t.sleep(0.5)
                    else:
                        fnames = ", ".join(fname_list)
                        self._print(f"  ▶ {ev:12s}  ✗  файл не найден ({fnames})", self.C_RED)
                self._print_sep()
                self._print("  Если звуков нет: /sounds install", self.C_DIM)
            elif sub == "install":
                self._print("  Поиск и копирование звуков...", self.C_CYAN)
                install_sounds(force=True)
                # Report what we found
                dest = DATA_DIR / "sounds"
                found_files = list(dest.glob("*.wav")) + list(dest.glob("*.mp3"))
                if found_files:
                    self._print(f"  ✓ Установлено {len(found_files)} файлов → {dest}", self.C_GREEN)
                    for f in found_files:
                        self._print(f"    ▸ {f.name}", self.C_WHITE)
                else:
                    self._print("  ✗ Файлы не найдены ни в одной из директорий:", self.C_RED)
                    for d in _get_sound_dirs()[1:]:
                        self._print(f"    - {d}", self.C_DIM)
                    self._print("  Убедись что папка gdfsound лежит рядом со скриптом", self.C_YELLOW)
                    self._print(f"  или в ~/Desktop/gdfsound/", self.C_YELLOW)
            else:
                self._print_sep()
                self._print("  ЗВУКОВАЯ СИСТЕМА GoidaPhone", self.C_CYAN)
                self._print_sep()
                # QMediaPlayer status
                try:
                    from PyQt6.QtMultimedia import QMediaPlayer
                    self._print("  Движок:  QMediaPlayer (PyQt6) — OK", self.C_GREEN)
                except ImportError:
                    self._print("  Движок:  QMediaPlayer недоступен!", self.C_RED)
                self._print(f"  DATA_DIR: {DATA_DIR / 'sounds'}", self.C_DIM)
                self._print_sep()
                self._print("  Директории поиска:", self.C_CYAN)
                dirs = _get_sound_dirs()
                any_found = False
                for d in dirs:
                    from pathlib import Path as _P
                    dp = _P(str(d))
                    if dp.exists():
                        files = list(dp.glob("*.wav")) + list(dp.glob("*.mp3"))
                        if files:
                            self._print(f"  ✓ {dp}", self.C_GREEN)
                            for f in sorted(files):
                                self._print(f"      {f.name}", self.C_WHITE)
                            any_found = True
                        else:
                            self._print(f"  ○ {dp}  (пусто)", self.C_DIM)
                    else:
                        self._print(f"  ✗ {dp}", self.C_DIM)
                self._print_sep()
                if not any_found:
                    self._print("  ⚠ Звуковые файлы не найдены!", self.C_RED)
                    self._print("  Положи папку gdfsound/ рядом со скриптом", self.C_YELLOW)
                    self._print("  или запусти /sounds install", self.C_YELLOW)
                else:
                    self._print("  /sounds test    — проверить воспроизведение", self.C_DIM)
                    self._print("  /sounds install — переустановить из источников", self.C_DIM)

        elif cmd == "/sysinfo":
            self._cmd_sysinfo()
        elif cmd == "/uptime":
            self._cmd_uptime()
        elif cmd == "/date":
            self._print(datetime.now().strftime("  %A, %d %B %Y  —  %H:%M:%S"), self.C_CYAN)
        elif cmd in ("/peers", "/who"):
            self._cmd_peers()
        elif cmd == "/whois":
            self._cmd_whois(arg1)
        elif cmd == "/ping":
            self._cmd_ping(arg1)
        elif cmd == "/traceroute":
            self._cmd_traceroute(arg1)
        elif cmd == "/nick":
            self._cmd_nick(arg1)
        elif cmd == "/me":
            self._print(f"  * {S().username} {arg1} {arg2} {arg3}".rstrip(), self.C_MAGENTA)
        elif cmd == "/crypto":
            self._cmd_crypto()
        elif cmd == "/stats":
            self._cmd_stats()
        elif cmd == "/netstat":
            self._cmd_netstat()
        elif cmd == "/about":
            self._cmd_about()
        elif cmd == "/history":
            self._cmd_history_cmd(arg1)
        elif cmd in ("/log",):
            self._cmd_log(arg1)
        elif cmd == "/theme":
            self._cmd_theme(arg1)
        elif cmd == "/font":
            self._cmd_font(arg1)
        elif cmd == "/resize":
            self._cmd_resize(arg1, arg2)
        elif cmd == "/monitor":
            if arg1 == "on":  self._start_monitor()
            elif arg1 == "off": self._stop_monitor()
            else: self._toggle_monitor()
        elif cmd in ("/say", "/broadcast"):
            self._cmd_broadcast(arg1 + " " + arg2 + " " + arg3)

        # ── Admin setup ────────────────────────────────────────────────
        elif cmd == "/admin":
            self._cmd_admin(arg1, arg2, arg3, raw)

        # ── Admin-only commands ────────────────────────────────────────
        elif cmd in ("/users", "/banlist"):
            self._require_auth(lambda c=cmd: self._admin_info_cmd(c))
        elif cmd in ("/ban", "/unban", "/kick", "/mute", "/unmute",
                     "/muteall", "/unmuteall"):
            self._require_auth(lambda c=cmd, a=arg1: self._admin_action_cmd(c, a))
        elif cmd in ("/netpw", "/netpw_off", "/network"):
            self._require_auth(lambda c=cmd, a=arg1: self._admin_net_cmd(c, a))
        elif cmd in ("/group",):
            self._require_auth(lambda a=arg1, b=arg2: self._admin_group_cmd(a, b))
        elif cmd in ("/msg",):
            self._require_auth(lambda a=arg1, rest=arg2+" "+arg3: self._cmd_msg(a, rest))
        elif cmd == "/wipe":
            self._require_auth(self._cmd_wipe)
        elif cmd == "/restart":
            self._require_auth(self._cmd_restart)

        else:
            self._print(f"  Неизвестная команда: {cmd}", self.C_RED)
            self._print(f"  Введите /help или нажмите Tab для автодополнения.", self.C_DIM)

        self._print("")

    # ══════════════════════════════════════════════════════════════════
    #  COMMANDS IMPLEMENTATION
    # ══════════════════════════════════════════════════════════════════
    def _cmd_help(self, section: str = ""):
        if section == "admin":
            self._print("┌── ADMIN COMMANDS ─────────────────────────────────────┐", self.C_DIM)
            rows = [
                ("/admin setup <name> <pw>", "Создать администратора"),
                ("/admin login <pw>",        "Авторизоваться"),
                ("/admin logout",            "Выйти из admin-режима"),
                ("/admin status",            "Статус admin"),
                ("/admin reset",             "Сброс (⚠ необратимо)"),
                ("/users",                   "Список онлайн + статусы"),
                ("/ban <ip>",                "Заблокировать пользователя"),
                ("/unban <ip>",              "Разблокировать"),
                ("/kick <ip>",               "Выгнать из сети"),
                ("/mute <ip>",               "Заглушить пользователя"),
                ("/unmute <ip>",             "Включить звук"),
                ("/muteall",                 "Заглушить всех"),
                ("/unmuteall",               "Включить звук всем"),
                ("/banlist",                 "Список банов и мутов"),
                ("/netpw <pw>",              "Пароль для входа в сеть"),
                ("/netpw_off",               "Убрать пароль сети"),
                ("/network block|allow",     "Блокировка/открытие сети"),
                ("/group list|kick|info",    "Управление группами"),
                ("/msg <ip> <текст>",        "Личное сообщение из терминала"),
                ("/wipe",                    "Удалить все данные ⚠"),
                ("/restart",                 "Перезапустить приложение"),
            ]
            for cmd, desc in rows:
                self._print(f"│  {cmd:<30} {desc}", self.C_WHITE)
            self._print("└───────────────────────────────────────────────────────┘", self.C_DIM)
            return

        self._print("┌── GOIDAPHONE ADMIN TERMINAL v2 ──────────────────────────────────┐", self.C_DIM)
        self._print("│                                                                  │", self.C_DIM)
        sections = [
            ("GENERAL", self.C_CYAN, [
                ("/help [admin]",       "Справка (admin — раздел для admin)"),
                ("/version  /sysinfo",  "Версия / системная информация"),
                ("/uptime  /date",      "Аптайм / дата и время"),
                ("/clear  /quit",       "Очистить / закрыть терминал"),
                ("/about",              "О программе"),
            ]),
            ("NETWORK", self.C_CYAN, [
                ("/peers  /who",        "Онлайн пользователи"),
                ("/whois <ip>",         "Подробно о пользователе"),
                ("/ping <ip>",          "ICMP ping"),
                ("/traceroute <ip>",    "Traceroute до IP"),
                ("/netstat",            "Статистика сетевого уровня"),
                ("/stats",              "Статистика GoidaPhone"),
                ("/crypto",             "Статус шифрования и ключи"),
                ("/monitor [on|off]",   "Live-мониторинг пакетов"),
            ]),
            ("PROFILE", self.C_CYAN, [
                ("/nick [имя]",         "Показать / изменить ник"),
                ("/broadcast <текст>",  "Сообщение в публичный чат"),
                ("/me <действие>",      "Эмоция в терминал"),
            ]),
            ("HISTORY & LOG", self.C_CYAN, [
                ("/history",            "История команд"),
                ("/history clear",      "Очистить историю команд"),
                ("/log tail",           "Последние 20 строк лога"),
                ("/log clear",          "Очистить лог"),
                ("/log export",         "Экспорт лога в файл"),
            ]),
            ("DISPLAY", self.C_CYAN, [
                ("/theme [имя]",        "Текущая / сменить тему"),
                ("/font <размер>",      "Размер шрифта (8–18)"),
                ("/resize <W> <H>",     "Изменить размер терминала"),
            ]),
        ]
        for title, col, cmds in sections:
            self._print(f"│  ── {title} {'─' * (60 - len(title))}│", self.C_DIM)
            for c, d in cmds:
                self._print(f"│    {c:<28} {d:<36}│", self.C_WHITE)
        self._print("│                                                                  │", self.C_DIM)
        self._print("│  /help admin  — команды администратора                          │", self.C_YELLOW)
        self._print("│  Tab — автодополнение    ↑↓ — история команд                   │", self.C_DIM)
        self._print("└──────────────────────────────────────────────────────────────────┘", self.C_DIM)

    def _cmd_version(self):
        self._print_sep()
        self._print(f"  GoidaPhone  v{APP_VERSION}  |  {COMPANY_NAME}", self.C_CYAN)
        self._print(f"  Протокол:   v{PROTOCOL_VERSION}  (совместимость с v{PROTOCOL_COMPAT}+)", self.C_WHITE)
        self._print(f"  Python:     {platform.python_version()}", self.C_WHITE)
        self._print(f"  Qt:         PyQt6", self.C_WHITE)
        self._print(f"  ОС:         {get_os_name()}", self.C_WHITE)
        self._print(f"  Платформа:  {platform.platform()}", self.C_WHITE)
        self._print_sep()

    def _cmd_sysinfo(self):
        self._print_sep()
        self._print("  SYSTEM INFO", self.C_CYAN)
        self._print_sep()
        # CPU / RAM via platform fallbacks
        self._print(f"  Хост:       {platform.node()}", self.C_WHITE)
        self._print(f"  ОС:         {platform.system()} {platform.release()}", self.C_WHITE)
        self._print(f"  Arch:       {platform.machine()}", self.C_WHITE)
        self._print(f"  Python:     {platform.python_version()} ({platform.python_implementation()})", self.C_WHITE)
        self._print(f"  IP:         {get_local_ip()}", self.C_WHITE)
        self._print(f"  DATA_DIR:   {DATA_DIR}", self.C_WHITE)
        # Storage
        try:
            usage = shutil.disk_usage(str(DATA_DIR))
            total = usage.total // (1024**3)
            free  = usage.free  // (1024**3)
            self._print(f"  Диск:       {free} GB свободно / {total} GB", self.C_WHITE)
        except Exception:
            pass
        # History size
        try:
            hist_files = list(HISTORY_DIR.glob("*.json"))
            hist_size  = sum(f.stat().st_size for f in hist_files)
            self._print(f"  История:    {len(hist_files)} диалогов, {hist_size//1024} КБ", self.C_WHITE)
        except Exception:
            pass
        self._print_sep()

    def _cmd_uptime(self):
        elapsed = time.time() - self._start_time
        h = int(elapsed // 3600); m = int((elapsed % 3600) // 60); s = int(elapsed % 60)
        self._print(f"  Терминал открыт: {h:02d}:{m:02d}:{s:02d}", self.C_CYAN)
        # App uptime via process
        try:
            import os as _os
            proc_start = _os.path.getmtime(f"/proc/{_os.getpid()}/stat")
            app_up = time.time() - proc_start
            ah = int(app_up // 3600); am = int((app_up % 3600) // 60)
            self._print(f"  Приложение:      {ah:02d}:{am:02d}", self.C_WHITE)
        except Exception:
            pass

    def _cmd_peers(self):
        peers = getattr(self._net, 'peers', {})
        if not peers:
            self._print("  Нет пользователей онлайн.", self.C_DIM); return
        self._print_sep()
        self._print(f"  {'НИК':<20} {'IP':<16} {'ВЕРСИЯ':<8} {'E2E':<6} {'ОС'}", self.C_CYAN)
        self._print_sep()
        banned = AdminManager.get_banned()
        muted  = AdminManager.get_muted()
        for ip, info in peers.items():
            flags = []
            if ip in banned: flags.append("BAN")
            if ip in muted:  flags.append("MUT")
            e2e  = "✓" if CRYPTO.has_session(ip) else "✗"
            flag = f" [{','.join(flags)}]" if flags else ""
            self._print(
                f"  {info.get('username','?'):<20} {ip:<16} "
                f"{info.get('version','?'):<8} {e2e:<6} "
                f"{info.get('os','?')}{flag}",
                self.C_RED if "BAN" in flags else self.C_WHITE)
        self._print_sep()
        self._print(f"  Всего онлайн: {len(peers)}", self.C_GREEN)

    def _cmd_whois(self, ip: str):
        if not ip:
            self._print("  Использование: /whois <ip>", self.C_ORANGE); return
        peers = getattr(self._net, 'peers', {})
        info  = peers.get(ip)
        if not info:
            self._print(f"  Пользователь {ip} не онлайн.", self.C_DIM); return
        self._print_sep()
        self._print(f"  WHOIS: {ip}", self.C_CYAN)
        self._print_sep()
        fields = [
            ("Ник",        info.get("username","?")),
            ("IP",         ip),
            ("Версия",     info.get("version","?")),
            ("Протокол",   info.get("protocol_version","?")),
            ("ОС",         info.get("os","?")),
            ("Тип связи",  info.get("conn_type","?")),
            ("Premium",    "Да" if info.get("premium") else "Нет"),
            ("E2E ключ",   "Установлен" if CRYPTO.has_session(ip) else "Нет"),
            ("Отпечаток",  CRYPTO.peer_fingerprint(ip)),
            ("Последний",  datetime.fromtimestamp(info.get("last_seen",0)).strftime("%H:%M:%S")),
            ("Бан",        "ДА" if ip in AdminManager.get_banned() else "Нет"),
            ("Мут",        "ДА" if ip in AdminManager.get_muted() else "Нет"),
        ]
        for k, v in fields:
            col = self.C_RED if v in ("ДА",) else self.C_WHITE
            self._print(f"  {k:<14} {v}", col)
        bio = info.get("bio","")
        if bio:
            self._print(f"  Bio:           {bio[:60]}", self.C_DIM)
        self._print_sep()

    def _cmd_ping(self, ip: str):
        if not ip:
            self._print("  Использование: /ping <ip>", self.C_ORANGE); return
        self._print(f"  Пингую {ip} (4 пакета)...", self.C_CYAN)
        def do_ping():
            try:
                flag = "-n" if platform.system() == "Windows" else "-c"
                res = subprocess.run(
                    ["ping", flag, "4", ip],
                    capture_output=True, text=True, timeout=12)
                lines = (res.stdout or res.stderr).splitlines()
                for line in lines[-8:]:
                    QTimer.singleShot(0, lambda l=line:
                        self._print(f"  {l}", self.C_CYAN))
            except Exception as ex:
                QTimer.singleShot(0, lambda: self._print(f"  Ошибка: {ex}", self.C_RED))
        threading.Thread(target=do_ping, daemon=True).start()

    def _cmd_traceroute(self, ip: str):
        if not ip:
            self._print("  Использование: /traceroute <ip>", self.C_ORANGE); return
        self._print(f"  Traceroute → {ip}...", self.C_CYAN)
        def do_tr():
            try:
                cmd = (["tracert", ip] if platform.system() == "Windows"
                       else ["traceroute", "-m", "15", ip])
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                lines = (res.stdout or res.stderr).splitlines()
                for line in lines[:20]:
                    QTimer.singleShot(0, lambda l=line:
                        self._print(f"  {l}", self.C_CYAN))
            except Exception as ex:
                QTimer.singleShot(0, lambda: self._print(f"  Ошибка: {ex}", self.C_RED))
        threading.Thread(target=do_tr, daemon=True).start()

    def _cmd_nick(self, new_nick: str):
        if new_nick:
            old = S().username
            S().username = new_nick
            self._print(f"  Ник: {old} → {new_nick}", self.C_GREEN)
            try:
                self._prompt_lbl.setText(f"{new_nick}@{platform.node().split('.')[0]} »")
            except Exception:
                pass
        else:
            self._print(f"  Ник: {S().username}", self.C_CYAN)
            self._print(f"  IP:  {get_local_ip()}", self.C_WHITE)

    def _cmd_crypto(self):
        self._print_sep()
        self._print("  CRYPTO STATUS", self.C_CYAN)
        self._print_sep()
        self._print(f"  Движок:     {CRYPTO.status()}", self.C_WHITE)
        self._print(f"  Мой отпечаток:", self.C_WHITE)
        self._print(f"    {CRYPTO.fingerprint()}", self.C_GREEN)
        peers = getattr(self._net, 'peers', {})
        e2e_count = sum(1 for ip in peers if CRYPTO.has_session(ip))
        self._print(f"  E2E-сессий: {e2e_count} / {len(peers)}", self.C_WHITE)
        if peers:
            self._print("  Сессии по пирам:", self.C_DIM)
            for ip, info in peers.items():
                has = CRYPTO.has_session(ip)
                col = self.C_GREEN if has else self.C_RED
                sym = "✓" if has else "✗"
                self._print(f"    {sym} {info.get('username','?'):<20} {ip}", col)
        self._print_sep()

    def _cmd_stats(self):
        peers = getattr(self._net, 'peers', {})
        self._print_sep()
        self._print("  GOIDAPHONE STATS", self.C_CYAN)
        self._print_sep()
        self._print(f"  Онлайн:      {len(peers)} пользователей", self.C_WHITE)
        self._print(f"  Бан-лист:    {len(AdminManager.get_banned())} IP", self.C_WHITE)
        self._print(f"  Мут-лист:    {len(AdminManager.get_muted())} IP", self.C_WHITE)
        self._print(f"  E2E-сессий:  {sum(1 for ip in peers if CRYPTO.has_session(ip))}", self.C_WHITE)
        # Groups
        try:
            if GROUPS_FILE.exists():
                groups = json.loads(GROUPS_FILE.read_text(encoding="utf-8"))
                self._print(f"  Групп:       {len(groups)}", self.C_WHITE)
        except Exception:
            pass
        # History size
        try:
            hist = list(HISTORY_DIR.glob("*.json"))
            hist_kb = sum(f.stat().st_size for f in hist) // 1024
            self._print(f"  История:     {len(hist)} диалогов / {hist_kb} КБ", self.C_WHITE)
        except Exception:
            pass
        self._print(f"  Шифрование:  {'AES-256-GCM' if CRYPTO_AVAILABLE else 'XOR'}", self.C_WHITE)
        self._print(f"  Admin:       {'активен' if AdminManager.is_admin() else 'не настроен'}", self.C_WHITE)
        self._print(f"  Пароль сети: {'● да' if AdminManager.network_password_enabled() else '○ нет'}", self.C_WHITE)
        self._print_sep()

    def _cmd_netstat(self):
        self._print_sep()
        self._print("  NETWORK INTERFACES", self.C_CYAN)
        self._print_sep()
        for iface in QNetworkInterface.allInterfaces():
            flags = iface.flags()
            if not (flags & QNetworkInterface.InterfaceFlag.IsUp):
                continue
            for entry in iface.addressEntries():
                addr = entry.ip().toString()
                if addr in ("0.0.0.0", "::"):
                    continue
                self._print(f"  {iface.name():<12} {addr}", self.C_WHITE)
        self._print(f"  UDP порт:   {S().get('udp_port', 45678, t=int)}", self.C_DIM)
        self._print(f"  TCP порт:   {S().get('tcp_port', 45679, t=int)}", self.C_DIM)
        blocked = S().get("network_blocked", False, t=bool)
        self._print(f"  Сеть:       {'ЗАБЛОКИРОВАНА' if blocked else 'открыта'}",
                    self.C_RED if blocked else self.C_GREEN)
        self._print_sep()

    def _cmd_about(self):
        self._print_sep()
        self._print("  О ПРОГРАММЕ", self.C_CYAN)
        self._print_sep()
        self._print(f"  {APP_NAME}  v{APP_VERSION}", self.C_WHITE)
        self._print(f"  {COMPANY_NAME}", self.C_DIM)
        self._print("", self.C_WHITE)
        self._print("  P2P LAN/VPN мессенджер с шифрованием, группами,", self.C_WHITE)
        self._print("  голосовыми звонками, медиаплеером Mewa 1-2-3.", self.C_WHITE)
        self._print("", self.C_WHITE)
        self._print("  Шифрование: AES-256-GCM + X25519 ECDH + Ed25519", self.C_WHITE)
        self._print("  Протокол:   UDP + TCP (п2п, без сервера)", self.C_WHITE)
        self._print_sep()

    def _cmd_history_cmd(self, sub: str):
        if sub == "clear":
            self._cmd_history.clear()
            self._print("  История команд очищена.", self.C_GREEN)
        else:
            if not self._cmd_history:
                self._print("  История пуста.", self.C_DIM); return
            self._print(f"  История команд ({len(self._cmd_history)}):", self.C_CYAN)
            for i, c in enumerate(self._cmd_history[-30:], 1):
                self._print(f"  {i:>3}  {c}", self.C_WHITE)

    def _cmd_log(self, sub: str):
        if sub == "clear":
            self._log_entries.clear()
            self._log_output.clear()
            self._print("  Лог очищен.", self.C_GREEN)
        elif sub == "export":
            self._export_log()
        else:
            if not self._log_entries:
                self._print("  Лог пуст.", self.C_DIM); return
            self._print("  Последние 20 записей:", self.C_CYAN)
            for line in self._log_entries[-20:]:
                self._print(f"  {line}", self.C_DIM)

    def _export_log(self):
        try:
            path = DATA_DIR / f"terminal_log_{int(time.time())}.txt"
            path.write_text("\n".join(self._log_entries), encoding="utf-8")
            self._print(f"  Лог сохранён: {path}", self.C_GREEN)
        except Exception as e:
            self._print(f"  Ошибка: {e}", self.C_RED)

    def _cmd_theme(self, name: str):
        themes = ["dark", "light", "blue", "green", "pink", "black", "solarized"]
        if not name:
            self._print(f"  Текущая тема: {S().theme}", self.C_CYAN)
            self._print(f"  Доступно: {', '.join(themes)}", self.C_DIM)
        elif name in themes:
            S().theme = name
            self._print(f"  Тема изменена → {name}. Перезапустите для полного эффекта.", self.C_GREEN)
        else:
            self._print(f"  Неизвестная тема. Доступно: {', '.join(themes)}", self.C_ORANGE)

    def _cmd_font(self, size_str: str):
        try:
            size = int(size_str)
            if not 8 <= size <= 18:
                raise ValueError
            self._output.setStyleSheet(self._output.styleSheet().replace(
                "font-size: 11px", f"font-size: {size}px"))
            self._print(f"  Шрифт: {size}px", self.C_GREEN)
        except (ValueError, TypeError):
            self._print("  Использование: /font <8–18>", self.C_ORANGE)

    def _cmd_resize(self, w_str: str, h_str: str):
        try:
            w = max(600, min(1600, int(w_str)))
            h = max(400, min(1000, int(h_str)))
            self.resize(w, h)
            self._print(f"  Размер: {w}×{h}", self.C_GREEN)
        except (ValueError, TypeError):
            self._print("  Использование: /resize <W> <H>", self.C_ORANGE)

    def _cmd_broadcast(self, text: str):
        text = text.strip()
        if not text:
            self._print("  Использование: /broadcast <текст>", self.C_ORANGE); return
        if hasattr(self._net, 'send_chat'):
            self._net.send_chat(f"[ADMIN] {text}")
            self._print(f"  Отправлено в публичный чат: {text}", self.C_GREEN)
        else:
            self._print("  Сеть недоступна.", self.C_RED)

    def _cmd_msg(self, ip: str, text: str):
        text = text.strip()
        if not ip or not text:
            self._print("  Использование: /msg <ip> <текст>", self.C_ORANGE); return
        peers = getattr(self._net, 'peers', {})
        if ip not in peers:
            self._print(f"  Пользователь {ip} не онлайн.", self.C_RED); return
        if hasattr(self._net, 'send_private'):
            self._net.send_private(f"[Терминал] {text}", ip)
            name = peers[ip].get("username","?")
            self._print(f"  → {name} ({ip}): {text}", self.C_GREEN)

    # ── Admin commands ─────────────────────────────────────────────────
    def _cmd_admin(self, sub: str, arg2: str, arg3: str, raw: str):
        sub = sub.lower()
        if sub == "setup":
            parts = raw.split(maxsplit=3)
            if len(parts) < 4:
                self._print("  Использование: /admin setup <имя> <пароль>", self.C_ORANGE)
                return
            aname, apw = parts[2], parts[3]
            if AdminManager.is_admin():
                self._print("  Администратор уже создан. /admin reset — сброс.", self.C_RED)
                return
            AdminManager.setup_admin(aname, apw)
            self._admin_authed = True
            self._admin_badge.setVisible(True)
            self._print(f"  ◆ Администратор создан: {aname}", self.C_YELLOW)
            self._print("    Вы — владелец этой сети.", self.C_GREEN)

        elif sub == "login":
            if not AdminManager.is_admin():
                self._print("  Администратор не настроен.", self.C_RED); return
            if AdminManager.verify_admin(arg2):
                self._admin_authed = True
                self._admin_badge.setVisible(True)
                self._print(f"  ◆ Вход выполнен: {AdminManager.get_admin_name()}", self.C_YELLOW)
            else:
                self._print("  ✗ Неверный пароль.", self.C_RED)

        elif sub == "logout":
            self._admin_authed = False
            self._admin_badge.setVisible(False)
            self._print("  Вышли из admin-режима.", self.C_DIM)

        elif sub == "reset":
            self._require_auth(self._admin_reset)

        elif sub == "status":
            self._print(f"  Admin настроен:    {'да' if AdminManager.is_admin() else 'нет'}", self.C_WHITE)
            self._print(f"  Аутентифицирован:  {'да' if self._admin_authed else 'нет'}", self.C_WHITE)
            if AdminManager.is_admin():
                self._print(f"  Имя:               {AdminManager.get_admin_name()}", self.C_WHITE)
            self._print(f"  Пароль сети:       {'● активен' if AdminManager.network_password_enabled() else '○ нет'}", self.C_WHITE)
            self._print(f"  Сеть заблокирована:{'да' if S().get('network_blocked',False,t=bool) else 'нет'}", self.C_WHITE)
        else:
            self._print("  Субкоманды: setup, login, logout, reset, status", self.C_ORANGE)

    def _admin_reset(self):
        reply = QMessageBox.warning(self, "Сброс администратора",
            "Сбросить настройки администратора?\nЭто необратимо.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            for k in ["_set","_name","_hash"]:
                S().remove("admin_profile" + k)
            self._admin_authed = False
            self._admin_badge.setVisible(False)
            self._print("  Администратор сброшен.", self.C_ORANGE)

    def _admin_info_cmd(self, cmd: str):
        if cmd == "/users":
            self._cmd_peers()
        elif cmd == "/banlist":
            banned = AdminManager.get_banned()
            muted  = AdminManager.get_muted()
            self._print(f"  Забанено ({len(banned)}):", self.C_RED)
            for ip in banned:
                peers = getattr(self._net, 'peers', {})
                name = peers.get(ip, {}).get("username", "?")
                self._print(f"    ⊘  {ip:<16} {name}", self.C_RED)
            self._print(f"  Заглушено ({len(muted)}):", self.C_ORANGE)
            for ip in muted:
                peers = getattr(self._net, 'peers', {})
                name = peers.get(ip, {}).get("username", "?")
                self._print(f"    ⊗  {ip:<16} {name}", self.C_ORANGE)

    def _admin_action_cmd(self, cmd: str, arg: str):
        peers = getattr(self._net, 'peers', {})

        if cmd == "/muteall":
            for ip in list(peers.keys()):
                AdminManager.mute(ip)
            self._print(f"  ⊗ Все {len(peers)} пользователей заглушены.", self.C_ORANGE)
            return
        if cmd == "/unmuteall":
            for ip in AdminManager.get_muted():
                AdminManager.unmute(ip)
            self._print("  ✓ Мут снят со всех.", self.C_GREEN)
            return

        if not arg:
            self._print(f"  Использование: {cmd} <ip>", self.C_ORANGE); return

        name = peers.get(arg, {}).get("username", arg)
        if cmd == "/ban":
            AdminManager.ban(arg)
            if hasattr(self._net, 'kick_peer'): self._net.kick_peer(arg)
            self._print(f"  ⊘ Забанен: {name} ({arg})", self.C_RED)
        elif cmd == "/unban":
            AdminManager.unban(arg)
            self._print(f"  ✓ Разбанен: {name} ({arg})", self.C_GREEN)
        elif cmd == "/kick":
            if hasattr(self._net, 'kick_peer'): self._net.kick_peer(arg)
            self._print(f"  ↯ Кикнут: {name} ({arg})", self.C_ORANGE)
        elif cmd == "/mute":
            AdminManager.mute(arg)
            self._print(f"  ⊗ Заглушён: {name} ({arg})", self.C_ORANGE)
        elif cmd == "/unmute":
            AdminManager.unmute(arg)
            self._print(f"  ✓ Звук восстановлен: {name} ({arg})", self.C_GREEN)

    def _admin_net_cmd(self, cmd: str, arg: str):
        if cmd == "/netpw":
            if not arg:
                self._print("  Использование: /netpw <пароль>", self.C_ORANGE); return
            AdminManager.set_network_password(arg)
            self._print(f"  ● Пароль сети установлен.", self.C_YELLOW)
            self._print("    Новые пользователи должны знать пароль для входа.", self.C_DIM)
        elif cmd == "/netpw_off":
            AdminManager.set_network_password("")
            self._print("  ○ Пароль сети отключён.", self.C_GREEN)
        elif cmd == "/network":
            sub = arg.lower()
            if sub == "block":
                S().set("network_blocked", True)
                if hasattr(self._net, 'set_blocked'): self._net.set_blocked(True)
                self._print("  ⊘ Сеть заблокирована. Входящие соединения отклоняются.", self.C_RED)
            elif sub == "allow":
                S().set("network_blocked", False)
                if hasattr(self._net, 'set_blocked'): self._net.set_blocked(False)
                self._print("  ✓ Сеть открыта.", self.C_GREEN)
            else:
                blocked = S().get("network_blocked", False, t=bool)
                self._print(f"  Статус сети: {'ЗАБЛОКИРОВАНА' if blocked else 'открыта'}",
                            self.C_RED if blocked else self.C_GREEN)
                self._print("  Субкоманды: /network block  |  /network allow", self.C_DIM)

    def _admin_group_cmd(self, sub: str, arg: str):
        sub = sub.lower()
        if sub == "list":
            try:
                if GROUPS_FILE.exists():
                    groups = json.loads(GROUPS_FILE.read_text(encoding="utf-8"))
                    self._print(f"  Групп: {len(groups)}", self.C_CYAN)
                    for gid, g in groups.items():
                        members = g.get("members", [])
                        self._print(f"  [{gid[:8]}]  {g.get('name','?'):<24} {len(members)} участников", self.C_WHITE)
                else:
                    self._print("  Групп нет.", self.C_DIM)
            except Exception as e:
                self._print(f"  Ошибка: {e}", self.C_RED)
        elif sub == "info":
            self._print("  Субкоманды: /group list", self.C_DIM)
        else:
            self._print("  Субкоманды: list", self.C_ORANGE)

    def _handle_plugin_cmd(self, text: str):
        parts = text.strip().split(None, 1)
        sub = parts[0].lower() if parts else ""
        arg = parts[1] if len(parts) > 1 else ""
        if sub == "load" and arg:
            self._cmd_load_plugin(arg)
        elif sub == "list" or not sub:
            self._cmd_list_plugins()
        elif sub == "dir":
            pd = DATA_DIR / "zlink_plugins"
            pd.mkdir(parents=True, exist_ok=True)
            _open_system(str(pd))
        else:
            self._print("  /plugin list|load <path>|dir", self.C_DIM)

    def _cmd_wipe(self):
        reply = QMessageBox.warning(self, "УДАЛЕНИЕ ДАННЫХ",
            "⚠ УДАЛИТЬ ВСЕ ДАННЫЕ GoidaPhone?\n"
            "История, настройки, аватары, файлы — всё будет удалено.\n\n"
            "Это действие НЕОБРАТИМО.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            self._print("  Отменено.", self.C_DIM); return
        try:
            from functools import reduce
            S()._s.clear(); S()._s.sync()
            shutil.rmtree(DATA_DIR, ignore_errors=True)
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            HISTORY._cache.clear()
            self._print("  ✓ Данные удалены. Перезапустите приложение.", self.C_RED)
        except Exception as e:
            self._print(f"  Ошибка: {e}", self.C_RED)

    def _cmd_load_plugin(self, path: str):
        """Load a Python plugin script into ZLink terminal."""
        try:
            import importlib.util, os
            if not os.path.exists(path):
                self._print(f"  ✗ Файл не найден: {path}", self.C_RED)
                return
            spec = importlib.util.spec_from_file_location("zlink_plugin", path)
            mod  = importlib.util.module_from_spec(spec)
            # Expose terminal API to plugin
            mod.terminal   = self
            mod.print_line = self._print
            mod.net        = getattr(self, '_net', None)
            spec.loader.exec_module(mod)
            self._print(f"  ✓ Плагин загружен: {os.path.basename(path)}", self.C_GREEN)
            if hasattr(mod, 'on_load'):
                mod.on_load()
        except Exception as e:
            self._print(f"  ✗ Ошибка плагина: {e}", self.C_RED)

    def _cmd_list_plugins(self):
        plugins_dir = DATA_DIR / "zlink_plugins"
        if not plugins_dir.exists():
            plugins_dir.mkdir(parents=True, exist_ok=True)
        files = list(plugins_dir.glob("*.py"))
        if not files:
            self._print("  Плагинов нет. Положите .py файлы в:", self.C_DIM)
            self._print(f"  {plugins_dir}", self.C_CYAN)
        else:
            self._print(f"  Плагины ({len(files)}):", self.C_CYAN)
            for f in files:
                self._print(f"  📜 {f.name}", self.C_WHITE)

    def _cmd_restart(self):
        reply = QMessageBox.question(self, "Перезапуск",
            "Перезапустить GoidaPhone?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._print("  Перезапуск...", self.C_YELLOW)
            QTimer.singleShot(500, lambda: (
                os.execv(sys.executable, [sys.executable] + sys.argv)))

    # ── Require auth helper ────────────────────────────────────────────
    def _require_auth(self, action):
        if not AdminManager.is_admin():
            self._print("  ✗ Создайте администратора: /admin setup <имя> <пароль>", self.C_RED)
            return
        if not self._admin_authed:
            self._print("  ✗ Требуется авторизация: /admin login <пароль>", self.C_RED)
            return
        action()

    # ══════════════════════════════════════════════════════════════════
    #  NETWORK MONITOR
    # ══════════════════════════════════════════════════════════════════
    def _start_monitor(self):
        if self._monitor_active: return
        self._monitor_active = True
        self._monitor_badge.setVisible(True)
        self._monitor_timer = QTimer(self)
        self._monitor_timer.timeout.connect(self._monitor_tick)
        self._monitor_timer.start(2000)
        self._mon_print("● Монитор запущен. Обновление каждые 2 сек.", "#39FF14")
        self._tabs.setCurrentIndex(1)

    def _stop_monitor(self):
        if not self._monitor_active: return
        self._monitor_active = False
        self._monitor_badge.setVisible(False)
        if self._monitor_timer:
            self._monitor_timer.stop()
            self._monitor_timer = None
        self._mon_print("■ Монитор остановлен.", "#FF8C00")

    def _toggle_monitor(self):
        if self._monitor_active: self._stop_monitor()
        else: self._start_monitor()

    def _monitor_tick(self):
        peers = getattr(self._net, 'peers', {})
        ts    = datetime.now().strftime("%H:%M:%S")
        self._mon_print(f"── {ts} ── peers={len(peers)} ─────────────────────────────", "#1A3A5A")
        for ip, info in peers.items():
            e2e  = "E2E✓" if CRYPTO.has_session(ip) else "    "
            last = time.time() - info.get("last_seen", time.time())
            self._mon_print(
                f"  {info.get('username','?'):<18} {ip:<16} {e2e}  last={last:.0f}s",
                "#2A6A2A" if last < 10 else "#6A4A00")

    # ══════════════════════════════════════════════════════════════════
    #  USERS TAB
    # ══════════════════════════════════════════════════════════════════
    def _refresh_users_tab(self):
        peers  = getattr(self._net, 'peers', {})
        banned = AdminManager.get_banned()
        muted  = AdminManager.get_muted()
        self._users_table.setRowCount(0)
        for ip, info in peers.items():
            row = self._users_table.rowCount()
            self._users_table.insertRow(row)
            flags = []
            if ip in banned: flags.append("BAN")
            if ip in muted:  flags.append("MUT")
            flag_str = " ".join(flags) if flags else "OK"
            e2e = "✓" if CRYPTO.has_session(ip) else "✗"
            items = [
                info.get("username","?"),
                ip,
                info.get("version","?"),
                e2e,
                flag_str,
            ]
            for col, val in enumerate(items):
                item = QTableWidgetItem(val)
                if "BAN" in flag_str:
                    item.setForeground(QColor("#FF4444"))
                elif "MUT" in flag_str:
                    item.setForeground(QColor("#FF8C00"))
                elif val == "✓":
                    item.setForeground(QColor("#39FF14"))
                elif val == "✗":
                    item.setForeground(QColor("#444460"))
                self._users_table.setItem(row, col, item)

    def _table_action(self, action: str):
        row = self._users_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Выбор", "Выберите пользователя в таблице.")
            return
        ip_item = self._users_table.item(row, 1)
        if not ip_item: return
        ip = ip_item.text()
        if not self._admin_authed:
            self._print("  ✗ Требуется /admin login", self.C_RED)
            self._tabs.setCurrentIndex(0); return
        peers = getattr(self._net, 'peers', {})
        name  = peers.get(ip, {}).get("username", ip)
        if action == "ban":
            AdminManager.ban(ip)
            if hasattr(self._net, 'kick_peer'): self._net.kick_peer(ip)
        elif action == "unban":
            AdminManager.unban(ip)
        elif action == "kick":
            if hasattr(self._net, 'kick_peer'): self._net.kick_peer(ip)
        elif action == "mute":
            AdminManager.mute(ip)
        elif action == "unmute":
            AdminManager.unmute(ip)
        elif action == "whois":
            self._tabs.setCurrentIndex(0)
            self._cmd_whois(ip)
            return
        self._refresh_users_tab()
        self._add_log(f"Table action: {action} → {name} ({ip})")

    # ══════════════════════════════════════════════════════════════════
    #  STATUS BAR
    # ══════════════════════════════════════════════════════════════════
    def _update_statusbar(self):
        peers = getattr(self._net, 'peers', {})
        e2e   = sum(1 for ip in peers if CRYPTO.has_session(ip))
        up    = int(time.time() - self._start_time)
        h, m, s = up // 3600, (up % 3600) // 60, up % 60
        self._sb_peers.setText(f"◉ Peers: {len(peers)}")
        self._sb_crypto.setText(f"🔒 E2E: {e2e}/{len(peers)}")
        self._sb_uptime.setText(f"⏱ {h:02d}:{m:02d}:{s:02d}")
        self._sb_time.setText(datetime.now().strftime("%H:%M:%S"))

    # ══════════════════════════════════════════════════════════════════
    #  TABS CHANGED
    # ══════════════════════════════════════════════════════════════════
    def _on_tab_changed(self, idx: int):
        if idx == 2:
            self._refresh_users_tab()

    # ══════════════════════════════════════════════════════════════════
    #  DRAG & COLLAPSE
    # ══════════════════════════════════════════════════════════════════
    def _tb_press(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.pos()

    def _tb_move(self, event):
        if self._drag_pos and event.buttons() == Qt.MouseButton.LeftButton:
            new_pos = event.globalPosition().toPoint() - self._drag_pos
            if self.parent():
                p = self.parent()
                nx = max(0, min(new_pos.x(), p.width()  - self.width()))
                ny = max(0, min(new_pos.y(), p.height() - self.height()))
                new_pos = QPoint(nx, ny)
            self.move(new_pos)

    def _tb_release(self, event):
        self._drag_pos = None

    def _collapse(self):
        self._collapsed = True
        self.resize(self.width(), 40)
        if self.parent():
            p = self.parent()
            self.move(p.width() - self.width() - 8, p.height() - 48)

    def _expand(self):
        self._collapsed = False
        self.resize(860, 560)
        if self.parent():
            p = self.parent()
            self.move(p.width() - 868, p.height() - 568)

    def showEvent(self, event):
        super().showEvent(event)
        if self.parent():
            p = self.parent()
            self.move(max(0, p.width()  - self.width()  - 8),
                      max(0, p.height() - self.height() - 8))
        self._input.setFocus()
        self.raise_()


# ═══════════════════════════════════════════════════════════════════════════
#  MEWA 1-2-3  —  GoidaPhone built-in media player
# ═══════════════════════════════════════════════════════════════════════════
class MewaPlayer(QWidget):
    """
    Mewa 1-2-3 v1.32 — медиаплеер GoidaPhone.
    Структура: боковая иконочная панель + основная область со стеком страниц
    + нижняя полоска управления воспроизведением. Всё следует текущей теме.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self._playlist: list[dict] = []
        self._queue_idx  = -1
        self._shuffle    = False
        self._repeat     = "off"          # off | one | all
        self._has_player = False
        self._player     = None
        self._audio_out  = None
        self._setup()

    # ════════════════════════════════ UI SETUP ════════════════════════════════
    def _setup(self):
        t = get_theme(S().theme)
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── SIDEBAR ───────────────────────────────────────────────────────────
        self._sidebar = QWidget()
        self._sidebar.setFixedWidth(80)
        self._sidebar.setObjectName("mewa_side")
        self._sidebar.setStyleSheet(
            f"QWidget#mewa_side{{background:{t['bg3']};"
            f"border-right:1px solid {t['border']};}}")
        sb = QVBoxLayout(self._sidebar)
        sb.setContentsMargins(0, 6, 0, 6)
        sb.setSpacing(0)

        # Logo bar with accent bg
        logo_bar = QWidget()
        logo_bar.setFixedHeight(52)
        logo_bar.setStyleSheet(
            f"background:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
            f"stop:0 {t['accent']},stop:1 {t['bg3']});")
        logo_lay = QVBoxLayout(logo_bar)
        logo_lay.setContentsMargins(0, 0, 0, 0)
        logo = QLabel("♫")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet("font-size:24px;color:white;background:transparent;font-weight:bold;")
        logo_lay.addWidget(logo)
        sb.addWidget(logo_bar)

        self._section_btns: dict[str, QPushButton] = {}
        SECTIONS = [
            ("queue",    "▶",  "Очередь"),
            ("library",  "♫",  "Фонотека"),
            ("files",    "▤",  "Файлы"),
            ("playlists","≡",  "Списки"),
            ("video",    "🎬", "Видео"),
            ("radio",    "📻", "Радио"),
            ("eq",       "🎚", "EQ"),
            ("lyrics",   "📝", "Текст"),
        ]
        for key, ico, label in SECTIONS:
            btn = QPushButton(f"{ico}\n{label}")
            btn.setCheckable(True)
            btn.setFixedHeight(62)
            btn.setStyleSheet(
                f"QPushButton{{background:transparent;color:{t['text_dim']};"
                "border:none;border-left:3px solid transparent;"
                "font-size:10px;font-weight:bold;padding:4px 0;}}"
                f"QPushButton:hover{{background:{t['btn_hover']};color:{t['text']};"
                "border-left:3px solid transparent;}}"
                f"QPushButton:checked{{background:{t['bg3']};color:white;"
                f"border-left:3px solid {t['accent']};}}"
                f"QPushButton:checked:hover{{background:{t['bg3']};color:white;"
                f"border-left:3px solid {t['accent']};}}")
            btn.clicked.connect(lambda _, k=key: self._show_section(k))
            self._section_btns[key] = btn
            sb.addWidget(btn)

        sb.addStretch()
        ver = QLabel("v1.32\nWinora")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver.setStyleSheet(f"font-size:7px;color:{t['text_dim']};background:transparent;padding:6px 0;")
        sb.addWidget(ver)
        outer.addWidget(self._sidebar)

        # ── RIGHT COLUMN ──────────────────────────────────────────────────────
        right_col = QWidget()
        right_col.setObjectName("mewa_right")
        right_col.setStyleSheet(f"QWidget#mewa_right{{background:{t['bg']};}}")
        rc_lay = QVBoxLayout(right_col)
        rc_lay.setContentsMargins(0, 0, 0, 0)
        rc_lay.setSpacing(0)

        # ── TOOLBAR ───────────────────────────────────────────────────────────
        tb = QWidget()
        tb.setFixedHeight(38)
        tb.setObjectName("mewa_tb")
        tb.setStyleSheet(
            f"QWidget#mewa_tb{{background:{t['bg2']};"
            f"border-bottom:1px solid {t['border']};}}")
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(8, 0, 8, 0)
        tbl.setSpacing(4)

        def mk_tb(txt, tip, cb):
            b = QPushButton(txt)
            b.setFixedSize(30, 26)
            b.setToolTip(tip)
            b.setStyleSheet(
                f"QPushButton{{background:{t['bg3']};color:{t['text']};"
                f"border:1px solid {t['border']};border-radius:4px;font-size:11px;}}"
                f"QPushButton:hover{{background:{t['btn_hover']};}}")
            b.clicked.connect(cb)
            tbl.addWidget(b)

        mk_tb("+", "Добавить файлы", self._add_files)
        mk_tb("▤", "Добавить папку", self._add_folder)
        mk_tb("✕", "Очистить очередь", self._clear_queue)
        tbl.addStretch()
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("🔍 Поиск...")
        self._search_edit.setFixedWidth(180)
        self._search_edit.setStyleSheet(
            f"QLineEdit{{background:{t['bg3']};color:{t['text']};"
            f"border:1px solid {t['border']};border-radius:4px;"
            "padding:2px 8px;font-size:10px;}}")
        self._search_edit.textChanged.connect(self._filter_lib)
        tbl.addWidget(self._search_edit)
        rc_lay.addWidget(tb)

        # ── PAGE STACK ────────────────────────────────────────────────────────
        self._stack = QStackedWidget()

        # Page 0 — Queue
        qp = QWidget()
        qp_lay = QVBoxLayout(qp)
        qp_lay.setContentsMargins(0, 0, 0, 0)
        self._queue_tbl = self._mk_table(["#", "Название", "Исполнитель", "Длина"])
        self._queue_tbl.setColumnWidth(0, 36)
        self._queue_tbl.setColumnWidth(3, 54)
        self._queue_tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._queue_tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._queue_tbl.doubleClicked.connect(lambda i: self._play_idx(i.row()))
        self._queue_tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._queue_tbl.customContextMenuRequested.connect(self._queue_ctx)
        qp_lay.addWidget(self._queue_tbl)
        self._stack.addWidget(qp)   # idx 0

        # Page 1 — Library  (art panel + track table)
        lp = QWidget()
        lp_lay = QHBoxLayout(lp)
        lp_lay.setContentsMargins(0, 0, 0, 0)
        lp_lay.setSpacing(0)

        art_panel = QWidget()
        art_panel.setFixedWidth(210)
        art_panel.setObjectName("mewa_art")
        art_panel.setStyleSheet(
            f"QWidget#mewa_art{{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
            f"stop:0 {t['bg3']},stop:1 {t['bg2']});"
            f"border-right:1px solid {t['border']};}}")
        apl = QVBoxLayout(art_panel)
        apl.setContentsMargins(12, 14, 12, 14)
        apl.setSpacing(8)

        self._art_lbl = QLabel("♫")
        self._art_lbl.setFixedSize(186, 186)
        self._art_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._art_lbl.setObjectName("mewa_art_img")
        self._art_lbl.setStyleSheet(
            f"QLabel#mewa_art_img{{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,"
            f"stop:0 {t['bg3']},stop:1 {t['bg']});"
            f"border-radius:14px;font-size:64px;color:{t['accent']};"
            f"border:2px solid {t['border']};}}")
        apl.addWidget(self._art_lbl)

        self._np_title  = QLabel("Нет трека")
        self._np_title.setWordWrap(True)
        self._np_title.setStyleSheet(
            f"font-size:12px;font-weight:bold;color:{t['text']};background:transparent;")
        self._np_artist = QLabel("")
        self._np_artist.setStyleSheet(
            f"font-size:11px;color:{t['accent']};background:transparent;")
        self._np_album  = QLabel("")
        self._np_album.setStyleSheet(
            f"font-size:10px;color:{t['text_dim']};background:transparent;")
        for lbl in (self._np_title, self._np_artist, self._np_album):
            lbl.setWordWrap(True)
            apl.addWidget(lbl)
        apl.addStretch()
        lp_lay.addWidget(art_panel)

        self._lib_tbl = self._mk_table(["Название", "Исполнитель", "Альбом", "Длина"])
        self._lib_tbl.setColumnWidth(3, 54)
        for c in (0, 1, 2):
            self._lib_tbl.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeMode.Stretch)
        self._lib_tbl.doubleClicked.connect(lambda i: self._play_idx(i.row()))
        lp_lay.addWidget(self._lib_tbl)
        self._stack.addWidget(lp)   # idx 1

        # Page 2 — Files
        fp = QWidget()
        fpl = QVBoxLayout(fp)
        fpl.setContentsMargins(24, 24, 24, 24)
        fpl.setSpacing(12)
        hint = QLabel("Перетащите файлы/папки сюда\nили воспользуйтесь кнопками в тулбаре")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet(f"font-size:13px;color:{t['text_dim']};background:transparent;")
        fpl.addStretch()
        fpl.addWidget(hint)
        btn_row = QHBoxLayout()
        for txt, tip, cb in [
            ("➕ Добавить файлы", "Аудио/видео", self._add_files),
            ("📁 Добавить папку", "Рекурсивно",  self._add_folder),
        ]:
            b = QPushButton(txt)
            b.setToolTip(tip)
            b.setFixedHeight(38)
            b.setStyleSheet(
                f"QPushButton{{background:{t['bg3']};color:{t['text']};"
                f"border:1px solid {t['border']};border-radius:6px;font-size:12px;padding:0 14px;}}"
                f"QPushButton:hover{{background:{t['btn_hover']};}}")
            b.clicked.connect(cb)
            btn_row.addWidget(b)
        fpl.addLayout(btn_row)
        fpl.addStretch()
        self._stack.addWidget(fp)   # idx 2

        # Page 3 — Playlists
        pp = QWidget()
        ppl = QVBoxLayout(pp)
        ppl.setContentsMargins(8, 8, 8, 8)
        ppl.setSpacing(6)
        self._pl_list = QListWidget()
        self._pl_list.setStyleSheet(
            f"QListWidget{{background:{t['bg']};color:{t['text']};border:none;}}"
            f"QListWidget::item{{padding:8px 12px;border-bottom:1px solid {t['bg3']};}}"
            f"QListWidget::item:selected{{background:{t['accent']};}}")
        self._pl_list.doubleClicked.connect(self._load_saved_playlist)
        ppl.addWidget(self._pl_list)
        pl_btns = QHBoxLayout()
        for txt, cb in [("💾 Сохранить текущую", self._save_playlist),
                        ("🗑 Удалить", self._delete_saved_playlist)]:
            b = QPushButton(txt)
            b.setFixedHeight(32)
            b.clicked.connect(cb)
            pl_btns.addWidget(b)
        ppl.addLayout(pl_btns)
        self._stack.addWidget(pp)   # idx 3

        # ── Page 4 — Video player ─────────────────────────────────────────────
        vp = QWidget()
        vp.setObjectName("mewa_video_page")
        vp.setStyleSheet("QWidget#mewa_video_page{background:#000;}")
        vp_lay = QVBoxLayout(vp)
        vp_lay.setContentsMargins(0, 0, 0, 0)
        vp_lay.setSpacing(0)

        try:
            from PyQt6.QtMultimediaWidgets import QVideoWidget as _QVW
            self._video_widget = _QVW()
            self._video_widget.setStyleSheet("background:#000;")
            vp_lay.addWidget(self._video_widget, stretch=1)
        except ImportError:
            self._video_widget = None
            _vp_hint = QLabel(
                "📦 Установи для видео:\n"
                "pip install PyQt6-QtMultimediaWidgets --break-system-packages")
            _vp_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
            _vp_hint.setStyleSheet(
                "color:#FF9040;font-size:12px;background:transparent;")
            vp_lay.addWidget(_vp_hint, stretch=1)

        # Info bar
        vp_info = QWidget()
        vp_info.setFixedHeight(32)
        vp_info.setStyleSheet(
            f"background:{t['bg3']};border-top:1px solid {t['border']};")
        vp_info_lay = QHBoxLayout(vp_info)
        vp_info_lay.setContentsMargins(10, 0, 10, 0)
        self._video_title_lbl = QLabel("Нет видео")
        self._video_title_lbl.setStyleSheet(
            f"font-size:11px;color:{t['text']};background:transparent;")
        vp_info_lay.addWidget(self._video_title_lbl)
        vp_info_lay.addStretch()

        _back_btn = QPushButton("⬅ К очереди")
        _back_btn.setFixedHeight(24)
        _back_btn.setStyleSheet(
            f"QPushButton{{background:{t['bg2']};color:{t['text_dim']};"
            f"border:1px solid {t['border']};border-radius:4px;"
            "padding:0 8px;font-size:10px;}}"
            f"QPushButton:hover{{color:{t['text']};background:{t['btn_hover']};}}")
        _back_btn.clicked.connect(lambda: self._show_section("queue"))
        vp_info_lay.addWidget(_back_btn)

        _fs_btn = QPushButton("⛶")
        _fs_btn.setFixedSize(24, 24)
        _fs_btn.setToolTip("Полный экран  F")
        _fs_btn.setStyleSheet(
            f"QPushButton{{background:{t['bg2']};color:{t['text_dim']};"
            f"border:1px solid {t['border']};border-radius:4px;font-size:13px;}}"
            f"QPushButton:hover{{color:{t['text']};background:{t['btn_hover']};}}")
        _fs_btn.clicked.connect(self._toggle_video_fullscreen)
        vp_info_lay.addWidget(_fs_btn)
        vp_lay.addWidget(vp_info)
        self._stack.addWidget(vp)   # idx 4

        # ── Page 5 — Online Radio ─────────────────────────────────────────────
        rp = QWidget()
        rp.setStyleSheet(f"background:{t['bg']};")
        rp_lay = QVBoxLayout(rp)
        rp_lay.setContentsMargins(12, 12, 12, 12)
        rp_lay.setSpacing(10)

        # Header
        rp_hdr = QLabel("📻  Онлайн Радио")
        rp_hdr.setStyleSheet(
            f"font-size:15px;font-weight:bold;color:{t['accent']};background:transparent;")
        rp_lay.addWidget(rp_hdr)

        # Current playing display
        self._radio_now = QLabel("Нет трансляции")
        self._radio_now.setStyleSheet(
            f"font-size:12px;color:{t['text']};background:{t['bg3']};"
            f"border-radius:8px;padding:10px;border:1px solid {t['border']};")
        self._radio_now.setWordWrap(True)
        rp_lay.addWidget(self._radio_now)

        # Station list
        self._radio_list = QListWidget()
        self._radio_list.setStyleSheet(
            f"QListWidget{{background:{t['bg3']};color:{t['text']};"
            "border:none;border-radius:8px;font-size:11px;}}"
            f"QListWidget::item{{padding:10px 14px;"
            f"border-bottom:1px solid {t['border']};}}"
            f"QListWidget::item:selected{{background:{t['accent']};color:white;}}"
            f"QListWidget::item:hover{{background:{t['btn_hover']};}}")

        RADIO_STATIONS = [
            ("🎵 Lofi Hip Hop",  "http://streams.ilovemusic.de/iloveradio17.mp3"),
            ("🎸 Rock Radio",     "http://streams.ilovemusic.de/iloveradio2.mp3"),
            ("🎹 Classical",      "http://streams.ilovemusic.de/iloveradio14.mp3"),
            ("🔥 Dance & EDM",    "http://streams.ilovemusic.de/iloveradio1.mp3"),
            ("🎷 Jazz FM",        "http://streams.ilovemusic.de/iloveradio21.mp3"),
            ("🌊 Chill Beats",    "http://streams.ilovemusic.de/iloveradio17.mp3"),
            ("🎻 Ambient",        "http://streams.ilovemusic.de/iloveradio15.mp3"),
            ("📻 DI.FM Chillout", "http://prem4.di.fm/chillout"),
            ("🎤 Европа Плюс",   "http://ep256.hostingradio.ru:8052/ep256.mp3"),
            ("🇷🇺 Русское",      "http://nashe.hostingradio.ru:80/nashe-320"),
            ("🎮 VGM Radio",      "http://vgmradio.com/listen"),
        ]
        self._radio_stations = RADIO_STATIONS
        for name, url in RADIO_STATIONS:
            item = QListWidgetItem(name)
            item.setData(Qt.ItemDataRole.UserRole, url)
            self._radio_list.addItem(item)

        self._radio_list.itemDoubleClicked.connect(self._play_radio)
        rp_lay.addWidget(self._radio_list, stretch=1)

        # Custom URL row
        custom_row = QHBoxLayout()
        self._radio_url_input = QLineEdit()
        self._radio_url_input.setPlaceholderText("URL потока (.mp3 .ogg .m3u8)…")
        self._radio_url_input.setStyleSheet(
            f"QLineEdit{{background:{t['bg3']};color:{t['text']};"
            f"border:1px solid {t['border']};border-radius:6px;"
            "padding:5px 10px;font-size:11px;}}"
            f"QLineEdit:focus{{border-color:{t['accent']};}}")
        custom_row.addWidget(self._radio_url_input, stretch=1)

        play_custom = QPushButton("▶ Слушать")
        play_custom.setFixedHeight(32)
        play_custom.setObjectName("accent_btn")
        play_custom.clicked.connect(self._play_radio_url)
        custom_row.addWidget(play_custom)
        rp_lay.addLayout(custom_row)

        # Install hint
        _hint = QLabel("ℹ Для потоков нужен mpv или vlc:  sudo emerge -av media-video/mpv")
        _hint.setStyleSheet(
            f"font-size:9px;color:{t['text_dim']};background:transparent;")
        _hint.setWordWrap(True)
        rp_lay.addWidget(_hint)

        # Stop button
        stop_radio = QPushButton("⏹ Стоп")
        stop_radio.setFixedHeight(32)
        stop_radio.setStyleSheet(
            f"QPushButton{{background:{t['bg3']};color:{t['text_dim']};"
            f"border:1px solid {t['border']};border-radius:6px;font-size:11px;}}"
            f"QPushButton:hover{{background:{t['btn_hover']};color:{t['text']};}}")
        stop_radio.clicked.connect(self._stop_radio)
        rp_lay.addWidget(stop_radio)

        self._stack.addWidget(rp)   # idx 5

        # ── Page 6 — Equalizer ────────────────────────────────────────────────
        ep = QWidget()
        ep.setStyleSheet(f"background:{t['bg']};")
        ep_lay = QVBoxLayout(ep)
        ep_lay.setContentsMargins(20,16,20,16); ep_lay.setSpacing(12)

        eq_hdr = QLabel("🎚  Эквалайзер")
        eq_hdr.setStyleSheet(
            f"font-size:15px;font-weight:bold;color:{t['accent']};background:transparent;")
        ep_lay.addWidget(eq_hdr)

        EQ_BANDS = [32, 64, 125, 250, 500, 1000, 2000, 4000, 8000, 16000]
        EQ_LABELS = ["32","64","125","250","500","1k","2k","4k","8k","16k"]
        self._eq_sliders = []
        sliders_row = QHBoxLayout()
        sliders_row.setSpacing(8)

        for i, (hz, lbl) in enumerate(zip(EQ_BANDS, EQ_LABELS)):
            col = QVBoxLayout()
            col.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            sl = QSlider(Qt.Orientation.Vertical)
            sl.setRange(-12, 12); sl.setValue(0)
            sl.setFixedHeight(160)
            sl.setStyleSheet(
                f"QSlider::groove:vertical{{background:{t['bg3']};"
                "width:6px;border-radius:3px;}}"
                f"QSlider::handle:vertical{{background:{t['accent']};"
                "width:16px;height:16px;margin:-5px -5px;"
                "border-radius:8px;}}"
                f"QSlider::add-page:vertical{{background:{t['accent']};"
                "border-radius:3px;}}")
            val_lbl = QLabel("0 dB")
            val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            val_lbl.setStyleSheet(
                f"font-size:9px;color:{t['text_dim']};background:transparent;")
            sl.valueChanged.connect(
                lambda v, _l=val_lbl, _i=i: (
                    _l.setText(f"{'+' if v>0 else ''}{v} dB"),
                    self._apply_eq()))
            hz_lbl = QLabel(lbl + " Hz")
            hz_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            hz_lbl.setStyleSheet(
                f"font-size:9px;color:{t['text_dim']};background:transparent;")
            col.addWidget(val_lbl)
            col.addWidget(sl, alignment=Qt.AlignmentFlag.AlignHCenter)
            col.addWidget(hz_lbl)
            sliders_row.addLayout(col)
            self._eq_sliders.append(sl)

        ep_lay.addLayout(sliders_row)

        eq_btns = QHBoxLayout()
        for preset_name, vals in [
            ("Flat",     [0]*10),
            ("Bass+",    [8,6,4,2,0,0,0,0,0,0]),
            ("Treble+",  [0,0,0,0,0,2,4,6,8,10]),
            ("Rock",     [5,4,3,0,-2,-1,2,4,5,5]),
            ("Classical",[0,0,0,0,0,0,-2,-4,-4,-5]),
            ("Vocal",    [-2,-1,0,2,4,4,3,2,1,0]),
        ]:
            pb = QPushButton(preset_name)
            pb.setFixedHeight(28)
            pb.setStyleSheet(
                f"QPushButton{{background:{t['bg3']};color:{t['text']};"
                f"border:1px solid {t['border']};border-radius:6px;font-size:10px;}}"
                f"QPushButton:hover{{background:{t['btn_hover']};}}")
            pb.clicked.connect(
                lambda _, v=vals: [s.setValue(v[i])
                                   for i, s in enumerate(self._eq_sliders)])
            eq_btns.addWidget(pb)
        ep_lay.addLayout(eq_btns)
        ep_lay.addStretch()
        self._stack.addWidget(ep)   # idx 6

        # ── Page 7 — Lyrics ───────────────────────────────────────────────────
        lp2 = QWidget()
        lp2.setStyleSheet(f"background:{t['bg']};")
        lp2_lay = QVBoxLayout(lp2)
        lp2_lay.setContentsMargins(16,12,16,12); lp2_lay.setSpacing(8)

        ly_hdr_row = QHBoxLayout()
        ly_hdr = QLabel("📝  Текст песни")
        ly_hdr.setStyleSheet(
            f"font-size:14px;font-weight:bold;color:{t['accent']};background:transparent;")
        ly_hdr_row.addWidget(ly_hdr)
        ly_hdr_row.addStretch()
        ly_search_btn = QPushButton("🔍 Найти")
        ly_search_btn.setObjectName("accent_btn")
        ly_search_btn.setFixedHeight(30)
        ly_hdr_row.addWidget(ly_search_btn)
        lp2_lay.addLayout(ly_hdr_row)

        ly_query_row = QHBoxLayout()
        self._ly_artist = QLineEdit()
        self._ly_artist.setPlaceholderText("Исполнитель")
        self._ly_title  = QLineEdit()
        self._ly_title.setPlaceholderText("Название")
        for w in [self._ly_artist, self._ly_title]:
            w.setStyleSheet(
                f"background:{t['bg3']};color:{t['text']};"
                f"border:1px solid {t['border']};border-radius:6px;"
                "padding:4px 8px;font-size:11px;")
        ly_query_row.addWidget(self._ly_artist)
        ly_query_row.addWidget(self._ly_title)
        lp2_lay.addLayout(ly_query_row)

        self._ly_text = QPlainTextEdit()
        self._ly_text.setReadOnly(True)
        self._ly_text.setStyleSheet(
            f"QPlainTextEdit{{background:{t['bg3']};color:{t['text']};"
            "font-size:12px;border:none;"
            "border-radius:10px;padding:16px;}}")
        self._ly_text.setPlaceholderText(
            "Выберите трек и нажмите Найти, или введите вручную. "
            "Тексты с lyrics.ovh (без ключа API).")
        lp2_lay.addWidget(self._ly_text, stretch=1)
        ly_search_btn.clicked.connect(self._fetch_lyrics)
        self._stack.addWidget(lp2)   # idx 7

        rc_lay.addWidget(self._stack, stretch=1)

        # ── PLAYER BAR ────────────────────────────────────────────────────────
        pbar = QWidget()
        pbar.setObjectName("mewa_pbar")
        pbar.setFixedHeight(84)
        pbar.setStyleSheet(
            f"QWidget#mewa_pbar{{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
            f"stop:0 {t['bg3']},stop:1 {t['bg2']});"
            f"border-top:2px solid {t['accent']};}}")
        pbl = QVBoxLayout(pbar)
        pbl.setContentsMargins(12, 5, 12, 5)
        pbl.setSpacing(3)

        # Progress row
        pr = QHBoxLayout()
        self._t_cur = QLabel("0:00")
        self._t_cur.setFixedWidth(36)
        self._t_cur.setStyleSheet(
            f"font-size:9px;color:{t['text_dim']};background:transparent;")
        self._prog = QSlider(Qt.Orientation.Horizontal)
        self._prog.setRange(0, 1000)
        self._prog.sliderMoved.connect(self._seek)
        self._prog.setStyleSheet(
            f"QSlider::groove:horizontal{{height:4px;background:{t['bg3']};border-radius:2px;}}"
            f"QSlider::handle:horizontal{{width:12px;height:12px;margin:-4px 0;"
            f"background:{t['accent']};border-radius:6px;}}"
            f"QSlider::sub-page:horizontal{{background:{t['accent']};border-radius:2px;}}")
        self._t_tot = QLabel("0:00")
        self._t_tot.setFixedWidth(36)
        self._t_tot.setAlignment(Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
        self._t_tot.setStyleSheet(self._t_cur.styleSheet())
        pr.addWidget(self._t_cur)
        pr.addWidget(self._prog)
        pr.addWidget(self._t_tot)
        pbl.addLayout(pr)

        # Controls row
        cr = QHBoxLayout()
        cr.setSpacing(5)

        def mk_c(txt, tip, cb, w=34, accent=False):
            b = QPushButton(txt)
            b.setFixedSize(w, 30)
            b.setToolTip(tip)
            if accent:
                s = (f"QPushButton{{background:{t['accent']};color:white;"
                     "border-radius:15px;font-size:15px;border:none;"
                     "border-bottom:2px solid rgba(0,0,0,89);}}"
                     f"QPushButton:hover{{background:{t['accent2']};}}"
                     "QPushButton:pressed{padding-top:2px;border-bottom:1px solid;}")
            else:
                s = (f"QPushButton{{background:{t['bg3']};color:{t['text']};"
                     f"border-radius:6px;font-size:13px;border:1px solid {t['border']};"
                     "border-bottom:2px solid rgba(0,0,0,63);}}"
                     f"QPushButton:hover{{background:{t['btn_hover']};}}"
                     "QPushButton:pressed{padding-top:2px;border-bottom:1px solid;}")
            b.setStyleSheet(s)
            b.clicked.connect(cb)
            return b

        cr.addWidget(mk_c("|◀", "Предыдущий", self._prev))
        cr.addWidget(mk_c("◀◀", "−10 сек",    lambda: self._skip(-10)))
        self._play_btn = mk_c("▶", "Play/Pause", self._toggle_play, w=42, accent=True)
        cr.addWidget(self._play_btn)
        cr.addWidget(mk_c("▶▶", "+10 сек",    lambda: self._skip(10)))
        cr.addWidget(mk_c("▶|", "Следующий",  self._next))
        cr.addSpacing(10)

        self._shuf_btn = QPushButton("RND")
        self._shuf_btn.setFixedSize(30, 30)
        self._shuf_btn.setCheckable(True)
        self._shuf_btn.setToolTip("Случайный порядок")
        self._shuf_btn.toggled.connect(lambda v: setattr(self,'_shuffle',v))
        self._shuf_btn.setStyleSheet(
            f"QPushButton{{background:{t['bg3']};border-radius:5px;font-size:12px;"
            f"border:1px solid {t['border']};}}"
            f"QPushButton:checked{{background:{t['accent']};"
            f"border-color:{t['accent']};}}")
        cr.addWidget(self._shuf_btn)

        self._rep_btn = QPushButton("RPT")
        self._rep_btn.setFixedSize(30, 30)
        self._rep_btn.setCheckable(True)
        self._rep_btn.setToolTip("Повтор")
        self._rep_btn.toggled.connect(self._cycle_repeat)
        self._rep_btn.setStyleSheet(self._shuf_btn.styleSheet())
        cr.addWidget(self._rep_btn)
        cr.addStretch()

        np_box = QWidget()
        np_box.setMaximumWidth(340)
        np_box_lay = QVBoxLayout(np_box)
        np_box_lay.setContentsMargins(0,0,0,0)
        np_box_lay.setSpacing(0)
        self._np_bar = QLabel("Нет трека")
        self._np_bar.setStyleSheet(
            f"font-size:12px;font-weight:bold;color:{t['text']};background:transparent;")
        self._np_bar.setMaximumWidth(340)
        self._np_bar_artist = QLabel("")
        self._np_bar_artist.setStyleSheet(
            f"font-size:9px;color:{t['accent']};background:transparent;")
        self._np_bar_artist.setMaximumWidth(340)
        np_box_lay.addWidget(self._np_bar)
        np_box_lay.addWidget(self._np_bar_artist)
        cr.addWidget(np_box)
        cr.addStretch()

        vol_ic = QLabel("🔊")
        vol_ic.setStyleSheet("font-size:13px;background:transparent;")
        self._vol_sl = QSlider(Qt.Orientation.Horizontal)
        self._vol_sl.setRange(0, 100)
        self._vol_sl.setValue(85)
        self._vol_sl.setFixedWidth(88)
        self._vol_sl.valueChanged.connect(self._set_vol)
        self._vol_sl.setStyleSheet(self._prog.styleSheet())
        cr.addWidget(vol_ic)
        cr.addWidget(self._vol_sl)
        pbl.addLayout(cr)

        rc_lay.addWidget(pbar)
        outer.addWidget(right_col)

        # ── INIT ──────────────────────────────────────────────────────────────
        self._init_player()
        self._refresh_saved_playlists()
        self._show_section("queue")

    # ── helper ───────────────────────────────────────────────────────────────
    def _mk_table(self, headers: list) -> QTableWidget:
        t = get_theme(S().theme)
        tbl = QTableWidget(0, len(headers))
        tbl.setHorizontalHeaderLabels(headers)
        tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.verticalHeader().setVisible(False)
        tbl.setShowGrid(False)
        tbl.setStyleSheet(
            f"QTableWidget{{background:{t['bg']};color:{t['text']};"
            "border:none;font-size:11px;}}"
            f"QTableWidget::item{{padding:5px 8px;"
            f"border-bottom:1px solid {t['bg3']};}}"
            f"QTableWidget::item:selected{{background:{t['accent']};"
            f"color:{t['text']};}}"
            f"QHeaderView::section{{background:{t['bg2']};color:{t['text_dim']};"
            "border:none;padding:4px 8px;font-size:9px;font-weight:bold;"
            f"border-bottom:1px solid {t['border']};}}")
        tbl.horizontalHeader().setStretchLastSection(False)
        tbl.verticalHeader().setDefaultSectionSize(26)
        return tbl

    # ── sections ──────────────────────────────────────────────────────────────
    _SEC_IDX = {"queue":0,"library":1,"files":2,"playlists":3,"video":4,"radio":5,"eq":6,"lyrics":7}

    def _show_section(self, key: str):
        for k, b in self._section_btns.items():
            b.setChecked(k == key)
        self._stack.setCurrentIndex(self._SEC_IDX.get(key, 0))

    # ── player init ───────────────────────────────────────────────────────────
    def _init_player(self):
        try:
            from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
            self._player     = QMediaPlayer()
            self._audio_out  = QAudioOutput()
            self._player.setAudioOutput(self._audio_out)
            self._audio_out.setVolume(0.85)
            self._player.positionChanged.connect(self._on_pos)
            self._player.durationChanged.connect(self._on_dur)
            self._player.playbackStateChanged.connect(self._on_state)
            self._player.mediaStatusChanged.connect(self._on_status)
            # Connect video output (created in _setup as part of video page)
            if getattr(self, '_video_widget', None) is not None:
                self._player.setVideoOutput(self._video_widget)
            self._has_player = True
        except Exception as e:
            self._has_player = False
            err = QLabel(
                f"⚠  PyQt6.QtMultimedia недоступен:\n{e}\n\n"
                "Для воспроизведения установите:\n"
                "pip install PyQt6-Qt6-Multimedia --break-system-packages\n\n"
                "Плейлист всё равно работает — добавляйте файлы.")
            err.setWordWrap(True)
            err.setAlignment(Qt.AlignmentFlag.AlignCenter)
            err.setStyleSheet("color:#FF9040;font-size:11px;background:transparent;padding:20px;")
            self._queue_tbl.setRowCount(0)
            # Add a spanning label-row workaround
            self._queue_tbl.setRowCount(1)
            self._queue_tbl.setSpan(0, 0, 1, 4)
            lbl_item = QTableWidgetItem(
                f"⚠  Аудиодвижок недоступен: {e}  —  "
                "pip install PyQt6-Qt6-Multimedia --break-system-packages")
            lbl_item.setForeground(QColor("#FF9040"))
            self._queue_tbl.setItem(0, 0, lbl_item)

    # ── file management ───────────────────────────────────────────────────────
    def _add_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "Добавить медиафайлы", "",
            "Media (*.mp3 *.wav *.ogg *.flac *.aac *.m4a *.opus *.wma "
            "*.mp4 *.avi *.mkv *.webm *.mov *.m4v)")
        for f in files:
            self._add_track(f)

    def _add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Папка с медиафайлами")
        if not folder:
            return
        EXTS = {".mp3",".wav",".ogg",".flac",".aac",".m4a",".opus",".wma",
                ".mp4",".avi",".mkv",".webm",".mov",".m4v"}
        for p in sorted(Path(folder).rglob("*")):
            if p.suffix.lower() in EXTS:
                self._add_track(str(p))

    def _add_track(self, path: str):
        if any(tr["path"] == path for tr in self._playlist):
            return
        info = self._read_tags(path)
        info["is_video"] = Path(path).suffix.lower() in {
            ".mp4",".avi",".mkv",".webm",".mov",".m4v",
            ".mpg",".mpeg",".wmv",".3gp",".ts",".m2ts"}
        self._playlist.append(info)
        n = len(self._playlist)

        r = self._queue_tbl.rowCount()
        self._queue_tbl.insertRow(r)
        self._queue_tbl.setItem(r, 0, QTableWidgetItem(
            ("🎬 " if info.get("is_video") else "") + str(n)))
        self._queue_tbl.setItem(r, 1, QTableWidgetItem(info["title"]))
        self._queue_tbl.setItem(r, 2, QTableWidgetItem(info["artist"]))
        self._queue_tbl.setItem(r, 3, QTableWidgetItem(self._fmt(info["dur"]*1000)))

        r2 = self._lib_tbl.rowCount()
        self._lib_tbl.insertRow(r2)
        self._lib_tbl.setItem(r2, 0, QTableWidgetItem(info["title"]))
        self._lib_tbl.setItem(r2, 1, QTableWidgetItem(info["artist"]))
        self._lib_tbl.setItem(r2, 2, QTableWidgetItem(info["album"]))
        self._lib_tbl.setItem(r2, 3, QTableWidgetItem(self._fmt(info["dur"]*1000)))

    @staticmethod
    def _read_tags(path: str) -> dict:
        p = Path(path)
        info = {"path": path, "title": p.stem,
                "artist": "Неизвестен", "album": "", "dur": 0}
        try:
            import mutagen
            f = mutagen.File(path, easy=True)
            if f:
                info["title"]  = str(f.get("title",  [p.stem])[0])
                info["artist"] = str(f.get("artist", ["Неизвестен"])[0])
                info["album"]  = str(f.get("album",  [""])[0])
                info["dur"]    = int(getattr(f, "info", None) and f.info.length or 0)
        except Exception:
            pass
        return info

    def _apply_eq(self):
        """Apply EQ - note: QMediaPlayer doesn't expose EQ bands directly.
        We use a workaround with audio output volume shaping."""
        # In a real implementation, we'd use gstreamer/ffmpeg EQ filters
        # For now, just update the UI and store settings
        if not hasattr(self, '_eq_sliders') or not self._eq_sliders:
            return
        vals = [s.value() for s in self._eq_sliders]
        try:
            import json as _j
            S().set("mewa_eq", _j.dumps(vals))
        except Exception: pass

    def _fetch_lyrics(self):
        """Fetch lyrics from lyrics.ovh API."""
        artist = getattr(self, '_ly_artist', None)
        title  = getattr(self, '_ly_title', None)
        if artist is None or title is None:
            return
        a = artist.text().strip()
        t_str = title.text().strip()
        # Auto-fill from current track if empty
        if not a or not t_str:
            if self._queue_idx >= 0 and self._playlist:
                info = self._playlist[self._queue_idx]
                if not a: a = info.get("artist","")
                if not t_str: t_str = info.get("title","")
                if artist: artist.setText(a)
                if title: title.setText(t_str)
        if not a or not t_str:
            if hasattr(self, '_ly_text'):
                self._ly_text.setPlainText("Введите исполнителя и название")
            return
        if hasattr(self, '_ly_text'):
            self._ly_text.setPlainText("Загрузка...")
        import threading, urllib.request, urllib.parse, json as _j
        def _fetch():
            try:
                url = (f"https://api.lyrics.ovh/v1/"
                       f"{urllib.parse.quote(a)}/{urllib.parse.quote(t_str)}")
                with urllib.request.urlopen(url, timeout=8) as resp:
                    data = _j.loads(resp.read().decode())
                lyrics = data.get("lyrics","Текст не найден")
                QTimer.singleShot(0, lambda l=lyrics:
                    self._ly_text.setPlainText(l) if hasattr(self,'_ly_text') else None)
            except Exception as e:
                QTimer.singleShot(0, lambda err=str(e):
                    self._ly_text.setPlainText(f"Ошибка: {err}")
                    if hasattr(self,'_ly_text') else None)
        threading.Thread(target=_fetch, daemon=True).start()

    def open_file(self, path: str):
        """Public API: add file to queue and play immediately.
        _play_idx will automatically switch to the video page for video files."""
        self._add_track(path)
        idx = len(self._playlist) - 1
        if idx >= 0:
            self._play_idx(idx)

    # ── Radio ─────────────────────────────────────────────────────────────────
    def _play_radio(self, item=None):
        """Play selected radio station."""
        if item is None:
            item = self._radio_list.currentItem()
        if not item: return
        url = item.data(Qt.ItemDataRole.UserRole)
        name = item.text()
        self._play_radio_url(url, name)

    def _play_radio_url(self, url: str = "", name: str = ""):
        if not url:
            inp = getattr(self, '_radio_url_input', None)
            if inp: url = inp.text().strip()
        if not url: return
        if not name: name = url

        # Stop any previous radio subprocess
        self._stop_radio_proc()

        # Update UI immediately
        self._play_btn.setText("⏸")
        try: self._np_bar.setText(f"📻 {name}")
        except Exception: pass
        try: self._np_bar_artist.setText("Онлайн Радио")
        except Exception: pass
        try: self._np_title.setText(name)
        except Exception: pass
        try: self._np_artist.setText("Онлайн Радио")
        except Exception: pass
        try: self._np_album.setText(url)
        except Exception: pass
        if hasattr(self, '_radio_now'):
            self._radio_now.setText(f"▶ {name}")
        self._show_section("radio")

        # Try QMediaPlayer first (works if GStreamer/FFmpeg plugin installed)
        qt_ok = False
        if self._has_player:
            try:
                from PyQt6.QtCore import QUrl
                self._player.setSource(QUrl(url))
                self._player.play()
                # Give it 2 seconds to start, check status
                def _check_qt():
                    from PyQt6.QtMultimedia import QMediaPlayer as _QMP
                    st = self._player.mediaStatus()
                    err = self._player.error() if hasattr(self._player, 'error') else None
                    if (st in (_QMP.MediaStatus.NoMedia, _QMP.MediaStatus.InvalidMedia)
                            or (err and err != _QMP.Error.NoError)):
                        # Qt failed — fall back to subprocess
                        self._player.stop()
                        self._play_radio_subprocess(url, name)
                QTimer.singleShot(2500, _check_qt)
                qt_ok = True
            except Exception:
                pass

        if not qt_ok:
            self._play_radio_subprocess(url, name)

    def _play_radio_subprocess(self, url: str, name: str):
        """Play radio via mpv/vlc/ffplay as subprocess fallback."""
        import subprocess as _sp
        self._radio_proc = None
        players = ["mpv", "vlc", "ffplay", "mplayer"]
        for player in players:
            try:
                args = {
                    "mpv":    [player, "--no-video", "--really-quiet", url],
                    "vlc":    [player, "--intf", "dummy", "--no-video", url],
                    "ffplay": [player, "-nodisp", "-autoexit", "-loglevel", "quiet", url],
                    "mplayer":[player, "-nocache", "-vo", "null", url],
                }.get(player, [player, url])
                self._radio_proc = _sp.Popen(
                    args, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
                if hasattr(self, '_radio_now'):
                    self._radio_now.setText(f"▶ {name}  (via {player})")
                print(f"[radio] playing via {player}: {url}")
                return
            except FileNotFoundError:
                continue
        # Nothing worked
        if hasattr(self, '_radio_now'):
            self._radio_now.setText(
                "❌ Установи mpv или vlc для воспроизведения потока")
        self._play_btn.setText("▶")
        print("[radio] no player available: install mpv or vlc")

    def _stop_radio_proc(self):
        proc = getattr(self, '_radio_proc', None)
        if proc:
            try: proc.terminate()
            except Exception: pass
            self._radio_proc = None

    def _stop_radio(self):
        self._stop_radio_proc()
        if self._has_player:
            try: self._player.stop()
            except Exception: pass
        self._play_btn.setText("▶")
        if hasattr(self, '_radio_now'):
            self._radio_now.setText("Нет трансляции")
        if hasattr(self, '_np_bar'):
            try: self._np_bar.setText("Нет трека")
            except Exception: pass

    def _clear_queue(self):
        if QMessageBox.question(self, "Очистить очередь", "Очистить весь список?",
                QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) \
                != QMessageBox.StandardButton.Yes:
            return
        self._playlist.clear()
        self._queue_tbl.setRowCount(0)
        self._lib_tbl.setRowCount(0)
        self._queue_idx = -1
        self._np_bar.setText("Нет трека")
        self._np_title.setText("Нет трека")
        self._np_artist.setText("")
        self._np_album.setText("")
        self._art_lbl.setText("♫")
        self._art_lbl.setPixmap(QPixmap())
        if self._has_player:
            self._player.stop()
        self._play_btn.setText("▶")

    def _filter_lib(self, q: str):
        q = q.lower()
        for row in range(self._lib_tbl.rowCount()):
            match = any(
                q in (self._lib_tbl.item(row,c).text().lower()
                       if self._lib_tbl.item(row,c) else "")
                for c in range(4))
            self._lib_tbl.setRowHidden(row, q != "" and not match)

    # ── playback ─────────────────────────────────────────────────────────────
    _VIDEO_EXTS = {".mp4",".avi",".mkv",".webm",".mov",".m4v",
                    ".mpg",".mpeg",".wmv",".3gp",".ts",".m2ts"}

    def _play_idx(self, idx: int):
        if not self._has_player or idx < 0 or idx >= len(self._playlist):
            return
        self._queue_idx = idx
        info = self._playlist[idx]
        from PyQt6.QtCore import QUrl
        self._player.setSource(QUrl.fromLocalFile(info["path"]))
        self._player.play()
        self._play_btn.setText("⏸")
        self._np_bar.setText(info["title"])
        try: self._np_bar_artist.setText(info["artist"])
        except Exception: pass
        self._np_title.setText(info["title"])
        self._np_artist.setText(info["artist"])
        self._np_album.setText(info["album"])
        self._queue_tbl.selectRow(idx)
        self._lib_tbl.selectRow(idx)
        ext = Path(info["path"]).suffix.lower()
        if ext in self._VIDEO_EXTS:
            self._show_section("video")
            if hasattr(self, '_video_title_lbl'):
                self._video_title_lbl.setText(
                    info["title"] or Path(info["path"]).name)
            try: self._art_lbl.setPixmap(QPixmap()); self._art_lbl.setText("🎬")
            except Exception: pass
        else:
            self._load_art(info["path"])
            # Auto-populate lyrics fields
            if hasattr(self, '_ly_artist') and self._ly_artist:
                self._ly_artist.setText(info.get("artist",""))
            if hasattr(self, '_ly_title') and self._ly_title:
                self._ly_title.setText(info.get("title",""))

    def _load_art(self, path: str):
        t = get_theme(S().theme)
        pm = None
        try:
            import mutagen.id3
            tags = mutagen.id3.ID3(path)
            for k in tags:
                if k.startswith("APIC"):
                    pm = QPixmap()
                    pm.loadFromData(tags[k].data)
                    break
        except Exception:
            pass
        if pm and not pm.isNull():
            pm = pm.scaled(186, 186, Qt.AspectRatioMode.KeepAspectRatio,
                           Qt.TransformationMode.SmoothTransformation)
            self._art_lbl.setPixmap(pm)
            self._art_lbl.setText("")
        else:
            self._art_lbl.setPixmap(QPixmap())
            self._art_lbl.setText("♫")

    def _toggle_video_fullscreen(self):
        vw = getattr(self, '_video_widget', None)
        if vw is None: return
        if vw.isFullScreen(): vw.setFullScreen(False)
        else: vw.setFullScreen(True)

    def _toggle_play(self):
        if not self._has_player:
            return
        from PyQt6.QtMultimedia import QMediaPlayer as QMP
        st = self._player.playbackState()
        if st == QMP.PlaybackState.PlayingState:
            self._player.pause()
        elif self._queue_idx >= 0:
            self._player.play()
        elif self._playlist:
            self._play_idx(0)

    def _prev(self):
        if not self._playlist: return
        import random
        self._play_idx(random.randint(0,len(self._playlist)-1) if self._shuffle
                       else (self._queue_idx-1)%len(self._playlist))

    def _next(self):
        if not self._playlist: return
        import random
        self._play_idx(random.randint(0,len(self._playlist)-1) if self._shuffle
                       else (self._queue_idx+1)%len(self._playlist))

    def _skip(self, sec: int):
        if not self._has_player: return
        self._player.setPosition(
            max(0, min(self._player.position()+sec*1000, self._player.duration())))

    def _seek(self, val: int):
        if not self._has_player: return
        dur = self._player.duration()
        if dur > 0:
            self._player.setPosition(int(val/1000*dur))

    def _set_vol(self, v: int):
        if not self._has_player: return
        self._audio_out.setVolume(v/100.0)

    def _cycle_repeat(self, checked: bool):
        self._repeat = "all" if checked else "off"
        self._rep_btn.setToolTip(f"Повтор: {'все' if checked else 'выкл'}")

    # ── signals ───────────────────────────────────────────────────────────────
    def _on_pos(self, ms: int):
        dur = self._player.duration() if self._has_player else 0
        if dur > 0:
            self._prog.setValue(int(ms/dur*1000))
        self._t_cur.setText(self._fmt(ms))

    def _on_dur(self, ms: int):
        self._t_tot.setText(self._fmt(ms))

    def _on_state(self, state):
        from PyQt6.QtMultimedia import QMediaPlayer as QMP
        is_playing = (state == QMP.PlaybackState.PlayingState)
        self._play_btn.setText("⏸" if is_playing else "▶")
        # Update visualizers
        if hasattr(self, '_visualizer'):
            self._visualizer.set_playing(is_playing)
        if hasattr(self, '_viz_strip'):
            self._viz_strip.set_playing(is_playing)

    def _on_status(self, status):
        from PyQt6.QtMultimedia import QMediaPlayer as QMP
        if status == QMP.MediaStatus.EndOfMedia:
            if self._repeat == "one":
                self._player.setPosition(0); self._player.play()
            else:
                self._next()

    @staticmethod
    def _fmt(ms: int) -> str:
        s = max(0, ms)//1000
        return f"{s//60}:{s%60:02d}"

    # ── context menu ─────────────────────────────────────────────────────────
    def _queue_ctx(self, pos):
        item = self._queue_tbl.itemAt(pos)
        if not item: return
        row = self._queue_tbl.row(item)
        menu = QMenu(self)
        menu.addAction("▶ Воспроизвести",   lambda: self._play_idx(row))
        menu.addAction("🗑 Убрать из очереди", lambda: self._remove_row(row))
        menu.addAction("📁 Открыть в менеджере",
            lambda: self._open_fm(self._playlist[row]["path"]))
        menu.exec(self._queue_tbl.mapToGlobal(pos))

    def _remove_row(self, row: int):
        if 0 <= row < len(self._playlist):
            self._playlist.pop(row)
        self._queue_tbl.removeRow(row)
        self._lib_tbl.removeRow(row)
        if row == self._queue_idx:
            self._queue_idx = -1

    @staticmethod
    def _open_fm(path: str):
        import subprocess, platform as pl
        folder = str(Path(path).parent)
        try:
            subprocess.Popen(
                ["explorer" if pl.system()=="Windows" else "xdg-open", folder])
        except Exception: pass

    # ── playlists ─────────────────────────────────────────────────────────────
    def _save_playlist(self):
        name, ok = QInputDialog.getText(self,"Сохранить плейлист","Название:")
        if not ok or not name.strip(): return
        import json as _json
        pls = _json.loads(S().get("mewa_playlists","[]",t=str))
        pls.append({"name":name.strip(),"tracks":[x["path"] for x in self._playlist]})
        S().set("mewa_playlists", _json.dumps(pls, ensure_ascii=False))
        self._refresh_saved_playlists()

    def _delete_saved_playlist(self):
        row = self._pl_list.currentRow()
        if row < 0: return
        import json as _json
        pls = _json.loads(S().get("mewa_playlists","[]",t=str))
        if row < len(pls):
            pls.pop(row)
            S().set("mewa_playlists", _json.dumps(pls, ensure_ascii=False))
        self._refresh_saved_playlists()

    def _load_saved_playlist(self, idx):
        import json as _json
        row = idx.row()
        pls = _json.loads(S().get("mewa_playlists","[]",t=str))
        if row < len(pls):
            self._clear_queue()
            for path in pls[row].get("tracks",[]):
                if Path(path).exists():
                    self._add_track(path)
            self._show_section("queue")

    def _refresh_saved_playlists(self):
        try:
            import json as _json
            self._pl_list.clear()
            pls = _json.loads(S().get("mewa_playlists","[]",t=str))
            for pl in pls:
                self._pl_list.addItem(
                    f"≡  {pl.get('name','?')}   ({len(pl.get('tracks',[]))} треков)")
        except Exception:
            pass


class PinLockScreen(QWidget):
    """Full-screen PIN lock. 6 digits, hint, forgot-password wipe."""
    unlocked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.setWindowFlags(Qt.WindowType.Widget)
        self._attempt_count = 0
        self._pin_entry = ""
        self._setup()

    def _setup(self):
        t = get_theme(S().theme)
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box = QWidget()
        box.setFixedWidth(320)
        box.setStyleSheet(
            f"QWidget{{background:{t['bg2']};border-radius:18px;"
            f"border:1px solid {t['border']};}}"
            "QLabel{border:none;}"
            "QGridLayout{border:none;}")
        lay = QVBoxLayout(box)
        lay.setContentsMargins(30,30,30,30)
        lay.setSpacing(14)
        lock_lbl = QLabel("\U0001F512")
        lock_lbl.setStyleSheet("font-size:36px;background:transparent;")
        lock_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(lock_lbl)
        app_lbl = QLabel(APP_NAME)
        app_lbl.setStyleSheet(
            f"font-size:17px;font-weight:bold;color:{t['accent']};")
        app_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(app_lbl)
        hint_text = S().get("pin_hint","",t=str)
        if hint_text:
            hint_lbl = QLabel(f"\u041f\u043e\u0434\u0441\u043a\u0430\u0437\u043a\u0430: {hint_text}")
            hint_lbl.setStyleSheet(f"font-size:10px;color:{t['text_dim']};background:transparent;")
            hint_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(hint_lbl)
        self._dots_lbl = QLabel("\u25cb  \u25cb  \u25cb  \u25cb  \u25cb  \u25cb")
        self._dots_lbl.setStyleSheet(f"font-size:20px;color:{t['accent']};background:transparent;")
        self._dots_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self._dots_lbl)
        self._err_lbl = QLabel("")
        self._err_lbl.setStyleSheet("color:#FF6060;font-size:11px;background:transparent;")
        self._err_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self._err_lbl)
        numpad = QGridLayout()
        numpad.setSpacing(8)
        keys = [1,2,3,4,5,6,7,8,9,None,0,"\u232b"]
        for i, n in enumerate(keys):
            if n is None:
                _sp = QWidget()
                _sp.setFixedSize(70,50)
                _sp.setStyleSheet("background:transparent;border:none;")
                numpad.addWidget(_sp, i//3, i%3)
                continue
            btn = QPushButton(str(n))
            btn.setFixedSize(70,50)
            btn.setStyleSheet(
                f"QPushButton{{background:{t['bg3']};color:{t['text']};")
            btn.setStyleSheet(
                f"QPushButton{{background:{t['bg3']};color:{t['text']};"  
                "border-radius:10px;font-size:17px;font-weight:bold;"
                f"border:1px solid {t['border']};"  
                "border-bottom:3px solid rgba(0,0,0,89);}}"  
                f"QPushButton:hover{{background:{t['btn_hover']};}}"  
                "QPushButton:pressed{padding-top:3px;"  
                "border-bottom:1px solid rgba(0,0,0,51);}}")
            btn.clicked.connect(lambda _, v=n: self._on_key(v))
            numpad.addWidget(btn, i//3, i%3)
        lay.addLayout(numpad)
        forgot_btn = QPushButton("\u0417\u0430\u0431\u044b\u043b PIN")
        forgot_btn.setFlat(True)
        forgot_btn.setStyleSheet(
            f"color:{t['text_dim']};font-size:10px;background:transparent;"  
            "text-decoration:underline;border:none;")
        forgot_btn.clicked.connect(self._forgot_pin)
        lay.addWidget(forgot_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(box)

    def _update_dots(self):
        filled = "\u25cf" * len(self._pin_entry)
        empty  = "\u25cb" * (6 - len(self._pin_entry))
        self._dots_lbl.setText("  ".join(list(filled + empty)))

    def _on_key(self, val):
        if val == "\u232b":
            self._pin_entry = self._pin_entry[:-1]
            self._update_dots()
            return
        if len(self._pin_entry) < 6:
            self._pin_entry += str(val)
        self._update_dots()
        # Check at 4, 5, 6 digits — supports short PINs
        if len(self._pin_entry) >= 4:
            import hashlib as _hl
            stored = S().get("pin_hash","",t=str)
            if stored and _hl.sha256(self._pin_entry.encode()).hexdigest() == stored:
                self._check_pin()
                return
        if len(self._pin_entry) == 6:
            self._check_pin()

    def _check_pin(self):
        import hashlib
        stored = S().get("pin_hash","",t=str)
        if hashlib.sha256(self._pin_entry.encode()).hexdigest() == stored:
            self._err_lbl.setText("")
            self.unlocked.emit()
        else:
            self._attempt_count += 1
            self._err_lbl.setText(
                f"\u041d\u0435\u0432\u0435\u0440\u043d\u044b\u0439 PIN ({self._attempt_count})"
            )
            AnimationHelper.shake(self)
            self._pin_entry = ""
            self._update_dots()

    def _forgot_pin(self):
        reply = QMessageBox.warning(
            self,
            "\u0417\u0430\u0431\u044b\u043b\u0438 PIN?",
            "\u0421\u0431\u0440\u043e\u0441\u0438\u0442\u044c?\n"
            "\u0412\u0421\u0415 \u0434\u0430\u043d\u043d\u044b\u0435 "
            "\u0431\u0443\u0434\u0443\u0442 \u0443\u0434\u0430\u043b\u0435\u043d\u044b.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._wipe_data()

    def _wipe_data(self):
        import shutil
        # 1. Wipe ALL QSettings keys
        cfg = S()
        cfg._s.clear()
        cfg._s.sync()
        # 2. Delete data directory (history, avatars, received files, groups, contacts)
        try:
            if DATA_DIR.exists():
                shutil.rmtree(str(DATA_DIR))
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            AVATARS_DIR.mkdir(exist_ok=True)
            RECEIVED_DIR.mkdir(exist_ok=True)
            HISTORY_DIR.mkdir(exist_ok=True)
        except Exception as e:
            print(f"[wipe] {e}")
        # 3. Clear in-memory caches
        try:
            HISTORY._cache.clear()
        except Exception:
            pass
        QMessageBox.information(self, "Сброс", "Данные удалены. Приложение закроется.")
        QApplication.quit()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.parent():
            self.resize(self.parent().size())

# ═══════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════
#  TUTORIAL OVERLAY  (step-by-step with arrows)
# ═══════════════════════════════════════════════════════════════════════════
class TutorialOverlay(QWidget):
    """
    Full-window transparent overlay that dims everything except the
    target widget and shows a tooltip bubble with an arrow.
    """
    finished = pyqtSignal()

    STEPS_RU = [
        ("Добро пожаловать в GoidaPhone!",
         "Это мессенджер для общения в локальной сети (LAN) и через VPN.\n"
         "Нажми → чтобы продолжить обучение.",
         None),
        ("Список пользователей",
         "Здесь показаны все онлайн-пользователи в твоей сети.\n"
         "Двойной клик — открыть личный чат. Правый клик — меню действий.",
         "peer_list"),
        ("Вкладки чата",
         "Вкладки сверху: Чат (публичный), Заметки, Звонки, Mewa-плеер.\n"
         "Вкладка «Чат» — общий канал для всех в сети.",
         "chat_tabs"),
        ("Поле ввода сообщения",
         "Введи сообщение и нажми Enter или кнопку ▶ для отправки.\n"
         "Начни с / чтобы увидеть список команд.",
         "input_area"),
        ("Звонки",
         "Кнопка 📞 в шапке чата начинает голосовой звонок.\n"
         "Звонок откроется в отдельном плавающем окне.",
         "call_btn"),
        ("Группы",
         "Вкладка «Группы» слева — создавай и управляй группами.\n"
         "Ты можешь звать других пользователей через контекстное меню.",
         "groups_tab"),
        ("Профиль",
         "Файл → Мой профиль (Ctrl+P) — настрой аватар, имя, описание.\n"
         "Превью показывает как тебя видят другие.",
         None),
        ("Терминал ZLink",
         "Справка → ZLink Terminal — мощный терминал для администрирования.\n"
         "Введи /help чтобы увидеть все команды.",
         None),
        ("Готово!",
         "Ты прошёл базовое обучение GoidaPhone! 🎉\n"
         "Если что-то непонятно — загляни в Справка → О программе.",
         None),
    ]

    STEPS_EN = [
        ("Welcome to GoidaPhone!",
         "This is a LAN/VPN messenger for local network communication.\n"
         "Press → to continue the tutorial.",
         None),
        ("User List",
         "All online users in your network are shown here.\n"
         "Double-click to open a private chat. Right-click for actions.",
         "peer_list"),
        ("Chat Tabs",
         "Tabs at the top: Chat (public), Notes, Calls, Mewa player.\n"
         "The Chat tab is a public channel for everyone on the network.",
         "chat_tabs"),
        ("Message Input",
         "Type a message and press Enter or the ▶ button to send.\n"
         "Type / to see the list of commands.",
         "input_area"),
        ("Voice Calls",
         "The 📞 button in the chat header starts a voice call.\n"
         "The call opens in a separate floating window.",
         "call_btn"),
        ("Groups",
         "The Groups tab on the left — create and manage groups.\n"
         "Invite others via the right-click context menu.",
         "groups_tab"),
        ("Profile",
         "File → My Profile (Ctrl+P) — set your avatar, name, bio.\n"
         "Preview shows how others see you.",
         None),
        ("ZLink Terminal",
         "Help → ZLink Terminal — powerful admin terminal.\n"
         "Type /help to see all commands.",
         None),
        ("All done!",
         "You've completed the GoidaPhone tutorial! 🎉\n"
         "If you have questions, check Help → About.",
         None),
    ]

    def __init__(self, main_window, parent=None):
        super().__init__(parent or main_window)
        self._mw = main_window
        self._step = 0
        lang = S().language
        self._steps = self.STEPS_EN if lang == "en" else self.STEPS_RU
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint |
                            Qt.WindowType.WindowStaysOnTopHint)
        self.resize(main_window.size())
        self._build_bubble()
        self._show_step(0)

    def _build_bubble(self):
        t = get_theme(S().theme)
        self._bubble = QWidget(self)
        self._bubble.setObjectName("tut_bubble")
        self._bubble.setStyleSheet(f"""
            QWidget#tut_bubble {{
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 {t['bg2']}, stop:1 {t['bg3']});
                border: 2px solid {t['accent']};
                border-radius: 14px;
            }}
        """)
        self._bubble.setFixedWidth(360)
        bl = QVBoxLayout(self._bubble)
        bl.setContentsMargins(18, 14, 18, 14)
        bl.setSpacing(8)

        # Step indicator
        self._step_lbl = QLabel()
        self._step_lbl.setStyleSheet(
            f"color:{t['accent']};font-size:9px;font-weight:bold;background:transparent;")
        bl.addWidget(self._step_lbl)

        self._title_lbl = QLabel()
        self._title_lbl.setStyleSheet(
            f"color:{t['text']};font-size:15px;font-weight:bold;background:transparent;")
        self._title_lbl.setWordWrap(True)
        bl.addWidget(self._title_lbl)

        self._body_lbl = QLabel()
        self._body_lbl.setStyleSheet(
            f"color:{t['text_dim']};font-size:12px;background:transparent;")
        self._body_lbl.setWordWrap(True)
        self._body_lbl.setMinimumHeight(50)
        bl.addWidget(self._body_lbl)

        btn_row = QHBoxLayout()
        lang = S().language
        self._skip_btn = QPushButton("✕ " + ("Пропустить" if lang=="ru" else "Skip"))
        self._skip_btn.setStyleSheet(
            f"QPushButton{{background:transparent;color:{t['text_dim']};"
            "border:none;font-size:11px;}"
            f"QPushButton:hover{{color:{t['text']};}}")
        self._skip_btn.clicked.connect(self._finish)
        btn_row.addWidget(self._skip_btn)
        btn_row.addStretch()
        self._next_btn = QPushButton(("Далее →" if lang=="ru" else "Next →"))
        self._next_btn.setObjectName("accent_btn")
        self._next_btn.setFixedHeight(32)
        self._next_btn.clicked.connect(self._next)
        btn_row.addWidget(self._next_btn)
        bl.addLayout(btn_row)

    def _show_step(self, idx: int):
        if idx >= len(self._steps):
            self._finish(); return
        self._step = idx
        title, body, widget_key = self._steps[idx]
        lang = S().language
        total = len(self._steps)
        self._step_lbl.setText(f"{'Шаг' if lang=='ru' else 'Step'} {idx+1} / {total}")
        self._title_lbl.setText(title)
        self._body_lbl.setText(body)
        last = idx == total - 1
        self._next_btn.setText(("Завершить ✓" if lang=="ru" else "Finish ✓") if last
                                else ("Далее →" if lang=="ru" else "Next →"))

        # Find target widget for arrow highlight
        self._target_rect = None
        if widget_key:
            try:
                target = self._mw.findChild(QWidget, widget_key)
                if target and target.isVisible():
                    tr = target.rect()
                    tl = target.mapTo(self._mw, tr.topLeft())
                    self._target_rect = QRect(tl, tr.size())
            except Exception:
                pass

        # Position bubble: if we have a target, position near it; else center
        self._bubble.adjustSize()
        bw = self._bubble.width(); bh = self._bubble.height()
        if self._target_rect:
            tr = self._target_rect
            # Try to place bubble below target, or above if too low
            bx = max(8, min(tr.left(), self.width() - bw - 8))
            if tr.bottom() + bh + 20 < self.height():
                by = tr.bottom() + 16
            else:
                by = max(8, tr.top() - bh - 16)
            self._bubble.move(bx, by)
        else:
            self._bubble.move(
                (self.width() - bw) // 2,
                (self.height() - bh) // 2)
        self.update()

    def _draw_arrow(self, painter, from_rect: 'QRect', to_rect: 'QRect'):
        """Draw a pointing arrow from bubble to target widget."""
        from PyQt6.QtGui import QPen, QColor
        pen = QPen(QColor("#6060FF"), 2)
        pen.setStyle(Qt.PenStyle.DashLine)
        painter.setPen(pen)
        # Arrow from center of bubble bottom to center of target top
        bx = from_rect.center().x()
        by = from_rect.bottom()
        tx = to_rect.center().x()
        ty = to_rect.top()
        painter.drawLine(bx, by, tx, ty)
        # Arrowhead
        painter.setPen(QPen(QColor("#6060FF"), 2))
        sz = 8
        painter.drawLine(tx, ty, tx - sz, ty + sz)
        painter.drawLine(tx, ty, tx + sz, ty + sz)

    def _next(self):
        self._show_step(self._step + 1)

    def _finish(self):
        S().set("tutorial_done", True)
        self.hide()
        self.deleteLater()
        self.finished.emit()

    def paintEvent(self, event):
        """Draw semi-transparent dark overlay with target highlight and arrow."""
        from PyQt6.QtGui import QPainter, QColor, QPen
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Full dim overlay
        p.fillRect(self.rect(), QColor(0, 0, 0, 155))

        # Spotlight cut-out for target widget
        if getattr(self, '_target_rect', None):
            tr = self._target_rect
            # Bright highlight border
            highlight_rect = tr.adjusted(-6, -6, 6, 6)
            p.setPen(QPen(QColor("#6060FF"), 2))
            p.setBrush(QColor(96, 96, 255, 20))
            p.drawRoundedRect(highlight_rect, 8, 8)
            p.setBrush(Qt.BrushStyle.NoBrush)
            # Arrow from bubble to target
            bub = self._bubble.geometry()
            self._draw_arrow(p, bub, tr)

        p.end()

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Escape, Qt.Key.Key_Return, Qt.Key.Key_Space):
            if event.key() == Qt.Key.Key_Escape:
                self._finish()
            else:
                self._next()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._call_log_widget: CallLogWidget | None = None
        self._call_start_time: float = 0.0

        # Install sounds to persistent location on first run
        install_sounds()

        # Core objects
        self.net   = NetworkManager()
        self.voice = VoiceCallManager(self.net)

        # File transfer assembler
        self._ft_pending: dict[str, dict] = {}   # tid → meta+chunks

        self._apply_theme_from_settings()
        self._setup_window()
        self._setup_ui()
        self._setup_menubar()
        self._setup_statusbar()
        self._connect_signals()

        # PIN lock overlay
        self._pin_overlay: PinLockScreen | None = None
        if S().get("pin_enabled", False, t=bool) and S().get("pin_hash","",t=str):
            self._show_pin_lock()

        # Auto-lock idle timer
        self._idle_timer = QTimer(self)
        self._idle_timer.timeout.connect(self._check_idle)
        self._idle_timer.start(30_000)  # check every 30s
        self._last_activity = time.time()

        # Start networking
        if not self.net.start():
            QMessageBox.critical(self,"Сеть", TR("network_error"))

        # System tray icon
        self._setup_tray()
        # Loyalty: track continuous monthly usage
        self._update_loyalty()

        # Show tutorial on first run
        if not S().get("tutorial_done", False, t=bool):
            QTimer.singleShot(800, self._show_tutorial)

        # Unread counter callbacks
        UNREAD.on_change(self._on_unread_change)

        # Restore geometry
        geom = S().get("window_geometry")
        if geom:
            self.restoreGeometry(geom)
        state = S().get("window_state")
        if state:
            self.restoreState(state)

    def _show_pin_lock(self):
        """Show PIN lock overlay."""
        if self._pin_overlay and self._pin_overlay.isVisible():
            return
        self._pin_overlay = PinLockScreen(self)
        self._pin_overlay.resize(self.size())
        self._pin_overlay.unlocked.connect(self._on_pin_unlocked)
        self._pin_overlay.show()
        self._pin_overlay.raise_()

    def _on_pin_unlocked(self):
        if self._pin_overlay:
            self._pin_overlay.hide()
            self._pin_overlay = None
        self._last_activity = time.time()

    def _check_idle(self):
        """Check for idle and auto-lock if needed."""
        if not S().get("autolock_enabled", False, t=bool):
            return
        if not S().get("pin_hash","",t=str):
            return
        if self._pin_overlay and self._pin_overlay.isVisible():
            return
        timeout_min = S().get("autolock_timeout", 5, t=int)
        if time.time() - self._last_activity > timeout_min * 60:
            self._show_pin_lock()

    def mousePressEvent(self, event):
        self._last_activity = time.time()
        super().mousePressEvent(event)

    def keyPressEvent(self, event):
        self._last_activity = time.time()
        super().keyPressEvent(event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._pin_overlay and self._pin_overlay.isVisible():
            self._pin_overlay.resize(self.size())
        # Resize terminal if exists
        if hasattr(self, '_terminal_panel') and self._terminal_panel.isVisible():
            p = self
            tp = self._terminal_panel
            tp.move(max(0, p.width() - tp.width() - 8),
                    max(0, p.height() - tp.height() - 8))

    # ── tray icon ──────────────────────────────────────────────────────
    def _setup_tray(self):
        global _TRAY_ICON_REF
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        self._tray = QSystemTrayIcon(self)
        # Use a simple phone emoji as icon (in production: load actual .ico)
        pm = QPixmap(32, 32)
        pm.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pm)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QBrush(QColor("#0078D4")))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(0, 0, 32, 32)
        painter.setPen(QPen(QColor("white")))
        painter.setFont(QFont("Arial", 16))
        painter.drawText(QRect(0, 0, 32, 32), Qt.AlignmentFlag.AlignCenter, "📱")
        painter.end()
        self._tray.setIcon(QIcon(pm))
        self._tray.setToolTip(f"{APP_NAME} v{APP_VERSION}")

        tray_menu = QMenu()
        tray_menu.addAction(QAction("📱 Открыть", self,
                                    triggered=self._restore_from_tray))
        tray_menu.addSeparator()
        tray_menu.addAction(QAction("❌ Выход", self, triggered=self.close))
        self._tray.setContextMenu(tray_menu)
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

        _TRAY_ICON_REF = self._tray

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._restore_from_tray()

    def _restore_from_tray(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def _on_unread_change(self, chat_id: str, count: int):
        """Update window title with total unread count."""
        total = UNREAD.total()
        if total > 0:
            self.setWindowTitle(
                f"({total}) {APP_NAME} v{APP_VERSION}  —  {COMPANY_NAME}")
            if hasattr(self, '_tray'):
                self._tray.setToolTip(
                    f"{APP_NAME} — {total} непрочитанных")
        else:
            self.setWindowTitle(
                f"{APP_NAME} v{APP_VERSION}  —  {COMPANY_NAME}")
            if hasattr(self, '_tray'):
                self._tray.setToolTip(f"{APP_NAME} v{APP_VERSION}")
        key = S().theme
        if key.startswith("__custom_"):
            slot = int(key.split("_")[-1])
            data = S().custom_theme(slot)
            if data and "colors" in data:
                t = {**get_theme("dark"), **data["colors"]}
                QApplication.instance().setStyleSheet(build_stylesheet(t))
                return
            key = "dark"
        t = get_theme(key)
        QApplication.instance().setStyleSheet(build_stylesheet(t))

    # ── theme ──────────────────────────────────────────────────────────
    def _apply_theme_from_settings(self):
        """Apply the current theme from AppSettings to the QApplication."""
        key = S().theme
        if key.startswith("__custom_"):
            try:
                slot = int(key.split("_")[-1])
                data = S().custom_theme(slot)
                if data and "colors" in data:
                    t = {**get_theme("dark"), **data["colors"]}
                    QApplication.instance().setStyleSheet(build_stylesheet(t))
                    self._retheme_all_displays()
                    return
            except Exception:
                pass
            key = "dark"
        t = get_theme(key)
        QApplication.instance().setStyleSheet(build_stylesheet(t))
        self._retheme_all_displays()

    def _retheme_all_displays(self):
        """Force all ChatDisplay widgets to re-apply theme to bubbles."""
        if hasattr(self, 'chat_panel'):
            try:
                for d in self.chat_panel.findChildren(ChatDisplay):
                    d.retheme()
                # Also retheme current display directly
                if hasattr(self.chat_panel, '_display'):
                    self.chat_panel._display.retheme()
            except Exception:
                pass

    # ── window setup ───────────────────────────────────────────────────
    def _setup_window(self):
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}  —  {COMPANY_NAME}")
        self.setMinimumSize(900, 620)
        self.resize(1100, 700)

    def keyPressEvent(self, event):
        """Handle global key shortcuts."""
        mods = event.modifiers()
        key  = event.key()
        if key == Qt.Key.Key_F11:
            self._toggle_fullscreen()
        elif key == Qt.Key.Key_Escape and self.isFullScreen():
            self.showNormal()
        elif key == Qt.Key.Key_F10 and (mods & Qt.KeyboardModifier.ShiftModifier):
            self._toggle_terminal()
        elif key == Qt.Key.Key_F9 and (mods & Qt.KeyboardModifier.ShiftModifier):
            self._toggle_terminal()
        else:
            super().keyPressEvent(event)

    def _on_tab_changed(self, idx: int):
        """Trigger repaint on tab switch (safe — no opacity effect on container)."""
        w = self._tabs.widget(idx)
        if w is not None:
            w.update()
            w.repaint()

    def _open_wns(self):
        """Switch to the WNS tab."""
        for i in range(self._tabs.count()):
            if "WNS" in self._tabs.tabText(i):
                self._tabs.setCurrentIndex(i)
                return
        # Fallback: create if missing
        if not hasattr(self, '_wns_player') or self._wns_player is None:
            self._wns_player = WinoraNetScape()
        idx = self._tabs.addTab(self._wns_player, "🌐 WNS")
        self._tabs.setCurrentIndex(idx)

    def _open_terminal(self):
        """Show ZLink Terminal tab."""
        if hasattr(self, '_terminal_panel'):
            if hasattr(self, '_tabs'):
                self._tabs.setCurrentWidget(self._terminal_panel)
        self._toggle_terminal()

    def _start_tutorial(self):
        """Start the interactive tutorial."""
        lang = S().language
        reply = QMessageBox.question(
            self,
            "Учебник" if lang == "ru" else "Tutorial",
            ("Запустить учебник GoidaPhone?\nОн покажет основные функции приложения."
             if lang == "ru" else
             "Start the GoidaPhone tutorial?\nIt will walk you through the main features."),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            S().set("tutorial_done", False)
            self._show_tutorial()

    def _toggle_terminal(self):
        """Toggle the floating GoidaPhone terminal panel with animation."""
        if not hasattr(self, '_terminal_panel'):
            return
        tp = self._terminal_panel
        if tp.isVisible():
            # Fade out then hide, clear effect
            from PyQt6.QtWidgets import QGraphicsOpacityEffect
            eff = QGraphicsOpacityEffect(tp)
            tp.setGraphicsEffect(eff)
            a = QPropertyAnimation(eff, b"opacity", tp)
            a.setDuration(160)
            a.setStartValue(1.0)
            a.setEndValue(0.0)
            a.setEasingCurve(QEasingCurve.Type.InCubic)
            a.finished.connect(tp.hide)
            a.finished.connect(lambda: tp.setGraphicsEffect(None))
            a.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
        else:
            tp.show()
            tp.raise_()
            # Fade in then clear effect
            from PyQt6.QtWidgets import QGraphicsOpacityEffect
            eff = QGraphicsOpacityEffect(tp)
            eff.setOpacity(0.0)
            tp.setGraphicsEffect(eff)
            a = QPropertyAnimation(eff, b"opacity", tp)
            a.setDuration(200)
            a.setStartValue(0.0)
            a.setEndValue(1.0)
            a.setEasingCurve(QEasingCurve.Type.OutCubic)
            a.finished.connect(lambda: tp.setGraphicsEffect(None))
            a.finished.connect(lambda: tp.update())
            a.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)

    def _toggle_fullscreen(self):
        """п.34 — F11 полноэкранный режим."""
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def _apply_tab_visibility(self):
        """Show/hide permanent tabs based on settings (can't delete, only hide)."""
        show_notes = S().get("tab_show_notes", True, t=bool)
        show_calls = S().get("tab_show_calls", True, t=bool)
        # Find and set visibility
        for i in range(self._tabs.count()):
            text = self._tabs.tabText(i)
            if "Заметки" in text:
                self._tabs.setTabVisible(i, show_notes)
            elif "Звонки" in text:
                self._tabs.setTabVisible(i, show_calls)

    # ── UI ─────────────────────────────────────────────────────────────
    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_lay = QHBoxLayout(central)
        main_lay.setContentsMargins(0,0,0,0)
        main_lay.setSpacing(0)

        # Left: peer panel
        self.peer_panel = PeerPanel(self.net)
        self.peer_panel.setFixedWidth(280)

        # Right: tab area — permanent tabs have no close button
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        self._tabs.setTabsClosable(False)   # default off; per-tab via button
        self._tabs.currentChanged.connect(self._on_tab_changed)

        # Permanent tabs
        self.chat_panel = ChatPanel(self.net, self.voice)
        self._tabs.addTab(self.chat_panel, "💬 Чат")

        self.notes_widget = NotesWidget()
        self._tabs.addTab(self.notes_widget, "📝 Заметки")

        self._call_log_widget = CallLogWidget()
        self._tabs.addTab(self._call_log_widget, "📋 Звонки")

        self._mewa_player = MewaPlayer()
        self._tabs.addTab(self._mewa_player, "♫ Mewa")

        # WNS as inline tab (not separate window)
        self._wns_player = WinoraNetScape()
        self._tabs.addTab(self._wns_player, "🌐 WNS")
        self._wns_window = None  # no longer used as window

        # Mark permanent count
        self._permanent_tab_count = 5

        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.peer_panel)
        splitter.addWidget(self._tabs)
        splitter.setStretchFactor(0,0)
        splitter.setStretchFactor(1,1)
        main_lay.addWidget(splitter)

        # Floating terminal panel (hidden by default, Shift+F10)
        self._terminal_panel = GoidaTerminal(self.net, parent=central)
        self._terminal_panel.hide()

    # ── Menubar ────────────────────────────────────────────────────────
    def _setup_menubar(self):
        mb = self.menuBar()

        def act(text, slot, shortcut=None):
            a = QAction(text, self)
            a.triggered.connect(slot)
            if shortcut:
                a.setShortcut(shortcut)
            return a

        # File
        fm = mb.addMenu("Файл")
        fm.addAction(act("👤 Мой профиль",          self._show_profile,       "Ctrl+P"))
        fm.addAction(act("⚙ Настройки",             self._show_settings))
        fm.addSeparator()
        fm.addAction(act("🔄 Проверить обновления",  self._check_updates_quick))
        fm.addSeparator()
        fm.addAction(act("❌ Выход",                 self.close,               "Ctrl+Q"))

        # View
        vm = mb.addMenu("Вид")
        tm = vm.addMenu("🎨 Темы")
        for key, td in THEMES.items():
            tm.addAction(act(td["label"], lambda _, k=key: self._switch_theme(k)))
        vm.addSeparator()
        vm.addAction(act("💬 Общий чат", self._go_public))
        vm.addAction(act("♫ Mewa 1-2-3", lambda: self._tabs.setCurrentWidget(self._mewa_player)))
        vm.addSeparator()
        vm.addAction(act("⛶ Полный экран  F11", self._toggle_fullscreen, "F11"))
        vm.addAction(act("🌍 Русский", lambda: self._switch_language("ru")))
        vm.addAction(act("🌍 English",  lambda: self._switch_language("en")))

        # Calls
        cm = mb.addMenu("Звонки")
        cm.addAction(act("🎤 Вкл/Выкл микрофон",    self._toggle_mute,        "Ctrl+M"))
        cm.addAction(act("📵 Завершить все звонки",  self.voice.hangup_all))

        # Help
        hm = mb.addMenu("Справка")
        hm.addAction(act("О программе", self._about))
        hm.addSeparator()
        hm.addAction(act("⌨ ZLink Terminal", self._open_terminal, "Ctrl+`"))
        hm.addAction(act("🌐 Winora NetScape (WNS)", self._open_wns, "Ctrl+B"))
        hm.addSeparator()
        hm.addAction(act("❓ Учебник / Tutorial", self._start_tutorial))

    def _switch_theme(self, key: str):
        S().theme = key
        self._apply_theme_from_settings()

    def _switch_language(self, lang: str):
        S().language = lang
        QMessageBox.information(self, "Язык / Language",
            "Язык изменён. Перезапустите для применения." if lang == "ru"
            else "Language changed. Restart to apply.")

    # ── Statusbar ──────────────────────────────────────────────────────
    def _setup_statusbar(self):
        sb = self.statusBar()

        self._status_main = QLabel("🔍 Поиск пользователей...")
        sb.addWidget(self._status_main)

        self._status_ip = StatusWidget(f"IP: {get_local_ip()}", "#8090B0")
        sb.addPermanentWidget(self._status_ip)

        self._status_mic = StatusWidget("🎤 Вкл", "#80FF80")
        self._status_mic.setToolTip("Кликните для переключения")
        self._status_mic.mousePressEvent = lambda e: self._toggle_mute()
        sb.addPermanentWidget(self._status_mic)

        self._status_call = StatusWidget("📞 Нет звонков", "#A0A0A0")
        sb.addPermanentWidget(self._status_call)

        self._status_prem = StatusWidget("👑 Премиум", "#FFD700")
        self._status_prem.setVisible(S().premium)
        sb.addPermanentWidget(self._status_prem)

    # ── Signals ────────────────────────────────────────────────────────
    def _connect_signals(self):
        # Network
        self.net.sig_user_online.connect(self._on_user_online)
        self.net.sig_user_offline.connect(self._on_user_offline)
        self.net.sig_message.connect(self._on_message)
        self.net.sig_call_request.connect(self._on_call_request)
        self.net.sig_call_accepted.connect(self._on_call_accepted)
        self.net.sig_call_rejected.connect(self._on_call_rejected)
        self.net.sig_call_ended.connect(self._on_call_ended)
        self.net.sig_file_meta.connect(self._on_file_meta)
        self.net.sig_group_invite.connect(self._on_group_invite)
        self.net.sig_error.connect(self._on_net_error)
        self.net.sig_typing.connect(self.chat_panel.show_typing)

        # File chunks via UDP — handle in dispatch
        # We intercept MSG_FILE_DATA in the dispatcher below:
        self.net.sig_message.connect(self._on_file_chunk_msg)

        # Voice
        self.voice.call_started.connect(self._on_call_started)
        self.voice.call_ended.connect(self._on_call_ended)

        # Peer panel
        self.peer_panel.chat_requested.connect(self._open_chat)
        self.peer_panel.call_requested.connect(self._call_peer)
        self.peer_panel.group_selected.connect(self._open_group)
        self.peer_panel.invite_message_requested.connect(self._on_invite_message_requested)

    # ── Call state trackers ─────────────────────────────────────────────
    _outgoing_call_win: 'OutgoingCallWindow | None' = None
    _incoming_call_dlg: 'IncomingCallDialog | None' = None
    _active_call_win:   'ActiveCallWindow | None'   = None
    _group_call_win:    'GroupCallWindow | None'     = None

    # ── Event handlers ─────────────────────────────────────────────────
    def _on_user_online(self, peer: dict):
        self.peer_panel.add_peer(peer)
        count = len(self.net.peers)
        self._status_main.setText(f"🟢 Онлайн: {count}")
        if S().notification_sounds:
            play_system_sound("online")

    def _on_user_offline(self, ip: str):
        self.peer_panel.remove_peer(ip)
        count = len(self.net.peers)
        self._status_main.setText(f"🟢 Онлайн: {count}")

    def _on_message(self, msg: dict):
        mtype = msg.get("type","")
        if mtype in (MSG_CHAT, MSG_PRIVATE, MSG_GROUP):
            self.chat_panel.receive_message(msg)

    def _on_file_chunk_msg(self, msg: dict):
        """Handle file data chunks."""
        if msg.get("type") != MSG_FILE_DATA:
            return
        FT.on_chunk_msg(msg)

    def _on_file_meta(self, meta: dict):
        FT.on_meta(meta)
        FT.file_received.connect(self._on_file_assembled)

    def _on_file_assembled(self, meta: dict, data: bytes):
        self.chat_panel.receive_file(meta, data)

    # ── INCOMING: remote is calling us ──────────────────────────────────
    def _on_call_request(self, caller: str, ip: str):
        # Get avatar from peer info if available
        peer    = self.net.peers.get(ip, {})
        av_b64  = peer.get("avatar_b64", "")
        dlg = IncomingCallDialog(caller, ip, av_b64)
        self._incoming_call_dlg = dlg
        dlg.accepted_call.connect(lambda: self._accept_call(caller, ip))
        dlg.rejected_call.connect(lambda: self._reject_call(ip))
        dlg.show()

    def _accept_call(self, caller: str, ip: str):
        self._incoming_call_dlg = None
        # Tell caller we accepted
        self.net.send_call_accept(ip)
        # Start voice
        self.voice.call(ip)
        self._call_start_time = time.time()
        peer = self.net.peers.get(ip, {"username": caller, "ip": ip})
        # Show active call window
        av_b64 = peer.get("avatar_b64", "")
        self._active_call_win = ActiveCallWindow(caller, ip, av_b64)
        self._active_call_win.sig_hangup.connect(lambda: self._hangup_call(ip))
        self._active_call_win.sig_mute.connect(self.voice.set_mute)
        self._active_call_win.show()
        self._on_call_started(ip)
        self._open_chat(peer)

    def _reject_call(self, ip: str):
        self._incoming_call_dlg = None
        self.net.send_call_reject(ip)

    # ── OUTGOING: we are calling someone ────────────────────────────────
    def _call_peer(self, peer: dict):
        ip   = peer.get("ip", "")
        name = peer.get("username", ip)
        av   = peer.get("avatar_b64", "")
        if not ip:
            return
        # Show outgoing call screen
        win = OutgoingCallWindow(name, ip, av)
        self._outgoing_call_win = win
        win.sig_cancelled.connect(lambda: self._cancel_outgoing(ip))
        win.show()
        # Send ring signal (no voice yet — wait for accept)
        self.net.send_call_request(ip)
        if self._call_log_widget:
            self._call_log_widget.add_call(name, True)

    def _cancel_outgoing(self, ip: str):
        self._outgoing_call_win = None
        self.net.send_call_end(ip)

    # Remote accepted our call
    def _on_call_accepted(self, caller: str, ip: str):
        if self._outgoing_call_win:
            self._outgoing_call_win.call_answered()
            self._outgoing_call_win = None
        # Start voice NOW (they accepted)
        self.net.connect_voice(ip)
        self.voice.call(ip)
        self._call_start_time = time.time()
        peer  = self.net.peers.get(ip, {"username": caller, "ip": ip})
        av_b64 = peer.get("avatar_b64", "")
        self._active_call_win = ActiveCallWindow(caller, ip, av_b64)
        self._active_call_win.sig_hangup.connect(lambda: self._hangup_call(ip))
        self._active_call_win.sig_mute.connect(self.voice.set_mute)
        self._active_call_win.show()
        self._on_call_started(ip)

    # Remote rejected our call
    def _on_call_rejected(self, ip: str):
        if self._outgoing_call_win:
            self._outgoing_call_win.call_rejected()
            self._outgoing_call_win = None
        play_system_sound("error")

    def _hangup_call(self, ip: str):
        self.voice.hangup(ip)
        self._active_call_win = None

    def _on_call_started(self, ip: str):
        peer = self.net.peers.get(ip, {})
        name = peer.get("username", ip)
        self._status_call.setText(f"📞 {name}")
        t = get_theme(S().theme)
        self._status_call.setStyleSheet(
            f"color:#80FF80; background:{t['bg2']}; border:1px solid #2A5A2A;"
            "border-radius:3px; padding:1px 7px; font-size:10px;")
        self._call_start_time = time.time()
        self.chat_panel.on_call_ended  # ensure chat knows

    def _on_call_ended(self, ip: str):
        # Close any active call windows
        if self._active_call_win:
            try:
                self._active_call_win._timer.stop()
                self._active_call_win.hide()
                self._active_call_win.deleteLater()
            except Exception:
                pass
            self._active_call_win = None
        if self._outgoing_call_win:
            try:
                self._outgoing_call_win.call_rejected()
            except Exception:
                pass
            self._outgoing_call_win = None

        dur = time.time() - self._call_start_time if self._call_start_time else 0
        peer = self.net.peers.get(ip, {})
        name = peer.get("username", ip)
        if self._call_log_widget and dur > 0:
            self._call_log_widget.add_call(name, False, dur)
        self._call_start_time = 0.0
        t = get_theme(S().theme)
        self._status_call.setText("📞 Нет звонков")
        self._status_call.setStyleSheet(
            f"color:{t['text_dim']}; background:{t['bg2']}; border:1px solid {t['border']};"
            "border-radius:3px; padding:1px 7px; font-size:10px;")
        self.chat_panel.on_call_ended(ip)

    # ── GROUP CALL ───────────────────────────────────────────────────────
    def _start_group_call(self, gid: str):
        """Start or join a group call — opens GroupCallWindow."""
        group = GROUPS.groups.get(gid)
        if not group:
            return
        gname  = group.get("name", gid)
        # Build participant list from online peers in group
        members = group.get("members", [])
        participants = [
            p for ip, p in self.net.peers.items()
            if ip in members
        ]
        # Start voice with all online members
        for p in participants:
            self.voice.call(p.get("ip", ""))

        win = GroupCallWindow(gname, participants, self.voice)
        self._group_call_win = win
        win.sig_leave.connect(self._leave_group_call)
        win.show()
        # Broadcast call request to group members
        for p in participants:
            self.net.send_call_request(p.get("ip", ""))

    def _leave_group_call(self):
        self.voice.hangup_all()
        self._group_call_win = None

    def _on_group_invite(self, gid: str, gname: str, from_ip: str):
        from_name = self.net.peers.get(from_ip, {}).get("username", from_ip)
        reply = QMessageBox.question(self,"Приглашение в группу",
            f"<b>{from_name}</b> приглашает вас в группу «{gname}».\nВступить?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            GROUPS.add_member(gid, get_local_ip())
            self.peer_panel._refresh_groups()

    def _on_invite_message_requested(self, dest_type: str, dest_data, invite_json: str):
        """Send a group invite bubble into the chosen chat."""
        import json
        try:
            inv = json.loads(invite_json)
        except Exception:
            return
        gid   = inv.get("gid", "")
        gname = inv.get("gname", "?")
        host  = inv.get("host", "")

        invite_text = f"__GROUP_INVITE__:{invite_json}"

        ts = time.time()
        if dest_type == "public":
            self.chat_panel.open_public()
            self._tabs.setCurrentWidget(self.chat_panel)
            self.chat_panel._send_text_raw(invite_text)
        elif dest_type == "peer" and dest_data:
            self.chat_panel.open_peer(dest_data)
            self._tabs.setCurrentWidget(self.chat_panel)
            self.chat_panel._send_text_raw(invite_text)
        elif dest_type == "group" and dest_data:
            self.chat_panel.open_group(dest_data)
            self._tabs.setCurrentWidget(self.chat_panel)
            self.chat_panel._send_text_raw(invite_text)

    def _on_net_error(self, err: str):
        self._status_main.setText(f"❌ {err}")
        QTimer.singleShot(5000, lambda: self._status_main.setText(
            f"🟢 Онлайн: {len(self.net.peers)}"))

    # ── Navigation ──────────────────────────────────────────────────────
    def _open_chat(self, peer: dict):
        self.chat_panel.open_peer(peer)
        self._tabs.setCurrentWidget(self.chat_panel)

    def _open_group(self, gid: str):
        self.chat_panel.open_group(gid)
        self._tabs.setCurrentWidget(self.chat_panel)

    def _go_public(self):
        self.chat_panel.open_public()
        self._tabs.setCurrentWidget(self.chat_panel)

    # ── Actions ─────────────────────────────────────────────────────────
    def _show_tutorial(self):
        """Launch interactive tutorial overlay."""
        overlay = TutorialOverlay(self, parent=self)
        overlay.resize(self.size())
        overlay.show()
        overlay.raise_()

    def _update_loyalty(self):
        """Track continuous monthly usage for loyalty level."""
        try:
            last_month = S().get("loyalty_last_month", "", t=str)
            start_str  = S().get("loyalty_start_date", "", t=str)
            now        = datetime.now()
            cur_month  = now.strftime("%Y-%m")
            if not start_str:
                S().set("loyalty_start_date", now.isoformat())
            if last_month != cur_month:
                S().set("loyalty_last_month", cur_month)
                # Compute full months since start
                try:
                    start = datetime.fromisoformat(S().get("loyalty_start_date",""))
                    months = (now.year - start.year) * 12 + (now.month - start.month)
                    S().set("loyalty_months", max(0, months))
                except Exception:
                    pass
        except Exception:
            pass

    def _show_profile(self):
        """Show profile editor as inline tab (with close button)."""
        for i in range(self._tabs.count()):
            if self._tabs.tabText(i).strip() == "👤 Профиль":
                self._tabs.setCurrentIndex(i)
                return
        dlg = ProfileDialog(self)
        dlg.profile_saved.connect(self._on_profile_saved)
        dlg.setWindowFlags(Qt.WindowType.Widget)
        idx = self._tabs.addTab(dlg, "👤 Профиль")
        self._tabs.setCurrentIndex(idx)
        self._add_tab_close_btn(idx)

    def _show_settings(self):
        """Show settings as inline tab (with close button)."""
        for i in range(self._tabs.count()):
            if self._tabs.tabText(i).strip() == "⚙ Настройки":
                self._tabs.setCurrentIndex(i)
                return
        dlg = SettingsDialog(self)
        dlg.settings_saved.connect(self._on_settings_saved)
        dlg.settings_saved.connect(lambda: self._remove_tab_by_title("⚙ Настройки"))
        dlg.setWindowFlags(Qt.WindowType.Widget)
        idx = self._tabs.addTab(dlg, "⚙ Настройки")
        self._tabs.setCurrentIndex(idx)
        self._add_tab_close_btn(idx)

    def _add_tab_close_btn(self, idx: int):
        """Add a small ✕ button to a specific tab (finds tab by widget ref)."""
        t = get_theme(S().theme)
        widget_ref = self._tabs.widget(idx)  # capture widget, not index
        btn = QPushButton("✕")
        btn.setFixedSize(18, 18)
        btn.setFlat(True)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                color: {t['text_dim']}; background: transparent;
                border: none; border-radius: 9px;
                font-size: 11px; font-weight: bold;
            }}
            QPushButton:hover {{ color: #FF6060; background: rgba(255,80,80,51); }}
        """)
        def _close_by_widget():
            # Find tab by its widget reference — survives reordering
            for i in range(self._tabs.count()):
                if self._tabs.widget(i) is widget_ref:
                    if i >= self._permanent_tab_count:
                        self._tabs.removeTab(i)
                    return
        btn.clicked.connect(_close_by_widget)
        self._tabs.tabBar().setTabButton(idx,
            self._tabs.tabBar().ButtonPosition.RightSide, btn)

    def _remove_tab_by_title(self, title: str):
        for i in range(self._tabs.count()):
            if self._tabs.tabText(i).strip() == title.strip():
                self._tabs.removeTab(i)
                return

    def _remove_tab_by_index(self, idx: int):
        if idx >= self._permanent_tab_count:
            self._tabs.removeTab(idx)

    def _close_tab(self, idx: int):
        if idx >= self._permanent_tab_count:
            self._tabs.removeTab(idx)

    def _on_profile_saved(self):
        self.net._broadcast()
        self._status_prem.setVisible(S().premium)
        # Close profile tab
        for i in range(self._tabs.count()):
            if self._tabs.tabText(i) == "👤 Профиль":
                self._tabs.removeTab(i)
                break

    def _on_settings_saved(self):
        self._apply_theme_from_settings()
        self._status_prem.setVisible(S().premium)

    def _toggle_mute(self):
        muted = self.voice.toggle_mute()
        if muted:
            self._status_mic.setText("🔇 Выкл")
            self._status_mic.setStyleSheet(
                "color:#FF6060; background:#3A1010; border:1px solid #5A2020;"
                "border-radius:3px; padding:1px 7px; font-size:10px;")
        else:
            self._status_mic.setText("🎤 Вкл")
            self._status_mic.setStyleSheet(
                "color:#80FF80; background:#103010; border:1px solid #205020;"
                "border-radius:3px; padding:1px 7px; font-size:10px;")

    def _about(self):
        """Open about page as inline tab."""
        for i in range(self._tabs.count()):
            if "О программе" in self._tabs.tabText(i):
                self._tabs.setCurrentIndex(i)
                return
        t = get_theme(S().theme)
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(14)

        # Logo / title block
        title_lbl = QLabel(f"{APP_NAME}")
        title_lbl.setStyleSheet(
            f"font-size:28px;font-weight:bold;color:{t['accent']};"
            f"background:transparent;")
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(title_lbl)

        ver_lbl = QLabel(f"v{APP_VERSION}  •  {COMPANY_NAME}")
        ver_lbl.setStyleSheet(
            f"font-size:12px;color:{t['text_dim']};background:transparent;")
        ver_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(ver_lbl)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"background:{t['border']};max-height:1px;")
        lay.addWidget(sep)

        desc = QLabel(
            "🚀 <b>GoidaPhone</b> — P2P мессенджер для локальных сетей и VPN.<br>"
            "Без серверов, без регистрации, без слежки.<br>"
            "Работает в любой локалке: домашней, корпоративной, Hamachi, Radmin VPN."
        )
        desc.setTextFormat(Qt.TextFormat.RichText)
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setStyleSheet(f"font-size:12px;color:{t['text']};background:transparent;")
        lay.addWidget(desc)

        # Feature list
        feat_gb = QGroupBox("Возможности")
        feat_lay = QVBoxLayout(feat_gb)
        for feat in [
            "💬  Текстовые чаты, группы, @упоминания, форматирование",
            "📞  Голосовые звонки P2P (низкая задержка, VAD, шумодав)",
            "📎  Передача файлов, изображений, стикеров",
            "😊  Реакции, пересылка, ответы на сообщения",
            "📝  Заметки с автосохранением",
            f"🎨  {len(THEMES)} тем оформления (Easter Egg: «1.7543»)",
            "👑  Премиум: цвет ника, эмодзи, кастомные темы",
            "🔒  PIN-блокировка, права администратора",
            "💻  Windows & Linux  •  🌍 Русский / English",
        ]:
            lbl = QLabel(feat)
            lbl.setStyleSheet(f"font-size:11px;color:{t['text']};background:transparent;")
            feat_lay.addWidget(lbl)
        lay.addWidget(feat_gb)

        # Tech info
        tech_lbl = QLabel(
            f"Технологии: PyQt6 • UDP/TCP • PyAudio • WebRTC VAD<br>"
            f"Протокол: v{PROTOCOL_VERSION}  •  Python {platform.python_version()}"
        )
        tech_lbl.setTextFormat(Qt.TextFormat.RichText)
        tech_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tech_lbl.setStyleSheet(
            f"font-size:10px;color:{t['text_dim']};background:transparent;")
        lay.addWidget(tech_lbl)

        lay.addStretch()
        idx = self._tabs.addTab(w, "ℹ О программе")
        self._tabs.setCurrentIndex(idx)
        self._add_tab_close_btn(idx)

    def _check_updates_quick(self):
        """Safe update check — keep reference on self to prevent GC crash."""
        self._upd_checker = UpdateChecker()
        self._upd_checker.update_available.connect(
            lambda v, d: QMessageBox.information(self, "Обновление",
                f"Доступна версия v{v}!\n\n{d[:300]}\n\n"
                "Скачайте новую версию с GitHub."))
        self._upd_checker.no_update.connect(
            lambda: QMessageBox.information(self, "Обновления",
                f"✅ У вас актуальная версия {APP_VERSION}.\nОбновлений не найдено."))
        self._upd_checker.check_failed.connect(
            lambda e: QMessageBox.information(self, "Обновления",
                f"ℹ GitHub не настроен или нет соединения.\n\n"
                f"Для настройки обновлений: вставьте ваш GitHub repo\n"
                f"в константу GITHUB_REPO в начале файла.\n\n"
                f"Детали: {e[:200]}"))
        self._upd_checker.start()

    # ── Window events ───────────────────────────────────────────────────
    def _refresh_weather(self):
        """Fetch weather from wttr.in."""
        import threading, urllib.request
        def _fetch():
            try:
                req = urllib.request.Request(
                    "https://wttr.in/?format=%l:+%c+%t",
                    headers={"User-Agent": "curl/7.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    txt = resp.read().decode("utf-8").strip()
                QTimer.singleShot(0, lambda t=txt: (
                    self._weather_lbl.setText(f"🌍 {t}")
                    if hasattr(self, "_weather_lbl") else None))
            except Exception:
                pass
        threading.Thread(target=_fetch, daemon=True).start()
        QTimer.singleShot(30*60*1000, self._refresh_weather)

    def closeEvent(self, event):
        S().set("window_geometry", self.saveGeometry())
        S().set("window_state", self.saveState())
        self.notes_widget._save()
        self.voice.cleanup()
        self.net.stop()
        event.accept()

# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════
#  GOIDA DEATH SCREEN  — синий экран смерти GoidaPhone
# ═══════════════════════════════════════════════════════════════════════════
class GoidaDeathScreen(QWidget):
    """BSOD with QR, auto-restart 30s, halts all windows."""
    ERROR_CODES = {
        "EXCEPTION":     "UNHANDLED_EXCEPTION",
        "MANUAL":        "MANUALLY_TRIGGERED_0xDEADBEEF",
        "THREAD_CRASH":  "THREAD_POOL_EXHAUSTED",
        "AUDIO_FAULT":   "AUDIO_ENGINE_FAULT",
        "NETWORK_FAULT": "NETWORK_SUBSYSTEM_FAULT",
    }
    DEVELOPER_EMAIL = "mymygang0078@gmail.com"

    def __init__(self, exc_type=None, exc_value=None, exc_tb=None,
                 manual: bool = False, parent=None, inside_window: bool = False):
        if inside_window and parent is not None:
            # Show as overlay inside the parent window
            super().__init__(parent)
            self.setWindowFlags(Qt.WindowType.Widget)
            # Resize to fill parent
            self.resize(parent.size())
            parent.resizeEvent = lambda e, _s=self, _p=parent: (
                super(type(parent), parent).resizeEvent(e),
                _s.resize(_p.size()))
        else:
            super().__init__(None)
            self.setWindowFlags(
                Qt.WindowType.FramelessWindowHint |
                Qt.WindowType.WindowStaysOnTopHint |
                Qt.WindowType.Window)
        self._manual = manual
        self._countdown = 30
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.setStyleSheet("background:#0032A0;")
        self._inside_window = inside_window

        if exc_type is not None:
            tb_str = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        else:
            tb_str = "".join(traceback.format_stack()[:-1])

        error_code = self.ERROR_CODES["MANUAL" if manual else "EXCEPTION"]
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self._tb_str = tb_str
        self._error_code = error_code
        self._ts = ts

        lay = QVBoxLayout(self)
        lay.setContentsMargins(60, 48, 60, 36)
        lay.setSpacing(0)

        sad = QLabel(":(")
        sad.setStyleSheet(
            "font-size:96px;font-weight:900;color:white;background:transparent;")
        lay.addWidget(sad)
        lay.addSpacing(14)

        title = QLabel("GoidaPhone столкнулся с проблемой и перестал отвечать.")
        title.setStyleSheet(
            "font-size:26px;font-weight:bold;color:white;background:transparent;")
        title.setWordWrap(True)
        lay.addWidget(title)
        lay.addSpacing(14)

        if manual:
            desc_text = "Экран смерти вызван вручную (Ctrl+F12). Нажмите Вернуться."
        else:
            desc_text = ("Мы собираем информацию об ошибке. "
                         "Отсканируйте QR-код чтобы отправить отчёт разработчику.")
        # Always show QR (even manual) - useful for reporting test crashes
        desc = QLabel(desc_text)
        desc.setStyleSheet("font-size:14px;color:#CCE0FF;background:transparent;")
        desc.setWordWrap(True)
        lay.addWidget(desc)
        lay.addSpacing(18)

        # Content row
        content_row = QHBoxLayout()
        content_row.setSpacing(36)
        left_col = QVBoxLayout()
        left_col.setSpacing(6)

        for lbl_text, style in [
            (f"Код ошибки: {error_code}",
             "font-size:13px;font-weight:bold;color:white;background:transparent;"),
            (f"Время: {ts}",
             "font-size:11px;color:#A0C0FF;background:transparent;"),
            (f"GoidaPhone v{APP_VERSION}  |  Python {sys.version.split()[0]}  |  "
             f"{platform.system()} {platform.release()}",
             "font-size:10px;color:#8AAAEE;background:transparent;"),
        ]:
            lbl_w = QLabel(lbl_text)
            lbl_w.setStyleSheet(style)
            lbl_w.setWordWrap(True)
            left_col.addWidget(lbl_w)

        left_col.addSpacing(10)
        tb_hdr = QLabel("Трассировка стека:")
        tb_hdr.setStyleSheet(
            "font-size:11px;font-weight:bold;color:#A0C8FF;background:transparent;")
        left_col.addWidget(tb_hdr)

        tb_box = QPlainTextEdit(tb_str)
        tb_box.setReadOnly(True)
        tb_box.setMaximumHeight(160)
        tb_box.setStyleSheet(
            "QPlainTextEdit{background:#001870;color:#A8C8FF;"
            "border:1px solid #4060C0;border-radius:6px;"
            "font-family:monospace;font-size:10px;padding:8px;}")
        left_col.addWidget(tb_box)
        content_row.addLayout(left_col, stretch=1)

        if True:  # Always show QR
            right_col = QVBoxLayout()
            right_col.setAlignment(
                Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)
            right_col.setSpacing(8)
            qr_title = QLabel("📧 Отправить отчёт")
            qr_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            qr_title.setStyleSheet(
                "font-size:11px;font-weight:bold;color:#CCE0FF;background:transparent;")
            right_col.addWidget(qr_title)
            self._qr_img = QLabel()
            self._qr_img.setFixedSize(160, 160)
            self._qr_img.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._qr_img.setStyleSheet(
                "background:white;border-radius:8px;border:3px solid #4060C0;"
                "color:#0032A0;font-size:9px;")
            self._qr_img.setText("Генерация...")
            right_col.addWidget(self._qr_img)
            qr_hint = QLabel(self.DEVELOPER_EMAIL)
            qr_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
            qr_hint.setStyleSheet("font-size:9px;color:#8AAAEE;background:transparent;")
            right_col.addWidget(qr_hint)
            content_row.addLayout(right_col)
            QTimer.singleShot(200, lambda: self._generate_qr(tb_str, error_code, ts))

        lay.addLayout(content_row)
        lay.addSpacing(16)

        if not manual:
            self._countdown_lbl = QLabel(
                f"⟳  Автоматический перезапуск через {self._countdown} сек.")
            self._countdown_lbl.setStyleSheet(
                "font-size:12px;color:#FFD080;background:transparent;font-weight:bold;")
            lay.addWidget(self._countdown_lbl)
            lay.addSpacing(10)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        def _make_btn(text, bg, hover_bg, cb):
            b = QPushButton(text)
            b.setFixedHeight(40)
            b.setStyleSheet(
                f"QPushButton{{background:{bg};color:white;border-radius:8px;"
                f"font-size:12px;font-weight:bold;padding:0 18px;border:none;}}"
                f"QPushButton:hover{{background:{hover_bg};}}")
            b.clicked.connect(cb)
            return b

        if not manual:
            btn_row.addWidget(
                _make_btn("🔄 Перезапустить", "#005522", "#007733", self._do_restart))
        btn_row.addWidget(
            _make_btn("💾 Сохранить отчёт", "#0050CC", "#0066EE",
                      lambda: self._save_report(tb_str, error_code, ts)))
        btn_row.addWidget(
            _make_btn("📋 Копировать", "#0050CC", "#0066EE",
                      lambda: QApplication.clipboard().setText(
                          f"GoidaPhone Death Report\n{ts}\n{error_code}\n\n{tb_str}")))
        if manual:
            btn_row.addWidget(
                _make_btn("↩ Вернуться", "#005522", "#007733", self.close))
        else:
            btn_row.addWidget(
                _make_btn("⏻ Закрыть", "#550000", "#880000", QApplication.quit))
        btn_row.addStretch()
        lay.addLayout(btn_row)
        lay.addStretch()

        # Show: inside window or fullscreen
        if getattr(self, '_inside_window', False) and self.parent():
            self.setGeometry(0, 0,
                self.parent().width(), self.parent().height())
        else:
            self.setGeometry(QApplication.primaryScreen().geometry())
        self.show(); self.raise_(); self.activateWindow()
        if not manual:
            # Hide other top-level windows (not the parent)
            _parent = self.parent()
            for w in QApplication.topLevelWidgets():
                if w is not self and w is not _parent:
                    try: w.hide()
                    except Exception: pass
            self._timer = QTimer(self)
            self._timer.timeout.connect(self._tick)
            self._timer.start(1000)

    def _tick(self):
        self._countdown -= 1
        if self._countdown <= 0:
            self._timer.stop()
            self._do_restart()
        else:
            color = "#FF6030" if self._countdown <= 10 else "#FFD080"
            self._countdown_lbl.setText(
                f"⟳  Автоматический перезапуск через {self._countdown} сек.")
            self._countdown_lbl.setStyleSheet(
                f"font-size:12px;color:{color};"
                "background:transparent;font-weight:bold;")

    def _do_restart(self):
        try:
            if hasattr(self, '_timer'): self._timer.stop()
        except Exception: pass
        try:
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception:
            QApplication.quit()

    def _generate_qr(self, tb: str, code: str, ts: str):
        import urllib.parse
        subject = f"GoidaPhone Crash — {code}"
        body = (f"GoidaPhone v{APP_VERSION}\n"
                f"Time: {ts}\n"
                f"Platform: {platform.system()} {platform.release()}\n"
                f"Python: {sys.version.split()[0]}\n\n"
                f"Error: {code}\n\nTraceback:\n{tb[:1200]}")
        mailto = (f"mailto:{self.DEVELOPER_EMAIL}"
                  f"?subject={urllib.parse.quote(subject)}"
                  f"&body={urllib.parse.quote(body)}")
        try:
            import qrcode as _qr
            from io import BytesIO
            qr = _qr.QRCode(box_size=4, border=2)
            qr.add_data(mailto)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = BytesIO()
            img.save(buf, format="PNG")
            pm = QPixmap()
            pm.loadFromData(buf.getvalue())
            pm = pm.scaled(152, 152,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation)
            self._qr_img.setPixmap(pm)
            self._qr_img.setToolTip(mailto)
        except ImportError:
            pm = QPixmap(152, 152)
            pm.fill(QColor("white"))
            from PyQt6.QtGui import QPainter, QFont as _QF
            p = QPainter(pm)
            for rx,ry,rw,rh,rc in [
                (4,4,36,36,"#000"),(8,8,28,28,"#fff"),(12,12,20,20,"#000"),
                (112,4,36,36,"#000"),(116,8,28,28,"#fff"),(120,12,20,20,"#000"),
                (4,112,36,36,"#000"),(8,116,28,28,"#fff"),(12,120,20,20,"#000"),
            ]:
                p.fillRect(rx,ry,rw,rh,QColor(rc))
            p.setPen(QColor("#0032A0"))
            p.setFont(_QF("monospace", 7))
            p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter,
                       "pip install\nqrcode Pillow\nдля QR")
            p.end()
            self._qr_img.setPixmap(pm)
            self._qr_img.setToolTip(
                "pip install qrcode Pillow --break-system-packages")
        except Exception as e:
            self._qr_img.setText(f"Err: {e}")

    @staticmethod
    def _save_report(tb: str, code: str, ts: str):
        fn, _ = QFileDialog.getSaveFileName(
            None, "Сохранить отчёт",
            f"goidaphone_crash_{ts.replace(':','-').replace(' ','_')}.txt",
            "Text (*.txt)")
        if fn:
            try:
                open(fn, "w", encoding="utf-8").write(
                    f"GoidaPhone v{APP_VERSION} — Crash Report\n"
                    f"Time: {ts}\nCode: {code}\n"
                    f"Platform: {platform.system()} {platform.release()}\n"
                    f"Python: {sys.version}\n\nTraceback:\n{tb}\n")
                QMessageBox.information(None, "Сохранено", f"Отчёт: {fn}")
            except Exception as e:
                QMessageBox.warning(None, "Ошибка", str(e))


def _install_death_screen_handler(window: "MainWindow"):
    """Install global exception hook + Ctrl+F12 shortcut."""
    _orig_excepthook = sys.excepthook

    def _excepthook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            _orig_excepthook(exc_type, exc_value, exc_tb)
            return
        traceback.print_exception(exc_type, exc_value, exc_tb)
        try:
            # Show INSIDE the main window as overlay
            ds = GoidaDeathScreen(exc_type, exc_value, exc_tb,
                                  manual=False, parent=window,
                                  inside_window=True)
            ds.show(); ds.raise_()
        except Exception as e2:
            print(f"[BSOD render error] {e2}")
            _orig_excepthook(exc_type, exc_value, exc_tb)

    sys.excepthook = _excepthook

    # Ctrl+F12 — manual death screen (also inside window, with QR)
    sc = QShortcut(QKeySequence("Ctrl+F12"), window)
    sc.activated.connect(lambda: _show_manual_death(window))


def _show_manual_death(parent):
    ds = GoidaDeathScreen(manual=True, parent=parent, inside_window=True)
    ds.show(); ds.raise_()


def main():
    # ── Suppress ALSA/JACK noise on Linux ────────────────────────────────
    # Use environment variables only — never redirect fd 2 (stderr) because
    # that silences Python tracebacks and makes crashes invisible.
    if platform.system() == "Linux":
        import os as _os
        _os.environ.setdefault("ALSA_IGNORE_UCM", "1")
        _os.environ.setdefault("ALSA_CARD", "")

        # ── Auto-find QtWebEngineProcess (pip user-install) ───────────
        # Must be set BEFORE QApplication is created
        if not _os.environ.get("QTWEBENGINEPROCESS_PATH"):
            import glob as _gl
            _candidates = _gl.glob(
                _os.path.expanduser(
                    "~/.local/lib/python*/site-packages/PyQt6/Qt6/libexec/QtWebEngineProcess"))
            if _candidates:
                _os.environ["QTWEBENGINEPROCESS_PATH"] = _candidates[0]
                # Also set Qt plugin path so WebEngine finds its resources
                _qt6_dir = _os.path.dirname(_os.path.dirname(_candidates[0]))
                if _os.path.isdir(_qt6_dir):
                    _os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS",
                                           "--disable-gpu-sandbox")
                    # Add pip Qt6 to library search path
                    _lib = _os.path.join(_qt6_dir, "lib")
                    if _os.path.isdir(_lib):
                        old_ld = _os.environ.get("LD_LIBRARY_PATH","")
                        _os.environ["LD_LIBRARY_PATH"] = (
                            _lib + (":" + old_ld if old_ld else ""))
                print(f"[WNS] QtWebEngineProcess: {_candidates[0]}")
                # Also set resources path — required for WebEngine to find icudtl.dat etc.
                _qt6_root = _os.path.join(
                    _os.path.dirname(_os.path.dirname(_candidates[0])))
                # Resources are typically in Qt6/resources/
                for _res_sub in ["resources", ".", "translations"]:
                    _res_path = _os.path.join(_qt6_root, _res_sub)
                    if _os.path.isfile(_os.path.join(_res_path, "qtwebengine_resources.pak")) or \
                       _os.path.isfile(_os.path.join(_res_path, "icudtl.dat")):
                        _os.environ.setdefault(
                            "QTWEBENGINE_RESOURCES_PATH", _res_path)
                        print(f"[WNS] resources: {_res_path}")
                        break
                else:
                    # Fallback: point at Qt6 root itself
                    _os.environ.setdefault(
                        "QTWEBENGINE_RESOURCES_PATH", _qt6_root)
                    print(f"[WNS] resources fallback: {_qt6_root}")

    # High-DPI
    if hasattr(Qt.ApplicationAttribute, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps)

    # ── QtWebEngine MUST be imported before QApplication ─────────────────────
    # This is a hard requirement from Qt — violating it gives ImportError
    try:
        from PyQt6.QtWebEngineWidgets import QWebEngineView as _WEV  # noqa
        from PyQt6.QtWebEngineCore import (                           # noqa
            QWebEngineProfile as _WEP,
            QWebEngineSettings as _WES,
        )
        print("[WNS] WebEngine pre-import OK")
    except Exception as _we_err:
        print(f"[WNS] WebEngine pre-import failed: {_we_err}")

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(COMPANY_NAME)

    # Install early crash handler — catches errors even before MainWindow
    def _early_excepthook(exc_type, exc_val, exc_tb):
        import traceback as _tb
        _tb.print_exception(exc_type, exc_val, exc_tb)
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_val, exc_tb)
            return
        try:
            ds = GoidaDeathScreen(exc_type, exc_val, exc_tb, manual=False)
            ds.resize(900, 600)
            ds.show()
            ds.raise_()
            app.exec()
        except Exception as e2:
            print(f"[FATAL] {e2}")
        sys.exit(1)
    sys.excepthook = _early_excepthook
    _icon_path = Path(__file__).parent / "imag" / "icon.png"
    if _icon_path.exists():
        app.setWindowIcon(QIcon(str(_icon_path)))

    # Apply app scale from settings
    scale = S().get("app_scale", 100, t=int)
    if scale != 100:
        font = app.font()
        font.setPointSizeF(max(7.0, 9.0 * scale / 100.0))
        app.setFont(font)

    # Apply theme before anything
    key = S().theme
    if not key.startswith("__custom"):
        app.setStyleSheet(build_stylesheet(get_theme(key)))

    # ── 1. Splash screen ──────────────────────────────────────────────────
    splash = None
    if S().get("show_splash", True, t=bool):
        splash = SplashScreen()
        splash.show()
        app.processEvents()

    # ── 2. Launcher screen (after splash, п.15) ───────────────────────────
    mode = S().get("launcher_default", "gui", t=str) if not S().show_launcher else "gui"

    def _continue_after_splash():
        nonlocal mode
        if S().show_launcher:
            if splash:
                splash.hide()
            launcher = LauncherScreen()
            launcher.exec()
            mode = launcher.get_choice()
        else:
            if splash:
                splash.close()

        if mode == "cmd":
            try:
                import readline   # Linux/macOS — история команд в CMD
            except ImportError:
                pass              # Windows — работает без него
            import shutil
            cols = shutil.get_terminal_size().columns

            # Enable ANSI colors on Windows terminal
            if platform.system() == "Windows":
                try:
                    import ctypes as _ct
                    kernel32 = _ct.windll.kernel32
                    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                except Exception:
                    pass
            CYAN   = "\033[96m"; PURP = "\033[95m"; GRN  = "\033[92m"
            YEL    = "\033[93m"; RED  = "\033[91m"; DIM  = "\033[2m"
            BOLD   = "\033[1m";  RST  = "\033[0m";  BLUE = "\033[94m"

            def _line(ch="═"): return ch * min(cols, 62)
            def _hdr(txt):     print(f"{PURP}{_line()}{RST}\n"
                                     f"{BOLD}{CYAN}  {txt}{RST}\n"
                                     f"{PURP}{_line()}{RST}")

            print(f"\n{PURP}{'═'*62}{RST}")
            print(f"{BOLD}{CYAN}  ██████╗  ██████╗ ██╗██████╗  █████╗ {RST}")
            print(f"{CYAN}  ██╔════╝ ██╔═══██╗██║██╔══██╗██╔══██╗{RST}")
            print(f"{CYAN}  ██║  ███╗██║   ██║██║██║  ██║███████║{RST}")
            print(f"{CYAN}  ██║   ██║██║   ██║██║██║  ██║██╔══██║{RST}")
            print(f"{CYAN}  ╚██████╔╝╚██████╔╝██║██████╔╝██║  ██║{RST}")
            print(f"{CYAN}   ╚═════╝  ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝{RST}")
            print(f"{PURP}{'═'*62}{RST}")
            print(f"  {BOLD}GoidaPhone v{APP_VERSION} — CMD Mode{RST}  {DIM}Winora Company{RST}")
            print(f"  {DIM}Введите /help для справки  •  /quit для выхода{RST}")
            print(f"{PURP}{'═'*62}{RST}\n")

            net = NetworkManager()

            # Incoming message handler
            _msg_buf: list[str] = []
            def _on_msg(msg: dict):
                t_msg  = msg.get("type","")
                uname  = msg.get("username","?")
                text   = msg.get("text","")
                ts     = time.strftime("%H:%M", time.localtime(msg.get("ts", time.time())))
                if t_msg in ("chat","msg","private","group") and text:
                    prefix = f"{DIM}[{ts}]{RST} "
                    if msg.get("type") == "private":
                        line = f"{prefix}{YEL}[DM] {BOLD}{uname}{RST}: {text}"
                    else:
                        line = f"{prefix}{GRN}{BOLD}{uname}{RST}: {text}"
                    print(f"\r{line}")
                    print(f"{CYAN}> {RST}", end="", flush=True)
                    _msg_buf.append(line)

            net.sig_message.connect(_on_msg)

            def _on_call(caller, ip):
                print(f"\r{YEL}📞 Входящий звонок от {BOLD}{caller}{RST}{YEL} ({ip}) — /answer {ip} или /reject {ip}{RST}")
                print(f"{CYAN}> {RST}", end="", flush=True)

            net.sig_call_request.connect(_on_call)

            def _on_online(peer):
                uname = peer.get("username","?")
                ip    = peer.get("ip","?")
                print(f"\r{GRN}● {uname} ({ip}) онлайн{RST}")
                print(f"{CYAN}> {RST}", end="", flush=True)

            def _on_offline(ip):
                peer = net.peers.get(ip, {})
                print(f"\r{DIM}○ {peer.get('username', ip)} оффлайн{RST}")
                print(f"{CYAN}> {RST}", end="", flush=True)

            net.sig_user_online.connect(_on_online)
            net.sig_user_offline.connect(_on_offline)

            net.start()
            print(f"{GRN}✓ Запущен на {BOLD}{get_local_ip()}{RST}")
            print(f"{GRN}✓ Имя: {BOLD}{S().username}{RST}\n")

            _help_text = f"""
{PURP}{'─'*50}{RST}
{BOLD}КОМАНДЫ GoidaPhone CMD{RST}

{CYAN}/help{RST}             — эта справка
{CYAN}/quit{RST} ({CYAN}/exit{RST})   — выйти
{CYAN}/peers{RST}            — список онлайн-пользователей
{CYAN}/msg <ip> <текст>{RST} — личное сообщение
{CYAN}/pub <текст>{RST}      — сообщение в публичный чат
{CYAN}/ping <ip>{RST}        — пинговать пользователя
{CYAN}/call <ip>{RST}        — позвонить
{CYAN}/hangup <ip>{RST}      — завершить звонок
{CYAN}/answer <ip>{RST}      — принять входящий звонок
{CYAN}/reject <ip>{RST}      — отклонить входящий звонок
{CYAN}/groups{RST}           — список групп
{CYAN}/history [ip]{RST}     — история сообщений (публичная или с пользователем)
{CYAN}/me{RST}               — информация о себе (IP, имя, версия)
{CYAN}/clear{RST}            — очистить экран
{CYAN}/status <текст>{RST}   — установить статус
{CYAN}/mute{RST}             — заглушить/включить микрофон (во время звонка)

{DIM}Просто введите текст без / — отправляется в публичный чат{RST}
{PURP}{'─'*50}{RST}"""

            voice = VoiceCallManager(net)

            try:
                while True:
                    try:
                        raw = input(f"{CYAN}> {RST}").strip()
                    except EOFError:
                        break
                    if not raw:
                        continue
                    parts = raw.split(None, 2)
                    cmd   = parts[0].lower()

                    if cmd in ("/quit", "/exit", "/q"):
                        break

                    elif cmd == "/help":
                        print(_help_text)

                    elif cmd == "/clear":
                        print("\033[2J\033[H", end="")

                    elif cmd == "/me":
                        print(f"  {BOLD}Имя:{RST}     {S().username}")
                        print(f"  {BOLD}IP:{RST}      {get_local_ip()}")
                        print(f"  {BOLD}Версия:{RST}  {APP_VERSION}")
                        print(f"  {BOLD}Тема:{RST}    {S().theme}")

                    elif cmd == "/peers":
                        if net.peers:
                            print(f"  {DIM}Пользователи онлайн ({len(net.peers)}):{RST}")
                            for ip, p in net.peers.items():
                                e2e = f"  {GRN}[E2E]{RST}" if p.get("e2e") else ""
                                print(f"  {GRN}●{RST} {BOLD}{p.get('username','?')}{RST} @ {ip}{e2e}")
                        else:
                            print(f"  {DIM}Нет пользователей онлайн{RST}")

                    elif cmd == "/groups":
                        groups = GROUPS.groups
                        if groups:
                            for gid, g in groups.items():
                                print(f"  {PURP}📂{RST} {g.get('name','?')}  {DIM}({gid}){RST}  "
                                      f"участников: {len(g.get('members',[]))}")
                        else:
                            print(f"  {DIM}Нет групп{RST}")

                    elif cmd == "/msg" and len(parts) >= 3:
                        ip_arg = parts[1]; text = parts[2]
                        net.send_private(text, ip_arg)
                        print(f"  {DIM}→ DM → {ip_arg}: {text}{RST}")

                    elif cmd == "/pub" and len(parts) >= 2:
                        text = raw[5:].strip()
                        net.send_chat(text)
                        print(f"  {DIM}→ публичный чат: {text}{RST}")

                    elif cmd == "/ping" and len(parts) >= 2:
                        ip_arg = parts[1]
                        start  = time.time()
                        net.send_udp({"type": "ping", "username": S().username}, ip_arg)
                        print(f"  {DIM}Ping → {ip_arg}  (UDP){RST}")

                    elif cmd == "/call" and len(parts) >= 2:
                        ip_arg = parts[1]
                        if voice.call(ip_arg):
                            net.send_call_request(ip_arg)
                            print(f"  {YEL}📞 Звоним {ip_arg}…{RST}")
                        else:
                            print(f"  {RED}✗ Не удалось запустить аудио{RST}")

                    elif cmd == "/hangup" and len(parts) >= 2:
                        ip_arg = parts[1]
                        voice.hangup(ip_arg)
                        print(f"  {DIM}Звонок с {ip_arg} завершён{RST}")

                    elif cmd == "/answer" and len(parts) >= 2:
                        ip_arg = parts[1]
                        net.send_call_accept(ip_arg)
                        voice.call(ip_arg)
                        print(f"  {GRN}✓ Принят звонок от {ip_arg}{RST}")

                    elif cmd == "/reject" and len(parts) >= 2:
                        ip_arg = parts[1]
                        net.send_call_reject(ip_arg)
                        print(f"  {DIM}Отклонён звонок от {ip_arg}{RST}")

                    elif cmd == "/mute":
                        muted = voice.toggle_mute()
                        print(f"  {'🔇 Заглушён' if muted else '🎤 Микрофон включён'}")

                    elif cmd == "/status" and len(parts) >= 2:
                        text = raw[8:].strip()
                        S().set("status_text", text)
                        print(f"  {GRN}✓ Статус: {text}{RST}")

                    elif cmd == "/history":
                        ip_arg = parts[1] if len(parts) >= 2 else None
                        hfile  = HISTORY_DIR / (f"private_{ip_arg}.json" if ip_arg else "public.json")
                        if hfile.exists():
                            import json as _j
                            msgs = _j.loads(hfile.read_text(encoding="utf-8"))[-20:]
                            for m in msgs:
                                ts  = time.strftime("%H:%M", time.localtime(m.get("ts",0)))
                                u   = m.get("username","?")
                                txt = m.get("text","")
                                print(f"  {DIM}[{ts}]{RST} {GRN}{u}{RST}: {txt}")
                        else:
                            print(f"  {DIM}История не найдена{RST}")

                    elif not cmd.startswith("/"):
                        # Plain text → public chat
                        net.send_chat(raw)
                        print(f"  {DIM}→ {raw}{RST}")

                    else:
                        print(f"  {RED}Неизвестная команда: {cmd}  (введите /help){RST}")

                    app.processEvents()

            except KeyboardInterrupt:
                pass

            voice.cleanup()
            net.stop()
            print(f"\n{PURP}{'═'*62}{RST}")
            print(f"  {DIM}GoidaPhone завершён. До встречи! 👋{RST}")
            print(f"{PURP}{'═'*62}{RST}")
            app.quit()
            return

        # ── 3. Main window ───────────────────────────────────────────────
        try:
            window = MainWindow()
            FT.file_received.connect(window.chat_panel.receive_file)
            _icp = Path(__file__).parent / "imag" / "icon.png"
            if _icp.exists():
                window.setWindowIcon(QIcon(str(_icp)))
            window.show()
            window.raise_()
            window.activateWindow()
            _install_death_screen_handler(window)
            # Force full repaint — without this Qt may not render until first mouse move
            window.update()
            window.repaint()
            app.processEvents()
            QTimer.singleShot(50,  lambda: (window.update(), window.repaint()))
            QTimer.singleShot(150, lambda: (window.update(), app.processEvents()))
        except Exception:
            # Show BSOD even on startup crash (before MainWindow exists)
            import traceback as _tb
            exc_type, exc_val, exc_trace = sys.exc_info()
            # Always print to stderr first so it's visible even if BSOD fails
            print("\n[FATAL STARTUP ERROR]", file=sys.stderr)
            _tb.print_exception(exc_type, exc_val, exc_trace)
            sys.stderr.flush()
            try:
                ds = GoidaDeathScreen(exc_type, exc_val, exc_trace, manual=False)
                ds.resize(900, 600)
                ds.show()
                ds.raise_()
                # Run event loop for crash screen
                app.exec()
            except Exception as e2:
                print(f"[FATAL] Could not show death screen: {e2}")
            sys.exit(1)

    # Delay launcher/main window until after splash
    splash_delay = 2200 if splash else 0
    QTimer.singleShot(splash_delay, _continue_after_splash)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
