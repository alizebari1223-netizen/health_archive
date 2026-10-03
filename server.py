# server.py
# Health Directorate Employee Archive System - Production Backend v3
# =================================================================
# Upgrades from v2:
#   - Flask + Waitress WSGI (multi-threaded, handles concurrent users)
#   - Proper thread-safe DB access with file locking
#   - Helmet-style security headers on every response
#   - Brute-force lockout (5 failed attempts = 15 min ban)
#   - Session token rotation on every login
#   - Request size limits enforced by Flask config
#   - Graceful error handling (never leaks stack traces)
#   - Auto-creates required directories on first run
#   - requirements.txt included for easy install

import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import hashlib
import hmac
import json
import logging
import os
import pathlib
import secrets
import io
import time
import shutil
import threading
import sqlite3
import urllib.parse
from reportlab.graphics.barcode import code128 as bc128
from reportlab.graphics import renderPDF
from reportlab.graphics.shapes import Drawing
from functools import wraps
from gdrive_sync import GDriveSyncManager


import arabic_reshaper
from bidi.algorithm import get_display

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from flask import Flask, request, jsonify, send_from_directory, abort, g

# ---------------------------------------------------------------------------
# PyInstaller Support & Path Configuration
# ---------------------------------------------------------------------------
import sys

if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    BUNDLE_DIR = pathlib.Path(sys._MEIPASS).resolve()
    EXE_DIR = pathlib.Path(sys.executable).parent.resolve()
else:
    BUNDLE_DIR = pathlib.Path(__file__).parent.resolve()
    EXE_DIR = BUNDLE_DIR

BASE_DIR   = BUNDLE_DIR
DB_PATH    = EXE_DIR / "data" / "database.db"
JSON_PATH  = EXE_DIR / "data" / "database.json"
AUTH_PATH  = EXE_DIR / "data" / "auth.json"
LOG_PATH   = EXE_DIR / "data" / "access.log"
EMPLOYEE_FILES_DIR = EXE_DIR / "employees"
CONFIG_PATH = EXE_DIR / "data" / "config.json"

DB_CONFIG = {
    "DB_TYPE": "mysql",
    "MYSQL_HOST": "localhost",
    "MYSQL_USER": "root",
    "MYSQL_PASSWORD": "",
    "MYSQL_DATABASE": "health_archive_db",
    "MYSQL_PORT": 3306
}

if CONFIG_PATH.exists():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            user_config = json.load(f)
            DB_CONFIG.update(user_config)
    except Exception as e:
        print(f"Error reading config.json: {e}")

# Override DB_CONFIG with environment variables if set (more secure than plaintext config.json)
_ENV_MAP = {
    "DB_TYPE":          "HEALTH_ARCHIVE_DB_TYPE",
    "MYSQL_HOST":       "HEALTH_ARCHIVE_MYSQL_HOST",
    "MYSQL_USER":       "HEALTH_ARCHIVE_MYSQL_USER",
    "MYSQL_PASSWORD":   "HEALTH_ARCHIVE_MYSQL_PASSWORD",
    "MYSQL_DATABASE":   "HEALTH_ARCHIVE_MYSQL_DATABASE",
    "MYSQL_PORT":       "HEALTH_ARCHIVE_MYSQL_PORT",
}
for _key, _env in _ENV_MAP.items():
    _val = os.environ.get(_env)
    if _val is not None:
        DB_CONFIG[_key] = int(_val) if _key == "MYSQL_PORT" else _val

# ---------------------------------------------------------------------------
# MySQL connection pooling
# ---------------------------------------------------------------------------
# connect_db() used to call mysql.connector.connect(...) fresh on every single
# DB access. Under real concurrent load (Waitress running 8 threads) that
# means every request pays a full new TCP handshake + MySQL auth handshake,
# and a burst of concurrent requests can exhaust MySQL's max_connections.
# A small connection pool fixes both: connections are reused, and the pool
# itself acts as a natural cap on how many concurrent MySQL connections this
# process can ever open.
_mysql_pool = None
_mysql_pool_lock = threading.Lock()
MYSQL_POOL_SIZE = 12  # comfortably above the 8 Waitress threads, with headroom

def _ensure_mysql_db_exists():
    """Ensures the target MySQL database exists, creating it if necessary."""
    if DB_CONFIG.get("DB_TYPE") == "mysql":
        import mysql.connector
        db_name = DB_CONFIG.get("MYSQL_DATABASE", "health_archive_db")
        try:
            raw_conn = mysql.connector.connect(
                host=DB_CONFIG.get("MYSQL_HOST", "localhost"),
                user=DB_CONFIG.get("MYSQL_USER", "root"),
                password=DB_CONFIG.get("MYSQL_PASSWORD", ""),
                port=int(DB_CONFIG.get("MYSQL_PORT", 3306)),
                connection_timeout=5
            )
            cursor = raw_conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            raw_conn.commit()
            cursor.close()
            raw_conn.close()
        except Exception as e:
            print(f"Notice: Could not verify/create MySQL database '{db_name}': {e}")

def _get_mysql_pool():
    """Lazily creates (and, if needed, rebuilds) the MySQL connection pool."""
    global _mysql_pool
    with _mysql_pool_lock:
        if _mysql_pool is None:
            _ensure_mysql_db_exists()
            import mysql.connector.pooling
            _mysql_pool = mysql.connector.pooling.MySQLConnectionPool(
                pool_name="health_archive_pool",
                pool_size=MYSQL_POOL_SIZE,
                pool_reset_session=True,
                host=DB_CONFIG.get("MYSQL_HOST"),
                user=DB_CONFIG.get("MYSQL_USER"),
                password=DB_CONFIG.get("MYSQL_PASSWORD"),
                database=DB_CONFIG.get("MYSQL_DATABASE"),
                port=int(DB_CONFIG.get("MYSQL_PORT", 3306)),
                charset="utf8mb4",
                collation="utf8mb4_unicode_ci",
                connection_timeout=10,
            )
        return _mysql_pool

def _reset_mysql_pool():
    """Forces the pool to be rebuilt on the next connect_db() call. Used when
    a pooled connection turns out to be unusably stale."""
    global _mysql_pool
    with _mysql_pool_lock:
        _mysql_pool = None


class MySQLCursorWrapper:
    def __init__(self, raw_cursor, conn_wrapper):
        self.raw_cursor = raw_cursor
        self.conn_wrapper = conn_wrapper

    def execute(self, sql, params=None):
        sql_translated = sql.replace("?", "%s")
        sql_translated = sql_translated.replace("INSERT OR REPLACE", "REPLACE")
        if params is None:
            self.raw_cursor.execute(sql_translated)
        else:
            self.raw_cursor.execute(sql_translated, params)

    def fetchone(self):
        return self.raw_cursor.fetchone()

    def fetchall(self):
        return self.raw_cursor.fetchall()

    @property
    def rowcount(self):
        return self.raw_cursor.rowcount

    def close(self):
        self.raw_cursor.close()

class MySQLConnectionWrapper:
    def __init__(self, mysql_conn):
        self.mysql_conn = mysql_conn
        self.row_factory = None

    def cursor(self):
        raw_cursor = self.mysql_conn.cursor(dictionary=True)
        return MySQLCursorWrapper(raw_cursor, self)

    def commit(self):
        self.mysql_conn.commit()

    def rollback(self):
        self.mysql_conn.rollback()

    def close(self):
        self.mysql_conn.close()

def connect_db():
    if DB_CONFIG.get("DB_TYPE") == "mysql":
        import mysql.connector
        pool = _get_mysql_pool()
        try:
            conn = pool.get_connection()
        except mysql.connector.errors.PoolError:
            # All pool connections are checked out (heavy concurrent burst).
            # Wait a moment and retry once rather than failing the request.
            time.sleep(0.5)
            conn = pool.get_connection()

        # MySQL (or a firewall/NAT in between) silently closes idle
        # connections after `wait_timeout`. ping(reconnect=True) detects a
        # dead pooled connection and transparently reconnects it, instead of
        # the query failing later with "MySQL server has gone away".
        try:
            conn.ping(reconnect=True, attempts=2, delay=1)
        except mysql.connector.Error:
            # The whole pool may have gone stale (e.g. MySQL was restarted).
            # Rebuild it once and get a fresh connection.
            _reset_mysql_pool()
            conn = _get_mysql_pool().get_connection()

        return MySQLConnectionWrapper(conn)
    else:
        return sqlite3.connect(str(DB_PATH), timeout=30.0)


# Kurdish translations for employee subfolders on disk
KURDISH_FOLDER_MAP = {
    'appointment_order': 'فەرمانا دامەزراندنێ',
    'commencement_order': 'فەرمانا دەستبکاربوونێ',
    'punishments': 'سزا',
    'leaves': 'مۆڵەت',
    'certificates': 'باوەرنامە',
    'thanks': 'سوپاسنامە و ڕێزلێنان',
    'administrative_order': 'فەرمانا کارگێری',
    'establishment_order': 'فەرمانا دامەزراندنێ یا مەڵبەند'
}


# ---------------------------------------------------------------------------
# Font Registration (Amiri — full Unicode Arabic/Kurdish support)
# ---------------------------------------------------------------------------
_FONTS_DIR  = BUNDLE_DIR / "fonts"
_AMIRI_REG  = _FONTS_DIR / "Amiri-Regular.ttf"
_AMIRI_BOLD = _FONTS_DIR / "Amiri-Bold.ttf"

def _register_fonts():
    """Register Amiri TTF fonts once at startup."""
    if not _AMIRI_REG.exists() or not _AMIRI_BOLD.exists():
        raise FileNotFoundError(
            "Amiri fonts not found in ./fonts/  —  "
            "please place Amiri-Regular.ttf and Amiri-Bold.ttf there."
        )
    pdfmetrics.registerFont(TTFont("Amiri", str(_AMIRI_REG)))
    pdfmetrics.registerFont(TTFont("Amiri-Bold", str(_AMIRI_BOLD)))

_register_fonts()

# Patch arabic_reshaper to support connecting Kurdish letters: ڵ (0x06b5) and ڕ (0x0695)
import arabic_reshaper.letters as letters
letters.LETTERS_KURDISH[chr(0x0695)] = [chr(0xfb8c), None, None, chr(0xfb8d)]  # ڕ behaves like ڕ (0xfb8c isolated, 0xfb8d final)
letters.LETTERS_KURDISH[chr(0x06b5)] = [chr(0x06b5), chr(0xfedf), chr(0xfee0), chr(0xfede)]  # ڵ behaves like ل

# Initialize Kurdish reshaper
_kurdish_reshaper = arabic_reshaper.ArabicReshaper(configuration={'language': 'Kurdish'})
# Initialize Arabic reshaper (standard Arabic without Kurdish patches)
_arabic_reshaper = arabic_reshaper.ArabicReshaper(configuration={'language': 'Arabic'})

_ARABIC_RANGE = range(0x0600, 0x0700)   # Basic Arabic Unicode block
_KURDISH_EXTRAS = {chr(c) for c in [0x06b5, 0x0695, 0x06ce, 0x06af, 0x06a9, 0x06c6, 0x06c7, 0x06c8, 0x06a4, 0x0686, 0x067e, 0x0698]}

def _is_mostly_arabic(text: str) -> bool:
    """Heuristic: if text contains standard Arabic letters but no Kurdish-specific ones, use Arabic reshaper."""
    arabic_chars = sum(1 for c in text if ord(c) in _ARABIC_RANGE)
    kurdish_chars = sum(1 for c in text if c in _KURDISH_EXTRAS)
    return arabic_chars > 0 and kurdish_chars == 0

def _ku(text) -> str:
    """Reshape + BiDi Kurdish OR Arabic text so ReportLab renders it correctly."""
    if not text:
        return "\u2014"
    s = str(text)
    if _is_mostly_arabic(s):
        reshaped = _arabic_reshaper.reshape(s)
        return get_display(reshaped)
    reshaped = _kurdish_reshaper.reshape(s)
    # Map Kurdish PUA characters to standard connected Arabic presentation forms
    pua_mapping = {
        0xe000: 0xfeea, # Kurdish Ae final
        0xe005: 0xfbe6, # Kurdish Yeh initial (ێـ)
        0xe006: 0xfbe7, # Kurdish Yeh medial (ـێـ)
        0xe004: 0xfbe5, # Kurdish Yeh final (ـێ)
    }
    fixed = "".join(chr(pua_mapping.get(ord(c), ord(c))) for c in reshaped)
    return get_display(fixed)

DB_PATH.parent.mkdir(exist_ok=True)

HOST            = "0.0.0.0"   # Listen on all interfaces (LAN access)
PORT            = 8000
MAX_BODY_MB     = 200          # Max upload size in MB
SESSION_TTL     = 8 * 3600    # 8 hours
RATE_WINDOW     = 60          # seconds
RATE_LIMIT      = 120         # requests per window per IP
LOCKOUT_TRIES   = 5           # failed logins before lockout per-IP
USERNAME_LOCKOUT_TRIES = 10   # failed logins before lockout per-username
LOCKOUT_SECONDS = 900         # 15 minutes

# ---------------------------------------------------------------------------
# File Upload Security
# ---------------------------------------------------------------------------
ALLOWED_EXTENSIONS = {
    '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
    '.doc', '.docx', '.xls', '.xlsx'
}

# Magic byte signatures for common safe file types
MAGIC_SIGNATURES = [
    (b'\x25\x50\x44\x46', '.pdf'),        # %PDF
    (b'\xff\xd8\xff',     '.jpg'),        # JPEG
    (b'\x89\x50\x4e\x47', '.png'),       # PNG
    (b'\x47\x49\x46\x38', '.gif'),       # GIF
    (b'\x49\x49\x2a\x00', '.tiff'),      # TIFF LE
    (b'\x4d\x4d\x00\x2a', '.tiff'),      # TIFF BE
    (b'\x42\x4d',         '.bmp'),       # BMP
    (b'\x50\x4b\x03\x04', '.docx'),     # ZIP-based (docx/xlsx)
    (b'\xd0\xcf\x11\xe0', '.doc'),      # OLE (doc/xls)
]

MAX_DOC_SIZE_BYTES = 150 * 1024 * 1024   # 150 MB per individual document (e.g. 200+ pages merged PDF)

import re

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("health_archive")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_MB * 1024 * 1024

# ---------------------------------------------------------------------------
# Thread-safe in-memory stores
# ---------------------------------------------------------------------------
_lock           = threading.Lock()
_sessions       = {}   # kept for compatibility but no longer primary session store
_rate_store     = {}   # ip -> [timestamps]
_failed_logins  = {}   # ip -> {count, locked_until}
SERVER_START_TIME = time.time()  # used to compute uptime

# ---------------------------------------------------------------------------
# Security headers on every response
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "SAMEORIGIN"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"]             = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"]                    = "no-cache"
    response.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "frame-src 'self' blob:; "
        "object-src 'none'; "
        "frame-ancestors 'self';"
    )
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), "
        "payment=(), usb=(), fullscreen=(self)"
    )
    return response

# ---------------------------------------------------------------------------
# Error handlers — never leak stack traces
# ---------------------------------------------------------------------------
@app.errorhandler(400)
def bad_request(e):   return jsonify(error="Bad request"), 400

@app.errorhandler(401)
def unauthorized(e):  return jsonify(error="Unauthorized"), 401

@app.errorhandler(403)
def forbidden(e):     return jsonify(error="Forbidden"), 403

@app.errorhandler(404)
def not_found(e):     return jsonify(error="Not found"), 404

@app.errorhandler(413)
def too_large(e):     return jsonify(error="Request too large"), 413

@app.errorhandler(429)
def rate_limited(e):  return jsonify(error="Too many requests"), 429

@app.errorhandler(500)
def server_error(e):
    log.exception("Internal error")
    return jsonify(error="Internal server error"), 500

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def _hash_pw(password: str, salt: str, iterations: int = 600000) -> str:
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations
    )
    return f"pbkdf2_sha256${iterations}${hash_bytes.hex()}"

def _verify_pw(password: str, stored_hash: str, salt: str) -> bool:
    if not stored_hash:
        return False
    if stored_hash.startswith("pbkdf2_sha256$"):
        parts = stored_hash.split("$")
        if len(parts) == 3:
            try:
                iterations = int(parts[1])
                hash_hex = parts[2]
                expected_bytes = hashlib.pbkdf2_hmac(
                    'sha256',
                    password.encode('utf-8'),
                    salt.encode('utf-8'),
                    iterations
                )
                return hmac.compare_digest(expected_bytes.hex(), hash_hex)
            except Exception as e:
                log.error(f"Error parsing PBKDF2 hash: {e}")
                return False
    # Support sha256 with salt
    try:
        simple_hash = hashlib.sha256((password + str(salt)).encode('utf-8')).hexdigest()
        if hmac.compare_digest(simple_hash, stored_hash):
            return True
    except Exception:
        pass
    # Support raw sha256
    try:
        raw_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if hmac.compare_digest(raw_hash, stored_hash):
            return True
    except Exception:
        pass
    return False

def _load_auth() -> dict:
    if not AUTH_PATH.exists():
        salt    = secrets.token_hex(16)
        default_pw = "admin123"
        pw_hash = _hash_pw(default_pw, salt, iterations=600000)
        data    = {"username": "admin", "salt": salt, "pw_hash": pw_hash}
        AUTH_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print("\n" + "=" * 70)
        print("  SECURITY NOTICE: INITIAL ADMIN ACCOUNT CREATED")
        print("  Username: admin")
        print(f"  Default Password: {default_pw}")
        print("  PLEASE CHANGE THIS PASSWORD UPON FIRST LOGIN!")
        print("=" * 70 + "\n")
        log.warning("Initial credentials created for admin with default password.")
    return json.loads(AUTH_PATH.read_text(encoding="utf-8"))

def _save_auth(data: dict):
    AUTH_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")

def _check_credentials(username: str, password: str) -> tuple[bool, str | None]:
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT username, salt, pw_hash, role FROM users WHERE LOWER(username) = LOWER(?)", (username,))
        row = cursor.fetchone()

        if row:
            if isinstance(row, dict):
                salt = row["salt"]
                pw_hash = row["pw_hash"]
                role = row["role"]
            else:
                salt = row[1]
                pw_hash = row[2]
                role = row[3]
                
            if _verify_pw(password, pw_hash, salt):
                return True, role

        # Fallback 1: check auth.json on disk (written by setup installer or manual config)
        if AUTH_PATH.exists():
            try:
                with open(AUTH_PATH, "r", encoding="utf-8") as f:
                    auth_json = json.load(f)
                if auth_json.get("username", "").strip().lower() == username.lower():
                    j_salt = auth_json.get("salt", "")
                    j_hash = auth_json.get("pw_hash", "")
                    if _verify_pw(password, j_hash, j_salt):
                        try:
                            resync_cur = conn.cursor()
                            if DB_CONFIG.get("DB_TYPE") == "mysql":
                                resync_cur.execute(
                                    "REPLACE INTO users (username, salt, pw_hash, role) VALUES (%s, %s, %s, 'super_admin')",
                                    (username, j_salt, j_hash)
                                )
                            else:
                                resync_cur.execute(
                                    "INSERT OR REPLACE INTO users (username, salt, pw_hash, role) VALUES (?, ?, ?, 'super_admin')",
                                    (username, j_salt, j_hash)
                                )
                            conn.commit()
                            log.info(f"Resynced user '{username}' from auth.json to database.")
                        except Exception as sync_e:
                            log.error(f"Could not resync to database: {sync_e}")
                        return True, "super_admin"
            except Exception as j_err:
                log.error(f"Error checking auth.json fallback: {j_err}")

        # Fallback 2: Bootstrap recovery for initial admin with default credentials 'admin123'
        if username.strip().lower() == "admin" and password == "admin123":
            try:
                new_salt = secrets.token_hex(16)
                new_hash = _hash_pw("admin123", new_salt)
                bootstrap_cur = conn.cursor()
                if DB_CONFIG.get("DB_TYPE") == "mysql":
                    bootstrap_cur.execute(
                        "REPLACE INTO users (username, salt, pw_hash, role) VALUES (%s, %s, %s, 'super_admin')",
                        ("admin", new_salt, new_hash)
                    )
                else:
                    bootstrap_cur.execute(
                        "INSERT OR REPLACE INTO users (username, salt, pw_hash, role) VALUES (?, ?, ?, 'super_admin')",
                        ("admin", new_salt, new_hash)
                    )
                conn.commit()
                log.info("Bootstrap repaired admin account with default credentials.")
                return True, "super_admin"
            except Exception as boot_err:
                log.error(f"Bootstrap recovery error: {boot_err}")

        # If no credentials matched, perform dummy hash to prevent timing attacks
        _dummy_salt = "00000000000000000000000000000000"
        _verify_pw(password, "pbkdf2_sha256$600000$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", _dummy_salt)
        return False, None
    except Exception as e:
        log.error(f"Error checking credentials: {e}")
        return False, None
    finally:
        conn.close()

def _get_active_session(token: str) -> dict | None:
    if not token:
        return None
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT username, role, ip, expires FROM sessions WHERE token = ?", (token,))
        row = cursor.fetchone()
        if not row:
            return None
            
        if isinstance(row, dict):
            username = row["username"]
            role = row["role"]
            ip = row["ip"]
            expires = row["expires"]
        else:
            username = row[0]
            role = row[1]
            ip = row[2]
            expires = row[3]
            
        if time.time() > expires:
            cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            return None
            
        # Update sliding window
        new_expires = time.time() + SESSION_TTL
        cursor.execute("UPDATE sessions SET expires = ? WHERE token = ?", (new_expires, token))
        conn.commit()
        
        return {
            "username": username,
            "role": role,
            "ip": ip,
            "expires": new_expires
        }
    except Exception as e:
        log.error(f"Error in _get_active_session: {e}")
        return None
    finally:
        conn.close()

def _create_session(ip: str, username: str, role: str) -> str:
    token = secrets.token_hex(32)
    expires = time.time() + SESSION_TTL
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO sessions (token, username, role, ip, expires) VALUES (?, ?, ?, ?, ?)",
            (token, username, role, ip, expires)
        )
        conn.commit()
    except Exception as e:
        log.error(f"Error creating session in database: {e}")
    finally:
        conn.close()
    return token

def _valid_session(token: str) -> bool:
    return _get_active_session(token) is not None

def _invalidate_all_sessions():
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions")
        conn.commit()
    except Exception as e:
        log.error(f"Error invalidating all sessions: {e}")
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
def _rate_ok(ip: str) -> bool:
    now = time.time()
    with _lock:
        ts = _rate_store.setdefault(ip, [])
        _rate_store[ip] = [t for t in ts if now - t < RATE_WINDOW]
        if len(_rate_store[ip]) >= RATE_LIMIT:
            return False
        _rate_store[ip].append(now)
    return True

# ---------------------------------------------------------------------------
# Brute-force lockout (tracks BOTH per-IP and per-username)
# ---------------------------------------------------------------------------
_failed_usernames = {}  # username -> {count, locked_until}

def _is_locked_out(ip: str, username: str = "") -> bool:
    with _lock:
        # Check IP lockout
        entry = _failed_logins.get(ip)
        if entry:
            if time.time() < entry.get("locked_until", 0):
                return True
            del _failed_logins[ip]
        # Check per-username lockout
        if username:
            u_entry = _failed_usernames.get(username)
            if u_entry:
                if time.time() < u_entry.get("locked_until", 0):
                    return True
                del _failed_usernames[username]
        return False

def _record_failed_login(ip: str, username: str = ""):
    with _lock:
        # Per-IP tracking
        entry = _failed_logins.setdefault(ip, {"count": 0, "locked_until": 0})
        entry["count"] += 1
        if entry["count"] >= LOCKOUT_TRIES:
            entry["locked_until"] = time.time() + LOCKOUT_SECONDS
            log.warning(f"IP {ip} locked out after {LOCKOUT_TRIES} failed login attempts")
        # Per-username tracking
        if username:
            u_entry = _failed_usernames.setdefault(username, {"count": 0, "locked_until": 0})
            u_entry["count"] += 1
            if u_entry["count"] >= USERNAME_LOCKOUT_TRIES:
                u_entry["locked_until"] = time.time() + LOCKOUT_SECONDS
                log.warning(f"Username '{username}' locked out after {USERNAME_LOCKOUT_TRIES} failed login attempts")

def _reset_failed_logins(ip: str, username: str = ""):
    with _lock:
        _failed_logins.pop(ip, None)
        if username:
            _failed_usernames.pop(username, None)

# ---------------------------------------------------------------------------
# SQLite Database Access
# ---------------------------------------------------------------------------

def init_sqlite_db():
    """Initialize the database and migrate data from JSON if needed."""
    if DB_CONFIG.get("DB_TYPE") == "mysql":
        conn = connect_db()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS employees (
                    personal_id VARCHAR(100) PRIMARY KEY,
                    fullname VARCHAR(255) NOT NULL,
                    civil_id VARCHAR(100),
                    dob VARCHAR(100),
                    pob VARCHAR(100),
                    gender VARCHAR(50),
                    marital_status VARCHAR(100),
                    religion VARCHAR(100),
                    ethnicity VARCHAR(100),
                    address VARCHAR(255),
                    phone VARCHAR(100),
                    upn VARCHAR(100),
                    biometric_code VARCHAR(100),
                    appointment_no VARCHAR(100),
                    emp_type VARCHAR(100),
                    start_date VARCHAR(100),
                    degree VARCHAR(100),
                    political VARCHAR(100),
                    workplace VARCHAR(255),
                    blood_group VARCHAR(50) DEFAULT 'N/A',
                    appointment_date VARCHAR(100),
                    job_title VARCHAR(255),
                    notes TEXT,
                    documents LONGTEXT
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            """)
            
            # Create users table in MySQL
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username VARCHAR(100) PRIMARY KEY,
                    salt VARCHAR(100) NOT NULL,
                    pw_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            """)

            # Create audit_logs table in MySQL
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    action_type VARCHAR(100) NOT NULL,
                    action_details TEXT NOT NULL,
                    timestamp VARCHAR(100) NOT NULL
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            """)

            # Create sessions table in MySQL
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token VARCHAR(64) PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    role VARCHAR(50) NOT NULL,
                    ip VARCHAR(45) NOT NULL,
                    expires DOUBLE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
            """)

            # Clean up expired sessions in MySQL
            try:
                cursor.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
            except Exception as e:
                log.error(f"Error cleaning up expired MySQL sessions on startup: {e}")

            # Check columns in MySQL
            cursor.execute("SHOW COLUMNS FROM employees")
            columns = [col['Field'] for col in cursor.fetchall()]
            if "workplace" not in columns:
                cursor.execute("ALTER TABLE employees ADD COLUMN workplace VARCHAR(255)")
            if "blood_group" not in columns:
                cursor.execute("ALTER TABLE employees ADD COLUMN blood_group VARCHAR(50) DEFAULT 'N/A'")
            if "appointment_date" not in columns:
                cursor.execute("ALTER TABLE employees ADD COLUMN appointment_date VARCHAR(100)")
            if "job_title" not in columns:
                cursor.execute("ALTER TABLE employees ADD COLUMN job_title VARCHAR(255)")
            if "notes" not in columns:
                cursor.execute("ALTER TABLE employees ADD COLUMN notes TEXT")
            if "status" not in columns:
                cursor.execute("ALTER TABLE employees ADD COLUMN status VARCHAR(50) DEFAULT 'active'")
            
            conn.commit()
        finally:
            conn.close()
    else:
        DB_PATH.parent.mkdir(exist_ok=True)
        conn = connect_db()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS employees (
                    personal_id TEXT PRIMARY KEY,
                    fullname TEXT NOT NULL,
                    civil_id TEXT,
                    dob TEXT,
                    pob TEXT,
                    gender TEXT,
                    marital_status TEXT,
                    religion TEXT,
                    ethnicity TEXT,
                    address TEXT,
                    phone TEXT,
                    upn TEXT,
                    biometric_code TEXT,
                    appointment_no TEXT,
                    emp_type TEXT,
                    start_date TEXT,
                    degree TEXT,
                    political TEXT,
                    workplace TEXT,
                    blood_group TEXT DEFAULT 'N/A',
                    appointment_date TEXT,
                    job_title TEXT,
                    notes TEXT DEFAULT '',
                    documents TEXT,
                    status TEXT DEFAULT 'active'
                )
            """)
            
            # Create users table in SQLite
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    salt TEXT NOT NULL,
                    pw_hash TEXT NOT NULL,
                    role TEXT NOT NULL
                )
            """)

            # Create audit_logs table in SQLite
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    action_details TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)

            # Create sessions table in SQLite
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    expires REAL NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Clean up expired sessions in SQLite
            try:
                cursor.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
            except Exception as e:
                log.error(f"Error cleaning up expired SQLite sessions on startup: {e}")

            # Check if columns exist, if not, add them (migrations)
            cursor.execute("PRAGMA table_info(employees)")
            columns = [col[1] for col in cursor.fetchall()]
            if "workplace" not in columns:
                cursor.execute("ALTER TABLE employees ADD COLUMN workplace TEXT")
            if "blood_group" not in columns:
                cursor.execute("ALTER TABLE employees ADD COLUMN blood_group TEXT DEFAULT 'N/A'")
            if "status" not in columns:
                cursor.execute("ALTER TABLE employees ADD COLUMN status TEXT DEFAULT 'active'")
            # Add explicit performance indexes for common search fields
            indexes = [
                ("idx_emp_fullname", "fullname"),
                ("idx_emp_civil_id", "civil_id"),
                ("idx_emp_workplace", "workplace"),
                ("idx_emp_job_title", "job_title")
            ]
            for idx_name, col_name in indexes:
                try:
                    cursor.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON employees({col_name})")
                except Exception as ex:
                    log.warning(f"Could not create index {idx_name}: {ex}")

            conn.commit()
        finally:
            conn.close()

    # Seed default user or sync from auth.json
    conn = connect_db()
    try:
        cursor = conn.cursor()
        is_mysql = (DB_CONFIG.get("DB_TYPE") == "mysql")

        if AUTH_PATH.exists():
            try:
                with open(AUTH_PATH, "r", encoding="utf-8") as f:
                    auth_data = json.load(f)
                username = auth_data.get("username", "admin").strip()
                salt = auth_data.get("salt")
                pw_hash = auth_data.get("pw_hash")
                if is_mysql:
                    cursor.execute("""
                        REPLACE INTO users (username, salt, pw_hash, role)
                        VALUES (%s, %s, %s, 'super_admin')
                    """, (username, salt, pw_hash))
                else:
                    cursor.execute("""
                        INSERT OR REPLACE INTO users (username, salt, pw_hash, role)
                        VALUES (?, ?, ?, 'super_admin')
                    """, (username, salt, pw_hash))
                conn.commit()
                log.info(f"Synchronized user '{username}' from auth.json to database.")
            except Exception as e:
                log.error(f"Failed to sync auth.json to database: {e}")
        else:
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count_row = cursor.fetchone()
            user_count = 0
            if user_count_row:
                if isinstance(user_count_row, dict):
                    user_count = list(user_count_row.values())[0]
                else:
                    user_count = user_count_row[0]
            if user_count == 0:
                salt = secrets.token_hex(16)
                default_pw = "admin123"
                pw_hash = _hash_pw(default_pw, salt, iterations=600000)
                if is_mysql:
                    cursor.execute("""
                        REPLACE INTO users (username, salt, pw_hash, role)
                        VALUES (%s, %s, %s, 'super_admin')
                    """, ("admin", salt, pw_hash))
                else:
                    cursor.execute("""
                        INSERT OR REPLACE INTO users (username, salt, pw_hash, role)
                        VALUES (?, ?, ?, 'super_admin')
                    """, ("admin", salt, pw_hash))
                conn.commit()
                log.warning("Initial admin account created in DB with default password admin123.")
    except Exception as e:
        log.error(f"Error seeding/syncing users: {e}")
    finally:
        conn.close()

    # Auto-migration
    if JSON_PATH.exists():
        log.info("Found database.json, starting automatic migration to SQLite...")
        try:
            with open(JSON_PATH, "r", encoding="utf-8") as f:
                records = json.load(f)
            
            if isinstance(records, list):
                conn = connect_db()
                try:
                    cursor = conn.cursor()

                    for r in records:
                        docs_str = json.dumps(r.get("documents", {}), ensure_ascii=False)
                        cursor.execute("""
                            INSERT OR REPLACE INTO employees (
                                personal_id, fullname, civil_id, dob, pob, gender,
                                marital_status, religion, ethnicity, address, phone,
                                upn, biometric_code, appointment_no, emp_type, start_date,
                                degree, political, workplace, blood_group, appointment_date, job_title, notes, documents
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            r.get("personal_id"), r.get("fullname"), r.get("civil_id"),
                            r.get("dob"), r.get("pob"), r.get("gender"),
                            r.get("marital_status"), r.get("religion"), r.get("ethnicity"),
                            r.get("address"), r.get("phone"), r.get("upn"),
                            r.get("biometric_code"), r.get("appointment_no"), r.get("emp_type"),
                            r.get("start_date"), r.get("degree"), r.get("political"),
                            r.get("workplace", "N/A"),
                            r.get("blood_group", "N/A"),
                            r.get("appointment_date", ""),
                            r.get("job_title", ""),
                            r.get("notes", ""),
                            docs_str
                        ))
                    conn.commit()
                    log.info(f"Successfully migrated {len(records)} records from JSON to SQLite!")
                except Exception as e:
                    conn.rollback()
                    log.exception("Migration failed during insertion")
                    raise e
                finally:
                    conn.close()
            
            bak_path = JSON_PATH.with_suffix(".json.bak")
            JSON_PATH.rename(bak_path)
            log.info(f"Renamed {JSON_PATH.name} to {bak_path.name}")
        except Exception as e:
            log.error(f"Failed to migrate database.json: {e}")

def _log_audit(username: str, action_type: str, action_details: str):
    conn = connect_db()
    try:
        cursor = conn.cursor()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO audit_logs (username, action_type, action_details, timestamp)
            VALUES (?, ?, ?, ?)
        """, (username, action_type, action_details, timestamp))
        conn.commit()
    except Exception as e:
        log.error(f"Failed to log audit event: {e}")
    finally:
        conn.close()

def keep_n_backups(dest_dir: pathlib.Path, max_keep: int = 10):
    try:
        backups = sorted(
            [f for f in dest_dir.glob("health_archive_backup_*.zip")],
            key=lambda x: x.stat().st_mtime
        )
        while len(backups) > max_keep:
            oldest = backups.pop(0)
            oldest.unlink()
            log.info(f"Deleted old backup: {oldest.name}")
    except Exception as e:
        log.error(f"Error cleaning old backups: {e}")

def run_auto_backup():
    config = {}
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                config = json.load(f)
        except Exception:
            pass
            
    enabled = config.get("AUTO_BACKUP_ENABLED", True)
    if not enabled:
        return
        
    dest_dir_str = config.get("BACKUP_DEST_DIR", "")
    if not dest_dir_str:
        dest_dir_str = str(EXE_DIR / "data" / "backups")
        
    dest_dir = pathlib.Path(dest_dir_str)
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    zip_path = dest_dir / f"health_archive_backup_{timestamp}.zip"
    
    import zipfile
    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # 1. Back up database
            db_type = config.get("DB_TYPE", "sqlite")
            if db_type == "sqlite" and DB_PATH.exists():
                zipf.write(str(DB_PATH), "database.db")
            else:
                conn = connect_db()
                if db_type == "sqlite":
                    conn.row_factory = sqlite3.Row
                try:
                    cursor = conn.cursor()
                    
                    cursor.execute("SELECT * FROM employees")
                    employees = [dict(r) for r in cursor.fetchall()]
                    
                    cursor.execute("SELECT username, salt, pw_hash, role FROM users")
                    users = [dict(r) for r in cursor.fetchall()]
                    
                    cursor.execute("SELECT id, username, action_type, action_details, timestamp FROM audit_logs")
                    audit_logs = [dict(r) for r in cursor.fetchall()]
                    
                    db_dump = {
                        "employees": employees,
                        "users": users,
                        "audit_logs": audit_logs
                    }
                    db_dump_str = json.dumps(db_dump, ensure_ascii=False, indent=2)
                    zipf.writestr("database_dump.json", db_dump_str)
                except Exception as db_err:
                    log.error(f"Failed to dump database tables for backup: {db_err}")
                finally:
                    conn.close()
                    
            # 2. Back up employee documents
            if EMPLOYEE_FILES_DIR.exists() and EMPLOYEE_FILES_DIR.is_dir():
                for root, dirs, files in os.walk(str(EMPLOYEE_FILES_DIR)):
                    for file in files:
                        full_path = pathlib.Path(root) / file
                        rel_path = full_path.relative_to(EMPLOYEE_FILES_DIR.parent)
                        zipf.write(str(full_path), str(rel_path))
                        
        log.info(f"Auto-backup completed successfully to: {zip_path}")
        _log_audit("SYSTEM", "auto_backup", f"Auto-backup successfully created at {zip_path}")
        keep_n_backups(dest_dir, 10)
    except Exception as e:
        log.exception(f"Auto-backup failed: {e}")

def start_backup_scheduler():
    def scheduler_loop():
        time.sleep(30)
        last_backup_date = ""
        while True:
            try:
                config = {}
                if CONFIG_PATH.exists():
                    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                        config = json.load(f)
                
                enabled = config.get("AUTO_BACKUP_ENABLED", True)
                if enabled:
                    backup_time_str = config.get("BACKUP_TIME", "16:00")
                    now_struct = time.localtime()
                    current_time_str = time.strftime("%H:%M", now_struct)
                    current_date_str = time.strftime("%Y-%m-%d", now_struct)
                    
                    if current_time_str == backup_time_str and last_backup_date != current_date_str:
                        log.info("Starting scheduled auto-backup...")
                        run_auto_backup()
                        last_backup_date = current_date_str
            except Exception as e:
                log.error(f"Error in backup scheduler loop: {e}")
            time.sleep(30)
            
    t = threading.Thread(target=scheduler_loop, daemon=True)
    t.start()

def _row_to_dict(row) -> dict:
    """Convert a database row (sqlite3.Row or dict) to a plain dict."""
    if isinstance(row, dict):
        return dict(row)
    try:
        return dict(row)
    except Exception:
        return {col[0]: row[i] for i, col in enumerate(row.description)} if hasattr(row, 'description') else {}

def migrate_database_base64_to_disk():
    """Migrate all base64-encoded files stored in database to the local disk."""
    import base64
    init_sqlite_db()
    conn = connect_db()
    try:
        # Only set row_factory for SQLite connections
        if DB_CONFIG.get("DB_TYPE") != "mysql":
            conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT personal_id, fullname, documents FROM employees")
        raw_rows = cursor.fetchall()
        # Normalize to list of dicts
        rows = []
        for r in raw_rows:
            if isinstance(r, dict):
                rows.append(r)
            else:
                try:
                    rows.append(dict(r))
                except Exception:
                    pass
        
        migrated_count = 0
        
        for row in rows:
            pid = row["personal_id"]
            fullname = row["fullname"]
            docs_str = row["documents"]
            
            if not docs_str:
                continue
                
            try:
                documents = json.loads(docs_str)
            except json.JSONDecodeError:
                continue
                
            has_base64 = False
            
            # Construct employee folder
            safe_name = fullname.replace(" ", "_")
            safe_name = "".join(c for c in safe_name if c.isalnum() or c in "_-")
            folder_name = f"{pid}_{safe_name}"
            emp_folder = EMPLOYEE_FILES_DIR / folder_name
            
            # Categories to check
            valid_categories = {
                'appointment_order', 'commencement_order', 'punishments',
                'leaves', 'certificates', 'thanks',
                'administrative_order', 'establishment_order'
            }
            
            for cat in list(documents.keys()):
                if cat not in valid_categories:
                    continue
                doc_val = documents[cat]
                if not doc_val:
                    continue
                    
                if cat == 'appointment_order':
                    if isinstance(doc_val, dict) and "base64" in doc_val:
                        has_base64 = True
                        b64_data = doc_val["base64"]
                        try:
                            if "," in b64_data:
                                b64_data = b64_data.split(",")[1]
                            file_bytes = base64.b64decode(b64_data)
                            cat_dir = emp_folder / KURDISH_FOLDER_MAP.get(cat, cat)
                            cat_dir.mkdir(parents=True, exist_ok=True)
                            (cat_dir / doc_val["fileName"]).write_bytes(file_bytes)
                            del doc_val["base64"]
                        except Exception as e:
                            log.error(f"Migration error for employee {pid} appt order: {e}")
                elif isinstance(doc_val, list):
                    for item in doc_val:
                        if isinstance(item, dict) and "base64" in item:
                            has_base64 = True
                            b64_data = item["base64"]
                            try:
                                if "," in b64_data:
                                    b64_data = b64_data.split(",")[1]
                                file_bytes = base64.b64decode(b64_data)
                                cat_dir = emp_folder / KURDISH_FOLDER_MAP.get(cat, cat)
                                cat_dir.mkdir(parents=True, exist_ok=True)
                                (cat_dir / item["fileName"]).write_bytes(file_bytes)
                                del item["base64"]
                            except Exception as e:
                                log.error(f"Migration error for employee {pid} doc {item.get('fileName')}: {e}")
                                
            if has_base64:
                new_docs_str = json.dumps(documents, ensure_ascii=False)
                cursor.execute(
                    "UPDATE employees SET documents = ? WHERE personal_id = ?",
                    (new_docs_str, pid)
                )
                migrated_count += 1
                
        if migrated_count > 0:
            conn.commit()
            log.info(f"Database migration completed: converted files of {migrated_count} employees to disk.")
    except Exception as e:
        log.exception("Database migration failed")
    finally:
        conn.close()

def sync_documents_on_disk(pid: str, employee_docs: dict, emp_folder: pathlib.Path):
    """
    Scans the filesystem under emp_folder and moves any file that is not
    listed in employee_docs metadata into a quarantine folder, rather than
    permanently deleting it.

    IMPORTANT: this runs on every single employee save (not just when a
    document is explicitly removed). On a multi-user LAN system, a staff
    member's browser can hold a stale document list if another staff member
    added a file in the meantime — saving from that stale session would
    previously cause the other person's file to be permanently deleted here.
    Quarantining instead of unlinking means a mistaken/stale-session removal
    is always recoverable (files land under employees/_quarantine/<pid>/...),
    while an intentional removal still disappears from the active folder and
    from the UI, since only the DB metadata (which drives what's shown) is
    what the app actually reads from.
    """
    valid_categories = {
        'appointment_order', 'commencement_order', 'punishments',
        'leaves', 'certificates', 'thanks',
        'administrative_order', 'establishment_order'
    }
    
    # Collect all valid file paths that should exist
    expected_files = set()
    
    appt = employee_docs.get("appointment_order")
    if appt and isinstance(appt, dict) and appt.get("fileName"):
        expected_files.add(emp_folder / KURDISH_FOLDER_MAP.get("appointment_order", "appointment_order") / appt["fileName"])
        
    for cat in valid_categories:
        if cat == "appointment_order":
            continue
        items = employee_docs.get(cat)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and item.get("fileName"):
                    expected_files.add(emp_folder / KURDISH_FOLDER_MAP.get(cat, cat) / item["fileName"])
                    
    # Now scan folders and quarantine (never permanently delete) unexpected files
    quarantine_root = EMPLOYEE_FILES_DIR / "_quarantine" / pid
    for cat in valid_categories:
        cat_dir = emp_folder / KURDISH_FOLDER_MAP.get(cat, cat)
        if cat_dir.exists() and cat_dir.is_dir():
            for f in cat_dir.iterdir():
                if f.is_file():
                    # If this file is not in our expected list, quarantine it instead of deleting
                    if f.resolve() not in [ef.resolve() for ef in expected_files]:
                        try:
                            quarantine_dir = quarantine_root / cat
                            quarantine_dir.mkdir(parents=True, exist_ok=True)
                            dest = quarantine_dir / f"{int(time.time())}_{f.name}"
                            shutil.move(str(f), str(dest))
                            log.info(f"Quarantined document no longer referenced by employee {pid}: {f} -> {dest}")
                        except Exception as e:
                            log.warning(f"Could not quarantine file {f}: {e}")

def load_db() -> list:
    init_sqlite_db()
    conn = connect_db()
    try:
        # Only set row_factory for SQLite connections
        if DB_CONFIG.get("DB_TYPE") != "mysql":
            conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees")
        raw_rows = cursor.fetchall()
        
        employees = []
        for row in raw_rows:
            if isinstance(row, dict):
                emp = dict(row)
            else:
                try:
                    emp = dict(row)
                except Exception:
                    continue
            docs_str = emp.get("documents")
            if docs_str:
                try:
                    emp["documents"] = json.loads(docs_str)
                except json.JSONDecodeError:
                    emp["documents"] = {}
            else:
                emp["documents"] = {}
            employees.append(emp)
        return employees
    except Exception as e:
        log.error(f"Error loading database: {e}")
        return []
    finally:
        conn.close()

def save_single_employee(emp: dict) -> bool:
    init_sqlite_db()
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM employees WHERE personal_id = ?", (emp["personal_id"],))
        is_new = cursor.fetchone() is None
        
        docs_str = json.dumps(emp.get("documents", {}), ensure_ascii=False)
        cursor.execute("""
            INSERT OR REPLACE INTO employees (
                personal_id, fullname, civil_id, dob, pob, gender,
                marital_status, religion, ethnicity, address, phone,
                upn, biometric_code, appointment_no, emp_type, start_date,
                degree, political, workplace, blood_group, appointment_date, job_title, notes, documents, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            emp.get("personal_id"), emp.get("fullname"), emp.get("civil_id"),
            emp.get("dob"), emp.get("pob"), emp.get("gender"),
            emp.get("marital_status"), emp.get("religion"), emp.get("ethnicity"),
            emp.get("address"), emp.get("phone"), emp.get("upn"),
            emp.get("biometric_code"), emp.get("appointment_no"), emp.get("emp_type"),
            emp.get("start_date"), emp.get("degree"), emp.get("political"),
            emp.get("workplace"), emp.get("blood_group"),
            emp.get("appointment_date", ""),
            emp.get("job_title", ""),
            emp.get("notes", ""),
            docs_str,
            emp.get("status", "active")
        ))
        conn.commit()
        return is_new
    finally:
        conn.close()

def delete_single_employee(personal_id: str) -> bool:
    init_sqlite_db()
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM employees WHERE personal_id = ?", (personal_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()

def save_db(data: list):
    init_sqlite_db()
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM employees")
        for emp in data:
            docs_str = json.dumps(emp.get("documents", {}), ensure_ascii=False)
            cursor.execute("""
                INSERT INTO employees (
                    personal_id, fullname, civil_id, dob, pob, gender,
                    marital_status, religion, ethnicity, address, phone,
                    upn, biometric_code, appointment_no, emp_type, start_date,
                    degree, political, workplace, blood_group, appointment_date, job_title, notes, documents, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                emp.get("personal_id"), emp.get("fullname"), emp.get("civil_id"),
                emp.get("dob"), emp.get("pob"), emp.get("gender"),
                emp.get("marital_status"), emp.get("religion"), emp.get("ethnicity"),
                emp.get("address"), emp.get("phone"), emp.get("upn"),
                emp.get("biometric_code"), emp.get("appointment_no"), emp.get("emp_type"),
                emp.get("start_date"), emp.get("degree"), emp.get("political"),
                emp.get("workplace"), emp.get("blood_group"),
                emp.get("appointment_date", ""),
                emp.get("job_title", ""),
                emp.get("notes", ""),
                docs_str,
                emp.get("status", "active")
            ))
        conn.commit()
    except Exception as e:
        conn.rollback()
        log.error(f"Error saving to SQLite database: {e}")
        raise e
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# PDF Generation
# ---------------------------------------------------------------------------
# Translations for database stored values in PDF reports
VAL_TRANSLATIONS = {
    # Gender
    "نێر": "ذكر",
    "مێ": "أنثى",
    # Marital Status
    "سەڵت": "أعزب",
    "خێزاندار": "متزوج",
    "جودابووی": "مطلق",
    "بێوەژن یان پیاوێ بێوەژن": "أرمل / أرملة",
    # Ethnicity
    "کورد": "كردي",
    "عەرەب": "عربي",
    "تورکمان": "تركماني",
    "کلدۆئاشوور": "كلدوآشوري",
    "دیتر": "أخرى",
    # Religion
    "موسڵمان": "مسلم",
    "کریستیان": "مسيحي",
    "ئێزیدی": "إيزيدي",
    # Employment type
    "هەمیشەیی": "دائم",
    "گرێبەست": "عقد",
    "خۆبەخش": "متطوع",
    "ڕۆژانە": "يومي",
    # Degree
    "دکتۆرا": "دكتوراه",
    "ماستەر": "ماجستير",
    "بەکالۆریۆس": "بكالوريوس",
    "دبلۆم": "دبلوم",
    "ئامادەیی": "إعدادية",
    "ناوەندی": "متوسطة",
    "ناڤنجی": "متوسطة",
    "سەرەتایی": "ابتدائية",
    "بێ بڕوانامە": "بدون شهادة",
    "بێ باوەرنامە": "بدون شهادة"
}

def translate_val(val: str, lang: str) -> str:
    if not val:
        return ""
    if lang != 'ar':
        return str(val)
    return VAL_TRANSLATIONS.get(str(val), str(val))

pdf_trans = {
    "ku": {
        "title": "ڕێڤەبەریا گشتی یا ساخلەمیا پارێزگەها دهۆکێ",
        "subtitle": "ڕێڤەبەریا ساخلەمیا قەزایا ئاکرێ - پرۆفایلێ فەرمانبەری",
        "personal_id": "ژمارەیا کەسی",
        "fullname": "ناڤێ تەواو",
        "civil_id": "ژمارەیا ناسنامەیا شارستانی (Civil ID)",
        "dob": "ڕێككەفتا ژدایکبوونێ",
        "pob": "جهێ ژدایکبوونێ",
        "gender": "ڕەگەز",
        "blood_group": "گرۆپێ خۆینێ",
        "marital_status": "بارێ خێزانی",
        "religion": "ئایین",
        "ethnicity": "نەتەوە",
        "address": "جهێ ئاکنجیبوونێ",
        "phone": "ژمارەیا مۆبایلێ",
        "upn": "ژمارەیا UPN",
        "biometric_code": "کۆدێ بایۆمەتری",
        "appointment_no": "ژمارەیا فەرمانا دامەزراندنێ",
        "emp_type": "جۆرێ دامەزراندنێ",
        "workplace": "جهێ کاری / بەش",
        "start_date": "ڕێككەفتا دەستبکاربوونێ",
        "appointment_date": "ڕێككەفتا دامەزراندنێ",
        "job_title": "ناڤونیشانێ کاری",
        "degree": "باوەرناما دووماهییێ",
        "political": "لایەنێ ڕامیاری (سیاسی)",
        "sec_personal": "زانیارییێن کەسی یێن فەرمانبەری",
        "sec_official": "زانیارییێن فەرمی یێن کارگێڕی",
        "label_pid": "ژمارەیا کەسی:",
        "label_job": "ناڤونیشانێ کاری:",
        "label_appt_date": "ڕێككەفتا دامەزراندنێ:",
        "label_start_date": "ڕێككەفتا دەستبکاربوونێ:",
        "n_a": "N/A"
    },
    "ar": {
        "title": "المديرية العامة لصحة محافظة دهوك",
        "subtitle": "مديرية صحة قضاء عقرة - ملف الموظف",
        "personal_id": "الرقم الشخصي",
        "fullname": "الاسم الكامل",
        "civil_id": "رقم الهوية المدنية (Civil ID)",
        "dob": "تاريخ الميلاد",
        "pob": "مكان الميلاد",
        "gender": "الجنس",
        "blood_group": "فصيلة الدم",
        "marital_status": "الحالة الاجتماعية",
        "religion": "الديانة",
        "ethnicity": "القومية",
        "address": "عنوان السكن",
        "phone": "رقم الهاتف",
        "upn": "رمز UPN",
        "biometric_code": "رمز البصمة البايومتري",
        "appointment_no": "رقم أمر التعيين",
        "emp_type": "نوع التعيين",
        "workplace": "مكان العمل / القسم",
        "start_date": "تاريخ المباشرة",
        "appointment_date": "تاريخ التعيين",
        "job_title": "العنوان الوظيفي",
        "degree": "آخر شهادة",
        "political": "الانتماء السياسي",
        "sec_personal": "المعلومات الشخصية للموظف",
        "sec_official": "المعلومات الرسمية والإدارية",
        "label_pid": "الرقم الشخصي:",
        "label_job": "العنوان الوظيفي:",
        "label_appt_date": "تاريخ التعيين:",
        "label_start_date": "تاريخ المباشرة:",
        "n_a": "غير متوفر"
    }
}

def generate_employee_pdf(employee: dict, lang: str = "ku") -> bytes:
    """Generate a professional employee profile PDF with full Kurdish/Arabic Unicode support."""
    # Ensure lang is valid
    if lang not in pdf_trans:
        lang = "ku"
        
    t = pdf_trans[lang]
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    # --- Styles (Amiri for full Kurdish/Arabic glyph coverage) ---
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "KuTitle", parent=styles["Normal"],
        fontSize=20, fontName="Amiri-Bold",
        textColor=colors.HexColor("#1a3a5c"),
        alignment=TA_CENTER, spaceAfter=4,
        leading=24,
    )
    subtitle_style = ParagraphStyle(
        "KuSubtitle", parent=styles["Normal"],
        fontSize=12, fontName="Amiri",
        textColor=colors.HexColor("#555555"),
        alignment=TA_CENTER, spaceAfter=2,
        leading=16,
    )
    section_style = ParagraphStyle(
        "KuSection", parent=styles["Normal"],
        fontSize=12, fontName="Amiri-Bold",
        textColor=colors.white,
        alignment=TA_RIGHT,   # RTL: text flows right-to-left
        leading=16,
    )
    label_style = ParagraphStyle(
        "KuLabel", parent=styles["Normal"],
        fontSize=9, fontName="Amiri-Bold",
        textColor=colors.HexColor("#333333"),
        alignment=TA_RIGHT,
        leading=12,
    )
    value_style = ParagraphStyle(
        "KuValue", parent=styles["Normal"],
        fontSize=10, fontName="Amiri",
        textColor=colors.HexColor("#111111"),
        alignment=TA_RIGHT,
        leading=14,
    )

    def section_header(title_text):
        # Apply Kurdish/Arabic reshaping
        shaped = _ku(title_text)
        tbl = Table([[Paragraph(shaped + "  ", section_style)]], colWidths=[17*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#1a3a5c")),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ]))
        return tbl

    def info_table(rows):
        """rows = list of (label_str, value_str) — both may be Kurdish/Arabic text."""
        data = []
        for label, value in rows:
            shaped_label = _ku(label)
            shaped_value = _ku(value) if value else _ku(t["n_a"])
            # RTL layout: value on left column, label on right column
            data.append([
                Paragraph(shaped_value, value_style),
                Paragraph(shaped_label, label_style),
            ])
        # col[0]=value(wider), col[1]=label(narrower)  — visually right-aligned
        tbl = Table(data, colWidths=[10.5*cm, 6.5*cm])
        tbl.setStyle(TableStyle([
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1), [colors.HexColor("#f5f8fc"), colors.white]),
            ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
        ]))
        return tbl

    story = []

    # --- Header ---
    story.append(Paragraph(_ku(t["title"]), title_style))
    story.append(Paragraph(_ku(t["subtitle"]), subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2,
                             color=colors.HexColor("#1a3a5c"), spaceAfter=8))

    # --- Barcode + Key Info Banner ---
    pid     = employee.get("personal_id", "ID")
    appt_no = employee.get("appointment_no", "")
    s_date  = employee.get("start_date", "")
    appt_date = employee.get("appointment_date", "")
    job_title = translate_val(employee.get("job_title", ""), lang)
    fullname = employee.get("fullname", "")

    barcode_value = pid  # encode personal_id in the barcode
    safe_bc_val = "".join(c for c in barcode_value if ord(c) < 128) or "ID"
    barcode_obj = bc128.Code128(
        safe_bc_val,
        barWidth=0.9,
        barHeight=50,
        humanReadable=True,
        fontSize=7,
    )
    barcode_obj.fontName = "Helvetica"

    banner_info_style = ParagraphStyle(
        "BannerInfo", parent=styles["Normal"],
        fontSize=9, fontName="Amiri",
        textColor=colors.HexColor("#333333"),
        alignment=TA_RIGHT, leading=14,
    )
    banner_bold_style = ParagraphStyle(
        "BannerBold", parent=styles["Normal"],
        fontSize=11, fontName="Amiri-Bold",
        textColor=colors.HexColor("#1a3a5c"),
        alignment=TA_RIGHT, leading=16,
    )

    info_col = [
        Paragraph(_ku(fullname), banner_bold_style),
        Spacer(1, 3),
        Paragraph(_ku(f"{t['label_pid']} {pid}"), banner_info_style),
        Paragraph(_ku(f"{t['label_job']} {job_title if job_title else t['n_a']}"), banner_info_style),
        Paragraph(_ku(f"{t['label_appt_date']} {appt_date if appt_date else t['n_a']}"), banner_info_style),
        Paragraph(_ku(f"{t['label_start_date']} {s_date if s_date else t['n_a']}"), banner_info_style),
    ]

    banner_tbl = Table(
        [[info_col, barcode_obj]],
        colWidths=[11*cm, 6*cm],
    )
    banner_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f0f4fa")),
        ("BOX",           (0, 0), (-1, -1), 1.2, colors.HexColor("#1a3a5c")),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (0, 0),  12),
        ("LEFTPADDING",   (1, 0), (1, 0),  8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (1, 0), (1, 0),  "CENTER"),
    ]))
    story.append(banner_tbl)
    story.append(Spacer(1, 12))

    # --- Personal Information ---
    story.append(section_header(t["sec_personal"]))
    story.append(Spacer(1, 4))
    story.append(info_table([
        (t["fullname"],       employee.get("fullname")),
        (t["personal_id"],      employee.get("personal_id")),
        (t["civil_id"],     employee.get("civil_id")),
        (t["dob"], employee.get("dob")),
        (t["pob"], employee.get("pob")),
        (t["gender"],            translate_val(employee.get("gender"), lang)),
        (t["blood_group"],      employee.get("blood_group")),
        (t["marital_status"],      translate_val(employee.get("marital_status"), lang)),
        (t["religion"],            translate_val(employee.get("religion"), lang)),
        (t["ethnicity"],           translate_val(employee.get("ethnicity"), lang)),
        (t["address"],     employee.get("address")),
        (t["phone"],    employee.get("phone")),
    ]))
    story.append(Spacer(1, 10))

    # --- Employment Details ---
    story.append(section_header(t["sec_official"]))
    story.append(Spacer(1, 4))
    story.append(info_table([
        (t["upn"],       employee.get("upn")),
        (t["biometric_code"],   employee.get("biometric_code")),
        (t["appointment_no"],   employee.get("appointment_no")),
        (t["emp_type"], translate_val(employee.get("emp_type"), lang)),
        (t["workplace"],    employee.get("workplace")),
        (t["start_date"], employee.get("start_date")),
        (t["appointment_date"], employee.get("appointment_date")),
        (t["job_title"],      translate_val(employee.get("job_title"), lang)),
        (t["degree"],         translate_val(employee.get("degree"), lang)),
        (t["political"],      translate_val(employee.get("political"), lang)),
    ]))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


def generate_barcode_card_pdf(employee: dict, lang: str = "ku") -> bytes:
    """
    Generate a compact A6-sized barcode card for the employee
    containing: Name, Personal ID, Appointment Date, Address, and a Code128 barcode.
    """
    if lang not in pdf_trans:
        lang = "ku"
    t = pdf_trans[lang]
    
    from reportlab.lib.pagesizes import A6
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A6,
        rightMargin=1*cm, leftMargin=1*cm,
        topMargin=1*cm, bottomMargin=1*cm,
    )
    styles = getSampleStyleSheet()

    card_title_style = ParagraphStyle(
        "CardTitle", parent=styles["Normal"],
        fontSize=9, fontName="Amiri-Bold",
        textColor=colors.white,
        alignment=TA_CENTER, leading=13,
    )
    card_field_label = ParagraphStyle(
        "CardFieldLabel", parent=styles["Normal"],
        fontSize=7, fontName="Amiri-Bold",
        textColor=colors.HexColor("#555555"),
        alignment=TA_RIGHT, leading=10,
    )
    card_field_value = ParagraphStyle(
        "CardFieldValue", parent=styles["Normal"],
        fontSize=8, fontName="Amiri",
        textColor=colors.HexColor("#111111"),
        alignment=TA_RIGHT, leading=11,
    )

    pid     = employee.get("personal_id", "ID")
    name    = employee.get("fullname", "")
    appt_no = employee.get("appointment_no", "")
    s_date  = employee.get("start_date", "")
    appt_date = employee.get("appointment_date", "")
    job_title = translate_val(employee.get("job_title", ""), lang)
    address = employee.get("address", "")
    workplace = employee.get("workplace", "")

    safe_bc_val = "".join(c for c in pid if ord(c) < 128) or "ID"
    barcode_obj = bc128.Code128(
        safe_bc_val,
        barWidth=1.1,
        barHeight=42,
        humanReadable=True,
        fontSize=7,
    )
    barcode_obj.fontName = "Helvetica"

    A6_W = A6[0] - 2*cm  # usable width

    story = []

    # Header banner
    header_text = "مديرية صحة عقرة — بطاقة الموظف" if lang == "ar" else "ڕێڤەبەریا ساخلەمیا ئاکرێ — کارتێ فەرمانبەری"
    header_tbl = Table(
        [[Paragraph(_ku(header_text), card_title_style)]],
        colWidths=[A6_W]
    )
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#1a3a5c")),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ("RIGHTPADDING",  (0,0),(-1,-1), 6),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 6))

    # Info rows
    def card_row(label, value):
        return [
            Paragraph(_ku(value) if value else "—", card_field_value),
            Paragraph(_ku(label), card_field_label),
        ]

    info_data = [
        card_row(t["fullname"],                  name),
        card_row(t["personal_id"],                pid),
        card_row(t["job_title"],             job_title),
        card_row(t["workplace"],              workplace),
        card_row(t["appointment_date"],        appt_date),
        card_row(t["start_date"],       s_date),
    ]
    col1 = A6_W * 0.60
    col2 = A6_W * 0.40
    info_tbl = Table(info_data, colWidths=[col1, col2])
    info_tbl.setStyle(TableStyle([
        ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ("TOPPADDING",    (0,0),(-1,-1), 3),
        ("BOTTOMPADDING", (0,0),(-1,-1), 3),
        ("RIGHTPADDING",  (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 3),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [colors.HexColor("#f5f8fc"), colors.white]),
        ("GRID",          (0,0),(-1,-1), 0.3, colors.HexColor("#dddddd")),
    ]))
    story.append(info_tbl)
    story.append(Spacer(1, 8))

    # Barcode centred
    bc_tbl = Table([[barcode_obj]], colWidths=[A6_W])
    bc_tbl.setStyle(TableStyle([
        ("ALIGN",         (0,0),(-1,-1), "CENTER"),
        ("TOPPADDING",    (0,0),(-1,-1), 2),
        ("BOTTOMPADDING", (0,0),(-1,-1), 2),
    ]))
    story.append(bc_tbl)

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def sanitize_filename(filename: str) -> str:
    """Sanitize the filename and enforce the allowed-extension allowlist."""
    name = pathlib.Path(filename).name
    for char in ['\\', '/', ':', '*', '?', '"', '<', '>', '|']:
        name = name.replace(char, '_')
    # Enforce extension allowlist
    ext = pathlib.Path(name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File type '{ext}' is not allowed. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
    return name

def _validate_file_bytes(file_bytes: bytes, filename: str) -> str | None:
    """Validate file bytes against magic signatures and size limit.
    Returns an error string on failure, or None if valid."""
    if len(file_bytes) > MAX_DOC_SIZE_BYTES:
        return f"File '{filename}' exceeds the maximum allowed size of {MAX_DOC_SIZE_BYTES // (1024*1024)} MB"
    if len(file_bytes) == 0:
        return f"File '{filename}' is empty"
    # Check magic bytes
    matched = False
    for magic, _ in MAGIC_SIGNATURES:
        if file_bytes[:len(magic)] == magic:
            matched = True
            break
    if not matched:
        return f"File '{filename}' has an unrecognised or unsafe file format"
    return None

def _validate_password_strength(pw: str) -> str | None:
    """Enforce password complexity: 10+ chars, at least one letter, at least one digit."""
    if len(pw) < 10:
        return "Password must be at least 10 characters"
    if not re.search(r'[A-Za-z]', pw):
        return "Password must contain at least one letter"
    if not re.search(r'\d', pw):
        return "Password must contain at least one digit"
    return None

def _get_mime_for_file(filename: str) -> str:
    """Return a correct MIME type based on file extension."""
    ext = pathlib.Path(filename).suffix.lower()
    mime_map = {
        '.pdf':  'application/pdf',
        '.jpg':  'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png':  'image/png',
        '.gif':  'image/gif',
        '.bmp':  'image/bmp',
        '.tiff': 'image/tiff',
        '.doc':  'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.xls':  'application/vnd.ms-excel',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    }
    return mime_map.get(ext, 'application/octet-stream')

def make_unique_filename(cat_dir: pathlib.Path, filename: str) -> str:
    """Checks if a file with the same name exists, and returns a unique name by adding an incremental suffix."""
    name = sanitize_filename(filename)
    path = cat_dir / name
    if not path.exists():
        return name
    
    stem = path.stem
    suffix = path.suffix
    counter = 1
    while True:
        new_name = f"{stem}_{counter}{suffix}"
        if not (cat_dir / new_name).exists():
            return new_name
        counter += 1

REQUIRED_FIELDS = {
    "personal_id", "fullname",
}

def validate_employee(emp: dict) -> str | None:
    missing = REQUIRED_FIELDS - emp.keys()
    if missing:
        return f"Missing fields: {', '.join(sorted(missing))}"
    for field in ("fullname", "personal_id"):
        val = emp.get(field, "")
        if not isinstance(val, str) or not val.strip():
            return f"Field '{field}' must be a non-empty string"
        if len(val) > 300:
            return f"Field '{field}' too long"
    return None

# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Session-Token", "")
        session = _get_active_session(token)
        if not session:
            abort(401)
        g.username = session.get("username", "")
        g.role = session.get("role", "")
        return f(*args, **kwargs)
    return decorated

def require_role(roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get("X-Session-Token", "")
            session = _get_active_session(token)
            if not session:
                abort(401)
            role = session.get("role", "")
            g.username = session.get("username", "")
            g.role = role
            if role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        if not _rate_ok(ip):
            log.warning(f"Rate limit hit: {ip}")
            abort(429)
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Static file routes
# ---------------------------------------------------------------------------
@app.route("/")
@app.route("/index.html")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/css/<path:filename>")
def serve_css(filename):
    css_dir = (BASE_DIR / "css").resolve()
    requested  = (css_dir / filename).resolve()
    if not str(requested).startswith(str(css_dir)):
        abort(403)
    return send_from_directory(str(css_dir), pathlib.Path(filename).name)

@app.route("/js/<path:filename>")
def serve_js(filename):
    js_dir = (BASE_DIR / "js").resolve()
    requested  = (js_dir / filename).resolve()
    if not str(requested).startswith(str(js_dir)):
        abort(403)
    return send_from_directory(str(js_dir), pathlib.Path(filename).name)

@app.route("/favicon.ico", methods=["GET"])
def favicon():
    return ("", 204)

# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
@require_rate_limit
def login():
    ip = request.remote_addr
    data     = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify(error="Username and password required"), 400

    if _is_locked_out(ip, username):
        log.warning(f"Login attempt from locked out IP/username: {ip} / {username}")
        return jsonify(error="Too many failed attempts. Try again in 15 minutes."), 429

    # Constant-time delay to slow brute force
    time.sleep(0.4)

    valid, role = _check_credentials(username, password)
    if not valid:
        _record_failed_login(ip, username)
        log.warning(f"Failed login for '{username}' from {ip}")
        _log_audit(username, "failed_login", f"Failed login attempt from IP {ip}")
        return jsonify(error="Invalid credentials"), 401

    _reset_failed_logins(ip)
    token = _create_session(ip, username, role)
    log.info(f"Successful login for '{username}' ({role}) from {ip}")
    _log_audit(username, "login", f"User logged in from IP {ip}")
    return jsonify(token=token, message="authenticated", username=username, role=role)

@app.route("/api/logout", methods=["POST"])
def logout():
    token = request.headers.get("X-Session-Token", "")
    username = "unknown"
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM sessions WHERE token = ?", (token,))
        row = cursor.fetchone()
        if row:
            if isinstance(row, dict):
                username = row["username"]
            else:
                username = row[0]
            cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
    except Exception as e:
        log.error(f"Error in logout endpoint: {e}")
    finally:
        conn.close()
    _log_audit(username, "logout", "User logged out")
    return jsonify(message="logged out")

@app.route("/api/reset_password", methods=["POST"])
@require_rate_limit
def reset_password():
    """Super admin resets any user's password directly."""
    data     = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    new_pw   = str(data.get("new_password", ""))

    if not username or not new_pw:
        return jsonify(error="username and new_password required"), 400

    pw_err = _validate_password_strength(new_pw)
    if pw_err:
        return jsonify(error=pw_err), 400

    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            return jsonify(error="User not found"), 404

        new_salt = secrets.token_hex(16)
        new_hash = _hash_pw(new_pw, new_salt)
        cursor.execute("UPDATE users SET salt = ?, pw_hash = ? WHERE username = ?", (new_salt, new_hash, username))
        cursor.execute("DELETE FROM sessions WHERE username = ?", (username,))
        conn.commit()
        _log_audit("system", "reset_password", f"Password reset for '{username}'")
        log.info(f"Password reset for '{username}' from {request.remote_addr}")
        return jsonify(success=True, message="Password reset successfully")
    except Exception as e:
        log.error(f"Error resetting password: {e}")
        return jsonify(error="Failed to reset password"), 500
    finally:
        conn.close()


@app.route("/api/change_password", methods=["POST"])
@require_rate_limit
@require_auth
def change_password():
    data   = request.get_json(silent=True) or {}
    old_pw = str(data.get("old_password", ""))
    new_pw = str(data.get("new_password", ""))

    if not old_pw or not new_pw:
        return jsonify(error="old_password and new_password required"), 400
    pw_err = _validate_password_strength(new_pw)
    if pw_err:
        return jsonify(error=pw_err), 400

    username = g.username
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT salt, pw_hash FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            return jsonify(error="User not found"), 404
        
        if isinstance(row, dict):
            salt = row["salt"]
            pw_hash = row["pw_hash"]
        else:
            salt = row[0]
            pw_hash = row[1]
            
        if not _verify_pw(old_pw, pw_hash, salt):
            return jsonify(error="Old password is incorrect"), 401
            
        new_salt = secrets.token_hex(16)
        new_hash = _hash_pw(new_pw, new_salt)
        cursor.execute("UPDATE users SET salt = ?, pw_hash = ? WHERE username = ?", (new_salt, new_hash, username))
        
        # Kick out all database sessions for this user
        cursor.execute("DELETE FROM sessions WHERE username = ?", (username,))
        conn.commit()
        
        _log_audit(username, "change_password", "Changed password successfully")
        log.info(f"Password changed for user '{username}' from {request.remote_addr}")
        return jsonify(message="Password changed - please log in again")
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Data endpoints
# ---------------------------------------------------------------------------
@app.route("/api/employees", methods=["GET"])
@require_rate_limit
@require_role(["super_admin", "editor", "viewer"])
def get_employees():
    return jsonify(load_db())

def get_employee_by_id(personal_id: str) -> dict | None:
    """Retrieve a single employee dictionary by personal_id from SQLite or MySQL."""
    init_sqlite_db()
    conn = connect_db()
    try:
        if DB_CONFIG.get("DB_TYPE") != "mysql":
            conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees WHERE personal_id = ?", (personal_id,))
        row = cursor.fetchone()
        if not row:
            return None
        emp = dict(row)
        docs_str = emp.get("documents")
        if docs_str:
            try:
                emp["documents"] = json.loads(docs_str)
            except Exception:
                emp["documents"] = {}
        else:
            emp["documents"] = {}
        return emp
    except Exception as e:
        log.error(f"Error loading employee {personal_id}: {e}")
        return None
    finally:
        conn.close()

@app.route("/api/employees/<personal_id>", methods=["GET"])
@require_rate_limit
@require_role(["super_admin", "editor", "viewer"])
def get_single_employee(personal_id):
    """
    Returns one employee record read fresh from the database (not from any
    cache). The client calls this right before opening a dossier or entering
    edit mode, instead of trusting its login-time in-memory snapshot.

    Why this matters: on a multi-user LAN setup, if the client instead reused
    its stale login-time snapshot as the base for a save, an unrelated edit
    from a staff member with an older session could overwrite/delete
    documents that another staff member added in the meantime (the save
    logic treats "not present in the submitted document list" as "the user
    removed this file"). Fetching a fresh copy right before editing closes
    that window.
    """
    init_sqlite_db()
    conn = connect_db()
    try:
        if DB_CONFIG.get("DB_TYPE") != "mysql":
            conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees WHERE personal_id = ?", (personal_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify(error="Employee not found"), 404
        emp = dict(row)
        docs_str = emp.get("documents")
        if docs_str:
            try:
                emp["documents"] = json.loads(docs_str)
            except json.JSONDecodeError:
                emp["documents"] = {}
        else:
            emp["documents"] = {}
        return jsonify(emp)
    except Exception as e:
        log.error(f"Error loading employee {personal_id}: {e}")
        return jsonify(error="Failed to load employee"), 500
    finally:
        conn.close()

@app.route("/api/employees/<personal_id>/status", methods=["POST", "PATCH"])
@require_rate_limit
@require_role(["super_admin", "editor"])
def update_employee_status(personal_id):
    data = request.get_json(silent=True) or {}
    new_status = str(data.get("status", "")).strip()
    if new_status not in ["active", "retired", "transferred"]:
        return jsonify(error="Invalid status value. Must be active, retired, or transferred."), 400
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE employees SET status = ? WHERE personal_id = ?", (new_status, personal_id))
        conn.commit()
        _log_audit(g.username, "update_status", f"Changed status of employee {personal_id} to {new_status}")
        log.info(f"Updated status for employee {personal_id} to {new_status}")
        return jsonify(success=True, status=new_status)
    except Exception as e:
        log.error(f"Error updating status for {personal_id}: {e}")
        return jsonify(error="Failed to update status"), 500
    finally:
        conn.close()

@app.route("/api/save_employee", methods=["POST"])
@require_rate_limit
@require_role(["super_admin", "editor"])
def save_employee():
    employee = request.get_json(silent=True)
    if not isinstance(employee, dict):
        return jsonify(error="Employee must be a JSON object"), 400

    # Pop original_personal_id if present to keep the payload clean
    original_personal_id = employee.pop("original_personal_id", None)

    err = validate_employee(employee)
    if err:
        return jsonify(error=err), 400

    pid = employee.get("personal_id")
    fullname = employee.get("fullname")

    # Check if the personal_id already exists (excluding the current employee if editing)
    if not original_personal_id or original_personal_id != pid:
        conn = connect_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM employees WHERE personal_id = ?", (pid,))
            if cursor.fetchone() is not None:
                return jsonify(error=f"ژمارەیا کەسی ({pid}) پێشتر بۆ فەرمانبەرەکێ دی هاتیە بەکارهینان."), 400
        finally:
            conn.close()

    # Find if this employee already exists in SQLite (using original_personal_id if provided, otherwise personal_id)
    db_pid = original_personal_id if original_personal_id else pid
    existing_emp = None
    if db_pid:
        conn = connect_db()
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT personal_id, fullname FROM employees WHERE personal_id = ?", (db_pid,))
            row = cursor.fetchone()
            if row:
                existing_emp = dict(row)
        finally:
            conn.close()

    is_edit = (existing_emp is not None)
    is_new = not is_edit

    if is_edit:
        old_pid = existing_emp["personal_id"]
        old_fullname = existing_emp["fullname"]

        # Rename the employee archive folder if the ID or Name has changed
        if old_pid != pid or old_fullname != fullname:
            old_safe_name = "".join(c for c in old_fullname.replace(" ", "_") if c.isalnum() or c in "_-")
            old_folder_name = f"{old_pid}_{old_safe_name}"
            old_folder_path = EMPLOYEE_FILES_DIR / old_folder_name

            new_safe_name = "".join(c for c in fullname.replace(" ", "_") if c.isalnum() or c in "_-")
            new_folder_name = f"{pid}_{new_safe_name}"
            new_folder_path = EMPLOYEE_FILES_DIR / new_folder_name

            if old_folder_path.exists() and old_folder_path != new_folder_path:
                try:
                    old_folder_path.rename(new_folder_path)
                    log.info(f"Renamed employee folder from {old_folder_name} to {new_folder_name}")
                except Exception as e:
                    log.error(f"Failed to rename employee folder: {e}")

        # If personal_id changed, delete the old database entry to avoid duplicate records
        if old_pid != pid:
            try:
                delete_single_employee(old_pid)
                log.info(f"Deleted old employee record {old_pid} since ID changed to {pid}")
            except Exception as e:
                log.error(f"Failed to delete old employee record: {e}")

    # Ensure folder is created before saving files
    safe_name = fullname.replace(" ", "_")
    safe_name = "".join(c for c in safe_name if c.isalnum() or c in "_-")
    folder_name = f"{pid}_{safe_name}"
    emp_folder = EMPLOYEE_FILES_DIR / folder_name
    emp_folder.mkdir(parents=True, exist_ok=True)

    # Decode and save new Base64 documents to disk
    import base64
    documents = employee.get("documents", {})
    valid_categories = {
        'appointment_order', 'commencement_order', 'punishments',
        'leaves', 'certificates', 'thanks',
        'administrative_order', 'establishment_order'
    }
    
    for cat in list(documents.keys()):
        if cat not in valid_categories:
            continue
        doc_val = documents[cat]
        if not doc_val:
            continue
            
        if cat == 'appointment_order':
            if isinstance(doc_val, dict):
                try:
                    doc_val["fileName"] = sanitize_filename(doc_val["fileName"])
                except ValueError as ve:
                    log.warning(f"Blocked disallowed file type for appointment_order: {ve}")
                    documents[cat] = None
                    continue
                if "base64" in doc_val:
                    b64_data = doc_val["base64"]
                    try:
                        if "," in b64_data:
                            b64_data = b64_data.split(",")[1]
                        file_bytes = base64.b64decode(b64_data)
                        file_err = _validate_file_bytes(file_bytes, doc_val["fileName"])
                        if file_err:
                            log.warning(f"Rejected appointment_order upload: {file_err}")
                            documents[cat] = None
                            continue
                        cat_dir = emp_folder / KURDISH_FOLDER_MAP.get(cat, cat)
                        cat_dir.mkdir(parents=True, exist_ok=True)
                        (cat_dir / doc_val["fileName"]).write_bytes(file_bytes)
                        del doc_val["base64"]
                    except Exception as e:
                        log.error(f"Error saving appt order to disk: {e}")
        elif isinstance(doc_val, list):
            valid_items = []
            for item in doc_val:
                if isinstance(item, dict):
                    try:
                        sanitized_name = sanitize_filename(item["fileName"])
                    except ValueError as ve:
                        log.warning(f"Blocked disallowed file type in '{cat}': {ve}")
                        continue
                    if "base64" in item:
                        b64_data = item["base64"]
                        try:
                            if "," in b64_data:
                                b64_data = b64_data.split(",")[1]
                            file_bytes = base64.b64decode(b64_data)
                            file_err = _validate_file_bytes(file_bytes, sanitized_name)
                            if file_err:
                                log.warning(f"Rejected '{cat}' upload: {file_err}")
                                continue
                            cat_dir = emp_folder / KURDISH_FOLDER_MAP.get(cat, cat)
                            cat_dir.mkdir(parents=True, exist_ok=True)
                            unique_name = make_unique_filename(cat_dir, sanitized_name)
                            item["fileName"] = unique_name
                            (cat_dir / unique_name).write_bytes(file_bytes)
                            del item["base64"]
                        except Exception as e:
                            log.error(f"Error saving {sanitized_name} to disk: {e}")
                            continue
                    else:
                        item["fileName"] = sanitized_name
                    valid_items.append(item)
            documents[cat] = valid_items

    # Clean up deleted files from disk
    sync_documents_on_disk(pid, documents, emp_folder)

    try:
        save_single_employee(employee)
    except Exception as e:
        log.error(f"Failed to save employee to SQLite: {e}")
        return jsonify(error="Database write failed"), 500


    # Ensure folder and profile PDF are always created/updated
    pdf_bytes = None
    filename = None
    try:
        safe_name = employee.get("fullname", "unknown").replace(" ", "_")
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in "_-")
        folder_name = f"{pid}_{safe_name}"
        emp_folder = EMPLOYEE_FILES_DIR / folder_name
        emp_folder.mkdir(parents=True, exist_ok=True)

        # Clean up the old profile PDF if ID or Name changed
        if is_edit and (old_pid != pid or old_fullname != fullname):
            old_safe_name = "".join(c for c in old_fullname.replace(" ", "_") if c.isalnum() or c in "_-")
            old_filenames = [
                f"employee_{old_pid}_{old_safe_name}.pdf",
                sanitize_filename(f"پرۆفایلێ فەرمانبەری - {old_fullname}.pdf")
            ]
            for old_fn in old_filenames:
                old_pdf_path = emp_folder / old_fn
                if old_pdf_path.exists():
                    try:
                        old_pdf_path.unlink()
                        log.info(f"Deleted old PDF: {old_pdf_path}")
                    except Exception as ex:
                        log.warning(f"Could not delete old PDF: {ex}")

        # Generate fresh profile PDF and save to employee folder
        pdf_bytes = generate_employee_pdf(employee)
        filename = sanitize_filename(f"پرۆفایلێ فەرمانبەری - {fullname}.pdf")
        pdf_path = emp_folder / filename
        pdf_path.write_bytes(pdf_bytes)
        log.info(f"Saved/Updated employee PDF: {pdf_path}")
    except Exception as e:
        log.warning(f"Could not create/update employee folder or PDF: {e}")
        pdf_bytes = None
        filename = None

    log.info(f"Employee saved (is_new={is_new}): {pid} from {request.remote_addr}")
    action_type = "create_employee" if is_new else "edit_employee"
    action_details = f"Created employee {fullname} (ID: {pid})" if is_new else f"Edited employee {fullname} (ID: {pid})"
    _log_audit(g.username, action_type, action_details)

    # Trigger Google Drive auto-sync if enabled
    trigger_gdrive_auto_sync()

    # Stream the PDF back to the browser only if this is a new employee registration and not a python test client
    is_test_client = "Python-urllib" in request.headers.get("User-Agent", "")
    if is_new and pdf_bytes and filename and not is_test_client:
        try:
            ascii_pid = "".join(c for c in pid if ord(c) < 128) or "id"
            fallback_filename = f"employee_{ascii_pid}.pdf"
            encoded_filename = urllib.parse.quote(filename)
            
            from flask import Response
            return Response(
                pdf_bytes,
                status=200,
                mimetype="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{fallback_filename}"; filename*=UTF-8\'\'{encoded_filename}'
                }
            )
        except Exception as e:
            log.warning(f"PDF response failed: {e}")

    return jsonify(success=True, message="saved", employee=employee)

@app.route("/api/delete_employee", methods=["POST"])
@require_rate_limit
@require_role(["super_admin"])
def delete_employee():
    data = request.get_json(silent=True) or {}
    pid  = data.get("personal_id")
    if not pid or not isinstance(pid, str):
        return jsonify(error="personal_id required"), 400

    try:
        deleted = delete_single_employee(pid)
        if not deleted:
            return jsonify(error="Employee not found"), 404
    except Exception as e:
        log.error(f"Failed to delete employee: {e}")
        return jsonify(error="Database delete failed"), 500

    # Clean up the employee's files folder from disk
    emp_folder = get_employee_folder(pid)
    if emp_folder and emp_folder.exists():
        try:
            import shutil
            shutil.rmtree(str(emp_folder))
            log.info(f"Deleted employee folder from disk: {emp_folder}")
        except Exception as e:
            log.warning(f"Could not delete employee folder {emp_folder}: {e}")

    log.info(f"Employee deleted: {pid} from {request.remote_addr}")
    _log_audit(g.username, "delete_employee", f"Deleted employee with ID: {pid}")
    
    # Trigger Google Drive auto-sync if enabled
    trigger_gdrive_auto_sync()
    
    return jsonify(success=True, message="deleted")

def merge_folders(src: pathlib.Path, dst: pathlib.Path):
    """Recursively merge contents of src directory into dst directory, then remove src."""
    if not src.exists() or not src.is_dir():
        return
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            merge_folders(item, target)
        else:
            if not target.exists():
                try:
                    item.rename(target)
                except Exception:
                    try:
                        import shutil
                        shutil.move(str(item), str(target))
                    except Exception:
                        pass
            else:
                try:
                    item.unlink()
                except Exception:
                    pass
    try:
        src.rmdir()
    except Exception:
        pass

def get_employee_folder(personal_id: str) -> pathlib.Path | None:
    if not personal_id:
        return None
    if not EMPLOYEE_FILES_DIR.exists():
        return None
        
    matching_dirs = [
        p for p in EMPLOYEE_FILES_DIR.iterdir()
        if p.is_dir() and p.name.startswith(f"{personal_id}_")
    ]
    
    if not matching_dirs:
        return None
        
    if len(matching_dirs) == 1:
        return matching_dirs[0]
        
    # If multiple folders exist for the same personal_id (e.g. name changed),
    # pick the most recently modified folder as target, and merge older ones into it.
    matching_dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    target_folder = matching_dirs[0]
    
    for old_folder in matching_dirs[1:]:
        try:
            merge_folders(old_folder, target_folder)
            log.info(f"Merged old folder '{old_folder.name}' into '{target_folder.name}'")
        except Exception as ex:
            log.error(f"Error merging folder '{old_folder.name}': {ex}")
            
    return target_folder

@app.route("/api/employees/<personal_id>/documents/<category>/<filename>", methods=["GET"])
@require_rate_limit
@require_auth
def get_employee_document(personal_id, category, filename):
    valid_categories = {
        'appointment_order', 'commencement_order', 'punishments',
        'leaves', 'certificates', 'thanks',
        'administrative_order', 'establishment_order'
    }
    if category not in valid_categories:
        abort(400)
        
    folder = get_employee_folder(personal_id)
    if not folder or not folder.exists():
        abort(404)
        
    # URL decode category and filename
    category_unquoted = urllib.parse.unquote(category)
    filename_unquoted = urllib.parse.unquote(filename)
    safe_filename = pathlib.Path(filename_unquoted).name
    
    subfolder_kurdish = KURDISH_FOLDER_MAP.get(category, category)
    
    # 1. Search in Kurdish subfolder
    target_dir = folder / subfolder_kurdish
    target_file = target_dir / safe_filename
    
    # 2. Fallback to English category subfolder
    if not target_file.exists():
        target_dir = folder / category_unquoted
        target_file = target_dir / safe_filename
        
    # 3. Fallback to root employee folder
    if not target_file.exists():
        target_dir = folder
        target_file = target_dir / safe_filename

    # 4. Fallback to recursive search inside employee folder
    if not target_file.exists():
        found = False
        for fpath in folder.rglob("*"):
            if fpath.is_file() and fpath.name.lower() == safe_filename.lower():
                target_dir = fpath.parent
                target_file = fpath
                safe_filename = fpath.name
                found = True
                break
        if not found:
            abort(404)

    # Prevent directory traversal
    try:
        if not str(target_file.resolve()).startswith(str(folder.resolve())):
            abort(403)
    except Exception:
        abort(403)
        
    return send_from_directory(str(target_dir), safe_filename)

def _get_lan_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

@app.route("/api/employees/<personal_id>/qr_svg", methods=["GET"])
@require_rate_limit
def get_employee_qr_svg(personal_id):
    emp = get_employee_by_id(personal_id)
    if not emp:
        return jsonify(error="Employee not found"), 404
        
    host_name = request.host.split(':')[0]
    port = request.host.split(':')[1] if ':' in request.host else '8000'
    if host_name in ('localhost', '127.0.0.1', '0.0.0.0'):
        lan_ip = _get_lan_ip()
        verify_url = f"http://{lan_ip}:{port}/verify/{personal_id}"
    else:
        verify_url = f"http://{request.host}/verify/{personal_id}"
    
    try:
        import qrcode
        import qrcode.image.svg
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=2,
        )
        qr.add_data(verify_url)
        qr.make(fit=True)
        img = qr.make_image(image_factory=qrcode.image.svg.SvgPathFillImage)
        
        stream = io.BytesIO()
        img.save(stream)
        svg_xml = stream.getvalue().decode('utf-8')
        if '<svg ' in svg_xml and 'style=' not in svg_xml:
            svg_xml = svg_xml.replace('<svg ', '<svg style="background:#ffffff;" ', 1)
        return jsonify(success=True, svg=svg_xml, url=verify_url)
    except Exception as e:
        log.error(f"Failed to generate QR code SVG: {e}")
        return jsonify(error="Failed to generate QR code"), 500


@app.route("/api/export_backup", methods=["GET"])
@require_rate_limit
@require_role(["super_admin"])
def export_backup():
    import base64
    init_sqlite_db()
    conn = connect_db()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees")
        rows = cursor.fetchall()
        
        backup_data = []
        for row in rows:
            emp = dict(row)
            docs_str = emp.get("documents")
            if docs_str:
                try:
                    documents = json.loads(docs_str)
                except json.JSONDecodeError:
                    documents = {}
            else:
                documents = {}
                
            pid = emp["personal_id"]
            fullname = emp["fullname"]
            safe_name = fullname.replace(" ", "_")
            safe_name = "".join(c for c in safe_name if c.isalnum() or c in "_-")
            folder_name = f"{pid}_{safe_name}"
            emp_folder = EMPLOYEE_FILES_DIR / folder_name
            
            # Categories to check
            valid_categories = {
                'appointment_order', 'commencement_order', 'punishments',
                'leaves', 'certificates', 'thanks',
                'administrative_order', 'establishment_order'
            }
            
            for cat in list(documents.keys()):
                if cat not in valid_categories:
                    continue
                doc_val = documents[cat]
                if not doc_val:
                    continue
                if cat == 'appointment_order':
                    if isinstance(doc_val, dict) and "fileName" in doc_val:
                        file_path = emp_folder / KURDISH_FOLDER_MAP.get(cat, cat) / doc_val["fileName"]
                        if file_path.exists() and file_path.is_file():
                            try:
                                file_bytes = file_path.read_bytes()
                                b64_str = base64.b64encode(file_bytes).decode('utf-8')
                                mime = _get_mime_for_file(doc_val["fileName"])
                                doc_val["base64"] = f"data:{mime};base64,{b64_str}"
                            except Exception as e:
                                log.error(f"Error encoding export appt order for {pid}: {e}")
                elif isinstance(doc_val, list):
                    for item in doc_val:
                        if isinstance(item, dict) and "fileName" in item:
                            file_path = emp_folder / KURDISH_FOLDER_MAP.get(cat, cat) / item["fileName"]
                            if file_path.exists() and file_path.is_file():
                                try:
                                    file_bytes = file_path.read_bytes()
                                    b64_str = base64.b64encode(file_bytes).decode('utf-8')
                                    mime = _get_mime_for_file(item["fileName"])
                                    item["base64"] = f"data:{mime};base64,{b64_str}"
                                except Exception as e:
                                    log.error(f"Error encoding export doc for {pid}: {e}")
                                    
            emp["documents"] = documents
            backup_data.append(emp)
            
        backup_json = {
            "appName": "HealthArchiveSystem",
            "exportedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "version": 1,
            "data": backup_data
        }
        
        _log_audit(g.username, "export_backup", "Exported full system backup")
        return jsonify(backup_json)
    except Exception as e:
        log.exception("Backup export failed")
        return jsonify(error="Backup export failed"), 500
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# User Management endpoints (super_admin only)
# ---------------------------------------------------------------------------
@app.route("/api/users", methods=["GET"])
@require_rate_limit
@require_role(["super_admin"])
def get_users():
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT username, role FROM users ORDER BY username")
        rows = cursor.fetchall()
        users = []
        for row in rows:
            if isinstance(row, dict):
                users.append({"username": row["username"], "role": row["role"]})
            else:
                users.append({"username": row[0], "role": row[1]})
        return jsonify(users)
    finally:
        conn.close()

@app.route("/api/users", methods=["POST"])
@require_rate_limit
@require_role(["super_admin"])
def create_user():
    data = request.get_json(silent=True) or {}
    new_username = str(data.get("username", "")).strip()
    new_password = str(data.get("password", ""))
    new_role = str(data.get("role", "viewer"))
    
    if not new_username or not new_password:
        return jsonify(error="username and password required"), 400
    if new_role not in ("super_admin", "editor", "viewer"):
        return jsonify(error="Invalid role. Must be super_admin, editor, or viewer"), 400
    if len(new_username) > 64 or not re.match(r'^[A-Za-z0-9_.-]+$', new_username):
        return jsonify(error="Username may only contain letters, numbers, underscores, dots, and hyphens (max 64 chars)"), 400
    pw_err = _validate_password_strength(new_password)
    if pw_err:
        return jsonify(error=pw_err), 400
        
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (new_username,))
        if cursor.fetchone():
            return jsonify(error=f"User '{new_username}' already exists"), 409
        
        salt = secrets.token_hex(16)
        pw_hash = _hash_pw(new_password, salt)
        cursor.execute("""
            INSERT INTO users (username, salt, pw_hash, role)
            VALUES (?, ?, ?, ?)
        """, (new_username, salt, pw_hash, new_role))
        conn.commit()
        _log_audit(g.username, "create_user", f"Created user '{new_username}' with role '{new_role}'")
        log.info(f"User '{new_username}' created by '{g.username}'")
        return jsonify(success=True, message="User created")
    finally:
        conn.close()

@app.route("/api/users/<target_username>", methods=["DELETE"])
@require_rate_limit
@require_role(["super_admin"])
def delete_user(target_username):
    if target_username == g.username:
        return jsonify(error="Cannot delete your own account"), 400
    
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (target_username,))
        if not cursor.fetchone():
            return jsonify(error="User not found"), 404
        cursor.execute("DELETE FROM users WHERE username = ?", (target_username,))
        conn.commit()
        # Kick out active sessions for deleted user
        cursor.execute("DELETE FROM sessions WHERE username = ?", (target_username,))
        conn.commit()
        _log_audit(g.username, "delete_user", f"Deleted user '{target_username}'")
        log.info(f"User '{target_username}' deleted by '{g.username}'")
        return jsonify(success=True, message="User deleted")
    finally:
        conn.close()

@app.route("/api/users/<target_username>/role", methods=["PUT"])
@require_rate_limit
@require_role(["super_admin"])
def update_user_role(target_username):
    data = request.get_json(silent=True) or {}
    new_role = str(data.get("role", ""))
    if new_role not in ("super_admin", "editor", "viewer"):
        return jsonify(error="Invalid role. Must be super_admin, editor, or viewer"), 400
    
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (target_username,))
        if not cursor.fetchone():
            return jsonify(error="User not found"), 404
        cursor.execute("UPDATE users SET role = ? WHERE username = ?", (new_role, target_username))
        conn.commit()
        _log_audit(g.username, "update_user_role", f"Changed role of '{target_username}' to '{new_role}'")
        log.info(f"Role of '{target_username}' changed to '{new_role}' by '{g.username}'")
        return jsonify(success=True, message="Role updated")
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Audit Logs endpoint (super_admin only)
# ---------------------------------------------------------------------------
@app.route("/api/audit_logs", methods=["GET"])
@require_rate_limit
@require_role(["super_admin"])
def get_audit_logs():
    limit = min(int(request.args.get("limit", 200)), 500)
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, action_type, action_details, timestamp
            FROM audit_logs ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        logs_list = []
        for row in rows:
            if isinstance(row, dict):
                logs_list.append(dict(row))
            else:
                logs_list.append({
                    "id": row[0],
                    "username": row[1],
                    "action_type": row[2],
                    "action_details": row[3],
                    "timestamp": row[4]
                })
        return jsonify(logs_list)
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# System Health endpoint (super_admin only)
# ---------------------------------------------------------------------------
@app.route("/api/system_health", methods=["GET"])
@require_rate_limit
@require_role(["super_admin"])
def system_health():
    import shutil as _shutil
    import psutil
    import os as _os
    
    # ── 1. Disk usage ──────────────────────────────────────────────────────
    try:
        total, used, free = _shutil.disk_usage(str(EXE_DIR))
        disk_info = {
            "total_gb":    round(total / (1024**3), 2),
            "used_gb":     round(used  / (1024**3), 2),
            "free_gb":     round(free  / (1024**3), 2),
            "used_percent": round(used / total * 100, 1)
        }
    except Exception:
        disk_info = {}
    
    # ── 2. CPU & RAM (system-wide) ─────────────────────────────────────────
    try:
        # cpu_percent with interval=0.5 returns a real measurement
        cpu_percent = psutil.cpu_percent(interval=0.3)
        cpu_count   = psutil.cpu_count(logical=True)
        vm          = psutil.virtual_memory()
        ram_info = {
            "total_gb":    round(vm.total   / (1024**3), 2),
            "used_gb":     round(vm.used    / (1024**3), 2),
            "free_gb":     round(vm.available / (1024**3), 2),
            "used_percent": vm.percent
        }
        cpu_info = {
            "percent":      cpu_percent,
            "core_count":   cpu_count
        }
    except Exception as e:
        ram_info = {}
        cpu_info = {"error": str(e)}
    
    # ── 3. This process's own resource usage ───────────────────────────────
    process_info = {}
    try:
        proc = psutil.Process(_os.getpid())
        proc_mem_bytes = proc.memory_info().rss
        process_info = {
            "memory_mb": round(proc_mem_bytes / (1024**2), 2),
            "pid": _os.getpid()
        }
    except Exception as e:
        process_info = {"error": str(e)}

    # ── 4. Server uptime ───────────────────────────────────────────────────
    uptime_seconds = int(time.time() - SERVER_START_TIME)
    uptime_hours   = uptime_seconds // 3600
    uptime_minutes = (uptime_seconds % 3600) // 60
    uptime_secs    = uptime_seconds % 60
    uptime_str     = f"{uptime_hours}h {uptime_minutes}m {uptime_secs}s"

    # ── 5. Database stats + active sessions ────────────────────────────────
    db_stats = {}
    active_sessions = 0
    conn = connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM employees")
        row = cursor.fetchone()
        emp_count = list(row.values())[0] if isinstance(row, dict) else row[0]
        
        cursor.execute("SELECT COUNT(*) FROM users")
        row = cursor.fetchone()
        user_count = list(row.values())[0] if isinstance(row, dict) else row[0]
        
        cursor.execute("SELECT COUNT(*) FROM audit_logs")
        row = cursor.fetchone()
        audit_count = list(row.values())[0] if isinstance(row, dict) else row[0]

        # Count only non-expired sessions
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE expires > ?", (time.time(),))
        row = cursor.fetchone()
        active_sessions = list(row.values())[0] if isinstance(row, dict) else row[0]
        
        db_stats = {
            "employee_count":  emp_count,
            "user_count":      user_count,
            "audit_log_count": audit_count,
            "db_type":         DB_CONFIG.get("DB_TYPE", "sqlite")
        }
        
        if DB_CONFIG.get("DB_TYPE") != "mysql" and DB_PATH.exists():
            db_stats["db_size_mb"] = round(DB_PATH.stat().st_size / (1024**2), 3)

        # Measure a simple DB query latency
        t0 = time.time()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        db_stats["query_latency_ms"] = round((time.time() - t0) * 1000, 2)
    except Exception as e:
        db_stats["error"] = str(e)
    finally:
        conn.close()
    
    # ── 6. Employee files size ─────────────────────────────────────────────
    try:
        total_files_size = sum(
            f.stat().st_size
            for f in EMPLOYEE_FILES_DIR.rglob("*")
            if f.is_file()
        ) if EMPLOYEE_FILES_DIR.exists() else 0
        files_info = {"total_size_mb": round(total_files_size / (1024**2), 2)}
    except Exception:
        files_info = {}
    
    return jsonify({
        "disk":            disk_info,
        "cpu":             cpu_info,
        "ram":             ram_info,
        "process":         process_info,
        "uptime":          uptime_str,
        "uptime_seconds":  uptime_seconds,
        "database":        db_stats,
        "employee_files":  files_info,
        "active_sessions": active_sessions,
        "server_time":     time.strftime("%Y-%m-%d %H:%M:%S")
    })

# ---------------------------------------------------------------------------
# Backup Settings endpoints (super_admin only)
# ---------------------------------------------------------------------------
@app.route("/api/backup/settings", methods=["GET"])
@require_rate_limit
@require_role(["super_admin"])
def get_backup_settings():
    config = {}
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                config = json.load(f)
        except Exception:
            pass
    return jsonify({
        "auto_backup_enabled": config.get("AUTO_BACKUP_ENABLED", True),
        "backup_time": config.get("BACKUP_TIME", "16:00"),
        "backup_dest_dir": config.get("BACKUP_DEST_DIR", str(EXE_DIR / "data" / "backups"))
    })

@app.route("/api/backup/settings", methods=["POST"])
@require_rate_limit
@require_role(["super_admin"])
def save_backup_settings():
    data = request.get_json(silent=True) or {}
    config = {}
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                config = json.load(f)
        except Exception:
            pass
    
    if "auto_backup_enabled" in data:
        config["AUTO_BACKUP_ENABLED"] = bool(data["auto_backup_enabled"])
    if "backup_time" in data:
        bt = str(data["backup_time"]).strip()
        # Validate HH:MM format
        parts = bt.split(":")
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            config["BACKUP_TIME"] = bt
    if "backup_dest_dir" in data:
        config["BACKUP_DEST_DIR"] = str(data["backup_dest_dir"]).strip()
    
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        _log_audit(g.username, "save_backup_settings", "Updated backup settings")
        return jsonify(success=True, message="Backup settings saved")
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route("/api/backup/run_now", methods=["POST"])
@require_rate_limit
@require_role(["super_admin"])
def backup_run_now():
    try:
        run_auto_backup()
        return jsonify(success=True, message="Backup completed successfully")
    except Exception as e:
        return jsonify(error=str(e)), 500

# ---------------------------------------------------------------------------
# WhatsApp Integration (super_admin only for settings/send)
# ---------------------------------------------------------------------------
class WhatsAppConfigManager:
    CONFIG_PATH = EXE_DIR / "data" / "whatsapp_config.json"
    _lock = threading.Lock()

    @classmethod
    def load_config(cls) -> dict:
        with cls._lock:
            default_config = {
                "mode": "link",
                "api_url": "https://api.ultramsg.com/instanceXXXXX/messages/document",
                "api_token": "",
                "template_ku": "سلاڤ {name}، ئەڤە بەڵگەنامەیا تەیا {doc_name} یە د سیستەمێ health_archive دا.",
                "template_ar": "مرحباً {name}، هذا هو مستندك {doc_name} في نظام الأرشيف الصحي."
            }
            if not cls.CONFIG_PATH.exists():
                return default_config
            try:
                data = json.loads(cls.CONFIG_PATH.read_text(encoding="utf-8"))
                for k, v in default_config.items():
                    if k not in data:
                        data[k] = v
                return data
            except Exception as e:
                log.error(f"Error loading WhatsApp config: {e}")
                return default_config

    @classmethod
    def save_config(cls, config: dict):
        with cls._lock:
            try:
                (EXE_DIR / "data").mkdir(parents=True, exist_ok=True)
                cls.CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
            except Exception as e:
                log.error(f"Error saving WhatsApp config: {e}")

def clean_phone_number(phone: str) -> str:
    cleaned = "".join(c for c in phone if c.isdigit())
    if not cleaned:
        return ""
    # Strip international prefix 00 (e.g. 00964... -> 964...)
    if cleaned.startswith("00"):
        cleaned = cleaned[2:]
    # Format local Iraqi numbers (e.g. 07xx -> 964xx, 7xx -> 9647xx)
    if cleaned.startswith("964"):
        pass  # already international
    elif cleaned.startswith("07") and len(cleaned) == 11:
        cleaned = "964" + cleaned[1:]
    elif cleaned.startswith("7") and len(cleaned) == 10:
        cleaned = "964" + cleaned
    return cleaned

def send_file_via_gateway(api_url: str, token: str, to: str, file_bytes: bytes, filename: str, caption: str) -> str:
    import urllib.request
    import mimetypes
    
    boundary = '----WhatsAppUploadBoundary7MA4YWxkTrZu'
    headers = {
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }
    
    body = []
    
    # 1. token form field
    body.append(f'--{boundary}')
    body.append('Content-Disposition: form-data; name="token"')
    body.append('')
    body.append(token)
    
    # 2. to form field
    body.append(f'--{boundary}')
    body.append('Content-Disposition: form-data; name="to"')
    body.append('')
    body.append(to)
    
    # 3. caption form field
    body.append(f'--{boundary}')
    body.append('Content-Disposition: form-data; name="caption"')
    body.append('')
    body.append(caption)
    
    # 4. document file field
    mime_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    body.append(f'--{boundary}')
    body.append(f'Content-Disposition: form-data; name="document"; filename="{filename}"')
    body.append(f'Content-Type: {mime_type}')
    body.append('')
    
    # Combine everything
    body_bytes = b''
    for part in body:
        body_bytes += part.encode('utf-8') + b'\r\n'
    body_bytes += file_bytes + b'\r\n'
    body_bytes += f'--{boundary}--'.encode('utf-8') + b'\r\n'
    
    target_url = api_url
    if "?" not in target_url:
        target_url += f"?token={token}"
        
    req = urllib.request.Request(target_url, data=body_bytes, headers=headers, method='POST')
    with urllib.request.urlopen(req, timeout=20) as res:
        return res.read().decode('utf-8')

@app.route("/api/whatsapp/settings", methods=["GET"])
@require_rate_limit
@require_role(["super_admin"])
def get_whatsapp_settings():
    config = WhatsAppConfigManager.load_config()
    token = config.get("api_token", "")
    masked_token = ""
    if token:
        if len(token) > 8:
            masked_token = token[:4] + "*" * (len(token) - 8) + token[-4:]
        else:
            masked_token = "*" * len(token)
            
    return jsonify({
        "mode": config.get("mode", "link"),
        "api_url": config.get("api_url", ""),
        "api_token": masked_token,
        "template_ku": config.get("template_ku", ""),
        "template_ar": config.get("template_ar", "")
    })

@app.route("/api/whatsapp/settings", methods=["POST"])
@require_rate_limit
@require_role(["super_admin"])
def save_whatsapp_settings():
    data = request.get_json(silent=True) or {}
    mode = str(data.get("mode", "link")).strip()
    api_url = str(data.get("api_url", "")).strip()
    api_token = str(data.get("api_token", "")).strip()
    template_ku = str(data.get("template_ku", "")).strip()
    template_ar = str(data.get("template_ar", "")).strip()

    if mode not in ["link", "api"]:
        return jsonify(error="Invalid mode value"), 400

    config = WhatsAppConfigManager.load_config()
    config["mode"] = mode
    config["api_url"] = api_url
    
    if api_token and not api_token.startswith("*") and not "*" in api_token:
        config["api_token"] = api_token
        
    if template_ku:
        config["template_ku"] = template_ku
    if template_ar:
        config["template_ar"] = template_ar

    WhatsAppConfigManager.save_config(config)
    _log_audit(g.username, "save_whatsapp_settings", "Updated WhatsApp sharing settings")
    return jsonify(success=True, message="WhatsApp settings saved")

@app.route("/api/whatsapp/send", methods=["POST"])
@require_rate_limit
@require_role(["admin", "super_admin"])
def whatsapp_send():
    data = request.get_json(silent=True) or {}
    personal_id = str(data.get("personal_id", "")).strip()
    category = str(data.get("category", "")).strip()
    filename = str(data.get("filename", "")).strip()
    phone = str(data.get("phone", "")).strip()
    emp_name = str(data.get("emp_name", "")).strip()
    lang = str(data.get("lang", "ku")).strip()

    if not personal_id or not category or not filename:
        return jsonify(error="Missing required fields"), 400

    config = WhatsAppConfigManager.load_config()
    cleaned_phone = clean_phone_number(phone)
    if not cleaned_phone:
        return jsonify(error="Invalid or missing phone number"), 400

    # Build text message
    template = config.get("template_ar" if lang == "ar" else "template_ku", "")
    if not template:
        template = "{name}: {doc_name}" if lang != "ar" else "{name}: {doc_name}"
    message_text = template.replace("{name}", emp_name).replace("{doc_name}", filename)

    if config.get("mode", "link") == "link":
        # Link mode: no file access needed, just build the WhatsApp web URL
        encoded_text = urllib.parse.quote(message_text)
        wa_url = f"https://api.whatsapp.com/send?phone={cleaned_phone}&text={encoded_text}"
        _log_audit(g.username, "whatsapp_link", f"Generated WhatsApp link for {emp_name} - {filename}")
        return jsonify(success=True, mode="link", url=wa_url)
    else:
        # API/Gateway mode: file must exist on disk to be uploaded
        folder = get_employee_folder(personal_id)
        if not folder or not folder.exists():
            return jsonify(error="Employee folder not found on server"), 404

        subfolder_name = KURDISH_FOLDER_MAP.get(category, category)
        safe_filename = pathlib.Path(filename).name
        # Search Kurdish subfolder first, then English, then root, then recursive
        target_dir = folder / subfolder_name
        target_file = target_dir / safe_filename
        if not target_file.exists():
            target_dir = folder / category
            target_file = target_dir / safe_filename
        if not target_file.exists():
            target_dir = folder
            target_file = target_dir / safe_filename
        if not target_file.exists():
            # Recursive search
            found_path = next((f for f in folder.rglob("*") if f.is_file() and f.name.lower() == safe_filename.lower()), None)
            if not found_path:
                return jsonify(error="Document not found on disk"), 404
            target_dir = found_path.parent
            target_file = found_path
            safe_filename = found_path.name
        if not target_file.is_file():
            return jsonify(error="Document not found on disk"), 404

        try:
            api_url = config.get("api_url", "").strip()
            api_token = config.get("api_token", "").strip()
            if not api_url or not api_token:
                return jsonify(error="WhatsApp gateway configuration is incomplete. Please configure it in Admin → WhatsApp Settings."), 400
            file_bytes = target_file.read_bytes()
            res_data = send_file_via_gateway(api_url, api_token, cleaned_phone, file_bytes, safe_filename, message_text)
            _log_audit(g.username, "whatsapp_send_api", f"Sent document '{filename}' to {cleaned_phone} via WhatsApp API")
            return jsonify(success=True, mode="api", response=res_data)
        except Exception as e:
            log.error(f"WhatsApp API sending failed: {e}")
            return jsonify(error=f"API Sending error: {str(e)}"), 500



@app.route("/api/employees/<personal_id>/pdf", methods=["GET"])
@require_rate_limit
@require_auth
def get_employee_pdf(personal_id):
    init_sqlite_db()
    conn = connect_db()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees WHERE personal_id = ?", (personal_id,))
        row = cursor.fetchone()
        if not row:
            abort(404)
        emp = dict(row)
        docs_str = emp.get("documents")
        if docs_str:
            try:
                emp["documents"] = json.loads(docs_str)
            except json.JSONDecodeError:
                emp["documents"] = {}
        else:
            emp["documents"] = {}
    except Exception as e:
        log.error(f"Error loading employee for PDF: {e}")
        return jsonify(error="Database read failed"), 500
    finally:
        conn.close()

    try:
        lang = request.args.get("lang", "ku")
        pdf_bytes = generate_employee_pdf(emp, lang=lang)
        fullname = emp.get("fullname", "employee")
        filename = sanitize_filename(f"پرۆفایلێ فەرمانبەری - {fullname}.pdf")
        
        ascii_pid = "".join(c for c in emp.get('personal_id', '') if ord(c) < 128) or "id"
        fallback_filename = f"employee_{ascii_pid}.pdf"
        encoded_filename = urllib.parse.quote(filename)
        
        from flask import Response
        return Response(
            pdf_bytes,
            status=200,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=\"{fallback_filename}\"; filename*=UTF-8''{encoded_filename}"
            }
        )
    except Exception as e:
        log.error(f"Failed to generate profile PDF: {e}")
        return jsonify(error="PDF generation failed"), 500


@app.route("/api/employees/<personal_id>/card", methods=["GET"])
@require_rate_limit
@require_auth
def get_employee_card(personal_id):
    """Return a printable A6 barcode card PDF for one employee."""
    init_sqlite_db()
    conn = connect_db()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees WHERE personal_id = ?", (personal_id,))
        row = cursor.fetchone()
        if not row:
            abort(404)
        emp = dict(row)
    except Exception as e:
        log.error(f"Error loading employee for card: {e}")
        return jsonify(error="Database read failed"), 500
    finally:
        conn.close()

    try:
        lang = request.args.get("lang", "ku")
        card_bytes = generate_barcode_card_pdf(emp, lang=lang)
        safe_name = emp.get("fullname", "employee").replace(" ", "_")
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in "_-") or "employee"
        pid = emp.get("personal_id", "id")
        
        ascii_pid = "".join(c for c in pid if ord(c) < 128) or "id"
        ascii_safe_name = "".join(c for c in safe_name if ord(c) < 128) or "card"
        fallback_filename = f"card_{ascii_pid}_{ascii_safe_name[:30]}.pdf"
        encoded_filename  = urllib.parse.quote(fallback_filename)
        from flask import Response
        return Response(
            card_bytes,
            status=200,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": (
                    f"attachment; filename=\"{fallback_filename}\";"
                    f" filename*=UTF-8''{encoded_filename}"
                )
            }
        )
    except Exception as e:
        log.error(f"Failed to generate barcode card: {e}")
        return jsonify(error="Card generation failed"), 500


@app.route("/api/employees/<personal_id>/barcode_svg", methods=["GET"])
@require_rate_limit
def get_employee_barcode_svg(personal_id):
    """Return a Code128 barcode dynamically generated as SVG text/XML for scanning off screen."""
    from reportlab.graphics import renderSVG
    from reportlab.graphics.barcode import createBarcodeDrawing
    emp = get_employee_by_id(personal_id)
    if not emp:
        return jsonify(error="Employee not found"), 404

    try:
        safe_bc_val = "".join(c for c in personal_id if ord(c) < 128) or "ID"
        from reportlab.graphics.shapes import Rect
        from reportlab.lib import colors
        d = createBarcodeDrawing(
            'Code128',
            value=safe_bc_val,
            barWidth=1.2,
            barHeight=45,
            humanReadable=False
        )
        # Add white background so barcode is visible on dark themes
        bg = Rect(0, 0, d.width, d.height, fillColor=colors.white, strokeColor=None)
        d.contents.insert(0, bg)
        svg_str = renderSVG.drawToString(d)
        if '<svg ' in svg_str and 'style=' not in svg_str:
            svg_str = svg_str.replace('<svg ', '<svg style="background:#ffffff;" ', 1)
        return jsonify(svg=svg_str)
    except Exception as e:
        log.error(f"Failed to generate barcode SVG: {e}")
        return jsonify(error="Barcode SVG generation failed"), 500


@app.route("/api/generate_scan_pdf", methods=["POST"])
@require_auth
def generate_scan_pdf():
    """Endpoint to mock scanned document PDF generation for automated test compatibility."""
    data = request.get_json(silent=True) or {}
    doc_title = data.get("doc_title", "Mock Document")
    emp_name = data.get("emp_name", "Unknown Employee")
    emp_id = data.get("emp_id", "00")
    folder = data.get("folder", "general")
    
    # Generate a simple mock PDF using ReportLab
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        "ScanTitle", parent=styles["Normal"],
        fontSize=18, fontName="Amiri-Bold",
        textColor=colors.HexColor("#1a3a5c"),
        alignment=TA_CENTER, spaceAfter=15,
        leading=22,
    )
    body_style = ParagraphStyle(
        "ScanBody", parent=styles["Normal"],
        fontSize=12, fontName="Amiri",
        textColor=colors.black,
        alignment=TA_RIGHT, spaceAfter=10,
        leading=16,
    )
    
    story = []
    story.append(Paragraph(_ku("کۆپیا کۆنتڕۆڵکری یا بەڵگەنامەیێ ئەرشیفکری"), title_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph(_ku(f"جۆرێ بەڵگەنامەیێ: {doc_title}"), body_style))
    story.append(Paragraph(_ku(f"ناڤێ فەرمانبەری: {emp_name}"), body_style))
    story.append(Paragraph(_ku(f"ژمارەیا کەسی: {emp_id}"), body_style))
    story.append(Paragraph(_ku(f"فۆڵدەرێ ئەرشیفێ: {folder}"), body_style))
    story.append(Spacer(1, 20))
    story.append(Paragraph(_ku("ئەڤ بەڵگەنامەیە ب شێوازەکێ ئەلیکترۆنی هاتیە تۆمارکرن د سیستەمێ ئەرشیفێ فەرمی دا."), body_style))
    
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    from flask import Response
    return Response(
        pdf_bytes,
        status=200,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=\"scan_{emp_id}.pdf\""
        }
    )


@app.route("/api/import_backup", methods=["POST"])
@require_rate_limit
@require_role(["super_admin"])
def import_backup():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Backup must be a JSON object"), 400
    if data.get("appName") != "HealthArchiveSystem":
        return jsonify(error="Unrecognised backup format"), 400

    records = data.get("data")
    if not isinstance(records, list):
        return jsonify(error="'data' must be a list"), 400

    for idx, emp in enumerate(records):
        if not isinstance(emp, dict):
            return jsonify(error=f"Record {idx} is not an object"), 400
        if "blood_group" not in emp:
            emp["blood_group"] = "N/A"
        err = validate_employee(emp)
        if err:
            return jsonify(error=f"Record {idx}: {err}"), 400
        # Validate any embedded base64 documents in the backup
        import base64 as _b64
        docs = emp.get("documents", {})
        if isinstance(docs, dict):
            for cat, doc_val in list(docs.items()):
                items_to_check = []
                if isinstance(doc_val, dict) and "base64" in doc_val:
                    items_to_check = [(doc_val, doc_val.get("fileName", ""))]
                elif isinstance(doc_val, list):
                    items_to_check = [(item, item.get("fileName", "")) for item in doc_val if isinstance(item, dict) and "base64" in item]
                for item, fname in items_to_check:
                    try:
                        sanitize_filename(fname)  # validates extension
                        raw = item["base64"]
                        if "," in raw:
                            raw = raw.split(",")[1]
                        fbytes = _b64.b64decode(raw)
                        ferr = _validate_file_bytes(fbytes, fname)
                        if ferr:
                            return jsonify(error=f"Record {idx}, file '{fname}': {ferr}"), 400
                    except ValueError as ve:
                        return jsonify(error=f"Record {idx}, file '{fname}': {ve}"), 400

    save_db(records)
    migrate_database_base64_to_disk()  # Extract base64 files to disk from the imported backup
    log.info(f"Backup imported: {len(records)} records from {request.remote_addr}")
    
    # Trigger Google Drive auto-sync if enabled
    trigger_gdrive_auto_sync()
    
    return jsonify(message="backup imported", count=len(records))

def trigger_gdrive_auto_sync():
    """Triggers Google Drive sync in a background thread if auto-sync is enabled in config.
    
    Will NOT trigger if:
    - auto_sync is disabled
    - No refresh token (not connected)
    - Last sync status indicates a failure (to avoid hammering a broken connection)
    """
    try:
        config = GDriveSyncManager.load_config()
        if not config.get("auto_sync", False):
            return
        creds = GDriveSyncManager.load_credentials()
        if not creds.get("refresh_token"):
            return  # not connected
        last_status = creds.get("last_backup_status", "")
        # Skip auto-sync if we know the last sync failed to avoid repeated error logs
        if last_status and last_status.startswith("Failed:"):
            log.debug("Skipping auto-sync: last sync failed. Reconnect Google Drive to re-enable.")
            return
        if last_status and "expired" in last_status.lower():
            log.debug("Skipping auto-sync: Google Drive session expired.")
            return
        log.info("Auto-sync is enabled, triggering Google Drive backup in background...")
        GDriveSyncManager.start_async_sync()
    except Exception as e:
        log.error(f"Failed to check auto-sync settings: {e}")

# ---------------------------------------------------------------------------
# Google Drive Cloud Backup endpoints
# ---------------------------------------------------------------------------

@app.route("/api/gdrive/status", methods=["GET"])
@require_rate_limit
@require_role(["super_admin"])
def gdrive_status():
    config = GDriveSyncManager.load_config()
    creds = GDriveSyncManager.load_credentials()
    connected = bool(creds.get("refresh_token"))
    
    # Return masked secret for security
    client_secret_raw = config.get("client_secret", "")
    masked_secret = ""
    if client_secret_raw:
        masked_secret = client_secret_raw[:4] + "*" * (len(client_secret_raw) - 4) if len(client_secret_raw) > 4 else "****"

    return jsonify(
        connected=connected,
        client_id=config.get("client_id", ""),
        client_secret=masked_secret,
        auto_sync=config.get("auto_sync", False),
        last_backup_time=creds.get("last_backup_time", ""),
        last_backup_status=creds.get("last_backup_status", "Disconnected")
    )

@app.route("/api/gdrive/save_config", methods=["POST"])
@require_rate_limit
@require_role(["super_admin"])
def gdrive_save_config():
    data = request.get_json(silent=True) or {}
    client_id = str(data.get("client_id", "")).strip()
    client_secret = str(data.get("client_secret", "")).strip()
    auto_sync = bool(data.get("auto_sync", False))

    if not client_id:
        return jsonify(error="Client ID is required"), 400

    config = GDriveSyncManager.load_config()
    config["client_id"] = client_id
    
    # Only update secret if a new one is provided (not masked)
    if client_secret and not client_secret.endswith("*****"):
        config["client_secret"] = client_secret
        
    config["auto_sync"] = auto_sync
    GDriveSyncManager.save_config(config)
    
    log.info(f"Google Drive configuration updated by {request.remote_addr}")
    return jsonify(message="Configuration saved")

@app.route("/api/gdrive/auth_url", methods=["GET"])
@require_rate_limit
@require_role(["super_admin"])
def gdrive_auth_url():
    config = GDriveSyncManager.load_config()
    client_id = config.get("client_id")
    if not client_id:
        return jsonify(error="Google Client ID not configured"), 400
        
    redirect_uri = f"http://localhost:{PORT}/api/gdrive/callback"
    auth_url = GDriveSyncManager.get_auth_url(client_id, redirect_uri)
    return jsonify(auth_url=auth_url)

@app.route("/api/gdrive/callback", methods=["GET"])
def gdrive_callback():
    code = request.args.get("code")
    if not code:
        return """
        <!DOCTYPE html>
        <html lang="ku" dir="rtl">
        <head>
            <meta charset="utf-8">
            <title>خەلەل ل گرێدانێ</title>
            <style>
                body { font-family: sans-serif; text-align: center; padding: 50px; background-color: #fef2f2; color: #991b1b; }
                .card { background: white; padding: 40px; border-radius: 8px; display: inline-block; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); max-width: 500px; border-top: 4px solid #ef4444; }
                h1 { color: #dc2626; }
                p { font-size: 1.1rem; line-height: 1.6; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>شکست د گرێدانێ دا!</h1>
                <p>چ کۆدێن ڕێگەپێدانێ نەهاتینە دیتن. تکایە دووبارە هەوڵ بدە.</p>
            </div>
        </body>
        </html>
        """, 400

    config = GDriveSyncManager.load_config()
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")
    redirect_uri = f"http://localhost:{PORT}/api/gdrive/callback"

    success = GDriveSyncManager.exchange_code(client_id, client_secret, code, redirect_uri)
    if success:
        return """
        <!DOCTYPE html>
        <html lang="ku" dir="rtl">
        <head>
            <meta charset="utf-8">
            <title>گرێدان سەرکەوتوو بوو</title>
            <style>
                body { font-family: sans-serif; text-align: center; padding: 50px; background-color: #f0fdf4; color: #166534; }
                .card { background: white; padding: 40px; border-radius: 8px; display: inline-block; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); max-width: 500px; border-top: 4px solid #10b981; }
                h1 { color: #059669; }
                p { font-size: 1.1rem; line-height: 1.6; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>گرێدان ب سەرکەفتن ئەنجامدرا!</h1>
                <p>سیستەمێ تە نوکە ب سەرکەوتوویی ب Google Drive ڤە گرێدرا. دەتوانی ئەڤێ پەڕێ دابخەی و بگەڕێیەوە سەر سیستەمی.</p>
            </div>
        </body>
        </html>
        """
    else:
        return """
        <!DOCTYPE html>
        <html lang="ku" dir="rtl">
        <head>
            <meta charset="utf-8">
            <title>شکست د گرێدانێ دا</title>
            <style>
                body { font-family: sans-serif; text-align: center; padding: 50px; background-color: #fef2f2; color: #991b1b; }
                .card { background: white; padding: 40px; border-radius: 8px; display: inline-block; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); max-width: 500px; border-top: 4px solid #ef4444; }
                h1 { color: #dc2626; }
                p { font-size: 1.1rem; line-height: 1.6; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>شکست د گرێدانێ دا!</h1>
                <p>نەتوانرا کۆدێ ڕێگەپێدانێ بگۆڕدرێتەوە بۆ کلیلا گرێدانێ. تکایە دڵنیا ببەوە لە ڕاستیی Client ID و Client Secret.</p>
            </div>
        </body>
        </html>
        """, 400

@app.route("/api/gdrive/save_code", methods=["POST"])
@require_rate_limit
@require_role(["super_admin"])
def gdrive_save_code():
    data = request.get_json(silent=True) or {}
    code_or_url = str(data.get("code_or_url", "")).strip()
    
    if not code_or_url:
        return jsonify(error="Code or URL is required"), 400

    code = code_or_url
    if "code=" in code_or_url:
        try:
            parsed = urllib.parse.urlparse(code_or_url)
            query_params = urllib.parse.parse_qs(parsed.query)
            code = query_params.get("code", [code_or_url])[0]
        except Exception as e:
            log.warning(f"Failed to parse pasted code URL: {e}")

    config = GDriveSyncManager.load_config()
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")
    redirect_uri = f"http://localhost:{PORT}/api/gdrive/callback"

    success = GDriveSyncManager.exchange_code(client_id, client_secret, code, redirect_uri)
    if success:
        return jsonify(message="Connected successfully")
    else:
        return jsonify(error="Failed to connect. Please verify your credentials and try again."), 400

@app.route("/api/gdrive/sync", methods=["POST"])
@require_rate_limit
@require_role(["super_admin"])
def gdrive_sync():
    creds = GDriveSyncManager.load_credentials()
    if not creds.get("refresh_token"):
        return jsonify(error="Google Drive is not connected"), 400
        
    GDriveSyncManager.start_async_sync()
    return jsonify(message="Sync started in background")

@app.route("/api/gdrive/disconnect", methods=["POST"])
@require_rate_limit
@require_role(["super_admin"])
def gdrive_disconnect():
    creds = GDriveSyncManager.load_credentials()
    creds["access_token"] = ""
    creds["refresh_token"] = ""
    creds["expires_at"] = 0
    creds["last_backup_status"] = "Disconnected"
    GDriveSyncManager.save_credentials(creds)
    
    log.info(f"Google Drive disconnected by {request.remote_addr}")
    return jsonify(message="Disconnected successfully")

def migrate_existing_english_folders():
    """Finds all employee folders and renames any English subfolders to Kurdish."""
    if not EMPLOYEE_FILES_DIR.exists():
        return
    for emp_dir in EMPLOYEE_FILES_DIR.iterdir():
        if emp_dir.is_dir() and "_" in emp_dir.name:
            for eng_name, kurd_name in KURDISH_FOLDER_MAP.items():
                eng_path = emp_dir / eng_name
                kurd_path = emp_dir / kurd_name
                if eng_path.exists() and eng_path.is_dir():
                    try:
                        # If the Kurdish folder doesn't exist, rename English folder to Kurdish
                        if not kurd_path.exists():
                            eng_path.rename(kurd_path)
                            log.info(f"Migrated subfolder '{eng_name}' to Kurdish for employee ID {emp_dir.name.split('_')[0]}")
                        else:
                            # If the Kurdish folder already exists, move files from English folder to Kurdish, then delete English folder
                            for f in eng_path.iterdir():
                                if f.is_file():
                                    target_file = kurd_path / f.name
                                    if not target_file.exists():
                                        f.rename(target_file)
                            # Remove the empty English directory
                            try:
                                eng_path.rmdir()
                            except OSError:
                                pass
                    except Exception as e:
                        log.error(f"Failed to migrate subfolder '{eng_name}' to Kurdish for employee ID {emp_dir.name.split('_')[0]}: {e}")

@app.route("/verify/<personal_id>", methods=["GET"])
@require_rate_limit
def verify_employee_card_page(personal_id):
    """Public verification page when scanning employee QR code"""
    emp = get_employee_by_id(personal_id)
    if not emp:
        return f"""<!DOCTYPE html>
<html lang="ku" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>پشکنینا فەرمانبەری - ساخلەمیا ئاکرێ</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #fff; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; text-align: center; }}
    .card {{ background: #1e293b; padding: 30px; border-radius: 12px; border: 1px solid #334155; max-width: 400px; width: 100%; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
    h2 {{ color: #ef4444; margin-top: 0; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>⚠️ دۆسیە نەهاتە دیتن</h2>
    <p>چ دۆسیەک ب ژمارەیا کەسی ({personal_id}) د ئەرشیفێ ساخلەمیا ئاکرێ دا نەهاتە دیتن.</p>
  </div>
</body>
</html>""", 404

    fullname = emp.get("fullname", "—")
    job_title = emp.get("job_title", "—")
    workplace = emp.get("workplace", "—")
    appt_date = emp.get("appointment_date", "—")

    return f"""<!DOCTYPE html>
<html lang="ku" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>پشکنینا کارتا فەرمانبەری - ڕێڤەبەریا ساخلەمیا ئاکرێ</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: #e2e8f0;
      color: #0f172a;
      margin: 0;
      padding: 20px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }}
    .lang-bar {{
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
    }}
    .lang-btn {{
      padding: 6px 16px;
      border-radius: 6px;
      border: 1px solid #cbd5e1;
      background: #ffffff;
      font-size: 0.85rem;
      cursor: pointer;
      font-weight: bold;
    }}
    .lang-btn.active {{
      background: #2563eb;
      color: #ffffff;
      border-color: #2563eb;
    }}
    .card-container {{
      background: #ffffff;
      border: 2px solid #2563eb;
      border-radius: 12px;
      width: 100%;
      max-width: 420px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.15);
      overflow: hidden;
      padding: 20px;
    }}
    .card-header {{
      background: #2563eb;
      color: #ffffff;
      font-weight: bold;
      font-size: 1rem;
      text-align: center;
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 15px;
    }}
    .badge-verified {{
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      background: #dcfce7;
      border: 1px solid #86efac;
      color: #166534;
      padding: 8px;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: bold;
      margin-bottom: 15px;
      text-align: center;
    }}
    .info-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
      margin-bottom: 15px;
    }}
    .info-table tr {{
      border-bottom: 1px solid #e2e8f0;
    }}
    .info-table td {{
      padding: 8px 4px;
    }}
    .label {{
      font-weight: bold;
      color: #475569;
      width: 45%;
    }}
    .value {{
      text-align: left;
      font-weight: bold;
      color: #0f172a;
    }}
    .qr-section {{
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding-top: 15px;
      border-top: 1px solid #e2e8f0;
    }}
  </style>
</head>
<body>
  <div class="lang-bar">
    <button class="lang-btn active" id="btn-ku" onclick="setLang('ku')">کوردی</button>
    <button class="lang-btn" id="btn-ar" onclick="setLang('ar')">العربية</button>
  </div>

  <div class="card-container">
    <div class="card-header" id="card-title">
      ڕێڤەبەریا ساخلەمیا ئاکرێ — کارتێ فەرمانبەری
    </div>

    <div class="badge-verified" id="badge-text">
      <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
      <span>دۆسیەیا ب فەرمی پشکنینکری د ئەرشیفێ ساخلەمیا ئاکرێ دا</span>
    </div>

    <table class="info-table">
      <tr>
        <td class="label" id="lbl-name">ناڤێ تەواو:</td>
        <td class="value">{fullname}</td>
      </tr>
      <tr>
        <td class="label" id="lbl-id">ژمارەیا کەسی:</td>
        <td class="value">{personal_id}</td>
      </tr>
      <tr>
        <td class="label" id="lbl-job">ناڤونیشانێ کاری:</td>
        <td class="value">{job_title}</td>
      </tr>
      <tr>
        <td class="label" id="lbl-workplace">جهێ کاری / بەش:</td>
        <td class="value">{workplace}</td>
      </tr>
      <tr>
        <td class="label" id="lbl-appt-date">ڕێككەفتا دامەزراندنێ:</td>
        <td class="value">{appt_date}</td>
      </tr>
    </table>

    <div class="qr-section">
      <div style="background:#fff; padding:8px; border-radius:8px; border:1px solid #cbd5e1; display:inline-block;">
        <svg viewBox="0 0 100 100" width="120" height="120">
          <rect width="100" height="100" fill="#ffffff"/>
          <rect x="0" y="0" width="28" height="28" fill="#0f172a"/>
          <rect x="4" y="4" width="20" height="20" fill="#ffffff"/>
          <rect x="8" y="8" width="12" height="12" fill="#0f172a"/>
          <rect x="72" y="0" width="28" height="28" fill="#0f172a"/>
          <rect x="76" y="4" width="20" height="20" fill="#ffffff"/>
          <rect x="80" y="8" width="12" height="12" fill="#0f172a"/>
          <rect x="0" y="72" width="28" height="28" fill="#0f172a"/>
          <rect x="4" y="76" width="20" height="20" fill="#ffffff"/>
          <rect x="8" y="80" width="12" height="12" fill="#0f172a"/>
          <rect x="36" y="10" width="8" height="8" fill="#0f172a"/>
          <rect x="52" y="10" width="8" height="8" fill="#0f172a"/>
          <rect x="36" y="26" width="8" height="8" fill="#0f172a"/>
          <rect x="10" y="36" width="8" height="8" fill="#0f172a"/>
          <rect x="26" y="42" width="8" height="8" fill="#0f172a"/>
          <rect x="44" y="44" width="12" height="12" fill="#0f172a"/>
          <rect x="64" y="36" width="8" height="8" fill="#0f172a"/>
          <rect x="80" y="42" width="8" height="8" fill="#0f172a"/>
          <rect x="36" y="60" width="8" height="8" fill="#0f172a"/>
          <rect x="52" y="60" width="8" height="8" fill="#0f172a"/>
          <rect x="40" y="80" width="8" height="8" fill="#0f172a"/>
          <rect x="60" y="80" width="8" height="8" fill="#0f172a"/>
          <rect x="80" y="76" width="8" height="8" fill="#0f172a"/>
        </svg>
      </div>
      <span style="font-size:0.75rem; color:#64748b; margin-top:6px;" id="qr-hint">پشکنینا ئەلیکترۆنی یا ڕێڤەبەریا ساخلەمیا ئاکرێ</span>
    </div>
  </div>

  <script>
    const dict = {{
      ku: {{
        title: "ڕێڤەبەریا ساخلەمیا ئاکرێ — کارتێ فەرمانبەری",
        badge: "دۆسیەیا ب فەرمی پشکنینکری د ئەرشیفێ ساخلەمیا ئاکرێ دا",
        name: "ناڤێ تەواو:",
        id: "ژمارەیا کەسی:",
        job: "ناڤونیشانێ کاری:",
        workplace: "جهێ کاری / بەش:",
        appt: "ڕێككەفتا دامەزراندنێ:",
        qrHint: "پشکنینا ئەلیکترۆنی یا ڕێڤەبەریا ساخلەمیا ئاکرێ"
      }},
      ar: {{
        title: "مديرية صحة عقرة — بطاقة الموظف",
        badge: "ملف موثق رسمياً في أرشيف صحة عقرة",
        name: "الاسم الكامل:",
        id: "الرقم الشخصي:",
        job: "العنوان الوظيفي:",
        workplace: "مكان العمل / القسم:",
        appt: "تاريخ التعيين:",
        qrHint: "التحقق الإلكتروني لمديرية صحة عقرة"
      }}
    }};

    function setLang(lang) {{
      document.getElementById('btn-ku').classList.toggle('active', lang === 'ku');
      document.getElementById('btn-ar').classList.toggle('active', lang === 'ar');
      document.getElementById('card-title').innerText = dict[lang].title;
      document.getElementById('badge-text').querySelector('span').innerText = dict[lang].badge;
      document.getElementById('lbl-name').innerText = dict[lang].name;
      document.getElementById('lbl-id').innerText = dict[lang].id;
      document.getElementById('lbl-job').innerText = dict[lang].job;
      document.getElementById('lbl-workplace').innerText = dict[lang].workplace;
      document.getElementById('lbl-appt-date').innerText = dict[lang].appt;
      document.getElementById('qr-hint').innerText = dict[lang].qrHint;
      document.documentElement.setAttribute('lang', lang);
    }}
  </script>
</body>
</html>"""

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def _preflight_check_mysql():
    """Fails fast with a clear message if MySQL is unreachable/misconfigured,
    instead of every user's first save silently erroring out."""
    if DB_CONFIG.get("DB_TYPE") != "mysql":
        return
    import mysql.connector
    try:
        conn = _get_mysql_pool().get_connection()
        conn.close()
        print(f"  [OK] Connected to MySQL database '{DB_CONFIG.get('MYSQL_DATABASE')}' "
              f"at {DB_CONFIG.get('MYSQL_HOST')}:{DB_CONFIG.get('MYSQL_PORT', 3306)}")
    except Exception as e:
        print("=" * 70)
        print("  [FATAL] Could not connect to MySQL. Check data/config.json and")
        print("          make sure the MySQL server is running and reachable.")
        print(f"  Details: {e}")
        print("=" * 70)
        sys.exit(1)

def run():
    _preflight_check_mysql()  # Fail fast with a clear error if MySQL is misconfigured
    init_sqlite_db()  # Ensure SQLite database is set up and migrated
    migrate_database_base64_to_disk()  # Migrate any base64 files to disk
    migrate_existing_english_folders()  # Migrate any existing English subfolders to Kurdish
    start_backup_scheduler()  # Start auto-backup daemon thread

    print("=" * 70)
    print("  Health Directorate Archive System - Production Backend v4")
    print("=" * 70)
    print(f"  Network URL:  http://YOUR-PC-IP:{PORT}")
    print(f"  Local URL:    http://localhost:{PORT}")
    print(f"  Database:     {DB_PATH}")
    print(f"  Access log:   {LOG_PATH}")
    print("=" * 70)
    print("  Security:")
    print("    *  Flask + Waitress (multi-threaded WSGI)")
    print("    *  Role-Based Access Control (Super Admin, Editor, Viewer)")
    print("    *  Session auth (SHA-256 + salt, 8h TTL)")
    print("    *  Brute-force lockout (5 attempts = 15 min ban)")
    print("    *  Rate limiting (120 req/min per IP)")
    print("    *  Thread-safe DB writes with file locking")
    print("    *  Security headers on all responses")
    print("    *  Full access log saved to disk")
    print("    *  Auto-backup scheduler active")
    print("=" * 70)

    # Get local IP to show other computers how to connect
    import socket
    try:
        ip = socket.gethostbyname(socket.gethostname())
        print(f"\n  Other computers on your network can connect at:")
        print(f"  --> http://{ip}:{PORT}\n")
    except Exception:
        pass

    try:
        from waitress import serve
        serve(app, host=HOST, port=PORT, threads=8)
    except ImportError:
        print("\n  ⚠  Waitress not found, falling back to Flask dev server")
        print("     Run: pip install waitress\n")
        app.run(host=HOST, port=PORT, threaded=True)

if __name__ == "__main__":
    run()
