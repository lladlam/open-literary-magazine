"""Database initialization and models for 请输入文本 magazine."""
import sqlite3
import os
import re
import bcrypt
from datetime import datetime
from threading import Lock

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'magazine.db')
_db_lock = Lock()

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password_strength(password):
    if len(password) < 8:
        return False, '密码至少8位'
    if not re.search(r'[A-Z]', password):
        return False, '密码需包含大写字母'
    if not re.search(r'[a-z]', password):
        return False, '密码需包含小写字母'
    if not re.search(r'[0-9]', password):
        return False, '密码需包含数字'
    return True, ''

def verify_password(stored, password):
    import hashlib, secrets
    # Try bcrypt first
    if stored.startswith('$2'):
        try:
            return bcrypt.checkpw(password.encode(), stored.encode())
        except Exception:
            return False
    # Fallback: old SHA-256 format (salt:hash)
    try:
        salt, h = stored.split(':')
        computed = hashlib.sha256((salt + password).encode()).hexdigest()
        return computed == h
    except Exception:
        return False

def is_legacy_password(stored):
    return not stored.startswith('$2')

def migrate_password(conn, user_id, password):
    conn.execute("UPDATE users SET password=? WHERE id=?", (hash_password(password), user_id))

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'users' CHECK(role IN ('superadmins','admins','users')),
        avatar TEXT DEFAULT '',
        banned INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        author_name TEXT NOT NULL,
        contact TEXT NOT NULL,
        author_bio TEXT DEFAULT '',
        content TEXT DEFAULT '',
        synopsis TEXT DEFAULT '',
        creation_note TEXT DEFAULT '',
        file_path TEXT DEFAULT '',
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending','reviewing','passed','failed')),
        review_reason TEXT DEFAULT '',
        reviewed_by INTEGER,
        reviewed_at TIMESTAMP,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_edited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        edit_locked_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (reviewed_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """)

    defaults = {
        'submit_open': '0',
        'submit_start': '',
        'submit_end': '',
        'wait_period_enabled': '1',
    }
    for k, v in defaults.items():
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

    existing = c.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        pwd = hash_password('admin')
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'superadmins')",
                  ('admin', pwd))

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized.")
