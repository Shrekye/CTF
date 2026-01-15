import sqlite3
from werkzeug.security import generate_password_hash
import os

DB_PATH = os.environ.get("CTF_DB_PATH", "ctf.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL,
    profile_data TEXT,
    created_at TIMESTAMP
);
"""

def seed():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript(SCHEMA)
    admin_username = "admin"
    admin_password = "AdminTest123!"
    password_hash = generate_password_hash(admin_password)
    profile_data = "flag: ER{succ3ss_JP0!}"
    cur.execute("""
        INSERT OR REPLACE INTO users (id, username, password_hash, email, role, profile_data, created_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    """, (0, admin_username, password_hash, "admin@example.local", "admin", profile_data))
    try:
        cur.execute("""
            INSERT INTO users (username, password_hash, email, role, profile_data, created_at)
            VALUES (?, ?, ?, 'user', ?, datetime('now'))
        """, ("alice", generate_password_hash("alicepass"), "alice@example.local", "Profil de alice"))
    except Exception:
        pass
    conn.commit()
    conn.close()
    print(f"Seeded DB at {DB_PATH} with admin id=0 and flag.")

if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    seed()
