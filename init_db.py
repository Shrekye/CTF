import sqlite3
import os
from werkzeug.security import generate_password_hash

print("🧠 Initialisation des bases de données ...")

# ——————————————————————————
# IDOR DATABASE
# ——————————————————————————

DB_PATH = os.environ.get("CTF_IDOR_DB_PATH", "/app/idor.db")

def get_db():
    return sqlite3.connect(DB_PATH)

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
    print(f"[*] Init IDOR DB → {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Tables
    cur.executescript(SCHEMA)

    # --- ADMIN (ID 0) ---
    cur.execute("""
        INSERT OR REPLACE INTO users
        (id, username, password_hash, email, role, profile_data, created_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    """, (
        0,
        "admin",
        generate_password_hash("AdminTest123!"),
        "admin@example.local",
        "admin",
        "flag: ER{succ3ss_JP0!}"
    ))

    # --- USER (ID 1) ---
    cur.execute("""
        INSERT OR IGNORE INTO users
        (id, username, password_hash, email, role, profile_data, created_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    """, (
        1,
        "alice",
        generate_password_hash("alicepass"),
        "alice@example.local",
        "user",
        "Profil de alice"
    ))

    conn.commit()
    conn.close()

    print("[+] IDOR DB prête (admin=0, alice=1)")

if __name__ == "__main__":
    # Création dossier SAFE
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    seed()

# ——————————————————————————
# SQLi DATABASE
# ——————————————————————————

SQLI_DB = os.path.join("challenges", "sql", "challenge.db")

os.makedirs(os.path.dirname(SQLI_DB), exist_ok=True)

conn = sqlite3.connect(SQLI_DB)
cur = conn.cursor()

print(f" → Création des tables pour {SQLI_DB}")

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flag TEXT NOT NULL
)
""")

# Ajout de comptes et flag
cur.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("admin", "supersecret"))
cur.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("alice", "password123"))

sqli_flag = "ER{succ3ss_JP02!}"
cur.execute("INSERT OR IGNORE INTO flags (flag) VALUES (?)", (sqli_flag,))

conn.commit()
conn.close()
print(f" → SQLi DB initialisée: {SQLI_DB}")

print("🎉 Initialisation complète !")
print(f"  - SQLi login admin:{sqli_flag}")
