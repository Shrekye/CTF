#!/usr/bin/env python3
import sqlite3
import os

DB_FILE = "challenge.db"

# Supprimer l'ancienne DB pour repartir propre
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

conn = sqlite3.connect(DB_FILE)
c = conn.cursor()

# Tables
c.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)
""")

c.execute("""
CREATE TABLE flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flag TEXT NOT NULL
)
""")

# Insérer comptes normaux
users = [
    ("admin", "supersecret"),   # compte 'admin' (mot de passe connu uniquement pour enseignant)
    ("alice", "password123")
]

c.executemany("INSERT INTO users (username, password) VALUES (?, ?)", users)

# Insérer le flag
flag_value = "ER{succ3ss_JP02!}"
c.execute("INSERT INTO flags (flag) VALUES (?)", (flag_value,))

conn.commit()
conn.close()

print(f"[init_db] Base initialisée dans {DB_FILE}. Flag inséré.")
