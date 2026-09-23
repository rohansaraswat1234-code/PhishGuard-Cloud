import sqlite3
import getpass
from pathlib import Path
from werkzeug.security import generate_password_hash

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "database" / "phishguard.db"

print("\n=== PhishGuard Admin Setup ===\n")

name = input("Admin name: ").strip()
email = input("Admin email: ").strip().lower()
password = getpass.getpass("Admin password: ")

if not name or not email or not password:
    print("All fields are required.")
    raise SystemExit

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

existing = cursor.execute(
    "SELECT id FROM users WHERE email = ?",
    (email,)
).fetchone()

if existing:
    print("Account with this email already exists.")
else:
    cursor.execute(
        """
        INSERT INTO users (
            name,
            email,
            password_hash,
            role
        )
        VALUES (?, ?, ?, 'admin')
        """,
        (
            name,
            email,
            generate_password_hash(password)
        )
    )

    conn.commit()
    print("\nAdmin account created successfully ✅")

conn.close()
