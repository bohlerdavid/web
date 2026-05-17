import sqlite3
import os
from werkzeug.security import generate_password_hash

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'devices.db')

print("=== Passwort zurücksetzen ===")
print(f"Datenbank: {db_path}\n")

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

users = conn.execute("SELECT id, username, full_name, role FROM app_users").fetchall()
if not users:
    print("Keine Benutzer gefunden!")
    conn.close()
    exit(1)

print("Vorhandene Benutzer:")
for u in users:
    print(f"  [{u['id']}] {u['username']} ({u['full_name']}) — {u['role']}")

print()
username = input("Benutzername eingeben: ").strip()
user = conn.execute("SELECT id FROM app_users WHERE username=?", (username,)).fetchone()
if not user:
    print(f"Benutzer '{username}' nicht gefunden!")
    conn.close()
    exit(1)

password = input("Neues Passwort: ").strip()
if not password:
    print("Passwort darf nicht leer sein!")
    conn.close()
    exit(1)

conn.execute(
    "UPDATE app_users SET password_hash=?, must_change_pw=0 WHERE username=?",
    (generate_password_hash(password), username)
)
conn.commit()
conn.close()

print(f"\nPasswort für '{username}' erfolgreich geändert!")
