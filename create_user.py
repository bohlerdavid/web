import sqlite3
import sys
import os
from werkzeug.security import generate_password_hash

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'devices.db')

username = input("Benutzername: ").strip()
full_name = input("Vollstaendiger Name: ").strip()
password = input("Passwort: ").strip()
role = input("Rolle (admin/viewer) [admin]: ").strip() or "admin"

if not username or not password:
    print("Fehler: Benutzername und Passwort sind erforderlich.")
    sys.exit(1)

conn = sqlite3.connect(db_path)
try:
    pw_hash = generate_password_hash(password)
    conn.execute(
        "INSERT INTO app_users (username, password_hash, full_name, role, must_change_pw) VALUES (?,?,?,?,?)",
        (username, pw_hash, full_name, role, 0)
    )
    conn.commit()
    print(f"\nBenutzer '{username}' erfolgreich erstellt!")
except sqlite3.IntegrityError:
    print(f"\nFehler: Benutzername '{username}' existiert bereits.")
finally:
    conn.close()
