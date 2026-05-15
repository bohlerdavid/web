import sqlite3
import csv
import io
import os
import re
import secrets
import time
from functools import wraps
from datetime import datetime, date, timedelta, timezone
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, g, Response, abort, jsonify, session
)
from werkzeug.security import generate_password_hash, check_password_hash
import scanner

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'it-device-mgmt-secret-2024')

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'devices.db')

# ---------------------------------------------------------------------------
# Brute-force protection
# ---------------------------------------------------------------------------

_login_attempts = {}  # {ip: {'count': N, 'locked_until': timestamp}}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300  # 5 minutes


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def execute_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    return cur.lastrowid


def row_to_dict(row):
    """Convert a sqlite3.Row to a plain dict so templates can use .get()."""
    if row is None:
        return {}
    return dict(row)


# ---------------------------------------------------------------------------
# Database initialisation
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS locations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT    NOT NULL,
    building  TEXT,
    floor     TEXT,
    room      TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    email      TEXT,
    department TEXT,
    phone      TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS devices (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    category         TEXT NOT NULL DEFAULT 'Other',
    serial_number    TEXT,
    mac_address      TEXT,
    ip_address       TEXT,
    operating_system TEXT,
    status           TEXT NOT NULL DEFAULT 'active',
    location_id      INTEGER REFERENCES locations(id) ON DELETE SET NULL,
    user_id          INTEGER REFERENCES users(id) ON DELETE SET NULL,
    purchase_date    TEXT,
    warranty_expiry  TEXT,
    notes            TEXT,
    created_at       TEXT DEFAULT (datetime('now')),
    cpu_info         TEXT,
    ram_info         TEXT,
    manufacturer     TEXT,
    model            TEXT
);

CREATE TABLE IF NOT EXISTS discovered_devices (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ip                 TEXT,
    mac                TEXT,
    hostname           TEXT,
    vendor             TEXT,
    os                 TEXT,
    os_accuracy        TEXT,
    first_seen         TEXT,
    last_seen          TEXT,
    status             TEXT DEFAULT 'new',
    imported_device_id INTEGER,
    cpu                TEXT,
    cpu_cores          INTEGER,
    ram_gb             REAL,
    disks              TEXT,
    manufacturer       TEXT,
    model              TEXT,
    serial_number      TEXT,
    os_caption         TEXT,
    os_build           TEXT,
    last_boot          TEXT,
    hw_status          TEXT DEFAULT 'pending',
    hw_error           TEXT,
    hw_queried_at      TEXT
);

CREATE TABLE IF NOT EXISTS app_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    full_name     TEXT,
    role          TEXT    NOT NULL DEFAULT 'viewer',
    must_change_pw INTEGER DEFAULT 0,
    created_at    TEXT    DEFAULT (datetime('now')),
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS detail_sections (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    icon       TEXT DEFAULT 'bi-grid',
    position   INTEGER DEFAULT 0,
    width      TEXT DEFAULT 'half',
    min_height INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS detail_fields (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    section_id  INTEGER NOT NULL REFERENCES detail_sections(id) ON DELETE CASCADE,
    label       TEXT NOT NULL,
    field_key   TEXT NOT NULL UNIQUE,
    field_type  TEXT NOT NULL DEFAULT 'text',
    position    INTEGER DEFAULT 0,
    visible     INTEGER DEFAULT 1,
    field_width   TEXT DEFAULT 'third',
    display_style TEXT DEFAULT 'stacked',
    created_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS device_field_values (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    field_id   INTEGER NOT NULL REFERENCES detail_fields(id) ON DELETE CASCADE,
    value      TEXT,
    UNIQUE(device_id, field_id)
);
"""

def migrate_db():
    """Add missing columns to existing tables without dropping data."""
    db = get_db()
    discovered_new_cols = [
        ('cpu', 'TEXT'), ('cpu_cores', 'INTEGER'), ('ram_gb', 'REAL'),
        ('disks', 'TEXT'), ('manufacturer', 'TEXT'), ('model', 'TEXT'),
        ('serial_number', 'TEXT'), ('os_caption', 'TEXT'), ('os_build', 'TEXT'),
        ('last_boot', 'TEXT'), ('hw_status', "TEXT DEFAULT 'pending'"),
        ('hw_error', 'TEXT'), ('hw_queried_at', 'TEXT'),
    ]
    for col, col_type in discovered_new_cols:
        try:
            db.execute(f'ALTER TABLE discovered_devices ADD COLUMN {col} {col_type}')
            db.commit()
        except:
            pass  # column already exists

    devices_new_cols = [
        ('cpu_info', 'TEXT'), ('ram_info', 'TEXT'),
        ('manufacturer', 'TEXT'), ('model', 'TEXT'),
    ]
    for col, col_type in devices_new_cols:
        try:
            db.execute(f'ALTER TABLE devices ADD COLUMN {col} {col_type}')
            db.commit()
        except:
            pass  # column already exists

    # Ensure new layout tables exist (for existing DBs that predate the schema addition)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS detail_sections (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT NOT NULL,
        icon       TEXT DEFAULT 'bi-grid',
        position   INTEGER DEFAULT 0,
        width      TEXT DEFAULT 'half',
        min_height INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS detail_fields (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        section_id  INTEGER NOT NULL REFERENCES detail_sections(id) ON DELETE CASCADE,
        label       TEXT NOT NULL,
        field_key   TEXT NOT NULL UNIQUE,
        field_type  TEXT NOT NULL DEFAULT 'text',
        position    INTEGER DEFAULT 0,
        visible     INTEGER DEFAULT 1,
        field_width   TEXT DEFAULT 'third',
        display_style TEXT DEFAULT 'stacked',
        created_at    TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS device_field_values (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        field_id   INTEGER NOT NULL REFERENCES detail_fields(id) ON DELETE CASCADE,
        value      TEXT,
        UNIQUE(device_id, field_id)
    );
    """)
    db.commit()

    # Add new columns to detail_sections if they don't exist yet
    section_new_cols = [
        ('width', "TEXT DEFAULT 'half'"),
        ('min_height', 'INTEGER DEFAULT 0'),
    ]
    for col, col_type in section_new_cols:
        try:
            db.execute(f'ALTER TABLE detail_sections ADD COLUMN {col} {col_type}')
            db.commit()
        except:
            pass  # column already exists

    # Add new columns to detail_fields if they don't exist yet
    fields_new_cols = [
        ('visible', 'INTEGER DEFAULT 1'),
        ('field_width', "TEXT DEFAULT 'third'"),
        ('display_style', "TEXT DEFAULT 'stacked'"),
    ]
    for col, col_type in fields_new_cols:
        try:
            db.execute(f'ALTER TABLE detail_fields ADD COLUMN {col} {col_type}')
            db.commit()
        except:
            pass  # column already exists


def _make_field_key(label, db):
    """Generate a unique field_key slug from a label."""
    base = re.sub(r'[^a-z0-9]+', '_', label.lower()).strip('_')
    key = base
    suffix = 2
    while db.execute("SELECT id FROM detail_fields WHERE field_key = ?", (key,)).fetchone():
        key = f"{base}_{suffix}"
        suffix += 1
    return key


def init_db():
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        db.commit()
        migrate_db()

        # Seed default sections/fields if empty
        section_count = db.execute("SELECT COUNT(*) FROM detail_sections").fetchone()[0]
        if section_count == 0:
            default_sections = [
                ('Basisinformationen', 'bi-info-circle', 0, [
                    ('Seriennummer', 'text', 0),
                    ('Betriebssystem', 'text', 1),
                    ('Kaufdatum', 'date', 2),
                    ('Garantie bis', 'date', 3),
                ]),
                ('Netzwerk', 'bi-ethernet', 1, [
                    ('IP-Adresse', 'text', 0),
                    ('MAC-Adresse', 'text', 1),
                    ('Hostname', 'text', 2),
                ]),
                ('Hardware', 'bi-cpu', 2, [
                    ('CPU', 'text', 0),
                    ('RAM', 'text', 1),
                    ('Festplatte', 'text', 2),
                    ('Hersteller', 'text', 3),
                    ('Modell', 'text', 4),
                ]),
                ('Notizen', 'bi-journal-text', 3, [
                    ('Notizen', 'textarea', 0),
                ]),
            ]
            for sec_name, sec_icon, sec_pos, fields in default_sections:
                cur = db.execute(
                    "INSERT INTO detail_sections (name, icon, position) VALUES (?,?,?)",
                    (sec_name, sec_icon, sec_pos)
                )
                sec_id = cur.lastrowid
                for f_label, f_type, f_pos in fields:
                    f_key = _make_field_key(f_label, db)
                    db.execute(
                        "INSERT INTO detail_fields (section_id, label, field_key, field_type, position) VALUES (?,?,?,?,?)",
                        (sec_id, f_label, f_key, f_type, f_pos)
                    )
            db.commit()

        # Create default admin if no users exist
        existing = db.execute("SELECT COUNT(*) FROM app_users").fetchone()[0]
        if existing == 0:
            pw_hash = generate_password_hash('Admin1234!')
            db.execute(
                "INSERT INTO app_users (username, password_hash, full_name, role, must_change_pw) VALUES (?,?,?,?,?)",
                ('admin', pw_hash, 'Administrator', 'admin', 1)
            )
            db.commit()
            print("=" * 50)
            print("Standard-Admin erstellt:")
            print("  Benutzername: admin")
            print("  Passwort:     Admin1234!")
            print("  Bitte sofort ändern!")
            print("=" * 50)


# ---------------------------------------------------------------------------
# CSRF helpers
# ---------------------------------------------------------------------------

def generate_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf(token):
    return token and token == session.get('csrf_token')


def validate_csrf_flexible():
    """Accept CSRF token from X-CSRFToken header OR form field."""
    header_token = request.headers.get('X-CSRFToken', '')
    form_token = request.form.get('csrf_token', '')
    return validate_csrf(header_token) or validate_csrf(form_token)


# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        if session.get('role') != 'admin':
            flash('Zugriff verweigert. Administratorrechte erforderlich.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Before-request: force password change middleware
# ---------------------------------------------------------------------------

@app.before_request
def check_must_change_pw():
    exempt = {'login', 'logout', 'static'}
    if request.endpoint in exempt:
        return
    if 'user_id' not in session:
        return
    if session.get('must_change_pw') and request.endpoint not in {'profile', 'profile_change_password'}:
        flash('Bitte ändern Sie Ihr Passwort, bevor Sie fortfahren.', 'warning')
        return redirect(url_for('profile'))


# ---------------------------------------------------------------------------
# Template filters & context processors
# ---------------------------------------------------------------------------

@app.template_filter('de_date')
def de_date(value):
    """Convert YYYY-MM-DD to DD.MM.YYYY for display."""
    if not value:
        return '—'
    try:
        d = datetime.strptime(str(value)[:10], '%Y-%m-%d')
        return d.strftime('%d.%m.%Y')
    except (ValueError, TypeError):
        return value


@app.template_filter('status_badge')
def status_badge(status):
    mapping = {
        'active':          ('success',   'Aktiv'),
        'inactive':        ('secondary', 'Inaktiv'),
        'maintenance':     ('warning',   'Wartung'),
        'decommissioned':  ('danger',    'Ausgemustert'),
    }
    cls, label = mapping.get(status, ('light', status))
    return f'<span class="badge bg-{cls}">{label}</span>'


@app.context_processor
def inject_globals():
    return {
        'now': datetime.now(timezone.utc).replace(tzinfo=None),
        'csrf_token': generate_csrf,
    }


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        token = request.form.get('csrf_token', '')
        if not validate_csrf(token):
            flash('Ungültige Anfrage. Bitte versuchen Sie es erneut.', 'danger')
            return render_template('login.html', csrf_token=generate_csrf())

        ip = request.remote_addr
        now = time.time()

        # Check lockout
        attempt_info = _login_attempts.get(ip, {'count': 0, 'locked_until': 0})
        if attempt_info['locked_until'] > now:
            remaining_minutes = int((attempt_info['locked_until'] - now) / 60) + 1
            flash(f'Zu viele Fehlversuche. Bitte {remaining_minutes} Minute(n) warten.', 'danger')
            return render_template('login.html', csrf_token=generate_csrf())

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = query_db("SELECT * FROM app_users WHERE username = ?", (username,), one=True)

        if user and check_password_hash(user['password_hash'], password):
            # Success — reset attempts
            _login_attempts.pop(ip, None)

            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name'] or user['username']
            session['must_change_pw'] = bool(user['must_change_pw'])

            # Update last_login
            execute_db(
                "UPDATE app_users SET last_login = datetime('now') WHERE id = ?",
                (user['id'],)
            )

            next_url = request.form.get('next') or request.args.get('next') or url_for('dashboard')
            return redirect(next_url)
        else:
            # Failure — increment attempts
            count = attempt_info['count'] + 1
            locked_until = 0
            if count >= LOGIN_MAX_ATTEMPTS:
                locked_until = now + LOGIN_LOCKOUT_SECONDS
                flash(f'Zu viele Fehlversuche. Bitte {LOGIN_LOCKOUT_SECONDS // 60} Minuten warten.', 'danger')
            else:
                remaining = LOGIN_MAX_ATTEMPTS - count
                flash(f'Ungültiger Benutzername oder Passwort. Noch {remaining} Versuch(e).', 'danger')
            _login_attempts[ip] = {'count': count, 'locked_until': locked_until}
            return render_template('login.html', csrf_token=generate_csrf())

    return render_template('login.html', csrf_token=generate_csrf())


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

@app.route('/profile')
@login_required
def profile():
    user = query_db("SELECT * FROM app_users WHERE id = ?", (session['user_id'],), one=True)
    return render_template('profile.html', user=user)


@app.route('/profile/change-password', methods=['POST'])
@login_required
def profile_change_password():
    token = request.form.get('csrf_token', '')
    if not validate_csrf(token):
        flash('Ungültige Anfrage.', 'danger')
        return redirect(url_for('profile'))

    current_pw = request.form.get('current_password', '')
    new_pw = request.form.get('new_password', '')
    confirm_pw = request.form.get('confirm_password', '')

    user = query_db("SELECT * FROM app_users WHERE id = ?", (session['user_id'],), one=True)

    if not check_password_hash(user['password_hash'], current_pw):
        flash('Aktuelles Passwort ist falsch.', 'danger')
        return redirect(url_for('profile'))

    if len(new_pw) < 8:
        flash('Neues Passwort muss mindestens 8 Zeichen lang sein.', 'danger')
        return redirect(url_for('profile'))

    has_letter = any(c.isalpha() for c in new_pw)
    has_digit = any(c.isdigit() for c in new_pw)
    if not (has_letter and has_digit):
        flash('Neues Passwort muss mindestens einen Buchstaben und eine Zahl enthalten.', 'danger')
        return redirect(url_for('profile'))

    if new_pw != confirm_pw:
        flash('Passwörter stimmen nicht überein.', 'danger')
        return redirect(url_for('profile'))

    new_hash = generate_password_hash(new_pw)
    execute_db(
        "UPDATE app_users SET password_hash = ?, must_change_pw = 0 WHERE id = ?",
        (new_hash, session['user_id'])
    )
    session['must_change_pw'] = False
    flash('✓ Passwort wurde erfolgreich geändert.', 'success')
    return redirect(url_for('profile'))


# ---------------------------------------------------------------------------
# App User Management (admin only)
# ---------------------------------------------------------------------------

@app.route('/users')
@admin_required
def users():
    user_list = query_db("SELECT * FROM app_users ORDER BY username ASC")
    return render_template('users.html', users=user_list)


@app.route('/users/new', methods=['GET', 'POST'])
@admin_required
def user_new():
    if request.method == 'POST':
        token = request.form.get('csrf_token', '')
        if not validate_csrf(token):
            flash('Ungültige Anfrage.', 'danger')
            return render_template('user_form.html', user=request.form, edit=False)

        username = request.form.get('username', '').strip()
        full_name = request.form.get('full_name', '').strip()
        role = request.form.get('role', 'viewer')
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        error = None
        if not username:
            error = 'Benutzername ist erforderlich.'
        elif len(password) < 8:
            error = 'Passwort muss mindestens 8 Zeichen lang sein.'
        elif password != confirm_password:
            error = 'Passwörter stimmen nicht überein.'
        else:
            existing = query_db("SELECT id FROM app_users WHERE username = ?", (username,), one=True)
            if existing:
                error = f'Benutzername "{username}" ist bereits vergeben.'

        if error:
            flash(error, 'danger')
            return render_template('user_form.html', user=request.form, edit=False)

        pw_hash = generate_password_hash(password)
        execute_db(
            "INSERT INTO app_users (username, password_hash, full_name, role, must_change_pw) VALUES (?,?,?,?,?)",
            (username, pw_hash, full_name or None, role, 1)
        )
        flash(f'Benutzer "{username}" wurde erfolgreich erstellt.', 'success')
        return redirect(url_for('users'))

    return render_template('user_form.html', user={}, edit=False)


@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def user_edit(user_id):
    app_user = row_to_dict(query_db("SELECT * FROM app_users WHERE id = ?", (user_id,), one=True))
    if not app_user:
        abort(404)

    if request.method == 'POST':
        token = request.form.get('csrf_token', '')
        if not validate_csrf(token):
            flash('Ungültige Anfrage.', 'danger')
            return render_template('user_form.html', user=app_user, edit=True, user_id=user_id)

        username = request.form.get('username', '').strip()
        full_name = request.form.get('full_name', '').strip()
        role = request.form.get('role', 'viewer')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username:
            flash('Benutzername ist erforderlich.', 'danger')
            return render_template('user_form.html', user=request.form, edit=True, user_id=user_id)

        # Check username uniqueness (excluding current user)
        existing = query_db(
            "SELECT id FROM app_users WHERE username = ? AND id != ?", (username, user_id), one=True
        )
        if existing:
            flash(f'Benutzername "{username}" ist bereits vergeben.', 'danger')
            return render_template('user_form.html', user=request.form, edit=True, user_id=user_id)

        if new_password:
            if len(new_password) < 8:
                flash('Passwort muss mindestens 8 Zeichen lang sein.', 'danger')
                return render_template('user_form.html', user=request.form, edit=True, user_id=user_id)
            if new_password != confirm_password:
                flash('Passwörter stimmen nicht überein.', 'danger')
                return render_template('user_form.html', user=request.form, edit=True, user_id=user_id)
            pw_hash = generate_password_hash(new_password)
            execute_db(
                "UPDATE app_users SET username=?, full_name=?, role=?, password_hash=?, must_change_pw=1 WHERE id=?",
                (username, full_name or None, role, pw_hash, user_id)
            )
        else:
            execute_db(
                "UPDATE app_users SET username=?, full_name=?, role=? WHERE id=?",
                (username, full_name or None, role, user_id)
            )

        flash(f'Benutzer "{username}" wurde erfolgreich aktualisiert.', 'success')
        return redirect(url_for('users'))

    return render_template('user_form.html', user=app_user, edit=True, user_id=user_id)


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def user_delete(user_id):
    token = request.form.get('csrf_token', '')
    if not validate_csrf(token):
        flash('Ungültige Anfrage.', 'danger')
        return redirect(url_for('users'))

    if user_id == session.get('user_id'):
        flash('Sie können Ihren eigenen Account nicht löschen.', 'danger')
        return redirect(url_for('users'))

    app_user = query_db("SELECT * FROM app_users WHERE id = ?", (user_id,), one=True)
    if not app_user:
        abort(404)
    execute_db("DELETE FROM app_users WHERE id = ?", (user_id,))
    flash(f'Benutzer "{app_user["username"]}" wurde erfolgreich gelöscht.', 'success')
    return redirect(url_for('users'))


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

@app.route('/seed')
@login_required
def seed():
    db = get_db()

    # Guard: only seed if no devices exist yet
    if db.execute("SELECT COUNT(*) FROM devices").fetchone()[0] > 0:
        flash('Beispieldaten bereits vorhanden — Seed wurde nicht erneut ausgeführt.', 'warning')
        return redirect(url_for('dashboard'))

    # Locations
    locations = [
        ('Hauptgebäude Büro 1', 'Hauptgebäude', 'EG', '101'),
        ('Hauptgebäude Büro 2', 'Hauptgebäude', '1. OG', '201'),
        ('Serverraum',          'Nebengebäude',  'UG',   'SR-01'),
        ('Home Office',         '—',             '—',    '—'),
    ]
    for loc in locations:
        db.execute(
            "INSERT INTO locations (name, building, floor, room) VALUES (?,?,?,?)",
            loc
        )

    # Users (legacy employee users — kept for DB compatibility)
    users = [
        ('Anna Müller',   'a.mueller@firma.de',   'IT',         '+49 30 12345-10'),
        ('Ben Schmidt',   'b.schmidt@firma.de',   'Buchhaltung','+49 30 12345-11'),
        ('Clara Becker',  'c.becker@firma.de',    'Vertrieb',   '+49 30 12345-12'),
        ('David Wagner',  'd.wagner@firma.de',    'Management', '+49 30 12345-13'),
        ('Eva Schulz',    'e.schulz@firma.de',    'HR',         '+49 30 12345-14'),
    ]
    for u in users:
        db.execute(
            "INSERT INTO users (name, email, department, phone) VALUES (?,?,?,?)",
            u
        )

    db.commit()

    # Devices
    today = date.today()
    devices = [
        ('Workstation-IT-01',  'PC',      'SN-PC-001',  'AA:BB:CC:DD:EE:01', '192.168.1.10',
         'Windows 11 Pro',   'active',        1, 1,
         '2022-03-15', '2025-03-15', 'IT-Abteilung Hauptrechner'),
        ('Laptop-Sales-01',   'Laptop',   'SN-LP-001',  'AA:BB:CC:DD:EE:02', '192.168.1.11',
         'Windows 11 Home',  'active',        2, 3,
         '2023-01-10', '2026-01-10', 'Vertrieb Außendienst'),
        ('Server-PROD-01',    'Server',   'SN-SRV-001', 'AA:BB:CC:DD:EE:03', '10.0.0.1',
         'Ubuntu Server 22', 'active',        3, 1,
         '2021-06-01', (today + timedelta(days=45)).strftime('%Y-%m-%d'), 'Produktionsserver'),
        ('Drucker-HG-EG',     'Printer',  'SN-PR-001',  None,                '192.168.1.20',
         None,               'maintenance',   1, None,
         '2020-05-20', '2023-05-20', 'Netzwerkdrucker EG'),
        ('Switch-HG-01',      'Network',  'SN-SW-001',  'AA:BB:CC:DD:EE:05', '192.168.1.254',
         None,               'active',        1, 1,
         '2021-09-01', (today + timedelta(days=70)).strftime('%Y-%m-%d'), '24-Port Managed Switch'),
        ('iPhone-Mgmt-01',    'Phone',    'SN-PH-001',  None,                None,
         'iOS 17',          'active',        4, 4,
         '2023-11-01', '2025-11-01', 'Geschäftshandy Management'),
        ('iPad-HR-01',        'Tablet',   'SN-TAB-001', None,                '192.168.1.30',
         'iPadOS 17',       'inactive',      2, 5,
         '2022-07-15', '2024-07-15', 'HR Tablet'),
        ('Monitor-IT-02',     'Monitor',  'SN-MON-001', None,                None,
         None,               'active',        1, 1,
         '2023-04-01', '2026-04-01', '27" 4K Display'),
        ('Laptop-OLD-01',     'Laptop',   'SN-LP-OLD',  'AA:BB:CC:DD:EE:09', None,
         'Windows 10',      'decommissioned',1, None,
         '2018-02-10', '2021-02-10', 'Altgerät ausgemustert'),
        ('Server-BACKUP-01',  'Server',   'SN-SRV-002', 'AA:BB:CC:DD:EE:10', '10.0.0.2',
         'Debian 12',       'active',        3, 1,
         '2022-12-01', (today + timedelta(days=20)).strftime('%Y-%m-%d'), 'Backup-Server'),
    ]
    for d in devices:
        db.execute(
            """INSERT INTO devices
               (name, category, serial_number, mac_address, ip_address,
                operating_system, status, location_id, user_id,
                purchase_date, warranty_expiry, notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            d
        )

    db.commit()
    flash('Beispieldaten wurden erfolgreich eingefügt.', 'success')
    return redirect(url_for('dashboard'))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route('/')
@login_required
def dashboard():
    total = query_db("SELECT COUNT(*) as c FROM devices", one=True)['c']

    status_counts = query_db(
        "SELECT status, COUNT(*) as c FROM devices GROUP BY status"
    )

    category_counts = query_db(
        "SELECT category, COUNT(*) as c FROM devices GROUP BY category ORDER BY c DESC"
    )

    recent = query_db(
        """SELECT d.*, l.name as location_name
           FROM devices d
           LEFT JOIN locations l ON d.location_id = l.id
           ORDER BY d.created_at DESC LIMIT 5"""
    )

    ninety_days = (date.today() + timedelta(days=90)).strftime('%Y-%m-%d')
    today_str   = date.today().strftime('%Y-%m-%d')
    expiring = query_db(
        """SELECT d.*, l.name as location_name
           FROM devices d
           LEFT JOIN locations l ON d.location_id = l.id
           WHERE d.warranty_expiry BETWEEN ? AND ?
           ORDER BY d.warranty_expiry ASC""",
        (today_str, ninety_days)
    )

    status_map = {r['status']: r['c'] for r in status_counts}

    return render_template(
        'dashboard.html',
        total=total,
        status_map=status_map,
        category_counts=category_counts,
        recent=recent,
        expiring=expiring,
    )


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

CATEGORIES = ['PC', 'Laptop', 'Server', 'Printer', 'Network', 'Phone', 'Tablet', 'Monitor', 'Other']
STATUSES   = ['active', 'inactive', 'maintenance', 'decommissioned']

STATUS_LABELS = {
    'active':         'Aktiv',
    'inactive':       'Inaktiv',
    'maintenance':    'Wartung',
    'decommissioned': 'Ausgemustert',
}

CATEGORY_LABELS = {
    'PC':      'PC',
    'Laptop':  'Laptop',
    'Server':  'Server',
    'Printer': 'Drucker',
    'Network': 'Netzwerk',
    'Phone':   'Telefon',
    'Tablet':  'Tablet',
    'Monitor': 'Monitor',
    'Other':   'Sonstiges',
}


@app.route('/devices')
@login_required
def devices():
    search   = request.args.get('search', '').strip()
    status   = request.args.get('status', '')
    category = request.args.get('category', '')
    location = request.args.get('location', '')

    query  = """SELECT d.*, l.name as location_name
                FROM devices d
                LEFT JOIN locations l ON d.location_id = l.id
                WHERE 1=1"""
    params = []

    if search:
        query += """ AND (d.name LIKE ? OR d.serial_number LIKE ?
                         OR d.ip_address LIKE ? OR d.mac_address LIKE ?)"""
        like = f'%{search}%'
        params += [like, like, like, like]
    if status:
        query += " AND d.status = ?"
        params.append(status)
    if category:
        query += " AND d.category = ?"
        params.append(category)
    if location:
        query += " AND d.location_id = ?"
        params.append(location)

    query += " ORDER BY d.name ASC"

    device_list = query_db(query, params)
    locations   = query_db("SELECT * FROM locations ORDER BY name")

    return render_template(
        'devices.html',
        devices=device_list,
        locations=locations,
        categories=CATEGORIES,
        category_labels=CATEGORY_LABELS,
        statuses=STATUSES,
        status_labels=STATUS_LABELS,
        search=search,
        sel_status=status,
        sel_category=category,
        sel_location=location,
    )


@app.route('/devices/export')
@login_required
def devices_export():
    search   = request.args.get('search', '').strip()
    status   = request.args.get('status', '')
    category = request.args.get('category', '')
    location = request.args.get('location', '')

    query  = """SELECT d.name, d.category, d.serial_number, d.mac_address,
                       d.ip_address, d.operating_system, d.status,
                       l.name as location_name,
                       d.purchase_date, d.warranty_expiry, d.notes
                FROM devices d
                LEFT JOIN locations l ON d.location_id = l.id
                WHERE 1=1"""
    params = []

    if search:
        query += " AND (d.name LIKE ? OR d.serial_number LIKE ? OR d.ip_address LIKE ?)"
        like = f'%{search}%'
        params += [like, like, like]
    if status:
        query += " AND d.status = ?"
        params.append(status)
    if category:
        query += " AND d.category = ?"
        params.append(category)
    if location:
        query += " AND d.location_id = ?"
        params.append(location)

    query += " ORDER BY d.name ASC"
    rows = query_db(query, params)

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow([
        'Name', 'Kategorie', 'Seriennummer', 'MAC-Adresse',
        'IP-Adresse', 'Betriebssystem', 'Status',
        'Standort', 'Kaufdatum', 'Garantie bis', 'Notizen'
    ])
    for row in rows:
        writer.writerow([
            row['name'], CATEGORY_LABELS.get(row['category'], row['category']),
            row['serial_number'] or '', row['mac_address'] or '',
            row['ip_address'] or '', row['operating_system'] or '',
            STATUS_LABELS.get(row['status'], row['status']),
            row['location_name'] or '',
            row['purchase_date'] or '', row['warranty_expiry'] or '',
            row['notes'] or ''
        ])

    output.seek(0)
    filename = f"geraete_export_{date.today().strftime('%Y%m%d')}.csv"
    return Response(
        output.getvalue().encode('utf-8-sig'),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


@app.route('/devices/new', methods=['GET', 'POST'])
@login_required
def device_new():
    locations = query_db("SELECT * FROM locations ORDER BY name")

    if request.method == 'POST':
        name      = request.form.get('name', '').strip()
        if not name:
            flash('Gerätename ist erforderlich.', 'danger')
            return render_template('device_form.html', device=request.form,
                                   locations=locations,
                                   categories=CATEGORIES, statuses=STATUSES,
                                   category_labels=CATEGORY_LABELS,
                                   status_labels=STATUS_LABELS, edit=False)

        execute_db(
            """INSERT INTO devices
               (name, category, serial_number, mac_address, ip_address,
                operating_system, status, location_id,
                purchase_date, warranty_expiry, notes,
                cpu_info, ram_info, manufacturer, model)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                name,
                request.form.get('category', 'Other'),
                request.form.get('serial_number', '').strip() or None,
                request.form.get('mac_address', '').strip() or None,
                request.form.get('ip_address', '').strip() or None,
                request.form.get('operating_system', '').strip() or None,
                request.form.get('status', 'active'),
                request.form.get('location_id') or None,
                request.form.get('purchase_date') or None,
                request.form.get('warranty_expiry') or None,
                request.form.get('notes', '').strip() or None,
                request.form.get('cpu_info', '').strip() or None,
                request.form.get('ram_info', '').strip() or None,
                request.form.get('manufacturer', '').strip() or None,
                request.form.get('model', '').strip() or None,
            )
        )
        flash('Gerät wurde erfolgreich hinzugefügt.', 'success')
        return redirect(url_for('devices'))

    # Pre-fill from query params (e.g. when importing from scanner)
    prefill = {
        'ip_address':       request.args.get('ip', ''),
        'mac_address':      request.args.get('mac', ''),
        'name':             request.args.get('name', ''),
        'operating_system': request.args.get('os', ''),
        'manufacturer':     request.args.get('manufacturer', ''),
        'model':            request.args.get('model', ''),
        'serial_number':    request.args.get('serial', ''),
        'cpu_info':         request.args.get('cpu', ''),
        'ram_info':         request.args.get('ram', ''),
    }

    return render_template('device_form.html', device=prefill, locations=locations,
                           categories=CATEGORIES, statuses=STATUSES,
                           category_labels=CATEGORY_LABELS,
                           status_labels=STATUS_LABELS, edit=False)


@app.route('/devices/<int:device_id>')
@login_required
def device_detail(device_id):
    device = query_db(
        """SELECT d.*, l.name as location_name, l.building, l.floor, l.room
           FROM devices d
           LEFT JOIN locations l ON d.location_id = l.id
           WHERE d.id = ?""",
        (device_id,), one=True
    )
    if not device:
        abort(404)

    sections = query_db("SELECT * FROM detail_sections ORDER BY position")
    fields_by_section = {}
    for s in sections:
        fields = query_db(
            """SELECT f.id, f.section_id, f.label, f.field_key, f.field_type,
                      f.position, f.created_at,
                      COALESCE(f.visible, 1) as visible,
                      COALESCE(f.field_width, 'third') as field_width,
                      COALESCE(f.display_style, 'stacked') as display_style,
                      COALESCE(v.value,'') as value
               FROM detail_fields f
               LEFT JOIN device_field_values v ON v.field_id=f.id AND v.device_id=?
               WHERE f.section_id=?
               ORDER BY f.position""",
            (device_id, s['id'])
        )
        fields_by_section[s['id']] = [dict(row) for row in fields]

    is_admin = session.get('role') == 'admin'
    return render_template('device_detail.html', device=device,
                           category_labels=CATEGORY_LABELS,
                           status_labels=STATUS_LABELS,
                           sections=sections,
                           fields_by_section=fields_by_section,
                           is_admin=is_admin)


@app.route('/devices/<int:device_id>/edit', methods=['GET', 'POST'])
@login_required
def device_edit(device_id):
    device    = row_to_dict(query_db("SELECT * FROM devices WHERE id = ?", (device_id,), one=True))
    if not device:
        abort(404)
    locations = query_db("SELECT * FROM locations ORDER BY name")

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Gerätename ist erforderlich.', 'danger')
            return render_template('device_form.html', device=request.form,
                                   locations=locations,
                                   categories=CATEGORIES, statuses=STATUSES,
                                   category_labels=CATEGORY_LABELS,
                                   status_labels=STATUS_LABELS, edit=True,
                                   device_id=device_id)

        execute_db(
            """UPDATE devices SET
               name=?, category=?, serial_number=?, mac_address=?, ip_address=?,
               operating_system=?, status=?, location_id=?,
               purchase_date=?, warranty_expiry=?, notes=?,
               cpu_info=?, ram_info=?, manufacturer=?, model=?
               WHERE id=?""",
            (
                name,
                request.form.get('category', 'Other'),
                request.form.get('serial_number', '').strip() or None,
                request.form.get('mac_address', '').strip() or None,
                request.form.get('ip_address', '').strip() or None,
                request.form.get('operating_system', '').strip() or None,
                request.form.get('status', 'active'),
                request.form.get('location_id') or None,
                request.form.get('purchase_date') or None,
                request.form.get('warranty_expiry') or None,
                request.form.get('notes', '').strip() or None,
                request.form.get('cpu_info', '').strip() or None,
                request.form.get('ram_info', '').strip() or None,
                request.form.get('manufacturer', '').strip() or None,
                request.form.get('model', '').strip() or None,
                device_id,
            )
        )
        flash('Gerät wurde erfolgreich aktualisiert.', 'success')
        return redirect(url_for('device_detail', device_id=device_id))

    return render_template('device_form.html', device=device,
                           locations=locations,
                           categories=CATEGORIES, statuses=STATUSES,
                           category_labels=CATEGORY_LABELS,
                           status_labels=STATUS_LABELS,
                           edit=True, device_id=device_id)


@app.route('/devices/<int:device_id>/wol', methods=['POST'])
@login_required
def device_wol(device_id):
    device = query_db("SELECT * FROM devices WHERE id=?", (device_id,), one=True)
    if not device:
        abort(404)
    mac = device['mac_address']
    if not mac:
        return jsonify({'error': 'Keine MAC-Adresse für dieses Gerät gespeichert.'})
    try:
        scanner.wake_on_lan(mac)
        return jsonify({'ok': True, 'msg': f'Magic Packet wurde an {mac} gesendet. PC startet in Kürze.'})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/devices/<int:device_id>/rdp')
@login_required
def device_rdp(device_id):
    device = query_db("SELECT * FROM devices WHERE id=?", (device_id,), one=True)
    if not device:
        abort(404)
    ip = device['ip_address']
    if not ip:
        flash('Keine IP-Adresse für dieses Gerät gespeichert.', 'warning')
        return redirect(url_for('device_detail', device_id=device_id))
    name = device['name'].replace(' ', '_')
    rdp_content = f"""full address:s:{ip}
username:s:
screen mode id:i:2
use multimon:i:0
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:32
compression:i:1
keyboardhook:i:2
audiocapturemode:i:0
videoplaybackmode:i:1
connection type:i:7
networkautodetect:i:1
bandwidthautodetect:i:1
displayconnectionbar:i:1
autoreconnection enabled:i:1
authentication level:i:2
prompt for credentials:i:1
negotiate security layer:i:1
redirectclipboard:i:1
redirectprinters:i:1
redirectsmartcards:i:1
bitmapcachepersistenable:i:1
"""
    return Response(
        rdp_content,
        mimetype='application/x-rdp',
        headers={'Content-Disposition': f'attachment; filename="{name}.rdp"'}
    )


@app.route('/devices/<int:device_id>/delete', methods=['POST'])
@login_required
def device_delete(device_id):
    device = query_db("SELECT * FROM devices WHERE id = ?", (device_id,), one=True)
    if not device:
        abort(404)
    execute_db("DELETE FROM devices WHERE id = ?", (device_id,))
    flash('Gerät wurde erfolgreich gelöscht.', 'success')
    return redirect(url_for('devices'))


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------

@app.route('/locations')
@login_required
def locations():
    search = request.args.get('search', '').strip()
    query  = """SELECT l.*, COUNT(d.id) as device_count
                FROM locations l
                LEFT JOIN devices d ON d.location_id = l.id
                WHERE 1=1"""
    params = []
    if search:
        query += " AND (l.name LIKE ? OR l.building LIKE ? OR l.room LIKE ?)"
        like = f'%{search}%'
        params += [like, like, like]
    query += " GROUP BY l.id ORDER BY l.name ASC"
    location_list = query_db(query, params)
    return render_template('locations.html', locations=location_list, search=search)


@app.route('/locations/new', methods=['GET', 'POST'])
@login_required
def location_new():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Name ist erforderlich.', 'danger')
            return render_template('location_form.html', location=request.form, edit=False)

        execute_db(
            "INSERT INTO locations (name, building, floor, room) VALUES (?,?,?,?)",
            (
                name,
                request.form.get('building', '').strip() or None,
                request.form.get('floor', '').strip() or None,
                request.form.get('room', '').strip() or None,
            )
        )
        flash('Standort wurde erfolgreich hinzugefügt.', 'success')
        return redirect(url_for('locations'))

    return render_template('location_form.html', location={}, edit=False)


@app.route('/locations/<int:location_id>/edit', methods=['GET', 'POST'])
@login_required
def location_edit(location_id):
    location = row_to_dict(query_db("SELECT * FROM locations WHERE id = ?", (location_id,), one=True))
    if not location:
        abort(404)

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Name ist erforderlich.', 'danger')
            return render_template('location_form.html', location=request.form,
                                   edit=True, location_id=location_id)

        execute_db(
            "UPDATE locations SET name=?, building=?, floor=?, room=? WHERE id=?",
            (
                name,
                request.form.get('building', '').strip() or None,
                request.form.get('floor', '').strip() or None,
                request.form.get('room', '').strip() or None,
                location_id,
            )
        )
        flash('Standort wurde erfolgreich aktualisiert.', 'success')
        return redirect(url_for('locations'))

    return render_template('location_form.html', location=location,
                           edit=True, location_id=location_id)


@app.route('/locations/<int:location_id>/delete', methods=['POST'])
@login_required
def location_delete(location_id):
    location = query_db("SELECT * FROM locations WHERE id = ?", (location_id,), one=True)
    if not location:
        abort(404)
    execute_db("DELETE FROM locations WHERE id = ?", (location_id,))
    flash('Standort wurde erfolgreich gelöscht.', 'success')
    return redirect(url_for('locations'))


# ---------------------------------------------------------------------------
# Network Scanner
# ---------------------------------------------------------------------------

@app.route('/scan')
@login_required
def scan():
    return render_template('scan.html')


@app.route('/scan/start', methods=['POST'])
@login_required
def scan_start():
    state = scanner.get_scan_state()
    if state.get('running'):
        return jsonify({'error': 'Scan läuft bereits'})

    network = request.form.get('network', '').strip() or None
    use_nmap = request.form.get('use_nmap', 'true').lower() not in ('false', '0', '')
    tool = request.form.get('tool', 'auto')

    scanner.start_scan(network=network, use_nmap=use_nmap, tool=tool)
    return jsonify({'ok': True})


@app.route('/scan/status')
@login_required
def scan_status():
    return jsonify(scanner.get_scan_state())


@app.route('/scan/save', methods=['POST'])
@login_required
def scan_save():
    state = scanner.get_scan_state()
    results = state.get('results', [])
    saved = 0
    db = get_db()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    for r in results:
        existing = db.execute(
            "SELECT id, status, imported_device_id FROM discovered_devices WHERE ip = ?",
            (r['ip'],)
        ).fetchone()

        if existing:
            db.execute(
                """UPDATE discovered_devices
                   SET mac=?, hostname=?, vendor=?, os=?, os_accuracy=?,
                       last_seen=?
                   WHERE ip=?""",
                (
                    r.get('mac', ''),
                    r.get('hostname', ''),
                    r.get('vendor', ''),
                    r.get('os', ''),
                    r.get('os_accuracy', ''),
                    now_str,
                    r['ip'],
                )
            )
        else:
            db.execute(
                """INSERT INTO discovered_devices
                   (ip, mac, hostname, vendor, os, os_accuracy, first_seen, last_seen, status)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    r.get('ip', ''),
                    r.get('mac', ''),
                    r.get('hostname', ''),
                    r.get('vendor', ''),
                    r.get('os', ''),
                    r.get('os_accuracy', ''),
                    r.get('first_seen', now_str),
                    now_str,
                    'new',
                )
            )
        saved += 1

    db.commit()
    return jsonify({'saved': saved})


@app.route('/scan/list')
@login_required
def scan_list():
    rows = query_db("SELECT * FROM discovered_devices ORDER BY ip ASC")
    return jsonify([dict(r) for r in rows])


@app.route('/scan/import/<int:disc_id>', methods=['POST'])
@login_required
def scan_import(disc_id):
    disc = query_db(
        "SELECT * FROM discovered_devices WHERE id = ?", (disc_id,), one=True
    )
    if not disc:
        abort(404)
    execute_db(
        "UPDATE discovered_devices SET status='imported' WHERE id=?",
        (disc_id,)
    )
    disc_d = dict(disc)
    return redirect(url_for(
        'device_new',
        ip=disc_d.get('ip') or '',
        mac=disc_d.get('mac') or '',
        name=disc_d.get('hostname') or '',
        os=disc_d.get('os_caption') or disc_d.get('os') or '',
        manufacturer=disc_d.get('manufacturer') or '',
        model=disc_d.get('model') or '',
        serial=disc_d.get('serial_number') or '',
        cpu=disc_d.get('cpu') or '',
        ram=str(disc_d.get('ram_gb') or ''),
    ))


@app.route('/scan/dismiss/<int:disc_id>', methods=['POST'])
@login_required
def scan_dismiss(disc_id):
    disc = query_db(
        "SELECT id FROM discovered_devices WHERE id = ?", (disc_id,), one=True
    )
    if not disc:
        abort(404)
    execute_db(
        "UPDATE discovered_devices SET status='ignored' WHERE id=?",
        (disc_id,)
    )
    return jsonify({'ok': True})


@app.route('/scan/reset/<int:disc_id>', methods=['POST'])
@login_required
def scan_reset(disc_id):
    disc = query_db(
        "SELECT id FROM discovered_devices WHERE id = ?", (disc_id,), one=True
    )
    if not disc:
        abort(404)
    execute_db(
        "UPDATE discovered_devices SET status='new' WHERE id=?",
        (disc_id,)
    )
    return jsonify({'ok': True})


@app.route('/scan/hardware/<int:disc_id>', methods=['POST'])
@login_required
def scan_hardware(disc_id):
    device = query_db("SELECT * FROM discovered_devices WHERE id=?", (disc_id,), one=True)
    if not device:
        return jsonify({'error': 'not found'}), 404

    ip = device['ip']
    username = request.form.get('username') or None
    password = request.form.get('password') or None
    domain   = request.form.get('domain') or ''
    method   = request.form.get('method', 'auto')  # auto, wmi, ssh

    hw = {}

    # Step 1: SMB/NetBIOS info (no credentials, always try)
    smb = scanner.get_smb_info(ip)
    if smb.get('hostname'):
        execute_db("UPDATE discovered_devices SET hostname=? WHERE id=?",
                   (smb['hostname'], disc_id))
    if smb.get('os') and not device['os']:
        execute_db("UPDATE discovered_devices SET os=? WHERE id=?",
                   (smb['os'], disc_id))

    # Step 2: WMI (try without credentials first, then with)
    if method in ('auto', 'wmi'):
        hw = scanner.query_hardware_wmi(ip, username, password, domain)
        if hw.get('error') == 'access_denied' and not username:
            execute_db(
                "UPDATE discovered_devices SET hw_status='needs_credentials', hw_error=? WHERE id=?",
                ('Credentials erforderlich', disc_id))
            return jsonify({'status': 'needs_credentials', 'ip': ip})

    # Step 3: SSH fallback
    if method == 'ssh' and username:
        hw = scanner.query_hardware_ssh(ip, username, password)

    if hw.get('error') and hw['error'] not in (None, ''):
        error_map = {
            'wmi_not_installed':      'pip install wmi pywin32 erforderlich',
            'paramiko_not_installed': 'pip install paramiko erforderlich',
            'access_denied':          'Zugriff verweigert — Credentials eingeben',
            'unreachable':            'Host nicht erreichbar (RPC/WMI blockiert)',
        }
        err_msg = error_map.get(hw['error'], hw['error'])
        execute_db(
            "UPDATE discovered_devices SET hw_status=?, hw_error=?, hw_queried_at=datetime('now') WHERE id=?",
            ('error', err_msg, disc_id))
        return jsonify({'status': 'error', 'error': err_msg})

    # Save hardware info
    now = datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M')
    execute_db("""
        UPDATE discovered_devices SET
            cpu=?, cpu_cores=?, ram_gb=?, disks=?, manufacturer=?, model=?,
            serial_number=?, os_caption=?, os_build=?, last_boot=?,
            hw_status='ok', hw_error=NULL, hw_queried_at=?
        WHERE id=?
    """, (
        hw.get('cpu'), hw.get('cpu_cores'), hw.get('ram_gb'),
        hw.get('disks'), hw.get('manufacturer'), hw.get('model'),
        hw.get('serial'), hw.get('os_caption'), hw.get('os_build'),
        hw.get('last_boot'), now, disc_id
    ))

    return jsonify({'status': 'ok', 'data': hw})


@app.route('/scan/hardware/all', methods=['POST'])
@login_required
def scan_hardware_all():
    devices = query_db(
        "SELECT * FROM discovered_devices WHERE status IN ('new', 'imported') ORDER BY ip ASC"
    )
    results = {'ok': 0, 'error': 0, 'needs_credentials': 0, 'total': len(devices)}

    for device in devices:
        ip = device['ip']
        disc_id = device['id']

        # SMB first
        smb = scanner.get_smb_info(ip)
        if smb.get('hostname'):
            execute_db("UPDATE discovered_devices SET hostname=? WHERE id=?",
                       (smb['hostname'], disc_id))
        if smb.get('os') and not device['os']:
            execute_db("UPDATE discovered_devices SET os=? WHERE id=?",
                       (smb['os'], disc_id))

        # WMI without credentials
        hw = scanner.query_hardware_wmi(ip)
        if hw.get('error') == 'access_denied':
            execute_db(
                "UPDATE discovered_devices SET hw_status='needs_credentials', hw_error=? WHERE id=?",
                ('Credentials erforderlich', disc_id))
            results['needs_credentials'] += 1
            continue

        if hw.get('error') and hw['error'] not in (None, ''):
            error_map = {
                'wmi_not_installed':      'pip install wmi pywin32 erforderlich',
                'paramiko_not_installed': 'pip install paramiko erforderlich',
                'unreachable':            'Host nicht erreichbar (RPC/WMI blockiert)',
            }
            err_msg = error_map.get(hw['error'], hw['error'])
            execute_db(
                "UPDATE discovered_devices SET hw_status=?, hw_error=?, hw_queried_at=datetime('now') WHERE id=?",
                ('error', err_msg, disc_id))
            results['error'] += 1
            continue

        now = datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M')
        execute_db("""
            UPDATE discovered_devices SET
                cpu=?, cpu_cores=?, ram_gb=?, disks=?, manufacturer=?, model=?,
                serial_number=?, os_caption=?, os_build=?, last_boot=?,
                hw_status='ok', hw_error=NULL, hw_queried_at=?
            WHERE id=?
        """, (
            hw.get('cpu'), hw.get('cpu_cores'), hw.get('ram_gb'),
            hw.get('disks'), hw.get('manufacturer'), hw.get('model'),
            hw.get('serial'), hw.get('os_caption'), hw.get('os_build'),
            hw.get('last_boot'), now, disc_id
        ))
        results['ok'] += 1

    return jsonify(results)


# ---------------------------------------------------------------------------
# Device field values
# ---------------------------------------------------------------------------

@app.route('/devices/<int:device_id>/fields', methods=['POST'])
@login_required
def device_save_fields(device_id):
    if not validate_csrf_flexible():
        return jsonify({'error': 'CSRF validation failed'}), 403
    device = query_db("SELECT id FROM devices WHERE id=?", (device_id,), one=True)
    if not device:
        abort(404)
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    if not data:
        return jsonify({'error': 'No data'}), 400
    db = get_db()
    for field_id_str, value in data.items():
        try:
            field_id_int = int(field_id_str)
        except (ValueError, TypeError):
            continue
        db.execute(
            "INSERT OR REPLACE INTO device_field_values (device_id, field_id, value) VALUES (?,?,?)",
            (device_id, field_id_int, str(value) if value is not None else '')
        )
    db.commit()
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# Layout editor (admin only)
# ---------------------------------------------------------------------------

@app.route('/layout')
@admin_required
def layout_editor():
    sections = query_db("SELECT * FROM detail_sections ORDER BY position")
    fields_by_section = {}
    for s in sections:
        fields = query_db(
            "SELECT * FROM detail_fields WHERE section_id=? ORDER BY position",
            (s['id'],)
        )
        fields_by_section[s['id']] = fields
    return render_template('layout_editor.html', sections=sections,
                           fields_by_section=fields_by_section)


@app.route('/layout/sections', methods=['POST'])
@admin_required
def layout_section_create():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    name = (data.get('name') or '').strip()
    icon = (data.get('icon') or 'bi-grid').strip()
    if not name:
        return jsonify({'error': 'Name required'}), 400
    db = get_db()
    max_pos = db.execute("SELECT COALESCE(MAX(position),0) FROM detail_sections").fetchone()[0]
    cur = db.execute(
        "INSERT INTO detail_sections (name, icon, position) VALUES (?,?,?)",
        (name, icon, max_pos + 1)
    )
    db.commit()
    sec_id = cur.lastrowid
    row = db.execute("SELECT * FROM detail_sections WHERE id=?", (sec_id,)).fetchone()
    return jsonify(dict(row))


@app.route('/layout/sections/<int:section_id>/update', methods=['POST'])
@admin_required
def layout_section_update(section_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    name = (data.get('name') or '').strip()
    icon = (data.get('icon') or 'bi-grid').strip()
    if not name:
        return jsonify({'error': 'Name required'}), 400
    width = data.get('width', 'half')
    min_height = int(data.get('min_height', 0) or 0)
    db = get_db()
    db.execute("UPDATE detail_sections SET name=?, icon=?, width=?, min_height=? WHERE id=?",
               (name, icon, width, min_height, section_id))
    db.commit()
    row = db.execute("SELECT * FROM detail_sections WHERE id=?", (section_id,)).fetchone()
    if not row:
        abort(404)
    return jsonify(dict(row))


@app.route('/layout/sections/<int:section_id>/width', methods=['POST'])
@admin_required
def layout_section_width(section_id):
    if not validate_csrf_flexible():
        return jsonify({'error': 'CSRF validation failed'}), 403
    data = request.get_json() or {}
    width = data.get('width', 'half')
    if width not in ('half', 'third', 'full'):
        width = 'half'
    execute_db("UPDATE detail_sections SET width=? WHERE id=?", (width, section_id))
    return jsonify({'ok': True})


@app.route('/layout/sections/<int:section_id>/height', methods=['POST'])
@admin_required
def layout_section_height(section_id):
    if not validate_csrf_flexible():
        return jsonify({'error': 'CSRF validation failed'}), 403
    data = request.get_json() or {}
    height = int(data.get('height', 0) or 0)
    execute_db("UPDATE detail_sections SET min_height=? WHERE id=?", (height, section_id))
    return jsonify({'ok': True})


@app.route('/layout/fields/<int:field_id>/toggle-visible', methods=['POST'])
@admin_required
def layout_field_toggle_visible(field_id):
    if not validate_csrf_flexible():
        return jsonify({'error': 'CSRF validation failed'}), 403
    field = query_db("SELECT visible FROM detail_fields WHERE id=?", (field_id,), one=True)
    if not field:
        abort(404)
    new_val = 0 if field['visible'] else 1
    execute_db("UPDATE detail_fields SET visible=? WHERE id=?", (new_val, field_id))
    return jsonify({'ok': True, 'visible': new_val})


@app.route('/layout/fields/<int:field_id>/field-width', methods=['POST'])
@admin_required
def layout_field_width(field_id):
    if not validate_csrf_flexible():
        return jsonify({'error': 'CSRF validation failed'}), 403
    data = request.get_json() or {}
    fw = data.get('field_width', 'third')
    if fw not in ('third', 'half', 'full'):
        fw = 'third'
    execute_db("UPDATE detail_fields SET field_width=? WHERE id=?", (fw, field_id))
    return jsonify({'ok': True})


@app.route('/layout/fields/<int:field_id>/display-style', methods=['POST'])
@admin_required
def layout_field_display_style(field_id):
    if not validate_csrf_flexible():
        return jsonify({'error': 'CSRF validation failed'}), 403
    data = request.get_json() or {}
    style = data.get('display_style', 'stacked')
    if style not in ('stacked', 'inline'):
        style = 'stacked'
    execute_db("UPDATE detail_fields SET display_style=? WHERE id=?", (style, field_id))
    return jsonify({'ok': True, 'display_style': style})


@app.route('/layout/sections/<int:section_id>/delete', methods=['POST'])
@admin_required
def layout_section_delete(section_id):
    db = get_db()
    sec = db.execute("SELECT * FROM detail_sections WHERE id=?", (section_id,)).fetchone()
    if not sec:
        abort(404)
    db.execute("DELETE FROM detail_sections WHERE id=?", (section_id,))
    db.commit()
    return jsonify({'ok': True})


@app.route('/layout/sections/reorder', methods=['POST'])
@admin_required
def layout_sections_reorder():
    if not validate_csrf_flexible():
        return jsonify({'error': 'CSRF validation failed'}), 403
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    db = get_db()
    for item in data:
        db.execute("UPDATE detail_sections SET position=? WHERE id=?",
                   (item['position'], item['id']))
    db.commit()
    return jsonify({'ok': True})


@app.route('/layout/fields', methods=['POST'])
@admin_required
def layout_field_create():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    label = (data.get('label') or '').strip()
    section_id = data.get('section_id')
    field_type = data.get('field_type', 'text')
    if not label or not section_id:
        return jsonify({'error': 'label and section_id required'}), 400
    db = get_db()
    sec = db.execute("SELECT id FROM detail_sections WHERE id=?", (section_id,)).fetchone()
    if not sec:
        return jsonify({'error': 'Section not found'}), 404
    max_pos = db.execute(
        "SELECT COALESCE(MAX(position),0) FROM detail_fields WHERE section_id=?",
        (section_id,)
    ).fetchone()[0]
    field_key = _make_field_key(label, db)
    cur = db.execute(
        "INSERT INTO detail_fields (section_id, label, field_key, field_type, position) VALUES (?,?,?,?,?)",
        (section_id, label, field_key, field_type, max_pos + 1)
    )
    db.commit()
    row = db.execute("SELECT * FROM detail_fields WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify(dict(row))


@app.route('/layout/fields/<int:field_id>/update', methods=['POST'])
@admin_required
def layout_field_update(field_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    label = (data.get('label') or '').strip()
    field_type = data.get('field_type', 'text')
    section_id = data.get('section_id')
    if not label:
        return jsonify({'error': 'label required'}), 400
    db = get_db()
    field = db.execute("SELECT * FROM detail_fields WHERE id=?", (field_id,)).fetchone()
    if not field:
        abort(404)
    if section_id:
        db.execute(
            "UPDATE detail_fields SET label=?, field_type=?, section_id=? WHERE id=?",
            (label, field_type, section_id, field_id)
        )
    else:
        db.execute(
            "UPDATE detail_fields SET label=?, field_type=? WHERE id=?",
            (label, field_type, field_id)
        )
    db.commit()
    row = db.execute("SELECT * FROM detail_fields WHERE id=?", (field_id,)).fetchone()
    return jsonify(dict(row))


@app.route('/layout/fields/<int:field_id>/delete', methods=['POST'])
@admin_required
def layout_field_delete(field_id):
    db = get_db()
    field = db.execute("SELECT id FROM detail_fields WHERE id=?", (field_id,)).fetchone()
    if not field:
        abort(404)
    db.execute("DELETE FROM detail_fields WHERE id=?", (field_id,))
    db.commit()
    return jsonify({'ok': True})


@app.route('/layout/fields/reorder', methods=['POST'])
@admin_required
def layout_fields_reorder():
    if not validate_csrf_flexible():
        return jsonify({'error': 'CSRF validation failed'}), 403
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    field_ids = data.get('field_ids', [])
    db = get_db()
    for pos, fid in enumerate(field_ids):
        db.execute("UPDATE detail_fields SET position=? WHERE id=?", (pos, fid))
    db.commit()
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# Wiki
# ---------------------------------------------------------------------------

@app.route('/wiki')
@login_required
def wiki():
    return render_template('wiki.html')


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
