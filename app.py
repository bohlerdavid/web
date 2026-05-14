import sqlite3
import csv
import io
import os
from datetime import datetime, date, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, g, Response, abort, jsonify
)
import scanner

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'it-device-mgmt-secret-2024')

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'devices.db')


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
    created_at       TEXT DEFAULT (datetime('now'))
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
    imported_device_id INTEGER
);
"""

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        db.commit()


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
def inject_now():
    return {'now': datetime.utcnow()}


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

@app.route('/seed')
def seed():
    db = get_db()

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

    # Users
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
def dashboard():
    total = query_db("SELECT COUNT(*) as c FROM devices", one=True)['c']

    status_counts = query_db(
        "SELECT status, COUNT(*) as c FROM devices GROUP BY status"
    )

    category_counts = query_db(
        "SELECT category, COUNT(*) as c FROM devices GROUP BY category ORDER BY c DESC"
    )

    recent = query_db(
        """SELECT d.*, l.name as location_name, u.name as user_name
           FROM devices d
           LEFT JOIN locations l ON d.location_id = l.id
           LEFT JOIN users u     ON d.user_id     = u.id
           ORDER BY d.created_at DESC LIMIT 5"""
    )

    ninety_days = (date.today() + timedelta(days=90)).strftime('%Y-%m-%d')
    today_str   = date.today().strftime('%Y-%m-%d')
    expiring = query_db(
        """SELECT d.*, l.name as location_name, u.name as user_name
           FROM devices d
           LEFT JOIN locations l ON d.location_id = l.id
           LEFT JOIN users u     ON d.user_id     = u.id
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
def devices():
    search   = request.args.get('search', '').strip()
    status   = request.args.get('status', '')
    category = request.args.get('category', '')
    location = request.args.get('location', '')

    query  = """SELECT d.*, l.name as location_name, u.name as user_name
                FROM devices d
                LEFT JOIN locations l ON d.location_id = l.id
                LEFT JOIN users u     ON d.user_id     = u.id
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
def devices_export():
    search   = request.args.get('search', '').strip()
    status   = request.args.get('status', '')
    category = request.args.get('category', '')
    location = request.args.get('location', '')

    query  = """SELECT d.name, d.category, d.serial_number, d.mac_address,
                       d.ip_address, d.operating_system, d.status,
                       l.name as location_name, u.name as user_name,
                       d.purchase_date, d.warranty_expiry, d.notes
                FROM devices d
                LEFT JOIN locations l ON d.location_id = l.id
                LEFT JOIN users u     ON d.user_id     = u.id
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
        'Standort', 'Benutzer', 'Kaufdatum', 'Garantie bis', 'Notizen'
    ])
    for row in rows:
        writer.writerow([
            row['name'], CATEGORY_LABELS.get(row['category'], row['category']),
            row['serial_number'] or '', row['mac_address'] or '',
            row['ip_address'] or '', row['operating_system'] or '',
            STATUS_LABELS.get(row['status'], row['status']),
            row['location_name'] or '', row['user_name'] or '',
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
def device_new():
    locations = query_db("SELECT * FROM locations ORDER BY name")
    users     = query_db("SELECT * FROM users ORDER BY name")

    if request.method == 'POST':
        name      = request.form.get('name', '').strip()
        if not name:
            flash('Gerätename ist erforderlich.', 'danger')
            return render_template('device_form.html', device=request.form,
                                   locations=locations, users=users,
                                   categories=CATEGORIES, statuses=STATUSES,
                                   category_labels=CATEGORY_LABELS,
                                   status_labels=STATUS_LABELS, edit=False)

        execute_db(
            """INSERT INTO devices
               (name, category, serial_number, mac_address, ip_address,
                operating_system, status, location_id, user_id,
                purchase_date, warranty_expiry, notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                name,
                request.form.get('category', 'Other'),
                request.form.get('serial_number', '').strip() or None,
                request.form.get('mac_address', '').strip() or None,
                request.form.get('ip_address', '').strip() or None,
                request.form.get('operating_system', '').strip() or None,
                request.form.get('status', 'active'),
                request.form.get('location_id') or None,
                request.form.get('user_id') or None,
                request.form.get('purchase_date') or None,
                request.form.get('warranty_expiry') or None,
                request.form.get('notes', '').strip() or None,
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
    }

    return render_template('device_form.html', device=prefill, locations=locations,
                           users=users, categories=CATEGORIES, statuses=STATUSES,
                           category_labels=CATEGORY_LABELS,
                           status_labels=STATUS_LABELS, edit=False)


@app.route('/devices/<int:device_id>')
def device_detail(device_id):
    device = query_db(
        """SELECT d.*, l.name as location_name, l.building, l.floor, l.room,
                  u.name as user_name, u.email as user_email,
                  u.department as user_department
           FROM devices d
           LEFT JOIN locations l ON d.location_id = l.id
           LEFT JOIN users u     ON d.user_id     = u.id
           WHERE d.id = ?""",
        (device_id,), one=True
    )
    if not device:
        abort(404)
    return render_template('device_detail.html', device=device,
                           category_labels=CATEGORY_LABELS,
                           status_labels=STATUS_LABELS)


@app.route('/devices/<int:device_id>/edit', methods=['GET', 'POST'])
def device_edit(device_id):
    device    = row_to_dict(query_db("SELECT * FROM devices WHERE id = ?", (device_id,), one=True))
    if not device:
        abort(404)
    locations = query_db("SELECT * FROM locations ORDER BY name")
    users     = query_db("SELECT * FROM users ORDER BY name")

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Gerätename ist erforderlich.', 'danger')
            return render_template('device_form.html', device=request.form,
                                   locations=locations, users=users,
                                   categories=CATEGORIES, statuses=STATUSES,
                                   category_labels=CATEGORY_LABELS,
                                   status_labels=STATUS_LABELS, edit=True,
                                   device_id=device_id)

        execute_db(
            """UPDATE devices SET
               name=?, category=?, serial_number=?, mac_address=?, ip_address=?,
               operating_system=?, status=?, location_id=?, user_id=?,
               purchase_date=?, warranty_expiry=?, notes=?
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
                request.form.get('user_id') or None,
                request.form.get('purchase_date') or None,
                request.form.get('warranty_expiry') or None,
                request.form.get('notes', '').strip() or None,
                device_id,
            )
        )
        flash('Gerät wurde erfolgreich aktualisiert.', 'success')
        return redirect(url_for('device_detail', device_id=device_id))

    return render_template('device_form.html', device=device,
                           locations=locations, users=users,
                           categories=CATEGORIES, statuses=STATUSES,
                           category_labels=CATEGORY_LABELS,
                           status_labels=STATUS_LABELS,
                           edit=True, device_id=device_id)


@app.route('/devices/<int:device_id>/delete', methods=['POST'])
def device_delete(device_id):
    device = query_db("SELECT * FROM devices WHERE id = ?", (device_id,), one=True)
    if not device:
        abort(404)
    execute_db("DELETE FROM devices WHERE id = ?", (device_id,))
    flash('Gerät wurde erfolgreich gelöscht.', 'success')
    return redirect(url_for('devices'))


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

@app.route('/users')
def users():
    search = request.args.get('search', '').strip()
    query  = """SELECT u.*, COUNT(d.id) as device_count
                FROM users u
                LEFT JOIN devices d ON d.user_id = u.id
                WHERE 1=1"""
    params = []
    if search:
        query += " AND (u.name LIKE ? OR u.email LIKE ? OR u.department LIKE ?)"
        like = f'%{search}%'
        params += [like, like, like]
    query += " GROUP BY u.id ORDER BY u.name ASC"
    user_list = query_db(query, params)
    return render_template('users.html', users=user_list, search=search)


@app.route('/users/new', methods=['GET', 'POST'])
def user_new():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Name ist erforderlich.', 'danger')
            return render_template('user_form.html', user=request.form, edit=False)

        execute_db(
            "INSERT INTO users (name, email, department, phone) VALUES (?,?,?,?)",
            (
                name,
                request.form.get('email', '').strip() or None,
                request.form.get('department', '').strip() or None,
                request.form.get('phone', '').strip() or None,
            )
        )
        flash('Benutzer wurde erfolgreich hinzugefügt.', 'success')
        return redirect(url_for('users'))

    return render_template('user_form.html', user={}, edit=False)


@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
def user_edit(user_id):
    user = row_to_dict(query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True))
    if not user:
        abort(404)

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Name ist erforderlich.', 'danger')
            return render_template('user_form.html', user=request.form,
                                   edit=True, user_id=user_id)

        execute_db(
            "UPDATE users SET name=?, email=?, department=?, phone=? WHERE id=?",
            (
                name,
                request.form.get('email', '').strip() or None,
                request.form.get('department', '').strip() or None,
                request.form.get('phone', '').strip() or None,
                user_id,
            )
        )
        flash('Benutzer wurde erfolgreich aktualisiert.', 'success')
        return redirect(url_for('users'))

    return render_template('user_form.html', user=user, edit=True, user_id=user_id)


@app.route('/users/<int:user_id>/delete', methods=['POST'])
def user_delete(user_id):
    user = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        abort(404)
    execute_db("DELETE FROM users WHERE id = ?", (user_id,))
    flash('Benutzer wurde erfolgreich gelöscht.', 'success')
    return redirect(url_for('users'))


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------

@app.route('/locations')
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
def scan():
    return render_template('scan.html')


@app.route('/scan/start', methods=['POST'])
def scan_start():
    state = scanner.get_scan_state()
    if state.get('running'):
        return jsonify({'error': 'Scan läuft bereits'})

    network = request.form.get('network', '').strip() or None
    use_nmap = request.form.get('use_nmap', 'true').lower() not in ('false', '0', '')

    scanner.start_scan(network=network, use_nmap=use_nmap)
    return jsonify({'ok': True})


@app.route('/scan/status')
def scan_status():
    return jsonify(scanner.get_scan_state())


@app.route('/scan/save', methods=['POST'])
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
            # Preserve status and imported_device_id, update last_seen and other fields
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
def scan_list():
    rows = query_db("SELECT * FROM discovered_devices ORDER BY ip ASC")
    return jsonify([dict(r) for r in rows])


@app.route('/scan/import/<int:disc_id>', methods=['POST'])
def scan_import(disc_id):
    disc = query_db(
        "SELECT * FROM discovered_devices WHERE id = ?", (disc_id,), one=True
    )
    if not disc:
        abort(404)
    # Mark as imported
    execute_db(
        "UPDATE discovered_devices SET status='imported' WHERE id=?",
        (disc_id,)
    )
    return redirect(url_for(
        'device_new',
        ip=disc['ip'] or '',
        mac=disc['mac'] or '',
        name=disc['hostname'] or '',
        os=disc['os'] or '',
    ))


@app.route('/scan/dismiss/<int:disc_id>', methods=['POST'])
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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
