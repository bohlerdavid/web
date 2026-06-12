import os
import json
import secrets
import smtplib
import time
import logging
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, g, abort, jsonify, session
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_talisman import Talisman
import pymysql
import pymysql.cursors

load_dotenv()

logger = logging.getLogger(__name__)

app = Flask(__name__)

_secret_key = os.environ.get('SECRET_KEY')
if not _secret_key:
    raise RuntimeError('SECRET_KEY environment variable must be set')
app.secret_key = _secret_key

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') != 'development'

Talisman(
    app,
    force_https=False,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy={
        'default-src': ["'self'", 'cdn.jsdelivr.net'],
        'script-src': ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'js.stripe.com'],
        'style-src': ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net'],
        'frame-src': ["'none'"],
        'img-src': ["'self'", 'data:', 'dl.polyhaven.org'],
        'connect-src': ["'self'", 'dl.polyhaven.org'],
    },
    referrer_policy='strict-origin-when-cross-origin',
    feature_policy={},
    session_cookie_secure=True,
)

# ---------------------------------------------------------------------------
# Database (MySQL)
# ---------------------------------------------------------------------------

def _parse_db_url():
    url = os.environ.get('MYSQL_URL') or os.environ.get('DATABASE_URL', '')
    if not url:
        raise RuntimeError('MYSQL_URL environment variable not set')
    p = urlparse(url)
    return {
        'host':     p.hostname,
        'port':     p.port or 3306,
        'user':     p.username,
        'password': p.password,
        'database': p.path.lstrip('/'),
        'charset':  'utf8mb4',
        'cursorclass': pymysql.cursors.DictCursor,
        'autocommit': False,
    }


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = pymysql.connect(**_parse_db_url())
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    query = query.replace('?', '%s')
    db = get_db()
    with db.cursor() as cur:
        cur.execute(query, args)
        rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def execute_db(query, args=()):
    query = query.replace('?', '%s')
    db = get_db()
    with db.cursor() as cur:
        cur.execute(query, args)
        last_id = cur.lastrowid
    db.commit()
    return last_id


def row_to_dict(row):
    if row is None:
        return {}
    return dict(row)


SCHEMA_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS app_users (
        id            INT PRIMARY KEY AUTO_INCREMENT,
        username      VARCHAR(100) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        full_name     VARCHAR(200),
        email         VARCHAR(200),
        created_at    DATETIME DEFAULT NOW(),
        last_login    DATETIME
    )""",
    """CREATE TABLE IF NOT EXISTS subscriptions (
        id                 INT PRIMARY KEY AUTO_INCREMENT,
        user_id            INT NOT NULL UNIQUE,
        plan               VARCHAR(20) NOT NULL DEFAULT 'free',
        status             VARCHAR(20) NOT NULL DEFAULT 'active',
        stripe_customer_id VARCHAR(100),
        stripe_sub_id      VARCHAR(100),
        current_period_end DATETIME,
        created_at         DATETIME DEFAULT NOW()
    )""",
]

# Idempotent schema migrations — each is tried individually; existing columns are ignored.
SCHEMA_MIGRATIONS = [
    "ALTER TABLE app_users ADD COLUMN email_verified TINYINT NOT NULL DEFAULT 1",
    "ALTER TABLE app_users ADD COLUMN email_verify_token VARCHAR(64) NULL",
    "ALTER TABLE app_users ADD COLUMN email_verify_expires DATETIME NULL",
    "ALTER TABLE app_users ADD COLUMN pw_reset_token VARCHAR(64) NULL",
    "ALTER TABLE app_users ADD COLUMN pw_reset_expires DATETIME NULL",
    "ALTER TABLE subscriptions ADD COLUMN plan_interval VARCHAR(10) NOT NULL DEFAULT 'monthly'",
]


def init_db():
    with app.app_context():
        db = get_db()
        with db.cursor() as cur:
            for stmt in SCHEMA_STATEMENTS:
                cur.execute(stmt)
            for migration in SCHEMA_MIGRATIONS:
                try:
                    cur.execute(migration)
                except Exception:
                    pass
            cur.execute("SELECT COUNT(*) as c FROM app_users")
            count = cur.fetchone()['c']
            if count == 0:
                pw_hash = generate_password_hash('Admin1234!')
                cur.execute(
                    "INSERT INTO app_users (username, password_hash, full_name) VALUES (%s, %s, %s)",
                    ('admin', pw_hash, 'Administrator')
                )
        db.commit()


# ---------------------------------------------------------------------------
# Email helpers
# ---------------------------------------------------------------------------

def _send_email_brevo_api(to_addr, subject, html_body):
    """Send via Brevo HTTP API (HTTPS/443) — bypasses SMTP port blocking on Railway."""
    api_key   = os.environ.get('BREVO_API_KEY', '')
    mail_from = os.environ.get('MAIL_FROM') or os.environ.get('SMTP_USER', '')
    from_name = os.environ.get('MAIL_FROM_NAME', 'HolzBau 3D')
    if not api_key:
        return None  # API not configured -> caller falls back to SMTP
    payload = {
        'sender':      {'name': from_name, 'email': mail_from},
        'to':          [{'email': to_addr}],
        'subject':     subject,
        'htmlContent': html_body,
    }
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        'https://api.brevo.com/v3/smtp/email',
        data=data,
        headers={
            'api-key':      api_key,
            'Content-Type': 'application/json',
            'Accept':       'application/json',
        },
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if 200 <= resp.status < 300:
                logger.info('Email sent via Brevo API to %s', to_addr)
                return True
            logger.error('Brevo API unexpected status %s', resp.status)
            return False
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', 'replace')[:300]
        logger.error('Brevo API HTTPError %s: %s', e.code, body)
        return False
    except Exception as e:
        logger.error('Brevo API failed: %s', e)
        return False


def send_email(to_addr, subject, html_body):
    # 1) Prefer Brevo HTTP API (works on Railway where SMTP ports are blocked)
    api_result = _send_email_brevo_api(to_addr, subject, html_body)
    if api_result is not None:
        return api_result

    # 2) Fallback: classic SMTP
    smtp_host = os.environ.get('SMTP_HOST', '')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    smtp_user = os.environ.get('SMTP_USER', '')
    smtp_pass = os.environ.get('SMTP_PASS', '')
    mail_from = os.environ.get('MAIL_FROM', smtp_user)
    if not smtp_host or not smtp_user:
        logger.warning('send_email: neither BREVO_API_KEY nor SMTP_HOST/SMTP_USER configured')
        return False
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = f'HolzBau 3D <{mail_from}>'
    msg['To'] = to_addr
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.sendmail(mail_from, [to_addr], msg.as_string())
        logger.info('Email sent via SMTP to %s', to_addr)
        return True
    except Exception as e:
        logger.error('send_email SMTP failed: %s', e)
        return False


def _email_verify_html(display_name, verify_url):
    return f'''<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#faf6f0;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#faf6f0;padding:40px 16px;">
<tr><td align="center">
<table width="540" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08);max-width:540px;width:100%;">
  <tr><td style="background:linear-gradient(135deg,#d97706,#92400e);padding:28px 40px;">
    <span style="color:#fff;font-size:1.35rem;font-weight:800;letter-spacing:-0.5px;">HolzBAU <span style="font-size:1rem;">3D</span></span>
  </td></tr>
  <tr><td style="padding:40px;">
    <h2 style="margin:0 0 16px;font-size:1.15rem;color:#1a1a1a;font-weight:700;">E-Mail-Adresse bestätigen</h2>
    <p style="margin:0 0 10px;color:#374151;line-height:1.65;font-size:.95rem;">Hallo <strong>{display_name}</strong>,</p>
    <p style="margin:0 0 28px;color:#374151;line-height:1.65;font-size:.95rem;">danke für deine Registrierung bei HolzBau 3D! Bitte bestätige deine E-Mail-Adresse, um dein Konto zu aktivieren:</p>
    <table cellpadding="0" cellspacing="0"><tr><td>
      <a href="{verify_url}" style="display:inline-block;background:linear-gradient(135deg,#d97706,#92400e);color:#ffffff;text-decoration:none;padding:14px 32px;border-radius:10px;font-weight:700;font-size:.95rem;">E-Mail bestätigen</a>
    </td></tr></table>
    <p style="margin:28px 0 8px;color:#9ca3af;font-size:.8rem;line-height:1.5;">Dieser Link ist 48 Stunden gültig. Falls du dich nicht registriert hast, kannst du diese E-Mail ignorieren.</p>
    <p style="margin:0;color:#c4c9d4;font-size:.72rem;word-break:break-all;">Link: {verify_url}</p>
  </td></tr>
  <tr><td style="padding:18px 40px;border-top:1px solid #f3f4f6;">
    <p style="margin:0;color:#d1d5db;font-size:.72rem;">&copy; 2026 HolzBau 3D &middot; <a href="https://holzbau3d.app" style="color:#d97706;text-decoration:none;">holzbau3d.app</a></p>
  </td></tr>
</table>
</td></tr>
</table>
</body></html>'''


def _email_reset_html(display_name, reset_url):
    return f'''<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#faf6f0;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#faf6f0;padding:40px 16px;">
<tr><td align="center">
<table width="540" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08);max-width:540px;width:100%;">
  <tr><td style="background:linear-gradient(135deg,#d97706,#92400e);padding:28px 40px;">
    <span style="color:#fff;font-size:1.35rem;font-weight:800;letter-spacing:-0.5px;">HolzBAU <span style="font-size:1rem;">3D</span></span>
  </td></tr>
  <tr><td style="padding:40px;">
    <h2 style="margin:0 0 16px;font-size:1.15rem;color:#1a1a1a;font-weight:700;">Passwort zurücksetzen</h2>
    <p style="margin:0 0 10px;color:#374151;line-height:1.65;font-size:.95rem;">Hallo <strong>{display_name}</strong>,</p>
    <p style="margin:0 0 28px;color:#374151;line-height:1.65;font-size:.95rem;">du hast ein neues Passwort für dein HolzBau 3D Konto angefordert. Klicke auf den Button, um dein Passwort zurückzusetzen:</p>
    <table cellpadding="0" cellspacing="0"><tr><td>
      <a href="{reset_url}" style="display:inline-block;background:linear-gradient(135deg,#d97706,#92400e);color:#ffffff;text-decoration:none;padding:14px 32px;border-radius:10px;font-weight:700;font-size:.95rem;">Passwort zurücksetzen</a>
    </td></tr></table>
    <p style="margin:28px 0 8px;color:#9ca3af;font-size:.8rem;line-height:1.5;">Dieser Link ist 1 Stunde gültig. Falls du kein neues Passwort angefordert hast, kannst du diese E-Mail ignorieren — dein Passwort bleibt unverändert.</p>
    <p style="margin:0;color:#c4c9d4;font-size:.72rem;word-break:break-all;">Link: {reset_url}</p>
  </td></tr>
  <tr><td style="padding:18px 40px;border-top:1px solid #f3f4f6;">
    <p style="margin:0;color:#d1d5db;font-size:.72rem;">&copy; 2026 HolzBau 3D &middot; <a href="https://holzbau3d.app" style="color:#d97706;text-decoration:none;">holzbau3d.app</a></p>
  </td></tr>
</table>
</td></tr>
</table>
</body></html>'''


# ---------------------------------------------------------------------------
# Brute-force / rate-limit protection
# ---------------------------------------------------------------------------

_login_attempts    = {}
_register_attempts = {}
_checkout_attempts = {}
_resend_attempts   = {}
_reset_attempts    = {}

LOGIN_MAX_ATTEMPTS    = 5
LOGIN_LOCKOUT_SECONDS = 300
REGISTER_MAX_ATTEMPTS = 10
CHECKOUT_MAX_ATTEMPTS = 5
RESEND_MAX_ATTEMPTS   = 3
RESET_MAX_ATTEMPTS    = 3


def _is_safe_redirect(url):
    if not url:
        return False
    test = urljoin(request.host_url, url)
    return test.startswith(request.host_url)


def _check_rate_limit(store, ip, max_attempts, window=600):
    """Returns True if the IP is over the limit (blocked)."""
    now = time.time()
    entry = store.get(ip, {'count': 0, 'since': now})
    if now - entry['since'] > window:
        entry = {'count': 0, 'since': now}
    entry['count'] += 1
    store[ip] = entry
    return entry['count'] > max_attempts


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

def generate_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf(token):
    return token and token == session.get('csrf_token')


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
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Context processor
# ---------------------------------------------------------------------------

@app.context_processor
def inject_globals():
    user_plan = 'free'
    if session.get('user_id'):
        user_plan = get_user_plan(session['user_id'])
    return {'user_plan': user_plan, 'csrf_token': generate_csrf()}


# ---------------------------------------------------------------------------
# Health / utility
# ---------------------------------------------------------------------------

@app.route('/health')
def health():
    return 'ok', 200


@app.route('/ping')
def ping():
    if 'user_id' in session:
        session.modified = True
    return '', 204


@app.route('/robots.txt')
def robots_txt():
    body = (
        'User-agent: *\n'
        'Allow: /\n'
        'Disallow: /admin/\n'
        'Sitemap: https://holzbau3d.app/sitemap.xml\n'
    )
    return app.response_class(body, mimetype='text/plain')


@app.route('/sitemap.xml')
def sitemap():
    body = '''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://holzbau3d.app/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>https://holzbau3d.app/pricing</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>https://holzbau3d.app/impressum</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
  <url><loc>https://holzbau3d.app/datenschutz</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
  <url><loc>https://holzbau3d.app/nutzungsbedingungen</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
</urlset>'''
    return app.response_class(body, mimetype='application/xml')


@app.route('/nutzungsbedingungen')
def nutzungsbedingungen():
    return render_template('nutzungsbedingungen.html')


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('landing.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('holzbau'))

    if request.method == 'POST':
        token = request.form.get('csrf_token', '')
        if not validate_csrf(token):
            flash('Ungültige Anfrage. Bitte erneut versuchen.', 'danger')
            return render_template('login.html', csrf_token=generate_csrf())

        ip = request.remote_addr
        now = time.time()
        attempt_info = _login_attempts.get(ip, {'count': 0, 'locked_until': 0})
        if attempt_info['locked_until'] > now:
            remaining = int((attempt_info['locked_until'] - now) / 60) + 1
            flash(f'Zu viele Fehlversuche. Bitte {remaining} Minute(n) warten.', 'danger')
            return render_template('login.html', csrf_token=generate_csrf())

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = query_db("SELECT * FROM app_users WHERE username = ?", (username,), one=True)

        if user and check_password_hash(user['password_hash'], password):
            # Block login if email is set but not verified
            if not user.get('email_verified', 1) and user.get('email'):
                flash('Bitte bestätige zuerst deine E-Mail-Adresse.', 'warning')
                return render_template('login.html', csrf_token=generate_csrf(),
                                       unverified_email=user['email'])
            _login_attempts.pop(ip, None)
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name'] or user['username']
            session['role'] = 'admin' if user['username'] == 'admin' else 'user'
            execute_db("UPDATE app_users SET last_login = NOW() WHERE id = ?", (user['id'],))
            raw_next = request.form.get('next') or request.args.get('next', '')
            next_url = raw_next if _is_safe_redirect(raw_next) else url_for('holzbau')
            return redirect(next_url)
        else:
            count = attempt_info['count'] + 1
            locked_until = now + LOGIN_LOCKOUT_SECONDS if count >= LOGIN_MAX_ATTEMPTS else 0
            if locked_until:
                flash(f'Zu viele Fehlversuche. Bitte {LOGIN_LOCKOUT_SECONDS // 60} Minuten warten.', 'danger')
            else:
                flash(f'Ungültiger Benutzername oder Passwort. Noch {LOGIN_MAX_ATTEMPTS - count} Versuch(e).', 'danger')
            _login_attempts[ip] = {'count': count, 'locked_until': locked_until}

    return render_template('login.html', csrf_token=generate_csrf())


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('holzbau'))

    if request.method == 'POST':
        if _check_rate_limit(_register_attempts, request.remote_addr, REGISTER_MAX_ATTEMPTS):
            flash('Zu viele Registrierungsversuche. Bitte warte 10 Minuten.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf())

        token = request.form.get('csrf_token', '')
        if not validate_csrf(token):
            flash('Ungültige Anfrage.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf())

        username  = request.form.get('username', '').strip()
        password  = request.form.get('password', '')
        full_name = request.form.get('full_name', '').strip()
        email     = request.form.get('email', '').strip().lower()

        if len(username) < 3:
            flash('Benutzername muss mindestens 3 Zeichen lang sein.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf())
        if len(password) < 8:
            flash('Passwort muss mindestens 8 Zeichen lang sein.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf())
        if not email or '@' not in email or '.' not in email.split('@')[-1]:
            flash('Bitte gib eine gültige E-Mail-Adresse ein.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf())

        if query_db("SELECT id FROM app_users WHERE username = ?", (username,), one=True):
            flash('Benutzername bereits vergeben.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf())

        if query_db("SELECT id FROM app_users WHERE email = ?", (email,), one=True):
            flash('Diese E-Mail-Adresse ist bereits registriert.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf())

        verify_token   = secrets.token_urlsafe(32)
        verify_expires = (datetime.utcnow() + timedelta(hours=48)).strftime('%Y-%m-%d %H:%M:%S')

        execute_db(
            "INSERT INTO app_users "
            "(username, password_hash, full_name, email, email_verified, email_verify_token, email_verify_expires) "
            "VALUES (?,?,?,?,0,?,?)",
            (username, generate_password_hash(password), full_name, email, verify_token, verify_expires)
        )

        base_url   = os.environ.get('BASE_URL', 'https://holzbau3d.app')
        verify_url = f"{base_url}/verify-email/{verify_token}"
        sent = send_email(
            email,
            'HolzBau 3D – E-Mail-Adresse bestätigen',
            _email_verify_html(full_name or username, verify_url)
        )
        if not sent:
            logger.warning('Verification email not sent (SMTP not configured?)')

        session['pending_verify_email'] = email
        return redirect(url_for('verify_pending', email=email))

    return render_template('register.html', csrf_token=generate_csrf())


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------

@app.route('/verify-pending')
def verify_pending():
    email = request.args.get('email', '') or session.get('pending_verify_email', '')
    return render_template('verify_pending.html', email=email)


@app.route('/verify-status')
def verify_status():
    """JSON-Status für das Auto-Polling der verify_pending-Seite."""
    email = session.get('pending_verify_email') or request.args.get('email', '')
    if not email:
        return jsonify(verified=False)
    row = query_db("SELECT email_verified FROM app_users WHERE email = ?", (email,), one=True)
    verified = bool(row and row['email_verified'] == 1)
    if verified:
        session.pop('pending_verify_email', None)
    return jsonify(verified=verified)


@app.route('/verify-email/<token>')
def verify_email(token):
    if not token or len(token) > 128:
        flash('Ungültiger Link.', 'danger')
        return redirect(url_for('login'))

    user = query_db(
        "SELECT * FROM app_users WHERE email_verify_token = ? AND email_verify_expires > UTC_TIMESTAMP()",
        (token,), one=True
    )
    if not user:
        expired = query_db("SELECT id FROM app_users WHERE email_verify_token = ?", (token,), one=True)
        if expired:
            flash('Dieser Bestätigungslink ist abgelaufen. Bitte fordere einen neuen an.', 'warning')
            return render_template('verify_pending.html', email='', expired=True)
        flash('Ungültiger Bestätigungslink.', 'danger')
        return redirect(url_for('login'))

    execute_db(
        "UPDATE app_users SET email_verified=1, email_verify_token=NULL, email_verify_expires=NULL WHERE id=?",
        (user['id'],)
    )
    session.permanent = True
    session['user_id']   = user['id']
    session['username']  = user['username']
    session['full_name'] = user['full_name'] or user['username']
    session['role']      = 'admin' if user['username'] == 'admin' else 'user'
    execute_db("UPDATE app_users SET last_login = NOW() WHERE id = ?", (user['id'],))
    flash('E-Mail erfolgreich bestätigt. Willkommen bei HolzBau 3D! 🪵', 'success')
    return redirect(url_for('holzbau'))


@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        token = request.form.get('csrf_token', '')
        if not validate_csrf(token):
            flash('Ungültige Anfrage.', 'danger')
            return render_template('verify_pending.html', email='', csrf_token=generate_csrf())

        if _check_rate_limit(_resend_attempts, request.remote_addr, RESEND_MAX_ATTEMPTS):
            flash('Zu viele Versuche. Bitte warte 10 Minuten.', 'warning')
            return redirect(url_for('login'))

        email = request.form.get('email', '').strip().lower()
        if email:
            user = query_db(
                "SELECT * FROM app_users WHERE email = ? AND email_verified = 0",
                (email,), one=True
            )
            if user:
                verify_token   = secrets.token_urlsafe(32)
                verify_expires = (datetime.utcnow() + timedelta(hours=48)).strftime('%Y-%m-%d %H:%M:%S')
                execute_db(
                    "UPDATE app_users SET email_verify_token=?, email_verify_expires=? WHERE id=?",
                    (verify_token, verify_expires, user['id'])
                )
                base_url   = os.environ.get('BASE_URL', 'https://holzbau3d.app')
                verify_url = f"{base_url}/verify-email/{verify_token}"
                send_email(
                    email,
                    'HolzBau 3D – E-Mail-Adresse bestätigen',
                    _email_verify_html(user['full_name'] or user['username'], verify_url)
                )

        flash('Falls diese E-Mail registriert und noch nicht bestätigt ist, haben wir dir einen neuen Bestätigungslink gesendet.', 'success')
        return redirect(url_for('verify_pending', email=email))

    # GET — redirect to login (the form lives in verify_pending.html)
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        token = request.form.get('csrf_token', '')
        if not validate_csrf(token):
            flash('Ungültige Anfrage.', 'danger')
            return render_template('forgot_password.html', csrf_token=generate_csrf())

        if _check_rate_limit(_reset_attempts, request.remote_addr, RESET_MAX_ATTEMPTS):
            flash('Zu viele Versuche. Bitte warte 10 Minuten.', 'warning')
            return render_template('forgot_password.html', csrf_token=generate_csrf(), submitted=True)

        email = request.form.get('email', '').strip().lower()
        if email:
            user = query_db("SELECT * FROM app_users WHERE email = ?", (email,), one=True)
            if user:
                reset_token   = secrets.token_urlsafe(32)
                reset_expires = (datetime.utcnow() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
                execute_db(
                    "UPDATE app_users SET pw_reset_token=?, pw_reset_expires=? WHERE id=?",
                    (reset_token, reset_expires, user['id'])
                )
                base_url  = os.environ.get('BASE_URL', 'https://holzbau3d.app')
                reset_url = f"{base_url}/reset-password/{reset_token}"
                send_email(
                    email,
                    'HolzBau 3D – Passwort zurücksetzen',
                    _email_reset_html(user['full_name'] or user['username'], reset_url)
                )

        # Always show the same message (don't reveal if email exists)
        return render_template('forgot_password.html', csrf_token=generate_csrf(), submitted=True)

    return render_template('forgot_password.html', csrf_token=generate_csrf())


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if not token or len(token) > 128:
        flash('Ungültiger Link.', 'danger')
        return redirect(url_for('login'))

    user = query_db(
        "SELECT * FROM app_users WHERE pw_reset_token = ? AND pw_reset_expires > UTC_TIMESTAMP()",
        (token,), one=True
    )
    if not user:
        flash('Dieser Link ist ungültig oder abgelaufen. Bitte fordere einen neuen an.', 'warning')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token', '')):
            flash('Ungültige Anfrage.', 'danger')
            return redirect(url_for('reset_password', token=token))

        new_pw      = request.form.get('new_password', '')
        confirm_pw  = request.form.get('confirm_password', '')

        if len(new_pw) < 8:
            flash('Passwort muss mindestens 8 Zeichen haben.', 'danger')
            return render_template('reset_password.html', token=token, csrf_token=generate_csrf())
        if new_pw != confirm_pw:
            flash('Passwörter stimmen nicht überein.', 'danger')
            return render_template('reset_password.html', token=token, csrf_token=generate_csrf())

        execute_db(
            "UPDATE app_users SET password_hash=?, pw_reset_token=NULL, pw_reset_expires=NULL WHERE id=?",
            (generate_password_hash(new_pw), user['id'])
        )
        flash('Passwort erfolgreich geändert. Du kannst dich jetzt anmelden.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token, csrf_token=generate_csrf())


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = query_db("SELECT * FROM app_users WHERE id = ?", (session['user_id'],), one=True)
    if request.method == 'POST':
        token = request.form.get('csrf_token', '')
        if not validate_csrf(token):
            flash('Ungültige Anfrage.', 'danger')
            return redirect(url_for('profile'))

        current_pw = request.form.get('current_password', '')
        new_pw     = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        if not check_password_hash(user['password_hash'], current_pw):
            flash('Aktuelles Passwort ist falsch.', 'danger')
            return redirect(url_for('profile'))
        if len(new_pw) < 8:
            flash('Neues Passwort muss mindestens 8 Zeichen haben.', 'danger')
            return redirect(url_for('profile'))
        if new_pw != confirm_pw:
            flash('Passwörter stimmen nicht überein.', 'danger')
            return redirect(url_for('profile'))

        execute_db("UPDATE app_users SET password_hash = ? WHERE id = ?",
                   (generate_password_hash(new_pw), session['user_id']))
        flash('Passwort erfolgreich geändert.', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=row_to_dict(user), csrf_token=generate_csrf())


@app.route('/profile/send-reset', methods=['POST'])
@login_required
def profile_send_reset():
    if not validate_csrf(request.form.get('csrf_token', '')):
        flash('Ungültige Anfrage.', 'danger')
        return redirect(url_for('profile'))

    user = query_db("SELECT * FROM app_users WHERE id = ?", (session['user_id'],), one=True)
    if not user or not user.get('email'):
        flash('Keine E-Mail-Adresse hinterlegt. Bitte wende dich an den Support.', 'warning')
        return redirect(url_for('profile'))

    reset_token   = secrets.token_urlsafe(32)
    reset_expires = (datetime.utcnow() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
    execute_db(
        "UPDATE app_users SET pw_reset_token=?, pw_reset_expires=? WHERE id=?",
        (reset_token, reset_expires, user['id'])
    )
    base_url  = os.environ.get('BASE_URL', 'https://holzbau3d.app')
    reset_url = f"{base_url}/reset-password/{reset_token}"
    sent = send_email(
        user['email'],
        'HolzBau 3D – Passwort zurücksetzen',
        _email_reset_html(user['full_name'] or user['username'], reset_url)
    )
    if sent:
        flash(f'Passwort-Reset E-Mail wurde an {user["email"]} gesendet.', 'success')
    else:
        flash('E-Mail konnte nicht gesendet werden. Bitte ändere das Passwort direkt hier.', 'danger')
    return redirect(url_for('profile'))


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.route('/admin/users')
@admin_required
def admin_users():
    users = query_db("""
        SELECT u.id, u.username, u.full_name, u.email, u.created_at, u.last_login,
               COALESCE(u.email_verified, 1) as email_verified,
               COALESCE(s.plan, 'free') as plan, COALESCE(s.status, '') as sub_status
        FROM app_users u
        LEFT JOIN subscriptions s ON s.user_id = u.id
        ORDER BY u.created_at DESC
    """)
    return render_template('admin_users.html', users=users)


@app.route('/admin/delete_user', methods=['POST'])
@admin_required
def admin_delete_user():
    if not validate_csrf(request.form.get('csrf_token', '')):
        flash('Ungültiges CSRF-Token.', 'danger')
        return redirect(url_for('admin_users'))

    user_id = request.form.get('user_id', type=int)
    if not user_id:
        flash('Ungültige Eingabe.', 'danger')
        return redirect(url_for('admin_users'))

    user = query_db('SELECT * FROM app_users WHERE id=?', [user_id], one=True)
    if not user:
        flash('Benutzer nicht gefunden.', 'danger')
        return redirect(url_for('admin_users'))
    if user['username'] == 'admin':
        flash('Der Admin-Account kann nicht gelöscht werden.', 'danger')
        return redirect(url_for('admin_users'))
    if user_id == session.get('user_id'):
        flash('Du kannst deinen eigenen Account nicht löschen.', 'danger')
        return redirect(url_for('admin_users'))

    # Cancel Stripe subscription if active
    stripe_key = os.environ.get('STRIPE_SECRET_KEY')
    sub = query_db('SELECT stripe_sub_id FROM subscriptions WHERE user_id=?', [user_id], one=True)
    if sub and sub.get('stripe_sub_id') and stripe_key:
        try:
            import stripe
            stripe.api_key = stripe_key
            stripe.Subscription.cancel(sub['stripe_sub_id'])
            logger.info('Stripe subscription cancelled for deleted user %s', user_id)
        except Exception as e:
            logger.error('Stripe cancel on delete failed for user %s: %s', user_id, e)

    execute_db('DELETE FROM subscriptions WHERE user_id=?', [user_id])
    username = user['username']
    execute_db('DELETE FROM app_users WHERE id=?', [user_id])

    flash(f'Benutzer „{username}" wurde gelöscht.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/set_plan', methods=['POST'])
@admin_required
def admin_set_plan():
    if not validate_csrf(request.form.get('csrf_token', '')):
        flash('Ungültiges CSRF-Token.', 'danger')
        return redirect(url_for('admin_users'))
    user_id = request.form.get('user_id', type=int)
    plan = request.form.get('plan', 'free')
    if not user_id or plan not in ('free', 'premium'):
        flash('Ungültige Eingabe.', 'danger')
        return redirect(url_for('admin_users'))
    status = 'active' if plan == 'premium' else 'cancelled'
    existing = query_db('SELECT id FROM subscriptions WHERE user_id=?', [user_id], one=True)
    if existing:
        execute_db('UPDATE subscriptions SET plan=?, status=?, stripe_sub_id=NULL WHERE user_id=?',
                   [plan, status, user_id])
    else:
        execute_db('INSERT INTO subscriptions (user_id, plan, status) VALUES (?,?,?)',
                   [user_id, plan, status])
    username = query_db('SELECT username FROM app_users WHERE id=?', [user_id], one=True)
    name = username['username'] if username else f'#{user_id}'
    flash(f'Plan von {name} auf {plan.upper()} gesetzt.', 'success')
    return redirect(url_for('admin_users'))


# ---------------------------------------------------------------------------
@app.route('/admin/email-test', methods=['GET'])
@admin_required
def admin_email_test():
    cfg = {
        'BREVO_API_KEY': os.environ.get('BREVO_API_KEY', ''),
        'SMTP_HOST': os.environ.get('SMTP_HOST', ''),
        'SMTP_PORT': os.environ.get('SMTP_PORT', '587'),
        'SMTP_USER': os.environ.get('SMTP_USER', ''),
        'SMTP_PASS': os.environ.get('SMTP_PASS', ''),
        'MAIL_FROM': os.environ.get('MAIL_FROM', ''),
        'BASE_URL':  os.environ.get('BASE_URL', ''),
    }
    def mask(v):
        if not v:
            return '<LEER>'
        if len(v) <= 6:
            return v[0] + '***'
        return v[:3] + '***' + v[-2:]
    # Ausgehende oeffentliche IP dieser App ermitteln (fuer Brevo IP-Whitelist)
    out_ip = '?'
    for ip_url in ('https://api.ipify.org', 'https://checkip.amazonaws.com', 'https://ifconfig.me/ip'):
        try:
            with urllib.request.urlopen(ip_url, timeout=8) as r:
                out_ip = r.read().decode('utf-8').strip()
            if out_ip:
                break
        except Exception:
            continue
    L = []
    L.append('############################################################')
    L.append('# AUSGEHENDE IP DIESER APP (Railway): ' + out_ip)
    L.append('# -> falls Brevo zwingend eine IP verlangt, DIESE eintragen.')
    L.append('# -> Achtung: kann sich bei Railway-Neustart aendern!')
    L.append('############################################################')
    L.append('')
    L.append('=== E-Mail-Konfiguration (Railway Env) ===')
    L.append('BREVO_API_KEY: ' + (mask(cfg['BREVO_API_KEY']) + '  (Laenge: ' + str(len(cfg['BREVO_API_KEY'])) + ')' if cfg['BREVO_API_KEY'] else '<<< LEER -> nutzt SMTP-Fallback >>>'))
    L.append('MAIL_FROM:     ' + (cfg['MAIL_FROM'] or '<LEER -> nutzt SMTP_USER>'))
    L.append('BASE_URL:      ' + (cfg['BASE_URL'] or '<LEER -> default https://holzbau3d.app>'))
    L.append('')
    L.append('--- SMTP (nur Fallback) ---')
    L.append('SMTP_HOST: ' + (cfg['SMTP_HOST'] or '<LEER>'))
    L.append('SMTP_PORT: ' + cfg['SMTP_PORT'])
    L.append('SMTP_USER: ' + (cfg['SMTP_USER'] or '<LEER>'))
    L.append('SMTP_PASS: ' + mask(cfg['SMTP_PASS']) + '  (Laenge: ' + str(len(cfg['SMTP_PASS'])) + ')')
    L.append('')
    test_to = request.values.get('to', '').strip()
    if test_to:
        frm = cfg['MAIL_FROM'] or cfg['SMTP_USER']
        # --- Weg 1: Brevo HTTP API (bevorzugt) — mit voller Fehleranzeige ---
        if cfg['BREVO_API_KEY']:
            L.append('=== Test via Brevo HTTP-API an ' + test_to + ' ===')
            L.append('POST https://api.brevo.com/v3/smtp/email (Absender: ' + frm + ') ...')
            from_name = os.environ.get('MAIL_FROM_NAME', 'HolzBau 3D')
            payload = {
                'sender':      {'name': from_name, 'email': frm},
                'to':          [{'email': test_to}],
                'subject':     'HolzBau 3D - API Test',
                'htmlContent': '<p>HTTP-API-Test erfolgreich!</p>',
            }
            req = urllib.request.Request(
                'https://api.brevo.com/v3/smtp/email',
                data=json.dumps(payload).encode('utf-8'),
                headers={'api-key': cfg['BREVO_API_KEY'],
                         'Content-Type': 'application/json',
                         'Accept': 'application/json'},
                method='POST',
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    rbody = resp.read().decode('utf-8', 'replace')
                    L.append('HTTP-Status: ' + str(resp.status))
                    L.append('Brevo-Antwort: ' + rbody[:400])
                    L.append('')
                    L.append('==> ERFOLG: Brevo hat die Mail angenommen. Pruefe Posteingang + Spam.')
            except urllib.error.HTTPError as e:
                rbody = e.read().decode('utf-8', 'replace')
                L.append('HTTP-Status: ' + str(e.code))
                L.append('Brevo-Antwort: ' + rbody[:500])
                L.append('')
                if e.code == 401:
                    L.append('==> 401 UNAUTHORIZED: API-Key falsch ODER IP nicht autorisiert.')
                    L.append('   - BREVO_API_KEY pruefen (v3, beginnt mit xkeysib-).')
                    L.append('   - Falls IP-Beschraenkung aktiv: in Brevo 0.0.0.0/0 erlauben')
                    L.append('     oder die IP oben (' + out_ip + ') eintragen.')
                elif e.code == 400:
                    L.append('==> 400 BAD REQUEST: meist Absender nicht verifiziert.')
                    L.append('   Verifiziere ' + frm + ' in Brevo:')
                    L.append('   Senders, Domains & Dedicated IPs > Senders > Add a sender.')
                else:
                    L.append('==> Fehlercode ' + str(e.code) + ' — siehe Brevo-Antwort oben.')
            except Exception as e:
                L.append('==> FEHLER (' + type(e).__name__ + '): ' + str(e))
        else:
            # --- Weg 2: SMTP Schritt-fuer-Schritt (Fallback-Diagnose) ---
            L.append('=== Test via SMTP an ' + test_to + ' ===')
            L.append('(Kein BREVO_API_KEY gesetzt -> teste SMTP. Hinweis: Railway blockiert oft SMTP-Ports!)')
            host = cfg['SMTP_HOST']
            port = int(cfg['SMTP_PORT'] or '587')
            user = cfg['SMTP_USER']
            pw   = cfg['SMTP_PASS']
            if not host or not user:
                L.append('FEHLER: SMTP_HOST oder SMTP_USER fehlt.')
            else:
                try:
                    L.append('1) Verbinde TCP zu ' + host + ':' + str(port) + ' ...')
                    s = smtplib.SMTP(host, port, timeout=15)
                    L.append('   OK verbunden')
                    s.ehlo(); L.append('2) STARTTLS ...'); s.starttls(); s.ehlo()
                    L.append('   OK TLS aktiv')
                    L.append('3) LOGIN als ' + user + ' ...'); s.login(user, pw)
                    L.append('   OK Login akzeptiert')
                    m = MIMEMultipart('alternative')
                    m['Subject'] = 'HolzBau 3D - SMTP Test'
                    m['From'] = 'HolzBau 3D <' + (frm or user) + '>'
                    m['To'] = test_to
                    m.attach(MIMEText('<p>SMTP-Test erfolgreich!</p>', 'html', 'utf-8'))
                    s.sendmail(frm or user, [test_to], m.as_string()); s.quit()
                    L.append('   OK GESENDET')
                    L.append(''); L.append('==> ERFOLG: Pruefe Posteingang + Spam.')
                except Exception as e:
                    L.append(''); L.append('==> FEHLER (' + type(e).__name__ + '): ' + str(e))
                    L.append(''); L.append('==> Timeout = Railway blockiert SMTP. Loesung: BREVO_API_KEY setzen!')
    else:
        L.append('Tipp: ?to=deine@email.de an die URL anhaengen, um einen Testversand zu starten.')
    html = ('<html><body style="font-family:Consolas,monospace;background:#0e1117;color:#dde5f4;padding:24px;">'
            '<h2 style="color:#4e8cdd;">HolzBau 3D - E-Mail Diagnose</h2>'
            '<pre style="white-space:pre-wrap;font-size:13px;line-height:1.7;background:#161b27;padding:18px;border-radius:10px;border:1px solid #283755;">'
            + '\n'.join(L) +
            '</pre><form method="get" style="margin-top:16px;">'
            '<input name="to" placeholder="test@email.de" value="' + test_to + '" '
            'style="padding:9px;width:260px;border-radius:6px;border:1px solid #283755;background:#161b27;color:#fff;">'
            '<button style="padding:9px 18px;margin-left:8px;border-radius:6px;border:none;background:#4e8cdd;color:#fff;cursor:pointer;font-weight:600;">Test senden</button>'
            '</form></body></html>')
    return html


@app.route('/admin/stripe-check', methods=['GET'])
@admin_required
def admin_stripe_check():
    sk      = os.environ.get('STRIPE_SECRET_KEY', '')
    price_m = os.environ.get('STRIPE_PRICE_ID', '')
    price_y = os.environ.get('STRIPE_YEARLY_PRICE_ID', '')
    wh      = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
    def mask(v):
        if not v:
            return '<LEER>'
        if len(v) <= 10:
            return v[0] + '***'
        return v[:7] + '***' + v[-3:]
    mode = '?'
    if sk.startswith('sk_test_') or sk.startswith('rk_test_'):
        mode = 'TEST'
    elif sk.startswith('sk_live_') or sk.startswith('rk_live_'):
        mode = 'LIVE'
    L = []
    L.append('=== Stripe-Konfiguration (Railway Env) ===')
    L.append('STRIPE_SECRET_KEY:      ' + (mask(sk) + '   [Modus: ' + mode + ']' if sk else '<<< LEER / NICHT GESETZT >>>'))
    L.append('STRIPE_PRICE_ID (Monat):' + (' ' + price_m if price_m else ' <<< LEER >>>'))
    L.append('STRIPE_YEARLY_PRICE_ID: ' + (price_y if price_y else '<<< LEER -> Jahres-Abo wird NICHT angezeigt! >>>'))
    L.append('STRIPE_WEBHOOK_SECRET:  ' + ('gesetzt (' + mask(wh) + ')' if wh else '<<< LEER >>>'))
    L.append('')
    L.append('--> yearly_configured = ' + str(bool(price_y)) +
             '   (' + ('Jahres-Karte SICHTBAR' if price_y else 'nur Monats-Button') + ')')
    L.append('')
    L.append('=== Validierung der Price-IDs direkt bei Stripe ===')
    if not sk:
        L.append('Kein STRIPE_SECRET_KEY -> keine Validierung moeglich.')
    else:
        try:
            import stripe
            stripe.api_key = sk
            for label, pid in (('Monat ', price_m), ('Jahr  ', price_y)):
                if not pid:
                    L.append(label + ': (keine Price-ID gesetzt)')
                    continue
                try:
                    p = stripe.Price.retrieve(pid)
                    amount = (getattr(p, 'unit_amount', None) or 0) / 100.0
                    cur = (getattr(p, 'currency', '') or '').upper()
                    rec = getattr(p, 'recurring', None)
                    interval = getattr(rec, 'interval', 'einmalig') if rec else 'einmalig'
                    active = 'aktiv' if getattr(p, 'active', False) else 'INAKTIV!'
                    livemode = 'LIVE' if getattr(p, 'livemode', False) else 'TEST'
                    L.append(label + ': ' + ('%.2f' % amount) + ' ' + cur + ' / ' + interval +
                             '  [' + active + ', ' + livemode + ']  ' + pid)
                    if livemode != mode and mode in ('TEST', 'LIVE'):
                        L.append('        !! WARNUNG: Price ist ' + livemode + ', Key ist ' + mode +
                                 ' -> MISMATCH! Checkout schlaegt fehl.')
                except Exception as e:
                    L.append(label + ': FEHLER (' + type(e).__name__ + '): ' + str(e)[:160])
                    L.append('        -> Price-ID existiert nicht in diesem Modus (' + mode + ')?')
        except Exception as e:
            L.append('Stripe-Fehler: ' + type(e).__name__ + ': ' + str(e)[:160])
    L.append('')
    if not price_y:
        L.append('NAECHSTER SCHRITT: STRIPE_YEARLY_PRICE_ID in Railway setzen')
        L.append('(Stripe > Produkte > Premium > Jahres-Preis > price_... kopieren).')
    html = ('<html><body style="font-family:Consolas,monospace;background:#0e1117;color:#dde5f4;padding:24px;">'
            '<h2 style="color:#4e8cdd;">HolzBau 3D - Stripe Diagnose</h2>'
            '<pre style="white-space:pre-wrap;font-size:13px;line-height:1.7;background:#161b27;'
            'padding:18px;border-radius:10px;border:1px solid #283755;">'
            + '\n'.join(L) +
            '</pre></body></html>')
    return html


@app.route('/admin/sub-check', methods=['GET'])
@admin_required
def admin_sub_check():
    L = []
    L.append('=== Benutzer & Abo-Status (Datenbank) ===')
    try:
        users = query_db(
            'SELECT u.id, u.username, u.email, s.plan, s.status, s.plan_interval, s.stripe_sub_id, s.current_period_end '
            'FROM app_users u LEFT JOIN subscriptions s ON s.user_id = u.id ORDER BY u.id', []
        )
        for u in users:
            L.append('  #' + str(u['id']) + '  ' + str(u['username']) + '  <' + str(u['email'] or '-') + '>'
                     + '  plan=' + str(u['plan'] or 'free')
                     + '  status=' + str(u['status'] or '-')
                     + '  intervall=' + str(u['plan_interval'] or '-')
                     + '  sub=' + str(u['stripe_sub_id'] or '-')
                     + '  bis=' + str(u['current_period_end'] or '-'))
    except Exception as e:
        L.append('DB-FEHLER: ' + type(e).__name__ + ': ' + str(e)[:200])
    L.append('')
    L.append('=== Bezahlte Stripe Checkout-Sessions (letzte 20) ===')
    sessions_by_user = {}
    try:
        import stripe
        stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '')
        for cs in stripe.checkout.Session.list(limit=20).data:
            meta = dict(getattr(cs, 'metadata', None) or {})
            uid = int(meta.get('user_id', 0) or 0)
            paid = getattr(cs, 'payment_status', '')
            L.append('  user_id=' + str(uid) + '  bezahlt=' + paid
                     + '  plan=' + str(meta.get('plan_type'))
                     + '  sub=' + str(getattr(cs, 'subscription', None)))
            if uid and paid == 'paid' and getattr(cs, 'mode', '') == 'subscription':
                sessions_by_user.setdefault(uid, cs)
    except Exception as e:
        L.append('STRIPE-FEHLER: ' + type(e).__name__ + ': ' + str(e)[:200])
    L.append('')
    activate = request.args.get('activate', type=int)
    if activate:
        L.append('=== Aktivierung erzwingen fuer User #' + str(activate) + ' ===')
        cs = sessions_by_user.get(activate)
        if not cs:
            L.append('Keine bezahlte Checkout-Session fuer diesen User gefunden.')
        else:
            try:
                meta = dict(getattr(cs, 'metadata', None) or {})
                interval = 'yearly' if meta.get('plan_type') == 'yearly' else 'monthly'
                _activate_premium(activate, getattr(cs, 'customer', None),
                                  getattr(cs, 'subscription', None), interval)
                row = query_db('SELECT plan, status, plan_interval FROM subscriptions WHERE user_id=?', [activate], one=True)
                L.append('OK -> DB jetzt: ' + str(row_to_dict(row) if row else None))
                L.append('Bestaetigungs-Mail mit Rechnung wurde versendet (falls E-Mail hinterlegt).')
            except Exception as e:
                L.append('AKTIVIERUNG FEHLGESCHLAGEN (' + type(e).__name__ + '): ' + str(e)[:300])
    else:
        L.append('Tipp: ?activate=USER_ID anhaengen, um Premium fuer einen User mit bezahlter Session zu aktivieren.')
    html = ('<html><body style="font-family:Consolas,monospace;background:#0e1117;color:#dde5f4;padding:24px;">'
            '<h2 style="color:#4e8cdd;">HolzBau 3D - Abo Diagnose</h2>'
            '<pre style="white-space:pre-wrap;font-size:13px;line-height:1.7;background:#161b27;'
            'padding:18px;border-radius:10px;border:1px solid #283755;">'
            + '\n'.join(L) +
            '</pre></body></html>')
    return html


# ---------------------------------------------------------------------------
# HolzBau 3D App
# ---------------------------------------------------------------------------

@app.route('/holzbau')
@login_required
def holzbau():
    plan = get_user_plan(session['user_id'])
    return render_template('holzbau.html', show_ads=(plan == 'free'), user_plan=plan)


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------

@app.route('/landing')
def landing():
    return redirect(url_for('index'), 301)


@app.route('/impressum')
def impressum():
    return render_template('impressum.html')


@app.route('/datenschutz')
def datenschutz():
    return render_template('datenschutz.html')


@app.route('/pricing')
def pricing_public():
    return render_template('pricing_public.html')


# ---------------------------------------------------------------------------
# Subscription
# ---------------------------------------------------------------------------

def get_user_plan(user_id):
    row = query_db('SELECT plan, status FROM subscriptions WHERE user_id=?', [user_id], one=True)
    if row and row['plan'] == 'premium' and row['status'] == 'active':
        return 'premium'
    return 'free'


@app.route('/subscribe')
@login_required
def subscribe():
    user_id = session['user_id']

    # Fallback/Sync: Beim Rücksprung von Stripe (?success=1) oder manuell (?sync=1)
    # bezahlte Checkout-Sessions dieses Users suchen und das Abo aktivieren,
    # falls der Webhook (noch) nicht gegriffen hat.
    cs_id = request.args.get('session_id')
    if (request.args.get('success') or request.args.get('sync')) and get_user_plan(user_id) == 'free':
        try:
            import stripe
            stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '')
            if cs_id:
                sessions = [stripe.checkout.Session.retrieve(cs_id)]
            else:
                sessions = stripe.checkout.Session.list(limit=100).data
            for cs in sessions:
                meta = dict(getattr(cs, 'metadata', None) or {})
                if (int(meta.get('user_id', 0) or 0) == user_id
                        and getattr(cs, 'payment_status', '') == 'paid'
                        and getattr(cs, 'mode', '') == 'subscription'):
                    interval = 'yearly' if meta.get('plan_type') == 'yearly' else 'monthly'
                    _activate_premium(user_id, getattr(cs, 'customer', None),
                                      getattr(cs, 'subscription', None), interval)
                    flash('Dein Premium-Abo wurde aktiviert. Eine Bestätigung mit Rechnung ist unterwegs per E-Mail. ✨', 'success')
                    break
        except Exception as e:
            logger.error('Checkout success fallback failed: %s', type(e).__name__)

    plan = get_user_plan(user_id)
    stripe_configured = bool(os.environ.get('STRIPE_SECRET_KEY'))
    yearly_configured = bool(os.environ.get('STRIPE_YEARLY_PRICE_ID'))
    sub = query_db('SELECT * FROM subscriptions WHERE user_id=?', [user_id], one=True)
    return render_template("subscribe.html", plan=plan, stripe_configured=stripe_configured,
                           yearly_configured=yearly_configured,
                           sub=row_to_dict(sub) if sub else {}, csrf_token=generate_csrf())


@app.route('/subscribe/create-checkout', methods=['POST'])
@login_required
def subscribe_create_checkout():
    if not validate_csrf(request.form.get('csrf_token', '')):
        abort(403)
    if _check_rate_limit(_checkout_attempts, request.remote_addr, CHECKOUT_MAX_ATTEMPTS):
        flash('Zu viele Versuche. Bitte warte kurz.', 'danger')
        return redirect(url_for('subscribe'))
    stripe_key = os.environ.get('STRIPE_SECRET_KEY')
    plan_type = request.form.get('plan_type', 'monthly')
    if plan_type == 'yearly':
        price_id = os.environ.get('STRIPE_YEARLY_PRICE_ID') or os.environ.get('STRIPE_PRICE_ID')
    else:
        price_id = os.environ.get('STRIPE_PRICE_ID')
    if not stripe_key or not price_id:
        flash('Stripe ist nicht konfiguriert.', 'danger')
        return redirect(url_for('subscribe'))
    try:
        import stripe
        stripe.api_key = stripe_key
        user_id = session['user_id']
        sub_row = query_db('SELECT stripe_customer_id FROM subscriptions WHERE user_id=?', [user_id], one=True)
        customer_id = sub_row['stripe_customer_id'] if sub_row and sub_row['stripe_customer_id'] else None
        checkout = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{'price': price_id, 'quantity': 1}],
            mode='subscription',
            success_url=request.host_url + 'subscribe?success=1&session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.host_url + 'subscribe?cancelled=1',
            metadata={'user_id': str(user_id), 'plan_type': plan_type},
            subscription_data={'metadata': {'user_id': str(user_id), 'plan_type': plan_type}},
        )
        return redirect(checkout.url, code=303)
    except Exception as e:
        logger.error('Stripe checkout error: %s', type(e).__name__)
        flash('Zahlung konnte nicht gestartet werden. Bitte versuche es erneut.', 'danger')
        return redirect(url_for('subscribe'))


@app.route('/subscribe/cancel', methods=['POST'])
@login_required
def subscribe_cancel():
    if not validate_csrf(request.form.get('csrf_token', '')):
        abort(403)
    user_id = session['user_id']
    stripe_key = os.environ.get('STRIPE_SECRET_KEY')
    if not stripe_key:
        flash('Stripe nicht konfiguriert.', 'danger')
        return redirect(url_for('subscribe'))
    try:
        import stripe
        stripe.api_key = stripe_key
        sub_row = query_db('SELECT stripe_sub_id FROM subscriptions WHERE user_id=?', [user_id], one=True)
        if sub_row and sub_row['stripe_sub_id']:
            stripe.Subscription.modify(sub_row['stripe_sub_id'], cancel_at_period_end=True)
            execute_db('UPDATE subscriptions SET status=? WHERE user_id=?', ['cancelled', user_id])
            flash('Abo wird zum Ende der Laufzeit gekündigt.', 'success')
        else:
            flash('Kein aktives Abo gefunden.', 'warning')
    except Exception as e:
        flash(f'Fehler: {str(e)}', 'danger')
    return redirect(url_for('subscribe'))


@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    stripe_key = os.environ.get('STRIPE_SECRET_KEY')
    webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')
    if not stripe_key or not webhook_secret:
        logger.error('Stripe webhook called but STRIPE_SECRET_KEY or STRIPE_WEBHOOK_SECRET not set')
        abort(400)
    try:
        import stripe
        stripe.api_key = stripe_key
        payload = request.get_data()
        sig = request.headers.get('Stripe-Signature', '')
        event = stripe.Webhook.construct_event(payload, sig, webhook_secret)
        _handle_stripe_event(event)
        return jsonify(ok=True)
    except stripe.error.SignatureVerificationError:
        logger.warning('Stripe webhook signature verification failed')
        abort(400)
    except Exception as e:
        logger.error('Stripe webhook error: %s', type(e).__name__)
        return jsonify(error='Webhook error'), 400


def _email_premium_html(display_name, amount_txt, interval, invoice_url):
    interval_txt = 'Jahres-Abo' if interval == 'yearly' else 'Monats-Abo'
    invoice_block = ''
    if invoice_url:
        invoice_block = (
            '<table cellpadding="0" cellspacing="0" style="margin:0 0 24px;"><tr><td style="background:linear-gradient(135deg,#d97706,#92400e);border-radius:10px;">'
            f'<a href="{invoice_url}" style="display:inline-block;padding:13px 30px;color:#ffffff;text-decoration:none;font-weight:700;font-size:.95rem;">📄 Rechnung ansehen &amp; herunterladen</a>'
            '</td></tr></table>'
        )
    return f'''<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#faf6f0;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#faf6f0;padding:40px 16px;">
<tr><td align="center">
<table width="540" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08);max-width:540px;width:100%;">
  <tr><td style="background:linear-gradient(135deg,#d97706,#92400e);padding:28px 40px;">
    <span style="color:#fff;font-size:1.35rem;font-weight:800;letter-spacing:-0.5px;">HolzBAU <span style="font-size:1rem;">3D</span></span>
  </td></tr>
  <tr><td style="padding:40px;">
    <h2 style="margin:0 0 16px;font-size:1.15rem;color:#1a1a1a;font-weight:700;">✨ Premium ist aktiv!</h2>
    <p style="margin:0 0 10px;color:#374151;line-height:1.65;font-size:.95rem;">Hallo <strong>{display_name}</strong>,</p>
    <p style="margin:0 0 20px;color:#374151;line-height:1.65;font-size:.95rem;">vielen Dank für dein Vertrauen! Dein <strong>{interval_txt}</strong> ({amount_txt}) ist ab sofort aktiv — alle Premium-Features sind freigeschaltet.</p>
    <table cellpadding="0" cellspacing="0" style="width:100%;background:#fef9f0;border:1px solid #fde68a;border-radius:10px;margin:0 0 24px;"><tr><td style="padding:16px 20px;font-size:.88rem;color:#374151;line-height:2;">
      ✅ Unbegrenzte Balken &amp; Projekte<br>
      ✅ Vollständig werbefrei<br>
      ✅ PDF Export &amp; Druckpläne<br>
      ✅ Säge-Tool &amp; Schnittplan-Optimierung
    </td></tr></table>
    {invoice_block}
    <p style="margin:0;color:#9ca3af;font-size:.8rem;line-height:1.6;">Du kannst dein Abo jederzeit unter „Mein Abonnement" verwalten oder kündigen.</p>
  </td></tr>
  <tr><td style="background:#faf6f0;padding:20px 40px;border-top:1px solid #f0e8dc;">
    <p style="margin:0;color:#9ca3af;font-size:.75rem;">HolzBau 3D · <a href="https://holzbau3d.app" style="color:#d97706;">holzbau3d.app</a></p>
  </td></tr>
</table>
</td></tr>
</table>
</body></html>'''


def _activate_premium(user_id, customer_id, sub_id, interval, notify=True):
    """Setzt einen User auf Premium. Genutzt von Webhook UND Checkout-Success-Fallback.
    Holt Laufzeit-Ende + Rechnungslink von Stripe und mailt eine Bestätigung (einmalig)."""
    if not user_id:
        return False
    existing = query_db('SELECT * FROM subscriptions WHERE user_id=?', [user_id], one=True)
    already = bool(existing and existing['plan'] == 'premium' and existing['status'] == 'active'
                   and existing['stripe_sub_id'] == sub_id)

    period_end = None
    invoice_url = None
    amount_txt = '99,99 € / Jahr' if interval == 'yearly' else '9,99 € / Monat'
    try:
        import stripe
        stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '')
        if sub_id and stripe.api_key:
            s = stripe.Subscription.retrieve(sub_id)
            cpe = getattr(s, 'current_period_end', None)
            if cpe:
                period_end = datetime.fromtimestamp(cpe).isoformat()
            li = getattr(s, 'latest_invoice', None)
            if li:
                inv = stripe.Invoice.retrieve(li)
                invoice_url = getattr(inv, 'hosted_invoice_url', None)
                amt = getattr(inv, 'amount_paid', None)
                cur = (getattr(inv, 'currency', '') or '').upper()
                if amt:
                    amount_txt = ('%.2f' % (amt / 100)).replace('.', ',') + ' ' + cur + \
                                 (' / Jahr' if interval == 'yearly' else ' / Monat')
    except Exception as e:
        logger.error('activate_premium: Stripe lookup failed: %s', type(e).__name__)

    if existing:
        execute_db('UPDATE subscriptions SET stripe_customer_id=?, stripe_sub_id=?, plan=?, status=?, plan_interval=?, '
                   'current_period_end=COALESCE(?, current_period_end) WHERE user_id=?',
                   [customer_id, sub_id, 'premium', 'active', interval, period_end, user_id])
    else:
        execute_db('INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_sub_id, plan, status, plan_interval, current_period_end) '
                   'VALUES (?,?,?,?,?,?,?)',
                   [user_id, customer_id, sub_id, 'premium', 'active', interval, period_end])

    if notify and not already:
        u = query_db('SELECT email, full_name, username FROM app_users WHERE id=?', [user_id], one=True)
        if u and u['email']:
            send_email(u['email'], 'HolzBau 3D – Premium aktiviert ✨ (Rechnung)',
                       _email_premium_html(u['full_name'] or u['username'], amount_txt, interval, invoice_url))
    return True


def _handle_stripe_event(event):
    data = event['data']['object']
    etype = event['type']
    if etype == 'checkout.session.completed':
        user_id = int(data.get('metadata', {}).get('user_id', 0))
        plan_type = data.get('metadata', {}).get('plan_type', 'monthly')
        interval = 'yearly' if plan_type == 'yearly' else 'monthly'
        _activate_premium(user_id, data.get('customer'), data.get('subscription'), interval)
    elif etype in ('customer.subscription.deleted', 'customer.subscription.updated'):
        sub_id = data.get('id')
        status = data.get('status', 'cancelled')
        plan = 'premium' if status == 'active' else 'free'
        db_status = 'active' if status == 'active' else 'cancelled'
        period_end = datetime.fromtimestamp(data.get('current_period_end', 0)).isoformat() if data.get('current_period_end') else None
        execute_db('UPDATE subscriptions SET plan=?, status=?, current_period_end=? WHERE stripe_sub_id=?',
                   [plan, db_status, period_end, sub_id])


# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
else:
    with app.app_context():
        init_db()
