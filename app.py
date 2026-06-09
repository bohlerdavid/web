import os
import secrets
import time
from functools import wraps
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, g, abort, jsonify, session
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import pymysql
import pymysql.cursors

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'holzbau3d-secret-key')

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

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
    # Convert SQLite ? placeholders to MySQL %s
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


def init_db():
    with app.app_context():
        db = get_db()
        with db.cursor() as cur:
            for stmt in SCHEMA_STATEMENTS:
                cur.execute(stmt)
            # Create default admin if no users exist
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
# Brute-force protection
# ---------------------------------------------------------------------------

_login_attempts = {}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300


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
# Health
# ---------------------------------------------------------------------------

@app.route('/health')
def health():
    return 'ok', 200


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('holzbau'))
    return redirect(url_for('landing'))


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
            _login_attempts.pop(ip, None)
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name'] or user['username']
            session['role'] = 'admin' if user['username'] == 'admin' else 'user'
            execute_db("UPDATE app_users SET last_login = NOW() WHERE id = ?", (user['id'],))
            next_url = request.form.get('next') or request.args.get('next') or url_for('holzbau')
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
        token = request.form.get('csrf_token', '')
        if not validate_csrf(token):
            flash('Ungültige Anfrage.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf())

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()

        if len(username) < 3:
            flash('Benutzername muss mindestens 3 Zeichen lang sein.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf())
        if len(password) < 8:
            flash('Passwort muss mindestens 8 Zeichen lang sein.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf())

        existing = query_db("SELECT id FROM app_users WHERE username = ?", (username,), one=True)
        if existing:
            flash('Benutzername bereits vergeben.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf())

        user_id = execute_db(
            "INSERT INTO app_users (username, password_hash, full_name, email) VALUES (?,?,?,?)",
            (username, generate_password_hash(password), full_name, email)
        )
        session.permanent = True
        session['user_id'] = user_id
        session['username'] = username
        session['full_name'] = full_name or username
        session['role'] = 'user'
        flash('Willkommen bei HolzBau 3D!', 'success')
        return redirect(url_for('holzbau'))

    return render_template('register.html', csrf_token=generate_csrf())


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing'))


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
        new_pw = request.form.get('new_password', '')
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


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.route('/admin/users')
@admin_required
def admin_users():
    users = query_db("""
        SELECT u.id, u.username, u.full_name, u.email, u.created_at, u.last_login,
               COALESCE(s.plan, 'free') as plan, COALESCE(s.status, '') as sub_status
        FROM app_users u
        LEFT JOIN subscriptions s ON s.user_id = u.id
        ORDER BY u.created_at DESC
    """)
    return render_template('admin_users.html', users=users)


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
    return render_template('landing.html')


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
    plan = get_user_plan(user_id)
    stripe_configured = bool(os.environ.get('STRIPE_SECRET_KEY'))
    sub = query_db('SELECT * FROM subscriptions WHERE user_id=?', [user_id], one=True)
    return render_template('subscribe.html', plan=plan, stripe_configured=stripe_configured,
                           sub=row_to_dict(sub) if sub else {}, csrf_token=generate_csrf())


@app.route('/subscribe/create-checkout', methods=['POST'])
@login_required
def subscribe_create_checkout():
    if not validate_csrf(request.form.get('csrf_token', '')):
        abort(403)
    stripe_key = os.environ.get('STRIPE_SECRET_KEY')
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
            success_url=request.host_url + 'subscribe?success=1',
            cancel_url=request.host_url + 'subscribe?cancelled=1',
            metadata={'user_id': str(user_id)},
        )
        return redirect(checkout.url, code=303)
    except Exception as e:
        flash(f'Stripe Fehler: {str(e)}', 'danger')
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
    if not stripe_key:
        abort(400)
    try:
        import stripe
        stripe.api_key = stripe_key
        payload = request.get_data()
        sig = request.headers.get('Stripe-Signature', '')
        if webhook_secret:
            event = stripe.Webhook.construct_event(payload, sig, webhook_secret)
        else:
            import json
            event = stripe.Event.construct_from(json.loads(payload), stripe_key)
        _handle_stripe_event(event)
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(error=str(e)), 400


def _handle_stripe_event(event):
    data = event['data']['object']
    etype = event['type']
    if etype == 'checkout.session.completed':
        user_id = int(data.get('metadata', {}).get('user_id', 0))
        if not user_id:
            return
        customer_id = data.get('customer')
        sub_id = data.get('subscription')
        existing = query_db('SELECT id FROM subscriptions WHERE user_id=?', [user_id], one=True)
        if existing:
            execute_db('UPDATE subscriptions SET stripe_customer_id=?, stripe_sub_id=?, plan=?, status=? WHERE user_id=?',
                       [customer_id, sub_id, 'premium', 'active', user_id])
        else:
            execute_db('INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_sub_id, plan, status) VALUES (?,?,?,?,?)',
                       [user_id, customer_id, sub_id, 'premium', 'active'])
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
