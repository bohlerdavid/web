import os
import json
import html
import base64
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
# Harte Obergrenze fuer jeden Request-Body. Ohne sie puffert Werkzeug ein Formular
# unbegrenzt im RAM — und zwar BEVOR die View ueberhaupt laeuft, also vor CSRF- und
# Premium-Pruefung. Ein 89-MB-Feld ergab gemessen 336 MB Spitze. Werkzeug 3.0.3
# (so gepinnt) hat dafuer keinen eigenen Default; 3.1 haette einen.
# 8 MB reichen fuer Feedback samt Screenshot mit Luft nach oben.
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') != 'development'

Talisman(
    app,
    force_https=False,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    # Die CSP war zu eng fuer die eigenen Einbindungen: Google Fonts, GA4 und
    # AdSense standen im HTML, wurden aber vom Browser abgewiesen. Konkret hiess
    # das: keine Messdaten in Analytics, keine Anzeigen (auch fuer Googles Pruefer
    # nicht -> AdSense-Ablehnung), und die Seite lief in Systemschriften statt in
    # Newsreader/Work Sans. Jeder Eintrag hier ist gegen die Live-Seite gemessen,
    # nicht geraten.
    content_security_policy={
        'default-src': ["'self'", 'cdn.jsdelivr.net'],
        'script-src': [
            "'self'", "'unsafe-inline'",
            'cdn.jsdelivr.net',            # three.js
            'js.stripe.com',
            'www.googletagmanager.com',    # GA4
            # AdSense laedt seine Bausteine ueber mehrere Google-Hosts nach.
            '*.googlesyndication.com',
            '*.googleadservices.com',
            '*.doubleclick.net',
            'adservice.google.com',
            'www.google.com',
            '*.adtrafficquality.google',   # sodar2.js — Erkennung ungueltiger Klicks
            'fundingchoicesmessages.google.com',   # Einwilligungs-Banner (CMP)
        ],
        'style-src': ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'fonts.googleapis.com'],
        # Ohne font-src greift default-src — und gstatic war damit gesperrt.
        'font-src': ["'self'", 'data:', 'fonts.gstatic.com'],
        # Anzeigen laufen in iframes; 'none' hat sie vollstaendig unterbunden.
        'frame-src': [
            "'self'",
            '*.googlesyndication.com',
            '*.doubleclick.net',
            'www.google.com',
            '*.adtrafficquality.google',   # Googles Erkennung ungueltiger Klicks
            'fundingchoicesmessages.google.com',
        ],
        # Werbemittel kommen von beliebigen Werbetreibenden — eine Whitelist ist
        # hier nicht moeglich. https: erlaubt nur Bilder, keine Ausfuehrung.
        'img-src': ["'self'", 'data:', 'https:'],
        'connect-src': [
            "'self'",
            'dl.polyhaven.org',
            # GA4 sendet je nach Region an ZWEI verschiedene Domainfamilien:
            # www.google-analytics.com UND region1.analytics.google.com.
            # Nur die erste zu erlauben sieht richtig aus, verwirft aber still
            # genau die Messdaten — gemessen, nicht vermutet.
            '*.google-analytics.com',
            '*.analytics.google.com',
            'www.googletagmanager.com',
            '*.googlesyndication.com',
            '*.doubleclick.net',
            '*.adtrafficquality.google',
            'fundingchoicesmessages.google.com',
        ],
        # Kein fremder Code darf die Seite selbst einbetten (Clickjacking).
        'frame-ancestors': ["'self'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'object-src': ["'none'"],
    },
    referrer_policy='strict-origin-when-cross-origin',
    feature_policy={},
    session_cookie_secure=True,
)


@app.after_request
def _no_cache_html(resp):
    # HTML-Seiten (App, Landing …) nie cachen -> nach Deploys immer frischer Code,
    # niemand hängt auf einer veralteten Version fest. Statische Assets bleiben cachebar.
    if resp.headers.get('Content-Type', '').startswith('text/html'):
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
    return resp

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
    """CREATE TABLE IF NOT EXISTS feedback (
        id           INT PRIMARY KEY AUTO_INCREMENT,
        user_id      INT NOT NULL,
        kind         VARCHAR(10)  NOT NULL DEFAULT 'bug',
        subject      VARCHAR(200) NOT NULL,
        message      TEXT         NOT NULL,
        screenshot   MEDIUMBLOB   NULL,
        shot_mime    VARCHAR(20)  NULL,
        ctx          TEXT         NULL,
        status       VARCHAR(12)  NOT NULL DEFAULT 'neu',
        admin_reply  TEXT         NULL,
        created      DATETIME     NOT NULL,
        updated      DATETIME     NULL,
        INDEX (user_id), INDEX (status)
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
    "ALTER TABLE subscriptions ADD COLUMN sub_started DATETIME NULL",
    "ALTER TABLE app_users ADD COLUMN lang VARCHAR(5) NOT NULL DEFAULT 'de'",
    "ALTER TABLE subscriptions ADD COLUMN reminder_stage VARCHAR(4) NOT NULL DEFAULT ''",
    # Weekly Premium-upsell mailing: opt-out flag, unsubscribe token, throttle timestamp
    "ALTER TABLE app_users ADD COLUMN marketing_opt_out TINYINT NOT NULL DEFAULT 0",
    "ALTER TABLE app_users ADD COLUMN unsub_token VARCHAR(64) NULL",
    "ALTER TABLE app_users ADD COLUMN last_upsell_sent DATETIME NULL",
    # Verlaengerungs-Erinnerung: speichert das Periodenende, fuer das bereits
    # gemailt wurde. Als Schluessel bewusst das Datum und kein Flag — bei der
    # naechsten Periode aendert sich current_period_end, damit passt der
    # gespeicherte Wert nicht mehr und es wird von selbst erneut erinnert.
    # (reminder_stage taugt dafuer nicht: _activate_premium setzt es bei jeder
    #  Verlaengerung auf '' zurueck.)
    "ALTER TABLE subscriptions ADD COLUMN renewal_notice_for DATETIME NULL",
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


def _stripe_api_get(path, params=None):
    """Direkter Stripe-REST-Aufruf (GET) — unabhaengig von SDK-Versionsunterschieden."""
    import base64
    from urllib.parse import urlencode
    sk = os.environ.get('STRIPE_SECRET_KEY', '')
    if not sk:
        raise RuntimeError('STRIPE_SECRET_KEY fehlt')
    url = 'https://api.stripe.com/v1/' + path
    if params:
        url += '?' + urlencode(params)
    req = urllib.request.Request(url)
    req.add_header('Authorization', 'Basic ' + base64.b64encode((sk + ':').encode()).decode())
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode('utf-8'))


SUPPORTED_LANGS = ('de', 'en', 'fr')


def _norm_lang(value):
    v = (value or 'de')[:2].lower()
    return v if v in SUPPORTED_LANGS else 'de'


def _request_lang():
    """Sprache des aktuellen Besuchers: Cookie > Accept-Language > de."""
    cookie = request.cookies.get('hb_lang')
    if cookie:
        return _norm_lang(cookie)
    accept = request.headers.get('Accept-Language', '')
    return _norm_lang(accept)


EMAIL_I18N = {
    'de': {
        'v_subject': 'HolzBau 3D – E-Mail-Adresse bestätigen',
        'v_title':   'E-Mail-Adresse bestätigen',
        'hello':     'Hallo',
        'v_body':    'danke für deine Registrierung bei HolzBau 3D! Bitte bestätige deine E-Mail-Adresse, um dein Konto zu aktivieren:',
        'v_button':  'E-Mail bestätigen',
        'v_note':    'Dieser Link ist 48 Stunden gültig. Falls du dich nicht registriert hast, kannst du diese E-Mail ignorieren.',
        'r_subject': 'HolzBau 3D – Passwort zurücksetzen',
        'r_title':   'Passwort zurücksetzen',
        'r_body':    'du hast ein neues Passwort für dein HolzBau 3D Konto angefordert. Klicke auf den Button, um dein Passwort zurückzusetzen:',
        'r_button':  'Passwort zurücksetzen',
        'r_note':    'Dieser Link ist 1 Stunde gültig. Falls du kein neues Passwort angefordert hast, kannst du diese E-Mail ignorieren — dein Passwort bleibt unverändert.',
        'p_subject': 'HolzBau 3D – Premium aktiviert ✨ (Rechnung)',
        'p_title':   '✨ Premium ist aktiv!',
        'p_thanks':  'vielen Dank für dein Vertrauen! Dein <strong>{plan}</strong> ({amount}) ist ab sofort aktiv — alle Premium-Features sind freigeschaltet.',
        'p_plan_y':  'Jahres-Abo',
        'p_plan_m':  'Monats-Abo',
        'p_features': '✅ Unbegrenzte Balken &amp; Projekte<br>✅ Vollständig werbefrei<br>✅ PDF Export &amp; Druckpläne<br>✅ Säge-Tool &amp; Schnittplan-Optimierung',
        'p_invoice': '📄 Rechnung ansehen &amp; herunterladen',
        'p_box_title': 'Deine Vertragsdaten',
        'p_box_plan': 'Abo',
        'p_box_amount': 'Preis',
        'p_box_next': 'Nächste Abbuchung',
        'p_box_next_none': 'wird dir von Stripe angezeigt',
        'p_renew': '<strong>Wichtig:</strong> Dein Abo verlängert sich automatisch und wird immer wieder abgebucht, bis du kündigst. Es gibt keine Mindestlaufzeit — du kannst jederzeit kündigen, ohne Frist.',
        'p_cancel_hint': 'Kündigen kannst du jederzeit mit einem Klick unter „Mein Abonnement“. Nach der Kündigung behältst du Premium bis zum Ende des bereits bezahlten Zeitraums, danach wird nichts mehr abgebucht.',
        'p_manage':  'Du kannst dein Abo jederzeit unter „Mein Abonnement" verwalten oder kündigen.',
        'per_year':  ' / Jahr',
        'per_month': ' / Monat',
    },
    'en': {
        'v_subject': 'HolzBau 3D – Confirm your email address',
        'v_title':   'Confirm your email address',
        'hello':     'Hello',
        'v_body':    'thanks for signing up for HolzBau 3D! Please confirm your email address to activate your account:',
        'v_button':  'Confirm email',
        'v_note':    'This link is valid for 48 hours. If you did not sign up, you can safely ignore this email.',
        'r_subject': 'HolzBau 3D – Reset your password',
        'r_title':   'Reset your password',
        'r_body':    'you requested a new password for your HolzBau 3D account. Click the button below to reset your password:',
        'r_button':  'Reset password',
        'r_note':    'This link is valid for 1 hour. If you did not request a new password, you can ignore this email — your password remains unchanged.',
        'p_subject': 'HolzBau 3D – Premium activated ✨ (invoice)',
        'p_title':   '✨ Premium is active!',
        'p_thanks':  'thank you for your trust! Your <strong>{plan}</strong> ({amount}) is now active — all premium features are unlocked.',
        'p_plan_y':  'annual plan',
        'p_plan_m':  'monthly plan',
        'p_features': '✅ Unlimited beams &amp; projects<br>✅ Completely ad-free<br>✅ PDF export &amp; construction plans<br>✅ Saw tool &amp; cutting plan optimisation',
        'p_invoice': '📄 View &amp; download invoice',
        'p_box_title': 'Your contract details',
        'p_box_plan': 'Plan',
        'p_box_amount': 'Price',
        'p_box_next': 'Next charge',
        'p_box_next_none': 'shown to you by Stripe',
        'p_renew': '<strong>Important:</strong> your subscription renews automatically and is charged again and again until you cancel. There is no minimum term — you can cancel at any time, with no notice period.',
        'p_cancel_hint': 'You can cancel any time with one click under “My subscription”. After cancelling you keep Premium until the end of the period you already paid for; nothing further will be charged.',
        'p_manage':  'You can manage or cancel your subscription at any time under "My subscription".',
        'per_year':  ' / year',
        'per_month': ' / month',
    },
    'fr': {
        'v_subject': 'HolzBau 3D – Confirmez votre adresse e-mail',
        'v_title':   'Confirmez votre adresse e-mail',
        'hello':     'Bonjour',
        'v_body':    'merci de votre inscription sur HolzBau 3D ! Veuillez confirmer votre adresse e-mail pour activer votre compte :',
        'v_button':  'Confirmer l’e-mail',
        'v_note':    'Ce lien est valable 48 heures. Si vous ne vous êtes pas inscrit, vous pouvez ignorer cet e-mail.',
        'r_subject': 'HolzBau 3D – Réinitialiser votre mot de passe',
        'r_title':   'Réinitialiser le mot de passe',
        'r_body':    'vous avez demandé un nouveau mot de passe pour votre compte HolzBau 3D. Cliquez sur le bouton pour réinitialiser votre mot de passe :',
        'r_button':  'Réinitialiser le mot de passe',
        'r_note':    'Ce lien est valable 1 heure. Si vous n’avez pas demandé de nouveau mot de passe, vous pouvez ignorer cet e-mail — votre mot de passe reste inchangé.',
        'p_subject': 'HolzBau 3D – Premium activé ✨ (facture)',
        'p_title':   '✨ Premium est actif !',
        'p_thanks':  'merci de votre confiance ! Votre <strong>{plan}</strong> ({amount}) est désormais actif — toutes les fonctionnalités Premium sont débloquées.',
        'p_plan_y':  'abonnement annuel',
        'p_plan_m':  'abonnement mensuel',
        'p_features': '✅ Poutres &amp; projets illimités<br>✅ Sans aucune publicité<br>✅ Export PDF &amp; plans d’impression<br>✅ Outil scie &amp; optimisation du plan de coupe',
        'p_invoice': '📄 Voir &amp; télécharger la facture',
        'p_box_title': 'Vos données contractuelles',
        'p_box_plan': 'Abonnement',
        'p_box_amount': 'Prix',
        'p_box_next': 'Prochain prélèvement',
        'p_box_next_none': 'affiché par Stripe',
        'p_renew': '<strong>Important :</strong> votre abonnement se renouvelle automatiquement et est prélevé encore et encore jusqu’à votre résiliation. Aucune durée minimale — vous pouvez résilier à tout moment, sans préavis.',
        'p_cancel_hint': 'Vous pouvez résilier à tout moment en un clic sous « Mon abonnement ». Après résiliation, vous conservez Premium jusqu’à la fin de la période déjà payée ; plus rien ne sera prélevé.',
        'p_manage':  'Vous pouvez gérer ou résilier votre abonnement à tout moment sous « Mon abonnement ».',
        'per_year':  ' / an',
        'per_month': ' / mois',
    },
}


def _email_shell(inner):
    return f'''<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#faf6f0;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#faf6f0;padding:40px 16px;">
<tr><td align="center">
<table width="540" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08);max-width:540px;width:100%;">
  <tr><td style="background:linear-gradient(135deg,#d97706,#92400e);padding:28px 40px;">
    <span style="color:#fff;font-size:1.35rem;font-weight:800;letter-spacing:-0.5px;">HolzBAU <span style="font-size:1rem;">3D</span></span>
  </td></tr>
  <tr><td style="padding:40px;">
{inner}
  </td></tr>
  <tr><td style="padding:18px 40px;border-top:1px solid #f3f4f6;">
    <p style="margin:0;color:#d1d5db;font-size:.72rem;">&copy; 2026 HolzBau 3D &middot; <a href="https://holzbau3d.app" style="color:#d97706;text-decoration:none;">holzbau3d.app</a></p>
  </td></tr>
</table>
</td></tr>
</table>
</body></html>'''


def _email_verify_html(display_name, verify_url, lang='de'):
    T = EMAIL_I18N.get(_norm_lang(lang), EMAIL_I18N['de'])
    return _email_shell(f'''    <h2 style="margin:0 0 16px;font-size:1.15rem;color:#1a1a1a;font-weight:700;">{T['v_title']}</h2>
    <p style="margin:0 0 10px;color:#374151;line-height:1.65;font-size:.95rem;">{T['hello']} <strong>{display_name}</strong>,</p>
    <p style="margin:0 0 28px;color:#374151;line-height:1.65;font-size:.95rem;">{T['v_body']}</p>
    <table cellpadding="0" cellspacing="0"><tr><td>
      <a href="{verify_url}" style="display:inline-block;background:linear-gradient(135deg,#d97706,#92400e);color:#ffffff;text-decoration:none;padding:14px 32px;border-radius:10px;font-weight:700;font-size:.95rem;">{T['v_button']}</a>
    </td></tr></table>
    <p style="margin:28px 0 8px;color:#9ca3af;font-size:.8rem;line-height:1.5;">{T['v_note']}</p>
    <p style="margin:0;color:#c4c9d4;font-size:.72rem;word-break:break-all;">Link: {verify_url}</p>''')


def _email_reset_html(display_name, reset_url, lang='de'):
    T = EMAIL_I18N.get(_norm_lang(lang), EMAIL_I18N['de'])
    return _email_shell(f'''    <h2 style="margin:0 0 16px;font-size:1.15rem;color:#1a1a1a;font-weight:700;">{T['r_title']}</h2>
    <p style="margin:0 0 10px;color:#374151;line-height:1.65;font-size:.95rem;">{T['hello']} <strong>{display_name}</strong>,</p>
    <p style="margin:0 0 28px;color:#374151;line-height:1.65;font-size:.95rem;">{T['r_body']}</p>
    <table cellpadding="0" cellspacing="0"><tr><td>
      <a href="{reset_url}" style="display:inline-block;background:linear-gradient(135deg,#d97706,#92400e);color:#ffffff;text-decoration:none;padding:14px 32px;border-radius:10px;font-weight:700;font-size:.95rem;">{T['r_button']}</a>
    </td></tr></table>
    <p style="margin:28px 0 8px;color:#9ca3af;font-size:.8rem;line-height:1.5;">{T['r_note']}</p>
    <p style="margin:0;color:#c4c9d4;font-size:.72rem;word-break:break-all;">Link: {reset_url}</p>''')


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


# ---------------------------------------------------------------------------
# SEO: mehrsprachige Meta-Daten + Sprach-URLs (/, /en, /fr)
# ---------------------------------------------------------------------------

SITE = 'https://holzbau3d.app'


def _admin_email():
    """Adresse fuer Admin-Benachrichtigungen. Vorrang hat ADMIN_EMAIL aus der
    Umgebung; sonst die Adresse des 'admin'-Kontos, das die Rolle definiert
    (siehe session['role']-Zuweisung beim Login)."""
    env = os.environ.get('ADMIN_EMAIL', '').strip()
    if env:
        return env
    try:
        r = query_db("SELECT email FROM app_users WHERE username='admin'", [], one=True)
        if r and r['email']:
            return r['email']
    except Exception:
        pass
    return os.environ.get('MAIL_FROM', '') or 'info@holzbau3d.app'

SEO_META = {
    'de': {
        'title': 'Holzbau 3D – Holzkonstruktion planen, 3D Holzdesign | Gratis',
        'desc': 'Holzbau 3D – das kostenlose Konstruktionsprogramm & 3D-Holzdesign-Tool: Holzkonstruktionen online planen – Pergola, Carport, Dachstuhl & mehr direkt im Browser, mit Stückliste, Schnittplan & PDF-Export. Jetzt gratis starten.',
        'keywords': 'Holzbau, Holzbau 3D, 3D Holzdesign, Holzdesign 3D, Holzkonstruktion, Holz Konstruktion, Holzbau Konstruktion, Konstruktion aus Holz, Holzkonstruktion 3D, Holzkonstruktion planen, Holzkonstruktion planen kostenlos, Holzkonstruktion online, Holz konstruieren, Holzbau planen, Holzbau Software kostenlos, Holzbausoftware kostenlos, Konstruktionsprogramm Holzbau kostenlos, 3D Holz Planer kostenlos, Holzbau Programm, 3D Holzbau, Pergola planen, Carport planen, Dachstuhl planen, Stückliste, Schnittplan',
        'og_title': 'Holzbau 3D – Holzkonstruktion in 3D planen & konstruieren',
        'og_desc': 'Holzkonstruktionen online planen und konstruieren – Pergola, Carport, Dachstuhl & mehr. Gratis im Browser, mit Stückliste und PDF-Export.',
        'og_locale': 'de_DE',
    },
    'en': {
        'title': 'Wood Construction 3D – Plan Timber Structures & 3D Wood Design | Free',
        'desc': 'HolzBau 3D: plan and design wood constructions online for free – pergola, carport, roof truss & more, right in your browser. Timber construction in 3D, with parts list, cutting plan & PDF export. Start free.',
        'keywords': 'wood construction, wood construction 3D, timber construction, timber construction 3D, plan wood construction, design timber structure, wood construction software, wood construction online, timber framing, 3D wood design, pergola, carport, roof truss, online wood planner, parts list, cutting plan',
        'og_title': 'Wood Construction 3D – Plan & design timber structures online',
        'og_desc': 'Plan and design wood constructions online – pergola, carport, roof truss & more. Free in your browser, with parts list and PDF export.',
        'og_locale': 'en_US',
    },
    'fr': {
        'title': 'Construction bois 3D – Concevez vos ossatures en ligne | Gratuit',
        'desc': 'HolzBau 3D : concevez et planifiez vos constructions bois en ligne gratuitement – pergola, carport, charpente & plus, directement dans le navigateur. Construction bois en 3D, avec liste de pièces, plan de coupe et export PDF.',
        'keywords': 'construction bois, construction bois 3D, ossature bois, charpente 3D, concevoir construction bois, planifier construction bois, logiciel construction bois, construction bois en ligne, plan bois, 3D bois, pergola, carport, charpente, planificateur bois en ligne, liste de pièces, plan de coupe',
        'og_title': 'Construction bois 3D – Concevez vos ossatures en 3D en ligne',
        'og_desc': 'Concevez et planifiez vos constructions bois en ligne – pergola, carport, charpente & plus. Gratuit dans le navigateur, avec liste de pièces et export PDF.',
        'og_locale': 'fr_FR',
    },
}


FAQ_ITEMS = {
    'de': [
        ('Ist HolzBau 3D kostenlos?', 'Ja. Du kannst Holzkonstruktionen kostenlos in 3D planen. Premium schaltet zusätzlich PDF-Export, Säge-Tool, Schnittplan-Optimierung und unbegrenzte Projekte frei.'),
        ('Kann ich eine Pergola selbst planen?', 'Ja. Mit HolzBau 3D planst du Pergola, Carport, Dachstuhl, Terrassenüberdachung und beliebige Holzkonstruktionen selbst – inklusive Stückliste und Schnittplan.'),
        ('Muss ich etwas installieren?', 'Nein. HolzBau 3D läuft komplett im Browser – ohne Installation, auf PC, Tablet und Smartphone.'),
        ('Welche Konstruktionen kann ich bauen?', 'Vom Carport über die Pergola bis zum kompletten Dachstuhl: Du setzt Balken, Pfosten, Pfetten und Sparren maßstabsgetreu in 3D und drehst die Konstruktion frei im Raum.'),
        ('Bekomme ich eine Stückliste?', 'Ja. HolzBau 3D erzeugt automatisch eine Stückliste mit allen Balken, Längen und Querschnitten. Als Premium-Nutzer exportierst du sie als CSV und PDF.'),
        ('In welchen Sprachen ist HolzBau 3D verfügbar?', 'HolzBau 3D gibt es auf Deutsch, Englisch und Französisch – die Sprache wechselst du jederzeit mit einem Klick.'),
        ('Kann ich Premium kündigen?', 'Ja, jederzeit. Du kündigst dein Premium-Abo mit einem Klick im Bereich „Mein Abonnement". Es gibt keine Mindestlaufzeit und keine Kündigungsfrist.'),
        ('Bekomme ich mein Geld zurück?', 'Nein, bereits gezahlte Beträge werden nicht erstattet. Stattdessen behältst du nach der Kündigung deinen vollen Premium-Zugang bis zum Ende des bezahlten Zeitraums – danach wird das Abo einfach nicht verlängert.'),
    ],
    'en': [
        ('Is HolzBau 3D free?', 'Yes. You can plan wood constructions in 3D for free. Premium additionally unlocks PDF export, the saw tool, cutting-plan optimisation and unlimited projects.'),
        ('Can I design a pergola myself?', 'Yes. With HolzBau 3D you design pergolas, carports, roof trusses, patio roofs and any wood construction yourself – including parts list and cutting plan.'),
        ('Do I need to install anything?', 'No. HolzBau 3D runs entirely in your browser – no installation, on PC, tablet and smartphone.'),
        ('What can I build?', 'From a carport and a pergola to a complete roof truss: you place beams, posts, purlins and rafters to scale in 3D and rotate the structure freely in space.'),
        ('Do I get a parts list?', 'Yes. HolzBau 3D automatically generates a parts list with all beams, lengths and sections. As a Premium user you export it as CSV and PDF.'),
        ('Which languages does HolzBau 3D support?', 'HolzBau 3D is available in German, English and French – switch the language any time with one click.'),
        ('Can I cancel Premium?', 'Yes, any time. You cancel your Premium subscription with one click under "My subscription". There is no minimum term and no notice period.'),
        ('Do I get a refund?', 'No, amounts already paid are not refunded. Instead, after cancelling you keep full Premium access until the end of the paid period – the subscription is then simply not renewed.'),
    ],
    'fr': [
        ('HolzBau 3D est-il gratuit ?', 'Oui. Vous pouvez concevoir des constructions bois en 3D gratuitement. Premium débloque en plus l’export PDF, l’outil scie, l’optimisation du plan de coupe et les projets illimités.'),
        ('Puis-je concevoir une pergola moi-même ?', 'Oui. Avec HolzBau 3D, vous concevez pergola, carport, charpente, couverture de terrasse et toute construction bois vous-même – liste de pièces et plan de coupe inclus.'),
        ('Dois-je installer quelque chose ?', 'Non. HolzBau 3D fonctionne entièrement dans le navigateur – sans installation, sur PC, tablette et smartphone.'),
        ('Que puis-je construire ?', 'Du carport à la pergola jusqu’à une charpente complète : vous placez poutres, poteaux, pannes et chevrons à l’échelle en 3D et faites pivoter la structure librement.'),
        ('Ai-je une liste de pièces ?', 'Oui. HolzBau 3D génère automatiquement une liste de pièces avec toutes les poutres, longueurs et sections. En tant qu’utilisateur Premium, vous l’exportez en CSV et PDF.'),
        ('Dans quelles langues HolzBau 3D est-il disponible ?', 'HolzBau 3D est disponible en allemand, anglais et français – changez de langue à tout moment en un clic.'),
        ('Puis-je résilier Premium ?', 'Oui, à tout moment. Vous résiliez votre abonnement Premium en un clic dans « Mon abonnement ». Aucune durée minimale ni préavis.'),
        ('Suis-je remboursé ?', 'Non, les montants déjà payés ne sont pas remboursés. Après la résiliation, vous conservez l’accès Premium complet jusqu’à la fin de la période payée – l’abonnement n’est ensuite simplement pas renouvelé.'),
    ],
}

FAQ_HEADING = {'de': 'Häufige Fragen', 'en': 'Frequently Asked Questions', 'fr': 'Questions fréquentes'}


def _seo_faq(lang):
    """FAQPage-JSON-LD (Rich Snippets) pro Sprache."""
    faqs = FAQ_ITEMS.get(_norm_lang(lang), FAQ_ITEMS['de'])
    items = [{'@type': 'Question', 'name': q,
              'acceptedAnswer': {'@type': 'Answer', 'text': a}} for q, a in faqs]
    return {'@context': 'https://schema.org', '@type': 'FAQPage', 'mainEntity': items}


def _seo_context(lang):
    lang = _norm_lang(lang)
    m = SEO_META[lang]
    path = '' if lang == 'de' else '/' + lang
    app_ld = {
        '@context': 'https://schema.org', '@type': 'SoftwareApplication',
        'name': 'Holzbau 3D',
        'alternateName': ['HolzBau 3D', 'Holzbau 3D Planer', 'Holzkonstruktion 3D', 'Holzbau Konstruktion Software'],
        'applicationCategory': 'DesignApplication',
        'applicationSubCategory': 'CAD',
        'operatingSystem': 'Web Browser', 'url': SITE + (path or '/'),
        'inLanguage': lang, 'description': m['desc'], 'keywords': m['keywords'],
        'offers': [
            {'@type': 'Offer', 'price': '0', 'priceCurrency': 'EUR', 'name': 'Free'},
            {'@type': 'Offer', 'price': '9.99', 'priceCurrency': 'EUR', 'name': 'Premium'},
            {'@type': 'Offer', 'price': '99.99', 'priceCurrency': 'EUR', 'name': 'Premium Yearly'},
        ],
    }
    # Top guides for the homepage teaser (internal linking → helps indexing/ranking)
    guides = [{
        'title': (_blog.ARTICLES[s].get(lang) or _blog.ARTICLES[s]['de'])['title'],
        'url': _blog.article_url(s, lang),
        'icon': _blog.ARTICLES[s].get('icon', '📄'),
    } for s in _blog.ordered_slugs()[:6]]
    guides_cta = {'de': 'Alle Ratgeber ansehen', 'en': 'View all guides', 'fr': 'Voir tous les guides'}
    guides_lead = {
        'de': 'Praxis-Anleitungen rund um Holzkonstruktionen – von der Pergola bis zum Dachstuhl.',
        'en': 'Hands-on guides for wood constructions – from pergola to roof truss.',
        'fr': 'Guides pratiques pour les constructions bois – de la pergola à la charpente.',
    }
    return {
        'seo': m, 'seo_lang': lang,
        'guides': guides,
        'guides_url': _blog.GUIDES_PATH[lang],
        'guides_heading': _blog.GUIDES_TITLE[lang].split('–')[0].strip(),
        'guides_lead': guides_lead[lang],
        'guides_cta': guides_cta[lang],
        'canonical': SITE + (path or '/'),
        'alternates': [
            ('de', SITE + '/'), ('en', SITE + '/en'), ('fr', SITE + '/fr'),
            ('x-default', SITE + '/'),
        ],
        'jsonld_app': json.dumps(app_ld, ensure_ascii=False),
        'jsonld_faq': json.dumps(_seo_faq(lang), ensure_ascii=False),
        'faq_items': FAQ_ITEMS.get(lang, FAQ_ITEMS['de']),
        'faq_heading': FAQ_HEADING.get(lang, FAQ_HEADING['de']),
    }


@app.route('/robots.txt')
def robots_txt():
    body = (
        'User-agent: *\n'
        'Allow: /\n'
        'Disallow: /admin/\n'
        'Disallow: /cron/\n'
        f'Sitemap: {SITE}/sitemap.xml\n'
    )
    return app.response_class(body, mimetype='text/plain')


@app.route('/ads.txt')
def ads_txt():
    # Google AdSense Publisher-Autorisierung (Pflicht für Auszahlung, gegen Anzeigenbetrug)
    body = 'google.com, pub-1405082500215735, DIRECT, f08c47fec0942fa0\n'
    return app.response_class(body, mimetype='text/plain')


def _security_txt_body():
    # RFC 9116 — klarer Meldeweg für Sicherheitslücken. Expires dynamisch (+1 Jahr),
    # damit die Datei nie abläuft.
    expires = (datetime.utcnow() + timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%SZ')
    return (
        '# Sicherheitslücken bitte vertraulich an die Kontaktadresse melden.\n'
        'Contact: mailto:info@holzbau3d.app\n'
        f'Expires: {expires}\n'
        'Preferred-Languages: de, en, fr\n'
        f'Canonical: {SITE}/.well-known/security.txt\n'
    )


@app.route('/.well-known/security.txt')
def security_txt():
    return app.response_class(_security_txt_body(), mimetype='text/plain')


@app.route('/security.txt')
def security_txt_legacy():
    # Alt-Pfad, viele Scanner prüfen auch die Wurzel.
    return app.response_class(_security_txt_body(), mimetype='text/plain')


@app.route('/sitemap.xml')
def sitemap():
    def alts():
        return ''.join(
            f'<xhtml:link rel="alternate" hreflang="{h}" href="{u}"/>'
            for h, u in [('de', SITE + '/'), ('en', SITE + '/en'), ('fr', SITE + '/fr'), ('x-default', SITE + '/')]
        )
    home = ''.join(
        f'<url><loc>{u}</loc>{alts()}<changefreq>weekly</changefreq><priority>1.0</priority></url>'
        for u in [SITE + '/', SITE + '/en', SITE + '/fr']
    )
    import blog_content as _b
    # Ratgeber-Index je Sprache
    guide_idx = ''.join(
        f'<url><loc>{SITE}{p}</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>'
        for p in _b.GUIDES_PATH.values()
    )
    # Ratgeber-Artikel je Sprache mit hreflang-Alternates
    guide_arts = ''
    for slug in _b.ordered_slugs():
        a_alts = ''.join(
            f'<xhtml:link rel="alternate" hreflang="{l}" href="{SITE}{_b.article_url(slug, l)}"/>'
            for l in ('de', 'en', 'fr')
        )
        for l in ('de', 'en', 'fr'):
            guide_arts += (f'<url><loc>{SITE}{_b.article_url(slug, l)}</loc>{a_alts}'
                           f'<changefreq>monthly</changefreq><priority>0.7</priority></url>')
    body = f'''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
  {home}
  {guide_idx}
  {guide_arts}
  <url><loc>{SITE}/pricing</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>{SITE}/ueber-uns</loc><changefreq>yearly</changefreq><priority>0.5</priority></url>
  <url><loc>{SITE}/impressum</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
  <url><loc>{SITE}/datenschutz</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
  <url><loc>{SITE}/nutzungsbedingungen</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
  <url><loc>{SITE}/widerruf</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
</urlset>'''
    return app.response_class(body, mimetype='application/xml')


@app.route('/nutzungsbedingungen')
def nutzungsbedingungen():
    return render_template('nutzungsbedingungen.html')


@app.route('/widerruf')
def widerruf():
    # Widerrufsbelehrung + Muster-Formular. Fehlte bisher komplett — ohne
    # Belehrung laeuft die Widerrufsfrist fuer Verbraucher nicht regulaer an.
    return render_template('widerruf.html')


# ---------------------------------------------------------------------------
# Feedback-Tickets
# ---------------------------------------------------------------------------

FEEDBACK_STATUS = ('neu', 'in_arbeit', 'erledigt', 'abgelehnt')
FEEDBACK_STATUS_LABEL = {
    'neu': 'Neu', 'in_arbeit': 'In Arbeit', 'erledigt': 'Erledigt', 'abgelehnt': 'Abgelehnt',
}
# Screenshots kommen als data:-URL aus dem Browser (schon auf 1280px/WebP
# heruntergerechnet). Grosszuegige Obergrenze, damit ein 4K-Monitor nicht
# stumm abgelehnt wird, aber MEDIUMBLOB (16 MB) nicht sprengt.
FEEDBACK_MAX_IMG = 3 * 1024 * 1024

# Liste OHNE den screenshot-BLOB: das Template braucht daraus nur ein Ja/Nein,
# das Bild selbst holt der Browser ueber /feedback/<id>/screenshot nach.
# 'f.*' htte pro Aufruf jedes Bild durch MySQL, PyMySQL und Jinja gezogen.
FB_LIST_SQL = (
    'SELECT f.id, f.user_id, f.kind, f.subject, f.message, f.ctx, f.status, '
    'f.admin_reply, f.created, f.updated, f.screenshot IS NOT NULL AS has_shot, '
    'u.username, u.email FROM feedback f JOIN app_users u ON u.id=f.user_id '
)


@app.route('/feedback', methods=['POST'])
@login_required
def feedback_create():
    if not validate_csrf(request.form.get('csrf_token', '')):
        abort(403)
    if get_user_plan(session['user_id']) != 'premium':
        return jsonify(ok=False, error='Feedback ist eine Premium-Funktion.'), 403

    kind = request.form.get('kind', 'bug')
    if kind not in ('bug', 'idea'):
        kind = 'bug'
    subject = (request.form.get('subject') or '').strip()[:200]
    message = (request.form.get('message') or '').strip()[:5000]
    if not subject or not message:
        return jsonify(ok=False, error='Bitte Betreff und Beschreibung ausfüllen.'), 400

    shot = None
    shot_mime = None
    raw = request.form.get('screenshot') or ''
    if raw.startswith('data:image/'):
        try:
            kopf, b64 = raw.split(',', 1)
            # Erst die Laenge der ROHFORM pruefen, dann dekodieren — sonst liegt
            # das Bild schon entschluesselt im Speicher, bevor wir es ablehnen.
            if len(b64) * 3 // 4 <= FEEDBACK_MAX_IMG:
                # Tatsaechlichen Typ aus dem Kopf lesen: toDataURL('image/webp')
                # faellt in Browsern ohne WebP-Encoder still auf PNG zurueck.
                # Fest 'image/webp' auszuliefern waere dann schlicht gelogen.
                mime = kopf[5:kopf.find(';')] if ';' in kopf else 'image/webp'
                if mime in ('image/webp', 'image/png', 'image/jpeg'):
                    shot = base64.b64decode(b64)
                    shot_mime = mime
        except Exception:
            shot = None
            shot_mime = None

    ctx = (request.form.get('ctx') or '')[:1000]
    execute_db('INSERT INTO feedback (user_id, kind, subject, message, screenshot, shot_mime, ctx, status, created) '
               'VALUES (?,?,?,?,?,?,?,?,?)',
               [session['user_id'], kind, subject, message, shot, shot_mime, ctx, 'neu',
                datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')])

    # Admin benachrichtigen, damit ein Ticket nicht wochenlang liegen bleibt.
    try:
        u = query_db('SELECT username, email FROM app_users WHERE id=?', [session['user_id']], one=True)
        art = 'Fehler' if kind == 'bug' else 'Vorschlag'
        # Alles hier kommt aus einem Formular und landet als HTML in einer Mail —
        # ohne Escapen koennte ein Nutzer beliebiges Markup ins Admin-Postfach
        # schreiben. Die Jinja-Vorlagen escapen automatisch, dieser f-String nicht.
        e_subject = html.escape(subject)
        e_message = html.escape(message[:800]).replace('\n', '<br>')
        e_user = html.escape(str(u['username']) if u else '?')
        e_mail = html.escape(str(u['email']) if u else '?')
        send_email(_admin_email(), f'HolzBau 3D – Neues Feedback ({art}): {subject[:80]}',
                   _email_shell(
                       f'<h2 style="margin:0 0 16px;font-size:1.15rem;">Neues Feedback</h2>'
                       f'<p style="margin:0 0 8px;color:#374151;"><strong>{art}</strong> von '
                       f'{e_user} ({e_mail})</p>'
                       f'<p style="margin:0 0 8px;color:#374151;"><strong>{e_subject}</strong></p>'
                       f'<p style="margin:0 0 16px;color:#374151;">{e_message}</p>'
                       f'<p style="margin:0;"><a href="{SITE}/admin/feedback">Im Ticket-System öffnen</a></p>'))
    except Exception as e:
        logger.error('feedback: Admin-Mail fehlgeschlagen: %s', type(e).__name__)

    return jsonify(ok=True)


@app.route('/feedback/<int:fid>/screenshot')
@login_required
def feedback_screenshot(fid):
    row = query_db('SELECT user_id, screenshot, shot_mime FROM feedback WHERE id=?', [fid], one=True)
    if not row or not row['screenshot']:
        abort(404)
    # Nur der Verfasser selbst oder ein Admin — sonst koennte jeder mit einer
    # geratenen ID fremde Bildschirminhalte abrufen.
    if row['user_id'] != session['user_id'] and session.get('role') != 'admin':
        abort(403)
    return app.response_class(row['screenshot'], mimetype=row['shot_mime'] or 'image/webp')


@app.route('/admin/feedback')
@admin_required
def admin_feedback():
    status = request.args.get('status', '')
    if status and status in FEEDBACK_STATUS:
        rows = query_db(FB_LIST_SQL + 'WHERE f.status=? ORDER BY f.created DESC', [status])
    else:
        # Einfache Anfuehrungszeichen: bei aktivem ANSI_QUOTES-Modus waeren
        # "neu" & Co. Bezeichner statt Zeichenketten und die Abfrage wuerde brechen.
        rows = query_db(FB_LIST_SQL +
            "ORDER BY FIELD(f.status, 'neu', 'in_arbeit', 'erledigt', 'abgelehnt'), f.created DESC", [])
    zaehler = {s: 0 for s in FEEDBACK_STATUS}
    for r in query_db('SELECT status, COUNT(*) c FROM feedback GROUP BY status', []):
        zaehler[r['status']] = r['c']
    return render_template('admin_feedback.html', tickets=rows, zaehler=zaehler,
                           filter_status=status, labels=FEEDBACK_STATUS_LABEL,
                           csrf_token=generate_csrf())


@app.route('/admin/feedback/<int:fid>', methods=['POST'])
@admin_required
def admin_feedback_update(fid):
    if not validate_csrf(request.form.get('csrf_token', '')):
        abort(403)
    row = query_db('SELECT f.id, f.subject, f.status, f.admin_reply, u.email, u.full_name, u.username, u.lang '
                   'FROM feedback f JOIN app_users u ON u.id=f.user_id WHERE f.id=?', [fid], one=True)
    if not row:
        abort(404)
    status = request.form.get('status', row['status'])
    if status not in FEEDBACK_STATUS:
        status = row['status']
    reply = (request.form.get('admin_reply') or '').strip()[:5000]
    reply_neu = reply and reply != (row['admin_reply'] or '')

    execute_db('UPDATE feedback SET status=?, admin_reply=?, updated=? WHERE id=?',
               [status, reply or None, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), fid])

    # Nur bei einer NEUEN Antwort mailen — sonst bekaeme der Nutzer bei jeder
    # Statusaenderung dieselbe Antwort noch einmal zugeschickt.
    if reply_neu and row['email']:
        u_lang = _norm_lang(row['lang'])
        try:
            send_email(row['email'], FEEDBACK_I18N[u_lang]['subject'].replace('{subject}', row['subject']),
                       _email_feedback_html(row['full_name'] or row['username'], row['subject'],
                                            reply, FEEDBACK_STATUS_LABEL.get(status, status), u_lang))
        except Exception as e:
            logger.error('feedback: Antwort-Mail fehlgeschlagen: %s', type(e).__name__)
    flash('Ticket aktualisiert.' + (' Antwort per E-Mail gesendet.' if reply_neu else ''), 'success')
    return redirect(url_for('admin_feedback', status=request.args.get('status', '')))


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.before_request
def _redirect_to_https():
    # Behind the Railway proxy the real scheme is in X-Forwarded-Proto.
    # Redirect plain-http GET/HEAD requests to https (301) for SEO canonicalisation.
    if request.method in ('GET', 'HEAD') and request.headers.get('X-Forwarded-Proto') == 'http':
        target = 'https://' + request.host + request.full_path
        if target.endswith('?'):
            target = target[:-1]
        return redirect(target, code=301)


@app.route('/')
def index():
    return render_template('landing.html', **_seo_context('de'))


@app.route('/en')
@app.route('/en/')
def index_en():
    return render_template('landing.html', **_seo_context('en'))


@app.route('/fr')
@app.route('/fr/')
def index_fr():
    return render_template('landing.html', **_seo_context('fr'))


# ---------------------------------------------------------------------------
# Ratgeber / Blog (SEO-Content, DE/EN/FR)
# ---------------------------------------------------------------------------
import blog_content as _blog


def _blog_index(lang):
    lang = _norm_lang(lang)
    arts = []
    for slug in _blog.ordered_slugs():
        a = _blog.ARTICLES[slug].get(lang) or _blog.ARTICLES[slug]['de']
        arts.append({'slug': slug, 'icon': _blog.ARTICLES[slug]['icon'],
                     'title': a['title'], 'desc': a['desc'], 'url': _blog.article_url(slug, lang)})
    alts = [(l, SITE + _blog.GUIDES_PATH[l]) for l in ('de', 'en', 'fr')]
    alts.append(('x-default', SITE + _blog.GUIDES_PATH['de']))
    return render_template('blog_index.html', seo_lang=lang, articles=arts, ui=_blog.BLOG_UI[lang],
                           page_title=_blog.GUIDES_TITLE[lang], intro=_blog.GUIDES_INTRO[lang],
                           home_url=('/' if lang == 'de' else '/' + lang),
                           guides_alts=[(l, SITE + _blog.GUIDES_PATH[l]) for l in ('de', 'en', 'fr')],
                           canonical=SITE + _blog.GUIDES_PATH[lang], alternates=alts)


def _blog_article(slug, lang):
    lang = _norm_lang(lang)
    if slug not in _blog.ARTICLES:
        abort(404)
    a = _blog.ARTICLES[slug].get(lang) or _blog.ARTICLES[slug]['de']
    alts = [(l, SITE + _blog.article_url(slug, l)) for l in ('de', 'en', 'fr')]
    alts.append(('x-default', SITE + _blog.article_url(slug, 'de')))
    url = SITE + _blog.article_url(slug, lang)
    article_ld = json.dumps({
        '@context': 'https://schema.org', '@type': 'Article',
        'headline': a['title'], 'description': a['desc'], 'inLanguage': lang,
        'datePublished': a['date'], 'dateModified': a['date'],
        'author': {'@type': 'Person', 'name': 'David Bohler', 'url': SITE + '/ueber-uns'},
        'publisher': {'@type': 'Organization', 'name': 'HolzBau 3D',
                      'logo': {'@type': 'ImageObject', 'url': SITE + '/static/og-image.png'}},
        'image': SITE + '/static/og-image.png',
        'mainEntityOfPage': {'@type': 'WebPage', '@id': url},
    }, ensure_ascii=False)
    crumb_ld = json.dumps({
        '@context': 'https://schema.org', '@type': 'BreadcrumbList',
        'itemListElement': [
            {'@type': 'ListItem', 'position': 1, 'name': 'HolzBau 3D', 'item': SITE + ('/' if lang == 'de' else '/' + lang)},
            {'@type': 'ListItem', 'position': 2, 'name': _blog.GUIDES_TITLE[lang].split('–')[0].strip(), 'item': SITE + _blog.GUIDES_PATH[lang]},
            {'@type': 'ListItem', 'position': 3, 'name': a['title'], 'item': url},
        ],
    }, ensure_ascii=False)
    others = [{'slug': s, 'icon': _blog.ARTICLES[s]['icon'],
               'title': (_blog.ARTICLES[s].get(lang) or _blog.ARTICLES[s]['de'])['title'],
               'url': _blog.article_url(s, lang)}
              for s in _blog.ordered_slugs() if s != slug]
    return render_template('blog_article.html', seo_lang=lang, art=a, slug=slug, ui=_blog.BLOG_UI[lang],
                           guides_url=_blog.GUIDES_PATH[lang], guides_title=_blog.GUIDES_TITLE[lang].split('–')[0].strip(),
                           home_url=('/' if lang == 'de' else '/' + lang), others=others,
                           app_url=('/holzbau'), canonical=url, alternates=alts,
                           jsonld_article=article_ld, jsonld_crumb=crumb_ld)


@app.route('/ratgeber')
def blog_index_de():
    return _blog_index('de')


@app.route('/en/guides')
def blog_index_en():
    return _blog_index('en')


@app.route('/fr/guides')
def blog_index_fr():
    return _blog_index('fr')


@app.route('/ratgeber/<slug>')
def blog_article_de(slug):
    return _blog_article(slug, 'de')


@app.route('/en/guides/<slug>')
def blog_article_en(slug):
    return _blog_article(slug, 'en')


@app.route('/fr/guides/<slug>')
def blog_article_fr(slug):
    return _blog_article(slug, 'fr')


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
        user_lang      = _request_lang()

        execute_db(
            "INSERT INTO app_users "
            "(username, password_hash, full_name, email, email_verified, email_verify_token, email_verify_expires, lang) "
            "VALUES (?,?,?,?,0,?,?,?)",
            (username, generate_password_hash(password), full_name, email, verify_token, verify_expires, user_lang)
        )

        base_url   = os.environ.get('BASE_URL', 'https://holzbau3d.app')
        verify_url = f"{base_url}/verify-email/{verify_token}"
        sent = send_email(
            email,
            EMAIL_I18N[user_lang]['v_subject'],
            _email_verify_html(full_name or username, verify_url, user_lang)
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
                u_lang = _norm_lang(user.get('lang') if hasattr(user, 'get') else 'de')
                send_email(
                    email,
                    EMAIL_I18N[u_lang]['v_subject'],
                    _email_verify_html(user['full_name'] or user['username'], verify_url, u_lang)
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
                u_lang = _norm_lang(user.get('lang') if hasattr(user, 'get') else 'de')
                send_email(
                    email,
                    EMAIL_I18N[u_lang]['r_subject'],
                    _email_reset_html(user['full_name'] or user['username'], reset_url, u_lang)
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

    tickets = query_db('SELECT id, kind, subject, message, status, admin_reply, created, updated, '
                       'screenshot IS NOT NULL AS has_shot '
                       'FROM feedback WHERE user_id=? ORDER BY created DESC', [session['user_id']])
    return render_template('profile.html', user=row_to_dict(user), csrf_token=generate_csrf(),
                           tickets=tickets, fb_labels=FEEDBACK_STATUS_LABEL)


@app.route('/profile/delete', methods=['GET', 'POST'])
@login_required
def profile_delete():
    user_id = session['user_id']
    user    = query_db("SELECT * FROM app_users WHERE id = ?", (user_id,), one=True)
    sub     = query_db(
        "SELECT plan, status, current_period_end, stripe_sub_id "
        "FROM subscriptions WHERE user_id=?", [user_id], one=True)
    is_premium = get_user_plan(user_id) == 'premium'
    period_end = None
    if sub and sub.get('current_period_end'):
        period_end = _to_dt(sub['current_period_end'])

    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token', '')):
            flash('Ungültige Anfrage.', 'danger')
            return redirect(url_for('profile_delete'))
        confirm_word = request.form.get('confirm', '').strip().lower()
        if confirm_word != 'löschen':
            flash('Bitte tippe genau "löschen" ein, um zu bestätigen.', 'danger')
            return redirect(url_for('profile_delete'))

        stripe_key = os.environ.get('STRIPE_SECRET_KEY', '')
        if sub and sub.get('stripe_sub_id') and stripe_key:
            try:
                import requests as _r
                resp = _r.delete(
                    f'https://api.stripe.com/v1/subscriptions/{sub["stripe_sub_id"]}',
                    auth=(stripe_key, ''), timeout=10)
                logger.info('Stripe cancel on self-delete user %s: %s', user_id, resp.status_code)
            except Exception as e:
                logger.error('Stripe cancel on self-delete failed user %s: %s', user_id, e)

        _send_delete_email(user_id, sub_info=dict(sub) if sub else None)
        execute_db('DELETE FROM subscriptions WHERE user_id=?', [user_id])
        execute_db('DELETE FROM app_users WHERE id=?', [user_id])
        session.clear()
        flash('Dein Konto wurde dauerhaft gelöscht.', 'success')
        return redirect(url_for('index'))

    return render_template('delete_account.html',
                           user=row_to_dict(user) if user else {},
                           is_premium=is_premium,
                           period_end=period_end,
                           csrf_token=generate_csrf())


@app.route('/profile/set-lang', methods=['POST'])
@login_required
def profile_set_lang():
    if not validate_csrf(request.form.get('csrf_token', '')):
        abort(403)
    lang = _norm_lang(request.form.get('lang', 'de'))
    execute_db("UPDATE app_users SET lang=? WHERE id=?", (lang, session['user_id']))
    flash({'de': 'Sprache gespeichert.', 'en': 'Language saved.', 'fr': 'Langue enregistrée.'}[lang], 'success')
    resp = redirect(url_for('profile'))
    resp.set_cookie('hb_lang', lang, max_age=31536000, samesite='Lax')  # UI sofort mitschalten
    return resp


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
    u_lang = _norm_lang(user.get('lang') if hasattr(user, 'get') else 'de')
    sent = send_email(
        user['email'],
        EMAIL_I18N[u_lang]['r_subject'],
        _email_reset_html(user['full_name'] or user['username'], reset_url, u_lang)
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
    # Stripe = Source of Truth: alle User mit Stripe-Bezug live aktualisieren
    for r in query_db("SELECT user_id FROM subscriptions WHERE stripe_sub_id IS NOT NULL OR stripe_customer_id IS NOT NULL", []):
        _sync_user_from_stripe(r['user_id'])

    users = query_db("""
        SELECT u.id, u.username, u.full_name, u.email, u.created_at, u.last_login,
               COALESCE(u.email_verified, 1) as email_verified,
               COALESCE(s.plan, 'free') as plan, COALESCE(s.status, '') as sub_status,
               s.plan_interval, s.sub_started, s.current_period_end
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
            L.append('  #' + str(u['id']) + '  ' + str(u['username']) + '  (' + str(u['email'] or '-') + ')'
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
        for cs in _stripe_api_get('checkout/sessions', {'limit': 20}).get('data', []):
            meta = cs.get('metadata') or {}
            uid = int(meta.get('user_id', 0) or 0)
            paid = cs.get('payment_status', '')
            L.append('  user_id=' + str(uid) + '  bezahlt=' + paid
                     + '  plan=' + str(meta.get('plan_type'))
                     + '  sub=' + str(cs.get('subscription')))
            if uid and paid == 'paid' and cs.get('mode') == 'subscription':
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
                meta = cs.get('metadata') or {}
                interval = 'yearly' if meta.get('plan_type') == 'yearly' else 'monthly'
                _activate_premium(activate, cs.get('customer'), cs.get('subscription'), interval)
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


@app.route('/admin/test-reminder', methods=['GET'])
@admin_required
def admin_test_reminder():
    """Schickt eine Beispiel-Ablauferinnerung an die angegebene Adresse (Vorschau)."""
    to = request.args.get('to', '').strip()
    stage = request.args.get('stage', '7d')
    lang = _norm_lang(request.args.get('lang', 'de'))
    if not to:
        return ('Tipp: ?to=deine@email.de&stage=7d&lang=de  (stage=7d oder 2d, lang=de/en/fr)', 200)
    sample_date = (datetime.utcnow() + timedelta(days=7 if stage != '2d' else 2)).strftime('%d.%m.%Y')
    ok = send_email(to, EXPIRY_I18N[lang]['subject'].replace('{days}', EXPIRY_I18N[lang]['d2'] if stage == '2d' else EXPIRY_I18N[lang]['d7']),
                    _email_expiry_html('Test', sample_date, stage, lang))
    return ('OK gesendet an ' + to + ' (' + stage + ', ' + lang + ')') if ok else ('Versand fehlgeschlagen', 500)


# ---------------------------------------------------------------------------
# HolzBau 3D App
# ---------------------------------------------------------------------------

@app.route('/holzbau')
@login_required
def holzbau():
    plan = get_user_plan(session['user_id'])
    # csrf_token: der Editor postet Feedback per fetch — ohne Token wuerde
    # validate_csrf() jede Meldung mit 403 abweisen.
    return render_template('holzbau.html', show_ads=(plan == 'free'), user_plan=plan,
                           csrf_token=generate_csrf())


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------

@app.route('/landing')
def landing():
    return redirect(url_for('index'), 301)


@app.route('/impressum')
def impressum():
    return render_template('impressum.html')


@app.route('/ueber-uns')
def ueber_uns():
    return render_template('ueber_uns.html')


@app.route('/datenschutz')
def datenschutz():
    return render_template('datenschutz.html')


@app.route('/pricing')
def pricing_public():
    return render_template('pricing_public.html')


# ---------------------------------------------------------------------------
# Subscription
# ---------------------------------------------------------------------------

def _to_dt(v):
    """Robust: DB-DATETIME (datetime ODER ISO-String) -> datetime, sonst None."""
    if not v:
        return None
    if isinstance(v, datetime):
        return v
    try:
        return datetime.fromisoformat(str(v).replace('Z', '').replace('T', ' ').strip())
    except Exception:
        return None


def get_user_plan(user_id):
    row = query_db('SELECT plan, status, current_period_end FROM subscriptions WHERE user_id=?', [user_id], one=True)
    if not row or row['plan'] != 'premium':
        return 'free'
    status = row['status']
    # 'active'  = laufend / verlängert sich -> Zugang
    # 'cancelled' = gekündigt, Zugang NUR bis zum bezahlten Periodenende
    # 'expired'/sonst = kein Zugang
    if status == 'active':
        return 'premium'
    if status == 'cancelled':
        pe = _to_dt(row['current_period_end'])
        if pe is None or pe > datetime.utcnow():
            return 'premium'   # noch innerhalb der bezahlten Laufzeit
        return 'free'          # Laufzeit abgelaufen -> gesperrt
    return 'free'


def _sync_user_from_stripe(user_id):
    """Stripe ist Source of Truth: holt Plan + Laufzeit live von Stripe und
    schreibt sie in die DB (Cache). Manuell gesetzte Pläne ohne Stripe-Bezug
    (z.B. admin) bleiben unangetastet. Gibt die aktualisierte DB-Zeile zurück."""
    sub = query_db('SELECT * FROM subscriptions WHERE user_id=?', [user_id], one=True)
    if not sub:
        return None
    sub_id = sub['stripe_sub_id']
    customer_id = sub['stripe_customer_id']
    if not os.environ.get('STRIPE_SECRET_KEY') or (not sub_id and not customer_id):
        return sub  # kein Stripe-Bezug -> nichts zu syncen (manueller Plan bleibt)
    try:
        s = None
        if sub_id:
            s = _stripe_api_get('subscriptions/' + sub_id)
        elif customer_id:
            lst = _stripe_api_get('subscriptions', {'customer': customer_id, 'status': 'all', 'limit': 1})
            data = lst.get('data') or []
            s = data[0] if data else None
        if not s or s.get('error'):
            return sub
        status = s.get('status')
        cancel_at_end = bool(s.get('cancel_at_period_end'))
        items = (s.get('items') or {}).get('data') or [{}]
        price = items[0].get('price') or {}
        rec = price.get('recurring') or {}
        interval = 'yearly' if rec.get('interval') == 'year' else 'monthly'
        cpe = s.get('current_period_end') or items[0].get('current_period_end')
        period_end = datetime.utcfromtimestamp(cpe).strftime('%Y-%m-%d %H:%M:%S') if cpe else None
        sd = s.get('start_date') or s.get('created')
        started = datetime.utcfromtimestamp(sd).strftime('%Y-%m-%d %H:%M:%S') if sd else None
        if status in ('active', 'trialing', 'past_due'):
            plan = 'premium'
            db_status = 'cancelled' if cancel_at_end else 'active'
        else:  # canceled, unpaid, incomplete_expired, paused, incomplete
            plan = 'free'
            db_status = 'expired'
        # Reminder-Zähler zurücksetzen, sobald NICHT (mehr) gekündigt
        reset_reminder = '' if db_status != 'cancelled' else None
        execute_db('UPDATE subscriptions SET plan=?, status=?, plan_interval=?, '
                   'current_period_end=?, sub_started=COALESCE(sub_started, ?), '
                   'stripe_sub_id=COALESCE(stripe_sub_id, ?), '
                   'reminder_stage=COALESCE(?, reminder_stage) WHERE user_id=?',
                   [plan, db_status, interval, period_end, started, s.get('id'), reset_reminder, user_id])
        return query_db('SELECT * FROM subscriptions WHERE user_id=?', [user_id], one=True)
    except Exception as e:
        logger.error('sync_user_from_stripe(%s) failed: %s', user_id, type(e).__name__)
        return sub


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
            if cs_id:
                sessions = [_stripe_api_get('checkout/sessions/' + cs_id)]
            else:
                sessions = _stripe_api_get('checkout/sessions', {'limit': 100}).get('data', [])
            for cs in sessions:
                meta = cs.get('metadata') or {}
                if (int(meta.get('user_id', 0) or 0) == user_id
                        and cs.get('payment_status') == 'paid'
                        and cs.get('mode') == 'subscription'):
                    interval = 'yearly' if meta.get('plan_type') == 'yearly' else 'monthly'
                    _activate_premium(user_id, cs.get('customer'), cs.get('subscription'), interval)
                    flash('Dein Premium-Abo wurde aktiviert. Eine Bestätigung mit Rechnung ist unterwegs per E-Mail. ✨', 'success')
                    break
        except Exception as e:
            logger.error('Checkout success fallback failed: %s', type(e).__name__)

    # Stripe = Source of Truth: aktuellen Abo-Stand live holen
    _sync_user_from_stripe(user_id)

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
    sub_row = query_db('SELECT stripe_sub_id FROM subscriptions WHERE user_id=?', [user_id], one=True)
    if not sub_row or not sub_row['stripe_sub_id']:
        flash('Kein aktives Abo gefunden.', 'warning')
        return redirect(url_for('subscribe'))
    try:
        import requests as _req
        r = _req.post(
            f'https://api.stripe.com/v1/subscriptions/{sub_row["stripe_sub_id"]}',
            data={'cancel_at_period_end': 'true'},
            auth=(stripe_key, ''), timeout=10)
        r.raise_for_status()
    except Exception as e:
        logger.error('Stripe cancel_at_period_end failed for user %s: %s', user_id, e)
        flash(f'Fehler bei Stripe: {str(e)}', 'danger')
        return redirect(url_for('subscribe'))
    _sync_user_from_stripe(user_id)
    _send_cancel_email(user_id)
    flash('Abo wird zum Ende der Laufzeit gekündigt. Du behältst Premium bis dahin. Eine Bestätigung kommt per E-Mail.', 'success')
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


@app.route('/cron/subscription-reminders', methods=['GET', 'POST'])
def cron_subscription_reminders():
    """Täglich von einem Cron aufzurufen. Schützt per CRON_SECRET.
    1) synct alle Stripe-Abos (sperrt abgelaufene automatisch),
    2) sendet 7-Tage- und 2-Tage-Ablauf-Erinnerungen (gekündigte Abos),
    3) erinnert eine Woche vor der nächsten Abbuchung (aktive Abos)."""
    secret = os.environ.get('CRON_SECRET', '')
    given = request.args.get('key') or request.headers.get('X-Cron-Key', '')
    if not secret or given != secret:
        abort(403)
    # 1) Stripe = Source of Truth: alle mit Stripe-Bezug aktualisieren
    synced = 0
    for r in query_db("SELECT user_id FROM subscriptions WHERE stripe_sub_id IS NOT NULL OR stripe_customer_id IS NOT NULL", []):
        _sync_user_from_stripe(r['user_id'])
        synced += 1
    # 2) Erinnerungen verschicken
    log = _run_subscription_reminders()
    # 3) Verlängerungs-Erinnerungen (aktive Abos, ~7 Tage vor Abbuchung)
    renewals = _run_renewal_notices()
    return jsonify(ok=True, synced=synced, reminders=log, renewals=renewals)


@app.route('/cron/premium-upsell', methods=['GET', 'POST'])
def cron_premium_upsell():
    """Weekly upsell email to all non-premium users (trigger e.g. every Sunday ~18:00).
    Secured via CRON_SECRET (?key= or X-Cron-Key header). Throttled to once per 5 days
    per user, so an accidental double-trigger on the same day won't double-send."""
    secret = os.environ.get('CRON_SECRET', '')
    given = request.args.get('key') or request.headers.get('X-Cron-Key', '')
    if not secret or given != secret:
        abort(403)
    base_url = os.environ.get('BASE_URL', 'https://holzbau3d.app').rstrip('/')
    subscribe_url = base_url + '/subscribe'
    rows = query_db(
        """SELECT u.id, u.email, u.full_name, u.username, u.unsub_token
             FROM app_users u
             LEFT JOIN subscriptions s ON s.user_id = u.id
            WHERE u.email IS NOT NULL AND u.email <> ''
              AND u.email_verified = 1
              AND u.marketing_opt_out = 0
              AND NOT (
                    COALESCE(s.plan, '') = 'premium' AND (
                      s.status = 'active'
                      OR (s.status = 'cancelled' AND (s.current_period_end IS NULL OR s.current_period_end > NOW()))
                    )
                  )
              AND (u.last_upsell_sent IS NULL OR u.last_upsell_sent < DATE_SUB(NOW(), INTERVAL 5 DAY))""",
        [])
    sent = 0
    failed = 0
    for r in rows:
        try:
            token = r.get('unsub_token')
            if not token:
                token = secrets.token_urlsafe(32)
                execute_db('UPDATE app_users SET unsub_token=? WHERE id=?', [token, r['id']])
            unsub_url = base_url + '/abmelden?token=' + token
            name = r.get('full_name') or r.get('username') or ''
            body = _email_upsell_html(name, subscribe_url, unsub_url)
            if send_email(r['email'], 'Hol mehr aus deinen Holzprojekten – HolzBau 3D Premium', body):
                execute_db('UPDATE app_users SET last_upsell_sent=NOW() WHERE id=?', [r['id']])
                sent += 1
            else:
                failed += 1
        except Exception as e:
            failed += 1
            logger.error('premium-upsell send failed for user %s: %s', r.get('id'), type(e).__name__)
    logger.info('premium-upsell: %s sent, %s failed, %s candidates', sent, failed, len(rows))
    return jsonify(ok=True, candidates=len(rows), sent=sent, failed=failed)


@app.route('/abmelden')
def unsubscribe_marketing():
    """One-click unsubscribe from marketing emails (DSGVO)."""
    token = (request.args.get('token') or '').strip()
    done = False
    if token:
        u = query_db('SELECT id FROM app_users WHERE unsub_token=?', [token], one=True)
        if u:
            execute_db('UPDATE app_users SET marketing_opt_out=1 WHERE id=?', [u['id']])
            done = True
    msg = ('Du wurdest erfolgreich abgemeldet und erhältst keine Angebots-E-Mails mehr.'
           if done else
           'Abmeldelink ungültig oder abgelaufen. Bitte kontaktiere uns über das Impressum.')
    page = f'''<!DOCTYPE html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Abmeldung – HolzBau 3D</title>
<style>body{{font-family:'Segoe UI',Arial,sans-serif;background:#faf6f0;color:#3a2a1a;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center;padding:20px}}
.card{{background:#fff;border:1px solid #e3d6c4;border-radius:14px;padding:36px 40px;max-width:460px;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,.08)}}
h1{{font-size:20px;margin:0 0 12px}}p{{color:#5a4a38;line-height:1.6;margin:0 0 20px}}
a{{display:inline-block;background:#9a5b2c;color:#fff;text-decoration:none;padding:11px 24px;border-radius:8px;font-weight:600}}</style>
</head><body><div class="card"><h1>HolzBau 3D</h1><p>{html.escape(msg)}</p><a href="https://holzbau3d.app/">Zur Startseite</a></div></body></html>'''
    return page, (200 if done else 404)


def _email_premium_html(display_name, amount_txt, interval, invoice_url, lang='de', next_billing=None):
    T = EMAIL_I18N.get(_norm_lang(lang), EMAIL_I18N['de'])
    interval_txt = T['p_plan_y'] if interval == 'yearly' else T['p_plan_m']
    invoice_block = ''
    if invoice_url:
        invoice_block = (
            '<table cellpadding="0" cellspacing="0" style="margin:0 0 24px;"><tr><td style="background:linear-gradient(135deg,#d97706,#92400e);border-radius:10px;">'
            f'<a href="{invoice_url}" style="display:inline-block;padding:13px 30px;color:#ffffff;text-decoration:none;font-weight:700;font-size:.95rem;">{T["p_invoice"]}</a>'
            '</td></tr></table>'
        )
    amount_display = amount_txt + (T['per_year'] if interval == 'yearly' else T['per_month'])
    thanks = T['p_thanks'].replace('{plan}', interval_txt).replace('{amount}', amount_display)
    # Vertragskasten: Was genau wurde abgeschlossen, was kostet es, wann wird das
    # naechste Mal abgebucht. Vorher stand in der Mail weder die automatische
    # Verlaengerung noch ein Datum — der Kaeufer hatte es nirgends schriftlich.
    zeile = ('<tr><td style="padding:3px 0;color:#6b7280;">{k}</td>'
             '<td style="padding:3px 0;color:#1a1a1a;font-weight:700;text-align:right;">{v}</td></tr>')
    next_txt = next_billing or T['p_box_next_none']
    box = (
        '<table cellpadding="0" cellspacing="0" style="width:100%;background:#fff;border:1px solid #e5e7eb;'
        'border-radius:10px;margin:0 0 20px;"><tr><td style="padding:16px 20px;">'
        f'<div style="font-size:.78rem;font-weight:700;color:#92400e;text-transform:uppercase;'
        f'letter-spacing:.5px;margin-bottom:8px;">{T["p_box_title"]}</div>'
        '<table cellpadding="0" cellspacing="0" style="width:100%;font-size:.9rem;">'
        + zeile.format(k=T['p_box_plan'], v=interval_txt)
        + zeile.format(k=T['p_box_amount'], v=amount_display)
        + zeile.format(k=T['p_box_next'], v=next_txt)
        + '</table></td></tr></table>'
    )
    return _email_shell(f'''    <h2 style="margin:0 0 16px;font-size:1.15rem;color:#1a1a1a;font-weight:700;">{T['p_title']}</h2>
    <p style="margin:0 0 10px;color:#374151;line-height:1.65;font-size:.95rem;">{T['hello']} <strong>{display_name}</strong>,</p>
    <p style="margin:0 0 20px;color:#374151;line-height:1.65;font-size:.95rem;">{thanks}</p>
    {box}
    <table cellpadding="0" cellspacing="0" style="width:100%;background:#fffbeb;border:1px solid #fcd34d;border-radius:10px;margin:0 0 20px;"><tr><td style="padding:14px 20px;font-size:.9rem;color:#374151;line-height:1.6;">
      {T['p_renew']}
    </td></tr></table>
    <table cellpadding="0" cellspacing="0" style="width:100%;background:#fef9f0;border:1px solid #fde68a;border-radius:10px;margin:0 0 24px;"><tr><td style="padding:16px 20px;font-size:.88rem;color:#374151;line-height:2;">
      {T['p_features']}
    </td></tr></table>
    {invoice_block}
    <p style="margin:0 0 10px;color:#6b7280;font-size:.85rem;line-height:1.6;">{T['p_cancel_hint']}</p>
    <p style="margin:0;color:#9ca3af;font-size:.8rem;line-height:1.6;">{T['p_manage']}</p>''')


def _email_upsell_html(display_name, subscribe_url, unsub_url):
    """Weekly Premium-upsell email for non-premium users (approved 'Warmes Handwerk' design)."""
    name = html.escape(display_name or '').strip() or 'Holzbauer'
    return f'''<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f0e9df;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#f0e9df;font-size:1px;line-height:1px;">Mehr aus deinen Holzprojekten: werbefrei, PDF-Export, Säge-Tool &amp; unbegrenzte Projekte – 2 Monate gratis im Jahresabo.</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f0e9df;padding:24px 12px;"><tr><td align="center">
    <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:600px;background:#fbf7f1;border:1px solid #e3d6c4;border-radius:14px;overflow:hidden;font-family:Georgia,'Times New Roman',serif;">
      <tr><td style="height:5px;background:#9a5b2c;font-size:0;line-height:0;">&nbsp;</td></tr>
      <tr><td style="padding:26px 40px 8px;">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr>
          <td style="width:30px;vertical-align:middle;"><div style="width:26px;height:26px;background:#9a5b2c;border-radius:6px;"></div></td>
          <td style="padding-left:10px;vertical-align:middle;font-family:Georgia,serif;font-size:20px;font-weight:bold;color:#3a2a1a;">HolzBau&nbsp;3D</td>
        </tr></table>
      </td></tr>
      <tr><td style="padding:14px 40px 4px;">
        <h1 style="margin:0;font-family:Georgia,serif;font-weight:normal;font-size:30px;line-height:1.2;color:#2a1c0e;">Hallo {name}, hol das Maximum<br>aus deinen Holzprojekten.</h1>
      </td></tr>
      <tr><td style="padding:14px 40px 6px;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.65;color:#5a4a38;">
        Du planst deine Konstruktionen schon kostenlos in 3D – stark! Mit <strong style="color:#9a5b2c;">HolzBau&nbsp;3D&nbsp;Premium</strong> arbeitest du schneller, sauberer und ganz ohne Werbung. Alles freigeschaltet, für ein faires Abo.
      </td></tr>
      <tr><td style="padding:12px 40px 6px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-family:Arial,Helvetica,sans-serif;font-size:15px;color:#3a2a1a;">
          <tr><td style="padding:7px 0;line-height:1.5;"><span style="color:#3d7a3d;font-weight:bold;">✓</span>&nbsp;&nbsp;<strong>Unbegrenzte Projekte &amp; Balken</strong> – keine Limits mehr</td></tr>
          <tr><td style="padding:7px 0;line-height:1.5;"><span style="color:#3d7a3d;font-weight:bold;">✓</span>&nbsp;&nbsp;<strong>Vollständig werbefrei</strong> – volle Konzentration aufs Konstruieren</td></tr>
          <tr><td style="padding:7px 0;line-height:1.5;"><span style="color:#3d7a3d;font-weight:bold;">✓</span>&nbsp;&nbsp;<strong>PDF-Export &amp; Druckpläne</strong> – direkt für Bauantrag oder Werkstatt</td></tr>
          <tr><td style="padding:7px 0;line-height:1.5;"><span style="color:#3d7a3d;font-weight:bold;">✓</span>&nbsp;&nbsp;<strong>Säge-Tool &amp; Schnittplan-Optimierung</strong> – weniger Verschnitt, weniger Kosten</td></tr>
          <tr><td style="padding:7px 0;line-height:1.5;"><span style="color:#3d7a3d;font-weight:bold;">✓</span>&nbsp;&nbsp;<strong>Gruppen &amp; Ebenen</strong> – Überblick auch bei großen Projekten</td></tr>
          <tr><td style="padding:7px 0;line-height:1.5;"><span style="color:#3d7a3d;font-weight:bold;">✓</span>&nbsp;&nbsp;<strong>Prioritäts-Support</strong> – wir helfen zuerst dir</td></tr>
        </table>
      </td></tr>
      <tr><td style="padding:18px 40px 6px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3ebdf;border:1px solid #e3d6c4;border-radius:10px;"><tr>
          <td align="center" style="padding:18px 20px;font-family:Arial,Helvetica,sans-serif;">
            <div style="font-size:14px;color:#5a4a38;">Schon ab</div>
            <div style="font-family:Georgia,serif;font-size:34px;color:#2a1c0e;padding:2px 0;"><strong>9,99&nbsp;€</strong><span style="font-size:15px;color:#5a4a38;">/Monat</span></div>
            <div style="font-size:14px;color:#9a5b2c;font-weight:bold;">oder 99,99&nbsp;€/Jahr&nbsp;— 2 Monate&nbsp;gratis&nbsp;🎉</div>
          </td>
        </tr></table>
      </td></tr>
      <tr><td align="center" style="padding:22px 40px 8px;">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr>
          <td align="center" style="background:#9a5b2c;border-radius:8px;">
            <a href="{subscribe_url}" target="_blank" style="display:inline-block;padding:15px 38px;font-family:Arial,Helvetica,sans-serif;font-size:16px;font-weight:bold;color:#ffffff;text-decoration:none;border-radius:8px;">Jetzt Premium freischalten →</a>
          </td>
        </tr></table>
      </td></tr>
      <tr><td align="center" style="padding:4px 40px 26px;font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#8a7a68;">Jederzeit kündbar · keine Mindestlaufzeit</td></tr>
      <tr><td style="padding:0 40px;"><div style="border-top:1px solid #e8ddce;font-size:0;line-height:0;">&nbsp;</div></td></tr>
      <tr><td style="padding:18px 40px 28px;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:1.6;color:#9a8b78;">
        Du erhältst diese E-Mail, weil du ein kostenloses HolzBau&nbsp;3D-Konto hast.<br>
        <a href="{unsub_url}" style="color:#9a5b2c;">Keine Angebote mehr erhalten (abmelden)</a>
        &nbsp;·&nbsp;<a href="https://holzbau3d.app/impressum" style="color:#9a5b2c;">Impressum</a>
        &nbsp;·&nbsp;<a href="https://holzbau3d.app/datenschutz" style="color:#9a5b2c;">Datenschutz</a>
        <br><br>© 2026 HolzBau 3D
      </td></tr>
    </table>
  </td></tr></table>
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
    started = None
    invoice_url = None
    amount_txt = '99,99 €' if interval == 'yearly' else '9,99 €'
    try:
        if sub_id:
            s = _stripe_api_get('subscriptions/' + sub_id)
            sd = s.get('start_date') or s.get('created')
            if sd:
                started = datetime.utcfromtimestamp(sd).strftime('%Y-%m-%d %H:%M:%S')
            cpe = s.get('current_period_end')
            if not cpe:
                # Neuere Stripe-API-Versionen: Laufzeit liegt am Subscription-Item
                items = (s.get('items') or {}).get('data') or []
                if items:
                    cpe = items[0].get('current_period_end')
            if cpe:
                period_end = datetime.utcfromtimestamp(cpe).strftime('%Y-%m-%d %H:%M:%S')
            li = s.get('latest_invoice')
            if li:
                inv = _stripe_api_get('invoices/' + li)
                invoice_url = inv.get('hosted_invoice_url')
                amt = inv.get('amount_paid')
                cur = (inv.get('currency') or '').upper()
                if amt:
                    amount_txt = ('%.2f' % (amt / 100)).replace('.', ',') + ' ' + cur
    except Exception as e:
        logger.error('activate_premium: Stripe lookup failed: %s', type(e).__name__)

    if existing:
        execute_db('UPDATE subscriptions SET stripe_customer_id=?, stripe_sub_id=?, plan=?, status=?, plan_interval=?, '
                   "current_period_end=COALESCE(?, current_period_end), sub_started=COALESCE(?, sub_started), reminder_stage='' WHERE user_id=?",
                   [customer_id, sub_id, 'premium', 'active', interval, period_end, started, user_id])
    else:
        execute_db('INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_sub_id, plan, status, plan_interval, current_period_end, sub_started) '
                   'VALUES (?,?,?,?,?,?,?,?)',
                   [user_id, customer_id, sub_id, 'premium', 'active', interval, period_end, started])

    if notify and not already:
        u = query_db('SELECT email, full_name, username, lang FROM app_users WHERE id=?', [user_id], one=True)
        if u and u['email']:
            u_lang = _norm_lang(u.get('lang') if hasattr(u, 'get') else 'de')
            # period_end kommt von Stripe im DB-Format — fuer die Mail lesbar machen.
            pe_dt = _to_dt(period_end)
            next_txt = pe_dt.strftime('%d.%m.%Y') if pe_dt else None
            send_email(u['email'], EMAIL_I18N[u_lang]['p_subject'],
                       _email_premium_html(u['full_name'] or u['username'], amount_txt, interval,
                                           invoice_url, u_lang, next_txt))
    return True


# Antwort auf ein Feedback-Ticket.
FEEDBACK_I18N = {
    'de': {
        'subject': 'HolzBau 3D – Antwort auf dein Feedback: {subject}',
        'title': 'Antwort auf dein Feedback',
        'intro': 'du hast uns Feedback geschickt — hier ist unsere Antwort.',
        'your': 'Dein Feedback', 'answer': 'Unsere Antwort', 'status': 'Status',
        'button': 'Meine Tickets ansehen',
        'thanks': 'Danke, dass du dir die Zeit genommen hast. Solche Hinweise machen HolzBau 3D besser.',
    },
    'en': {
        'subject': 'HolzBau 3D – Reply to your feedback: {subject}',
        'title': 'Reply to your feedback',
        'intro': 'you sent us feedback — here is our reply.',
        'your': 'Your feedback', 'answer': 'Our reply', 'status': 'Status',
        'button': 'View my tickets',
        'thanks': 'Thank you for taking the time. Reports like yours make HolzBau 3D better.',
    },
    'fr': {
        'subject': 'HolzBau 3D – Réponse à votre retour : {subject}',
        'title': 'Réponse à votre retour',
        'intro': 'vous nous avez envoyé un retour — voici notre réponse.',
        'your': 'Votre retour', 'answer': 'Notre réponse', 'status': 'Statut',
        'button': 'Voir mes tickets',
        'thanks': 'Merci d’avoir pris le temps. Ces retours améliorent HolzBau 3D.',
    },
}


def _email_feedback_html(display_name, subject, reply, status_txt, lang='de'):
    T = FEEDBACK_I18N.get(_norm_lang(lang), FEEDBACK_I18N['de'])
    L = EMAIL_I18N.get(_norm_lang(lang), EMAIL_I18N['de'])
    base_url = os.environ.get('BASE_URL', 'https://holzbau3d.app')
    # Nutzertexte escapen — sie kommen aus einem Formular und landen hier in HTML.
    name_e = html.escape(display_name or '')
    subject_e = html.escape(subject or '')
    reply_e = html.escape(reply or '').replace('\n', '<br>')
    return _email_shell(f'''    <h2 style="margin:0 0 16px;font-size:1.15rem;color:#1a1a1a;font-weight:700;">{T['title']}</h2>
    <p style="margin:0 0 10px;color:#374151;line-height:1.65;font-size:.95rem;">{L['hello']} <strong>{name_e}</strong>,</p>
    <p style="margin:0 0 20px;color:#374151;line-height:1.65;font-size:.95rem;">{T['intro']}</p>
    <table cellpadding="0" cellspacing="0" style="width:100%;background:#fff;border:1px solid #e5e7eb;border-radius:10px;margin:0 0 16px;"><tr><td style="padding:14px 18px;">
      <div style="font-size:.75rem;font-weight:700;color:#9ca3af;text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px;">{T['your']}</div>
      <div style="color:#374151;font-size:.92rem;">{subject_e}</div>
    </td></tr></table>
    <table cellpadding="0" cellspacing="0" style="width:100%;background:#fffbeb;border:1px solid #fcd34d;border-radius:10px;margin:0 0 16px;"><tr><td style="padding:14px 18px;">
      <div style="font-size:.75rem;font-weight:700;color:#92400e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px;">{T['answer']}</div>
      <div style="color:#374151;font-size:.92rem;line-height:1.6;">{reply_e}</div>
      <div style="margin-top:10px;font-size:.8rem;color:#9ca3af;">{T['status']}: <strong style="color:#92400e;">{status_txt}</strong></div>
    </td></tr></table>
    <table cellpadding="0" cellspacing="0" style="margin:0 0 16px;"><tr><td style="background:linear-gradient(135deg,#d97706,#92400e);border-radius:10px;">
      <a href="{base_url}/profile#feedback" style="display:inline-block;padding:13px 30px;color:#ffffff;text-decoration:none;font-weight:700;font-size:.95rem;">{T['button']}</a>
    </td></tr></table>
    <p style="margin:0;color:#9ca3af;font-size:.8rem;line-height:1.6;">{T['thanks']}</p>''')


# Erinnerung eine Woche VOR der naechsten Abbuchung eines AKTIVEN Abos.
# Bewusst nuechtern und ohne Verkaufsdruck: der Zweck ist, dass niemand von einer
# Abbuchung ueberrascht wird. Datum und Betrag stehen drin, der Kuendigungsweg auch.
RENEWAL_I18N = {
    'de': {
        'subject': 'HolzBau 3D – Dein Abo verlängert sich am {date} ({amount})',
        'title': 'Erinnerung: dein Abo verlängert sich',
        'body': 'nur damit du Bescheid weißt: dein <strong>{plan}</strong> ist aktiv und verlängert sich '
                'automatisch am <strong>{date}</strong>. Dann werden <strong>{amount}</strong> über Stripe abgebucht.',
        'nothing': 'Du musst nichts tun — wenn du Premium weiter nutzen willst, läuft alles von selbst weiter.',
        'cancel': 'Möchtest du nicht verlängern? Dann kündige einfach vorher unter „Mein Abonnement“. '
                  'Du behältst Premium bis zum {date} und es wird nichts mehr abgebucht.',
        'button': 'Abo ansehen oder kündigen',
    },
    'en': {
        'subject': 'HolzBau 3D – Your subscription renews on {date} ({amount})',
        'title': 'Reminder: your subscription renews',
        'body': 'just so you know: your <strong>{plan}</strong> is active and will renew automatically on '
                '<strong>{date}</strong>. <strong>{amount}</strong> will then be charged via Stripe.',
        'nothing': 'You do not need to do anything — if you want to keep Premium, it simply continues.',
        'cancel': 'Do not want to renew? Just cancel beforehand under “My subscription”. '
                  'You keep Premium until {date} and nothing further will be charged.',
        'button': 'View or cancel subscription',
    },
    'fr': {
        'subject': 'HolzBau 3D – Votre abonnement se renouvelle le {date} ({amount})',
        'title': 'Rappel : votre abonnement se renouvelle',
        'body': 'pour information : votre <strong>{plan}</strong> est actif et se renouvellera automatiquement le '
                '<strong>{date}</strong>. <strong>{amount}</strong> seront alors prélevés via Stripe.',
        'nothing': 'Vous n’avez rien à faire — si vous souhaitez conserver Premium, tout continue automatiquement.',
        'cancel': 'Vous ne souhaitez pas renouveler ? Résiliez simplement avant, sous « Mon abonnement ». '
                  'Vous conservez Premium jusqu’au {date} et plus rien ne sera prélevé.',
        'button': 'Voir ou résilier l’abonnement',
    },
}

EXPIRY_I18N = {
    'de': {
        'subject': 'HolzBau 3D – Dein Premium-Zugang endet in {days}',
        'd7': '7 Tagen', 'd2': '2 Tagen',
        'title': 'Dein Premium-Zugang endet bald',
        'body': 'dein gekündigtes Premium-Abo läuft am <strong>{date}</strong> aus — also in {days}. Danach hast du keinen Zugang mehr zu den Premium-Funktionen (unbegrenzte Balken, PDF-Export, Säge-Tool, werbefrei).',
        'button': 'Premium fortsetzen',
        'note': 'Möchtest du Premium behalten? Du kannst es jederzeit mit einem Klick reaktivieren — bereits erstellte Projekte bleiben dir natürlich erhalten.',
    },
    'en': {
        'subject': 'HolzBau 3D – Your Premium access ends in {days}',
        'd7': '7 days', 'd2': '2 days',
        'title': 'Your Premium access is ending soon',
        'body': 'your cancelled Premium subscription ends on <strong>{date}</strong> — in {days}. After that you will lose access to the Premium features (unlimited beams, PDF export, saw tool, ad-free).',
        'button': 'Keep Premium',
        'note': 'Want to keep Premium? You can reactivate it any time with a single click — your existing projects are of course preserved.',
    },
    'fr': {
        'subject': 'HolzBau 3D – Votre accès Premium se termine dans {days}',
        'd7': '7 jours', 'd2': '2 jours',
        'title': 'Votre accès Premium se termine bientôt',
        'body': 'votre abonnement Premium résilié se termine le <strong>{date}</strong> — dans {days}. Vous perdrez alors l’accès aux fonctionnalités Premium (poutres illimitées, export PDF, outil scie, sans publicité).',
        'button': 'Conserver Premium',
        'note': 'Vous souhaitez conserver Premium ? Vous pouvez le réactiver à tout moment en un clic — vos projets existants sont bien sûr conservés.',
    },
}


def _email_renewal_html(display_name, date_txt, amount_txt, interval, lang='de'):
    T = RENEWAL_I18N.get(_norm_lang(lang), RENEWAL_I18N['de'])
    L = EMAIL_I18N.get(_norm_lang(lang), EMAIL_I18N['de'])
    plan_txt = L['p_plan_y'] if interval == 'yearly' else L['p_plan_m']
    base_url = os.environ.get('BASE_URL', 'https://holzbau3d.app')
    body = T['body'].replace('{date}', date_txt).replace('{amount}', amount_txt).replace('{plan}', plan_txt)
    cancel = T['cancel'].replace('{date}', date_txt)
    return _email_shell(f'''    <h2 style="margin:0 0 16px;font-size:1.15rem;color:#1a1a1a;font-weight:700;">{T['title']}</h2>
    <p style="margin:0 0 10px;color:#374151;line-height:1.65;font-size:.95rem;">{L['hello']} <strong>{display_name}</strong>,</p>
    <p style="margin:0 0 16px;color:#374151;line-height:1.65;font-size:.95rem;">{body}</p>
    <p style="margin:0 0 16px;color:#374151;line-height:1.65;font-size:.95rem;">{T['nothing']}</p>
    <p style="margin:0 0 24px;color:#374151;line-height:1.65;font-size:.95rem;">{cancel}</p>
    <table cellpadding="0" cellspacing="0" style="margin:0 0 8px;"><tr><td style="background:linear-gradient(135deg,#d97706,#92400e);border-radius:10px;">
      <a href="{base_url}/subscribe" style="display:inline-block;padding:13px 30px;color:#ffffff;text-decoration:none;font-weight:700;font-size:.95rem;">{T['button']}</a>
    </td></tr></table>''')


def _email_expiry_html(display_name, end_date, stage, lang='de'):
    T = EXPIRY_I18N.get(_norm_lang(lang), EXPIRY_I18N['de'])
    L = EMAIL_I18N.get(_norm_lang(lang), EMAIL_I18N['de'])
    days = T['d2'] if stage == '2d' else T['d7']
    base_url = os.environ.get('BASE_URL', 'https://holzbau3d.app')
    body = T['body'].replace('{date}', end_date).replace('{days}', days)
    return _email_shell(f'''    <h2 style="margin:0 0 16px;font-size:1.15rem;color:#1a1a1a;font-weight:700;">{T['title']}</h2>
    <p style="margin:0 0 10px;color:#374151;line-height:1.65;font-size:.95rem;">{L['hello']} <strong>{display_name}</strong>,</p>
    <p style="margin:0 0 24px;color:#374151;line-height:1.65;font-size:.95rem;">{body}</p>
    <table cellpadding="0" cellspacing="0" style="margin:0 0 24px;"><tr><td style="background:linear-gradient(135deg,#d97706,#92400e);border-radius:10px;">
      <a href="{base_url}/subscribe" style="display:inline-block;padding:13px 32px;color:#ffffff;text-decoration:none;font-weight:700;font-size:.95rem;">{T['button']}</a>
    </td></tr></table>
    <p style="margin:0;color:#9ca3af;font-size:.8rem;line-height:1.6;">{T['note']}</p>''')


CANCEL_I18N = {
    'de': {
        'subject': 'HolzBau 3D – Abo gekündigt (Premium bis {date})',
        'title': 'Abo gekündigt — schade, dass du gehst',
        'body': 'deine Kündigung ist bestätigt. Du behältst deinen vollen <strong>Premium-Zugang noch bis zum {date}</strong> — danach wird dein Konto automatisch auf Free umgestellt. Es wird nichts weiter abgebucht, und deine bereits erstellten Projekte bleiben dir erhalten.',
        'button': 'Premium fortsetzen',
        'note': 'Hast du es dir anders überlegt? Du kannst Premium jederzeit mit einem Klick wieder aktivieren. Über Feedback, warum du gekündigt hast, freuen wir uns sehr.',
    },
    'en': {
        'subject': 'HolzBau 3D – Subscription cancelled (Premium until {date})',
        'title': 'Subscription cancelled — sorry to see you go',
        'body': 'your cancellation is confirmed. You keep full <strong>Premium access until {date}</strong> — after that your account automatically switches to Free. Nothing more will be charged, and your existing projects are preserved.',
        'button': 'Resume Premium',
        'note': 'Changed your mind? You can reactivate Premium any time with a single click. We’d love to hear why you cancelled.',
    },
    'fr': {
        'subject': 'HolzBau 3D – Abonnement résilié (Premium jusqu’au {date})',
        'title': 'Abonnement résilié — désolé de vous voir partir',
        'body': 'votre résiliation est confirmée. Vous conservez un <strong>accès Premium complet jusqu’au {date}</strong> — ensuite votre compte passe automatiquement en Free. Aucun autre prélèvement, et vos projets existants sont conservés.',
        'button': 'Reprendre Premium',
        'note': 'Vous avez changé d’avis ? Vous pouvez réactiver Premium à tout moment en un clic. N’hésitez pas à nous dire pourquoi vous avez résilié.',
    },
}


def _email_cancel_html(display_name, end_date, lang='de'):
    T = CANCEL_I18N.get(_norm_lang(lang), CANCEL_I18N['de'])
    L = EMAIL_I18N.get(_norm_lang(lang), EMAIL_I18N['de'])
    base_url = os.environ.get('BASE_URL', 'https://holzbau3d.app')
    body = T['body'].replace('{date}', end_date)
    return _email_shell(f'''    <h2 style="margin:0 0 16px;font-size:1.15rem;color:#1a1a1a;font-weight:700;">{T['title']}</h2>
    <p style="margin:0 0 10px;color:#374151;line-height:1.65;font-size:.95rem;">{L['hello']} <strong>{display_name}</strong>,</p>
    <p style="margin:0 0 24px;color:#374151;line-height:1.65;font-size:.95rem;">{body}</p>
    <table cellpadding="0" cellspacing="0" style="margin:0 0 24px;"><tr><td style="background:linear-gradient(135deg,#d97706,#92400e);border-radius:10px;">
      <a href="{base_url}/subscribe" style="display:inline-block;padding:13px 32px;color:#ffffff;text-decoration:none;font-weight:700;font-size:.95rem;">{T['button']}</a>
    </td></tr></table>
    <p style="margin:0;color:#9ca3af;font-size:.8rem;line-height:1.6;">{T['note']}</p>''')


def _send_cancel_email(user_id):
    """Bestätigungs-Mail nach Kündigung (mit Datum bis wann Premium läuft)."""
    row = query_db('SELECT s.current_period_end, u.email, u.full_name, u.username, u.lang '
                   'FROM subscriptions s JOIN app_users u ON u.id = s.user_id WHERE u.id=?', [user_id], one=True)
    if not row or not row['email']:
        return
    lang = _norm_lang(row['lang'] if not hasattr(row, 'get') else row.get('lang'))
    pe = _to_dt(row['current_period_end'])
    end_txt = pe.strftime('%d.%m.%Y') if pe else '—'
    subj = CANCEL_I18N[lang]['subject'].replace('{date}', end_txt)
    send_email(row['email'], subj, _email_cancel_html(row['full_name'] or row['username'], end_txt, lang))


def _send_delete_email(user_id, sub_info=None):
    """Bestätigungs-Mail nach Konto-Löschung — wird VOR dem DB-Delete aufgerufen."""
    row = query_db('SELECT email, full_name, username, lang FROM app_users WHERE id=?', [user_id], one=True)
    if not row or not row['email']:
        return
    lang     = _norm_lang(row.get('lang') if hasattr(row, 'get') else 'de')
    name     = row['full_name'] or row['username'] or row['email']
    email    = row['email']
    now_str  = datetime.utcnow().strftime('%d.%m.%Y %H:%M UTC')

    had_sub  = sub_info and sub_info.get('stripe_sub_id')
    pe       = _to_dt(sub_info['current_period_end']) if sub_info and sub_info.get('current_period_end') else None
    end_str  = pe.strftime('%d.%m.%Y') if pe else None

    SUBJ = {'de': 'Dein HolzBau 3D Konto wurde gelöscht',
            'en': 'Your HolzBau 3D account has been deleted',
            'fr': 'Votre compte HolzBau 3D a été supprimé'}
    HELLO = {'de': 'Hallo', 'en': 'Hello', 'fr': 'Bonjour'}
    BODY = {
        'de': (
            f'<p style="margin:0 0 12px;color:#374151;line-height:1.65;font-size:.95rem;">'
            f'{HELLO[lang]} <strong>{name}</strong>,</p>'
            f'<p style="margin:0 0 12px;color:#374151;line-height:1.65;font-size:.95rem;">'
            f'dein Konto bei HolzBau 3D wurde am <strong>{now_str}</strong> dauerhaft gelöscht.</p>'
            + (f'<div style="background:#fef2f2;border-left:4px solid #ef4444;padding:14px 18px;border-radius:8px;margin:0 0 16px;">'
               f'<p style="margin:0 0 6px;color:#991b1b;font-weight:700;font-size:.9rem;">Abonnement gekündigt</p>'
               f'<p style="margin:0;color:#7f1d1d;font-size:.88rem;line-height:1.5;">'
               f'Dein aktives Premium-Abonnement{(" (gültig bis " + end_str + ")") if end_str else ""} wurde sofort und unwiderruflich gekündigt.</p>'
               f'</div>' if had_sub else '')
            + f'<p style="margin:0 0 6px;color:#374151;font-weight:700;font-size:.92rem;">Folgendes wurde gelöscht:</p>'
            f'<ul style="margin:0 0 16px;padding-left:20px;color:#4b5563;font-size:.88rem;line-height:1.8;">'
            f'<li>Login &amp; Zugangsdaten (E-Mail: {email})</li>'
            f'<li>Alle gespeicherten Projekte und Konstruktionen</li>'
            + (f'<li>Premium-Abonnement (sofort beendet)</li>' if had_sub else '')
            + f'<li>Alle persönlichen Daten</li>'
            f'</ul>'
            f'<p style="margin:0 0 16px;color:#6b7280;font-size:.88rem;line-height:1.5;">'
            f'Diese Aktion ist endgültig. Dein Konto kann nicht wiederhergestellt werden.</p>'
            f'<p style="margin:0;color:#9ca3af;font-size:.8rem;">Bei Fragen: support@holzbau3d.app</p>'
        ),
        'en': (
            f'<p style="margin:0 0 12px;color:#374151;line-height:1.65;font-size:.95rem;">'
            f'{HELLO[lang]} <strong>{name}</strong>,</p>'
            f'<p style="margin:0 0 12px;color:#374151;line-height:1.65;font-size:.95rem;">'
            f'your HolzBau 3D account was permanently deleted on <strong>{now_str}</strong>.</p>'
            + (f'<div style="background:#fef2f2;border-left:4px solid #ef4444;padding:14px 18px;border-radius:8px;margin:0 0 16px;">'
               f'<p style="margin:0 0 6px;color:#991b1b;font-weight:700;font-size:.9rem;">Subscription cancelled</p>'
               f'<p style="margin:0;color:#7f1d1d;font-size:.88rem;line-height:1.5;">'
               f'Your active Premium subscription{(" (valid until " + end_str + ")") if end_str else ""} was immediately and irrevocably cancelled.</p>'
               f'</div>' if had_sub else '')
            + f'<p style="margin:0 0 6px;color:#374151;font-weight:700;font-size:.92rem;">The following was deleted:</p>'
            f'<ul style="margin:0 0 16px;padding-left:20px;color:#4b5563;font-size:.88rem;line-height:1.8;">'
            f'<li>Login &amp; credentials (email: {email})</li>'
            f'<li>All saved projects and constructions</li>'
            + (f'<li>Premium subscription (terminated immediately)</li>' if had_sub else '')
            + f'<li>All personal data</li>'
            f'</ul>'
            f'<p style="margin:0 0 16px;color:#6b7280;font-size:.88rem;line-height:1.5;">'
            f'This action is final. Your account cannot be restored.</p>'
            f'<p style="margin:0;color:#9ca3af;font-size:.8rem;">Questions? support@holzbau3d.app</p>'
        ),
        'fr': (
            f'<p style="margin:0 0 12px;color:#374151;line-height:1.65;font-size:.95rem;">'
            f'{HELLO[lang]} <strong>{name}</strong>,</p>'
            f'<p style="margin:0 0 12px;color:#374151;line-height:1.65;font-size:.95rem;">'
            f'votre compte HolzBau 3D a été définitivement supprimé le <strong>{now_str}</strong>.</p>'
            + (f'<div style="background:#fef2f2;border-left:4px solid #ef4444;padding:14px 18px;border-radius:8px;margin:0 0 16px;">'
               f'<p style="margin:0 0 6px;color:#991b1b;font-weight:700;font-size:.9rem;">Abonnement résilié</p>'
               f'<p style="margin:0;color:#7f1d1d;font-size:.88rem;line-height:1.5;">'
               f'Votre abonnement Premium actif{(" (valable jusqu\'au " + end_str + ")") if end_str else ""} a été résilié immédiatement et irrévocablement.</p>'
               f'</div>' if had_sub else '')
            + f'<p style="margin:0 0 6px;color:#374151;font-weight:700;font-size:.92rem;">Éléments supprimés :</p>'
            f'<ul style="margin:0 0 16px;padding-left:20px;color:#4b5563;font-size:.88rem;line-height:1.8;">'
            f'<li>Identifiants &amp; accès (e-mail : {email})</li>'
            f'<li>Tous les projets et constructions sauvegardés</li>'
            + (f'<li>Abonnement Premium (résilié immédiatement)</li>' if had_sub else '')
            + f'<li>Toutes les données personnelles</li>'
            f'</ul>'
            f'<p style="margin:0 0 16px;color:#6b7280;font-size:.88rem;line-height:1.5;">'
            f'Cette action est définitive. Votre compte ne peut pas être restauré.</p>'
            f'<p style="margin:0;color:#9ca3af;font-size:.8rem;">Questions ? support@holzbau3d.app</p>'
        ),
    }
    html = _email_shell(
        f'<h2 style="margin:0 0 20px;font-size:1.1rem;color:#dc2626;font-weight:800;">'
        f'{"Konto gelöscht" if lang=="de" else ("Account deleted" if lang=="en" else "Compte supprimé")}'
        f'</h2>' + BODY[lang]
    )
    send_email(email, SUBJ[lang], html)


def _price_text(interval):
    """Angezeigter Betrag je Intervall. Quelle sind dieselben Env-Variablen wie
    auf der Kaufseite, damit Mail und Seite nie auseinanderlaufen."""
    if interval == 'yearly':
        return os.environ.get('PRICE_YEARLY_TEXT', '99,99 €')
    return os.environ.get('PRICE_MONTHLY_TEXT', '9,99 €')


def _run_renewal_notices():
    """Erinnert eine Woche vor der naechsten Abbuchung eines AKTIVEN Abos.
    Damit weiss jeder, dass sein Abo laeuft, und wird von der Abbuchung nicht
    ueberrascht. Nur fuer nicht gekuendigte Abos — gekuendigte bekommen die
    Ablaufwarnung aus _run_subscription_reminders().
    Idempotent ueber renewal_notice_for (= das Periodenende, fuer das bereits
    gemailt wurde). Gibt eine Log-Liste zurueck."""
    out = []
    rows = query_db(
        "SELECT s.user_id, s.current_period_end, s.plan_interval, s.renewal_notice_for, "
        "u.email, u.full_name, u.username, u.lang "
        "FROM subscriptions s JOIN app_users u ON u.id = s.user_id "
        "WHERE s.plan='premium' AND s.status='active'", []
    )
    now = datetime.utcnow()
    for r in rows:
        pe = _to_dt(r['current_period_end'])
        if not pe or not r['email']:
            continue
        days_left = (pe - now).total_seconds() / 86400.0
        # Ab 8 Tagen vorher, nicht als enges Fenster: faellt der Cron mal mehrere
        # Tage aus, wuerde ein enges Fenster die Erinnerung still verschlucken.
        # So kommt sie notfalls spaeter — spaet ist besser als eine ueberraschende
        # Abbuchung. Doppelt kann sie durch renewal_notice_for nicht kommen.
        if not (0 < days_left <= 8.0):
            continue
        already = _to_dt(r['renewal_notice_for'])
        if already and abs((already - pe).total_seconds()) < 3600:
            continue   # fuer genau diese Periode schon erinnert
        interval = r['plan_interval'] or 'monthly'
        u_lang = _norm_lang(r['lang'])
        date_txt = pe.strftime('%d.%m.%Y')
        amount_txt = _price_text(interval)
        subject = (RENEWAL_I18N[u_lang]['subject']
                   .replace('{date}', date_txt).replace('{amount}', amount_txt))
        ok = send_email(r['email'], subject,
                        _email_renewal_html(r['full_name'] or r['username'],
                                            date_txt, amount_txt, interval, u_lang))
        if ok:
            execute_db('UPDATE subscriptions SET renewal_notice_for=? WHERE user_id=?',
                       [pe.strftime('%Y-%m-%d %H:%M:%S'), r['user_id']])
            out.append(f"user {r['user_id']}: Verlaengerungs-Erinnerung gesendet "
                       f"(Abbuchung {date_txt}, {amount_txt}, in {days_left:.1f}d)")
        else:
            out.append(f"user {r['user_id']}: Mail-Versand fehlgeschlagen")
    return out


def _run_subscription_reminders():
    """Sendet Erinnerungen 7 Tage und 2 Tage vor Ablauf gekündigter Abos.
    Idempotent über reminder_stage (''/'7d'/'2d'). Gibt eine Log-Liste zurück."""
    out = []
    rows = query_db(
        "SELECT s.user_id, s.current_period_end, s.reminder_stage, "
        "u.email, u.full_name, u.username, u.lang "
        "FROM subscriptions s JOIN app_users u ON u.id = s.user_id "
        "WHERE s.plan='premium' AND s.status='cancelled'", []
    )
    now = datetime.utcnow()
    for r in rows:
        pe = _to_dt(r['current_period_end'])
        if not pe or not r['email']:
            continue
        days_left = (pe - now).total_seconds() / 86400.0
        if days_left < 0:
            continue
        stage = r['reminder_stage'] or ''
        send_stage = None
        if days_left <= 2 and stage != '2d':
            send_stage = '2d'
        elif days_left <= 7 and stage == '':
            send_stage = '7d'
        if not send_stage:
            continue
        u_lang = _norm_lang(r['lang'] if not hasattr(r, 'get') else r.get('lang'))
        subj_days = EXPIRY_I18N[u_lang]['d2'] if send_stage == '2d' else EXPIRY_I18N[u_lang]['d7']
        subject = EXPIRY_I18N[u_lang]['subject'].replace('{days}', subj_days)
        ok = send_email(r['email'], subject,
                        _email_expiry_html(r['full_name'] or r['username'], pe.strftime('%d.%m.%Y'), send_stage, u_lang))
        if ok:
            execute_db('UPDATE subscriptions SET reminder_stage=? WHERE user_id=?', [send_stage, r['user_id']])
            out.append(f"user {r['user_id']}: {send_stage}-Erinnerung gesendet (Ablauf in {days_left:.1f}d)")
        else:
            out.append(f"user {r['user_id']}: Mail-Versand fehlgeschlagen")
    return out


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
        row = query_db('SELECT user_id FROM subscriptions WHERE stripe_sub_id=?', [sub_id], one=True)
        if row:
            _sync_user_from_stripe(row['user_id'])


# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
else:
    with app.app_context():
        init_db()
