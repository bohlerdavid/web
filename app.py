import os
import re
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
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urljoin

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, g, abort, jsonify, session, Response
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
# Einzelne FORMULARFELDER haben eine eigene, viel kleinere Grenze (Default
# 500 KB). Das gilt unabhaengig von MAX_CONTENT_LENGTH und hat beim
# Serverspeicher zugeschlagen: ein Projekt-JSON ueber 500 KB wurde von Werkzeug
# abgewiesen, bevor die Route ueberhaupt lief — der Nutzer sah eine rohe
# HTML-Fehlerseite statt einer verstaendlichen Meldung, und die eigene
# 3-MB-Grenze (PROJEKT_MAX_BYTES) waere nie erreicht worden.
# Etwas mehr als PROJEKT_MAX_BYTES, damit die eigene Pruefung zuerst greift.
app.config['MAX_FORM_MEMORY_SIZE'] = 4 * 1024 * 1024
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
        # cdn.jsdelivr.net MUSS mit rein: dort liegt die Bootstrap-Icons-Schrift.
        # Vorher gab es kein font-src, die Regel fiel auf default-src zurueck und
        # dort steht jsdelivr — die praezisere Regel hat die Icons ausgesperrt,
        # jedes <i class="bi …"> wurde zum leeren Rechteck.
        'font-src': ["'self'", 'data:', 'fonts.gstatic.com', 'cdn.jsdelivr.net'],
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
        # HIER ist der Kauf gestorben — und zwar lautlos.
        #
        # form-action gilt in Chrome und Safari AUCH fuer die Weiterleitung,
        # die auf ein abgeschicktes Formular folgt. Der Ablauf war:
        #   1. Formular POSTet an /subscribe/create-checkout  (eigene Domain, erlaubt)
        #   2. Server antwortet 303 -> https://checkout.stripe.com/...
        #   3. Browser prueft das ZIEL gegen form-action 'self' -> nicht erlaubt
        #   4. Er verwirft die Weiterleitung. Die Seite bleibt einfach stehen.
        #
        # Kein Fehler, keine Meldung, keine Zeile im Server-Log: dort sah alles
        # richtig aus, weil serverseitig auch alles richtig war. Genau deshalb
        # meldete der Probelauf "OK" und jeder Test lief gruen, waehrend kein
        # einziger Kunde durchkam. Der Beleg steht nur in der Browser-Konsole:
        # "Refused to send form data to 'https://checkout.stripe.com/...'".
        #
        # In Firefox funktionierte der Kauf uebrigens — der wendet form-action
        # nicht auf Weiterleitungen an.
        'form-action': ["'self'", 'checkout.stripe.com', 'js.stripe.com'],
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


# Alle Tabellen mit Personenbezug, absteigend nach Abhaengigkeit. app_users
# kommt zuletzt, sonst zeigen die uebrigen Zeilen auf ein Konto, das es nicht
# mehr gibt.
PERSONENBEZOGENE_TABELLEN = (
    ('feedback', 'user_id'),        # Betreff, Nachricht, Screenshot, Projekt-JSON
    ('feature_use', 'user_id'),     # welche Funktion wann benutzt wurde
    ('checkout_intents', 'user_id'),  # Kaufversuche und woran sie scheiterten
    ('projects', 'user_id'),        # gespeicherte Modelle inkl. Bauvorhaben (Ort!)
    ('subscriptions', 'user_id'),
)


def _nutzerdaten_loeschen(user_id):
    """Loescht ALLE personenbezogenen Zeilen eines Kontos.

    Bisher raeumten beide Loeschpfade (Selbstloeschung und Admin-Loeschung) nur
    subscriptions und app_users ab. Liegen geblieben sind feedback — mit
    Betreff, Nachrichtentext, Screenshot und dem mitgeschickten Projekt-JSON —
    und feature_use. Fremdschluessel, die das automatisch erledigen wuerden,
    gibt es nicht. Die Datenschutzerklaerung sagt aber zu, "alle
    personenbezogenen Daten innerhalb von 30 Tagen" zu loeschen.

    Fehler beim Aufraeumen werden protokolliert, halten die Kontoloeschung aber
    nicht auf: ein Nutzer, der sein Konto loescht, darf nicht an einer
    Nebentabelle scheitern.
    """
    # Zuerst die Zugangslisten: sie haengen am Projekt, nicht am Konto. Waeren
    # die Projekte schon weg, liessen sich ihre Adressen nicht mehr zuordnen und
    # blieben als Waisen liegen — obwohl es Daten Dritter sind.
    try:
        execute_db('DELETE FROM share_access WHERE project_id IN '
                   '(SELECT id FROM projects WHERE user_id=?)', [user_id])
    except Exception as e:
        logger.error('Loeschen der Zugangslisten fuer Nutzer %s fehlgeschlagen: %s',
                     user_id, type(e).__name__)
    for tabelle, spalte in PERSONENBEZOGENE_TABELLEN:
        try:
            execute_db('DELETE FROM %s WHERE %s=?' % (tabelle, spalte), [user_id])
        except Exception as e:
            logger.error('Loeschen aus %s fuer Nutzer %s fehlgeschlagen: %s',
                         tabelle, user_id, type(e).__name__)
    execute_db('DELETE FROM app_users WHERE id=?', [user_id])
    logger.info('Konto %s und zugehoerige Daten geloescht', user_id)


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
    # Protokoll jedes Cron-Aufrufs. Ohne das ist von aussen nicht zu sehen, ob
    # der externe Dienst (cron-job.org) ueberhaupt anklopft — und genau das war
    # monatelang unklar. ABGELEHNTE Aufrufe kommen bewusst MIT hinein: nur so
    # laesst sich "der Cron ruft nie an" von "der Cron ruft mit falschem
    # Schluessel an" unterscheiden. Beides sieht sonst gleich aus (= nichts).
    """CREATE TABLE IF NOT EXISTS cron_runs (
        id        INT PRIMARY KEY AUTO_INCREMENT,
        job       VARCHAR(60)  NOT NULL,
        ran_at    DATETIME     NOT NULL,
        ok        TINYINT      NOT NULL DEFAULT 1,
        grund     VARCHAR(24)  NULL,
        note      TEXT         NULL,
        ip        VARCHAR(45)  NULL,
        INDEX (job), INDEX (ran_at)
    )""",
    # Wer benutzt welches Premium-Feature? `plan` ist der SERVER-seitig zum
    # Zeitpunkt festgestellte Plan — nicht der Browser-Wert, den ein Nutzer
    # faelschen kann. Eine Zeile mit plan='free' heisst: hier hat jemand die
    # Client-Sperre umgangen. Zeilen mit plan='premium' sind normale Nutzung
    # (gratis Feature-Statistik als Nebenprodukt).
    """CREATE TABLE IF NOT EXISTS feature_use (
        id       INT PRIMARY KEY AUTO_INCREMENT,
        user_id  INT          NULL,
        feature  VARCHAR(60)  NOT NULL,
        plan     VARCHAR(12)  NOT NULL,
        used_at  DATETIME     NOT NULL,
        INDEX (feature), INDEX (used_at), INDEX (plan)
    )""",
    # Gespeicherte Projekte. Das JSON enthaelt auch die Bauvorhaben-Angaben und
    # damit einen ORT — personenbezogene Daten. Deshalb steht projects in
    # PERSONENBEZOGENE_TABELLEN, wird also mit dem Konto geloescht, und in der
    # Datenschutzerklaerung genannt.
    # LONGTEXT statt TEXT: TEXT fasst 65 KB, ein Modell mit ein paar tausend
    # Balken und Ausschnitten ist groesser. Die eigentliche Grenze setzt
    # PROJEKT_MAX_BYTES in der Route.
    # Fuer einen Ansehen-Link freigeschaltete E-Mail-Adressen. Das sind Daten
    # DRITTER — der Zimmerer, der Statiker, der Bauherr. Sie haengen am Projekt,
    # nicht am Konto, und werden deshalb an drei Stellen ausdruecklich mit
    # geloescht: beim Widerruf, beim Loeschen des Projekts und beim Loeschen des
    # Kontos. PERSONENBEZOGENE_TABELLEN greift hier nicht, weil dort ueber
    # user_id geloescht wird und diese Tabelle keine hat.
    # Der Kaufweg. Eine Zeile je Klick auf "Abo abschliessen" — mit dem Ausgang.
    #
    # Warum ueberhaupt: bis hierher hinterliess ein gescheiterter Kauf KEINE
    # Spur. Am 05.08.2026 kam ein Kunde nicht zur Kasse und meldete es per
    # E-Mail; serverseitig war nichts zu finden, weil serverseitig alles
    # richtig war. Wer nicht schreibt, wo der Weg endet, sucht beim naechsten
    # Mal wieder von vorn.
    #
    # `grund` benennt die Sackgasse, und zwar genau die vier, die es gibt:
    #   sitzung   – CSRF-Merkmal veraltet (Tab lag zu lange offen)
    #   limit     – zu viele Versuche in kurzer Zeit
    #   technik   – Stripe nicht erreichbar oder nicht konfiguriert
    #   zurueck   – bei Stripe auf Abbrechen geklickt (?cancelled=1)
    #   abgelaufen– Stripe hat die Sitzung nach 24 h verfallen lassen
    #
    # Rechtsgrundlage ist NICHT die Nutzungsstatistik (Art. 6 I f), sondern die
    # Anbahnung des Vertrags (Art. 6 I b) — deshalb greift der Widerspruch
    # gegen die Funktionsstatistik hier bewusst nicht: wer nicht bezahlen kann,
    # muss auffindbar bleiben, sonst ist ihm nicht zu helfen. Die Zeilen haengen
    # am Konto und werden mit ihm geloescht (PERSONENBEZOGENE_TABELLEN).
    """CREATE TABLE IF NOT EXISTS checkout_intents (
        id           INT PRIMARY KEY AUTO_INCREMENT,
        user_id      INT          NOT NULL,
        plan_type    VARCHAR(12)  NOT NULL,
        status       VARCHAR(12)  NOT NULL,
        grund        VARCHAR(20)  NULL,
        session_id   VARCHAR(80)  NULL,
        gestartet_at DATETIME     NOT NULL,
        beendet_at   DATETIME     NULL,
        INDEX (user_id), INDEX (status), INDEX (gestartet_at), INDEX (session_id)
    )""",
    # Klickzaehler der Startseite. BEWUSST nur ein Zaehler je Tag, Ziel und
    # Sprache — es gibt hier kein Feld, ueber das sich jemand wiedererkennen
    # liesse: keine Kennung, keine IP, kein Cookie, keine Uhrzeit. Damit ist es
    # kein Personenbezug und braucht kein Einwilligungsbanner.
    #
    # Der Preis dafuer ist ehrlich zu nennen: die Reihenfolge der Klicks eines
    # Besuchs laesst sich damit NICHT rekonstruieren. Man sieht, WO geklickt
    # wird, nicht, wer welchen Weg genommen hat. Das war die Abwaegung.
    """CREATE TABLE IF NOT EXISTS landing_clicks (
        id      INT PRIMARY KEY AUTO_INCREMENT,
        tag     DATE         NOT NULL,
        ziel    VARCHAR(40)  NOT NULL,
        sprache VARCHAR(5)   NOT NULL,
        anzahl  INT          NOT NULL DEFAULT 0,
        UNIQUE KEY uq_tag_ziel_sprache (tag, ziel, sprache)
    )""",
    """CREATE TABLE IF NOT EXISTS share_access (
        id         INT PRIMARY KEY AUTO_INCREMENT,
        project_id INT          NOT NULL,
        email      VARCHAR(255) NOT NULL,
        created_at DATETIME     NOT NULL,
        INDEX (project_id)
    )""",
    """CREATE TABLE IF NOT EXISTS projects (
        id          INT PRIMARY KEY AUTO_INCREMENT,
        user_id     INT          NOT NULL,
        name        VARCHAR(120) NOT NULL,
        daten       LONGTEXT     NOT NULL,
        groesse     INT          NOT NULL DEFAULT 0,
        created_at  DATETIME     NOT NULL,
        updated_at  DATETIME     NOT NULL,
        INDEX (user_id), INDEX (updated_at)
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
    # Feedback: das Projekt-JSON, das der Nutzer freiwillig mitschickt (nur Geometrie,
    # ohne eingebettete Bild-Vorlage). MEDIUMTEXT reicht mit Abstand.
    "ALTER TABLE feedback ADD COLUMN project MEDIUMTEXT NULL",
    "ALTER TABLE app_users ADD COLUMN unsub_token VARCHAR(64) NULL",
    "ALTER TABLE app_users ADD COLUMN last_upsell_sent DATETIME NULL",
    # Wie oft die Werbemail schon rausging. Ohne Zaehler lief sie ALLE 5 TAGE
    # unbegrenzt weiter — wer sich vor zwei Monaten registriert hat, bekam rund
    # ein Dutzend. Das liest sich als Spam und drueckt bei Brevo die Zustellrate
    # fuer ALLE Mails, auch fuer Verifizierung und Abo-Ablauf.
    "ALTER TABLE app_users ADD COLUMN upsell_count INT NOT NULL DEFAULT 0",
    # Einmalige Ankuendigung neuer Funktionen. Eigene Spalte statt eines Flags
    # im Upsell-Zaehler: die beiden Mails haben verschiedene Zwecke, und diese
    # hier darf sich NIE wiederholen, auch nicht wenn der Cron zweimal laeuft.
    "ALTER TABLE app_users ADD COLUMN feature_mail_sent DATETIME NULL",
    # Bestandsnutzer haben schon reichlich bekommen. Sie starten deshalb bei 2
    # und erhalten hoechstens noch EINE Mail statt drei.
    # Idempotent: nach dem ersten Lauf steht dort 2, die Bedingung greift nicht
    # mehr. Ein neu angeschriebener Nutzer hat 1 und wird ebenfalls nicht
    # erfasst. Die Migrationen laufen bei JEDEM Start.
    "UPDATE app_users SET upsell_count=2 WHERE last_upsell_sent IS NOT NULL AND upsell_count=0",
    # Verlaengerungs-Erinnerung: speichert das Periodenende, fuer das bereits
    # gemailt wurde. Als Schluessel bewusst das Datum und kein Flag — bei der
    # naechsten Periode aendert sich current_period_end, damit passt der
    # gespeicherte Wert nicht mehr und es wird von selbst erneut erinnert.
    # (reminder_stage taugt dafuer nicht: _activate_premium setzt es bei jeder
    #  Verlaengerung auf '' zurueck.)
    "ALTER TABLE subscriptions ADD COLUMN renewal_notice_for DATETIME NULL",
    # Welche Verlaengerungs-Erinnerungen fuer die aktuelle Periode schon raus sind
    # ('7d' und/oder '1d'), damit 7-Tage- UND 1-Tag-Erinnerung getrennt feuern.
    "ALTER TABLE subscriptions ADD COLUMN renewal_stage VARCHAR(8) NOT NULL DEFAULT ''",
    # Grund der Abweisung als Code statt nur im Fliesstext. Noetig, um "der Cron
    # ruft mit falschem Schluessel an" von "irgendjemand hat die URL ohne
    # Schluessel aufgerufen" zu unterscheiden — die Uebersicht hat das sonst
    # verwechselt und einen Testaufruf als Cron-Problem gemeldet.
    "ALTER TABLE cron_runs ADD COLUMN grund VARCHAR(24) NULL",
    # E-Mail eindeutig machen. Bisher stand UNIQUE nur auf username; die
    # Eindeutigkeit der Adresse pruefte allein der Registrierungs-Code — und der
    # hat bei zwei gleichzeitigen Anmeldungen eine Luecke. Ohne diese Bedingung
    # trifft ausserdem das Passwort-Zuruecksetzen (WHERE email=?, one=True) bei
    # Doppeleintraegen stillschweigend das falsche Konto.
    # NULL bleibt mehrfach erlaubt (MySQL zaehlt NULL nicht als Dublette), das
    # Admin-Konto ohne Adresse stoert also nicht.
    "ALTER TABLE app_users ADD UNIQUE INDEX uniq_email (email)",
    # Widerspruch gegen die Nutzungsstatistik (Art. 21 DSGVO). Die Erhebung
    # stuetzt sich auf berechtigtes Interesse — dann muss ein Widerspruch
    # moeglich und wirksam sein, nicht nur in der Erklaerung erwaehnt.
    "ALTER TABLE app_users ADD COLUMN stats_opt_out TINYINT NOT NULL DEFAULT 0",
    # Bezahlschranken-Treffer erfassen. Bisher meldete requirePremium NUR den
    # Fall, dass jemand die Schranke PASSIERT — der abgeprallte Free-Nutzer
    # hinterliess keine Spur. Genau diese Zahl fehlt aber fuer die Frage, warum
    # so wenige zahlen. DEFAULT 'used' gibt allen Altzeilen rueckwirkend die
    # richtige Bedeutung, ohne Datenwanderung.
    "ALTER TABLE feature_use ADD COLUMN event VARCHAR(10) NOT NULL DEFAULT 'used'",
    # Stabiler ASCII-Schluessel neben der Roh-Beschriftung. Die bisherigen Namen
    # sind deutsche UI-Texte mit Emoji ("📋 Stückliste exportieren") — benennt
    # man einen Knopf um, zerfaellt die Statistik in zwei Haelften. Ausserdem gibt
    # es bereits eine echte Dublette: 'Vorlagen' und '📦 Vorlagen' fuer dieselbe
    # Schranke.
    "ALTER TABLE feature_use ADD COLUMN fkey VARCHAR(40) NULL",
    "ALTER TABLE feature_use ADD INDEX idx_user_zeit (user_id, used_at)",
    # Echte Wiederkehr statt Schaetzung: last_login wird bei jedem Login
    # ueberschrieben, damit ist "war schon mal wieder da" nur heuristisch
    # (Abstand zu created_at). Ein Zaehler und der VORIGE Login beantworten die
    # Frage exakt.
    "ALTER TABLE app_users ADD COLUMN login_count INT NOT NULL DEFAULT 0",
    "ALTER TABLE app_users ADD COLUMN prev_login DATETIME NULL",
    # Ansehen-Link fuer ein Projekt. NULL = nicht freigegeben. MySQL erlaubt
    # beliebig viele NULL in einem UNIQUE-Index, der Normalfall bleibt also
    # unberuehrt und nur echte Token muessen eindeutig sein.
    "ALTER TABLE projects ADD COLUMN share_token VARCHAR(64) NULL",
    "ALTER TABLE projects ADD COLUMN share_at DATETIME NULL",
    "CREATE UNIQUE INDEX uniq_share_token ON projects (share_token)",
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
            # Waisen aufraeumen: Zeilen aus frueher geloeschten Konten. Bis
            # _nutzerdaten_loeschen existierte, raeumten beide Loeschpfade nur
            # subscriptions und app_users ab — feedback und feature_use blieben
            # mit ihrer user_id stehen, obwohl das Konto weg war. Idempotent,
            # laeuft bei jedem Start und findet danach nichts mehr.
            for tabelle, spalte in PERSONENBEZOGENE_TABELLEN:
                try:
                    cur.execute('DELETE FROM %s WHERE %s IS NOT NULL AND %s NOT IN '
                                '(SELECT id FROM app_users)' % (tabelle, spalte, spalte))
                    if cur.rowcount:
                        logger.warning('%d verwaiste Zeile(n) aus %s entfernt (Konto existiert nicht mehr)',
                                       cur.rowcount, tabelle)
                except Exception as e:
                    logger.error('Waisen-Aufraeumen in %s fehlgeschlagen: %s', tabelle, type(e).__name__)
            cur.execute("SELECT COUNT(*) as c FROM app_users")
            count = cur.fetchone()['c']
            if count == 0:
                # Kein hartkodiertes Passwort mehr. 'Admin1234!' stand frueher
                # hier — ein Standard-Credential, mit dem sich JEDER als admin
                # anmelden konnte, solange es niemand aendert (CWE-798). Jetzt:
                # aus ADMIN_PASSWORD, sonst ein zufaelliges, das EINMALIG ins
                # Log geht. So existiert nie ein bekanntes Admin-Passwort.
                admin_pw = os.environ.get('ADMIN_PASSWORD', '').strip()
                if not admin_pw:
                    admin_pw = secrets.token_urlsafe(18)
                    logger.warning(
                        'Kein ADMIN_PASSWORD gesetzt — zufaelliges Admin-Passwort erzeugt: %s '
                        '— JETZT notieren und nach dem ersten Login im Profil aendern. '
                        'Es erscheint nur dieses eine Mal.', admin_pw)
                pw_hash = generate_password_hash(admin_pw)
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
        'p_features': '✅ Fertige Vorlagen für Carport, Gartenhaus &amp; Co.<br>✅ Vollständig werbefrei<br>✅ PDF-, DXF- &amp; CNC-Export<br>✅ Säge-Tool, Schnittplan &amp; Kalkulation',
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
        'p_features': '✅ Ready-made templates for carport, garden shed &amp; more<br>✅ Completely ad-free<br>✅ PDF, DXF &amp; CNC export<br>✅ Saw tool, cutting plan &amp; costing',
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
        'p_features': '✅ Modèles prêts : carport, abri de jardin &amp; plus<br>✅ Sans aucune publicité<br>✅ Export PDF, DXF &amp; CNC<br>✅ Outil scie, plan de coupe &amp; chiffrage',
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
# Fuenf Versuche pro IP und zehn Minuten — daran ist der Kauf gescheitert.
# Der Zaehler laeuft bei JEDEM Aufruf hoch, auch beim erfolgreichen. Wer den
# Knopf beim Ausprobieren fuenfmal drueckt, oder wer bei Stripe abbricht und es
# noch einmal versucht, ist danach zehn Minuten gesperrt — und die Meldung
# stand ausserhalb des Bildes. Fuer den Kunden: "es passiert nix".
# Schlimmer noch: gezaehlt wurde pro IP. Hinter einem Firmenanschluss oder im
# Mobilfunk teilen sich viele Leute eine Adresse; fuenf Kaufversuche von
# irgendwem sperrten dort alle anderen mit.
# Jetzt pro KONTO (die Route ist ohnehin angemeldet) und mit Luft nach oben.
# Missbrauch einer einzelnen Anmeldung bremst das immer noch.
CHECKOUT_MAX_ATTEMPTS = 12
RESEND_MAX_ATTEMPTS   = 3
RESET_MAX_ATTEMPTS    = 3


def _is_safe_redirect(url):
    # Nur echte, seiteninterne Pfade. Der alte Test (urljoin + startswith)
    # liess '/\evil.com' durch: urljoin haengt es an die eigene Domain, der
    # Browser macht aus dem Backslash aber '/', also '//evil.com' — protokoll-
    # relativ auf eine FREMDE Domain (Open Redirect, Phishing nach dem Login).
    # Kein Rechte-Bypass, aber eine echte Luecke. Jetzt streng: muss mit genau
    # EINEM '/' beginnen und darf weder Schema noch Host tragen.
    if not url or not url.startswith('/') or url.startswith('//') or url.startswith('/\\'):
        return False
    teile = urlparse(url)
    if teile.scheme or teile.netloc:
        return False
    return _ist_per_get_erreichbar(teile.path)


def _ist_per_get_erreichbar(pfad):
    """Kann man diesen Pfad ueberhaupt mit einer GET-Anfrage aufrufen?

    Nach dem Login wird `next` als GET angesteuert. Zeigt es auf eine Route,
    die nur POST kann, bekommt der Kunde 405 METHOD NOT ALLOWED — eine nackte
    Fehlerseite. Genau das passierte auf dem Weg zum Abo: der Kaufknopf schickt
    an /subscribe/create-checkout (nur POST); war die Sitzung abgelaufen,
    landete man ueber das Login als GET dort. Fuer den Kunden sah das aus wie
    "der Link funktioniert nicht" — und der Kauf war zu Ende.
    """
    from werkzeug.routing import RequestRedirect
    try:
        app.url_map.bind('').match(pfad, method='GET')
        return True
    except RequestRedirect:
        return True          # nur ein fehlender Schraegstrich — per GET erreichbar
    except Exception:
        return False         # unbekannt oder nur POST


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
            return redirect(url_for('login', next=_ziel_nach_login()))
        return f(*args, **kwargs)
    return decorated


def _ziel_nach_login():
    """Wohin nach dem Login — und zwar so, dass man dort auch ankommt.

    Bisher wurde stur request.path mitgegeben. Bei einem abgeschickten
    Formular ist das eine Route, die nur POST kann; nach dem Login wird sie
    als GET aufgerufen und der Kunde bekommt 405. Auf dem Weg zum Abo war das
    das Ende des Kaufs.

    Fuer eine GET-Anfrage bleibt alles wie bisher. Fuer ein Formular nehmen wir
    die Seite, von der es kam — dort steht der Knopf noch einmal.
    """
    if request.method == 'GET':
        return request.path
    hin = request.referrer or ''
    teile = urlparse(hin)
    if hin and (not teile.netloc or teile.netloc == urlparse(request.host_url).netloc):
        pfad = teile.path or ''
        if pfad.startswith('/') and not pfad.startswith('//') and _ist_per_get_erreichbar(pfad):
            return pfad
    return ''


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


@app.route('/health/zahlung')
def health_zahlung():
    """Ist der Weg zum Abo von aussen betrachtet in Ordnung?

    Ein Kunde hat gemeldet, dass er kein Upgrade auswaehlen kann. Die Ursache
    liess sich von aussen nicht feststellen: /subscribe braucht ein Login, und
    ob eine Umgebungsvariable auf Railway gesetzt ist, sieht man dem HTML nicht
    an. Ein Bezahlweg, der lautlos verschwinden kann, ohne dass es jemandem
    auffaellt, ist die teuerste Art von Fehler.

    Zurueck kommen NUR Ja/Nein-Werte. Kein Schluessel, kein Praefix, keine
    Preis-ID — die gehoeren in keine oeffentliche Antwort, auch nicht
    abgekuerzt. Was hier steht, weiss ein Angreifer ohnehin.
    """
    schluessel = bool(os.environ.get('STRIPE_SECRET_KEY'))
    monat = bool(os.environ.get('STRIPE_PRICE_ID'))
    jahr = bool(os.environ.get('STRIPE_YEARLY_PRICE_ID'))
    # Erreichbar heisst: Stripe antwortet uns mit unserem Schluessel. Ein
    # abgelaufener oder zurueckgezogener Schluessel sieht sonst genauso aus wie
    # ein gesetzter.
    erreichbar = None
    if schluessel:
        try:
            _stripe_api_get('prices', {'limit': 1})
            erreichbar = True
        except Exception as e:
            erreichbar = False
            logger.error('Stripe nicht erreichbar: %s', type(e).__name__)
    kaufbar = bool(schluessel and monat and erreichbar)
    if not kaufbar:
        logger.error('ZAHLWEG GESTOERT: key=%s monat=%s jahr=%s erreichbar=%s',
                     schluessel, monat, jahr, erreichbar)
    return jsonify({
        'kaufbar': kaufbar,
        'stripe_key': schluessel,
        'preis_monat': monat,
        'preis_jahr': jahr,
        'stripe_erreichbar': erreichbar,
    }), (200 if kaufbar else 503)


@app.route('/ping')
def ping():
    if 'user_id' in session:
        session.modified = True
    return '', 204


# ---------------------------------------------------------------------------
# SEO: mehrsprachige Meta-Daten + Sprach-URLs (/, /en, /fr)
# ---------------------------------------------------------------------------

SITE = 'https://holzbau3d.app'

# ---------------------------------------------------------------------------
# Zeitzone
# ---------------------------------------------------------------------------
# Gespeichert wird durchgaengig UTC (datetime.utcnow()). Angezeigt wurde der Wert
# bisher roh — im Sommer also zwei Stunden zu frueh, im Winter eine. Das betraf
# nicht nur die Optik: ein Periodenende um 23:00 UTC faellt lokal schon auf den
# NAECHSTEN Tag, die Abo-Mail haette also das falsche Datum genannt.
LOCAL_TZ_NAME = os.environ.get('LOCAL_TZ', 'Europe/Luxembourg')
try:
    from zoneinfo import ZoneInfo
    LOCAL_TZ = ZoneInfo(LOCAL_TZ_NAME)
except Exception:  # pragma: no cover — fehlt tzdata, lieber UTC als Absturz
    LOCAL_TZ = timezone.utc
    logging.getLogger(__name__).warning('Zeitzone %s nicht ladbar, nutze UTC', LOCAL_TZ_NAME)


def to_local(v):
    """UTC-Wert aus der DB in die lokale Zeit umrechnen. Nimmt datetime oder
    String, gibt datetime zurueck (oder None)."""
    d = _to_dt(v) if not isinstance(v, datetime) else v
    if not d:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(LOCAL_TZ)


@app.template_filter('lokal')
def _filter_lokal(v, fmt='%d.%m.%Y %H:%M'):
    """Jinja: {{ wert|lokal }} -> '15.07.2026 20:32'. Ein zentraler Filter statt
    an jeder Anzeigestelle einzeln zu rechnen."""
    d = to_local(v)
    return d.strftime(fmt) if d else '—'


@app.template_filter('lokal_datum')
def _filter_lokal_datum(v):
    d = to_local(v)
    return d.strftime('%d.%m.%Y') if d else '—'


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
        # Max ~160 Zeichen: Google schneidet dahinter ab. Die alte Fassung hatte
        # 236 — abgeschnitten wurde mitten im Satz, ausgerechnet vor dem
        # "Jetzt gratis starten". Schluesselwoerter stehen vorn.
        'desc': 'Holzkonstruktionen kostenlos online planen: Pergola, Carport, Dachstuhl & mehr in 3D – direkt im Browser, mit Stückliste, Schnittplan & PDF-Export.',
        'keywords': 'Holzbau, Holzbau 3D, 3D Holzdesign, Holzdesign 3D, Holzkonstruktion, Holz Konstruktion, Holzbau Konstruktion, Konstruktion aus Holz, Holzkonstruktion 3D, Holzkonstruktion planen, Holzkonstruktion planen kostenlos, Holzkonstruktion online, Holz konstruieren, Holzbau planen, Holzbau Software kostenlos, Holzbausoftware kostenlos, Konstruktionsprogramm Holzbau kostenlos, 3D Holz Planer kostenlos, Holzbau Programm, 3D Holzbau, Pergola planen, Carport planen, Dachstuhl planen, Stückliste, Schnittplan',
        'og_title': 'Holzbau 3D – Holzkonstruktion in 3D planen & konstruieren',
        'og_desc': 'Holzkonstruktionen online planen und konstruieren – Pergola, Carport, Dachstuhl & mehr. Gratis im Browser, mit Stückliste und PDF-Export.',
        'og_locale': 'de_DE',
    },
    'en': {
        'title': 'Wood Construction 3D – Plan Timber Structures Online | Free',
        'desc': 'Plan wood constructions online for free: pergola, carport, roof truss & more in 3D – right in your browser, with parts list, cutting plan & PDF export.',
        'keywords': 'wood construction, wood construction 3D, timber construction, timber construction 3D, plan wood construction, design timber structure, wood construction software, wood construction online, timber framing, 3D wood design, pergola, carport, roof truss, online wood planner, parts list, cutting plan',
        'og_title': 'Wood Construction 3D – Plan & design timber structures online',
        'og_desc': 'Plan and design wood constructions online – pergola, carport, roof truss & more. Free in your browser, with parts list and PDF export.',
        'og_locale': 'en_US',
    },
    'fr': {
        'title': 'Construction bois 3D – Concevez vos ossatures en ligne | Gratuit',
        'desc': 'Concevez vos constructions bois en ligne gratuitement : pergola, carport, charpente & plus en 3D – avec liste de pièces, plan de coupe et export PDF.',
        'keywords': 'construction bois, construction bois 3D, ossature bois, charpente 3D, concevoir construction bois, planifier construction bois, logiciel construction bois, construction bois en ligne, plan bois, 3D bois, pergola, carport, charpente, planificateur bois en ligne, liste de pièces, plan de coupe',
        'og_title': 'Construction bois 3D – Concevez vos ossatures en 3D en ligne',
        'og_desc': 'Concevez et planifiez vos constructions bois en ligne – pergola, carport, charpente & plus. Gratuit dans le navigateur, avec liste de pièces et export PDF.',
        'og_locale': 'fr_FR',
    },
}


FAQ_ITEMS = {
    'de': [
        ('Ist HolzBau 3D kostenlos?', 'Ja. Du kannst Holzkonstruktionen kostenlos in 3D planen. Es gibt keine Begrenzung der Bauteilanzahl, du kannst speichern, laden und die Stückliste als CSV exportieren. Premium macht das Planen vielfältiger und schneller: fertige Vorlagen, PDF-, DXF- und CNC-Export, Schnittplan-Optimierung, Kalkulation und Säge-Werkzeug — werbefrei.'),
        ('Kann ich eine Pergola selbst planen?', 'Ja. Mit HolzBau 3D planst du Pergola, Carport, Dachstuhl, Terrassenüberdachung und beliebige Holzkonstruktionen selbst – inklusive Stückliste und Schnittplan.'),
        ('Muss ich etwas installieren?', 'Nein. HolzBau 3D läuft komplett im Browser – ohne Installation, auf PC, Tablet und Smartphone.'),
        ('Welche Konstruktionen kann ich bauen?', 'Vom Carport über die Pergola bis zum kompletten Dachstuhl: Du setzt Balken, Pfosten, Pfetten und Sparren maßstabsgetreu in 3D und drehst die Konstruktion frei im Raum.'),
        ('Bekomme ich eine Stückliste?', 'Ja. HolzBau 3D erzeugt automatisch eine Stückliste mit allen Balken, Längen und Querschnitten. Als Premium-Nutzer exportierst du sie als CSV und PDF.'),
        ('In welchen Sprachen ist HolzBau 3D verfügbar?', 'HolzBau 3D gibt es auf Deutsch, Englisch und Französisch – die Sprache wechselst du jederzeit mit einem Klick.'),
        ('Kann ich Premium kündigen?', 'Ja, jederzeit. Du kündigst dein Premium-Abo mit einem Klick im Bereich „Mein Abonnement". Es gibt keine Mindestlaufzeit und keine Kündigungsfrist.'),
        ('Bekomme ich mein Geld zurück?', 'Nein, bereits gezahlte Beträge werden nicht erstattet. Stattdessen behältst du nach der Kündigung deinen vollen Premium-Zugang bis zum Ende des bezahlten Zeitraums – danach wird das Abo einfach nicht verlängert.'),
    ],
    'en': [
        ('Is HolzBau 3D free?', 'Yes. You can plan wood constructions in 3D for free. There is no limit on the number of parts, and you can save, load and export the parts list as CSV. Premium makes planning richer and faster: ready-made templates, PDF, DXF and CNC export, cutting-plan optimisation, costing and the saw tool — ad-free.'),
        ('Can I design a pergola myself?', 'Yes. With HolzBau 3D you design pergolas, carports, roof trusses, patio roofs and any wood construction yourself – including parts list and cutting plan.'),
        ('Do I need to install anything?', 'No. HolzBau 3D runs entirely in your browser – no installation, on PC, tablet and smartphone.'),
        ('What can I build?', 'From a carport and a pergola to a complete roof truss: you place beams, posts, purlins and rafters to scale in 3D and rotate the structure freely in space.'),
        ('Do I get a parts list?', 'Yes. HolzBau 3D automatically generates a parts list with all beams, lengths and sections. As a Premium user you export it as CSV and PDF.'),
        ('Which languages does HolzBau 3D support?', 'HolzBau 3D is available in German, English and French – switch the language any time with one click.'),
        ('Can I cancel Premium?', 'Yes, any time. You cancel your Premium subscription with one click under "My subscription". There is no minimum term and no notice period.'),
        ('Do I get a refund?', 'No, amounts already paid are not refunded. Instead, after cancelling you keep full Premium access until the end of the paid period – the subscription is then simply not renewed.'),
    ],
    'fr': [
        ('HolzBau 3D est-il gratuit ?', 'Oui. Vous pouvez concevoir des constructions bois en 3D gratuitement. Le nombre de pièces n’est pas limité, et vous pouvez enregistrer, charger et exporter la liste de pièces en CSV. Premium rend la conception plus riche et plus rapide : modèles prêts à l’emploi, export PDF, DXF et CNC, optimisation du plan de coupe, chiffrage et outil scie — sans publicité.'),
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


# Sichtbarer Text der Startseite, je Sprache. Kommt bewusst vom SERVER:
# /en und /fr sind sprachgezielte SEO-Seiten, und Google bewertet das
# ausgelieferte HTML. Vorher stand hier fest deutscher Text, den erst die
# Client-Uebersetzung haette ersetzen muessen — fuer die meisten Texte fehlten
# die Woerterbuch-Eintraege aber ganz, so dass /en und /fr weitgehend deutsch
# waren (55 Passagen auf der Live-Seite nachgemessen).
# Schluessel mit _html enthalten Markup und brauchen im Template |safe.
LANDING_TXT = {
    'de': {
        'nav_features': 'Features',
        'nav_preise': 'Preise',
        'nav_ratgeber': 'Ratgeber',
        'nav_faq': 'FAQ',
        'nav_anmelden': 'Anmelden',
        'nav_start': 'Kostenlos starten',
        'hero_badge': '🪵 Browser-basiert · Keine Installation',
        'hero_h1_html': 'Holzbau in <em>3D</em>:<br>Holzkonstruktion&nbsp;<span class="hero-ul">online</span> planen',
        'hero_sub': 'Mit HolzBau 3D planst und konstruierst du deine Holzkonstruktion direkt im Browser – Pergola, Carport, Dachstuhl oder jede andere Konstruktion aus Holz. Stückliste auf Knopfdruck, präzise 3D-Ansicht, sofort bereit ohne Installation.',
        'hero_cta1': 'Kostenlos testen',
        'hero_cta2': 'Preise & Abos ansehen',
        'mock_ansicht': '3D-Ansicht · frei drehbar',
        'mock_p1': 'Pfosten 100×100 mm · 4 Stk — 2,40 m',
        'mock_p2': 'Pfette 120×80 mm · 2 Stk — 2,80 m',
        'mock_p3': 'Pfette 120×80 mm · 2 Stk — 2,00 m',
        'mock_p4': 'Sparren 60×40 mm · 4 Stk — 2,00 m',
        'mock_gesamt': 'Gesamt: 27,20 lfm',
        'mock_werkzeug1': 'Auswählen',
        'mock_werkzeug2': 'Verschieben',
        'mock_d1': '2,80 m',
        'mock_d2': '2,00 m',
        'mock_d3': '2,40 m',
        'feat_eyebrow': 'Features',
        'feat_h2': 'Alles was du brauchst',
        'feat_lead': 'Von der ersten Idee über die Materialkosten bis zum fertigen Zuschnitt — HolzBau 3D begleitet dein gesamtes Projekt.',
        'feat_neu': 'Neu',
        'f1_t': '3D Visualisierung',
        'f1_p': 'Interaktive 3D-Ansicht deiner Holzkonstruktion direkt im Browser. Drehen, zoomen, inspizieren — ohne Plugin oder Installation.',
        'f2_t': 'Grundriss als Vorlage',
        'f2_p': 'Grundriss-Foto, Scan oder Plan laden, per bekannter Strecke maßhaltig kalibrieren und die Konstruktion einfach darüber nachzeichnen.',
        'f3_t': 'Vorlagen nach Maß',
        'f3_p': 'Carport, Pergola, Gartenhaus oder Terrassendach: einfach Maße eingeben und die komplette Konstruktion wird automatisch erzeugt — durchgerechnet statt hingestellt. Pfetten liegen auf den Stützen, Sparren sitzen mit einer Kerve auf, Ecken sind verblattet, Kopfbänder steifen aus. Kein Bauteil steckt im anderen. Dazu zwei fertige Erdgeschosswohnungen zum Laden und Weiterbauen, klassisch und architektonisch: Ständerwerk im 625er Raster, Stürze, Brüstungsriegel und OSB-Beplankung mit Fensterausschnitten. Jede Wand liegt in einer eigenen Gruppe — ausblenden und du siehst, wie sie innen aufgebaut ist. Die Pergola kannst du ohne Abo erzeugen.',
        'f4_t': 'Materialkosten & Angebot',
        'f4_p': 'Sofort sehen, was dein Projekt kostet. Preise je Holzart pflegen und ein fertiges Angebots-PDF mit eigenem Briefkopf erstellen.',
        'f5_t': 'Verschnitt-Optimierung',
        'f5_p': 'Zuschnittpläne für Balken (1D) und 2D-Plattenzuschnitt für OSB/Sperrholz wie bei Cutlist Optimizer — inkl. Sägeblattbreite und Restholz.',
        'f6_t': 'Ausfräsungen & CNC',
        'f6_p': 'Aussparungen per Maus auf der Platte platzieren; überlappende Löcher verschmelzen zu komplexen Formen. Als echtes 3D-Loch — und als CNC-Fräsplan (DXF, 1:1) direkt für die Fräse exportierbar.',
        'f7_t': 'Stückliste, CSV & DXF',
        'f7_p': 'Automatische Stückliste als CSV, bemaßte Einzelteil-Zeichnungen und DXF-Export der Planansichten — bereit für Werkstatt und CAD.',
        'f8_t': 'Querschnitts-Assistent',
        'f8_p': 'Aus Spannweite und Achsabstand einen sinnvollen Holzquerschnitt vorgeschlagen bekommen — nimmt dir das Raten ab.',
        'f9_t': 'Maßstabsgetreuer Druck',
        'f9_p': 'Druckfertige Pläne als PDF im echten Maßstab (1:1 bis 1:100) — 1:1 sogar als Schablone direkt aufs Holz. Für Bauantrag oder Werkstatt.',
        'f10_t': 'Holzverbindungen',
        'f10_p': 'Auflager, Überblattung, Zapfen mit vierseitiger Schulter und Sackloch — als echte Geometrie, nicht angedeutet, sondern zugeschnitten. Das Zapfenloch wird genau so tief wie der Zapfen dick ist, nicht quer durch das ganze Bauteil. Ein Bauteil markieren genügt: es wird an alles angepasst, was es berührt, und nur es selbst wird eingeschnitten. Werkstattzeichnung und DXF zeigen danach das Bauteil, nicht mehr den Rohling.',
        'f11_t': 'Kollisionsprüfung',
        'f11_p': 'Einschalten und dranlassen: überall dort, wo zwei Bauteile denselben Raum belegen, wird genau dieser Bereich rot — auch tief in der Konstruktion. Eine Überschneidung von 40 mm sieht man im 3D nicht, auf der Baustelle schon.',
        'f12_t': 'Projekte online & teilen',
        'f12_p': 'Projekte auf dem Server speichern und am nächsten Gerät weiterarbeiten. Zum Zeigen einen Ansehen-Link erzeugen — nur für die E-Mail-Adressen, die du freischaltest, 7 Tage gültig, danach löscht er sich selbst.',
        'bsp_eyebrow': 'Beispiele',
        'bsp_h2': 'Was du bauen kannst',
        'bsp_lead': 'Von der Pergola bis zum Dachstuhl — HolzBau 3D deckt alle gängigen Holzkonstruktionen ab.',
        'bsp_3d': 'In 3D drehen',
        'v3d_laedt': 'Lädt …',
        'v3d_fehler': '3D-Ansicht nicht verfügbar.',
        'v3d_erneut': '↻ Erneut versuchen',
        'b1_t': 'Pergola',
        'b1_p': 'Klassische Pergola mit Längs- und Querbalken. Ideal für Garten und Terrasse.',
        'b1_s': '19 Balken · 3,0 × 4,0 m · 0,60 m³',
        'b2_t': 'Carport',
        'b2_p': 'Pultdach-Carport mit Auto-Objekt — so siehst du sofort, ob dein Wagen reinpasst.',
        'b2_s': '16 Balken · 3,0 × 5,0 m · 0,70 m³',
        'b3_t': 'Wand mit Fenster',
        'b3_p': 'Ständerwerk mit Fensterwechsel, Sturz und einseitiger OSB-Beplankung.',
        'b3_s': '17 Teile · 3,6 × 2,6 m · 9,4 m² OSB',
        'b4_t': 'Dachstuhl',
        'b4_p': 'Satteldach mit Sparren, Pfetten und Firstpfette — die Basis jedes Dachs.',
        'b4_s': '15 Teile · 6,0 × 6,0 m · 1,09 m³',
        'b1_alt': 'Pergola — in HolzBau 3D geplant und gerendert',
        'b2_alt': 'Carport — in HolzBau 3D geplant und gerendert',
        'b3_alt': 'Wand mit Fenster — in HolzBau 3D geplant und gerendert',
        'b4_alt': 'Dachstuhl — in HolzBau 3D geplant und gerendert',
        'pr_eyebrow': 'Preise',
        'pr_h2': 'Einfache, faire Preise',
        'pr_lead': 'Kostenlos planen — ohne Limit bei der Größe. Premium macht es vielfältiger, einfacher und schneller. Monatlich kündbar, keine Bindung.',
        'pr_free_desc': 'Voll nutzbar · mit Werbung',
        'pr_free_f1': '✓ 3D-Planer mit Gruppen & Ebenen',
        'pr_free_f2': '✓ Als Datei speichern (unbegrenzt) · 1 Projekt online',
        'pr_free_f3': '✓ Stückliste als CSV',
        'pr_free_f4': '⚠ Mit Werbung',
        'pr_free_f5': '✗ PDF-, DXF- & CNC-Export',
        'pr_free_f6': '✗ Vorlagen, Säge & Schnittplan',
        'pr_free_cta': 'Kostenlos starten',
        'pr_mon_desc': 'Werbefrei · schneller & einfacher planen',
        'pr_mon_cta': 'Monatlich starten',
        'pr_monat': '/Monat',
        'pr_jahr': '/Jahr',
        'pr_save': '🎉 Spare 19,89 €',
        'pr_badge': 'Meistgewählt',
        'pr_year_name': 'Premium Jährlich',
        'pr_year_desc': '= 8,33 €/Monat · 2 Monate gratis',
        'pr_year_cta': 'Jährlich starten',
        'pr_f1': '✓ 50 Projekte online · unbegrenzt als Datei · Vorlagen nach Maß',
        'pr_f2': '✓ Materialkosten & Angebots-PDF',
        'pr_f3': '✓ Schnittplan, 2D-Plattenzuschnitt & Ausfräsungen',
        'pr_f4': '✓ Stückliste als CSV, DXF & Druck-PDF',
        'pr_f5_html': '✓ <strong>Vollständig werbefrei</strong>',
        'pr_f6': '✓ Prioritäts-Support',
        'fu_ueber': 'Über uns',
        'fu_login': 'Login',
        'fu_impressum': 'Impressum',
        'fu_datenschutz': 'Datenschutz',
        'fu_agb': 'Nutzungsbedingungen',
        'fu_widerruf': 'Widerruf',
        'fu_cookies': 'Cookie-Einstellungen',
    },
    'en': {
        'nav_features': 'Features',
        'nav_preise': 'Pricing',
        'nav_ratgeber': 'Guides',
        'nav_faq': 'FAQ',
        'nav_anmelden': 'Log in',
        'nav_start': 'Start for free',
        'hero_badge': '🪵 Browser-based · No installation',
        'hero_h1_html': 'Wood construction in <em>3D</em>:<br>Plan your timber structure&nbsp;<span class="hero-ul">online</span>',
        'hero_sub': 'With HolzBau 3D you plan and design your wood construction right in the browser – pergola, carport, roof truss or any other timber structure. Parts list at the push of a button, precise 3D view, ready to go with no installation.',
        'hero_cta1': 'Try it free',
        'hero_cta2': 'See pricing & plans',
        'mock_ansicht': '3D view · rotate freely',
        'mock_p1': 'Post 100×100 mm · 4 pcs — 2.40 m',
        'mock_p2': 'Purlin 120×80 mm · 2 pcs — 2.80 m',
        'mock_p3': 'Purlin 120×80 mm · 2 pcs — 2.00 m',
        'mock_p4': 'Rafter 60×40 mm · 4 pcs — 2.00 m',
        'mock_gesamt': 'Total: 27.20 lin m',
        'mock_werkzeug1': 'Select',
        'mock_werkzeug2': 'Move',
        'mock_d1': '2.80 m',
        'mock_d2': '2.00 m',
        'mock_d3': '2.40 m',
        'feat_eyebrow': 'Features',
        'feat_h2': 'Everything you need',
        'feat_lead': 'From the first idea through material costs to the finished cutting plan — HolzBau 3D is with you for the whole project.',
        'feat_neu': 'New',
        'f1_t': '3D visualization',
        'f1_p': 'Interactive 3D view of your timber structure right in the browser. Rotate, zoom, inspect — no plugin, no installation.',
        'f2_t': 'Floor plan as a template',
        'f2_p': 'Load a floor plan photo, scan or drawing, calibrate it to true scale using a known distance and simply trace your structure over it.',
        'f3_t': 'Templates made to measure',
        'f3_p': 'Carport, pergola, garden shed or patio roof: just enter the dimensions and the complete structure is generated automatically — worked out, not just placed. Purlins rest on the posts, rafters are birdsmouthed onto them, corners are half-lapped, knee braces stiffen the frame. No part sits inside another. Plus two ready-made ground-floor apartments to load and build on, classic and architectural: studs on a 625 mm grid, lintels, sill rails and OSB sheathing with window cut-outs. Every wall sits in its own group — hide it and you see how it is built inside. The pergola is free — no subscription needed.',
        'f4_t': 'Material costs & quotes',
        'f4_p': 'See instantly what your project costs. Keep prices per timber type up to date and create a finished quote PDF with your own letterhead.',
        'f5_t': 'Cutting optimization',
        'f5_p': 'Cutting plans for beams (1D) and 2D panel cutting for OSB/plywood just like Cutlist Optimizer — including saw blade kerf and leftover stock.',
        'f6_t': 'Cut-outs & CNC',
        'f6_p': 'Place cut-outs on the panel with the mouse; overlapping holes merge into complex shapes. Shown as a real 3D opening — and exportable as a CNC milling plan (DXF, 1:1) straight to the router.',
        'f7_t': 'Parts list, CSV & DXF',
        'f7_p': 'Automatic parts list as CSV, dimensioned single-part drawings and DXF export of the plan views — ready for the workshop and for CAD.',
        'f8_t': 'Cross-section assistant',
        'f8_p': 'Get a sensible timber cross-section suggested from your span and on-center spacing — no more guesswork.',
        'f9_t': 'True-to-scale printing',
        'f9_p': 'Print-ready plans as PDF at true scale (1:1 to 1:100) — at 1:1 even as a full-size template straight onto the timber. For your building permit application or the workshop.',
        'f10_t': 'Timber joints',
        'f10_p': 'Bearing notch, halved lap, and a tenon with a four-sided shoulder and blind mortise — as real geometry, actually cut, not just hinted at. The mortise is cut exactly as deep as the tenon is thick, no longer straight through the whole part. Select a single part: it is fitted to everything it touches, and only it gets cut. Workshop drawings and DXF then show the part, not the blank.',
        'f11_t': 'Clash detection',
        'f11_p': 'Switch it on and leave it on: wherever two parts occupy the same space, exactly that region turns red — even deep inside the structure. A 40 mm overlap is invisible in 3D, but not on site.',
        'f12_t': 'Projects online & sharing',
        'f12_p': 'Save projects on the server and carry on at the next device. Create a view link to show your work — only for the e-mail addresses you allow, valid for 7 days, then deleted automatically.',
        'bsp_eyebrow': 'Examples',
        'bsp_h2': 'What you can build',
        'bsp_lead': 'From a pergola to a roof truss — HolzBau 3D covers every common timber structure.',
        'bsp_3d': 'Rotate in 3D',
        'v3d_laedt': 'Loading …',
        'v3d_fehler': '3D view not available.',
        'v3d_erneut': '↻ Try again',
        'b1_t': 'Pergola',
        'b1_p': 'Classic pergola with lengthwise and cross beams. Ideal for the garden and the patio.',
        'b1_s': '19 beams · 3.0 × 4.0 m · 0.60 m³',
        'b2_t': 'Carport',
        'b2_p': 'Mono-pitch carport with a car object — so you can see straight away whether your car fits.',
        'b2_s': '16 beams · 3.0 × 5.0 m · 0.70 m³',
        'b3_t': 'Wall with window',
        'b3_p': 'Stud frame with window framing, lintel and OSB sheathing on one side.',
        'b3_s': '17 parts · 3.6 × 2.6 m · 9.4 m² OSB',
        'b4_t': 'Roof truss',
        'b4_p': 'Gable roof with rafters, purlins and a ridge purlin — the basis of every roof.',
        'b4_s': '15 parts · 6.0 × 6.0 m · 1.09 m³',
        'b1_alt': 'Pergola — timber structure planned and rendered in HolzBau 3D',
        'b2_alt': 'Carport — timber carport structure planned and rendered in HolzBau 3D',
        'b3_alt': 'Wall with window — timber stud frame planned and rendered in HolzBau 3D',
        'b4_alt': 'Roof truss — timber roof structure planned and rendered in HolzBau 3D',
        'pr_eyebrow': 'Pricing',
        'pr_h2': 'Simple, fair pricing',
        'pr_lead': 'Plan for free — no limit on size. Premium makes it richer, easier and faster. Cancel any month, no lock-in.',
        'pr_free_desc': 'Fully usable · with ads',
        'pr_free_f1': '✓ 3D planner with groups & layers',
        'pr_free_f2': '✓ Save as a file (unlimited) · 1 project online',
        'pr_free_f3': '✓ Parts list as CSV',
        'pr_free_f4': '⚠ With ads',
        'pr_free_f5': '✗ PDF, DXF & CNC export',
        'pr_free_f6': '✗ Templates, saw & cutting plan',
        'pr_free_cta': 'Start for free',
        'pr_mon_desc': 'Ad-free · plan faster & more easily',
        'pr_mon_cta': 'Start monthly',
        'pr_monat': '/month',
        'pr_jahr': '/year',
        'pr_save': '🎉 Save €19.89',
        'pr_badge': 'Most popular',
        'pr_year_name': 'Premium Yearly',
        'pr_year_desc': '= €8.33/month · 2 months free',
        'pr_year_cta': 'Start yearly',
        'pr_f1': '✓ 50 projects online · unlimited as files · templates made to measure',
        'pr_f2': '✓ Material costs & quote PDF',
        'pr_f3': '✓ Cutting plan, 2D panel cutting & cut-outs',
        'pr_f4': '✓ Parts list as CSV, DXF & print PDF',
        'pr_f5_html': '✓ <strong>Completely ad-free</strong>',
        'pr_f6': '✓ Priority support',
        'fu_ueber': 'About us',
        'fu_login': 'Login',
        'fu_impressum': 'Imprint',
        'fu_datenschutz': 'Privacy',
        'fu_agb': 'Terms of Use',
        'fu_widerruf': 'Right of Withdrawal',
        'fu_cookies': 'Cookie Settings',
    },
    'fr': {
        'nav_features': 'Fonctionnalités',
        'nav_preise': 'Tarifs',
        'nav_ratgeber': 'Conseils',
        'nav_faq': 'FAQ',
        'nav_anmelden': 'Connexion',
        'nav_start': 'Démarrer gratuitement',
        'hero_badge': '🪵 Dans le navigateur · Sans installation',
        'hero_h1_html': 'La construction bois en <em>3D</em> :<br>concevez votre ossature&nbsp;<span class="hero-ul">en ligne</span>',
        'hero_sub': "Avec HolzBau 3D, vous concevez et planifiez votre construction bois directement dans le navigateur – pergola, carport, charpente ou toute autre structure en bois. Liste de pièces en un clic, vue 3D précise, prêt à l'emploi sans installation.",
        'hero_cta1': 'Essayer gratuitement',
        'hero_cta2': 'Voir les tarifs & abonnements',
        'mock_ansicht': 'Vue 3D · rotation libre',
        'mock_p1': 'Poteau 100×100 mm · 4 pcs — 2,40 m',
        'mock_p2': 'Panne 120×80 mm · 2 pcs — 2,80 m',
        'mock_p3': 'Panne 120×80 mm · 2 pcs — 2,00 m',
        'mock_p4': 'Chevron 60×40 mm · 4 pcs — 2,00 m',
        'mock_gesamt': 'Total : 27,20 ml',
        'mock_werkzeug1': 'Sélectionner',
        'mock_werkzeug2': 'Déplacer',
        'mock_d1': '2,80 m',
        'mock_d2': '2,00 m',
        'mock_d3': '2,40 m',
        'feat_eyebrow': 'Fonctionnalités',
        'feat_h2': 'Tout ce dont vous avez besoin',
        'feat_lead': "De la première idée au coût des matériaux jusqu'au plan de coupe final — le logiciel de construction bois HolzBau 3D accompagne l'ensemble de votre projet.",
        'feat_neu': 'Nouveau',
        'f1_t': 'Visualisation 3D',
        'f1_p': 'Vue 3D interactive de votre construction bois directement dans le navigateur. Tournez, zoomez, inspectez — sans plugin ni installation.',
        'f2_t': 'Le plan au sol comme modèle',
        'f2_p': "Chargez une photo, un scan ou un plan au sol, calibrez-le à l'échelle grâce à une distance connue et redessinez simplement votre construction par-dessus.",
        'f3_t': 'Modèles sur mesure',
        'f3_p': 'Carport, pergola, abri de jardin ou toit de terrasse : saisissez vos dimensions et la construction complète est générée automatiquement — calculée, pas simplement posée. Les pannes reposent sur les poteaux, les chevrons sont entaillés dessus, les angles sont mi-bois, les aisseliers contreventent. Aucune pièce ne traverse une autre. En plus, deux appartements de plain-pied prêts à charger et à compléter, classique et architectural : montants au pas de 625 mm, linteaux, traverses d\'allège et panneaux OSB avec découpes de fenêtres. Chaque mur est dans son propre groupe — masquez-le et vous voyez comment il est construit à l\'intérieur. La pergola est gratuite, sans abonnement.',
        'f4_t': 'Coût des matériaux & devis',
        'f4_p': 'Voyez immédiatement ce que coûte votre projet. Gérez les prix par essence de bois et créez un devis PDF complet avec votre propre en-tête.',
        'f5_t': 'Optimisation des chutes',
        'f5_p': 'Plans de coupe pour les poutres (1D) et débit de panneaux 2D pour OSB/contreplaqué comme dans Cutlist Optimizer — largeur de lame et bois restant inclus.',
        'f6_t': 'Évidements & CNC',
        'f6_p': 'Placez les évidements à la souris sur le panneau ; les trous qui se chevauchent fusionnent en formes complexes.',
        'f7_t': 'Liste de pièces, CSV & DXF',
        'f7_p': "Liste de pièces automatique en CSV, dessins cotés de chaque pièce et export DXF des vues en plan — prêts pour l'atelier et la CAO.",
        'f8_t': 'Assistant de section',
        'f8_p': "Obtenez une section de bois pertinente à partir de la portée et de l'entraxe — fini les approximations.",
        'f9_t': "Impression à l'échelle",
        'f9_p': "Plans prêts à imprimer en PDF à l'échelle réelle (1:1 à 1:100) — le 1:1 sert même de gabarit à poser sur le bois. Pour le permis de construire ou l'atelier.",
        'f10_t': 'Assemblages bois',
        'f10_p': "Appui entaillé, mi-bois et tenon à épaulement sur quatre faces avec mortaise borgne — en géométrie réelle, vraiment découpés. La mortaise est exactement aussi profonde que le tenon est épais, plus de traversée complète de la pièce. Sélectionne une seule pièce : elle s'ajuste à tout ce qu'elle touche, et elle seule est entaillée. Le plan d'atelier et le DXF montrent ensuite la pièce, plus le brut.",
        'f11_t': 'Détection de collisions',
        'f11_p': "Active-la et laisse-la : partout où deux pièces occupent le même espace, cette zone précise devient rouge — même au cœur de la structure. Un chevauchement de 40 mm ne se voit pas en 3D, sur le chantier si.",
        'f12_t': 'Projets en ligne & partage',
        'f12_p': "Enregistre tes projets sur le serveur et continue sur un autre appareil. Crée un lien de consultation — réservé aux adresses e-mail que tu autorises, valable 7 jours, puis supprimé automatiquement.",
        'bsp_eyebrow': 'Exemples',
        'bsp_h2': 'Ce que vous pouvez construire',
        'bsp_lead': 'De la pergola à la charpente — HolzBau 3D couvre toutes les constructions bois courantes.',
        'bsp_3d': 'Tourner en 3D',
        'v3d_laedt': 'Chargement …',
        'v3d_fehler': 'Vue 3D indisponible.',
        'v3d_erneut': '↻ Réessayer',
        'b1_t': 'Pergola',
        'b1_p': 'Pergola classique avec poutres longitudinales et transversales. Idéale pour le jardin et la terrasse.',
        'b1_s': '19 poutres · 3,0 × 4,0 m · 0,60 m³',
        'b2_t': 'Carport',
        'b2_p': 'Carport à toit monopente avec objet voiture — vous voyez tout de suite si votre véhicule rentre.',
        'b2_s': '16 poutres · 3,0 × 5,0 m · 0,70 m³',
        'b3_t': 'Mur avec fenêtre',
        'b3_p': 'Ossature avec chevêtre de fenêtre, linteau et panneaux OSB sur une face.',
        'b3_s': '17 pièces · 3,6 × 2,6 m · 9,4 m² OSB',
        'b4_t': 'Charpente',
        'b4_p': 'Toit à deux pans avec chevrons, pannes et panne faîtière — la base de tout toit.',
        'b4_s': '15 pièces · 6,0 × 6,0 m · 1,09 m³',
        'b1_alt': 'Pergola en bois — conçue et rendue en 3D avec HolzBau 3D',
        'b2_alt': 'Carport en bois — conçu et rendu en 3D avec HolzBau 3D',
        'b3_alt': 'Mur à ossature bois avec fenêtre — conçu et rendu en 3D avec HolzBau 3D',
        'b4_alt': 'Charpente bois — conçue et rendue en 3D avec HolzBau 3D',
        'pr_eyebrow': 'Tarifs',
        'pr_h2': 'Des tarifs simples et justes',
        'pr_lead': 'Concevez gratuitement — sans limite de taille. Premium rend la planification plus riche, plus simple et plus rapide. Résiliable chaque mois, sans engagement.',
        'pr_free_desc': 'Pleinement utilisable · avec publicité',
        'pr_free_f1': '✓ Planificateur 3D avec groupes & calques',
        'pr_free_f2': '✓ Enregistrer en fichier (illimité) · 1 projet en ligne',
        'pr_free_f3': '✓ Liste de pièces en CSV',
        'pr_free_f4': '⚠ Avec publicité',
        'pr_free_f5': '✗ Export PDF, DXF & CNC',
        'pr_free_f6': '✗ Modèles, scie & plan de coupe',
        'pr_free_cta': 'Démarrer gratuitement',
        'pr_mon_desc': 'Sans publicité · concevoir plus vite et plus simplement',
        'pr_mon_cta': 'Choisir le mensuel',
        'pr_monat': '/mois',
        'pr_jahr': '/an',
        # MUSS kurz bleiben (<= ~110px): der Chip sitzt links neben 'Le plus
        # populaire' auf derselben Hoehe. 'Économisez 19,89 €' war 145px breit
        # und ueberlappte den Badge — beide haben denselben Hintergrund, es sah
        # daher nicht kaputt aus, sondern nach EINER Pille mit abgeschnittenem
        # Betrag: '🎉 Économisez 1'. Also ein falscher Preis auf der Preisseite.
        'pr_save': '🎉 −19,89 €',
        'pr_badge': 'Le plus populaire',
        'pr_year_name': 'Premium annuel',
        'pr_year_desc': '= 8,33 €/mois · 2 mois offerts',
        'pr_year_cta': "Choisir l'annuel",
        'pr_f1': '✓ 50 projets en ligne · illimité en fichier · modèles sur mesure',
        'pr_f2': '✓ Coût des matériaux & devis PDF',
        'pr_f3': '✓ Plan de coupe, débit de panneaux 2D & évidements',
        'pr_f4': "✓ Liste de pièces en CSV, DXF & PDF d'impression",
        'pr_f5_html': '✓ <strong>Totalement sans publicité</strong>',
        'pr_f6': '✓ Support prioritaire',
        'fu_ueber': 'À propos',
        'fu_login': 'Connexion',
        'fu_impressum': 'Mentions légales',
        'fu_datenschutz': 'Confidentialité',
        'fu_agb': "Conditions d'utilisation",
        'fu_widerruf': 'Droit de rétractation',
        'fu_cookies': 'Paramètres des cookies',
    },
}


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
        # Sichtbarer Text der Startseite in der Sprache der Route — im Template L.<schluessel>
        'L': LANDING_TXT.get(lang, LANDING_TXT['de']),
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


@app.route('/figures/<slug>.svg')
def figure_svg(slug):
    """Artikel-eigenes Diagramm als eigenstaendige SVG-Datei — fuers JSON-LD-
    und og:image. So hat jeder Artikel ein passendes Bild statt fuer alle
    dasselbe og-image.png."""
    key = _figures.hero_key(slug)
    if not key:
        abort(404)
    # XML-Deklaration nur fuer die EIGENSTAENDIGE Datei (Scraper/als Bild geladen);
    # INLINE im Artikel darf sie NICHT stehen, dort kommt die Figur ohne Prolog.
    svg = '<?xml version="1.0" encoding="UTF-8"?>\n' + _figures._F[key][0]()
    resp = app.response_class(svg, mimetype='image/svg+xml')
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


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
  <url><loc>{SITE}/demo</loc><changefreq>monthly</changefreq><priority>0.9</priority></url>
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
# Fuer E-Mails: die laufen serverseitig, dorthin kommt static/i18n.js nie. Auf
# der Profilseite uebersetzt der Browser die deutschen Labels von oben; eine
# Mail wuerde sonst "Status: Erledigt" mitten im englischen Text zeigen.
FEEDBACK_STATUS_I18N = {
    'de': FEEDBACK_STATUS_LABEL,
    'en': {'neu': 'New', 'in_arbeit': 'In progress', 'erledigt': 'Done', 'abgelehnt': 'Declined'},
    'fr': {'neu': 'Nouveau', 'in_arbeit': 'En cours', 'erledigt': 'Terminé', 'abgelehnt': 'Refusé'},
}


def _status_label(status, lang='de'):
    return FEEDBACK_STATUS_I18N.get(_norm_lang(lang), FEEDBACK_STATUS_LABEL).get(status, status)
# Screenshots kommen als data:-URL aus dem Browser (schon auf 1280px/WebP
# heruntergerechnet). Grosszuegige Obergrenze, damit ein 4K-Monitor nicht
# stumm abgelehnt wird, aber MEDIUMBLOB (16 MB) nicht sprengt.
FEEDBACK_MAX_IMG = 3 * 1024 * 1024

# Reines Geometrie-JSON ist klein (selbst grosse Aufbauten bleiben unter 1 MB).
# Der Deckel ist nur ein Riegel gegen einen pathologisch grossen Aufbau — und er
# haelt zusammen mit dem Screenshot den 8-MB-Upload (MAX_CONTENT_LENGTH) sicher ein.
FEEDBACK_MAX_PROJECT = 4 * 1024 * 1024

# Liste OHNE den screenshot-BLOB: das Template braucht daraus nur ein Ja/Nein,
# das Bild selbst holt der Browser ueber /feedback/<id>/screenshot nach.
# 'f.*' htte pro Aufruf jedes Bild durch MySQL, PyMySQL und Jinja gezogen.
FB_LIST_SQL = (
    'SELECT f.id, f.user_id, f.kind, f.subject, f.message, f.ctx, f.status, '
    'f.admin_reply, f.created, f.updated, f.screenshot IS NOT NULL AS has_shot, '
    'f.project IS NOT NULL AS has_project, '
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

    # Freiwillig mitgeschicktes Projekt-JSON. Nur speichern, wenn es wirklich JSON
    # ist und den Deckel einhaelt — sonst legt jemand beliebigen Text in die Spalte.
    project = None
    raw_proj = request.form.get('project') or ''
    if raw_proj and len(raw_proj) <= FEEDBACK_MAX_PROJECT:
        try:
            json.loads(raw_proj)
            project = raw_proj
        except Exception:
            project = None

    ctx = (request.form.get('ctx') or '')[:1000]
    execute_db('INSERT INTO feedback (user_id, kind, subject, message, screenshot, shot_mime, ctx, project, status, created) '
               'VALUES (?,?,?,?,?,?,?,?,?,?)',
               [session['user_id'], kind, subject, message, shot, shot_mime, ctx, project, 'neu',
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


@app.route('/feedback/<int:fid>/project')
@login_required
def feedback_project(fid):
    row = query_db('SELECT user_id, project FROM feedback WHERE id=?', [fid], one=True)
    if not row or not row['project']:
        abort(404)
    # Gleiche Schranke wie beim Screenshot: nur der Verfasser oder ein Admin.
    if row['user_id'] != session['user_id'] and session.get('role') != 'admin':
        abort(403)
    return app.response_class(
        row['project'], mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename="feedback_{fid}_projekt.json"'})


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
                                            reply, _status_label(status, u_lang), u_lang))
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
import blog_figures as _figures
import blog_fotos as _fotos


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
    # Technische Diagramme einspeisen — dieselbe Quelle bleibt unveraendert, nur
    # die gerenderte Kopie bekommt die SVGs. Behebt "null Bilder" ohne die grossen
    # Content-Strings anzufassen.
    a = dict(a)
    a['body_html'] = _figures.inject(a['body_html'], slug, lang)
    # Echtes Projektfoto (falls hinterlegt) ganz oben einblenden — staerkstes
    # E-E-A-T-Signal. Fehlt die Datei, bleibt alles unveraendert.
    a['body_html'] = _fotos.inject(a['body_html'], slug, lang, app.static_folder, SITE)
    # Artikel-eigenes Bild fuers JSON-LD/OG. Reihenfolge: echtes Foto > Diagramm-
    # SVG > allgemeines og-image.
    hero = _figures.hero_key(slug)
    if _fotos.vorhanden(app.static_folder, slug):
        bild_url = _fotos.bild_url(SITE, slug)
    elif hero:
        bild_url = SITE + '/figures/' + slug + '.svg'
    else:
        bild_url = SITE + '/static/og-image.png'
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
        'image': bild_url,
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
        if not user and '@' in username:
            # Sehr haeufige Falle: Das Zuruecksetzen des Passworts laeuft ueber die
            # E-Mail — danach tippt fast jeder auch beim Anmelden seine E-Mail ein
            # und scheitert, weil hier nur der Benutzername gesucht wurde. Nach
            # fuenf Versuchen sperrt ihn dann auch noch die Fehlversuchszaehlung.
            # Darum: sieht die Eingabe nach einer E-Mail aus, hilfsweise danach suchen.
            treffer = query_db("SELECT * FROM app_users WHERE LOWER(email) = LOWER(?) "
                               "ORDER BY id LIMIT 2", (username,))
            # Nur bei EINDEUTIGEM Treffer anmelden. Die E-Mail hat keine
            # UNIQUE-Bedingung in der Tabelle (nur eine Pruefung bei der
            # Registrierung) — bei zwei Konten mit derselben Adresse duerfen wir
            # nicht raten, welches gemeint ist.
            if len(treffer) == 1:
                user = treffer[0]

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
            # prev_login MUSS den alten last_login uebernehmen, BEVOR dieser
            # ueberschrieben wird — in einer Anweisung, sonst geht der Vorwert
            # verloren. MySQL wertet die SET-Ausdruecke von links nach rechts
            # aus, darum steht prev_login zuerst.
            execute_db("UPDATE app_users SET prev_login = last_login, last_login = NOW(), "
                       "login_count = login_count + 1 WHERE id = ?", (user['id'],))
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

        # Seit dem UNIQUE-Index auf email kann die Datenbank die Anlage abweisen.
        # Das passiert genau dann, wenn zwei Anmeldungen mit derselben Adresse
        # gleichzeitig durch die Pruefung oben gerutscht sind — genau die Luecke,
        # die der Index schliesst. Ohne dieses except saehe der Zweite einen
        # Serverfehler statt einer verstaendlichen Meldung.
        try:
            execute_db(
                "INSERT INTO app_users "
                "(username, password_hash, full_name, email, email_verified, email_verify_token, email_verify_expires, lang) "
                "VALUES (?,?,?,?,0,?,?,?)",
                (username, generate_password_hash(password), full_name, email, verify_token, verify_expires, user_lang)
            )
        except Exception as e:
            logger.warning('Registrierung abgewiesen (vermutlich Dublette): %s', type(e).__name__)
            flash('Dieser Benutzername oder diese E-Mail-Adresse ist bereits vergeben.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf())

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
    # Die Bestaetigung meldet direkt an — das ist der ERSTE Login und muss
    # mitgezaehlt werden, sonst steht bei jedem neuen Konto 0 und die Zahl
    # "war schon mal wieder da" haette einen systematischen Versatz.
    execute_db("UPDATE app_users SET prev_login = last_login, last_login = NOW(), "
               "login_count = login_count + 1 WHERE id = ?", (user['id'],))
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

        # email_verified=1: Der Link ging an genau diese Adresse — wer ihn
        # anklickt und ein neues Passwort setzt, hat den Zugriff darauf bewiesen.
        # Ohne das bleibt ein unbestaetigtes Konto nach dem Zuruecksetzen weiter
        # ausgesperrt ("Bitte bestaetige zuerst deine E-Mail-Adresse") — mit
        # einem Passwort, das nachweislich stimmt. Das versteht niemand.
        execute_db(
            "UPDATE app_users SET password_hash=?, pw_reset_token=NULL, pw_reset_expires=NULL, "
            "email_verified=1 WHERE id=?",
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
        _nutzerdaten_loeschen(user_id)
        session.clear()
        flash('Dein Konto wurde dauerhaft gelöscht.', 'success')
        return redirect(url_for('index'))

    return render_template('delete_account.html',
                           user=row_to_dict(user) if user else {},
                           is_premium=is_premium,
                           period_end=period_end,
                           csrf_token=generate_csrf())


@app.route('/telemetry/feature', methods=['POST'])
@login_required
def telemetry_feature():
    """Ein Premium-Feature meldet, dass es gerade benutzt wird. Der ENTSCHEIDENDE
    Punkt: der Plan wird HIER server-seitig festgestellt, nicht vom Browser
    uebernommen. Wer IS_PREMIUM im Browser auf true setzt, schaltet die Funktion
    zwar frei — aber diese Zeile bekommt trotzdem plan='free' und der Fall ist
    belegt. Absichtlich sehr genuegsam: kein flash, kein Redirect, Fehler werden
    verschluckt. Telemetrie darf die App nie stoeren."""
    if not validate_csrf(request.form.get('csrf_token', '')):
        return ('', 204)   # still schlucken, nicht 403 — ein Beacon soll nie auffallen
    # Widerspruch zuerst pruefen, VOR jeder Verarbeitung. Ein Schalter, der nur
    # in der Oberflaeche steht, aber den Schreibpfad nicht anhaelt, ist wertlos.
    if _stats_abgelehnt(session['user_id']):
        return ('', 204)
    feature = (request.form.get('feature', '') or '').strip()[:60]
    if not feature:
        return ('', 204)
    # Feste Auswahl statt Durchreichen: der Browser darf nicht bestimmen, was in
    # der Spalte landet. Unbekanntes faellt auf 'used' zurueck — so kann ein
    # alter, noch zwischengespeicherter Editor ohne event weiterhin melden.
    art = (request.form.get('event', '') or '').strip().lower()
    if art not in ('used', 'blocked'):
        art = 'used'
    try:
        plan = get_user_plan(session['user_id'])
        execute_db('INSERT INTO feature_use (user_id, feature, event, plan, used_at) '
                   'VALUES (?, ?, ?, ?, NOW())',
                   [session['user_id'], feature, art, plan])
    except Exception as e:
        logger.warning('feature_use Protokoll fehlgeschlagen: %s', type(e).__name__)
    return ('', 204)


# Was auf der Startseite ueberhaupt gezaehlt werden darf. Die Liste steht
# HIER und nicht im Markup: der Browser darf nicht bestimmen, welche Werte in
# der Spalte landen. Alles Unbekannte faellt lautlos durch — sonst waere der
# offene Endpunkt eine Einladung, die Tabelle mit Phantasie zu fuellen.
LANDING_ZIELE = {
    'nav_start', 'nav_anmelden', 'nav_features', 'nav_preise', 'nav_ratgeber', 'nav_faq',
    'hero_demo', 'hero_preise',
    'preis_free', 'preis_monat', 'preis_jahr',
    'ratgeber_alle',
}
_landing_clicks_limit = {}


@app.route('/telemetry/landing', methods=['POST'])
def telemetry_landing():
    """Ein Klickziel der Startseite meldet sich. OHNE Login und OHNE Kennung.

    Gespeichert wird ausschliesslich ein Zaehler je (Tag, Ziel, Sprache). Es
    gibt kein Feld, ueber das ein Besucher wiedererkennbar waere: keine
    Kennung, keine IP, kein Cookie, keine Uhrzeit unterhalb des Tages. Damit
    liegt kein Personenbezug vor und es braucht kein Einwilligungsbanner.

    Die IP wird fuer die Drosselung fluechtig im Arbeitsspeicher benutzt und
    NIRGENDS gespeichert — ohne sie waere ein offener Zaehl-Endpunkt in fuenf
    Minuten mit erfundenen Zahlen gefuellt.

    Kein CSRF-Merkmal: die Seite ist anonym, ein Token setzte erst ein
    Sitzungs-Cookie — also genau das, was hier vermieden werden soll. Zu
    schuetzen ist ohnehin nichts: es gibt keinen Nutzer, in dessen Namen etwas
    geschaehe. Missbrauch faengt die Weissliste und die Drosselung ab.
    """
    ziel = (request.form.get('ziel', '') or '').strip()[:40]
    if ziel not in LANDING_ZIELE:
        return ('', 204)
    if _check_rate_limit(_landing_clicks_limit, request.remote_addr or '-', 60, window=300):
        return ('', 204)
    # Die Sprache kommt von der SEITE, nicht aus dem Cookie: die Startseite
    # entscheidet sie ueber die Route (/, /en, /fr). Wer auf /en steht und
    # einen deutschen Browser hat, waere ueber _request_lang() falsch gezaehlt
    # worden. Fest auf die drei bekannten Werte geklemmt.
    sprache = (request.form.get('sprache', '') or '').strip().lower()[:5]
    if sprache not in ('de', 'en', 'fr'):
        sprache = 'de'
    try:
        execute_db(
            'INSERT INTO landing_clicks (tag, ziel, sprache, anzahl) '
            'VALUES (CURDATE(), ?, ?, 1) '
            'ON DUPLICATE KEY UPDATE anzahl = anzahl + 1',
            [ziel, sprache])
    except Exception as e:
        logger.warning('landing_clicks fehlgeschlagen (%s: %s)', type(e).__name__, str(e)[:200])
    return ('', 204)


def _stats_abgelehnt(user_id):
    """Hat dieses Konto der Nutzungsstatistik widersprochen?

    Bei Zweifel (Spalte fehlt, DB-Fehler) wird NICHT erfasst — im Zweifel gegen
    die Datenverarbeitung, nicht dafuer.
    """
    try:
        r = query_db('SELECT stats_opt_out FROM app_users WHERE id=?', [user_id], one=True)
        return bool(r and r['stats_opt_out'])
    except Exception as e:
        logger.warning('stats_opt_out nicht lesbar (%s) — im Zweifel nicht erfassen', type(e).__name__)
        return True


@app.route('/profile/set-stats', methods=['POST'])
@login_required
def profile_set_stats():
    """Widerspruch gegen die Nutzungsstatistik (Art. 21 DSGVO) ein-/ausschalten.

    Beim Widerspruch werden die bereits erhobenen Zeilen geloescht — sonst waere
    es nur ein Stopp fuer die Zukunft, und die Datenschutzerklaerung sagt
    ausdruecklich Loeschung zu.
    """
    if not validate_csrf(request.form.get('csrf_token', '')):
        abort(403)
    user_id = session['user_id']
    # Checkbox "Statistik erlauben": nicht angehakt -> Widerspruch
    erlauben = bool(request.form.get('stats_erlauben'))
    execute_db('UPDATE app_users SET stats_opt_out=? WHERE id=?', [0 if erlauben else 1, user_id])
    if not erlauben:
        try:
            execute_db('DELETE FROM feature_use WHERE user_id=?', [user_id])
        except Exception as e:
            logger.error('Statistik-Loeschung fuer Nutzer %s fehlgeschlagen: %s', user_id, type(e).__name__)
        flash('Widerspruch gespeichert. Deine bisherigen Statistikdaten wurden gelöscht.', 'success')
    else:
        flash('Danke — die anonyme Auswertung hilft uns, die App zu verbessern.', 'success')
    return redirect(url_for('profile'))


# ══════════════════════════════════════════════
# PROJEKTE AUF DEM SERVER
# ══════════════════════════════════════════════
# Bis hierher lebte ein Projekt nur als Datei auf dem eigenen Rechner. Das
# bleibt so — unbegrenzt und kostenlos, auch fuer den freien Plan. Der
# Serverspeicher kommt dazu, damit man zwischen Geraeten weiterarbeiten kann.
#
# Warum die Zahlen so sind:
#   - Ein Projekt-JSON mit ein paar tausend Balken liegt im Bereich einiger
#     hundert Kilobyte. 3 MB je Projekt ist grosszuegig und deckelt trotzdem.
#   - 50 statt "unbegrenzt" fuer Premium: fuehlt sich unbegrenzt an, schuetzt
#     aber gegen ein Skript, das die Datenbank vollschreibt.
PROJEKTE_FREI = 1
PROJEKTE_PREMIUM = 50
PROJEKT_MAX_BYTES = 3 * 1024 * 1024


def _projekt_limit(user_id):
    return PROJEKTE_PREMIUM if get_user_plan(user_id) == 'premium' else PROJEKTE_FREI


def _projekt_anzahl(user_id):
    r = query_db('SELECT COUNT(*) AS c FROM projects WHERE user_id=?', [user_id], one=True)
    return (r or {}).get('c', 0) or 0


@app.errorhandler(413)
def _zu_gross(e):
    """Werkzeug wirft 413, BEVOR eine Route laeuft. Fuer die Projekt-Routen muss
    daraus JSON werden — der Editor erwartet JSON und wuerde an einer HTML-Seite
    nur "Serverfehler 413" anzeigen koennen."""
    if request.path.startswith('/projekte/'):
        return jsonify({'fehler': 'Das Projekt ist zu groß für den Server. '
                                  'Als Datei lässt es sich weiterhin speichern.'}), 413
    return e


@app.route('/projekte/liste')
@login_required
def projekte_liste():
    """Liste fuer den Editor. Ohne `daten` — die koennen viele Megabyte sein und
    werden erst beim Oeffnen geholt."""
    user_id = session['user_id']
    rows = query_db('SELECT id, name, groesse, updated_at FROM projects '
                    'WHERE user_id=? ORDER BY updated_at DESC', [user_id]) or []
    limit = _projekt_limit(user_id)
    return jsonify({
        'projekte': [{'id': r['id'], 'name': r['name'], 'groesse': r['groesse'],
                      'geaendert': r['updated_at'].strftime('%d.%m.%Y %H:%M')
                                   if r['updated_at'] else ''} for r in rows],
        'limit': limit,
        'plan': get_user_plan(user_id),
        # Ueber dem Limit (nach einer Kuendigung) bleibt alles LESBAR, nur
        # Speichern ist gesperrt. Die Arbeit von Kunden wird nicht geloescht.
        'gesperrt': len(rows) > limit,
    })


@app.route('/projekte/<int:pid>')
@login_required
def projekt_holen(pid):
    r = query_db('SELECT name, daten FROM projects WHERE id=? AND user_id=?',
                 [pid, session['user_id']], one=True)
    if not r:
        return jsonify({'fehler': 'Projekt nicht gefunden.'}), 404
    return jsonify({'name': r['name'], 'daten': r['daten']})


@app.route('/projekte/speichern', methods=['POST'])
@login_required
def projekt_speichern():
    if not validate_csrf(request.form.get('csrf_token', '')):
        return jsonify({'fehler': 'Sitzung abgelaufen. Bitte die Seite neu laden.'}), 403
    user_id = session['user_id']
    name = (request.form.get('name', '') or '').strip()[:120] or 'Unbenanntes Projekt'
    daten = request.form.get('daten', '') or ''
    if len(daten.encode('utf-8')) > PROJEKT_MAX_BYTES:
        return jsonify({'fehler': 'Das Projekt ist größer als %d MB und lässt sich nicht '
                                  'auf dem Server speichern. Als Datei geht es weiterhin.'
                                  % (PROJEKT_MAX_BYTES // (1024 * 1024))}), 413
    # Nur echtes Projekt-JSON annehmen. Sonst landet Muell in der Spalte, der
    # beim Oeffnen erst im Browser auffaellt.
    try:
        geparst = json.loads(daten)
        if not isinstance(geparst, dict):
            raise ValueError('kein Objekt')
    except Exception:
        return jsonify({'fehler': 'Die Projektdaten sind unlesbar.'}), 400

    pid = request.form.get('id', '')
    anzahl = _projekt_anzahl(user_id)
    limit = _projekt_limit(user_id)
    jetzt = datetime.now()

    if pid:
        # Ueberschreiben. Erlaubt, solange man nicht UEBER dem Limit liegt —
        # sonst koennte ein freies Konto sein einziges Projekt nie mehr sichern.
        vorhanden = query_db('SELECT id FROM projects WHERE id=? AND user_id=?',
                             [pid, user_id], one=True)
        if not vorhanden:
            return jsonify({'fehler': 'Projekt nicht gefunden.'}), 404
        if anzahl > limit:
            return jsonify({'fehler': _projekt_sperrtext(anzahl, limit)}), 403
        execute_db('UPDATE projects SET name=?, daten=?, groesse=?, updated_at=? '
                   'WHERE id=? AND user_id=?',
                   [name, daten, len(daten.encode('utf-8')), jetzt, pid, user_id])
        return jsonify({'id': int(pid), 'name': name})

    if anzahl >= limit:
        return jsonify({'fehler': _projekt_sperrtext(anzahl, limit)}), 403
    execute_db('INSERT INTO projects (user_id, name, daten, groesse, created_at, updated_at) '
               'VALUES (?,?,?,?,?,?)',
               [user_id, name, daten, len(daten.encode('utf-8')), jetzt, jetzt])
    neu = query_db('SELECT id FROM projects WHERE user_id=? ORDER BY id DESC LIMIT 1',
                   [user_id], one=True)
    return jsonify({'id': (neu or {}).get('id'), 'name': name})


def _projekt_sperrtext(anzahl, limit):
    """Eine Meldung fuer beide Faelle — und sie sagt ausdruecklich, dass nichts
    verloren geht. Wer nach einer Kuendigung ueber dem Limit liegt, soll nicht
    fuerchten muessen, dass seine Arbeit weg ist."""
    if anzahl > limit:
        return ('Du hast %d Projekte auf dem Server, dein Plan erlaubt %d. '
                'Alle bleiben lesbar und lassen sich öffnen und als Datei '
                'herunterladen — nur das Speichern ist gesperrt. Lösche ein '
                'Projekt oder wechsle zu Premium.' % (anzahl, limit))
    return ('Dein Plan erlaubt %d Projekt%s auf dem Server. Speichere als Datei, '
            'lösche ein vorhandenes Projekt oder wechsle zu Premium.'
            % (limit, '' if limit == 1 else 'e'))


@app.route('/projekte/<int:pid>/umbenennen', methods=['POST'])
@login_required
def projekt_umbenennen(pid):
    if not validate_csrf(request.form.get('csrf_token', '')):
        return jsonify({'fehler': 'Sitzung abgelaufen.'}), 403
    name = (request.form.get('name', '') or '').strip()[:120]
    if not name:
        return jsonify({'fehler': 'Bitte einen Namen angeben.'}), 400
    execute_db('UPDATE projects SET name=? WHERE id=? AND user_id=?',
               [name, pid, session['user_id']])
    return jsonify({'name': name})


# ── Ansehen-Link ──────────────────────────────────────────────────────────
# Ein Link ohne Anmeldung ist praktisch oeffentlich: er landet in Verlaeufen,
# Messenger-Vorschauen und irgendwann in einem Index. Deshalb drei Regeln:
#   1. Nur auf ausdrueckliche Freigabe je Projekt, jederzeit widerrufbar.
#   2. Das Token ist lang genug, um nicht erraten zu werden.
#   3. WEISSLISTE statt Schwarzliste beim Ausliefern. Eine Schwarzliste
#      ("alles ausser bauvorhaben") wuerde jedes kuenftige Feld automatisch
#      mit veroeffentlichen — genau so entstehen Datenlecks.
SHARE_ERLAUBTE_FELDER = ('version', 'groups', 'beams', 'decos')


def _share_saeubern(roh):
    """Aus dem gespeicherten Projekt wird das, was oeffentlich gezeigt werden
    darf: Geometrie und Gruppen. NICHT dabei sind die Bauvorhaben-Angaben (dort
    steht der ORT) und die Bild-Vorlage."""
    try:
        d = json.loads(roh)
    except Exception:
        return None
    if not isinstance(d, dict):
        return None
    return {k: d[k] for k in SHARE_ERLAUBTE_FELDER if k in d}


def _share_stueckliste(daten):
    """Kurze Stueckliste, gruppiert wie im Editor: gleiche Holzart und gleiche
    Masse zaehlen zusammen. Bewusst hier gerechnet und nicht im Browser — die
    oeffentliche Seite soll ohne den ganzen Editor auskommen."""
    gruppen = {}
    for b in (daten.get('beams') or []):
        if not isinstance(b, dict):
            continue
        try:
            L, B, H = float(b.get('L', 0)), float(b.get('B', 0)), float(b.get('H', 0))
        except (TypeError, ValueError):
            continue
        art = str(b.get('woodType', ''))[:60]
        schluessel = (art, round(L), round(B), round(H))
        g = gruppen.setdefault(schluessel, {'anzahl': 0, 'namen': set()})
        g['anzahl'] += 1
        if b.get('name'):
            g['namen'].add(str(b['name'])[:60])
    raus = []
    for (art, L, B, H), g in gruppen.items():
        raus.append({
            'anzahl': g['anzahl'], 'holz': art, 'l': L, 'b': B, 'h': H,
            'name': ', '.join(sorted(g['namen'])[:3]) or '—',
            'volumen': round(g['anzahl'] * L * B * H / 1e9, 3),   # m3
        })
    raus.sort(key=lambda r: (-r['anzahl'], r['holz']))
    return raus


SHARE_TAGE = 7                  # Gueltigkeit eines Ansehen-Links
SHARE_ZUGANG_TAGE = 7           # so lange bleibt ein bestaetigter Betrachter drin
SHARE_CODE_MINUTEN = 15
SHARE_VERSUCHE = 5


def _share_projekt(token):
    """Projekt zu einem Token — oder None, wenn es keins gibt oder der Link
    abgelaufen ist. Die Ablaufpruefung steht ABSICHTLICH hier und nicht nur im
    Cron: ein abgelaufener Link muss sofort tot sein, auch wenn das Aufraeumen
    noch nicht gelaufen ist."""
    r = query_db('SELECT id, name, daten, share_at FROM projects WHERE share_token=?',
                 [token], one=True)
    if not r or not r['share_at']:
        return None
    if datetime.now() - r['share_at'] > timedelta(days=SHARE_TAGE):
        return None
    return r


def _share_frei(pid, email):
    r = query_db('SELECT id FROM share_access WHERE project_id=? AND email=?',
                 [pid, (email or '').strip().lower()], one=True)
    return bool(r)


@app.route('/projekte/<int:pid>/teilen', methods=['POST'])
@login_required
def projekt_teilen(pid):
    if not validate_csrf(request.form.get('csrf_token', '')):
        return jsonify({'fehler': 'Sitzung abgelaufen.'}), 403
    user_id = session['user_id']
    r = query_db('SELECT id FROM projects WHERE id=? AND user_id=?', [pid, user_id], one=True)
    if not r:
        return jsonify({'fehler': 'Projekt nicht gefunden.'}), 404

    if request.form.get('an') != '1':
        # Widerruf nimmt die freigeschalteten Adressen MIT. Sie sind Daten
        # Dritter und haben ohne Link keinen Zweck mehr.
        execute_db('UPDATE projects SET share_token=NULL, share_at=NULL WHERE id=? AND user_id=?',
                   [pid, user_id])
        execute_db('DELETE FROM share_access WHERE project_id=?', [pid])
        return jsonify({'an': False})

    mails = []
    for teil in re.split(r'[,;\s]+', request.form.get('mails', '') or ''):
        t = teil.strip().lower()
        if t and re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', t) and t not in mails:
            mails.append(t)
    if not mails:
        return jsonify({'fehler': 'Bitte mindestens eine gültige E-Mail-Adresse angeben. '
                                  'Nur wer eine davon besitzt, kann den Link öffnen.'}), 400
    if len(mails) > 20:
        return jsonify({'fehler': 'Höchstens 20 Adressen je Link.'}), 400

    token = secrets.token_urlsafe(24)
    jetzt = datetime.now()
    execute_db('UPDATE projects SET share_token=?, share_at=? WHERE id=? AND user_id=?',
               [token, jetzt, pid, user_id])
    execute_db('DELETE FROM share_access WHERE project_id=?', [pid])
    for m in mails:
        execute_db('INSERT INTO share_access (project_id, email, created_at) VALUES (?,?,?)',
                   [pid, m, jetzt])
    basis = os.environ.get('BASE_URL', 'https://holzbau3d.app').rstrip('/')
    return jsonify({'an': True, 'link': basis + '/p/' + token,
                    'mails': mails, 'tage': SHARE_TAGE,
                    'bis': (jetzt + timedelta(days=SHARE_TAGE)).strftime('%d.%m.%Y')})


def _share_darf_sehen(token):
    z = session.get('share_ok', {}).get(token)
    if not z:
        return False
    try:
        return datetime.now() < datetime.fromisoformat(z)
    except Exception:
        return False


@app.route('/p/<token>')
def projekt_ansehen(token):
    """Nur-Ansicht. Kein Login, keine Bearbeitung, kein Rueckweg ins Konto —
    die Seite kennt weder Nutzernamen noch E-Mail des Besitzers."""
    p = _share_projekt(token)
    if not p:
        return render_template('projekt_ansicht.html', weg=True), 404
    if not _share_darf_sehen(token):
        return render_template('projekt_ansicht.html', token=token, tor=True,
                               schritt=request.args.get('schritt', 'mail'),
                               meldung=request.args.get('m', ''))
    daten = _share_saeubern(p['daten'])
    if daten is None:
        return render_template('projekt_ansicht.html', weg=True), 404
    return render_template('projekt_ansicht.html',
                           projekt_name=p['name'], token=token,
                           teile=_share_stueckliste(daten),
                           anzahl=len(daten.get('beams') or []),
                           bis=(p['share_at'] + timedelta(days=SHARE_TAGE)).strftime('%d.%m.%Y'))


@app.route('/p/<token>/code', methods=['POST'])
def projekt_ansehen_code(token):
    """Schritt 1: Adresse eintragen. Die Antwort ist IMMER dieselbe — sonst
    liesse sich abklopfen, welche Adressen freigeschaltet sind, und das waere
    eine Auskunft ueber Dritte."""
    p = _share_projekt(token)
    if not p:
        return render_template('projekt_ansicht.html', weg=True), 404
    email = (request.form.get('email', '') or '').strip().lower()[:255]
    if _share_frei(p['id'], email):
        code = '%06d' % secrets.randbelow(1000000)
        session['share_code'] = {
            'token': token, 'email': email,
            'hash': generate_password_hash(code),
            'bis': (datetime.now() + timedelta(minutes=SHARE_CODE_MINUTEN)).isoformat(),
            'versuche': 0,
        }
        try:
            send_email(email, 'Dein Zugangscode für ein HolzBau-3D-Projekt',
                       '<p>Jemand hat dir ein Projekt aus HolzBau 3D zum Ansehen freigegeben.</p>'
                       '<p style="font-size:26px;font-weight:bold;letter-spacing:3px">%s</p>'
                       '<p>Der Code gilt %d Minuten. Wenn du das nicht angefordert hast, '
                       'ignoriere diese Nachricht einfach.</p>' % (code, SHARE_CODE_MINUTEN))
        except Exception as e:
            logger.error('Zugangscode konnte nicht gesendet werden: %s', type(e).__name__)
    return redirect(url_for('projekt_ansehen', token=token, schritt='code',
                            m='Wenn diese Adresse freigegeben ist, haben wir dir gerade '
                              'einen Code geschickt.'))


@app.route('/p/<token>/pruefen', methods=['POST'])
def projekt_ansehen_pruefen(token):
    """Schritt 2: Code eintragen."""
    if not _share_projekt(token):
        return render_template('projekt_ansicht.html', weg=True), 404
    s = session.get('share_code') or {}
    fehler = 'Der Code stimmt nicht oder ist abgelaufen. Bitte neu anfordern.'
    if s.get('token') != token:
        return redirect(url_for('projekt_ansehen', token=token, schritt='mail', m=fehler))
    try:
        abgelaufen = datetime.now() > datetime.fromisoformat(s.get('bis', ''))
    except Exception:
        abgelaufen = True
    if abgelaufen or s.get('versuche', 0) >= SHARE_VERSUCHE:
        session.pop('share_code', None)
        return redirect(url_for('projekt_ansehen', token=token, schritt='mail', m=fehler))
    if not check_password_hash(s.get('hash', ''), (request.form.get('code', '') or '').strip()):
        s['versuche'] = s.get('versuche', 0) + 1
        session['share_code'] = s
        return redirect(url_for('projekt_ansehen', token=token, schritt='code',
                                m='Der Code stimmt nicht. Noch %d Versuch(e).'
                                  % max(0, SHARE_VERSUCHE - s['versuche'])))
    ok = dict(session.get('share_ok') or {})
    ok[token] = (datetime.now() + timedelta(days=SHARE_ZUGANG_TAGE)).isoformat()
    session['share_ok'] = ok
    session.pop('share_code', None)
    return redirect(url_for('projekt_ansehen', token=token))


@app.route('/p/<token>/modell.json')
def projekt_ansehen_json(token):
    p = _share_projekt(token)
    if not p or not _share_darf_sehen(token):
        abort(404)
    daten = _share_saeubern(p['daten'])
    if daten is None:
        abort(404)
    antwort = jsonify(daten)
    # Nicht in Suchmaschinen und nicht in fremden Zwischenspeichern.
    antwort.headers['X-Robots-Tag'] = 'noindex, nofollow'
    antwort.headers['Cache-Control'] = 'private, no-store'
    return antwort


def _share_aufraeumen():
    """Abgelaufene Links wirklich loeschen, nicht nur sperren. Der Nutzer hat
    7 Tage zugesagt bekommen — danach soll auch nichts mehr dastehen."""
    grenze = datetime.now() - timedelta(days=SHARE_TAGE)
    alt = query_db('SELECT id FROM projects WHERE share_token IS NOT NULL AND share_at < ?',
                   [grenze]) or []
    for r in alt:
        execute_db('DELETE FROM share_access WHERE project_id=?', [r['id']])
    execute_db('UPDATE projects SET share_token=NULL, share_at=NULL '
               'WHERE share_token IS NOT NULL AND share_at < ?', [grenze])
    return len(alt)


@app.route('/projekte/<int:pid>/loeschen', methods=['POST'])
@login_required
def projekt_loeschen(pid):
    if not validate_csrf(request.form.get('csrf_token', '')):
        return jsonify({'fehler': 'Sitzung abgelaufen.'}), 403
    # Die freigeschalteten Adressen gehoeren zum Projekt und sind Daten Dritter —
    # sie duerfen es nicht ueberleben.
    execute_db('DELETE FROM share_access WHERE project_id=?', [pid])
    execute_db('DELETE FROM projects WHERE id=? AND user_id=?', [pid, session['user_id']])
    return jsonify({'ok': True})


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

ADMIN_USERS_PRO_SEITE = 20

# Sortierbare Spalten der Benutzerliste. Weisse Liste, weil der Schluessel aus
# der URL kommt: nur diese Werte duerfen jemals in ein ORDER BY geraten.
ADMIN_USERS_SORTIERUNG = {
    'nr':       'u.created_at',            # die laufende Nummer IST die Reihenfolge
    'name':     'u.username',
    'voll':     'u.full_name',
    'mail':     'u.email',
    'plan':     "COALESCE(s.plan, 'free')",
    'laufzeit': 's.current_period_end',
    'erstellt': 'u.created_at',
    'login':    'u.last_login',
}


@app.route('/admin/users')
@admin_required
def admin_users():
    try:
        seite = max(1, int(request.args.get('seite', 1)))
    except (TypeError, ValueError):
        seite = 1

    # Sortierung laeuft ueber die DATENBANK, nicht im Browser: sonst wuerde nur
    # die angezeigte Seite umsortiert und "aeltester Login" zeigte den
    # aeltesten der 20 sichtbaren statt den aeltesten ueberhaupt.
    # Weisse Liste — Spaltennamen kommen NIE aus der URL in das SQL.
    sortier_spalte = ADMIN_USERS_SORTIERUNG.get(
        request.args.get('sort', ''), None)
    # Ohne Angabe gilt die Grundordnung — und die Spalte wird auch so markiert,
    # damit man sieht, wonach die Liste gerade sortiert ist.
    sortierung = request.args.get('sort', '') if sortier_spalte else 'erstellt'
    richtung = 'asc' if request.args.get('richtung') == 'asc' else 'desc'
    if sortier_spalte is None:
        sortier_spalte = 'u.created_at'
    # NULL immer ans Ende (nie eingeloggt, kein Abo) — in beide Richtungen.
    # Und u.id als letzter Schluessel: ohne eindeutige Ordnung koennen bei
    # gleichen Werten Zeilen zwischen zwei Seiten doppelt oder gar nicht
    # auftauchen.
    order_by = '(%s IS NULL), %s %s, u.id DESC' % (
        sortier_spalte, sortier_spalte, 'ASC' if richtung == 'asc' else 'DESC')

    gesamt = (query_db('SELECT COUNT(*) AS c FROM app_users', [], one=True) or {}).get('c', 0) or 0
    seiten = max(1, (gesamt + ADMIN_USERS_PRO_SEITE - 1) // ADMIN_USERS_PRO_SEITE)
    seite = min(seite, seiten)                     # ?seite=999 landet auf der letzten
    versatz = (seite - 1) * ADMIN_USERS_PRO_SEITE

    # Erst nur die IDs dieser Seite holen — damit der Stripe-Abgleich gleich
    # weiss, welche Konten ueberhaupt sichtbar sind. Der LEFT JOIN muss schon
    # hier stehen: nach Plan oder Laufzeit sortiert man ueber die
    # Abo-Tabelle, und die Seiteneinteilung muss derselben Ordnung folgen.
    ids = [r['id'] for r in (query_db(
        'SELECT u.id FROM app_users u '
        'LEFT JOIN subscriptions s ON s.user_id = u.id '
        'ORDER BY ' + order_by + ' LIMIT ? OFFSET ?',
        [ADMIN_USERS_PRO_SEITE, versatz]) or [])]
    if not ids:
        return render_template('admin_users.html', users=[], gesamt=gesamt,
                               seite=1, seiten=1, pro_seite=ADMIN_USERS_PRO_SEITE, von=0, bis=0,
                               sortierung=sortierung, richtung=richtung)

    platzhalter = ','.join(['?'] * len(ids))
    # Stripe = Source of Truth — aber nur fuer die 20 sichtbaren Konten. Vorher
    # lief bei JEDEM Seitenaufruf ein Stripe-Aufruf fuer JEDES verknuepfte Konto;
    # das waechst mit der Nutzerzahl, obwohl man ohnehin nur eine Seite sieht.
    for r in query_db('SELECT user_id FROM subscriptions WHERE user_id IN (%s) '
                      'AND (stripe_sub_id IS NOT NULL OR stripe_customer_id IS NOT NULL)'
                      % platzhalter, ids) or []:
        _sync_user_from_stripe(r['user_id'])

    # Erst NACH dem Abgleich lesen, sonst zeigt die Seite den Stand von vorher.
    users = query_db("""
        SELECT u.id, u.username, u.full_name, u.email, u.created_at, u.last_login,
               COALESCE(u.email_verified, 1) as email_verified,
               COALESCE(s.plan, 'free') as plan, COALESCE(s.status, '') as sub_status,
               s.plan_interval, s.sub_started, s.current_period_end
        FROM app_users u
        LEFT JOIN subscriptions s ON s.user_id = u.id
        WHERE u.id IN (%s)
        ORDER BY {}
    """.format(order_by) % platzhalter, ids) or []

    return render_template('admin_users.html', users=users, gesamt=gesamt,
                           seite=seite, seiten=seiten, pro_seite=ADMIN_USERS_PRO_SEITE,
                           von=versatz + 1, bis=versatz + len(users),
                           sortierung=sortierung, richtung=richtung)


@app.route('/admin/mails')
@admin_required
def admin_mails():
    """Uebersicht: welche Mails gehen raus, welcher Cron treibt sie, laeuft er?

    Der wichtigste Teil ist der Cron-Zustand. Ob cron-job.org wirklich anklopft,
    war von aussen nicht feststellbar — ein nie aufgerufener Job und ein mit
    falschem Schluessel abgewiesener Job sehen beide aus wie: nichts passiert.
    Seit cron_runs steht beides schwarz auf weiss."""
    # Seit wann wird ueberhaupt protokolliert? Ohne diese Angabe ist "noch nie
    # gelaufen" irrefuehrend: die Tabelle entsteht erst beim Deploy, und ein
    # taeglicher Job hat danach vielleicht schlicht noch nicht gefeuert.
    aeltester = query_db('SELECT MIN(ran_at) AS a FROM cron_runs', [], one=True)
    protokoll_seit = _to_dt(aeltester['a']) if aeltester and aeltester.get('a') else None

    jobs = []
    for j in CRON_JOBS:
        letzter_ok = query_db(
            'SELECT ran_at, note FROM cron_runs WHERE job=? AND ok=1 ORDER BY ran_at DESC LIMIT 1',
            [j['job']], one=True)
        # NUR echte Cron-Versuche: ein Aufruf ganz ohne Schluessel kam nicht von
        # cron-job.org (ein eingerichteter Job schickt immer einen mit). Ihn
        # mitzuzaehlen hiesse dem Nutzer erzaehlen, sein Cron habe angerufen,
        # obwohl es ein Scanner oder ein Test war.
        letzter_fehl = query_db(
            "SELECT ran_at, note FROM cron_runs WHERE job=? AND ok=0 "
            "AND COALESCE(grund,'') IN ('falscher_schluessel','kein_secret') "
            "ORDER BY ran_at DESC LIMIT 1", [j['job']], one=True)
        # Fremdaufrufe getrennt zeigen, damit sie erklaerbar bleiben statt zu beunruhigen.
        letzter_fremd = query_db(
            "SELECT ran_at, note FROM cron_runs WHERE job=? AND ok=0 "
            "AND COALESCE(grund,'') = 'kein_schluessel' ORDER BY ran_at DESC LIMIT 1",
            [j['job']], one=True)
        anzahl = query_db('SELECT COUNT(*) AS c FROM cron_runs WHERE job=? AND ok=1', [j['job']], one=True)
        ok_dt = _to_dt(letzter_ok['ran_at']) if letzter_ok else None
        stunden_her = ((datetime.utcnow() - ok_dt).total_seconds() / 3600.0) if ok_dt else None

        if ok_dt is None and letzter_fehl:
            zustand = 'abgewiesen'
            text = ('Der Job ruft an, wird aber abgewiesen (403) — er schickt einen Schlüssel mit, '
                    'nur den falschen. Trage den Wert aus CRON_SECRET bei cron-job.org ein.')
        elif ok_dt is None:
            zustand = 'nie'
            text = 'Dieser Job hat sich hier noch NIE gemeldet. Es ging bisher keine dieser Mails raus.'
            # Ehrlich bleiben: bei jungem Protokoll ist das noch kein Beweis.
            if protokoll_seit and (datetime.utcnow() - protokoll_seit).total_seconds() < j['max_stunden'] * 3600:
                text += (' ACHTUNG: das Protokoll ist jünger als ein Job-Zeitraum — vielleicht war er '
                         'einfach noch nicht dran. Erst nach einem vollen Zeitraum ist das aussagekräftig.')
        elif stunden_her is not None and stunden_her > j['max_stunden']:
            zustand, text = 'ueberfaellig', 'Der letzte erfolgreiche Lauf ist zu lange her — der Job scheint zu stehen.'
        else:
            zustand, text = 'laeuft', 'Läuft.'

        jobs.append({
            'job': j['job'], 'name': j['name'], 'plan': j['plan'], 'zweck': j['zweck'],
            'zustand': zustand, 'text': text,
            'letzter_ok': ok_dt, 'letzter_ok_note': letzter_ok['note'] if letzter_ok else None,
            'stunden_her': round(stunden_her, 1) if stunden_her is not None else None,
            'letzter_fehl': _to_dt(letzter_fehl['ran_at']) if letzter_fehl else None,
            'letzter_fehl_note': letzter_fehl['note'] if letzter_fehl else None,
            'letzter_fremd': _to_dt(letzter_fremd['ran_at']) if letzter_fremd else None,
            'letzter_fremd_note': letzter_fremd['note'] if letzter_fremd else None,
            'laeufe': anzahl['c'] if anzahl else 0,
            'url': (os.environ.get('BASE_URL', 'https://holzbau3d.app').rstrip('/')
                    + '/cron/' + j['job'] + '?key=DEIN_CRON_SECRET'),
        })

    vorlagen = []
    for v in MAIL_VORLAGEN:
        eintrag = {k: v[k] for k in ('key', 'name', 'wann', 'ausloeser') if k in v}
        eintrag['job'] = v.get('job')
        try:
            eintrag['betreff'] = v['render']('de')[0]
        except Exception as e:
            # Eine kaputte Vorlage darf die Uebersicht nicht mitreissen — sie
            # soll im Gegenteil genau das anzeigen.
            eintrag['betreff'] = None
            eintrag['fehler'] = '%s: %s' % (type(e).__name__, e)
        vorlagen.append(eintrag)

    letzte = query_db('SELECT job, ran_at, ok, note, ip FROM cron_runs ORDER BY ran_at DESC LIMIT 20', [])
    cron_secret_gesetzt = bool(os.environ.get('CRON_SECRET', ''))
    return render_template('admin_mails.html', jobs=jobs, vorlagen=vorlagen,
                           ohne_vorlage=MAIL_OHNE_VORLAGE, letzte=letzte,
                           cron_secret_gesetzt=cron_secret_gesetzt,
                           protokoll_seit=protokoll_seit)


# Wegwerf-/Einweg-Mailanbieter. Bewusst kurz und offensichtlich gehalten: die
# Liste soll einen Verdacht anzeigen, keine Wahrheit behaupten.
WEGWERF_DOMAINS = (
    'mailinator.com', 'guerrillamail.com', 'guerrillamail.info', '10minutemail.com',
    'tempmail.com', 'temp-mail.org', 'yopmail.com', 'trashmail.com', 'wegwerfmail.de',
    'sharklasers.com', 'getnada.com', 'maildrop.cc', 'dispostable.com', 'mailnesia.com',
    'throwawaymail.com', 'fakeinbox.com', 'spam4.me', 'moakt.com', 'emailondeck.com',
)


@app.route('/admin/nutzer-analyse')
@admin_required
def admin_nutzer_analyse():
    """Wie viele der Registrierungen sind ECHTE, erreichbare Menschen?

    Hintergrund: Aus den nackten Zahlen 'X Registrierte, Y Abos' laesst sich keine
    Konversionsrate ableiten, solange unklar ist, wie viele der Konten Testkonten,
    Bekannte oder Bots sind. Diese Seite teilt die Nutzer daher in Stufen auf und
    nennt bei jeder Zahl ihre Unsicherheit, statt eine Quote zu behaupten.
    """
    heute = datetime.utcnow()

    nutzer = query_db("""
        SELECT u.id, u.username, u.full_name, u.email, u.created_at, u.last_login,
               COALESCE(u.email_verified, 1) AS email_verified, u.lang,
               u.email_verify_token, COALESCE(u.login_count, 0) AS login_count,
               COALESCE(s.plan, 'free') AS plan, COALESCE(s.status, '') AS sub_status
        FROM app_users u
        LEFT JOIN subscriptions s ON s.user_id = u.id
        WHERE u.username <> 'admin'
        ORDER BY u.created_at
    """) or []

    # Ab wann ist email_verified ueberhaupt aussagekraeftig? Die Migration hat
    # allen damals vorhandenen Zeilen DEFAULT 1 gegeben — erst seit die
    # Registrierung 0 setzt, bedeutet eine 1 wirklich "hat bestaetigt". Wir
    # leiten den Stichtag aus den Daten ab: das aelteste Konto, das je einen
    # Bestaetigungs-Token hatte oder unbestaetigt ist.
    stichtag = None
    for u in nutzer:
        if (not u['email_verified']) or u['email_verify_token']:
            stichtag = u['created_at']
            break

    def _stufe(u):
        """Grobe Einordnung eines Kontos. Bewusst konservativ."""
        angelegt = _to_dt(u['created_at'])
        zuletzt = _to_dt(u['last_login'])
        domain = (u['email'] or '').split('@')[-1].lower()
        if u['plan'] == 'premium':
            return 'zahlend'
        if domain in WEGWERF_DOMAINS:
            return 'wegwerf'
        if not u['email_verified']:
            # Nie bestaetigt und nie eingeloggt -> mit Abstand haeufigste Form
            # von Bot- und Karteileichen-Registrierungen.
            return 'unbestaetigt'
        # Der Zaehler ist die harte Zahl — aber erst seit seinem Einbau. Alle
        # vorher angelegten Konten stehen auf 0, obwohl sie eingeloggt waren.
        # Darum nur als Beleg NACH OBEN verwenden, nie zum Abwerten: >= 2 ist
        # sicher "wiedergekommen", alles andere faellt auf die alte Schaetzung
        # zurueck.
        if (u.get('login_count') or 0) >= 2:
            return 'wiedergekommen'
        if not zuletzt or not angelegt:
            return 'nie_aktiv'
        # verify_email setzt last_login mit — ein Abstand unter 30 Minuten heisst
        # also "einmal angemeldet und nie wieder", nicht "war zweimal da".
        if (zuletzt - angelegt).total_seconds() < 1800:
            return 'einmal'
        return 'wiedergekommen'

    stufen = {'zahlend': [], 'wiedergekommen': [], 'einmal': [], 'nie_aktiv': [],
              'unbestaetigt': [], 'wegwerf': []}
    for u in nutzer:
        stufen[_stufe(u)].append(u)

    # Registrierungen je Kalenderwoche — zum Abgleich mit dem Suchverkehr.
    wochen = {}
    for u in nutzer:
        d = _to_dt(u['created_at'])
        if not d:
            continue
        montag = (d - timedelta(days=d.weekday())).strftime('%Y-%m-%d')
        w = wochen.setdefault(montag, {'woche': montag, 'n': 0, 'bestaetigt': 0})
        w['n'] += 1
        if u['email_verified']:
            w['bestaetigt'] += 1
    wochen = sorted(wochen.values(), key=lambda w: w['woche'])

    # E-Mail-Domains: eine ungewoehnliche Haeufung ist ein Bot-Hinweis.
    domains = {}
    for u in nutzer:
        d = (u['email'] or '').split('@')[-1].lower() or '—'
        e = domains.setdefault(d, {'domain': d, 'n': 0, 'bestaetigt': 0})
        e['n'] += 1
        if u['email_verified']:
            e['bestaetigt'] += 1
    domains = sorted(domains.values(), key=lambda d: -d['n'])[:15]

    sprachen = {}
    for u in nutzer:
        sprachen[u['lang'] or 'de'] = sprachen.get(u['lang'] or 'de', 0) + 1

    # Doppelte E-Mail-Adressen. Wichtig, weil die Spalte KEINE UNIQUE-Bedingung
    # hat — die Eindeutigkeit prueft nur der Registrierungs-Code (app.py ca. 1744),
    # und der hat eine Luecke bei gleichzeitigen Anmeldungen. Solange hier etwas
    # steht, kann weder ein UNIQUE-Index gesetzt noch der Login sicher auf die
    # E-Mail umgestellt werden — und das Passwort-Zuruecksetzen (WHERE email=?,
    # one=True) wuerde stillschweigend das falsche Konto treffen.
    _per_mail = {}
    for u in nutzer:
        m = (u['email'] or '').strip().lower()
        if m:
            _per_mail.setdefault(m, []).append(u['username'])
    doppelte = sorted(({'email': m, 'konten': k} for m, k in _per_mail.items() if len(k) > 1),
                      key=lambda d: -len(d['konten']))

    # Hat der UNIQUE-Index wirklich gegriffen? Die Migrationen laufen in einem
    # stillen try/except (init_db) — ein fehlgeschlagener ALTER faellt sonst
    # niemandem auf. Darum hier direkt nachsehen statt hoffen.
    try:
        unique_aktiv = bool(query_db("SHOW INDEX FROM app_users WHERE Key_name = 'uniq_email'", []))
    except Exception:
        unique_aktiv = None      # nicht feststellbar

    # "Erreichbar" = bestaetigte Adresse, keine Wegwerfdomain. Nur diese Menge
    # ist ueberhaupt ein sinnvoller Nenner fuer eine Konversionsrate.
    erreichbar = len(stufen['zahlend']) + len(stufen['wiedergekommen']) \
        + len(stufen['einmal']) + len(stufen['nie_aktiv'])
    zahlend = len(stufen['zahlend'])
    quote_alle = (zahlend / len(nutzer) * 100) if nutzer else 0
    quote_erreichbar = (zahlend / erreichbar * 100) if erreichbar else 0
    aktiv = len(stufen['zahlend']) + len(stufen['wiedergekommen'])
    quote_aktiv = (zahlend / aktiv * 100) if aktiv else 0

    return render_template('admin_nutzer_analyse.html',
                           gesamt=len(nutzer), stufen=stufen, wochen=wochen,
                           domains=domains, sprachen=sorted(sprachen.items()),
                           erreichbar=erreichbar, aktiv=aktiv, zahlend=zahlend,
                           quote_alle=quote_alle, quote_erreichbar=quote_erreichbar,
                           quote_aktiv=quote_aktiv, stichtag=stichtag, heute=heute,
                           doppelte=doppelte, unique_aktiv=unique_aktiv)


@app.route('/admin/nutzung')
@admin_required
def admin_nutzung():
    """Wo prallen Gratis-Nutzer an der Bezahlschranke ab?

    Die Gegenseite zu /admin/feature-use: dort steht event='used' (wer hat eine
    Funktion benutzt — und wer hat dabei die Client-Sperre umgangen), hier
    event='blocked' (wer wollte eine Funktion und kam nicht ran). Letzteres ist
    die Zahl, an der haengt, ob die Grenze zwischen frei und bezahlt richtig
    liegt.

    Bewusst nur ABSOLUTE Zahlen und Namen: bei wenigen aktiven Nutzern taeuscht
    jede Prozentangabe eine Genauigkeit vor, die nicht existiert — ein einzelner
    Nutzer bewegt eine Quote um viele Punkte.
    """
    try:
        tage = max(1, min(365, int(request.args.get('tage', 30))))
    except (TypeError, ValueError):
        tage = 30
    seit = 'used_at >= DATE_SUB(NOW(), INTERVAL %d DAY)' % tage

    # Seit wann wird ueberhaupt gemessen? Ohne diese Zeile liest man eine "0"
    # als "stoert niemanden", obwohl sie "wir messen erst seit gestern" heisst.
    start = query_db("SELECT MIN(used_at) AS a FROM feature_use WHERE event='blocked'", [], one=True)
    messbeginn = (start or {}).get('a')

    schranken = query_db(
        "SELECT feature, COUNT(*) AS treffer, COUNT(DISTINCT user_id) AS nutzer, "
        "MAX(used_at) AS zuletzt "
        "FROM feature_use WHERE event='blocked' AND " + seit +
        " GROUP BY feature ORDER BY nutzer DESC, treffer DESC", []) or []

    kz = query_db("SELECT COUNT(DISTINCT user_id) AS u, COUNT(*) AS n "
                  "FROM feature_use WHERE event='blocked' AND " + seit, [], one=True) or {}

    # Wer mehrfach UND an verschiedenen Tagen anstoesst, meint es ernst. Das ist
    # das brauchbarste Kaufnaehe-Signal, das sich aus diesen Daten bilden laesst.
    heisse = query_db(
        "SELECT u.id, u.username, u.email, "
        "       COUNT(DISTINCT DATE(fu.used_at)) AS tage, "
        "       COUNT(DISTINCT fu.feature) AS schranken, MAX(fu.used_at) AS zuletzt "
        "FROM feature_use fu JOIN app_users u ON u.id = fu.user_id "
        "WHERE fu.event='blocked' AND fu.plan='free' AND " + seit.replace('used_at', 'fu.used_at') +
        " GROUP BY u.id, u.username, u.email "
        "HAVING tage >= 2 ORDER BY tage DESC, schranken DESC LIMIT 20", []) or []

    genutzt = query_db(
        "SELECT feature, COUNT(DISTINCT user_id) AS nutzer FROM feature_use "
        "WHERE event='used' AND " + seit + " GROUP BY feature", []) or []
    genutzt_map = {g['feature']: g['nutzer'] for g in genutzt}

    return render_template('admin_nutzung.html', schranken=schranken, heisse=heisse,
                           genutzt=genutzt_map, tage=tage,
                           betroffene=kz.get('u') or 0, treffer=kz.get('n') or 0,
                           messbeginn=messbeginn)


@app.route('/admin/feature-use')
@admin_required
def admin_feature_use():
    """Wer benutzt welche Premium-Features — und benutzt sie jemand, der gar
    kein Premium hat? plan='free' in dieser Tabelle ist genau das: eine umgangene
    Client-Sperre. plan='premium' ist normale Nutzung (Feature-Statistik)."""
    tage = request.args.get('tage', type=int) or 30
    tage = max(1, min(tage, 365))
    seit = "used_at > DATE_SUB(NOW(), INTERVAL %d DAY)" % tage

    # Je Feature: wie oft und von wie vielen VERSCHIEDENEN Nutzern, getrennt nach Plan.
    zeilen = query_db(
        "SELECT feature, plan, COUNT(*) AS n, COUNT(DISTINCT user_id) AS nutzer "
        "FROM feature_use WHERE event='used' AND " + seit + " GROUP BY feature, plan", [])
    feat = {}
    for r in zeilen:
        f = feat.setdefault(r['feature'], {'feature': r['feature'], 'free_n': 0, 'free_u': 0, 'prem_n': 0, 'prem_u': 0})
        if r['plan'] == 'premium':
            f['prem_n'] = r['n']; f['prem_u'] = r['nutzer']
        else:
            f['free_n'] = r['n']; f['free_u'] = r['nutzer']
    features = sorted(feat.values(), key=lambda x: (-x['free_u'], -x['free_n'], x['feature']))

    # Die Kennzahl, um die es geht: wie viele UNTERSCHIEDLICHE Free-Nutzer haben
    # ueberhaupt ein Premium-Feature benutzt?
    # event='used' ist hier ZWINGEND: seit die Bezahlschranken-Treffer in
    # derselben Tabelle landen, wuerde diese Seite sonst jeden voellig normalen
    # Free-Nutzer als "Client-Sperre umgangen" melden — und damit genau den
    # Zweck zerstoeren, fuer den sie gebaut wurde.
    kz = query_db("SELECT COUNT(DISTINCT user_id) AS u, COUNT(*) AS n "
                  "FROM feature_use WHERE event='used' AND plan='free' AND " + seit, [], one=True)
    free_nutzer = kz['u'] if kz else 0
    free_ereignisse = kz['n'] if kz else 0

    # Die letzten Free-Umgehungen konkret — mit Nutzername, damit man handeln kann.
    letzte = query_db(
        "SELECT fu.feature, fu.used_at, u.username, u.email "
        "FROM feature_use fu LEFT JOIN app_users u ON u.id = fu.user_id "
        "WHERE fu.event='used' AND fu.plan='free' AND " + seit
        + " ORDER BY fu.used_at DESC LIMIT 40", [])

    gesamt = query_db("SELECT COUNT(*) AS c FROM feature_use WHERE event='used'", [], one=True)
    return render_template('admin_feature_use.html', features=features, letzte=letzte,
                           free_nutzer=free_nutzer, free_ereignisse=free_ereignisse,
                           tage=tage, gesamt=(gesamt['c'] if gesamt else 0))


# Nach dieser Zeit gilt eine offene Kasse als aufgegeben. Stripe laesst eine
# Checkout-Sitzung nach 24 Stunden verfallen; zwei Stunden Luft, damit ein
# spaet eintreffendes checkout.session.expired die Zeile noch selbst schliessen
# kann, bevor die Auswertung sie fuer sich entscheidet.
KAUFWEG_OFFEN_STUNDEN = 26


def _kaufweg_ausgang(zeile, jetzt):
    """Was ist aus diesem Versuch geworden?

    'gestartet' ist KEIN Endzustand — es heisst nur, dass niemand
    zurueckgemeldet hat. Nach 26 Stunden ist das eine Aufgabe, davor laeuft es
    vielleicht noch. Diese Unterscheidung hier und nicht in SQL, damit sie an
    einer Stelle steht und lesbar bleibt.
    """
    st = zeile['status']
    if st != 'gestartet':
        return st
    begonnen = _to_dt(zeile['gestartet_at'])
    if begonnen and (jetzt - begonnen).total_seconds() > KAUFWEG_OFFEN_STUNDEN * 3600:
        return 'abgebrochen'
    return 'laeuft'


@app.route('/admin/kaufweg')
@admin_required
def admin_kaufweg():
    """Wer wollte zahlen — und wo blieb er haengen?

    Zwei Quellen, bewusst getrennt gehalten:
      - checkout_intents: angemeldete Nutzer, ihre eigenen Kaufversuche, mit
        Namen. Das ist der Teil, bei dem Nachfassen moeglich ist.
      - landing_clicks: anonyme Tageszaehler der Startseite. Hier gibt es
        niemanden zum Nachfassen, nur die Frage, WO geklickt wird.
    Beide zusammen ergeben den Trichter — mit einer Luecke dazwischen, die auf
    der Seite ausdruecklich benannt wird.
    """
    tage = request.args.get('tage', 30, type=int)
    if tage not in (7, 30, 90):
        tage = 30
    jetzt = datetime.now()

    zeilen = query_db(
        "SELECT c.id, c.user_id, c.plan_type, c.status, c.grund, c.gestartet_at, "
        "c.beendet_at, u.username, u.email "
        "FROM checkout_intents c LEFT JOIN app_users u ON u.id = c.user_id "
        "WHERE c.gestartet_at >= DATE_SUB(NOW(), INTERVAL ? DAY) "
        "ORDER BY c.id DESC", [tage]) or []
    zeilen = [dict(row_to_dict(z)) for z in zeilen]
    for z in zeilen:
        z['ausgang'] = _kaufweg_ausgang(z, jetzt)

    zahlen = {'gestartet': 0, 'bezahlt': 0, 'abgebrochen': 0, 'fehler': 0, 'laeuft': 0}
    gruende = {}
    for z in zeilen:
        zahlen[z['ausgang']] = zahlen.get(z['ausgang'], 0) + 1
        if z['ausgang'] in ('fehler', 'abgebrochen'):
            g = z['grund'] or ('offen' if z['status'] == 'gestartet' else '—')
            gruende[g] = gruende.get(g, 0) + 1
    zahlen['gestartet'] = len(zeilen)
    gruende = sorted(gruende.items(), key=lambda p: -p[1])

    # Die Liste zum Nachfassen: nur, was wirklich nicht bezahlt wurde.
    haenger = [z for z in zeilen if z['ausgang'] in ('abgebrochen', 'fehler')]

    klicks = query_db(
        "SELECT ziel, sprache, SUM(anzahl) AS n FROM landing_clicks "
        "WHERE tag >= DATE_SUB(CURDATE(), INTERVAL ? DAY) "
        "GROUP BY ziel, sprache", [tage]) or []
    je_ziel = {}
    for k in klicks:
        e = je_ziel.setdefault(k['ziel'], {'ziel': k['ziel'], 'n': 0, 'de': 0, 'en': 0, 'fr': 0})
        n = int(k['n'] or 0)
        e['n'] += n
        if k['sprache'] in e:
            e[k['sprache']] += n
    je_ziel = sorted(je_ziel.values(), key=lambda e: -e['n'])
    abo_klicks = sum(e['n'] for e in je_ziel if e['ziel'] in ('preis_monat', 'preis_jahr'))

    erster = query_db("SELECT MIN(gestartet_at) AS a FROM checkout_intents", [], one=True)
    erster_klick = query_db("SELECT MIN(tag) AS a FROM landing_clicks", [], one=True)

    return render_template('admin_kaufweg.html', tage=tage, zeilen=zeilen,
                           zahlen=zahlen, gruende=gruende, haenger=haenger,
                           ziele=je_ziel, abo_klicks=abo_klicks,
                           messbeginn=(erster or {}).get('a'),
                           messbeginn_klicks=(erster_klick or {}).get('a'))


@app.route('/admin/mails/<key>')
@admin_required
def admin_mail_vorschau(key):
    """Rendert eine Vorlage mit Beispielwerten — ueber DIESELBE Funktion, die
    auch der echte Versand benutzt. Nachbauen waere wertlos: die Kopie stimmte
    genau so lange, bis jemand die Vorlage aendert."""
    v = next((x for x in MAIL_VORLAGEN if x['key'] == key), None)
    if not v:
        abort(404)
    lang = _norm_lang(request.args.get('lang', 'de'))
    _betreff, html = v['render'](lang)
    return Response(html, mimetype='text/html')


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

    username = user['username']
    _nutzerdaten_loeschen(user_id)

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
    # 'cancelled' heisst in der Abo-Seite: "Dein Abo wurde gekuendigt, du kannst
    # es wieder aktivieren" — samt Erneuern-Karten. Wer nie eines hatte, bekam
    # damit eine Falschaussage zu lesen und landete im falschen Zweig.
    # 'expired' fuehrt in den normalen Kaufzweig.
    status = 'active' if plan == 'premium' else 'expired'
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
@app.route('/admin/smtp-probe', methods=['GET', 'POST'])
@admin_required
def admin_smtp_probe():
    """Stimmen diese SMTP-Zugangsdaten — ja oder nein?

    Gmail meldet beim Einrichten eines Absenders nur "Die Einrichtung dieses
    Kontos konnte nicht abgeschlossen werden". Das kann alles heissen. Brevos
    Protokoll blieb leer, die Anmeldung ist also gar nicht erst zustande
    gekommen — aber welchen Satz der Server dabei gesagt hat, sieht man
    nirgends.

    Hier wird genau diese eine Anmeldung durchgefuehrt und die Antwort des
    Servers im Klartext gezeigt. Die Zugangsdaten werden NICHT gespeichert,
    nicht protokolliert und nicht weitergegeben — sie leben nur fuer die Dauer
    dieser einen Anfrage.
    """
    class _Fertig(Exception):
        """Abbruch nach erfolgreicher Zweitanmeldung — kein Fehler."""

    ergebnis = []
    host = request.form.get('host', 'smtp-relay.brevo.com').strip()
    port = request.form.get('port', '587').strip()
    # Bewusst NICHT getrimmt: sonst faellt genau der Fehler nie auf, um den es geht.
    user = request.form.get('user', '')
    pw   = request.form.get('pass', '')
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token', '')):
            ergebnis.append(('rot', 'Ungültige Anfrage — bitte die Seite neu laden.'))
        elif not user or not pw:
            ergebnis.append(('rot', 'Anmeldename und Schlüssel werden beide gebraucht.'))
        else:
            # Ein Leerzeichen am Anfang oder Ende — beim Kopieren aus der
            # Brevo-Oberflaeche schnell passiert und von aussen nicht zu sehen.
            # Genau daran ist die Einrichtung eine Stunde lang gescheitert, und
            # Gmail sagte nur "konnte nicht abgeschlossen werden". Deshalb wird
            # es hier ausdruecklich benannt UND beides ausprobiert.
            unsauber = (user != user.strip()) or (pw != pw.strip())
            if unsauber:
                ergebnis.append(('gelb', 'ACHTUNG: In Anmeldename oder Schlüssel steht ein '
                                         'Leerzeichen am Anfang oder Ende. Das ist der häufigste '
                                         'Grund für eine abgelehnte Anmeldung — es wird gleich '
                                         'auch ohne probiert.'))
            try:
                srv = smtplib.SMTP(host, int(port or 587), timeout=20)
                ergebnis.append(('gruen', 'Verbindung zu %s:%s steht.' % (host, port)))
                srv.ehlo()
                if srv.has_extn('starttls'):
                    srv.starttls()
                    srv.ehlo()
                    ergebnis.append(('gruen', 'Verschlüsselung (STARTTLS) ausgehandelt.'))
                else:
                    ergebnis.append(('gelb', 'Server bietet kein STARTTLS an.'))
                try:
                    srv.login(user, pw)
                    ergebnis.append(('gruen', 'ANMELDUNG ERFOLGREICH — diese Daten sind richtig. '
                                              'Genau so gehören sie in Gmail.'))
                except smtplib.SMTPAuthenticationError as e:
                    if unsauber:
                        try:
                            srv.login(user.strip(), pw.strip())
                            ergebnis.append(('gruen', 'OHNE die Leerzeichen klappt die Anmeldung! '
                                                      'Das war die ganze Ursache — beim Einfügen in '
                                                      'Gmail auf Leerzeichen am Rand achten.'))
                            srv.quit()
                            raise _Fertig()
                        except smtplib.SMTPAuthenticationError:
                            pass
                    ergebnis.append(('rot', 'Anmeldung abgelehnt: %s %s'
                                     % (e.smtp_code, (e.smtp_error or b'').decode('utf-8', 'replace')[:200])))
                    ergebnis.append(('grau', 'Bei Brevo heisst der Anmeldename NICHT deine E-Mail, '
                                             'sondern die Kennung von der SMTP-Seite '
                                             '(z. B. ae71da001@smtp-brevo.com). Das Passwort ist ein '
                                             'SMTP-SCHLÜSSEL — nicht der API-Schlüssel, nicht das Kontopasswort. '
                                             'Der Schlüssel wird nur bei der Erstellung angezeigt; '
                                             'wer ihn nicht kopiert hat, muss einen neuen erzeugen.'))
                srv.quit()
            except _Fertig:
                pass
            except Exception as e:
                ergebnis.append(('rot', 'Kein Durchkommen: %s: %s' % (type(e).__name__, str(e)[:200])))
    from html import escape as _e
    farben = {'gruen': '#16a34a', 'rot': '#dc2626', 'gelb': '#d97706', 'grau': '#9ca3af'}
    zeilen = ''.join('<div style="color:%s;margin:6px 0;line-height:1.6">%s</div>'
                     % (farben[f], _e(t)) for f, t in ergebnis)
    return ('<html><body style="font-family:system-ui,sans-serif;background:#0e1117;color:#dde5f4;'
            'padding:28px;max-width:760px;margin:auto">'
            '<h2 style="color:#4e8cdd">SMTP-Zugangsdaten prüfen</h2>'
            '<p style="color:#9ca3af;font-size:14px;line-height:1.6">Prüft eine Anmeldung direkt beim '
            'Mailserver und zeigt dessen Antwort. Die Eingaben werden nicht gespeichert und nicht '
            'protokolliert.</p>'
            '<form method="POST" style="display:grid;gap:10px;margin:20px 0">'
            '<input type="hidden" name="csrf_token" value="' + generate_csrf() + '">'
            '<label>Server<input name="host" value="' + _e(host) + '" style="width:100%;padding:8px"></label>'
            '<label>Port<input name="port" value="' + _e(port) + '" style="width:100%;padding:8px"></label>'
            '<label>Anmeldename<input name="user" value="' + _e(user) + '" '
            'placeholder="z. B. ae71da001@smtp-brevo.com" style="width:100%;padding:8px"></label>'
            '<label>SMTP-Schlüssel<input name="pass" type="password" style="width:100%;padding:8px"></label>'
            '<button type="submit" style="padding:10px 18px;background:#4e8cdd;border:0;border-radius:8px;'
            'color:#fff;font-weight:700;cursor:pointer">Anmeldung prüfen</button>'
            '</form>'
            '<div style="background:#161b27;border:1px solid #283755;border-radius:10px;padding:16px">'
            + (zeilen or '<span style="color:#9ca3af">Noch nichts geprüft.</span>') +
            '</div></body></html>')


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
    # ── PROBELAUF: genau der Klick, der beim Kunden nichts tut ──────────────
    # Zwei Runden Raten haben nichts gebracht, weil die eigentliche Antwort von
    # Stripe nirgends sichtbar war. Hier wird der Kauf mit DENSELBEN Werten
    # angestossen wie im echten Knopf — und die Antwort im Klartext gezeigt.
    # Es entsteht hoechstens eine unbezahlte Checkout-Sitzung; die verfaellt.
    L.append('=== Webhook ===')
    try:
        gut = query_db("SELECT ran_at, note FROM cron_runs WHERE job='stripe-webhook' "
                       "AND ok=1 ORDER BY ran_at DESC LIMIT 1", [], one=True)
        schlecht = query_db("SELECT ran_at, note FROM cron_runs WHERE job='stripe-webhook' "
                            "AND ok=0 ORDER BY ran_at DESC LIMIT 1", [], one=True)
        L.append('Zuletzt ERFOLGREICH verarbeitet: '
                 + (str(gut['ran_at']) + '   ' + str(gut['note'] or '')[:80]
                    if gut else 'noch nie'))
        L.append('Zuletzt GESCHEITERT:             '
                 + (str(schlecht['ran_at']) if schlecht else 'noch nie'))
        if gut and schlecht and gut['ran_at'] > schlecht['ran_at']:
            L.append('--> Der letzte Fehlschlag ist AELTER als der letzte Erfolg.')
            L.append('    Der Webhook laeuft; was darunter steht, ist Vergangenheit.')
        elif schlecht and (not gut or schlecht['ran_at'] >= gut['ran_at']):
            L.append('--> Der letzte Zustellversuch ist GESCHEITERT — Spur unten.')
        L.append('')
        zeilen = query_db("SELECT ran_at, note FROM cron_runs WHERE job='stripe-webhook' "
                          "AND ok=0 ORDER BY ran_at DESC LIMIT 5", [])
        if zeilen:
            L.append('Die letzten Fehlschlaege (aelteste Eintraege bleiben stehen):')
            for z in zeilen:
                L.append('  ' + str(z['ran_at']) + '  ' + str(z['note'] or '')[:300])
        else:
            L.append('Kein Fehlschlag protokolliert.')
    except Exception as e:
        L.append('  Protokoll nicht lesbar: ' + type(e).__name__)
    L.append('')
    L.append('=== Probelauf: derselbe Aufruf wie der Kauf-Knopf ===')
    if not sk or not price_m:
        L.append('Kein Schluessel oder kein Monatspreis gesetzt — Probelauf entfaellt.')
    else:
        uid = session.get('user_id')
        row = query_db('SELECT stripe_customer_id, plan, status FROM subscriptions WHERE user_id=?',
                       [uid], one=True)
        kunde = (row or {}).get('stripe_customer_id') or None
        L.append('Dein Konto: plan=' + str((row or {}).get('plan') or 'free')
                 + '  status=' + str((row or {}).get('status') or '-')
                 + '  Stripe-Kunde=' + (kunde or '(keiner)'))
        if kunde:
            try:
                k = _stripe_api_get('customers/' + kunde)
                L.append('  Kunde bei Stripe: gefunden, livemode=' + str(k.get('livemode')))
                if bool(k.get('livemode')) != (mode == 'LIVE') and mode in ('TEST', 'LIVE'):
                    L.append('  !! Der Kunde gehoert zum anderen Modus — genau das bricht den Kauf ab.')
            except Exception as e:
                L.append('  Kunde bei Stripe: NICHT GEFUNDEN (' + type(e).__name__ + ': '
                         + str(e)[:120] + ')')
                L.append('  -> Das ist die Ursache, wenn der Knopf nichts tut.')
        try:
            import stripe
            stripe.api_key = sk

            def probe(mit_kunde):
                return stripe.checkout.Session.create(
                    customer=mit_kunde,
                    payment_method_types=['card'],
                    line_items=[{'price': price_m, 'quantity': 1}],
                    mode='subscription',
                    success_url=request.host_url + 'subscribe?success=1',
                    cancel_url=request.host_url + 'subscribe?cancelled=1',
                    metadata={'user_id': str(uid), 'plan_type': 'monthly', 'probelauf': '1'},
                )
            if kunde:
                try:
                    probe(kunde)
                    L.append('MIT gespeichertem Kunden:  OK — Stripe haette geoeffnet.')
                except Exception as e:
                    L.append('MIT gespeichertem Kunden:  FEHLER ' + type(e).__name__)
                    L.append('   ' + str(e)[:400])
            try:
                probe(None)
                L.append('OHNE Kundenkennung:        OK — der zweite Versuch traegt.')
            except Exception as e:
                L.append('OHNE Kundenkennung:        FEHLER ' + type(e).__name__)
                L.append('   ' + str(e)[:400])
                L.append('   -> Dann liegt es NICHT am Kunden, sondern an Preis, Schluessel')
                L.append('      oder Kontoeinstellung. Der Text oben sagt, woran.')
        except Exception as e:
            L.append('Probelauf nicht moeglich: ' + type(e).__name__ + ': ' + str(e)[:200])
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
            'SELECT u.id, u.username, u.email, s.plan, s.status, s.plan_interval, s.stripe_sub_id, '
            's.current_period_end, s.renewal_notice_for, s.renewal_stage '
            'FROM app_users u LEFT JOIN subscriptions s ON s.user_id = u.id ORDER BY u.id', []
        )
        for u in users:
            L.append('  #' + str(u['id']) + '  ' + str(u['username']) + '  (' + str(u['email'] or '-') + ')'
                     + '  plan=' + str(u['plan'] or 'free')
                     + '  status=' + str(u['status'] or '-')
                     + '  intervall=' + str(u['plan_interval'] or '-')
                     + '  sub=' + str(u['stripe_sub_id'] or '-')
                     + '  bis=' + str(u['current_period_end'] or '-')
                     + '  verlaeng.-mail_fuer=' + str(u['renewal_notice_for'] or '-')
                     + '  stufen=' + str(u['renewal_stage'] or '-'))
    except Exception as e:
        L.append('DB-FEHLER: ' + type(e).__name__ + ': ' + str(e)[:200])
    L.append('')
    # Die Ueberschrift hiess "Bezahlte Checkout-Sessions" — aufgelistet wurde
    # aber JEDE der letzten 20, gefiltert erst eine Zeile spaeter und nur fuer
    # den ?activate=-Knopf. Wer die Ausgabe las, sah "bezahlt=unpaid" unter
    # einer Ueberschrift, die das Gegenteil behauptete. Jetzt sagt sie, was
    # dasteht, und zaehlt am Ende, wie viele davon wirklich bezahlt sind.
    L.append('=== Stripe Checkout-Sessions (letzte 20, ALLE Status) ===')
    sessions_by_user = {}
    try:
        alle = _stripe_api_get('checkout/sessions', {'limit': 20}).get('data', [])
        bezahlt_n = 0
        for cs in alle:
            meta = cs.get('metadata') or {}
            uid = int(meta.get('user_id', 0) or 0)
            paid = cs.get('payment_status', '')
            L.append('  user_id=' + str(uid) + '  bezahlt=' + paid
                     + '  plan=' + str(meta.get('plan_type'))
                     + '  sub=' + str(cs.get('subscription')))
            if uid and paid == 'paid' and cs.get('mode') == 'subscription':
                sessions_by_user.setdefault(uid, cs)
                bezahlt_n += 1
        L.append('  --> %d von %d bezahlt. Der Rest sind abgebrochene Kaeufe.' % (bezahlt_n, len(alle)))
        L.append('      Wer, wann und WARUM steht unter /admin/kaufweg — Stripe kennt die')
        L.append('      Gruende nicht, weil die drei haeufigsten hier entstehen, nicht dort.')
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
        L.append('Tipp: ?renew1d=USER_ID anhaengen, um die 1-Tag-Verlaengerungsmail sofort an diesen User zu senden.')

    renew1d = request.args.get('renew1d', type=int)
    if renew1d:
        L.append('')
        L.append('=== 1-Tag-Verlaengerungsmail sofort senden fuer User #' + str(renew1d) + ' ===')
        try:
            r = query_db(
                "SELECT s.current_period_end, s.plan_interval, s.renewal_notice_for, s.renewal_stage, "
                "u.email, u.full_name, u.username, u.lang "
                "FROM subscriptions s JOIN app_users u ON u.id = s.user_id WHERE s.user_id=?",
                [renew1d], one=True)
            if not r:
                L.append('Kein Abo/User gefunden.')
            elif not r['email']:
                L.append('Keine E-Mail hinterlegt.')
            else:
                pe = _to_dt(r['current_period_end'])
                interval = r['plan_interval'] or 'monthly'
                u_lang = _norm_lang(r['lang'])
                date_txt = _filter_lokal_datum(pe) if pe else '-'
                amount_txt = _price_text(interval)
                subject = (RENEWAL_I18N[u_lang]['d1_subject']
                           .replace('{date}', date_txt).replace('{amount}', amount_txt))
                ok = send_email(r['email'], subject,
                                _email_renewal_html(r['full_name'] or r['username'],
                                                    date_txt, amount_txt, interval, u_lang, '1d'))
                if ok:
                    # Stufe merken, damit der taegliche Cron sie nicht ein zweites Mal schickt
                    sent = set(x for x in (r['renewal_stage'] or '').split(',') if x)
                    if not sent and r['renewal_notice_for']:
                        sent = {'7d'}
                    sent.add('1d')
                    if pe:
                        execute_db('UPDATE subscriptions SET renewal_notice_for=?, renewal_stage=? WHERE user_id=?',
                                   [pe.strftime('%Y-%m-%d %H:%M:%S'), ','.join(sorted(sent)), renew1d])
                    else:
                        execute_db('UPDATE subscriptions SET renewal_stage=? WHERE user_id=?',
                                   [','.join(sorted(sent)), renew1d])
                    L.append('OK -> 1-Tag-Mail an ' + str(r['email']) + ' gesendet. stufen jetzt: ' + ','.join(sorted(sent)))
                else:
                    L.append('Mail-Versand FEHLGESCHLAGEN (send_email=False) — ist BREVO_API_KEY gesetzt?')
        except Exception as e:
            L.append('FEHLER (' + type(e).__name__ + '): ' + str(e)[:300])

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


@app.route('/demo')
def demo():
    """Oeffentliche, login-freie Ansicht des 3D-Planers.

    Zweck: Googlebot (und jeder Besucher) sieht das eigentliche Produkt sofort,
    ohne Konto. Bisher landete Googlebot auf /holzbau -> 302 /login, das Produkt
    war fuer die AdSense-Pruefung unsichtbar ("minderwertige Inhalte").

    Bewusst KEIN session['user_id']: der Plan wird direkt 'free' gesetzt, sonst
    wuerde get_user_plan(session['user_id']) fuer anonyme Anfragen crashen.
    show_ads=False, weil vor der AdSense-Freigabe keine Anzeigen laufen sollen;
    demo=True schaltet im Template das Beispielmodell + die Registrieren-CTA frei.
    Speichern/Export bleiben client-seitig premium-gesperrt -> Funnel zur Anmeldung.
    """
    return render_template('holzbau.html', show_ads=False, user_plan='free',
                           demo=True, csrf_token=generate_csrf())


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


_STRIPE_RANG = {'active': 0, 'trialing': 1, 'past_due': 2}


def _stripe_abos_holen(max_seiten=10):
    """Holt ALLE Abos aus Stripe in einem Durchlauf, Kunde mit ausgeklappt.

    Bewusst nicht je Nutzer anfragen: bei ~90 Konten waeren das hunderte
    Einzelaufrufe und damit ein sicherer Timeout. So sind es ein bis zwei.
    Rueckgabe: Liste der Abo-Objekte (jeweils mit ausgeklapptem 'customer').
    """
    alle = []
    nach = None
    for _ in range(max_seiten):
        p = {'status': 'all', 'limit': 100, 'expand[]': 'data.customer'}
        if nach:
            p['starting_after'] = nach
        antwort = _stripe_api_get('subscriptions', p) or {}
        daten = antwort.get('data') or []
        alle.extend(daten)
        if not daten or not antwort.get('has_more'):
            break
        nach = daten[-1].get('id')
    return alle


def _stripe_bestes_je_mail(abos):
    """Je E-Mail-Adresse das beste Abo: aktiv schlaegt gekuendigt, sonst das neuere.
    Rueckgabe: ({email_klein: (kunden_id, abo)}, anzahl_ohne_zuordenbare_email)
    """
    beste = {}
    ohne_mail = 0
    for s in abos:
        kunde = s.get('customer')
        if not isinstance(kunde, dict):
            continue          # nicht ausgeklappt oder geloeschter Kunde
        mail = (kunde.get('email') or '').strip().lower()
        if not mail:
            ohne_mail += 1
            continue
        schluessel = (_STRIPE_RANG.get(s.get('status'), 9), -(s.get('created') or 0))
        if mail not in beste or schluessel < beste[mail][0]:
            beste[mail] = (schluessel, kunde.get('id'), s)
    return {m: (v[1], v[2]) for m, v in beste.items()}, ohne_mail


def _stripe_abgleich_alle():
    """Gleicht alle Stripe-Abos mit den lokalen Konten ab (Zuordnung ueber E-Mail).

    WARUM DAS NOETIG IST: Ein von Hand im Stripe-Dashboard angelegtes Abo erzeugt
    KEINE Checkout-Session. Damit greift keiner der uebrigen Wege:
      - Webhook 'checkout.session.completed' feuert nie,
      - _sync_user_from_stripe steigt bei fehlender Zeile/Stripe-ID sofort aus,
      - der ?sync=1-Fallback durchsucht Checkout-Sessions, die es nicht gibt.
    Der Nutzer bliebe dauerhaft 'free', obwohl er in Stripe bezahlt. Hier wird die
    fehlende Verknuepfung hergestellt; Plan/Status/Laufzeit setzt danach
    _sync_user_from_stripe.
    Rueckgabe: (ok, Meldung)
    """
    if not os.environ.get('STRIPE_SECRET_KEY'):
        return False, 'STRIPE_SECRET_KEY ist auf dem Server nicht gesetzt.'
    try:
        karte, ohne_mail = _stripe_bestes_je_mail(_stripe_abos_holen())
    except Exception as e:
        logger.error('stripe_abgleich_alle fehlgeschlagen: %s', type(e).__name__)
        return False, 'Stripe war nicht erreichbar (%s).' % type(e).__name__
    if not karte:
        zusatz = ' (%d Kunde(n) ohne E-Mail)' % ohne_mail if ohne_mail else ''
        return False, 'Stripe kennt keine Abos mit zuordenbarer E-Mail%s.' % zusatz

    gefunden = len(karte)
    neu, aktuell, fremd = [], 0, []
    for u in query_db('SELECT id, email FROM app_users', []):
        mail = (u['email'] or '').strip().lower()
        # pop: was uebrig bleibt, sind Abos ohne Konto in der App
        treffer = karte.pop(mail, None)
        if not treffer:
            continue
        customer_id, s = treffer
        sub_id = s.get('id')
        vorhanden = query_db('SELECT user_id, stripe_sub_id FROM subscriptions WHERE user_id=?',
                             [u['id']], one=True)
        if vorhanden and vorhanden['stripe_sub_id'] == sub_id:
            _sync_user_from_stripe(u['id'])       # nur Stand auffrischen
            aktuell += 1
            continue
        # Sicherheitsnetz: ein Abo darf nicht einem zweiten Konto zugeschlagen werden.
        besitzer = query_db('SELECT user_id FROM subscriptions WHERE stripe_sub_id=? AND user_id<>?',
                            [sub_id, u['id']], one=True)
        if besitzer:
            fremd.append('%s hängt an #%s' % (u['email'], besitzer['user_id']))
            continue
        if vorhanden:
            execute_db('UPDATE subscriptions SET stripe_customer_id=?, stripe_sub_id=? WHERE user_id=?',
                       [customer_id, sub_id, u['id']])
        else:
            execute_db('INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_sub_id, plan, status) '
                       'VALUES (?, ?, ?, ?, ?)', [u['id'], customer_id, sub_id, 'free', 'active'])
        _sync_user_from_stripe(u['id'])
        neu.append(u['email'])

    # Was uebrig blieb, ist NICHT automatisch herrenlos: steht in Stripe eine
    # andere Adresse als in der App (Firmen- statt persoenliche Adresse), wurde
    # das Abo evtl. von Hand zugeordnet. Solche mit bestehender Verknuepfung
    # hier herausnehmen, sonst meldet der Abgleich sie fuer immer als
    # "ohne Konto" — eine Falschmeldung.
    herrenlos = {}
    for m, (cid, s) in karte.items():
        if not _stripe_verknuepft(s.get('id'), cid):
            herrenlos[m] = (cid, s)
    von_hand = len(karte) - len(herrenlos)
    karte = herrenlos

    def _liste(werte, grenze=5):
        rest = len(werte) - grenze
        return ', '.join(werte[:grenze]) + (' … +%d' % rest if rest > 0 else '')

    teile = ['%d Abo(s) in Stripe' % gefunden]
    teile.append('%d neu verknüpft%s' % (len(neu), (': ' + _liste(neu)) if neu else ''))
    teile.append('%d bereits aktuell' % aktuell)
    if von_hand:
        teile.append('%d bereits von Hand zugeordnet (abweichende E-Mail in Stripe)' % von_hand)
    if fremd:
        teile.append('%d übersprungen (%s)' % (len(fremd), _liste(fremd, 3)))
    if karte:
        teile.append('%d Stripe-Abo(s) noch ohne Konto: %s — unter „Stripe-Zuordnung“ von Hand zuweisen'
                     % (len(karte), _liste(sorted(karte.keys()))))
    if ohne_mail:
        teile.append('%d Stripe-Kunde(n) ohne E-Mail' % ohne_mail)
    return True, 'Stripe-Abgleich — ' + ' · '.join(teile) + '.'


@app.route('/admin/stripe-abgleich', methods=['POST'])
@admin_required
def admin_stripe_abgleich():
    """Holt in Stripe angelegte Abos per E-Mail in die lokalen Konten."""
    if not validate_csrf(request.form.get('csrf_token', '')):
        abort(403)
    ok, meldung = _stripe_abgleich_alle()
    flash(meldung, 'success' if ok else 'warning')
    return redirect(url_for('admin_users'))


def _stripe_verknuepft(sub_id, customer_id):
    """Haengt dieses Abo (oder sein Kunde) bereits an einem Konto? -> user_id"""
    r = query_db('SELECT user_id FROM subscriptions WHERE stripe_sub_id=?', [sub_id], one=True)
    if r:
        return r['user_id']
    if customer_id:
        r = query_db('SELECT user_id FROM subscriptions WHERE stripe_customer_id=?',
                     [customer_id], one=True)
        if r:
            return r['user_id']
    return None


def _aehnlichkeit(a, b):
    """0..1 — grobe Namensaehnlichkeit, nur fuer die Vorschlags-Reihenfolge."""
    from difflib import SequenceMatcher
    a, b = (a or '').strip().lower(), (b or '').strip().lower()
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


@app.route('/admin/stripe-zuordnung', methods=['GET', 'POST'])
@admin_required
def admin_stripe_zuordnung():
    """Stripe-Abos von Hand einem Konto zuordnen.

    Noetig, weil die automatische Zuordnung ueber die E-Mail laeuft und in Stripe
    oft eine ANDERE Adresse steht als in der App (z.B. die Sammeladresse der
    Firma statt der persoenlichen). Der Abgleich meldet solche Abos dann als
    "ohne Konto in der App", was schlicht falsch ist.

    Bewusst KEIN automatisches Raten ueber Domain oder Namen: hier haengen Geld
    und Zugang dran. Die Seite schlaegt den wahrscheinlichsten Nutzer nur vor —
    zuordnen muss der Mensch.
    """
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token', '')):
            abort(403)
        sub_id = (request.form.get('sub_id') or '').strip()
        customer_id = (request.form.get('customer_id') or '').strip()
        try:
            uid = int(request.form.get('user_id') or 0)
        except ValueError:
            uid = 0
        if not sub_id or not uid:
            flash('Bitte ein Abo und einen Nutzer auswählen.', 'warning')
            return redirect(url_for('admin_stripe_zuordnung'))
        if not query_db('SELECT id FROM app_users WHERE id=?', [uid], one=True):
            flash('Nutzer nicht gefunden.', 'danger')
            return redirect(url_for('admin_stripe_zuordnung'))
        besitzer = query_db('SELECT user_id FROM subscriptions WHERE stripe_sub_id=? AND user_id<>?',
                            [sub_id, uid], one=True)
        if besitzer:
            flash('Dieses Abo hängt bereits an Nutzer #%s — nicht übernommen.' % besitzer['user_id'],
                  'warning')
            return redirect(url_for('admin_stripe_zuordnung'))
        if query_db('SELECT user_id FROM subscriptions WHERE user_id=?', [uid], one=True):
            execute_db('UPDATE subscriptions SET stripe_customer_id=?, stripe_sub_id=? WHERE user_id=?',
                       [customer_id or None, sub_id, uid])
        else:
            execute_db('INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_sub_id, plan, status) '
                       'VALUES (?, ?, ?, ?, ?)', [uid, customer_id or None, sub_id, 'free', 'active'])
        neu = row_to_dict(_sync_user_from_stripe(uid) or {})
        flash('Abo %s wurde Nutzer #%s zugeordnet — Plan jetzt "%s", Status "%s".'
              % (sub_id, uid, neu.get('plan', '?'), neu.get('status', '?')), 'success')
        return redirect(url_for('admin_stripe_zuordnung'))

    if not os.environ.get('STRIPE_SECRET_KEY'):
        flash('STRIPE_SECRET_KEY ist auf dem Server nicht gesetzt.', 'warning')
        return render_template('admin_stripe_zuordnung.html', offen=[], zugeordnet=0, nutzer=[])

    try:
        abos = _stripe_abos_holen()
    except Exception as e:
        logger.error('stripe_zuordnung: %s', type(e).__name__)
        flash('Stripe war nicht erreichbar (%s).' % type(e).__name__, 'danger')
        return render_template('admin_stripe_zuordnung.html', offen=[], zugeordnet=0, nutzer=[])

    nutzer = query_db("""
        SELECT u.id, u.username, u.full_name, u.email,
               COALESCE(s.plan, 'free') AS plan, s.stripe_sub_id
        FROM app_users u LEFT JOIN subscriptions s ON s.user_id = u.id
        WHERE u.username <> 'admin'
        ORDER BY u.username
    """) or []

    offen, zugeordnet = [], 0
    for s in abos:
        kunde = s.get('customer') if isinstance(s.get('customer'), dict) else {}
        cid = kunde.get('id')
        if _stripe_verknuepft(s.get('id'), cid):
            zugeordnet += 1
            continue
        mail = (kunde.get('email') or '').strip().lower()
        domain = mail.split('@')[-1] if '@' in mail else ''
        name = kunde.get('name') or ''
        # Vorschlaege bewerten: gleiche Domain wiegt schwer (Firmenadresse vs.
        # persoenliche Adresse ist genau der Fall, der hier auftritt),
        # Namensaehnlichkeit kommt als zweites Signal dazu.
        kand = []
        for u in nutzer:
            u_mail = (u['email'] or '').lower()
            punkte = 0.0
            gruende = []
            if domain and u_mail.endswith('@' + domain):
                punkte += 1.0
                gruende.append('gleiche Domain')
            ae = max(_aehnlichkeit(name, u['full_name']), _aehnlichkeit(name, u['username']))
            if ae >= 0.55:
                punkte += ae
                gruende.append('ähnlicher Name')
            if punkte > 0:
                kand.append({'u': u, 'punkte': punkte, 'grund': ' + '.join(gruende)})
        kand.sort(key=lambda k: -k['punkte'])
        preis = ((s.get('items') or {}).get('data') or [{}])[0].get('price') or {}
        betrag = preis.get('unit_amount')
        offen.append({
            'sub_id': s.get('id'), 'customer_id': cid,
            'email': kunde.get('email') or '—', 'name': name or '—',
            'status': s.get('status'),
            'betrag': ('%.2f %s' % (betrag / 100.0, (preis.get('currency') or '').upper())) if betrag else '—',
            'intervall': (preis.get('recurring') or {}).get('interval') or '—',
            'vorschlaege': kand[:3],
        })

    return render_template('admin_stripe_zuordnung.html',
                           offen=offen, zugeordnet=zugeordnet, nutzer=nutzer)


@app.route('/subscribe')
@login_required
def subscribe():
    user_id = session['user_id']

    # Fallback/Sync: Beim Rücksprung von Stripe (?success=1) oder manuell (?sync=1)
    # bezahlte Checkout-Sessions dieses Users suchen und das Abo aktivieren,
    # falls der Webhook (noch) nicht gegriffen hat.
    cs_id = request.args.get('session_id')

    # Rueckkehr von Stripe ueber "Abbrechen". Das ist das sauberste
    # Abbruchsignal, das es gibt: es kommt sofort und ohne Umweg ueber einen
    # Webhook, der erst nach 24 Stunden feuert. Bisher wurde es weggeworfen.
    if request.args.get('cancelled'):
        _kaufweg_abschluss('abgebrochen', 'zurueck', cs_id, user_id)

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


@app.route('/subscribe/status')
@login_required
def subscribe_status():
    """Was entscheidet die Abo-Seite gerade fuer DICH?

    Ein Kunde und der Betreiber melden beide "der Abo-Link tut nichts". Von
    aussen war nichts zu sehen: die Seite braucht ein Login, und in ein fremdes
    Konto sieht man zu Recht nicht hinein. Statt weiter zu raten, sagt die Seite
    hier selbst, welchen der vier Bloecke sie anzeigt und warum.

    Nur die EIGENEN Werte, nur angemeldet, und keine Kennungen — weder
    Stripe-IDs noch Schluessel. Wer das hier aufruft, sieht nichts, was er nicht
    ohnehin ueber sich selbst wissen darf.
    """
    user_id = session['user_id']
    sub = row_to_dict(query_db('SELECT * FROM subscriptions WHERE user_id=?', [user_id], one=True))
    plan = get_user_plan(user_id)
    stripe_da = bool(os.environ.get('STRIPE_SECRET_KEY'))
    status = sub.get('status')
    # Dieselbe Reihenfolge wie in subscribe.html — sonst diagnostiziert man
    # etwas anderes, als der Kunde sieht.
    if not stripe_da:
        block, kaufknopf = 'stripe-fehlt', False
    elif plan == 'premium' and status != 'cancelled':
        block, kaufknopf = 'kuendigen', False
    elif sub and status == 'cancelled':
        block, kaufknopf = 'erneuern', True
    else:
        block, kaufknopf = 'kaufen', True
    return jsonify({
        'angezeigter_block': block,
        'kaufknopf_sichtbar': kaufknopf,
        'plan': plan,
        'status_in_der_datenbank': status,
        'abo_zeile_vorhanden': bool(sub),
        'mit_stripe_verknuepft': bool(sub.get('stripe_customer_id') or sub.get('stripe_sub_id')),
        'laufzeit_bis': str(sub.get('current_period_end') or ''),
        'stripe_eingerichtet': stripe_da,
        'jahresabo_eingerichtet': bool(os.environ.get('STRIPE_YEARLY_PRICE_ID')),
        'hinweis': ('Du bist bereits Premium — deshalb steht dort "Abo kündigen" '
                    'und kein Kaufknopf.' if block == 'kuendigen'
                    else 'Der Kaufknopf müsste sichtbar sein.' if kaufknopf
                    else 'Stripe ist nicht eingerichtet.'),
    })


def _kaufweg_notiz(user_id, plan_type, status, grund=None, session_id=None):
    """Haelt einen Kaufversuch fest. Stoert nie den Kauf.

    Absichtlich genauso genuegsam wie die Telemetrie: jeder Fehler wird
    geschluckt und nur protokolliert. Eine Statistikzeile darf niemanden am
    Bezahlen hindern — das waere die Umkehrung des Zwecks.
    """
    try:
        return execute_db(
            'INSERT INTO checkout_intents '
            '(user_id, plan_type, status, grund, session_id, gestartet_at) '
            'VALUES (?, ?, ?, ?, ?, NOW())',
            [user_id, (plan_type or 'monthly')[:12], status[:12],
             (grund or None), (session_id or None)])
    except Exception as e:
        logger.warning('Kaufweg-Notiz fehlgeschlagen (%s: %s)', type(e).__name__, str(e)[:200])
        return None


def _kaufweg_abschluss(status, grund=None, session_id=None, user_id=None):
    """Schliesst den juengsten offenen Versuch ab.

    Ueber session_id, wenn Stripe sie mitliefert — das ist eindeutig. Sonst
    ueber das Konto, und dann NUR die juengste offene Zeile: wer zweimal
    hintereinander klickt, soll nicht beide Zeilen auf einmal geschlossen
    bekommen.
    """
    try:
        if session_id:
            r = query_db("SELECT id FROM checkout_intents WHERE session_id=? "
                         "AND status='gestartet' ORDER BY id DESC LIMIT 1",
                         [session_id], one=True)
        elif user_id:
            r = query_db("SELECT id FROM checkout_intents WHERE user_id=? "
                         "AND status='gestartet' ORDER BY id DESC LIMIT 1",
                         [user_id], one=True)
        else:
            return False
        if not r:
            return False
        execute_db('UPDATE checkout_intents SET status=?, grund=?, beendet_at=NOW() WHERE id=?',
                   [status[:12], (grund or None), r['id']])
        return True
    except Exception as e:
        logger.warning('Kaufweg-Abschluss fehlgeschlagen (%s: %s)', type(e).__name__, str(e)[:200])
        return False


@app.route('/subscribe/create-checkout', methods=['POST'])
@login_required
def subscribe_create_checkout():
    if not validate_csrf(request.form.get('csrf_token', '')):
        # Eine nackte 403-Seite war hier die zweite Sackgasse auf dem Weg zum
        # Abo. Das Merkmal veraltet mit der Sitzung, und die haelt eine Stunde
        # — wer den Tab beim Ueberlegen offen liegen laesst, klickt genau da
        # hinein. Abgewiesen wird der Kauf weiterhin (nichts wird ausgefuehrt),
        # aber der Kunde bekommt einen Weg zurueck statt einer Fehlerseite.
        logger.warning('Checkout mit veraltetem CSRF-Merkmal abgewiesen')
        _kaufweg_notiz(session.get('user_id'), request.form.get('plan_type'),
                       'fehler', 'sitzung')
        return redirect(url_for('subscribe', fehler='sitzung') + '#abo-aktion')
    if _check_rate_limit(_checkout_attempts, 'u%s' % session.get('user_id'),
                         CHECKOUT_MAX_ATTEMPTS):
        flash('Zu viele Versuche. Bitte warte kurz.', 'danger')
        _kaufweg_notiz(session.get('user_id'), request.form.get('plan_type'),
                       'fehler', 'limit')
        return redirect(url_for('subscribe', fehler='limit') + '#abo-aktion')
    stripe_key = os.environ.get('STRIPE_SECRET_KEY')
    plan_type = request.form.get('plan_type', 'monthly')
    if plan_type == 'yearly':
        price_id = os.environ.get('STRIPE_YEARLY_PRICE_ID') or os.environ.get('STRIPE_PRICE_ID')
    else:
        price_id = os.environ.get('STRIPE_PRICE_ID')
    if not stripe_key or not price_id:
        logger.error('Checkout ohne Stripe-Konfiguration angefordert')
        _kaufweg_notiz(session['user_id'], plan_type, 'fehler', 'technik')
        return redirect(url_for('subscribe', fehler='technik') + '#abo-aktion')
    user_id = session['user_id']
    sub_row = query_db('SELECT stripe_customer_id FROM subscriptions WHERE user_id=?', [user_id], one=True)
    customer_id = sub_row['stripe_customer_id'] if sub_row and sub_row['stripe_customer_id'] else None

    def _sitzung(kunde):
        import stripe
        stripe.api_key = stripe_key
        return stripe.checkout.Session.create(
            customer=kunde,
            payment_method_types=['card'],
            line_items=[{'price': price_id, 'quantity': 1}],
            mode='subscription',
            success_url=request.host_url + 'subscribe?success=1&session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.host_url + 'subscribe?cancelled=1',
            metadata={'user_id': str(user_id), 'plan_type': plan_type},
            subscription_data={'metadata': {'user_id': str(user_id), 'plan_type': plan_type}},
        )

    try:
        try:
            checkout = _sitzung(customer_id)
        except Exception as e1:
            # Ein gespeicherter Stripe-Kunde kann zu einem ANDEREN Schluessel
            # gehoeren — typisch nach dem Wechsel von Test- auf Live-Modus.
            # Stripe antwortet dann "No such customer", und zwar jedes Mal:
            # der Kunde kommt nie zur Kasse, egal wie oft er klickt. Das
            # betrifft genau die, die schon einmal ein Abo hatten.
            # Zweiter Versuch ohne Kundenkennung — Stripe legt dann eine neue
            # an. Lieber ein doppelter Kundeneintrag als ein verlorener Kauf.
            if not customer_id:
                raise
            logger.warning('Checkout mit gespeichertem Stripe-Kunden fehlgeschlagen (%s: %s) '
                           '— zweiter Versuch ohne Kundenkennung',
                           type(e1).__name__, str(e1)[:200])
            checkout = _sitzung(None)
        # Erst JETZT notieren: vorher steht nicht fest, dass es ueberhaupt eine
        # Kasse gibt. Die Kennung macht den Abschluss spaeter eindeutig — der
        # Webhook meldet dieselbe zurueck.
        _kaufweg_notiz(user_id, plan_type, 'gestartet', None, checkout.id)
        return redirect(checkout.url, code=303)
    except Exception as e:
        # Der Kunde wollte zahlen und konnte nicht — das ist die eine Meldung,
        # die nicht nur im Log stehen darf. Ohne einen zweiten Weg gibt er auf.
        # Die Meldung von Stripe gehoert ins Log. Ohne sie stand dort nur
        # "Exception" — und die naechste Suche begann wieder bei null.
        logger.error('Stripe checkout error: %s: %s', type(e).__name__, str(e)[:300])
        _kaufweg_notiz(user_id, plan_type, 'fehler', 'technik')
        return redirect(url_for('subscribe', fehler='technik') + '#abo-aktion')


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
    """Nimmt Stripe-Ereignisse entgegen — und antwortet NIE mit 500.

    Am 05.08.2026 kam auf einen Zustellversuch ein blanker 500 zurueck, also
    eine Ausnahme an allen Auffangnetzen vorbei. Von aussen war nur Flasks
    Standard-Fehlerseite zu sehen, und Stripe zaehlt so etwas als Fehlschlag,
    bis es den Endpunkt abschaltet.

    Deshalb liegt jetzt ein Netz um die GANZE Funktion. Eine echte HTTP-Antwort
    (etwa 400 bei falscher Signatur) geht weiterhin durch — alles andere wird
    mit voller Fehlerspur festgehalten und mit 200 quittiert. Empfangen haben
    wir das Ereignis schliesslich; nur verarbeiten konnten wir es nicht, und
    das ist Stripes Problem nicht.
    """
    from werkzeug.exceptions import HTTPException
    try:
        return _stripe_webhook_verarbeiten()
    except HTTPException:
        raise                                   # 400 bei falscher Signatur bleibt 400
    except Exception:
        import traceback
        spur = traceback.format_exc()
        logger.error('Stripe webhook: unbehandelter Fehler -- %s', spur)
        _cron_protokoll('stripe-webhook', False, spur[-1800:], 'ausnahme')
        return jsonify(ok=True)


def _stripe_signaturfehler(stripe):
    """Die Klasse fuer "Signatur passt nicht" — je nach SDK-Fassung woanders.

    Bis stripe-python 11 lag sie unter stripe.error, seither direkt unter
    stripe. requirements.txt sagt nur stripe>=8.0.0; ein Neubau kann also
    jederzeit eine Fassung ziehen, in der stripe.error fehlt. Stuende der Pfad
    fest im except-Zweig, wuerde beim ersten Fehler ein AttributeError WAEHREND
    der Fehlerbehandlung fliegen — und genau das ergibt einen 500.
    """
    for pfad in (('error', 'SignatureVerificationError'), ('SignatureVerificationError',)):
        ziel = stripe
        for teil in pfad:
            ziel = getattr(ziel, teil, None)
            if ziel is None:
                break
        if ziel is not None:
            return ziel
    return None


def _stripe_webhook_verarbeiten():
    stripe_key = os.environ.get('STRIPE_SECRET_KEY')
    webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')
    if not stripe_key or not webhook_secret:
        logger.error('Stripe webhook called but STRIPE_SECRET_KEY or STRIPE_WEBHOOK_SECRET not set')
        abort(400)
    import stripe
    stripe.api_key = stripe_key
    SigErr = _stripe_signaturfehler(stripe)
    try:
        payload = request.get_data()
        sig = request.headers.get('Stripe-Signature', '')
        # Das SDK prueft die Signatur — dafuer ist es da.
        stripe.Webhook.construct_event(payload, sig, webhook_secret)
        # ...und danach wird mit der ROHEN Nutzlast weitergearbeitet, nicht mit
        # dem Rueckgabeobjekt des SDK.
        #
        # Genau hier lag der Fehler, den Stripe seit dem 2. August gemeldet hat:
        # KeyError: 'get' in stripe/_stripe_object.py. Seit stripe-python 12 ist
        # StripeObject KEIN dict mehr — es haelt seine Werte in self._data und
        # bildet jeden Attributzugriff auf self[...] ab. `event.get('type')`
        # sucht dadurch einen SCHLUESSEL namens "get" und fliegt. Unser ganzer
        # Ereigniscode arbeitet mit .get(). requirements.txt sagt nur
        # stripe>=8.0.0, ein Neubau zog also irgendwann die neue Fassung —
        # und ab da schlug jedes Ereignis fehl.
        #
        # Mit json.loads bekommen wir schlichte dicts. Das Verhalten ist damit
        # von der SDK-Fassung unabhaengig, und zwar dauerhaft.
        event = json.loads(payload.decode('utf-8'))
    except Exception as e:
        if SigErr is not None and isinstance(e, SigErr):
            logger.warning('Stripe webhook signature verification failed')
        else:
            logger.error('Stripe webhook nicht lesbar: %s: %s', type(e).__name__, str(e)[:300])
        abort(400)

    # Ein Fehler bei der VERARBEITUNG darf nicht mit 400 beantwortet werden.
    # 400 heisst fuer Stripe "deine Anfrage war fehlerhaft" — es versucht es
    # wieder und wieder und schaltet den Endpunkt nach ein paar Tagen ab. Genau
    # das war im Gange (neun Versuche, Abschaltung angekuendigt fuer den 11.).
    # Der Abo-Stand haengt ohnehin nicht allein am Webhook: /subscribe holt ihn
    # bei jedem Aufruf frisch von Stripe (_sync_user_from_stripe).
    try:
        _handle_stripe_event(event)
        # Auch der ERFOLG wird festgehalten. Ohne ihn sieht man in der
        # Fehlerliste nur alte Eintraege und weiss nicht, ob seither ueberhaupt
        # etwas angekommen ist — genau diese Verwechslung gab es schon.
        _cron_protokoll('stripe-webhook', True,
                        '%s (%s)' % (event.get('type'), event.get('id')), 'ok')
    except Exception:
        import traceback
        spur = traceback.format_exc()
        logger.error('Stripe webhook: Ereignis %s (%s) nicht verarbeitet -- %s',
                     event.get('type'), event.get('id'), spur)
        # ...und zusaetzlich dorthin, wo man ohne Server-Logs hinkommt: Stripe
        # zeigt nur unsere eigene Antwort, und an die Railway-Logs kommt man im
        # Zweifel nicht schnell genug heran. cron_runs ist dafuer schon da.
        _cron_protokoll('stripe-webhook', False,
                        '%s (%s) -- %s' % (event.get('type'), event.get('id'),
                                           spur[-1500:]),
                        'fehler')
    return jsonify(ok=True)


def _cron_protokoll(job, ok, note, grund='ok'):
    """Haelt fest, dass der Cron angeklopft hat — erfolgreich ODER abgewiesen.
    Bewusst in try/except: ein kaputtes Protokoll darf niemals den Versand
    verhindern. Lieber eine Luecke in der Uebersicht als eine Mail, die nicht
    rausgeht."""
    try:
        execute_db('INSERT INTO cron_runs (job, ran_at, ok, grund, note, ip) VALUES (?, NOW(), ?, ?, ?, ?)',
                   [job, 1 if ok else 0, grund, (note or '')[:2000],
                    (request.headers.get('X-Forwarded-For', '') or request.remote_addr or '')[:45]])
    except Exception as e:
        logger.warning('cron_runs Protokoll fehlgeschlagen (%s): %s', job, type(e).__name__)


def _cron_schluessel_pruefen(job):
    """True = Aufruf ist echt. Schreibt jeden Versuch ins Protokoll.

    Der GRUND wird als Code festgehalten, nicht nur im Fliesstext. Sonst kann
    die Uebersicht "der Cron ruft mit falschem Schluessel an" nicht von
    "irgendwer hat die URL ohne Schluessel geoeffnet" unterscheiden — und genau
    das hat sie verwechselt: ein Testaufruf ohne Schluessel wurde als
    Cron-Problem gemeldet, obwohl cron-job.org nie angerufen hatte.
    """
    secret = os.environ.get('CRON_SECRET', '')
    given = request.args.get('key') or request.headers.get('X-Cron-Key', '')
    if not secret:
        _cron_protokoll(job, False, 'CRON_SECRET ist auf dem Server nicht gesetzt — Aufruf abgewiesen',
                        'kein_secret')
        return False
    if not given:
        # Ein eingerichteter Cron schickt IMMER einen Schluessel mit. Ohne
        # Schluessel war das jemand anderes: ein Scanner, ein Test, ein
        # versehentlicher Aufruf im Browser. Das sagt ueber den Cron nichts aus.
        _cron_protokoll(job, False,
                        'Aufruf ohne Schluessel abgewiesen (403). Ein eingerichteter Cron-Job '
                        'schickt immer einen Schluessel mit — das war also nicht cron-job.org, '
                        'sondern ein Scanner, ein Test oder ein Aufruf im Browser.',
                        'kein_schluessel')
        return False
    if given != secret:
        # Den Schluessel NICHT protokollieren, auch nicht teilweise.
        _cron_protokoll(job, False,
                        'Der mitgeschickte Schluessel passt nicht zu CRON_SECRET — Aufruf '
                        'abgewiesen (403). Hier hat jemand mit EINEM Schluessel angerufen, '
                        'also sehr wahrscheinlich der Cron-Job mit einem veralteten Wert.',
                        'falscher_schluessel')
        return False
    return True


@app.route('/cron/subscription-reminders', methods=['GET', 'POST'])
def cron_subscription_reminders():
    """Täglich von einem Cron aufzurufen. Schützt per CRON_SECRET.
    1) synct alle Stripe-Abos (sperrt abgelaufene automatisch),
    2) sendet 7-Tage- und 2-Tage-Ablauf-Erinnerungen (gekündigte Abos),
    3) erinnert eine Woche vor der nächsten Abbuchung (aktive Abos)."""
    if not _cron_schluessel_pruefen('subscription-reminders'):
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
    # 4) Abgelaufene Ansehen-Links wirklich entfernen (7 Tage zugesagt)
    try:
        _share_aufraeumen()
    except Exception as e:
        logger.error('Aufraeumen der Ansehen-Links fehlgeschlagen: %s', type(e).__name__)
    _cron_protokoll('subscription-reminders', True,
                    '%d Abos mit Stripe abgeglichen · %d Ablaufwarnung(en) · %d Verlaengerungs-Erinnerung(en)%s'
                    % (synced, len(log), len(renewals),
                       ('\n' + '\n'.join(log + renewals)) if (log or renewals) else ''))
    return jsonify(ok=True, synced=synced, reminders=log, renewals=renewals)


# Werbemail: Obergrenze und wachsender Abstand.
#
# Vorher lief sie unbegrenzt alle 5 Tage weiter. Wer nach der dritten Mail nicht
# gekauft hat, kauft auch nach der zwoelften nicht — dafuer sinkt bei Brevo die
# Zustellrate fuer ALLE Mails, auch fuer Verifizierung und Abo-Ablauf. Der
# Abstand waechst, damit der letzte Anlauf nicht direkt hinterherkommt.
UPSELL_MAX = 3
UPSELL_ABSTAND = (5, 14, 30)     # Tage vor der 1., 2. und 3. Mail



# ══════════════════════════════════════════════
# EINMALIGE FUNKTIONS-ANKUENDIGUNG
# ══════════════════════════════════════════════
# Bewusst KEINE Werbemail: sie erzaehlt, was dazugekommen ist, und verkauft
# nichts. Fuer zahlende Kunden ist das ein Service, fuer alle anderen der beste
# Grund zurueckzukommen. Genau ein Satz am Ende weist Nicht-Abonnenten darauf
# hin, was davon Premium ist — mehr nicht.
#
# Wer sie NICHT bekommt: wer der Werbung widersprochen hat. Eine
# "Neuigkeiten"-Mail an Abgemeldete ist rechtlich weiterhin Werbung und
# praktisch das, was die Zustellrate ruiniert.
#
# EINMALIG ueber feature_mail_sent: ein zweiter Cron-Aufruf findet niemanden
# mehr. Deshalb liegt sie auch NICHT im taeglichen Cron.
FEATURE_MAIL_I18N = {
    'de': {
        'subject': 'Neu in HolzBau 3D: Holzverbindungen, Kollisionsprüfung und Projekte online',
        'preheader': 'Auflager und Überblattung als echter Zuschnitt, rote Kollisionsanzeige, Projekte speichern und teilen.',
        'hallo': 'Hallo',
        'fallback_name': 'zusammen',
        'intro': 'In den letzten Wochen ist einiges dazugekommen — hier das Wichtigste in Kürze.',
        'punkte': [
            ('Holzverbindungen',
             'Auflager, Überblattung sowie Schlitz und Zapfen als echte Geometrie — nicht angedeutet, sondern zugeschnitten. Ein Bauteil markieren genügt: es wird an alles angepasst, was es berührt, und nur es selbst wird eingeschnitten.'),
            ('Kollisionsprüfung',
             'Einschalten und dranlassen: wo zwei Bauteile denselben Raum belegen, wird genau dieser Bereich rot — auch tief in der Konstruktion. Eine Überschneidung von 40 mm sieht man im 3D nicht, auf der Baustelle schon.'),
            ('Giebel beplanken',
             'Dreieckige Flächen werden erkannt und die Platten passend zu den Sparren schräg zugeschnitten. Kein Nacharbeiten von Hand mehr.'),
            ('Schnitt A–A und Achsmaße',
             'Der Plan enthält jetzt einen Vertikalschnitt und Maßketten der Ständer- und Riegelachsen — damit muss niemand mehr Maße aus der Stückliste zurückrechnen.'),
            ('Projekte online speichern und teilen',
             'Projekte auf dem Server ablegen und am nächsten Gerät weiterarbeiten. Zum Zeigen einen Ansehen-Link erzeugen — nur für die E-Mail-Adressen, die du freischaltest, 7 Tage gültig, danach löscht er sich selbst.'),
        ],
        'cta': 'Jetzt ausprobieren',
        'premium_hinweis': 'Schnittplan, CNC-Export und die maßstäblichen Pläne gehören zu Premium — Planen, Verbinden und die Kollisionsprüfung sind für alle da.',
        'schluss': 'Wenn dir etwas fehlt oder etwas nicht stimmt: einfach auf diese Mail antworten. Fast alles hier oben ist aus solchen Rückmeldungen entstanden.',
        'gruss': 'Viele Grüße<br>David von HolzBau 3D',
        'unsub': 'Keine E-Mails mehr erhalten',
    },
    'en': {
        'subject': 'New in HolzBau 3D: timber joints, clash detection and projects online',
        'preheader': 'Bearing notches and halved laps as real cuts, red clash display, save and share projects.',
        'hallo': 'Hello',
        'fallback_name': 'there',
        'intro': 'Quite a bit has been added over the past weeks — here are the highlights.',
        'punkte': [
            ('Timber joints',
             'Bearing notch, halved lap and mortise-and-tenon as real geometry — actually cut, not just hinted at. Select a single part: it is fitted to everything it touches, and only it gets cut.'),
            ('Clash detection',
             'Switch it on and leave it on: wherever two parts occupy the same space, exactly that region turns red — even deep inside the structure. A 40 mm overlap is invisible in 3D, but not on site.'),
            ('Cladding gable ends',
             'Triangular surfaces are detected and the panels are cut at an angle to match the rafters. No more reworking by hand.'),
            ('Section A–A and axis dimensions',
             'Plans now include a vertical section and dimension chains for stud and rail axes — nobody has to back-calculate measurements from the parts list any more.'),
            ('Save projects online and share them',
             'Keep projects on the server and carry on at the next device. Create a view link to show your work — only for the e-mail addresses you allow, valid for 7 days, then deleted automatically.'),
        ],
        'cta': 'Try it now',
        'premium_hinweis': 'Cutting plans, CNC export and true-to-scale drawings are Premium — planning, joints and clash detection are there for everyone.',
        'schluss': 'If something is missing or does not work: just reply to this e-mail. Almost everything above came out of feedback like that.',
        'gruss': 'Best regards<br>David from HolzBau 3D',
        'unsub': 'Stop receiving e-mails',
    },
    'fr': {
        'subject': 'Nouveau dans HolzBau 3D : assemblages, détection de collisions et projets en ligne',
        'preheader': 'Appuis entaillés et mi-bois en découpe réelle, collisions en rouge, projets enregistrés et partagés.',
        'hallo': 'Bonjour',
        'fallback_name': 'à tous',
        'intro': 'Beaucoup de choses se sont ajoutées ces dernières semaines — voici l’essentiel.',
        'punkte': [
            ('Assemblages bois',
             'Appui entaillé, mi-bois et tenon-mortaise en géométrie réelle — vraiment découpés, pas seulement suggérés. Sélectionnez une seule pièce : elle s’ajuste à tout ce qu’elle touche, et elle seule est entaillée.'),
            ('Détection de collisions',
             'Activez-la et laissez-la : partout où deux pièces occupent le même espace, cette zone précise devient rouge — même au cœur de la structure. Un chevauchement de 40 mm ne se voit pas en 3D, sur le chantier si.'),
            ('Habillage des pignons',
             'Les surfaces triangulaires sont reconnues et les panneaux découpés en biais selon les chevrons. Plus de reprise à la main.'),
            ('Coupe A–A et cotes d’axes',
             'Les plans comportent désormais une coupe verticale et des chaînes de cotes des axes de montants et traverses — plus besoin de recalculer les mesures depuis la liste de pièces.'),
            ('Projets en ligne et partage',
             'Enregistrez vos projets sur le serveur et continuez sur un autre appareil. Créez un lien de consultation — réservé aux adresses e-mail que vous autorisez, valable 7 jours, puis supprimé automatiquement.'),
        ],
        'cta': 'Essayer maintenant',
        'premium_hinweis': 'Plans de coupe, export CNC et plans à l’échelle relèvent de Premium — la conception, les assemblages et la détection de collisions sont pour tout le monde.',
        'schluss': 'S’il manque quelque chose ou si un point ne va pas : répondez simplement à cet e-mail. Presque tout ce qui précède vient de retours de ce genre.',
        'gruss': 'Cordialement<br>David de HolzBau 3D',
        'unsub': 'Ne plus recevoir d’e-mails',
    },
}


def _email_feature_html(display_name, editor_url, unsub_url, lang='de', premium=False):
    """Die Ankuendigung im selben Gewand wie die uebrigen Mails."""
    T = FEATURE_MAIL_I18N.get(_norm_lang(lang), FEATURE_MAIL_I18N['de'])
    name = html.escape(display_name or '').strip() or T['fallback_name']
    punkte = ''.join(
        '<tr><td style="padding:9px 0;line-height:1.55;">'
        '<strong style="color:#3a2a1a;">' + titel + '</strong><br>'
        '<span style="color:#5a4a3a;">' + text + '</span></td></tr>'
        for titel, text in T['punkte'])
    # Der Premium-Hinweis nur fuer die, die keins haben — einem zahlenden Kunden
    # zu erklaeren, was Premium kann, ist bestenfalls ueberfluessig.
    hinweis = ('' if premium else
               '<tr><td style="padding:14px 0 0;font-size:13px;line-height:1.5;'
               'color:#7a6a5a;">' + T['premium_hinweis'] + '</td></tr>')
    lg = _norm_lang(lang)
    return (
        '<!DOCTYPE html>\n<html lang="' + lg + '"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0"></head>\n'
        '<body style="margin:0;padding:0;background:#f0e9df;">\n'
        '  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#f0e9df;'
        'font-size:1px;line-height:1px;">' + T['preheader'] + '</div>\n'
        '  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="background:#f0e9df;padding:24px 12px;"><tr><td align="center">\n'
        '    <table role="presentation" width="600" cellpadding="0" cellspacing="0" '
        'style="width:600px;max-width:600px;background:#fbf7f1;border:1px solid #e3d6c4;'
        'border-radius:14px;overflow:hidden;font-family:Georgia,\'Times New Roman\',serif;">\n'
        '      <tr><td style="height:5px;background:#9a5b2c;font-size:0;line-height:0;">&nbsp;</td></tr>\n'
        '      <tr><td style="padding:26px 40px 8px;">\n'
        '        <table role="presentation" cellpadding="0" cellspacing="0"><tr>\n'
        '          <td style="width:30px;vertical-align:middle;"><div style="width:26px;'
        'height:26px;background:#9a5b2c;border-radius:6px;"></div></td>\n'
        '          <td style="padding-left:10px;vertical-align:middle;font-size:20px;'
        'font-weight:bold;color:#3a2a1a;">HolzBau&nbsp;3D</td>\n'
        '        </tr></table>\n      </td></tr>\n'
        '      <tr><td style="padding:10px 40px 0;font-size:16px;color:#3a2a1a;">'
        + T['hallo'] + ' ' + name + ',</td></tr>\n'
        '      <tr><td style="padding:10px 40px 0;font-size:15px;line-height:1.6;'
        'color:#5a4a3a;">' + T['intro'] + '</td></tr>\n'
        '      <tr><td style="padding:12px 40px 0;"><table role="presentation" width="100%" '
        'cellpadding="0" cellspacing="0" style="font-size:14px;">\n'
        + punkte + hinweis +
        '      </table></td></tr>\n'
        '      <tr><td align="center" style="padding:26px 40px 6px;">\n'
        '        <a href="' + editor_url + '" style="display:inline-block;background:#9a5b2c;'
        'color:#fff;text-decoration:none;padding:13px 30px;border-radius:8px;font-size:16px;'
        'font-weight:bold;">' + T['cta'] + '</a>\n      </td></tr>\n'
        '      <tr><td style="padding:20px 40px 0;font-size:14px;line-height:1.6;'
        'color:#5a4a3a;">' + T['schluss'] + '</td></tr>\n'
        '      <tr><td style="padding:18px 40px 26px;font-size:14px;line-height:1.6;'
        'color:#3a2a1a;">' + T['gruss'] + '</td></tr>\n'
        '      <tr><td style="padding:14px 40px 22px;border-top:1px solid #e3d6c4;'
        'font-size:12px;color:#9a8a7a;">\n'
        '        <a href="' + unsub_url + '" style="color:#9a8a7a;">' + T['unsub'] + '</a>\n'
        '      </td></tr>\n    </table>\n  </td></tr></table>\n</body></html>')


@app.route('/admin/feature-mail-vorschau')
@admin_required
def admin_feature_mail_vorschau():
    """Erst lesen, dann senden. Eine Rundmail an alle laesst sich nicht
    zurueckholen — die Vorschau kostet nichts und verhindert genau das.
    ?lang=de|en|fr und ?premium=1 zeigen die Varianten."""
    basis = os.environ.get('BASE_URL', 'https://holzbau3d.app').rstrip('/')
    return _email_feature_html('David', basis + '/editor',
                               basis + '/abmelden?token=BEISPIEL',
                               _norm_lang(request.args.get('lang', 'de')),
                               request.args.get('premium') == '1')


@app.route('/cron/feature-mail', methods=['GET', 'POST'])
def cron_feature_mail():
    """Einmalige Ankuendigung neuer Funktionen.

    Absichtlich hinter dem CRON_SECRET und NICHT im taeglichen Cron: sie wird
    von Hand ausgeloest, wenn sie raus soll. Ein zweiter Aufruf findet niemanden
    mehr, weil feature_mail_sent gesetzt ist.

    Wer sie bekommt: bestaetigte E-Mail, kein Werbe-Widerspruch, noch nicht
    angeschrieben. Abo oder nicht spielt keine Rolle — neue Funktionen sind fuer
    zahlende Kunden ein Service, nicht Werbung.
    """
    if not _cron_schluessel_pruefen('feature-mail'):
        abort(403)
    basis = os.environ.get('BASE_URL', 'https://holzbau3d.app').rstrip('/')

    # Wie viele stehen insgesamt noch aus? Getrennt gezaehlt, damit der Aufrufer
    # den Fortschritt sieht, ohne die Mails zu verschicken.
    def _offen():
        r = query_db(
            """SELECT COUNT(*) AS c FROM app_users u
                WHERE u.email IS NOT NULL AND u.email <> ''
                  AND u.email_verified = 1 AND u.marketing_opt_out = 0
                  AND u.feature_mail_sent IS NULL""", [], one=True)
        return (r or {}).get('c', 0) or 0

    # Nur nachsehen, nichts verschicken.
    if request.args.get('nur_zaehlen') == '1':
        return jsonify(ok=True, offen=_offen(), verschickt=0)

    # HAEPPCHENWEISE. Beim ersten Versuch lief die Route in einen Timeout: rund
    # 87 Mails nacheinander dauern bei Brevo etwa 35 Sekunden, cron-job.org
    # bricht nach 30 ab — und der Arbeitsprozess wird irgendwann ohnehin
    # abgeraeumt. Weil jeder Empfaenger SOFORT markiert wird, ist ein Abbruch
    # harmlos: der naechste Aufruf macht genau dort weiter. Trotzdem soll ein
    # Aufruf zuegig antworten, statt sich abschiessen zu lassen.
    try:
        limit = max(1, min(100, int(request.args.get('limit', 20))))
    except (TypeError, ValueError):
        limit = 20
    rows = query_db(
        """SELECT u.id, u.email, u.full_name, u.username, u.unsub_token, u.lang,
                  COALESCE(s.plan, 'free') AS plan, COALESCE(s.status, '') AS status,
                  s.current_period_end
             FROM app_users u
             LEFT JOIN subscriptions s ON s.user_id = u.id
            WHERE u.email IS NOT NULL AND u.email <> ''
              AND u.email_verified = 1
              AND u.marketing_opt_out = 0
              AND u.feature_mail_sent IS NULL
            LIMIT ?""", [limit]) or []
    sent, failed = 0, 0
    for r in rows:
        try:
            token = r.get('unsub_token')
            if not token:
                token = secrets.token_urlsafe(32)
                execute_db('UPDATE app_users SET unsub_token=? WHERE id=?', [token, r['id']])
            u_lang = _norm_lang(r.get('lang'))
            ende = r.get('current_period_end')
            premium = (r.get('plan') == 'premium' and (
                r.get('status') == 'active'
                or (r.get('status') == 'cancelled'
                    and (not ende or ende > datetime.now()))))
            body = _email_feature_html(r.get('full_name') or r.get('username') or '',
                                       basis + '/editor',
                                       basis + '/abmelden?token=' + token,
                                       u_lang, premium)
            if send_email(r['email'], FEATURE_MAIL_I18N[u_lang]['subject'], body):
                # SOFORT markieren, nicht am Ende des Laufs: bricht er in der
                # Mitte ab, darf niemand die Mail beim naechsten Versuch ein
                # zweites Mal bekommen.
                execute_db('UPDATE app_users SET feature_mail_sent=NOW() WHERE id=?', [r['id']])
                sent += 1
            else:
                failed += 1
        except Exception as e:
            logger.error('feature-mail an Nutzer %s fehlgeschlagen: %s',
                         r.get('id'), type(e).__name__)
            failed += 1
    offen = _offen()
    _cron_protokoll('feature-mail', True,
                    '%d verschickt, %d fehlgeschlagen, %d in diesem Haeppchen, %d noch offen'
                    % (sent, failed, len(rows), offen))
    # `offen` ist die Antwort auf die einzige Frage, die der Aufrufer hat:
    # muss ich nochmal? 0 heisst fertig.
    return jsonify(ok=True, sent=sent, failed=failed, kandidaten=len(rows), offen=offen)


@app.route('/cron/premium-upsell', methods=['GET', 'POST'])
def cron_premium_upsell():
    """Werbemail an Nutzer OHNE laufendes Abo. Taeglich aufrufbar — wer wann
    dran ist, entscheidet die Abfrage, nicht der Cron-Takt.

    Wer sie NICHT bekommt:
      - laufende Abo-Kunden (aktiv oder gekuendigt mit noch bezahlter Laufzeit)
      - wer der Werbung widersprochen hat (marketing_opt_out, Abmeldelink)
      - wer keine bestaetigte E-Mail hat
      - wer die Mail schon UPSELL_MAX mal bekommen hat
    Der Abstand waechst mit jeder Mail (UPSELL_ABSTAND), damit der letzte
    Anlauf nicht direkt hinterherkommt."""
    if not _cron_schluessel_pruefen('premium-upsell'):
        abort(403)
    base_url = os.environ.get('BASE_URL', 'https://holzbau3d.app').rstrip('/')
    subscribe_url = base_url + '/subscribe'
    rows = query_db(
        """SELECT u.id, u.email, u.full_name, u.username, u.unsub_token, u.lang
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
              AND u.upsell_count < %d
              AND (u.last_upsell_sent IS NULL
                   OR u.last_upsell_sent < DATE_SUB(NOW(), INTERVAL
                        (CASE u.upsell_count WHEN 0 THEN %d WHEN 1 THEN %d ELSE %d END) DAY))"""
        % (UPSELL_MAX, UPSELL_ABSTAND[0], UPSELL_ABSTAND[1], UPSELL_ABSTAND[2]),
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
            # Die Sprache des Nutzers, wie bei allen anderen Mails. Bis eben
            # ging diese eine Mail immer deutsch raus — u.lang wurde nicht
            # einmal geladen.
            u_lang = _norm_lang(r.get('lang'))
            body = _email_upsell_html(name, subscribe_url, unsub_url, u_lang)
            if send_email(r['email'], UPSELL_I18N[u_lang]['subject'], body):
                execute_db('UPDATE app_users SET last_upsell_sent=NOW(), '
                           'upsell_count=upsell_count+1 WHERE id=?', [r['id']])
                sent += 1
            else:
                failed += 1
        except Exception as e:
            failed += 1
            logger.error('premium-upsell send failed for user %s: %s', r.get('id'), type(e).__name__)
    logger.info('premium-upsell: %s sent, %s failed, %s candidates', sent, failed, len(rows))
    _cron_protokoll('premium-upsell', True,
                    '%d Empfaenger in Frage · %d gesendet · %d fehlgeschlagen'
                    % (len(rows), sent, failed))
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


UPSELL_I18N = {
    'de': {
        'subject':   'Hol mehr aus deinen Holzprojekten – HolzBau 3D Premium',
        'preheader': 'Schneller planen: fertige Vorlagen, PDF- & CNC-Export, Schnittplan – werbefrei, 2 Monate gratis im Jahresabo.',
        'fallback_name': 'Holzbauer',
        'h1':        'Hallo {name}, hol das Maximum<br>aus deinen Holzprojekten.',
        'intro':     'Du planst deine Konstruktionen schon kostenlos in 3D – stark! Mit <strong style="color:#9a5b2c;">HolzBau&nbsp;3D&nbsp;Premium</strong> arbeitest du schneller, sauberer und ganz ohne Werbung. Alles freigeschaltet, für ein faires Abo.',
        'b1t': 'Fertige Vorlagen nach Maß', 'b1d': 'Carport, Gartenhaus, Terrassendach — die Pergola ist gratis',
        'b2t': 'Vollständig werbefrei',            'b2d': 'volle Konzentration aufs Konstruieren',
        'b3t': 'PDF-Export &amp; Druckpläne',      'b3d': 'direkt für Bauantrag oder Werkstatt',
        'b4t': 'Säge-Tool &amp; Schnittplan-Optimierung', 'b4d': 'weniger Verschnitt, weniger Kosten',
        'b5t': 'Gruppen &amp; Ebenen',             'b5d': 'Überblick auch bei großen Projekten',
        'b6t': 'Prioritäts-Support',               'b6d': 'wir helfen zuerst dir',
        'from':      'Schon ab',
        'per_month': '/Monat',
        'yearly':    'oder {y}/Jahr&nbsp;— 2 Monate&nbsp;gratis&nbsp;🎉',
        'cta':       'Jetzt Premium freischalten →',
        'nostrings': 'Jederzeit kündbar · keine Mindestlaufzeit',
        'why':       'Du erhältst diese E-Mail, weil du ein kostenloses HolzBau&nbsp;3D-Konto hast.',
        'unsub':     'Keine Angebote mehr erhalten (abmelden)',
        'imprint':   'Impressum',
        'privacy':   'Datenschutz',
    },
    'en': {
        'subject':   'Get more out of your timber projects – HolzBau 3D Premium',
        'preheader': 'Plan faster: ready-made templates, PDF & CNC export, cutting plan – ad-free, 2 months free on the yearly plan.',
        'fallback_name': 'there',
        'h1':        'Hello {name}, get the most<br>out of your timber projects.',
        'intro':     'You are already planning your structures in 3D for free – nice work! With <strong style="color:#9a5b2c;">HolzBau&nbsp;3D&nbsp;Premium</strong> you work faster, cleaner and completely without ads. Everything unlocked, for a fair subscription.',
        'b1t': 'Ready-made templates to size',   'b1d': 'carport, pergola, garden house, patio roof',
        'b2t': 'Completely ad-free',               'b2d': 'full focus on your design',
        'b3t': 'PDF export &amp; print plans',     'b3d': 'ready for the permit office or the workshop',
        'b4t': 'Saw tool &amp; cutting optimiser', 'b4d': 'less offcut, lower cost',
        'b5t': 'Groups &amp; layers',              'b5d': 'keep track even on big projects',
        'b6t': 'Priority support',                 'b6d': 'you get helped first',
        'from':      'From just',
        'per_month': '/month',
        'yearly':    'or {y}/year&nbsp;— 2 months&nbsp;free&nbsp;🎉',
        'cta':       'Unlock Premium now →',
        'nostrings': 'Cancel anytime · no minimum term',
        'why':       'You are receiving this email because you have a free HolzBau&nbsp;3D account.',
        'unsub':     'Stop receiving offers (unsubscribe)',
        'imprint':   'Legal notice',
        'privacy':   'Privacy',
    },
    'fr': {
        'subject':   'Tirez le meilleur de vos projets bois – HolzBau 3D Premium',
        'preheader': 'Concevez plus vite : modèles prêts, export PDF & CNC, plan de coupe – sans publicité, 2 mois offerts sur l’abonnement annuel.',
        'fallback_name': 'à vous',
        'h1':        'Bonjour {name}, tirez le meilleur<br>de vos projets bois.',
        'intro':     'Vous concevez déjà vos structures en 3D gratuitement – bravo ! Avec <strong style="color:#9a5b2c;">HolzBau&nbsp;3D&nbsp;Premium</strong>, vous travaillez plus vite, plus proprement et sans aucune publicité. Tout est débloqué, pour un abonnement au juste prix.',
        'b1t': 'Modèles prêts à la bonne taille', 'b1d': 'carport, pergola, abri de jardin, toiture',
        'b2t': 'Entièrement sans publicité',       'b2d': 'toute votre attention à la conception',
        'b3t': 'Export PDF &amp; plans imprimés',  'b3d': 'prêts pour le permis de construire ou l’atelier',
        'b4t': 'Outil scie &amp; optimisation des coupes', 'b4d': 'moins de chutes, moins de frais',
        'b5t': 'Groupes &amp; calques',            'b5d': 'gardez la vue d’ensemble sur les grands projets',
        'b6t': 'Support prioritaire',              'b6d': 'vous êtes servi en premier',
        'from':      'À partir de',
        'per_month': '/mois',
        'yearly':    'ou {y}/an&nbsp;— 2 mois&nbsp;offerts&nbsp;🎉',
        'cta':       'Activer Premium →',
        'nostrings': 'Résiliable à tout moment · sans durée minimale',
        'why':       'Vous recevez cet e-mail parce que vous avez un compte HolzBau&nbsp;3D gratuit.',
        'unsub':     'Ne plus recevoir d’offres (se désabonner)',
        'imprint':   'Mentions légales',
        'privacy':   'Confidentialité',
    },
}


def _email_upsell_html(display_name, subscribe_url, unsub_url, lang='de'):
    """Weekly Premium-upsell email for non-premium users ('Warmes Handwerk' design).

    Lag lange nur auf Deutsch vor — englische und franzoesische Nutzer bekamen
    eine deutsche Werbe-Mail. Aufgefallen ist es erst, als die Mail-Uebersicht
    im Admin alle Vorlagen nebeneinander zeigte.
    """
    T = UPSELL_I18N.get(_norm_lang(lang), UPSELL_I18N['de'])
    name = html.escape(display_name or '').strip() or T['fallback_name']
    # Preise kommen aus denselben Env-Variablen wie die Kaufseite, damit Mail und
    # Seite nie auseinanderlaufen.
    m_preis, j_preis = _price_text('monthly'), _price_text('yearly')
    punkte = ''.join(
        f'<tr><td style="padding:7px 0;line-height:1.5;"><span style="color:#3d7a3d;font-weight:bold;">✓</span>&nbsp;&nbsp;'
        f'<strong>{T[f"b{i}t"]}</strong> – {T[f"b{i}d"]}</td></tr>'
        for i in range(1, 7)
    )
    return f'''<!DOCTYPE html>
<html lang="{_norm_lang(lang)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f0e9df;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#f0e9df;font-size:1px;line-height:1px;">{T['preheader']}</div>
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
        <h1 style="margin:0;font-family:Georgia,serif;font-weight:normal;font-size:30px;line-height:1.2;color:#2a1c0e;">{T['h1'].replace('{name}', name)}</h1>
      </td></tr>
      <tr><td style="padding:14px 40px 6px;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.65;color:#5a4a38;">
        {T['intro']}
      </td></tr>
      <tr><td style="padding:12px 40px 6px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-family:Arial,Helvetica,sans-serif;font-size:15px;color:#3a2a1a;">
          {punkte}
        </table>
      </td></tr>
      <tr><td style="padding:18px 40px 6px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3ebdf;border:1px solid #e3d6c4;border-radius:10px;"><tr>
          <td align="center" style="padding:18px 20px;font-family:Arial,Helvetica,sans-serif;">
            <div style="font-size:14px;color:#5a4a38;">{T['from']}</div>
            <div style="font-family:Georgia,serif;font-size:34px;color:#2a1c0e;padding:2px 0;"><strong>{m_preis}</strong><span style="font-size:15px;color:#5a4a38;">{T['per_month']}</span></div>
            <div style="font-size:14px;color:#9a5b2c;font-weight:bold;">{T['yearly'].replace('{y}', j_preis)}</div>
          </td>
        </tr></table>
      </td></tr>
      <tr><td align="center" style="padding:22px 40px 8px;">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr>
          <td align="center" style="background:#9a5b2c;border-radius:8px;">
            <a href="{subscribe_url}" target="_blank" style="display:inline-block;padding:15px 38px;font-family:Arial,Helvetica,sans-serif;font-size:16px;font-weight:bold;color:#ffffff;text-decoration:none;border-radius:8px;">{T['cta']}</a>
          </td>
        </tr></table>
      </td></tr>
      <tr><td align="center" style="padding:4px 40px 26px;font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#8a7a68;">{T['nostrings']}</td></tr>
      <tr><td style="padding:0 40px;"><div style="border-top:1px solid #e8ddce;font-size:0;line-height:0;">&nbsp;</div></td></tr>
      <tr><td style="padding:18px 40px 28px;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:1.6;color:#9a8b78;">
        {T['why']}<br>
        <a href="{unsub_url}" style="color:#9a5b2c;">{T['unsub']}</a>
        &nbsp;·&nbsp;<a href="https://holzbau3d.app/impressum" style="color:#9a5b2c;">{T['imprint']}</a>
        &nbsp;·&nbsp;<a href="https://holzbau3d.app/datenschutz" style="color:#9a5b2c;">{T['privacy']}</a>
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
            # Lokal formatieren: 23:00 UTC ist lokal schon der Folgetag.
            next_txt = _filter_lokal_datum(pe_dt) if pe_dt else None
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
        'd1_subject': 'HolzBau 3D – Morgen wird dein Abo verlängert ({amount})',
        'd1_title': 'Morgen wird dein Abo verlängert',
        'd1_body': 'kurze Erinnerung: dein <strong>{plan}</strong> verlängert sich <strong>morgen, am {date}</strong>. '
                   'Dann werden <strong>{amount}</strong> über Stripe abgebucht.',
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
        'd1_subject': 'HolzBau 3D – Your subscription renews tomorrow ({amount})',
        'd1_title': 'Your subscription renews tomorrow',
        'd1_body': 'a quick reminder: your <strong>{plan}</strong> renews <strong>tomorrow, on {date}</strong>. '
                   '<strong>{amount}</strong> will then be charged via Stripe.',
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
        'd1_subject': 'HolzBau 3D – Votre abonnement se renouvelle demain ({amount})',
        'd1_title': 'Votre abonnement se renouvelle demain',
        'd1_body': 'petit rappel : votre <strong>{plan}</strong> se renouvelle <strong>demain, le {date}</strong>. '
                   '<strong>{amount}</strong> seront alors prélevés via Stripe.',
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
        'body': 'dein gekündigtes Premium-Abo läuft am <strong>{date}</strong> aus — also in {days}. Danach hast du keinen Zugang mehr zu den Premium-Funktionen (Vorlagen, PDF-Export, Säge-Tool, werbefrei).',
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
        'body': 'votre abonnement Premium résilié se termine le <strong>{date}</strong> — dans {days}. Vous perdrez alors l’accès aux fonctionnalités Premium (modèles, export PDF, outil scie, sans publicité).',
        'button': 'Conserver Premium',
        'note': 'Vous souhaitez conserver Premium ? Vous pouvez le réactiver à tout moment en un clic — vos projets existants sont bien sûr conservés.',
    },
}


def _email_renewal_html(display_name, date_txt, amount_txt, interval, lang='de', stage='7d'):
    T = RENEWAL_I18N.get(_norm_lang(lang), RENEWAL_I18N['de'])
    L = EMAIL_I18N.get(_norm_lang(lang), EMAIL_I18N['de'])
    plan_txt = L['p_plan_y'] if interval == 'yearly' else L['p_plan_m']
    base_url = os.environ.get('BASE_URL', 'https://holzbau3d.app')
    # 1-Tag-Stufe: dringlicherer Titel/Text ("morgen"); sonst die Wochen-Variante.
    title = T.get('d1_title', T['title']) if stage == '1d' else T['title']
    body_tpl = T.get('d1_body', T['body']) if stage == '1d' else T['body']
    body = body_tpl.replace('{date}', date_txt).replace('{amount}', amount_txt).replace('{plan}', plan_txt)
    cancel = T['cancel'].replace('{date}', date_txt)
    return _email_shell(f'''    <h2 style="margin:0 0 16px;font-size:1.15rem;color:#1a1a1a;font-weight:700;">{title}</h2>
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
    end_txt = _filter_lokal_datum(pe) if pe else '—'
    subj = CANCEL_I18N[lang]['subject'].replace('{date}', end_txt)
    send_email(row['email'], subj, _email_cancel_html(row['full_name'] or row['username'], end_txt, lang))


# ---------------------------------------------------------------------------
# Mail-Uebersicht fuers Admin-Panel
# ---------------------------------------------------------------------------
# Eine Liste ALLER Mails, die das System verschickt — mit Ausloeser und einer
# echten Vorschau. "Echt" heisst: die Vorschau ruft dieselbe Funktion auf, die
# auch der Versand nutzt. Eine nachgebaute Vorschau waere wertlos, sie wuerde
# genau dann noch stimmen, wenn die Vorlage sich aendert.
#
# 'render' bekommt die Sprache und liefert (Betreff, HTML). Die Beispielwerte
# sind bewusst erkennbar erfunden (Max Mustermann), damit niemand eine Vorschau
# fuer eine echte Mail haelt.
def _mail_beispiel_datum(tage=7):
    return _filter_lokal_datum(datetime.utcnow() + timedelta(days=tage))


MAIL_VORLAGEN = [
    {
        'key': 'verify',
        'name': 'E-Mail bestätigen',
        'wann': 'Sofort nach der Registrierung.',
        'ausloeser': 'ereignis',
        'render': lambda lang: (
            EMAIL_I18N[lang]['v_subject'],
            _email_verify_html('Max Mustermann', 'https://holzbau3d.app/verify-email/BEISPIEL-TOKEN', lang)),
    },
    {
        'key': 'reset',
        'name': 'Passwort zurücksetzen',
        'wann': 'Wenn jemand „Passwort vergessen“ nutzt.',
        'ausloeser': 'ereignis',
        'render': lambda lang: (
            EMAIL_I18N[lang]['r_subject'],
            _email_reset_html('Max Mustermann', 'https://holzbau3d.app/reset-password/BEISPIEL-TOKEN', lang)),
    },
    {
        'key': 'premium',
        'name': 'Premium aktiviert',
        'wann': 'Nach erfolgreicher Zahlung (Stripe-Webhook).',
        'ausloeser': 'ereignis',
        'render': lambda lang: (
            EMAIL_I18N[lang]['p_subject'],
            _email_premium_html('Max Mustermann', _price_text('monthly'), 'monthly',
                                'https://invoice.stripe.com/BEISPIEL', lang, _mail_beispiel_datum(30))),
    },
    {
        'key': 'renewal',
        'name': 'Verlängerung — 7 Tage vorher',
        'wann': 'Rund 7 Tage vor der nächsten Abbuchung eines aktiven Abos.',
        'ausloeser': 'cron',
        'job': 'subscription-reminders',
        'render': lambda lang: (
            RENEWAL_I18N[lang]['subject'].replace('{date}', _mail_beispiel_datum(7))
                                         .replace('{amount}', _price_text('monthly')),
            _email_renewal_html('Max Mustermann', _mail_beispiel_datum(7), _price_text('monthly'), 'monthly', lang, '7d')),
    },
    {
        'key': 'renewal1d',
        'name': 'Verlängerung — 1 Tag vorher',
        'wann': 'Rund 1 Tag vor der nächsten Abbuchung eines aktiven Abos.',
        'ausloeser': 'cron',
        'job': 'subscription-reminders',
        'render': lambda lang: (
            RENEWAL_I18N[lang]['d1_subject'].replace('{date}', _mail_beispiel_datum(1))
                                            .replace('{amount}', _price_text('monthly')),
            _email_renewal_html('Max Mustermann', _mail_beispiel_datum(1), _price_text('monthly'), 'monthly', lang, '1d')),
    },
    {
        'key': 'expiry7',
        'name': 'Abo läuft ab — 7 Tage',
        'wann': '7 Tage bevor ein gekündigtes Abo endet.',
        'ausloeser': 'cron',
        'job': 'subscription-reminders',
        'render': lambda lang: (
            EXPIRY_I18N[lang]['subject'].replace('{days}', EXPIRY_I18N[lang]['d7']),
            _email_expiry_html('Max Mustermann', _mail_beispiel_datum(7), '7d', lang)),
    },
    {
        'key': 'expiry2',
        'name': 'Abo läuft ab — 2 Tage',
        'wann': '2 Tage bevor ein gekündigtes Abo endet.',
        'ausloeser': 'cron',
        'job': 'subscription-reminders',
        'render': lambda lang: (
            EXPIRY_I18N[lang]['subject'].replace('{days}', EXPIRY_I18N[lang]['d2']),
            _email_expiry_html('Max Mustermann', _mail_beispiel_datum(2), '2d', lang)),
    },
    {
        'key': 'cancel',
        'name': 'Kündigung bestätigt',
        'wann': 'Sofort nach einer Kündigung.',
        'ausloeser': 'ereignis',
        'render': lambda lang: (
            CANCEL_I18N[lang]['subject'].replace('{date}', _mail_beispiel_datum(21)),
            _email_cancel_html('Max Mustermann', _mail_beispiel_datum(21), lang)),
    },
    {
        'key': 'feedback',
        'name': 'Antwort auf Feedback',
        'wann': 'Wenn du im Admin-Panel auf ein Feedback antwortest.',
        'ausloeser': 'ereignis',
        'render': lambda lang: (
            FEEDBACK_I18N[lang]['subject'].replace('{subject}', 'Beispiel-Betreff'),
            _email_feedback_html('Max Mustermann', 'Beispiel-Betreff',
                                 'Das ist der Beispieltext deiner Antwort.',
                                 _status_label('erledigt', lang), lang)),
    },
    {
        'key': 'upsell',
        'name': 'Premium-Werbung',
        'wann': 'Wöchentlich an alle Nicht-Premium-Nutzer (höchstens alle 5 Tage pro Person).',
        'ausloeser': 'cron',
        'job': 'premium-upsell',
        'render': lambda lang: (
            UPSELL_I18N[lang]['subject'],
            _email_upsell_html('Max Mustermann', 'https://holzbau3d.app/subscribe',
                               'https://holzbau3d.app/abmelden?token=BEISPIEL', lang)),
    },
]

# Diese zwei Mails bauen ihr HTML direkt an der Versandstelle zusammen, statt
# eine eigene Vorlagen-Funktion zu haben. Sie ehrlich auflisten statt zu
# verschweigen — eine Uebersicht, die etwas weglaesst, ist keine Uebersicht.
MAIL_OHNE_VORLAGE = [
    {'name': 'Konto gelöscht', 'wann': 'Nach der Konto-Löschung, kurz vor dem Entfernen der Daten.',
     'wo': '_send_delete_email()'},
    {'name': 'Neues Feedback (an dich)', 'wann': 'Sobald ein Nutzer Feedback abschickt.',
     'wo': 'submit_feedback()'},
]

# Was der externe Dienst (cron-job.org) aufrufen SOLL. Der Zeitplan steht dort,
# nicht hier — deshalb ist 'plan' reiner Beschreibungstext, den du beim Anlegen
# des Jobs eingestellt hast. 'max_stunden' sagt, ab wann Schweigen verdaechtig ist.
CRON_JOBS = [
    {'job': 'subscription-reminders', 'name': 'Abo-Erinnerungen & Stripe-Abgleich',
     'plan': 'täglich', 'max_stunden': 26,
     'zweck': 'Gleicht alle Abos mit Stripe ab, warnt vor Ablauf (7/2 Tage) und erinnert an die Verlängerung.'},
    {'job': 'premium-upsell', 'name': 'Premium-Werbung',
     'plan': 'wöchentlich', 'max_stunden': 24 * 8,
     'zweck': 'Schickt Nicht-Premium-Nutzern die Werbe-Mail.'},
]


def _send_delete_email(user_id, sub_info=None):
    """Bestätigungs-Mail nach Konto-Löschung — wird VOR dem DB-Delete aufgerufen."""
    row = query_db('SELECT email, full_name, username, lang FROM app_users WHERE id=?', [user_id], one=True)
    if not row or not row['email']:
        return
    lang     = _norm_lang(row.get('lang') if hasattr(row, 'get') else 'de')
    name     = row['full_name'] or row['username'] or row['email']
    email    = row['email']
    now_str  = _filter_lokal(datetime.utcnow()) + ' Uhr'

    had_sub  = sub_info and sub_info.get('stripe_sub_id')
    pe       = _to_dt(sub_info['current_period_end']) if sub_info and sub_info.get('current_period_end') else None
    end_str  = _filter_lokal_datum(pe) if pe else None

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
    """Erinnert vor der naechsten Abbuchung eines AKTIVEN Abos — in ZWEI Stufen:
    ~7 Tage vorher UND ~1 Tag vorher. Damit wird niemand von der Abbuchung
    ueberrascht. Nur fuer nicht gekuendigte Abos — gekuendigte bekommen die
    Ablaufwarnung aus _run_subscription_reminders().
    Idempotent pro Periode ueber renewal_notice_for (= Periodenende) + renewal_stage
    (welche Stufen '7d'/'1d' schon raus sind). Gibt eine Log-Liste zurueck."""
    out = []
    rows = query_db(
        "SELECT s.user_id, s.current_period_end, s.plan_interval, s.renewal_notice_for, "
        "s.renewal_stage, u.email, u.full_name, u.username, u.lang "
        "FROM subscriptions s JOIN app_users u ON u.id = s.user_id "
        "WHERE s.plan='premium' AND s.status='active'", []
    )
    now = datetime.utcnow()
    for r in rows:
        pe = _to_dt(r['current_period_end'])
        if not pe or not r['email']:
            continue
        days_left = (pe - now).total_seconds() / 86400.0
        if days_left <= 0 or days_left > 8.0:
            continue

        # Welche Stufen wurden fuer GENAU diese Periode schon gesendet?
        already_for = _to_dt(r['renewal_notice_for'])
        same_period = already_for and abs((already_for - pe).total_seconds()) < 3600
        if same_period:
            sent = set(x for x in (r['renewal_stage'] or '').split(',') if x)
            # Altbestand: frueher gab es nur eine Mail (~7 Tage vorher) ohne Stufe.
            # Die zaehlt als '7d', damit sie nicht ein zweites Mal als Wochen-Mail kommt.
            if not sent:
                sent = {'7d'}
        else:
            sent = set()   # neue Periode -> Stufen zuruecksetzen

        # Faellige Stufe bestimmen: 1-Tag hat Vorrang, wenn wir schon nah dran sind.
        if 0 < days_left <= 1.5 and '1d' not in sent:
            stage = '1d'
        elif 1.5 < days_left <= 8.0 and '7d' not in sent:
            stage = '7d'
        else:
            continue   # fuer die aktuelle Naehe schon erinnert

        interval = r['plan_interval'] or 'monthly'
        u_lang = _norm_lang(r['lang'])
        date_txt = _filter_lokal_datum(pe)
        amount_txt = _price_text(interval)
        subj_key = 'd1_subject' if stage == '1d' else 'subject'
        subject = (RENEWAL_I18N[u_lang].get(subj_key, RENEWAL_I18N[u_lang]['subject'])
                   .replace('{date}', date_txt).replace('{amount}', amount_txt))
        ok = send_email(r['email'], subject,
                        _email_renewal_html(r['full_name'] or r['username'],
                                            date_txt, amount_txt, interval, u_lang, stage))
        if ok:
            sent.add(stage)
            execute_db('UPDATE subscriptions SET renewal_notice_for=?, renewal_stage=? WHERE user_id=?',
                       [pe.strftime('%Y-%m-%d %H:%M:%S'), ','.join(sorted(sent)), r['user_id']])
            out.append(f"user {r['user_id']}: Verlaengerungs-Erinnerung [{stage}] gesendet "
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
                        _email_expiry_html(r['full_name'] or r['username'], _filter_lokal_datum(pe), send_stage, u_lang))
        if ok:
            execute_db('UPDATE subscriptions SET reminder_stage=? WHERE user_id=?', [send_stage, r['user_id']])
            out.append(f"user {r['user_id']}: {send_stage}-Erinnerung gesendet (Ablauf in {days_left:.1f}d)")
        else:
            out.append(f"user {r['user_id']}: Mail-Versand fehlgeschlagen")
    return out


def _nutzer_zu_stripe_kunde(cust):
    """Welches Konto gehoert zu diesem Stripe-Kunden? 0, wenn keines passt.

    Erst ueber die gespeicherte Kundenkennung, sonst ueber die E-Mail-Adresse
    bei Stripe. Genau diese Zuordnung fehlte bisher beim Checkout-Ereignis —
    dort wurde blind auf die Metadaten vertraut.
    """
    if not cust:
        return 0
    row = query_db('SELECT user_id FROM subscriptions WHERE stripe_customer_id=?', [cust], one=True)
    if row:
        return row['user_id']
    try:
        mail = ((_stripe_api_get('customers/' + cust) or {}).get('email') or '').strip()
        if mail:
            u = query_db('SELECT id FROM app_users WHERE LOWER(email)=LOWER(?)', [mail], one=True)
            if u:
                return u['id']
    except Exception as e:
        logger.error('Kunden-E-Mail bei Stripe nicht lesbar (%s): %s', cust, str(e)[:200])
    return 0


def _handle_stripe_event(event):
    data = event['data']['object']
    etype = event['type']
    if etype == 'checkout.session.completed':
        """Hier ist der Webhook gestorben.

        Frueher stand hier int(data.get('metadata', {}).get('user_id', 0)).
        Der Vorgabewert {} greift nur, wenn der SCHLUESSEL FEHLT — schickt
        Stripe dagegen "metadata": null, kommt None zurueck und .get() darauf
        wirft. Und eine Sitzung ohne unsere Metadaten gibt es wirklich: jeder
        Zahlungslink und jede im Stripe-Dashboard erzeugte Sitzung hat keine.
        Die Ausnahme wurde mit 400 beantwortet, Stripe hat es neun Mal wieder
        versucht und wollte den Endpunkt abschalten.
        """
        meta = data.get('metadata') or {}
        try:
            user_id = int(meta.get('user_id') or 0)
        except (TypeError, ValueError):
            user_id = 0
        interval = 'yearly' if meta.get('plan_type') == 'yearly' else 'monthly'
        if not user_id:
            # Ohne Metadaten ueber den Kunden zuordnen, statt aufzugeben.
            user_id = _nutzer_zu_stripe_kunde(data.get('customer'))
            if user_id:
                logger.info('Checkout ohne Metadaten dem Konto %s zugeordnet', user_id)
        if user_id:
            _activate_premium(user_id, data.get('customer'), data.get('subscription'), interval)
        else:
            logger.warning('checkout.session.completed ohne zuordenbares Konto '
                           '(Kunde=%s, Sitzung=%s) — nichts freigeschaltet',
                           data.get('customer'), data.get('id'))
        _kaufweg_abschluss('bezahlt', None, data.get('id'), user_id or None)
    elif etype == 'checkout.session.expired':
        # Stripe laesst eine unbezahlte Kasse nach 24 Stunden verfallen. Das ist
        # der zweite Abbruchweg neben ?cancelled=1: wer den Tab einfach
        # zumacht, kommt hier an — nur eben einen Tag spaeter.
        # Muss im Stripe-Dashboard fuer den Endpunkt aktiviert sein; fehlt das
        # Ereignis, faengt die 26-Stunden-Regel in der Auswertung den Fall auf.
        _kaufweg_abschluss('abgebrochen', 'abgelaufen', data.get('id'))
    elif etype in ('customer.subscription.created', 'customer.subscription.deleted',
                   'customer.subscription.updated'):
        # 'created' war frueher nicht dabei — dadurch kam ein von Hand im Stripe-
        # Dashboard angelegtes Abo nie in der App an (es gibt dazu keine
        # Checkout-Session, also auch kein checkout.session.completed).
        sub_id = data.get('id')
        cust = data.get('customer')
        row = query_db('SELECT user_id FROM subscriptions WHERE stripe_sub_id=?', [sub_id], one=True)
        if not row and cust:
            # Kunde schon bekannt, nur dieses Abo noch nicht -> nachtragen.
            row = query_db('SELECT user_id FROM subscriptions WHERE stripe_customer_id=?', [cust], one=True)
            if row:
                execute_db('UPDATE subscriptions SET stripe_sub_id=? WHERE user_id=?', [sub_id, row['user_id']])
        if not row and cust:
            # Letzter Weg: Kunde bei Stripe nachschlagen und ueber die E-Mail zuordnen.
            try:
                mail = ((_stripe_api_get('customers/' + cust) or {}).get('email') or '').strip()
                if mail:
                    u = query_db('SELECT id FROM app_users WHERE LOWER(email)=LOWER(?)', [mail], one=True)
                    if u:
                        if query_db('SELECT user_id FROM subscriptions WHERE user_id=?', [u['id']], one=True):
                            execute_db('UPDATE subscriptions SET stripe_customer_id=?, stripe_sub_id=? '
                                       'WHERE user_id=?', [cust, sub_id, u['id']])
                        else:
                            execute_db('INSERT INTO subscriptions (user_id, stripe_customer_id, '
                                       'stripe_sub_id, plan, status) VALUES (?, ?, ?, ?, ?)',
                                       [u['id'], cust, sub_id, 'free', 'active'])
                        row = {'user_id': u['id']}
                        logger.info('Stripe-Abo %s ueber E-Mail dem Nutzer %s zugeordnet', sub_id, u['id'])
            except Exception as e:
                logger.error('Zuordnung ueber Kunden-E-Mail fehlgeschlagen (%s): %s', sub_id, type(e).__name__)
        if row:
            _sync_user_from_stripe(row['user_id'])
        else:
            logger.warning('Stripe-Event %s fuer Abo %s: kein passendes Konto gefunden', etype, sub_id)


# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
else:
    with app.app_context():
        init_db()
