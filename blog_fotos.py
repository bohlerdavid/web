# -*- coding: utf-8 -*-
"""Echte Projektfotos in ausgewaehlte Ratgeber-Artikel einblenden.

Warum: Googles AdSense-/Search-Qualitaet verlangt "original content" und
"first-hand expertise" (E-E-A-T). Eigene Fotos gebauter Projekte sind das
staerkste Signal dafuer, dass hinter der Seite echte Erfahrung steht – kein
maschinell erzeugter Text.

Wie es funktioniert:
  - Fuer jeden Slug ist EIN fester Dateiname reserviert (static/projekte/<datei>).
  - Solange die Datei NICHT existiert, wird nichts eingefuegt. So erscheint auf
    der Live-Seite nie ein kaputtes Platzhalterbild – wichtig waehrend der
    laufenden AdSense-Pruefung.
  - Sobald David die Datei in static/projekte/ ablegt (und pusht), erscheint das
    Foto automatisch ganz oben im Artikel, mit fertiger Bildunterschrift, und
    wird zum OG-/JSON-LD-Hero-Bild.

David muss also nur die Fotos liefern. Die Bildunterschriften unten sind bewusst
ehrlich und ohne erfundene Details – bei Bedarf hier den Text je Sprache anpassen.
"""
import os

# slug -> {datei, de/en/fr Bildunterschrift}
FOTOS = {
    'pergola-selbst-bauen': {
        'datei': 'pergola.jpg',
        'de': 'Eigenes Projektfoto: eine fertig aufgebaute Holz-Pergola im Garten.',
        'en': 'Our own project photo: a finished timber pergola in the garden.',
        'fr': 'Photo de notre projet : une pergola en bois terminée dans le jardin.',
    },
    'carport-selbst-planen': {
        'datei': 'carport.jpg',
        'de': 'Eigenes Projektfoto: ein selbst gebauter Holz-Carport.',
        'en': 'Our own project photo: a self-built timber carport.',
        'fr': 'Photo de notre projet : un carport en bois construit soi-même.',
    },
    'gartenhaus-selbst-planen': {
        'datei': 'gartenhaus.jpg',
        'de': 'Eigenes Projektfoto: ein Gartenhaus aus Holz in Eigenleistung.',
        'en': 'Our own project photo: a timber garden house built by hand.',
        'fr': 'Photo de notre projet : un abri de jardin en bois autoconstruit.',
    },
}

# Alt-Texte: knapp, beschreibend, ohne Keyword-Stopfen.
_ALT = {
    'pergola-selbst-bauen': {'de': 'Selbst gebaute Holz-Pergola im Garten',
                             'en': 'Self-built timber pergola in a garden',
                             'fr': 'Pergola en bois autoconstruite dans un jardin'},
    'carport-selbst-planen': {'de': 'Selbst gebauter Holz-Carport',
                              'en': 'Self-built timber carport',
                              'fr': 'Carport en bois autoconstruit'},
    'gartenhaus-selbst-planen': {'de': 'Selbst gebautes Gartenhaus aus Holz',
                                 'en': 'Self-built timber garden house',
                                 'fr': 'Abri de jardin en bois autoconstruit'},
}


def _pfad(static_ordner, slug):
    """Absoluter Pfad zur reservierten Fotodatei (oder None, wenn kein Slug)."""
    eintrag = FOTOS.get(slug)
    if not eintrag:
        return None
    return os.path.join(static_ordner, 'projekte', eintrag['datei'])


def vorhanden(static_ordner, slug):
    """True, wenn fuer den Slug bereits ein echtes Foto hinterlegt ist."""
    p = _pfad(static_ordner, slug)
    return bool(p) and os.path.exists(p)


def bild_url(site, slug):
    """Absolute URL des Projektfotos (fuer OG-/JSON-LD-Bild). Ohne Existenzpruefung."""
    eintrag = FOTOS.get(slug)
    if not eintrag:
        return None
    return site + '/static/projekte/' + eintrag['datei']


def _figure(site, slug, lang):
    eintrag = FOTOS[slug]
    cap = eintrag.get(lang, eintrag['de'])
    alt = _ALT.get(slug, {}).get(lang, cap)
    url = site + '/static/projekte/' + eintrag['datei']
    return (
        '<figure style="margin:0 0 26px;">'
        '<img src="%s" alt="%s" loading="lazy" '
        'style="width:100%%;height:auto;border-radius:10px;display:block;">'
        '<figcaption style="font-size:.85rem;color:#6b7280;text-align:center;'
        'margin-top:8px;">%s</figcaption></figure>'
    ) % (url, alt, cap)


def inject(body_html, slug, lang, static_ordner, site):
    """Setzt das Projektfoto ganz an den Anfang des Artikels – aber nur, wenn die
    Datei existiert. Fehlt sie, bleibt der Artikel unveraendert."""
    if not vorhanden(static_ordner, slug):
        return body_html
    return _figure(site, slug, lang) + body_html
