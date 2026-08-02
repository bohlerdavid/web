# -*- coding: utf-8 -*-
"""Technische SVG-Diagramme fuer die Ratgeber-Artikel.

Warum ueberhaupt: die Artikel hatten NULL Bilder bei einem sichtbaren Thema —
genau das beanstandet AdSense als "minderwertige Inhalte". Diese Diagramme sind
im Code gezeichneter Erstanbieter-Content: Querschnitte, Verbindungen, Rahmen,
Dachformen. Kein Wettbewerber hat sie, und sie beweisen den Werkzeugcharakter.

Bewusst geometrisch einfach (Rechtecke, Linien, wenige Zahlen) statt kunstvoll:
so sind sie robust, schnell und in jeder Sprache lesbar. Beschriftung nur ueber
die <figcaption> je Sprache; die Zeichnung selbst traegt nur Zahlen.

Stil: warme Holztoene, duenne Striche, heller Panel-Hintergrund — passt zur Seite.
"""

# ── Palette ──────────────────────────────────────────────────────────────────
HOLZ = '#c98a4a'       # Holzflaeche
HOLZ_D = '#a06a2c'     # Holz dunkel (Kante/Hirnholz)
LINIE = '#5b4327'      # Kontur
MASS = '#8a8a8a'       # Masslinie
BODEN = '#d8c9a8'      # Erdreich
BETON = '#b9bec4'      # Beton
METALL = '#8a9098'     # Metall (Anker)
PANEL = '#faf4e8'      # Diagramm-Hintergrund
GRUEN = '#3d7a3d'


def _wrap(inner, vb='0 0 400 260', h=None):
    st = 'width:100%;max-width:520px;height:auto;display:block;margin:0 auto;'
    return ('<svg viewBox="%s" xmlns="http://www.w3.org/2000/svg" role="img" '
            'style="%s" preserveAspectRatio="xMidYMid meet">'
            '<rect x="0" y="0" width="100%%" height="100%%" fill="%s" rx="8"/>%s</svg>'
            ) % (vb, st, PANEL, inner)


def _txt(x, y, s, size=12, anchor='middle', fill=LINIE, weight='400'):
    return ('<text x="%s" y="%s" font-family="Segoe UI,system-ui,sans-serif" '
            'font-size="%s" font-weight="%s" text-anchor="%s" fill="%s">%s</text>'
            ) % (x, y, size, weight, anchor, fill, s)


# ── Diagramme ────────────────────────────────────────────────────────────────
def frame_post_beam():
    """Pfosten-Pfetten-Rahmen mit Kopfband und Sparren (Pergola/Carport)."""
    p = []
    # zwei Pfosten
    for px in (70, 320):
        p.append('<rect x="%d" y="70" width="14" height="150" fill="%s" stroke="%s"/>' % (px, HOLZ, LINIE))
    # Pfette oben
    p.append('<rect x="60" y="60" width="274" height="14" fill="%s" stroke="%s"/>' % (HOLZ_D, LINIE))
    # Sparren
    for sx in range(85, 320, 40):
        p.append('<rect x="%d" y="46" width="8" height="16" fill="%s" stroke="%s"/>' % (sx, HOLZ, LINIE))
    # Kopfbaender (45 Grad)
    p.append('<path d="M84 90 L110 74" stroke="%s" stroke-width="8" stroke-linecap="round"/>' % HOLZ)
    p.append('<path d="M320 90 L294 74" stroke="%s" stroke-width="8" stroke-linecap="round"/>' % HOLZ)
    # Boden
    p.append('<line x1="30" y1="220" x2="370" y2="220" stroke="%s" stroke-width="2"/>' % BODEN)
    # Masslinie Hoehe
    p.append('<line x1="45" y1="67" x2="45" y2="220" stroke="%s" stroke-width="1"/>' % MASS)
    p.append(_txt(38, 150, '2,20–2,50 m', 11, 'middle', MASS) .replace('x="38"', 'x="18" transform="rotate(-90 18 150)"'))
    # Masslinie Spannweite
    p.append('<line x1="77" y1="235" x2="327" y2="235" stroke="%s" stroke-width="1"/>' % MASS)
    p.append(_txt(202, 249, 'Spannweite ≤ 4 m', 11, 'middle', MASS))
    return _wrap(''.join(p))


def foundation_hanchor():
    """Punktfundament im Schnitt: Erdreich, Beton, H-Anker, Pfosten ueber Grund."""
    p = []
    # Erdreich
    p.append('<rect x="0" y="120" width="400" height="140" fill="%s"/>' % BODEN)
    p.append('<line x1="0" y1="120" x2="400" y2="120" stroke="%s" stroke-width="2"/>' % LINIE)
    # Betonblock (frostfrei ~80cm)
    p.append('<rect x="150" y="120" width="100" height="110" fill="%s" stroke="%s"/>' % (BETON, LINIE))
    # H-Anker im Beton
    p.append('<rect x="192" y="96" width="16" height="40" fill="%s" stroke="%s"/>' % (METALL, LINIE))
    # Pfosten ueber dem Boden (Abstand!)
    p.append('<rect x="184" y="30" width="32" height="66" fill="%s" stroke="%s"/>' % (HOLZ, LINIE))
    # Luftspalt-Markierung
    p.append('<line x1="150" y1="112" x2="184" y2="112" stroke="%s" stroke-width="1" stroke-dasharray="3 2"/>' % GRUEN)
    p.append(_txt(120, 116, '5–10 cm', 10, 'end', GRUEN))
    # Frosttiefe
    p.append('<line x1="270" y1="120" x2="270" y2="230" stroke="%s" stroke-width="1"/>' % MASS)
    p.append(_txt(300, 178, '~80 cm', 11, 'middle', MASS).replace('x="300"', 'x="292"'))
    p.append(_txt(300, 192, 'frostfrei', 10, 'middle', MASS).replace('x="300"', 'x="292"'))
    p.append(_txt(200, 20, '', 10))
    return _wrap(''.join(p))


def joint_details():
    """Vier Holzverbindungen im Schema: Zapfen, Blatt, Versatz, Kerve (2x2)."""
    def cell(ox, oy, kind):
        c = []
        if kind == 'zapfen':  # Zapfen + Zapfenloch
            c.append('<rect x="%d" y="%d" width="60" height="26" fill="%s" stroke="%s"/>' % (ox, oy+18, HOLZ, LINIE))
            c.append('<rect x="%d" y="%d" width="22" height="60" fill="%s" stroke="%s"/>' % (ox+52, oy, HOLZ_D, LINIE))
            c.append('<rect x="%d" y="%d" width="18" height="14" fill="%s" stroke="%s"/>' % (ox+44, oy+24, HOLZ, LINIE))
        elif kind == 'blatt':  # Ueberblattung
            c.append('<rect x="%d" y="%d" width="70" height="16" fill="%s" stroke="%s"/>' % (ox, oy+14, HOLZ, LINIE))
            c.append('<rect x="%d" y="%d" width="16" height="70" fill="%s" stroke="%s"/>' % (ox+30, oy, HOLZ_D, LINIE))
        elif kind == 'versatz':  # Versatz (schraeg)
            c.append('<rect x="%d" y="%d" width="70" height="16" fill="%s" stroke="%s"/>' % (ox, oy+40, HOLZ, LINIE))
            c.append('<path d="M%d %d l40 -40 l16 0 l-40 40 z" fill="%s" stroke="%s"/>' % (ox+18, oy+40, HOLZ_D, LINIE))
        else:  # kerve (Sparren auf Pfette eingekaemmt)
            c.append('<rect x="%d" y="%d" width="16" height="60" fill="%s" stroke="%s"/>' % (ox+40, oy, HOLZ_D, LINIE))
            c.append('<path d="M%d %d l70 -20 l0 16 l-70 20 z" fill="%s" stroke="%s"/>' % (ox, oy+44, HOLZ, LINIE))
        return ''.join(c)
    p = [cell(30, 26, 'zapfen'), cell(230, 26, 'blatt'),
         cell(30, 150, 'versatz'), cell(230, 150, 'kerve')]
    # Trennlinien
    p.append('<line x1="200" y1="20" x2="200" y2="240" stroke="#e2d6bd" stroke-width="1"/>')
    p.append('<line x1="20" y1="130" x2="380" y2="130" stroke="#e2d6bd" stroke-width="1"/>')
    p += [_txt(60, 118, '1', 13, 'middle', MASS, '700'), _txt(300, 118, '2', 13, 'middle', MASS, '700'),
          _txt(60, 236, '3', 13, 'middle', MASS, '700'), _txt(300, 236, '4', 13, 'middle', MASS, '700')]
    return _wrap(''.join(p), '0 0 400 260')


def roof_forms():
    """Vier Dachformen im Vergleich: Satteldach, Walmdach, Pultdach, Flachdach."""
    def house(ox, roof):
        c = ['<rect x="%d" y="70" width="70" height="40" fill="%s" stroke="%s"/>' % (ox, '#efe4d0', LINIE)]
        if roof == 'sattel':
            c.append('<path d="M%d 70 l35 -34 l35 34 z" fill="%s" stroke="%s"/>' % (ox, HOLZ, LINIE))
        elif roof == 'walm':
            c.append('<path d="M%d 70 l18 -26 l34 0 l18 26 z" fill="%s" stroke="%s"/>' % (ox, HOLZ, LINIE))
        elif roof == 'pult':
            c.append('<path d="M%d 70 l0 -30 l70 18 l0 12 z" fill="%s" stroke="%s"/>' % (ox, HOLZ, LINIE))
        else:  # flach
            c.append('<rect x="%d" y="62" width="70" height="10" fill="%s" stroke="%s"/>' % (ox, HOLZ, LINIE))
        return ''.join(c)
    labels = [('1', 40), ('2', 145), ('3', 250), ('4', 355)]
    p = [house(20, 'sattel'), house(125, 'walm'), house(230, 'pult'), house(335, 'flach')]
    for n, x in labels:
        p.append(_txt(x, 130, n, 13, 'middle', MASS, '700'))
    return _wrap(''.join(p), '0 0 420 150')


def roof_truss():
    """Sparrendach mit Kehlbalken: First, Sparren, Kehlbalken, Spannweite."""
    p = []
    # Sparrenpaar
    p.append('<path d="M40 190 L200 50 L360 190" fill="none" stroke="%s" stroke-width="10" stroke-linejoin="round"/>' % HOLZ)
    # Kehlbalken
    p.append('<rect x="110" y="112" width="180" height="12" fill="%s" stroke="%s"/>' % (HOLZ_D, LINIE))
    # First-Markierung
    p.append('<circle cx="200" cy="52" r="4" fill="%s"/>' % LINIE)
    # Wandoberkanten
    p.append('<rect x="30" y="188" width="24" height="24" fill="#efe4d0" stroke="%s"/>' % LINIE)
    p.append('<rect x="346" y="188" width="24" height="24" fill="#efe4d0" stroke="%s"/>' % LINIE)
    # Masslinie Spannweite
    p.append('<line x1="42" y1="228" x2="358" y2="228" stroke="%s" stroke-width="1"/>' % MASS)
    p.append(_txt(200, 242, 'Spannweite', 11, 'middle', MASS))
    # Neigung
    p.append(_txt(120, 108, '∠', 16, 'middle', GRUEN))
    return _wrap(''.join(p), '0 0 400 252')


def beam_load():
    """Statik: Einfeldtraeger mit Streckenlast und Durchbiegung."""
    p = []
    # Auflager (Dreiecke)
    p.append('<path d="M40 150 l12 -20 l-24 0 z" fill="%s"/>' % METALL)
    p.append('<path d="M360 150 l12 -20 l-24 0 z" fill="%s"/>' % METALL)
    # Traeger
    p.append('<rect x="28" y="118" width="344" height="14" fill="%s" stroke="%s"/>' % (HOLZ, LINIE))
    # Lastpfeile
    for x in range(50, 360, 30):
        p.append('<line x1="%d" y1="78" x2="%d" y2="112" stroke="%s" stroke-width="2"/>' % (x, x, GRUEN))
        p.append('<path d="M%d 112 l-4 -8 l8 0 z" fill="%s"/>' % (x, GRUEN))
    p.append('<line x1="46" y1="76" x2="356" y2="76" stroke="%s" stroke-width="2"/>' % GRUEN)
    p.append(_txt(200, 68, 'Last q', 11, 'middle', GRUEN))
    # Durchbiegung (gestrichelt)
    p.append('<path d="M40 140 Q200 176 360 140" fill="none" stroke="%s" stroke-width="1.5" stroke-dasharray="5 3"/>' % '#c0392b')
    p.append(_txt(200, 198, 'Durchbiegung', 10, 'middle', '#c0392b'))
    # Spannweite L
    p.append('<line x1="40" y1="168" x2="360" y2="168" stroke="%s" stroke-width="1"/>' % MASS)
    p.append(_txt(200, 224, 'L', 13, 'middle', MASS, '700').replace('y="224"', 'y="216"'))
    return _wrap(''.join(p), '0 0 400 230')


def wall_frame():
    """Staenderwand: Schwelle, Staender, Raehm, Beplankung (Gartenhaus/Wand)."""
    p = []
    p.append('<rect x="40" y="196" width="320" height="14" fill="%s" stroke="%s"/>' % (HOLZ_D, LINIE))  # Schwelle
    p.append('<rect x="40" y="40" width="320" height="14" fill="%s" stroke="%s"/>' % (HOLZ_D, LINIE))    # Raehm
    for x in range(48, 356, 48):  # Staender
        p.append('<rect x="%d" y="54" width="12" height="142" fill="%s" stroke="%s"/>' % (x, HOLZ, LINIE))
    # Beplankung (halbtransparent rechts)
    p.append('<rect x="220" y="54" width="140" height="142" fill="%s" fill-opacity="0.35" stroke="%s"/>' % ('#cdbf94', LINIE))
    p.append(_txt(290, 130, 'OSB', 12, 'middle', LINIE))
    # Achsabstand
    p.append('<line x1="54" y1="224" x2="102" y2="224" stroke="%s" stroke-width="1"/>' % MASS)
    p.append(_txt(78, 238, 'e = 62,5 cm', 10, 'middle', MASS))
    return _wrap(''.join(p), '0 0 400 250')


def leanto():
    """Terrassendach an der Wand: Wandpfette, Sparren mit Gefaelle, Stuetze."""
    p = []
    # Wand
    p.append('<rect x="40" y="30" width="20" height="190" fill="#e6ddce" stroke="%s"/>' % LINIE)
    p.append('<rect x="52" y="50" width="14" height="14" fill="%s" stroke="%s"/>' % (HOLZ_D, LINIE))  # Wandpfette
    # Sparren mit Gefaelle
    p.append('<path d="M60 58 L340 120" stroke="%s" stroke-width="12" stroke-linecap="round"/>' % HOLZ)
    # Stuetze vorn
    p.append('<rect x="326" y="120" width="14" height="100" fill="%s" stroke="%s"/>' % (HOLZ, LINIE))
    # Boden
    p.append('<line x1="30" y1="220" x2="370" y2="220" stroke="%s" stroke-width="2"/>' % BODEN)
    # Gefaelle
    p.append(_txt(200, 78, 'Gefälle', 10, 'middle', GRUEN))
    return _wrap(''.join(p), '0 0 400 240')


def wood_durability():
    """Balkenvergleich: natuerliche Dauerhaftigkeit gaengiger Holzarten."""
    rows = [('Fichte/KVH', 1.5, '#d7b98a'), ('Douglasie', 3.0, HOLZ), ('Lärche', 3.6, HOLZ_D), ('Eiche', 4.2, '#7a5a2a')]
    p = []
    x0, w = 130, 220
    for i, (name, val, col) in enumerate(rows):
        y = 34 + i * 48
        p.append(_txt(120, y + 20, name, 12, 'end', LINIE))
        p.append('<rect x="%d" y="%d" width="%d" height="22" fill="%s" stroke="%s" rx="3"/>' % (x0, y+4, int(val / 5 * w), col, LINIE))
    p.append('<line x1="%d" y1="26" x2="%d" y2="226" stroke="%s" stroke-width="1"/>' % (x0, x0, MASS))
    p.append(_txt(x0 + w / 2, 244, 'natürliche Dauerhaftigkeit im Freien →', 10, 'middle', MASS))
    return _wrap(''.join(p), '0 0 400 256')


def end_grain():
    """Holzschutz: Wasserablauf am Hirnholz — Pfostenkappe und Schraege."""
    p = []
    # Pfosten links: gerade -> Wasser steht
    p.append('<rect x="70" y="70" width="40" height="150" fill="%s" stroke="%s"/>' % (HOLZ, LINIE))
    p.append('<ellipse cx="90" cy="70" rx="20" ry="6" fill="#7fb3d5"/>')
    p.append(_txt(90, 246, '✗ flach', 11, 'middle', '#c0392b'))
    # Pfosten rechts: abgeschraegt/Kappe -> Wasser laeuft ab
    p.append('<rect x="260" y="70" width="40" height="150" fill="%s" stroke="%s"/>' % (HOLZ, LINIE))
    p.append('<path d="M255 70 l50 0 l-8 -14 l-34 0 z" fill="%s" stroke="%s"/>' % (METALL, LINIE))  # Kappe
    p.append('<path d="M280 56 q14 8 26 26" fill="none" stroke="#7fb3d5" stroke-width="2"/>')
    p.append(_txt(280, 246, '✓ Kappe/Schräge', 11, 'middle', GRUEN))
    p.append('<line x1="30" y1="220" x2="370" y2="220" stroke="%s" stroke-width="2"/>' % BODEN)
    return _wrap(''.join(p), '0 0 400 258')


def setback_plan():
    """Grundriss: Grenzabstand von Carport/Pergola zur Grundstuecksgrenze."""
    p = []
    # Grundstueck
    p.append('<rect x="30" y="30" width="340" height="200" fill="#f3ece0" stroke="%s" stroke-width="2"/>' % GRUEN)
    p.append(_txt(200, 22, 'Grundstücksgrenze', 10, 'middle', GRUEN))
    # Haus
    p.append('<rect x="60" y="60" width="120" height="90" fill="#e0d3bb" stroke="%s"/>' % LINIE)
    p.append(_txt(120, 110, 'Haus', 12, 'middle', LINIE))
    # Carport an der Grenze
    p.append('<rect x="250" y="150" width="100" height="70" fill="%s" fill-opacity="0.6" stroke="%s"/>' % (HOLZ, LINIE))
    p.append(_txt(300, 190, 'Carport', 11, 'middle', LINIE))
    # Abstandsmass
    p.append('<line x1="350" y1="185" x2="370" y2="185" stroke="%s" stroke-width="1"/>' % MASS)
    p.append(_txt(300, 238, 'Grenzabstand: lokale Vorschrift beachten', 10, 'middle', MASS))
    return _wrap(''.join(p), '0 0 400 250')


# ── Registry: welche Diagramme, mit welcher Bildunterschrift (DE/EN/FR) ──────
_F = {
    'frame': (frame_post_beam, {
        'de': 'Pfosten-Pfetten-Rahmen mit Kopfband und Sparren – schematischer Aufbau.',
        'en': 'Post-and-beam frame with knee brace and rafters – schematic build-up.',
        'fr': 'Ossature poteau-poutre avec aisselier et chevrons – schéma.'}),
    'foundation': (foundation_hanchor, {
        'de': 'Punktfundament im Schnitt: H-Anker, Luftspalt zum Erdreich, frostfreie Gründung.',
        'en': 'Point foundation in section: H-anchor, air gap to soil, frost-free depth.',
        'fr': 'Fondation ponctuelle en coupe : ancre en H, espace d’air, hors gel.'}),
    'joints': (joint_details, {
        'de': 'Vier Holzverbindungen: 1 Zapfen, 2 Überblattung, 3 Versatz, 4 Kerve (Aufklämmung).',
        'en': 'Four timber joints: 1 mortise-and-tenon, 2 half-lap, 3 abutment, 4 birdsmouth notch.',
        'fr': 'Quatre assemblages : 1 tenon-mortaise, 2 mi-bois, 3 embrèvement, 4 entaille.'}),
    'roofforms': (roof_forms, {
        'de': 'Dachformen im Vergleich: 1 Satteldach, 2 Walmdach, 3 Pultdach, 4 Flachdach.',
        'en': 'Roof forms compared: 1 gable, 2 hip, 3 mono-pitch, 4 flat roof.',
        'fr': 'Formes de toit : 1 deux pans, 2 croupé, 3 monopente, 4 toit plat.'}),
    'truss': (roof_truss, {
        'de': 'Sparrendach mit Kehlbalken – First, Sparrenpaar und Spannweite.',
        'en': 'Rafter roof with collar beam – ridge, rafter pair and span.',
        'fr': 'Charpente à chevrons avec entrait – faîte, chevrons et portée.'}),
    'load': (beam_load, {
        'de': 'Einfeldträger unter Streckenlast q – Auflager, Spannweite L und Durchbiegung.',
        'en': 'Simply supported beam under load q – supports, span L and deflection.',
        'fr': 'Poutre sur deux appuis sous charge q – appuis, portée L et flèche.'}),
    'wall': (wall_frame, {
        'de': 'Ständerwand: Schwelle, Ständer im Achsabstand, Rähm und OSB-Beplankung.',
        'en': 'Stud wall: sill plate, studs at fixed spacing, top plate and OSB sheathing.',
        'fr': 'Mur à ossature : lisse basse, montants, lisse haute et voile OSB.'}),
    'leanto': (leanto, {
        'de': 'Terrassendach an der Wand: Wandpfette, Sparren mit Gefälle, vordere Stütze.',
        'en': 'Lean-to terrace roof: wall plate, sloped rafters, front post.',
        'fr': 'Toit de terrasse adossé : panne murale, chevrons en pente, poteau avant.'}),
    'durability': (wood_durability, {
        'de': 'Natürliche Dauerhaftigkeit gängiger Holzarten im Freien (Richtwerte).',
        'en': 'Natural durability of common wood species outdoors (indicative).',
        'fr': 'Durabilité naturelle des essences courantes en extérieur (indicatif).'}),
    'endgrain': (end_grain, {
        'de': 'Holzschutz am Hirnholz: flach staut Wasser, Kappe oder Schräge leitet es ab.',
        'en': 'End-grain protection: a flat top pools water, a cap or bevel sheds it.',
        'fr': 'Protection du bois de bout : à plat l’eau stagne, un chapeau l’évacue.'}),
    'setback': (setback_plan, {
        'de': 'Grundriss mit Grenzabstand – die lokal gültige Vorschrift ist maßgeblich.',
        'en': 'Site plan with boundary setback – local regulations are decisive.',
        'fr': 'Plan avec recul de limite – la réglementation locale prévaut.'}),
}

# Welche Figuren je Artikel, in welcher Reihenfolge.
FIGURES_BY_SLUG = {
    'pergola-selbst-bauen':          ['frame', 'foundation'],
    'carport-selbst-planen':         ['frame', 'roofforms'],
    'dachstuhl-konstruieren':        ['truss', 'load'],
    'gartenhaus-selbst-planen':      ['wall', 'roofforms'],
    'terrassenueberdachung-planen':  ['leanto', 'foundation'],
    'holzverbindungen-uebersicht':   ['joints', 'frame'],
    'holzarten-vergleich':           ['durability'],
    'fundamente-holzbau':            ['foundation', 'endgrain'],
    'holzschutz-grundlagen':         ['endgrain', 'foundation'],
    'baugenehmigung-carport-pergola':['setback', 'roofforms'],
    'werkzeuge-holzbau':             ['frame'],
    'dachformen-vergleich':          ['roofforms', 'truss'],
    'statik-grundlagen-holzbau':     ['load', 'truss'],
}


def figure_html(key, lang):
    """Ein <figure> mit SVG + uebersetzter Bildunterschrift."""
    fn, caps = _F[key]
    cap = caps.get(lang, caps['de'])
    return ('<figure style="margin:22px 0;">%s'
            '<figcaption style="font-size:.85rem;color:#6b7280;text-align:center;'
            'margin-top:8px;">%s</figcaption></figure>') % (fn(), cap)


def inject(body_html, slug, lang):
    """Fuegt die Diagramme des Artikels nach ausgewaehlten <h2> ein.

    Nach dem 1. und (falls vorhanden) 3. <h2> — so stehen sie im Textfluss statt
    als Block am Ende. Sind es weniger H2 als Figuren, kommen die restlichen ans
    Ende des ersten Absatzes.
    """
    keys = FIGURES_BY_SLUG.get(slug, [])
    if not keys:
        return body_html
    # Positionen der schliessenden </h2>-Absaetze finden -> danach einfuegen.
    import re
    # Wir haengen jede Figur nach dem n-ten kompletten Absatz <p>...</p> ein,
    # das direkt auf ein <h2> folgt. Einfach und robust: nach dem 1. </p> und
    # nach einem spaeteren </p>.
    p_ends = [m.end() for m in re.finditer(r'</p>', body_html)]
    if not p_ends:
        return body_html + ''.join(figure_html(k, lang) for k in keys)
    ziele = []
    if len(p_ends) >= 1:
        ziele.append(p_ends[0])
    if len(keys) >= 2 and len(p_ends) >= 4:
        ziele.append(p_ends[3])
    elif len(keys) >= 2 and len(p_ends) >= 2:
        ziele.append(p_ends[len(p_ends) // 2])
    # Von hinten einfuegen, damit die Offsets stabil bleiben.
    paare = list(zip(ziele, keys))
    for pos, key in sorted(paare, key=lambda x: -x[0]):
        body_html = body_html[:pos] + figure_html(key, lang) + body_html[pos:]
    return body_html


def hero_key(slug):
    """Erste Figur eines Artikels — fuer JSON-LD/OG-Bild."""
    ks = FIGURES_BY_SLUG.get(slug)
    return ks[0] if ks else None
