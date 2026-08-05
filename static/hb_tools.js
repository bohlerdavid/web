/* HolzBau 3D — Tools: Spannweiten, parametrische Vorlagen, DXF, 2D-Plattenzuschnitt. Auto-generiert. */
/* ===== span_table.js ===== */
/*
 * span_table.js — Querschnitts-Assistent fuer holzbau3d.app
 * ---------------------------------------------------------------
 * Reiner Tabellen-Lookup (KEIN Statikersatz!).
 * Schlaegt Heimwerkern aus Bauteiltyp + Spannweite + Achsabstand
 * einen sinnvollen MINDEST-Holzquerschnitt (B x H in mm) vor.
 *
 * Grundlage: Nadelholz der Festigkeitsklasse C24 (uebliches Bau-Fichte/Tanne).
 * Alle Werte sind KONSERVATIVE Richtwerte fuer normale Wohn-/Dachlasten
 * (moderate Schneelast, uebliche Dachneigung, Nutzlast Wohnen ~2 kN/m2).
 *
 * WICHTIG: Ersetzt keine statische Berechnung. Bei tragenden Bauteilen
 * ist ein Statiker/Tragwerksplaner hinzuzuziehen.
 */

(function (global) {
  'use strict';

  var DISCLAIMER =
    'Richtwert – ersetzt keine statische Berechnung. Bei tragenden Bauteilen einen Statiker hinzuziehen.';

  /*
   * Tabellenaufbau:
   *  - sparren / balken: nach Spannweite (mm) und Achsabstand (mm),
   *      Wert = [B, H] in mm.
   *  - pfosten: nach Knicklaenge/Hoehe (mm) und Lastklasse,
   *      Wert = [B, H] in mm (quadratisch).
   *
   * Die Stuetzstellen sind in aufsteigender Reihenfolge angegeben,
   * damit der Lookup "naechst-groesserer Wert" zuverlaessig funktioniert.
   */
  var HOLZ_SPAN_TABLE = {
    meta: {
      holzart: 'Nadelholz C24 (Fichte/Tanne)',
      grundlage:
        'Konservative Richtwerte fuer uebliche Wohn-/Dachlasten. Kein Statikersatz.',
      einheiten: { spannweite: 'mm', achsabstand: 'mm', querschnitt: 'mm (B x H)' },
      disclaimer: DISCLAIMER
    },

    /* ---------------- DACHSPARREN ---------------- */
    sparren: {
      label: 'Dachsparren',
      lastannahme: 'Dach, moderate Schneelast, Sparren als Einfeldtraeger',
      spans: [1500, 2000, 2500, 3000, 3500, 4000, 4500, 5000], // mm
      spacings: [500, 700, 900], // mm (Achsabstand)
      // grid[spanMm][spacingMm] = [B, H]
      grid: {
        1500: { 500: [60, 80],  700: [60, 100], 900: [60, 120] },
        2000: { 500: [60, 100], 700: [60, 120], 900: [80, 120] },
        2500: { 500: [60, 120], 700: [60, 140], 900: [80, 140] },
        3000: { 500: [60, 140], 700: [80, 140], 900: [80, 160] },
        3500: { 500: [80, 140], 700: [80, 160], 900: [80, 180] },
        4000: { 500: [80, 160], 700: [80, 180], 900: [100, 200] },
        4500: { 500: [80, 180], 700: [100, 200], 900: [100, 220] },
        5000: { 500: [80, 200], 700: [100, 220], 900: [120, 240] }
      }
    },

    /* ---------------- DECKENBALKEN / PFETTE ---------------- */
    balken: {
      label: 'Deckenbalken / Pfette',
      lastannahme: 'Geschossdecke Wohnen (~2 kN/m2) bzw. Pfette, Einfeldtraeger',
      spans: [1500, 2000, 2500, 3000, 3500, 4000, 4500, 5000], // mm
      spacings: [500, 700, 900], // mm (Achsabstand)
      grid: {
        1500: { 500: [60, 120], 700: [60, 140], 900: [80, 160] },
        2000: { 500: [60, 140], 700: [80, 160], 900: [80, 180] },
        2500: { 500: [80, 160], 700: [80, 180], 900: [100, 200] },
        3000: { 500: [80, 180], 700: [100, 200], 900: [100, 220] },
        3500: { 500: [100, 200], 700: [100, 220], 900: [120, 240] },
        4000: { 500: [100, 220], 700: [120, 240], 900: [120, 260] },
        4500: { 500: [120, 240], 700: [120, 260], 900: [140, 280] },
        5000: { 500: [120, 260], 700: [140, 280], 900: [160, 300] }
      }
    },

    /* ---------------- PFOSTEN / STUETZE ---------------- */
    pfosten: {
      label: 'Pfosten / Stuetze',
      lastannahme:
        'Druckstab, Bemessung nach Knicklaenge (Hoehe) und ungefaehrer Auflast',
      heights: [2000, 2500, 3000, 3500, 4000], // mm (Knicklaenge = Hoehe)
      // Lastklassen als ungefaehre Vertikallast auf die Stuetze:
      loads: ['leicht', 'mittel', 'schwer'],
      loadInfo: {
        leicht: 'bis ca. 10 kN (z.B. leichtes Dach, Pergola, Carport)',
        mittel: 'bis ca. 25 kN (z.B. Decke ueber einem Geschoss)',
        schwer: 'bis ca. 50 kN (z.B. mehrere Geschosse / grosse Lasteinzugsflaeche)'
      },
      // grid[heightMm][loadClass] = [B, H] (quadratisch)
      grid: {
        2000: { leicht: [80, 80],   mittel: [100, 100], schwer: [140, 140] },
        2500: { leicht: [80, 80],   mittel: [120, 120], schwer: [140, 140] },
        3000: { leicht: [100, 100], mittel: [120, 120], schwer: [160, 160] },
        3500: { leicht: [100, 100], mittel: [140, 140], schwer: [180, 180] },
        4000: { leicht: [120, 120], mittel: [140, 140], schwer: [200, 200] }
      }
    }
  };

  /* ----------------------------------------------------------------
   * Hilfsfunktionen
   * ---------------------------------------------------------------- */

  // Liefert den naechst-groesseren (>=) Wert aus einer aufsteigend
  // sortierten Liste. Gibt zusaetzlich zurueck, ob der Eingabewert die
  // Tabellengrenze ueberschritten hat (dann wird der Maximalwert genommen).
  function pickNextLarger(sortedValues, value) {
    for (var i = 0; i < sortedValues.length; i++) {
      if (value <= sortedValues[i]) {
        return { value: sortedValues[i], clamped: false };
      }
    }
    return {
      value: sortedValues[sortedValues.length - 1],
      clamped: true
    };
  }

  function toNumber(x) {
    var n = Number(x);
    return isFinite(n) ? n : NaN;
  }

  /* ----------------------------------------------------------------
   * Hauptfunktion
   *
   * suggestCrossSection(type, spanMm, spacingMm, opts)
   *
   *  type      : 'sparren' | 'balken' | 'pfosten'
   *  spanMm    : Spannweite in mm (bei 'pfosten' = Hoehe / Knicklaenge in mm)
   *  spacingMm : Achsabstand in mm (bei 'pfosten' ignoriert)
   *  opts      : optionales Objekt
   *                - opts.load : 'leicht' | 'mittel' | 'schwer' (nur pfosten,
   *                              Default 'mittel')
   *
   * Rueckgabe : { B, H, hint, disclaimer }
   *              B, H  = empfohlener Querschnitt in mm (null bei Fehler)
   *              hint  = Deutscher Hinweistext
   *              disclaimer = immer DISCLAIMER
   * ---------------------------------------------------------------- */
  function suggestCrossSection(type, spanMm, spacingMm, opts) {
    opts = opts || {};
    var t = String(type == null ? '' : type).toLowerCase().trim();
    var entry = HOLZ_SPAN_TABLE[t];

    if (!entry) {
      return {
        B: null,
        H: null,
        hint:
          'Unbekannter Bauteiltyp "' +
          String(type) +
          '". Erlaubt sind: sparren, balken, pfosten.',
        disclaimer: DISCLAIMER
      };
    }

    /* ---- Sonderfall Pfosten / Stuetze ---- */
    if (t === 'pfosten') {
      var height = toNumber(spanMm);
      if (!(height > 0)) {
        return {
          B: null,
          H: null,
          hint: 'Bitte eine gueltige Hoehe (Knicklaenge) in mm angeben.',
          disclaimer: DISCLAIMER
        };
      }

      var loadClass = String(opts.load || 'mittel').toLowerCase().trim();
      if (entry.loads.indexOf(loadClass) === -1) {
        loadClass = 'mittel';
      }

      var hPick = pickNextLarger(entry.heights, height);
      var pDim = entry.grid[hPick.value][loadClass];

      var pHints = [];
      pHints.push(
        'Pfosten C24, Lastklasse "' +
          loadClass +
          '" (' +
          entry.loadInfo[loadClass] +
          ').'
      );
      pHints.push(
        'Bemessungshoehe (Knicklaenge): ' + hPick.value + ' mm.'
      );
      if (hPick.clamped) {
        pHints.push(
          'Angefragte Hoehe (' +
            height +
            ' mm) liegt ueber der Tabellengrenze (' +
            entry.heights[entry.heights.length - 1] +
            ' mm) – groesster Tabellenwert verwendet. Unbedingt statisch pruefen lassen!'
        );
      }

      return {
        B: pDim[0],
        H: pDim[1],
        hint: pHints.join(' '),
        disclaimer: DISCLAIMER
      };
    }

    /* ---- Sparren / Balken ---- */
    var span = toNumber(spanMm);
    var spacing = toNumber(spacingMm);

    if (!(span > 0)) {
      return {
        B: null,
        H: null,
        hint: 'Bitte eine gueltige Spannweite in mm angeben.',
        disclaimer: DISCLAIMER
      };
    }
    if (!(spacing > 0)) {
      return {
        B: null,
        H: null,
        hint: 'Bitte einen gueltigen Achsabstand in mm angeben.',
        disclaimer: DISCLAIMER
      };
    }

    var spanPick = pickNextLarger(entry.spans, span);
    var spacingPick = pickNextLarger(entry.spacings, spacing);

    var dim = entry.grid[spanPick.value][spacingPick.value];

    var hints = [];
    hints.push(
      entry.label +
        ' (C24), Bemessung fuer Spannweite ' +
        spanPick.value +
        ' mm bei Achsabstand ' +
        spacingPick.value +
        ' mm.'
    );

    if (spanPick.clamped) {
      hints.push(
        'Angefragte Spannweite (' +
          span +
          ' mm) liegt ueber der Tabellengrenze (' +
          entry.spans[entry.spans.length - 1] +
          ' mm) – groesster Tabellenwert verwendet. Unbedingt statisch pruefen lassen!'
      );
    } else if (span < spanPick.value) {
      hints.push(
        'Auf naechst-groessere Spannweite (' +
          spanPick.value +
          ' mm) aufgerundet.'
      );
    }

    if (spacingPick.clamped) {
      hints.push(
        'Angefragter Achsabstand (' +
          spacing +
          ' mm) liegt ueber der Tabellengrenze (' +
          entry.spacings[entry.spacings.length - 1] +
          ' mm) – groesster Tabellenwert (dichtester Abstand) verwendet. Unbedingt statisch pruefen lassen!'
      );
    } else if (spacing < spacingPick.value) {
      hints.push(
        'Auf naechst-groesseren Achsabstand (' +
          spacingPick.value +
          ' mm) aufgerundet (konservativ).'
      );
    }

    return {
      B: dim[0],
      H: dim[1],
      hint: hints.join(' '),
      disclaimer: DISCLAIMER
    };
  }

  /* ----------------------------------------------------------------
   * Export
   * ---------------------------------------------------------------- */
  if (typeof global !== 'undefined') {
    global.HOLZ_SPAN_TABLE = HOLZ_SPAN_TABLE;
    global.suggestCrossSection = suggestCrossSection;
  }

  // Zusaetzlich CommonJS-Export, falls in einer Node-Umgebung genutzt.
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { HOLZ_SPAN_TABLE: HOLZ_SPAN_TABLE, suggestCrossSection: suggestCrossSection };
  }
})(typeof window !== 'undefined' ? window : this);

/* ===== parametric.js ===== */
/* ============================================================================
 * holzbau3d.app — Parametrische Holzkonstruktions-Generatoren
 * ----------------------------------------------------------------------------
 * Erzeugt aus wenigen Masseingaben komplette Holzkonstruktionen als
 * Balken-Arrays im Editor-Format.
 *
 * Balken-Objekt:
 *   { name, woodType, shape:'rect', L, B, H, axis, x, y, z, rx, ry, rz,
 *     group, phase, cutouts? }
 *
 * Konvention (identisch zum 3D-Editor):
 *   - Ursprung (x,y,z) = MINIMALE Ecke ("Punkt 0"), Millimeter, y=0 = Boden.
 *   - Ausdehnung in +Richtung ab (x,y,z):
 *        Breite entlang X = (axis==='x' ? L : B)
 *        Hoehe  entlang Y = (axis==='y' ? L : H)
 *        Tiefe  entlang Z = (axis==='z' ? L : B)
 *   - axis: Achse entlang der die Laenge L laeuft.
 *   - rx/ry/rz: Drehung in Grad um die jeweilige Achse, angewandt um den
 *        Balken-Mittelpunkt (fuer Dachneigungen der Sparren).
 *   - woodType nur aus:
 *        'Fichte','Kiefer','Lärche','Eiche','Douglasie','Brettschichtholz (BSH)'
 *
 * KONSTRUKTIVE REGELN (seit der Ueberarbeitung der Vorlagen):
 *   1. Kein Bauteil steckt in einem anderen. Wo ein geneigter Sparren auf
 *      einer waagerechten Pfette liegt, bekommt er eine KERVE — sonst
 *      beruehrt er sie nur auf einer Linie oder schneidet hinein.
 *   2. Jede Last findet einen Weg bis zum Boden. Pfetten liegen AUF den
 *      Stuetzen, nicht in ihnen; sich kreuzende Rahmenhoelzer werden ueber
 *      Eck VERBLATTET, damit beide aufliegen.
 *   3. Ein Rechteck aus vier gelenkig verbundenen Staeben ist beweglich.
 *      Wo Kopfbaender geometrisch moeglich sind, sitzen welche.
 *   Das ersetzt keinen Standsicherheitsnachweis — es sorgt dafuer, dass die
 *   Vorlage baubar ist und nicht nur so aussieht.
 * ==========================================================================*/

(function (root) {
  'use strict';

  var DEG = 180 / Math.PI, RAD = Math.PI / 180;
  var r1 = function (v) { return Math.round(v * 10) / 10; };

  // Balken-Factory: fuellt alle Pflichtfelder mit sinnvollen Defaults.
  function mk(o) {
    return {
      name:     o.name     != null ? o.name     : 'Balken',
      woodType: o.woodType != null ? o.woodType : 'Fichte',
      shape:    'rect',
      L:        Math.round(o.L),
      B:        Math.round(o.B),
      H:        Math.round(o.H),
      axis:     o.axis     != null ? o.axis     : 'x',
      x:        r1(o.x || 0),
      y:        r1(o.y || 0),
      z:        r1(o.z || 0),
      rx:       o.rx != null ? o.rx : 0,
      ry:       o.ry != null ? o.ry : 0,
      rz:       o.rz != null ? o.rz : 0,
      group:    o.group != null ? o.group : 'Bauteil',
      phase:    o.phase != null ? o.phase : null
    };
  }

  // Zahl mit Fallback (akzeptiert 0 als gueltigen Wert).
  function num(v, def) {
    var n = parseFloat(v);
    return isFinite(n) ? n : def;
  }

  // Gleichmaessig verteilte Positionen 0..span (inkl. beider Enden),
  // Abstand <= maxSpacing. Liefert Mindest-Ecken-Koordinaten (0 .. span-sec).
  function spread(span, sec, maxSpacing) {
    var usable = Math.max(0, span - sec);
    var n = Math.max(1, Math.ceil(usable / maxSpacing));
    var out = [];
    for (var i = 0; i <= n; i++) out.push(Math.round((i * usable) / n));
    return out;
  }

  /* ==========================================================================
   * GEOMETRIE — dieselben Formeln wie im Editor
   * ========================================================================*/

  function ausd(b) {
    if (b.axis === 'x') return [b.L, b.H, b.B];
    if (b.axis === 'y') return [b.B, b.L, b.H];
    return [b.B, b.H, b.L];
  }
  function achsen(b) {
    if (b.axis === 'y') return { iL: 1, iH: 2, iB: 0 };
    if (b.axis === 'z') return { iL: 2, iH: 1, iB: 0 };
    return { iL: 0, iH: 1, iB: 2 };
  }
  // Quaternion aus Euler XYZ — Zeichen fuer Zeichen wie THREE.Quaternion.
  function quat(rx, ry, rz) {
    var c1 = Math.cos(rx / 2), s1 = Math.sin(rx / 2),
        c2 = Math.cos(ry / 2), s2 = Math.sin(ry / 2),
        c3 = Math.cos(rz / 2), s3 = Math.sin(rz / 2);
    return [s1 * c2 * c3 + c1 * s2 * s3, c1 * s2 * c3 - s1 * c2 * s3,
            c1 * c2 * s3 + s1 * s2 * c3, c1 * c2 * c3 - s1 * s2 * s3];
  }
  function dreh(q, v) {
    var x = v[0], y = v[1], z = v[2], qx = q[0], qy = q[1], qz = q[2], qw = q[3];
    var ix =  qw * x + qy * z - qz * y, iy =  qw * y + qz * x - qx * z;
    var iz =  qw * z + qx * y - qy * x, iw = -qx * x - qy * y - qz * z;
    return [ix * qw + iw * -qx + iy * -qz - iz * -qy,
            iy * qw + iw * -qy + iz * -qx - ix * -qz,
            iz * qw + iw * -qz + ix * -qy - iy * -qx];
  }
  // Weltlage eines Punktes in lokalen, an der Bauteilecke beginnenden Koordinaten.
  function welt(b, lok) {
    var e = ausd(b), q = quat((b.rx || 0) * RAD, (b.ry || 0) * RAD, (b.rz || 0) * RAD);
    var d = dreh(q, [lok[0] - e[0] / 2, lok[1] - e[1] / 2, lok[2] - e[2] / 2]);
    return [b.x + e[0] / 2 + d[0], b.y + e[1] / 2 + d[1], b.z + e[2] / 2 + d[2]];
  }

  /* Die Schnittebene eines Bauteils ist die LAENGS-HOEHEN-Ebene; gestochen
     wird durch die Breite. In ihr ist die Abbildung (u,v) -> Welt affin, also
     durch drei Punkte vollstaendig bestimmt. Damit laesst sich jeder
     Halbraum der Welt in eine Gerade in (u,v) uebersetzen — und ein
     Gegenstueck ist nichts anderes als ein Schnitt von Halbraeumen. */
  function karte(b) {
    var e = ausd(b), a = achsen(b);
    var l0 = [0, 0, 0]; l0[a.iB] = e[a.iB] / 2;
    var p00 = welt(b, l0);
    var lu = l0.slice(); lu[a.iL] = 1;
    var lv = l0.slice(); lv[a.iH] = 1;
    var pu = welt(b, lu), pv = welt(b, lv);
    return { p00: p00, L: e[a.iL], H: e[a.iH],
             Du: [pu[0] - p00[0], pu[1] - p00[1], pu[2] - p00[2]],
             Dv: [pv[0] - p00[0], pv[1] - p00[1], pv[2] - p00[2]] };
  }

  // Polygon an der Geraden a*u + b*v = c abschneiden (behalten: <= c).
  function clip(poly, a, b, c) {
    var out = [], i, p, q, dp, dq, t;
    for (i = 0; i < poly.length; i++) {
      p = poly[i]; q = poly[(i + 1) % poly.length];
      dp = a * p[0] + b * p[1] - c; dq = a * q[0] + b * q[1] - c;
      if (dp <= 1e-9) out.push(p);
      if ((dp < -1e-9 && dq > 1e-9) || (dp > 1e-9 && dq < -1e-9)) {
        t = dp / (dp - dq);
        out.push([p[0] + (q[0] - p[0]) * t, p[1] + (q[1] - p[1]) * t]);
      }
    }
    return out;
  }

  function flaeche(poly) {
    var s = 0, i, j;
    for (i = 0, j = poly.length - 1; i < poly.length; j = i++) {
      s += (poly[j][0] + poly[i][0]) * (poly[j][1] - poly[i][1]);
    }
    return Math.abs(s / 2);
  }

  // Weltkasten eines ungedrehten Bauteils: [x0,x1,y0,y1,z0,z1].
  function kasten(b) {
    var e = ausd(b);
    return [b.x, b.x + e[0], b.y, b.y + e[1], b.z, b.z + e[2]];
  }

  /* AUFLAGER EINSCHNEIDEN.
     Geschnitten wird immer am TATSAECHLICHEN Gegenstueck, nie an der gedachten
     Ebene. Die Bauteilmasse werden gerundet — schon 0,4 mm Unterschied
     zwischen Soll-Ebene und gerundetem Balken genuegten, damit die
     Kollisionspruefung wieder anschlaegt. `s` begrenzt die Auflagerbreite auf
     der genannten Achse (0 = volle Breite des Gegenstuecks). */
  function aufKlotz(k, achse, s, vonUnten) {
    var kk = k.slice();
    if (s > 0) {
      if (vonUnten) kk[2 * achse + 1] = kk[2 * achse] + s;
      else kk[2 * achse] = kk[2 * achse + 1] - s;
    }
    kk[2] = kk[3] - 900;                     // nur bis unter die Oberkante
    return kk;
  }

  /* Halbraum-Bausteine. n·P <= c heisst "auf dieser Seite der Ebene". */
  function hsMax(i, v) { var n = [0, 0, 0]; n[i] = 1; return { n: n, c: v }; }
  function hsMin(i, v) { var n = [0, 0, 0]; n[i] = -1; return { n: n, c: -v }; }
  function hsKasten(k) {
    return [hsMin(0, k[0]), hsMax(0, k[1]), hsMin(1, k[2]),
            hsMax(1, k[3]), hsMin(2, k[4]), hsMax(2, k[5])];
  }
  // Ebene durch p mit Normale n (weggenommen wird die Seite, in die n zeigt).
  function hsEbene(n, p) { return { n: n, c: n[0] * p[0] + n[1] * p[1] + n[2] * p[2] }; }

  /* Aus `b` alles herausnehmen, was in ALLEN angegebenen Halbraeumen liegt.
     Liefert das Bauteil zurueck, damit sich Schnitte verketten lassen. */
  function schneide(b, hs, art) {
    var k = karte(b);
    var poly = [[0, 0], [k.L, 0], [k.L, k.H], [0, k.H]];
    for (var i = 0; i < hs.length && poly.length >= 3; i++) {
      var n = hs[i].n;
      var a = n[0] * k.Du[0] + n[1] * k.Du[1] + n[2] * k.Du[2];
      var bb = n[0] * k.Dv[0] + n[1] * k.Dv[1] + n[2] * k.Dv[2];
      var c = hs[i].c - (n[0] * k.p00[0] + n[1] * k.p00[1] + n[2] * k.p00[2]);
      if (Math.abs(a) < 1e-9 && Math.abs(bb) < 1e-9) {
        // Ebene senkrecht zur Schnittebene: gilt fuer das ganze Bauteil oder
        // fuer keinen Punkt.
        if (c < -1e-6) { poly = []; }
        continue;
      }
      poly = clip(poly, a, bb, c);
    }
    if (poly.length < 3 || flaeche(poly) < 100) return b;   // nichts Nennenswertes
    b.cutouts = b.cutouts || [];
    b.cutouts.push({ shape: 'poly', ebene: 'seite', verbindung: art || 'auflager',
      ecken: poly.map(function (p) {
        return { u: Math.round(p[0] * 10) / 10, v: Math.round(p[1] * 10) / 10 };
      }) });
    return b;
  }

  /* UEBERBLATTUNG ueber Eck: beide Balken geben die halbe Ueberdeckung ab.
     `unten` sagt, wer sein UNTERES Stueck hergibt — der liegt danach oben. */
  function verblatten(a, b, aLiegtOben) {
    var ka = [Math.max(a.x, b.x), Math.min(a.x + ausd(a)[0], b.x + ausd(b)[0]),
              0, 0,
              Math.max(a.z, b.z), Math.min(a.z + ausd(a)[2], b.z + ausd(b)[2])];
    var lo = Math.max(a.y, b.y), hi = Math.min(a.y + ausd(a)[1], b.y + ausd(b)[1]);
    var m = (lo + hi) / 2;
    schneide(a, hsKasten([ka[0], ka[1], aLiegtOben ? lo : m, aLiegtOben ? m : hi, ka[4], ka[5]]), 'blatt');
    schneide(b, hsKasten([ka[0], ka[1], aLiegtOben ? m : lo, aLiegtOben ? hi : m, ka[4], ka[5]]), 'blatt');
  }

  /* KOPFBAND.
     Beschrieben wird die Ecke, die es aussteift: die Flanke der Stuetze
     (Koordinate a0, Richtung s = +1/-1), die Unterkante des Traegers (y1) und
     die Schenkellaenge. Beide Enden werden an EBENEN abgeschnitten —
     senkrecht an der Stuetzenflanke, waagerecht unter dem Traeger. Genau so
     saegt man ein Kopfband. Es greift damit g + h*wurzel(2) weit aus.       */
  function kopfband(o) {
    var w = Math.SQRT1_2, ue = o.h + 30;
    var L = Math.SQRT2 * o.schenkel + 2 * ue;
    var mA = o.a0 + o.s * o.schenkel / 2, mY = o.y1 - o.schenkel / 2;
    var cA = mA + o.s * w * o.h / 2, cY = mY - w * o.h / 2;
    var b, e;
    if (o.ebene === 'xy') {
      b = mk({ name: o.name, woodType: o.holz, L: L, B: o.breite, H: o.h, axis: 'x',
               rz: o.s > 0 ? 45 : 135, x: 0, y: 0, z: o.quer, group: o.group });
      e = ausd(b);
      b.x = r1(cA - e[0] / 2); b.y = r1(cY - e[1] / 2);
    } else {
      b = mk({ name: o.name, woodType: o.holz, L: L, B: o.breite, H: o.h, axis: 'z',
               rx: o.s > 0 ? -45 : -135, x: o.quer, y: 0, z: 0, group: o.group });
      e = ausd(b);
      b.z = r1(cA - e[2] / 2); b.y = r1(cY - e[1] / 2);
    }
    var g = 6000, iA = o.ebene === 'xy' ? 0 : 2, iQ = o.ebene === 'xy' ? 2 : 0;
    var flanke = [hsMin(1, cY - g), hsMax(1, o.y1), hsMin(iQ, o.quer - g), hsMax(iQ, o.quer + o.breite + g)];
    flanke.push(o.s > 0 ? hsMax(iA, o.a0) : hsMin(iA, o.a0));
    schneide(b, flanke, 'auflager');
    schneide(b, [hsMin(1, o.y1), hsMax(1, o.y1 + g),
                 hsMin(iA, cA - g), hsMax(iA, cA + g),
                 hsMin(iQ, o.quer - g), hsMax(iQ, o.quer + o.breite + g)], 'auflager');
    return b;
  }

  /* Auflagerbreite einer Kerve: so breit wie moeglich, aber nie tiefer als ein
     Drittel der Sparrenhoehe — mehr schwaecht den Sparren zu sehr. Bei einem
     flachen Dach liegt der Sparren damit ueber die volle Pfettenbreite auf. */
  function auflagerbreite(pfetteB, sparrenH, tan) {
    if (tan <= 1e-6) return pfetteB;
    return Math.max(30, Math.min(pfetteB, (sparrenH / 3) / tan));
  }

  // ==========================================================================
  // 1) CARPORT  — Pultdach, Neigung quer ueber die Breite (X)
  //    Niedrig bei x=0, hoch bei x=width. Sparren liegen quer (axis 'x').
  //
  //    Frueher steckten die Sparren in den Pfetten (bis 8 Durchdringungen).
  //    Jetzt sitzen sie mit einer Kerve auf; die Neigung wird aus dem
  //    GERUNDETEN Hoehenunterschied zurueckgerechnet, damit beide Auflager
  //    exakt in einer Ebene liegen.
  //    Quer zur Fahrtrichtung bleibt der Carport ein Zweigelenkrahmen — dort
  //    muessen die Pfosten eingespannt sein (Pfostenanker im Fundament).
  //    Ein Querriegel wuerde die Einfahrt versperren.
  // ==========================================================================
  function genCarport(p) {
    p = p || {};
    var width  = Math.round(num(p.width, 3000));
    var depth  = Math.round(num(p.depth, 5000));
    var height = Math.round(num(p.height, 2200));
    var postSec = Math.round(num(p.postSec, 120));
    var pitch  = num(p.pitch, 5);

    var beams = [];
    var pfB = postSec, pfH = 160, spB = 80, spH = 160;
    var stich = width - pfB;                                  // Abstand der Auflager
    var rise = Math.round(stich * Math.tan(pitch * RAD));
    var tan = rise / stich, ang = Math.atan(tan) * DEG;
    var s = auflagerbreite(pfB, spH, tan);
    var okN = height + pfH, okH = okN + rise;                 // Pfetten-Oberkanten

    // --- Pfosten: Raster entlang der Tiefe (max ~2,5 m) ---
    var nSeg = Math.max(1, Math.ceil(depth / 2500));
    var zRows = [];
    for (var r = 0; r <= nSeg; r++) {
      var zRow = Math.round((r * depth) / nSeg);
      if (r === 0) zRow = 0;
      else if (r === nSeg) zRow = depth - postSec;
      else zRow = Math.round(zRow - postSec / 2);
      zRows.push(zRow);
      beams.push(mk({ name: 'Pfosten niedrig', woodType: 'Douglasie',
        L: height, B: postSec, H: postSec, axis: 'y',
        x: 0, y: 0, z: zRow, group: 'Pfosten' }));
      beams.push(mk({ name: 'Pfosten hoch', woodType: 'Douglasie',
        L: height + rise, B: postSec, H: postSec, axis: 'y',
        x: width - postSec, y: 0, z: zRow, group: 'Pfosten' }));
    }

    // --- Laengs-Pfetten AUF den Pfosten ---
    var pfN = mk({ name: 'Pfette niedrig', woodType: 'Brettschichtholz (BSH)',
      L: depth, B: pfB, H: pfH, axis: 'z',
      x: 0, y: height, z: 0, group: 'Pfetten' });
    var pfHo = mk({ name: 'Pfette hoch', woodType: 'Brettschichtholz (BSH)',
      L: depth, B: pfB, H: pfH, axis: 'z',
      x: width - pfB, y: height + rise, z: 0, group: 'Pfetten' });
    beams.push(pfN, pfHo);
    var kN = kasten(pfN), kH = kasten(pfHo);

    // --- Sparren quer, mit Kerve auf beiden Pfetten ---
    var ue = Math.min(300, Math.round(width / 8));
    var nSp = Math.max(2, Math.round(depth / 700) + 1);
    var spL = Math.round((width + 2 * ue) / Math.cos(ang * RAD));
    for (var i = 0; i < nSp; i++) {
      var zS = Math.round((i * (depth - spB)) / (nSp - 1));
      var sp = mk({ name: 'Sparren', woodType: 'Fichte',
        L: spL, B: spB, H: spH, axis: 'x', rz: ang,
        x: 0, y: 0, z: zS, group: 'Sparren' });
      // Unterkante durch den Auflagerpunkt (x = s, y = okN) legen
      var ist = welt(sp, [0, 0, 0]);
      var ziel = [-ue, kN[3] - (s + ue) * tan, zS];
      sp.x = r1(sp.x + ziel[0] - ist[0]); sp.y = r1(sp.y + ziel[1] - ist[1]);
      schneide(sp, hsKasten(aufKlotz([kN[0], kN[1], 0, kN[3], -1e5, 1e5], 0, s, true)), 'auflager');
      schneide(sp, hsKasten(aufKlotz([kH[0], kH[1], 0, kH[3], -1e5, 1e5], 0, s, true)), 'auflager');
      beams.push(sp);
    }

    // --- Kopfbaender laengs an den Endpfosten ---
    var lueck = zRows.length > 1 ? zRows[1] - (zRows[0] + postSec) : depth - 2 * postSec;
    var hKb = Math.min(100, Math.round(postSec * 0.9));
    var g = Math.max(250, Math.min(600, Math.round(lueck - hKb * Math.SQRT2 - 40)));
    if (g >= 250) {
      [[0, height, 'niedrig'], [width - pfB, height + rise, 'hoch']].forEach(function (v) {
        beams.push(kopfband({ name: 'Kopfband ' + v[2], holz: 'Douglasie', group: 'Aussteifung',
          ebene: 'zy', a0: postSec, s: 1, y1: v[1], schenkel: g, h: hKb,
          breite: postSec, quer: v[0] }));
        beams.push(kopfband({ name: 'Kopfband ' + v[2], holz: 'Douglasie', group: 'Aussteifung',
          ebene: 'zy', a0: depth - postSec, s: -1, y1: v[1], schenkel: g, h: hKb,
          breite: postSec, quer: v[0] }));
      });
    }
    return beams;
  }

  // ==========================================================================
  // 2) PERGOLA — 4 Eckpfosten, umlaufender Rahmen oben, Querlatten (~40 cm)
  //
  //    Der Querrahmen war frueher ZWISCHEN die Laengsbalken gesetzt: er hing
  //    ohne Auflager an seinen Verbindungen. Jetzt laufen alle vier Balken
  //    durch und sind ueber Eck verblattet — jeder liegt auf. Acht
  //    Kopfbaender machen das Gestell in beiden Richtungen steif.
  // ==========================================================================
  function genPergola(p) {
    p = p || {};
    var width  = Math.round(num(p.width, 3000));
    var depth  = Math.round(num(p.depth, 4000));
    var height = Math.round(num(p.height, 2400));
    var postSec = Math.round(num(p.postSec, 120));

    var beams = [];
    var frB = postSec, frH = 160, latB = 60, latH = 100;

    var xs = [0, width - postSec], zs = [0, depth - postSec];
    for (var a = 0; a < 2; a++) for (var b = 0; b < 2; b++) {
      beams.push(mk({ name: 'Eckpfosten', woodType: 'Lärche',
        L: height, B: postSec, H: postSec, axis: 'y',
        x: xs[a], y: 0, z: zs[b], group: 'Pfosten' }));
    }

    // Rahmen: quer (X) liegt unten auf den Pfosten, laengs (Z) oben darauf.
    var quer = [
      mk({ name: 'Rahmen quer V', woodType: 'Lärche', L: width, B: frB, H: frH,
           axis: 'x', x: 0, y: height, z: 0, group: 'Rahmen' }),
      mk({ name: 'Rahmen quer H', woodType: 'Lärche', L: width, B: frB, H: frH,
           axis: 'x', x: 0, y: height, z: depth - frB, group: 'Rahmen' })];
    var laengs = [
      mk({ name: 'Rahmen längs L', woodType: 'Lärche', L: depth, B: frB, H: frH,
           axis: 'z', x: 0, y: height, z: 0, group: 'Rahmen' }),
      mk({ name: 'Rahmen längs R', woodType: 'Lärche', L: depth, B: frB, H: frH,
           axis: 'z', x: width - frB, y: height, z: 0, group: 'Rahmen' })];
    for (var i = 0; i < 2; i++) for (var j = 0; j < 2; j++) verblatten(laengs[i], quer[j], true);
    beams = beams.concat(quer, laengs);

    // Querlatten auf dem Rahmen
    var nl = Math.max(2, Math.round(depth / 400) + 1);
    for (var k = 0; k < nl; k++) {
      var zL = Math.round((k * (depth - latB)) / (nl - 1));
      beams.push(mk({ name: 'Querlatte', woodType: 'Lärche',
        L: width, B: latB, H: latH, axis: 'x',
        x: 0, y: height + frH, z: zL, group: 'Sparren' }));
    }

    // Acht Kopfbaender: an jedem Pfosten eines in Laengs- und eines in Querrichtung.
    var hKb = Math.min(100, Math.round(postSec * 0.8));
    var frei = Math.min(width, depth) - 2 * postSec;
    var g = Math.max(200, Math.min(500, Math.round(frei / 2 - hKb * Math.SQRT2)));
    var bKb = Math.max(60, Math.round(postSec * 0.6));
    var mitte = Math.round((postSec - bKb) / 2);
    [[0, 1], [width - postSec, -1]].forEach(function (vx) {
      [[0, 1], [depth - postSec, -1]].forEach(function (vz) {
        beams.push(kopfband({ name: 'Kopfband quer', holz: 'Lärche', group: 'Aussteifung',
          ebene: 'xy', a0: vx[1] > 0 ? postSec : width - postSec, s: vx[1], y1: height,
          schenkel: g, h: hKb, breite: bKb, quer: vz[0] + mitte }));
        beams.push(kopfband({ name: 'Kopfband längs', holz: 'Lärche', group: 'Aussteifung',
          ebene: 'zy', a0: vz[1] > 0 ? postSec : depth - postSec, s: vz[1], y1: height,
          schenkel: g, h: hKb, breite: bKb, quer: vx[0] + mitte }));
      });
    });
    return beams;
  }

  // ==========================================================================
  // 3) GARTENHAUS — Staenderbauweise, Pultdach mit Gefaelle ueber die Tiefe
  //
  //    Die alte Fassung hatte je nach Masseingabe 17 bis 32 Durchdringungen:
  //    die geneigten Seiten-Raehme liefen durch die waagerechten, die
  //    Staender steckten in den Raehmen, die Sparren in den Pfetten.
  //    Neu: Schwellenkranz ueber Eck verblattet; die geneigten Seitenraehme
  //    laufen durch und sitzen mit einer Kerve auf jedem Seitenstaender; die
  //    waagerechten Raehme vorn und hinten sind dazwischen eingepasst und
  //    tragen die Sparren, die wiederum eine Kerve bekommen.
  // ==========================================================================
  function genGartenhaus(p) {
    p = p || {};
    var width  = Math.round(num(p.width, 3000));
    var depth  = Math.round(num(p.depth, 2500));
    var wallH  = Math.round(num(p.wallH, 2200));
    var postSec = Math.round(num(p.postSec, 100));

    var beams = [];
    var sillB = postSec, sillH = 60, rahmB = postSec, rahmH = 60;
    var spB = 80, spH = 140;
    var stich = depth - rahmB;
    var rise = Math.round(stich * Math.tan(10 * RAD));
    var tan = rise / stich, ang = Math.atan(tan) * DEG;
    var s = auflagerbreite(rahmB, spH, tan);
    var okV = wallH + rahmH;                    // Oberkante Raehm vorn
    var okH = okV + rise;                       // Oberkante Raehm hinten

    // --- Schwellenkranz, ueber Eck verblattet ---
    var sV = mk({ name: 'Schwelle V', L: width, B: sillB, H: sillH, axis: 'x',
      x: 0, y: 0, z: 0, group: 'Rahmen' });
    var sH = mk({ name: 'Schwelle H', L: width, B: sillB, H: sillH, axis: 'x',
      x: 0, y: 0, z: depth - sillB, group: 'Rahmen' });
    var sL = mk({ name: 'Schwelle L', L: depth, B: sillB, H: sillH, axis: 'z',
      x: 0, y: 0, z: 0, group: 'Rahmen' });
    var sR = mk({ name: 'Schwelle R', L: depth, B: sillB, H: sillH, axis: 'z',
      x: width - sillB, y: 0, z: 0, group: 'Rahmen' });
    [sL, sR].forEach(function (l) { [sV, sH].forEach(function (q) { verblatten(l, q, true); }); });
    beams.push(sV, sH, sL, sR);

    /* Unterkante der Seitenraehme: die Ebene der Sparrenunterkanten, um die
       (senkrecht gemessene) Raehmhoehe nach unten versetzt. Auf ihr enden die
       Seitenstaender. */
    var uk = function (z) { return okV + (z - s) * tan - rahmH / Math.cos(ang * RAD); };

    // --- Seitenstaender (inkl. Ecken) ---
    var zs = spread(depth, postSec, 800);
    var seitenSt = [[], []];
    zs.forEach(function (pz) {
      var top = uk(pz + postSec);                       // Kerve ueber die volle Breite
      [0, width - postSec].forEach(function (px, k) {
        var st = mk({ name: 'Ständer ' + (k ? 'R' : 'L'), L: Math.max(100, top - sillH),
          B: postSec, H: postSec, axis: 'y', x: px, y: sillH, z: pz, group: 'Pfosten' });
        seitenSt[k].push(st); beams.push(st);
      });
    });
    // --- Vorder-/Rueckstaender (ohne Ecken; die gehoeren zur Seitenwand) ---
    var xs = spread(width, postSec, 800);
    xs.forEach(function (px, i) {
      if (i === 0 || i === xs.length - 1) return;
      beams.push(mk({ name: 'Ständer V', L: okV - rahmH - sillH, B: postSec, H: postSec,
        axis: 'y', x: px, y: sillH, z: 0, group: 'Pfosten' }));
      beams.push(mk({ name: 'Ständer H', L: okH - rahmH - sillH, B: postSec, H: postSec,
        axis: 'y', x: px, y: sillH, z: depth - postSec, group: 'Pfosten' }));
    });

    // --- Raehm vorn/hinten, waagerecht, zwischen die Seitenraehme eingepasst ---
    var rV = mk({ name: 'Rähm V', L: width - 2 * rahmB, B: rahmB, H: rahmH, axis: 'x',
      x: rahmB, y: okV - rahmH, z: 0, group: 'Rahmen' });
    var rH = mk({ name: 'Rähm H', L: width - 2 * rahmB, B: rahmB, H: rahmH, axis: 'x',
      x: rahmB, y: okH - rahmH, z: depth - rahmB, group: 'Rahmen' });
    beams.push(rV, rH);
    var kV = kasten(rV), kHi = kasten(rH);

    // --- Seitenraehme: geneigt, ueber jedem Seitenstaender eingekerbt ---
    [0, width - rahmB].forEach(function (px, k) {
      var rl = mk({ name: 'Rähm ' + (k ? 'R' : 'L'), L: Math.round(depth / Math.cos(ang * RAD)),
        B: rahmB, H: rahmH, axis: 'z', rx: -ang, x: px, y: 0, z: 0, group: 'Rahmen' });
      var ist = welt(rl, [0, rahmH, 0]);              // Oberkante am vorderen Ende
      rl.y = r1(rl.y + (kV[3] - (s - kV[4]) * tan) - ist[1]);
      rl.z = r1(rl.z + 0 - ist[2]);
      seitenSt[k].forEach(function (st) {
        var ks = kasten(st);
        schneide(rl, hsKasten([px - 50, px + rahmB + 50, ks[3] - 900, ks[3], ks[4], ks[5]]),
          'auflager');
      });
      beams.push(rl);
    });

    // --- Sparren: auf Raehm V und H, mit Kerve ---
    var nutz = width - 2 * rahmB;
    var nSp = Math.max(2, Math.round(nutz / 700) + 1);
    var spL = Math.round(depth / Math.cos(ang * RAD));
    for (var m = 0; m < nSp; m++) {
      var xS = Math.round(rahmB + (m * (nutz - spB)) / (nSp - 1));
      var sp = mk({ name: 'Sparren', woodType: 'Fichte', L: spL, B: spB, H: spH,
        axis: 'z', rx: -ang, x: xS, y: 0, z: 0, group: 'Sparren' });
      var i0 = welt(sp, [0, 0, 0]);
      sp.y = r1(sp.y + (kV[3] - (s - kV[4]) * tan) - i0[1]);
      sp.z = r1(sp.z + 0 - i0[2]);
      schneide(sp, hsKasten(aufKlotz([-1e5, 1e5, 0, kV[3], kV[4], kV[5]], 2, s, true)), 'auflager');
      schneide(sp, hsKasten(aufKlotz([-1e5, 1e5, 0, kHi[3], kHi[4], kHi[5]], 2, s, true)), 'auflager');
      beams.push(sp);
    }

    // --- Kopfbaender in den Giebelwaenden ---
    var hKb = Math.min(90, Math.round(postSec * 0.9));
    var bKb = Math.max(50, Math.round(postSec * 0.6));
    var g = Math.max(200, Math.min(450, Math.round((xs[1] - postSec) - hKb * Math.SQRT2 - 30)));
    if (g >= 200 && width > 2 * postSec + 400) {
      [[postSec, 1], [width - postSec, -1]].forEach(function (v) {
        beams.push(kopfband({ name: 'Kopfband V', group: 'Aussteifung', ebene: 'xy',
          a0: v[0], s: v[1], y1: okV - rahmH, schenkel: g, h: hKb, breite: bKb,
          quer: Math.round((postSec - bKb) / 2) }));
        beams.push(kopfband({ name: 'Kopfband H', group: 'Aussteifung', ebene: 'xy',
          a0: v[0], s: v[1], y1: okH - rahmH, schenkel: g, h: hKb, breite: bKb,
          quer: depth - postSec + Math.round((postSec - bKb) / 2) }));
      });
    }
    return beams;
  }

  // ==========================================================================
  // 4) TERRASSE — Anlehn-Pultdach an der Hauswand
  //    Wandpfette hoch (wallH), Frontpfosten (frontH), Sparren mit Gefaelle
  //    von der Wand (z=0, hoch) zur Front (z=depth, niedrig).
  //
  //    Die Wandpfette wird an die Hauswand geschraubt — sie hat im Modell
  //    bewusst kein Auflager, und quer ausgesteift wird ueber die Wand.
  //    In Laengsrichtung sitzen Kopfbaender an den Frontpfosten.
  //    Frueher schnitten die Sparren bis 12-fach in die Pfetten; die Front
  //    konnte sogar HOEHER liegen als die Wand, dann lief das Wasser aufs Haus zu.
  // ==========================================================================
  function genTerrasse(p) {
    p = p || {};
    var width  = Math.round(num(p.width, 4000));
    var depth  = Math.round(num(p.depth, 3000));
    var wallH  = Math.round(num(p.wallH, 2600));
    var frontH = Math.round(num(p.frontH, 2200));
    var postSec = Math.round(num(p.postSec, 120));

    var beams = [];
    var pfB = postSec, pfH = 160, spB = 80, spH = 160;
    // Ein Pultdach muss zur Front hin FALLEN. Liegt die Front zu hoch, wird
    // sie gesenkt — lieber die Eingabe korrigieren als ein Dach bauen, das
    // das Wasser gegen die Hauswand leitet.
    var stich = depth - pfB;
    var minGefaelle = Math.round(stich * Math.tan(3 * RAD));
    if (wallH - frontH < minGefaelle) frontH = wallH - minGefaelle;
    var rise = wallH - frontH;
    var tan = rise / stich, ang = Math.atan(tan) * DEG;
    var s = auflagerbreite(pfB, spH, tan);
    var okW = wallH + pfH, okF = frontH + pfH;

    var pfW = mk({ name: 'Wandpfette', woodType: 'Brettschichtholz (BSH)',
      L: width, B: pfB, H: pfH, axis: 'x',
      x: 0, y: wallH, z: 0, group: 'Pfetten' });
    beams.push(pfW);

    var nPosts = Math.max(2, Math.round(width / 2000) + 1);
    var xs = [];
    for (var i = 0; i < nPosts; i++) xs.push(Math.round((i * (width - postSec)) / (nPosts - 1)));
    xs.forEach(function (px) {
      beams.push(mk({ name: 'Frontpfosten', woodType: 'Douglasie',
        L: frontH, B: postSec, H: postSec, axis: 'y',
        x: px, y: 0, z: depth - postSec, group: 'Pfosten' }));
    });
    var pfF = mk({ name: 'Frontpfette', woodType: 'Brettschichtholz (BSH)',
      L: width, B: pfB, H: pfH, axis: 'x',
      x: 0, y: frontH, z: depth - pfB, group: 'Pfetten' });
    beams.push(pfF);
    var kW = kasten(pfW), kF = kasten(pfF);

    // Sparren: Unterkante durch (z = s, okW) — Gefaelle nach vorn.
    var nSp = Math.max(2, Math.round(width / 700) + 1);
    var ue = Math.min(250, Math.round(depth / 10));
    var spL = Math.round((depth + ue) / Math.cos(ang * RAD));
    for (var k = 0; k < nSp; k++) {
      var xS = Math.round((k * (width - spB)) / (nSp - 1));
      var sp = mk({ name: 'Sparren', woodType: 'Fichte', L: spL, B: spB, H: spH,
        axis: 'z', rx: ang, x: xS, y: 0, z: 0, group: 'Sparren' });
      var i0 = welt(sp, [0, 0, 0]);
      sp.y = r1(sp.y + (kW[3] + (kW[5] - s) * tan) - i0[1]);
      sp.z = r1(sp.z + 0 - i0[2]);
      schneide(sp, hsKasten(aufKlotz([-1e5, 1e5, 0, kW[3], kW[4], kW[5]], 2, s, false)), 'auflager');
      schneide(sp, hsKasten(aufKlotz([-1e5, 1e5, 0, kF[3], kF[4], kF[5]], 2, s, false)), 'auflager');
      beams.push(sp);
    }

    // Kopfbaender laengs an den aeusseren Frontpfosten
    var hKb = Math.min(100, Math.round(postSec * 0.9));
    var frei = xs.length > 1 ? xs[1] - postSec : width - 2 * postSec;
    var g = Math.max(250, Math.min(600, Math.round(frei - hKb * Math.SQRT2 - 40)));
    if (g >= 250 && width > 2 * postSec + 600) {
      beams.push(kopfband({ name: 'Kopfband L', holz: 'Douglasie', group: 'Aussteifung',
        ebene: 'xy', a0: postSec, s: 1, y1: frontH, schenkel: g, h: hKb,
        breite: postSec, quer: depth - postSec }));
      beams.push(kopfband({ name: 'Kopfband R', holz: 'Douglasie', group: 'Aussteifung',
        ebene: 'xy', a0: width - postSec, s: -1, y1: frontH, schenkel: g, h: hKb,
        breite: postSec, quer: depth - postSec }));
    }
    return beams;
  }

  // ==========================================================================
  // PARAM-DEFINITIONEN fuer die UI
  // ==========================================================================
  var PARAM_TEMPLATES = {
    carport: {
      label: 'Carport (Pultdach)',
      gen: genCarport,
      params: [
        { key: 'width',   label: 'Breite (mm)',        def: 3000, min: 2000, max: 8000 },
        { key: 'depth',   label: 'Tiefe / Länge (mm)', def: 5000, min: 2000, max: 9000 },
        { key: 'height',  label: 'Höhe Traufe (mm)',   def: 2200, min: 1800, max: 3500 },
        { key: 'postSec', label: 'Pfostenquerschnitt (mm)', def: 120, min: 80, max: 200 },
        { key: 'pitch',   label: 'Dachneigung (°)',    def: 5,    min: 0,   max: 25 }
      ]
    },
    pergola: {
      label: 'Pergola',
      gen: genPergola,
      params: [
        { key: 'width',   label: 'Breite (mm)',        def: 3000, min: 1500, max: 6000 },
        { key: 'depth',   label: 'Tiefe (mm)',         def: 4000, min: 1500, max: 7000 },
        { key: 'height',  label: 'Höhe (mm)',          def: 2400, min: 1800, max: 3200 },
        { key: 'postSec', label: 'Pfostenquerschnitt (mm)', def: 120, min: 80, max: 200 }
      ]
    },
    gartenhaus: {
      label: 'Gartenhaus (Ständerbau)',
      gen: genGartenhaus,
      params: [
        { key: 'width',   label: 'Breite (mm)',        def: 3000, min: 2000, max: 6000 },
        { key: 'depth',   label: 'Tiefe (mm)',         def: 2500, min: 2000, max: 6000 },
        { key: 'wallH',   label: 'Wandhöhe (mm)',      def: 2200, min: 1800, max: 3000 },
        { key: 'postSec', label: 'Ständerquerschnitt (mm)', def: 100, min: 60, max: 160 }
      ]
    },
    terrasse: {
      label: 'Terrassenüberdachung (Anlehn)',
      gen: genTerrasse,
      params: [
        { key: 'width',   label: 'Breite (mm)',        def: 4000, min: 2000, max: 8000 },
        { key: 'depth',   label: 'Auskragung / Tiefe (mm)', def: 3000, min: 1500, max: 5000 },
        { key: 'wallH',   label: 'Höhe an der Wand (mm)',   def: 2600, min: 2200, max: 3500 },
        { key: 'frontH',  label: 'Höhe vorne (mm)',    def: 2200, min: 1800, max: 3200 },
        { key: 'postSec', label: 'Pfostenquerschnitt (mm)', def: 120, min: 80, max: 200 }
      ]
    }
  };

  // ==========================================================================
  // EXPORT
  // ==========================================================================
  var API = {
    genCarport: genCarport,
    genPergola: genPergola,
    genGartenhaus: genGartenhaus,
    genTerrasse: genTerrasse,
    PARAM_TEMPLATES: PARAM_TEMPLATES
  };

  if (root) {
    root.hb_param = API;
    root.PARAM_TEMPLATES = PARAM_TEMPLATES;
    root.genCarport = genCarport;
    root.genPergola = genPergola;
    root.genGartenhaus = genGartenhaus;
    root.genTerrasse = genTerrasse;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = API;
  }

})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));

/* ===== dxf.js ===== */
/*
 * dxf.js — 2D-DXF-Export (AutoCAD R12 / AC1009 ASCII) fuer holzbau3d.app
 * ------------------------------------------------------------------
 * Exportiert eine Holzbau-Konstruktion (Array von Balken) als 2D-DXF
 * mit drei nebeneinander/uebereinander angeordneten Ansichten:
 *
 *   DRAUFSICHT (Layer 'DRAUFSICHT', blau)  : X -> dxfX, Z -> dxfY (Z invertiert -> Norden oben)
 *   VORNE      (Layer 'VORNE', gruen)      : X -> dxfX, Y -> dxfY  (unterhalb der Draufsicht)
 *   SEITE      (Layer 'SEITE', rot)        : Z -> dxfX, Y -> dxfY  (rechts neben der Vorderansicht)
 *
 * Jeder Balken wird in jeder Ansicht als geschlossenes POLYLINE-Rechteck
 * (Bounding-Box-Projektion) gezeichnet. Einheiten: Millimeter.
 *
 * Balken-Objektformat:
 *   { name, woodType, shape:'rect', L, B, H, axis:'x'|'y'|'z', x, y, z, rx, ry, rz, group, phase }
 *   - axis: Achse entlang der die Laenge L laeuft ('y' = stehender Pfosten).
 *   - x,y,z: minimale Ecke ("Punkt 0") in mm, y=0 = Boden.
 *   - Ausdehnung: Breite X = (axis==='x'?L:B), Hoehe Y = (axis==='y'?L:H), Tiefe Z = (axis==='z'?L:B).
 *
 * Keine externe Bibliothek. Reiner R12-ASCII-Text.
 */
(function (global) {
  'use strict';

  var CR = '\r\n'; // DXF verwendet konventionell CRLF (Reader akzeptieren auch LF)

  // --- Hilfsfunktionen -----------------------------------------------------

  // Numerischen Wert robust holen (Fallback 0)
  function num(v) {
    v = +v;
    return isFinite(v) ? v : 0;
  }

  // Zahl DXF-tauglich formatieren: auf 4 Nachkommastellen runden,
  // ueberfluessige Nullen entfernen, negatives Null vermeiden.
  function fmt(n) {
    var r = Math.round(num(n) * 1e4) / 1e4;
    if (Object.is(r, -0)) r = 0;
    return String(r);
  }

  // --- DXF-Baustein-Erzeuger ----------------------------------------------

  // Buffer-Objekt mit Gruppencode/Wert-Schreiber und Extents-Tracking
  function makeBuffer() {
    return {
      lines: [],
      minX: Infinity, maxX: -Infinity,
      minY: Infinity, maxY: -Infinity,
      // Gruppencode + Wert anhaengen
      put: function (code, value) {
        this.lines.push(String(code));
        this.lines.push(String(value));
      },
      // dxf-Punkt fuer Extents beruecksichtigen
      track: function (dx, dy) {
        if (dx < this.minX) this.minX = dx;
        if (dx > this.maxX) this.maxX = dx;
        if (dy < this.minY) this.minY = dy;
        if (dy > this.maxY) this.maxY = dy;
      },
      text: function () {
        return this.lines.join(CR);
      }
    };
  }

  // Geschlossenes Rechteck als R12-POLYLINE emittieren.
  // pts = [[dxfX,dxfY], ...] (hier vier Eckpunkte).
  function emitPolyline(buf, layer, pts) {
    buf.put(0, 'POLYLINE');
    buf.put(8, layer);
    buf.put(66, 1);   // Vertices folgen
    buf.put(70, 1);   // Bit 1 = geschlossene Polylinie
    // Standard-Elevations-/Ausrichtungswerte (2D)
    buf.put(10, 0);
    buf.put(20, 0);
    buf.put(30, 0);
    for (var i = 0; i < pts.length; i++) {
      var x = pts[i][0], y = pts[i][1];
      buf.track(x, y);
      buf.put(0, 'VERTEX');
      buf.put(8, layer);
      buf.put(10, fmt(x));
      buf.put(20, fmt(y));
      buf.put(30, 0);
    }
    buf.put(0, 'SEQEND');
    buf.put(8, layer);
  }

  // Einzeiliger TEXT (Ansichts-Beschriftung) als R12-TEXT emittieren.
  function emitText(buf, layer, dx, dy, height, content) {
    buf.track(dx, dy);
    buf.track(dx + height * String(content).length * 0.7, dy + height);
    buf.put(0, 'TEXT');
    buf.put(8, layer);
    buf.put(10, fmt(dx));
    buf.put(20, fmt(dy));
    buf.put(30, 0);
    buf.put(40, fmt(height));
    buf.put(1, content);
  }

  // --- Hauptfunktion -------------------------------------------------------

  /* `umriss` ist optional: eine Funktion (balken, projektion) -> {ringe},
     die den ECHTEN Umriss eines Bauteils in einer Ansicht liefert. Der Editor
     reicht dafuer _ansichtRinge herein, das Drehungen und Ausschnitte kennt.

     Ohne sie bleibt es bei der achsparallelen Kiste — das war bisher der
     einzige Weg, und er zeichnete einen um 30 Grad gedrehten Sparren als
     liegendes Rechteck ueber die volle Dachhoehe. Wer die DXF in CAD oeffnet,
     misst darin nach; deshalb ist der ehrliche Umriss hier genauso wichtig wie
     im Ausdruck. */
  function ringeVon(umriss, b, proj) {
    try {
      var r = umriss(b, proj);
      return (r && r.ringe && r.ringe.length) ? r.ringe : null;
    } catch (e) { return null; }
  }

  /* Die Kiste aus L/B/H ist bei einem gedrehten Bauteil zu klein — sie kennt
     die Drehung nicht. Wird der echte Umriss gezeichnet, muessen auch die
     Grenzen daraus kommen. */
  function spanneAuf(bx, ringe) {
    if (ringe.oben) ringe.oben.forEach(function (ring) { ring.forEach(function (p) {
      if (p[0] < bx.x0) bx.x0 = p[0]; if (p[0] > bx.x1) bx.x1 = p[0];
      if (p[1] < bx.z0) bx.z0 = p[1]; if (p[1] > bx.z1) bx.z1 = p[1];
    }); });
    if (ringe.vorne) ringe.vorne.forEach(function (ring) { ring.forEach(function (p) {
      if (p[0] < bx.x0) bx.x0 = p[0]; if (p[0] > bx.x1) bx.x1 = p[0];
      if (p[1] < bx.y0) bx.y0 = p[1]; if (p[1] > bx.y1) bx.y1 = p[1];
    }); });
    if (ringe.seite) ringe.seite.forEach(function (ring) { ring.forEach(function (p) {
      if (p[0] < bx.z0) bx.z0 = p[0]; if (p[0] > bx.z1) bx.z1 = p[0];
      if (p[1] < bx.y0) bx.y0 = p[1]; if (p[1] > bx.y1) bx.y1 = p[1];
    }); });
  }

  function beamsToDXF(beams, umriss) {
    beams = Array.isArray(beams) ? beams : [];
    if (typeof umriss !== 'function') umriss = null;

    // 1) Balken-Boxen (Bounding-Boxes in Modellkoordinaten) berechnen.
    var boxes = beams.map(function (b) {
      b = b || {};
      var axis = (b.axis === 'x' || b.axis === 'y' || b.axis === 'z') ? b.axis : 'x';
      var L = num(b.L), B = num(b.B), H = num(b.H);
      var wX = (axis === 'x' ? L : B); // Ausdehnung entlang X
      var hY = (axis === 'y' ? L : H); // Ausdehnung entlang Y
      var dZ = (axis === 'z' ? L : B); // Ausdehnung entlang Z
      var x0 = num(b.x), y0 = num(b.y), z0 = num(b.z);
      var bx = {
        beam: b,
        x0: x0, x1: x0 + wX,
        y0: y0, y1: y0 + hY,
        z0: z0, z1: z0 + dZ
      };
      if (umriss) {
        // Dieselben drei Projektionen wie die Planansichten im Editor.
        bx.ringe = {
          oben:  ringeVon(umriss, b, function (x, y, z) { return [x, z]; }),
          vorne: ringeVon(umriss, b, function (x, y, z) { return [x, y]; }),
          seite: ringeVon(umriss, b, function (x, y, z) { return [z, y]; })
        };
        // Die Grenzen muessen zum Gezeichneten passen, sonst stimmt der Versatz
        // zwischen den Ansichten nicht mehr.
        spanneAuf(bx, bx.ringe);
      }
      return bx;
    });

    // 2) Globale Modellgrenzen ermitteln.
    var minX = Infinity, maxX = -Infinity;
    var minY = Infinity, maxY = -Infinity;
    var minZ = Infinity, maxZ = -Infinity;
    boxes.forEach(function (bx) {
      if (bx.x0 < minX) minX = bx.x0;
      if (bx.x1 > maxX) maxX = bx.x1;
      if (bx.y0 < minY) minY = bx.y0;
      if (bx.y1 > maxY) maxY = bx.y1;
      if (bx.z0 < minZ) minZ = bx.z0;
      if (bx.z1 > maxZ) maxZ = bx.z1;
    });
    if (!isFinite(minX)) { minX = maxX = minY = maxY = minZ = maxZ = 0; }

    var sizeX = maxX - minX, sizeY = maxY - minY, sizeZ = maxZ - minZ;
    var maxExtent = Math.max(sizeX, sizeY, sizeZ, 1);
    var gap = Math.max(200, 0.15 * maxExtent);   // Abstand zwischen den Ansichten
    var textH = Math.max(50, 0.05 * maxExtent);  // Beschriftungshoehe

    // 3) Ansichts-Versatz.
    //    Draufsicht liegt "oben" bei dxfY in [-maxZ, -minZ] (Z invertiert).
    //    Vorderansicht darunter: Oberkante (maxY) unter Draufsicht-Unterkante (-maxZ).
    var frontDeltaY = (-maxZ - gap) - maxY;
    //    Seitenansicht rechts neben Vorderansicht: linke Kante (minZ) rechts von maxX.
    var sideDeltaX = (maxX + gap) - minZ;

    // 4) Entities aufbauen (Extents werden dabei mitgefuehrt).
    var ent = makeBuffer();

    boxes.forEach(function (bx) {
      var layerBase = bx.beam.group || bx.beam.name || '';

      // -- Draufsicht: X -> dxfX, Z -> -dxfY (Norden oben) --
      if (bx.ringe && bx.ringe.oben) {
        bx.ringe.oben.forEach(function (ring) {
          emitPolyline(ent, 'DRAUFSICHT', ring.map(function (p) { return [p[0], -p[1]]; }));
        });
      } else {
        emitPolyline(ent, 'DRAUFSICHT', [
          [bx.x0, -bx.z0], [bx.x1, -bx.z0], [bx.x1, -bx.z1], [bx.x0, -bx.z1]
        ]);
      }

      // -- Vorderansicht: X -> dxfX, Y -> dxfY (nach unten versetzt) --
      if (bx.ringe && bx.ringe.vorne) {
        bx.ringe.vorne.forEach(function (ring) {
          emitPolyline(ent, 'VORNE', ring.map(function (p) { return [p[0], p[1] + frontDeltaY]; }));
        });
      } else {
        emitPolyline(ent, 'VORNE', [
          [bx.x0, bx.y0 + frontDeltaY], [bx.x1, bx.y0 + frontDeltaY],
          [bx.x1, bx.y1 + frontDeltaY], [bx.x0, bx.y1 + frontDeltaY]
        ]);
      }

      // -- Seitenansicht: Z -> dxfX (nach rechts versetzt), Y -> dxfY (Basis wie Vorne) --
      if (bx.ringe && bx.ringe.seite) {
        bx.ringe.seite.forEach(function (ring) {
          emitPolyline(ent, 'SEITE', ring.map(function (p) { return [p[0] + sideDeltaX, p[1] + frontDeltaY]; }));
        });
      } else {
        emitPolyline(ent, 'SEITE', [
          [bx.z0 + sideDeltaX, bx.y0 + frontDeltaY], [bx.z1 + sideDeltaX, bx.y0 + frontDeltaY],
          [bx.z1 + sideDeltaX, bx.y1 + frontDeltaY], [bx.z0 + sideDeltaX, bx.y1 + frontDeltaY]
        ]);
      }

      // layerBase aktuell ungenutzt (alle Balken pro Ansicht auf gemeinsamem Layer)
      void layerBase;
    });

    // Ansichts-Beschriftungen (auf dem jeweiligen Layer).
    if (boxes.length) {
      emitText(ent, 'DRAUFSICHT', minX, -minZ + textH * 0.6, textH, 'DRAUFSICHT');
      emitText(ent, 'VORNE', minX, maxY + frontDeltaY + textH * 0.6, textH, 'VORNE');
      emitText(ent, 'SEITE', minZ + sideDeltaX, maxY + frontDeltaY + textH * 0.6, textH, 'SEITE');
    }

    // 5) Zeichnungs-Extents fuer den HEADER.
    var exMinX = isFinite(ent.minX) ? ent.minX : 0;
    var exMinY = isFinite(ent.minY) ? ent.minY : 0;
    var exMaxX = isFinite(ent.maxX) ? ent.maxX : 0;
    var exMaxY = isFinite(ent.maxY) ? ent.maxY : 0;

    // 6) Gesamtdatei zusammensetzen.
    var out = makeBuffer();

    // -- HEADER --
    out.put(0, 'SECTION');
    out.put(2, 'HEADER');
    out.put(9, '$ACADVER'); out.put(1, 'AC1009'); // AutoCAD R12
    out.put(9, '$INSUNITS'); out.put(70, 4);       // 4 = Millimeter
    out.put(9, '$EXTMIN');
    out.put(10, fmt(exMinX)); out.put(20, fmt(exMinY)); out.put(30, 0);
    out.put(9, '$EXTMAX');
    out.put(10, fmt(exMaxX)); out.put(20, fmt(exMaxY)); out.put(30, 0);
    out.put(0, 'ENDSEC');

    // -- TABLES (Layer-Definitionen) --
    out.put(0, 'SECTION');
    out.put(2, 'TABLES');
    out.put(0, 'TABLE');
    out.put(2, 'LAYER');
    out.put(70, 3); // Anzahl Layer
    // Layer 1: DRAUFSICHT (blau = 5)
    out.put(0, 'LAYER'); out.put(2, 'DRAUFSICHT'); out.put(70, 0); out.put(62, 5); out.put(6, 'CONTINUOUS');
    // Layer 2: VORNE (gruen = 3)
    out.put(0, 'LAYER'); out.put(2, 'VORNE'); out.put(70, 0); out.put(62, 3); out.put(6, 'CONTINUOUS');
    // Layer 3: SEITE (rot = 1)
    out.put(0, 'LAYER'); out.put(2, 'SEITE'); out.put(70, 0); out.put(62, 1); out.put(6, 'CONTINUOUS');
    out.put(0, 'ENDTAB');
    out.put(0, 'ENDSEC');

    // -- ENTITIES --
    out.put(0, 'SECTION');
    out.put(2, 'ENTITIES');
    // vorbereitete Entity-Zeilen einfuegen
    Array.prototype.push.apply(out.lines, ent.lines);
    out.put(0, 'ENDSEC');

    // -- EOF --
    out.put(0, 'EOF');

    return out.text() + CR;
  }

  // --- Export --------------------------------------------------------------
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = beamsToDXF;
    module.exports.beamsToDXF = beamsToDXF;
  }
  if (global && typeof global === 'object') {
    global.beamsToDXF = beamsToDXF;
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));

/* ===== panel2d.js ===== */
/*
 * panel2d.js — 2D-Plattenzuschnitt-Optimierer (Guillotine Bin Packing)
 * fuer holzbau3d.app
 *
 * Ordnet rechteckige Zuschnittteile (Breite x Hoehe, mm) moeglichst
 * effizient auf Standard-Platten (z.B. 2500x1250 mm) an und minimiert
 * Plattenanzahl und Verschnitt.
 *
 * Eigenstaendig, keine Imports, IIFE-gekapselt.
 * Exponiert: window.pack2D, window.pack2DToSVG (+ module.exports fuer Node).
 */
(function (root) {
  'use strict';

  // ---------------------------------------------------------------------------
  // Hilfsfunktionen
  // ---------------------------------------------------------------------------

  function clampNum(v, def) {
    return (typeof v === 'number' && isFinite(v)) ? v : def;
  }

  function normalizeOpts(opts) {
    opts = opts || {};
    return {
      panelW: clampNum(opts.panelW, 2500),
      panelH: clampNum(opts.panelH, 1250),
      kerf: clampNum(opts.kerf, 4),
      allowRotate: opts.allowRotate !== false, // default true
      margin: clampNum(opts.margin, 0)
    };
  }

  // ---------------------------------------------------------------------------
  // Guillotine-Packing
  //
  // Je Platte halten wir eine Liste freier Rest-Rechtecke (freeRects).
  // Zu Beginn ist das der nutzbare Bereich (Platte abzueglich margin).
  //
  // Beim Platzieren eines Teils belegt es effektiv (w+kerf) x (h+kerf) im
  // Rest-Rechteck (Saegeschnitt zwischen Nachbarn), die tatsaechlichen
  // Teilmasse bleiben aber w x h. Wir suchen nach "Best Area Fit" (kleinster
  // uebrigbleibender Flaechenrest) ueber alle freien Rechtecke und beide
  // Orientierungen. Nach der Platzierung wird das genutzte Rest-Rechteck per
  // Guillotine-Split ("Shorter Leftover Axis Split", SLAS) in zwei neue
  // Rest-Rechtecke zerlegt.
  // ---------------------------------------------------------------------------

  function newPanel(usableW, usableH, margin, panelW, panelH) {
    return {
      w: panelW,
      h: panelH,
      placements: [],
      // freie Rechtecke in absoluten Plattenkoordinaten
      freeRects: [{ x: margin, y: margin, w: usableW, h: usableH }]
    };
  }

  // Versucht ein Teil (in gegebener Orientierung ow x oh, inkl. kerf-Bedarf)
  // in die freeRects einer Platte einzupassen. Gibt den besten Treffer zurueck
  // oder null.
  function findBestFit(panel, needW, needH) {
    var best = null;
    var bestScore = Infinity;
    for (var i = 0; i < panel.freeRects.length; i++) {
      var fr = panel.freeRects[i];
      if (needW <= fr.w + 1e-9 && needH <= fr.h + 1e-9) {
        // Best Area Fit: kleinster Flaechenrest, Tie-Break kuerzere Restseite
        var areaFit = fr.w * fr.h - needW * needH;
        var leftoverH = Math.abs(fr.w - needW);
        var leftoverV = Math.abs(fr.h - needH);
        var shortSide = Math.min(leftoverH, leftoverV);
        var score = areaFit + shortSide * 1e-6;
        if (score < bestScore) {
          bestScore = score;
          best = { index: i, rect: fr };
        }
      }
    }
    return best;
  }

  // Guillotine-Split nach SLAS (Shorter Leftover Axis Split).
  // Das freie Rechteck fr wird durch ein platziertes (needW x needH inkl. kerf)
  // an seiner oberen-linken Ecke belegt; die zwei Reststuecke werden erzeugt.
  function splitFreeRect(fr, needW, needH) {
    var leftoverHoriz = fr.w - needW; // Rest rechts
    var leftoverVert = fr.h - needH;  // Rest unten
    var result = [];

    // SLAS: entlang der kuerzeren Rest-Achse schneiden.
    // Wenn leftoverHoriz < leftoverVert -> horizontaler Schnitt bevorzugt
    // (rechtes Reststueck ist schmal, unteres Reststueck volle Breite).
    var splitHorizontal = leftoverHoriz <= leftoverVert;

    var right, bottom;
    if (splitHorizontal) {
      // Rechts: schmal, nur so hoch wie das Teil
      right = { x: fr.x + needW, y: fr.y, w: leftoverHoriz, h: needH };
      // Unten: volle Breite des freien Rechtecks
      bottom = { x: fr.x, y: fr.y + needH, w: fr.w, h: leftoverVert };
    } else {
      // Rechts: volle Hoehe des freien Rechtecks
      right = { x: fr.x + needW, y: fr.y, w: leftoverHoriz, h: fr.h };
      // Unten: nur so breit wie das Teil
      bottom = { x: fr.x, y: fr.y + needH, w: needW, h: leftoverVert };
    }

    if (right.w > 1e-9 && right.h > 1e-9) result.push(right);
    if (bottom.w > 1e-9 && bottom.h > 1e-9) result.push(bottom);
    return result;
  }

  // Entfernt freie Rechtecke, die vollstaendig in einem anderen enthalten sind.
  function pruneFreeRects(freeRects) {
    for (var i = 0; i < freeRects.length; i++) {
      for (var j = i + 1; j < freeRects.length; j++) {
        if (isContained(freeRects[i], freeRects[j])) {
          freeRects.splice(i, 1);
          i--;
          break;
        }
        if (isContained(freeRects[j], freeRects[i])) {
          freeRects.splice(j, 1);
          j--;
        }
      }
    }
  }

  function isContained(a, b) {
    // ist a vollstaendig in b enthalten?
    return a.x >= b.x - 1e-9 && a.y >= b.y - 1e-9 &&
           a.x + a.w <= b.x + b.w + 1e-9 &&
           a.y + a.h <= b.y + b.h + 1e-9;
  }

  // ---------------------------------------------------------------------------
  // pack2D — Hauptfunktion
  // ---------------------------------------------------------------------------
  function pack2D(parts, opts) {
    var o = normalizeOpts(opts);
    var panelW = o.panelW, panelH = o.panelH;
    var margin = o.margin, kerf = o.kerf, allowRotate = o.allowRotate;

    var usableW = panelW - 2 * margin;
    var usableH = panelH - 2 * margin;

    // Eingabe kopieren + validieren
    var items = [];
    var unplaced = [];
    var idCounter = 0;

    (parts || []).forEach(function (p) {
      var w = clampNum(p.w, NaN);
      var h = clampNum(p.h, NaN);
      var id = (p.id !== undefined && p.id !== null) ? p.id : ('p' + (idCounter++));
      var label = (p.label !== undefined && p.label !== null) ? p.label : String(id);
      var item = { w: w, h: h, id: id, label: label };

      if (!isFinite(w) || !isFinite(h) || w <= 0 || h <= 0) {
        // ungueltige Masse -> nicht platzierbar
        unplaced.push(item);
        return;
      }
      // Passt das Teil ueberhaupt (in irgendeiner Orientierung) auf eine leere Platte?
      var fitsNormal = (w <= usableW + 1e-9 && h <= usableH + 1e-9);
      var fitsRotated = allowRotate && (h <= usableW + 1e-9 && w <= usableH + 1e-9);
      if (!fitsNormal && !fitsRotated) {
        unplaced.push(item);
        return;
      }
      items.push(item);
    });

    // FFD: absteigend nach Flaeche sortieren, Tie-Break max(w,h).
    // Deterministisch (stabiler Vergleich, keine Zufallswerte).
    items.sort(function (a, b) {
      var areaA = a.w * a.h, areaB = b.w * b.h;
      if (areaB !== areaA) return areaB - areaA;
      var maxA = Math.max(a.w, a.h), maxB = Math.max(b.w, b.h);
      if (maxB !== maxA) return maxB - maxA;
      // stabiler finaler Tie-Break ueber id-String
      var sa = String(a.id), sb = String(b.id);
      return sa < sb ? -1 : (sa > sb ? 1 : 0);
    });

    var panels = [];

    for (var k = 0; k < items.length; k++) {
      var it = items[k];
      var placed = false;

      // Versuche in bestehenden Platten, dann neue Platte.
      for (var pi = 0; pi <= panels.length && !placed; pi++) {
        var panel;
        if (pi === panels.length) {
          panel = newPanel(usableW, usableH, margin, panelW, panelH);
        } else {
          panel = panels[pi];
        }

        // Kerf-Bedarf: das Teil belegt (w+kerf) x (h+kerf) im Rest-Rechteck,
        // damit ein Saegeschnitt zu den Nachbarn passt. Am rechten/unteren Rand
        // wird durch den margin/Plattenrand ohnehin nicht weiter geschnitten,
        // aber wir modellieren konservativ konstant mit kerf.
        var placement = tryPlaceInPanel(panel, it, kerf, allowRotate);
        if (placement) {
          panel.placements.push(placement);
          if (pi === panels.length) panels.push(panel);
          placed = true;
        }
      }

      if (!placed) {
        // Sollte kaum vorkommen (Teil passt auf leere Platte, wurde oben geprueft),
        // aber zur Sicherheit:
        unplaced.push({ w: it.w, h: it.h, id: it.id, label: it.label });
      }
    }

    // Statistik
    var partArea = 0;
    panels.forEach(function (pn) {
      pn.placements.forEach(function (pl) { partArea += pl.w * pl.h; });
    });
    var panelArea = panels.length * panelW * panelH;
    var wastePct = panelArea > 0 ? ((panelArea - partArea) / panelArea) * 100 : 0;

    return {
      panels: panels.map(function (pn) {
        return { w: pn.w, h: pn.h, placements: pn.placements };
      }),
      unplaced: unplaced,
      stats: {
        panelCount: panels.length,
        partArea: partArea,
        panelArea: panelArea,
        wastePct: Math.round(wastePct * 100) / 100
      }
    };
  }

  // Versucht ein Teil in eine konkrete Platte zu platzieren.
  // Probiert beide Orientierungen (falls erlaubt), waehlt Best Area Fit.
  // Gibt placement { x, y, w, h, rotated, id, label } zurueck oder null.
  function tryPlaceInPanel(panel, it, kerf, allowRotate) {
    var candidates = [];
    // Orientierung 0: normal
    candidates.push({ w: it.w, h: it.h, rotated: false });
    // Orientierung 1: gedreht
    if (allowRotate && (it.w !== it.h)) {
      candidates.push({ w: it.h, h: it.w, rotated: true });
    }

    var best = null;
    var bestScore = Infinity;
    var bestCand = null;

    for (var c = 0; c < candidates.length; c++) {
      var cand = candidates[c];
      var needW = cand.w + kerf;
      var needH = cand.h + kerf;
      var fit = findBestFit(panel, needW, needH);
      if (fit) {
        var fr = fit.rect;
        var areaFit = fr.w * fr.h - needW * needH;
        var leftoverH = Math.abs(fr.w - needW);
        var leftoverV = Math.abs(fr.h - needH);
        var score = areaFit + Math.min(leftoverH, leftoverV) * 1e-6;
        if (score < bestScore) {
          bestScore = score;
          best = fit;
          bestCand = cand;
        }
      }
    }

    if (!best) return null;

    var frUsed = best.rect;
    var nW = bestCand.w + kerf;
    var nH = bestCand.h + kerf;

    // freies Rechteck entfernen und durch Splits ersetzen
    panel.freeRects.splice(best.index, 1);
    var splits = splitFreeRect(frUsed, nW, nH);
    for (var s = 0; s < splits.length; s++) {
      panel.freeRects.push(splits[s]);
    }
    pruneFreeRects(panel.freeRects);

    // tatsaechliche Teilmasse (ohne kerf) an der oberen-linken Ecke
    return {
      x: frUsed.x,
      y: frUsed.y,
      w: bestCand.w,
      h: bestCand.h,
      rotated: bestCand.rotated,
      id: it.id,
      label: it.label
    };
  }

  // ---------------------------------------------------------------------------
  // pack2DToSVG — rendert das Ergebnis als SVG-String
  // ---------------------------------------------------------------------------
  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function fmt(n) {
    return Math.round(n * 100) / 100;
  }

  function pack2DToSVG(result, opts) {
    var o = normalizeOpts(opts);
    var panelW = o.panelW, panelH = o.panelH;

    var panels = (result && result.panels) || [];
    var gap = Math.max(panelW, panelH) * 0.04; // Abstand zwischen Platten
    var pad = gap;
    var labelH = Math.max(panelH * 0.08, 40); // Platz fuer Plattenueberschrift

    // Gesamtgroesse (viewBox in mm-Koordinaten)
    var totalW = panelW + 2 * pad;
    var totalH = pad;
    for (var i = 0; i < panels.length; i++) {
      totalH += labelH + panels[i].h + gap;
    }
    if (panels.length === 0) totalH += labelH + gap;
    totalH += pad;

    var fontMain = Math.max(panelH * 0.05, 28);
    var fontPart = Math.max(panelH * 0.03, 18);

    var svg = [];
    svg.push(
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' +
      fmt(totalW) + ' ' + fmt(totalH) +
      '" width="100%" preserveAspectRatio="xMidYMin meet" ' +
      'font-family="Arial, Helvetica, sans-serif">'
    );
    // Hintergrund
    svg.push('<rect x="0" y="0" width="' + fmt(totalW) + '" height="' +
      fmt(totalH) + '" fill="#ffffff"/>');

    var cursorY = pad;
    for (var p = 0; p < panels.length; p++) {
      var panel = panels[p];
      var ox = pad;
      var oy = cursorY + labelH;

      var used = 0;
      for (var q = 0; q < panel.placements.length; q++) {
        used += panel.placements[q].w * panel.placements[q].h;
      }
      var panelAreaThis = panel.w * panel.h;
      var wp = panelAreaThis > 0 ? ((panelAreaThis - used) / panelAreaThis) * 100 : 0;

      // Ueberschrift
      svg.push('<text x="' + fmt(ox) + '" y="' + fmt(cursorY + labelH * 0.7) +
        '" font-size="' + fmt(fontMain) + '" font-weight="bold" fill="#333333">' +
        'Platte ' + (p + 1) + ' (' + fmt(panel.w) + ' x ' + fmt(panel.h) +
        ' mm) - Verschnitt ' + fmt(Math.round(wp * 10) / 10) + '%' +
        '</text>');

      // Plattenflaeche (Verschnitt hell)
      svg.push('<rect x="' + fmt(ox) + '" y="' + fmt(oy) + '" width="' +
        fmt(panel.w) + '" height="' + fmt(panel.h) +
        '" fill="#f0f0f0" stroke="#999999" stroke-width="' +
        fmt(Math.max(panelW * 0.0015, 2)) + '"/>');

      // Teile
      for (var r = 0; r < panel.placements.length; r++) {
        var pl = panel.placements[r];
        var x = ox + pl.x;
        var y = oy + pl.y;
        svg.push('<rect x="' + fmt(x) + '" y="' + fmt(y) + '" width="' +
          fmt(pl.w) + '" height="' + fmt(pl.h) +
          '" fill="#c8a06e" stroke="#8a6a3e" stroke-width="' +
          fmt(Math.max(panelW * 0.0008, 1)) + '"/>');

        // Label + Masse (zentriert), nur wenn genug Platz
        var cx = x + pl.w / 2;
        var cy = y + pl.h / 2;
        var labelText = esc(pl.label);
        var dimText = fmt(pl.w) + ' x ' + fmt(pl.h) + (pl.rotated ? ' ↻' : '');
        var minSide = Math.min(pl.w, pl.h);
        if (minSide > fontPart * 1.5) {
          svg.push('<text x="' + fmt(cx) + '" y="' + fmt(cy - fontPart * 0.2) +
            '" font-size="' + fmt(fontPart) + '" fill="#3a2a12" ' +
            'text-anchor="middle" dominant-baseline="middle">' + labelText + '</text>');
          svg.push('<text x="' + fmt(cx) + '" y="' + fmt(cy + fontPart * 1.0) +
            '" font-size="' + fmt(fontPart * 0.85) + '" fill="#5a4526" ' +
            'text-anchor="middle" dominant-baseline="middle">' + dimText + '</text>');
        }
      }

      cursorY = oy + panel.h + gap;
    }

    if (panels.length === 0) {
      svg.push('<text x="' + fmt(pad) + '" y="' + fmt(pad + labelH * 0.7) +
        '" font-size="' + fmt(fontMain) + '" fill="#999999">Keine Teile platziert</text>');
    }

    svg.push('</svg>');
    return svg.join('');
  }


  // ---------------------------------------------------------------------------
  // Beplankung: eine rechteckige Flaeche in Plattenformate aufteilen
  // ---------------------------------------------------------------------------
  /*
   * planBeplankung — reine Zahlenfunktion, absichtlich ohne three.js und ohne DOM,
   * damit die Stossregel in Node pruefbar ist.
   *
   * Der Punkt, an dem so eine Funktion ueblicherweise unbrauchbar wird: sie
   * teilt stur das Plattenformat ab und legt die Fugen dorthin, wo gerade Platz
   * ist. Im Holzbau muss ein Plattenstoss aber auf einem TRAEGER liegen
   * (Staender, Sparren, Riegel) — sonst haengt die Kante frei und die Beplankung
   * ist nicht befestigbar. Darum bekommt die Funktion die Traegerachsen und legt
   * jede Fuge auf die naechstgelegene Achse, die noch in Reichweite liegt.
   *
   * WICHTIG bei der Reichweite: die Fuge wird NICHT abgezogen
   * (max = p + format, nicht p + format - fuge). Sonst faellt genau der Traeger
   * aus dem Fenster, der exakt auf dem Plattenmass sitzt — und das ist der
   * Regelfall: das Staenderraster 625 wird ja gewaehlt, DAMIT die 1250er Platte
   * auf einem Staender stoesst.
   *
   * opt = {
   *   breite, hoehe   : Flaechenmasse in mm
   *   format          : [w, h] Plattenformat in mm
   *   fuge            : Dehnungsfuge zwischen den Platten in mm (Standard 0)
   *   traegerU        : Achsen quer zur Breite (mm, relativ zur Flaechenkante)
   *   traegerV        : Achsen quer zur Hoehe
   *   minRest         : schmalstes zulaessiges Reststueck (Standard 100)
   * }
   * Rueckgabe { platten: [{u, v, w, h, rand}], hinweise: [..] }
   *   u,v = linke untere Ecke in der Flaeche; rand = angeschnittenes Stueck.
   */
  function _kanten(laenge, format, fuge, traeger, minRest) {
    var kanten = [0], p = 0, wache = 0;
    traeger = (traeger || []).slice().sort(function (a, b) { return a - b; });
    while (p < laenge - 0.5 && wache++ < 500) {
      var max = p + format;                    // Fuge NICHT abziehen, s.o.
      if (max >= laenge - 0.5) { kanten.push(laenge); break; }
      // Groesste Traegerachse, die noch in Reichweite liegt und echt weiterfuehrt.
      var ziel = null;
      for (var i = 0; i < traeger.length; i++) {
        var t = traeger[i];
        if (t > p + 1 && t <= max + 0.001) ziel = t;
      }
      var naechste = (ziel === null) ? max : ziel;
      // Reststueck zu schmal? Dann lieber die vorletzte Fuge zurueckziehen, aber
      // NUR wenn dafuer eine andere Traegerachse zur Verfuegung steht — sonst
      // bliebe der Stoss in der Luft. Ist keine da, bleibt der Splitter stehen
      // und wird als Hinweis gemeldet.
      if (laenge - naechste > 0.5 && laenge - naechste < minRest) {
        var ersatz = null;
        for (var j = 0; j < traeger.length; j++) {
          var t2 = traeger[j];
          if (t2 > p + minRest && t2 < naechste - 0.5 && laenge - t2 >= minRest) ersatz = t2;
        }
        if (ersatz !== null) naechste = ersatz;
      }
      kanten.push(naechste);
      p = naechste;
    }
    if (kanten[kanten.length - 1] < laenge - 0.5) kanten.push(laenge);
    return kanten;
  }

  function planBeplankung(opt) {
    opt = opt || {};
    var breite = Math.max(1, opt.breite || 0);
    var hoehe = Math.max(1, opt.hoehe || 0);
    var fmt = opt.format || [2500, 1250];
    var fuge = Math.max(0, opt.fuge || 0);
    var minRest = opt.minRest == null ? 100 : opt.minRest;
    var hinweise = [];

    // Ausrichtung: die Variante waehlen, die WENIGER Platten braucht. Bei
    // Gleichstand die, die in der Hoehe ohne Quernaht auskommt — eine
    // waagerechte Fuge ohne Riegel dahinter ist die haeufigste Fehlerquelle.
    function zaehle(fw, fh) {
      var ku = _kanten(breite, fw, fuge, opt.traegerU, minRest);
      var kv = _kanten(hoehe, fh, fuge, opt.traegerV, minRest);
      return { ku: ku, kv: kv, n: (ku.length - 1) * (kv.length - 1), reihen: kv.length - 1 };
    }
    var a = zaehle(fmt[0], fmt[1]);
    var b = zaehle(fmt[1], fmt[0]);
    var wahl = (b.n < a.n || (b.n === a.n && b.reihen < a.reihen)) ? b : a;

    var platten = [];
    for (var iv = 0; iv < wahl.kv.length - 1; iv++) {
      for (var iu = 0; iu < wahl.ku.length - 1; iu++) {
        var u0 = wahl.ku[iu], u1 = wahl.ku[iu + 1];
        var v0 = wahl.kv[iv], v1 = wahl.kv[iv + 1];
        // Die Fuge geht von der PLATTE ab, nicht von der Reichweite.
        var w = u1 - u0 - (u1 < breite - 0.5 ? fuge : 0);
        var h = v1 - v0 - (v1 < hoehe - 0.5 ? fuge : 0);
        if (w < 1 || h < 1) continue;
        var vollU = Math.abs((u1 - u0) - Math.max(fmt[0], fmt[1])) < 0.5 ||
                    Math.abs((u1 - u0) - Math.min(fmt[0], fmt[1])) < 0.5;
        var vollV = Math.abs((v1 - v0) - Math.max(fmt[0], fmt[1])) < 0.5 ||
                    Math.abs((v1 - v0) - Math.min(fmt[0], fmt[1])) < 0.5;
        platten.push({ u: u0, v: v0, w: w, h: h, rand: !(vollU && vollV) });
      }
    }

    // Ehrliche Rueckmeldung statt stiller Naeherung.
    var ohneTraeger = 0;
    for (var k = 1; k < wahl.ku.length - 1; k++) {
      var trifft = (opt.traegerU || []).some(function (t) { return Math.abs(t - wahl.ku[k]) < 1; });
      if (!trifft) ohneTraeger++;
    }
    if (ohneTraeger) hinweise.push(ohneTraeger + ' senkrechte Fuge(n) liegen nicht auf einem Träger');
    var quer = wahl.kv.length - 2;
    if (quer > 0) {
      var querOhne = 0;
      for (var m = 1; m < wahl.kv.length - 1; m++) {
        var t3 = (opt.traegerV || []).some(function (t) { return Math.abs(t - wahl.kv[m]) < 1; });
        if (!t3) querOhne++;
      }
      if (querOhne) hinweise.push(querOhne + ' waagerechte Fuge(n) ohne Riegel dahinter');
    }
    var schmal = platten.filter(function (p2) { return p2.w < minRest || p2.h < minRest; }).length;
    if (schmal) hinweise.push(schmal + ' sehr schmale(s) Randstück(e)');

    return { platten: platten, hinweise: hinweise };
  }

  // ---------------------------------------------------------------------------
  // Export
  // ---------------------------------------------------------------------------
  var api = { pack2D: pack2D, pack2DToSVG: pack2DToSVG, planBeplankung: planBeplankung };

  if (typeof root !== 'undefined' && root) {
    root.pack2D = pack2D;
    root.pack2DToSVG = pack2DToSVG;
    root.planBeplankung = planBeplankung;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }

})(typeof window !== 'undefined' ? window : this);
