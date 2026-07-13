/* HolzBau 3D — Tools: Spannweiten-Tabelle, parametrische Vorlagen, DXF-Export. Auto-generiert. */
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
 *     group, phase }
 *
 * Konvention (identisch zum 3D-Editor):
 *   - Ursprung (x,y,z) = MINIMALE Ecke ("Punkt 0"), Millimeter, y=0 = Boden.
 *   - Ausdehnung in +Richtung ab (x,y,z):
 *        Breite entlang X = (axis==='x' ? L : B)
 *        Hoehe  entlang Y = (axis==='y' ? L : H)
 *        Tiefe  entlang Z = (axis==='z' ? L : B)
 *   - axis: Achse entlang der die Laenge L laeuft.
 *        'x'/'z' = liegend/horizontal, 'y' = stehend (Pfosten).
 *   - rx/ry/rz: Drehung in Grad um die jeweilige Achse, angewandt um den
 *        Balken-Mittelpunkt (fuer Dachneigungen der Sparren).
 *   - woodType nur aus:
 *        'Fichte','Kiefer','Lärche','Eiche','Douglasie','Brettschichtholz (BSH)'
 * ==========================================================================*/

(function (root) {
  'use strict';

  var DEG = 180 / Math.PI;

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
      x:        Math.round(o.x || 0),
      y:        Math.round(o.y || 0),
      z:        Math.round(o.z || 0),
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

  // ==========================================================================
  // 1) CARPORT  — Pultdach, Neigung quer ueber die Breite (X)
  //    Tief low bei x=0, hoch bei x=width. Sparren liegen quer (axis 'x').
  // ==========================================================================
  function genCarport(p) {
    p = p || {};
    var width  = num(p.width, 3000);
    var depth  = num(p.depth, 5000);
    var height = num(p.height, 2200);
    var postSec = num(p.postSec, 120);
    var pitch  = num(p.pitch, 5);

    var beams = [];
    var pfetteB = postSec, pfetteH = 160;
    var sparB = 80, sparH = 160;
    var rise = Math.round(width * Math.tan(pitch * Math.PI / 180));

    // --- Pfosten: Raster entlang der Tiefe (max ~2,5 m) ---
    var nSeg = Math.max(1, Math.ceil(depth / 2500));
    for (var r = 0; r <= nSeg; r++) {
      var zRow = Math.round((r * depth) / nSeg);
      if (r === 0) zRow = 0;
      else if (r === nSeg) zRow = depth - postSec;         // Endreihe einruecken
      else zRow = Math.round(zRow - postSec / 2);          // Mittelreihe zentrieren
      // niedrige Traufseite (x=0)
      beams.push(mk({ name: 'Pfosten', woodType: 'Douglasie',
        L: height, B: postSec, H: postSec, axis: 'y',
        x: 0, y: 0, z: zRow, group: 'Pfosten' }));
      // hohe Traufseite (x=width)
      beams.push(mk({ name: 'Pfosten', woodType: 'Douglasie',
        L: height + rise, B: postSec, H: postSec, axis: 'y',
        x: width - postSec, y: 0, z: zRow, group: 'Pfosten' }));
    }

    // --- Laengs-Pfetten (auf den Pfosten, entlang Z) ---
    beams.push(mk({ name: 'Pfette niedrig', woodType: 'Brettschichtholz (BSH)',
      L: depth, B: pfetteB, H: pfetteH, axis: 'z',
      x: 0, y: height, z: 0, group: 'Pfetten' }));
    beams.push(mk({ name: 'Pfette hoch', woodType: 'Brettschichtholz (BSH)',
      L: depth, B: pfetteB, H: pfetteH, axis: 'z',
      x: width - pfetteB, y: height + rise, z: 0, group: 'Pfetten' }));

    // --- Sparren quer (axis 'x'), Abstand ~70 cm, liegen auf beiden Pfetten ---
    var nSp = Math.max(2, Math.round(depth / 700) + 1);
    var spY = height + pfetteH + rise / 2;   // Unterkante beider Enden auf Pfettenoberkante
    for (var i = 0; i < nSp; i++) {
      var zS = Math.round((i * (depth - sparB)) / (nSp - 1));
      beams.push(mk({ name: 'Sparren', woodType: 'Fichte',
        L: width, B: sparB, H: sparH, axis: 'x',
        x: 0, y: spY, z: zS, rz: pitch, group: 'Sparren' }));
    }

    return beams;
  }

  // ==========================================================================
  // 2) PERGOLA — 4 Eckpfosten, umlaufender Rahmen oben, Querlatten (~40 cm)
  // ==========================================================================
  function genPergola(p) {
    p = p || {};
    var width  = num(p.width, 3000);
    var depth  = num(p.depth, 4000);
    var height = num(p.height, 2400);
    var postSec = num(p.postSec, 120);

    var beams = [];
    var frB = postSec, frH = 160;   // Rahmenquerschnitt
    var latB = 60, latH = 100;      // Querlatten

    // --- 4 Eckpfosten ---
    var xs = [0, width - postSec];
    var zs = [0, depth - postSec];
    for (var a = 0; a < xs.length; a++) {
      for (var b = 0; b < zs.length; b++) {
        beams.push(mk({ name: 'Eckpfosten', woodType: 'Lärche',
          L: height, B: postSec, H: postSec, axis: 'y',
          x: xs[a], y: 0, z: zs[b], group: 'Pfosten' }));
      }
    }

    // --- Umlaufender Rahmen oben ---
    // Laengsbalken (entlang Z) direkt auf den Pfosten
    beams.push(mk({ name: 'Rahmen längs L', woodType: 'Lärche',
      L: depth, B: frB, H: frH, axis: 'z',
      x: 0, y: height, z: 0, group: 'Rahmen' }));
    beams.push(mk({ name: 'Rahmen längs R', woodType: 'Lärche',
      L: depth, B: frB, H: frH, axis: 'z',
      x: width - frB, y: height, z: 0, group: 'Rahmen' }));
    // Querbalken (entlang X), zwischen die Laengsbalken eingesetzt -> keine Eck-Ueberlappung
    var inX = frB, inL = Math.max(1, width - 2 * frB);
    beams.push(mk({ name: 'Rahmen quer V', woodType: 'Lärche',
      L: inL, B: frB, H: frH, axis: 'x',
      x: inX, y: height, z: 0, group: 'Rahmen' }));
    beams.push(mk({ name: 'Rahmen quer H', woodType: 'Lärche',
      L: inL, B: frB, H: frH, axis: 'x',
      x: inX, y: height, z: depth - frB, group: 'Rahmen' }));

    // --- Querlatten oben quer (axis 'x'), Abstand ~40 cm ---
    var nl = Math.max(2, Math.round(depth / 400) + 1);
    var ly = height + frH;
    for (var i = 0; i < nl; i++) {
      var zL = Math.round((i * (depth - latB)) / (nl - 1));
      beams.push(mk({ name: 'Querlatte', woodType: 'Lärche',
        L: width, B: latB, H: latH, axis: 'x',
        x: 0, y: ly, z: zL, group: 'Sparren' }));
    }

    return beams;
  }

  // ==========================================================================
  // 3) GARTENHAUS — Staenderbauweise, leichtes Pultdach (Gefaelle ueber Tiefe)
  //    Bodenschwellen-Rahmen, Eck-/Zwischenpfosten, Raehm, Pultdach-Sparren.
  // ==========================================================================
  function genGartenhaus(p) {
    p = p || {};
    var width  = num(p.width, 3000);
    var depth  = num(p.depth, 2500);
    var wallH  = num(p.wallH, 2200);
    var postSec = num(p.postSec, 100);

    var beams = [];
    var sillB = postSec, sillH = 60;   // Schwelle (flach)
    var rahmB = postSec, rahmH = 60;   // Raehm (flach)
    var spB = 80, spH = 140;           // Sparren
    var rise = Math.round(depth * Math.tan(10 * Math.PI / 180)); // ~10° Gefaelle
    var angDeg = Math.atan2(rise, depth) * DEG;

    // --- Bodenschwellen-Rahmen (y=0) ---
    beams.push(mk({ name: 'Schwelle V', L: width, B: sillB, H: sillH, axis: 'x',
      x: 0, y: 0, z: 0, group: 'Rahmen' }));
    beams.push(mk({ name: 'Schwelle H', L: width, B: sillB, H: sillH, axis: 'x',
      x: 0, y: 0, z: depth - sillB, group: 'Rahmen' }));
    beams.push(mk({ name: 'Schwelle L', L: Math.max(1, depth - 2 * sillB),
      B: sillB, H: sillH, axis: 'z', x: 0, y: 0, z: sillB, group: 'Rahmen' }));
    beams.push(mk({ name: 'Schwelle R', L: Math.max(1, depth - 2 * sillB),
      B: sillB, H: sillH, axis: 'z', x: width - sillB, y: 0, z: sillB, group: 'Rahmen' }));

    // --- Staender (auf der Schwelle stehend, y=sillH) ---
    // Vorderwand (z=0) niedrig, Rueckwand (z=depth) hoch -> Pultgefaelle.
    var xs = spread(width, postSec, 800);
    var frontL = wallH - sillH;
    var backL  = wallH + rise - sillH;
    for (var i = 0; i < xs.length; i++) {
      beams.push(mk({ name: 'Ständer V', L: frontL, B: postSec, H: postSec, axis: 'y',
        x: xs[i], y: sillH, z: 0, group: 'Pfosten' }));
      beams.push(mk({ name: 'Ständer H', L: backL, B: postSec, H: postSec, axis: 'y',
        x: xs[i], y: sillH, z: depth - postSec, group: 'Pfosten' }));
    }
    // Seitenwaende: Zwischenstaender (ohne Ecken), Hoehe linear interpoliert
    var zs = spread(depth, postSec, 800);
    for (var j = 1; j < zs.length - 1; j++) {
      var pz = zs[j];
      var frac = pz / Math.max(1, depth - postSec);
      var h = Math.round(frontL + rise * frac);
      beams.push(mk({ name: 'Ständer L', L: h, B: postSec, H: postSec, axis: 'y',
        x: 0, y: sillH, z: pz, group: 'Pfosten' }));
      beams.push(mk({ name: 'Ständer R', L: h, B: postSec, H: postSec, axis: 'y',
        x: width - postSec, y: sillH, z: pz, group: 'Pfosten' }));
    }

    // --- Raehm (oberer Rahmen) ---
    // Vorne/hinten horizontal, Seiten geneigt (folgen dem Pultgefaelle).
    beams.push(mk({ name: 'Rähm V', L: width, B: rahmB, H: rahmH, axis: 'x',
      x: 0, y: wallH, z: 0, group: 'Rahmen' }));
    beams.push(mk({ name: 'Rähm H', L: width, B: rahmB, H: rahmH, axis: 'x',
      x: 0, y: wallH + rise, z: depth - rahmB, group: 'Rahmen' }));
    var sideY = Math.round(wallH + rise / 2 - rahmH / 2);
    beams.push(mk({ name: 'Rähm L', L: depth, B: rahmB, H: rahmH, axis: 'z',
      x: 0, y: sideY, z: 0, rx: -angDeg, group: 'Rahmen' }));
    beams.push(mk({ name: 'Rähm R', L: depth, B: rahmB, H: rahmH, axis: 'z',
      x: width - rahmB, y: sideY, z: 0, rx: -angDeg, group: 'Rahmen' }));

    // --- Pultdach-Sparren (laengs, axis 'z'), Abstand ~70 cm ---
    var nSp = Math.max(2, Math.round(width / 700) + 1);
    var spY = wallH + rahmH + rise / 2;   // Unterkante der Enden auf Raehm-Oberkante
    for (var k = 0; k < nSp; k++) {
      var xS = Math.round((k * (width - spB)) / (nSp - 1));
      beams.push(mk({ name: 'Sparren', woodType: 'Fichte',
        L: depth, B: spB, H: spH, axis: 'z',
        x: xS, y: spY, z: 0, rx: -angDeg, group: 'Sparren' }));
    }

    return beams;
  }

  // ==========================================================================
  // 4) TERRASSE — Anlehn-Pultdach an Hauswand
  //    Wandpfette hoch (wallH), Frontpfosten (frontH), Sparren mit Gefaelle
  //    von der Wand (z=0, hoch) zur Front (z=depth, niedrig).
  // ==========================================================================
  function genTerrasse(p) {
    p = p || {};
    var width  = num(p.width, 4000);
    var depth  = num(p.depth, 3000);
    var wallH  = num(p.wallH, 2600);
    var frontH = num(p.frontH, 2200);
    var postSec = num(p.postSec, 120);

    var beams = [];
    var pfB = postSec, pfH = 160;      // Pfetten
    var spB = 80, spH = 160;           // Sparren
    var rise = Math.max(0, wallH - frontH);
    var angDeg = Math.atan2(rise, depth) * DEG;

    // --- Wandanschluss-Pfette (hoch, an der Wand z=0, entlang X) ---
    beams.push(mk({ name: 'Wandpfette', woodType: 'Brettschichtholz (BSH)',
      L: width, B: pfB, H: pfH, axis: 'x',
      x: 0, y: wallH, z: 0, group: 'Pfetten' }));

    // --- Frontpfosten (2-3) ---
    var nPosts = Math.max(2, Math.round(width / 2000) + 1);
    var xs = [];
    for (var i = 0; i < nPosts; i++) xs.push(Math.round((i * (width - postSec)) / (nPosts - 1)));
    for (var a = 0; a < xs.length; a++) {
      beams.push(mk({ name: 'Frontpfosten', woodType: 'Douglasie',
        L: frontH, B: postSec, H: postSec, axis: 'y',
        x: xs[a], y: 0, z: depth - postSec, group: 'Pfosten' }));
    }

    // --- Frontpfette (niedrig, auf den Frontpfosten, entlang X) ---
    beams.push(mk({ name: 'Frontpfette', woodType: 'Brettschichtholz (BSH)',
      L: width, B: pfB, H: pfH, axis: 'x',
      x: 0, y: frontH, z: depth - pfB, group: 'Pfetten' }));

    // --- Sparren (laengs, axis 'z') mit Gefaelle Wand->Front, Abstand ~70 cm ---
    var nSp = Math.max(2, Math.round(width / 700) + 1);
    var spY = frontH + pfH + rise / 2;   // Unterkante der Enden auf Pfetten-Oberkante
    for (var k = 0; k < nSp; k++) {
      var xS = Math.round((k * (width - spB)) / (nSp - 1));
      beams.push(mk({ name: 'Sparren', woodType: 'Fichte',
        L: depth, B: spB, H: spH, axis: 'z',
        x: xS, y: spY, z: 0, rx: angDeg, group: 'Sparren' }));  // Wandende (z=0) hoch
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

  function beamsToDXF(beams) {
    beams = Array.isArray(beams) ? beams : [];

    // 1) Balken-Boxen (Bounding-Boxes in Modellkoordinaten) berechnen.
    var boxes = beams.map(function (b) {
      b = b || {};
      var axis = (b.axis === 'x' || b.axis === 'y' || b.axis === 'z') ? b.axis : 'x';
      var L = num(b.L), B = num(b.B), H = num(b.H);
      var wX = (axis === 'x' ? L : B); // Ausdehnung entlang X
      var hY = (axis === 'y' ? L : H); // Ausdehnung entlang Y
      var dZ = (axis === 'z' ? L : B); // Ausdehnung entlang Z
      var x0 = num(b.x), y0 = num(b.y), z0 = num(b.z);
      return {
        beam: b,
        x0: x0, x1: x0 + wX,
        y0: y0, y1: y0 + hY,
        z0: z0, z1: z0 + dZ
      };
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
      emitPolyline(ent, 'DRAUFSICHT', [
        [bx.x0, -bx.z0],
        [bx.x1, -bx.z0],
        [bx.x1, -bx.z1],
        [bx.x0, -bx.z1]
      ]);

      // -- Vorderansicht: X -> dxfX, Y -> dxfY (nach unten versetzt) --
      emitPolyline(ent, 'VORNE', [
        [bx.x0, bx.y0 + frontDeltaY],
        [bx.x1, bx.y0 + frontDeltaY],
        [bx.x1, bx.y1 + frontDeltaY],
        [bx.x0, bx.y1 + frontDeltaY]
      ]);

      // -- Seitenansicht: Z -> dxfX (nach rechts versetzt), Y -> dxfY (Basis wie Vorne) --
      emitPolyline(ent, 'SEITE', [
        [bx.z0 + sideDeltaX, bx.y0 + frontDeltaY],
        [bx.z1 + sideDeltaX, bx.y0 + frontDeltaY],
        [bx.z1 + sideDeltaX, bx.y1 + frontDeltaY],
        [bx.z0 + sideDeltaX, bx.y1 + frontDeltaY]
      ]);

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
