EIGENE PROJEKTFOTOS – so blendest du sie in die Ratgeber-Artikel ein
====================================================================

Warum das wichtig ist
----------------------
Google (AdSense + Suche) bewertet Seiten hoeher, wenn "eigener Content" und
"first-hand expertise" erkennbar sind. Eigene Fotos gebauter Projekte sind das
staerkste Signal dafuer, dass hinter der Seite echte Erfahrung steht.

Wie es funktioniert
-------------------
Fuer drei Artikel ist je EIN fester Dateiname reserviert. Sobald du eine Datei
mit genau diesem Namen hier ablegst und pushst, erscheint das Foto automatisch:
  - ganz oben im Artikel, mit fertiger Bildunterschrift (DE/EN/FR)
  - als Vorschaubild bei Google und beim Teilen (OG/JSON-LD)

Solange eine Datei fehlt, bleibt der Artikel unveraendert – es erscheint KEIN
kaputtes Platzhalterbild. Du kannst also auch nur ein oder zwei Fotos liefern.

Welche Dateien
--------------
Lege die Fotos in diesen Ordner (static/projekte/) mit GENAU diesen Namen:

  pergola.jpg     -> Artikel "Pergola selbst bauen"
  carport.jpg     -> Artikel "Carport selbst planen"
  gartenhaus.jpg  -> Artikel "Gartenhaus selbst planen"

Empfehlung fuers Foto
---------------------
  - Querformat, mind. 1200 px breit (z. B. 1600 x 1000), scharf, gut belichtet
  - JPG, moeglichst unter ~400 KB (bei Bedarf vorher verkleinern)
  - Ein echtes, selbst gebautes Projekt – kein Stockfoto

Bildunterschrift anpassen (optional)
------------------------------------
Die Texte stehen in der Datei blog_fotos.py (Dict FOTOS, je Sprache de/en/fr).
Standard ist bewusst neutral gehalten ("Eigenes Projektfoto: ..."). Wenn du
konkrete Angaben hast (Ort, Holzart, Jahr), machen sie das Signal noch staerker –
dann dort den Text ersetzen.

Danach: committen und pushen (git add static/projekte/pergola.jpg ...), Railway
deployt automatisch, das Foto ist live.
