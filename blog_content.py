# -*- coding: utf-8 -*-
"""Ratgeber-/Blog-Inhalte für HolzBau 3D (SEO). DE/EN/FR.
Struktur: ARTICLES[slug][lang] = {title, desc, h1, lead, date, body_html, kw}
Slugs sind sprachneutral (eine URL je Sprache via Präfix /, /en, /fr)."""

# Sprachspezifische URL-Pfade des Ratgebers
GUIDES_PATH = {'de': '/ratgeber', 'en': '/en/guides', 'fr': '/fr/guides'}
GUIDES_TITLE = {
    'de': 'Ratgeber – Holzbau, Pergola, Carport & Dachstuhl selbst planen',
    'en': 'Guides – Plan wood constructions, pergolas, carports & roof trusses',
    'fr': 'Guides – Concevoir constructions bois, pergola, carport & charpente',
}
GUIDES_INTRO = {
    'de': 'Praxis-Anleitungen zum selbst Planen von Holzkonstruktionen in 3D – kostenlos, direkt im Browser.',
    'en': 'Hands-on guides to designing wood constructions in 3D yourself – free, right in your browser.',
    'fr': 'Guides pratiques pour concevoir vous-même des constructions bois en 3D – gratuit, dans le navigateur.',
}

ARTICLES = {
    'pergola-selbst-bauen': {
        'order': 1, 'icon': '🌿',
        'de': {
            'title': 'Pergola selbst bauen: Anleitung mit kostenlosem 3D-Plan',
            'desc': 'Pergola selbst bauen und planen: Maße, Holz, Fundament und Statik – Schritt für Schritt. Mit HolzBau 3D planst du deine Pergola kostenlos in 3D inkl. Stückliste.',
            'kw': 'Pergola selbst bauen, Pergola selbst planen, Pergola 3D, Pergola Bauplan',
            'date': '2026-06-12',
            'h1': 'Pergola selbst bauen – Schritt für Schritt mit 3D-Plan',
            'lead': 'Eine Pergola ist das ideale Einsteigerprojekt im Holzbau: überschaubar, günstig und mit großer Wirkung im Garten. Mit einem sauberen 3D-Plan vermeidest du Fehler beim Materialeinkauf und beim Aufbau.',
            'body_html': '''
<h2>1. Maße und Standort festlegen</h2>
<p>Lege zuerst Länge, Breite und Höhe deiner Pergola fest. Übliche Maße sind 3 × 4 Meter bei rund 2,20–2,50 m Höhe. Achte auf den Sonnenverlauf und genügend Abstand zur Grundstücksgrenze. In HolzBau 3D gibst du die Grundfläche ein und siehst sofort die räumliche Wirkung.</p>
<h2>2. Das richtige Holz wählen</h2>
<p>Für tragende Pfosten eignen sich 12 × 12 cm Kanthölzer aus Konstruktionsvollholz (KVH) oder Lärche. Für Querbalken und Sparren reichen meist 8 × 16 cm. Druckimprägniertes Holz oder Lärche/Douglasie hält der Witterung am längsten stand.</p>
<h2>3. Fundament und Pfostenanker</h2>
<p>Pergola-Pfosten gehören nie direkt in die Erde. Setze Punktfundamente aus Beton und verschraube die Pfosten über H-Anker oder Stützenfüße. Das hält die Konstruktion trocken und langlebig.</p>
<h2>4. Konstruktion in 3D planen</h2>
<p>Bevor du Holz kaufst, plane die komplette Pergola in 3D: Pfosten, Pfetten, Sparren und Verstrebungen. So erkennst du Kollisionen früh und bekommst eine exakte <strong>Stückliste</strong> mit allen Längen – das spart Verschnitt und Geld.</p>
<h2>5. Aufbau-Reihenfolge</h2>
<p>Pfosten ausrichten und lotrecht fixieren → Querbalken (Pfetten) auflegen und verschrauben → Sparren im gleichen Abstand montieren → Diagonalstreben für die Aussteifung. Zum Schluss Lasur oder Öl auftragen.</p>
<p class="cta-note">Plane deine Pergola jetzt kostenlos in 3D und exportiere die Stückliste – ganz ohne Installation.</p>
''',
        },
        'en': {
            'title': 'Build a Pergola Yourself: Guide with a Free 3D Plan',
            'desc': 'Build and design a pergola yourself: dimensions, timber, foundation and bracing – step by step. Plan your pergola in 3D for free with HolzBau 3D, parts list included.',
            'kw': 'build a pergola yourself, design a pergola, pergola 3D, pergola plan',
            'date': '2026-06-12',
            'h1': 'Build a Pergola Yourself – Step by Step with a 3D Plan',
            'lead': 'A pergola is the ideal entry-level timber project: manageable, affordable and with a big impact in the garden. A clean 3D plan helps you avoid mistakes when buying material and during assembly.',
            'body_html': '''
<h2>1. Define dimensions and location</h2>
<p>Start with the length, width and height of your pergola. Common sizes are 3 × 4 metres at around 2.2–2.5 m height. Mind the sun path and keep enough distance to the property line. In HolzBau 3D you enter the footprint and instantly see the spatial result.</p>
<h2>2. Choose the right timber</h2>
<p>For load-bearing posts use 12 × 12 cm squared timber (glulam/KVH) or larch. For beams and rafters 8 × 16 cm is usually enough. Pressure-treated timber or larch/Douglas fir lasts longest outdoors.</p>
<h2>3. Foundation and post anchors</h2>
<p>Pergola posts should never go straight into the soil. Use concrete point footings and bolt the posts onto H-anchors or post feet. This keeps the structure dry and durable.</p>
<h2>4. Plan the structure in 3D</h2>
<p>Before buying timber, plan the whole pergola in 3D: posts, purlins, rafters and braces. You spot collisions early and get an exact <strong>parts list</strong> with all lengths – saving offcuts and money.</p>
<h2>5. Assembly order</h2>
<p>Align and plumb the posts → place and bolt the beams (purlins) → fit the rafters at equal spacing → add diagonal braces for stiffness. Finally apply stain or oil.</p>
<p class="cta-note">Plan your pergola in 3D for free and export the parts list – no installation needed.</p>
''',
        },
        'fr': {
            'title': 'Construire une pergola soi-même : guide avec plan 3D gratuit',
            'desc': 'Construire et concevoir une pergola soi-même : dimensions, bois, fondation et contreventement – étape par étape. Concevez votre pergola en 3D gratuitement avec HolzBau 3D.',
            'kw': 'construire une pergola soi-même, concevoir une pergola, pergola 3D, plan pergola',
            'date': '2026-06-12',
            'h1': 'Construire une pergola soi-même – étape par étape en 3D',
            'lead': 'La pergola est le projet idéal pour débuter en construction bois : simple, abordable et à fort effet dans le jardin. Un bon plan 3D évite les erreurs d’achat et de montage.',
            'body_html': '''
<h2>1. Définir les dimensions et l’emplacement</h2>
<p>Commencez par la longueur, la largeur et la hauteur. Les tailles courantes sont 3 × 4 mètres pour environ 2,2–2,5 m de haut. Tenez compte de la course du soleil et de la distance à la limite de propriété. Dans HolzBau 3D, vous saisissez l’emprise et visualisez aussitôt le résultat.</p>
<h2>2. Choisir le bon bois</h2>
<p>Pour les poteaux porteurs, utilisez des bois carrés de 12 × 12 cm (lamellé-collé/KVH) ou du mélèze. Pour les poutres et chevrons, 8 × 16 cm suffisent. Le bois traité ou le mélèze/douglas résiste le mieux aux intempéries.</p>
<h2>3. Fondation et ancrages</h2>
<p>Les poteaux ne doivent jamais être plantés dans la terre. Utilisez des plots béton et fixez les poteaux sur des ancrages en H ou pieds de poteau. La structure reste sèche et durable.</p>
<h2>4. Concevoir la structure en 3D</h2>
<p>Avant d’acheter le bois, concevez toute la pergola en 3D : poteaux, pannes, chevrons et contreventements. Vous repérez tôt les collisions et obtenez une <strong>liste de pièces</strong> exacte avec toutes les longueurs – moins de chutes, moins de dépenses.</p>
<h2>5. Ordre de montage</h2>
<p>Aligner et mettre d’aplomb les poteaux → poser et visser les poutres (pannes) → fixer les chevrons à intervalles réguliers → ajouter les diagonales de contreventement. Enfin, appliquer lasure ou huile.</p>
<p class="cta-note">Concevez votre pergola en 3D gratuitement et exportez la liste de pièces – sans installation.</p>
''',
        },
    },
    'carport-selbst-planen': {
        'order': 2, 'icon': '🚗',
        'de': {
            'title': 'Carport selbst planen: 3D-Software für deinen Holz-Carport',
            'desc': 'Carport selbst planen mit kostenloser 3D-Software: Größe, Pfosten, Dachneigung und Stückliste. Plane deinen Holz-Carport online im Browser mit HolzBau 3D.',
            'kw': 'Carport selbst planen, Carport planen, Carport 3D, Holz-Carport Bauplan',
            'date': '2026-06-12',
            'h1': 'Carport selbst planen – mit 3D-Software im Browser',
            'lead': 'Ein Carport schützt das Auto und ist als Holzkonstruktion gut selbst zu bauen. Wichtig sind die richtige Größe, eine saubere Statik und ein durchdachter Plan.',
            'body_html': '''
<h2>Größe und Stellplatz</h2>
<p>Plane pro PKW rund 2,7 × 5,0 m, besser 3,0 × 5,5 m für bequemes Ein- und Aussteigen. Für zwei Fahrzeuge etwa 6,0 m Breite. Berücksichtige die Durchfahrtshöhe (mind. 2,2 m).</p>
<h2>Pfosten, Pfetten und Dach</h2>
<p>Tragende Pfosten meist 12 × 12 cm, Pfetten 10 × 20 cm. Bei Flachdach reicht ein leichtes Gefälle (3–5°) für den Wasserablauf; ein Pultdach leitet Regen gezielt ab. Plane Diagonalstreben für die Aussteifung gegen Wind.</p>
<h2>In 3D planen und Material berechnen</h2>
<p>In HolzBau 3D setzt du Pfosten, Träger und Sparren maßstabsgetreu und erhältst die <strong>komplette Stückliste</strong>. So kennst du Holzbedarf und Kosten, bevor du im Baumarkt stehst.</p>
<p class="cta-note">Plane deinen Carport jetzt gratis in 3D – inklusive Stückliste und Druckplan.</p>
''',
        },
        'en': {
            'title': 'Design a Carport Yourself: 3D Software for Timber Carports',
            'desc': 'Design a carport yourself with free 3D software: size, posts, roof pitch and parts list. Plan your timber carport online in the browser with HolzBau 3D.',
            'kw': 'design a carport, plan a carport, carport 3D, timber carport plan',
            'date': '2026-06-12',
            'h1': 'Design a Carport Yourself – with 3D Software in the Browser',
            'lead': 'A carport protects your car and is a great DIY timber project. The keys are the right size, sound structure and a well-thought-out plan.',
            'body_html': '''
<h2>Size and parking space</h2>
<p>Plan around 2.7 × 5.0 m per car, better 3.0 × 5.5 m for comfortable access. For two cars about 6.0 m width. Mind the clearance height (at least 2.2 m).</p>
<h2>Posts, purlins and roof</h2>
<p>Load-bearing posts are usually 12 × 12 cm, purlins 10 × 20 cm. A flat roof needs a slight fall (3–5°) for drainage; a mono-pitch roof sheds rain in one direction. Add diagonal braces to stiffen against wind.</p>
<h2>Plan in 3D and calculate material</h2>
<p>In HolzBau 3D you place posts, beams and rafters to scale and get the <strong>full parts list</strong>. You know the timber demand and cost before you reach the store.</p>
<p class="cta-note">Plan your carport in 3D for free – parts list and print plan included.</p>
''',
        },
        'fr': {
            'title': 'Concevoir un carport soi-même : logiciel 3D pour carport bois',
            'desc': 'Concevoir un carport soi-même avec un logiciel 3D gratuit : taille, poteaux, pente de toit et liste de pièces. Planifiez votre carport bois en ligne avec HolzBau 3D.',
            'kw': 'concevoir un carport, plan de carport, carport 3D, carport bois',
            'date': '2026-06-12',
            'h1': 'Concevoir un carport soi-même – logiciel 3D dans le navigateur',
            'lead': 'Un carport protège la voiture et constitue un excellent projet bois en autoconstruction. L’essentiel : la bonne taille, une structure solide et un plan réfléchi.',
            'body_html': '''
<h2>Taille et emplacement</h2>
<p>Prévoyez environ 2,7 × 5,0 m par voiture, idéalement 3,0 × 5,5 m pour un accès confortable. Pour deux véhicules, environ 6,0 m de large. Tenez compte de la hauteur de passage (au moins 2,2 m).</p>
<h2>Poteaux, pannes et toit</h2>
<p>Poteaux porteurs généralement 12 × 12 cm, pannes 10 × 20 cm. Un toit plat nécessite une légère pente (3–5°) pour l’évacuation ; un toit monopente dirige la pluie. Ajoutez des diagonales contre le vent.</p>
<h2>Concevoir en 3D et calculer le matériel</h2>
<p>Dans HolzBau 3D, vous placez poteaux, poutres et chevrons à l’échelle et obtenez la <strong>liste complète de pièces</strong>. Vous connaissez le besoin en bois et le coût avant l’achat.</p>
<p class="cta-note">Concevez votre carport en 3D gratuitement – liste de pièces et plan d’impression inclus.</p>
''',
        },
    },
    'dachstuhl-konstruieren': {
        'order': 3, 'icon': '🏠',
        'de': {
            'title': 'Dachstuhl konstruieren: Grundlagen & 3D-Planung für Einsteiger',
            'desc': 'Dachstuhl konstruieren leicht erklärt: Sparrendach, Pfettendach, Dachneigung und Holzquerschnitte. Plane deinen Dachstuhl in 3D mit HolzBau 3D – kostenlos.',
            'kw': 'Dachstuhl konstruieren, Dachstuhl planen, Sparrendach, Pfettendach, Dachstuhl 3D',
            'date': '2026-06-12',
            'h1': 'Dachstuhl konstruieren – Grundlagen und 3D-Planung',
            'lead': 'Der Dachstuhl ist das Herzstück jedes Hauses. Wer die Grundtypen und die wichtigsten Holzquerschnitte kennt, kann eine einfache Konstruktion sicher in 3D planen.',
            'body_html': '''
<h2>Sparrendach oder Pfettendach?</h2>
<p>Beim <strong>Sparrendach</strong> bilden gegenüberliegende Sparren ein Dreieck und stützen sich gegenseitig – ideal für einfache Satteldächer ohne Innenstützen. Das <strong>Pfettendach</strong> trägt die Sparren über horizontale Pfetten (First-, Mittel-, Fußpfette) und erlaubt größere Spannweiten und Dachfenster.</p>
<h2>Dachneigung und Querschnitte</h2>
<p>Übliche Neigungen liegen zwischen 30° und 45°. Sparren häufig 8 × 18 cm bis 10 × 20 cm, je nach Spannweite und Schneelast. Die genauen Querschnitte richten sich nach Statik – im Zweifel einen Statiker hinzuziehen.</p>
<h2>In 3D planen statt nur skizzieren</h2>
<p>Mit HolzBau 3D legst du Grundriss, Pfetten und Sparren maßstabsgetreu an, drehst die Konstruktion frei im Raum und exportierst die <strong>Stückliste</strong> mit allen Längen und Schnittwinkeln. So wird aus der Skizze ein belastbarer Plan.</p>
<p class="cta-note">Plane deinen Dachstuhl jetzt kostenlos in 3D – mit Stückliste und Schnittplan.</p>
''',
        },
        'en': {
            'title': 'Design a Roof Truss: Basics & 3D Planning for Beginners',
            'desc': 'Roof truss design made simple: rafter roof, purlin roof, roof pitch and timber sections. Plan your roof truss in 3D with HolzBau 3D – free.',
            'kw': 'design a roof truss, roof truss planning, rafter roof, purlin roof, roof truss 3D',
            'date': '2026-06-12',
            'h1': 'Design a Roof Truss – Basics and 3D Planning',
            'lead': 'The roof truss is the heart of every house. Once you know the basic types and the key timber sections, you can plan a simple structure safely in 3D.',
            'body_html': '''
<h2>Rafter roof or purlin roof?</h2>
<p>In a <strong>rafter roof</strong>, opposing rafters form a triangle and support each other – ideal for simple gable roofs without internal posts. A <strong>purlin roof</strong> carries the rafters on horizontal purlins (ridge, middle, eaves) and allows larger spans and roof windows.</p>
<h2>Roof pitch and sections</h2>
<p>Common pitches are between 30° and 45°. Rafters are often 8 × 18 cm to 10 × 20 cm, depending on span and snow load. Exact sections follow the structural calculation – when in doubt, consult a structural engineer.</p>
<h2>Plan in 3D instead of just sketching</h2>
<p>With HolzBau 3D you set the floor plan, purlins and rafters to scale, rotate the structure freely in space and export the <strong>parts list</strong> with all lengths and cutting angles. Your sketch becomes a solid plan.</p>
<p class="cta-note">Plan your roof truss in 3D for free – with parts list and cutting plan.</p>
''',
        },
        'fr': {
            'title': 'Concevoir une charpente : bases & planification 3D pour débutants',
            'desc': 'Concevoir une charpente simplement : toit à chevrons, toit à pannes, pente et sections de bois. Concevez votre charpente en 3D avec HolzBau 3D – gratuit.',
            'kw': 'concevoir une charpente, plan de charpente, toit à chevrons, toit à pannes, charpente 3D',
            'date': '2026-06-12',
            'h1': 'Concevoir une charpente – bases et planification 3D',
            'lead': 'La charpente est le cœur de chaque maison. En connaissant les types de base et les sections de bois clés, on peut planifier une structure simple en toute sécurité en 3D.',
            'body_html': '''
<h2>Toit à chevrons ou à pannes ?</h2>
<p>Dans un <strong>toit à chevrons</strong>, des chevrons opposés forment un triangle et se soutiennent mutuellement – idéal pour les toits à deux pans simples sans poteaux intérieurs. Le <strong>toit à pannes</strong> porte les chevrons sur des pannes horizontales (faîtière, intermédiaire, sablière) et permet de plus grandes portées.</p>
<h2>Pente et sections</h2>
<p>Les pentes courantes vont de 30° à 45°. Les chevrons font souvent de 8 × 18 cm à 10 × 20 cm, selon la portée et la charge de neige. Les sections exactes dépendent du calcul de structure – en cas de doute, consultez un ingénieur.</p>
<h2>Concevoir en 3D plutôt que simplement esquisser</h2>
<p>Avec HolzBau 3D, vous placez le plan, les pannes et les chevrons à l’échelle, faites pivoter la structure et exportez la <strong>liste de pièces</strong> avec longueurs et angles de coupe. Votre esquisse devient un plan solide.</p>
<p class="cta-note">Concevez votre charpente en 3D gratuitement – avec liste de pièces et plan de coupe.</p>
''',
        },
    },
}


BLOG_UI = {
    'de': {'to_app': 'Kostenlos starten', 'home': 'Startseite', 'all': 'Alle Ratgeber',
           'read': 'Weiterlesen', 'cta': 'Jetzt kostenlos in 3D planen', 'more': 'Weitere Ratgeber'},
    'en': {'to_app': 'Start free', 'home': 'Home', 'all': 'All guides',
           'read': 'Read more', 'cta': 'Plan it in 3D for free', 'more': 'More guides'},
    'fr': {'to_app': 'Commencer gratuitement', 'home': 'Accueil', 'all': 'Tous les guides',
           'read': 'Lire la suite', 'cta': 'Planifier en 3D gratuitement', 'more': 'Autres guides'},
}


def article_url(slug, lang):
    base = GUIDES_PATH.get(lang, '/ratgeber')
    return base + '/' + slug


def ordered_slugs():
    return [s for s, _ in sorted(ARTICLES.items(), key=lambda kv: kv[1]['order'])]
