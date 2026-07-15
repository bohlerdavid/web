/*
 * Leichter 3D-Viewer fuer die Landing Page.
 *
 * Wird NICHT beim Seitenaufruf geladen. Die Beispiel-Karten zeigen ein statisches
 * PNG; erst ein Klick auf "In 3D drehen" laedt dieses Modul und three.js nach.
 * Bis dahin kostet der Viewer 0 Byte — die Landing Page bleibt schnell.
 *
 * Aufruf:  HB3DViewer.mount(containerEl, '/static/models/carport.json')
 */
(function (root) {
  'use strict';

  // Bare specifier, aufgeloest ueber die importmap der Seite. Direkte CDN-URLs
  // funktionieren hier NICHT: OrbitControls importiert intern selbst 'three',
  // und ohne importmap scheitert genau dieser innere Import.
  var THREE_URL = 'three';
  var OC_URL = 'three/addons/controls/OrbitControls.js';

  // 1:1 die Palette aus templates/holzbau.html. Weicht sie ab, zeigt die Landing
  // Page andere Farben als der Editor — beim ersten Bauen hatte ich fuenf Werte
  // aus dem Gedaechtnis geschrieben und danebengelegen.
  var WOOD_COLORS = {
    'Fichte': 0xd4a96a, 'Kiefer': 0xc8864c, 'Lärche': 0xb87333, 'Eiche': 0x8b6914,
    'Buche': 0xd49b63, 'Douglasie': 0xa0522d, 'Brettschichtholz (BSH)': 0xe8c090,
    'Sperrholz': 0xf5deb3, 'OSB': 0xcdc294, 'Benutzerdefiniert': 0x888888,
  };
  var SHEET = { 'Sperrholz': 1, 'OSB': 1 };

  var _mods = null;
  function loadModules() {
    if (_mods) return _mods;
    _mods = Promise.all([import(THREE_URL), import(OC_URL)]).then(function (m) {
      return { THREE: m[0], OrbitControls: m[1].OrbitControls };
    });
    return _mods;
  }

  // Platte mit rechteckigen Ausfraesungen. Spiegelt die Logik des Editors:
  // duennste Achse = Dicke, laengere Flaechenseite = u-Achse.
  function panelGeo(THREE, beam, W, H, D) {
    var axes = [
      { v: W, e: new THREE.Vector3(1, 0, 0) },
      { v: H, e: new THREE.Vector3(0, 1, 0) },
      { v: D, e: new THREE.Vector3(0, 0, 1) },
    ];
    var ti = 0, i;
    for (i = 1; i < 3; i++) if (axes[i].v < axes[ti].v) ti = i;
    var face = axes.filter(function (_, k) { return k !== ti; });
    if (face[1].v > face[0].v) face.reverse();
    var A = face[0].v, B = face[1].v, T = axes[ti].v;

    var shape = new THREE.Shape();
    shape.moveTo(-A / 2, -B / 2); shape.lineTo(A / 2, -B / 2);
    shape.lineTo(A / 2, B / 2); shape.lineTo(-A / 2, B / 2); shape.closePath();

    (beam.cutouts || []).forEach(function (c) {
      var path = new THREE.Path();
      if (c.shape === 'circle') {
        var cx = (c.u || 0) - A / 2, cy = (c.v || 0) - B / 2, r = Math.max(1, (c.dia || 100) / 2);
        for (var k = 0; k <= 40; k++) {
          var a = k / 40 * Math.PI * 2, px = cx + r * Math.cos(a), py = cy + r * Math.sin(a);
          k === 0 ? path.moveTo(px, py) : path.lineTo(px, py);
        }
      } else {
        var x0 = (c.u || 0) - A / 2, y0 = (c.v || 0) - B / 2;
        var w = Math.max(1, c.w || 100), h = Math.max(1, c.h || 100);
        path.moveTo(x0, y0); path.lineTo(x0 + w, y0);
        path.lineTo(x0 + w, y0 + h); path.lineTo(x0, y0 + h);
      }
      path.closePath();
      shape.holes.push(path);
    });

    var geo = new THREE.ExtrudeGeometry(shape, { depth: T, bevelEnabled: false });
    geo.translate(0, 0, -T / 2);
    var eX = face[0].e.clone(), eY = face[1].e.clone(), eZ = axes[ti].e.clone();
    if (eX.clone().cross(eY).dot(eZ) < 0) eZ.negate();
    geo.applyMatrix4(new THREE.Matrix4().makeBasis(eX, eY, eZ));
    geo.computeVertexNormals();
    return geo;
  }

  function beamMesh(THREE, b) {
    var W, H, D;
    if (b.axis === 'x') { W = b.L; H = b.H; D = b.B; }
    else if (b.axis === 'y') { W = b.B; H = b.L; D = b.H; }
    else { W = b.B; H = b.H; D = b.L; }

    var geo = (SHEET[b.woodType] && b.cutouts && b.cutouts.length)
      ? panelGeo(THREE, b, W, H, D)
      : new THREE.BoxGeometry(W, H, D);
    var mat = new THREE.MeshStandardMaterial({
      color: WOOD_COLORS[b.woodType] || 0xc8864c, roughness: 0.85, metalness: 0.0,
    });
    var m = new THREE.Mesh(geo, mat);
    m.position.set(b.x + W / 2, b.y + H / 2, b.z + D / 2);
    var rad = Math.PI / 180;
    m.rotation.set((b.rx || 0) * rad, (b.ry || 0) * rad, (b.rz || 0) * rad);
    m.castShadow = true; m.receiveShadow = true;
    return m;
  }

  // PKW — identische Referenzform wie das Deko-Objekt im Editor.
  function carGroup(THREE, p) {
    p = p || {};
    var L = p.L || 4500, W = p.W || 1820, H = p.H || 1460;
    var g = new THREE.Group();
    var body = new THREE.MeshStandardMaterial({ color: 0x2f4a6d, roughness: 0.42, metalness: 0.25 });
    var glass = new THREE.MeshStandardMaterial({ color: 0x1a2430, roughness: 0.12, metalness: 0.55 });
    var tyre = new THREE.MeshStandardMaterial({ color: 0x16181c, roughness: 0.95 });
    var rim = new THREE.MeshStandardMaterial({ color: 0xb8bcc4, roughness: 0.35, metalness: 0.8 });

    function ext(pts, depth, mat, bevel) {
      var s = new THREE.Shape();
      pts.forEach(function (q, i) { i === 0 ? s.moveTo(q[0], q[1]) : s.lineTo(q[0], q[1]); });
      s.closePath();
      var geo = new THREE.ExtrudeGeometry(s, {
        depth: depth, bevelEnabled: !!bevel, bevelThickness: bevel || 0,
        bevelSize: bevel || 0, bevelSegments: 2, curveSegments: 6,
      });
      geo.translate(0, 0, -depth / 2);
      geo.rotateY(-Math.PI / 2);
      var m = new THREE.Mesh(geo, mat);
      m.castShadow = true; m.receiveShadow = true;
      return m;
    }

    var Wb = 1700;
    g.add(ext([[-2250, 280], [-2250, 700], [-2210, 830], [-1980, 890], [-1400, 930],
      [-780, 965], [1850, 1000], [2130, 955], [2250, 810], [2250, 280]], Wb, body, 28));
    g.add(ext([[-780, 960], [-30, 1430], [900, 1450], [1350, 1430], [1850, 995]], Wb - 90, glass, 12));
    var roof = new THREE.Mesh(new THREE.BoxGeometry(Wb - 40, 55, 1200), body);
    roof.position.set(0, 1440, 660); roof.castShadow = true; g.add(roof);

    var r = 350, tw = 225;
    [[-800, -1350], [800, -1350], [-800, 1300], [800, 1300]].forEach(function (w) {
      var t = new THREE.Mesh(new THREE.CylinderGeometry(r, r, tw, 20), tyre);
      t.rotation.z = Math.PI / 2; t.position.set(w[0], r, w[1]); t.castShadow = true; g.add(t);
      var d = new THREE.Mesh(new THREE.CylinderGeometry(r * 0.6, r * 0.6, tw + 8, 16), rim);
      d.rotation.z = Math.PI / 2; d.position.set(w[0] * 1.006, r, w[1]); g.add(d);
    });
    [[-1, 0xf4f2e2, 620], [1, 0xd23b2e, 860]].forEach(function (q) {
      [-1, 1].forEach(function (side) {
        var l = new THREE.Mesh(new THREE.BoxGeometry(300, 130, 60),
          new THREE.MeshStandardMaterial({ color: q[1], roughness: 0.3, emissive: q[1], emissiveIntensity: 0.25 }));
        l.position.set(side * 570, q[2], q[0] * 2245);
        g.add(l);
      });
    });
    g.scale.set(W / 1820, H / 1460, L / 4500);
    return g;
  }

  function mount(el, modelUrl) {
    el.innerHTML = '<div class="hb3d-load">3D wird geladen …</div>';
    return Promise.all([loadModules(), fetch(modelUrl).then(function (r) { return r.json(); })])
      .then(function (res) {
        var THREE = res[0].THREE, OrbitControls = res[0].OrbitControls, data = res[1];
        el.innerHTML = '';

        var W = el.clientWidth, H = el.clientHeight || 360;
        var renderer = new THREE.WebGLRenderer({ antialias: true });
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        renderer.setSize(W, H);
        renderer.shadowMap.enabled = true;
        renderer.shadowMap.type = THREE.PCFSoftShadowMap;
        el.appendChild(renderer.domElement);

        var scene = new THREE.Scene();
        scene.background = new THREE.Color(0xf7f2e8);

        var group = new THREE.Group();
        (data.beams || []).forEach(function (b) { group.add(beamMesh(THREE, b)); });
        if (data.car) {
          var c = carGroup(THREE, data.car);
          c.position.set(data.car.x || 0, 0, data.car.z || 0);
          if (data.car.ry) c.rotation.y = data.car.ry * Math.PI / 180;
          group.add(c);
        }
        scene.add(group);

        // Modell zentrieren, damit die Kamera unabhaengig vom Modell passt
        var box = new THREE.Box3().setFromObject(group);
        var ctr = box.getCenter(new THREE.Vector3());
        var size = box.getSize(new THREE.Vector3());
        group.position.sub(new THREE.Vector3(ctr.x, box.min.y, ctr.z));
        var span = Math.max(size.x, size.z, size.y);

        // Boden grosszuegig + Nebel auf die Hintergrundfarbe: sonst wird beim
        // Drehen die harte Kante der Bodenplatte sichtbar.
        scene.fog = new THREE.Fog(0xf7f2e8, span * 1.8, span * 6);
        var ground = new THREE.Mesh(
          new THREE.PlaneGeometry(span * 30, span * 30),
          new THREE.MeshStandardMaterial({ color: 0xe6ddcc, roughness: 1 })
        );
        ground.rotation.x = -Math.PI / 2; ground.position.y = -2; ground.receiveShadow = true;
        scene.add(ground);

        scene.add(new THREE.AmbientLight(0xffffff, 0.62));
        var sun = new THREE.DirectionalLight(0xffffff, 1.05);
        sun.position.set(-span, span * 1.4, -span * 0.8);
        sun.castShadow = true;
        sun.shadow.mapSize.set(1024, 1024);
        var d = span * 1.2;
        sun.shadow.camera.left = -d; sun.shadow.camera.right = d;
        sun.shadow.camera.top = d; sun.shadow.camera.bottom = -d;
        sun.shadow.camera.far = span * 5;
        scene.add(sun);
        var fill = new THREE.DirectionalLight(0xffffff, 0.3);
        fill.position.set(span, span * 0.6, span); scene.add(fill);

        var camera = new THREE.PerspectiveCamera(38, W / H, 10, span * 40);
        var dist = span * 1.75;
        camera.position.set(-dist * 0.75, dist * 0.5, -dist * 0.7);

        var controls = new OrbitControls(camera, renderer.domElement);
        controls.target.set(0, size.y * 0.4, 0);
        controls.enableDamping = true;
        controls.dampingFactor = 0.08;
        controls.enablePan = false;
        controls.minDistance = span * 0.7;
        controls.maxDistance = span * 4;
        controls.maxPolarAngle = Math.PI / 2 - 0.04;   // nie unter den Boden schauen
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.9;
        controls.addEventListener('start', function () { controls.autoRotate = false; });
        controls.update();

        var alive = true;
        function tick() {
          if (!alive) return;
          requestAnimationFrame(tick);
          controls.update();
          renderer.render(scene, camera);
        }
        tick();

        function onResize() {
          var w = el.clientWidth, h = el.clientHeight || 360;
          renderer.setSize(w, h);
          camera.aspect = w / h;
          camera.updateProjectionMatrix();
        }
        window.addEventListener('resize', onResize);

        return {
          destroy: function () {
            alive = false;
            window.removeEventListener('resize', onResize);
            controls.dispose();
            renderer.dispose();
            el.innerHTML = '';
          },
        };
      })
      .catch(function (err) {
        el.innerHTML = '<div class="hb3d-load">3D-Ansicht nicht verfügbar.</div>';
        console.warn('[HB3D] Viewer:', err);
        throw err;
      });
  }

  root.HB3DViewer = { mount: mount };
})(window);
