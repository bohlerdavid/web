/* ── HolzBau 3D i18n Engine ─────────────────────────────────────────────
   Übersetzt die Seite client-seitig (DE ist Quellsprache im Markup).
   Sprache: localStorage/Cookie 'hb_lang' > Browser-Sprache > de.
   Dynamisch erzeugte DOM-Knoten werden via MutationObserver übersetzt. */
(function () {
  var SUP = ['de', 'en', 'fr'];
  function norm(l) { l = (l || 'de').slice(0, 2).toLowerCase(); return SUP.indexOf(l) >= 0 ? l : 'de'; }

  var stored = null;
  try { stored = localStorage.getItem('hb_lang'); } catch (e) {}
  if (!stored) { var m = document.cookie.match(/(?:^|;\s*)hb_lang=([a-z]{2})/); if (m) stored = m[1]; }
  // Server-Sprache (vom SEO-Routing in <html lang> gesetzt) als starker Hinweis vor Browser
  var serverLang = (document.documentElement.getAttribute('lang') || '').slice(0, 2);
  var lang = norm(stored || serverLang || (navigator.language || 'de'));
  window.hbLang = lang;
  try { localStorage.setItem('hb_lang', lang); } catch (e) {}
  document.cookie = 'hb_lang=' + lang + ';path=/;max-age=31536000;SameSite=Lax';
  document.documentElement.setAttribute('lang', lang);

  var dict = (window.HB_I18N && window.HB_I18N[lang]) || null;
  window.t = function (s) { return (dict && dict[s]) || s; };

  function trText(node) {
    var s = node.nodeValue; if (!s || !dict) return;
    var tr = s.trim(); if (!tr) return;
    var rep = dict[tr];
    if (rep && rep !== tr) node.nodeValue = s.replace(tr, rep);
  }

  var ATTRS = ['title', 'placeholder', 'alt', 'aria-label'];
  function trAttrs(el) {
    if (!el.getAttribute || !dict) return;
    for (var i = 0; i < ATTRS.length; i++) {
      var a = ATTRS[i], v = el.getAttribute(a);
      if (v) { var tv = v.trim(), rep = dict[tv]; if (rep && rep !== tv) el.setAttribute(a, v.replace(tv, rep)); }
    }
    if (el.tagName === 'INPUT' && (el.type === 'submit' || el.type === 'button')) {
      var v2 = el.value, r2 = v2 && dict[v2.trim()];
      if (r2) el.value = r2;
    }
  }

  function walk(root) {
    if (!dict) return;
    if (root.nodeType === 3) { trText(root); return; }
    if (root.nodeType !== 1) return;
    var tag = root.tagName;
    if (tag === 'SCRIPT' || tag === 'STYLE') return;
    trAttrs(root);
    var w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: function (n) {
        var p = n.parentNode;
        if (p && (p.tagName === 'SCRIPT' || p.tagName === 'STYLE')) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    var n, arr = [];
    while ((n = w.nextNode())) arr.push(n);
    for (var i = 0; i < arr.length; i++) trText(arr[i]);
    if (root.querySelectorAll) {
      var els = root.querySelectorAll('[title],[placeholder],[alt],[aria-label],input[type=submit],input[type=button]');
      for (var j = 0; j < els.length; j++) trAttrs(els[j]);
    }
  }

  window.hbSetLang = function (l) {
    l = norm(l);
    try { localStorage.setItem('hb_lang', l); } catch (e) {}
    document.cookie = 'hb_lang=' + l + ';path=/;max-age=31536000;SameSite=Lax';
    // Auf der Startseite die server-gerenderte SEO-Sprachversion ansteuern (/, /en, /fr)
    var p = location.pathname.replace(/\/+$/, '');
    if (p === '' || p === '/en' || p === '/fr') {
      location.href = (l === 'de' ? '/' : '/' + l);
    } else {
      location.reload();
    }
  };

  function injectSwitcher() {
    if (document.getElementById('hb-lang-pill')) return;
    var inApp = !!document.getElementById('topbar');
    var d = document.createElement('div');
    d.id = 'hb-lang-pill';
    d.style.cssText = 'position:fixed;left:10px;bottom:' + (document.getElementById('statusbar') ? '32px' : '12px') +
      ';z-index:99998;display:flex;gap:2px;background:' + (inApp ? 'rgba(22,27,39,.92)' : 'rgba(255,255,255,.95)') +
      ';border:1px solid ' + (inApp ? '#283755' : '#d8cdb8') +
      ';border-radius:999px;padding:3px 5px;font:600 11px/1 Inter,"Segoe UI",sans-serif;box-shadow:0 2px 10px rgba(0,0,0,.18);';
    SUP.forEach(function (l) {
      var b = document.createElement('button');
      b.type = 'button';
      b.textContent = l.toUpperCase();
      b.style.cssText = 'border:none;background:' + (l === lang ? '#4e8cdd' : 'transparent') +
        ';color:' + (l === lang ? '#fff' : (inApp ? '#8fa3c8' : '#7a6a55')) +
        ';padding:4px 8px;border-radius:999px;cursor:pointer;font:inherit;';
      b.onclick = function () { window.hbSetLang(l); };
      d.appendChild(b);
    });
    document.body.appendChild(d);
  }

  function start() {
    injectSwitcher();
    if (!dict) return;
    walk(document.body);
    new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var mu = muts[i];
        if (mu.type === 'characterData') { trText(mu.target); continue; }
        for (var j = 0; j < mu.addedNodes.length; j++) walk(mu.addedNodes[j]);
      }
    }).observe(document.body, { childList: true, subtree: true, characterData: true });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
