/* ============================================================
   IT Asset Management — Main JavaScript
   ============================================================ */

'use strict';

/* ---------- Sidebar Toggle ---------- */
(function () {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.querySelector('.main-content');
    const toggleBtn = document.getElementById('sidebarToggle');

    if (!sidebar || !toggleBtn) return;

    // Restore saved state
    if (localStorage.getItem('sidebarCollapsed') === 'true') {
        sidebar.classList.add('collapsed');
        if (mainContent) mainContent.classList.add('expanded');
    }

    toggleBtn.addEventListener('click', function () {
        sidebar.classList.toggle('collapsed');
        if (mainContent) mainContent.classList.toggle('expanded');
        localStorage.setItem('sidebarCollapsed', sidebar.classList.contains('collapsed'));
    });
})();

/* ---------- Delete Confirmation ---------- */
(function () {
    document.addEventListener('click', function (e) {
        const btn = e.target.closest('[data-confirm]');
        if (!btn) return;
        const msg = btn.dataset.confirm || 'Sind Sie sicher, dass Sie diesen Eintrag löschen möchten?';
        if (!confirm(msg)) {
            e.preventDefault();
            e.stopPropagation();
        }
    });

    // Handle delete forms triggered by buttons with data-confirm
    document.addEventListener('submit', function (e) {
        const form = e.target;
        if (!form.dataset.confirm) return;
        if (!confirm(form.dataset.confirm)) {
            e.preventDefault();
        }
    });
})();

/* ---------- Auto-dismiss Alerts ---------- */
(function () {
    const alerts = document.querySelectorAll('.alert.alert-success');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) bsAlert.close();
        }, 8000);
    });
})();

/* ---------- Clickable Table Rows ---------- */
(function () {
    const rows = document.querySelectorAll('tr[data-href]');
    rows.forEach(function (row) {
        row.style.cursor = 'pointer';
        row.addEventListener('click', function (e) {
            // Don't navigate if clicking a button/link/form inside the row
            if (e.target.closest('a, button, form, input, select')) return;
            window.location.href = row.dataset.href;
        });
    });
})();

/* ---------- Filter Form — Live Submit on Select Change ---------- */
(function () {
    const filterForm = document.getElementById('filterForm');
    if (!filterForm) return;
    filterForm.querySelectorAll('select').forEach(function (sel) {
        sel.addEventListener('change', function () {
            filterForm.submit();
        });
    });
})();

/* ---------- Animated Category Bars (Dashboard) ---------- */
(function () {
    const bars = document.querySelectorAll('.cat-bar-inner[data-width]');
    if (!bars.length) return;
    // Trigger animation after a small delay so CSS transition fires
    requestAnimationFrame(function () {
        requestAnimationFrame(function () {
            bars.forEach(function (bar) {
                bar.style.width = bar.dataset.width + '%';
            });
        });
    });
})();

/* ---------- Warranty Date Colour Coding ---------- */
(function () {
    const cells = document.querySelectorAll('[data-warranty]');
    const now = new Date();
    now.setHours(0, 0, 0, 0);

    cells.forEach(function (cell) {
        const val = cell.dataset.warranty;
        if (!val) return;
        const d = new Date(val);
        const diff = Math.floor((d - now) / 86400000); // days
        if (diff < 0) {
            cell.classList.add('warranty-critical');
        } else if (diff <= 30) {
            cell.classList.add('warranty-critical');
        } else if (diff <= 90) {
            cell.classList.add('warranty-warning');
        }
    });
})();

/* ---------- Search Input — Clear Button ---------- */
(function () {
    const searchInputs = document.querySelectorAll('.search-input-wrap input[type="search"], .search-input-wrap input[type="text"]');
    searchInputs.forEach(function (input) {
        // nothing extra needed — browser handles type=search clear; type=text handled by filter form
    });
})();

/* ---------- Tooltip Initialisation ---------- */
(function () {
    const tooltipEls = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipEls.forEach(function (el) {
        new bootstrap.Tooltip(el, { trigger: 'hover' });
    });
})();
