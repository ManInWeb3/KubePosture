// Shared UI behaviors — sortable tables + row filtering.
//
// Markup contract (kept minimal so templates stay declarative):
//
//   <table data-sortable>              ← opt-in: auto-init sort on click
//     <thead><tr>
//       <th class="sortable sort-asc">A</th>
//       <th class="sortable">B</th>
//     </tr></thead>
//     <tbody>
//       <tr data-emptystate>…</tr>     ← optional: empty-state row, never sorted/filtered
//       <tr data-priority="immediate" data-fix="yes">…</tr>
//     </tbody>
//   </table>
//
//   <!-- Cells may carry data-sort="<numeric>" to override textContent; -->
//   <!-- used for priority/severity rank + EPSS + KEV boolean. -->
//
// Row-filter contract:
//
//   <select data-filter-table="my-table" data-filter-attr="priority">
//     <option value="">all</option>
//     <option value="immediate">IMMEDIATE</option>
//   </select>
//   <button type="button" data-filter-reset="my-table">Reset</button>
//   <span data-filter-count="my-table">N</span>  ← live visible-rows count
//
// Rows are hidden when a select's value doesn't match the row's
// data-<attr>. Rows with `data-emptystate` are always visible (they're
// the "no rows" placeholder).

(function () {
  'use strict';

  // ── Sortable tables ───────────────────────────────────────────
  function getCellKey(cell) {
    if (cell && cell.dataset && cell.dataset.sort != null) return cell.dataset.sort;
    return (cell && cell.textContent ? cell.textContent : '').trim();
  }

  function compare(a, b) {
    var an = parseFloat(a), bn = parseFloat(b);
    if (Number.isFinite(an) && Number.isFinite(bn)) return an - bn;
    return a.localeCompare(b);
  }

  function initSortable(table) {
    var tbody = table.querySelector('tbody');
    if (!tbody) return;
    var headers = table.querySelectorAll('th.sortable');
    var dir = {};

    // Honor server-set default direction: dir reflects the CURRENT state
    // (true=asc, false=desc) so the next click correctly flips it.
    headers.forEach(function (th) {
      var col = Array.from(th.parentNode.children).indexOf(th);
      if (th.classList.contains('sort-asc')) dir[col] = true;
      else if (th.classList.contains('sort-desc')) dir[col] = false;
    });

    headers.forEach(function (th) {
      th.addEventListener('click', function () {
        var col = Array.from(th.parentNode.children).indexOf(th);
        var allRows = Array.from(tbody.querySelectorAll('tr'));
        var sortable = allRows.filter(function (r) { return !r.dataset.emptystate; });
        var fixed = allRows.filter(function (r) { return r.dataset.emptystate; });
        dir[col] = !dir[col];
        sortable.sort(function (a, b) {
          var cmp = compare(getCellKey(a.children[col]), getCellKey(b.children[col]));
          return dir[col] ? cmp : -cmp;
        });
        sortable.concat(fixed).forEach(function (r) { tbody.appendChild(r); });
        headers.forEach(function (h) { h.classList.remove('sort-asc', 'sort-desc'); });
        th.classList.add(dir[col] ? 'sort-asc' : 'sort-desc');
      });
    });
  }

  // ── Row filters (dropdown selects + text inputs that hide rows by data-attr) ──
  //
  // Extended markup contract:
  //   data-filter-mode="contains"   — row attr is comma-separated; match if value is in list
  //   data-filter-mode="substring"  — case-insensitive substring match (for <input> text search)
  //   (default)                     — exact match (original behavior)
  //
  //   Works with both <select> and <input> elements.
  function initTableFilters(tableId) {
    var table = document.getElementById(tableId);
    if (!table) return;
    var tbody = table.querySelector('tbody');
    var filters = document.querySelectorAll('[data-filter-table="' + tableId + '"][data-filter-attr]');
    if (!filters.length) return;
    var resetBtn = document.querySelector('button[data-filter-reset="' + tableId + '"]');
    var counter = document.querySelector('[data-filter-count="' + tableId + '"]');

    function apply() {
      var visible = 0;
      var rows = tbody ? tbody.querySelectorAll('tr') : [];
      rows.forEach(function (tr) {
        if (tr.dataset.emptystate) return;
        var show = true;
        filters.forEach(function (f) {
          var want = f.value;
          if (!want) return;
          var attr = f.dataset.filterAttr;
          var mode = f.dataset.filterMode || 'exact';
          var cell = tr.dataset[attr] || '';
          if (mode === 'contains') {
            if (cell.split(',').indexOf(want) === -1) show = false;
          } else if (mode === 'substring') {
            if (cell.toLowerCase().indexOf(want.toLowerCase()) === -1) show = false;
          } else {
            if (cell !== want) show = false;
          }
        });
        tr.hidden = !show;
        if (show) visible += 1;
      });
      if (counter) counter.textContent = visible;
    }

    filters.forEach(function (f) {
      var tag = f.tagName.toLowerCase();
      f.addEventListener(tag === 'input' ? 'input' : 'change', apply);
    });
    if (resetBtn) {
      resetBtn.addEventListener('click', function () {
        filters.forEach(function (f) { f.value = ''; });
        apply();
      });
    }

    // Apply on load so pre-selected filter values take effect immediately.
    apply();
  }

  function initIfNeeded(table) {
    if (table.dataset.sortableInited === '1') return;
    initSortable(table);
    table.dataset.sortableInited = '1';
  }

  function initFilterGroups(root) {
    var seen = new Set();
    (root || document).querySelectorAll('[data-filter-table]').forEach(function (el) {
      var id = el.getAttribute('data-filter-table');
      if (id && !seen.has(id)) { seen.add(id); initTableFilters(id); }
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('table[data-sortable]').forEach(initIfNeeded);
    initFilterGroups(document);
  });

  // Re-init after HTMX swaps so partial-loaded tables are wired too.
  document.addEventListener('htmx:afterSwap', function (e) {
    var scope = e.target || document;
    if (scope.querySelectorAll) {
      scope.querySelectorAll('table[data-sortable]').forEach(initIfNeeded);
    }
    // Also catch the case where the swap target itself IS a sortable table.
    if (scope.matches && scope.matches('table[data-sortable]')) initIfNeeded(scope);
  });
})();
