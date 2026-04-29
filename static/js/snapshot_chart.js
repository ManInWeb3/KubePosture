/* Shared ApexCharts factory for Snapshot trend blocks.
 *
 * Used by:
 *   - workloads/list.html       — global / per-cluster trend
 *   - workloads/detail.html     — per-workload trend with image-set events
 *
 * Backend: GET /api/v1/snapshots/series/?scope=...
 * Response shape (see core/api/views_snapshot.py):
 *   { scope_kind, captured_at[], totals[], severity{}, priority{}, events[] }
 */
(function (global) {
  "use strict";

  // Severity color tokens — aligned to Tabler badges in templates.
  var SEVERITY_COLORS = {
    critical: "#d63939", // red
    high:     "#f76707", // orange
    medium:   "#f59f00", // yellow
    low:      "#206bc4", // azure
    info:     "#74c0fc", // blue-light
    unknown:  "#adb5bd", // gray
  };
  var SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];

  var PRIORITY_COLORS = {
    immediate:    "#d63939",
    out_of_cycle: "#f76707",
    scheduled:    "#206bc4",
    defer:        "#adb5bd",
  };
  var PRIORITY_ORDER = ["immediate", "out_of_cycle", "scheduled", "defer"];
  var PRIORITY_LABELS = {
    immediate: "Immediate",
    out_of_cycle: "Out-of-Cycle",
    scheduled: "Scheduled",
    defer: "Defer",
  };

  function buildSeries(data, stack) {
    var keys = stack === "priority" ? PRIORITY_ORDER : SEVERITY_ORDER;
    var bag = stack === "priority" ? data.priority : data.severity;
    var colors = stack === "priority" ? PRIORITY_COLORS : SEVERITY_COLORS;
    var labels = stack === "priority" ? PRIORITY_LABELS : null;

    var series = [];
    var palette = [];
    keys.forEach(function (k) {
      var arr = (bag && bag[k]) || [];
      // Skip series that are all zero — keeps the legend tight.
      var anyNonZero = arr.some(function (n) { return n > 0; });
      if (!anyNonZero) return;
      series.push({
        name: labels ? labels[k] : (k.charAt(0).toUpperCase() + k.slice(1)),
        data: arr,
      });
      palette.push(colors[k]);
    });
    return { series: series, palette: palette };
  }

  function buildAnnotations(events, capturedAt) {
    if (!events || !events.length) return { xaxis: [] };
    // Map captured_at → numeric x position by index for clean alignment.
    var idxByTs = {};
    capturedAt.forEach(function (ts, i) { idxByTs[ts] = i; });
    var xann = events.map(function (ev) {
      var idx = idxByTs[ev.captured_at];
      if (idx === undefined) return null;
      return {
        x: new Date(ev.captured_at).getTime(),
        strokeDashArray: 4,
        borderColor: "#206bc4",
        label: {
          borderColor: "#206bc4",
          style: { color: "#fff", background: "#206bc4" },
          text: ev.change_kind,
        },
      };
    }).filter(Boolean);
    return { xaxis: xann };
  }

  function timestampSeries(captured_at, series) {
    // ApexCharts area chart with a datetime x-axis wants
    // [{x: ts, y: value}, ...] pairs.
    return series.map(function (s) {
      return {
        name: s.name,
        data: s.data.map(function (v, i) {
          return { x: new Date(captured_at[i]).getTime(), y: v };
        }),
      };
    });
  }

  function emptyState(el, msg) {
    el.innerHTML = (
      '<div class="text-center text-muted py-5">' +
      '<div>' + (msg || "No snapshots in window.") + '</div>' +
      '<div class="small mt-1">Run <code>python manage.py snapshot_capture</code> ' +
      'or trigger an import to populate the trend.</div>' +
      '</div>'
    );
  }

  function render(opts) {
    var el = document.getElementById(opts.elId);
    if (!el) return;
    var stack = opts.stack || "severity";

    var url = "/api/v1/snapshots/series/?scope=" + encodeURIComponent(opts.scope);
    Object.keys(opts.params || {}).forEach(function (k) {
      var v = opts.params[k];
      if (v === undefined || v === null || v === "") return;
      url += "&" + encodeURIComponent(k) + "=" + encodeURIComponent(v);
    });

    el.innerHTML = '<div class="text-center text-muted py-4">Loading…</div>';

    fetch(url, {
      credentials: "same-origin",
      headers: { "Accept": "application/json" },
    })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (data) {
        if (!data.captured_at || !data.captured_at.length) {
          emptyState(el);
          return;
        }
        var built = buildSeries(data, stack);
        if (!built.series.length) {
          emptyState(el, "All series are zero in this window.");
          return;
        }
        var ts = timestampSeries(data.captured_at, built.series);
        var annotations = (opts.scope === "workload")
          ? buildAnnotations(data.events, data.captured_at)
          : { xaxis: [] };

        var dim = document.documentElement.getAttribute("data-bs-theme") === "dim";

        var chart = new ApexCharts(el, {
          chart: {
            type: "area",
            height: opts.height || 280,
            stacked: true,
            toolbar: { show: false },
            zoom: { enabled: false },
            background: "transparent",
            animations: { enabled: false },
          },
          theme: { mode: dim ? "dark" : "light" },
          series: ts,
          colors: built.palette,
          stroke: { curve: "stepline", width: 1 },
          fill: {
            type: "gradient",
            gradient: { opacityFrom: 0.55, opacityTo: 0.15 },
          },
          dataLabels: { enabled: false },
          xaxis: {
            type: "datetime",
            labels: { datetimeUTC: false },
          },
          yaxis: {
            labels: {
              formatter: function (v) { return Math.round(v); },
            },
            title: { text: "Active findings" },
          },
          legend: { position: "top", horizontalAlign: "right" },
          tooltip: { x: { format: "yyyy-MM-dd HH:mm" } },
          annotations: annotations,
          grid: { borderColor: dim ? "#373e47" : "#e9ecef" },
        });
        chart.render();
        el._snapshotChart = chart;
      })
      .catch(function (err) {
        el.innerHTML = (
          '<div class="text-center text-danger py-4">' +
          'Failed to load trend: ' + (err && err.message || err) +
          '</div>'
        );
      });
  }

  global.renderSnapshotChart = render;
})(window);
