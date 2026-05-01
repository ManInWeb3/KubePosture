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

  // Right-edge pad past the last snapshot. ApexCharts auto-pads datetime
  // axes by ~10-15% of the data range when no min/max is set; for a 90-day
  // window that's ~12 days of empty space, which buries the latest tick.
  var FUTURE_PAD_MS = 12 * 60 * 60 * 1000;
  var HOUR_MS = 60 * 60 * 1000;
  var DAY_MS = 24 * HOUR_MS;

  // Map an interval token to the chart window + matching API days param.
  //   1d → rolling 24-hour view, future-pad 6h
  //   1w → 7 calendar days starting at midnight of the oldest day, future-pad 12h
  //   2w → same but 14 days
  // Returns null for unknown tokens so the caller can fall back to the
  // legacy "show every datapoint we got back" behaviour.
  function intervalBounds(interval) {
    var now = Date.now();
    if (interval === "1d") {
      return {
        xMin: now - 24 * HOUR_MS,
        xMax: now + 6 * HOUR_MS,
        padMs: 6 * HOUR_MS,
        days: 2,
      };
    }
    var lookback = interval === "2w" ? 14 : (interval === "1w" ? 7 : 0);
    if (!lookback) return null;
    var oldest = new Date();
    oldest.setDate(oldest.getDate() - (lookback - 1));
    oldest.setHours(0, 0, 0, 0);
    return {
      xMin: oldest.getTime(),
      xMax: now + 12 * HOUR_MS,
      padMs: 12 * HOUR_MS,
      days: lookback + 1,
    };
  }

  // Severity color tokens — aligned to Tabler badges in templates.
  var SEVERITY_COLORS = {
    critical: "#d63939", // red
    high:     "#f76707", // orange
    medium:   "#f59f00", // yellow
    low:      "#206bc4", // azure
    info:     "#adb5bd", // gray
    unknown:  "#adb5bd", // gray
  };
  var SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];

  var PRIORITY_COLORS = {
    immediate:    "#d63939", // red
    out_of_band:  "#f76707", // orange
    scheduled:    "#f59f00", // yellow
    defer:        "#adb5bd", // gray
  };
  var PRIORITY_ORDER = ["immediate", "out_of_band", "scheduled", "defer"];
  var PRIORITY_LABELS = {
    immediate: "Immediate",
    out_of_band: "Out-of-Band",
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

  function timestampSeries(captured_at, series, padToTs) {
    // ApexCharts area chart with a datetime x-axis wants
    // [{x: ts, y: value}, ...] pairs. `padToTs` extends each series
    // by one duplicate point at the right-edge pad so the latest
    // state stays visible across the future-pad gap.
    return series.map(function (s) {
      var data = s.data.map(function (v, i) {
        return { x: new Date(captured_at[i]).getTime(), y: v };
      });
      if (padToTs && data.length) {
        data.push({ x: padToTs, y: data[data.length - 1].y });
      }
      return { name: s.name, data: data };
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

  function buildChart(el, data, opts) {
    var stack = opts.stack || "severity";

    if (!data.captured_at || !data.captured_at.length) {
      emptyState(el);
      return;
    }
    var built = buildSeries(data, stack);
    if (!built.series.length) {
      emptyState(el, "All series are zero in this window.");
      return;
    }
    var bounds = opts.bounds || null;
    var firstX = new Date(data.captured_at[0]).getTime();
    var lastX = new Date(data.captured_at[data.captured_at.length - 1]).getTime();
    var padMs = bounds ? bounds.padMs : FUTURE_PAD_MS;
    // Pad-point lands at the chart's right edge so the dashed forecast
    // segment extends all the way to xMax (no gap between last real
    // datapoint and the right boundary).
    var xMax = bounds ? bounds.xMax : (lastX + padMs);
    var xMin = bounds ? bounds.xMin : firstX;
    var padToX = xMax;
    var ts = timestampSeries(data.captured_at, built.series, padToX);
    var annotations = (opts.scope === "workload")
      ? buildAnnotations(data.events, data.captured_at)
      : { xaxis: [] };

    var theme = document.documentElement.getAttribute("data-bs-theme");
    var dark = theme === "dim" || theme === "dark";

    el.innerHTML = "";  // clear any "Loading…" placeholder
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
      theme: { mode: dark ? "dark" : "light" },
      series: ts,
      colors: built.palette,
      stroke: { curve: "stepline", width: 1 },
      fill: {
        type: "gradient",
        gradient: { opacityFrom: 0.55, opacityTo: 0.15 },
      },
      forecastDataPoints: {
        count: 1,
        dashArray: 4,
        fillOpacity: 0.3,
      },
      dataLabels: { enabled: false },
      xaxis: {
        type: "datetime",
        min: xMin,
        max: xMax,
        labels: { datetimeUTC: false },
      },
      yaxis: {
        labels: {
          formatter: function (v) { return Math.round(v); },
        },
        title: { text: "Active findings" },
      },
      legend: { position: "top", horizontalAlign: "right" },
      tooltip: {
        x: {
          formatter: function (val) {
            return new Date(val).toLocaleString(undefined, {
              year: "numeric", month: "short", day: "2-digit",
              hour: "2-digit", minute: "2-digit",
            });
          },
        },
      },
      annotations: annotations,
      grid: { borderColor: dark ? "#373e47" : "#e9ecef" },
    });
    chart.render();
    el._snapshotChart = chart;
  }

  function render(opts) {
    var el = document.getElementById(opts.elId);
    if (!el) return;

    // Tear down any prior ApexCharts instance bound to this element.
    // Without this, repeated render() calls (stack toggle, filter
    // change) leak listeners and produce stale tooltips.
    if (el._snapshotChart) {
      try { el._snapshotChart.destroy(); } catch (e) { /* ignore */ }
      el._snapshotChart = null;
    }

    // Resolve interval → bounds + matching API days. Bounds get
    // attached to opts so buildChart sees them; params.days is
    // overridden so the API window matches the visible window.
    var bounds = intervalBounds(opts.interval);
    var params = {};
    Object.keys(opts.params || {}).forEach(function (k) { params[k] = opts.params[k]; });
    if (bounds) {
      params.days = bounds.days;
      opts.bounds = bounds;
    }

    var url = "/api/v1/snapshots/series/?scope=" + encodeURIComponent(opts.scope);
    Object.keys(params).forEach(function (k) {
      var v = params[k];
      if (v === undefined || v === null || v === "") return;
      url += "&" + encodeURIComponent(k) + "=" + encodeURIComponent(v);
    });

    // Stack toggles change presentation only — same URL ⇒ reuse cached
    // payload instead of re-fetching.
    if (el._snapshotUrl === url && el._snapshotData) {
      buildChart(el, el._snapshotData, opts);
      return;
    }

    // Token guards against stale fetches: when the user toggles filters
    // quickly, an older response settling later must not overwrite the
    // newer one's cache, or the next render with the same (newer) URL
    // would short-circuit to bad data.
    el._snapshotToken = (el._snapshotToken || 0) + 1;
    var token = el._snapshotToken;

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
        if (token !== el._snapshotToken) return;
        el._snapshotUrl = url;
        el._snapshotData = data;
        buildChart(el, data, opts);
      })
      .catch(function (err) {
        if (token !== el._snapshotToken) return;
        el.innerHTML = (
          '<div class="text-center text-danger py-4">' +
          'Failed to load trend: ' + (err && err.message || err) +
          '</div>'
        );
      });
  }

  global.renderSnapshotChart = render;
})(window);
