"""Self-contained, offline-ready interactive HTML report generator."""

from __future__ import annotations

import html
import json
import os
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sift.models import NormalizedFinding, PriorityTier

_CSP_POLICY = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
    "base-uri 'none'; form-action 'none';"
)

_INLINE_CSS = """
:root {
  --bg: #f6f8fa;
  --surface: #ffffff;
  --surface-alt: #f0f3f7;
  --border: #d0d7de;
  --text: #1f2328;
  --text-muted: #57606a;
  --accent: #0969da;
  --accent-soft: #ddf4ff;
  --p1-bg: #cf222e;
  --p1-fg: #ffffff;
  --p1-soft: #ffebe9;
  --p1-text: #a40e26;
  --p2-bg: #bf8700;
  --p2-fg: #ffffff;
  --p2-soft: #fff8c5;
  --p2-text: #7d4e00;
  --p3-bg: #0969da;
  --p3-fg: #ffffff;
  --p3-soft: #ddf4ff;
  --p3-text: #0550ae;
  --p4-bg: #6e7781;
  --p4-fg: #ffffff;
  --p4-soft: #eaeef2;
  --p4-text: #424a53;
  --kev-bg: #82071e;
  --kev-fg: #ffffff;
  --kev-soft: #ffdce0;
  --kev-text: #82071e;
  --warn-bg: #fff8c5;
  --warn-border: #d4a72c;
  --warn-text: #633c01;
  --row-hover: #f3f6fa;
  --shadow: 0 1px 3px rgba(31, 35, 40, 0.08);
}

[data-theme="dark"] {
  --bg: #0d1117;
  --surface: #161b22;
  --surface-alt: #1f2630;
  --border: #30363d;
  --text: #e6edf3;
  --text-muted: #8b949e;
  --accent: #58a6ff;
  --accent-soft: #132c47;
  --p1-bg: #da3633;
  --p1-fg: #ffffff;
  --p1-soft: #3c1618;
  --p1-text: #ff7b72;
  --p2-bg: #d29922;
  --p2-fg: #0d1117;
  --p2-soft: #3b2a08;
  --p2-text: #e3b341;
  --p3-bg: #388bfd;
  --p3-fg: #ffffff;
  --p3-soft: #132c47;
  --p3-text: #79c0ff;
  --p4-bg: #6e7681;
  --p4-fg: #ffffff;
  --p4-soft: #262c36;
  --p4-text: #adbac7;
  --kev-bg: #b62324;
  --kev-fg: #ffffff;
  --kev-soft: #3f1419;
  --kev-text: #ffa198;
  --warn-bg: #332609;
  --warn-border: #9e6a03;
  --warn-text: #f2cc60;
  --row-hover: #1c222b;
  --shadow: 0 1px 4px rgba(0, 0, 0, 0.35);
}

*, *::before, *::after { box-sizing: border-box; }

body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

.container {
  max-width: 1360px;
  margin: 0 auto;
  padding: 24px 20px 48px;
}

.header {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--border);
}

.title-group h1 {
  margin: 0 0 6px;
  font-size: 1.5rem;
  font-weight: 700;
  letter-spacing: -0.01em;
}

.meta-line {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  font-size: 0.85rem;
  color: var(--text-muted);
}

.header-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 7px 12px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.15s ease, border-color 0.15s ease;
}

.btn:hover { background: var(--surface-alt); }
.btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

.warnings-banner {
  margin-bottom: 20px;
  padding: 12px 16px;
  border-radius: 8px;
  border: 1px solid var(--warn-border);
  background: var(--warn-bg);
  color: var(--warn-text);
  font-size: 0.875rem;
}

.warnings-banner strong { display: block; margin-bottom: 4px; }
.warnings-banner ul { margin: 0; padding-left: 20px; }

.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(165px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}

.kpi-card {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  width: 100%;
  padding: 14px 16px;
  border-radius: 10px;
  border: 1px solid var(--border);
  border-top: 4px solid var(--border);
  background: var(--surface);
  color: var(--text);
  box-shadow: var(--shadow);
  text-align: left;
  cursor: pointer;
  transition: transform 0.12s ease, border-color 0.15s ease;
}

.kpi-card:hover { transform: translateY(-1px); }
.kpi-card:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.kpi-card.is-active { box-shadow: 0 0 0 2px var(--accent); }

.kpi-card[data-filter="ALL"] { border-top-color: var(--accent); }
.kpi-card[data-filter="P1"] { border-top-color: var(--p1-bg); }
.kpi-card[data-filter="P2"] { border-top-color: var(--p2-bg); }
.kpi-card[data-filter="P3"] { border-top-color: var(--p3-bg); }
.kpi-card[data-filter="P4"] { border-top-color: var(--p4-bg); }
.kpi-card[data-filter="KEV"] { border-top-color: var(--kev-bg); }

.kpi-label {
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-muted);
}

.kpi-value {
  margin-top: 4px;
  font-size: 1.75rem;
  font-weight: 700;
  line-height: 1.15;
}

.kpi-card[data-filter="P1"] .kpi-value { color: var(--p1-text); }
.kpi-card[data-filter="P2"] .kpi-value { color: var(--p2-text); }
.kpi-card[data-filter="P3"] .kpi-value { color: var(--p3-text); }
.kpi-card[data-filter="P4"] .kpi-value { color: var(--p4-text); }
.kpi-card[data-filter="KEV"] .kpi-value { color: var(--kev-text); }

.controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
  padding: 12px 14px;
  border-radius: 10px;
  border: 1px solid var(--border);
  background: var(--surface);
  box-shadow: var(--shadow);
}

.search-wrap {
  flex: 1 1 280px;
  min-width: 220px;
}

.search-input {
  width: 100%;
  padding: 8px 12px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg);
  color: var(--text);
  font-size: 0.9rem;
}

.search-input:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 2px var(--accent-soft);
}

.filter-group {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.filter-btn {
  padding: 6px 11px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--bg);
  color: var(--text);
  font-size: 0.82rem;
  font-weight: 600;
  cursor: pointer;
  transition: background-color 0.15s ease, color 0.15s ease, border-color 0.15s ease;
}

.filter-btn:hover { background: var(--surface-alt); }
.filter-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

.filter-btn.is-active {
  background: var(--accent);
  border-color: var(--accent);
  color: #ffffff;
}

.filter-btn[data-filter="P1"].is-active {
  background: var(--p1-bg);
  border-color: var(--p1-bg);
  color: var(--p1-fg);
}

.filter-btn[data-filter="P2"].is-active {
  background: var(--p2-bg);
  border-color: var(--p2-bg);
  color: var(--p2-fg);
}

.filter-btn[data-filter="P3"].is-active {
  background: var(--p3-bg);
  border-color: var(--p3-bg);
  color: var(--p3-fg);
}

.filter-btn[data-filter="P4"].is-active {
  background: var(--p4-bg);
  border-color: var(--p4-bg);
  color: var(--p4-fg);
}

.filter-btn[data-filter="KEV"].is-active {
  background: var(--kev-bg);
  border-color: var(--kev-bg);
  color: var(--kev-fg);
}

.results-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
  font-size: 0.84rem;
  color: var(--text-muted);
}

.table-card {
  border-radius: 10px;
  border: 1px solid var(--border);
  background: var(--surface);
  box-shadow: var(--shadow);
  overflow-x: auto;
}

table.findings-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.findings-table thead th {
  position: sticky;
  top: 0;
  padding: 11px 12px;
  background: var(--surface-alt);
  border-bottom: 1px solid var(--border);
  text-align: left;
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  color: var(--text-muted);
  white-space: nowrap;
}

.findings-table th.num,
.findings-table td.num { text-align: right; }

.findings-table th.center,
.findings-table td.center { text-align: center; }

.sort-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 0;
  border: 0;
  background: transparent;
  color: inherit;
  font: inherit;
  text-transform: inherit;
  letter-spacing: inherit;
  cursor: pointer;
}

.sort-btn:hover { color: var(--text); }
.sort-indicator { font-size: 0.72rem; opacity: 0.65; }
th[aria-sort="ascending"] .sort-indicator,
th[aria-sort="descending"] .sort-indicator { opacity: 1; color: var(--accent); }

.finding-row {
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  transition: background-color 0.12s ease;
}

.finding-row:hover { background: var(--row-hover); }
.finding-row:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }

.finding-row td {
  padding: 10px 12px;
  vertical-align: middle;
}

.chevron-cell {
  width: 28px;
  text-align: center;
  color: var(--text-muted);
  font-size: 0.8rem;
  user-select: none;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.82rem;
}

.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 700;
  white-space: nowrap;
}

.badge-p1 { background: var(--p1-soft); color: var(--p1-text); }
.badge-p2 { background: var(--p2-soft); color: var(--p2-text); }
.badge-p3 { background: var(--p3-soft); color: var(--p3-text); }
.badge-p4 { background: var(--p4-soft); color: var(--p4-text); }
.badge-kev { background: var(--kev-bg); color: var(--kev-fg); }

.scanner-chip {
  display: inline-block;
  margin: 2px 4px 2px 0;
  padding: 2px 7px;
  border-radius: 5px;
  border: 1px solid var(--border);
  background: var(--surface-alt);
  color: var(--text);
  font-size: 0.75rem;
  font-weight: 600;
}

.detail-row {
  border-bottom: 1px solid var(--border);
  background: var(--bg);
}

.detail-row.is-hidden { display: none; }

.detail-panel {
  padding: 14px 18px 16px 40px;
  display: grid;
  gap: 12px;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 10px 18px;
}

.detail-label {
  font-size: 0.74rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-muted);
  margin-bottom: 3px;
}

.detail-text {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 0.875rem;
}

.ref-list {
  margin: 0;
  padding-left: 18px;
  font-size: 0.82rem;
}

.ref-list a {
  color: var(--accent);
  word-break: break-all;
}

.empty-state {
  padding: 36px 20px;
  text-align: center;
  color: var(--text-muted);
  font-size: 0.95rem;
}

.footer {
  margin-top: 24px;
  text-align: center;
  font-size: 0.78rem;
  color: var(--text-muted);
}

@media print {
  :root,
  [data-theme="dark"] {
    --bg: #ffffff;
    --surface: #ffffff;
    --surface-alt: #f4f6f8;
    --border: #c5ccd3;
    --text: #111111;
    --text-muted: #444444;
    --accent: #0969da;
    --p1-soft: #ffebe9;
    --p1-text: #8b0000;
    --p2-soft: #fff8c5;
    --p2-text: #6e4500;
    --p3-soft: #ddf4ff;
    --p3-text: #0550ae;
    --p4-soft: #eaeef2;
    --p4-text: #333333;
    --kev-bg: #82071e;
    --kev-fg: #ffffff;
    --shadow: none;
  }

  body { background: #ffffff; color: #111111; }
  .container { max-width: 100%; padding: 0; }
  .header-actions, .controls, .chevron-cell, .col-chevron { display: none !important; }
  .table-card { overflow: visible; box-shadow: none; border: 1px solid #c5ccd3; }
  .kpi-card { box-shadow: none; break-inside: avoid; }
  .finding-row, .detail-row { break-inside: avoid; }
  .detail-row.is-hidden { display: table-row; }
  .detail-panel { padding: 8px 12px; }
}
""".strip()

_INLINE_JS = """
(function () {
  "use strict";

  var dataEl = document.getElementById("sift-findings-data");
  var findings = [];
  try {
    findings = JSON.parse((dataEl && dataEl.textContent) || "[]");
  } catch (err) {
    findings = [];
  }

  var state = {
    filter: "ALL",
    query: "",
    sortKey: "priority",
    sortDir: "asc",
    expanded: {}
  };

  var tbody = document.getElementById("findings-tbody");
  var searchInput = document.getElementById("search-input");
  var resultsCount = document.getElementById("results-count");
  var filterButtons = Array.prototype.slice.call(
    document.querySelectorAll("[data-filter]")
  );
  var sortButtons = Array.prototype.slice.call(
    document.querySelectorAll("[data-sort-key]")
  );
  var themeToggle = document.getElementById("theme-toggle");
  var printBtn = document.getElementById("print-btn");

  function getPreferredTheme() {
    try {
      var saved = window.localStorage.getItem("sift-report-theme");
      if (saved === "dark" || saved === "light") {
        return saved;
      }
    } catch (e) {
      /* ignore storage restrictions */
    }
    if (
      window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: dark)").matches
    ) {
      return "dark";
    }
    return "light";
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    if (themeToggle) {
      themeToggle.textContent = theme === "dark" ? "Light Mode" : "Dark Mode";
      themeToggle.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
    }
    try {
      window.localStorage.setItem("sift-report-theme", theme);
    } catch (e) {
      /* ignore storage restrictions */
    }
  }

  applyTheme(getPreferredTheme());

  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      var current = document.documentElement.getAttribute("data-theme");
      applyTheme(current === "dark" ? "light" : "dark");
    });
  }

  if (printBtn) {
    printBtn.addEventListener("click", function () {
      window.print();
    });
  }

  function isSafeHttpUrl(url) {
    if (typeof url !== "string") {
      return false;
    }
    try {
      var parsed = new URL(url);
      return (
        (parsed.protocol === "http:" || parsed.protocol === "https:") &&
        Boolean(parsed.hostname)
      );
    } catch (e) {
      return false;
    }
  }

  function formatCvss(score) {
    return typeof score === "number" ? score.toFixed(1) : "-";
  }

  function formatEpss(score) {
    return typeof score === "number" ? (score * 100).toFixed(1) + "%" : "-";
  }

  function matchesFilter(item) {
    if (state.filter === "KEV") {
      return Boolean(item.in_kev);
    }
    if (state.filter !== "ALL" && item.priority !== state.filter) {
      return false;
    }
    return true;
  }

  function matchesQuery(item) {
    if (!state.query) {
      return true;
    }
    var haystack = [
      item.identifier || "",
      item.cve_id || "",
      item.rule_id || "",
      item.target || "",
      item.service || "",
      item.description || "",
      item.priority_reason || "",
      (item.scanner_sources || []).join(" ")
    ]
      .join(" ")
      .toLowerCase();
    return haystack.indexOf(state.query) !== -1;
  }

  function compareNullableNumber(a, b, dir) {
    var aNull = typeof a !== "number";
    var bNull = typeof b !== "number";
    if (aNull && bNull) {
      return 0;
    }
    if (aNull) {
      return 1;
    }
    if (bNull) {
      return -1;
    }
    return dir === "asc" ? a - b : b - a;
  }

  function sortItems(items) {
    var key = state.sortKey;
    var dir = state.sortDir;
    return items.slice().sort(function (a, b) {
      var cmp = 0;
      if (key === "priority") {
        cmp = dir === "asc"
          ? a.priority_rank - b.priority_rank
          : b.priority_rank - a.priority_rank;
      } else if (key === "cvss") {
        cmp = compareNullableNumber(a.cvss_score, b.cvss_score, dir);
      } else if (key === "epss") {
        cmp = compareNullableNumber(a.epss_score, b.epss_score, dir);
      } else if (key === "kev") {
        var aKev = a.in_kev ? 1 : 0;
        var bKev = b.in_kev ? 1 : 0;
        cmp = dir === "asc" ? aKev - bKev : bKev - aKev;
      } else if (key === "target") {
        cmp = (a.target || "").localeCompare(b.target || "");
        if (dir === "desc") {
          cmp = -cmp;
        }
      }
      if (cmp !== 0) {
        return cmp;
      }
      return a.index - b.index;
    });
  }

  function createEl(tag, className, text) {
    var el = document.createElement(tag);
    if (className) {
      el.className = className;
    }
    if (text !== undefined && text !== null) {
      el.textContent = String(text);
    }
    return el;
  }

  function createDetailField(label, valueText, isMono) {
    var box = createEl("div");
    box.appendChild(createEl("div", "detail-label", label));
    box.appendChild(
      createEl("p", isMono ? "detail-text mono" : "detail-text", valueText)
    );
    return box;
  }

  function buildDetailRow(item, isOpen) {
    var tr = createEl("tr", isOpen ? "detail-row" : "detail-row is-hidden");
    tr.setAttribute("data-detail-for", String(item.index));

    var td = document.createElement("td");
    td.colSpan = 10;

    var panel = createEl("div", "detail-panel");

    var descBox = createEl("div");
    descBox.appendChild(createEl("div", "detail-label", "Description"));
    descBox.appendChild(
      createEl("p", "detail-text", item.description || "No description provided.")
    );
    panel.appendChild(descBox);

    var grid = createEl("div", "detail-grid");

    var scannersBox = createEl("div");
    scannersBox.appendChild(createEl("div", "detail-label", "Scanner Sources"));
    var chipsWrap = createEl("div");
    var sources = item.scanner_sources || [];
    for (var i = 0; i < sources.length; i++) {
      chipsWrap.appendChild(createEl("span", "scanner-chip", sources[i]));
    }
    scannersBox.appendChild(chipsWrap);
    grid.appendChild(scannersBox);

    grid.appendChild(
      createDetailField("Priority Rationale", item.priority_reason || "-", false)
    );

    if (item.rule_id && item.cve_id) {
      grid.appendChild(createDetailField("Rule ID", item.rule_id, true));
    }
    if (item.fixed_version) {
      grid.appendChild(createDetailField("Fixed Version", item.fixed_version, true));
    }
    if (typeof item.epss_percentile === "number") {
      grid.appendChild(
        createDetailField(
          "EPSS Percentile",
          (item.epss_percentile * 100).toFixed(1) + "%",
          true
        )
      );
    }
    if (item.in_kev) {
      var kevParts = ["Listed in CISA KEV"];
      if (item.kev_date_added) {
        kevParts.push("Added: " + item.kev_date_added);
      }
      if (item.kev_due_date) {
        kevParts.push("Due: " + item.kev_due_date);
      }
      if (item.kev_ransomware_use === true) {
        kevParts.push("Known Ransomware Use");
      }
      grid.appendChild(createDetailField("CISA KEV Details", kevParts.join(" | "), false));
    }

    panel.appendChild(grid);

    if (item.references && item.references.length > 0) {
      var refsBox = createEl("div");
      refsBox.appendChild(createEl("div", "detail-label", "References"));
      var ul = createEl("ul", "ref-list");
      for (var r = 0; r < item.references.length; r++) {
        var ref = item.references[r];
        var li = document.createElement("li");
        if (isSafeHttpUrl(ref)) {
          var link = document.createElement("a");
          link.href = ref;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          link.textContent = ref;
          li.appendChild(link);
        } else {
          li.textContent = ref;
        }
        ul.appendChild(li);
      }
      refsBox.appendChild(ul);
      panel.appendChild(refsBox);
    }

    td.appendChild(panel);
    tr.appendChild(td);
    return tr;
  }

  function buildFindingRow(item, isOpen) {
    var tr = createEl("tr", "finding-row");
    tr.tabIndex = 0;
    tr.setAttribute("aria-expanded", isOpen ? "true" : "false");

    var chevTd = createEl("td", "chevron-cell", isOpen ? "\u25bc" : "\u25b8");
    tr.appendChild(chevTd);

    var prioTd = document.createElement("td");
    var badgeClass = "badge badge-" + (item.priority || "p4").toLowerCase();
    prioTd.appendChild(
      createEl("span", badgeClass, item.priority + " (" + item.priority_label + ")")
    );
    tr.appendChild(prioTd);

    tr.appendChild(createEl("td", "mono", item.target));
    tr.appendChild(
      createEl("td", "num mono", item.port !== null && item.port !== undefined ? item.port : "-")
    );
    tr.appendChild(createEl("td", "", item.service || "-"));
    tr.appendChild(createEl("td", "mono", item.identifier || "N/A"));
    tr.appendChild(createEl("td", "num mono", formatCvss(item.cvss_score)));
    tr.appendChild(createEl("td", "num mono", formatEpss(item.epss_score)));

    var kevTd = createEl("td", "center");
    if (item.in_kev) {
      kevTd.appendChild(createEl("span", "badge badge-kev", "KEV"));
    } else {
      kevTd.textContent = "-";
    }
    tr.appendChild(kevTd);

    var srcTd = document.createElement("td");
    var sources = item.scanner_sources || [];
    for (var s = 0; s < sources.length; s++) {
      srcTd.appendChild(createEl("span", "scanner-chip", sources[s]));
    }
    tr.appendChild(srcTd);

    function toggle() {
      state.expanded[item.index] = !state.expanded[item.index];
      render();
    }

    tr.addEventListener("click", toggle);
    tr.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        toggle();
      }
    });

    return tr;
  }

  function updateControls() {
    for (var i = 0; i < filterButtons.length; i++) {
      var btn = filterButtons[i];
      var active = btn.getAttribute("data-filter") === state.filter;
      btn.classList.toggle("is-active", active);
      btn.setAttribute("aria-pressed", active ? "true" : "false");
    }

    for (var j = 0; j < sortButtons.length; j++) {
      var sBtn = sortButtons[j];
      var th = sBtn.parentElement;
      var ind = sBtn.querySelector(".sort-indicator");
      var key = sBtn.getAttribute("data-sort-key");
      if (key === state.sortKey) {
        if (th) {
          th.setAttribute("aria-sort", state.sortDir === "asc" ? "ascending" : "descending");
        }
        if (ind) {
          ind.textContent = state.sortDir === "asc" ? "\u25b2" : "\u25bc";
        }
      } else {
        if (th) {
          th.setAttribute("aria-sort", "none");
        }
        if (ind) {
          ind.textContent = "\u2195";
        }
      }
    }
  }

  function render() {
    updateControls();
    if (!tbody) {
      return;
    }

    var filtered = [];
    for (var i = 0; i < findings.length; i++) {
      if (matchesFilter(findings[i]) && matchesQuery(findings[i])) {
        filtered.push(findings[i]);
      }
    }
    var sorted = sortItems(filtered);

    if (resultsCount) {
      resultsCount.textContent =
        "Showing " + sorted.length + " of " + findings.length + " findings";
    }

    while (tbody.firstChild) {
      tbody.removeChild(tbody.firstChild);
    }

    if (sorted.length === 0) {
      var emptyTr = document.createElement("tr");
      var emptyTd = createEl(
        "td",
        "empty-state",
        findings.length === 0
          ? "No findings matched the scan criteria."
          : "No findings match the current search or filter."
      );
      emptyTd.colSpan = 10;
      emptyTr.appendChild(emptyTd);
      tbody.appendChild(emptyTr);
      return;
    }

    var frag = document.createDocumentFragment();
    for (var k = 0; k < sorted.length; k++) {
      var item = sorted[k];
      var isOpen = Boolean(state.expanded[item.index]);
      frag.appendChild(buildFindingRow(item, isOpen));
      frag.appendChild(buildDetailRow(item, isOpen));
    }
    tbody.appendChild(frag);
  }

  for (var f = 0; f < filterButtons.length; f++) {
    filterButtons[f].addEventListener("click", function (ev) {
      var chosen = ev.currentTarget.getAttribute("data-filter") || "ALL";
      state.filter = chosen;
      render();
    });
  }

  if (searchInput) {
    searchInput.addEventListener("input", function () {
      state.query = (searchInput.value || "").trim().toLowerCase();
      render();
    });
  }

  for (var s = 0; s < sortButtons.length; s++) {
    sortButtons[s].addEventListener("click", function (ev) {
      var key = ev.currentTarget.getAttribute("data-sort-key");
      if (!key) {
        return;
      }
      if (state.sortKey === key) {
        state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
      } else {
        state.sortKey = key;
        state.sortDir = key === "cvss" || key === "epss" || key === "kev" ? "desc" : "asc";
      }
      render();
    });
  }

  render();
})();
""".strip()


def _escape_html(value: str) -> str:
    """Strictly escape untrusted text for safe interpolation into HTML."""
    return html.escape(value, quote=True)


def _serialize_json_for_html(payload: object) -> str:
    """Serialize JSON safely for embedding inside a <script type='application/json'> tag."""
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return (
        raw.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _is_safe_http_url(url: str) -> bool:
    """Return True only for absolute http:// or https:// URLs."""
    parsed = urlsplit(url.strip())
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)


def _finding_to_record(index: int, finding: NormalizedFinding) -> dict[str, Any]:
    """Convert a NormalizedFinding to a JSON-serializable dict for the client dashboard."""
    intel = finding.threat_intel
    fixed_version_raw = finding.metadata.get("fixed_version")
    fixed_version = str(fixed_version_raw) if fixed_version_raw is not None else None
    return {
        "index": index,
        "priority": finding.priority.value,
        "priority_rank": finding.priority.rank,
        "priority_label": finding.priority.label,
        "target": finding.target,
        "port": finding.port,
        "service": finding.service,
        "cve_id": finding.cve_id,
        "rule_id": finding.rule_id,
        "identifier": finding.cve_id or finding.rule_id or "N/A",
        "cvss_score": finding.cvss_score,
        "epss_score": intel.epss_score,
        "epss_percentile": intel.epss_percentile,
        "in_kev": intel.in_kev,
        "kev_date_added": intel.kev_date_added.isoformat() if intel.kev_date_added else None,
        "kev_due_date": intel.kev_due_date.isoformat() if intel.kev_due_date else None,
        "kev_ransomware_use": intel.kev_ransomware_use,
        "scanner_sources": list(finding.scanner_sources),
        "priority_reason": finding.priority_reason,
        "description": finding.description,
        "fixed_version": fixed_version,
        "references": list(finding.references),
    }


def _render_warnings_html(warnings: Sequence[str]) -> str:
    """Render an escaped warning callout banner if enrichment/pipeline warnings exist."""
    if not warnings:
        return ""
    items = "".join(f"<li>{_escape_html(warning)}</li>" for warning in warnings)
    return (
        '<section class="warnings-banner" role="alert">'
        "<strong>Warnings</strong>"
        f"<ul>{items}</ul>"
        "</section>"
    )


def _render_static_references_html(references: Sequence[str]) -> str:
    """Render escaped reference list items, only linking http/https URLs."""
    if not references:
        return ""
    items: list[str] = []
    for ref in references:
        escaped = _escape_html(ref)
        if _is_safe_http_url(ref):
            items.append(
                f'<li><a href="{escaped}" target="_blank" '
                f'rel="noopener noreferrer">{escaped}</a></li>'
            )
        else:
            items.append(f"<li>{escaped}</li>")
    return (
        "<div>"
        '<div class="detail-label">References</div>'
        f'<ul class="ref-list">{"".join(items)}</ul>'
        "</div>"
    )


def _render_static_rows_html(findings: Sequence[NormalizedFinding]) -> str:
    """Pre-render strictly escaped table rows for progressive enhancement (no-JS fallback)."""
    if not findings:
        return (
            '<tr><td colspan="10" class="empty-state">'
            "No findings matched the scan criteria."
            "</td></tr>"
        )

    rows: list[str] = []
    for idx, finding in enumerate(findings):
        intel = finding.threat_intel
        badge_cls = f"badge badge-{finding.priority.value.lower()}"
        priority_text = f"{finding.priority.value} ({finding.priority.label})"
        identifier = _escape_html(finding.cve_id or finding.rule_id or "N/A")
        port_str = str(finding.port) if finding.port is not None else "-"
        service_str = _escape_html(finding.service or "-")
        cvss_str = f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "-"
        epss_str = f"{intel.epss_score:.1%}" if intel.epss_score is not None else "-"
        kev_html = '<span class="badge badge-kev">KEV</span>' if finding.in_kev else "-"
        chips_html = "".join(
            f'<span class="scanner-chip">{_escape_html(src)}</span>'
            for src in finding.scanner_sources
        )
        desc_html = _escape_html(finding.description or "No description provided.")
        reason_html = _escape_html(finding.priority_reason or "-")
        refs_html = _render_static_references_html(finding.references)

        rows.append(
            f'<tr class="finding-row" tabindex="0" aria-expanded="false">'
            f'<td class="chevron-cell">&#9656;</td>'
            f'<td><span class="{badge_cls}">{_escape_html(priority_text)}</span></td>'
            f'<td class="mono">{_escape_html(finding.target)}</td>'
            f'<td class="num mono">{port_str}</td>'
            f"<td>{service_str}</td>"
            f'<td class="mono">{identifier}</td>'
            f'<td class="num mono">{cvss_str}</td>'
            f'<td class="num mono">{epss_str}</td>'
            f'<td class="center">{kev_html}</td>'
            f"<td>{chips_html}</td>"
            f"</tr>"
            f'<tr class="detail-row is-hidden" data-detail-for="{idx}">'
            f'<td colspan="10"><div class="detail-panel">'
            f'<div><div class="detail-label">Description</div>'
            f'<p class="detail-text">{desc_html}</p></div>'
            f'<div class="detail-grid">'
            f'<div><div class="detail-label">Scanner Sources</div><div>{chips_html}</div></div>'
            f'<div><div class="detail-label">Priority Rationale</div>'
            f'<p class="detail-text">{reason_html}</p></div>'
            f"</div>"
            f"{refs_html}"
            f"</div></td></tr>"
        )
    return "".join(rows)


def format_html(
    findings: Sequence[NormalizedFinding],
    *,
    raw_count: int | None = None,
    duplicates_merged: int = 0,
    warnings: Sequence[str] = (),
    generated_at: datetime | None = None,
) -> str:
    """Render prioritized findings as a self-contained, XSS-safe interactive HTML dashboard."""
    timestamp = (generated_at or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M:%S UTC")

    tier_counts: dict[PriorityTier, int] = {tier: 0 for tier in PriorityTier}
    for finding in findings:
        tier_counts[finding.priority] += 1
    kev_count = sum(1 for finding in findings if finding.in_kev)

    meta_parts = [f"<span>Generated: {_escape_html(timestamp)}</span>"]
    if raw_count is not None:
        meta_parts.append(f"<span>Raw Ingested: {raw_count}</span>")
        meta_parts.append(f"<span>Duplicates Merged: {duplicates_merged}</span>")

    records = [_finding_to_record(idx, finding) for idx, finding in enumerate(findings)]
    json_payload = _serialize_json_for_html(records)
    warnings_html = _render_warnings_html(warnings)
    static_rows_html = _render_static_rows_html(findings)

    total = len(findings)
    p1 = tier_counts[PriorityTier.P1]
    p2 = tier_counts[PriorityTier.P2]
    p3 = tier_counts[PriorityTier.P3]
    p4 = tier_counts[PriorityTier.P4]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="{_CSP_POLICY}">
  <title>sift &mdash; Vulnerability Prioritization Report</title>
  <style>{_INLINE_CSS}</style>
</head>
<body>
  <div class="container">
    <header class="header">
      <div class="title-group">
        <h1>sift &mdash; Vulnerability Prioritization Report</h1>
        <div class="meta-line">{"".join(meta_parts)}</div>
      </div>
      <div class="header-actions">
        <button id="theme-toggle" class="btn" type="button" aria-pressed="false">Dark Mode</button>
        <button id="print-btn" class="btn" type="button">Print / Save PDF</button>
      </div>
    </header>

    {warnings_html}

    <section class="kpi-grid" aria-label="Summary metrics">
      <button type="button" class="kpi-card is-active" data-filter="ALL" aria-pressed="true">
        <span class="kpi-label">Total Findings</span>
        <span class="kpi-value">{total}</span>
      </button>
      <button type="button" class="kpi-card" data-filter="P1" aria-pressed="false">
        <span class="kpi-label">P1 (Urgent)</span>
        <span class="kpi-value">{p1}</span>
      </button>
      <button type="button" class="kpi-card" data-filter="P2" aria-pressed="false">
        <span class="kpi-label">P2 (High)</span>
        <span class="kpi-value">{p2}</span>
      </button>
      <button type="button" class="kpi-card" data-filter="P3" aria-pressed="false">
        <span class="kpi-label">P3 (Medium)</span>
        <span class="kpi-value">{p3}</span>
      </button>
      <button type="button" class="kpi-card" data-filter="P4" aria-pressed="false">
        <span class="kpi-label">P4 (Low/Info)</span>
        <span class="kpi-value">{p4}</span>
      </button>
      <button type="button" class="kpi-card" data-filter="KEV" aria-pressed="false">
        <span class="kpi-label">CISA KEV</span>
        <span class="kpi-value">{kev_count}</span>
      </button>
    </section>

    <section class="controls" aria-label="Filter and search findings">
      <div class="search-wrap">
        <input
          id="search-input"
          class="search-input"
          type="search"
          placeholder="Search by CVE, target, service, scanner, or description..."
          aria-label="Search findings"
        >
      </div>
      <div class="filter-group" role="group" aria-label="Priority tier filters">
        <button type="button" class="filter-btn is-active" data-filter="ALL" aria-pressed="true">
          All ({total})
        </button>
        <button type="button" class="filter-btn" data-filter="P1" aria-pressed="false">
          P1 ({p1})
        </button>
        <button type="button" class="filter-btn" data-filter="P2" aria-pressed="false">
          P2 ({p2})
        </button>
        <button type="button" class="filter-btn" data-filter="P3" aria-pressed="false">
          P3 ({p3})
        </button>
        <button type="button" class="filter-btn" data-filter="P4" aria-pressed="false">
          P4 ({p4})
        </button>
        <button type="button" class="filter-btn" data-filter="KEV" aria-pressed="false">
          KEV Only ({kev_count})
        </button>
      </div>
    </section>

    <div class="results-bar">
      <span id="results-count">Showing {total} of {total} findings</span>
      <span>Click any row to expand vulnerability details</span>
    </div>

    <main class="table-card">
      <table class="findings-table">
        <thead>
          <tr>
            <th class="col-chevron" scope="col" aria-label="Expand"></th>
            <th scope="col" aria-sort="ascending">
              <button type="button" class="sort-btn" data-sort-key="priority">
                Priority <span class="sort-indicator" aria-hidden="true">&#9650;</span>
              </button>
            </th>
            <th scope="col" aria-sort="none">
              <button type="button" class="sort-btn" data-sort-key="target">
                Target <span class="sort-indicator" aria-hidden="true">&#8597;</span>
              </button>
            </th>
            <th class="num" scope="col">Port</th>
            <th scope="col">Service</th>
            <th scope="col">CVE / Rule</th>
            <th class="num" scope="col" aria-sort="none">
              <button type="button" class="sort-btn" data-sort-key="cvss">
                CVSS <span class="sort-indicator" aria-hidden="true">&#8597;</span>
              </button>
            </th>
            <th class="num" scope="col" aria-sort="none">
              <button type="button" class="sort-btn" data-sort-key="epss">
                EPSS <span class="sort-indicator" aria-hidden="true">&#8597;</span>
              </button>
            </th>
            <th class="center" scope="col" aria-sort="none">
              <button type="button" class="sort-btn" data-sort-key="kev">
                KEV <span class="sort-indicator" aria-hidden="true">&#8597;</span>
              </button>
            </th>
            <th scope="col">Scanners</th>
          </tr>
        </thead>
        <tbody id="findings-tbody">{static_rows_html}</tbody>
      </table>
    </main>

    <footer class="footer">
      Generated offline by <strong>sift</strong> &mdash; Universal Scan Normalizer &amp;
      Risk Prioritizer (CISA KEV + FIRST EPSS).
    </footer>
  </div>

  <script id="sift-findings-data" type="application/json">{json_payload}</script>
  <script>{_INLINE_JS}</script>
</body>
</html>
"""


def _validate_safe_output_path(output_path: Path) -> Path:
    """Reject symlink targets, symlinked parent directories, and directory targets."""
    if output_path.is_symlink() or output_path.parent.is_symlink():
        raise ValueError(f"Refusing to write HTML report through symlink: {output_path}")
    if output_path.exists() and output_path.is_dir():
        raise ValueError(f"Output path is a directory, expected a file: {output_path}")
    if not output_path.is_absolute():
        current = Path.cwd()
        for part in output_path.parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise ValueError(f"Refusing to traverse symlinked directory: {current}")
    return output_path


def export_html(
    findings: Sequence[NormalizedFinding],
    output_path: Path,
    *,
    raw_count: int | None = None,
    duplicates_merged: int = 0,
    warnings: Sequence[str] = (),
    generated_at: datetime | None = None,
) -> Path:
    """Write prioritized findings to a standalone interactive HTML file on disk."""
    _validate_safe_output_path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rendered = format_html(
        findings,
        raw_count=raw_count,
        duplicates_merged=duplicates_merged,
        warnings=warnings,
        generated_at=generated_at,
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    fd = os.open(output_path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(rendered)
    return output_path
