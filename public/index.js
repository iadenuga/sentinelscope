// ── Home page JavaScript ────────────────────────────────────────

// Base URL for all API requests — empty string means same origin
const API_BASE = "";

// ── handleSearch ────────────────────────────────────────────────
// Reads the input field and navigates to the results page
// with the target as a query parameter
function handleSearch() {
  const input = document.getElementById("searchInput");
  const target = input.value.trim();

  if (!target) {
    showToast("Please enter a domain or IP address.");
    return;
  }

  // Navigates to results.html with the target value in the URL
  window.location.href = `results.html?target=${encodeURIComponent(target)}`;
}

// Pressing Enter in the search field also triggers the search
document.getElementById("searchInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") handleSearch();
});

// ── loadHistory ─────────────────────────────────────────────────
// FETCH CALL 1 — GET /api/history
// Retrieves the 20 most recent scan records from the database
// and renders them into the history table on the home page
async function loadHistory() {
  const container = document.getElementById("historyContainer");
  container.innerHTML = `<div class="table-placeholder"><div class="spinner"></div></div>`;

  try {
    const res = await fetch(`${API_BASE}/api/history`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const records = await res.json();

    if (!records.length) {
      container.innerHTML = `
        <div class="table-placeholder">
          No scan history yet — run a scan above to get started.
        </div>`;
      return;
    }

    // Builds the HTML table rows from the fetched records
    const rows = records.map((r) => {
      const date = new Date(r.scanned_at).toLocaleString();
      const portPills = (r.ports || [])
        .slice(0, 6)
        .map((p) => `<span class="port-pill">${p}</span>`)
        .join("");
      const extraPorts = r.ports && r.ports.length > 6
        ? `<span class="port-pill">+${r.ports.length - 6}</span>`
        : "";
      const riskClass = riskCSSClass(r.risk_level);

      return `
        <tr class="fade-in">
          <td>
            <a class="history-target" href="results.html?target=${encodeURIComponent(r.target)}">
              ${escHtml(r.target)}
            </a>
          </td>
          <td class="text-mono text-sm">${escHtml(r.ip || "—")}</td>
          <td class="text-sm">${escHtml(r.country || "—")}</td>
          <td>
            <div class="port-pills">${portPills}${extraPorts}</div>
          </td>
          <td><span class="risk-badge ${riskClass}">${r.risk_level || "unknown"}</span></td>
          <td class="text-xs text-dim">${date}</td>
        </tr>`;
    }).join("");

    container.innerHTML = `
      <table class="data-table">
        <thead>
          <tr>
            <th>Target</th>
            <th>IP</th>
            <th>Country</th>
            <th>Open Ports</th>
            <th>Risk</th>
            <th>Scanned At</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;

  } catch (err) {
    console.error("History fetch error:", err);
    container.innerHTML = `
      <div class="table-placeholder" style="color:var(--accent-danger);">
        Failed to load history — ${err.message}
      </div>`;
  }
}

// ── riskCSSClass ────────────────────────────────────────────────
// Maps a risk level string to the corresponding CSS class
function riskCSSClass(level) {
  const map = { low: "risk-low", medium: "risk-medium", high: "risk-high" };
  return map[level] || "risk-unknown";
}

// ── escHtml ─────────────────────────────────────────────────────
// Escapes special characters to prevent XSS in dynamic HTML
function escHtml(str) {
  const d = document.createElement("div");
  d.textContent = String(str);
  return d.innerHTML;
}

// ── showToast ───────────────────────────────────────────────────
// Shows a brief notification message at the bottom-right corner
function showToast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 3500);
}

// Loads history automatically when the page first opens
loadHistory();
