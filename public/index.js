// Home page JavaScript for SentinelScope

// Handles search button click
function handleSearch() {
  const input = document.getElementById("searchInput");
  const target = input.value.trim();

  if (!target) {
    alert("Please enter a domain or IP address.");
    return;
  }

  window.location.href = "results.html?target=" + encodeURIComponent(target);
}

// Enter key triggers search
const searchInput = document.getElementById("searchInput");
if (searchInput) {
  searchInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      handleSearch();
    }
  });
}

// FETCH CALL 1 — GET /api/history
// Retrieves scan history from Supabase and displays in table
async function loadHistory() {
  const container = document.getElementById("historyContainer");
  container.innerHTML = '<div class="table-placeholder"><div class="spinner"></div></div>';

  try {
    const res = await fetch("/api/history");
    
    if (!res.ok) {
      throw new Error("HTTP " + res.status);
    }
    
    const records = await res.json();

    if (!records || records.length === 0) {
      container.innerHTML = '<div class="table-placeholder">No scans yet. Run one above to get started.</div>';
      return;
    }

    let rows = "";
    records.forEach(function (r) {
      const date = new Date(r.scanned_at).toLocaleString();
      
      const portPills = (r.ports || []).slice(0, 5).map(function (p) {
        return '<span class="port-pill">' + p + "</span>";
      }).join(" ");
      
      const extra = r.ports && r.ports.length > 5
        ? '<span class="port-pill">+' + (r.ports.length - 5) + "</span>"
        : "";

      const riskClass = "risk-" + (r.risk_level || "low");

      rows += "<tr>" +
        '<td><a class="history-target" href="results.html?target=' + encodeURIComponent(r.target) + '">' + escapeHtml(r.target) + "</a></td>" +
        "<td>" + escapeHtml(r.ip || "—") + "</td>" +
        "<td>" + escapeHtml(r.country || "—") + "</td>" +
        '<td><div class="port-pills">' + portPills + extra + "</div></td>" +
        '<td><span class="risk-badge ' + riskClass + '">' + (r.risk_level || "—") + "</span></td>" +
        "<td>" + date + "</td>" +
        "</tr>";
    });

    container.innerHTML =
      '<table class="data-table">' +
        "<thead><tr>" +
          "<th>Target</th>" +
          "<th>IP</th>" +
          "<th>Country</th>" +
          "<th>Ports</th>" +
          "<th>Risk</th>" +
          "<th>Scanned At</th>" +
        "</tr></thead>" +
        "<tbody>" + rows + "</tbody>" +
      "</table>";

  } catch (err) {
    console.error("History fetch error:", err);
    container.innerHTML = '<div class="table-placeholder" style="color:var(--accent-danger);">Failed to load history: ' + err.message + "</div>";
  }
}

// Helper to escape HTML and prevent XSS
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
}

// Load history when page loads
loadHistory();