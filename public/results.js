// ── Results page JavaScript ─────────────────────────────────────
// Handles the two remaining fetch calls:
//   FETCH 2 — GET /api/scan/:target  (Shodan external data)
//   FETCH 3 — POST /api/history      (save result to Supabase)

const API_BASE = "";

// Chart.js global defaults to match the dark theme palette
Chart.defaults.color = "#4a6a7c";
Chart.defaults.borderColor = "#1a2d40";
Chart.defaults.font.family = "'Share Tech Mono', monospace";

// Holds chart instances so they can be destroyed before re-render
let portsChartInst = null;
let servicesChartInst = null;

// Holds the Leaflet map instance for cleanup between renders
let leafletMap = null;

// ── init ────────────────────────────────────────────────────────
// Runs when the page loads; reads the target from the URL and
// kicks off the scan
function init() {
  const params = new URLSearchParams(window.location.search);
  const target = params.get("target") || "";

  if (!target) {
    showError("No target specified. Go back and enter a domain or IP.");
    return;
  }

  document.getElementById("targetDisplay").textContent = target;
  document.getElementById("rescanInput").value = "";
  document.title = `SentinelScope — ${target}`;

  runScan(target);
}

// ── runScan ─────────────────────────────────────────────────────
// FETCH CALL 2 — GET /api/scan/:target
// Queries the backend which calls the Shodan API and returns
// shaped exposure data for the given target
async function runScan(target) {
  showLoading();

  try {
    const res = await fetch(`${API_BASE}/api/scan/${encodeURIComponent(target)}`);
    const data = await res.json();

    console.log("Full data from backend:", data);
    console.log("Vulns from backend:", data.vulns);
    console.log("First vuln entry:", data.vulns ? data.vulns[0] : "none");

    if (!res.ok) {
      showError(data.error || `Scan failed with HTTP ${res.status}`);
      return;
    }

    // Renders all result sections with the returned data
    renderStats(data);
    renderHostInfo(data);
    renderRisk(data);
    renderVulns(data);
    renderServicesTable(data);
    renderCharts(data);
    renderMap(data);

    showResults();

    // Saves the completed scan to the database after rendering
    saveScanHistory(target, data);

  } catch (err) {
    console.error("Scan error:", err);
    showError(`Network error: ${err.message}`);
  }
}

// ── saveScanHistory ─────────────────────────────────────────────
// FETCH CALL 3 — POST /api/history
// Writes the scan result to Supabase for the history feed
// on the home page; runs silently after results are shown
async function saveScanHistory(target, data) {
  const riskLevel = computeRiskLevel(data);

  try {
    const res = await fetch(`${API_BASE}/api/history`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target,
        ip:        data.ip,
        org:       data.org,
        country:   data.country,
        ports:     data.ports,
        vulns:     data.vulns,
        riskLevel,
      }),
    });

    if (!res.ok) {
      console.warn("History save returned non-OK status:", res.status);
    }
  } catch (err) {
    // Save failure is non-critical — results are still visible
    console.warn("Could not save scan history:", err.message);
  }
}

// ── computeRiskLevel ────────────────────────────────────────────
// Calculates a simple risk tier based on port count and CVE count
function computeRiskLevel(data) {
  const portCount = (data.ports || []).length;
  const vulnCount = (data.vulns || []).length;
  const score = portCount + vulnCount * 5;

  if (score >= 30) return "high";
  if (score >= 10) return "medium";
  return "low";
}

// ── renderStats ─────────────────────────────────────────────────
// Fills in the four summary stat boxes at the top of the results
function renderStats(data) {
  const strip = document.getElementById("statsStrip");
  const risk = computeRiskLevel(data);
  const riskClass = { low: "risk-low", medium: "risk-medium", high: "risk-high" }[risk] || "risk-unknown";

  strip.innerHTML = `
    <div class="stat-box fade-in">
      <div class="stat-box-value">${(data.ports || []).length}</div>
      <div class="stat-box-label">Open Ports</div>
    </div>
    <div class="stat-box fade-in">
      <div class="stat-box-value">${(data.services || []).length}</div>
      <div class="stat-box-label">Services</div>
    </div>
    <div class="stat-box fade-in">
      <div class="stat-box-value" style="color:var(--accent-danger)">${(data.vulns || []).length}</div>
      <div class="stat-box-label">CVEs Found</div>
    </div>
    <div class="stat-box fade-in">
      <span class="risk-badge ${riskClass}" style="font-size:1rem; padding:0.4rem 0.9rem;">${risk}</span>
      <div class="stat-box-label mt-1">Risk Level</div>
    </div>`;
}

// ── renderHostInfo ───────────────────────────────────────────────
// Populates the host information sidebar card
function renderHostInfo(data) {
  const rows = [
    ["IP Address",   data.ip       || "—"],
    ["Organization", data.org      || "—"],
    ["ISP",          data.isp      || "—"],
    ["Country",      data.country  || "—"],
    ["City",         data.city     || "—"],
    ["OS",           data.os       || "Unknown"],
    ["Last Updated", data.lastUpdate ? new Date(data.lastUpdate).toLocaleDateString() : "—"],
    ["Hostnames",    (data.hostnames || []).join(", ") || "—"],
    ["Tags",         (data.tags || []).join(", ")      || "None"],
  ];

  document.getElementById("hostInfo").innerHTML = rows
    .map(([k, v]) => `
      <div class="info-row">
        <span class="info-key">${k}</span>
        <span class="info-val">${escHtml(String(v))}</span>
      </div>`)
    .join("");
}

// ── renderRisk ──────────────────────────────────────────────────
// Sets the risk badge, explainer text, and animated progress bar
function renderRisk(data) {
  const risk = computeRiskLevel(data);
  const badge = document.getElementById("riskBadge");
  const explainer = document.getElementById("riskExplainer");
  const fill = document.getElementById("riskFill");

  const config = {
    low:    { cls: "risk-low",    color: "var(--accent-2)",      width: "25%", text: "Minimal exposure — few open ports, no known CVEs." },
    medium: { cls: "risk-medium", color: "var(--accent-warn)",   width: "60%", text: "Moderate exposure — several services or vulnerabilities found." },
    high:   { cls: "risk-high",   color: "var(--accent-danger)", width: "95%", text: "High exposure — many open ports and/or active CVEs detected." },
  };

  const c = config[risk] || { cls: "risk-unknown", color: "var(--text-dim)", width: "5%", text: "Risk could not be determined." };

  badge.className = `risk-badge ${c.cls}`;
  badge.textContent = risk;
  explainer.textContent = c.text;

  // Slight delay so the CSS transition animates on paint
  setTimeout(() => {
    fill.style.width = c.width;
    fill.style.background = c.color;
  }, 150);
}

//clean the cves to match NVD expected input
const cleanCve = (cve) => {
  if (!cve) return null;
  const upper = String(cve).toUpperCase().trim();
  return /^CVE-\d{4}-\d{4,}$/.test(upper) ? upper : null;
};

// ── renderVulns ─────────────────────────────────────────────────
// Renders CVE tags; each links to the NVD advisory page

function renderVulns(data) {
  console.log("renderVulns called");
  console.log("data.vulns raw:", data.vulns);

  const container = document.getElementById("vulnContainer");
  const vulns = (data.vulns || [])
    
    .map(cleanCve)
    .filter(Boolean);

  if (!vulns.length) {
    container.innerHTML = `<p class="text-dim text-sm">No known CVEs detected for this host.</p>`;
    return;
  }

  const tags = vulns
    .map((cve) => `
      <a class="vuln-tag"
         href="https://nvd.nist.gov/vuln/detail/${cve}"
         target="_blank" rel="noopener">
        ${escHtml(cve)}
      </a>`)
    .join("");

  container.innerHTML = `<div class="vuln-list">${tags}</div>
    <p class="text-xs text-dim mt-1">Click any CVE to view the NVD advisory.</p>`;
}

// ── renderServicesTable ──────────────────────────────────────────
// Fills the services table rows with port/product/banner data
function renderServicesTable(data) {
  const tbody = document.getElementById("servicesBody");
  const services = data.services || [];

  if (!services.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-dim); padding:2rem;">No service data returned.</td></tr>`;
    return;
  }

  tbody.innerHTML = services.map((s) => `
    <tr>
      <td class="text-accent text-mono">${s.port}</td>
      <td class="text-mono">${escHtml(s.transport || "—")}</td>
      <td>${escHtml(s.product || "—")}</td>
      <td class="text-dim">${escHtml(s.version || "—")}</td>
      <td>
        ${s.banner
          ? `<div class="banner-text">${escHtml(s.banner)}</div>`
          : `<span class="text-dim">—</span>`}
      </td>
    </tr>`).join("");
}

// ── renderCharts ─────────────────────────────────────────────────
// Builds the Chart.js bar chart (ports) and doughnut chart (services)
function renderCharts(data) {
  // Destroys old instances to prevent Chart.js "canvas already in use" errors
  if (portsChartInst)    { portsChartInst.destroy(); }
  if (servicesChartInst) { servicesChartInst.destroy(); }

  const ports = (data.ports || []).slice(0, 15);

  // Accent color palette for chart bars
  const barColors = ports.map(() => "rgba(0,229,255,0.7)");

  portsChartInst = new Chart(
    document.getElementById("portsChart"),
    {
      type: "bar",
      data: {
        labels:   ports.map(String),
        datasets: [{
          label:           "Open Ports",
          data:            ports.map(() => 1),
          backgroundColor: barColors,
          borderColor:     "rgba(0,229,255,1)",
          borderWidth:     1,
          borderRadius:    2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: {
            display: false,
            grid: { color: "rgba(26,45,64,0.5)" },
          },
          x: {
            ticks: { color: "#4a6a7c", font: { size: 10 } },
            grid:  { display: false },
          },
        },
      },
    }
  );

  // Builds service product labels for the doughnut chart
  const productCounts = {};
  (data.services || []).forEach((s) => {
    const label = s.product || "Unknown";
    productCounts[label] = (productCounts[label] || 0) + 1;
  });

  const donutLabels = Object.keys(productCounts);
  const donutData   = Object.values(productCounts);

  const donutColors = [
    "rgba(0,229,255,0.7)",
    "rgba(0,255,157,0.7)",
    "rgba(255,183,0,0.7)",
    "rgba(255,60,90,0.7)",
    "rgba(100,149,237,0.7)",
    "rgba(200,100,255,0.7)",
    "rgba(255,160,60,0.7)",
  ];

  servicesChartInst = new Chart(
    document.getElementById("servicesChart"),
    {
      type: "doughnut",
      data: {
        labels:   donutLabels,
        datasets: [{
          data:            donutData,
          backgroundColor: donutColors.slice(0, donutLabels.length),
          borderColor:     "var(--bg-card)",
          borderWidth:     2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "65%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#4a6a7c", boxWidth: 10, font: { size: 10 } },
          },
        },
      },
    }
  );
}

// ── renderMap ────────────────────────────────────────────────────
// Initializes (or re-initializes) the Leaflet interactive map
// and drops a marker at the target's geolocation
function renderMap(data) {
  const lat = data.latitude;
  const lon = data.longitude;

  // Tears down previous map instance to avoid Leaflet re-init errors
  if (leafletMap) {
    leafletMap.remove();
    leafletMap = null;
  }

  // Falls back gracefully if no coordinates were returned
  if (!lat || !lon) {
    document.getElementById("map").innerHTML =
      `<div style="height:260px;display:flex;align-items:center;justify-content:center;color:var(--text-dim);font-family:var(--font-mono);font-size:0.82rem;">No geolocation data available.</div>`;
    return;
  }

  // Resets the map div in case Leaflet left artifacts from prior render
  const mapEl = document.getElementById("map");
  mapEl.innerHTML = "";

  leafletMap = L.map("map", { zoomControl: true }).setView([lat, lon], 8);

  // OpenStreetMap tile layer
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "© OpenStreetMap contributors",
    maxZoom: 18,
  }).addTo(leafletMap);

  // Custom marker using a CSS-styled div instead of the default icon
  const markerIcon = L.divIcon({
    className: "",
    html: `<div style="
      width:14px; height:14px;
      background:var(--accent);
      border:2px solid var(--bg);
      border-radius:50%;
      box-shadow: 0 0 10px rgba(0,229,255,0.8);
    "></div>`,
    iconSize:   [14, 14],
    iconAnchor: [7, 7],
  });

  L.marker([lat, lon], { icon: markerIcon })
    .addTo(leafletMap)
    .bindPopup(`<b>${data.ip}</b><br/>${data.city || ""}, ${data.country || ""}`)
    .openPopup();
}

// ── rescan ───────────────────────────────────────────────────────
// Navigates to results.html for the newly entered target
function rescan() {
  const val = document.getElementById("rescanInput").value.trim();
  if (!val) return;
  window.location.href = `results.html?target=${encodeURIComponent(val)}`;
}

// ── UI state helpers ─────────────────────────────────────────────
function showLoading() {
  document.getElementById("loadingState").style.display  = "block";
  document.getElementById("errorState").style.display    = "none";
  document.getElementById("resultsContent").style.display = "none";
}

function showResults() {
  document.getElementById("loadingState").style.display   = "none";
  document.getElementById("errorState").style.display     = "none";
  document.getElementById("resultsContent").style.display = "block";
}

function showError(msg) {
  document.getElementById("loadingState").style.display   = "none";
  document.getElementById("resultsContent").style.display = "none";
  document.getElementById("errorState").style.display     = "block";
  document.getElementById("errorMsg").textContent         = msg;
}

// ── escHtml ──────────────────────────────────────────────────────
// Escapes HTML special characters to prevent XSS in dynamic content
function escHtml(str) {
  const d = document.createElement("div");
  d.textContent = String(str);
  return d.innerHTML;
}

// ── showToast ────────────────────────────────────────────────────
// Displays a brief status message in the bottom-right corner
function showToast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 3500);
}

// Kicks off the scan as soon as the page is ready
init();
