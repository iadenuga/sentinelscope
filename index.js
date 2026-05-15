// Main Express server entry point for SentinelScope
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const { createClient } = require("@supabase/supabase-js");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Parses incoming JSON request bodies
app.use(express.json());

// Allows requests from the frontend origin
app.use(cors());

// Serves all static files from the public folder (HTML, CSS, JS)
app.use(express.static("public"));

// Supabase client initialized with environment variables
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// Shodan API base URL
const SHODAN_BASE = "https://api.shodan.io";

// ─────────────────────────────────────────────
// ENDPOINT 1 — GET /api/scan/:target
// Fetches live exposure data from the Shodan API
// for a given domain or IP address target
// ─────────────────────────────────────────────
app.get("/api/scan/:target", async (req, res) => {
  const { target } = req.params;
  const apiKey = process.env.SHODAN_API_KEY;

  try {
    // Determines whether the target looks like an IP or a domain name
    const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(target);

    let shodanData;

    if (isIP) {
      // Direct host lookup when target is an IP address
      const response = await fetch(
        `${SHODAN_BASE}/shodan/host/${target}?key=${apiKey}`
      );
      if (!response.ok) {
        const errBody = await response.json().catch(() => ({}));
        return res.status(response.status).json({
          error: errBody.error || "Shodan API error for IP lookup",
        });
      }
      shodanData = await response.json();
    } else {
      // DNS resolve then host lookup when target is a domain
      const dnsRes = await fetch(
        `${SHODAN_BASE}/dns/resolve?hostnames=${target}&key=${apiKey}`
      );
      if (!dnsRes.ok) {
        return res.status(dnsRes.status).json({ error: "DNS resolution failed" });
      }
      const dnsData = await dnsRes.json();
      const resolvedIP = dnsData[target];

      if (!resolvedIP) {
        return res.status(404).json({ error: "Could not resolve domain to an IP" });
      }

      const hostRes = await fetch(
        `${SHODAN_BASE}/shodan/host/${resolvedIP}?key=${apiKey}`
      );
      if (!hostRes.ok) {
        const errBody = await hostRes.json().catch(() => ({}));
        return res.status(hostRes.status).json({
          error: errBody.error || "Shodan host lookup failed",
        });
      }
      shodanData = await hostRes.json();
    }

    // Extracts and shapes the relevant fields from the Shodan response
    const shaped = {
      ip: shodanData.ip_str || target,
      org: shodanData.org || "Unknown",
      isp: shodanData.isp || "Unknown",
      country: shodanData.country_name || "Unknown",
      city: shodanData.city || "Unknown",
      latitude: shodanData.latitude || null,
      longitude: shodanData.longitude || null,
      os: shodanData.os || null,
      lastUpdate: shodanData.last_update || null,
      ports: shodanData.ports || [],
      vulns: Array.isArray(shodanData.vulns)
        ? shodanData.vulns
        : shodanData.vulns && typeof shodanData.vulns === "object"
          ? Object.keys(shodanData.vulns)
          : [],
      services: (shodanData.data || []).map((s) => ({
        port: s.port,
        transport: s.transport,
        product: s.product || null,
        version: s.version || null,
        banner: s.data ? s.data.slice(0, 200) : null,
      })),
      hostnames: shodanData.hostnames || [],
      tags: shodanData.tags || [],
    };
  
    res.json(shaped);
  } catch (err) {
    console.error("Scan endpoint error:", err.message);
    res.status(500).json({ error: "Internal server error during scan" });
  }
});

// ─────────────────────────────────────────────
// ENDPOINT 2 — POST /api/history
// Writes a completed scan result to the Supabase database
// so users can revisit previous scans
// ─────────────────────────────────────────────
app.post("/api/history", async (req, res) => {
  const { target, ip, org, country, ports, vulns, riskLevel } = req.body;

  if (!target) {
    return res.status(400).json({ error: "target is required" });
  }

  try {
    const { data, error } = await supabase.from("scan_history").insert([
      {
        target,
        ip,
        org,
        country,
        ports: ports || [],
        vulns: vulns || [],
        risk_level: riskLevel || "unknown",
        scanned_at: new Date().toISOString(),
      },
    ]).select();

    if (error) {
      console.error("Supabase insert error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    res.status(201).json({ message: "Scan saved", record: data[0] });
  } catch (err) {
    console.error("History POST error:", err.message);
    res.status(500).json({ error: "Failed to save scan history" });
  }
});

// ─────────────────────────────────────────────
// ENDPOINT 3 — GET /api/history
// Retrieves the 20 most recent scan records from Supabase
// for display in the recent scans section on the home page
// ─────────────────────────────────────────────
app.get("/api/history", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("scan_history")
      .select("*")
      .order("scanned_at", { ascending: false })
      .limit(20);

    if (error) {
      console.error("Supabase fetch error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    res.json(data);
  } catch (err) {
    console.error("History GET error:", err.message);
    res.status(500).json({ error: "Failed to retrieve scan history" });
  }
});

// Serves all static files from the public folder using absolute path
app.use(express.static(__dirname + "/public"));


// Starts the server on the configured port
app.listen(PORT, () => {
  console.log(`SentinelScope server running on port ${PORT}`);
});
