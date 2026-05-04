// Heppafilter — Popup Script

const RISK_CONFIG = {
  LOW:      { bg: "#052e16", border: "#166534", label: "#22c55e", badge: "#14532d", badgeText: "#86efac" },
  MEDIUM:   { bg: "#2d1a00", border: "#92400e", label: "#f59e0b", badge: "#78350f", badgeText: "#fde68a" },
  HIGH:     { bg: "#2d0a0a", border: "#991b1b", label: "#ef4444", badge: "#7f1d1d", badgeText: "#fca5a5" },
  CRITICAL: { bg: "#1c0505", border: "#7f1d1d", label: "#dc2626", badge: "#450a0a", badgeText: "#fca5a5" },
};

function renderResult(result) {
  const main   = document.getElementById("main");
  const config = RISK_CONFIG[result.risk_level] || RISK_CONFIG.LOW;
  const pct    = Math.round(result.confidence * 100);
  const isPhish = result.label === "PHISHING";

  const signals = result.risk_signals?.map(s =>
    `<div class="signal-item"><span>⚠</span> ${s}</div>`
  ).join("") || "";

  const mitre = result.mitre_technique
    ? `<div class="mitre-tag">MITRE ${result.mitre_technique}</div>`
    : "";

  main.innerHTML = `
    <div class="result-card" style="background:${config.bg}; border-color:${config.border};">
      <div class="result-label" style="color:${config.label};">
        ${isPhish ? "⚠ PHISHING" : "✓ LEGITIMATE"}
      </div>
      <div style="text-align:center;">
        <span class="risk-badge" style="background:${config.badge}; color:${config.badgeText};">
          ${result.risk_level} RISK
        </span>
      </div>
      <div class="confidence-row">
        <span>Confidence</span>
        <span>${pct}%</span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill" style="width:${pct}%; background:${config.label};"></div>
      </div>
      ${signals ? `<div class="signals-list">${signals}</div>` : ""}
      ${mitre}
      <div class="url-display">${result.url}</div>
    </div>
  `;
}

function renderOffline() {
  document.getElementById("main").innerHTML = `
    <div class="api-offline">
      <div style="font-size:22px;margin-bottom:8px;">⚡</div>
      <strong style="color:#d6d3d1;">API Offline</strong><br>
      Start the Heppafilter server:<br>
      <code style="color:#60a5fa;">python heppafilter/api.py</code>
    </div>
  `;
}

// ── Load current tab result ────────────────────────────────────────────────
chrome.runtime.sendMessage({ action: "GET_RESULT" }, result => {
  if (result) {
    renderResult(result);
  } else {
    renderOffline();
  }
});

// ── Manual check ──────────────────────────────────────────────────────────
document.getElementById("check-btn").addEventListener("click", async () => {
  const url = document.getElementById("manual-url").value.trim();
  if (!url) return;

  document.getElementById("main").innerHTML =
    `<div class="loading">Analysing...</div>`;

  chrome.runtime.sendMessage({ action: "CHECK_URL", url }, result => {
    if (result) {
      renderResult(result);
    } else {
      renderOffline();
    }
  });
});
