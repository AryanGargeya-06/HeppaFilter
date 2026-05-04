// Heppafilter — Background Service Worker
// Intercepts navigation events and checks URLs against the ML API.

const API_BASE   = "http://localhost:5000";
const CACHE_TTL  = 5 * 60 * 1000; // 5 minutes
const cache      = {};             // Simple in-memory cache {url -> {result, ts}}

const RISK_COLOURS = {
  LOW:      { colour: "#22c55e", text: "Safe"     },
  MEDIUM:   { colour: "#f59e0b", text: "Caution"  },
  HIGH:     { colour: "#ef4444", text: "Danger"   },
  CRITICAL: { colour: "#7f1d1d", text: "Blocked"  },
};

async function checkUrl(url) {
  // Skip internal browser pages
  if (!url || url.startsWith("chrome") || url.startsWith("about") || url.startsWith("edge")) {
    return null;
  }

  // Return cached result if still fresh
  if (cache[url] && (Date.now() - cache[url].ts) < CACHE_TTL) {
    return cache[url].result;
  }

  try {
    const response = await fetch(`${API_BASE}/predict`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
    });

    if (!response.ok) return null;

    const result    = await response.json();
    cache[url]      = { result, ts: Date.now() };
    return result;

  } catch (err) {
    // API offline — fail silently (do not block browsing)
    console.warn("[Heppafilter] API unreachable:", err.message);
    return null;
  }
}

function showWarning(tabId, result) {
  const config = RISK_COLOURS[result.risk_level] || RISK_COLOURS.LOW;

  if (result.risk_level === "HIGH" || result.risk_level === "CRITICAL") {
    chrome.notifications.create({
      type:     "basic",
      iconUrl:  "icons/icon48.png",
      title:    `⚠ Heppafilter: ${config.text} Site Detected`,
      message:  `${result.url}\nRisk: ${result.risk_level} (${(result.confidence * 100).toFixed(1)}% confidence)`,
      priority: 2,
    });
  }

  // Send result to content script for optional inline banner
  chrome.tabs.sendMessage(tabId, {
    action: "HEPPAFILTER_RESULT",
    result: result,
  }).catch(() => {}); // Tab may not have content script yet
}

// ── Listen for tab navigation ─────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;

  const result = await checkUrl(tab.url);
  if (result) {
    // Store in extension storage for popup to read
    await chrome.storage.session.set({ [`result_${tabId}`]: result });
    showWarning(tabId, result);
  }
});

// ── Message bridge for popup ───────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "GET_RESULT") {
    chrome.tabs.query({ active: true, currentWindow: true }, async ([tab]) => {
      if (!tab) return sendResponse(null);
      const stored = await chrome.storage.session.get(`result_${tab.id}`);
      sendResponse(stored[`result_${tab.id}`] || null);
    });
    return true; // Keep channel open for async
  }

  if (msg.action === "CHECK_URL") {
    checkUrl(msg.url).then(sendResponse);
    return true;
  }
});
