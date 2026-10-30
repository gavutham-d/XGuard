/**
 * Local Chrome Storage abstraction for XGuard.
 * Persists user preferences, scan history, safe-listed domains, and bypass tokens.
 */

const DEFAULT_SETTINGS = {
  protectionMode: "balanced", // balanced, strict, learning
  scanTimeoutMs: 3000,
  privacyMode: false,
  soundAlerts: false,
  backendUrl: "http://127.0.0.1:8000",
  trustedDomains: ["google.com", "github.com", "microsoft.com", "apple.com"]
};

export async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get("settings", (res) => {
      resolve({ ...DEFAULT_SETTINGS, ...(res.settings || {}) });
    });
  });
}

export async function saveSettings(newSettings) {
  const current = await getSettings();
  const updated = { ...current, ...newSettings };
  return new Promise((resolve) => {
    chrome.storage.local.set({ settings: updated }, () => resolve(updated));
  });
}

export async function getHistory(limit = 100) {
  return new Promise((resolve) => {
    chrome.storage.local.get("scanHistory", (res) => {
      const history = res.scanHistory || [];
      resolve(history.slice(0, limit));
    });
  });
}

export async function addHistoryEntry(scanResult) {
  const history = await getHistory(500);
  // Add new scan to top
  const entry = {
    scanId: scanResult.scan_id || ("local-" + Date.now()),
    url: scanResult.url,
    hostname: scanResult.hostname,
    registeredDomain: scanResult.registered_domain,
    riskScore: scanResult.risk_score,
    riskLevel: scanResult.risk_level,
    category: scanResult.predicted_category,
    evidence: scanResult.evidence || [],
    redirectChain: scanResult.redirect_chain || [],
    recommendedAction: scanResult.recommended_action,
    timestamp: scanResult.scan_timestamp || new Date().toISOString(),
    durationMs: scanResult.scan_duration_ms || 0,
    userAction: scanResult.user_action || "inspected"
  };

  const updated = [entry, ...history.filter(h => h.scanId !== entry.scanId)].slice(0, 500);
  return new Promise((resolve) => {
    chrome.storage.local.set({ scanHistory: updated }, () => resolve(entry));
  });
}

export async function deleteHistoryEntry(scanId) {
  const history = await getHistory(500);
  const updated = history.filter(h => h.scanId !== scanId);
  return new Promise((resolve) => {
    chrome.storage.local.set({ scanHistory: updated }, () => resolve(true));
  });
}

export async function clearAllHistory() {
  return new Promise((resolve) => {
    chrome.storage.local.set({ scanHistory: [] }, () => resolve(true));
  });
}

// In-Memory / Session-level one-time navigation bypass tokens
// Prevents interception loops when a user explicitly accepts the risk and chooses "Continue anyway"
export async function setBypassToken(url) {
  return new Promise((resolve) => {
    chrome.storage.session.get("bypasses", (res) => {
      const bypasses = res.bypasses || {};
      bypasses[url] = Date.now() + 60000; // valid for 60 seconds
      chrome.storage.session.set({ bypasses }, () => resolve(true));
    });
  });
}

export async function consumeBypassToken(url) {
  return new Promise((resolve) => {
    chrome.storage.session.get("bypasses", (res) => {
      const bypasses = res.bypasses || {};
      const exp = bypasses[url];
      if (exp && exp > Date.now()) {
        delete bypasses[url];
        chrome.storage.session.set({ bypasses }, () => resolve(true));
      } else {
        resolve(false);
      }
    });
  });
}
