/**
 * Background Service Worker for XGuard (Manifest V3).
 * Orchestrates scans, maintains cache, manages warnings and context menus.
 */

import { scanUrl } from "../shared/api.js";
import { addHistoryEntry, getSettings, setBypassToken } from "../shared/storage.js";

// Session-level in-memory cache for recent scans
const scanCache = new Map();

// Context Menus & Extension Lifecycle
chrome.runtime.onInstalled.addListener(() => {
  // Context menus
  chrome.contextMenus.create({
    id: "tg_scan_link",
    title: "🛡️ XGuard: Inspect Link Safety",
    contexts: ["link"]
  });

  chrome.contextMenus.create({
    id: "tg_open_sidepanel",
    title: "🛡️ Open XGuard Security Dashboard",
    contexts: ["page", "action"]
  });

  // Enable side panel on action button click or context menu
  if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
    chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => {});
  }

  // Open Welcome page on first install
  chrome.tabs.create({
    url: chrome.runtime.getURL("src/welcome/welcome.html")
  });
});

// Handle Context Menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "tg_scan_link" && info.linkUrl) {
    const result = await executeScan(info.linkUrl);
    if (result.recommended_action === "allow") {
      chrome.notifications.create({
        type: "basic",
        iconUrl: chrome.runtime.getURL("icons/icon128.png"),
        title: "XGuard: Verified Low Risk",
        message: `Destination ${result.registered_domain || info.linkUrl} classified safe (Score: ${result.risk_score}/100).`
      });
    } else {
      openWarningPage(result, info.linkUrl, tab?.id, true);
    }
  } else if (info.menuItemId === "tg_open_sidepanel" && tab?.id) {
    chrome.sidePanel.open({ tabId: tab.id }).catch(() => {});
  }
});

// Core scan dispatcher
async function executeScan(url, pageSignals = null) {
  // Check memory cache first (1 minute TTL)
  const cached = scanCache.get(url);
  if (cached && Date.now() - cached.timestamp < 60000) {
    return cached.data;
  }

  const result = await scanUrl(url, { page_signals: pageSignals });

  // Update cache
  scanCache.set(url, {
    data: result,
    timestamp: Date.now()
  });

  // Persist to local storage history
  try {
    await addHistoryEntry(result);
  } catch (e) {
    console.error("Failed to add scan to local storage:", e);
  }

  return result;
}

function openWarningPage(scanResult, originalUrl, tabId, openInNewTab = false) {
  const warningUrl = chrome.runtime.getURL(
    `src/warning/warning.html?scan_id=${encodeURIComponent(scanResult.scan_id || "")}&url=${encodeURIComponent(originalUrl)}&score=${scanResult.risk_score}&level=${scanResult.risk_level}&cat=${encodeURIComponent(scanResult.predicted_category)}`
  );

  // Store active scan result for warning page to read full evidence
  chrome.storage.session.set({
    [`warning_data_${scanResult.scan_id}`]: scanResult
  });

  if (openInNewTab || !tabId) {
    chrome.tabs.create({ url: warningUrl });
  } else {
    chrome.tabs.update(tabId, { url: warningUrl });
  }
}

// Message Listener for Content Scripts & UI
chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
  if (req.action === "INTERCEPT_AND_SCAN") {
    executeScan(req.url, req.pageSignals).then((res) => {
      sendResponse(res);
    });
    return true; // Keep channel open for async response
  }

  if (req.action === "OPEN_WARNING_INTERSTITIAL") {
    openWarningPage(
      req.scanResult,
      req.originalUrl,
      sender.tab?.id,
      req.isNewTab
    );
    sendResponse({ status: "navigated" });
    return true;
  }

  if (req.action === "OPEN_SIDE_PANEL") {
    if (sender.tab?.id) {
      chrome.sidePanel.open({ tabId: sender.tab.id }).catch(() => {});
    }
    sendResponse({ status: "opened" });
    return true;
  }

  if (req.action === "RECORD_OVERRIDE") {
    const { url, scanId } = req;
    setBypassToken(url);

    // Notify active tabs of bypass authorization
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach((t) => {
        if (t.id) {
          chrome.tabs.sendMessage(t.id, {
            action: "AUTHORIZE_BYPASS",
            url: url
          }).catch(() => {});
        }
      });
    });

    // Notify backend if online
    getSettings().then((st) => {
      const backendUrl = st.backendUrl || "http://127.0.0.1:8000";
      fetch(`${backendUrl}/api/v1/scan/${scanId}/override`, { method: "POST" }).catch(() => {});
    });

    sendResponse({ status: "authorized" });
    return true;
  }
});
