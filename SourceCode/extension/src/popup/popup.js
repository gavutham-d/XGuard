/**
 * Main Popup Controller for XGuard.
 */

import { scanUrl } from "../shared/api.js";
import { getSettings, getHistory } from "../shared/storage.js";
import { getRiskBadgeClass } from "../shared/utils.js";

document.addEventListener("DOMContentLoaded", async () => {
  const popupSiteDomain = document.getElementById("popupSiteDomain");
  const popupRiskBadge = document.getElementById("popupRiskBadge");
  const popupRiskScore = document.getElementById("popupRiskScore");
  const popupTotalScans = document.getElementById("popupTotalScans");
  const popupThreatsBlocked = document.getElementById("popupThreatsBlocked");
  const popupActiveMode = document.getElementById("popupActiveMode");
  const btnOpenSidePanel = document.getElementById("btnOpenSidePanel");
  const btnRescanPopup = document.getElementById("btnRescanPopup");
  const linkOpenSettings = document.getElementById("linkOpenSettings");

  // Load settings & history KPIs
  const settings = await getSettings();
  popupActiveMode.textContent = settings.protectionMode.toUpperCase();

  const history = await getHistory(50);
  popupTotalScans.textContent = history.length;
  popupThreatsBlocked.textContent = history.filter(
    (h) => h.riskLevel === "high" || h.riskLevel === "critical"
  ).length;

  // Inspect active tab
  async function inspectActiveTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const tab = tabs[0];
      if (!tab || !tab.url || !tab.url.startsWith("http")) {
        popupSiteDomain.textContent = "Browser / Local Page";
        popupRiskScore.textContent = "0/100";
        popupRiskBadge.textContent = "SAFE";
        popupRiskBadge.className = "badge badge-low";
        return;
      }

      try {
        const u = new URL(tab.url);
        popupSiteDomain.textContent = u.hostname;
      } catch (e) {
        popupSiteDomain.textContent = tab.url;
      }

      popupRiskBadge.textContent = "SCANNING";
      popupRiskBadge.className = "badge badge-unknown";

      const res = await scanUrl(tab.url);
      popupRiskScore.textContent = `${res.risk_score}/100`;
      popupRiskBadge.textContent = res.risk_level.toUpperCase();
      popupRiskBadge.className = `badge ${getRiskBadgeClass(res.risk_level)}`;
    });
  }

  // Open sidebar dashboard
  btnOpenSidePanel.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (tab?.id && chrome.sidePanel && chrome.sidePanel.open) {
        chrome.sidePanel.open({ tabId: tab.id }).catch(() => {});
        window.close();
      }
    });
  });

  linkOpenSettings.addEventListener("click", (e) => {
    e.preventDefault();
    btnOpenSidePanel.click();
  });

  btnRescanPopup.addEventListener("click", () => inspectActiveTab());

  inspectActiveTab();
});
