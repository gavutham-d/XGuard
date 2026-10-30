/**
 * Interstitial Warning Page Controller for XGuard.
 * Provides clear risk explainability, safe return, and confirmed override navigation.
 */

import { escapeHtml, truncateUrl } from "../shared/utils.js";

document.addEventListener("DOMContentLoaded", async () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || "Unknown Destination";
  const scanId = params.get("scan_id") || "";
  const initialScore = params.get("score") || "75";
  const initialLevel = params.get("level") || "high";
  const initialCategory = params.get("cat") || "phishing";

  // Elements
  const destinationUrlEl = document.getElementById("destinationUrl");
  const riskLevelBadgeEl = document.getElementById("riskLevelBadge");
  const categoryBadgeEl = document.getElementById("categoryBadge");
  const riskScoreEl = document.getElementById("riskScore");
  const verdictTextEl = document.getElementById("verdictText");
  const evidenceListEl = document.getElementById("evidenceList");
  const btnBackToSafety = document.getElementById("btnBackToSafety");
  const btnToggleDetails = document.getElementById("btnToggleDetails");
  const detailsDrawer = document.getElementById("detailsDrawer");
  const detHostnameEl = document.getElementById("detHostname");
  const detRegDomainEl = document.getElementById("detRegDomain");
  const detModelEl = document.getElementById("detModel");
  const detModelProbEl = document.getElementById("detModelProb");
  const redirectChainBox = document.getElementById("redirectChainBox");
  const intelMatchesBox = document.getElementById("intelMatchesBox");

  const btnOpenOverrideModal = document.getElementById("btnOpenOverrideModal");
  const overrideModal = document.getElementById("overrideModal");
  const acceptRiskCheckbox = document.getElementById("acceptRiskCheckbox");
  const btnConfirmProceed = document.getElementById("btnConfirmProceed");
  const btnCancelOverride = document.getElementById("btnCancelOverride");

  // Populate basic header data
  destinationUrlEl.textContent = targetUrl;
  riskScoreEl.textContent = initialScore;
  riskLevelBadgeEl.textContent = initialLevel.toUpperCase() + " RISK";
  categoryBadgeEl.textContent = initialCategory.toUpperCase();

  if (initialLevel === "critical") {
    verdictTextEl.textContent = "Confirmed Threat Indicator";
  } else if (initialLevel === "high") {
    verdictTextEl.textContent = "High Phishing Probability";
  } else {
    verdictTextEl.textContent = "Suspicious Destination";
  }

  // Load detailed telemetry from session storage
  let scanData = null;
  if (scanId) {
    try {
      const res = await chrome.storage.session.get(`warning_data_${scanId}`);
      scanData = res[`warning_data_${scanId}`];
    } catch (e) {}
  }

  if (scanData) {
    // Populate Evidence List
    evidenceListEl.innerHTML = "";
    if (scanData.evidence && scanData.evidence.length > 0) {
      scanData.evidence.forEach((ev) => {
        const li = document.createElement("li");
        li.className = "evidence-item";
        li.innerHTML = `
          <div class="evidence-dot"></div>
          <div>
            <strong>${escapeHtml(ev.name.replace(/_/g, " ").toUpperCase())}:</strong> 
            ${escapeHtml(ev.description)}
          </div>
        `;
        evidenceListEl.appendChild(li);
      });
    } else {
      evidenceListEl.innerHTML = `
        <li class="evidence-item">
          <div class="evidence-dot"></div>
          <div>Destination deviates from verified safety baselines for this category.</div>
        </li>
      `;
    }

    // Populate Technical Breakdown
    detHostnameEl.textContent = scanData.hostname || "--";
    detRegDomainEl.textContent = scanData.registered_domain || "--";
    detModelEl.textContent = scanData.model_version || "XGuard Ensemble 1.0";
    detModelProbEl.textContent = scanData.model_probability !== null 
      ? `${(scanData.model_probability * 100).toFixed(1)}%` 
      : "Rule-Based Heuristic";

    // Redirect Telemetry
    if (scanData.redirect_chain && scanData.redirect_chain.length > 0) {
      redirectChainBox.innerHTML = scanData.redirect_chain.map(h => 
        `Hop ${h.order}: ${escapeHtml(h.domain)} &rarr; Status ${h.status_code || 200}${h.is_cross_domain ? " [Cross-Domain Jump]" : ""}`
      ).join("<br>");
    } else {
      redirectChainBox.textContent = "Direct navigation (no intermediate redirect hops).";
    }

    // Threat Intel Feeds
    if (scanData.intelligence_matches && scanData.intelligence_matches.length > 0) {
      intelMatchesBox.innerHTML = scanData.intelligence_matches.map(m => 
        `Provider: ${escapeHtml(m.source)} | Match: ${m.matched ? "CONFIRMED MALICIOUS" : "Negative / Inconclusive"} ${m.threat_category ? `(${m.threat_category})` : ""}`
      ).join("<br>");
    } else {
      intelMatchesBox.textContent = "No external database matches; flagged via local ML & lexical signals.";
    }
  } else {
    // Fallback evidence from URL analysis
    evidenceListEl.innerHTML = `
      <li class="evidence-item">
        <div class="evidence-dot"></div>
        <div>URL structure exhibits strong lexical resemblance to known phishing vectors.</div>
      </li>
      <li class="evidence-item">
        <div class="evidence-dot"></div>
        <div>Destination domain lacks verified reputation record for this interaction.</div>
      </li>
    `;
  }

  // Button: Go Back to Safety
  btnBackToSafety.addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  // Button: Toggle Technical Details
  btnToggleDetails.addEventListener("click", () => {
    const isHidden = detailsDrawer.classList.contains("hidden");
    if (isHidden) {
      detailsDrawer.classList.remove("hidden");
      btnToggleDetails.textContent = "Hide Technical Breakdown";
    } else {
      detailsDrawer.classList.add("hidden");
      btnToggleDetails.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
        See Detailed Technical Breakdown
      `;
    }
  });

  // Override Modal Actions
  btnOpenOverrideModal.addEventListener("click", () => {
    overrideModal.classList.remove("hidden");
  });

  btnCancelOverride.addEventListener("click", () => {
    overrideModal.classList.add("hidden");
    acceptRiskCheckbox.checked = false;
    btnConfirmProceed.disabled = true;
  });

  acceptRiskCheckbox.addEventListener("change", (e) => {
    btnConfirmProceed.disabled = !e.target.checked;
  });

  btnConfirmProceed.addEventListener("click", () => {
    // Send override message to background script to authorize navigation
    chrome.runtime.sendMessage({
      action: "RECORD_OVERRIDE",
      url: targetUrl,
      scanId: scanId
    }, () => {
      // Navigate to destination
      window.location.assign(targetUrl);
    });
  });
});
