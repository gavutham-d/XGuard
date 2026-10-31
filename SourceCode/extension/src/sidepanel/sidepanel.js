/**
 * XGuard Side Panel Controller.
 * Handles live overview, active tab telemetry, AI chatbot, history, analytics,
 * QR phishing scanner, and settings management.
 */

import {
  scanUrl, sendChatMessage, checkBackendHealth, getModelInfo, submitFeedback,
  getAnalyticsSummary, getAnalyticsTimeseries, getAnalyticsCategories,
  getAnalyticsTelemetry, getAnalyticsTrends, getAnalyticsRecentEvents,
  getAnalyticsEffectiveness
} from "../shared/api.js";
import { getSettings, saveSettings, getHistory, deleteHistoryEntry, clearAllHistory } from "../shared/storage.js";
import { escapeHtml, truncateUrl, formatTimestamp, formatDateFull, getRiskBadgeClass } from "../shared/utils.js";

document.addEventListener("DOMContentLoaded", async () => {
  let activeTabUrl = "";
  let activeTabScanResult = null;
  let chatConversationHistory = [];

  // DOM Elements
  const tabButtons = document.querySelectorAll(".nav-tab");
  const tabPanels = document.querySelectorAll(".tab-panel");
  const themeToggleBtn = document.getElementById("themeToggleBtn");
  const backendHealthBadge = document.getElementById("backendHealthBadge");
  const backendHealthLabel = document.getElementById("backendHealthLabel");

  // Overview Elements
  const kpiTotalScans = document.getElementById("kpiTotalScans");
  const kpiSafeLinks = document.getElementById("kpiSafeLinks");
  const kpiSuspicious = document.getElementById("kpiSuspicious");
  const kpiRisky = document.getElementById("kpiRisky");
  const overviewModeBadge = document.getElementById("overviewModeBadge");
  const overviewActivityFeed = document.getElementById("overviewActivityFeed");
  const manualScanInput = document.getElementById("manualScanInput");
  const btnManualScan = document.getElementById("btnManualScan");
  const manualScanResult = document.getElementById("manualScanResult");
  const btnViewAllHistory = document.getElementById("btnViewAllHistory");

  // Current Site Elements
  const currentSiteDomain = document.getElementById("currentSiteDomain");
  const currentSiteFullUrl = document.getElementById("currentSiteFullUrl");
  const currentSiteLevelBadge = document.getElementById("currentSiteLevelBadge");
  const currentSiteScore = document.getElementById("currentSiteScore");
  const currentSiteVerdictTitle = document.getElementById("currentSiteVerdictTitle");
  const currentSiteVerdictDesc = document.getElementById("currentSiteVerdictDesc");
  const currentSiteEvidenceList = document.getElementById("currentSiteEvidenceList");
  const btnRescanCurrentSite = document.getElementById("btnRescanCurrentSite");
  const btnAskAssistantAboutCurrent = document.getElementById("btnAskAssistantAboutCurrent");

  // Chat Elements
  const chatMessages = document.getElementById("chatMessages");
  const chatInput = document.getElementById("chatInput");
  const btnSendChat = document.getElementById("btnSendChat");
  const btnClearChat = document.getElementById("btnClearChat");
  const promptChips = document.getElementById("promptChips");

  // History Elements
  const historySearchInput = document.getElementById("historySearchInput");
  const historyRiskFilter = document.getElementById("historyRiskFilter");
  const historyList = document.getElementById("historyList");
  const btnExportJson = document.getElementById("btnExportJson");
  const btnExportCsv = document.getElementById("btnExportCsv");
  const btnClearHistory = document.getElementById("btnClearHistory");


  // Analytics Elements are now managed directly in loadAnalyticsView() / render functions


  // QR Shield Elements
  const qrDropZone = document.getElementById("qrDropZone");
  const qrFileInput = document.getElementById("qrFileInput");
  const qrResultBox = document.getElementById("qrResultBox");
  const qrDecodedUrl = document.getElementById("qrDecodedUrl");
  const btnScanDecodedQr = document.getElementById("btnScanDecodedQr");
  const qrScanVerdict = document.getElementById("qrScanVerdict");

  // Settings Elements
  const protectionModeRadios = document.querySelectorAll("input[name='protectionMode']");
  const settingPrivacyMode = document.getElementById("settingPrivacyMode");
  const settingTimeoutSlider = document.getElementById("settingTimeoutSlider");
  const lblTimeoutVal = document.getElementById("lblTimeoutVal");
  const healthBackendVal = document.getElementById("healthBackendVal");
  const healthModelVal = document.getElementById("healthModelVal");
  const healthIntelVal = document.getElementById("healthIntelVal");
  const feedbackUrlInput = document.getElementById("feedbackUrlInput");
  const feedbackTypeSelect = document.getElementById("feedbackTypeSelect");
  const feedbackComment = document.getElementById("feedbackComment");
  const feedbackConsentCheck = document.getElementById("feedbackConsentCheck");
  const btnSubmitFeedback = document.getElementById("btnSubmitFeedback");

  // Navigation Tab Switching
  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      tabButtons.forEach((b) => b.classList.remove("active"));
      tabPanels.forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const targetPanel = document.getElementById(`panel-${targetTab}`);
      if (targetPanel) targetPanel.classList.add("active");

      // Scroll active tab into view
      btn.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });

      // Trigger panel-specific refresh
      if (targetTab === "history") loadHistoryView();
      if (targetTab === "analytics") loadAnalyticsView();
      if (targetTab === "current") inspectCurrentTab();
    });
  });

  // Nav scroll arrow buttons
  const navTabsScroll = document.getElementById("navTabsScroll");
  const navScrollLeft = document.getElementById("navScrollLeft");
  const navScrollRight = document.getElementById("navScrollRight");

  function updateScrollArrows() {
    if (!navTabsScroll) return;
    const { scrollLeft, scrollWidth, clientWidth } = navTabsScroll;
    navScrollLeft.classList.toggle("hidden", scrollLeft <= 2);
    navScrollRight.classList.toggle("hidden", scrollLeft + clientWidth >= scrollWidth - 2);
  }

  if (navTabsScroll) {
    navTabsScroll.addEventListener("scroll", updateScrollArrows);
    // Initial check after layout
    requestAnimationFrame(updateScrollArrows);
    new ResizeObserver(updateScrollArrows).observe(navTabsScroll);
  }

  navScrollLeft?.addEventListener("click", () => {
    navTabsScroll.scrollBy({ left: -100, behavior: "smooth" });
  });
  navScrollRight?.addEventListener("click", () => {
    navTabsScroll.scrollBy({ left: 100, behavior: "smooth" });
  });

  // Theme toggle
  themeToggleBtn.addEventListener("click", () => {
    document.body.classList.toggle("light-theme");
  });

  // View All History shortcut from Overview
  btnViewAllHistory.addEventListener("click", () => {
    document.querySelector(".nav-tab[data-tab='history']").click();
  });

  // 2. Initialize Settings & Health Diagnostics
  async function initSettingsAndHealth() {
    const settings = await getSettings();
    
    // Set protection mode radio
    protectionModeRadios.forEach((r) => {
      r.checked = r.value === settings.protectionMode;
      r.addEventListener("change", async (e) => {
        if (e.target.checked) {
          await saveSettings({ protectionMode: e.target.value });
          overviewModeBadge.textContent = `${e.target.value.toUpperCase()} MODE`;
        }
      });
    });

    overviewModeBadge.textContent = `${settings.protectionMode.toUpperCase()} MODE`;

    settingPrivacyMode.checked = !!settings.privacyMode;
    settingPrivacyMode.addEventListener("change", async (e) => {
      await saveSettings({ privacyMode: e.target.checked });
    });

    settingTimeoutSlider.value = settings.scanTimeoutMs || 3000;
    lblTimeoutVal.textContent = `${(settingTimeoutSlider.value / 1000).toFixed(1)}s`;
    settingTimeoutSlider.addEventListener("input", (e) => {
      lblTimeoutVal.textContent = `${(e.target.value / 1000).toFixed(1)}s`;
    });
    settingTimeoutSlider.addEventListener("change", async (e) => {
      await saveSettings({ scanTimeoutMs: parseInt(e.target.value) });
    });

    // Check Backend Health
    const health = await checkBackendHealth();
    if (health.status === "operational") {
      backendHealthBadge.className = "status-indicator-pill online";
      backendHealthLabel.textContent = "Engine Online";
      healthBackendVal.textContent = "Connected (127.0.0.1:8000)";
      healthBackendVal.className = "health-ok";
    } else {
      backendHealthBadge.className = "status-indicator-pill degraded";
      backendHealthLabel.textContent = "Offline Fallback";
      healthBackendVal.textContent = "Offline (Client Heuristic Active)";
      healthBackendVal.className = "health-warn";
    }

    const modelInfo = await getModelInfo();
    if (modelInfo) {
      healthModelVal.textContent = `${modelInfo.model_name} (v${modelInfo.model_version})`;
    } else {
      healthModelVal.textContent = "Client Heuristic Ensemble 1.0";
    }
  }

  // 3. Load Overview KPIs & Activity Feed
  async function loadOverview() {
    const history = await getHistory(50);
    const total = history.length;
    const safe = history.filter((h) => h.riskLevel === "low").length;
    const suspicious = history.filter((h) => h.riskLevel === "medium").length;
    const risky = history.filter((h) => h.riskLevel === "high" || h.riskLevel === "critical").length;

    kpiTotalScans.textContent = total;
    kpiSafeLinks.textContent = safe;
    kpiSuspicious.textContent = suspicious;
    kpiRisky.textContent = risky;

    // Render Recent Feed
    overviewActivityFeed.innerHTML = "";
    if (history.length === 0) {
      overviewActivityFeed.innerHTML = `<div class="empty-state">No link evaluations yet. Browse the web to see real-time protection in action.</div>`;
      return;
    }

    history.slice(0, 5).forEach((item) => {
      const div = document.createElement("div");
      div.className = "feed-item";
      div.innerHTML = `
        <div class="feed-left">
          <span class="feed-score-badge ${item.riskLevel}">${item.riskScore}</span>
          <span class="feed-domain">${escapeHtml(item.registeredDomain || item.hostname || "Link")}</span>
        </div>
        <span class="feed-time">${formatTimestamp(item.timestamp)}</span>
      `;
      overviewActivityFeed.appendChild(div);
    });
  }

  // ─── Human-Readable Scan Verdict Card Builder ───────────────────────────────
  /**
   * Translates technical scan API response into a plain-English layered verdict card.
   * Returns an HTML string ready to be inserted into the result container.
   */
  function buildScanVerdictCard(res, scannedUrl) {
    const score = res.risk_score ?? 0;
    const level = (res.risk_level || "low").toLowerCase();

    // Determine severity tier
    const tier = level === "low" ? "safe" : (level === "medium" ? "warning" : "danger");

    const iconMap = { safe: "✅", warning: "⚠️", danger: "🛑" };
    const titleMap = {
      safe: "This link looks safe",
      warning: "Suspicious Link — Proceed with Caution",
      danger: "Unsafe Link Detected — Do Not Visit"
    };
    const subtitleMap = {
      safe: "No threats found. It appears safe to visit.",
      warning: "Something unusual was detected. Be careful before clicking.",
      danger: "This link shows signs of being harmful. We recommend closing it."
    };

    // Plain-English reason mapping for common technical evidence names / keywords
    function translateEvidence(ev) {
      const name = (ev.name || "").toLowerCase();
      const desc = (ev.description || "");

      const translations = {
        ssrf: {
          title: "Hidden Redirection Detected",
          plain: "This web address tried to secretly reroute your connection to a private or internal network — a tactic attackers use to steal system data. XGuard automatically blocked it."
        },
        redirect: {
          title: "Suspicious Redirect",
          plain: "This link redirects you to a different destination than expected. This is a common trick used in phishing attacks."
        },
        phishing: {
          title: "Phishing Attempt",
          plain: "This page is pretending to be a trusted website (like your bank or email) to steal your password or personal details."
        },
        typosquat: {
          title: "Fake Website (Look-alike Domain)",
          plain: "The web address is slightly misspelled to look like a real, trusted site. It is designed to trick you into thinking it is legitimate."
        },
        brand: {
          title: "Brand Impersonation",
          plain: "This site is copying the look and name of a well-known brand to gain your trust. It is not the real website."
        },
        malware: {
          title: "Malware Risk",
          plain: "This link may attempt to install harmful software on your device without your knowledge."
        },
        suspicious_tld: {
          title: "Unusual Website Ending",
          plain: "The website uses an uncommon or suspicious domain extension often associated with spam and scam sites."
        },
        ip_address: {
          title: "Direct IP Address Link",
          plain: "This link uses a raw IP address instead of a proper website name. Legitimate sites almost never do this — it is a red flag."
        },
        long_url: {
          title: "Unusually Long Address",
          plain: "The web address is abnormally long, which is a common trick to hide the true destination of a link."
        },
        obfuscation: {
          title: "Hidden / Scrambled Content",
          plain: "Parts of this link or page have been deliberately scrambled or disguised, which is often done to hide malicious intent from security tools."
        },
        reputation: {
          title: "Poor Reputation",
          plain: "This website has been reported by other users or security databases as unsafe or untrustworthy."
        }
      };

      // Try to match against known keys
      for (const [key, val] of Object.entries(translations)) {
        if (name.includes(key) || desc.toLowerCase().includes(key)) {
          return val;
        }
      }

      // Fallback: use raw description but clean it up
      return {
        title: toTitleCase(ev.name || "Anomaly Detected"),
        plain: desc || "An unusual pattern was detected in this link."
      };
    }

    function toTitleCase(str) {
      return str.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
    }

    const reasons = (res.evidence && res.evidence.length > 0)
      ? res.evidence.map(ev => {
          const t = translateEvidence(ev);
          return `
            <div class="scan-reason-item">
              <div class="scan-reason-bullet ${tier}"></div>
              <div class="scan-reason-text">
                <div class="scan-reason-title">${escapeHtml(t.title)}</div>
                <div class="scan-reason-desc">${escapeHtml(t.plain)}</div>
              </div>
            </div>`;
        }).join("")
      : `<div class="scan-safe-note"><span>✓</span><span>No suspicious activity was found. This link appears clean and safe to visit.</span></div>`;

    // Advanced technical details (hidden behind toggle)
    const rawDetails = [
      `Score: ${score}/100 (${level.toUpperCase()})`,
      `Category: ${res.predicted_category || "N/A"}`,
      `Recommended Action: ${res.recommended_action || "N/A"}`,
      `Checks Completed: ${(res.checks_completed || []).join(", ") || "N/A"}`,
      res.evidence && res.evidence.length > 0
        ? `Raw Evidence:\n  • ` + res.evidence.map(e => `[${e.name}] ${e.description}`).join("\n  • ")
        : ""
    ].filter(Boolean).join("\n");

    const scoreLabel = `${score}/100`;
    const reasonsSection = tier !== "safe"
      ? `<div class="scan-reasons-label">Why was it flagged?</div>${reasons}`
      : reasons;

    return `
      <div class="scan-verdict-card">
        <div class="scan-verdict-header ${tier}">
          <div class="scan-verdict-icon ${tier}">${iconMap[tier]}</div>
          <div class="scan-verdict-title-group">
            <div class="scan-verdict-title ${tier}">${titleMap[tier]}</div>
            <div class="scan-verdict-subtitle" title="${escapeHtml(scannedUrl)}">${escapeHtml(truncateUrl(scannedUrl, 45))}</div>
          </div>
          <div class="scan-verdict-score ${tier}">${scoreLabel}</div>
        </div>
        <div class="scan-verdict-body">
          ${reasonsSection}
          <button class="scan-advanced-toggle" id="advancedToggle">
            <span>🔬 Advanced Technical Details</span>
            <span class="toggle-arrow">▼</span>
          </button>
          <pre class="scan-advanced-details" id="advancedDetails">${escapeHtml(rawDetails)}</pre>
        </div>
      </div>
    `;
  }

  // 4. Manual URL Scan Handler
  btnManualScan.addEventListener("click", async () => {
    const url = manualScanInput.value.trim();
    if (!url) return;

    btnManualScan.disabled = true;
    btnManualScan.textContent = "Scanning...";
    manualScanResult.classList.remove("hidden");
    manualScanResult.innerHTML = "<em>Evaluating destination across ML and threat feeds...</em>";

    const res = await scanUrl(url);
    btnManualScan.disabled = false;
    btnManualScan.textContent = "Scan";

    manualScanResult.innerHTML = buildScanVerdictCard(res, url);

    // Wire up the advanced toggle
    const toggle = manualScanResult.querySelector("#advancedToggle");
    const details = manualScanResult.querySelector("#advancedDetails");
    if (toggle && details) {
      toggle.addEventListener("click", () => {
        const isOpen = details.classList.toggle("open");
        toggle.classList.toggle("open", isOpen);
      });
    }

    // Refresh overview stats
    loadOverview();
  });

  // 5. Inspect Active Tab
  async function inspectCurrentTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const tab = tabs[0];
      if (!tab || !tab.url || !tab.url.startsWith("http")) {
        currentSiteDomain.textContent = "Internal / Browser Page";
        currentSiteFullUrl.textContent = tab?.url || "N/A";
        currentSiteScore.textContent = "0";
        currentSiteLevelBadge.textContent = "LOCAL";
        currentSiteVerdictTitle.textContent = "Internal Browser Context";
        currentSiteVerdictDesc.textContent = "Chrome extensions, local files, or browser system tabs.";
        currentSiteEvidenceList.innerHTML = `<li class="evidence-item"><div class="evidence-dot"></div><div>System context is not subject to external threat scanning.</div></li>`;
        return;
      }

      activeTabUrl = tab.url;
      try {
        const u = new URL(tab.url);
        currentSiteDomain.textContent = u.hostname;
      } catch (e) {
        currentSiteDomain.textContent = tab.url;
      }
      currentSiteFullUrl.textContent = tab.url;
      currentSiteEvidenceList.innerHTML = `<li class="evidence-loading">Scanning active webpage signals...</li>`;

      // Scan active tab URL
      const scanRes = await scanUrl(tab.url);
      activeTabScanResult = scanRes;

      currentSiteScore.textContent = scanRes.risk_score;
      currentSiteLevelBadge.textContent = scanRes.risk_level.toUpperCase();
      currentSiteLevelBadge.className = `badge ${getRiskBadgeClass(scanRes.risk_level)}`;

      if (scanRes.risk_level === "low") {
        currentSiteVerdictTitle.textContent = "Classified Low Risk";
        currentSiteVerdictDesc.textContent = "Destination matches expected safety baselines for this category.";
      } else if (scanRes.risk_level === "medium") {
        currentSiteVerdictTitle.textContent = "Suspicious Destination";
        currentSiteVerdictDesc.textContent = "Elevated lexical tokens or unverified domain structure observed.";
      } else {
        currentSiteVerdictTitle.textContent = "High-Confidence Threat";
        currentSiteVerdictDesc.textContent = "High phishing probability or deceptive brand spoofing detected.";
      }

      currentSiteEvidenceList.innerHTML = "";
      if (scanRes.evidence && scanRes.evidence.length > 0) {
        scanRes.evidence.forEach((ev) => {
          const li = document.createElement("li");
          li.className = "evidence-item";
          li.innerHTML = `<div class="evidence-dot"></div><div><strong>${escapeHtml(ev.name)}:</strong> ${escapeHtml(ev.description)}</div>`;
          currentSiteEvidenceList.appendChild(li);
        });
      } else {
        currentSiteEvidenceList.innerHTML = `<li class="evidence-item"><div class="evidence-dot" style="background:#10B981;"></div><div>No suspicious lexical, brand, or reputation anomalies detected.</div></li>`;
      }
    });
  }

  btnRescanCurrentSite.addEventListener("click", () => inspectCurrentTab());
  btnAskAssistantAboutCurrent.addEventListener("click", () => {
    document.querySelector(".nav-tab[data-tab='assistant']").click();
    chatInput.value = "Why was this site scored this way?";
    sendMessage();
  });

  // 6. XGuard Assistant (Chatbot)
  async function sendMessage() {
    const text = chatInput.value.trim();
    if (!text) return;

    // Add user message bubble
    appendChatBubble("user", text);
    chatInput.value = "";

    // Show bot thinking bubble
    const thinkingBubble = appendChatBubble("bot", "<em>Analyzing security telemetry and consulting threat knowledge base...</em>");

    // Call chat API
    const response = await sendChatMessage(text, activeTabScanResult, chatConversationHistory);

    // Update conversation history
    chatConversationHistory.push({ role: "user", content: text });
    chatConversationHistory.push({ role: "assistant", content: response.answer });

    // Replace thinking bubble with formatted answer
    thinkingBubble.innerHTML = `<p>${formatMarkdown(response.answer)}</p>`;
    if (response.grounded_evidence && response.grounded_evidence.length > 0) {
      const evBox = document.createElement("div");
      evBox.style.cssText = "font-size:11px; margin-top:8px; padding-top:6px; border-top:1px solid rgba(255,255,255,0.08); color:var(--text-muted);";
      evBox.innerHTML = `<strong>Telemetry Basis:</strong> ${escapeHtml(response.grounded_evidence.join(" • "))}`;
      thinkingBubble.appendChild(evBox);
    }

    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function appendChatBubble(role, htmlContent) {
    const b = document.createElement("div");
    b.className = `chat-bubble ${role}`;
    b.innerHTML = htmlContent;
    chatMessages.appendChild(b);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return b;
  }

  function formatMarkdown(text) {
    return escapeHtml(text)
      .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
      .replace(/\*(.*?)\*/g, "<em>$1</em>")
      .replace(/`([^`]+)`/g, "<code style='background:rgba(0,0,0,0.3); padding:1px 4px; border-radius:3px;'>$1</code>")
      .replace(/\n\n/g, "</p><p>")
      .replace(/\n/g, "<br>");
  }

  btnSendChat.addEventListener("click", sendMessage);
  chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
  });

  btnClearChat.addEventListener("click", () => {
    chatConversationHistory = [];
    chatMessages.innerHTML = `<div class="chat-bubble bot"><p>Conversation cleared. How can I assist with your web security?</p></div>`;
  });

  // Prompt Chips
  promptChips.addEventListener("click", (e) => {
    const chip = e.target.closest(".chip");
    if (chip) {
      chatInput.value = chip.getAttribute("data-prompt");
      sendMessage();
    }
  });

  // 7. History View & Filtering
  async function loadHistoryView() {
    const history = await getHistory(200);
    const filter = historyRiskFilter.value;
    const search = historySearchInput.value.toLowerCase().trim();

    const filtered = history.filter((item) => {
      if (filter !== "all" && item.riskLevel !== filter) return false;
      if (search && !item.url.toLowerCase().includes(search) && !(item.registeredDomain || "").toLowerCase().includes(search)) return false;
      return true;
    });

    historyList.innerHTML = "";
    if (filtered.length === 0) {
      historyList.innerHTML = `<div class="empty-state">No scan records match your filters.</div>`;
      return;
    }

    filtered.forEach((item) => {
      const card = document.createElement("div");
      card.className = "history-item";
      card.innerHTML = `
        <div class="history-item-top">
          <div style="display:flex; align-items:center; gap:8px;">
            <span class="badge ${getRiskBadgeClass(item.riskLevel)}">${item.riskScore}/100</span>
            <strong>${escapeHtml(item.registeredDomain || item.hostname || "URL")}</strong>
          </div>
          <div style="display:flex; align-items:center; gap:6px;">
            <span style="font-size:10px; color:var(--text-muted);">${formatDateFull(item.timestamp)}</span>
            <button class="icon-btn-sm btn-delete-entry" data-id="${item.scanId}" title="Delete entry" style="background:none; border:none; cursor:pointer; color:var(--text-muted);">
              &times;
            </button>
          </div>
        </div>
        <div class="history-url">${escapeHtml(truncateUrl(item.url, 50))}</div>
      `;
      historyList.appendChild(card);
    });

    // Delete single item handler
    document.querySelectorAll(".btn-delete-entry").forEach((b) => {
      b.addEventListener("click", async (e) => {
        const id = e.target.getAttribute("data-id");
        await deleteHistoryEntry(id);
        loadHistoryView();
        loadOverview();
      });
    });
  }

  historySearchInput.addEventListener("input", () => loadHistoryView());
  historyRiskFilter.addEventListener("change", () => loadHistoryView());

  btnClearHistory.addEventListener("click", async () => {
    if (confirm("Are you sure you want to delete all local scan history records?")) {
      await clearAllHistory();
      loadHistoryView();
      loadOverview();
    }
  });

  // Export to JSON
  btnExportJson.addEventListener("click", async () => {
    const history = await getHistory(500);
    const blob = new Blob([JSON.stringify(history, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threatguard_scan_history_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Export to CSV
  btnExportCsv.addEventListener("click", async () => {
    const history = await getHistory(500);
    const headers = ["Timestamp", "URL", "Registered Domain", "Risk Score", "Risk Level", "Category", "Action"];
    const rows = history.map((h) => [
      `"${h.timestamp}"`,
      `"${(h.url || "").replace(/"/g, '""')}"`,
      `"${h.registeredDomain || ""}"`,
      h.riskScore,
      h.riskLevel,
      h.category,
      h.userAction
    ]);
    const csvContent = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threatguard_scan_history_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  });


  // ── Analytics ─────────────────────────────────────────────────────────────────
  let analyticsCurrentPeriod = "7d";

  // Category colours
  const CAT_COLORS = {
    benign: "#10B981", safe: "#10B981",
    typosquatting: "#F59E0B", suspicious: "#F59E0B",
    phishing: "#EF4444", malware: "#DC2626",
    unknown: "#64748B", ssrf: "#8B5CF6",
    ssrf_restricted_destination: "#8B5CF6",
    brand_impersonation: "#F97316",
    malicious_redirect: "#EC4899",
  };
  function getCatColor(cat) {
    return CAT_COLORS[(cat || "").toLowerCase()] || "#60A5FA";
  }

  // Helpers
  function fmtMs(ms) {
    if (ms == null) return "N/A";
    return ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${ms.toFixed(1)} ms`;
  }
  function fmtDelta(pct) {
    if (pct == null) return { text: "", cls: "flat" };
    const sign = pct > 0 ? "▲" : pct < 0 ? "▼" : "—";
    return { text: `${sign} ${Math.abs(pct)}%`, cls: pct > 0 ? "up" : pct < 0 ? "down" : "flat" };
  }
  function telCell(label, val, cls = "") {
    return `<div class="telemetry-cell">
      <div class="telemetry-cell-label">${escapeHtml(label)}</div>
      <div class="telemetry-cell-value ${cls}">${escapeHtml(String(val ?? "N/A"))}</div>
    </div>`;
  }

  // Period pills
  const analyticsPeriodPills = document.getElementById("analyticsPeriodPills");
  const analyticsRefreshBtn  = document.getElementById("analyticsRefreshBtn");

  analyticsPeriodPills?.addEventListener("click", (e) => {
    const pill = e.target.closest(".period-pill");
    if (!pill) return;
    document.querySelectorAll(".period-pill").forEach(p => p.classList.remove("active"));
    pill.classList.add("active");
    analyticsCurrentPeriod = pill.getAttribute("data-period");
    loadAnalyticsView();
  });

  analyticsRefreshBtn?.addEventListener("click", () => {
    analyticsRefreshBtn.disabled = true;
    loadAnalyticsView().finally(() => { analyticsRefreshBtn.disabled = false; });
  });

  // ── Canvas timeline chart (no external deps) ────────────────────────────────
  function drawTimelineChart(buckets) {
    const canvas = document.getElementById("timelineChart");
    if (!canvas) return;
    const parent = canvas.parentElement;
    canvas.width  = parent ? parent.clientWidth : 280;
    canvas.height = 110;
    const ctx = canvas.getContext("2d");
    const W = canvas.width, H = canvas.height;
    const PAD = { top: 8, right: 8, bottom: 24, left: 26 };
    const cW = W - PAD.left - PAD.right;
    const cH = H - PAD.top  - PAD.bottom;

    ctx.clearRect(0, 0, W, H);
    if (!buckets?.length) return;

    const totals = buckets.map(b => b.total);
    const maxVal = Math.max(...totals, 1);
    const N = buckets.length;
    const toX = i => PAD.left + (N > 1 ? i * cW / (N - 1) : cW / 2);
    const toY = v => PAD.top + cH - (v / maxVal) * cH;

    // Grid
    ctx.strokeStyle = "rgba(255,255,255,0.05)";
    ctx.lineWidth = 1;
    for (let g = 0; g <= 3; g++) {
      const y = PAD.top + (g / 3) * cH;
      ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(PAD.left + cW, y); ctx.stroke();
      ctx.fillStyle = "rgba(100,116,139,0.7)";
      ctx.font = "9px 'Outfit',sans-serif"; ctx.textAlign = "right";
      ctx.fillText(String(Math.round(maxVal - (g / 3) * maxVal)), PAD.left - 3, y + 3);
    }

    // Filled area
    const grad = ctx.createLinearGradient(0, PAD.top, 0, PAD.top + cH);
    grad.addColorStop(0, "rgba(0,242,254,0.18)"); grad.addColorStop(1, "rgba(0,242,254,0)");
    ctx.beginPath();
    ctx.moveTo(toX(0), toY(totals[0]));
    for (let i = 1; i < N; i++) ctx.lineTo(toX(i), toY(totals[i]));
    ctx.lineTo(toX(N - 1), PAD.top + cH); ctx.lineTo(toX(0), PAD.top + cH); ctx.closePath();
    ctx.fillStyle = grad; ctx.fill();

    // Line
    ctx.beginPath(); ctx.strokeStyle = "#00F2FE"; ctx.lineWidth = 2; ctx.lineJoin = "round";
    ctx.moveTo(toX(0), toY(totals[0]));
    for (let i = 1; i < N; i++) ctx.lineTo(toX(i), toY(totals[i]));
    ctx.stroke();

    // Dots
    ctx.fillStyle = "#00F2FE";
    totals.forEach((v, i) => { if (v > 0) { ctx.beginPath(); ctx.arc(toX(i), toY(v), 2.5, 0, Math.PI * 2); ctx.fill(); } });

    // X labels — skip crowded ones
    const step = Math.ceil(N / 6);
    ctx.fillStyle = "rgba(100,116,139,0.85)"; ctx.font = "9px 'Outfit',sans-serif"; ctx.textAlign = "center";
    for (let i = 0; i < N; i++) {
      if (i % step === 0 || i === N - 1) ctx.fillText(buckets[i].label, toX(i), H - 5);
    }
  }

  // ── Summary cards ───────────────────────────────────────────────────────────
  function renderSummaryCards(data) {
    if (!data) return;
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val ?? "0"; };
    const setDelta = (id, pct) => {
      const el = document.getElementById(id); if (!el) return;
      const d = fmtDelta(pct); el.textContent = d.text; el.className = `amc-delta ${d.cls}`;
    };
    set("amcTotalScansVal", data.total_scans);
    set("amcThreatsVal",    data.threats_blocked);
    set("amcSuspiciousVal", data.suspicious_urls);
    set("amcBenignVal",     data.benign_urls);
    setDelta("amcTotalScansDelta", data.total_scans_delta_pct);
    setDelta("amcThreatsDelta",    data.threats_blocked_delta_pct);
    setDelta("amcSuspiciousDelta", data.suspicious_delta_pct);
  }

  // ── Timeline ────────────────────────────────────────────────────────────────
  function renderTimeline(data) {
    const loading   = document.getElementById("timelineLoading");
    const empty     = document.getElementById("timelineEmpty");
    const canvasArea = document.getElementById("timelineCanvasArea");
    const summary   = document.getElementById("timelineSummaryRow");
    const meta      = document.getElementById("timelineMeta");

    if (loading) loading.classList.add("hidden");

    if (!data?.buckets?.length || data.total === 0) {
      empty?.classList.remove("hidden"); canvasArea?.classList.add("hidden"); return;
    }
    empty?.classList.add("hidden"); canvasArea?.classList.remove("hidden");
    drawTimelineChart(data.buckets);

    if (summary) {
      const totalSusp  = data.buckets.reduce((s, b) => s + b.suspicious, 0);
      const totalBlock = data.buckets.reduce((s, b) => s + b.blocked, 0);
      summary.innerHTML =
        `<div class="timeline-summary-chip"><strong>${data.total}</strong> scans</div>` +
        (data.peak_label ? `<div class="timeline-summary-chip">Peak: <strong>${escapeHtml(data.peak_label)}</strong></div>` : "") +
        (totalSusp  ? `<div class="timeline-summary-chip" style="color:#FBBF24"><strong>${totalSusp}</strong> suspicious</div>` : "") +
        (totalBlock ? `<div class="timeline-summary-chip" style="color:#F87171"><strong>${totalBlock}</strong> blocked</div>` : "");
    }
    if (meta) meta.textContent = `${data.total} scans`;
  }

  // ── Category bars (compact) ─────────────────────────────────────────────────
  function renderCategories(data) {
    const loading = document.getElementById("donutLoading");
    const bars    = document.getElementById("catBarsCompact");
    if (loading) loading.classList.add("hidden");
    if (!bars) return;

    if (!data?.categories?.length || data.total === 0) {
      bars.classList.remove("hidden");
      bars.innerHTML = `<div style="color:var(--text-muted);font-size:11px;padding:8px 0">No scan data for this period.</div>`;
      return;
    }
    bars.classList.remove("hidden");
    bars.innerHTML = data.categories.map(cat => {
      const color = getCatColor(cat.category);
      const name  = cat.category.replace(/_/g, " ").toUpperCase();
      return `<div class="cat-compact-row">
        <span class="cat-compact-dot" style="background:${color}"></span>
        <span class="cat-compact-name">${escapeHtml(name)}</span>
        <div class="cat-compact-track">
          <div class="cat-compact-fill" style="width:${cat.percentage}%;background:${color}22;border-right:2px solid ${color}"></div>
        </div>
        <span class="cat-compact-pct">${cat.count} <span style="color:var(--text-muted)">${cat.percentage}%</span></span>
      </div>`;
    }).join("");
  }

  // ── Compact telemetry ───────────────────────────────────────────────────────
  function renderTelemetry(data) {
    const loading  = document.getElementById("telemetryLoading");
    const grid     = document.getElementById("telemetryContent");
    if (loading) loading.classList.add("hidden");
    if (!grid) return;
    grid.classList.remove("hidden");

    if (!data) { grid.innerHTML = `<div class="trends-empty">Unavailable.</div>`; return; }
    const sp = data.scan_performance || {};
    const ui = data.user_interaction || {};
    const overrideColor = (ui.override_rate_pct ?? 0) > 20 ? "danger" : (ui.override_rate_pct ?? 0) > 5 ? "warning" : "safe";

    grid.innerHTML = [
      telCell("AVG LATENCY",   fmtMs(sp.avg_latency_ms),      "accent"),
      telCell("P95 LATENCY",   fmtMs(sp.p95_latency_ms)),
      telCell("SUCCESS RATE",  sp.success_rate_pct != null ? `${sp.success_rate_pct}%` : "N/A", sp.success_rate_pct >= 95 ? "safe" : "warning"),
      telCell("USER OVERRIDES",ui.total_overrides ?? "N/A",   ui.total_overrides > 0 ? overrideColor : "safe"),
    ].join("");
  }

  // ── Main loader ─────────────────────────────────────────────────────────────
  async function loadAnalyticsView() {
    const period = analyticsCurrentPeriod;

    // Reset loading states
    ["timelineLoading","donutLoading","telemetryLoading"].forEach(id => {
      document.getElementById(id)?.classList.remove("hidden");
    });
    document.getElementById("timelineCanvasArea")?.classList.add("hidden");
    document.getElementById("timelineEmpty")?.classList.add("hidden");
    document.getElementById("catBarsCompact")?.classList.add("hidden");
    document.getElementById("telemetryContent")?.classList.add("hidden");

    const [summary, timeseries, categories, telemetry] = await Promise.all([
      getAnalyticsSummary(period),
      getAnalyticsTimeseries(period),
      getAnalyticsCategories(period),
      getAnalyticsTelemetry(period),
    ]);

    renderSummaryCards(summary);
    renderTimeline(timeseries);
    renderCategories(categories);
    renderTelemetry(telemetry);
  }


    // 9. QR Code Phishing Protection
  qrDropZone.addEventListener("click", () => qrFileInput.click());
  qrFileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (file) handleQrImage(file);
  });

  qrDropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    qrDropZone.style.borderColor = "#00F2FE";
  });
  qrDropZone.addEventListener("dragleave", () => {
    qrDropZone.style.borderColor = "";
  });
  qrDropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    qrDropZone.style.borderColor = "";
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleQrImage(e.dataTransfer.files[0]);
    }
  });

  // Handle Clipboard Paste for QR image
  window.addEventListener("paste", (e) => {
    const items = e.clipboardData?.items;
    if (!items) return;
    for (let i = 0; i < items.length; i++) {
      if (items[i].type.indexOf("image") !== -1) {
        const file = items[i].getAsFile();
        handleQrImage(file);
        break;
      }
    }
  });

  async function handleQrImage(file) {
    // Reset previous results
    qrResultBox.classList.add("hidden");
    qrScanVerdict.classList.add("hidden");

    // Show decoding state in the drop zone label
    const dropLabel = qrDropZone.querySelector(".qr-drop-text");
    if (dropLabel) dropLabel.textContent = "Decoding QR code…";

    try {
      // jsQR is loaded as a classic global script (works in all extension contexts)
      if (typeof jsQR === "undefined") {
        throw new Error("QR decoder library failed to load. Please reload the extension.");
      }

      // Draw the image onto an offscreen canvas to get pixel data
      const bitmap = await createImageBitmap(file);
      const canvas = document.createElement("canvas");
      canvas.width  = bitmap.width;
      canvas.height = bitmap.height;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(bitmap, 0, 0);
      bitmap.close();

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "dontInvert",
      });

      if (!code || !code.data) {
        // Nothing found — try inverted (light QR on dark background)
        const codeInv = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: "onlyInvert",
        });
        if (!codeInv || !codeInv.data) {
          qrResultBox.classList.remove("hidden");
          qrResultBox.innerHTML = `
            <div style="color:#FBBF24; font-size:12px; padding:6px 0; display:flex; gap:6px; align-items:center;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              No QR code found in this image. Try a clearer or higher-resolution photo.
            </div>`;
          return;
        }
        // Inverted QR found
        renderQrResult(codeInv.data);
        return;
      }

      renderQrResult(code.data);

    } catch (err) {
      qrResultBox.classList.remove("hidden");
      qrResultBox.innerHTML = `
        <div style="color:#F87171; font-size:12px; padding:6px 0; display:flex; gap:6px; align-items:center;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          ${escapeHtml(err.message || "Failed to decode QR code.")}
        </div>`;
    } finally {
      if (dropLabel) dropLabel.textContent = "Drag & drop QR image, click to browse, or paste clipboard";
    }
  }

  function renderQrResult(rawValue) {
    // Rebuild the result box with the real decoded value
    qrResultBox.innerHTML = `
      <span class="detail-lbl">Decoded Destination:</span>
      <div class="qr-decoded-url" id="qrDecodedUrl">${escapeHtml(rawValue)}</div>
      <button class="btn btn-primary btn-sm" id="btnScanDecodedQr">Inspect Extracted Link Safety</button>
    `;
    qrResultBox.classList.remove("hidden");
    qrScanVerdict.classList.add("hidden");

    document.getElementById("btnScanDecodedQr")?.addEventListener("click", async () => {
      const url = document.getElementById("qrDecodedUrl")?.textContent?.trim();
      if (!url) return;

      const btn = document.getElementById("btnScanDecodedQr");
      btn.disabled = true;
      btn.textContent = "Analyzing QR Destination…";

      try {
        const res = await scanUrl(url);
        const isLow = res.risk_level === "low";
        qrScanVerdict.classList.remove("hidden");
        qrScanVerdict.innerHTML = `
          <div style="background:rgba(0,0,0,0.4); border:1px solid ${isLow ? "#10B981" : "#EF4444"}; border-radius:8px; padding:12px; margin-top:10px;">
            <strong style="color:${isLow ? "#10B981" : "#F87171"};">Verdict: ${escapeHtml(res.risk_level.toUpperCase())} (${res.risk_score}/100)</strong>
            <p style="margin:4px 0; font-size:12px;">Category: <strong>${escapeHtml((res.predicted_category || "unknown").toUpperCase())}</strong></p>
            <p style="font-size:11px; color:var(--text-secondary);">${escapeHtml(res.evidence?.[0]?.description || "No anomalies detected.")}</p>
          </div>`;
      } catch (err) {
        qrScanVerdict.classList.remove("hidden");
        qrScanVerdict.innerHTML = `<div style="color:#F87171;font-size:12px;padding:8px 0;">Scan failed: ${escapeHtml(err.message)}</div>`;
      } finally {
        btn.disabled = false;
        btn.textContent = "Inspect Extracted Link Safety";
      }
    });
  }


  // btnScanDecodedQr listener is now attached dynamically inside handleQrImage()

  // 10. Submit Feedback
  btnSubmitFeedback.addEventListener("click", async () => {
    const url = feedbackUrlInput.value.trim();
    if (!url) {
      alert("Please provide the URL to report.");
      return;
    }
    if (!feedbackConsentCheck.checked) {
      alert("Please consent to telemetry report submission.");
      return;
    }

    btnSubmitFeedback.disabled = true;
    btnSubmitFeedback.textContent = "Submitting...";

    try {
      await submitFeedback({
        url: url,
        feedback_type: feedbackTypeSelect.value,
        user_comment: feedbackComment.value.trim(),
        user_consent: true
      });
      alert("Feedback received successfully. Thank you!");
      feedbackUrlInput.value = "";
      feedbackComment.value = "";
      feedbackConsentCheck.checked = false;
    } catch (e) {
      alert("Failed to send feedback to backend server.");
    } finally {
      btnSubmitFeedback.disabled = false;
      btnSubmitFeedback.textContent = "Submit Feedback Report";
    }
  });

  // Initial runs
  await initSettingsAndHealth();
  await loadOverview();
  inspectCurrentTab();
});
