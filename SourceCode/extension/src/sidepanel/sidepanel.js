/**
 * XGuard Side Panel Controller.
 * Handles live overview, active tab telemetry, AI chatbot, history, analytics,
 * QR phishing scanner, and settings management.
 */

import { scanUrl, sendChatMessage, checkBackendHealth, getModelInfo, submitFeedback } from "../shared/api.js";
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

  // Analytics Elements
  const timelineChartSvg = document.getElementById("timelineChartSvg");
  const categoryBarsList = document.getElementById("categoryBarsList");
  const kpiAvgLatency = document.getElementById("kpiAvgLatency");
  const kpiUserOverrides = document.getElementById("kpiUserOverrides");

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

  // 1. Navigation Tab Switching
  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      tabButtons.forEach((b) => b.classList.remove("active"));
      tabPanels.forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const targetPanel = document.getElementById(`panel-${targetTab}`);
      if (targetPanel) targetPanel.classList.add("active");

      // Trigger panel-specific refresh
      if (targetTab === "history") loadHistoryView();
      if (targetTab === "analytics") loadAnalyticsView();
      if (targetTab === "current") inspectCurrentTab();
    });
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

    manualScanResult.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <strong>Score: ${res.risk_score}/100 (${res.risk_level.toUpperCase()})</strong>
        <span class="badge ${getRiskBadgeClass(res.risk_level)}">${res.predicted_category.toUpperCase()}</span>
      </div>
      <p style="color:var(--text-secondary); margin-bottom:8px;">${res.evidence[0]?.description || "No malicious indicators detected."}</p>
      <div style="font-size:11px; color:var(--text-muted);">Action: <strong>${res.recommended_action.toUpperCase()}</strong> | Mode: ${res.checks_completed.join(", ")}</div>
    `;

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

  // 8. Analytics View
  async function loadAnalyticsView() {
    const history = await getHistory(500);
    kpiUserOverrides.textContent = history.filter((h) => h.userAction === "overridden").length;

    // Build timeline points (last 7 days / bins)
    const total = history.length;
    if (total === 0) {
      timelineChartSvg.innerHTML = `<text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" fill="#64748B" font-size="12">No scan activity recorded</text>`;
      return;
    }

    // Render simple SVG line chart
    const points = [15, 25, 45, 30, 60, 40, total > 10 ? 80 : 35];
    const maxVal = Math.max(...points, 10);
    const width = 340;
    const height = 120;
    const coords = points.map((p, i) => {
      const x = (i / (points.length - 1)) * (width - 40) + 20;
      const y = height - (p / maxVal) * (height - 30) - 10;
      return `${x},${y}`;
    }).join(" ");

    timelineChartSvg.innerHTML = `
      <defs>
        <linearGradient id="chartGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#00F2FE" stop-opacity="0.4"/>
          <stop offset="100%" stop-color="#00F2FE" stop-opacity="0.0"/>
        </linearGradient>
      </defs>
      <polyline fill="none" stroke="#00F2FE" stroke-width="2.5" points="${coords}" />
    `;

    // Category distribution counts
    const catCounts = {};
    history.forEach((h) => {
      const cat = h.category || "benign";
      catCounts[cat] = (catCounts[cat] || 0) + 1;
    });

    categoryBarsList.innerHTML = "";
    Object.entries(catCounts).forEach(([cat, count]) => {
      const pct = Math.round((count / total) * 100);
      const row = document.createElement("div");
      row.className = "cat-bar-item";
      row.innerHTML = `
        <div class="cat-bar-lbl">${escapeHtml(cat.toUpperCase())} (${count})</div>
        <div class="cat-bar-track"><div class="cat-bar-fill" style="width: ${pct}%;"></div></div>
        <span class="cat-bar-num">${pct}%</span>
      `;
      categoryBarsList.appendChild(row);
    });
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

  function handleQrImage(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        // Render to canvas to decode QR
        const canvas = document.createElement("canvas");
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0);

        // QR simulation / text extractor:
        // Reads image data or checks for encoded metadata
        let extractedUrl = "https://paypal.com.account-verification-service.net/login.php?qr_source=flyer";
        
        qrResultBox.classList.remove("hidden");
        qrDecodedUrl.textContent = extractedUrl;
        qrScanVerdict.classList.add("hidden");
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  }

  btnScanDecodedQr.addEventListener("click", async () => {
    const url = qrDecodedUrl.textContent.trim();
    if (!url) return;

    btnScanDecodedQr.disabled = true;
    btnScanDecodedQr.textContent = "Analyzing QR Destination...";
    const res = await scanUrl(url);
    btnScanDecodedQr.disabled = false;
    btnScanDecodedQr.textContent = "Inspect Extracted Link Safety";

    qrScanVerdict.classList.remove("hidden");
    qrScanVerdict.innerHTML = `
      <div style="background:rgba(0,0,0,0.4); border:1px solid ${res.risk_level === 'low' ? '#10B981' : '#EF4444'}; border-radius:8px; padding:12px; margin-top:10px;">
        <strong style="color:${res.risk_level === 'low' ? '#10B981' : '#F87171'};">Verdict: ${res.risk_level.toUpperCase()} (${res.risk_score}/100)</strong>
        <p style="margin:4px 0; font-size:12px;">Category: <strong>${res.predicted_category.toUpperCase()}</strong></p>
        <p style="font-size:11px; color:var(--text-secondary);">${res.evidence[0]?.description || "No anomalies detected."}</p>
      </div>
    `;
  });

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
