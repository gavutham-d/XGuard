/**
 * Content Script: Link Interception and Safe Navigation for XGuard.
 * Intercepts clicked links, shows brief scanning indicator,
 * coordinates risk evaluation with background worker, and routes to safety.
 */

(function () {
  let isScanning = false;
  let activeScanUrl = null;
  const sessionApprovedUrls = new Set();

  // Create or return floating scanning badge
  function createScanPill() {
    let pill = document.getElementById("threatguard-scan-pill");
    if (!pill) {
      pill = document.createElement("div");
      pill.id = "threatguard-scan-pill";
      pill.innerHTML = `
        <div class="tg-pill-inner">
          <div class="tg-spinner"></div>
          <span class="tg-pill-text">XGuard: Verifying destination...</span>
        </div>
      `;
      // Inject CSS styles into page
      const style = document.createElement("style");
      style.id = "threatguard-pill-styles";
      style.textContent = `
        #threatguard-scan-pill {
          position: fixed;
          top: 20px;
          left: 50%;
          transform: translateX(-50%) translateY(-20px);
          z-index: 2147483647;
          background: rgba(11, 15, 25, 0.94);
          backdrop-filter: blur(12px);
          -webkit-backdrop-filter: blur(12px);
          border: 1px solid rgba(0, 242, 254, 0.4);
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6), 0 0 15px rgba(0, 242, 254, 0.2);
          border-radius: 9999px;
          padding: 8px 18px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
          font-size: 13px;
          color: #F8FAFC;
          opacity: 0;
          transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
          pointer-events: none;
        }
        #threatguard-scan-pill.tg-visible {
          opacity: 1;
          transform: translateX(-50%) translateY(0);
        }
        #threatguard-scan-pill.tg-success {
          border-color: rgba(16, 185, 129, 0.6);
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6), 0 0 15px rgba(16, 185, 129, 0.3);
        }
        #threatguard-scan-pill.tg-danger {
          border-color: rgba(239, 68, 68, 0.6);
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6), 0 0 15px rgba(239, 68, 68, 0.3);
        }
        .tg-pill-inner {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .tg-spinner {
          width: 14px;
          height: 14px;
          border: 2px solid rgba(0, 242, 254, 0.2);
          border-top-color: #00F2FE;
          border-radius: 50%;
          animation: tg-spin 0.6s linear infinite;
        }
        .tg-success .tg-spinner {
          border-color: rgba(16, 185, 129, 0.2);
          border-top-color: #10B981;
        }
        @keyframes tg-spin {
          to { transform: rotate(360deg); }
        }
      `;
      if (!document.getElementById("threatguard-pill-styles")) {
        document.documentElement.appendChild(style);
      }
      document.documentElement.appendChild(pill);
    }
    return pill;
  }

  function showPill(text, state = "scanning") {
    const pill = createScanPill();
    pill.className = "tg-visible";
    if (state === "success") pill.classList.add("tg-success");
    if (state === "danger") pill.classList.add("tg-danger");
    pill.querySelector(".tg-pill-text").textContent = text;
  }

  function hidePill(delay = 0) {
    setTimeout(() => {
      const pill = document.getElementById("threatguard-scan-pill");
      if (pill) {
        pill.classList.remove("tg-visible");
      }
    }, delay);
  }

  // Intercept click events on links
  async function handleLinkClick(e) {
    // If target was already intercepted or user held right click, ignore
    if (e.button !== 0 && e.button !== 1) return; // 0=left click, 1=middle click

    const anchor = e.target.closest("a");
    if (!anchor) return;

    const href = anchor.href;
    if (!href) return;

    // Filter out internal hashes, javascript, mailto, tel
    if (
      href.startsWith("javascript:") ||
      href.startsWith("mailto:") ||
      href.startsWith("tel:") ||
      href.startsWith("#") ||
      href.includes(window.location.pathname + "#")
    ) {
      return;
    }

    // Only intercept HTTP and HTTPS
    if (!href.startsWith("http://") && !href.startsWith("https://")) {
      return;
    }

    // Check if session approved or bypass token exists
    if (sessionApprovedUrls.has(href)) {
      return; // Allow native navigation seamlessly
    }

    // Prevent navigation while verifying
    e.preventDefault();
    e.stopPropagation();

    if (isScanning && activeScanUrl === href) {
      return; // Prevent duplicate clicks
    }

    isScanning = true;
    activeScanUrl = href;

    const isNewTab =
      anchor.target === "_blank" ||
      e.ctrlKey ||
      e.metaKey ||
      e.button === 1;

    showPill("🛡️ XGuard: Verifying link safety...", "scanning");

    // Extract live page signals
    let pageSignals = null;
    if (window.__threatguard_page_signals) {
      pageSignals = window.__threatguard_page_signals();
    }

    // Check link text mismatch
    const anchorText = (anchor.innerText || "").trim();
    if (anchorText.startsWith("http://") || anchorText.startsWith("https://") || anchorText.includes(".com")) {
      try {
        const textHost = new URL(anchorText.startsWith("http") ? anchorText : "http://" + anchorText).hostname;
        const targetHost = new URL(href).hostname;
        if (textHost && targetHost && textHost !== targetHost && pageSignals) {
          pageSignals.link_text_mismatch = true;
        }
      } catch (err) {}
    }

    try {
      // Send scan message to background service worker
      chrome.runtime.sendMessage(
        {
          action: "INTERCEPT_AND_SCAN",
          url: href,
          pageSignals: pageSignals,
          linkText: anchorText
        },
        (result) => {
          isScanning = false;
          activeScanUrl = null;

          if (!result) {
            hidePill(0);
            resumeNavigation(href, isNewTab);
            return;
          }

          if (result.recommended_action === "allow") {
            // Low Risk: Show brief green pill and proceed smoothly
            showPill(`✓ Verified Safe (Score: ${result.risk_score})`, "success");
            sessionApprovedUrls.add(href);
            hidePill(350);
            setTimeout(() => {
              resumeNavigation(href, isNewTab);
            }, 300);
          } else {
            // Risky link: Do NOT navigate to malicious destination!
            // Direct user immediately to the XGuard warning interstitial page
            hidePill(0);
            chrome.runtime.sendMessage({
              action: "OPEN_WARNING_INTERSTITIAL",
              scanResult: result,
              originalUrl: href,
              isNewTab: isNewTab
            });
          }
        }
      );
    } catch (err) {
      isScanning = false;
      activeScanUrl = null;
      hidePill(0);
      resumeNavigation(href, isNewTab);
    }
  }

  function resumeNavigation(url, inNewTab) {
    if (inNewTab) {
      window.open(url, "_blank", "noopener,noreferrer");
    } else {
      window.location.assign(url);
    }
  }

  // Listen for bypass authorization from warning page override
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "AUTHORIZE_BYPASS") {
      sessionApprovedUrls.add(msg.url);
      sendResponse({ status: "ok" });
      return true;
    }
  });

  // Attach listener with capture=true to intercept before page scripts
  document.addEventListener("click", handleLinkClick, true);

  // Keyboard navigation (Enter key on focused link)
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && document.activeElement && document.activeElement.tagName === "A") {
      handleLinkClick({
        target: document.activeElement,
        preventDefault: () => e.preventDefault(),
        stopPropagation: () => e.stopPropagation(),
        ctrlKey: e.ctrlKey,
        metaKey: e.metaKey,
        button: 0
      });
    }
  }, true);
})();
