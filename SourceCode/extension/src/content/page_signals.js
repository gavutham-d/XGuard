/**
 * Content Script: Extracts live webpage signals for Layer E of XGuard.
 */

(function () {
  function extractPageSignals() {
    try {
      const currentHost = window.location.hostname.toLowerCase();
      const forms = Array.from(document.querySelectorAll("form"));
      let hasPassword = false;
      let hasCard = false;
      let hasCrossDomainForm = false;
      const formActions = [];

      forms.forEach((f) => {
        const passInputs = f.querySelectorAll("input[type='password']");
        if (passInputs.length > 0) hasPassword = true;

        const cardInputs = f.querySelectorAll(
          "input[name*='card'], input[name*='cc_'], input[autocomplete*='cc-number'], input[id*='credit']"
        );
        if (cardInputs.length > 0) hasCard = true;

        const action = f.getAttribute("action") || "";
        formActions.push(action);
        if (action.startsWith("http://") || action.startsWith("https://")) {
          try {
            const actionHost = new URL(action).hostname.toLowerCase();
            if (actionHost && actionHost !== currentHost && !actionHost.endsWith("." + currentHost)) {
              hasCrossDomainForm = true;
            }
          } catch (e) {}
        }
      });

      const iframes = document.querySelectorAll("iframe");

      return {
        has_password_field: hasPassword,
        has_card_field: hasCard,
        form_actions: formActions.slice(0, 5),
        has_cross_domain_form: hasCrossDomainForm,
        iframe_count: iframes.length,
        page_title: document.title || "",
        link_text_mismatch: false
      };
    } catch (e) {
      return {
        has_password_field: false,
        has_card_field: false,
        form_actions: [],
        has_cross_domain_form: false,
        iframe_count: 0,
        page_title: "",
        link_text_mismatch: false
      };
    }
  }

  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.action === "GET_PAGE_SIGNALS") {
      sendResponse(extractPageSignals());
      return true;
    }
  });

  window.__threatguard_page_signals = extractPageSignals;
})();
