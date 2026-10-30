
/**
 * API Client for XGuard backend.
 * Provides URL scanning, diagnostic logging, timeout handling,
 * and a local heuristic fallback if the backend is unavailable.
 */

import { getSettings } from "./storage.js";

// Known brands and their official domains.
// These rules are heuristics, not proof that a URL is malicious.
const CLIENT_BRANDS = {
  google: "google.com",
  microsoft: "microsoft.com",
  apple: "apple.com",
  paypal: "paypal.com",
  amazon: "amazon.com",
  netflix: "netflix.com",
  chase: "chase.com",
  bankofamerica: "bankofamerica.com",
  facebook: "facebook.com",
  binance: "binance.com",
  steam: "steampowered.com"
};

const RISKY_EXTENSIONS = [
  ".exe", ".scr", ".bat", ".vbs", ".msi", ".apk", ".dmg"
];

const SUSPICIOUS_WORDS = [
  "login", "verify", "secure", "account",
  "banking", "wallet", "password", "update"
];

const DEFAULT_BACKEND_URL = "http://127.0.0.1:8000";
const DEFAULT_TIMEOUT_MS = 10000;
const MAX_TIMEOUT_MS = 30000;

/**
 * Get a normalized backend URL from extension settings.
 */
async function getBackendConfig() {
  const settings = await getSettings();

  const configuredUrl =
    typeof settings.backendUrl === "string"
      ? settings.backendUrl.trim()
      : "";

  const backendUrl = (
    configuredUrl || DEFAULT_BACKEND_URL
  ).replace(/\/+$/, "");

  let parsedBackendUrl;

  try {
    parsedBackendUrl = new URL(backendUrl);
  } catch {
    throw new Error("Invalid backend URL in XGuard settings.");
  }

  if (
    parsedBackendUrl.protocol !== "http:" &&
    parsedBackendUrl.protocol !== "https:"
  ) {
    throw new Error("Backend URL must use HTTP or HTTPS.");
  }

  const configuredTimeout = Number(settings.scanTimeoutMs);

  const timeoutMs = Math.min(
    Math.max(
      Number.isFinite(configuredTimeout) && configuredTimeout > 0
        ? configuredTimeout
        : DEFAULT_TIMEOUT_MS,
      10000
    ),
    MAX_TIMEOUT_MS
  );

  return {
    settings,
    backendUrl,
    timeoutMs
  };
}

/**
 * Make a backend request with a timeout.
 * The timer remains active until the response body is read.
 */
async function backendRequest(
  url,
  options = {},
  timeoutMs = DEFAULT_TIMEOUT_MS
) {
  const controller = new AbortController();

  let timedOut = false;

  const timeoutId = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} from ${url}`);
    }

    return await response.json();
  } catch (error) {
    if (timedOut) {
      throw new Error(
        `Backend request timed out after ${timeoutMs} ms.`
      );
    }

    if (error.name === "AbortError") {
      throw new Error("Backend request was cancelled.");
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Scan a URL using the backend.
 * If the backend fails, use local heuristics and mark the result
 * as a fallback result rather than claiming an ML verdict.
 */
export async function scanUrl(url, customOptions = {}) {
  let settings = {};
  let protectionMode = "balanced";
  let backendUrl = DEFAULT_BACKEND_URL;

  try {
    const config = await getBackendConfig();

    settings = config.settings;
    protectionMode = settings.protectionMode || "balanced";
    backendUrl = config.backendUrl;

    const timeoutMs = config.timeoutMs;

    const requestBody = {
      url,
      options: {
        mode: protectionMode,
        resolve_redirects: true,
        ...customOptions
      }
    };

    console.info("[XGuard] Starting backend scan", {
      backendUrl,
      timeoutMs,
      url
    });

    const data = await backendRequest(
      `${backendUrl}/api/v1/scan`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(requestBody)
      },
      timeoutMs
    );

    console.info("[XGuard] Backend scan completed", {
      url,
      riskLevel: data.risk_level,
      riskScore: data.risk_score
    });

    return data;
  } catch (error) {
    console.error("[XGuard] Backend scan failed", {
      url,
      errorName: error.name,
      errorMessage: error.message,
      backendUrl
    });

    return localOfflineFallbackScan(
      url,
      protectionMode,
      error.message
    );
  }
}

/**
 * Conservative client-side fallback.
 *
 * This is not a replacement for backend ML, threat-intelligence
 * services, reputation checks, or redirect analysis.
 */
function localOfflineFallbackScan(
  rawUrl,
  mode = "balanced",
  errorReason = "Backend unavailable"
) {
  let parsedUrl;
  let hostname = "";
  let path = "";

  try {
    parsedUrl = new URL(rawUrl);
    hostname = parsedUrl.hostname.toLowerCase();
    path = parsedUrl.pathname.toLowerCase();

    if (
      parsedUrl.protocol !== "http:" &&
      parsedUrl.protocol !== "https:"
    ) {
      throw new Error("Only HTTP and HTTPS URLs can be scanned.");
    }
  } catch {
    return {
      scan_id: `local-fallback-${Date.now()}`,
      url: rawUrl,
      hostname: "",
      registered_domain: "",
      risk_score: 80,
      risk_level: "high",
      predicted_category: "invalid_url",
      model_probability: null,
      model_version: "Client-Offline-Heuristic-1.0",
      evidence: [{
        name: "invalid_or_unsupported_url",
        category: "validation",
        description: "The URL is invalid or uses an unsupported protocol.",
        severity: "high",
        source: "client_offline_engine"
      }],
      redirect_chain: [],
      intelligence_matches: [],
      checks_completed: ["url_validation"],
      checks_failed: [`backend_scan_failed: ${errorReason}`],
      recommended_action: "warn",
      scan_timestamp: new Date().toISOString(),
      scan_duration_ms: 0,
      user_action: "pending",
      detection_source: "local_fallback",
      backend_available: false
    };
  }

  const evidence = [];
  let riskScore = 10;
  let category = "unknown";

  // Detect IPv4 hosts and validate their octets.
  const ipv4Match = hostname.match(
    /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  );

  if (
    ipv4Match &&
    ipv4Match.slice(1).every(
      octet => Number(octet) >= 0 && Number(octet) <= 255
    )
  ) {
    evidence.push({
      name: "ip_address_host",
      category: "lexical",
      description: `Destination uses a raw IP address (${hostname}).`,
      severity: "medium",
      source: "client_offline_engine"
    });

    riskScore += 25;
    category = "suspicious";
  }

  // Detect internationalized Punycode hostnames.
  if (hostname.includes("xn--")) {
    evidence.push({
      name: "punycode_domain",
      category: "lexical",
      description: "Hostname contains Punycode and needs closer inspection.",
      severity: "medium",
      source: "client_offline_engine"
    });

    riskScore += 25;
    category = "possible_phishing";
  }

  // Detect potentially dangerous file extensions.
  const hasRiskyExtension = RISKY_EXTENSIONS.some(
    extension => path.endsWith(extension)
  );

  if (hasRiskyExtension) {
    evidence.push({
      name: "dangerous_file_extension",
      category: "lexical",
      description: "URL points to a potentially dangerous file type.",
      severity: "high",
      source: "client_offline_engine"
    });

    riskScore += 40;
    category = "possible_malware";
  }

  // Detect brand names used outside their official domains.
  for (const [brand, officialDomain] of Object.entries(CLIENT_BRANDS)) {
    const isOfficialDomain =
      hostname === officialDomain ||
      hostname.endsWith(`.${officialDomain}`);

    if (hostname.includes(brand) && !isOfficialDomain) {
      evidence.push({
        name: "possible_brand_impersonation",
        category: "brand",
        description:
          `Hostname contains "${brand}" but is not the official ` +
          `"${officialDomain}" domain.`,
        severity: "high",
        source: "client_offline_engine"
      });

      riskScore += 40;
      category = "possible_brand_impersonation";
      break;
    }
  }

  // Detect combinations of credential-related URL keywords.
  const lowerUrl = rawUrl.toLowerCase();

  const keywordMatches = SUSPICIOUS_WORDS.filter(
    word => lowerUrl.includes(word)
  );

  if (keywordMatches.length >= 2) {
    evidence.push({
      name: "credential_related_keywords",
      category: "lexical",
      description:
        `URL contains potentially sensitive terms: ` +
        `${keywordMatches.slice(0, 3).join(", ")}.`,
      severity: "medium",
      source: "client_offline_engine"
    });

    riskScore += 15;

    if (category === "unknown") {
      category = "suspicious";
    }
  }

  riskScore = Math.min(99, riskScore);

  let riskLevel = "low";

  if (riskScore >= 85) {
    riskLevel = "critical";
  } else if (riskScore >= 60) {
    riskLevel = "high";
  } else if (riskScore >= 25) {
    riskLevel = "medium";
  }

  // When the backend is unavailable, heuristics cannot establish
  // that a URL is safe. Use a warning rather than silently trusting it.
  let recommendedAction = "warn";

  if (riskLevel === "critical") {
    recommendedAction = "block";
  } else if (mode === "strict" && riskLevel !== "low") {
    recommendedAction = "block";
  }

  return {
    scan_id: `local-fallback-${Date.now()}`,
    url: rawUrl,
    hostname,
    registered_domain: hostname,
    risk_score: riskScore,
    risk_level: riskLevel,
    predicted_category: category,
    model_probability: null,
    model_version: "Client-Offline-Heuristic-1.0",
    evidence,
    redirect_chain: [],
    intelligence_matches: [],
    checks_completed: [
      "url_validation",
      "client_lexical_heuristics",
      "brand_rules"
    ],
    checks_failed: [
      `backend_scan_failed: ${errorReason}`
    ],
    recommended_action: recommendedAction,
    scan_timestamp: new Date().toISOString(),
    scan_duration_ms: 0,
    user_action: "pending",
    detection_source: "local_fallback",
    backend_available: false
  };
}

/**
 * Chat assistant.
 */
export async function sendChatMessage(
  message,
  currentScanContext = null,
  history = []
) {
  try {
    const config = await getBackendConfig();

    const result = await backendRequest(
      `${config.backendUrl}/api/v1/chat`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          message,
          current_scan_context: currentScanContext,
          conversation_history: history
        })
      },
      config.timeoutMs
    );

    return result;
  } catch (error) {
    console.error("[XGuard] Chat request failed:", error.message);

    return {
      answer:
        "The XGuard backend is currently unavailable. " +
        "I can only provide limited information from the current scan. " +
        "Please retry when the backend is online.",
      grounded_evidence: (
        currentScanContext?.evidence || []
      ).map(item => item.description).slice(0, 3),
      suggested_followups: [
        "What does this risk score mean?",
        "What is phishing?",
        "Why was this link flagged?"
      ],
      used_fallback: true,
      model_name: "Client Emergency Fallback"
    };
  }
}

/**
 * Check backend health.
 */
export async function checkBackendHealth() {
  try {
    const config = await getBackendConfig();

    return await backendRequest(
      `${config.backendUrl}/api/v1/health`,
      { method: "GET" },
      config.timeoutMs
    );
  } catch (error) {
    console.error("[XGuard] Health check failed:", error.message);

    return {
      status: "offline",
      error: error.message,
      database_connected: false,
      ml_model_loaded: false
    };
  }
}

/**
 * Retrieve model information.
 */
export async function getModelInfo() {
  try {
    const config = await getBackendConfig();

    return await backendRequest(
      `${config.backendUrl}/api/v1/model-info`,
      { method: "GET" },
      config.timeoutMs
    );
  } catch (error) {
    console.error("[XGuard] Model info request failed:", error.message);
    return null;
  }
}

/**
 * Submit user feedback.
 */
export async function submitFeedback(feedbackData) {
  const config = await getBackendConfig();

  return await backendRequest(
    `${config.backendUrl}/api/v1/feedback`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(feedbackData)
    },
    config.timeoutMs
  );
}
