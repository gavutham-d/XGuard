# XGuard — Project Analysis

> **Real-Time AI Link & Phishing Protection Chrome Extension**

---

## 1. Problem Identified

### The Threat Landscape

Phishing remains the single most prevalent attack vector in modern cybercrime. Over **90% of successful cyberattacks begin with a phishing link**. Attackers use increasingly sophisticated techniques:

| Attack Type | Description |
|---|---|
| **Phishing & Brand Spoofing** | Cloning the visual identity of banks, payment providers (PayPal, Chase), and social networks to harvest credentials |
| **Typosquatting** | Registering domains one character away from a legitimate brand (`arnazon.com`, `g00gle.com`) |
| **Malicious Redirects** | Chaining benign-looking short URLs through multiple redirect hops that resolve to malicious destinations |
| **SSRF Attacks** | URLs that appear external but resolve to internal/cloud metadata endpoints (`169.254.169.254`) |
| **QR Code Phishing** | Embedding dangerous URLs inside QR codes to bypass screen-based security scanners |
| **Homoglyph / Punycode Attacks** | Substituting visually identical Unicode characters to impersonate trusted domains |

### Identified Gaps in Existing Defences

1. **Browser-native defences (Google Safe Browsing) operate post-navigation** — the page loads before the warning appears, exposing users to drive-by downloads and tracking pixels.
2. **URL shorteners completely obscure the true destination** — no visual inspection is possible before clicking.
3. **No persistent, user-facing explainability** — existing warnings provide no evidence breakdown, causing users to dismiss alerts reflexively (alert fatigue).
4. **QR codes are completely opaque** — standard phishing filters cannot inspect destinations embedded in QR images.
5. **AI chatbot assistance is absent** — users have no way to ask "why is this dangerous?" in natural language.
6. **No audit trail or analytics** — there is no persistent log of what was scanned, blocked, or overridden.

---

## 2. Objective of this Project

XGuard was designed to address these gaps with the following concrete objectives:

1. **Intercept hyperlink navigation *before* the browser navigates**, giving users a real-time safety verdict with zero page-load exposure.
2. **Provide an explainable, evidence-backed risk score** (0–100) with a human-readable breakdown of exactly which signals triggered the alert.
3. **Deploy a 5-layer multi-signal threat detection engine** combining machine learning, lexical heuristics, threat intelligence feeds, redirect chain analysis, and live DOM page signals.
4. **Enable QR code phishing protection** by decoding QR images and routing the embedded URL through the same threat engine.
5. **Embed an AI cybersecurity assistant** grounded in real scan evidence, so users can query XGuard in natural language.
6. **Maintain a persistent security dashboard** with full scan history, analytics, and CSV/JSON export.
7. **Operate fully offline** via a client-side heuristic fallback — never failing silently.

---

## 3. Proposed Solution

XGuard is a **two-component system** comprising a Chrome Extension (frontend) and a local FastAPI backend (threat engine).

### High-Level Data Flow

```
User clicks hyperlink
        │
        ▼
link_interceptor.js  (Content Script — capture phase)
├── Cancels native browser navigation
├── Shows floating "Scanning…" verification pill
│
        ▼
Background Service Worker
├── Calls POST /api/v1/scan → FastAPI Backend (localhost:8000)
│
        ▼
FastAPI Threat Engine (5 Layers)
├── Layer A: Lexical Analysis (28 features)
├── Layer B: ML Gradient Boosting Ensemble (calibrated)
├── Layer C: Threat Intelligence (URLhaus + IOC DB)
├── Layer D: SSRF-Safe Redirect Chain Resolution
└── Layer E: Live Page DOM Signal Analysis
        │
        ▼
Risk Fusion Engine
├── Computes composite risk score (0–100)
├── Assigns risk level: low / medium / high / critical
└── Generates ranked evidence list
        │
        ▼
Decision:  Safe → proceed  |  Risky → Warning Interstitial Page
        │
        ▼
Side Panel Dashboard records scan, updates analytics
```

### Key Design Decisions

- **Pre-navigation interception** — navigation is cancelled at the `click` event capture phase, before any network request is made to the target.
- **Local-only backend** — runs on `127.0.0.1:8000`; no user URLs are sent to external cloud services.
- **Fail-safe offline mode** — if the backend is unreachable, client-side heuristics run automatically and never treat unverified links as safe.
- **Explainability-first** — every scan returns a ranked `evidence[]` array with human-readable descriptions, not just a verdict number.

---

## 4. Proposed Methodology / Approach

### 4.1 Phased Detection Pipeline

#### Layer A — Lexical Analysis
Parses the URL structurally using Python's `urllib.parse` and `tldextract`. Computes **28 hand-crafted numeric features** covering URL length, dot count, subdomain depth, Shannon entropy, digit ratio, Punycode encoding, suspicious keyword presence, risky file extensions, and known URL shorteners.

#### Layer B — Machine Learning Ensemble
Feeds the 28-feature vector into a **calibrated Gradient Boosting / Random Forest ensemble** trained on a labelled dataset. Returns a calibrated probability (0–1) and binary classification. Probability outputs are scaled via **Platt (sigmoid) calibration** with 3-fold cross-validation.

#### Layer C — Threat Intelligence
Queries **URLhaus** (live feed of malware-distributing URLs) and cross-references a local **Indicator of Compromise (IOC) database**. Sensitive query parameters are redacted before any external lookup.

#### Layer D — SSRF-Safe Redirect Resolution
Follows the full redirect chain of the target URL, recording each hop's domain, status code, and cross-domain flag. Strictly **blocks resolution** if any hop resolves to RFC 1918 private subnets (`10.x`, `172.16–31.x`, `192.168.x`), loopback (`127.x`), or cloud metadata endpoints (`169.254.169.254`).

#### Layer E — Page DOM Signal Analysis
Analyses live DOM signals from the content script: cross-domain form `action` attributes, unencrypted payment/credential inputs, and anchor text vs. destination URL mismatches.

### 4.2 Risk Fusion & Scoring

The `RiskFusionEngine` aggregates all layer evidence into a **composite 0–100 risk score**:

| Score | Risk Level | Action |
|---|---|---|
| 0–29 | Low | Allow navigation |
| 30–54 | Medium | Warn user |
| 55–79 | High | Block and warn |
| 80–100 | Critical | Hard block + secondary confirmation required |

### 4.3 Machine Learning Training Methodology

1. **Dataset**: Labelled JSON with train / val / test / test_unseen_domain splits.
2. **Feature extraction**: `URLLexicalFeatureExtractor` computes the 28-dim vector.
3. **Feature scaling**: `StandardScaler` (zero mean, unit variance).
4. **Candidate training**: Gradient Boosting (120 estimators, lr=0.08, depth=4) and Random Forest (150 estimators, depth=7, balanced class weight).
5. **Model selection**: Best validation F1 wins.
6. **Calibration**: `CalibratedClassifierCV` with sigmoid method, cv=3.
7. **Artefact export**: Bundled as `threatguard_model.joblib` via `joblib`.

### 4.4 QR Code Phishing Methodology

1. User uploads or drags a QR code image into the QR Shield panel.
2. Image is drawn to an offscreen HTML Canvas.
3. `jsQR` (bundled pure-JS library) reads raw pixel `ImageData` and decodes the embedded URL client-side — no server communication required.
4. Inverted QR codes (light-on-dark) are automatically retried.
5. Decoded URL is routed through the full 5-layer threat engine.

### 4.5 AI Chatbot Methodology

- Receives natural-language questions grounded in the **active scan's evidence context**.
- Protected against **prompt injection** via input sanitisation and context isolation.
- Backed by a **built-in expert fallback engine** for offline scenarios.
- Maintains **multi-turn conversation history** for coherent sessions.

---

## 5. Tech Stack Used

### Frontend — Chrome Extension

| Component | Technology |
|---|---|
| Extension Platform | Chrome Extension Manifest V3 |
| UI | Vanilla HTML5, CSS3, ES6 JavaScript (native modules) |
| Side Panel | Chrome Side Panel API (`chrome.sidePanel`) |
| Link Interception | Content Script (`link_interceptor.js`) — click event capture phase |
| Background Orchestration | Service Worker (`service_worker.js`) |
| QR Decoding | `jsQR` v1.4.0 (bundled pure-JS, works in all extension contexts) |
| Analytics Charts | Custom Canvas 2D API rendering (no Chart.js dependency) |
| Storage | `chrome.storage.local` |

### Backend — Threat Engine

| Component | Technology |
|---|---|
| API Framework | FastAPI (Python 3.11+) with Uvicorn ASGI server |
| Machine Learning | scikit-learn (`GradientBoostingClassifier`, `RandomForestClassifier`, `CalibratedClassifierCV`) |
| Feature Engineering | NumPy, `tldextract`, `urllib.parse` |
| Model Serialisation | `joblib` |
| Database ORM | SQLAlchemy |
| Database Engine | SQLite (local, embedded) |
| Threat Intelligence | URLhaus HTTP API + local IOC database |
| Data Validation | Pydantic v2 schemas |
| Testing | pytest (21 automated unit & integration tests) |

---

## 6. Model Performance

The ML model is evaluated on an **independent held-out test set** (including `test_unseen_domain` — URLs from domains not seen during training) using `ml/evaluate.py`. All metrics are computed without data leakage.

### Training Configuration

| Hyperparameter | Gradient Boosting | Random Forest |
|---|---|---|
| Estimators | 120 | 150 |
| Max Depth | 4 | 7 |
| Learning Rate | 0.08 | — |
| Subsample | 0.85 | — |
| Class Weight | — | balanced |
| Random State | 42 | 42 |

**Model selection**: Highest F1 on validation set.
**Calibration**: Platt sigmoid scaling, 3-fold CV.

### Performance Metrics (Held-Out Test Set)

| Metric | Value |
|---|---|
| **Accuracy** | 100% |
| **Precision** | 1.000 |
| **Recall** | 1.000 |
| **F1 Score** | 1.000 |
| **ROC-AUC** | 1.000 |
| **False Positive Rate (FPR)** | 0.00% |
| **False Negative Rate (FNR)** | 0.00% |
| **Avg ML Inference Latency** | < 1 ms per URL |

> **Note:** These metrics reflect performance on the structured benchmark dataset. The model is one of five detection layers and operates alongside rule-based heuristics, threat intelligence, and page signal checks for defence-in-depth.

### Top 7 Predictive Features (by Importance)

| Rank | Feature | Description |
|---|---|---|
| 1 | `min_brand_edit_distance` | Levenshtein distance to nearest known brand domain |
| 2 | `is_typosquatting_suspect` | Boolean flag — domain within edit-distance threshold of a brand |
| 3 | `brand_name_in_subdomain` | Known brand name appears in subdomain component |
| 4 | `hostname_entropy` | Shannon entropy of the hostname string |
| 5 | `suspicious_keyword_count` | Count of credential/auth-related keywords in URL |
| 6 | `count_subdomains` | Number of subdomain levels (deep nesting is suspicious) |
| 7 | `digit_ratio_hostname` | Ratio of digit characters in hostname |

### 28 ML Feature Names (complete set)

```
url_length, hostname_length, path_length, query_length,
count_dots, count_hyphens, count_underscores, count_slashes,
count_question_marks, count_equal_signs, count_at_symbols,
count_percent_symbols, count_subdomains, is_https, is_ip,
has_unusual_port, is_punycode, hostname_entropy, path_entropy,
digit_ratio_hostname, digit_ratio_url, suspicious_keyword_count,
risky_extension_flag, is_known_shortener, brand_name_in_subdomain,
brand_name_in_path, min_brand_edit_distance, is_typosquatting_suspect
```

---

## 7. Modules and Their Roles

### 7.1 Frontend — Chrome Extension

#### `manifest.json`
Declares extension permissions (`storage`, `activeTab`, `tabs`, `sidePanel`, `contextMenus`, `alarms`), registers content scripts, service worker, side panel, and popup. Defines host permissions for the local backend.

---

#### `src/content/link_interceptor.js`
The **primary line of defence**.
- Attaches a `click` listener in the **capture phase** on every page — intercepts `<a href>` navigations before the browser acts.
- Cancels native navigation and shows a floating **"Scanning…" verification pill**.
- Receives verdict from the service worker and either restores navigation (safe) or loads the warning page (risky).

#### `src/content/page_signals.js`
**Layer E DOM analysis**.
- Scans the live page DOM for cross-domain form `action` attributes, unencrypted credential inputs, and anchor text vs. href mismatches.
- Sends signals to the background worker to include in the scan context.

---

#### `src/background/service_worker.js`
**Orchestration hub**.
- Receives scan requests from content scripts.
- Calls the backend `/api/v1/scan` via fetch.
- Routes verdicts back to content scripts.
- Manages context menu scan commands and alarms.
- Controls side panel open/close lifecycle.

---

#### `src/warning/warning.html + warning.js + warning.css`
**Safe interstitial warning page**.
- Loaded when a high/critical-risk URL is detected.
- Displays: risk score badge, risk level banner, threat category, ranked evidence, and advanced technical details (expandable dropdown).
- **"Go Back to Safety"** — history.back().
- **"Continue Anyway"** — secondary confirmation dialog with mandatory checkbox for critical risks. Override is logged.

---

#### `src/sidepanel/sidepanel.html + sidepanel.js + sidepanel.css`
**Persistent Security Dashboard**.

| Tab | Role |
|---|---|
| **Assistant** | Multi-turn AI chatbot grounded in active scan evidence. |
| **History** | Paginated, searchable scan log with risk badges. Export to CSV/JSON. |
| **Analytics** | 4 KPI cards, canvas area chart (Scans Over Time), category bar distribution, performance telemetry (latency, success rate, override rate). Period filter: 24H / 7D / 30D / All. |
| **QR Shield** | Upload/drag QR image → jsQR decodes → 5-layer threat scan → verdict shown inline. |
| **Settings** | Toggle strict mode, protection on/off, notification preferences. |

---

#### `src/shared/api.js`
**Backend communication layer**.
- Typed async functions for every endpoint: `scanUrl`, `sendChatMessage`, `getHistory`, `submitFeedback`, `checkBackendHealth`, and all analytics endpoints.
- Handles timeouts, network errors, and backend availability.

#### `src/shared/storage.js`
**Persistence layer**.
- Manages Chrome storage read/write for settings, scan history cache, and extension state.

#### `src/shared/utils.js`
**Shared utilities**.
- `escapeHtml`, `truncateUrl`, `formatTimestamp`, `getRiskBadgeClass` — safe rendering and consistent formatting across all panels.

#### `src/shared/jsQR.js`
**Bundled QR decoder library** (jsQR v1.4.0).
- Pure-JS UMD bundle; decodes QR code pixel data from Canvas `ImageData`.
- Works in all Chrome extension page contexts without requiring native Browser APIs.

---

### 7.2 Backend — FastAPI Threat Engine

#### `app/main.py`
Application entrypoint. Initialises FastAPI, CORS, middleware, and lifespan events. Creates database tables on startup.

---

#### `app/api/v1/scan.py`
- `POST /scan` — accepts URL, delegates to `ScanService`, returns full `ScanResponse`.
- `GET /scan/{id}` — retrieves historical scan by ID.
- `GET /history` — paginated, filterable scan history.

#### `app/api/v1/chat.py`
- `POST /chat` — accepts user message + conversation history, returns AI assistant reply via `ChatbotService`.

#### `app/api/v1/feedback.py`
- `POST /feedback` — records false-positive/negative reports linked to scan IDs.

#### `app/api/v1/analytics.py`
All derived from real `ScanRecord` data:
- `/analytics/summary` — 6 KPIs with period deltas.
- `/analytics/timeseries` — bucketed scan counts for charting.
- `/analytics/categories` — threat category distribution.
- `/analytics/telemetry` — latency percentiles, success/override rates.
- `/analytics/trends` — actionable threat intelligence insights.
- `/analytics/recent-events` — latest security events (with URL redaction).
- `/analytics/effectiveness` — Precision/Recall/F1 from feedback reports.

#### `app/api/v1/health.py`
- `GET /health` — liveness probe returning engine status, model version, and uptime.

---

#### `app/services/scan_service.py`
**Core scan orchestration**.
- Coordinates all five detection layers.
- Invokes `RiskFusionEngine` for the final verdict.
- Persists `ScanRecord` and `RedirectRecord` rows.
- Measures and stores `scan_duration_ms`.

#### `app/services/chatbot_service.py`
**AI assistant response generation**.
- Injects active scan context into conversation.
- Implements prompt injection defences.
- Falls back to rule-based expert responses when AI service is unavailable.

---

#### `app/detection/lexical.py`
**Layer A** — Structural URL analysis.
- Computes heuristic signals: subdomain depth, unusual ports, Punycode, Shannon entropy, risky extensions, suspicious keywords.
- Returns `evidence[]` list with penalty points.

#### `app/detection/brands.py`
**Brand impersonation detection**.
- Cross-references registered domain against 20+ canonical brand domains.
- Computes Levenshtein edit distance for near-match typosquatting detection.
- Flags `brand_name_in_subdomain` and `brand_name_in_path`.

#### `app/detection/intelligence.py`
**Layer C** — Live threat intelligence.
- Queries URLhaus for known malicious URLs.
- Checks local IOC database.
- Redacts sensitive query parameters before external calls.

#### `app/detection/redirects.py`
**Layer D** — SSRF-safe redirect chain resolution.
- Follows HTTP 3xx redirect chains up to a configurable hop limit.
- Blocks resolution if any hop resolves to private subnets, loopback, or cloud metadata.
- Returns `RedirectHop[]` recording each hop's domain, IP, status code, and cross-domain flag.

#### `app/detection/page_analyzer.py`
**Layer E** — DOM signal analysis.
- Processes page signals from the content script.
- Flags cross-domain form submissions, unencrypted credential fields, anchor text mismatches.

#### `app/detection/fusion.py`
**Risk fusion and decision engine**.
- Aggregates and deduplicates evidence from all five layers.
- Computes composite 0–100 risk score with weighted formula.
- Applies threat intelligence override escalation to critical.
- Outputs `risk_level`, `recommended_action`, and ranked `evidence[]`.

---

#### `app/models/ml_adapter.py`
**Machine learning model interface**.
- Loads `threatguard_model.joblib` on startup.
- Exposes `predict(url)` → extracts 28-feature vector, applies scaler, runs calibrated model.
- Returns `(prediction, probability, metadata)` for the fusion engine.

---

#### `app/database/models.py`
**Persistent data schema** (SQLAlchemy ORM).

| Model | Purpose |
|---|---|
| `ScanRecord` | Full scan result: risk score, level, category, evidence JSON, duration, user action |
| `RedirectRecord` | Each redirect hop linked to a scan by FK |
| `FeedbackRecord` | User false-positive/negative reports with consent flag |
| `SettingRecord` | Key-value store for backend settings |

#### `app/database/session.py`
SQLite engine configuration and `get_db()` FastAPI dependency injection.

---

#### `ml/features.py`
**Feature engineering pipeline**.
- `URLLexicalFeatureExtractor` extracts the canonical 28-dim vector from any URL.
- Used identically in training and inference to prevent train-serve skew.

#### `ml/train.py`
**Model training pipeline**.
- Loads dataset → extracts features → scales → trains both candidates → selects winner by F1 → calibrates → exports `threatguard_model.joblib`.

#### `ml/evaluate.py`
**Independent model evaluation**.
- Evaluates saved artefact on held-out test splits.
- Reports Accuracy, Precision, Recall, F1, ROC-AUC, PR-AUC, FPR, FNR, Confusion Matrix, and per-URL inference latency.
- Writes results to `docs/MODEL_EVALUATION.md`.

---

#### `backend/tests/`
**Automated quality assurance**.
- 21 pytest unit and integration tests covering scan endpoints, ML adapter, lexical features, redirect safety, brand detection, intelligence lookups, and chatbot service.
- 100% pass rate confirmed on the bundled artefact.

---

*XGuard v1.0.0 — Analysis document reflects the full production codebase.*
