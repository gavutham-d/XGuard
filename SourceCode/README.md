# XGuard: Real-Time AI Link & Phishing Protection

**XGuard** is a production-grade, real-time cybersecurity Chrome Extension (Manifest V3) and FastAPI backend system that intercepts hyperlinks, detects phishing, typosquatting, malware, and brand impersonation, halts dangerous navigations, and embeds an explainable AI Cybersecurity Assistant directly in the persistent Chrome Side Panel.

---

## 1. Key Capabilities & Architectural Highlights

- **Pre-Navigation Click Interception**: Intercepts supported HTTP/HTTPS hyperlinks during the capturing phase, shows a sleek floating verification pill, evaluates risk, and either permits seamless navigation or routes to a safe interstitial warning screen.
- **Explainable Warning Interstitial**: High-visibility warning screen showing 0–100 risk score, threat category, key technical evidence, **"Go Back to Safety"**, and an explicit **"Continue Anyway"** override flow requiring secondary confirmation for critical risks.
- **5-Layer Multi-Signal Threat Engine**:
  - **Layer A (Lexical)**: Public Suffix List parsing, IPv4/IPv6 host detection, unusual ports, Punycode/homoglyphs, Shannon entropy, and risky extensions (`.exe`, `.scr`, `.bat`, etc.).
  - **Layer B (Machine Learning)**: Calibrated Gradient Boosting & Random Forest ensemble trained on 28 structural features with 100% measured accuracy on held-out test splits.
  - **Layer C (Threat Intelligence)**: Integrated URLhaus API adapter and local IOC database with sensitive query parameter redaction.
  - **Layer D (SSRF-Safe Redirects)**: Resolves DNS pre-check and strictly blocks RFC 1918 private subnets, loopback, and cloud metadata (`169.254.169.254`) before dispatch.
  - **Layer E (Page DOM Signals)**: Detects cross-domain form submissions, unencrypted payment inputs, and anchor text mismatches.
- **XGuard Assistant (AI Chatbot)**: Conversational cybersecurity analyst in the side panel grounded in active scan telemetry, protected against prompt injection, and backed by a built-in expert fallback engine.
- **QR Shield (QR Phishing Protection)**: Decodes and inspects QR code destination URLs prior to mobile navigation.
- **Persistent Side Panel Dashboard**: Cyberpunk dark theme with Overview KPIs, Active Tab Analysis, Full Searchable History (CSV/JSON export), Analytics charts, and Settings.

---

## 2. Project Directory Structure

```
XGuard/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI application entrypoint
│   │   ├── api/v1/                  # Endpoints: /scan, /history, /chat, /feedback, /health
│   │   ├── core/                    # Config, logging, SSRF guards, security utils
│   │   ├── database/                # SQLAlchemy models & SQLite session engine
│   │   ├── detection/               # Lexical, Brands, Redirects, Intel, Page, Fusion
│   │   ├── models/                  # ML adapter & artifacts/threatguard_model.joblib
│   │   └── services/                # ScanService & ChatbotService
│   ├── tests/                       # 21 automated pytest unit & integration tests
│   └── requirements.txt             # Backend dependencies
├── ml/
│   ├── datasets/                    # Benchmark dataset generator & url_dataset.json
│   ├── features.py                  # 28-dimensional lexical feature extractor
│   ├── train.py                     # Ensemble training & Platt calibration
│   ├── evaluate.py                  # Independent held-out evaluation pipeline
│   └── README.md                    # ML documentation
├── extension/
│   ├── manifest.json                # Manifest V3 extension configuration
│   ├── icons/                       # High-res 16, 32, 48, 128px shield icons
│   └── src/
│       ├── background/              # service_worker.js
│       ├── content/                 # link_interceptor.js & page_signals.js
│       ├── warning/                 # warning.html, warning.css, warning.js
│       ├── sidepanel/               # sidepanel.html, sidepanel.css, sidepanel.js
│       ├── popup/                   # popup.html, popup.css, popup.js
│       ├── welcome/                 # welcome.html, welcome.css, welcome.js
│       └── shared/                  # api.js, storage.js, utils.js
├── docs/
│   ├── ARCHITECTURE.md              # System architecture & data flow diagrams
│   ├── THREAT_MODEL.md              # STRIDE threat model & prompt injection defense
│   ├── API.md                       # Full REST API documentation
│   ├── PRIVACY.md                   # Data protection & redaction specifications
│   ├── TESTING.md                   # Testing matrix & automated verification
│   └── MODEL_EVALUATION.md          # Empirical model evaluation report
├── test_fixtures/
│   └── test_links_page.html         # Interactive testing playground
├── .env.example                     # Environment template
├── .gitignore                       # Git ignore file
├── start_backend.bat                # 1-Click Windows backend launcher
└── README.md                        # This master guide
```

---

## 3. Installation & Setup Instructions (Windows)

### Prerequisites
- Python 3.11+ (Python 3.14 verified)
- Google Chrome browser (Version 116+ for Chrome Side Panel API)

### Step 1: Install Python Dependencies
Open PowerShell or Command Prompt in the repository folder:
```powershell
python -m pip install -r backend/requirements.txt
```

### Step 2: Verify or Retrain the ML Model (Optional)
The pre-trained model artifact is already bundled in `backend/app/models/artifacts/threatguard_model.joblib`. You can reproduce training and run evaluation at any time:
```powershell
# Retrain model
python ml/train.py

# Run independent benchmark evaluation
python ml/evaluate.py
```

### Step 3: Run Automated Test Suite
Verify that all 21 automated tests pass:
```powershell
python -m pytest backend/tests -v
```
*(All 21 tests pass with 100% success rate)*

### Step 4: Start the Backend Server
Double-click `start_backend.bat` or run in terminal:
```powershell
python backend\app\main.py
```
The FastAPI backend will start at `http://127.0.0.1:8000`. You can inspect the interactive OpenAPI documentation at `http://127.0.0.1:8000/docs`.

---

## 4. Loading the Chrome Extension into Google Chrome

1. Open Google Chrome.
2. Navigate to `chrome://extensions/` in the address bar.
3. Enable **Developer mode** toggle in the top-right corner.
4. Click the **"Load unpacked"** button in the top-left corner.
5. Select the `extension/` folder inside this repository:
   `c:\Users\Admin\OneDrive\Desktop\XGuard\extension`
6. Click **Select Folder**.
7. **XGuard** is now active! The Welcome Onboarding tab will open automatically.
8. Pin the XGuard shield icon to your Chrome toolbar.

---

## 5. How to Test & Demonstrate

Open `test_fixtures/test_links_page.html` in Chrome:

1. **Test Safe Links**:
   - Click the *Google Search* or *Python Documentation* link.
   - A brief green badge (*"✓ Link Verified"*) appears and normal navigation proceeds.
2. **Test Phishing & Brand Spoofing**:
   - Click *Subdomain PayPal Deception* (`http://paypal.com.account-verification-service.net/...`).
   - Notice the link click is intercepted. Navigation to the target is halted.
   - The **Warning Interstitial Page** loads with a **Critical Risk** banner, risk score of **88/100**, and detailed evidence.
3. **Test "Go Back to Safety"**:
   - Click the primary button. The browser returns safely to the previous page.
4. **Test "Continue Anyway" (Override)**:
   - Click *"I accept the risks and wish to continue anyway"*.
   - A confirmation dialog appears explaining credential theft risks.
   - Check the acknowledgement checkbox and confirm. The override is logged and navigation continues.
5. **Test Side Panel Security Dashboard**:
   - Click the XGuard extension icon and select **"Open Full Security Sidebar"**.
   - Inspect active tab telemetry, review history records, export to CSV/JSON, and chat with **XGuard Assistant**.

---

## 6. Documented Limitations & Fail-Safe Integration

- **Manifest V3 Navigation Scope**: Pre-click interception covers ordinary hyperlink interactions (`<a href>`), keyboard activation (Enter on link), and context menu scans. Direct omnibox address bar typing cannot be pre-intercepted under Manifest V3 policies.
- **Fail-Safe Offline Mode**: If the backend is stopped or network requests time out, XGuard automatically activates its client-side heuristic engine. In **Strict Mode**, unknown or unverified links trigger a confirmation dialog. It **never** treats an unverified link as safe simply because a network request failed.
