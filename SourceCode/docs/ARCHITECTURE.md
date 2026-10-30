# XGuard: System Architecture & Design Specification

## 1. Executive Architecture Overview

**XGuard** is a multi-layered cybersecurity defense system designed for the Google Chrome environment (Manifest V3). It combines pre-navigation client-side link interception with an asynchronous, multi-engine detection backend and an integrated AI cybersecurity assistant in the Chrome Side Panel.

```mermaid
flowchart TD
    User([User Clicks Hyperlink]) --> CS[Content Script: link_interceptor.js]
    CS --> CheckToken{Has Bypass Token / Safe-listed?}
    CheckToken -- Yes --> NavDirect[Allow Native Browser Navigation]
    CheckToken -- No --> HaltNav[Halt Navigation & Show Scanning Pill]
    
    HaltNav --> SW[Background Service Worker]
    SW --> CacheCheck{In Recent Memory Cache?}
    CacheCheck -- Yes (Cached Verdict) --> NavDecision
    CacheCheck -- No --> API[FastAPI Detection Backend: /api/v1/scan]
    
    subgraph MultiLayerEngine [Detection & Risk Fusion Engine]
        API --> LayerA[Layer A: URL Lexical & Heuristics]
        API --> LayerB[Layer B: Calibrated ML Classifier]
        API --> LayerC[Layer C: Threat Intelligence Feeds]
        API --> LayerD[Layer D: SSRF-Safe Redirect Resolver]
        API --> LayerE[Layer E: Webpage DOM Signals]
        LayerA & LayerB & LayerC & LayerD & LayerE --> Fusion[Risk Fusion & Decision Engine]
    end
    
    Fusion --> APIRes[Standardized Result Schema]
    APIRes --> SW
    SW --> NavDecision{Recommended Action}
    
    NavDecision -- "allow" (Low Risk) --> FlashGreen[Flash Green Badge] --> NavDirect
    NavDecision -- "warn" / "block" (Risky) --> WarningPage[Display Warning Interstitial: warning.html]
    
    WarningPage --> ActionChoice{User Decision}
    ActionChoice -- "Go Back to Safety" --> BackSafety[history.back / Close Tab]
    ActionChoice -- "Continue Anyway" --> ModalConfirm[Require Secondary Override Confirmation]
    ModalConfirm --> LogOverride[Record Override & Issue Bypass Token] --> NavDirect
    
    subgraph SidePanelDashboard [Chrome Side Panel Dashboard]
        OverviewTab[A. Live Overview & KPIs]
        ActiveTab[B. Current Website Telemetry]
        AssistantTab[C. XGuard AI Assistant]
        HistoryTab[D. Scan History & Search]
        AnalyticsTab[E. Analytics & Charts]
        QRTab[F. QR Phishing Shield]
        SettingsTab[G. Protection Modes & Health]
    end
```

---

## 2. Multi-Layer Detection Pipeline

The detection engine operates across five independent, modular layers:

### Layer A: URL Structure & Lexical Analysis (`lexical.py`)
- **Public Suffix List Aware**: Utilizes `tldextract` to accurately parse subdomains, second-level domains, and multi-part public suffixes (e.g., `.co.uk`, `.com.au`).
- **Protocols & Ports**: Flags insecure HTTP transport and non-standard network ports (ports other than 80 and 443).
- **IP Address Detection**: Detects raw IPv4, IPv6, and dotted-decimal host representations.
- **Punycode / Homoglyphs**: Detects `xn--` prefix strings and Cyrillic/Greek lookalike homoglyphs imitating Latin characters.
- **Shannon Entropy**: Measures character entropy across hostnames and paths to detect algorithmically generated domains (DGA) and hex obfuscation.
- **Credential & Urgency Tokens**: Identifies token clusters (`login`, `verify`, `banking`, `recovery`, `suspended`, `wallet`).
- **Risky Payload Extensions**: Flags executable file extensions (`.exe`, `.scr`, `.bat`, `.vbs`, `.msi`, `.apk`).

### Layer B: Calibrated Machine Learning Classifier (`ml_adapter.py`)
- **Model**: Gradient Boosting & Random Forest ensemble trained on 28 structural and lexical features.
- **Calibration**: 3-Fold cross-validated Platt / Sigmoid calibration providing qualified probability estimates.
- **Inference Runtime**: Python scikit-learn / NumPy pipeline operating at sub-millisecond latency (0.03 ms/sample).
- **Adapter Interface**: Abstract base class (`BaseURLClassifier`) enabling replacement with Hugging Face transformers or ONNX runtimes.

### Layer C: Threat Intelligence Reputation (`intelligence.py`)
- **URLhaus Adapter**: Connects to the abuse.ch URLhaus threat feed to match confirmed malware distribution endpoints.
- **Local Curated IOC Feed**: Provides immediate, offline-capable matching of high-confidence malicious indicators.
- **Privacy Parameter Redaction**: Strips tokens, passwords, sessions, and sensitive query keys prior to external feed queries.
- **Asymmetric Evidence Rule**: Confirmed positive matches are treated as conclusive evidence; negative lookups are explicitly marked as "No record", never as proof of safety.

### Layer D: SSRF-Safe Redirect Analysis (`redirects.py`)
- **Pre-Resolution DNS Inspection**: Resolves destination hostnames via `socket.getaddrinfo` before initiating HTTP requests.
- **Strict SSRF Guard**: Validates IP addresses against RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and cloud metadata (`169.254.169.254`). Unsafe destinations are aborted immediately.
- **Hop-by-Hop Auditing**: Follows up to 5 redirect hops without fetching executable response bodies, identifying cross-domain jumps, loops, and shortener unwrapping.

### Layer E: Webpage Signals & Form Analysis (`page_analyzer.py`)
- **Cross-Domain Form Actions**: Detects credential forms where `form.action` domain diverges from the host domain.
- **Deceptive Anchor Text**: Flags instances where displayed clickable anchor text imitates a brand while the underlying `href` routes elsewhere.
- **Iframe Density**: Inspects nested iframe counts to defend against clickjacking.

---

## 3. Risk Fusion & Navigation Policy

The **Risk Fusion Engine** (`fusion.py`) compiles observations into an internal 0–100 scale:

| Risk Score | Risk Level | Default Action (Balanced) | Policy in Strict Mode | Policy in Learning Mode |
| :--- | :--- | :--- | :--- | :--- |
| **0 – 24** | `low` | `allow` (Continue) | `allow` | `allow` |
| **25 – 59** | `medium` | `warn` (Warning Interstitial) | `warn` | `warn` (Informative) |
| **60 – 84** | `high` | `warn` (Warning Interstitial) | `block` | `warn` (Informative) |
| **85 – 100** | `critical` | `block` (Strict Warning) | `block` | `warn` (Informative) |

---

## 4. Database Schema (SQLite / PostgreSQL Ready)

- `scan_records`: Stores `id`, `timestamp`, `url` (redacted), `hostname`, `registered_domain`, `risk_score`, `risk_level`, `predicted_category`, `model_probability`, `evidence_json`, `recommended_action`, `user_action`.
- `redirect_records`: Stores individual redirect hops (`scan_id`, `hop_order`, `url`, `domain`, `status_code`, `is_cross_domain`, `resolved_ip`).
- `feedback_records`: Stores user false-positive and missed-threat submissions with verified consent.
- `user_settings`: Key-value store for protection modes, timeouts, and privacy settings.
