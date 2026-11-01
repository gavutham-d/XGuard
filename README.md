# XGuard 🛡️

> **Real-Time AI Link & Phishing Protection for Chrome**

XGuard is a production-grade cybersecurity system that intercepts hyperlinks before navigation, evaluates them through a 5-layer threat detection engine, and stops phishing, typosquatting, malware, and brand impersonation — all in real time.

---

## What It Does

- **Intercepts clicks** on HTTP/HTTPS links before the browser navigates
- **Scores each URL** (0–100 risk) using a multi-layer ML + heuristics pipeline
- **Blocks dangerous links** with an explainable warning screen; safe links pass through seamlessly
- **AI Chatbot Assistant** in the Chrome Side Panel answers cybersecurity questions grounded in live scan data
- **QR Shield** decodes and inspects QR code URLs before mobile navigation
- **Offline Fail-Safe** — falls back to client-side heuristics if the backend is unreachable; never silently allows unverified links

## Architecture at a Glance

| Component | Technology |
|---|---|
| Chrome Extension | Manifest V3, Vanilla JS |
| Backend API | FastAPI (Python 3.11+) |
| Threat Detection | 5-layer engine (Lexical · ML · Threat Intel · Redirects · DOM) |
| ML Model | Calibrated Gradient Boosting + Random Forest ensemble (28 features) |
| Database | SQLite via SQLAlchemy |
| AI Assistant | Conversational chatbot with prompt-injection defenses |

## Repository Layout

```
XGuard/
├── SourceCode/          # Full project source
│   ├── backend/         # FastAPI app, detection engine, ML adapter, tests
│   ├── extension/       # Chrome extension (MV3) — popup, side panel, warning page
│   ├── ml/              # Dataset generation, feature extraction, training & evaluation
│   └── docs/            # Architecture, API, threat model, privacy & testing docs
└── README.md            # You are here
```

For full setup instructions, see [SourceCode/README.md](./SourceCode/README.md).
