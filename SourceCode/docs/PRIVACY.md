# XGuard: Privacy Architecture & Data Protection

## 1. Core Privacy Philosophy: Local-First Security

XGuard is engineered with privacy as a foundational principle:

1. **No Silent Browsing History Transmission**: The extension **never** streams the user's browsing history or web traffic to a remote cloud server. Scans are initiated exclusively when links are actively clicked or manually submitted.
2. **Local Storage by Default**: Scan history, domain trust lists, and settings are stored locally on the user's machine (`chrome.storage.local` and local SQLite `threatguard.db`).
3. **Sensitive Query Parameter Redaction**: Prior to logging, saving, or querying threat intelligence feeds, sensitive parameters (including `token`, `password`, `key`, `auth`, `session`, `secret`, `otp`, `signature`) are stripped and replaced with `[REDACTED]`.

---

## 2. Privacy Mode

When the user activates **Privacy Mode** in the Side Panel Settings:
- External network lookups to remote threat feeds (e.g. URLhaus) are completely disabled.
- The system operates strictly with local lexical heuristics, brand proximity rules, and local machine learning models.
- Local scan history retention can be cleared with a single click.

---

## 3. Telemetry & User Feedback

- **Explicit Consent**: When reporting a false positive or missed threat, the user must check an explicit consent box before any telemetry data is transmitted.
- **Data Export & Deletion**: Users can export their entire scan history to CSV or JSON, delete individual entries, or permanently clear all local records at any time.
