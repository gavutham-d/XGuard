# XGuard: REST API Documentation (v1)

Base URL: `http://127.0.0.1:8000/api/v1`

---

## 1. Scan Endpoint

### `POST /api/v1/scan`
Evaluates a target URL across lexical heuristics, brand spoofing detectors, the machine learning classifier, threat intelligence feeds, and SSRF-safe redirect inspection.

#### Request Body
```json
{
  "url": "http://paypal.com.account-verification-service.net/login.php?urgent=1",
  "options": {
    "mode": "balanced",
    "resolve_redirects": true,
    "page_signals": {
      "has_password_field": true,
      "has_card_field": false,
      "has_cross_domain_form": false,
      "iframe_count": 1,
      "page_title": "Account Verification",
      "link_text_mismatch": false
    }
  }
}
```

#### Response (200 OK)
```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "url": "http://paypal.com.account-verification-service.net/login.php?urgent=1",
  "hostname": "paypal.com.account-verification-service.net",
  "registered_domain": "account-verification-service.net",
  "risk_score": 88,
  "risk_level": "critical",
  "predicted_category": "brand_impersonation",
  "model_probability": 0.942,
  "model_version": "1.0.0",
  "evidence": [
    {
      "name": "subdomain_brand_spoofing",
      "category": "brand",
      "description": "Hostname embeds trusted brand 'paypal' as a subdomain, but registered domain is 'account-verification-service.net'.",
      "severity": "critical",
      "source": "brand_detector"
    },
    {
      "name": "credential_harvesting_tokens",
      "category": "lexical",
      "description": "URL contains sensitive authentication/urgency keywords: login, verify.",
      "severity": "medium",
      "source": "lexical_analyzer"
    }
  ],
  "redirect_chain": [
    {
      "order": 1,
      "url": "http://paypal.com.account-verification-service.net/login.php?urgent=1",
      "domain": "account-verification-service.net",
      "status_code": 200,
      "is_cross_domain": false,
      "resolved_ip": "104.21.48.12",
      "note": null
    }
  ],
  "intelligence_matches": [
    {
      "source": "XGuard Local IOC Feed",
      "matched": true,
      "threat_category": "phishing",
      "confidence": "high",
      "last_checked": "2026-10-12T12:00:00Z",
      "error": null,
      "details": { "description": "Known credential harvester domain" }
    }
  ],
  "checks_completed": ["lexical_analysis", "brand_verification", "threat_intelligence_feeds", "machine_learning_classifier", "redirect_analysis"],
  "checks_failed": [],
  "recommended_action": "block",
  "scan_timestamp": "2026-10-12T12:00:00.000Z",
  "scan_duration_ms": 2.45,
  "user_action": "pending"
}
```

---

## 2. History Endpoints

### `GET /api/v1/history`
Returns paginated local scan records with optional search and risk level filtering.

#### Query Parameters
- `skip` (int, default: 0): Records to skip for pagination.
- `limit` (int, default: 50): Max records to return.
- `risk_level` (string, optional): Filter by `low`, `medium`, `high`, `critical`.
- `q` (string, optional): Search string matching URL or domain.

### `DELETE /api/v1/history`
Clears entire scan history or deletes a specific entry by query param `scan_id`.

---

## 3. XGuard Assistant Chatbot Endpoint

### `POST /api/v1/chat`
Provides grounded cybersecurity answers based on the current scan context and cybersecurity knowledge base.

#### Request Body
```json
{
  "message": "Why was this link flagged?",
  "current_scan_context": {
    "url": "http://paypal.com.account-verification-service.net/login.php",
    "risk_score": 88,
    "risk_level": "critical",
    "predicted_category": "phishing",
    "evidence": [...]
  },
  "conversation_history": []
}
```

#### Response (200 OK)
```json
{
  "answer": "This destination was assigned a risk score of 88/100 (CRITICAL risk) because it embeds the brand 'paypal' within an unauthorized subdomain on 'account-verification-service.net'. Entering credentials here exposes you to account takeover.",
  "grounded_evidence": ["Hostname embeds brand 'paypal' as a subdomain"],
  "suggested_followups": [
    "Is this website safe to log in to?",
    "What should I do if I clicked this link?",
    "How do I verify the official domain?"
  ],
  "used_fallback": true,
  "model_name": "XGuard Embedded Security Engine"
}
```

---

## 4. Diagnostics & Health Endpoints

### `GET /api/v1/health`
Returns system status, database connectivity, ML model loading status, and threat feeds.

### `GET /api/v1/model-info`
Returns active ML model name, version, feature dimensions, top predictive features, and empirical validation metrics.
