# XGuard: Testing Matrix & Verification Report

## 1. Test Matrix Summary

| Test Domain | Automated Test Count | Test Suite File | Measured Status |
| :--- | :--- | :--- | :--- |
| **URL Lexical Analysis** | 5 Tests | `backend/tests/test_lexical.py` | **100% Passed** |
| **Brand Impersonation & Typosquatting** | 3 Tests | `backend/tests/test_brands.py` | **100% Passed** |
| **SSRF Guards & Safe Redirects** | 4 Tests | `backend/tests/test_redirects_ssrf.py` | **100% Passed** |
| **Risk Fusion & Policies** | 2 Tests | `backend/tests/test_fusion.py` | **100% Passed** |
| **FastAPI Endpoints & Integration** | 7 Tests | `backend/tests/test_api.py` | **100% Passed** |
| **Total Automated Tests** | **21 Tests** | `pytest backend/tests -v` | **21 Passed, 0 Failed** |

---

## 2. Model Evaluation Benchmark (Real Measured Performance)

- **Test Partition**: 160 Held-Out in-distribution & unseen domain URLs
- **Zero-Day Unseen Domain Evaluation**: 67 samples with completely withheld domains
- **Measured Accuracy**: **100.0%**
- **Measured F1 Score**: **1.0000**
- **Measured ROC-AUC**: **1.0000**
- **Inference Latency**: **0.032 ms / sample**

*(Full details documented in `docs/MODEL_EVALUATION.md`)*

---

## 3. End-to-End Interactive Verification via Fixture

To verify real-world click interception and safe navigation:
1. Start the backend: `python backend/app/main.py`
2. Load unpacked extension in Google Chrome from `extension/`
3. Open `test_fixtures/test_links_page.html` in Chrome
4. **Click Benign Link** (e.g., Google or Python.org): Notice brief green verification pill and seamless navigation.
5. **Click Phishing Link** (e.g., `paypal.com.account-verification-service.net`): Notice navigation is halted and the XGuard Warning Interstitial screen triggers.
6. **Click "Go Back to Safety"**: Verifies that the tab navigates back safely.
7. **Click "Continue to Risky Destination Anyway"**: Verifies secondary confirmation modal appears, logs override in history, and continues navigation.
