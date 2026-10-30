# XGuard: Machine Learning Subsystem

This directory contains the reproducible dataset generation, feature extraction, model training, calibration, and evaluation pipelines for **XGuard**.

---

## Architecture

```
ml/
├── features.py                  # 28-feature lexical, structural & brand extractor
├── datasets/
│   ├── generate_benchmark.py   # Reproducible dataset generator (Train/Val/Test/Unseen)
│   └── url_dataset.json        # Curated benchmark dataset
├── train.py                     # Training & Platt probability calibration pipeline
├── evaluate.py                  # Independent held-out & zero-day evaluation
└── README.md                    # This documentation
```

---

## Extracted Features (28 Dimensions)
The feature vector extracted by `URLLexicalFeatureExtractor` in `features.py` includes:
- **Lengths**: `url_length`, `hostname_length`, `path_length`, `query_length`
- **Structural Symbols**: `count_dots`, `count_hyphens`, `count_underscores`, `count_slashes`, `count_question_marks`, `count_equal_signs`, `count_at_symbols`, `count_percent_symbols`, `count_subdomains`
- **Protocols & Addresses**: `is_https`, `is_ip`, `has_unusual_port`, `is_punycode`
- **Information Theory**: `hostname_entropy`, `path_entropy` (Shannon entropy)
- **Token Distributions**: `digit_ratio_hostname`, `digit_ratio_url`
- **Semantic Indicators**: `suspicious_keyword_count`, `risky_extension_flag`, `is_known_shortener`
- **Brand & Impersonation**: `brand_name_in_subdomain`, `brand_name_in_path`, `min_brand_edit_distance`, `is_typosquatting_suspect`

---

## Reproduction Commands

To regenerate the dataset, retrain the model, and execute the full evaluation suite:

```bash
# 1. Generate partitioned benchmark dataset
python ml/datasets/generate_benchmark.py

# 2. Train and calibrate model artifact
python ml/train.py

# 3. Run evaluation across held-out and unseen domains
python ml/evaluate.py
```

The resulting model bundle is saved to:
`backend/app/models/artifacts/threatguard_model.joblib`
