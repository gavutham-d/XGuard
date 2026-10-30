"""
Model Training and Calibration Pipeline for XGuard.
Trains an ensemble classifier on lexical and structural URL features,
calibrates probabilities, and exports the model artifact.
"""

import json
import os
import sys
import numpy as np
import joblib
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, roc_auc_score, f1_score
from sklearn.preprocessing import StandardScaler

# Ensure ml directory is in path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from features import URLLexicalFeatureExtractor


def load_dataset(dataset_path: str):
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def train_model():
    dataset_path = os.path.join(current_dir, "datasets", "url_dataset.json")
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}. Run generate_benchmark.py first.")

    dataset = load_dataset(dataset_path)
    extractor = URLLexicalFeatureExtractor()

    # Split into train, val, and test sets
    train_data = [d for d in dataset if d["split"] == "train"]
    val_data = [d for d in dataset if d["split"] == "val"]
    test_data = [d for d in dataset if d["split"] in ("test", "test_unseen_domain")]

    print(f"Loaded dataset: {len(train_data)} train, {len(val_data)} val, {len(test_data)} test")

    # Extract features
    print("Extracting features from training set...")
    X_train = np.array([extractor.feature_vector(d["url"]) for d in train_data])
    y_train = np.array([d["label"] for d in train_data])

    print("Extracting features from validation set...")
    X_val = np.array([extractor.feature_vector(d["url"]) for d in val_data])
    y_val = np.array([d["label"] for d in val_data])

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    # Train Candidate 1: Gradient Boosting Classifier
    print("Training Gradient Boosting Classifier...")
    gb_model = GradientBoostingClassifier(
        n_estimators=120,
        learning_rate=0.08,
        max_depth=4,
        subsample=0.85,
        random_state=42
    )
    gb_model.fit(X_train_scaled, y_train)
    gb_val_preds = gb_model.predict(X_val_scaled)
    gb_val_probs = gb_model.predict_proba(X_val_scaled)[:, 1]
    gb_f1 = f1_score(y_val, gb_val_preds)
    gb_auc = roc_auc_score(y_val, gb_val_probs)
    print(f"Gradient Boosting Val F1: {gb_f1:.4f}, ROC-AUC: {gb_auc:.4f}")

    # Train Candidate 2: Random Forest Classifier
    print("Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=150,
        max_depth=7,
        class_weight="balanced",
        random_state=42
    )
    rf_model.fit(X_train_scaled, y_train)
    rf_val_preds = rf_model.predict(X_val_scaled)
    rf_val_probs = rf_model.predict_proba(X_val_scaled)[:, 1]
    rf_f1 = f1_score(y_val, rf_val_preds)
    rf_auc = roc_auc_score(y_val, rf_val_probs)
    print(f"Random Forest Val F1: {rf_f1:.4f}, ROC-AUC: {rf_auc:.4f}")

    # Select best candidate
    if gb_f1 >= rf_f1:
        best_base = gb_model
        model_name = "GradientBoostingClassifier"
    else:
        best_base = rf_model
        model_name = "RandomForestClassifier"

    print(f"Selected Best Model: {model_name}")

    # Calibrate probability predictions using Sigmoid / Platt scaling with 3-fold cross validation
    print("Calibrating probabilities...")
    calibrated_model = CalibratedClassifierCV(estimator=best_base, cv=3, method="sigmoid")
    calibrated_model.fit(X_train_scaled, y_train)

    # Calculate Feature Importances from base model
    importances = {}
    if hasattr(best_base, "feature_importances_"):
        for name, imp in zip(URLLexicalFeatureExtractor.FEATURE_NAMES, best_base.feature_importances_):
            importances[name] = round(float(imp), 4)

    # Top features
    sorted_importances = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    print("\nTop 7 Predictive Features:")
    for feat, imp in sorted_importances[:7]:
        print(f"  - {feat}: {imp:.4f}")

    # Package artifact bundle
    artifact_bundle = {
        "model_version": "1.0.0",
        "model_name": f"XGuard-{model_name}",
        "feature_names": URLLexicalFeatureExtractor.FEATURE_NAMES,
        "scaler": scaler,
        "calibrated_model": calibrated_model,
        "base_model": best_base,
        "feature_importances": importances,
        "val_metrics": {
            "val_f1": float(gb_f1 if model_name == "GradientBoostingClassifier" else rf_f1),
            "val_roc_auc": float(gb_auc if model_name == "GradientBoostingClassifier" else rf_auc)
        }
    }

    # Save to backend artifacts directory
    backend_artifact_dir = os.path.join(
        os.path.dirname(current_dir), "backend", "app", "models", "artifacts"
    )
    os.makedirs(backend_artifact_dir, exist_ok=True)
    artifact_path = os.path.join(backend_artifact_dir, "threatguard_model.joblib")
    joblib.dump(artifact_bundle, artifact_path)
    print(f"\nModel artifact successfully saved to: {artifact_path}")


if __name__ == "__main__":
    train_model()
