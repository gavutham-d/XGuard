"""
Production Machine Learning Adapter for XGuard.
Loads calibrated scikit-learn model artifact from disk, executes feature extraction,
and returns calibrated probabilities with feature explanations.
"""

import os
import sys
from typing import Dict, Any, Tuple
import joblib
import numpy as np

# Ensure ml directory can be imported
workspace_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
ml_dir = os.path.join(workspace_root, "ml")
if ml_dir not in sys.path:
    sys.path.append(ml_dir)

try:
    from features import URLLexicalFeatureExtractor
except ImportError:
    URLLexicalFeatureExtractor = None

from app.models.base import BaseURLClassifier
from app.core.logging import logger


class ThreatGuardMLAdapter(BaseURLClassifier):
    def __init__(self, artifact_path: str = None):
        if artifact_path is None:
            artifact_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "artifacts", "threatguard_model.joblib"
            )

        self.artifact_path = artifact_path
        self.is_loaded = False
        self.model = None
        self.scaler = None
        self.extractor = None
        self.metadata = {}

        self._load_artifact()

    def _load_artifact(self):
        if not os.path.exists(self.artifact_path):
            logger.warning(f"ML artifact not found at {self.artifact_path}. ML layer will operate in heuristic-fallback mode.")
            return

        try:
            bundle = joblib.load(self.artifact_path)
            self.model = bundle["calibrated_model"]
            self.scaler = bundle["scaler"]
            self.metadata = {
                "model_name": bundle.get("model_name", "XGuard-Ensemble"),
                "model_version": bundle.get("model_version", "1.0.0"),
                "feature_importances": bundle.get("feature_importances", {}),
                "val_metrics": bundle.get("val_metrics", {})
            }
            if URLLexicalFeatureExtractor:
                self.extractor = URLLexicalFeatureExtractor()
            self.is_loaded = True
            logger.info(f"Loaded ML model: {self.metadata['model_name']} v{self.metadata['model_version']}")
        except Exception as e:
            logger.error(f"Failed to load ML artifact from {self.artifact_path}: {e}")
            self.is_loaded = False

    def predict(self, url: str) -> Tuple[int, float, Dict[str, Any]]:
        """
        Predict maliciousness class and calibrated risk probability for a URL.
        Returns (predicted_class, probability, meta_info).
        """
        if not self.is_loaded or not self.extractor or not self.model:
            return 0, 0.0, {
                "status": "unavailable",
                "reason": "ML model artifact not loaded",
                "model_version": None
            }

        try:
            vec = self.extractor.feature_vector(url)
            X = np.array([vec])
            X_scaled = self.scaler.transform(X)

            # Calibrated probability for class 1 (malicious)
            probs = self.model.predict_proba(X_scaled)[0]
            malicious_prob = round(float(probs[1]), 4)
            predicted_class = 1 if malicious_prob >= 0.5 else 0

            return predicted_class, malicious_prob, {
                "status": "success",
                "model_name": self.metadata["model_name"],
                "model_version": self.metadata["model_version"],
                "threshold": 0.50
            }
        except Exception as e:
            logger.error(f"ML inference error on {url}: {e}")
            return 0, 0.0, {
                "status": "error",
                "error": str(e),
                "model_version": self.metadata.get("model_version")
            }

    def get_info(self) -> Dict[str, Any]:
        return {
            "loaded": self.is_loaded,
            "artifact_path": self.artifact_path,
            "model_name": self.metadata.get("model_name", "None"),
            "model_version": self.metadata.get("model_version", "None"),
            "features_count": len(self.extractor.FEATURE_NAMES) if self.extractor else 0,
            "top_features": dict(sorted(
                self.metadata.get("feature_importances", {}).items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]),
            "calibration_method": "Platt / Sigmoid 3-Fold Cross-Validation",
            "val_metrics": self.metadata.get("val_metrics", {})
        }


# Singleton instance
ml_adapter = ThreatGuardMLAdapter()
