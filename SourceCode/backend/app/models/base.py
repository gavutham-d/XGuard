"""
Base interface for machine learning URL classification adapters.
Allows interchangeable models (e.g. scikit-learn, Hugging Face, ONNX).
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple


class BaseURLClassifier(ABC):
    @abstractmethod
    def predict(self, url: str) -> Tuple[int, float, Dict[str, Any]]:
        """
        Evaluate URL string.
        Returns:
            (predicted_class [0=benign, 1=malicious],
             calibrated_risk_probability [0.0 to 1.0],
             metadata_dict [version, feature_contributions, status])
        """
        pass

    @abstractmethod
    def get_info(self) -> Dict[str, Any]:
        """Return model metadata, version, and training status."""
        pass
