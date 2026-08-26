"""
ml package.

Machine learning model training, management, and real-time threat detection engine.
"""

from ml.detector import DetectionResult, RansomwareDetector, ThreatLevel
from ml.model_manager import ModelManager, ModelMetadata
from ml.train_model import train_and_evaluate

__all__ = [
    "DetectionResult",
    "ModelManager",
    "ModelMetadata",
    "RansomwareDetector",
    "ThreatLevel",
    "train_and_evaluate",
]
