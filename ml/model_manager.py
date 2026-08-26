"""
ml/model_manager.py

Model serialization, loading, metadata management, and validation.
"""

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import joblib

import config
from features.feature_extractor import FEATURE_NAMES
from utils.logger import get_logger

logger = get_logger("model_manager")


@dataclass
class ModelMetadata:
    model_name: str
    feature_names: List[str]
    trained_at: float
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    parameters: Dict[str, Any] = field(default_factory=dict)
    version: str = "1.0.0"


class ModelManager:
    """Handles persistence and retrieval of trained machine learning models."""

    @staticmethod
    def save_model(model: Any, metadata: ModelMetadata, filepath: str = config.MODEL_PATH):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        payload = {
            "model": model,
            "metadata": metadata,
            "feature_names": metadata.feature_names,
            "saved_at": time.time(),
        }
        joblib.dump(payload, filepath)
        logger.info("Saved trained model to %s (Accuracy: %.4f, F1: %.4f)", filepath, metadata.accuracy, metadata.f1_score)

    @staticmethod
    def load_model(filepath: str = config.MODEL_PATH) -> Tuple[Any, Optional[ModelMetadata], List[str]]:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Trained model file not found at: {filepath}. Train the model first.")

        payload = joblib.load(filepath)
        model = payload.get("model")
        metadata = payload.get("metadata")
        feature_names = payload.get("feature_names", FEATURE_NAMES)

        logger.info("Loaded model from %s (Trained at: %s)", filepath, time.ctime(metadata.trained_at if metadata else 0))
        return model, metadata, feature_names

    @staticmethod
    def model_exists(filepath: str = config.MODEL_PATH) -> bool:
        return os.path.isfile(filepath)
