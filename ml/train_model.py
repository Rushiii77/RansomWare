"""
ml/train_model.py

Phase 7: Machine Learning Model Training & Evaluation.

Trains a Random Forest classifier on behavioral feature vectors, evaluates
performance (Accuracy, Precision, Recall, F1, ROC-AUC), and serializes the model.
"""

import argparse
import csv
import os
import time
from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

import config
from datasets.dataset_generator import generate_and_save_datasets
from features.feature_extractor import FEATURE_NAMES
from ml.model_manager import ModelManager, ModelMetadata
from utils.logger import get_logger

logger = get_logger("train_model")


def load_dataset_from_csv(filepath: str) -> Tuple[np.ndarray, np.ndarray]:
    """Load feature matrix X and label vector y from CSV."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset not found at: {filepath}")

    X_list = []
    y_list = []

    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vector = [float(row.get(name, 0.0)) for name in FEATURE_NAMES]
            label = float(row.get("label", 0.0))
            X_list.append(vector)
            y_list.append(label)

    return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.float32)


def train_and_evaluate(
    train_path: str = config.TRAIN_DATASET_PATH,
    test_path: str = config.TEST_DATASET_PATH,
    save_path: str = config.MODEL_PATH,
) -> Tuple[Any, ModelMetadata]:
    """Train Random Forest model, compute metrics, and save serialized artifact."""
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        logger.info("Datasets not found. Auto-generating fresh synthetic datasets...")
        generate_and_save_datasets(samples=6000)

    logger.info("Loading training data from %s...", train_path)
    X_train, y_train = load_dataset_from_csv(train_path)
    logger.info("Loading testing data from %s...", test_path)
    X_test, y_test = load_dataset_from_csv(test_path)

    logger.info("Training samples: %d | Testing samples: %d", len(X_train), len(X_test))

    # Initialize Random Forest Classifier
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )

    start_time = time.perf_counter()
    clf.fit(X_train, y_train)
    train_duration = time.perf_counter() - start_time
    logger.info("Model training completed in %.3fs.", train_duration)

    # Predictions & Probabilities
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1] if hasattr(clf, "predict_proba") else y_pred

    # Compute Metrics
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_prob))
    cm = confusion_matrix(y_test, y_pred)

    metadata = ModelMetadata(
        model_name="RandomForestClassifier",
        feature_names=FEATURE_NAMES,
        trained_at=time.time(),
        accuracy=round(acc, 4),
        precision=round(prec, 4),
        recall=round(rec, 4),
        f1_score=round(f1, 4),
        roc_auc=round(roc_auc, 4),
        parameters={
            "n_estimators": 100,
            "max_depth": 12,
            "train_samples": len(X_train),
            "test_samples": len(X_test),
        },
    )

    # Save model
    ModelManager.save_model(clf, metadata, filepath=save_path)

    # Log / Print Summary
    print("\n" + "=" * 65)
    print("         MACHINE LEARNING MODEL EVALUATION REPORT")
    print("=" * 65)
    print(f"Model Architecture:   RandomForestClassifier (100 trees, max_depth=12)")
    print(f"Dataset Size:         Train={len(X_train):,} | Test={len(X_test):,}")
    print("-" * 65)
    print(f"Accuracy:             {acc * 100:.2f}%")
    print(f"Precision:            {prec * 100:.2f}%")
    print(f"Recall:               {rec * 100:.2f}%")
    print(f"F1-Score:             {f1 * 100:.2f}%")
    print(f"ROC-AUC:              {roc_auc * 100:.2f}%")
    print("-" * 65)
    print("Confusion Matrix:")
    print(f"  [TN={cm[0][0]:<5}  FP={cm[0][1]:<5}] (True Benign / False Positive)")
    print(f"  [FN={cm[1][0]:<5}  TP={cm[1][1]:<5}] (False Negative / True Ransomware)")
    print("-" * 65)
    print("Feature Importances:")
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    for rank, idx in enumerate(sorted_idx, 1):
        print(f"  {rank:>2}. {FEATURE_NAMES[idx]:<25} {importances[idx] * 100:5.2f}%")
    print("=" * 65 + "\n")

    return clf, metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train and evaluate ransomware detection ML model.")
    parser.add_argument("--save-path", type=str, default=config.MODEL_PATH, help="Path to save trained model")
    args = parser.parse_args()

    train_and_evaluate(save_path=args.save_path)

