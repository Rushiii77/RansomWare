"""
ml/detector.py

Phase 8: Real-Time Threat Detection & Risk Scoring Engine.

Loads the trained machine learning model, receives behavioral feature vectors
from features.feature_extractor, computes ransomware probability, categorizes
the threat level, and attributes candidate offending processes.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

import config
from features.feature_extractor import FeatureExtractor, FEATURE_NAMES
from ml.model_manager import ModelManager, ModelMetadata
from monitoring.file_monitor import FileMonitor
from monitoring.process_monitor import ProcessMonitor, ProcessSnapshot
from utils.logger import get_logger

logger = get_logger("detector")


class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


@dataclass
class DetectionResult:
    """Detailed output of a real-time behavioral threat evaluation."""
    is_ransomware: bool
    threat_level: ThreatLevel
    confidence: float
    features: Dict[str, float]
    top_contributing_features: List[Tuple[str, float]] = field(default_factory=list)
    suspect_pid: Optional[int] = None
    suspect_name: Optional[str] = None
    evaluated_at: float = field(default_factory=time.time)

    def summary(self) -> str:
        status = f"[{self.threat_level.value}] Confidence: {self.confidence * 100:.1f}%"
        if self.is_ransomware and self.suspect_pid:
            status += f" | Suspect: PID {self.suspect_pid} ({self.suspect_name})"
        return status


class RansomwareDetector:
    """
    Inference coordinator that consumes feature vectors and scores threat likelihood.
    """

    def __init__(self, model_path: str = config.MODEL_PATH):
        self.model_path = model_path
        self._model: Optional[Any] = None
        self._metadata: Optional[ModelMetadata] = None
        self._feature_names: List[str] = FEATURE_NAMES
        self._load_or_train_model()

    def _load_or_train_model(self):
        """Load model from disk or trigger training if not yet built."""
        if not ModelManager.model_exists(self.model_path):
            logger.warning("No trained model found at %s. Triggering training now...", self.model_path)
            from ml.train_model import train_and_evaluate
            self._model, self._metadata = train_and_evaluate(save_path=self.model_path)
        else:
            self._model, self._metadata, self._feature_names = ModelManager.load_model(self.model_path)

    def _determine_threat_level(self, probability: float) -> Tuple[bool, ThreatLevel]:
        if probability >= config.THREAT_THRESHOLD_CRITICAL:
            return True, ThreatLevel.CRITICAL
        elif probability >= config.THREAT_THRESHOLD_HIGH:
            return True, ThreatLevel.HIGH_RISK
        elif probability >= config.THREAT_THRESHOLD_SUSPICIOUS:
            return False, ThreatLevel.SUSPICIOUS
        else:
            return False, ThreatLevel.SAFE

    def _identify_suspect_process(self, process_snapshots: List[ProcessSnapshot]) -> Tuple[Optional[int], Optional[str]]:
        """Identify the most likely offending process during an attack burst."""
        if not process_snapshots:
            return None, None

        # Filter out system or idle processes, pick highest CPU consumer
        candidates = [p for p in process_snapshots if p.pid > 0 and p.name.lower() not in ("kernel_task", "system", "idle")]
        if not candidates:
            candidates = process_snapshots

        top = max(candidates, key=lambda p: p.cpu_percent)
        return top.pid, top.name

    def evaluate_features(
        self,
        features: Dict[str, float],
        active_processes: Optional[List[ProcessSnapshot]] = None,
    ) -> DetectionResult:
        """
        Evaluate a single feature dictionary and return a DetectionResult.
        """
        vector = np.array([[features.get(name, 0.0) for name in self._feature_names]], dtype=np.float32)

        if hasattr(self._model, "predict_proba"):
            probs = self._model.predict_proba(vector)[0]
            # Class 1 is Ransomware
            ransomware_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        else:
            pred = self._model.predict(vector)[0]
            ransomware_prob = float(pred)

        is_threat, level = self._determine_threat_level(ransomware_prob)

        # Calculate top contributing features using model feature importances
        top_features = []
        if hasattr(self._model, "feature_importances_"):
            importances = self._model.feature_importances_
            feature_impacts = [(name, float(features.get(name, 0.0) * imp)) for name, imp in zip(self._feature_names, importances)]
            feature_impacts.sort(key=lambda x: x[1], reverse=True)
            top_features = feature_impacts[:3]

        suspect_pid, suspect_name = (None, None)
        if is_threat and active_processes:
            suspect_pid, suspect_name = self._identify_suspect_process(active_processes)

        result = DetectionResult(
            is_ransomware=is_threat,
            threat_level=level,
            confidence=round(ransomware_prob, 4),
            features=features,
            top_contributing_features=top_features,
            suspect_pid=suspect_pid,
            suspect_name=suspect_name,
        )

        if is_threat:
            logger.warning(
                "THREAT DETECTED [%s] Confidence=%.2f%% Suspect=%s (PID %s)",
                level.value, ransomware_prob * 100, suspect_name, suspect_pid
            )
        else:
            logger.debug("Evaluation result: %s (Prob=%.4f)", level.value, ransomware_prob)

        return result

    def evaluate_live(
        self,
        file_monitor: FileMonitor,
        process_monitor: ProcessMonitor,
        window_seconds: float = config.FEATURE_WINDOW_SECONDS,
    ) -> DetectionResult:
        """Helper to sample live monitors and evaluate current threat state."""
        extractor = FeatureExtractor(window_seconds=window_seconds)
        events = file_monitor.get_recent_events(seconds=window_seconds)
        processes = process_monitor.get_all_processes()

        # Find highest CPU process snapshot for window context
        top_proc = max(processes, key=lambda p: p.cpu_percent) if processes else None
        feat_result = extractor.extract(events, process_snapshot=top_proc)

        return self.evaluate_features(feat_result.features, active_processes=processes)


# ---------------------------------------------------------------------------
# Manual live detection loop: `python -m ml.detector`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 65)
    print("       LIVE REAL-TIME AI RANSOMWARE DETECTION ENGINE")
    print("=" * 65)
    detector = RansomwareDetector()

    p_mon = ProcessMonitor(poll_interval=2.0)
    f_mon = FileMonitor(config.DEFAULT_WATCH_DIRECTORY)

    p_mon.start()
    f_mon.start()

    print(f"Monitoring watch directory: {config.DEFAULT_WATCH_DIRECTORY}")
    print("Polling every 2s for threat activity... (Press Ctrl+C to exit)\n")

    try:
        while True:
            time.sleep(2.0)
            res = detector.evaluate_live(f_mon, p_mon)
            ts = time.strftime("%H:%M:%S", time.localtime(res.evaluated_at))
            ops = res.features.get("total_operations", 0)
            ratio = res.features.get("rename_modify_ratio", 0)

            color = "\033[92m" if res.threat_level == ThreatLevel.SAFE else (
                "\033[93m" if res.threat_level == ThreatLevel.SUSPICIOUS else "\033[91m"
            )
            reset = "\033[0m"

            print(f"[{ts}] {color}{res.summary()}{reset} | Ops: {ops:.0f} | Rename/Modify: {ratio:.2f}")
    except KeyboardInterrupt:
        print("\nStopping detector...")
    finally:
        f_mon.stop()
        p_mon.stop()

