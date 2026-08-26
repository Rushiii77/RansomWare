"""
tests/test_unit_ml.py

Automated unit tests for Phases 6-8:
- Dataset generation & schema validation
- Model training, evaluation metrics, and serialization
- Real-time RansomwareDetector inference and risk level scoring
"""

import os
import shutil
import tempfile
import time
import unittest

import numpy as np

import config
from datasets.dataset_generator import DatasetGenerator
from features.feature_extractor import FEATURE_NAMES
from ml.detector import DetectionResult, RansomwareDetector, ThreatLevel
from ml.model_manager import ModelManager, ModelMetadata
from ml.train_model import train_and_evaluate
from monitoring.process_monitor import ProcessSnapshot


class TestDatasetGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = DatasetGenerator(random_seed=42)

    def test_benign_samples_schema(self):
        sample = self.generator.generate_benign_dev_build()
        self.assertEqual(sample["label"], 0.0)
        for name in FEATURE_NAMES:
            self.assertIn(name, sample)

    def test_ransomware_samples_schema(self):
        sample = self.generator.generate_ransomware_rapid_burst()
        self.assertEqual(sample["label"], 1.0)
        self.assertGreater(sample["rename_modify_ratio"], 0.5)
        for name in FEATURE_NAMES:
            self.assertIn(name, sample)

    def test_dataset_generation_split(self):
        train, test = self.generator.generate_dataset(total_samples=100)
        self.assertEqual(len(train), 80)
        self.assertEqual(len(test), 20)


class TestModelTrainingAndManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.model_path = os.path.join(self.temp_dir, "test_model.pkl")
        self.train_path = os.path.join(self.temp_dir, "train.csv")
        self.test_path = os.path.join(self.temp_dir, "test.csv")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_train_and_save_pipeline(self):
        generator = DatasetGenerator(random_seed=42)
        train_data, test_data = generator.generate_dataset(total_samples=200)
        generator.save_to_csv(train_data, self.train_path)
        generator.save_to_csv(test_data, self.test_path)

        model, meta = train_and_evaluate(
            train_path=self.train_path,
            test_path=self.test_path,
            save_path=self.model_path,
        )

        self.assertTrue(os.path.isfile(self.model_path))
        self.assertGreater(meta.accuracy, 0.90)
        self.assertGreater(meta.f1_score, 0.90)

        # Load back via ModelManager
        loaded_model, loaded_meta, features = ModelManager.load_model(self.model_path)
        self.assertEqual(loaded_meta.model_name, "RandomForestClassifier")
        self.assertEqual(features, FEATURE_NAMES)


class TestRansomwareDetector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.model_path = os.path.join(cls.temp_dir, "detector_model.pkl")
        cls.train_path = os.path.join(cls.temp_dir, "train.csv")
        cls.test_path = os.path.join(cls.temp_dir, "test.csv")

        generator = DatasetGenerator(random_seed=42)
        train_data, test_data = generator.generate_dataset(total_samples=300)
        generator.save_to_csv(train_data, cls.train_path)
        generator.save_to_csv(test_data, cls.test_path)

        train_and_evaluate(
            train_path=cls.train_path,
            test_path=cls.test_path,
            save_path=cls.model_path,
        )
        cls.detector = RansomwareDetector(model_path=cls.model_path)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_benign_idle_detection(self):
        idle_features = {
            "num_created": 0.0,
            "num_modified": 1.0,
            "num_deleted": 0.0,
            "num_renamed": 0.0,
            "total_operations": 1.0,
            "operation_rate_per_sec": 0.1,
            "unique_directories": 1.0,
            "unique_extensions": 1.0,
            "rename_modify_ratio": 0.0,
            "cpu_percent": 1.0,
            "memory_mb": 30.0,
        }
        res = self.detector.evaluate_features(idle_features)
        self.assertFalse(res.is_ransomware)
        self.assertEqual(res.threat_level, ThreatLevel.SAFE)
        self.assertLess(res.confidence, 0.40)

    def test_ransomware_burst_detection(self):
        burst_features = {
            "num_created": 2.0,
            "num_modified": 120.0,
            "num_deleted": 0.0,
            "num_renamed": 115.0,
            "total_operations": 237.0,
            "operation_rate_per_sec": 23.7,
            "unique_directories": 8.0,
            "unique_extensions": 6.0,
            "rename_modify_ratio": 0.96,
            "cpu_percent": 75.0,
            "memory_mb": 180.0,
        }
        procs = [
            ProcessSnapshot(pid=401, name="python", exe_path="/usr/bin/python", cpu_percent=85.0, memory_mb=120.0, status="running", create_time=time.time(), username="test"),
            ProcessSnapshot(pid=402, name="Finder", exe_path="/System/Finder", cpu_percent=2.0, memory_mb=90.0, status="running", create_time=time.time(), username="test"),
        ]
        res = self.detector.evaluate_features(burst_features, active_processes=procs)
        self.assertTrue(res.is_ransomware)
        self.assertIn(res.threat_level, (ThreatLevel.HIGH_RISK, ThreatLevel.CRITICAL))
        self.assertGreaterEqual(res.confidence, 0.75)
        self.assertEqual(res.suspect_pid, 401)
        self.assertEqual(res.suspect_name, "python")


if __name__ == "__main__":
    unittest.main()

