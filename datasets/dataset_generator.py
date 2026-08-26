"""
datasets/dataset_generator.py

Phase 6: Synthetic Behavioral Dataset Generation.

Generates labeled behavioral datasets matching the feature vector schema defined in
features.feature_extractor.FEATURE_NAMES.

Profiles simulated:
- Benign:
    1. Idle system state
    2. General desktop / office work
    3. Heavy software build / compilation
    4. Bulk file copy / archive extract
- Malicious / Ransomware:
    1. Rapid mass encryption burst (high rate, high rename/modify ratio, multi-dir)
    2. Stealth / slow ransomware (moderate rate, high rename ratio)
    3. Selective document encryption burst
"""

import argparse
import csv
import os
import random
from typing import Dict, List, Tuple

import config
from features.feature_extractor import FEATURE_NAMES
from utils.logger import get_logger

logger = get_logger("dataset_generator")


def _clamp(val: float, low: float, high: float) -> float:
    return max(low, min(high, val))


class DatasetGenerator:
    """Generates synthetic behavioral feature samples for training and evaluation."""

    def __init__(self, random_seed: int = 42):
        random.seed(random_seed)

    def generate_benign_idle(self) -> Dict[str, float]:
        num_created = random.choice([0, 0, 0, 1])
        num_modified = random.choice([0, 0, 1, 2])
        num_deleted = random.choice([0, 0, 0, 1])
        num_renamed = 0
        total_ops = num_created + num_modified + num_deleted + num_renamed
        window = float(config.FEATURE_WINDOW_SECONDS)
        rate = round(total_ops / window, 3)

        return {
            "num_created": float(num_created),
            "num_modified": float(num_modified),
            "num_deleted": float(num_deleted),
            "num_renamed": float(num_renamed),
            "total_operations": float(total_ops),
            "operation_rate_per_sec": rate,
            "unique_directories": float(1 if total_ops > 0 else 0),
            "unique_extensions": float(random.choice([0, 1]) if total_ops > 0 else 0),
            "rename_modify_ratio": 0.0,
            "cpu_percent": round(random.uniform(0.1, 4.0), 2),
            "memory_mb": round(random.uniform(15.0, 60.0), 2),
            "label": 0.0,
        }

    def generate_benign_general_work(self) -> Dict[str, float]:
        num_created = random.randint(1, 6)
        num_modified = random.randint(3, 15)
        num_deleted = random.randint(0, 3)
        num_renamed = random.choice([0, 0, 1])
        total_ops = num_created + num_modified + num_deleted + num_renamed
        window = float(config.FEATURE_WINDOW_SECONDS)
        rate = round(total_ops / window, 3)
        ratio = round(num_renamed / num_modified if num_modified > 0 else 0.0, 3)

        return {
            "num_created": float(num_created),
            "num_modified": float(num_modified),
            "num_deleted": float(num_deleted),
            "num_renamed": float(num_renamed),
            "total_operations": float(total_ops),
            "operation_rate_per_sec": rate,
            "unique_directories": float(random.randint(1, 3)),
            "unique_extensions": float(random.randint(1, 4)),
            "rename_modify_ratio": ratio,
            "cpu_percent": round(random.uniform(2.0, 20.0), 2),
            "memory_mb": round(random.uniform(40.0, 180.0), 2),
            "label": 0.0,
        }

    def generate_benign_dev_build(self) -> Dict[str, float]:
        num_created = random.randint(25, 120)
        num_modified = random.randint(40, 160)
        num_deleted = random.randint(5, 30)
        num_renamed = random.randint(0, 3)
        total_ops = num_created + num_modified + num_deleted + num_renamed
        window = float(config.FEATURE_WINDOW_SECONDS)
        rate = round(total_ops / window, 3)
        ratio = round(num_renamed / num_modified if num_modified > 0 else 0.0, 3)

        return {
            "num_created": float(num_created),
            "num_modified": float(num_modified),
            "num_deleted": float(num_deleted),
            "num_renamed": float(num_renamed),
            "total_operations": float(total_ops),
            "operation_rate_per_sec": rate,
            "unique_directories": float(random.randint(4, 12)),
            "unique_extensions": float(random.randint(3, 8)),
            "rename_modify_ratio": ratio,
            "cpu_percent": round(random.uniform(45.0, 98.0), 2),
            "memory_mb": round(random.uniform(200.0, 850.0), 2),
            "label": 0.0,
        }

    def generate_benign_file_transfer(self) -> Dict[str, float]:
        num_created = random.randint(30, 90)
        num_modified = random.randint(5, 20)
        num_deleted = 0
        num_renamed = 0
        total_ops = num_created + num_modified + num_deleted + num_renamed
        window = float(config.FEATURE_WINDOW_SECONDS)
        rate = round(total_ops / window, 3)

        return {
            "num_created": float(num_created),
            "num_modified": float(num_modified),
            "num_deleted": 0.0,
            "num_renamed": 0.0,
            "total_operations": float(total_ops),
            "operation_rate_per_sec": rate,
            "unique_directories": float(random.randint(1, 4)),
            "unique_extensions": float(random.randint(1, 3)),
            "rename_modify_ratio": 0.0,
            "cpu_percent": round(random.uniform(10.0, 35.0), 2),
            "memory_mb": round(random.uniform(80.0, 250.0), 2),
            "label": 0.0,
        }

    def generate_ransomware_rapid_burst(self) -> Dict[str, float]:
        # High modification + high renaming (appending extension)
        base = random.randint(40, 180)
        num_modified = base
        num_renamed = int(base * random.uniform(0.85, 1.15))
        num_created = random.randint(0, 8)
        num_deleted = random.randint(0, 15)
        total_ops = num_created + num_modified + num_deleted + num_renamed
        window = float(config.FEATURE_WINDOW_SECONDS)
        rate = round(total_ops / window, 3)
        ratio = round(num_renamed / num_modified if num_modified > 0 else 1.0, 3)

        return {
            "num_created": float(num_created),
            "num_modified": float(num_modified),
            "num_deleted": float(num_deleted),
            "num_renamed": float(num_renamed),
            "total_operations": float(total_ops),
            "operation_rate_per_sec": rate,
            "unique_directories": float(random.randint(4, 16)),
            "unique_extensions": float(random.randint(4, 12)),
            "rename_modify_ratio": ratio,
            "cpu_percent": round(random.uniform(35.0, 95.0), 2),
            "memory_mb": round(random.uniform(70.0, 320.0), 2),
            "label": 1.0,
        }

    def generate_ransomware_stealth(self) -> Dict[str, float]:
        # Lower throughput but characteristically high rename ratio and multi-dir
        num_modified = random.randint(12, 35)
        num_renamed = int(num_modified * random.uniform(0.80, 1.05))
        num_created = random.randint(0, 3)
        num_deleted = random.randint(0, 4)
        total_ops = num_created + num_modified + num_deleted + num_renamed
        window = float(config.FEATURE_WINDOW_SECONDS)
        rate = round(total_ops / window, 3)
        ratio = round(num_renamed / num_modified if num_modified > 0 else 1.0, 3)

        return {
            "num_created": float(num_created),
            "num_modified": float(num_modified),
            "num_deleted": float(num_deleted),
            "num_renamed": float(num_renamed),
            "total_operations": float(total_ops),
            "operation_rate_per_sec": rate,
            "unique_directories": float(random.randint(2, 6)),
            "unique_extensions": float(random.randint(3, 7)),
            "rename_modify_ratio": ratio,
            "cpu_percent": round(random.uniform(15.0, 45.0), 2),
            "memory_mb": round(random.uniform(40.0, 150.0), 2),
            "label": 1.0,
        }

    def generate_ransomware_selective(self) -> Dict[str, float]:
        num_modified = random.randint(25, 75)
        num_renamed = int(num_modified * random.uniform(0.90, 1.10))
        num_created = random.randint(0, 5)
        num_deleted = random.randint(0, 8)
        total_ops = num_created + num_modified + num_deleted + num_renamed
        window = float(config.FEATURE_WINDOW_SECONDS)
        rate = round(total_ops / window, 3)
        ratio = round(num_renamed / num_modified if num_modified > 0 else 1.0, 3)

        return {
            "num_created": float(num_created),
            "num_modified": float(num_modified),
            "num_deleted": float(num_deleted),
            "num_renamed": float(num_renamed),
            "total_operations": float(total_ops),
            "operation_rate_per_sec": rate,
            "unique_directories": float(random.randint(2, 8)),
            "unique_extensions": float(random.randint(2, 6)),
            "rename_modify_ratio": ratio,
            "cpu_percent": round(random.uniform(25.0, 75.0), 2),
            "memory_mb": round(random.uniform(50.0, 220.0), 2),
            "label": 1.0,
        }

    def generate_dataset(self, total_samples: int = 5000) -> Tuple[List[Dict[str, float]], List[Dict[str, float]]]:
        """Generate balanced benign and ransomware samples with an 80/20 train/test split."""
        samples: List[Dict[str, float]] = []

        benign_generators = [
            (self.generate_benign_idle, 0.35),
            (self.generate_benign_general_work, 0.35),
            (self.generate_benign_dev_build, 0.20),
            (self.generate_benign_file_transfer, 0.10),
        ]

        ransomware_generators = [
            (self.generate_ransomware_rapid_burst, 0.50),
            (self.generate_ransomware_stealth, 0.25),
            (self.generate_ransomware_selective, 0.25),
        ]

        half = total_samples // 2

        # Generate Benign samples
        for _ in range(half):
            r = random.random()
            cum = 0.0
            for gen_fn, weight in benign_generators:
                cum += weight
                if r <= cum:
                    samples.append(gen_fn())
                    break

        # Generate Ransomware samples
        for _ in range(total_samples - half):
            r = random.random()
            cum = 0.0
            for gen_fn, weight in ransomware_generators:
                cum += weight
                if r <= cum:
                    samples.append(gen_fn())
                    break

        random.shuffle(samples)

        split_idx = int(len(samples) * 0.8)
        train_set = samples[:split_idx]
        test_set = samples[split_idx:]

        return train_set, test_set

    def save_to_csv(self, data: List[Dict[str, float]], filepath: str):
        """Save feature dictionaries to CSV with header."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        fieldnames = FEATURE_NAMES + ["label"]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in data:
                writer.writerow(row)

        logger.info("Saved %d samples to %s", len(data), filepath)


def generate_and_save_datasets(samples: int = 6000) -> Tuple[str, str]:
    generator = DatasetGenerator()
    train_data, test_data = generator.generate_dataset(total_samples=samples)

    generator.save_to_csv(train_data, config.TRAIN_DATASET_PATH)
    generator.save_to_csv(test_data, config.TEST_DATASET_PATH)

    logger.info(
        "Dataset generation complete: Train=%d samples (%s), Test=%d samples (%s)",
        len(train_data), config.TRAIN_DATASET_PATH,
        len(test_data), config.TEST_DATASET_PATH,
    )
    return config.TRAIN_DATASET_PATH, config.TEST_DATASET_PATH


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic behavioral dataset for ransomware detection.")
    parser.add_argument("--samples", type=int, default=6000, help="Total number of samples (default: 6000)")
    args = parser.parse_args()

    print(f"Generating dataset with {args.samples} samples...")
    train_p, test_p = generate_and_save_datasets(samples=args.samples)
    print(f"Saved training dataset: {train_p}")
    print(f"Saved testing dataset:  {test_p}")

