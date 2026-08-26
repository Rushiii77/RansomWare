"""
datasets package.

Provides behavioral dataset generation and synthesis utilities for ransomware detection ML pipelines.
"""

from datasets.dataset_generator import DatasetGenerator, generate_and_save_datasets

__all__ = ["DatasetGenerator", "generate_and_save_datasets"]

