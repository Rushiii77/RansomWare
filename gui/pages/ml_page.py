"""
gui/pages/ml_page.py

Phase 14 / Section 12 & 19: Machine Learning Model Management & Insights Page.

Displays model architecture, evaluation metrics, interactive Matplotlib
feature importance ranking chart, and training triggers.
"""

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

import matplotlib
matplotlib.use("QtAgg")
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np

import config
from datasets.dataset_generator import generate_and_save_datasets
from features.feature_extractor import FEATURE_NAMES
from ml.model_manager import ModelManager, ModelMetadata
from ml.train_model import train_and_evaluate


class MLModelPage(QWidget):
    """Machine Learning model metrics, feature importances, and management view."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.model = None
        self.metadata = None
        self._init_ui()
        self.load_model_info()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Header
        top_bar = QHBoxLayout()
        title = QLabel("🧠 Machine Learning Model & Behavioral Feature Analytics")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setStyleSheet("color: #f8fafc;")
        top_bar.addWidget(title)

        top_bar.addStretch()

        btn_gen = QPushButton("Generate Dataset")
        btn_gen.setStyleSheet("""
            QPushButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover { background-color: #475569; }
        """)
        btn_gen.clicked.connect(self._handle_generate_dataset)
        top_bar.addWidget(btn_gen)

        btn_retrain = QPushButton("Retrain AI Model")
        btn_retrain.setFont(QFont("Arial", 10, QFont.Bold))
        btn_retrain.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 6px 14px;
            }
            QPushButton:hover { background-color: #1d4ed8; }
        """)
        btn_retrain.clicked.connect(self._handle_retrain)
        top_bar.addWidget(btn_retrain)

        layout.addLayout(top_bar)

        # Metric Cards Row
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)

        self.card_acc = self._create_metric_box("Accuracy", "100.0%", "#22c55e")
        self.card_prec = self._create_metric_box("Precision", "100.0%", "#38bdf8")
        self.card_rec = self._create_metric_box("Recall", "100.0%", "#f43f5e")
        self.card_f1 = self._create_metric_box("F1-Score", "1.000", "#a855f7")

        cards_row.addWidget(self.card_acc)
        cards_row.addWidget(self.card_prec)
        cards_row.addWidget(self.card_rec)
        cards_row.addWidget(self.card_f1)
        layout.addLayout(cards_row)

        # Middle Content: Matplotlib Feature Importance Chart & Model Architecture Details
        content_row = QHBoxLayout()
        content_row.setSpacing(15)

        # Matplotlib Chart Frame
        chart_frame = QFrame()
        chart_frame.setStyleSheet("""
            QFrame {
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        chart_layout = QVBoxLayout(chart_frame)

        lbl_chart_title = QLabel("📊 Behavioral Feature Importance Weights (Random Forest)")
        lbl_chart_title.setFont(QFont("Arial", 11, QFont.Bold))
        lbl_chart_title.setStyleSheet("color: #e2e8f0;")
        chart_layout.addWidget(lbl_chart_title)

        self.fig = Figure(figsize=(6, 3.8), dpi=100, facecolor="#0f172a")
        self.canvas = FigureCanvas(self.fig)
        self.ax = self.fig.add_subplot(111)
        chart_layout.addWidget(self.canvas)

        content_row.addWidget(chart_frame, stretch=3)

        # Architecture Info Frame
        info_frame = QFrame()
        info_frame.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        info_layout = QVBoxLayout(info_frame)

        lbl_arch = QLabel("Model Specifications")
        lbl_arch.setFont(QFont("Arial", 11, QFont.Bold))
        lbl_arch.setStyleSheet("color: #38bdf8;")
        info_layout.addWidget(lbl_arch)

        self.lbl_details = QLabel(
            "• <b>Algorithm:</b> Random Forest Classifier<br>"
            "• <b>Ensemble:</b> 100 Decision Trees<br>"
            "• <b>Max Depth:</b> 12 splits<br>"
            "• <b>Classes:</b> 0 (Benign) vs 1 (Ransomware)<br>"
            "• <b>Feature Vector:</b> 11 Behavioral Metrics<br>"
            "• <b>Class Weights:</b> Balanced<br>"
            "• <b>Storage:</b> Joblib Binary Artifact<br>"
            f"• <b>Model Path:</b> <br><code>{config.MODEL_PATH}</code>"
        )
        self.lbl_details.setTextFormat(Qt.RichText)
        self.lbl_details.setStyleSheet("color: #cbd5e1; font-size: 11px; line-height: 1.6;")
        self.lbl_details.setWordWrap(True)
        info_layout.addWidget(self.lbl_details)
        info_layout.addStretch()

        content_row.addWidget(info_frame, stretch=2)
        layout.addLayout(content_row)

    def _create_metric_box(self, title: str, val: str, color_hex: str) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(8, 6, 8, 6)

        lbl_t = QLabel(title)
        lbl_t.setFont(QFont("Arial", 9))
        lbl_t.setStyleSheet("color: #94a3b8;")
        layout.addWidget(lbl_t)

        lbl_v = QLabel(val)
        lbl_v.setFont(QFont("Arial", 16, QFont.Bold))
        lbl_v.setStyleSheet(f"color: {color_hex};")
        layout.addWidget(lbl_v)

        frame.lbl_val = lbl_v
        return frame

    def load_model_info(self):
        try:
            if not ModelManager.model_exists():
                self.model, self.metadata = train_and_evaluate()
            else:
                self.model, self.metadata, _ = ModelManager.load_model()

            if self.metadata:
                self.card_acc.lbl_val.setText(f"{self.metadata.accuracy * 100:.1f}%")
                self.card_prec.lbl_val.setText(f"{self.metadata.precision * 100:.1f}%")
                self.card_rec.lbl_val.setText(f"{self.metadata.recall * 100:.1f}%")
                self.card_f1.lbl_val.setText(f"{self.metadata.f1_score:.3f}")

            self._draw_feature_importance_chart()

        except Exception as e:
            QMessageBox.warning(self, "Model Load Error", f"Could not load ML model info: {e}")

    def _draw_feature_importance_chart(self):
        self.ax.clear()
        self.ax.set_facecolor("#0f172a")

        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
            names = FEATURE_NAMES
            sorted_idx = np.argsort(importances)

            y_pos = np.arange(len(names))
            sorted_names = [names[i] for i in sorted_idx]
            sorted_vals = [importances[i] * 100 for i in sorted_idx]

            bars = self.ax.barh(y_pos, sorted_vals, color="#38bdf8", height=0.6, align="center")

            self.ax.set_yticks(y_pos)
            self.ax.set_yticklabels(sorted_names, color="#cbd5e1", fontsize=8)
            self.ax.set_xlabel("Importance Weight (%)", color="#94a3b8", fontsize=8)
            self.ax.tick_params(colors="#64748b", labelsize=8)
            self.ax.spines["bottom"].set_color("#334155")
            self.ax.spines["top"].set_color("#0f172a")
            self.ax.spines["left"].set_color("#334155")
            self.ax.spines["right"].set_color("#0f172a")
            self.fig.tight_layout()
            self.canvas.draw_idle()

    def _handle_generate_dataset(self):
        try:
            train_p, test_p = generate_and_save_datasets(samples=6000)
            QMessageBox.information(self, "Dataset Generated", f"Successfully synthesized fresh training dataset (6,000 samples):\n\n{train_p}")
        except Exception as e:
            QMessageBox.critical(self, "Generation Failed", f"Error generating dataset: {e}")

    def _handle_retrain(self):
        try:
            self.model, self.metadata = train_and_evaluate()
            self.load_model_info()
            QMessageBox.information(self, "Training Complete", f"Random Forest model retrained successfully!\nAccuracy: {self.metadata.accuracy*100:.2f}%\nF1 Score: {self.metadata.f1_score:.4f}")
        except Exception as e:
            QMessageBox.critical(self, "Retraining Failed", f"Error retraining model: {e}")

