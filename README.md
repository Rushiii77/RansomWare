# AI-Based Ransomware Detection & Process Termination System

**Final Delivery: Complete 18-Phase Implementation (100% Delivered).**

A defensive, academic, and demonstrable cybersecurity endpoint security application that uses Machine Learning and behavioral telemetry to detect ransomware activity and trigger automated process-level mitigation.

Strictly defensive and non-destructive: contains zero encryption algorithms, zero destructive payloads, and operates test simulations exclusively inside a safe sandbox folder (`test_environment/`).

---

## 18-Phase Implementation Matrix

| Phase | Module | Status | Description |
|:---:|---|:---:|---|
| **1** | Project Setup & Central Config | ✅ **Done** | Base directory structure, rotating logger (`utils/logger.py`), centralized settings (`config.py`). |
| **2** | Process Monitoring | ✅ **Done** | Background telemetry with `psutil` capturing PID, name, CPU%, memory, status, and username. |
| **3** | File-System Monitoring | ✅ **Done** | Real-time `watchdog` observer capturing `CREATE`, `MODIFY`, `DELETE`, and `RENAME` events. |
| **4** | Behavioral Feature Extraction | ✅ **Done** | Rolling 10s window calculating 11 behavioral features (operation rates, rename-modify ratios, multi-dir). |
| **5** | Safe Ransomware Simulator | ✅ **Done** | Sandbox burst test generator strictly confined to `test_environment/` with safety assertions. |
| **6** | Behavioral Dataset Synthesis | ✅ **Done** | 6,000 labeled behavioral samples across 4 benign and 3 attack profiles (`datasets/dataset_generator.py`). |
| **7** | Machine Learning Model Training | ✅ **Done** | 100-tree `RandomForestClassifier` with balanced class weights saved to `ml/saved_models/`. |
| **8** | Model Evaluation & Metrics | ✅ **Done** | 100% test accuracy, 1.000 F1 score, zero false positives during intensive developer compilation workloads. |
| **9** | Real-Time ML Threat Detector | ✅ **Done** | Live telemetry streaming, threat classification, and candidate offending PID attribution (`ml/detector.py`). |
| **10**| Risk Scoring Engine | ✅ **Done** | Configurable threat levels: `SAFE`, `SUSPICIOUS` (50–74), `HIGH_RISK` (75–89), `CRITICAL` (90–100). |
| **11**| Process Termination & Response | ✅ **Done** | Graceful `SIGTERM` with `SIGKILL` fallback and critical OS whitelist protection (`response/process_terminator.py`). |
| **12**| SQLite Persistence & Auditing | ✅ **Done** | Thread-safe SQLite storage for threat incidents, whitelists, and actions (`database/db_manager.py`). |
| **13**| Background System Tray / Menu Bar | ✅ **Done** | Background macOS Menu Bar & Windows System Tray shield daemon with dynamic status badges (`gui/tray_app.py`). |
| **14**| Multi-Tab Desktop Command Center | ✅ **Done** | Sleek PySide6 dark-themed GUI with 9 tabs: Dashboard, Processes, Activity, Alerts, Incidents, Reports, ML, Settings, About. |
| **15**| PDF Forensic Report Generation | ✅ **Done** | `ReportLab` engine exporting official incident investigation and audit summary PDFs (`reporting/report_generator.py`). |
| **16**| End-to-End System Integration | ✅ **Done** | Real-time thread coordination across telemetry, AI engine, SQLite, GUI, and tray. |
| **17**| Automated Testing & Verification | ✅ **Done** | 22 comprehensive unit and integration tests passing in < 1.2s (`tests/`). |
| **18**| Viva Defense & Presentation Guide | ✅ **Done** | Built-in academic presentation overview, architecture flowcharts, and Viva Q&A page. |

---

## Folder Structure

```
ransomware_detection/
├── app.py                          # Unified launcher (Desktop GUI / System Tray / CLI)
├── config.py                       # Central paths, settings & ML thresholds
├── requirements.txt                # Dependencies (PySide6, scikit-learn, psutil, watchdog, matplotlib, reportlab)
├── README.md                       # Complete documentation & run guide
│
├── gui/                            # PySide6 Desktop GUI & System Tray
│   ├── main_window.py              # Primary 9-tab cybersecurity dashboard window
│   ├── alert_dialog.py             # Interactive Terminate vs. Ignore popup prompt
│   ├── tray_app.py                 # macOS Menu Bar / Windows System Tray daemon
│   └── pages/
│       ├── dashboard_page.py       # Metrics, risk meter & Matplotlib trend chart
│       ├── processes_page.py       # Live process table with manual [Terminate]
│       ├── activity_page.py        # Real-time streaming file event stream
│       ├── alerts_page.py          # Threat alerts and rapid response controls
│       ├── incidents_page.py       # SQLite audit records & PDF export
│       ├── reports_page.py         # PDF forensic reports hub & archive
│       ├── ml_page.py              # ML architecture, metrics & feature importance chart
│       ├── settings_page.py        # Watch directory, thresholds & whitelist editor
│       └── about_page.py           # Academic presentation & Viva defense Q&A
│
├── monitoring/
│   ├── process_monitor.py          # Phase 2: Live psutil process telemetry
│   └── file_monitor.py             # Phase 3: Watchdog file-system observer
│
├── features/
│   └── feature_extractor.py        # Phase 4: Rolling window feature extraction
│
├── ml/
│   ├── detector.py                 # Phase 8/9: Real-time threat detection & PID attribution
│   ├── model_manager.py            # Phase 7: Model persistence & metadata
│   ├── train_model.py              # Phase 7: Random Forest training & evaluation
│   └── saved_models/
│       └── ransomware_detector_rf.pkl # Serialized trained AI model
│
├── response/
│   └── process_terminator.py       # Phase 11: Safe process termination engine
│
├── database/
│   ├── db_manager.py               # Phase 12: SQLite incident persistence & whitelist
│   └── incidents.db                # SQLite database file
│
├── reporting/
│   ├── report_generator.py         # Phase 15: ReportLab PDF forensic report generator
│   └── reports/                    # Exported PDF incident & audit reports
│
├── simulator/
│   ├── safe_ransomware_simulator.py# Phase 5: Harmless test burst generator
│   ├── mock_ransomware_actor.py    # Dedicated mock threat process for testing
│   └── demo_threat_test.py         # Guided threat test demonstration harness
│
├── datasets/
│   ├── dataset_generator.py        # Phase 6: Behavioral dataset generator
│   ├── training_dataset.csv        # 4,800 training samples
│   └── test_dataset.csv            # 1,200 test samples
│
├── utils/
│   └── logger.py                   # Centralized rotating file and console logging
│
├── tests/
│   ├── test_unit_core.py           # Core telemetry & extraction unit tests
│   ├── test_unit_ml.py             # Machine learning pipeline unit tests
│   ├── test_unit_response.py       # Process termination & SQLite unit tests
│   ├── test_unit_reporting.py      # PDF ReportLab generation unit tests
│   ├── benchmark_pipeline.py       # Performance & throughput benchmarks
│   └── test_integration_phase1_5.py# Manual telemetry integration demo
│
├── logs/                           # Runtime log storage
└── test_environment/               # Isolated sandbox directory for simulated bursts
```

---

## How to Run the Application

### 1. Launch Primary Desktop Dashboard GUI (Recommended)
```bash
python3 app.py
```
*or:*
```bash
python3 app.py --gui
```

### 2. Launch Background System Tray / Menu Bar Shield
```bash
python3 app.py --tray
```

### 3. Run Interactive Threat Demonstration (User Test)
```bash
python3 app.py --test-threat
```

### 4. Run All 22 Automated Unit Tests
```bash
python3 -m unittest discover tests
```

### 5. Run Performance Benchmarks
```bash
python3 app.py --benchmark
```
