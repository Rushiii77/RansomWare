# Contributing to AI-Based Ransomware Detection & Defense System

Thank you for your interest in contributing to this defensive cybersecurity project!

## 📌 Engineering Guidelines

1. **Safety First**: Never commit code that introduces destructive payloads or interacts with file paths outside `test_environment/`.
2. **Telemetry Decoupling**: Keep observation (Process/File monitors), inference (Machine Learning models), and reaction (Process Terminator) strictly decoupled into their respective packages.
3. **Thread Safety**: Ensure all background loops in `monitoring/` and `ml/` emit thread-safe signals and do not block the PySide6 Qt GUI event loop.
4. **Testing**: All pull requests must include unit tests in `tests/` and maintain a 100% test passing rate.

## 🚀 Development Workflow

1. Fork the repository and create your branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Set up virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Or venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```
3. Run the automated test suite:
   ```bash
   python3 -m unittest discover tests
   ```
4. Commit your changes and open a Pull Request.
