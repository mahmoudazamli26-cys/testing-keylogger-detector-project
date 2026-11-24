# 🛡️ Keylogger Detection & Behavioral Simulation Framework

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)
![Security](https://img.shields.io/badge/Focus-Endpoint%20Security%20%26%20Detection-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

An end-to-end cybersecurity research and endpoint detection framework designed to simulate keystroke-logging behaviors and validate real-time behavioral detection mechanisms on Windows environments.

> ⚠️ **Ethical & Educational Disclaimer:** This repository is strictly intended for authorized security testing, malware analysis research, and defensive endpoint engineering within isolated lab environments. Do not deploy or execute any simulation binaries on unauthorized systems.

---

## 📂 Repository Architecture

The project is organized into two primary modules covering offensive simulation and defensive detection:

    testing-keylogger-detector/
    ├── key-logger/key-logger/                     # Controlled Simulation & C2 Dashboard Module
    │   ├── detector-test.py                       # Lightweight keystroke simulation script
    │   └── totally safe/                          # Full simulation suite & local web interface
    │       ├── app.py                             # Flask-based monitoring & log dashboard backend
    │       ├── key-logger.py / key-loggern.pyw    # Foreground & background keystroke capture agents
    │       ├── setup-key-logger.bat               # Environment initialization script
    │       ├── templates/ & static/               # Web UI templates (Dashboard, Disclaimer, Error views)
    │       └── requirements.txt                   # Module dependencies
    │
    └── testing-keylogger-detector--main (9)/      # Behavioral Detection & Alerting Engine
        └── testing-keylogger-detector--main/
            ├── keylogger_detector.py              # Core heuristic & behavioral detection engine
            ├── test_detector.py                   # Automated validation & test suite for detector rules
            └── keylogger_alerts.jsonl             # Structured JSONL telemetry & alert output log

---

## ✨ Key Components & Features

### 1. Behavioral Detection Engine (`keylogger_detector.py`)
* **Real-Time Endpoint Telemetry:** Monitors active processes, suspicious API hooks, and anomalous file I/O patterns characteristic of keystroke loggers.
* **Structured Alert Logging:** Exports high-fidelity detection events directly to `keylogger_alerts.jsonl` in JSON Lines format for seamless SIEM ingestion and forensic auditing.
* **Automated Validation (`test_detector.py`):** Provides unit and integration test cases to benchmark detection accuracy and minimize false positives.

### 2. Controlled Simulation Suite (`key-logger/`)
* **Multi-Mode Execution:** Includes both console (`key-logger.py`) and windowless background (`key-loggern.pyw`) test agents alongside standalone PyInstaller build configurations (`*.spec`) to test binary vs. script detection.
* **Local Analysis Dashboard (`app.py`):** A lightweight Flask web interface (`templates/dashboard.html`) for visualizing captured test telemetry during controlled lab exercises.

---

## 🚀 Getting Started

### Prerequisites
* **Operating System:** Windows 10 / 11
* **Runtime:** Python 3.10+ (Tested on Python 3.13)

### Installation

1. **Clone the repository:**
   
       git clone https://github.com/mahmoudazamli26-cys/testing-keylogger-detector-v2.git
       cd testing-keylogger-detector-v2

2. **Install dependencies for the simulation module:**

       pip install -r "key-logger/key-logger/totally safe/requirements.txt"

---

## 💻 Usage Workflow (Lab Environment)

### Step 1: Start the Detection Engine
Launch the behavioral detector in an elevated terminal to monitor system activity:

    python "testing-keylogger-detector--main (9)/testing-keylogger-detector--main/keylogger_detector.py"

### Step 2: Run Automated Detector Verification
Verify that the detection rules trigger properly against baseline test cases:

    python "testing-keylogger-detector--main (9)/testing-keylogger-detector--main/test_detector.py"

### Step 3: Execute Controlled Simulation (Optional)
Run the lightweight test script or launch the local web dashboard to observe real-time alert generation in `keylogger_alerts.jsonl`:

    # Run lightweight simulation
    python "key-logger/key-logger/detector-test.py"

    # Or start the local web dashboard
    python "key-logger/key-logger/totally safe/app.py"

---

## 📊 Alert Telemetry Format

Detected anomalies are appended to `keylogger_alerts.jsonl` as structured JSON objects, enabling straightforward parsing and incident triage:

    {
      "timestamp": "2026-11-24T19:00:00Z",
      "severity": "HIGH",
      "process_name": "python.exe",
      "indicator": "Suspicious keyboard hook / rapid log file append detected",
      "status": "ALERT_TRIGGERED"
    }

---

## 📜 License

This project is licensed under the terms specified in the `License` file included in the repository.
