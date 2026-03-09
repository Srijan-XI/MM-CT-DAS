# Tech Stack for Windows

## 1. Programming Languages

- **Python (primary)** → ML, packet parsing, orchestration
- **Go (optional)** → lightweight services, parallel processing
- **PowerShell** → integration with Windows security APIs (firewall, processes)

## 2. Cybersecurity Libraries & Tools

- **PyShark** → packet analysis (uses Wireshark/tshark backend)
- **Scapy (Windows-compatible)** → packet sniffing & crafting
- **YARA** → rule-based malware detection
- **WinDivert (via pydivert)** → capture & filter Windows network traffic at packet level
- **Windows Event Logs (via pywin32)** → monitor system logs for anomalies

## 3. Machine Learning

- **Scikit-Learn** → lightweight ML models
- **PyTorch (CPU mode)** → deep learning support
- **ONNX Runtime** → optimized model execution on CPU

## 4. Data Storage

- **SQLite** → lightweight threat log storage
- **JSON/CSV** → training/testing datasets

## 5. System Integration & Dashboard

- **FastAPI** → backend API for detection system
- **Dash** → visualization dashboard (alerts, logs, graphs)
- **PowerShell scripts** → enforce firewall rules, terminate malicious processes

## 6. Threat Detection & Response

- **Windows Firewall API** (via PowerShell/PyWin32) → auto-block malicious IPs
- **Process Monitoring** (via WMI + Python) → kill suspicious processes
- **Task Scheduler** → keep monitoring service running in background

## 🔹 Deployment Setup on Windows

### Prerequisites

1. **Install Python (3.10+)** → via [python.org](https://python.org) or Anaconda
2. **Install Wireshark** → required for PyShark (tshark must be on PATH)
3. **Set up WinDivert driver** → for packet interception

### Installation Steps

1. **Create virtual environment** (recommended):
   ```powershell
   python -m venv cybersec-env
   cybersec-env\Scripts\Activate.ps1
   ```

2. **Install dependencies**:
   ```powershell
   pip install scapy pyshark pydivert yara-python scikit-learn streamlit flask pywin32 onnxruntime
   ```

3. **Run the service** → background monitoring + dashboard