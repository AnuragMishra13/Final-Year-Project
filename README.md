# Network Security Monitor: Real-time DDoS & Intrusion Detection

## Overview
This project is a real-time network security monitoring system that detects Distributed Denial of Service (DDoS) attacks and various intrusion attempts using machine learning models. It features a modern web dashboard for live monitoring, detailed event logs, and visualizations of detection results.

## Features
- **Real-time DDoS Detection** using CatBoost models
- **Intrusion Detection System (IDS)** for multiple attack types
- **Live Dashboard** with status indicators and event logs
- **Health Checks** for backend services
- **Interactive Controls** to start/stop monitoring
- **Detailed Metrics & Visualizations** (see `doc/` folder)

## Project Structure
```
Packet Capture API.py        # Captures network packets and extracts features
Prediction API.py           # Serves ML models for DDoS/IDS predictions
Server.py                   # Web server and real-time communication
Design/                     # Frontend (HTML, CSS, JS)
doc/                        # Metrics, reports, and images
Models/                     # Pre-trained model files
requirements.txt            # Python dependencies
README.md                   # Project documentation
```

## Installation
1. **Clone the repository**
2. **Install dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```
3. **Run the backend services** (in separate terminals):
   ```powershell
   python Packet Capture API.py
   python Prediction API.py
   python Server.py
   ```
4. **Open the dashboard**:
   - Open `Design/index.html` in your browser, or
   - Access via the Flask server (default: http://127.0.0.1:5000)

## Usage
- Click **Start Monitoring** to begin real-time detection.
- View DDoS and IDS status, event logs, and alerts on the dashboard.
- Use keyboard shortcuts:
  - `Ctrl+Shift+S` — Start monitoring
  - `Ctrl+Shift+T` — Stop monitoring
  - `Ctrl+Shift+C` — Clear event log

## Model Metrics
### DDoS Detection
- **Accuracy:** 0.8715
- **Precision:** 0.8752
- **Recall:** 0.8709
- **F1 Score:** 0.8712
- **ROC AUC:** 0.9917

![DDoS Confusion Matrix](doc/DDoS_confusion_matrix.png)
![DDoS Feature Importances](doc/DDoS_feature_importances.png)

See [DDoS_classification_report.txt](doc/DDoS_classification_report.txt) and [DDoS_feature_importance_list.csv](doc/DDoS_feature_importance_list.csv) for details.

### IDS Detection
- **Accuracy:** 0.9891
- **Precision:** 0.9891
- **Recall:** 0.9892
- **F1 Score:** 0.9891
- **ROC AUC:** 0.9997

![IDS Confusion Matrix](doc/IDS_confusion_matrix.png)
![IDS Feature Importances](doc/IDS_feature_importances.png)

See [IDS_classification_report.txt](doc/IDS_classification_report.txt) and [IDS_feature_importance_list.csv](doc/IDS_feature_importance_list.csv) for details.

## Documentation
- All metrics, reports, and images are in the `doc/` folder.
- Model files are in `Models/`.
- Frontend assets are in `Design/`.

## Requirements
See [requirements.txt](requirements.txt) for all dependencies.

## License
This project is for academic/research purposes.
