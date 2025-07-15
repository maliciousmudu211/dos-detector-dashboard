# DoS Detector Dashboard

A machine learning–based network anomaly detection system that monitors live network traffic and flags possible Denial of Service (DoS) attacks (e.g., SlowHTTPTest).

---

##Project Overview

This project uses a trained Random Forest model to classify live captured network flows. It extracts features from packets on the fly, makes predictions, and visualizes the results using an interactive Streamlit dashboard.

---

##Main Components

###Feature Extraction
- Uses `pyshark` to capture live packets from a network interface (e.g., `wlo1`).
- Extracts features such as packet length, inter-arrival time, protocol, etc.
- Saves live flows in `live_flows_features.csv`.

###ML Model
- Trained Random Forest model (`cicids_rf_model.joblib`) to classify normal and attack traffic.
- Supports incremental learning through feedback.

###Live Prediction
- Files: `live_feature_extractor.py` and `live_predictor_combined.py`.
- Captures packets and predicts in near real-time.

###Streamlit Dashboard
- File: `dashboard.py`.
- Displays live prediction results and threat summary in a web interface.

---

##Setup & Run

###Clone and install

```bash
git clone https://github.com/maliciousmudu211/dos-detector-dashboard.git
cd dos-detector-dashboard
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt

Start live capture and prediction

sudo python3 live_predictor_combined.py

This starts live feature extraction and writes predictions to live_predictions.csv.
Run the Streamlit dashboard

In a new terminal (inside your virtual environment):

streamlit run dashboard.py

Then visit http://localhost:8501 to view the dashboard.
Safe DoS Testing

    You can simulate DoS traffic safely on your own test network using tools like SlowHTTPTest or hping3.

    Only do this in controlled environments to avoid affecting other users or breaking terms of service.

Files in This Repository

    live_feature_extractor.py: Live capture and feature extraction logic.

    live_predictor_combined.py: Combines live capture and prediction.

    dashboard.py: Streamlit app for live monitoring.

    train_model.py: Training logic for Random Forest model.

    cicids_rf_model.joblib: Pre-trained model (large file tracked via LFS).

    feature_columns.joblib, label_encoder.joblib: Model support files.

    cicids_small.csv: Example dataset sample.

    templates/index.html: Extra template file.

    project_backup/: Backup data and large datasets.

Acknowledgements

    CICIDS2017 dataset from Canadian Institute for Cybersecurity.

    Scapy, PyShark, Streamlit, and other open-source tools.


Contact

If you'd like help or have questions, feel free to open an issue or reach out!
