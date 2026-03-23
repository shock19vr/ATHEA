# 🛡️ ATHEA: Automated Threat Hunting using Explainable AI

**ATHEA** (XAI EVTX Anomaly Detection) is a cutting-edge security tool designed to detect, analyze, and explain anomalies in Windows Event Logs (EVTX) and other security log formats. By combining unsupervised machine learning with Explainable AI (SHAP) and Generative AI (Google Gemini), ATHEA provides security analysts with deep insights into potential threats, reducing false positives and accelerating incident response.

The system features a comprehensive **Streamlit** dashboard for interactive analysis and a lightweight **Flask** web application for pipeline automation.

---

## 🌟 Key Features

### 🔍 Advanced Anomaly Detection
- **Multi-Algorithm Support**: utilized **Isolation Forest**, **Local Outlier Factor (LOF)**, and an **Ensemble** method to identify outliers.
- **Adaptive Contamination**: Automatically adjusts sensitivity based on dataset size for optimal performance on both small and large log files.
- **EventID Context Filtering**: Reduces false positives by correlating rare EventIDs with other suspicious indicators (e.g., night-time activity, failed logins).

### 💡 Explainable AI (XAI)
- **SHAP Integration**: Uses **SHapley Additive exPlanations** to provide local and global feature importance. deeply understanding *why* a specific event was flagged.
- **GenAI Threat Analysis**: Integrated **Google Gemini AI** to generate natural language narratives, threat assessments, and strategic recommendations for flagged anomalies.
- **Mitre ATT&CK Mapping**: Automatically maps detected anomalies to MITRE ATT&CK stages (e.g., Execution, Persistence, Privilege Escalation).

### 📊 Interactive Visualization
- **Dynamic Dashboards**: Built with **Plotly** and **Streamlit** for interactive exploration of anomaly scores, timelines, and cluster distributions.
- **Timeline Analysis**: Visualizes event sequences to identify patterns and temporal correlations.
- **Cluster Interpretation**: Groups similar anomalies using **HDBSCAN** and generates human-readable cluster labels.

### 🛠️ Robust Parsing & Data Handling
- **Multi-Format Support**: Parses **.evtx**, **.csv**, **.json**, **.log**, and **.txt** files.
- **Reference Database**: Includes a built-in SQLite database (`event_references.db`) containing extensive knowledge on Event IDs (Security, System, Sysmon, SQL Server) and MITRE TTPs.

---

## 🏗️ Architecture

The project is structured around key modules ensuring modularity and extensibility:

- **`app.py`**: Main Streamlit application entry point.
- **`parser.py`**: Unified log parser supporting multiple backends (`python-evtx`, `evtx`).
- **`features.py`**: Feature engineering engine extracting temporal, frequency, and categorical features.
- **`model.py`**: Implements `AnomalyDetector` (ML models) and `AnomalyClusterer` (HDBSCAN).
- **`explain.py`**: Handles SHAP computations and GenAI interactions via `gemini_analyzer.py`.
- **`db_manager.py`**: Manages the SQLite reference database for context enrichment.
- **`flask_app/`**: Alternative Flask-based web interface for simplified workflows.

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+
- [Git](https://git-scm.com/)

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/XAI_evtx_anomoly-detection.git
cd XAI_evtx_anomoly-detection
```

### 2. Create a Virtual Environment (Recommended)
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Initialize the Database
Before running the application, initialize the local reference database:
```bash
python init_database.py
```
*This creates `event_references.db` and populates it with Security, Sysmon, and MITRE definitions.*

### 5. Configure Environment Variables
Create a `.env` file in the root directory and add your Google Gemini API key for GenAI features:
```env
GEMINI_API_KEY=your_actual_api_key_here
```
*> Get your API key from [Google AI Studio](https://makersuite.google.com/app/apikey)*

---

## 🖥️ Usage

### Running the Streamlit Dashboard (Recommended)
The Streamlit interface offers the full feature set including interactive visualizations and detailed granular analysis.

```bash
streamlit run app.py
```
Access the dashboard at `http://localhost:8501`.

**Workflow:**
1. **Upload**: Go to **📤 Upload & Parse** and drop your log files (EVTX, CSV, etc.).
2. **Extract**: Click **Extract Features** to process raw logs into ML-ready vectors.
3. **Detect**: Navigate to **🔍 Anomaly Detection**, select an algorithm (e.g., Isolation Forest), and run detection.
4. **Visualize**: Use **📊 Visualization** to explore anomaly distributions and timelines.
5. **Explain**: Visit **💡 Explainability** to see SHAP plots and GenAI threat reports.
6. **Export**: Download results via **📥 Export Results**.

### Running the Flask App
For a simplified, one-click analysis pipeline:

```bash
cd flask_app
pip install -r requirements_flask.txt
python app.py
```
Access the web app at `http://localhost:5000`.

---

## 📂 Project Structure

```text
XAI_evtx_anomoly-detection/
├── app.py                      # Streamlit Dashboard (Main Entry)
├── parser.py                   # Log Parsing Logic
├── features.py                 # Feature Engineering
├── model.py                    # Anomaly Detection & Clustering Models
├── explain.py                  # XAI (SHAP) & GenAI Logic
├── genai_analyzer.py           # Gemini AI Integration
├── db_manager.py               # Database Interaction
├── init_database.py            # Database Initialization Script
├── event_references.db         # SQLite Reference Database (Generated)
├── requirements.txt            # Project Dependencies
├── flask_app/                  # Alternative Flask Web App
│   ├── app.py                  # Flask Backend
│   └── templates/              # HTML Templates
├── data/                       # Reference Data Modules
│   ├── eventid_reference_*.py  # Event ID Definitions
│   └── mitre_ttps_reference.py # MITRE ATT&CK Definitions
└── README.md                   # Project Documentation
```

---

## ⚙️ Configuration Hints

- **Processing Large Files**: For very large EVTX files (>500MB), the system automatically uses adaptive contamination. If you face memory issues, consider splitting files or converting to CSV externally using `evtx_to_csv_converter.py` (if available in your tools).
- **Model Tuning**:
    - **Contamination**: Adjust the slider in the Sidebar. Lower values (0.01-0.05) decrease false positives; higher values (0.1+) catch more subtle anomalies but may increase noise.
    - **Algorithms**: `Isolation Forest` is generally fastest. `Ensemble` provides the most robust results but takes longer.

---

## 🤝 Acknowledgements

- **MITRE ATT&CK®**: Tactics and Techniques used for threat classification.
- **Microsoft Guidelines**: Event ID verification and security auditing categories.
- **SHAP (SHapley Additive exPlanations)**: For model interpretability.

---

## 📄 License

[MIT License](LICENSE)
