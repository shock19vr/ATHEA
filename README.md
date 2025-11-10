# XAI EVTX Anomaly Detection System

Explainable AI-based APT (Advanced Persistent Threat) detection system for Windows Event Logs (EVTX) with dual UI interfaces - Streamlit and Flask.

## Overview

This system uses unsupervised machine learning combined with explainable AI (XAI) to detect anomalous security events in Windows logs. It provides intelligent threat analysis using SHAP explanations and Google Gemini AI, with MITRE ATT&CK framework mapping for attack pattern classification.

## Features

### Core Capabilities
- **Multi-format Log Parsing**: EVTX, CSV, JSON, and generic log file support
- **Unsupervised Anomaly Detection**: Isolation Forest, Local Outlier Factor (LOF), and Ensemble methods
- **Explainable AI**: SHAP-based explanations for model decisions
- **GenAI Analysis**: Google Gemini 2.5 Flash integration for strategic threat assessment
- **MITRE ATT&CK Mapping**: Automatic classification of anomalies to attack stages
- **Clustering**: HDBSCAN-based anomaly clustering for pattern identification
- **SQLite Database**: Centralized storage for event references and MITRE TTPs

### Event Intelligence
- **Security Events**: Windows Security log EventID mappings with risk scores
- **Sysmon Events**: Sysmon operational log analysis
- **System Events**: Windows System log monitoring
- **SQL Server Events**: SQL Server audit log support
- **MITRE TTPs**: Complete MITRE ATT&CK tactics and techniques database

### Dual UI Options

#### 1. Streamlit App (Main Interface)
Full-featured interactive dashboard with:
- Multi-page navigation (Upload, Detection, Visualization, Explainability, Export, Database)
- Real-time anomaly detection with adaptive contamination
- Interactive visualizations (Plotly charts)
- SHAP-based XAI explanations
- Gemini AI strategic analysis
- APT stage breakdown with expandable details
- Database viewer and statistics

#### 2. Flask App (Simplified UI)
One-click pipeline execution with:
- Single-page modern UI
- Automatic pipeline execution (Parse → Feature Engineering → Detection → Clustering → XAI)
- Real-time progress tracking
- Results dashboard with top anomalies
- XAI feature importance visualization
- CSV export functionality

## Architecture

### Pipeline Flow
```
Log Files → Parser → Feature Engineering → Anomaly Detection → Clustering → MITRE Mapping → XAI Explanation → Results
```

### Core Modules

- **`parser.py`**: Multi-format log parser (EVTX, CSV, JSON, generic logs)
- **`features.py`**: Feature engineering (temporal, categorical, frequency, security features)
- **`model.py`**: Anomaly detection models with adaptive contamination
- **`explain.py`**: SHAP-based explainability and Gemini AI integration
- **`ui_helpers.py`**: Visualization utilities for Streamlit
- **`db_manager.py`**: SQLite database manager for reference data
- **`eventid_mapper.py`**: EventID correlation engine with risk scoring
- **`genai_analyzer.py`**: Google Gemini AI analyzer for threat intelligence

### Reference Data Modules

- **`eventid_reference_security.py`**: Windows Security EventID database
- **`eventid_reference_sysmon.py`**: Sysmon EventID database
- **`eventid_reference_system.py`**: Windows System EventID database
- **`eventid_reference_sql.py`**: SQL Server EventID database
- **`mitre_ttps_reference.py`**: MITRE ATT&CK tactics and techniques

### Database

- **`init_database.py`**: Database initialization script
- **`event_references.db`**: SQLite database containing all reference data

## Installation

### Prerequisites
- Python 3.8+
- Windows (for EVTX parsing) or any OS (for CSV/JSON)

### Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd XAI_evtx_anomoly-detection
```

2. **Install dependencies**

For Streamlit app:
```bash
pip install -r requirements.txt
```

For Flask app:
```bash
cd flask_app
pip install -r requirements_flask.txt
```

3. **Initialize the database**
```bash
python init_database.py
```

4. **Configure Gemini API (Optional)**

Create a `.env` file in the root directory:
```
GEMINI_API_KEY=your_api_key_here
```

Get your API key from: https://makersuite.google.com/app/apikey

## Usage

### Streamlit App

```bash
streamlit run app.py
```

Navigate through the pages:
1. **Upload & Parse**: Upload EVTX/CSV/JSON files and parse events
2. **Anomaly Detection**: Run detection with configurable algorithms
3. **Visualization**: View interactive charts and APT stage breakdowns
4. **Explainability**: SHAP explanations and Gemini AI analysis
5. **Export Results**: Download results as CSV
6. **Database**: View reference data statistics

### Flask App

```bash
cd flask_app
python app.py
```

Access at: http://localhost:5000

1. Upload log files
2. Configure detection parameters (optional)
3. Click "Run Analysis"
4. View results and download CSV

## Configuration

### Detection Parameters

- **Algorithm**: `isolation_forest`, `lof`, or `ensemble`
- **Contamination**: Expected anomaly proportion (0.01 - 0.5)
- **Auto Contamination**: Adaptive contamination for small datasets (enabled by default)

### Clustering Parameters

- **Min Cluster Size**: Minimum events per cluster (default: 5)
- **Adaptive Mode**: Auto-adjust for dataset size (enabled by default)
- **Direct Classification Threshold**: Minimum anomalies for clustering (default: 10)

## Machine Learning Features

The system extracts 50+ features including:

### Temporal Features
- Hour of day, day of week, month
- Time since previous event
- Event rate per hour/day

### Categorical Features
- EventID encoding with risk scores
- Level (severity) encoding
- Channel encoding
- Computer/User frequency encoding

### Security Features
- Failed login patterns
- Privilege escalation indicators
- Lateral movement detection
- Persistence mechanism identification
- Defense evasion patterns

### Frequency Features
- EventID frequency per computer
- User activity patterns
- Rare event detection

## MITRE ATT&CK Mapping

Anomalies are automatically mapped to MITRE ATT&CK stages:

- **Stage 1**: Initial Access
- **Stage 2**: Execution, Credential Access
- **Stage 3**: Persistence, Privilege Escalation, Defense Evasion
- **Stage 4**: Discovery, Lateral Movement
- **Stage 5**: Collection, Command & Control
- **Stage 6**: Exfiltration
- **Stage 7**: Impact

## Explainability

### SHAP (SHapley Additive exPlanations)
- Global feature importance across all anomalies
- Individual anomaly explanations
- Feature contribution analysis
- Waterfall visualizations

### Gemini AI Analysis
- Strategic threat assessment
- Attack pattern identification
- Contextual recommendations
- Natural language explanations

## Database Schema

### Tables

- **`security_events`**: Windows Security EventID reference
- **`sysmon_events`**: Sysmon EventID reference
- **`system_events`**: Windows System EventID reference
- **`sql_events`**: SQL Server EventID reference
- **`mitre_tactics`**: MITRE ATT&CK tactics
- **`mitre_techniques`**: MITRE ATT&CK techniques
- **`analysis_results`**: Stored analysis results per session

## Output

### Results DataFrame Columns

- **Original Event Data**: EventRecordID, TimeCreatedISO, EventID, Level, Computer, User, Channel, EventData
- **Enriched Data**: EventID_Name, EventID_RiskScore, EventID_Category, MITRE_Tactics, MITRE_Techniques
- **ML Features**: 50+ engineered features
- **Detection Results**: Anomaly (0/1), AnomalyScore, AnomalyScoreNormalized
- **Clustering**: Cluster, ClusterLabel, MITRE_Stage, Confidence

### Export Formats

- **CSV**: Full results with all columns
- **XAI Report**: SHAP explanations for top anomalies

## Performance

- **Parsing**: ~1000 events/second (EVTX)
- **Feature Engineering**: ~5000 events/second
- **Detection**: ~10000 events/second
- **SHAP Computation**: ~100 samples/second

## Limitations

- EVTX parsing requires `python-evtx` library (Windows-optimized)
- SHAP computation can be slow for large datasets (>10000 events)
- Gemini AI requires API key and internet connection
- Unsupervised learning may produce false positives on novel benign patterns

## Troubleshooting

### Database Not Found
```bash
python init_database.py
```

### EVTX Parsing Errors
Ensure `python-evtx` is installed:
```bash
pip install python-evtx
```

### Gemini API Errors
- Verify API key in `.env` file
- Check internet connection
- Ensure API quota is not exceeded

### Memory Issues
- Reduce dataset size
- Use smaller background samples for SHAP (default: 100)
- Disable SHAP for very large datasets

## Dependencies

### Core
- streamlit>=1.28.0
- pandas>=2.0.0
- numpy>=1.24.0

### Machine Learning
- scikit-learn>=1.3.0 (includes HDBSCAN)

### Explainable AI
- shap>=0.42.0
- google-generativeai>=0.3.0

### Visualization
- plotly>=5.17.0

### Log Parsing
- python-evtx>=0.8.1
- lxml>=4.9.0

### Utilities
- joblib>=1.3.0
- tqdm>=4.66.0
- python-dotenv>=1.0.0

### Flask App (Additional)
- Flask>=3.0.0
- Werkzeug>=3.0.0

## Project Structure

```
XAI_evtx_anomoly-detection/
├── app.py                          # Streamlit main application
├── parser.py                       # Log parser module
├── features.py                     # Feature engineering module
├── model.py                        # Anomaly detection models
├── explain.py                      # XAI explainability module
├── ui_helpers.py                   # Streamlit visualization utilities
├── db_manager.py                   # Database manager
├── eventid_mapper.py               # EventID correlation engine
├── genai_analyzer.py               # Gemini AI analyzer
├── eventid_reference_security.py   # Security EventID database
├── eventid_reference_sysmon.py     # Sysmon EventID database
├── eventid_reference_system.py     # System EventID database
├── eventid_reference_sql.py        # SQL EventID database
├── mitre_ttps_reference.py         # MITRE ATT&CK reference
├── init_database.py                # Database initialization script
├── requirements.txt                # Streamlit app dependencies
├── event_references.db             # SQLite database (generated)
├── .env                            # Environment variables (create this)
└── flask_app/                      # Flask application
    ├── app.py                      # Flask main application
    ├── requirements_flask.txt      # Flask app dependencies
    ├── templates/
    │   └── index.html              # Flask UI template
    ├── static/
    │   └── app.js                  # Flask frontend JavaScript
    └── uploads/                    # Upload directory
```

## License

This project is provided as-is for educational and research purposes.

## Contributing

Contributions are welcome! Please ensure:
- Code follows existing style
- New features include documentation
- Database schema changes are reflected in `init_database.py`
- Both Streamlit and Flask apps remain functional

## Acknowledgments

- MITRE ATT&CK Framework for threat taxonomy
- SHAP library for explainability
- Google Gemini for AI-powered analysis
- python-evtx for EVTX parsing
- Scikit-learn for machine learning algorithms
