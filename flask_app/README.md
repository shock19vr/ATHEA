# Flask XAI EVTX Anomaly Detection

A modern Flask web application for XAI-powered security log anomaly detection with one-click pipeline execution.

## Features

- 🚀 **One-Click Pipeline**: Complete analysis with a single button click
- 📤 **Drag & Drop Upload**: Easy file upload with drag-and-drop support
- ⚙️ **Real-time Progress**: Live progress tracking during analysis
- 📊 **Interactive Results**: Beautiful visualizations and statistics
- 🔬 **XAI Explanations**: SHAP-based feature importance and individual explanations
- 🤖 **Gemini AI Integration**: Optional AI-powered threat analysis
- 💾 **Export Results**: Download complete analysis as CSV
- 🔄 **Session Management**: No auto-reload, manual control with "Start New" button

## Directory Structure

```
flask_app/
├── app.py                      # Main Flask application
├── templates/
│   └── index.html             # Main UI template
├── static/
│   └── app.js                 # Frontend JavaScript
├── uploads/                   # Uploaded log files
├── results/                   # Analysis results
├── requirements_flask.txt     # Python dependencies
└── README.md                  # This file
```

## Installation

### 1. Install Dependencies

```bash
cd flask_app
pip install -r requirements_flask.txt
```

### 2. Set Environment Variables (Optional)

Copy the example file and add your API key:

```bash
cp .env.example .env
```

Then edit `.env` and add your Gemini API key:

```
GEMINI_API_KEY=your_gemini_api_key_here
```

Get your API key from: https://makersuite.google.com/app/apikey

## Usage

### 1. Start the Flask Server

```bash
python app.py
```

The server will start on `http://localhost:5000`

### 2. Access the Web Interface

Open your browser and navigate to:
```
http://localhost:5000
```

### 3. Run Analysis

1. **Upload Files**: Drag and drop or click to upload EVTX, CSV, JSON, LOG, or TXT files
2. **Configure Settings**:
   - Detection Algorithm (Isolation Forest, LOF, or Ensemble)
   - Contamination rate (0.01 - 0.5)
   - Gemini API Key (optional, for AI analysis)
3. **Click "Run Complete Analysis"**: The entire pipeline executes automatically
4. **View Results**: Explore statistics, anomalies, and XAI explanations
5. **Download Results**: Export analysis as CSV
6. **Start New**: Click to reset and begin a new analysis

## Pipeline Stages

The one-click pipeline executes these stages automatically:

1. **Parsing** (10-25%): Parse uploaded log files
2. **Feature Engineering** (25-50%): Extract ML features
3. **Anomaly Detection** (50-75%): Run ML model
4. **XAI Computation** (75-95%): Compute SHAP values
5. **Saving Results** (95-100%): Save and display results

## API Endpoints

### File Upload
```
POST /api/upload
```

### Run Pipeline
```
POST /api/run_pipeline
Body: {
    "algorithm": "isolation_forest",
    "contamination": 0.1,
    "gemini_api_key": "optional_key"
}
```

### Get Status
```
GET /api/status
```

### Get Results
```
GET /api/results
```

### XAI Feature Importance
```
GET /api/xai/feature_importance
```

### XAI Explain Anomaly
```
GET /api/xai/explain/<index>
```

### Download Results
```
GET /api/download/results
```

### Reset Pipeline
```
POST /api/reset
```

## Key Differences from Streamlit Version

1. **No Auto-Reload**: Application state persists until user clicks "Start New"
2. **One-Click Execution**: Entire pipeline runs with single button click
3. **Session Management**: Each user session is isolated
4. **REST API**: Full API for programmatic access
5. **Modern UI**: Gradient design with smooth animations
6. **Progress Tracking**: Real-time progress bar with status messages

## Configuration

### Supported File Formats
- EVTX (Windows Event Logs)
- CSV (Comma-separated values)
- JSON (JavaScript Object Notation)
- LOG (Generic log files)
- TXT (Text files)

### Detection Algorithms
- **Isolation Forest**: Fast, efficient for high-dimensional data
- **Local Outlier Factor (LOF)**: Density-based anomaly detection
- **Ensemble**: Combines multiple algorithms

### Contamination
- Range: 0.01 to 0.5
- Default: 0.1 (10% expected anomalies)
- Auto-adjusts for small datasets

## Troubleshooting

### Port Already in Use
Change the port in `app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=5001)
```

### File Upload Fails
Check file size limit in `app.py`:
```python
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
```

### XAI Computation Slow
Reduce background samples in `app.py`:
```python
explainer.compute_shap_values(features_df, background_samples=50)
```

## Security Notes

- Files are stored in session-specific directories
- API key is never logged or stored permanently
- Session data is cleared on reset
- Use HTTPS in production

## Production Deployment

For production use:

1. **Use a production WSGI server**:
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

2. **Set up reverse proxy** (nginx/Apache)

3. **Enable HTTPS**

4. **Set secure secret key** in environment variables

5. **Configure file upload limits** based on your needs

## License

Same as parent project

## Support

For issues or questions, refer to the main project documentation.
