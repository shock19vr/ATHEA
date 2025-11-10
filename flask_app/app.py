"""
Flask Application for XAI EVTX Anomaly Detection
One-click pipeline execution with modern UI
Now with SQLite database integration
"""

import os
import sys
import json
import uuid
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, session
from werkzeug.utils import secure_filename
import pandas as pd
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add parent directory to path to import modules
sys.path.append(str(Path(__file__).parent.parent))

from parser import LogParser
from features import FeatureEngineer
from model import AnomalyDetector, AnomalyClusterer
from explain import AnomalyExplainer
from db_manager import get_db_manager

app = Flask(__name__)
app.secret_key = 'xai-evtx-anomaly-detection-secret-key-2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULTS_FOLDER'] = 'results'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size

# Allowed file extensions
ALLOWED_EXTENSIONS = {'evtx', 'csv', 'json', 'log', 'txt'}

# Get database manager instance (database should already exist)
db_path = str(Path(__file__).parent.parent / "event_references.db")
if not Path(db_path).exists():
    print("❌ ERROR: Database not found!")
    print(f"   Expected: {db_path}")
    print("   Please run: python init_database.py")
    print("   Or run the Streamlit app first to initialize the database.")
    sys.exit(1)

print(f"✅ Using database: {db_path}")
db = get_db_manager(db_path)
stats = db.get_statistics()
print(f"📊 Database loaded: {stats['total_events']} events, {stats['mitre_tactics']} tactics, {stats['mitre_techniques']} techniques")

# Global storage for pipeline state
pipeline_state = {}


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_session_id():
    """Get or create session ID"""
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    return session['session_id']


def get_pipeline_state():
    """Get pipeline state for current session"""
    session_id = get_session_id()
    if session_id not in pipeline_state:
        pipeline_state[session_id] = {
            'status': 'idle',
            'progress': 0,
            'message': 'Ready to start',
            'files': [],
            'parsed_data': None,
            'features_df': None,
            'ml_df': None,
            'results_df': None,
            'model': None,
            'explainer': None,
            'feature_cols': [],
            'anomaly_count': 0,
            'total_events': 0,
            'error': None
        }
    return pipeline_state[session_id]


def clear_pipeline_state():
    """Clear pipeline state for current session"""
    session_id = get_session_id()
    if session_id in pipeline_state:
        del pipeline_state[session_id]


def save_results_to_database(results_df: pd.DataFrame, session_id: str):
    """Save analysis results to database"""
    try:
        # Save only anomalies to database
        anomalies = results_df[results_df['Anomaly'] == 1]
        
        for idx, row in anomalies.iterrows():
            result_data = {
                'event_record_id': row.get('EventRecordID'),
                'event_id': row.get('EventID'),
                'computer': row.get('Computer'),
                'timestamp': row.get('TimeCreatedISO'),
                'anomaly': 1,
                'anomaly_score': row.get('AnomalyScoreNormalized', 0.0),
                'cluster_label': row.get('ClusterLabel'),
                'mitre_stage': row.get('MITRE_Stage'),
                'confidence': row.get('Confidence', 0.0)
            }
            db.insert_analysis_result(session_id, result_data)
        
        print(f"💾 Saved {len(anomalies)} anomalies to database (Session: {session_id[:8]}...)")
    except Exception as e:
        print(f"⚠️ Error saving results to database: {e}")


@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')


@app.route('/api/upload', methods=['POST'])
def upload_files():
    """Upload log files"""
    try:
        state = get_pipeline_state()
        
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided'}), 400
        
        files = request.files.getlist('files')
        uploaded_files = []
        
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                uploaded_files.append({
                    'name': filename,
                    'path': filepath,
                    'size': os.path.getsize(filepath)
                })
        
        state['files'] = uploaded_files
        state['status'] = 'files_uploaded'
        state['message'] = f'{len(uploaded_files)} file(s) uploaded successfully'
        
        return jsonify({
            'success': True,
            'files': uploaded_files,
            'message': state['message']
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/run_pipeline', methods=['POST'])
def run_pipeline():
    """Execute the complete pipeline"""
    try:
        state = get_pipeline_state()
        
        if not state['files']:
            return jsonify({'error': 'No files uploaded'}), 400
        
        # Get configuration
        config = request.json or {}
        algorithm = config.get('algorithm', 'isolation_forest')
        contamination = config.get('contamination', 0.1)
        gemini_api_key = config.get('gemini_api_key', os.getenv('GEMINI_API_KEY', ''))
        
        # Step 1: Parse logs
        state['status'] = 'parsing'
        state['progress'] = 10
        state['message'] = 'Parsing log files...'
        
        parser = LogParser()
        all_events = []
        
        for file_info in state['files']:
            filepath = file_info['path']
            if filepath.endswith('.evtx'):
                events = parser.parse_evtx(filepath)
            elif filepath.endswith('.csv'):
                events = parser.parse_csv(filepath)
            elif filepath.endswith('.json'):
                events = parser.parse_json(filepath)
            else:
                events = parser.parse_generic(filepath)
            
            all_events.extend(events)
        
        if not all_events:
            state['error'] = 'No events parsed from files'
            return jsonify({'error': state['error']}), 400
        
        parsed_df = pd.DataFrame(all_events)
        state['parsed_data'] = parsed_df
        state['total_events'] = len(parsed_df)
        state['progress'] = 25
        state['message'] = f'Parsed {len(parsed_df)} events'
        
        # Step 2: Feature Engineering
        state['status'] = 'feature_engineering'
        state['progress'] = 35
        state['message'] = 'Extracting ML features...'
        
        feature_engineer = FeatureEngineer()
        # Convert DataFrame to list of dicts for extract_features
        events_list = parsed_df.to_dict('records')
        features_df = feature_engineer.extract_features(events_list)
        
        # Get ML-ready features
        ml_df, feature_cols = feature_engineer.get_ml_features(features_df)
        
        state['features_df'] = features_df  # Full features with all columns
        state['ml_df'] = ml_df  # ML-ready numeric features only
        state['feature_cols'] = feature_cols
        state['progress'] = 50
        state['message'] = f'Extracted {len(feature_cols)} features'
        
        # Step 3: Anomaly Detection
        state['status'] = 'anomaly_detection'
        state['progress'] = 60
        state['message'] = 'Running anomaly detection...'
        
        detector = AnomalyDetector(
            algorithm=algorithm,
            contamination=contamination,
            auto_contamination=True
        )
        
        # Train and predict using ML-ready features
        metrics = detector.train(ml_df, feature_cols)
        predictions = detector.predict(ml_df, feature_cols)
        
        # Combine results with original features_df (which has all columns)
        results_df = features_df.copy()
        for col in predictions.columns:
            results_df[col] = predictions[col]
        
        state['results_df'] = results_df
        state['model'] = detector
        state['anomaly_count'] = int((results_df['Anomaly'] == 1).sum())
        state['progress'] = 70
        state['message'] = f'Detected {state["anomaly_count"]} anomalies'
        
        # Step 4: Clustering and MITRE Mapping
        if state['anomaly_count'] > 0:
            state['status'] = 'clustering'
            state['progress'] = 75
            state['message'] = 'Analyzing attack patterns...'
            
            anomalies = results_df[results_df['Anomaly'] == 1].copy()
            clusterer = AnomalyClusterer(min_cluster_size=5, adaptive=True, direct_classification_threshold=10)
            cluster_results = clusterer.cluster(anomalies, feature_cols)
            cluster_results = clusterer.map_to_mitre_stages(cluster_results, anomalies)
            
            # Update results_df with cluster information
            cluster_results.index = anomalies.index
            for col in ['Cluster', 'ClusterLabel', 'MITRE_Stage']:
                if col in cluster_results.columns:
                    results_df.loc[anomalies.index, col] = cluster_results[col]
            
            state['results_df'] = results_df
            state['progress'] = 80
            state['message'] = 'Clustering completed'
        
        # Step 5: XAI Explanations
        state['status'] = 'xai_computation'
        state['progress'] = 85
        state['message'] = 'Computing XAI explanations...'
        
        model = detector.model
        if isinstance(model, dict):
            model = model['isolation_forest']
        
        explainer = AnomalyExplainer(
            model,
            detector.scaler,
            feature_cols,
            gemini_api_key=gemini_api_key if gemini_api_key else None
        )
        
        # Compute SHAP on ML features
        explainer.compute_shap_values(ml_df, background_samples=100)
        state['explainer'] = explainer
        state['progress'] = 95
        state['message'] = 'XAI explanations computed'
        
        # Step 6: Save results
        state['status'] = 'saving'
        state['progress'] = 98
        state['message'] = 'Saving results...'
        
        session_id = get_session_id()
        results_path = os.path.join(app.config['RESULTS_FOLDER'], f'{session_id}_results.csv')
        results_df.to_csv(results_path, index=False)
        
        # Save anomalies to database
        save_results_to_database(results_df, session_id)
        
        # Complete
        state['status'] = 'completed'
        state['progress'] = 100
        state['message'] = 'Pipeline completed successfully!'
        
        return jsonify({
            'success': True,
            'total_events': state['total_events'],
            'anomaly_count': state['anomaly_count'],
            'anomaly_percentage': round((state['anomaly_count'] / state['total_events']) * 100, 2),
            'features_count': len(feature_cols),
            'results_file': results_path
        })
    
    except Exception as e:
        state['status'] = 'error'
        state['error'] = str(e)
        state['message'] = f'Error: {str(e)}'
        return jsonify({'error': str(e)}), 500


@app.route('/api/status')
def get_status():
    """Get current pipeline status"""
    state = get_pipeline_state()
    return jsonify({
        'status': state['status'],
        'progress': state['progress'],
        'message': state['message'],
        'total_events': state['total_events'],
        'anomaly_count': state['anomaly_count'],
        'error': state['error']
    })


@app.route('/api/results')
def get_results():
    """Get analysis results"""
    try:
        state = get_pipeline_state()
        
        if state['results_df'] is None:
            return jsonify({'error': 'No results available'}), 400
        
        results_df = state['results_df']
        anomalies = results_df[results_df['Anomaly'] == 1]
        
        # Summary statistics
        summary = {
            'total_events': len(results_df),
            'anomaly_count': len(anomalies),
            'anomaly_percentage': round((len(anomalies) / len(results_df)) * 100, 2),
            'high_risk_count': int((anomalies['AnomalyScoreNormalized'] > 0.8).sum()) if 'AnomalyScoreNormalized' in anomalies.columns else 0,
            'medium_risk_count': int(((anomalies['AnomalyScoreNormalized'] > 0.5) & (anomalies['AnomalyScoreNormalized'] <= 0.8)).sum()) if 'AnomalyScoreNormalized' in anomalies.columns else 0,
            'low_risk_count': int((anomalies['AnomalyScoreNormalized'] <= 0.5).sum()) if 'AnomalyScoreNormalized' in anomalies.columns else 0
        }
        
        # Top anomalies
        top_anomalies = []
        all_anomalies = []
        
        if len(anomalies) > 0:
            top_df = anomalies.nlargest(10, 'AnomalyScoreNormalized') if 'AnomalyScoreNormalized' in anomalies.columns else anomalies.head(10)
            
            for idx, row in top_df.iterrows():
                top_anomalies.append({
                    'index': int(idx),
                    'event_id': int(row.get('EventID', 0)) if pd.notna(row.get('EventID')) else None,
                    'score': float(row.get('AnomalyScoreNormalized', 0)),
                    'timestamp': str(row.get('TimeCreatedISO', 'N/A')),
                    'computer': str(row.get('Computer', 'N/A')),
                    'user': str(row.get('User', 'N/A'))
                })
            
            # All anomalies (limit to 100 for performance)
            all_df = anomalies.nlargest(100, 'AnomalyScoreNormalized') if 'AnomalyScoreNormalized' in anomalies.columns else anomalies.head(100)
            for idx, row in all_df.iterrows():
                all_anomalies.append({
                    'index': int(idx),
                    'event_id': int(row.get('EventID', 0)) if pd.notna(row.get('EventID')) else None,
                    'score': float(row.get('AnomalyScoreNormalized', 0)),
                    'timestamp': str(row.get('TimeCreatedISO', 'N/A')),
                    'computer': str(row.get('Computer', 'N/A')),
                    'user': str(row.get('User', 'N/A'))
                })
        
        return jsonify({
            'summary': summary,
            'top_anomalies': top_anomalies,
            'all_anomalies': all_anomalies
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/visualization/cluster_mitre')
def get_cluster_mitre_data():
    """Get cluster and MITRE stage distribution data for visualizations"""
    try:
        state = get_pipeline_state()
        
        if state['results_df'] is None:
            return jsonify({'error': 'No results available'}), 400
        
        results_df = state['results_df']
        anomalies = results_df[results_df['Anomaly'] == 1]
        
        # Cluster distribution
        cluster_data = {}
        if 'ClusterLabel' in anomalies.columns:
            cluster_counts = anomalies['ClusterLabel'].value_counts().to_dict()
            cluster_data = {str(k): int(v) for k, v in cluster_counts.items()}
        
        # MITRE stage distribution
        mitre_data = {}
        if 'MITRE_Stage' in anomalies.columns:
            mitre_counts = anomalies['MITRE_Stage'].value_counts().to_dict()
            mitre_data = {str(k): int(v) for k, v in mitre_counts.items()}
        
        return jsonify({
            'cluster_distribution': cluster_data,
            'mitre_distribution': mitre_data,
            'has_clusters': bool(cluster_data),
            'has_mitre': bool(mitre_data)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/xai/feature_importance')
def get_feature_importance():
    """Get global feature importance"""
    try:
        state = get_pipeline_state()
        
        if state['explainer'] is None:
            return jsonify({'error': 'XAI not computed'}), 400
        
        importance_df = state['explainer'].get_feature_importance()
        
        return jsonify({
            'features': importance_df['Feature'].tolist(),
            'importance': importance_df['Importance'].tolist()
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/xai/explain/<int:idx>')
def explain_anomaly(idx):
    """Get XAI explanation for specific anomaly"""
    try:
        state = get_pipeline_state()
        
        if state['explainer'] is None or state['ml_df'] is None:
            return jsonify({'error': 'XAI not computed'}), 400
        
        explanation = state['explainer'].explain_sample(
            idx,
            state['ml_df'],
            top_n=10
        )
        
        # Get event details
        event = state['results_df'].loc[idx].to_dict()
        
        # Convert numpy types to native Python types
        for key, value in event.items():
            if pd.isna(value):
                event[key] = None
            elif hasattr(value, 'item'):
                event[key] = value.item()
        
        return jsonify({
            'explanation': explanation,
            'event': event
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/gemini/analysis')
def get_gemini_analysis():
    """Get Gemini AI analysis"""
    try:
        state = get_pipeline_state()
        
        if state['explainer'] is None or state['results_df'] is None:
            return jsonify({'error': 'Analysis not available'}), 400
        
        # Generate global Gemini analysis
        analysis = state['explainer'].generate_global_genai_analysis(state['results_df'])
        
        if 'error' in analysis:
            return jsonify({'error': analysis['error']}), 400
        
        return jsonify(analysis)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/download/results')
def download_results():
    """Download results CSV"""
    try:
        session_id = get_session_id()
        results_path = os.path.join(app.config['RESULTS_FOLDER'], f'{session_id}_results.csv')
        
        if not os.path.exists(results_path):
            return jsonify({'error': 'Results file not found'}), 404
        
        return send_file(
            results_path,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'anomaly_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reset', methods=['POST'])
def reset_pipeline():
    """Reset pipeline and start new analysis"""
    try:
        clear_pipeline_state()
        return jsonify({'success': True, 'message': 'Pipeline reset successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Create directories if they don't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
