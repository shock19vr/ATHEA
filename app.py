"""
Explainable Log Anomaly Detection System
XAI-based APT Detector with Streamlit UI
"""

import streamlit as st
import pandas as pd
import os
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from parser import LogParser
from features import FeatureEngineer
from model import AnomalyDetector, AnomalyClusterer
from explain import AnomalyExplainer
from ui_helpers import Visualizer

# Page configuration
st.set_page_config(
    page_title="XAI Log Anomaly Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .main-header {font-size: 2.5rem; font-weight: bold; color: #2c3e50; text-align: center; margin-bottom: 1rem;}
    .sub-header {font-size: 1.2rem; color: #7f8c8d; text-align: center; margin-bottom: 2rem;}
    </style>
""", unsafe_allow_html=True)

# Initialize session state
for key in ['parsed_data', 'features_df', 'results_df', 'model', 'explainer', 'feature_cols', 'training_metrics', 'gemini_api_key']:
    if key not in st.session_state:
        if key == 'feature_cols':
            st.session_state[key] = []
        elif key == 'training_metrics':
            st.session_state[key] = {}
        elif key == 'gemini_api_key':
            # Load from environment variable if available
            st.session_state[key] = os.getenv('GEMINI_API_KEY', '')
        else:
            st.session_state[key] = None

def main():
    st.markdown('<div class="main-header">🛡️ Explainable Log Anomaly Detection System</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">XAI-based APT Detector for Security Logs</div>', unsafe_allow_html=True)
    
    with st.sidebar:
        st.title("Navigation")
        page = st.radio("Go to", ["📤 Upload & Parse", "🔍 Anomaly Detection", "📊 Visualization", "💡 Explainability", "📥 Export Results"])
        
        st.markdown("---")
        st.markdown("### Settings")
        st.session_state.algorithm = st.selectbox("Detection Algorithm", ["isolation_forest", "lof", "ensemble"], index=0)
        st.session_state.contamination = st.slider("Contamination", 0.01, 0.5, 0.1, 0.01)
        
        st.markdown("---")
        st.markdown("### 🤖 GenAI Settings")
        st.session_state.gemini_api_key = st.text_input(
            "Gemini API Key",
            value=st.session_state.gemini_api_key,
            type="password",
            help="Enter your Google Gemini API key for AI-powered analysis. Get it from: https://makersuite.google.com/app/apikey"
        )
        if st.session_state.gemini_api_key:
            st.success("✅ API Key configured")
        else:
            st.info("ℹ️ GenAI analysis requires API key")
    
    if page == "📤 Upload & Parse":
        page_upload_parse()
    elif page == "🔍 Anomaly Detection":
        page_anomaly_detection()
    elif page == "📊 Visualization":
        page_visualization()
    elif page == "💡 Explainability":
        page_explainability()
    elif page == "📥 Export Results":
        page_export()

def page_upload_parse():
    st.header("📤 Upload & Parse Log Files")
    uploaded_files = st.file_uploader("Choose log files", type=['evtx', 'csv', 'json', 'log', 'txt'], accept_multiple_files=True)
    
    if uploaded_files:
        st.success(f"✅ {len(uploaded_files)} file(s) uploaded")
        if st.button("🚀 Parse Files", type="primary"):
            parse_files(uploaded_files)
    
    if st.session_state.parsed_data is not None:
        st.markdown("---")
        st.subheader("📋 Parsed Events")
        df = st.session_state.parsed_data
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Events", len(df))
        with col2:
            st.metric("Unique Event IDs", df['EventID'].nunique() if 'EventID' in df.columns else 0)
        with col3:
            st.metric("Unique Hosts", df['Computer'].nunique() if 'Computer' in df.columns else 0)
        with col4:
            st.metric("Time Data", "Available" if 'TimeCreatedISO' in df.columns else "N/A")
        
        display_cols = get_display_columns(df, ['EventRecordID', 'TimeCreatedISO', 'EventID', 'Level', 'Computer', 'Channel'])
        if display_cols:
            st.dataframe(df[display_cols].head(100), use_container_width=True)
        
        st.markdown("---")
        if st.button("🔧 Extract Features", type="primary"):
            extract_features()
        
        if st.session_state.features_df is not None:
            st.success(f"✅ Extracted {len(st.session_state.feature_cols)} ML features")

def page_anomaly_detection():
    st.header("🔍 Anomaly Detection")
    
    if st.session_state.features_df is None:
        st.warning("⚠️ Please upload and parse files first, then extract features.")
        return
    
    col1, col2 = st.columns(2)
    with col1:
        st.info(f"**Algorithm:** {st.session_state.algorithm}")
    with col2:
        st.info(f"**Contamination:** {st.session_state.contamination}")
    
    if st.button("🚀 Detect Anomalies", type="primary"):
        detect_anomalies()
    
    if st.session_state.results_df is not None:
        st.markdown("---")
        df = st.session_state.results_df
        metrics = st.session_state.training_metrics
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Events", metrics.get('n_samples', 0))
        with col2:
            anomaly_count = metrics.get('n_anomalies', 0)
            anomaly_rate = metrics.get('anomaly_rate', 0) * 100
            st.metric("Anomalies Detected", f"{anomaly_count} ({anomaly_rate:.1f}%)")
        with col3:
            st.metric("Features Used", metrics.get('n_features', 0))
        with col4:
            st.metric("Algorithm", metrics.get('algorithm', 'N/A').upper())
        
        # Show adaptive contamination info if different
        if metrics.get('adaptive_mode') and metrics.get('contamination') != metrics.get('original_contamination'):
            st.info(f"🔧 **Adaptive Mode:** Contamination auto-adjusted from {metrics.get('original_contamination'):.2f} to {metrics.get('contamination'):.2f} for dataset size")
        
        anomalies = df[df['Anomaly'] == 1]
        if len(anomalies) > 0:
            display_cols = get_display_columns(anomalies, ['EventRecordID', 'TimeCreatedISO', 'EventID', 'Computer', 'AnomalyScoreNormalized'])
            if display_cols:
                st.dataframe(anomalies[display_cols].sort_values('AnomalyScoreNormalized', ascending=False).head(50), use_container_width=True)
        
        st.markdown("---")
        if st.button("🔗 Run Clustering"):
            cluster_anomalies()

def page_visualization():
    st.header("📊 Visualization Dashboard")
    
    if st.session_state.results_df is None:
        st.warning("⚠️ Please run anomaly detection first.")
        return
    
    df = st.session_state.results_df
    viz = Visualizer()
    
    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(viz.plot_anomaly_distribution(df), use_container_width=True)
    with col2:
        st.plotly_chart(viz.plot_anomaly_scores(df), use_container_width=True)
    
    st.plotly_chart(viz.plot_timeline(df), use_container_width=True)
    
    if 'ClusterLabel' in df.columns:
        st.markdown("---")
        anomalies_df = df[df['Anomaly'] == 1]
        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(viz.plot_cluster_distribution(anomalies_df), use_container_width=True)
        with col2:
            if 'MITRE_Stage' in df.columns:
                st.plotly_chart(viz.plot_mitre_stages(anomalies_df), use_container_width=True)
        
        # Detailed breakdown of anomalies by APT stage
        if 'MITRE_Stage' in df.columns:
            st.markdown("---")
            st.subheader("🎯 Anomalies by APT Stage")
            st.markdown("*Click each stage to see the specific anomalies responsible for that classification*")
            
            stage_groups = viz.display_anomalies_by_stage(df)
            
            if stage_groups:
                # Sort stages by their numeric order
                stage_order = ['Stage 1: Initial Access', 'Stage 2: Execution', 'Stage 2: Credential Access',
                             'Stage 3: Persistence', 'Stage 3: Privilege Escalation', 'Stage 3: Defense Evasion',
                             'Stage 4: Discovery', 'Stage 4: Lateral Movement', 
                             'Stage 5: Collection', 'Stage 5: Command & Control',
                             'Stage 6: Exfiltration', 'Stage 7: Impact']
                
                sorted_stages = sorted(stage_groups.keys(), 
                                     key=lambda x: stage_order.index(x) if x in stage_order else 999)
                
                for stage in sorted_stages:
                    stage_df = stage_groups[stage]
                    with st.expander(f"**{stage}** - {len(stage_df)} anomalies", expanded=False):
                        # Show summary statistics
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            if 'EventID' in stage_df.columns:
                                unique_eventids = stage_df['EventID'].nunique()
                                st.metric("Unique EventIDs", unique_eventids)
                        with col2:
                            if 'Computer' in stage_df.columns:
                                unique_computers = stage_df['Computer'].nunique()
                                st.metric("Affected Systems", unique_computers)
                        with col3:
                            if 'AnomalyScoreNormalized' in stage_df.columns:
                                avg_score = stage_df['AnomalyScoreNormalized'].mean()
                                st.metric("Avg Anomaly Score", f"{avg_score:.2f}")
                        
                        # Show the anomalies table
                        st.dataframe(stage_df, use_container_width=True, height=300)

def page_explainability():
    st.header("💡 AI-Powered Threat Intelligence")
    
    if st.session_state.results_df is None or st.session_state.model is None:
        st.warning("⚠️ Please run anomaly detection first.")
        return
    
    df = st.session_state.results_df
    anomalies = df[df['Anomaly'] == 1]
    
    if len(anomalies) == 0:
        st.info("✅ No anomalies detected - your logs appear normal!")
        return
    
    # Compute SHAP values automatically on first load if not already computed
    if st.session_state.explainer is None:
        with st.spinner("🧠 Computing AI explanations..."):
            compute_shap_values()
    
    if st.session_state.explainer is not None:
        # Generate global AI analysis first
        with st.spinner("🤖 Generating comprehensive threat analysis..."):
            global_analysis = st.session_state.explainer.generate_global_genai_analysis(df)
        
        # Display global analysis
        st.markdown("### 🌐 Overall Threat Landscape")
        
        if 'error' not in global_analysis:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                with st.expander("📊 Overview", expanded=True):
                    st.markdown(global_analysis.get('overview', 'No overview available'))
                
                with st.expander("🎯 Attack Patterns", expanded=True):
                    st.markdown(global_analysis.get('patterns', 'No patterns identified'))
            
            with col2:
                with st.expander("⚠️ Threat Assessment", expanded=True):
                    st.markdown(global_analysis.get('threat_assessment', 'No assessment available'))
                
                with st.expander("💡 Key Takeaways", expanded=True):
                    st.markdown(global_analysis.get('key_takeaways', 'No takeaways available'))
            
            with st.expander("🛡️ Strategic Recommendations", expanded=False):
                st.markdown(global_analysis.get('recommendations', 'No recommendations available'))
        else:
            st.warning("⚠️ Global AI analysis unavailable. Configure Gemini API key in sidebar.")
        
        st.markdown("---")
        # Group anomalies by EventID
        st.markdown("### 🔍 Anomaly Groups by Event Type")
        
        if 'EventID' in anomalies.columns:
            # Group by EventID - build aggregation dict dynamically
            agg_dict = {
                'AnomalyScoreNormalized': ['count', 'mean', 'max']
            }
            
            # Add Computer aggregation if column exists
            if 'Computer' in anomalies.columns:
                agg_dict['Computer'] = 'nunique'
            
            # Add User aggregation if column exists
            if 'User' in anomalies.columns:
                agg_dict['User'] = 'nunique'
            
            grouped = anomalies.groupby('EventID').agg(agg_dict).reset_index()
            
            # Flatten column names
            new_cols = ['EventID', 'Count', 'AvgScore', 'MaxScore']
            if 'Computer' in anomalies.columns:
                new_cols.append('UniqueComputers')
            if 'User' in anomalies.columns:
                new_cols.append('UniqueUsers')
            
            grouped.columns = new_cols
            
            # Add missing columns with 0 if they don't exist
            if 'UniqueComputers' not in grouped.columns:
                grouped['UniqueComputers'] = 0
            if 'UniqueUsers' not in grouped.columns:
                grouped['UniqueUsers'] = 0
            
            grouped = grouped.sort_values('MaxScore', ascending=False)
            
            # Display summary metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Anomalies", len(anomalies))
            with col2:
                st.metric("Unique Event Types", len(grouped))
            with col3:
                high_risk = len(anomalies[anomalies['AnomalyScoreNormalized'] > 0.8])
                st.metric("High Risk Events", high_risk)
            with col4:
                st.metric("Avg Risk Score", f"{anomalies['AnomalyScoreNormalized'].mean():.1%}")
            
            st.markdown("---")
        
            # Display grouped anomalies
            st.markdown("### 📋 Grouped Threat Analysis")
            
            for idx, row in grouped.iterrows():
                event_id = row['EventID']
                count = int(row['Count'])
                avg_score = row['AvgScore']
                max_score = row['MaxScore']
                
                # Risk badge
                if max_score > 0.8:
                    risk_badge = "🔴 CRITICAL"
                    badge_color = "red"
                elif max_score > 0.6:
                    risk_badge = "🟠 HIGH"
                    badge_color = "orange"
                elif max_score > 0.4:
                    risk_badge = "🟡 MEDIUM"
                    badge_color = "blue"
                else:
                    risk_badge = "🟢 LOW"
                    badge_color = "green"
                
                # Get all anomalies for this EventID
                group_anomalies = anomalies[anomalies['EventID'] == event_id]
                
                # Create expander for this group
                with st.expander(
                    f"{risk_badge} **EventID {event_id}** - {count} occurrence(s) | Max Risk: {max_score:.1%}",
                    expanded=(max_score > 0.7)
                ):
                    # Group metrics
                    gcol1, gcol2, gcol3, gcol4 = st.columns(4)
                    with gcol1:
                        st.metric("Occurrences", count)
                    with gcol2:
                        st.metric("Avg Risk", f"{avg_score:.1%}")
                    with gcol3:
                        st.metric("Unique Systems", int(row['UniqueComputers']))
                    with gcol4:
                        st.metric("Unique Users", int(row['UniqueUsers']))
                    
                    st.markdown("---")
                    
                    # Get representative anomaly (highest score)
                    representative_idx = group_anomalies['AnomalyScoreNormalized'].idxmax()
                    
                    # Generate AI analysis for this group
                    explanation = st.session_state.explainer.explain_sample(
                        representative_idx,
                        st.session_state.results_df,
                        top_n=5
                    )
                    
                    timeline_data = st.session_state.explainer.get_event_timeline(
                        representative_idx,
                        st.session_state.results_df,
                        window_minutes=10
                    )
                    
                    genai_analysis = st.session_state.explainer.generate_genai_analysis(
                        representative_idx,
                        st.session_state.results_df,
                        explanation,
                        timeline_data=timeline_data
                    )
                    
                    # Display AI analysis
                    if 'error' not in genai_analysis:
                        acol1, acol2 = st.columns([3, 2])
                        
                        with acol1:
                            st.markdown("**📝 Summary**")
                            st.info(genai_analysis.get('summary', 'No summary available'))
                            
                            st.markdown("**🔍 What Happened**")
                            st.markdown(genai_analysis.get('what_happened', 'No analysis available'))
                        
                        with acol2:
                            st.markdown("**💡 Key Takeaways**")
                            st.markdown(genai_analysis.get('key_takeaways', 'No takeaways available'))
                            
                            st.markdown("**🛡️ Recommendations**")
                            st.markdown(genai_analysis.get('recommendations', 'No recommendations available'))
                    else:
                        st.warning("⚠️ AI analysis unavailable for this group")
                    
                    # Show affected events table
                    st.markdown("---")
                    st.markdown("**📊 Affected Events**")
                    
                    display_cols = ['TimeCreatedISO', 'Computer', 'User', 'AnomalyScoreNormalized']
                    display_cols = [c for c in display_cols if c in group_anomalies.columns]
                    
                    if display_cols:
                        st.dataframe(
                            group_anomalies[display_cols].sort_values('AnomalyScoreNormalized', ascending=False),
                            use_container_width=True,
                            height=min(300, len(group_anomalies) * 35 + 38)
                        )
        else:
            st.warning("⚠️ EventID information not available. Cannot group anomalies.")

def page_export():
    st.header("📥 Export Results")
    
    if st.session_state.results_df is None:
        st.warning("⚠️ No results to export.")
        return
    
    df = st.session_state.results_df
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📄 Full Results")
        csv = df.to_csv(index=False)
        st.download_button("Download CSV", csv, f"anomaly_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
    
    with col2:
        st.subheader("🚨 Anomalies Only")
        anomalies = df[df['Anomaly'] == 1]
        anomalies_csv = anomalies.to_csv(index=False)
        st.download_button("Download Anomalies CSV", anomalies_csv, f"anomalies_only_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")

def get_display_columns(df, preferred_cols):
    """Safely get display columns, handling duplicates and missing columns"""
    available_cols = []
    seen = set()
    for col in preferred_cols:
        if col in df.columns and col not in seen:
            available_cols.append(col)
            seen.add(col)
    
    # If no preferred columns found, use first 5 columns
    if not available_cols and len(df.columns) > 0:
        available_cols = list(df.columns[:5])
    
    return available_cols

def parse_files(uploaded_files):
    parser = LogParser()
    all_events = []
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for i, uploaded_file in enumerate(uploaded_files):
        status_text.text(f"Parsing {uploaded_file.name}...")
        temp_path = Path("temp_" + uploaded_file.name)
        
        with open(temp_path, 'wb') as f:
            f.write(uploaded_file.getbuffer())
        
        try:
            events = parser.parse_file(str(temp_path))
            all_events.extend(events)
            st.success(f"✅ Parsed {len(events)} events from {uploaded_file.name}")
        except Exception as e:
            error_msg = str(e)
            st.error(f"❌ Error parsing {uploaded_file.name}:\n{error_msg}")
            
            # Show workaround for EVTX files
            if uploaded_file.name.lower().endswith('.evtx'):
                st.warning(
                    "💡 **Workaround for problematic EVTX files:**\n\n"
                    "1. Save your EVTX file locally\n"
                    "2. Run: `python evtx_workaround_parser.py your_file.evtx`\n"
                    "3. Upload the generated CSV file instead\n\n"
                    "Or use the standalone converter: `python evtx_to_csv_converter.py`"
                )
        finally:
            if temp_path.exists():
                temp_path.unlink()
        
        progress_bar.progress((i + 1) / len(uploaded_files))
    
    if all_events:
        st.session_state.parsed_data = pd.DataFrame(all_events)
        st.success(f"✅ Total events parsed: {len(all_events)}")

def extract_features():
    with st.spinner("Extracting features..."):
        engineer = FeatureEngineer()
        features_df = engineer.extract_features(st.session_state.parsed_data.to_dict('records'))
        ml_df, feature_cols = engineer.get_ml_features(features_df)
        
        # features_df already contains all data, no need to concatenate
        st.session_state.features_df = features_df
        st.session_state.feature_cols = feature_cols
        st.success(f"✅ Extracted {len(feature_cols)} features")

def detect_anomalies():
    with st.spinner("Training anomaly detection model..."):
        detector = AnomalyDetector(
            algorithm=st.session_state.algorithm, 
            contamination=st.session_state.contamination,
            auto_contamination=True  # Enable adaptive contamination for small files
        )
        metrics = detector.train(st.session_state.features_df, st.session_state.feature_cols)
        predictions = detector.predict(st.session_state.features_df, st.session_state.feature_cols)
        
        # Merge predictions with features_df, avoiding duplicate columns
        results_df = st.session_state.features_df.copy()
        for col in predictions.columns:
            if col not in results_df.columns:
                results_df[col] = predictions[col]
            else:
                results_df[col] = predictions[col]  # Overwrite if exists
        
        st.session_state.model = detector
        st.session_state.results_df = results_df
        st.session_state.training_metrics = metrics
        st.success(f"✅ Found {metrics['n_anomalies']} anomalies")

def cluster_anomalies():
    df = st.session_state.results_df
    anomalies = df[df['Anomaly'] == 1].copy()
    
    if len(anomalies) < 1:
        st.warning("⚠️ No anomalies detected to analyze.")
        return
    
    # Show different message for small vs large datasets
    n_anomalies = len(anomalies)
    if n_anomalies <= 10:
        st.info(f"💡 **Direct Classification Mode:** Using pattern matching for {n_anomalies} anomalies instead of clustering for better accuracy.")
    
    with st.spinner("🔍 Analyzing attack patterns..." if n_anomalies <= 10 else "🔗 Clustering anomalies..."):
        clusterer = AnomalyClusterer(min_cluster_size=5, adaptive=True, direct_classification_threshold=10)
        cluster_results = clusterer.cluster(anomalies, st.session_state.feature_cols)
        cluster_results = clusterer.map_to_mitre_stages(cluster_results, anomalies)
        
        # Set the index of cluster_results to match anomalies
        cluster_results.index = anomalies.index
        
        # Update results_df with cluster information
        for col in ['Cluster', 'ClusterLabel', 'MITRE_Stage']:
            st.session_state.results_df.loc[anomalies.index, col] = cluster_results[col]
        
        st.success(f"✅ Clustered into {cluster_results['Cluster'].nunique()} groups")

def compute_shap_values():
    with st.spinner("Computing SHAP values and initializing AI analysis..."):
        try:
            model = st.session_state.model.model
            if isinstance(model, dict):
                model = model['isolation_forest']
            
            # Initialize explainer with Gemini API key
            gemini_key = st.session_state.gemini_api_key if st.session_state.gemini_api_key else None
            explainer = AnomalyExplainer(
                model, 
                st.session_state.model.scaler, 
                st.session_state.feature_cols,
                gemini_api_key=gemini_key
            )
            explainer.compute_shap_values(st.session_state.features_df, background_samples=100)
            st.session_state.explainer = explainer
            
            if gemini_key:
                st.success("✅ SHAP values computed! GenAI analysis ready.")
            else:
                st.success("✅ SHAP values computed! (Add Gemini API key for AI-powered insights)")
        except Exception as e:
            st.error(f"Error: {e}")

if __name__ == "__main__":
    main()
