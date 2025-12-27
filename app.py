"""
Explainable Log Anomaly Detection System
XAI-based APT Detector with Streamlit UI
Now with SQLite database integration for all reference data
"""

import streamlit as st
import pandas as pd
import os
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
import uuid

# Load environment variables from .env file
load_dotenv()

from parser import LogParser
from features import FeatureEngineer
from model import AnomalyDetector, AnomalyClusterer
from explain import AnomalyExplainer
from ui_helpers import Visualizer
from db_manager import get_db_manager

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

# Initialize database on first run
@st.cache_resource
def init_db():
    """Initialize database with reference data if not exists"""
    db_path = "event_references.db"
    if not Path(db_path).exists():
        st.error("❌ Database not found! Please run: `python init_database.py` first.")
        st.stop()
    return get_db_manager(db_path)

# Initialize database
db = init_db()

# Initialize session state
for key in ['parsed_data', 'features_df', 'results_df', 'model', 'explainer', 'feature_cols', 'training_metrics', 'gemini_api_key', 'session_id']:
    if key not in st.session_state:
        if key == 'feature_cols':
            st.session_state[key] = []
        elif key == 'training_metrics':
            st.session_state[key] = {}
        elif key == 'gemini_api_key':
            # Load from environment variable if available
            st.session_state[key] = os.getenv('GEMINI_API_KEY', '')
        elif key == 'session_id':
            # Generate unique session ID for this analysis session
            st.session_state[key] = str(uuid.uuid4())
        else:
            st.session_state[key] = None

def main():
    st.markdown('<div class="main-header">🛡️ATHEA</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Automated Threat Hunting using Explainable AI</div>', unsafe_allow_html=True)
    
    with st.sidebar:
        st.title("Navigation")
        page = st.radio("Go to", ["📤 Upload & Parse", "🔍 Anomaly Detection", "📊 Visualization", "💡 Explainability", "📥 Export Results", "🗄️ Database"])
        
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
    elif page == "🗄️ Database":
        page_database()

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
        viz = Visualizer()  # Initialize visualizer for enhanced columns
        
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
            # Extract EventData fields as columns
            anomalies_with_eventdata = viz.extract_eventdata_columns(anomalies)
            
            # Use enhanced column selection for better context
            display_cols = viz.get_enhanced_anomaly_columns(anomalies)
            if not display_cols:
                display_cols = get_display_columns(anomalies_with_eventdata, ['EventRecordID', 'TimeCreatedISO', 'EventID', 'Computer', 'AnomalyScoreNormalized'])
            
            if display_cols:
                # Rename columns for readability
                display_df = anomalies_with_eventdata[display_cols].copy()
                column_renames = {
                    'TimeCreatedISO': 'Timestamp',
                    'EventID': 'Event ID',
                    'EventID_Name': 'Event Name',
                    'EventID_RiskScore': 'Risk',
                    'AnomalyScoreNormalized': 'Anomaly Score',
                    'MITRE_Stage': 'Attack Stage',
                    'TargetUserName': 'Target User',
                    'SubjectUserName': 'Subject User',
                    'WorkstationName': 'Workstation',
                    'IpAddress': 'IP Address',
                    'SourceAddress': 'Source IP',
                    'ProcessName': 'Process',
                    'CommandLine': 'Command',
                    'ServiceName': 'Service',
                    'LogonType': 'Logon Type',
                    'FailureReason': 'Failure Reason',
                    'ObjectName': 'Object',
                    'TaskName': 'Task'
                }
                rename_dict = {k: v for k, v in column_renames.items() if k in display_df.columns}
                display_df = display_df.rename(columns=rename_dict)
                
                st.dataframe(display_df.sort_values('Anomaly Score' if 'Anomaly Score' in display_df.columns else display_df.columns[0], ascending=False).head(50), use_container_width=True)
        
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
    
    # First row: Anomaly distribution and scores
    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(viz.plot_anomaly_distribution(df), use_container_width=True)
    with col2:
        st.plotly_chart(viz.plot_anomaly_scores(df), use_container_width=True)
    
    # Second row: Severity distribution and timeline
    col3, col4 = st.columns(2)
    with col3:
        st.plotly_chart(viz.plot_severity_distribution(df), use_container_width=True)
    with col4:
        st.plotly_chart(viz.plot_timeline(df), use_container_width=True)
    
    # Third row: Clustering and MITRE stages (if available)
    if 'ClusterLabel' in df.columns:
        st.markdown("---")
        anomalies_df = df[df['Anomaly'] == 1]
        col5, col6 = st.columns(2)
        with col5:
            st.plotly_chart(viz.plot_cluster_distribution(anomalies_df), use_container_width=True)
        with col6:
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
                        
                        # Show the anomalies table (EventData already extracted in ui_helpers)
                        display_df = stage_df.copy()
                        
                        # Rename columns for better readability
                        column_renames = {
                            'TimeCreatedISO': 'Timestamp',
                            'EventID': 'Event ID',
                            'EventID_Name': 'Event Name',
                            'EventID_RiskScore': 'Risk',
                            'AnomalyScoreNormalized': 'Anomaly Score',
                            'Confidence': 'Confidence',
                            'MITRE_Stage': 'Attack Stage',
                            'TargetUserName': 'Target User',
                            'SubjectUserName': 'Subject User',
                            'WorkstationName': 'Workstation',
                            'IpAddress': 'IP Address',
                            'SourceAddress': 'Source IP',
                            'ProcessName': 'Process',
                            'CommandLine': 'Command',
                            'ServiceName': 'Service',
                            'LogonType': 'Logon Type',
                            'FailureReason': 'Failure Reason',
                            'Status': 'Status',
                            'ObjectName': 'Object',
                            'TaskName': 'Task'
                        }
                        
                        # Rename only columns that exist
                        rename_dict = {k: v for k, v in column_renames.items() if k in display_df.columns}
                        display_df = display_df.rename(columns=rename_dict)
                        
                        st.dataframe(display_df, use_container_width=True, height=300)

def page_explainability():
    st.header("💡 Explainable AI & Threat Intelligence")
    
    if st.session_state.results_df is None or st.session_state.model is None:
        st.warning("⚠️ Please run anomaly detection first.")
        return
    
    df = st.session_state.results_df
    anomalies = df[df['Anomaly'] == 1]
    viz = Visualizer()  # Initialize visualizer for EventData extraction
    
    if len(anomalies) == 0:
        st.info("✅ No anomalies detected - your logs appear normal!")
        return
    
    # Compute SHAP values automatically on first load if not already computed
    if st.session_state.explainer is None:
        with st.spinner("🧠 Computing XAI explanations..."):
            compute_shap_values()
    
    if st.session_state.explainer is not None:
        # Create tabs for XAI and Gemini sections
        tab1, tab2 = st.tabs(["🔬 XAI Analysis (SHAP)", "🤖 Gemini AI Analysis"])
        
        # ========================================
        # TAB 1: XAI ANALYSIS (SHAP-BASED)
        # ========================================
        with tab1:
            st.markdown("### 🔬 Explainable AI - Model Reasoning")
            st.markdown("*Understanding why the ML model flagged events as anomalous using SHAP (SHapley Additive exPlanations)*")
            st.markdown("---")
            
            # Global Feature Importance
            st.markdown("#### 📊 Global Feature Importance")
            st.markdown("*Which features matter most across all anomalies?*")
            
            try:
                importance_df = st.session_state.explainer.get_feature_importance()
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    # Bar chart of top features
                    import plotly.graph_objects as go
                    top_n = min(15, len(importance_df))
                    top_features = importance_df.head(top_n)
                    
                    fig = go.Figure(go.Bar(
                        x=top_features['Importance'],
                        y=top_features['Feature'],
                        orientation='h',
                        marker=dict(
                            color=top_features['Importance'],
                            colorscale='Reds',
                            showscale=True,
                            colorbar=dict(title="SHAP Impact")
                        )
                    ))
                    fig.update_layout(
                        title=f"Top {top_n} Most Important Features",
                        xaxis_title="Mean |SHAP Value|",
                        yaxis_title="Feature",
                        height=500,
                        yaxis={'categoryorder': 'total ascending'}
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    st.markdown("**📈 Feature Statistics**")
                    st.dataframe(
                        importance_df.head(10).style.format({'Importance': '{:.4f}'}),
                        use_container_width=True,
                        height=400
                    )
                    
                    st.info(f"💡 **Insight**: The top feature '{importance_df.iloc[0]['Feature']}' has the highest impact on anomaly detection across all events.")
            
            except Exception as e:
                st.error(f"Error computing feature importance: {e}")
            
            st.markdown("---")
            
            # Individual Anomaly Explanations
            st.markdown("#### 🔍 Individual Anomaly Explanations")
            st.markdown("*Detailed SHAP-based reasoning for each anomaly*")
            
            # Select anomaly to explain
            anomaly_indices = anomalies.index.tolist()
            
            # Create selection options with context
            selection_options = []
            for idx in anomaly_indices[:50]:  # Limit to top 50 for performance
                event_id = df.loc[idx, 'EventID'] if 'EventID' in df.columns else 'N/A'
                score = df.loc[idx, 'AnomalyScoreNormalized'] if 'AnomalyScoreNormalized' in df.columns else 0
                timestamp = df.loc[idx, 'TimeCreatedISO'] if 'TimeCreatedISO' in df.columns else 'N/A'
                selection_options.append(f"Index {idx} | EventID {event_id} | Score: {score:.2%} | {timestamp}")
            
            selected_option = st.selectbox(
                "Select an anomaly to explain:",
                selection_options,
                help="Choose an anomaly to see detailed SHAP-based explanation"
            )
            
            if selected_option:
                selected_idx = int(selected_option.split('|')[0].replace('Index', '').strip())
                
                try:
                    # Generate explanation
                    explanation = st.session_state.explainer.explain_sample(
                        selected_idx,
                        st.session_state.features_df,
                        top_n=10
                    )
                    
                    # Display explanation
                    col1, col2 = st.columns([3, 2])
                    
                    with col1:
                        st.markdown("##### 🎯 Top Contributing Features")
                        
                        # Create waterfall-style visualization
                        top_features = explanation['top_features']
                        
                        for i, feat in enumerate(top_features[:8], 1):
                            feature_name = feat['feature']
                            shap_val = feat['shap_value']
                            feature_val = feat['value']
                            contribution = feat['contribution']
                            
                            # Color based on contribution
                            if contribution == "increases":
                                color = "🔴"
                                bar_color = "#ff4444"
                            else:
                                color = "🟢"
                                bar_color = "#44ff44"
                            
                            # Create progress bar for SHAP value
                            abs_shap = abs(shap_val)
                            max_shap = max([abs(f['shap_value']) for f in top_features])
                            bar_width = int((abs_shap / max_shap) * 100) if max_shap > 0 else 0
                            
                            st.markdown(f"""
                            **{i}. {feature_name}** {color}
                            - Feature Value: `{feature_val:.4f}`
                            - SHAP Value: `{shap_val:.4f}` ({contribution} anomaly score)
                            - Impact: {'█' * (bar_width // 5)}
                            """)
                        
                        st.markdown("---")
                        st.markdown("##### 📝 Natural Language Explanation")
                        st.info(explanation['explanation_text'])
                    
                    with col2:
                        st.markdown("##### 📊 Event Details")
                        
                        event = df.loc[selected_idx]
                        
                        # Display key event information
                        if 'EventID' in df.columns:
                            st.metric("Event ID", event.get('EventID', 'N/A'))
                        if 'AnomalyScoreNormalized' in df.columns:
                            st.metric("Anomaly Score", f"{event.get('AnomalyScoreNormalized', 0):.2%}")
                        if 'Computer' in df.columns:
                            st.metric("Computer", event.get('Computer', 'N/A'))
                        if 'User' in df.columns:
                            st.metric("User", event.get('User', 'N/A'))
                        
                        st.markdown("---")
                        st.markdown("##### 🧮 SHAP Interpretation")
                        st.markdown("""
                        **How to read SHAP values:**
                        - 🔴 **Positive SHAP**: Feature pushes prediction towards anomaly
                        - 🟢 **Negative SHAP**: Feature pushes prediction towards normal
                        - **Magnitude**: Larger absolute value = stronger impact
                        """)
                        
                        # Base value info
                        if 'base_value' in explanation:
                            st.markdown(f"**Base Value**: {explanation['base_value']:.4f}")
                            st.caption("The average model output across all training data")
                
                except Exception as e:
                    st.error(f"Error generating explanation: {e}")
            
            st.markdown("---")
            
            # Export explanations
            st.markdown("#### 💾 Export XAI Explanations")
            
            if st.button("📥 Generate Explanation Report for All Anomalies"):
                with st.spinner("Generating explanations for all anomalies..."):
                    try:
                        explanations_df = st.session_state.explainer.export_explanations(
                            st.session_state.features_df,
                            anomaly_indices[:100],  # Limit to 100 for performance
                            top_n=5
                        )
                        
                        st.success(f"✅ Generated explanations for {len(explanations_df)} anomalies")
                        st.dataframe(explanations_df, use_container_width=True, height=300)
                        
                        # Download button
                        csv = explanations_df.to_csv(index=False)
                        st.download_button(
                            label="📥 Download Explanations CSV",
                            data=csv,
                            file_name="xai_explanations.csv",
                            mime="text/csv"
                        )
                    except Exception as e:
                        st.error(f"Error exporting explanations: {e}")
        
        # ========================================
        # TAB 2: GEMINI AI ANALYSIS
        # ========================================
        with tab2:
            st.markdown("### 🤖 Gemini AI - Strategic Threat Analysis")
            st.markdown("*AI-powered contextual analysis and strategic recommendations*")
            st.markdown("---")
            
            # Generate global AI analysis
            with st.spinner("🤖 Generating comprehensive threat analysis..."):
                global_analysis = st.session_state.explainer.generate_global_genai_analysis(df)
            
            # Display global analysis
            st.markdown("#### 🌐 Overall Threat Landscape")
            
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
        
        st.markdown("---")
        # Group anomalies by EventID (shared across both tabs)
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
                    expanded=bool(max_score > 0.7)
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
                    
                    # Show affected events table
                    st.markdown("---")
                    st.markdown("**📊 Affected Events**")
                    
                    # Simplified display for Explainability page - basic info only
                    priority_cols = [
                        'TimeCreatedISO', 'EventID', 'EventID_Name',
                        'EventID_RiskScore', 'AnomalyScoreNormalized', 'Confidence',
                        'Computer', 'User'
                    ]
                    
                    display_cols = [c for c in priority_cols if c in group_anomalies.columns]
                    
                    if display_cols:
                        # Rename for readability
                        display_df = group_anomalies[display_cols].copy()
                        column_renames = {
                            'TimeCreatedISO': 'Timestamp',
                            'EventID': 'Event ID',
                            'EventID_Name': 'Event Name',
                            'EventID_RiskScore': 'Risk',
                            'AnomalyScoreNormalized': 'Anomaly Score'
                        }
                        rename_dict = {k: v for k, v in column_renames.items() if k in display_df.columns}
                        display_df = display_df.rename(columns=rename_dict)
                        
                        st.dataframe(
                            display_df.sort_values('Anomaly Score' if 'Anomaly Score' in display_df.columns else display_df.columns[0], ascending=False),
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
        
        # Save results to database
        save_results_to_database(results_df)
        
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
        
        # FORCE CORRECT MITRE STAGES - Direct override approach with proper logic
        print("\n🔧 Applying forced MITRE stage corrections...")
        
        if 'EventID' in st.session_state.results_df.columns:
            # Define EventID-to-Stage mappings
            stage_mappings = {
                # Stage 1: Initial Access
                'Stage 1: Initial Access': [4624, 4625, 4648, 4768, 4769, 4771, 4776, '4624', '4625', '4648', '4768', '4769', '4771', '4776'],
                
                # Stage 2: Execution
                'Stage 2: Execution': [4688, 1, 4689, '4688', '1', '4689'],
                
                # Stage 3: Persistence
                'Stage 3: Persistence': [4698, 4699, 4700, 4701, 7045, 7040, '4698', '4699', '4700', '4701', '7045', '7040'],
                
                # Stage 3: Defense Evasion
                'Stage 3: Defense Evasion': [4657, 4663, 4670, 1102, '4657', '4663', '4670', '1102'],
                
                # Stage 4: Credential Access
                'Stage 4: Credential Access': [4656, 4661, 4662, '4656', '4661', '4662'],
                
                # Stage 5: Lateral Movement
                'Stage 5: Lateral Movement': [4672, 4778, 4779, 5140, 5145, '4672', '4778', '4779', '5140', '5145'],
            }
            
            # Apply mappings
            for stage, event_ids in stage_mappings.items():
                mask = st.session_state.results_df['EventID'].isin(event_ids)
                count = mask.sum()
                if count > 0:
                    st.session_state.results_df.loc[mask, 'MITRE_Stage'] = stage
                    print(f"   ✅ Forced {count} events to {stage}")
        
        # Additional check: Events with CommandLine but NOT logon events should be Execution
        if 'CommandLine' in st.session_state.results_df.columns and 'EventID' in st.session_state.results_df.columns:
            has_command = (st.session_state.results_df['CommandLine'].notna() & 
                          (st.session_state.results_df['CommandLine'] != '') &
                          ~st.session_state.results_df['EventID'].isin([4624, 4625, 4648, '4624', '4625', '4648']))
            command_count = has_command.sum()
            if command_count > 0:
                st.session_state.results_df.loc[has_command, 'MITRE_Stage'] = 'Stage 2: Execution'
                print(f"   ✅ Forced {command_count} events with CommandLine to Stage 2: Execution")
        
        # Print final stage distribution
        print("\n📊 Final MITRE Stage Distribution:")
        stage_dist = st.session_state.results_df[st.session_state.results_df['Anomaly'] == 1]['MITRE_Stage'].value_counts()
        for stage, count in stage_dist.items():
            print(f"   {stage}: {count} anomalies")
        print()
        
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

def save_results_to_database(results_df: pd.DataFrame):
    """Save analysis results to database"""
    try:
        session_id = st.session_state.session_id
        
        # Save only anomalies to database (to avoid cluttering)
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

def page_database():
    """Database management and statistics page"""
    st.header("🗄️ Database Management")
    
    # Database statistics
    st.subheader("📊 Database Statistics")
    stats = db.get_statistics()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Events", stats['total_events'])
    with col2:
        st.metric("Security Events", stats['security_events'])
    with col3:
        st.metric("Sysmon Events", stats['sysmon_events'])
    with col4:
        st.metric("System Events", stats['system_events'])
    
    col5, col6, col7, col8 = st.columns(4)
    with col5:
        st.metric("SQL Events", stats['sql_events'])
    with col6:
        st.metric("MITRE Tactics", stats['mitre_tactics'])
    with col7:
        st.metric("MITRE Techniques", stats['mitre_techniques'])
    with col8:
        high_risk = db.search_events_by_risk(min_risk=7)
        st.metric("High Risk Events", len(high_risk))
    
    st.markdown("---")
    
    # Event lookup
    st.subheader("🔍 Event Lookup")
    col1, col2 = st.columns([2, 1])
    
    with col1:
        event_id_lookup = st.number_input("Enter EventID", min_value=1, max_value=99999, value=4624)
    with col2:
        channel_lookup = st.selectbox("Channel", ["Auto-detect", "Security", "Sysmon", "System", "SQL"])
    
    if st.button("🔎 Lookup Event"):
        channel = None if channel_lookup == "Auto-detect" else channel_lookup
        event = db.get_event_by_id_and_channel(event_id_lookup, channel)
        
        if event:
            st.success(f"✅ Found EventID {event_id_lookup}")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Name", event.get('name', 'N/A'))
            with col2:
                st.metric("Risk Score", event.get('risk_score', 'N/A'))
            with col3:
                st.metric("Severity", event.get('severity', 'N/A'))
            
            st.markdown("**Description:**")
            st.info(event.get('description', 'No description available'))
            
            st.markdown("**Category:**")
            st.write(event.get('category', 'Unknown'))
            
            if event.get('mitre_tactics'):
                st.markdown("**MITRE Tactics:**")
                st.write(", ".join(event['mitre_tactics']))
            
            if event.get('mitre_techniques'):
                st.markdown("**MITRE Techniques:**")
                st.write(", ".join(event['mitre_techniques']))
            
            if event.get('suspicious_when'):
                st.markdown("**Suspicious When:**")
                for item in event['suspicious_when']:
                    st.write(f"- {item}")
        else:
            st.error(f"❌ EventID {event_id_lookup} not found in database")
    
    st.markdown("---")
    
    # High risk events
    st.subheader("🔴 High Risk Events")
    risk_threshold = st.slider("Minimum Risk Score", 1, 10, 7)
    
    high_risk_events = db.search_events_by_risk(min_risk=risk_threshold)
    
    if high_risk_events:
        st.write(f"Found {len(high_risk_events)} events with risk score >= {risk_threshold}")
        
        # Convert to DataFrame for display
        df_high_risk = pd.DataFrame(high_risk_events)
        display_cols = ['event_id', 'name', 'source', 'risk_score', 'severity', 'category']
        display_cols = [c for c in display_cols if c in df_high_risk.columns]
        
        if display_cols:
            df_display = df_high_risk[display_cols].sort_values('risk_score', ascending=False)
            st.dataframe(df_display, use_container_width=True, height=400)
    else:
        st.info(f"No events found with risk score >= {risk_threshold}")
    
    st.markdown("---")
    
    # Analysis history
    st.subheader("📜 Analysis History")
    session_id = st.session_state.session_id
    
    st.info(f"Current Session ID: `{session_id}`")
    
    anomalies = db.get_anomalies_by_session(session_id)
    
    if anomalies:
        st.write(f"Found {len(anomalies)} anomalies in current session")
        
        df_anomalies = pd.DataFrame(anomalies)
        display_cols = ['event_id', 'computer', 'timestamp', 'anomaly_score', 'mitre_stage', 'confidence']
        display_cols = [c for c in display_cols if c in df_anomalies.columns]
        
        if display_cols:
            df_display = df_anomalies[display_cols].sort_values('anomaly_score', ascending=False)
            st.dataframe(df_display, use_container_width=True, height=300)
    else:
        st.info("No anomalies saved for current session yet. Run anomaly detection first.")
    
    st.markdown("---")
    
    # Database actions
    st.subheader("⚙️ Database Actions")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.info("ℹ️ To reinitialize database, run: `python init_database.py`")
    
    with col2:
        st.download_button(
            label="📥 Download Database",
            data=open("event_references.db", "rb").read(),
            file_name=f"event_references_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db",
            mime="application/octet-stream"
        )

if __name__ == "__main__":
    main()
