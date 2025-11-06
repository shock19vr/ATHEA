"""
UI Helpers Module
Visualization utilities for Streamlit dashboard.
"""

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from typing import List, Dict, Any, Optional


class Visualizer:
    """Generate interactive visualizations for anomaly detection results"""
    
    def __init__(self):
        self.color_palette = {
            'normal': '#2ecc71',
            'anomaly': '#e74c3c',
            'primary': '#3498db',
            'secondary': '#95a5a6'
        }
    
    def plot_anomaly_distribution(self, df: pd.DataFrame) -> go.Figure:
        """
        Create pie chart of anomaly distribution.
        
        Args:
            df: DataFrame with 'Anomaly' column
            
        Returns:
            Plotly figure
        """
        anomaly_counts = df['Anomaly'].value_counts()
        labels = ['Normal', 'Anomaly']
        values = [
            anomaly_counts.get(0, 0),
            anomaly_counts.get(1, 0)
        ]
        colors = [self.color_palette['normal'], self.color_palette['anomaly']]
        
        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            marker=dict(colors=colors),
            hole=0.3,
            textinfo='label+percent+value',
            textfont_size=14
        )])
        
        fig.update_layout(
            title='Anomaly Distribution',
            title_font_size=18,
            showlegend=True,
            height=400
        )
        
        return fig
    
    def plot_anomaly_scores(self, df: pd.DataFrame) -> go.Figure:
        """
        Create histogram of anomaly scores.
        
        Args:
            df: DataFrame with 'AnomalyScoreNormalized' and 'Anomaly' columns
            
        Returns:
            Plotly figure
        """
        fig = go.Figure()
        
        # Normal events
        normal_scores = df[df['Anomaly'] == 0]['AnomalyScoreNormalized']
        fig.add_trace(go.Histogram(
            x=normal_scores,
            name='Normal',
            marker_color=self.color_palette['normal'],
            opacity=0.7,
            nbinsx=30
        ))
        
        # Anomalous events
        anomaly_scores = df[df['Anomaly'] == 1]['AnomalyScoreNormalized']
        fig.add_trace(go.Histogram(
            x=anomaly_scores,
            name='Anomaly',
            marker_color=self.color_palette['anomaly'],
            opacity=0.7,
            nbinsx=30
        ))
        
        fig.update_layout(
            title='Distribution of Anomaly Scores',
            xaxis_title='Anomaly Score (Normalized)',
            yaxis_title='Count',
            barmode='overlay',
            height=400,
            showlegend=True
        )
        
        return fig
    
    def plot_timeline(self, df: pd.DataFrame, time_col: str = 'TimeCreatedISO') -> go.Figure:
        """
        Create timeline plot of anomalies.
        
        Args:
            df: DataFrame with time and anomaly columns
            time_col: Name of time column
            
        Returns:
            Plotly figure
        """
        if time_col not in df.columns or df[time_col].isna().all():
            # Fallback to index-based timeline
            df_plot = df.copy()
            df_plot['TimeIndex'] = range(len(df))
            time_col = 'TimeIndex'
        else:
            df_plot = df.copy()
            df_plot[time_col] = pd.to_datetime(df_plot[time_col], errors='coerce')
        
        # Aggregate by time bins
        if time_col == 'TimeIndex':
            # Group by index bins
            df_plot['TimeBin'] = pd.cut(df_plot[time_col], bins=50)
            grouped = df_plot.groupby('TimeBin').agg({
                'Anomaly': ['sum', 'count']
            }).reset_index()
            grouped.columns = ['TimeBin', 'Anomalies', 'Total']
            grouped['Normal'] = grouped['Total'] - grouped['Anomalies']
            grouped['TimeBinStr'] = grouped['TimeBin'].astype(str)
            
            x_vals = grouped['TimeBinStr']
        else:
            # Group by time period
            df_plot = df_plot.dropna(subset=[time_col])
            df_plot.set_index(time_col, inplace=True)
            
            # Determine frequency based on data span
            time_range = (df_plot.index.max() - df_plot.index.min()).total_seconds()
            if time_range < 3600:  # Less than 1 hour
                freq = '1min'
            elif time_range < 86400:  # Less than 1 day
                freq = '1H'
            else:
                freq = '1D'
            
            grouped = df_plot.resample(freq).agg({
                'Anomaly': ['sum', 'count']
            }).reset_index()
            grouped.columns = [time_col, 'Anomalies', 'Total']
            grouped['Normal'] = grouped['Total'] - grouped['Anomalies']
            
            x_vals = grouped[time_col]
        
        # Create stacked area chart
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=x_vals,
            y=grouped['Normal'],
            mode='lines',
            name='Normal',
            line=dict(width=0),
            fillcolor=self.color_palette['normal'],
            fill='tonexty',
            stackgroup='one'
        ))
        
        fig.add_trace(go.Scatter(
            x=x_vals,
            y=grouped['Anomalies'],
            mode='lines',
            name='Anomaly',
            line=dict(width=0),
            fillcolor=self.color_palette['anomaly'],
            fill='tonexty',
            stackgroup='one'
        ))
        
        fig.update_layout(
            title='Timeline of Events (Normal vs Anomaly)',
            xaxis_title='Time',
            yaxis_title='Event Count',
            height=400,
            hovermode='x unified',
            showlegend=True
        )
        
        return fig
    
    def plot_feature_correlation(self, df: pd.DataFrame, features: List[str], 
                                 top_n: int = 15) -> go.Figure:
        """
        Create correlation heatmap of top features.
        
        Args:
            df: Feature DataFrame
            features: List of feature names
            top_n: Number of top features to display
            
        Returns:
            Plotly figure
        """
        # Select top features based on variance
        feature_subset = df[features].var().nlargest(top_n).index.tolist()
        corr_matrix = df[feature_subset].corr()
        
        fig = go.Figure(data=go.Heatmap(
            z=corr_matrix.values,
            x=corr_matrix.columns,
            y=corr_matrix.columns,
            colorscale='RdBu',
            zmid=0,
            text=np.round(corr_matrix.values, 2),
            texttemplate='%{text}',
            textfont={"size": 8},
            colorbar=dict(title="Correlation")
        ))
        
        fig.update_layout(
            title=f'Feature Correlation Heatmap (Top {top_n})',
            height=600,
            width=700,
            xaxis={'side': 'bottom'},
        )
        
        return fig
    
    def plot_cluster_distribution(self, df: pd.DataFrame) -> go.Figure:
        """
        Create bar chart of cluster distribution.
        
        Args:
            df: DataFrame with 'ClusterLabel' column
            
        Returns:
            Plotly figure
        """
        if 'ClusterLabel' not in df.columns:
            return go.Figure()
        
        cluster_counts = df['ClusterLabel'].value_counts().reset_index()
        cluster_counts.columns = ['Cluster', 'Count']
        
        fig = go.Figure(data=[go.Bar(
            x=cluster_counts['Cluster'],
            y=cluster_counts['Count'],
            marker_color=self.color_palette['primary'],
            text=cluster_counts['Count'],
            textposition='auto',
        )])
        
        fig.update_layout(
            title='Anomaly Cluster Distribution',
            xaxis_title='Cluster',
            yaxis_title='Number of Anomalies',
            height=400,
            showlegend=False
        )
        
        return fig
    
    def plot_mitre_stages(self, df: pd.DataFrame) -> go.Figure:
        """
        Create bar chart of MITRE ATT&CK stage distribution with anomaly details.
        
        Args:
            df: DataFrame with 'MITRE_Stage' column
            
        Returns:
            Plotly figure
        """
        if 'MITRE_Stage' not in df.columns:
            return go.Figure()
        
        stage_counts = df['MITRE_Stage'].value_counts().reset_index()
        stage_counts.columns = ['Stage', 'Count']
        
        # Build detailed hover information for each stage
        hover_texts = []
        for stage in stage_counts['Stage']:
            stage_df = df[df['MITRE_Stage'] == stage]
            
            # Get unique EventIDs
            event_ids = stage_df['EventID'].value_counts().head(5) if 'EventID' in stage_df.columns else None
            
            # Get attack patterns/cluster labels if available
            cluster_labels = stage_df['ClusterLabel'].value_counts().head(3) if 'ClusterLabel' in stage_df.columns else None
            
            # Build hover text
            hover_text = f"<b>{stage}</b><br>"
            hover_text += f"Total Anomalies: {len(stage_df)}<br><br>"
            
            if event_ids is not None and len(event_ids) > 0:
                hover_text += "<b>Top EventIDs:</b><br>"
                for eid, count in event_ids.items():
                    hover_text += f"  • EventID {eid}: {count} events<br>"
                hover_text += "<br>"
            
            if cluster_labels is not None and len(cluster_labels) > 0:
                hover_text += "<b>Attack Patterns:</b><br>"
                for label, count in cluster_labels.items():
                    hover_text += f"  • {label}: {count}<br>"
            
            hover_texts.append(hover_text)
        
        # Color by stage severity
        colors = [self.color_palette['anomaly'] if 'Stage 1' in s or 'Stage 2' in s 
                 else self.color_palette['primary'] for s in stage_counts['Stage']]
        
        fig = go.Figure(data=[go.Bar(
            x=stage_counts['Stage'],
            y=stage_counts['Count'],
            marker_color=colors,
            text=stage_counts['Count'],
            textposition='auto',
            hovertemplate='%{customdata}<extra></extra>',
            customdata=hover_texts
        )])
        
        fig.update_layout(
            title='Potential APT Stage Distribution (MITRE ATT&CK)<br><sub>Hover over bars for anomaly details</sub>',
            xaxis_title='Stage',
            yaxis_title='Number of Anomalies',
            height=400,
            showlegend=False,
            xaxis={'tickangle': -45}
        )
        
        return fig
    
    def plot_top_anomalies(self, df: pd.DataFrame, top_n: int = 10) -> go.Figure:
        """
        Create table of top anomalies by score.
        
        Args:
            df: Full DataFrame with anomalies
            top_n: Number of top anomalies to display
            
        Returns:
            Plotly figure
        """
        # Get top anomalies
        anomalies = df[df['Anomaly'] == 1].copy()
        
        if len(anomalies) == 0:
            return go.Figure()
        
        anomalies = anomalies.nlargest(top_n, 'AnomalyScoreNormalized')
        
        # Select key columns
        display_cols = []
        for col in ['EventID', 'TimeCreatedISO', 'Computer', 'Level', 
                   'AnomalyScoreNormalized', 'ExplanationText']:
            if col in anomalies.columns:
                display_cols.append(col)
        
        if not display_cols:
            display_cols = anomalies.columns.tolist()[:5]
        
        # Create table
        fig = go.Figure(data=[go.Table(
            header=dict(
                values=display_cols,
                fill_color=self.color_palette['primary'],
                font=dict(color='white', size=12),
                align='left'
            ),
            cells=dict(
                values=[anomalies[col] for col in display_cols],
                fill_color='lavender',
                align='left',
                height=30
            )
        )])
        
        fig.update_layout(
            title=f'Top {top_n} Anomalies by Score',
            height=400
        )
        
        return fig
    
    def create_dashboard_metrics(self, df: pd.DataFrame, 
                                 metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create summary metrics for dashboard.
        
        Args:
            df: Full DataFrame
            metrics: Model training metrics
            
        Returns:
            Dictionary of formatted metrics
        """
        total_events = len(df)
        n_anomalies = (df['Anomaly'] == 1).sum() if 'Anomaly' in df.columns else 0
        anomaly_rate = (n_anomalies / total_events * 100) if total_events > 0 else 0
        
        # Time range
        if 'TimeCreatedISO' in df.columns:
            df_time = df.dropna(subset=['TimeCreatedISO'])
            if len(df_time) > 0:
                df_time['TimeCreatedISO'] = pd.to_datetime(df_time['TimeCreatedISO'], errors='coerce')
                time_range = f"{df_time['TimeCreatedISO'].min()} to {df_time['TimeCreatedISO'].max()}"
            else:
                time_range = "N/A"
        else:
            time_range = "N/A"
        
        # Top event types
        if 'EventID' in df.columns:
            top_events = df['EventID'].value_counts().head(3).to_dict()
        else:
            top_events = {}
        
        return {
            'total_events': total_events,
            'n_anomalies': n_anomalies,
            'anomaly_rate': f"{anomaly_rate:.2f}%",
            'time_range': time_range,
            'algorithm': metrics.get('algorithm', 'Unknown'),
            'n_features': metrics.get('n_features', 0),
            'top_events': top_events
        }
    
    def display_anomalies_by_stage(self, df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
        """
        Group anomalies by their MITRE ATT&CK stage and return organized data.
        
        Args:
            df: DataFrame with anomaly detection results
            
        Returns:
            Dictionary mapping stage names to DataFrames of anomalies
        """
        if 'MITRE_Stage' not in df.columns:
            return {}
        
        anomalies = df[df['Anomaly'] == 1].copy()
        if len(anomalies) == 0:
            return {}
        
        # Group by stage
        stage_groups = {}
        for stage in anomalies['MITRE_Stage'].unique():
            stage_df = anomalies[anomalies['MITRE_Stage'] == stage].copy()
            
            # Select relevant columns for display
            display_cols = []
            for col in ['EventRecordID', 'TimeCreatedISO', 'EventID', 'EventID_Name', 
                       'ClusterLabel', 'AnomalyScoreNormalized', 'Computer', 'Channel']:
                if col in stage_df.columns:
                    display_cols.append(col)
            
            if display_cols:
                stage_groups[stage] = stage_df[display_cols].sort_values(
                    'AnomalyScoreNormalized', ascending=False
                )
            else:
                stage_groups[stage] = stage_df
        
        return stage_groups
