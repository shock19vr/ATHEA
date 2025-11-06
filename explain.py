"""
Explainability Module
Implements SHAP-based explanations for anomaly predictions.
Enhanced with GenAI-powered analysis using Gemini.
"""

import pandas as pd
import numpy as np
import shap
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

# Import GenAI analyzer
try:
    from genai_analyzer import GeminiAnalyzer
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    GeminiAnalyzer = None


class AnomalyExplainer:
    """Generate explanations for anomaly detections using SHAP"""
    
    def __init__(self, model, scaler, feature_names: List[str], gemini_api_key: Optional[str] = None):
        """
        Initialize explainer.
        
        Args:
            model: Trained anomaly detection model
            scaler: Fitted StandardScaler
            feature_names: List of feature names
            gemini_api_key: Optional Gemini API key for GenAI analysis
        """
        self.model = model
        self.scaler = scaler
        self.feature_names = feature_names
        self.explainer = None
        self.shap_values = None
        
        # Initialize GenAI analyzer if available
        self.genai_analyzer = None
        if GENAI_AVAILABLE and GeminiAnalyzer:
            try:
                self.genai_analyzer = GeminiAnalyzer(api_key=gemini_api_key)
            except Exception as e:
                print(f"⚠️ GenAI analyzer initialization failed: {e}")
                self.genai_analyzer = None
        
    def compute_shap_values(self, X: pd.DataFrame, background_samples: int = 100):
        """
        Compute SHAP values for all samples.
        
        Args:
            X: Feature DataFrame
            background_samples: Number of background samples for SHAP
        """
        X_scaled = self.scaler.transform(X[self.feature_names].values)
        
        # Use TreeExplainer for tree-based models (Isolation Forest)
        # Use KernelExplainer for others
        try:
            if hasattr(self.model, 'decision_function'):
                # For Isolation Forest
                self.explainer = shap.TreeExplainer(
                    self.model,
                    feature_perturbation='interventional'
                )
                self.shap_values = self.explainer.shap_values(X_scaled)
            else:
                # For other models, use KernelExplainer with background data
                n_background = min(background_samples, len(X_scaled))
                background = shap.sample(X_scaled, n_background)
                
                self.explainer = shap.KernelExplainer(
                    lambda x: self.model.decision_function(x),
                    background
                )
                self.shap_values = self.explainer.shap_values(X_scaled)
        except Exception as e:
            print(f"SHAP computation error: {e}")
            # Fallback: use KernelExplainer
            n_background = min(background_samples, len(X_scaled))
            background = shap.sample(X_scaled, n_background)
            
            def predict_fn(x):
                try:
                    return self.model.decision_function(x)
                except:
                    return self.model.score_samples(x)
            
            self.explainer = shap.KernelExplainer(predict_fn, background)
            self.shap_values = self.explainer.shap_values(X_scaled)
    
    def explain_sample(self, idx: int, X: pd.DataFrame, top_n: int = 5) -> Dict[str, Any]:
        """
        Generate explanation for a specific sample.
        
        Args:
            idx: Sample index
            X: Feature DataFrame
            top_n: Number of top features to include
            
        Returns:
            Dictionary with explanation details
        """
        if self.shap_values is None:
            raise RuntimeError("SHAP values not computed. Call compute_shap_values() first.")
        
        # Get SHAP values for this sample
        sample_shap = self.shap_values[idx]
        sample_features = X[self.feature_names].iloc[idx].values
        
        # Get top contributing features (by absolute SHAP value)
        abs_shap = np.abs(sample_shap)
        top_indices = np.argsort(abs_shap)[-top_n:][::-1]
        
        # Build explanation
        top_features = []
        for i in top_indices:
            feature_name = self.feature_names[i]
            feature_value = sample_features[i]
            shap_value = sample_shap[i]
            contribution = "increases" if shap_value > 0 else "decreases"
            
            top_features.append({
                'feature': feature_name,
                'value': float(feature_value),
                'shap_value': float(shap_value),
                'contribution': contribution
            })
        
        # Generate natural language explanation
        explanation_text = self._generate_explanation_text(top_features)
        
        return {
            'idx': idx,
            'top_features': top_features,
            'explanation_text': explanation_text,
            'base_value': float(self.explainer.expected_value) if hasattr(self.explainer, 'expected_value') else 0.0
        }
    
    def _generate_explanation_text(self, top_features: List[Dict]) -> str:
        """Generate natural language explanation"""
        if not top_features:
            return "No significant features identified."
        
        parts = ["This event was flagged as anomalous due to:"]
        
        for feat in top_features[:3]:  # Top 3 features
            feature_name = feat['feature'].replace('_', ' ').lower()
            value = feat['value']
            contribution = feat['contribution']
            
            # Format value
            if abs(value) < 0.01:
                value_str = f"{value:.4f}"
            elif abs(value) < 1:
                value_str = f"{value:.2f}"
            else:
                value_str = f"{value:.1f}"
            
            parts.append(f"  • {feature_name.title()}: {value_str} ({contribution} anomaly score)")
        
        return "\n".join(parts)
    
    def get_feature_importance(self) -> pd.DataFrame:
        """
        Get global feature importance (mean absolute SHAP values).
        
        Returns:
            DataFrame with features and importance scores
        """
        if self.shap_values is None:
            raise RuntimeError("SHAP values not computed. Call compute_shap_values() first.")
        
        # Calculate mean absolute SHAP values
        importance = np.abs(self.shap_values).mean(axis=0)
        
        # Create DataFrame
        importance_df = pd.DataFrame({
            'Feature': self.feature_names,
            'Importance': importance
        }).sort_values('Importance', ascending=False)
        
        return importance_df
    
    def export_explanations(self, X: pd.DataFrame, anomaly_indices: List[int], 
                           top_n: int = 5) -> pd.DataFrame:
        """
        Export explanations for all anomalies to DataFrame.
        
        Args:
            X: Feature DataFrame
            anomaly_indices: List of anomaly indices
            top_n: Number of top features per explanation
            
        Returns:
            DataFrame with explanations
        """
        if self.shap_values is None:
            raise RuntimeError("SHAP values not computed. Call compute_shap_values() first.")
        
        explanations = []
        
        for idx in anomaly_indices:
            explanation = self.explain_sample(idx, X, top_n)
            
            # Extract top feature names and values
            top_feat_names = [f['feature'] for f in explanation['top_features']]
            top_feat_values = [f['value'] for f in explanation['top_features']]
            top_shap_values = [f['shap_value'] for f in explanation['top_features']]
            
            explanations.append({
                'Index': idx,
                'ExplanationText': explanation['explanation_text'],
                'TopFeature1': top_feat_names[0] if len(top_feat_names) > 0 else None,
                'TopFeature1_Value': top_feat_values[0] if len(top_feat_values) > 0 else None,
                'TopFeature1_SHAP': top_shap_values[0] if len(top_shap_values) > 0 else None,
                'TopFeature2': top_feat_names[1] if len(top_feat_names) > 1 else None,
                'TopFeature2_Value': top_feat_values[1] if len(top_feat_values) > 1 else None,
                'TopFeature2_SHAP': top_shap_values[1] if len(top_shap_values) > 1 else None,
                'TopFeature3': top_feat_names[2] if len(top_feat_names) > 2 else None,
                'TopFeature3_Value': top_feat_values[2] if len(top_feat_values) > 2 else None,
                'TopFeature3_SHAP': top_shap_values[2] if len(top_shap_values) > 2 else None,
            })
        
        return pd.DataFrame(explanations)
    
    def get_event_timeline(self, idx: int, df: pd.DataFrame, 
                          window_minutes: int = 10) -> Dict[str, Any]:
        """
        Get events before and after the anomaly to show timeline context.
        
        Args:
            idx: Index of the anomalous event
            df: Full DataFrame with all events
            window_minutes: Time window in minutes before/after
            
        Returns:
            Dictionary with timeline information including EventID patterns
        """
        if 'EpochSeconds' not in df.columns:
            return {'error': 'No temporal data available'}
        
        anomaly_time = df.loc[idx, 'EpochSeconds']
        if pd.isna(anomaly_time):
            return {'error': 'Anomaly has no timestamp'}
        
        window_seconds = window_minutes * 60
        
        # Get events in time window
        time_mask = (
            (df['EpochSeconds'] >= anomaly_time - window_seconds) &
            (df['EpochSeconds'] <= anomaly_time + window_seconds)
        )
        timeline_events = df[time_mask].copy()
        
        # Sort by time
        timeline_events = timeline_events.sort_values('EpochSeconds')
        
        # Mark the anomaly
        timeline_events['IsAnomalous'] = timeline_events.index == idx
        
        # Calculate relative time to anomaly
        timeline_events['SecondsFromAnomaly'] = (
            timeline_events['EpochSeconds'] - anomaly_time
        )
        
        # Analyze EventID patterns
        eventid_analysis = self._analyze_eventid_patterns(idx, timeline_events, df)
        
        return {
            'anomaly_time': anomaly_time,
            'anomaly_idx': idx,
            'window_minutes': window_minutes,
            'events': timeline_events,
            'events_before': len(timeline_events[timeline_events['SecondsFromAnomaly'] < 0]),
            'events_after': len(timeline_events[timeline_events['SecondsFromAnomaly'] > 0]),
            'eventid_analysis': eventid_analysis
        }
    
    def _analyze_eventid_patterns(self, idx: int, timeline_events: pd.DataFrame, 
                                  full_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze EventID patterns to determine if the anomaly EventID is contextually appropriate.
        
        Args:
            idx: Index of anomalous event
            timeline_events: Events in the timeline window
            full_df: Full DataFrame
            
        Returns:
            Dictionary with EventID pattern analysis
        """
        if 'EventID' not in full_df.columns:
            return {'available': False}
        
        anomaly_eventid = full_df.loc[idx, 'EventID']
        
        # Get EventIDs in timeline
        timeline_eventids = timeline_events['EventID'].dropna().values
        unique_timeline_eventids = set(timeline_eventids)
        
        # Get EventIDs in full dataset
        all_eventids = full_df['EventID'].dropna()
        eventid_frequency = all_eventids.value_counts()
        
        # Calculate statistics
        anomaly_frequency = eventid_frequency.get(anomaly_eventid, 0)
        anomaly_percentage = (anomaly_frequency / len(all_eventids) * 100) if len(all_eventids) > 0 else 0
        
        # Check if anomaly EventID appears in timeline (contextual similarity)
        eventid_in_context = anomaly_eventid in unique_timeline_eventids
        context_occurrences = np.sum(timeline_eventids == anomaly_eventid)
        
        # Determine if EventID is truly rare or just different
        is_rare = anomaly_frequency < 3 or anomaly_percentage < 2.0
        is_isolated = context_occurrences <= 1  # Only the anomaly itself
        
        # EventID diversity in timeline
        eventid_diversity = len(unique_timeline_eventids)
        
        # Classify the anomaly type
        if is_rare and is_isolated:
            classification = "Truly Rare Event"
            risk_level = "High"
        elif not is_rare and is_isolated:
            classification = "Isolated But Common Event"
            risk_level = "Medium"
        elif is_rare and not is_isolated:
            classification = "Rare Event with Context"
            risk_level = "Medium"
        else:
            classification = "Common Event in Context"
            risk_level = "Low"
        
        return {
            'available': True,
            'anomaly_eventid': int(anomaly_eventid),
            'anomaly_frequency_total': int(anomaly_frequency),
            'anomaly_percentage': float(anomaly_percentage),
            'appears_in_timeline': bool(eventid_in_context),
            'timeline_occurrences': int(context_occurrences),
            'is_rare': bool(is_rare),
            'is_isolated': bool(is_isolated),
            'timeline_diversity': int(eventid_diversity),
            'classification': classification,
            'risk_level': risk_level,
            'timeline_eventids': list(unique_timeline_eventids),
            'most_common_in_timeline': timeline_events['EventID'].mode().tolist() if len(timeline_events) > 0 else []
        }
    
    def generate_attack_narrative(self, idx: int, df: pd.DataFrame, 
                                 explanation: Dict[str, Any],
                                 timeline_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a human-readable narrative of what happened.
        
        Args:
            idx: Index of anomalous event
            df: Full DataFrame
            explanation: Explanation dictionary from explain_sample
            
        Returns:
            Human-readable narrative string
        """
        narrative_parts = []
        
        # Get event details
        event = df.loc[idx]
        
        # 1. When did it happen
        if 'EpochSeconds' in df.columns and pd.notna(event.get('EpochSeconds')):
            try:
                timestamp = datetime.fromtimestamp(event['EpochSeconds'])
                narrative_parts.append(
                    f"⏰ **When**: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
                )
                
                hour = timestamp.hour
                if hour < 6 or hour > 22:
                    narrative_parts.append("   ⚠️ Occurred during unusual hours (night time)")
                elif 9 <= hour <= 17:
                    narrative_parts.append("   📅 Occurred during business hours")
            except:
                pass
        
        # 2. What event was it
        if 'EventID' in df.columns:
            event_id = event.get('EventID', 'Unknown')
            narrative_parts.append(f"\n📌 **What**: Event ID {event_id}")
            
            # Add event type context
            event_types = {
                4624: "User Login (Successful)",
                4625: "User Login (Failed)",
                4648: "Explicit Credential Usage",
                4688: "New Process Created",
                4672: "Special Privileges Assigned",
                4720: "User Account Created",
                4732: "User Added to Security Group",
                7045: "New Service Installed",
                1: "Process Creation (Sysmon)",
                3: "Network Connection (Sysmon)",
                11: "File Created (Sysmon)"
            }
            
            if event_id in event_types:
                narrative_parts.append(f"   Type: {event_types[event_id]}")
        
        # 3. Where (Computer/Host)
        if 'Computer' in df.columns and pd.notna(event.get('Computer')):
            narrative_parts.append(f"\n🖥️ **Where**: {event['Computer']}")
        
        # 4. Who (User)
        if 'User' in df.columns and pd.notna(event.get('User')):
            narrative_parts.append(f"\n👤 **Who**: {event['User']}")
        
        # 5. Why it's anomalous (top features)
        narrative_parts.append("\n🚨 **Why Suspicious**:")
        
        top_features = explanation.get('top_features', [])
        for feat in top_features[:3]:
            feature_name = feat['feature']
            value = feat['value']
            contribution = feat['contribution']
            
            # Human-readable explanations for common features
            explanations = {
                'EventIDRarity': f"This event type is very rare (rarity score: {value:.3f})",
                'IsNightTime': f"Event occurred during night hours" if value > 0.5 else None,
                'EventsPerMinute': f"High event frequency: {value:.1f} events/minute",
                'TimeSincePrevEvent': f"Unusual timing: {value:.1f} seconds since previous event",
                'IsFailedLogin': "Failed login attempt detected" if value > 0.5 else None,
                'IsProcessCreation': "Suspicious process creation" if value > 0.5 else None,
                'LevelSeverity': f"High severity level: {value:.0f}/5",
                'UniqueEventIDsInWindow': f"Unusual diversity: {value:.0f} different event types nearby",
                'UserEventCount': f"User has abnormal activity count: {value:.0f} events",
            }
            
            explanation_text = explanations.get(feature_name)
            if explanation_text:
                narrative_parts.append(f"   • {explanation_text}")
            else:
                # Generic explanation
                narrative_parts.append(
                    f"   • {feature_name.replace('_', ' ').title()}: {value:.2f} ({contribution} suspicion)"
                )
        
        # 6. Risk assessment
        if 'AnomalyScoreNormalized' in df.columns:
            score = event.get('AnomalyScoreNormalized', 0)
            narrative_parts.append(f"\n⚡ **Risk Level**: {score:.1%}")
            
            if score > 0.9:
                narrative_parts.append("   🔴 CRITICAL - Immediate investigation required")
            elif score > 0.7:
                narrative_parts.append("   🟠 HIGH - Should be investigated soon")
            elif score > 0.5:
                narrative_parts.append("   🟡 MEDIUM - Review when possible")
            else:
                narrative_parts.append("   🟢 LOW - Minor anomaly")
        
        # 7. MITRE ATT&CK context if available
        if 'MITRE_Stage' in df.columns and pd.notna(event.get('MITRE_Stage')):
            stage = event['MITRE_Stage']
            narrative_parts.append(f"\n🎯 **Attack Stage**: {stage}")
        
        # 8. EventID Context (if timeline data available)
        if timeline_data and 'eventid_analysis' in timeline_data:
            eventid_info = timeline_data['eventid_analysis']
            if eventid_info.get('available', False):
                narrative_parts.append("\n🔍 **EventID Context**:")
                narrative_parts.append(f"   Classification: {eventid_info['classification']}")
                narrative_parts.append(f"   Overall frequency: {eventid_info['anomaly_percentage']:.1f}% of all events")
                
                if eventid_info['is_isolated']:
                    narrative_parts.append("   ⚠️ This EventID is isolated (no similar events nearby)")
                else:
                    narrative_parts.append(f"   ✓ Found {eventid_info['timeline_occurrences']} similar events in timeline")
                
                if eventid_info['is_rare'] and eventid_info['is_isolated']:
                    narrative_parts.append("   🚨 High priority: Rare and isolated event")
                elif not eventid_info['is_rare'] and eventid_info['is_isolated']:
                    narrative_parts.append("   ⚠️ Note: Common event appearing in unusual context")
        
        return "\n".join(narrative_parts)
    
    def generate_genai_analysis(self, 
                                idx: int, 
                                df: pd.DataFrame,
                                explanation: Dict[str, Any],
                                timeline_data: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """
        Generate AI-powered analysis using Gemini.
        
        Args:
            idx: Index of anomalous event
            df: Full DataFrame
            explanation: SHAP explanation data
            timeline_data: Optional timeline context
            
        Returns:
            Dictionary with AI analysis sections
        """
        if self.genai_analyzer is None:
            return {
                'error': 'GenAI analyzer not available',
                'summary': 'AI analysis requires Gemini API key. Set GEMINI_API_KEY environment variable.',
                'what_happened': 'GenAI analysis unavailable',
                'key_takeaways': 'Please configure Gemini API key to enable AI-powered insights',
                'recommendations': 'Get your API key from: https://makersuite.google.com/app/apikey'
            }
        
        try:
            # Get anomaly event
            anomaly_event = df.loc[idx]
            
            # Get timeline events
            if timeline_data and 'events' in timeline_data:
                timeline_events = timeline_data['events']
            else:
                # Create minimal timeline if not provided
                timeline_events = df.iloc[max(0, idx-5):min(len(df), idx+6)]
            
            # Get all anomalies
            all_anomalies = df[df['Anomaly'] == 1] if 'Anomaly' in df.columns else df.iloc[[idx]]
            
            # Generate AI analysis
            analysis = self.genai_analyzer.analyze_anomaly(
                anomaly_event=anomaly_event,
                timeline_events=timeline_events,
                all_anomalies=all_anomalies,
                explanation_data=explanation
            )
            
            return analysis
            
        except Exception as e:
            return {
                'error': f'Failed to generate AI analysis: {str(e)}',
                'summary': 'AI analysis encountered an error',
                'what_happened': str(e),
                'key_takeaways': 'Please check your API key and connection',
                'recommendations': 'Retry the analysis or check error logs'
            }
    
    def generate_global_genai_analysis(self, df: pd.DataFrame) -> Dict[str, str]:
        """
        Generate comprehensive AI analysis of all anomalies.
        
        Args:
            df: Full DataFrame with anomaly labels
            
        Returns:
            Dictionary with global AI analysis
        """
        if self.genai_analyzer is None:
            return {
                'error': 'GenAI analyzer not available',
                'overview': 'AI analysis requires Gemini API key. Set GEMINI_API_KEY environment variable.',
                'patterns': 'GenAI analysis unavailable',
                'threat_assessment': 'Please configure Gemini API key',
                'key_takeaways': 'Get your API key from: https://makersuite.google.com/app/apikey',
                'recommendations': 'Configure API key to enable comprehensive threat analysis'
            }
        
        try:
            # Get all anomalies
            all_anomalies = df[df['Anomaly'] == 1] if 'Anomaly' in df.columns else pd.DataFrame()
            
            if len(all_anomalies) == 0:
                return {
                    'overview': 'No anomalies detected in the dataset.',
                    'patterns': 'All events appear normal.',
                    'threat_assessment': 'No threats identified.',
                    'key_takeaways': '✅ System appears to be operating normally',
                    'recommendations': 'Continue monitoring for any unusual activity'
                }
            
            # Generate global analysis
            analysis = self.genai_analyzer.analyze_all_anomalies(
                all_anomalies=all_anomalies,
                full_dataset=df
            )
            
            return analysis
            
        except Exception as e:
            return {
                'error': f'Failed to generate global AI analysis: {str(e)}',
                'overview': 'AI analysis encountered an error',
                'patterns': str(e),
                'threat_assessment': 'Analysis failed',
                'key_takeaways': 'Please check your API key and connection',
                'recommendations': 'Retry the analysis or check error logs'
            }
