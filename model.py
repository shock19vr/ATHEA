"""
Anomaly Detection Model Module
Implements unsupervised anomaly detection using multiple algorithms.
"""

import pandas as pd
import numpy as np
from typing import Dict, Any, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import HDBSCAN
import joblib
from pathlib import Path
from eventid_mapper import get_mapper


class AnomalyDetector:
    """Unified anomaly detection with multiple algorithms"""
    
    def __init__(self, algorithm: str = 'isolation_forest', contamination: float = 0.1, 
                 auto_contamination: bool = True):
        """
        Initialize anomaly detector.
        
        Args:
            algorithm: 'isolation_forest', 'lof', or 'ensemble'
            contamination: Expected proportion of anomalies (0.0 to 0.5)
            auto_contamination: Automatically adjust contamination for small datasets
        """
        self.algorithm = algorithm
        self.contamination = contamination
        self.auto_contamination = auto_contamination
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = []
        self.is_fitted = False
        self.adaptive_threshold = None
        
    def train(self, features_df: pd.DataFrame, feature_cols: list) -> Dict[str, Any]:
        """
        Train anomaly detection model with adaptive contamination.
        
        Args:
            features_df: DataFrame with numeric features
            feature_cols: List of feature column names to use
            
        Returns:
            Training metrics dictionary
        """
        if features_df.empty:
            raise ValueError("Features DataFrame is empty")
        
        self.feature_names = feature_cols
        X = features_df[feature_cols].values
        n_samples = len(X)
        
        # Adaptive contamination for small files
        effective_contamination = self.contamination
        if self.auto_contamination:
            effective_contamination = self._calculate_adaptive_contamination(n_samples)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Adjust parameters based on dataset size
        n_estimators = min(200, max(50, n_samples // 2))
        n_neighbors = min(20, max(5, n_samples // 10))
        
        # Train model based on algorithm
        if self.algorithm == 'isolation_forest':
            self.model = IsolationForest(
                contamination=effective_contamination,
                random_state=42,
                n_estimators=n_estimators,
                max_samples=min(256, n_samples),
                max_features=min(len(feature_cols), max(1, len(feature_cols) // 2)),
                bootstrap=True,
                n_jobs=-1
            )
            self.model.fit(X_scaled)
            
        elif self.algorithm == 'lof':
            self.model = LocalOutlierFactor(
                contamination=effective_contamination,
                n_neighbors=n_neighbors,
                novelty=True,
                metric='minkowski',
                p=2,
                n_jobs=-1
            )
            self.model.fit(X_scaled)
            
        elif self.algorithm == 'ensemble':
            # Train both models with adaptive parameters
            self.model = {
                'isolation_forest': IsolationForest(
                    contamination=effective_contamination,
                    random_state=42,
                    n_estimators=n_estimators,
                    max_samples=min(256, n_samples),
                    bootstrap=True,
                    n_jobs=-1
                ),
                'lof': LocalOutlierFactor(
                    contamination=effective_contamination,
                    n_neighbors=n_neighbors,
                    novelty=True,
                    n_jobs=-1
                )
            }
            self.model['isolation_forest'].fit(X_scaled)
            self.model['lof'].fit(X_scaled)
        else:
            raise ValueError(f"Unknown algorithm: {self.algorithm}")
        
        self.is_fitted = True
        
        # Calculate adaptive threshold for small datasets
        if n_samples < 50:
            self._calculate_adaptive_threshold(X_scaled)
        
        # Calculate training metrics
        predictions = self.predict(features_df, feature_cols)
        n_anomalies = (predictions['Anomaly'] == 1).sum()
        
        metrics = {
            'algorithm': self.algorithm,
            'n_samples': len(features_df),
            'n_features': len(feature_cols),
            'n_anomalies': n_anomalies,
            'anomaly_rate': n_anomalies / len(features_df) if len(features_df) > 0 else 0,
            'contamination': effective_contamination,
            'original_contamination': self.contamination,
            'adaptive_mode': self.auto_contamination
        }
        
        return metrics
    
    def _calculate_adaptive_contamination(self, n_samples: int) -> float:
        """
        Calculate adaptive contamination based on dataset size.
        Small files: more aggressive (higher contamination)
        Large files: use configured contamination
        """
        if n_samples < 10:
            # Very small: flag top 30-50% as potentially anomalous
            return min(0.5, max(0.3, self.contamination * 3))
        elif n_samples < 50:
            # Small: increase sensitivity
            return min(0.3, self.contamination * 2)
        elif n_samples < 100:
            # Medium-small: slight increase
            return min(0.2, self.contamination * 1.5)
        else:
            # Normal: use configured value
            return self.contamination
    
    def _calculate_adaptive_threshold(self, X_scaled: np.ndarray):
        """
        Calculate adaptive scoring threshold for very small datasets.
        Uses percentile-based approach instead of fixed contamination.
        """
        if self.algorithm == 'isolation_forest':
            scores = self.model.score_samples(X_scaled)
            # Use 75th percentile as threshold for small files
            self.adaptive_threshold = np.percentile(scores, 25)
        elif self.algorithm == 'ensemble':
            if_scores = self.model['isolation_forest'].score_samples(X_scaled)
            self.adaptive_threshold = np.percentile(if_scores, 25)
    
    def predict(self, features_df: pd.DataFrame, feature_cols: list) -> pd.DataFrame:
        """
        Predict anomalies with adaptive thresholding.
        
        Args:
            features_df: DataFrame with numeric features
            feature_cols: List of feature column names
            
        Returns:
            DataFrame with predictions and scores
        """
        if not self.is_fitted:
            raise RuntimeError("Model not trained. Call train() first.")
        
        X = features_df[feature_cols].values
        X_scaled = self.scaler.transform(X)
        
        if self.algorithm == 'ensemble':
            # Ensemble prediction with weighted voting
            if_pred = self.model['isolation_forest'].predict(X_scaled)
            lof_pred = self.model['lof'].predict(X_scaled)
            
            if_score = self.model['isolation_forest'].score_samples(X_scaled)
            lof_score = self.model['lof'].score_samples(X_scaled)
            
            # Normalize scores to [0, 1]
            if_norm = self._normalize_scores(if_score)
            lof_norm = self._normalize_scores(lof_score)
            
            # Convert to binary (1 = anomaly, 0 = normal)
            if_binary = (if_pred == -1).astype(int)
            lof_binary = (lof_pred == -1).astype(int)
            
            # Weighted voting: both models agree = high confidence
            predictions = (if_binary + lof_binary >= 1).astype(int)
            
            # Combined confidence score
            scores = if_score  # Use raw IF scores for ranking
            normalized_scores = (if_norm + lof_norm) / 2
            
            # Override predictions if adaptive threshold is set
            if self.adaptive_threshold is not None:
                predictions = (scores <= self.adaptive_threshold).astype(int)
            
        else:
            pred = self.model.predict(X_scaled)
            scores = self.model.score_samples(X_scaled)
            normalized_scores = self._normalize_scores(scores)
            
            # Convert to binary
            predictions = (pred == -1).astype(int)
            
            # Override for adaptive threshold
            if self.adaptive_threshold is not None:
                predictions = (scores <= self.adaptive_threshold).astype(int)
        
        # Add confidence levels
        confidence = self._calculate_confidence(normalized_scores, predictions)
        
        # Create results dataframe
        results = pd.DataFrame({
            'Anomaly': predictions,
            'AnomalyScore': scores,
            'AnomalyScoreNormalized': normalized_scores,
            'Confidence': confidence
        })
        
        # Apply EventID context filter to reduce false positives
        results = self._apply_eventid_context_filter(results, features_df)
        
        return results
    
    def _calculate_confidence(self, normalized_scores: np.ndarray, 
                             predictions: np.ndarray) -> np.ndarray:
        """
        Calculate confidence levels for predictions.
        High confidence = extreme scores, Low confidence = near threshold
        """
        confidence = np.zeros(len(normalized_scores))
        
        for i, (score, pred) in enumerate(zip(normalized_scores, predictions)):
            if pred == 1:  # Anomaly
                # Higher score = higher confidence for anomaly
                if score > 0.8:
                    confidence[i] = 3  # High
                elif score > 0.6:
                    confidence[i] = 2  # Medium
                else:
                    confidence[i] = 1  # Low
            else:  # Normal
                # Lower score = higher confidence for normal
                if score < 0.2:
                    confidence[i] = 3
                elif score < 0.4:
                    confidence[i] = 2
                else:
                    confidence[i] = 1
        
        return confidence
    
    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """Normalize anomaly scores to [0, 1] range"""
        scores = np.array(scores)
        
        # Handle empty or constant arrays
        if len(scores) == 0:
            return scores
        
        min_score = scores.min()
        max_score = scores.max()
        
        if max_score == min_score:
            return np.ones_like(scores) * 0.5
        
        # Normalize to [0, 1]
        normalized = (scores - min_score) / (max_score - min_score)
        
        return normalized
    
    def _apply_eventid_context_filter(self, results: pd.DataFrame, 
                                      features_df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply EventID context filtering to reduce false positives.
        Events flagged ONLY because of rare EventID (without other suspicious indicators)
        should not be considered anomalies.
        
        Args:
            results: DataFrame with anomaly predictions
            features_df: Full features DataFrame with EventID and other features
            
        Returns:
            Filtered results DataFrame
        """
        if 'EventID' not in features_df.columns:
            return results
        
        # Define benign rare EventIDs that shouldn't trigger anomalies by themselves
        benign_rare_eventids = {
            # System maintenance and normal operations
            1074,   # System shutdown/restart
            6005,   # Event log service started
            6006,   # Event log service stopped
            6008,   # Unexpected shutdown
            6013,   # System uptime
            19,     # Installation success
            20,     # Installation failure (normal in updates)
            1000,   # Application error (common)
            1001,   # Application hang
            1002,   # Application install
            7036,   # Service state change
            7040,   # Service startup type change
            10000,  # COM+ Info
            10001,  # Perflib Info
            # Sysmon common events
            2,      # File creation time changed
            5,      # Process terminated
            # SQL Server routine events
            17806,  # SSPI context generated
            18456,  # Login succeeded (routine)
        }
        
        results_copy = results.copy()
        
        # For each anomaly, check if it's ONLY flagged due to rare EventID
        for idx in results[results['Anomaly'] == 1].index:
            event_id = features_df.loc[idx, 'EventID']
            
            # Check if this is a benign rare EventID
            is_benign_rare = event_id in benign_rare_eventids
            
            # Get features that contributed to the anomaly
            has_other_indicators = self._has_other_suspicious_indicators(idx, features_df)
            
            # If it's a benign rare EventID AND has no other suspicious indicators, downgrade it
            if is_benign_rare and not has_other_indicators:
                results_copy.loc[idx, 'Anomaly'] = 0
                results_copy.loc[idx, 'AnomalyScoreNormalized'] = min(0.4, results_copy.loc[idx, 'AnomalyScoreNormalized'])
                results_copy.loc[idx, 'Confidence'] = 1  # Low confidence
        
        return results_copy
    
    def _has_other_suspicious_indicators(self, idx: int, features_df: pd.DataFrame) -> bool:
        """
        Check if an event has suspicious indicators beyond just rare EventID.
        
        Returns True if event has other red flags like:
        - Night time activity
        - High event frequency
        - Failed logins
        - Process creation with suspicious patterns
        - Privilege escalation
        - etc.
        """
        suspicious_features = {
            'IsNightTime': 0.5,           # Night activity
            'IsFailedLogin': 0.5,          # Failed auth
            'IsProcessCreation': 0.5,      # New process
            'IsPrivilegeUse': 0.5,         # Privilege usage
            'IsGroupModification': 0.5,    # Group changes
            'IsScheduledTask': 0.5,        # Task scheduling
            'IsRegistryModification': 0.5, # Registry changes
            'IsSecurityLogCleared': 0.5,   # Log tampering
            'LogHasPowerShell': 0.5,       # PowerShell usage
            'LogHasScript': 0.5,           # Scripting
            'LogHasBase64': 0.5,           # Encoding
            'LogHasSuspicious': 0.5,       # Suspicious terms
            'LogHasPrivEsc': 0.5,          # Privilege escalation terms
        }
        
        # Check for high event frequency
        if 'EventsPerMinute' in features_df.columns:
            if features_df.loc[idx, 'EventsPerMinute'] > 20:
                return True
        
        # Check for unusual timing
        if 'TimeSincePrevEvent' in features_df.columns:
            time_gap = features_df.loc[idx, 'TimeSincePrevEvent']
            if time_gap > 300 or time_gap < 0.1:  # > 5 min or < 0.1 sec
                return True
        
        # Check for high diversity of events
        if 'UniqueEventIDsInWindow' in features_df.columns:
            if features_df.loc[idx, 'UniqueEventIDsInWindow'] > 10:
                return True
        
        # Check suspicious feature flags
        for feature, threshold in suspicious_features.items():
            if feature in features_df.columns:
                if features_df.loc[idx, feature] > threshold:
                    return True
        
        # Check EventID rarity (very rare events are suspicious)
        if 'EventIDRarity' in features_df.columns:
            if features_df.loc[idx, 'EventIDRarity'] > 0.8:  # Extremely rare
                return True
        
        return False
    
    def save_model(self, filepath: str):
        """Save trained model to disk"""
        if not self.is_fitted:
            raise RuntimeError("Model not trained. Nothing to save.")
        
        model_data = {
            'algorithm': self.algorithm,
            'contamination': self.contamination,
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_fitted': self.is_fitted
        }
        
        joblib.dump(model_data, filepath)
        
    def load_model(self, filepath: str):
        """Load trained model from disk"""
        model_data = joblib.load(filepath)
        
        self.algorithm = model_data['algorithm']
        self.contamination = model_data['contamination']
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.is_fitted = model_data['is_fitted']


class AnomalyClusterer:
    """Cluster anomalies into behavioral groups with adaptive parameters"""
    
    def __init__(self, min_cluster_size: int = 5, adaptive: bool = True, 
                 direct_classification_threshold: int = 10):
        """
        Initialize clusterer.
        
        Args:
            min_cluster_size: Minimum samples per cluster
            adaptive: Automatically adjust parameters for small datasets
            direct_classification_threshold: Use direct attack classification below this threshold
        """
        self.min_cluster_size = min_cluster_size
        self.adaptive = adaptive
        self.direct_classification_threshold = direct_classification_threshold
        self.clusterer = None
        self.is_fitted = False
        
    def cluster(self, anomaly_features: pd.DataFrame, feature_cols: list) -> pd.DataFrame:
        """
        Cluster anomalies into groups with adaptive parameters.
        For very small datasets, uses direct attack classification instead.
        
        Args:
            anomaly_features: DataFrame with features of anomalous events only
            feature_cols: Feature columns to use for clustering
            
        Returns:
            DataFrame with cluster assignments or attack type classifications
        """
        n_anomalies = len(anomaly_features)
        
        # For very small datasets, use direct attack type classification
        if n_anomalies <= self.direct_classification_threshold:
            return self._classify_attack_types(anomaly_features)
        
        # Adaptive minimum cluster size for larger datasets
        effective_min_cluster = self.min_cluster_size
        if self.adaptive:
            if n_anomalies < 10:
                effective_min_cluster = max(2, n_anomalies // 3)
            elif n_anomalies < 20:
                effective_min_cluster = max(3, n_anomalies // 4)
            else:
                effective_min_cluster = min(self.min_cluster_size, n_anomalies // 5)
        
        if n_anomalies < 2:
            # Not enough anomalies to cluster
            return pd.DataFrame({
                'Cluster': [-1] * n_anomalies,
                'ClusterLabel': ['Single Anomaly'] * n_anomalies
            })
        
        # Select most relevant features for clustering
        selected_features = self._select_clustering_features(anomaly_features, feature_cols)
        X = anomaly_features[selected_features].values
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Adaptive min_samples
        min_samples = max(1, min(3, effective_min_cluster // 2))
        
        # HDBSCAN clustering with adaptive parameters
        self.clusterer = HDBSCAN(
            min_cluster_size=effective_min_cluster,
            min_samples=min_samples,
            metric='euclidean',
            cluster_selection_epsilon=0.0,
            cluster_selection_method='eom'  # Excess of Mass for better small cluster detection
        )
        
        cluster_labels = self.clusterer.fit_predict(X_scaled)
        self.is_fitted = True
        
        # Create cluster interpretations
        cluster_names = self._interpret_clusters(anomaly_features, cluster_labels, selected_features)
        
        results = pd.DataFrame({
            'Cluster': cluster_labels,
            'ClusterLabel': [cluster_names.get(c, 'Unclustered') for c in cluster_labels]
        })
        
        return results
    
    def _select_clustering_features(self, df: pd.DataFrame, feature_cols: list) -> list:
        """
        Select most informative features for clustering.
        Prioritize high-variance features to improve cluster separation.
        """
        # Calculate variance for each feature
        variances = df[feature_cols].var()
        
        # Filter out low-variance features (keep top 70% or at least 10)
        threshold = variances.quantile(0.3)
        high_var_features = variances[variances > threshold].index.tolist()
        
        # Ensure we have at least some features
        if len(high_var_features) < 5 and len(feature_cols) >= 5:
            high_var_features = variances.nlargest(min(10, len(feature_cols))).index.tolist()
        elif len(high_var_features) == 0:
            high_var_features = feature_cols[:10]  # Fallback
        
        return high_var_features
    
    def _interpret_clusters(self, df: pd.DataFrame, labels: np.ndarray, 
                           feature_cols: list) -> Dict[int, str]:
        """
        Generate interpretable names for clusters based on dominant features.
        
        Args:
            df: DataFrame with anomaly features
            labels: Cluster labels
            feature_cols: Feature column names
            
        Returns:
            Dictionary mapping cluster_id -> cluster_name
        """
        cluster_names = {}
        
        unique_labels = set(labels)
        for label in unique_labels:
            if label == -1:
                cluster_names[label] = 'Unclustered'
                continue
            
            # Get samples in this cluster
            mask = labels == label
            cluster_df = df[mask]
            
            # Find dominant features (highest mean values)
            means = cluster_df[feature_cols].mean()
            top_features = means.nlargest(3).index.tolist()
            
            # Generate name from top features
            name_parts = []
            for feat in top_features:
                # Clean up feature name
                clean_name = feat.replace('_', ' ').replace('Is', '').replace('Has', '')
                name_parts.append(clean_name.strip())
            
            cluster_names[label] = f"Cluster {label}: {', '.join(name_parts[:2])}"
        
        return cluster_names
    
    def map_to_mitre_stages(self, cluster_labels: pd.DataFrame, 
                            features_df: pd.DataFrame) -> pd.DataFrame:
        """
        Map clusters to MITRE ATT&CK stages based on heuristics.
        
        Args:
            cluster_labels: DataFrame with cluster assignments
            features_df: DataFrame with full features
            
        Returns:
            DataFrame with MITRE stage mappings
        """
        mitre_stages = []
        
        for idx, row in cluster_labels.iterrows():
            cluster = row['Cluster']
            
            # Get feature values for this event
            features = features_df.loc[idx] if idx in features_df.index else {}
            
            # Heuristic mapping based on features (always attempt classification)
            stage = self._infer_mitre_stage(features)
            mitre_stages.append(stage)
        
        cluster_labels['MITRE_Stage'] = mitre_stages
        return cluster_labels
    
    def _infer_mitre_stage(self, features: pd.Series) -> str:
        """
        Enhanced MITRE ATT&CK stage inference using EventID knowledge base first,
        then falling back to feature-based pattern matching.
        """
        # FIRST: Use EventID knowledge base for accurate mapping
        event_id = features.get('EventID')
        channel = features.get('Channel', None)
        
        if pd.notna(event_id):
            try:
                event_id_int = int(event_id)
                mapper = get_mapper()
                
                # Get knowledge-based MITRE stage
                kb_stage = mapper.get_attack_stage_from_eventid(event_id_int, channel)
                
                # Get risk score for validation
                risk_score = mapper.calculate_risk_score(
                    event_id_int,
                    channel,
                    context={
                        'is_night_time': features.get('IsNightTime', 0) > 0,
                        'events_per_minute': features.get('EventsPerMinute', 0),
                        'failed_login_ratio': features.get('FailedLoginRatio', 0),
                        'has_powershell': features.get('LogHasPowerShell', 0) > 0,
                        'has_suspicious_content': features.get('LogHasSuspicious', 0) > 0
                    }
                )
                
                # High confidence: use knowledge base result if risk score is significant
                # (Don't rely solely on default fallback 'Execution' with low risk)
                if risk_score >= 6 or kb_stage != 'Stage 2: Execution':
                    return kb_stage
            except (ValueError, TypeError):
                pass
        
        # FALLBACK: Use feature-based scoring if EventID mapping unavailable
        scores = {
            'Initial Access': 0,
            'Execution': 0,
            'Persistence': 0,
            'Privilege Escalation': 0,
            'Defense Evasion': 0,
            'Credential Access': 0,
            'Discovery': 0,
            'Lateral Movement': 0,
            'Collection': 0,
            'Command and Control': 0,
            'Exfiltration': 0,
            'Impact': 0
        }
        
        # Initial Access indicators
        if features.get('IsFailedLogin', 0) > 0:
            scores['Initial Access'] += 5
        if features.get('FailedLoginRatio', 0) > 0.2:
            scores['Initial Access'] += 3
        if features.get('EventID') in [4625, 4648]:  # Failed logon, explicit credentials
            scores['Initial Access'] += 4
        if features.get('IsNightTime', 0) > 0 and features.get('IsFailedLogin', 0) > 0:
            scores['Initial Access'] += 2  # Night-time login attempts
        
        # Execution indicators
        if features.get('IsProcessCreation', 0) > 0:
            scores['Execution'] += 5
        if features.get('LogHasSuspicious', 0) > 0:
            scores['Execution'] += 4
        if features.get('EventID') in [1, 4688]:  # Sysmon/Windows process creation
            scores['Execution'] += 3
        if features.get('LogHasPowerShell', 0) > 0:
            scores['Execution'] += 6  # PowerShell is common in attacks
        if features.get('LogHasCmd', 0) > 0:
            scores['Execution'] += 3
        if features.get('LogHasScript', 0) > 0:
            scores['Execution'] += 4
        
        # Persistence indicators - ENHANCED to reduce Initial Access collision
        # Service-based persistence (CRITICAL)
        if features.get('EventID') in [7045, 4697]:  # Service installed
            scores['Persistence'] += 10  # Very strong indicator
        if features.get('EventID') in [7040]:  # Service startup type changed
            scores['Persistence'] += 8
        if features.get('EventID') in [7036]:  # Service state change
            scores['Persistence'] += 4
        
        # Scheduled Tasks (HIGH)
        if features.get('IsScheduledTask', 0) > 0:
            scores['Persistence'] += 9  # Increased from 6
        if features.get('EventID') in [4698, 106, 200, 201]:  # Task scheduler events
            scores['Persistence'] += 8
        
        # Registry persistence (HIGH)
        if features.get('IsRegistryModification', 0) > 0:
            scores['Persistence'] += 7  # Increased from 5
        if features.get('EventID') in [12, 13]:  # Sysmon registry events
            scores['Persistence'] += 8  # Increased from 5
        if features.get('EventID') == 4657:  # Windows registry modification
            scores['Persistence'] += 7
        
        # WMI persistence (CRITICAL)
        if features.get('EventID') in [19, 20, 21]:  # WMI filter/consumer/binding
            scores['Persistence'] += 10
        
        # Account-based persistence (HIGH)
        if features.get('EventID') == 4720:  # User account created
            scores['Persistence'] += 8
        if features.get('EventID') == 4722:  # User account enabled
            scores['Persistence'] += 7
        if features.get('EventID') == 4723:  # Password change attempt
            scores['Persistence'] += 6
        if features.get('EventID') == 4738:  # User account changed (flags, privileges)
            scores['Persistence'] += 7
        if features.get('EventID') == 4704:  # User right assigned (e.g., SeDebugPrivilege)
            scores['Persistence'] += 7
            scores['Privilege Escalation'] += 10  # STRONG privilege escalation indicator
            scores['Initial Access'] = 0  # NOT Initial Access - requires existing admin access
        if features.get('EventID') == 4717:  # System security access granted
            scores['Persistence'] += 7
            scores['Privilege Escalation'] += 9  # Strong privilege escalation
            scores['Initial Access'] = 0
        if features.get('EventID') in [4728, 4732, 4756]:  # Added to security group
            scores['Persistence'] += 8
        if features.get('EventID') in [4735, 4737, 4755]:  # Security group changed
            scores['Persistence'] += 7
            scores['Privilege Escalation'] += 7
        if features.get('EventID') == 4794:  # DSRM password set (DC backdoor)
            scores['Persistence'] += 10  # Critical persistence
            scores['Privilege Escalation'] += 10  # Critical privilege escalation
        
        # Driver/Kernel persistence (HIGH)
        if features.get('EventID') == 6:  # Driver loaded (Sysmon)
            scores['Persistence'] += 8
        
        # Process-based persistence (MEDIUM)
        if features.get('EventID') == 4688:  # Process creation
            # Add points if creating persistence mechanisms
            if (features.get('LogHasPowerShell', 0) > 0 or 
                features.get('LogHasCmd', 0) > 0 or 
                features.get('LogHasScript', 0) > 0):
                scores['Persistence'] += 4  # Could be creating persistence
        
        # File-based persistence (MEDIUM)
        if features.get('IsFileCreation', 0) > 0:
            # Check if in startup locations (need to check log content)
            if features.get('LogHasScript', 0) > 0:  # Script in startup
                scores['Persistence'] += 6
            else:
                scores['Persistence'] += 3
        if features.get('EventID') == 11:  # Sysmon file creation
            scores['Persistence'] += 5
        
        # Reduce Initial Access score if strong Persistence indicators present
        if (features.get('EventID') in [7045, 4697, 4720, 4723, 4738, 4704, 4705, 4717, 4718, 
                                        4735, 4737, 4755, 4794, 19, 20, 21] or 
            features.get('IsScheduledTask', 0) > 0):
            scores['Initial Access'] = max(0, scores['Initial Access'] - 3)
        
        # Privilege Escalation indicators
        if features.get('EventID') in [4672, 4673, 4674]:  # Special privileges
            scores['Privilege Escalation'] += 5
        if features.get('EventID') == 4704:  # User right assigned - additional boost here too
            scores['Privilege Escalation'] += 2  # Extra emphasis
        if features.get('EventID') == 4717:  # Security access granted - additional boost
            scores['Privilege Escalation'] += 2
        if features.get('EventID') == 8:  # Sysmon: CreateRemoteThread (process injection)
            scores['Privilege Escalation'] += 8
            scores['Defense Evasion'] += 6
        if features.get('EventID') == 10:  # Sysmon: ProcessAccess (LSASS access)
            scores['Privilege Escalation'] += 8
            scores['Credential Access'] += 9
        if features.get('LevelSeverity', 0) >= 4:  # Critical/Error events
            scores['Privilege Escalation'] += 2
        if features.get('EventID') == 4732:  # Member added to security group
            scores['Privilege Escalation'] += 6
        
        # Defense Evasion indicators
        if features.get('EventID') in [1102, 104, 1100]:  # Log clearing
            scores['Defense Evasion'] += 8
        if features.get('IsSecurityLogCleared', 0) > 0:
            scores['Defense Evasion'] += 10
        if features.get('EventID') == 4705:  # User right removed (disable monitoring)
            scores['Defense Evasion'] += 8  # Increased from 6
            scores['Privilege Escalation'] += 6  # Also indicates privilege operations
            scores['Initial Access'] = 0  # NOT Initial Access - requires existing admin access
        if features.get('EventID') == 4718:  # System security access removed
            scores['Defense Evasion'] += 7
            scores['Initial Access'] = 0
        if features.get('EventIDRarity', 0) > 0.8:  # Rare events
            scores['Defense Evasion'] += 3
        if features.get('IsNightTime', 0) > 0:
            scores['Defense Evasion'] += 1
        
        # Credential Access indicators
        if features.get('EventID') in [4624, 4625, 4768]:  # Logon/Kerberos TGT
            scores['Credential Access'] += 3
        if features.get('EventID') == 4769:  # Kerberos service ticket (Kerberoasting)
            scores['Credential Access'] += 6  # Increased for Kerberoasting
        if features.get('EventID') == 4771:  # Kerberos pre-auth failed (password spray)
            scores['Credential Access'] += 5
        if features.get('EventID') == 4776:  # NTLM authentication (Pass-the-Hash)
            scores['Credential Access'] += 6  # Increased from 4
            scores['Lateral Movement'] += 4
        if features.get('EventID') == 4656:  # Handle to object (LSASS, SAM access)
            scores['Credential Access'] += 7
        if features.get('EventID') == 4661:  # SAM/AD object access
            scores['Credential Access'] += 8  # High risk for credential theft
            scores['Discovery'] += 5
        if features.get('EventID') == 4662:  # AD operation (DCSync)
            scores['Credential Access'] += 9  # Critical - DCSync attack
            scores['Discovery'] += 4
        if features.get('EventID') == 4663:  # Object access (credential files)
            scores['Credential Access'] += 7
        if features.get('FailedLoginRatio', 0) > 0.5:
            scores['Credential Access'] += 5  # Password spraying/brute force
        
        # SQL Server credential access and attack indicators
        if features.get('EventID') == 18456:  # SQL login failed (brute force/spray)
            scores['Credential Access'] += 7
            scores['Initial Access'] += 4
        if features.get('EventID') == 18452:  # SQL login succeeded (after attacks)
            scores['Credential Access'] += 3
            scores['Initial Access'] += 3
        if features.get('EventID') == 18454:  # SQL account locked (brute force)
            scores['Credential Access'] += 8
        if features.get('EventID') in [229, 208]:  # SQL injection indicators
            scores['Credential Access'] += 6
            scores['Execution'] += 5
        if features.get('EventID') == 33210:  # SQL schema object access (credential tables)
            scores['Credential Access'] += 7
            scores['Collection'] += 6
        if features.get('EventID') == 33212:  # SQL principal management (backdoor)
            scores['Persistence'] += 9
            scores['Privilege Escalation'] += 8
        if features.get('EventID') == 15281:  # xp_cmdshell enabled (CRITICAL)
            scores['Execution'] += 10
            scores['Privilege Escalation'] += 9
        if features.get('EventID') == 15434:  # sa password change attempt
            scores['Persistence'] += 9
            scores['Credential Access'] += 8
        if features.get('EventID') in [15247, 33211]:  # SQL privilege escalation
            scores['Privilege Escalation'] += 7
        if features.get('EventID') in [17049, 17120]:  # SQL audit disabled
            scores['Defense Evasion'] += 9
        if features.get('EventID') == 3014:  # Database backup (exfiltration)
            scores['Collection'] += 6
            scores['Exfiltration'] += 5
        
        # Discovery indicators
        if features.get('UniqueIPCount', 0) > 3:
            scores['Discovery'] += 4
        if features.get('EventID') in [4798, 4799]:  # Group enumeration
            scores['Discovery'] += 5
        if features.get('IsNetworkConnection', 0) > 0:
            scores['Discovery'] += 2
        
        # Lateral Movement indicators
        if features.get('IsNetworkConnection', 0) > 0:
            scores['Lateral Movement'] += 3
        if features.get('UniqueIPCount', 0) > 5:
            scores['Lateral Movement'] += 6
        if features.get('EventID') in [3, 5156]:  # Network connections
            scores['Lateral Movement'] += 4
        if features.get('EventID') in [4624, 4648] and features.get('UniqueIPCount', 0) > 2:
            scores['Lateral Movement'] += 5  # Remote login from multiple IPs
        if features.get('EventID') == 4697:  # Service installation (PSExec)
            scores['Lateral Movement'] += 7
        
        # Collection indicators
        if features.get('EventID') in [11, 4663]:  # File access
            scores['Collection'] += 3
        if features.get('LogLength', 0) > 500:
            scores['Collection'] += 2
        
        # Command and Control indicators
        if features.get('IsNetworkConnection', 0) > 0 and features.get('EventsPerMinute', 0) > 10:
            scores['Command and Control'] += 5  # Beaconing behavior
        if features.get('EventID') == 3:  # Sysmon network connection
            scores['Command and Control'] += 3
        if features.get('IsNightTime', 0) > 0 and features.get('IsNetworkConnection', 0) > 0:
            scores['Command and Control'] += 3
        
        # Exfiltration indicators
        if features.get('LogLength', 0) > 1000:
            scores['Exfiltration'] += 4
        if features.get('IsNetworkConnection', 0) > 0 and features.get('LogLength', 0) > 500:
            scores['Exfiltration'] += 6
        if features.get('EventsPerMinute', 0) > 20:  # High data transfer rate
            scores['Exfiltration'] += 5
        
        # Impact indicators
        if features.get('EventID') in [1102, 104]:  # Log clearing
            scores['Impact'] += 5
        if features.get('LevelSeverity', 0) >= 4:
            scores['Impact'] += 2
        if features.get('EventID') == 4719:  # System audit policy change
            scores['Impact'] += 6
        
        # Find the stage with highest score
        # Always return best guess, even if scores are low or zero
        best_stage = max(scores.items(), key=lambda x: x[1])[0]
        
        # Map to simplified MITRE stages for display
        stage_mapping = {
            'Initial Access': 'Stage 1: Initial Access',
            'Execution': 'Stage 2: Execution',
            'Persistence': 'Stage 3: Persistence',
            'Privilege Escalation': 'Stage 3: Privilege Escalation',
            'Defense Evasion': 'Stage 3: Defense Evasion',
            'Credential Access': 'Stage 2: Credential Access',
            'Discovery': 'Stage 4: Discovery',
            'Lateral Movement': 'Stage 4: Lateral Movement',
            'Collection': 'Stage 5: Collection',
            'Command and Control': 'Stage 5: Command & Control',
            'Exfiltration': 'Stage 6: Exfiltration',
            'Impact': 'Stage 7: Impact'
        }
        
        return stage_mapping[best_stage]
    
    def _classify_attack_types(self, anomaly_features: pd.DataFrame) -> pd.DataFrame:
        """
        Direct attack type classification for small datasets.
        Uses pattern matching on parsed data instead of clustering.
        
        Args:
            anomaly_features: DataFrame with anomalous event features
            
        Returns:
            DataFrame with attack type classifications
        """
        attack_types = []
        cluster_labels = []
        
        for idx, row in anomaly_features.iterrows():
            attack_type, label = self._identify_attack_pattern(row)
            attack_types.append(attack_type)
            cluster_labels.append(label)
        
        results = pd.DataFrame({
            'Cluster': attack_types,
            'ClusterLabel': cluster_labels
        })
        
        return results
    
    def _identify_attack_pattern(self, features: pd.Series) -> Tuple[int, str]:
        """
        Identify specific attack pattern from event features.
        Uses EventID knowledge base for better accuracy.
        Returns attack type ID and descriptive label.
        """
        # FIRST: Check EventID knowledge base for high-confidence matches
        event_id = features.get('EventID')
        channel = features.get('Channel', None)
        
        if pd.notna(event_id):
            try:
                event_id_int = int(event_id)
                mapper = get_mapper()
                info = mapper.get_event_intelligence(event_id_int, channel)
                
                # Get context-aware risk score
                context = {
                    'is_night_time': features.get('IsNightTime', 0) > 0,
                    'events_per_minute': features.get('EventsPerMinute', 0),
                    'failed_login_ratio': features.get('FailedLoginRatio', 0),
                    'has_powershell': features.get('LogHasPowerShell', 0) > 0,
                    'has_suspicious_content': features.get('LogHasSuspicious', 0) > 0,
                    'is_failed_login': features.get('IsFailedLogin', 0) > 0,
                    'is_unusual': features.get('EventIDRarity', 0) > 0.8
                }
                risk_score = mapper.calculate_risk_score(event_id_int, channel, context)
                
                # Map EventID to attack pattern if confidence is high
                if risk_score >= 8:  # High confidence
                    event_name = info.get('name', '')
                    severity = info.get('severity', '')
                    
                    # Critical events
                    if event_id_int == 1102 or event_id_int == 104:
                        return (6, f"🛡️ Defense Evasion ({event_name})")
                    elif event_id_int == 4697 or event_id_int == 7045:
                        return (11, f"💉 Service Installation ({event_name})")
                    elif event_id_int == 4732 or event_id_int == 4728:
                        return (5, f"👑 Privilege Escalation ({event_name})")
                    elif event_id_int in [4698, 4699, 4700, 4701, 106]:
                        return (7, f"📌 Persistence ({event_name})")
                    elif event_id_int == 9:  # Sysmon RawAccessRead
                        return (8, "🔑 Credential Theft (LSASS Access)")
                    elif event_id_int == 10 and 'lsass' in str(features.get('TargetImage', '')).lower():
                        return (8, "🔑 Credential Theft (Process Access)")
                    elif event_id_int in [19, 20, 21]:  # WMI events
                        return (7, "📌 Persistence (WMI)")
            except (ValueError, TypeError):
                pass
        
        # SECOND: Analyze multiple indicators to determine attack type
        patterns = []
        
        # Pattern 1: Brute Force / Password Spray
        if features.get('IsFailedLogin', 0) > 0 or features.get('FailedLoginRatio', 0) > 0.3:
            score = 10
            if features.get('EventsPerMinute', 0) > 5:
                score += 5  # Rapid attempts
            if features.get('IsNightTime', 0) > 0:
                score += 3  # Night-time
            patterns.append((score, 1, '🔐 Brute Force Attack'))
        
        # Pattern 2: PowerShell Abuse / Malicious Script
        if features.get('LogHasPowerShell', 0) > 0:
            score = 10
            if features.get('LogHasBase64', 0) > 0:
                score += 5  # Encoded commands
            if features.get('LogHasSuspicious', 0) > 0:
                score += 5  # Known malicious patterns
            if features.get('LogEntropy', 0) > 4.5:
                score += 3  # High entropy = obfuscation
            patterns.append((score, 2, '💻 PowerShell Exploit'))
        
        # Pattern 3: Suspicious Process Execution
        if features.get('IsProcessCreation', 0) > 0:
            score = 8
            if features.get('LogHasCmd', 0) > 0:
                score += 3
            if features.get('LogHasSuspicious', 0) > 0:
                score += 5  # Suspicious commands
            if features.get('IsNightTime', 0) > 0:
                score += 2
            patterns.append((score, 3, '⚙️ Suspicious Process Execution'))
        
        # Pattern 4: Lateral Movement
        if features.get('UniqueIPCount', 0) > 3 or features.get('IsNetworkConnection', 0) > 0:
            score = 8
            if features.get('UniqueIPCount', 0) > 5:
                score += 5  # Many IPs
            if features.get('EventsPerMinute', 0) > 10:
                score += 3  # Rapid connections
            if features.get('IsSuccessfulLogin', 0) > 0:
                score += 4  # Remote login
            patterns.append((score, 4, '🌐 Lateral Movement'))
        
        # Pattern 5: Privilege Escalation
        if features.get('IsPrivilegeUse', 0) > 0 or features.get('IsGroupModification', 0) > 0:
            score = 10
            if features.get('LogHasPrivEsc', 0) > 0:
                score += 5  # Explicit priv esc indicators
            if features.get('EventID') == 4732:  # Group addition
                score += 5
            patterns.append((score, 5, '👑 Privilege Escalation'))
        
        # Pattern 6: Defense Evasion / Anti-Forensics
        if features.get('IsSecurityLogCleared', 0) > 0 or features.get('IsAuditPolicyChange', 0) > 0:
            score = 15  # Very suspicious
            if features.get('IsNightTime', 0) > 0:
                score += 5
            patterns.append((score, 6, '🛡️ Defense Evasion (Log Tampering)'))
        
        # Pattern 7: Persistence Mechanism
        if features.get('IsScheduledTask', 0) > 0 or features.get('IsRegistryModification', 0) > 0:
            score = 9
            if features.get('IsFileCreation', 0) > 0:
                score += 3
            if features.get('LogHasScript', 0) > 0:
                score += 4  # Script-based persistence
            patterns.append((score, 7, '📌 Persistence Establishment'))
        
        # Pattern 8: Credential Theft / Dumping
        if features.get('EventID') in [4776, 4768, 4769]:  # NTLM/Kerberos
            score = 8
            if features.get('FailedLoginRatio', 0) > 0.5:
                score += 4  # Many failures = credential stuffing
            if features.get('LogHasSuspicious', 0) > 0:
                score += 5  # Mimikatz, etc.
            patterns.append((score, 8, '🔑 Credential Theft'))
        
        # Pattern 9: Data Exfiltration
        if features.get('LogLength', 0) > 1000 and features.get('IsNetworkConnection', 0) > 0:
            score = 10
            if features.get('EventsPerMinute', 0) > 20:
                score += 5  # High throughput
            if features.get('IsNightTime', 0) > 0:
                score += 3
            patterns.append((score, 9, '📤 Data Exfiltration'))
        
        # Pattern 10: Network Reconnaissance
        if features.get('UniqueIPCount', 0) > 2 and features.get('EventsPerMinute', 0) > 8:
            score = 8
            if features.get('UniqueIPCount', 0) > 10:
                score += 5  # Scanning many targets
            patterns.append((score, 10, '🔍 Network Reconnaissance'))
        
        # Pattern 11: Service/DLL Injection
        if features.get('IsServiceInstalled', 0) > 0:
            score = 12  # Very suspicious (PSExec-like)
            if features.get('IsNightTime', 0) > 0:
                score += 3
            patterns.append((score, 11, '💉 Service Installation (PSExec)'))
        
        # Pattern 12: Rare/Anomalous Event
        if features.get('EventIDRarity', 0) > 0.8:
            score = 7
            if features.get('LevelSeverity', 0) >= 4:
                score += 3  # Critical/Error
            patterns.append((score, 12, '❓ Rare Event (Anomalous)'))
        
        # Pattern 13: Command & Control Beaconing
        if features.get('EventsPerMinute', 0) > 15 and features.get('IsNetworkConnection', 0) > 0:
            score = 9
            if features.get('IsNightTime', 0) > 0:
                score += 4
            patterns.append((score, 13, '📡 C2 Beaconing'))
        
        # Select highest scoring pattern
        if patterns:
            patterns.sort(reverse=True, key=lambda x: x[0])
            best_pattern = patterns[0]
            return (best_pattern[1], best_pattern[2])
        
        # Default: Generic anomaly
        return (0, '⚠️ Unclassified Anomaly')
