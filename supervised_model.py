"""
Supervised Anomaly Detection Model
Learns from labeled training data to detect specific attack patterns.
"""

import pandas as pd
import numpy as np
from typing import Dict, Any, Tuple, Optional, List
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
import joblib
from pathlib import Path
from training_data_manager import TrainingDataManager
from features import FeatureEngineer


class SupervisedAnomalyDetector:
    """Supervised learning model for anomaly detection with labeled data"""
    
    def __init__(self, model_type: str = 'random_forest'):
        """
        Initialize supervised anomaly detector.
        
        Args:
            model_type: 'random_forest' or 'gradient_boosting'
        """
        self.model_type = model_type
        self.classifier = None
        self.attack_type_classifier = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names = []
        self.is_fitted = False
        self.training_manager = TrainingDataManager()
        self.feature_engineer = FeatureEngineer()
        
    def train_from_dataset(self, dataset_name: str, 
                          test_size: float = 0.2,
                          validate: bool = True) -> Dict[str, Any]:
        """
        Train model from a labeled training dataset.
        
        Args:
            dataset_name: Name of the training dataset
            test_size: Proportion of data to use for testing
            validate: Whether to perform cross-validation
            
        Returns:
            Training metrics and results
        """
        # Load training data
        print(f"Loading training dataset: {dataset_name}")
        df, labels, attack_types = self.training_manager.get_training_dataframe(dataset_name)
        
        if df.empty:
            raise ValueError(f"Dataset {dataset_name} is empty")
        
        print(f"Loaded {len(df)} samples")
        print(f"Label distribution: {labels.value_counts().to_dict()}")
        
        # Extract features using FeatureEngineer
        print("Extracting features...")
        events = df.to_dict('records')
        features_df = self.feature_engineer.extract_features(events)
        ml_features, feature_cols = self.feature_engineer.get_ml_features(features_df)
        
        self.feature_names = feature_cols
        print(f"Extracted {len(feature_cols)} features")
        
        # Split data
        X_train, X_test, y_train, y_test, attack_train, attack_test = train_test_split(
            ml_features, labels, attack_types, 
            test_size=test_size, 
            random_state=42,
            stratify=labels
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train binary classifier (anomaly vs normal)
        print(f"\nTraining {self.model_type} binary classifier...")
        self.classifier = self._create_classifier()
        self.classifier.fit(X_train_scaled, y_train)
        
        # Predictions
        y_pred = self.classifier.predict(X_test_scaled)
        
        # Binary classification metrics
        binary_metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred, average='binary'),
            'classification_report': classification_report(y_test, y_pred, 
                                                          target_names=['Normal', 'Anomaly']),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
        }
        
        print("\n=== Binary Classification Results ===")
        print(f"Accuracy: {binary_metrics['accuracy']:.3f}")
        print(f"F1 Score: {binary_metrics['f1_score']:.3f}")
        print("\nClassification Report:")
        print(binary_metrics['classification_report'])
        
        # Train attack type classifier (for anomalies only)
        print("\nTraining attack type classifier...")
        anomaly_mask_train = y_train == 1
        anomaly_mask_test = y_test == 1
        
        if anomaly_mask_train.sum() > 0:
            X_anomaly_train = X_train_scaled[anomaly_mask_train]
            attack_train_filtered = attack_train[anomaly_mask_train]
            
            # Encode attack types
            self.label_encoder.fit(attack_train_filtered)
            attack_train_encoded = self.label_encoder.transform(attack_train_filtered)
            
            self.attack_type_classifier = self._create_classifier(n_classes=len(self.label_encoder.classes_))
            self.attack_type_classifier.fit(X_anomaly_train, attack_train_encoded)
            
            # Test attack type classification
            if anomaly_mask_test.sum() > 0:
                X_anomaly_test = X_test_scaled[anomaly_mask_test]
                attack_test_filtered = attack_test[anomaly_mask_test]
                attack_test_encoded = self.label_encoder.transform(attack_test_filtered)
                
                attack_pred = self.attack_type_classifier.predict(X_anomaly_test)
                
                attack_metrics = {
                    'accuracy': accuracy_score(attack_test_encoded, attack_pred),
                    'f1_score': f1_score(attack_test_encoded, attack_pred, average='weighted'),
                    'classification_report': classification_report(
                        attack_test_encoded, attack_pred,
                        target_names=self.label_encoder.classes_
                    )
                }
                
                print("\n=== Attack Type Classification Results ===")
                print(f"Accuracy: {attack_metrics['accuracy']:.3f}")
                print(f"F1 Score: {attack_metrics['f1_score']:.3f}")
                print("\nClassification Report:")
                print(attack_metrics['classification_report'])
            else:
                attack_metrics = {}
        else:
            attack_metrics = {}
            print("No anomalies in training set for attack type classification")
        
        # Cross-validation
        cv_scores = {}
        if validate and len(X_train) > 10:
            print("\nPerforming cross-validation...")
            cv_scores_binary = cross_val_score(
                self.classifier, X_train_scaled, y_train, 
                cv=min(5, len(X_train) // 2), 
                scoring='f1'
            )
            cv_scores['binary_cv_mean'] = cv_scores_binary.mean()
            cv_scores['binary_cv_std'] = cv_scores_binary.std()
            print(f"Binary CV F1 Score: {cv_scores['binary_cv_mean']:.3f} (+/- {cv_scores['binary_cv_std']:.3f})")
        
        # Feature importance
        feature_importance = self._get_feature_importance()
        
        self.is_fitted = True
        
        return {
            'binary_metrics': binary_metrics,
            'attack_type_metrics': attack_metrics,
            'cv_scores': cv_scores,
            'feature_importance': feature_importance,
            'n_train_samples': len(X_train),
            'n_test_samples': len(X_test),
            'n_features': len(feature_cols)
        }
    
    def _create_classifier(self, n_classes: Optional[int] = None):
        """Create classifier based on model type"""
        if self.model_type == 'random_forest':
            return RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            )
        elif self.model_type == 'gradient_boosting':
            return GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42
            )
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    def predict(self, features_df: pd.DataFrame, feature_cols: List[str]) -> pd.DataFrame:
        """
        Predict anomalies and attack types for new data.
        
        Args:
            features_df: DataFrame with features
            feature_cols: List of feature column names
            
        Returns:
            DataFrame with predictions
        """
        if not self.is_fitted:
            raise RuntimeError("Model not trained. Call train_from_dataset() first.")
        
        X = features_df[feature_cols].values
        X_scaled = self.scaler.transform(X)
        
        # Binary prediction (anomaly vs normal)
        anomaly_pred = self.classifier.predict(X_scaled)
        anomaly_proba = self.classifier.predict_proba(X_scaled)[:, 1]  # Probability of anomaly
        
        # Attack type prediction (for anomalies)
        attack_types = ['normal'] * len(anomaly_pred)
        attack_confidence = np.zeros(len(anomaly_pred))
        
        if self.attack_type_classifier is not None:
            anomaly_mask = anomaly_pred == 1
            if anomaly_mask.sum() > 0:
                X_anomalies = X_scaled[anomaly_mask]
                attack_pred_encoded = self.attack_type_classifier.predict(X_anomalies)
                attack_proba = self.attack_type_classifier.predict_proba(X_anomalies)
                
                # Decode attack types
                attack_pred = self.label_encoder.inverse_transform(attack_pred_encoded)
                
                # Get confidence (max probability)
                attack_conf = attack_proba.max(axis=1)
                
                # Fill in predictions for anomalies
                anomaly_indices = np.where(anomaly_mask)[0]
                for i, idx in enumerate(anomaly_indices):
                    attack_types[idx] = attack_pred[i]
                    attack_confidence[idx] = attack_conf[i]
        
        # Create results dataframe
        results = pd.DataFrame({
            'Anomaly': anomaly_pred,
            'AnomalyProbability': anomaly_proba,
            'AttackType': attack_types,
            'AttackConfidence': attack_confidence,
            'Confidence': self._calculate_confidence_level(anomaly_proba, attack_confidence)
        })
        
        return results
    
    def _calculate_confidence_level(self, anomaly_proba: np.ndarray, 
                                    attack_confidence: np.ndarray) -> np.ndarray:
        """Calculate overall confidence level (1=Low, 2=Medium, 3=High)"""
        confidence = np.ones(len(anomaly_proba), dtype=int)
        
        for i in range(len(anomaly_proba)):
            if anomaly_proba[i] > 0.8 and attack_confidence[i] > 0.7:
                confidence[i] = 3  # High
            elif anomaly_proba[i] > 0.6 and attack_confidence[i] > 0.5:
                confidence[i] = 2  # Medium
            else:
                confidence[i] = 1  # Low
        
        return confidence
    
    def _get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from trained classifier"""
        if not self.is_fitted or self.classifier is None:
            return {}
        
        if hasattr(self.classifier, 'feature_importances_'):
            importances = self.classifier.feature_importances_
            feature_imp = dict(zip(self.feature_names, importances))
            # Sort by importance
            feature_imp = dict(sorted(feature_imp.items(), key=lambda x: x[1], reverse=True))
            return feature_imp
        
        return {}
    
    def get_top_features(self, n: int = 10) -> List[Tuple[str, float]]:
        """
        Get top N most important features.
        
        Args:
            n: Number of top features to return
            
        Returns:
            List of (feature_name, importance) tuples
        """
        feature_imp = self._get_feature_importance()
        if not feature_imp:
            return []
        
        return list(feature_imp.items())[:n]
    
    def save_model(self, filepath: str):
        """Save trained model to disk"""
        if not self.is_fitted:
            raise RuntimeError("Model not trained. Nothing to save.")
        
        model_data = {
            'model_type': self.model_type,
            'classifier': self.classifier,
            'attack_type_classifier': self.attack_type_classifier,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'feature_names': self.feature_names,
            'is_fitted': self.is_fitted
        }
        
        joblib.dump(model_data, filepath)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load trained model from disk"""
        model_data = joblib.load(filepath)
        
        self.model_type = model_data['model_type']
        self.classifier = model_data['classifier']
        self.attack_type_classifier = model_data['attack_type_classifier']
        self.scaler = model_data['scaler']
        self.label_encoder = model_data['label_encoder']
        self.feature_names = model_data['feature_names']
        self.is_fitted = model_data['is_fitted']
        
        print(f"Model loaded from {filepath}")


class HybridAnomalyDetector:
    """
    Hybrid detector combining supervised and unsupervised learning.
    Uses supervised model when available, falls back to unsupervised.
    """
    
    def __init__(self, supervised_model: Optional[SupervisedAnomalyDetector] = None,
                 unsupervised_model = None):
        """
        Initialize hybrid detector.
        
        Args:
            supervised_model: Trained supervised model (optional)
            unsupervised_model: Unsupervised model (IsolationForest, etc.)
        """
        self.supervised_model = supervised_model
        self.unsupervised_model = unsupervised_model
        self.use_supervised = supervised_model is not None and supervised_model.is_fitted
        
    def predict(self, features_df: pd.DataFrame, feature_cols: List[str]) -> pd.DataFrame:
        """
        Predict using hybrid approach.
        
        Args:
            features_df: DataFrame with features
            feature_cols: List of feature column names
            
        Returns:
            DataFrame with predictions
        """
        if self.use_supervised:
            # Use supervised model
            results = self.supervised_model.predict(features_df, feature_cols)
        elif self.unsupervised_model is not None:
            # Fall back to unsupervised model
            results = self.unsupervised_model.predict(features_df, feature_cols)
        else:
            raise RuntimeError("No model available for prediction")
        
        return results
    
    def set_supervised_model(self, model: SupervisedAnomalyDetector):
        """Set or update supervised model"""
        self.supervised_model = model
        self.use_supervised = model.is_fitted
    
    def set_unsupervised_model(self, model):
        """Set or update unsupervised model"""
        self.unsupervised_model = model


if __name__ == "__main__":
    # Example usage
    print("=== Supervised Anomaly Detection Training ===\n")
    
    # Create sample dataset if it doesn't exist
    manager = TrainingDataManager()
    datasets = manager.list_datasets()
    
    if not any(ds['name'] == 'sample_anomalies' for ds in datasets):
        print("Creating sample dataset...")
        manager.create_sample_dataset()
    
    # Train supervised model
    detector = SupervisedAnomalyDetector(model_type='random_forest')
    
    try:
        metrics = detector.train_from_dataset('sample_anomalies', test_size=0.2)
        
        print("\n=== Training Complete ===")
        print(f"Trained on {metrics['n_train_samples']} samples")
        print(f"Tested on {metrics['n_test_samples']} samples")
        print(f"Using {metrics['n_features']} features")
        
        # Show top features
        print("\n=== Top 10 Most Important Features ===")
        top_features = detector.get_top_features(10)
        for i, (feature, importance) in enumerate(top_features, 1):
            print(f"{i}. {feature}: {importance:.4f}")
        
        # Save model
        detector.save_model('models/supervised_anomaly_detector.pkl')
        
    except Exception as e:
        print(f"Error during training: {e}")
        import traceback
        traceback.print_exc()
