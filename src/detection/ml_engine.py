"""
Machine Learning Engine for threat detection
Handles ML model loading, training, and inference
"""

import logging
import pickle
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import json

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


class CustomMLModel:
    """Custom ML model that works with our JSON-based trained models"""
    
    def __init__(self, model_data):
        self.model_name = model_data.get('model_name', 'unknown')
        self.rules = model_data.get('rules', [])
        self.feature_names = model_data.get('feature_names', [])
        self.accuracy = model_data.get('accuracy', 0.0)
        self.description = model_data.get('description', '')
    
    def predict(self, X):
        """Make predictions using rule-based logic"""
        if isinstance(X, pd.DataFrame):
            X = X.values.tolist()
        elif isinstance(X, np.ndarray):
            X = X.tolist()
        
        predictions = []
        
        for row in X:
            votes = []
            weights = []
            
            for rule in self.rules:
                if len(row) > rule['feature_index']:
                    feature_val = row[rule['feature_index']]
                    
                    if feature_val > rule['threshold']:
                        votes.append(rule['prediction'])
                    else:
                        votes.append(1 - rule['prediction'])
                    
                    # Use importance weight if available
                    weight = rule.get('importance', 1.0)
                    weights.append(weight)
            
            # Weighted majority vote
            if votes and weights:
                weighted_sum = sum(vote * weight for vote, weight in zip(votes, weights))
                total_weight = sum(weights)
                prediction = 1 if weighted_sum > total_weight * 0.4 else 0
            else:
                prediction = 0
            
            predictions.append(prediction)
        
        return predictions
    
    def predict_proba(self, X):
        """Return prediction probabilities"""
        predictions = self.predict(X)
        # Convert binary predictions to probabilities
        probabilities = []
        for pred in predictions:
            if pred == 1:
                probabilities.append([0.3, 0.7])  # High confidence in positive class
            else:
                probabilities.append([0.7, 0.3])  # High confidence in negative class
        
        return np.array(probabilities)


class MLEngine:
    """Machine Learning engine for threat detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        self.models_path = Path(config.get('ml_models_path', 'models/'))
        self.threshold = config.get('threat_threshold', 0.7)
        
        # Initialize models
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        
        # Feature columns for network packet analysis
        self.network_features = [
            'packet_length', 'payload_size', 'src_port', 'dst_port',
            'protocol_encoded', 'tcp_flags', 'ttl', 'inter_arrival_time'
        ]
        
    async def start(self):
        """Initialize ML engine"""
        try:
            self.logger.info("Starting ML Engine...")
            
            # Ensure models directory exists
            self.models_path.mkdir(exist_ok=True)
            
            # Load existing models
            await self._load_models()
            
            # Initialize default models if none exist
            if not self.models:
                await self._initialize_default_models()
            
            self.logger.info("ML Engine started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting ML Engine: {e}")
            raise
    
    async def _load_models(self):
        """Load existing ML models from disk"""
        try:
            # Load JSON models (from our custom training)
            json_model_files = list(self.models_path.glob('*.json'))
            
            for model_file in json_model_files:
                model_name = model_file.stem
                
                try:
                    with open(model_file, 'r') as f:
                        model_data = json.load(f)
                    
                    # Create model object from JSON data
                    self.models[model_name] = CustomMLModel(model_data)
                    self.feature_names[model_name] = model_data.get('feature_names', [])
                    
                    self.logger.info(f"Loaded JSON model: {model_name}")
                    
                except Exception as e:
                    self.logger.error(f"Error loading JSON model {model_name}: {e}")
            
            # Also try to load joblib models (for sklearn compatibility)
            model_files = list(self.models_path.glob('*.pkl'))
            
            for model_file in model_files:
                model_name = model_file.stem
                
                try:
                    # Load with joblib (compatible with training script)
                    model_data = joblib.load(model_file)
                    
                    self.models[model_name] = model_data['model']
                    if 'scaler' in model_data:
                        self.scalers[model_name] = model_data['scaler']
                    if 'encoder' in model_data:
                        self.encoders[model_name] = model_data['encoder']
                    
                    # Log model info
                    accuracy = model_data.get('accuracy', 'N/A')
                    self.logger.info(f"Loaded model: {model_name} (Accuracy: {accuracy})")
                    
                except Exception as e:
                    self.logger.error(f"Error loading model {model_name}: {e}")
            
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
    
    async def _initialize_default_models(self):
        """Initialize default ML models"""
        try:
            self.logger.info("Initializing default ML models...")
            
            # Anomaly Detection Model (Isolation Forest)
            anomaly_model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            
            # Classification Model (Random Forest)
            classifier_model = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                n_jobs=-1
            )
            
            # Store models
            self.models['anomaly_detector'] = anomaly_model
            self.models['threat_classifier'] = classifier_model
            
            # Initialize scalers
            self.scalers['anomaly_detector'] = StandardScaler()
            self.scalers['threat_classifier'] = StandardScaler()
            
            # Initialize encoders
            self.encoders['threat_classifier'] = LabelEncoder()
            
            self.logger.info("Default models initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing default models: {e}")
    
    async def analyze_packet(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze packet for threats using ML models"""
        try:
            # Extract features from packet
            features = self._extract_features(packet_info)
            
            if not features:
                return {'threat_detected': False, 'confidence': 0.0}
            
            results = {}
            
            # Run anomaly detection
            if 'anomaly_detector' in self.models:
                anomaly_result = await self._run_anomaly_detection(features)
                results['anomaly'] = anomaly_result
            
            # Run classification if we have a trained classifier
            if 'threat_classifier' in self.models:
                classification_result = await self._run_classification(features)
                results['classification'] = classification_result
            
            # Combine results
            final_result = self._combine_results(results)
            
            return final_result
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")
            return {'threat_detected': False, 'confidence': 0.0, 'error': str(e)}
    
    def _extract_features(self, packet_info: Dict[str, Any]) -> Optional[np.ndarray]:
        """Extract numerical features from packet info"""
        try:
            features = []
            
            # Packet length
            features.append(packet_info.get('length', 0))
            
            # Payload size
            features.append(packet_info.get('payload_size', 0))
            
            # Source port
            features.append(packet_info.get('src_port', 0))
            
            # Destination port
            features.append(packet_info.get('dst_port', 0))
            
            # Protocol encoding (simple)
            protocol = packet_info.get('protocol', '').lower()
            protocol_map = {'tcp': 1, 'udp': 2, 'icmp': 3, 'http': 4, 'https': 5}
            features.append(protocol_map.get(protocol, 0))
            
            # TCP flags (if available)
            features.append(packet_info.get('tcp_flags', 0))
            
            # TTL
            features.append(packet_info.get('ttl', 0))
            
            # Inter-arrival time (simplified)
            features.append(0)  # Would need packet timing for real implementation
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            return None
    
    async def _run_anomaly_detection(self, features: np.ndarray) -> Dict[str, Any]:
        """Run anomaly detection on features"""
        try:
            model = self.models['anomaly_detector']
            scaler = self.scalers.get('anomaly_detector')
            
            # Scale features if scaler is available
            if scaler:
                features_scaled = scaler.transform(features)
            else:
                features_scaled = features
            
            # Predict anomaly
            anomaly_score = model.decision_function(features_scaled)[0]
            is_anomaly = model.predict(features_scaled)[0] == -1
            
            # Convert score to confidence (0-1 range)
            confidence = abs(anomaly_score) / 2.0  # Rough conversion
            confidence = min(max(confidence, 0.0), 1.0)
            
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': float(anomaly_score),
                'confidence': float(confidence)
            }
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
            return {'is_anomaly': False, 'confidence': 0.0}
    
    async def _run_classification(self, features: np.ndarray) -> Dict[str, Any]:
        """Run threat classification on features"""
        try:
            model = self.models['threat_classifier']
            scaler = self.scalers.get('threat_classifier')
            
            # Scale features if scaler is available
            if scaler:
                features_scaled = scaler.transform(features)
            else:
                features_scaled = features
            
            # Predict threat class and probability
            prediction = model.predict(features_scaled)[0]
            probabilities = model.predict_proba(features_scaled)[0]
            
            max_prob = max(probabilities)
            
            return {
                'predicted_class': int(prediction),
                'confidence': float(max_prob),
                'probabilities': probabilities.tolist()
            }
            
        except Exception as e:
            self.logger.error(f"Error in classification: {e}")
            return {'predicted_class': 0, 'confidence': 0.0}
    
    def _combine_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Combine results from different models"""
        threat_detected = False
        max_confidence = 0.0
        threat_type = 'unknown'
        details = {}
        
        # Check anomaly detection
        if 'anomaly' in results:
            anomaly = results['anomaly']
            if anomaly.get('is_anomaly', False):
                threat_detected = True
                max_confidence = max(max_confidence, anomaly.get('confidence', 0))
                threat_type = 'anomaly'
            details['anomaly'] = anomaly
        
        # Check classification
        if 'classification' in results:
            classification = results['classification']
            class_confidence = classification.get('confidence', 0)
            if class_confidence > self.threshold:
                threat_detected = True
                max_confidence = max(max_confidence, class_confidence)
                threat_type = f"class_{classification.get('predicted_class', 0)}"
            details['classification'] = classification
        
        return {
            'threat_detected': threat_detected,
            'confidence': max_confidence,
            'threat_type': threat_type,
            'details': details
        }
    
    async def train_model(self, model_name: str, training_data: pd.DataFrame, 
                         labels: pd.Series = None):
        """Train or retrain a model"""
        try:
            self.logger.info(f"Training model: {model_name}")
            
            if model_name == 'anomaly_detector':
                await self._train_anomaly_detector(training_data)
            elif model_name == 'threat_classifier':
                await self._train_classifier(training_data, labels)
            else:
                raise ValueError(f"Unknown model: {model_name}")
            
            # Save model
            await self._save_model(model_name)
            
            self.logger.info(f"Model {model_name} trained successfully")
            
        except Exception as e:
            self.logger.error(f"Error training model {model_name}: {e}")
            raise
    
    async def _train_anomaly_detector(self, data: pd.DataFrame):
        """Train anomaly detection model"""
        # Prepare features
        features = data[self.network_features].fillna(0)
        
        # Scale features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # Train model
        model = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
        model.fit(features_scaled)
        
        # Store model and scaler
        self.models['anomaly_detector'] = model
        self.scalers['anomaly_detector'] = scaler
    
    async def _train_classifier(self, data: pd.DataFrame, labels: pd.Series):
        """Train classification model"""
        # Prepare features
        features = data[self.network_features].fillna(0)
        
        # Encode labels
        encoder = LabelEncoder()
        labels_encoded = encoder.fit_transform(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels_encoded, test_size=0.2, random_state=42
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        self.logger.info(f"Classification model accuracy: {accuracy:.3f}")
        
        # Store model, scaler, and encoder
        self.models['threat_classifier'] = model
        self.scalers['threat_classifier'] = scaler
        self.encoders['threat_classifier'] = encoder
    
    async def _save_model(self, model_name: str):
        """Save model to disk"""
        try:
            model_data = {
                'model': self.models[model_name]
            }
            
            if model_name in self.scalers:
                model_data['scaler'] = self.scalers[model_name]
            
            if model_name in self.encoders:
                model_data['encoder'] = self.encoders[model_name]
            
            model_file = self.models_path / f"{model_name}.pkl"
            
            with open(model_file, 'wb') as f:
                pickle.dump(model_data, f)
            
            self.logger.info(f"Model saved: {model_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving model {model_name}: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get ML engine status"""
        return {
            'models_loaded': list(self.models.keys()),
            'models_count': len(self.models),
            'threshold': self.threshold
        }
    
    async def shutdown(self):
        """Shutdown ML engine"""
        self.logger.info("ML Engine shutdown complete")