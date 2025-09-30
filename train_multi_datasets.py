"""
Multi-Dataset Training for MM-CT-DAS
Train models on all available cybersecurity datasets
"""

import os
import json
import csv
import random
from pathlib import Path

print("🚀 MM-CT-DAS Multi-Dataset Training")
print("=" * 45)

class CyberSecurityModel:
    """Enhanced cybersecurity model with domain knowledge"""
    
    def __init__(self, model_name):
        self.model_name = model_name
        self.rules = []
        self.feature_names = []
        self.accuracy = 0.0
        self.dataset_info = {}
    
    def train(self, X, y, feature_names, dataset_name):
        """Train model with cybersecurity-specific logic"""
        self.feature_names = feature_names
        self.dataset_info = {
            'dataset': dataset_name,
            'samples': len(X),
            'features': len(feature_names)
        }
        
        # Cybersecurity-specific feature importance
        important_features = self._identify_important_features(feature_names)
        
        # Create rules for important features
        for i, feature in enumerate(feature_names):
            values = [row[i] for row in X if len(row) > i and row[i] is not None]
            if not values:
                continue
                
            # Calculate statistics
            mean_val = sum(values) / len(values)
            sorted_values = sorted(values)
            median_val = sorted_values[len(sorted_values)//2]
            
            # Feature importance weight
            importance_weight = 2.0 if feature.lower() in important_features else 1.0
            
            # Create multiple thresholds for important features
            thresholds = [mean_val]
            if importance_weight > 1.0:
                q1 = sorted_values[len(sorted_values)//4]
                q3 = sorted_values[3*len(sorted_values)//4]
                thresholds.extend([q1, q3])
            
            for threshold in thresholds:
                # Determine prediction based on feature type and values
                prediction = self._determine_prediction(feature, threshold, mean_val, dataset_name)
                
                rule = {
                    'feature_index': i,
                    'feature_name': feature,
                    'threshold': threshold,
                    'prediction': prediction,
                    'importance': importance_weight,
                    'mean': mean_val,
                    'median': median_val
                }
                self.rules.append(rule)
        
        print(f"   Created {len(self.rules)} rules for {len(feature_names)} features")
    
    def _identify_important_features(self, feature_names):
        """Identify cybersecurity-relevant features"""
        important_keywords = [
            'bytes', 'packet', 'duration', 'count', 'rate', 'length', 
            'size', 'time', 'port', 'protocol', 'flow', 'connection',
            'attack', 'malware', 'threat', 'anomaly', 'suspicious'
        ]
        
        important_features = set()
        for feature in feature_names:
            feature_lower = feature.lower()
            for keyword in important_keywords:
                if keyword in feature_lower:
                    important_features.add(feature_lower)
                    break
        
        return important_features
    
    def _determine_prediction(self, feature_name, threshold, mean_val, dataset_name):
        """Determine prediction based on cybersecurity domain knowledge"""
        feature_lower = feature_name.lower()
        
        # Network intrusion patterns
        if 'bytes' in feature_lower or 'size' in feature_lower:
            return 1 if threshold > mean_val else 0  # High bytes = potential attack
        
        if 'count' in feature_lower or 'rate' in feature_lower:
            return 1 if threshold > mean_val else 0  # High counts = potential attack
        
        if 'duration' in feature_lower:
            return 1 if threshold > mean_val * 1.5 else 0  # Long duration = suspicious
        
        if 'port' in feature_lower:
            # Common attack ports
            if 20 <= threshold <= 25 or 53 <= threshold <= 80 or threshold == 443:
                return 0  # Normal services
            else:
                return 1  # Potentially malicious
        
        # Default behavior
        return 1 if random.random() > 0.4 else 0
    
    def predict(self, X):
        """Enhanced prediction with weighted voting"""
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
                    
                    weights.append(rule['importance'])
            
            # Weighted majority vote
            if votes and weights:
                weighted_sum = sum(vote * weight for vote, weight in zip(votes, weights))
                total_weight = sum(weights)
                prediction = 1 if weighted_sum > total_weight * 0.4 else 0
            else:
                prediction = 0
            
            predictions.append(prediction)
        
        return predictions

def load_dataset(file_path, max_rows=1000):
    """Load dataset with error handling"""
    try:
        print(f"   📁 Loading: {file_path}")
        
        data = []
        headers = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            
            # Get headers
            headers = next(reader)
            
            # Read data
            row_count = 0
            for row in reader:
                if row_count >= max_rows:
                    break
                
                # Process row
                processed_row = []
                for value in row:
                    try:
                        # Try numeric conversion
                        if '.' in value:
                            processed_row.append(float(value))
                        else:
                            processed_row.append(int(value))
                    except:
                        # Hash string values
                        processed_row.append(abs(hash(str(value))) % 10000)
                
                if len(processed_row) == len(headers):
                    data.append(processed_row)
                    row_count += 1
        
        print(f"      ✅ Loaded {len(data)} rows, {len(headers)} columns")
        return data, headers
        
    except Exception as e:
        print(f"      ❌ Error loading {file_path}: {e}")
        return None, None

def train_on_dataset(dataset_path, dataset_name, max_samples=800):
    """Train model on a specific dataset"""
    try:
        print(f"\n🎯 Training on {dataset_name}")
        
        # Load data
        data, headers = load_dataset(dataset_path, max_samples)
        if data is None:
            return None
        
        # Prepare features and target
        X = [row[:-1] for row in data]  # All but last column
        y = [int(row[-1] > 0) for row in data]  # Binary classification
        feature_names = headers[:-1]
        
        # Split data
        indices = list(range(len(X)))
        random.shuffle(indices)
        split_point = int(len(indices) * 0.8)
        
        train_indices = indices[:split_point]
        test_indices = indices[split_point:]
        
        X_train = [X[i] for i in train_indices]
        X_test = [X[i] for i in test_indices]
        y_train = [y[i] for i in train_indices]
        y_test = [y[i] for i in test_indices]
        
        print(f"   📊 Train: {len(X_train)}, Test: {len(X_test)}, Features: {len(feature_names)}")
        
        # Create and train model
        model = CyberSecurityModel(dataset_name)
        model.train(X_train, y_train, feature_names, dataset_name)
        
        # Test model
        y_pred = model.predict(X_test)
        correct = sum(1 for true, pred in zip(y_test, y_pred) if true == pred)
        accuracy = correct / len(y_test) if len(y_test) > 0 else 0.0
        model.accuracy = accuracy
        
        print(f"   🎯 Accuracy: {accuracy:.4f}")
        
        # Calculate additional metrics
        tp = sum(1 for true, pred in zip(y_test, y_pred) if true == 1 and pred == 1)
        fp = sum(1 for true, pred in zip(y_test, y_pred) if true == 0 and pred == 1)
        tn = sum(1 for true, pred in zip(y_test, y_pred) if true == 0 and pred == 0)
        fn = sum(1 for true, pred in zip(y_test, y_pred) if true == 1 and pred == 0)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        print(f"   📈 Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
        
        return {
            'model': model,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'features': len(feature_names),
            'confusion_matrix': {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn}
        }
        
    except Exception as e:
        print(f"   ❌ Training failed for {dataset_name}: {e}")
        return None

def main():
    """Train models on all available datasets"""
    print("Starting multi-dataset training...")
    
    # Define available datasets
    datasets = [
        {
            'path': 'data/Cyber Threat Detection/cyberfeddefender_dataset.csv',
            'name': 'cyber_threat_detection',
            'description': 'Cyber Threat Detection Dataset'
        },
        {
            'path': 'data/Network Intrusion Detection/Train_data.csv',
            'name': 'network_intrusion_train',
            'description': 'Network Intrusion Detection - Training'
        },
        {
            'path': 'data/Network Intrusion Detection/Test_data.csv',
            'name': 'network_intrusion_test',
            'description': 'Network Intrusion Detection - Testing'
        },
        {
            'path': 'data/Cyber Threat Data for New Malware Attacks/cyberthreat.csv',
            'name': 'malware_detection',
            'description': 'Malware Attack Detection'
        },
        {
            'path': 'data/UGRansome dataset/final(2).csv',
            'name': 'ransomware_detection',
            'description': 'Ransomware Detection'
        }
    ]
    
    # Create output directories
    os.makedirs("models", exist_ok=True)
    os.makedirs("results", exist_ok=True)
    
    trained_models = {}
    training_summary = {
        'total_datasets': len(datasets),
        'successful_trainings': 0,
        'failed_trainings': 0,
        'models': {}
    }
    
    # Train on each dataset
    for dataset_info in datasets:
        if os.path.exists(dataset_info['path']):
            result = train_on_dataset(
                dataset_info['path'], 
                dataset_info['name'], 
                max_samples=600
            )
            
            if result:
                trained_models[dataset_info['name']] = result
                training_summary['successful_trainings'] += 1
                training_summary['models'][dataset_info['name']] = {
                    'accuracy': result['accuracy'],
                    'precision': result['precision'],
                    'recall': result['recall'],
                    'f1_score': result['f1_score'],
                    'description': dataset_info['description']
                }
                
                # Save individual model
                model_data = {
                    'model_name': dataset_info['name'],
                    'description': dataset_info['description'],
                    'rules': result['model'].rules,
                    'feature_names': result['model'].feature_names,
                    'accuracy': result['accuracy'],
                    'precision': result['precision'],
                    'recall': result['recall'],
                    'f1_score': result['f1_score'],
                    'dataset_info': result['model'].dataset_info,
                    'confusion_matrix': result['confusion_matrix']
                }
                
                with open(f"models/{dataset_info['name']}_model.json", 'w') as f:
                    json.dump(model_data, f, indent=2)
                
            else:
                training_summary['failed_trainings'] += 1
        else:
            print(f"❌ Dataset not found: {dataset_info['path']}")
            training_summary['failed_trainings'] += 1
    
    # Save training summary
    with open("results/multi_dataset_training_summary.json", 'w') as f:
        json.dump(training_summary, f, indent=2)
    
    # Display results
    print(f"\n📊 Multi-Dataset Training Summary")
    print("=" * 50)
    print(f"Total datasets: {training_summary['total_datasets']}")
    print(f"Successful trainings: {training_summary['successful_trainings']}")
    print(f"Failed trainings: {training_summary['failed_trainings']}")
    
    if trained_models:
        print(f"\n🎯 Model Performance:")
        for name, metrics in training_summary['models'].items():
            print(f"\n{name}:")
            print(f"  Accuracy: {metrics['accuracy']:.4f}")
            print(f"  Precision: {metrics['precision']:.4f}")
            print(f"  Recall: {metrics['recall']:.4f}")
            print(f"  F1-Score: {metrics['f1_score']:.4f}")
    
    return len(trained_models) > 0

if __name__ == "__main__":
    success = main()
    
    if success:
        print(f"\n🎉 Multi-dataset training completed!")
        print(f"📁 Models saved in: models/")
        print(f"📊 Results saved in: results/")
    else:
        print(f"\n❌ No models were successfully trained")
    
    print("\nPress Enter to exit...")
    input()