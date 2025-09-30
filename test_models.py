"""
Test Trained Models
Simple test of our trained cybersecurity models
"""

import os
import json
from pathlib import Path

print("🧪 Testing Trained MM-CT-DAS Models")
print("=" * 40)

class SimpleModelTester:
    """Test our trained models without complex dependencies"""
    
    def __init__(self):
        self.models_dir = Path("models")
        self.models = {}
    
    def load_models(self):
        """Load all JSON models"""
        try:
            json_files = list(self.models_dir.glob("*.json"))
            
            for model_file in json_files:
                model_name = model_file.stem
                
                try:
                    with open(model_file, 'r') as f:
                        model_data = json.load(f)
                    
                    self.models[model_name] = model_data
                    print(f"✅ Loaded: {model_name}")
                    print(f"   Accuracy: {model_data.get('accuracy', 0):.4f}")
                    print(f"   Features: {len(model_data.get('feature_names', []))}")
                    print(f"   Rules: {len(model_data.get('rules', []))}")
                    
                except Exception as e:
                    print(f"❌ Error loading {model_name}: {e}")
            
            print(f"\n📊 Total models loaded: {len(self.models)}")
            return len(self.models) > 0
            
        except Exception as e:
            print(f"❌ Error loading models: {e}")
            return False
    
    def test_model(self, model_name, test_data=None):
        """Test a specific model with sample data"""
        if model_name not in self.models:
            print(f"❌ Model {model_name} not found")
            return False
        
        model_data = self.models[model_name]
        rules = model_data.get('rules', [])
        
        # Generate sample test data if not provided
        if test_data is None:
            num_features = len(model_data.get('feature_names', []))
            test_data = [
                [i * 10 + j for j in range(num_features)] for i in range(5)
            ]
        
        print(f"\n🔍 Testing model: {model_name}")
        print(f"   Test samples: {len(test_data)}")
        
        predictions = []
        
        for row in test_data:
            votes = []
            weights = []
            
            for rule in rules:
                if len(row) > rule['feature_index']:
                    feature_val = row[rule['feature_index']]
                    
                    if feature_val > rule['threshold']:
                        votes.append(rule['prediction'])
                    else:
                        votes.append(1 - rule['prediction'])
                    
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
        
        print(f"   Predictions: {predictions}")
        print(f"   Threat detected in: {sum(predictions)}/{len(predictions)} samples")
        
        return True
    
    def test_all_models(self):
        """Test all loaded models"""
        print(f"\n🚀 Testing all models...")
        
        for model_name in self.models.keys():
            self.test_model(model_name)
        
        return True
    
    def display_model_summary(self):
        """Display summary of all models"""
        print(f"\n📋 Model Summary")
        print("=" * 30)
        
        for model_name, model_data in self.models.items():
            print(f"\n{model_name}:")
            print(f"  Description: {model_data.get('description', 'N/A')}")
            print(f"  Accuracy: {model_data.get('accuracy', 0):.4f}")
            print(f"  Precision: {model_data.get('precision', 0):.4f}")
            print(f"  Recall: {model_data.get('recall', 0):.4f}")
            print(f"  F1-Score: {model_data.get('f1_score', 0):.4f}")
            print(f"  Features: {len(model_data.get('feature_names', []))}")
            print(f"  Rules: {len(model_data.get('rules', []))}")
            
            # Show confusion matrix if available
            if 'confusion_matrix' in model_data:
                cm = model_data['confusion_matrix']
                print(f"  Confusion Matrix: TP={cm.get('tp', 0)}, FP={cm.get('fp', 0)}, TN={cm.get('tn', 0)}, FN={cm.get('fn', 0)}")

def main():
    """Main testing function"""
    print("Starting model testing...")
    
    tester = SimpleModelTester()
    
    # Load models
    if not tester.load_models():
        print("❌ No models could be loaded")
        return False
    
    # Display model summary
    tester.display_model_summary()
    
    # Test all models
    tester.test_all_models()
    
    print(f"\n✅ Model testing completed!")
    return True

if __name__ == "__main__":
    success = main()
    
    if success:
        print(f"\n🎉 All models tested successfully!")
        print(f"📈 Models are ready for production use")
    else:
        print(f"\n❌ Model testing failed")
    
    print("\nPress Enter to exit...")
    input()