"""
Data Processing Module for MM-CT-DAS
Handles data preprocessing, feature engineering, and dataset management
"""

import pandas as pd
import numpy as np
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import json
from datetime import datetime
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectKBest, chi2, f_classif
import warnings
warnings.filterwarnings('ignore')


class DataProcessor:
    """Main data processing class for cybersecurity datasets"""
    
    def __init__(self, data_dir: str = "data", output_dir: str = "processed_data"):
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
        
        # Data storage
        self.datasets = {}
        self.processed_datasets = {}
        self.scalers = {}
        self.encoders = {}
        
        # Feature engineering parameters
        self.network_features = [
            'duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
            'same_srv_rate', 'diff_srv_rate', 'dst_host_count'
        ]
        
        self.threat_features = [
            'Packet_Length', 'Duration', 'Bytes_Sent', 'Bytes_Received',
            'Flow_Packets/s', 'Flow_Bytes/s', 'Avg_Packet_Size'
        ]
    
    def load_all_datasets(self) -> Dict[str, pd.DataFrame]:
        """Load all available cybersecurity datasets"""
        self.logger.info("Loading all cybersecurity datasets...")
        
        try:
            # Network Intrusion Detection
            self._load_network_intrusion_data()
            
            # Cyber Threat Detection  
            self._load_cyber_threat_data()
            
            # Malware Detection
            self._load_malware_data()
            
            # Ransomware Detection
            self._load_ransomware_data()
            
            self.logger.info(f"Successfully loaded {len(self.datasets)} datasets")
            return self.datasets
            
        except Exception as e:
            self.logger.error(f"Error loading datasets: {e}")
            return {}
    
    def _load_network_intrusion_data(self):
        """Load and preprocess network intrusion detection dataset"""
        try:
            train_path = self.data_dir / "Network Intrusion Detection" / "Train_data.csv"
            test_path = self.data_dir / "Network Intrusion Detection" / "Test_data.csv"
            
            if train_path.exists():
                # Load training data
                train_df = pd.read_csv(train_path)
                self.logger.info(f"Loaded network intrusion training data: {train_df.shape}")
                
                # Load test data if available
                test_df = None
                if test_path.exists():
                    test_df = pd.read_csv(test_path)
                    self.logger.info(f"Loaded network intrusion test data: {test_df.shape}")
                
                self.datasets['network_intrusion'] = {
                    'train': train_df,
                    'test': test_df,
                    'type': 'classification',
                    'target_column': 'class'
                }
                
        except Exception as e:
            self.logger.error(f"Error loading network intrusion data: {e}")
    
    def _load_cyber_threat_data(self):
        """Load cyber threat detection dataset"""
        try:
            data_path = self.data_dir / "Cyber Threat Detection" / "cyberfeddefender_dataset.csv"
            
            if data_path.exists():
                df = pd.read_csv(data_path)
                self.logger.info(f"Loaded cyber threat data: {df.shape}")
                
                self.datasets['cyber_threat'] = {
                    'data': df,
                    'type': 'classification',
                    'target_column': 'Label'
                }
                
        except Exception as e:
            self.logger.error(f"Error loading cyber threat data: {e}")
    
    def _load_malware_data(self):
        """Load malware detection dataset"""
        try:
            data_path = self.data_dir / "Cyber Threat Data for New Malware Attacks" / "cyberthreat.csv"
            
            if data_path.exists():
                df = pd.read_csv(data_path)
                self.logger.info(f"Loaded malware data: {df.shape}")
                
                self.datasets['malware'] = {
                    'data': df,
                    'type': 'classification',
                    'target_column': self._detect_target_column(df)
                }
                
        except Exception as e:
            self.logger.error(f"Error loading malware data: {e}")
    
    def _load_ransomware_data(self):
        """Load ransomware detection dataset"""
        try:
            data_path = self.data_dir / "UGRansome dataset" / "final(2).csv"
            
            if data_path.exists():
                df = pd.read_csv(data_path)
                self.logger.info(f"Loaded ransomware data: {df.shape}")
                
                self.datasets['ransomware'] = {
                    'data': df,
                    'type': 'classification',
                    'target_column': self._detect_target_column(df)
                }
                
        except Exception as e:
            self.logger.error(f"Error loading ransomware data: {e}")
    
    def _detect_target_column(self, df: pd.DataFrame) -> str:
        """Automatically detect the target column in a dataset"""
        # Common target column names
        possible_targets = [
            'label', 'Label', 'target', 'Target', 'class', 'Class',
            'attack', 'Attack', 'malware', 'Malware', 'threat', 'Threat'
        ]
        
        for col in possible_targets:
            if col in df.columns:
                return col
        
        # If no obvious target, use last column
        return df.columns[-1]
    
    def preprocess_dataset(self, dataset_name: str, sample_size: Optional[int] = None) -> Dict[str, Any]:
        """Preprocess a specific dataset"""
        if dataset_name not in self.datasets:
            raise ValueError(f"Dataset {dataset_name} not found")
        
        self.logger.info(f"Preprocessing dataset: {dataset_name}")
        
        dataset_info = self.datasets[dataset_name]
        
        if 'train' in dataset_info:
            # Handle train/test split datasets
            processed_data = self._preprocess_train_test_dataset(dataset_info, sample_size)
        else:
            # Handle single dataset
            processed_data = self._preprocess_single_dataset(dataset_info, sample_size)
        
        self.processed_datasets[dataset_name] = processed_data
        
        return processed_data
    
    def _preprocess_single_dataset(self, dataset_info: Dict, sample_size: Optional[int]) -> Dict[str, Any]:
        """Preprocess a single dataset"""
        df = dataset_info['data'].copy()
        target_col = dataset_info['target_column']
        
        # Sample data if requested
        if sample_size and len(df) > sample_size:
            df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)
            self.logger.info(f"Sampled {sample_size} rows from dataset")
        
        # Basic cleaning
        df = self._clean_dataset(df)
        
        # Feature engineering
        df = self._engineer_features(df)
        
        # Prepare features and target
        X, y = self._prepare_features_and_target(df, target_col)
        
        # Split into train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        return {
            'X_train': X_train,
            'X_test': X_test,
            'y_train': y_train,
            'y_test': y_test,
            'feature_names': X.columns.tolist(),
            'target_name': target_col,
            'original_shape': dataset_info['data'].shape,
            'processed_shape': df.shape
        }
    
    def _preprocess_train_test_dataset(self, dataset_info: Dict, sample_size: Optional[int]) -> Dict[str, Any]:
        """Preprocess dataset that already has train/test split"""
        train_df = dataset_info['train'].copy()
        test_df = dataset_info['test'].copy() if dataset_info['test'] is not None else None
        target_col = dataset_info['target_column']
        
        # Sample training data if requested
        if sample_size and len(train_df) > sample_size:
            train_df = train_df.sample(n=sample_size, random_state=42).reset_index(drop=True)
        
        # Clean datasets
        train_df = self._clean_dataset(train_df)
        if test_df is not None:
            test_df = self._clean_dataset(test_df)
        
        # Feature engineering
        train_df = self._engineer_features(train_df)
        if test_df is not None:
            test_df = self._engineer_features(test_df)
        
        # Prepare features and target
        X_train, y_train = self._prepare_features_and_target(train_df, target_col)
        
        if test_df is not None:
            X_test, y_test = self._prepare_features_and_target(test_df, target_col)
            # Ensure test set has same features as training set
            X_test = X_test.reindex(columns=X_train.columns, fill_value=0)
        else:
            # Create test split from training data
            X_train, X_test, y_train, y_test = train_test_split(
                X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
            )
        
        return {
            'X_train': X_train,
            'X_test': X_test,
            'y_train': y_train,
            'y_test': y_test,
            'feature_names': X_train.columns.tolist(),
            'target_name': target_col,
            'original_shape': train_df.shape,
            'processed_shape': train_df.shape
        }
    
    def _clean_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Basic dataset cleaning"""
        # Remove duplicate rows
        initial_rows = len(df)
        df = df.drop_duplicates()
        if len(df) < initial_rows:
            self.logger.info(f"Removed {initial_rows - len(df)} duplicate rows")
        
        # Handle missing values
        # Fill numeric columns with median
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            if df[col].isnull().sum() > 0:
                df[col].fillna(df[col].median(), inplace=True)
        
        # Fill categorical columns with mode
        categorical_cols = df.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            if df[col].isnull().sum() > 0:
                mode_value = df[col].mode()
                if len(mode_value) > 0:
                    df[col].fillna(mode_value[0], inplace=True)
                else:
                    df[col].fillna('unknown', inplace=True)
        
        return df
    
    def _engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Feature engineering for cybersecurity data"""
        df = df.copy()
        
        try:
            # Time-based features if timestamp exists
            time_cols = [col for col in df.columns if 'time' in col.lower() or 'timestamp' in col.lower()]
            for col in time_cols:
                if df[col].dtype == 'object':
                    try:
                        df[col] = pd.to_datetime(df[col])
                        df[f'{col}_hour'] = df[col].dt.hour
                        df[f'{col}_minute'] = df[col].dt.minute
                        df[f'{col}_dayofweek'] = df[col].dt.dayofweek
                    except:
                        pass
            
            # Network traffic features
            if 'src_bytes' in df.columns and 'dst_bytes' in df.columns:
                df['total_bytes'] = df['src_bytes'] + df['dst_bytes']
                df['bytes_ratio'] = df['src_bytes'] / (df['dst_bytes'] + 1)
            
            if 'duration' in df.columns and 'total_bytes' in df.columns:
                df['bytes_per_second'] = df['total_bytes'] / (df['duration'] + 1)
            
            # Port-based features
            port_cols = [col for col in df.columns if 'port' in col.lower()]
            for col in port_cols:
                if df[col].dtype in ['int64', 'float64']:
                    # Categorize ports
                    df[f'{col}_category'] = pd.cut(
                        df[col],
                        bins=[0, 1024, 49152, 65536],
                        labels=['system', 'registered', 'dynamic'],
                        include_lowest=True
                    ).astype(str)
            
            # IP address features (simplified)
            ip_cols = [col for col in df.columns if 'ip' in col.lower()]
            for col in ip_cols:
                if df[col].dtype == 'object':
                    # Extract last octet as a simple feature
                    try:
                        df[f'{col}_last_octet'] = df[col].str.split('.').str[-1].astype(int)
                    except:
                        pass
            
            # Protocol encoding
            protocol_cols = [col for col in df.columns if 'protocol' in col.lower()]
            for col in protocol_cols:
                if df[col].dtype == 'object':
                    le = LabelEncoder()
                    df[f'{col}_encoded'] = le.fit_transform(df[col].astype(str))
            
        except Exception as e:
            self.logger.warning(f"Feature engineering warning: {e}")
        
        return df
    
    def _prepare_features_and_target(self, df: pd.DataFrame, target_col: str) -> Tuple[pd.DataFrame, pd.Series]:
        """Prepare features and target variables"""
        # Handle target variable
        if target_col in df.columns:
            y = df[target_col].copy()
            
            # Convert target to binary if needed
            if df[target_col].dtype == 'object':
                if target_col == 'class':
                    # Network intrusion: normal vs attack
                    y = (y != 'normal').astype(int)
                else:
                    # Other datasets: encode labels
                    le = LabelEncoder()
                    y = le.fit_transform(y)
            
            # Remove target from features
            df = df.drop(columns=[target_col])
        else:
            raise ValueError(f"Target column '{target_col}' not found in dataset")
        
        # Select numeric features only
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        # Encode categorical features
        categorical_cols = df.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            try:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
                numeric_cols = numeric_cols.union([col])
            except:
                pass
        
        X = df[numeric_cols].copy()
        
        # Handle infinite values
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(0)
        
        return X, y
    
    def scale_features(self, dataset_name: str, scaler_type: str = 'standard') -> Dict[str, Any]:
        """Scale features for a processed dataset"""
        if dataset_name not in self.processed_datasets:
            raise ValueError(f"Processed dataset {dataset_name} not found")
        
        data = self.processed_datasets[dataset_name]
        
        # Choose scaler
        if scaler_type == 'standard':
            scaler = StandardScaler()
        elif scaler_type == 'minmax':
            scaler = MinMaxScaler()
        else:
            raise ValueError(f"Unknown scaler type: {scaler_type}")
        
        # Fit on training data and transform both train and test
        X_train_scaled = scaler.fit_transform(data['X_train'])
        X_test_scaled = scaler.transform(data['X_test'])
        
        # Store scaler
        self.scalers[dataset_name] = scaler
        
        # Update processed dataset
        self.processed_datasets[dataset_name].update({
            'X_train_scaled': pd.DataFrame(X_train_scaled, columns=data['feature_names']),
            'X_test_scaled': pd.DataFrame(X_test_scaled, columns=data['feature_names']),
            'scaler': scaler,
            'scaler_type': scaler_type
        })
        
        self.logger.info(f"Applied {scaler_type} scaling to {dataset_name}")
        
        return self.processed_datasets[dataset_name]
    
    def select_features(self, dataset_name: str, k_best: int = 20, method: str = 'f_classif') -> Dict[str, Any]:
        """Feature selection for a processed dataset"""
        if dataset_name not in self.processed_datasets:
            raise ValueError(f"Processed dataset {dataset_name} not found")
        
        data = self.processed_datasets[dataset_name]
        
        # Choose selection method
        if method == 'f_classif':
            selector = SelectKBest(score_func=f_classif, k=k_best)
        elif method == 'chi2':
            selector = SelectKBest(score_func=chi2, k=k_best)
        else:
            raise ValueError(f"Unknown feature selection method: {method}")
        
        # Use scaled features if available, otherwise original features
        X_train = data.get('X_train_scaled', data['X_train'])
        X_test = data.get('X_test_scaled', data['X_test'])
        
        # Fit selector and transform features
        X_train_selected = selector.fit_transform(X_train, data['y_train'])
        X_test_selected = selector.transform(X_test)
        
        # Get selected feature names
        selected_features = [data['feature_names'][i] for i in selector.get_support(indices=True)]
        
        # Update processed dataset
        self.processed_datasets[dataset_name].update({
            'X_train_selected': pd.DataFrame(X_train_selected, columns=selected_features),
            'X_test_selected': pd.DataFrame(X_test_selected, columns=selected_features),
            'selected_features': selected_features,
            'feature_selector': selector,
            'selection_method': method
        })
        
        self.logger.info(f"Selected {len(selected_features)} features for {dataset_name}")
        
        return self.processed_datasets[dataset_name]
    
    def save_processed_data(self, dataset_name: str, format: str = 'csv'):
        """Save processed dataset to disk"""
        if dataset_name not in self.processed_datasets:
            raise ValueError(f"Processed dataset {dataset_name} not found")
        
        data = self.processed_datasets[dataset_name]
        output_path = self.output_dir / dataset_name
        output_path.mkdir(exist_ok=True)
        
        if format == 'csv':
            # Save datasets
            data['X_train'].to_csv(output_path / 'X_train.csv', index=False)
            data['X_test'].to_csv(output_path / 'X_test.csv', index=False)
            data['y_train'].to_csv(output_path / 'y_train.csv', index=False)
            data['y_test'].to_csv(output_path / 'y_test.csv', index=False)
            
            # Save scaled data if available
            if 'X_train_scaled' in data:
                data['X_train_scaled'].to_csv(output_path / 'X_train_scaled.csv', index=False)
                data['X_test_scaled'].to_csv(output_path / 'X_test_scaled.csv', index=False)
            
            # Save selected features if available
            if 'X_train_selected' in data:
                data['X_train_selected'].to_csv(output_path / 'X_train_selected.csv', index=False)
                data['X_test_selected'].to_csv(output_path / 'X_test_selected.csv', index=False)
        
        # Save metadata
        metadata = {
            'dataset_name': dataset_name,
            'feature_names': data['feature_names'],
            'target_name': data['target_name'],
            'original_shape': data['original_shape'],
            'processed_shape': data['processed_shape'],
            'train_samples': len(data['X_train']),
            'test_samples': len(data['X_test']),
            'num_features': len(data['feature_names']),
            'processed_at': datetime.now().isoformat()
        }
        
        if 'selected_features' in data:
            metadata['selected_features'] = data['selected_features']
            metadata['num_selected_features'] = len(data['selected_features'])
        
        if 'scaler_type' in data:
            metadata['scaler_type'] = data['scaler_type']
        
        with open(output_path / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Saved processed data for {dataset_name} to {output_path}")
    
    def get_dataset_summary(self) -> Dict[str, Any]:
        """Get summary of all loaded and processed datasets"""
        summary = {
            'loaded_datasets': len(self.datasets),
            'processed_datasets': len(self.processed_datasets),
            'datasets': {}
        }
        
        for name, data in self.datasets.items():
            if 'train' in data:
                shape = data['train'].shape
            else:
                shape = data['data'].shape
            
            summary['datasets'][name] = {
                'type': data['type'],
                'target_column': data['target_column'],
                'shape': shape,
                'processed': name in self.processed_datasets
            }
            
            if name in self.processed_datasets:
                proc_data = self.processed_datasets[name]
                summary['datasets'][name].update({
                    'train_samples': len(proc_data['X_train']),
                    'test_samples': len(proc_data['X_test']),
                    'features': len(proc_data['feature_names']),
                    'scaled': 'X_train_scaled' in proc_data,
                    'feature_selected': 'X_train_selected' in proc_data
                })
        
        return summary
    
    def process_all_datasets(self, sample_size: Optional[int] = None, 
                           apply_scaling: bool = True, 
                           apply_feature_selection: bool = True):
        """Process all loaded datasets with common pipeline"""
        self.logger.info("Processing all datasets...")
        
        for dataset_name in self.datasets.keys():
            try:
                # Preprocess
                self.preprocess_dataset(dataset_name, sample_size)
                
                # Apply scaling
                if apply_scaling:
                    self.scale_features(dataset_name, 'standard')
                
                # Apply feature selection
                if apply_feature_selection:
                    max_features = min(20, len(self.processed_datasets[dataset_name]['feature_names']))
                    self.select_features(dataset_name, k_best=max_features)
                
                # Save processed data
                self.save_processed_data(dataset_name)
                
                self.logger.info(f"Successfully processed {dataset_name}")
                
            except Exception as e:
                self.logger.error(f"Error processing {dataset_name}: {e}")
        
        return self.get_dataset_summary()


# Utility functions
def load_and_process_data(data_dir: str = "data", sample_size: int = 5000) -> DataProcessor:
    """Convenience function to load and process all data"""
    processor = DataProcessor(data_dir)
    
    # Load all datasets
    processor.load_all_datasets()
    
    # Process all datasets
    processor.process_all_datasets(sample_size=sample_size)
    
    return processor


if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("🔧 MM-CT-DAS Data Processing Module")
    print("=" * 50)
    
    # Create processor and load data
    processor = load_and_process_data(sample_size=2000)
    
    # Print summary
    summary = processor.get_dataset_summary()
    print(f"\n📊 Processing Summary:")
    print(f"   Loaded datasets: {summary['loaded_datasets']}")
    print(f"   Processed datasets: {summary['processed_datasets']}")
    
    for name, info in summary['datasets'].items():
        print(f"\n   {name}:")
        print(f"     Shape: {info['shape']}")
        print(f"     Type: {info['type']}")
        print(f"     Processed: {info['processed']}")
        if info['processed']:
            print(f"     Features: {info['features']}")
            print(f"     Train samples: {info['train_samples']}")
            print(f"     Test samples: {info['test_samples']}")
    
    print(f"\n✅ Data processing completed!")
    print(f"📁 Processed data saved in: processed_data/")