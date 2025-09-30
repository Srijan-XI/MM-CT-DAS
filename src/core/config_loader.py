"""
Configuration loader for MM-CT-DAS system
Handles loading and validation of system configuration
"""

import json
import yaml
from pathlib import Path
from typing import Dict, Any
import logging


class ConfigLoader:
    """Load and manage system configuration"""
    
    def __init__(self, config_path: str = "config/system_config.yaml"):
        self.config_path = Path(config_path)
        self.logger = logging.getLogger(__name__)
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            if not self.config_path.exists():
                self.logger.warning(f"Config file not found: {self.config_path}")
                return self._get_default_config()
            
            with open(self.config_path, 'r') as f:
                if self.config_path.suffix == '.yaml' or self.config_path.suffix == '.yml':
                    config = yaml.safe_load(f)
                else:
                    config = json.load(f)
            
            self.logger.info(f"Configuration loaded from: {self.config_path}")
            return self._validate_config(config)
            
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            "system": {
                "name": "MM-CT-DAS",
                "version": "1.0.0",
                "debug": False
            },
            "network": {
                "interface": "auto",
                "capture_filter": "",
                "packet_buffer_size": 10000
            },
            "detection": {
                "ml_models_path": "models/",
                "yara_rules_path": "config/yara_rules/",
                "threat_threshold": 0.7,
                "enable_realtime": True
            },
            "database": {
                "type": "sqlite",
                "path": "data/threats.db",
                "max_connections": 10
            },
            "dashboard": {
                "port": 8501,
                "host": "localhost",
                "refresh_interval": 5
            },
            "response": {
                "auto_block": False,
                "firewall_integration": True,
                "email_notifications": False,
                "log_all_events": True
            },
            "logging": {
                "level": "INFO",
                "max_file_size": "10MB",
                "backup_count": 5
            }
        }
    
    def _validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate configuration parameters"""
        default_config = self._get_default_config()
        
        # Merge with defaults for missing keys
        for key, value in default_config.items():
            if key not in config:
                config[key] = value
            elif isinstance(value, dict):
                for subkey, subvalue in value.items():
                    if subkey not in config[key]:
                        config[key][subkey] = subvalue
        
        return config