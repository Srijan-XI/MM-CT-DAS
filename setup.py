#!/usr/bin/env python3
"""
MM-CT-DAS Setup Script
Handles initial system setup and dependency verification
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
import logging

def setup_logging():
    """Setup logging for setup process"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def check_python_version():
    """Check Python version compatibility"""
    logger = logging.getLogger(__name__)
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        logger.error("Python 3.10 or higher is required!")
        logger.error(f"Current version: {version.major}.{version.minor}")
        return False
    
    logger.info(f"Python version check passed: {version.major}.{version.minor}")
    return True

def check_system_requirements():
    """Check system requirements"""
    logger = logging.getLogger(__name__)
    
    # Check if running on Windows
    if platform.system() != 'Windows':
        logger.warning("This system is optimized for Windows. Some features may not work on other platforms.")
    
    # Check for required system tools
    required_tools = []
    
    # Check for Wireshark/tshark
    try:
        subprocess.run(['tshark', '--version'], 
                      capture_output=True, check=True)
        logger.info("Wireshark/tshark found")
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("Wireshark/tshark not found. Please install Wireshark and add tshark to PATH")
        required_tools.append("Wireshark")
    
    return required_tools

def create_directories():
    """Create required directories"""
    logger = logging.getLogger(__name__)
    
    directories = [
        'logs',
        'data',
        'models',
        'config/yara_rules',
        'temp'
    ]
    
    for directory in directories:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created directory: {directory}")

def install_dependencies():
    """Install Python dependencies"""
    logger = logging.getLogger(__name__)
    
    requirements_file = Path('requirements.txt')
    
    if not requirements_file.exists():
        logger.error("requirements.txt not found!")
        return False
    
    try:
        logger.info("Installing Python dependencies...")
        subprocess.run([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ], check=True)
        
        logger.info("Dependencies installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Error installing dependencies: {e}")
        return False

def verify_imports():
    """Verify that key imports work"""
    logger = logging.getLogger(__name__)
    
    test_imports = [
        ('scapy', 'scapy.all'),
        ('pyshark', 'pyshark'),
        ('sklearn', 'sklearn.ensemble'),
        ('yara', 'yara'),
        ('sqlite3', 'sqlite3'),
        ('pandas', 'pandas'),
        ('numpy', 'numpy')
    ]
    
    failed_imports = []
    
    for package_name, import_name in test_imports:
        try:
            __import__(import_name)
            logger.info(f"✓ {package_name} import successful")
        except ImportError as e:
            logger.error(f"✗ {package_name} import failed: {e}")
            failed_imports.append(package_name)
    
    return failed_imports

def create_initial_config():
    """Create initial configuration if not exists"""
    logger = logging.getLogger(__name__)
    
    config_file = Path('config/system_config.yaml')
    
    if config_file.exists():
        logger.info("Configuration file already exists")
        return
    
    logger.info("Configuration file created: config/system_config.yaml")
    logger.info("Please review and modify the configuration as needed")

def run_initial_tests():
    """Run basic system tests"""
    logger = logging.getLogger(__name__)
    
    logger.info("Running initial system tests...")
    
    # Test database creation
    try:
        import sqlite3
        test_db = Path('temp/test.db')
        conn = sqlite3.connect(test_db)
        conn.execute('CREATE TABLE test (id INTEGER)')
        conn.close()
        test_db.unlink()
        logger.info("✓ Database functionality test passed")
    except Exception as e:
        logger.error(f"✗ Database test failed: {e}")
    
    # Test network interface detection
    try:
        import psutil
        interfaces = psutil.net_if_addrs()
        logger.info(f"✓ Network interfaces detected: {len(interfaces)}")
        for interface in list(interfaces.keys())[:3]:  # Show first 3
            logger.info(f"  - {interface}")
    except Exception as e:
        logger.error(f"✗ Network interface detection failed: {e}")

def main():
    """Main setup function"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 50)
    logger.info("MM-CT-DAS System Setup")
    logger.info("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check system requirements
    missing_tools = check_system_requirements()
    if missing_tools:
        logger.warning(f"Missing tools: {', '.join(missing_tools)}")
        logger.warning("Please install these tools for full functionality")
    
    # Create directories
    create_directories()
    
    # Install dependencies
    if not install_dependencies():
        logger.error("Failed to install dependencies")
        sys.exit(1)
    
    # Verify imports
    failed_imports = verify_imports()
    if failed_imports:
        logger.error(f"Failed imports: {', '.join(failed_imports)}")
        logger.error("Please check your Python environment and requirements.txt")
        sys.exit(1)
    
    # Create initial configuration
    create_initial_config()
    
    # Run initial tests
    run_initial_tests()
    
    logger.info("=" * 50)
    logger.info("Setup completed successfully!")
    logger.info("=" * 50)
    logger.info("Next steps:")
    logger.info("1. Review configuration in config/system_config.yaml")
    logger.info("2. Run the system with: python main.py")
    logger.info("3. Access dashboard at: http://localhost:8501")

if __name__ == "__main__":
    main()