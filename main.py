#!/usr/bin/env python3
"""
MM-CT-DAS - Multi-Modal Cyber Threat Detection and Analysis System
Main application entry point for Windows deployment
"""

import sys
import os
import asyncio
import logging
from pathlib import Path

# Add src directory to Python path
sys.path.append(str(Path(__file__).parent / "src"))

from src.core.system_manager import SystemManager
from src.core.config_loader import ConfigLoader


def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/mm_ct_das.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )


async def main():
    """Main application entry point"""
    try:
        # Setup logging
        setup_logging()
        logger = logging.getLogger(__name__)
        
        logger.info("Starting MM-CT-DAS System...")
        
        # Load configuration
        config = ConfigLoader().load_config()
        
        # Initialize system manager
        system_manager = SystemManager(config)
        
        # Start the system
        await system_manager.start()
        
        logger.info("MM-CT-DAS System started successfully!")
        
        # Keep the system running
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutdown signal received...")
            await system_manager.shutdown()
            
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Run the main application
    asyncio.run(main())