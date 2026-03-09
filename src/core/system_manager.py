"""
System Manager for MM-CT-DAS
Coordinates all system components and services
"""

import asyncio
import logging
from typing import Dict, Any, List
from pathlib import Path

from .network_monitor import NetworkMonitor
from .database_manager import DatabaseManager
from ..detection.threat_detector import ThreatDetector
from ..detection.ml_engine import MLEngine
from ..response.response_manager import ResponseManager
from ..dashboard.dashboard_server import DashboardServer


class SystemManager:
    """Main system coordinator"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.services = {}
        self.running = False
        
        # Initialize components
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize all system components"""
        try:
            # Database manager
            self.services['database'] = DatabaseManager(self.config['database'])
            
            # Network monitor
            self.services['network'] = NetworkMonitor(
                self.config['network'],
                self.services['database']
            )
            
            # ML Engine
            self.services['ml_engine'] = MLEngine(self.config['detection'])
            
            # Threat detector
            self.services['threat_detector'] = ThreatDetector(
                self.config['detection'],
                self.services['ml_engine'],
                self.services['database']
            )
            
            # Response manager
            self.services['response'] = ResponseManager(
                self.config['response'],
                self.services['database']
            )
            
            # Dashboard server
            self.services['dashboard'] = DashboardServer(
                self.config['dashboard'],
                self.services['database']
            )
            
            # Connect components
            self._setup_event_pipeline()
            
            self.logger.info("All system components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing components: {e}")
            raise
    
    def _setup_event_pipeline(self):
        """Setup event pipeline between components"""
        # Network monitor -> Threat detector
        self.services['network'].set_packet_handler(
            self.services['threat_detector'].analyze_packet
        )
        
        # Threat detector -> Response manager
        self.services['threat_detector'].set_threat_handler(
            self.services['response'].handle_threat
        )
    
    async def start(self):
        """Start all system services"""
        if self.running:
            self.logger.warning("System is already running")
            return
        
        try:
            self.logger.info("Starting system services...")
            
            # Start services in order
            startup_order = [
                'database',
                'ml_engine', 
                'threat_detector',
                'response',
                'network',
                'dashboard'
            ]
            
            for service_name in startup_order:
                service = self.services[service_name]
                if hasattr(service, 'start'):
                    await service.start()
                    self.logger.info(f"Started {service_name} service")
            
            self.running = True
            self.logger.info("All services started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting services: {e}")
            await self.shutdown()
            raise
    
    async def shutdown(self):
        """Shutdown all services gracefully"""
        if not self.running:
            return
        
        self.logger.info("Shutting down system services...")
        
        # Shutdown in reverse order
        shutdown_order = [
            'dashboard',
            'network',
            'response',
            'threat_detector',
            'ml_engine',
            'database'
        ]
        
        for service_name in shutdown_order:
            try:
                service = self.services[service_name]
                if hasattr(service, 'shutdown'):
                    await service.shutdown()
                    self.logger.info(f"Shutdown {service_name} service")
            except Exception as e:
                self.logger.error(f"Error shutting down {service_name}: {e}")
        
        self.running = False
        self.logger.info("System shutdown complete")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status"""
        status = {
            'running': self.running,
            'services': {}
        }
        
        for service_name, service in self.services.items():
            if hasattr(service, 'get_status'):
                status['services'][service_name] = service.get_status()
            else:
                status['services'][service_name] = 'unknown'
        
        return status