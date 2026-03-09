"""
Network Monitor for packet capture and analysis
Uses PyShark and WinDivert for Windows network monitoring
"""

import asyncio
import logging
from typing import Callable, Optional, Dict, Any
import pyshark
import threading
from datetime import datetime


class NetworkMonitor:
    """Network packet monitoring service"""
    
    def __init__(self, config: Dict[str, Any], database_manager):
        self.config = config
        self.database = database_manager
        self.logger = logging.getLogger(__name__)
        
        self.interface = config.get('interface', 'auto')
        self.capture_filter = config.get('capture_filter', '')
        self.buffer_size = config.get('packet_buffer_size', 10000)
        
        self.capture = None
        self.running = False
        self.packet_handler = None
        self.capture_thread = None
        
    def set_packet_handler(self, handler: Callable):
        """Set packet handler function"""
        self.packet_handler = handler
    
    async def start(self):
        """Start network monitoring"""
        if self.running:
            return
        
        try:
            self.logger.info(f"Starting network monitor on interface: {self.interface}")
            
            # Determine interface
            interface = self._get_interface()
            
            # Create capture object
            if self.capture_filter:
                self.capture = pyshark.LiveCapture(
                    interface=interface,
                    bpf_filter=self.capture_filter
                )
            else:
                self.capture = pyshark.LiveCapture(interface=interface)
            
            # Start capture in separate thread
            self.running = True
            self.capture_thread = threading.Thread(
                target=self._capture_packets,
                daemon=True
            )
            self.capture_thread.start()
            
            self.logger.info("Network monitor started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting network monitor: {e}")
            raise
    
    def _get_interface(self) -> str:
        """Get network interface to monitor"""
        if self.interface == 'auto':
            # Auto-detect active interface
            try:
                import psutil
                interfaces = psutil.net_if_addrs()
                for interface_name in interfaces:
                    if interface_name != 'lo' and interface_name != 'Loopback':
                        return interface_name
                return list(interfaces.keys())[0]
            except:
                return None  # Let pyshark auto-detect
        return self.interface
    
    def _capture_packets(self):
        """Capture packets in separate thread"""
        try:
            for packet in self.capture.sniff_continuously():
                if not self.running:
                    break
                
                # Process packet
                self._process_packet(packet)
                
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
            self.running = False
    
    def _process_packet(self, packet):
        """Process captured packet"""
        try:
            # Extract packet info
            packet_info = self._extract_packet_info(packet)
            
            # Store in database
            if self.database:
                asyncio.create_task(self.database.store_packet(packet_info))
            
            # Send to threat detector
            if self.packet_handler:
                asyncio.create_task(self.packet_handler(packet_info))
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet) -> Dict[str, Any]:
        """Extract relevant information from packet"""
        info = {
            'timestamp': datetime.now().isoformat(),
            'length': len(packet),
            'protocol': packet.highest_layer,
        }
        
        # Try to extract network layer info
        try:
            if hasattr(packet, 'ip'):
                info.update({
                    'src_ip': packet.ip.src,
                    'dst_ip': packet.ip.dst,
                    'ttl': packet.ip.ttl if hasattr(packet.ip, 'ttl') else None
                })
            
            # Transport layer info
            if hasattr(packet, 'tcp'):
                info.update({
                    'src_port': packet.tcp.srcport,
                    'dst_port': packet.tcp.dstport,
                    'tcp_flags': packet.tcp.flags if hasattr(packet.tcp, 'flags') else None
                })
            elif hasattr(packet, 'udp'):
                info.update({
                    'src_port': packet.udp.srcport,
                    'dst_port': packet.udp.dstport
                })
                
            # Payload size
            if hasattr(packet, 'data'):
                info['payload_size'] = len(packet.data.data) if hasattr(packet.data, 'data') else 0
                
        except Exception as e:
            self.logger.debug(f"Error extracting packet details: {e}")
        
        return info
    
    async def shutdown(self):
        """Shutdown network monitor"""
        if not self.running:
            return
        
        self.logger.info("Shutting down network monitor...")
        self.running = False
        
        if self.capture:
            self.capture.close()
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5.0)
        
        self.logger.info("Network monitor shutdown complete")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status"""
        return {
            'running': self.running,
            'interface': self.interface,
            'filter': self.capture_filter
        }