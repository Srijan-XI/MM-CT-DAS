"""
Threat Detector - Main detection engine
Coordinates ML analysis, YARA rules, and behavioral analysis
"""

import logging
import asyncio
from typing import Dict, Any, Callable, Optional, List
from datetime import datetime
import json
import yara


class ThreatDetector:
    """Main threat detection coordinator"""
    
    def __init__(self, config: Dict[str, Any], ml_engine, database_manager):
        self.config = config
        self.ml_engine = ml_engine
        self.database = database_manager
        self.logger = logging.getLogger(__name__)
        
        self.yara_rules_path = config.get('yara_rules_path', 'config/yara_rules/')
        self.threat_threshold = config.get('threat_threshold', 0.7)
        self.realtime_enabled = config.get('enable_realtime', True)
        
        self.yara_rules = None
        self.threat_handler = None
        
        # Threat counters
        self.threat_stats = {
            'total_analyzed': 0,
            'threats_detected': 0,
            'false_positives': 0
        }
    
    async def start(self):
        """Initialize threat detector"""
        try:
            self.logger.info("Starting Threat Detector...")
            
            # Load YARA rules
            await self._load_yara_rules()
            
            self.logger.info("Threat Detector started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting Threat Detector: {e}")
            raise
    
    async def _load_yara_rules(self):
        """Load YARA rules for malware detection"""
        try:
            import os
            from pathlib import Path
            
            rules_path = Path(self.yara_rules_path)
            
            if not rules_path.exists():
                self.logger.warning(f"YARA rules path not found: {rules_path}")
                # Create default rules
                await self._create_default_yara_rules()
                return
            
            # Compile YARA rules
            rule_files = list(rules_path.glob('*.yar')) + list(rules_path.glob('*.yara'))
            
            if rule_files:
                rules_dict = {}
                for rule_file in rule_files:
                    rules_dict[rule_file.stem] = str(rule_file)
                
                self.yara_rules = yara.compile(filepaths=rules_dict)
                self.logger.info(f"Loaded {len(rule_files)} YARA rule files")
            else:
                self.logger.warning("No YARA rule files found")
                await self._create_default_yara_rules()
                
        except Exception as e:
            self.logger.error(f"Error loading YARA rules: {e}")
            # Continue without YARA rules
            self.yara_rules = None
    
    async def _create_default_yara_rules(self):
        """Create default YARA rules"""
        try:
            import os
            from pathlib import Path
            
            rules_path = Path(self.yara_rules_path)
            rules_path.mkdir(parents=True, exist_ok=True)
            
            # Basic network threat detection rules
            default_rules = """
rule SuspiciousNetworkActivity
{
    meta:
        description = "Detects suspicious network patterns"
        author = "MM-CT-DAS"
        date = "2025-09-29"
    
    strings:
        $http_malware = /GET \/[a-zA-Z0-9]{20,}\\.exe/ nocase
        $suspicious_ua = "User-Agent: " nocase
        $shell_commands = /cmd\.exe|powershell\.exe|bash/ nocase
        
    condition:
        any of them
}

rule PortScanDetection
{
    meta:
        description = "Detects potential port scanning"
        author = "MM-CT-DAS"
        
    strings:
        $nmap_scan = "Nmap scan" nocase
        $syn_flood = /SYN.*flood/ nocase
        
    condition:
        any of them
}

rule DataExfiltration
{
    meta:
        description = "Detects potential data exfiltration"
        author = "MM-CT-DAS"
        
    strings:
        $base64_large = /[A-Za-z0-9+\/]{100,}/
        $ftp_upload = /STOR.*\.(zip|rar|7z|tar)/ nocase
        
    condition:
        any of them
}
"""
            
            rule_file = rules_path / "default_rules.yar"
            with open(rule_file, 'w') as f:
                f.write(default_rules)
            
            # Compile the rules
            self.yara_rules = yara.compile(str(rule_file))
            self.logger.info("Created and loaded default YARA rules")
            
        except Exception as e:
            self.logger.error(f"Error creating default YARA rules: {e}")
    
    def set_threat_handler(self, handler: Callable):
        """Set threat handler function"""
        self.threat_handler = handler
    
    async def analyze_packet(self, packet_info: Dict[str, Any]):
        """Analyze packet for threats"""
        try:
            self.threat_stats['total_analyzed'] += 1
            
            # ML-based analysis
            ml_result = await self.ml_engine.analyze_packet(packet_info)
            
            # YARA-based analysis
            yara_result = await self._analyze_with_yara(packet_info)
            
            # Behavioral analysis
            behavioral_result = await self._behavioral_analysis(packet_info)
            
            # Combine results
            threat_result = await self._combine_analysis_results(
                packet_info, ml_result, yara_result, behavioral_result
            )
            
            # If threat detected, handle it
            if threat_result.get('threat_detected', False):
                await self._handle_detected_threat(threat_result)
            
            return threat_result
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")
            return {'threat_detected': False, 'error': str(e)}
    
    async def _analyze_with_yara(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze packet data with YARA rules"""
        try:
            if not self.yara_rules:
                return {'yara_matches': [], 'threat_detected': False}
            
            # Get packet payload data
            packet_data = packet_info.get('packet_data', '')
            if not packet_data:
                return {'yara_matches': [], 'threat_detected': False}
            
            # Convert to bytes if needed
            if isinstance(packet_data, str):
                packet_data = packet_data.encode('utf-8', errors='ignore')
            
            # Run YARA scan
            matches = self.yara_rules.match(data=packet_data)
            
            yara_result = {
                'yara_matches': [
                    {
                        'rule': match.rule,
                        'namespace': match.namespace,
                        'tags': match.tags,
                        'meta': match.meta
                    }
                    for match in matches
                ],
                'threat_detected': len(matches) > 0
            }
            
            if matches:
                self.logger.info(f"YARA matches found: {[m.rule for m in matches]}")
            
            return yara_result
            
        except Exception as e:
            self.logger.error(f"Error in YARA analysis: {e}")
            return {'yara_matches': [], 'threat_detected': False, 'error': str(e)}
    
    async def _behavioral_analysis(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """Perform behavioral analysis on packet"""
        try:
            behavioral_indicators = []
            threat_score = 0.0
            
            # Check for suspicious ports
            dst_port = packet_info.get('dst_port', 0)
            src_port = packet_info.get('src_port', 0)
            
            suspicious_ports = [135, 139, 445, 593, 1433, 3389, 5985, 5986]
            if dst_port in suspicious_ports or src_port in suspicious_ports:
                behavioral_indicators.append(f"Suspicious port usage: {dst_port}")
                threat_score += 0.3
            
            # Check packet size anomalies
            packet_length = packet_info.get('length', 0)
            payload_size = packet_info.get('payload_size', 0)
            
            if packet_length > 1500:  # Larger than standard MTU
                behavioral_indicators.append("Oversized packet detected")
                threat_score += 0.2
            
            if payload_size == 0 and packet_length > 100:
                behavioral_indicators.append("Empty payload with large headers")
                threat_score += 0.1
            
            # Check for potential scanning behavior
            if payload_size == 0 and dst_port in range(1, 1024):
                behavioral_indicators.append("Potential port scanning")
                threat_score += 0.4
            
            # Protocol-specific checks
            protocol = packet_info.get('protocol', '').lower()
            
            if protocol == 'icmp' and payload_size > 56:
                behavioral_indicators.append("ICMP with unusual payload size")
                threat_score += 0.2
            
            return {
                'behavioral_indicators': behavioral_indicators,
                'threat_score': min(threat_score, 1.0),
                'threat_detected': threat_score >= self.threat_threshold
            }
            
        except Exception as e:
            self.logger.error(f"Error in behavioral analysis: {e}")
            return {'behavioral_indicators': [], 'threat_score': 0.0, 'threat_detected': False}
    
    async def _combine_analysis_results(self, packet_info: Dict[str, Any], 
                                      ml_result: Dict[str, Any],
                                      yara_result: Dict[str, Any],
                                      behavioral_result: Dict[str, Any]) -> Dict[str, Any]:
        """Combine results from all analysis methods"""
        
        # Determine if threat is detected
        threat_detected = (
            ml_result.get('threat_detected', False) or
            yara_result.get('threat_detected', False) or
            behavioral_result.get('threat_detected', False)
        )
        
        # Calculate combined confidence
        confidences = []
        if ml_result.get('confidence'):
            confidences.append(ml_result['confidence'])
        if behavioral_result.get('threat_score'):
            confidences.append(behavioral_result['threat_score'])
        if yara_result.get('threat_detected'):
            confidences.append(0.9)  # High confidence for YARA matches
        
        combined_confidence = max(confidences) if confidences else 0.0
        
        # Determine threat type
        threat_types = []
        if ml_result.get('threat_detected'):
            threat_types.append(ml_result.get('threat_type', 'ml_detected'))
        if yara_result.get('yara_matches'):
            threat_types.extend([match['rule'] for match in yara_result['yara_matches']])
        if behavioral_result.get('threat_detected'):
            threat_types.append('behavioral_anomaly')
        
        # Determine severity
        severity = 'low'
        if combined_confidence >= 0.8:
            severity = 'critical'
        elif combined_confidence >= 0.6:
            severity = 'high'
        elif combined_confidence >= 0.4:
            severity = 'medium'
        
        return {
            'timestamp': datetime.now().isoformat(),
            'threat_detected': threat_detected,
            'confidence': combined_confidence,
            'severity': severity,
            'threat_types': threat_types,
            'source_ip': packet_info.get('src_ip'),
            'target_ip': packet_info.get('dst_ip'),
            'source_port': packet_info.get('src_port'),
            'target_port': packet_info.get('dst_port'),
            'protocol': packet_info.get('protocol'),
            'description': f"Threat detected: {', '.join(threat_types)}" if threat_types else "No threat detected",
            'analysis_details': {
                'ml_analysis': ml_result,
                'yara_analysis': yara_result,
                'behavioral_analysis': behavioral_result,
                'packet_info': packet_info
            }
        }
    
    async def _handle_detected_threat(self, threat_result: Dict[str, Any]):
        """Handle detected threat"""
        try:
            self.threat_stats['threats_detected'] += 1
            
            # Store threat in database
            if self.database:
                threat_id = await self.database.store_threat({
                    'timestamp': threat_result['timestamp'],
                    'threat_type': ', '.join(threat_result['threat_types']),
                    'severity': threat_result['severity'],
                    'confidence': threat_result['confidence'],
                    'source_ip': threat_result['source_ip'],
                    'target_ip': threat_result['target_ip'],
                    'description': threat_result['description'],
                    'details': threat_result['analysis_details']
                })
                
                threat_result['threat_id'] = threat_id
            
            # Send to response manager
            if self.threat_handler:
                await self.threat_handler(threat_result)
            
            # Log threat
            self.logger.warning(
                f"THREAT DETECTED - {threat_result['severity'].upper()}: "
                f"{threat_result['description']} "
                f"(Confidence: {threat_result['confidence']:.2f})"
            )
            
        except Exception as e:
            self.logger.error(f"Error handling detected threat: {e}")
    
    async def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze file for malware"""
        try:
            if not self.yara_rules:
                return {'threat_detected': False, 'error': 'No YARA rules loaded'}
            
            # Scan file with YARA
            matches = self.yara_rules.match(file_path)
            
            return {
                'file_path': file_path,
                'threat_detected': len(matches) > 0,
                'yara_matches': [
                    {
                        'rule': match.rule,
                        'namespace': match.namespace,
                        'tags': match.tags,
                        'meta': match.meta
                    }
                    for match in matches
                ],
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
            return {'threat_detected': False, 'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """Get threat detector status"""
        return {
            'realtime_enabled': self.realtime_enabled,
            'yara_rules_loaded': self.yara_rules is not None,
            'threat_threshold': self.threat_threshold,
            'statistics': self.threat_stats.copy()
        }
    
    async def shutdown(self):
        """Shutdown threat detector"""
        self.logger.info("Threat Detector shutdown complete")