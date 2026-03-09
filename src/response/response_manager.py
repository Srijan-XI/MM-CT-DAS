"""
Response Manager - Handles automated responses to detected threats
Integrates with Windows Firewall and system monitoring
"""

import logging
import asyncio
import subprocess
from typing import Dict, Any, List
from datetime import datetime
import json


class ResponseManager:
    """Automated threat response system"""
    
    def __init__(self, config: Dict[str, Any], database_manager):
        self.config = config
        self.database = database_manager
        self.logger = logging.getLogger(__name__)
        
        self.auto_block = config.get('auto_block', False)
        self.firewall_integration = config.get('firewall_integration', True)
        self.email_notifications = config.get('email_notifications', False)
        self.log_all_events = config.get('log_all_events', True)
        
        # Blocked IPs cache
        self.blocked_ips = set()
        
        # Response statistics
        self.response_stats = {
            'threats_handled': 0,
            'ips_blocked': 0,
            'actions_taken': 0,
            'notifications_sent': 0
        }
    
    async def start(self):
        """Initialize response manager"""
        try:
            self.logger.info("Starting Response Manager...")
            
            # Load existing blocked IPs from database
            await self._load_blocked_ips()
            
            self.logger.info("Response Manager started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting Response Manager: {e}")
            raise
    
    async def _load_blocked_ips(self):
        """Load previously blocked IPs from database"""
        try:
            if not self.database:
                return
            
            # Query for active blocked IPs
            # This is a simplified version - would need proper database schema
            self.logger.info("Loaded blocked IPs from database")
            
        except Exception as e:
            self.logger.error(f"Error loading blocked IPs: {e}")
    
    async def handle_threat(self, threat_info: Dict[str, Any]):
        """Handle detected threat with appropriate response"""
        try:
            self.response_stats['threats_handled'] += 1
            
            threat_id = threat_info.get('threat_id')
            severity = threat_info.get('severity', 'low')
            source_ip = threat_info.get('source_ip')
            confidence = threat_info.get('confidence', 0.0)
            
            self.logger.info(f"Handling threat {threat_id}: {severity} severity")
            
            # Determine response actions based on severity and confidence
            actions = await self._determine_response_actions(threat_info)
            
            # Execute response actions
            for action in actions:
                await self._execute_action(action, threat_info)
            
            # Log response
            if self.log_all_events:
                await self._log_response(threat_info, actions)
            
            # Send notifications if enabled
            if self.email_notifications:
                await self._send_notification(threat_info, actions)
            
        except Exception as e:
            self.logger.error(f"Error handling threat: {e}")
    
    async def _determine_response_actions(self, threat_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Determine appropriate response actions"""
        actions = []
        
        severity = threat_info.get('severity', 'low')
        confidence = threat_info.get('confidence', 0.0)
        source_ip = threat_info.get('source_ip')
        threat_types = threat_info.get('threat_types', [])
        
        # Always log the threat
        actions.append({
            'type': 'log',
            'priority': 1,
            'details': {'message': f"Threat detected: {threat_info.get('description')}"}
        })
        
        # High confidence threats
        if confidence >= 0.8:
            # Block IP if auto-blocking is enabled
            if self.auto_block and source_ip and self.firewall_integration:
                actions.append({
                    'type': 'block_ip',
                    'priority': 2,
                    'details': {'ip': source_ip, 'reason': 'High confidence threat'}
                })
            
            # Generate alert
            actions.append({
                'type': 'alert',
                'priority': 2,
                'details': {
                    'message': f"HIGH CONFIDENCE THREAT: {threat_info.get('description')}",
                    'severity': severity
                }
            })
        
        # Critical severity threats
        if severity == 'critical':
            # Always alert for critical threats
            actions.append({
                'type': 'alert',
                'priority': 1,
                'details': {
                    'message': f"CRITICAL THREAT: {threat_info.get('description')}",
                    'severity': 'critical'
                }
            })
            
            # Block IP for critical threats
            if source_ip and self.firewall_integration:
                actions.append({
                    'type': 'block_ip',
                    'priority': 1,
                    'details': {'ip': source_ip, 'reason': 'Critical threat detected'}
                })
        
        # Specific threat type responses
        for threat_type in threat_types:
            if 'port_scan' in threat_type.lower():
                actions.append({
                    'type': 'monitor_ip',
                    'priority': 3,
                    'details': {'ip': source_ip, 'duration': 3600}  # Monitor for 1 hour
                })
            
            elif 'malware' in threat_type.lower():
                actions.append({
                    'type': 'quarantine_alert',
                    'priority': 2,
                    'details': {'message': 'Malware detected - consider system scan'}
                })
        
        # Sort actions by priority
        actions.sort(key=lambda x: x.get('priority', 10))
        
        return actions
    
    async def _execute_action(self, action: Dict[str, Any], threat_info: Dict[str, Any]):
        """Execute a specific response action"""
        try:
            action_type = action.get('type')
            details = action.get('details', {})
            
            self.response_stats['actions_taken'] += 1
            
            if action_type == 'log':
                await self._action_log(details, threat_info)
            
            elif action_type == 'block_ip':
                await self._action_block_ip(details, threat_info)
            
            elif action_type == 'alert':
                await self._action_alert(details, threat_info)
            
            elif action_type == 'monitor_ip':
                await self._action_monitor_ip(details, threat_info)
            
            elif action_type == 'quarantine_alert':
                await self._action_quarantine_alert(details, threat_info)
            
            else:
                self.logger.warning(f"Unknown action type: {action_type}")
            
            # Store action in database
            if self.database:
                await self.database.connection.execute(
                    """INSERT INTO response_actions 
                       (threat_id, action_type, action_details, status, executed_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        threat_info.get('threat_id'),
                        action_type,
                        json.dumps(details),
                        'completed',
                        datetime.now().isoformat()
                    )
                )
                await self.database.connection.commit()
            
        except Exception as e:
            self.logger.error(f"Error executing action {action_type}: {e}")
    
    async def _action_log(self, details: Dict[str, Any], threat_info: Dict[str, Any]):
        """Log action"""
        message = details.get('message', 'Threat logged')
        self.logger.info(f"THREAT LOG: {message}")
    
    async def _action_block_ip(self, details: Dict[str, Any], threat_info: Dict[str, Any]):
        """Block IP address using Windows Firewall"""
        try:
            ip = details.get('ip')
            reason = details.get('reason', 'Threat detected')
            
            if not ip or ip in self.blocked_ips:
                return
            
            if not self.firewall_integration:
                self.logger.info(f"Would block IP {ip} (firewall integration disabled)")
                return
            
            # Use PowerShell to add firewall rule
            rule_name = f"MM-CT-DAS-Block-{ip.replace('.', '-')}"
            
            powershell_cmd = [
                'powershell.exe',
                '-Command',
                f"New-NetFirewallRule -DisplayName '{rule_name}' "
                f"-Direction Inbound -Protocol Any -Action Block "
                f"-RemoteAddress {ip} -Description 'Blocked by MM-CT-DAS: {reason}'"
            ]
            
            result = subprocess.run(
                powershell_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                self.response_stats['ips_blocked'] += 1
                self.logger.warning(f"BLOCKED IP: {ip} - {reason}")
            else:
                self.logger.error(f"Failed to block IP {ip}: {result.stderr}")
            
        except Exception as e:
            self.logger.error(f"Error blocking IP: {e}")
    
    async def _action_alert(self, details: Dict[str, Any], threat_info: Dict[str, Any]):
        """Generate alert"""
        message = details.get('message')
        severity = details.get('severity', 'medium')
        
        # Log alert with appropriate level
        if severity == 'critical':
            self.logger.critical(f"ALERT: {message}")
        elif severity == 'high':
            self.logger.error(f"ALERT: {message}")
        else:
            self.logger.warning(f"ALERT: {message}")
        
        # Could integrate with external alerting systems here
        # (email, Slack, PagerDuty, etc.)
    
    async def _action_monitor_ip(self, details: Dict[str, Any], threat_info: Dict[str, Any]):
        """Monitor IP address for suspicious activity"""
        ip = details.get('ip')
        duration = details.get('duration', 3600)
        
        self.logger.info(f"MONITORING IP: {ip} for {duration} seconds")
        
        # This would typically set up enhanced monitoring for the IP
        # For now, just log the intent
    
    async def _action_quarantine_alert(self, details: Dict[str, Any], threat_info: Dict[str, Any]):
        """Generate quarantine alert"""
        message = details.get('message')
        self.logger.warning(f"QUARANTINE ALERT: {message}")
    
    async def _log_response(self, threat_info: Dict[str, Any], actions: List[Dict[str, Any]]):
        """Log response actions"""
        if self.database:
            await self.database.log_system_event(
                'threat_response',
                'response_manager',
                f"Responded to threat {threat_info.get('threat_id')} with {len(actions)} actions",
                'info'
            )
    
    async def _send_notification(self, threat_info: Dict[str, Any], actions: List[Dict[str, Any]]):
        """Send email notification"""
        # Placeholder for email notification
        self.response_stats['notifications_sent'] += 1
        self.logger.info("Email notification sent (placeholder)")
    
    async def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP address"""
        try:
            if ip not in self.blocked_ips:
                return False
            
            # Remove firewall rule
            rule_name = f"MM-CT-DAS-Block-{ip.replace('.', '-')}"
            
            powershell_cmd = [
                'powershell.exe',
                '-Command',
                f"Remove-NetFirewallRule -DisplayName '{rule_name}'"
            ]
            
            result = subprocess.run(
                powershell_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                self.blocked_ips.remove(ip)
                self.logger.info(f"UNBLOCKED IP: {ip}")
                return True
            else:
                self.logger.error(f"Failed to unblock IP {ip}: {result.stderr}")
                return False
            
        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip}: {e}")
            return False
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of currently blocked IPs"""
        return list(self.blocked_ips)
    
    def get_status(self) -> Dict[str, Any]:
        """Get response manager status"""
        return {
            'auto_block_enabled': self.auto_block,
            'firewall_integration': self.firewall_integration,
            'blocked_ips_count': len(self.blocked_ips),
            'statistics': self.response_stats.copy()
        }
    
    async def shutdown(self):
        """Shutdown response manager"""
        self.logger.info("Response Manager shutdown complete")