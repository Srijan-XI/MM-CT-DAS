"""
Database Manager for MM-CT-DAS
Handles SQLite database operations for threat logging and analysis
"""

import sqlite3
import asyncio
import logging
import aiosqlite
from typing import Dict, Any, List, Optional
from datetime import datetime
import json


class DatabaseManager:
    """SQLite database manager for threat detection system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        self.db_path = config.get('path', 'data/threats.db')
        self.max_connections = config.get('max_connections', 10)
        
        self.connection = None
        
    async def start(self):
        """Initialize database and create tables"""
        try:
            # Ensure data directory exists
            import os
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            # Create connection
            self.connection = await aiosqlite.connect(self.db_path)
            
            # Create tables
            await self._create_tables()
            
            self.logger.info(f"Database initialized: {self.db_path}")
            
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise
    
    async def _create_tables(self):
        """Create database tables"""
        tables = [
            # Packets table
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                length INTEGER,
                payload_size INTEGER,
                packet_data TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            
            # Threats table
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                source_ip TEXT,
                target_ip TEXT,
                description TEXT,
                details TEXT,
                status TEXT DEFAULT 'detected',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            
            # ML Models table
            """
            CREATE TABLE IF NOT EXISTS ml_models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT UNIQUE NOT NULL,
                model_path TEXT NOT NULL,
                version TEXT,
                accuracy REAL,
                last_trained DATETIME,
                is_active BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            
            # System Events table
            """
            CREATE TABLE IF NOT EXISTS system_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                component TEXT NOT NULL,
                message TEXT,
                severity TEXT DEFAULT 'info',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            
            # Response Actions table
            """
            CREATE TABLE IF NOT EXISTS response_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id INTEGER,
                action_type TEXT NOT NULL,
                action_details TEXT,
                status TEXT DEFAULT 'pending',
                executed_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (threat_id) REFERENCES threats (id)
            )
            """
        ]
        
        for table_sql in tables:
            await self.connection.execute(table_sql)
        
        await self.connection.commit()
        
        # Create indexes for performance
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)",
            "CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)",
            "CREATE INDEX IF NOT EXISTS idx_system_events_timestamp ON system_events(timestamp)"
        ]
        
        for index_sql in indexes:
            await self.connection.execute(index_sql)
        
        await self.connection.commit()
    
    async def store_packet(self, packet_info: Dict[str, Any]):
        """Store packet information"""
        try:
            query = """
            INSERT INTO packets (
                timestamp, src_ip, dst_ip, src_port, dst_port,
                protocol, length, payload_size, packet_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            values = (
                packet_info.get('timestamp'),
                packet_info.get('src_ip'),
                packet_info.get('dst_ip'),
                packet_info.get('src_port'),
                packet_info.get('dst_port'),
                packet_info.get('protocol'),
                packet_info.get('length'),
                packet_info.get('payload_size'),
                json.dumps(packet_info)
            )
            
            await self.connection.execute(query, values)
            await self.connection.commit()
            
        except Exception as e:
            self.logger.error(f"Error storing packet: {e}")
    
    async def store_threat(self, threat_info: Dict[str, Any]) -> int:
        """Store threat detection"""
        try:
            query = """
            INSERT INTO threats (
                timestamp, threat_type, severity, confidence,
                source_ip, target_ip, description, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            values = (
                threat_info.get('timestamp', datetime.now().isoformat()),
                threat_info.get('threat_type'),
                threat_info.get('severity'),
                threat_info.get('confidence'),
                threat_info.get('source_ip'),
                threat_info.get('target_ip'),
                threat_info.get('description'),
                json.dumps(threat_info.get('details', {}))
            )
            
            cursor = await self.connection.execute(query, values)
            await self.connection.commit()
            
            return cursor.lastrowid
            
        except Exception as e:
            self.logger.error(f"Error storing threat: {e}")
            return None
    
    async def get_recent_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent threats"""
        try:
            query = """
            SELECT * FROM threats 
            ORDER BY created_at DESC 
            LIMIT ?
            """
            
            async with self.connection.execute(query, (limit,)) as cursor:
                rows = await cursor.fetchall()
                
                columns = [description[0] for description in cursor.description]
                return [dict(zip(columns, row)) for row in rows]
                
        except Exception as e:
            self.logger.error(f"Error getting recent threats: {e}")
            return []
    
    async def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat statistics"""
        try:
            stats = {}
            
            # Total threats
            async with self.connection.execute(
                "SELECT COUNT(*) FROM threats"
            ) as cursor:
                result = await cursor.fetchone()
                stats['total_threats'] = result[0] if result else 0
            
            # Threats by severity
            async with self.connection.execute(
                "SELECT severity, COUNT(*) FROM threats GROUP BY severity"
            ) as cursor:
                rows = await cursor.fetchall()
                stats['by_severity'] = dict(rows) if rows else {}
            
            # Recent activity (last 24 hours)
            async with self.connection.execute(
                """
                SELECT COUNT(*) FROM threats 
                WHERE datetime(created_at) > datetime('now', '-1 day')
                """
            ) as cursor:
                result = await cursor.fetchone()
                stats['last_24h'] = result[0] if result else 0
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {}
    
    async def log_system_event(self, event_type: str, component: str, 
                             message: str, severity: str = 'info'):
        """Log system event"""
        try:
            query = """
            INSERT INTO system_events (timestamp, event_type, component, message, severity)
            VALUES (?, ?, ?, ?, ?)
            """
            
            values = (
                datetime.now().isoformat(),
                event_type,
                component,
                message,
                severity
            )
            
            await self.connection.execute(query, values)
            await self.connection.commit()
            
        except Exception as e:
            self.logger.error(f"Error logging system event: {e}")
    
    async def shutdown(self):
        """Close database connection"""
        if self.connection:
            await self.connection.close()
            self.logger.info("Database connection closed")
    
    def get_status(self) -> Dict[str, Any]:
        """Get database status"""
        return {
            'connected': self.connection is not None,
            'db_path': self.db_path
        }