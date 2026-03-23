"""
Database Manager for Event Reference Data
Manages SQLite database for storing and retrieving event references, MITRE TTPs, and analysis results.
"""

import sqlite3
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import pandas as pd
from datetime import datetime


class DatabaseManager:
    """Manages SQLite database for event reference data"""
    
    def __init__(self, db_path: str = "event_references.db"):
        """Initialize database manager"""
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self._connect()
        self._create_tables()
    
    def _connect(self):
        """Connect to SQLite database"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row  # Enable column access by name
        self.cursor = self.conn.cursor()
    
    def _create_tables(self):
        """Create database schema"""
        
        # Security Events table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                event_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT,
                risk_score INTEGER,
                severity TEXT,
                description TEXT,
                mitre_tactics TEXT,
                mitre_techniques TEXT,
                suspicious_when TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Sysmon Events table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS sysmon_events (
                event_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT,
                risk_score INTEGER,
                severity TEXT,
                description TEXT,
                mitre_tactics TEXT,
                mitre_techniques TEXT,
                suspicious_when TEXT,
                key_fields TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # System Events table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_events (
                event_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT,
                risk_score INTEGER,
                severity TEXT,
                description TEXT,
                mitre_tactics TEXT,
                mitre_techniques TEXT,
                suspicious_when TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # SQL Server Events table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS sql_events (
                event_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT,
                risk_score INTEGER,
                severity TEXT,
                description TEXT,
                mitre_tactics TEXT,
                mitre_techniques TEXT,
                suspicious_when TEXT,
                states TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # MITRE Tactics table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS mitre_tactics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tactic_name TEXT UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # MITRE Techniques table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS mitre_techniques (
                technique_id TEXT PRIMARY KEY,
                technique_name TEXT NOT NULL,
                tactic_name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (tactic_name) REFERENCES mitre_tactics(tactic_name)
            )
        """)
        
        # Analysis Results table (for storing anomaly detection results)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                event_record_id INTEGER,
                event_id INTEGER,
                computer TEXT,
                timestamp TEXT,
                anomaly INTEGER,
                anomaly_score REAL,
                cluster_label TEXT,
                mitre_stage TEXT,
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for faster queries
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_risk ON security_events(risk_score)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_sysmon_risk ON sysmon_events(risk_score)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_system_risk ON system_events(risk_score)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_sql_risk ON sql_events(risk_score)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_technique_tactic ON mitre_techniques(tactic_name)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_session ON analysis_results(session_id)")
        
        self.conn.commit()
    
    # ==================== SECURITY EVENTS ====================
    
    def insert_security_event(self, event_id: int, event_data: Dict):
        """Insert or update a security event"""
        self.cursor.execute("""
            INSERT OR REPLACE INTO security_events 
            (event_id, name, category, risk_score, severity, description, 
             mitre_tactics, mitre_techniques, suspicious_when, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            event_id,
            event_data.get('name', ''),
            event_data.get('category', ''),
            event_data.get('risk_score', 5),
            event_data.get('severity', 'Unknown'),
            event_data.get('description', ''),
            json.dumps(event_data.get('mitre_tactics', [])),
            json.dumps(event_data.get('mitre_techniques', [])),
            json.dumps(event_data.get('suspicious_when', []))
        ))
        self.conn.commit()
    
    def get_security_event(self, event_id: int) -> Optional[Dict]:
        """Get security event by ID"""
        self.cursor.execute("SELECT * FROM security_events WHERE event_id = ?", (event_id,))
        row = self.cursor.fetchone()
        return self._row_to_dict(row) if row else None
    
    def get_all_security_events(self) -> List[Dict]:
        """Get all security events"""
        self.cursor.execute("SELECT * FROM security_events")
        return [self._row_to_dict(row) for row in self.cursor.fetchall()]
    
    # ==================== SYSMON EVENTS ====================
    
    def insert_sysmon_event(self, event_id: int, event_data: Dict):
        """Insert or update a sysmon event"""
        self.cursor.execute("""
            INSERT OR REPLACE INTO sysmon_events 
            (event_id, name, category, risk_score, severity, description, 
             mitre_tactics, mitre_techniques, suspicious_when, key_fields, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            event_id,
            event_data.get('name', ''),
            event_data.get('category', ''),
            event_data.get('risk_score', 5),
            event_data.get('severity', 'Unknown'),
            event_data.get('description', ''),
            json.dumps(event_data.get('mitre_tactics', [])),
            json.dumps(event_data.get('mitre_techniques', [])),
            json.dumps(event_data.get('suspicious_when', [])),
            json.dumps(event_data.get('key_fields', []))
        ))
        self.conn.commit()
    
    def get_sysmon_event(self, event_id: int) -> Optional[Dict]:
        """Get sysmon event by ID"""
        self.cursor.execute("SELECT * FROM sysmon_events WHERE event_id = ?", (event_id,))
        row = self.cursor.fetchone()
        return self._row_to_dict(row) if row else None
    
    def get_all_sysmon_events(self) -> List[Dict]:
        """Get all sysmon events"""
        self.cursor.execute("SELECT * FROM sysmon_events")
        return [self._row_to_dict(row) for row in self.cursor.fetchall()]
    
    # ==================== SYSTEM EVENTS ====================
    
    def insert_system_event(self, event_id: int, event_data: Dict):
        """Insert or update a system event"""
        self.cursor.execute("""
            INSERT OR REPLACE INTO system_events 
            (event_id, name, category, risk_score, severity, description, 
             mitre_tactics, mitre_techniques, suspicious_when, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            event_id,
            event_data.get('name', ''),
            event_data.get('category', ''),
            event_data.get('risk_score', 5),
            event_data.get('severity', 'Unknown'),
            event_data.get('description', ''),
            json.dumps(event_data.get('mitre_tactics', [])),
            json.dumps(event_data.get('mitre_techniques', [])),
            json.dumps(event_data.get('suspicious_when', []))
        ))
        self.conn.commit()
    
    def get_system_event(self, event_id: int) -> Optional[Dict]:
        """Get system event by ID"""
        self.cursor.execute("SELECT * FROM system_events WHERE event_id = ?", (event_id,))
        row = self.cursor.fetchone()
        return self._row_to_dict(row) if row else None
    
    def get_all_system_events(self) -> List[Dict]:
        """Get all system events"""
        self.cursor.execute("SELECT * FROM system_events")
        return [self._row_to_dict(row) for row in self.cursor.fetchall()]
    
    # ==================== SQL EVENTS ====================
    
    def insert_sql_event(self, event_id: int, event_data: Dict):
        """Insert or update a SQL Server event"""
        self.cursor.execute("""
            INSERT OR REPLACE INTO sql_events 
            (event_id, name, category, risk_score, severity, description, 
             mitre_tactics, mitre_techniques, suspicious_when, states, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            event_id,
            event_data.get('name', ''),
            event_data.get('category', ''),
            event_data.get('risk_score', 5),
            event_data.get('severity', 'Unknown'),
            event_data.get('description', ''),
            json.dumps(event_data.get('mitre_tactics', [])),
            json.dumps(event_data.get('mitre_techniques', [])),
            json.dumps(event_data.get('suspicious_when', [])),
            json.dumps(event_data.get('states', {}))
        ))
        self.conn.commit()
    
    def get_sql_event(self, event_id: int) -> Optional[Dict]:
        """Get SQL Server event by ID"""
        self.cursor.execute("SELECT * FROM sql_events WHERE event_id = ?", (event_id,))
        row = self.cursor.fetchone()
        return self._row_to_dict(row) if row else None
    
    def get_all_sql_events(self) -> List[Dict]:
        """Get all SQL Server events"""
        self.cursor.execute("SELECT * FROM sql_events")
        return [self._row_to_dict(row) for row in self.cursor.fetchall()]
    
    # ==================== MITRE ATT&CK ====================
    
    def insert_mitre_tactic(self, tactic_name: str, description: str):
        """Insert or update a MITRE tactic"""
        self.cursor.execute("""
            INSERT OR REPLACE INTO mitre_tactics (tactic_name, description)
            VALUES (?, ?)
        """, (tactic_name, description))
        self.conn.commit()
    
    def insert_mitre_technique(self, technique_id: str, technique_name: str, tactic_name: str):
        """Insert or update a MITRE technique"""
        self.cursor.execute("""
            INSERT OR REPLACE INTO mitre_techniques (technique_id, technique_name, tactic_name)
            VALUES (?, ?, ?)
        """, (technique_id, technique_name, tactic_name))
        self.conn.commit()
    
    def get_mitre_tactic(self, tactic_name: str) -> Optional[Dict]:
        """Get MITRE tactic by name"""
        self.cursor.execute("SELECT * FROM mitre_tactics WHERE tactic_name = ?", (tactic_name,))
        row = self.cursor.fetchone()
        return dict(row) if row else None
    
    def get_all_mitre_tactics(self) -> List[Dict]:
        """Get all MITRE tactics"""
        self.cursor.execute("SELECT * FROM mitre_tactics")
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_techniques_for_tactic(self, tactic_name: str) -> List[Dict]:
        """Get all techniques for a specific tactic"""
        self.cursor.execute("""
            SELECT * FROM mitre_techniques WHERE tactic_name = ?
        """, (tactic_name,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_technique_by_id(self, technique_id: str) -> Optional[Dict]:
        """Get technique by ID"""
        self.cursor.execute("SELECT * FROM mitre_techniques WHERE technique_id = ?", (technique_id,))
        row = self.cursor.fetchone()
        return dict(row) if row else None
    
    # ==================== UNIFIED EVENT LOOKUP ====================
    
    def get_event_by_id_and_channel(self, event_id: int, channel: str = None) -> Optional[Dict]:
        """Get event from appropriate table based on channel"""
        if channel:
            channel_lower = channel.lower()
            if "sysmon" in channel_lower or "operational" in channel_lower:
                return self.get_sysmon_event(event_id)
            elif "security" in channel_lower:
                return self.get_security_event(event_id)
            elif "system" in channel_lower or "task" in channel_lower or "powershell" in channel_lower:
                return self.get_system_event(event_id)
        
        # Try all tables if channel not specified
        event = self.get_security_event(event_id)
        if event:
            return event
        
        event = self.get_sysmon_event(event_id)
        if event:
            return event
        
        event = self.get_system_event(event_id)
        if event:
            return event
        
        event = self.get_sql_event(event_id)
        if event:
            return event
        
        return None
    
    def search_events_by_risk(self, min_risk: int = 7) -> List[Dict]:
        """Search all events with risk score >= threshold"""
        results = []
        
        # Search security events
        self.cursor.execute("SELECT * FROM security_events WHERE risk_score >= ?", (min_risk,))
        results.extend([{**self._row_to_dict(row), 'source': 'Security'} for row in self.cursor.fetchall()])
        
        # Search sysmon events
        self.cursor.execute("SELECT * FROM sysmon_events WHERE risk_score >= ?", (min_risk,))
        results.extend([{**self._row_to_dict(row), 'source': 'Sysmon'} for row in self.cursor.fetchall()])
        
        # Search system events
        self.cursor.execute("SELECT * FROM system_events WHERE risk_score >= ?", (min_risk,))
        results.extend([{**self._row_to_dict(row), 'source': 'System'} for row in self.cursor.fetchall()])
        
        # Search SQL events
        self.cursor.execute("SELECT * FROM sql_events WHERE risk_score >= ?", (min_risk,))
        results.extend([{**self._row_to_dict(row), 'source': 'SQL'} for row in self.cursor.fetchall()])
        
        return results
    
    # ==================== ANALYSIS RESULTS ====================
    
    def insert_analysis_result(self, session_id: str, result_data: Dict):
        """Insert analysis result"""
        self.cursor.execute("""
            INSERT INTO analysis_results 
            (session_id, event_record_id, event_id, computer, timestamp, 
             anomaly, anomaly_score, cluster_label, mitre_stage, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            result_data.get('event_record_id'),
            result_data.get('event_id'),
            result_data.get('computer'),
            result_data.get('timestamp'),
            result_data.get('anomaly', 0),
            result_data.get('anomaly_score', 0.0),
            result_data.get('cluster_label'),
            result_data.get('mitre_stage'),
            result_data.get('confidence', 0.0)
        ))
        self.conn.commit()
    
    def get_analysis_results(self, session_id: str) -> List[Dict]:
        """Get all analysis results for a session"""
        self.cursor.execute("""
            SELECT * FROM analysis_results WHERE session_id = ?
            ORDER BY anomaly_score DESC
        """, (session_id,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_anomalies_by_session(self, session_id: str) -> List[Dict]:
        """Get only anomalies for a session"""
        self.cursor.execute("""
            SELECT * FROM analysis_results 
            WHERE session_id = ? AND anomaly = 1
            ORDER BY anomaly_score DESC
        """, (session_id,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    # ==================== UTILITY METHODS ====================
    
    def _row_to_dict(self, row) -> Dict:
        """Convert SQLite row to dictionary with JSON parsing"""
        if not row:
            return None
        
        result = dict(row)
        
        # Parse JSON fields
        json_fields = ['mitre_tactics', 'mitre_techniques', 'suspicious_when', 'key_fields', 'states']
        for field in json_fields:
            if field in result and result[field]:
                try:
                    result[field] = json.loads(result[field])
                except (json.JSONDecodeError, TypeError):
                    result[field] = []
        
        return result
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        stats = {}
        
        self.cursor.execute("SELECT COUNT(*) as count FROM security_events")
        stats['security_events'] = self.cursor.fetchone()['count']
        
        self.cursor.execute("SELECT COUNT(*) as count FROM sysmon_events")
        stats['sysmon_events'] = self.cursor.fetchone()['count']
        
        self.cursor.execute("SELECT COUNT(*) as count FROM system_events")
        stats['system_events'] = self.cursor.fetchone()['count']
        
        self.cursor.execute("SELECT COUNT(*) as count FROM sql_events")
        stats['sql_events'] = self.cursor.fetchone()['count']
        
        self.cursor.execute("SELECT COUNT(*) as count FROM mitre_tactics")
        stats['mitre_tactics'] = self.cursor.fetchone()['count']
        
        self.cursor.execute("SELECT COUNT(*) as count FROM mitre_techniques")
        stats['mitre_techniques'] = self.cursor.fetchone()['count']
        
        stats['total_events'] = stats['security_events'] + stats['sysmon_events'] + stats['system_events'] + stats['sql_events']
        
        return stats
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Singleton instance
_db_manager = None

def get_db_manager(db_path: str = "event_references.db") -> DatabaseManager:
    """Get singleton database manager instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(db_path)
    return _db_manager
