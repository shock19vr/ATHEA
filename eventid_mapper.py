"""
EventID Mapper - Correlation Engine
Integrates all EventID reference databases to provide knowledge-based threat detection.
Maps EventIDs to risk scores, MITRE tactics, and attack patterns.
Now uses SQLite database for all reference data.
"""

import pandas as pd
from typing import Dict, List, Tuple, Optional
from db_manager import get_db_manager


class EventIDMapper:
    """Knowledge-based EventID correlation engine using database"""
    
    def __init__(self, db_path: str = "event_references.db"):
        self.db = get_db_manager(db_path)
        
        # Cache for frequently accessed data
        self._tactic_cache = {}
        self._technique_cache = {}
    
    def get_event_intelligence(self, event_id: int, channel: str = None) -> Dict:
        """
        Get comprehensive intelligence for an EventID from database.
        
        Args:
            event_id: The EventID to look up
            channel: Optional channel name (Security, Sysmon, System)
            
        Returns:
            Dictionary with all available intelligence
        """
        # Get event from database
        info = self.db.get_event_by_id_and_channel(event_id, channel)
        
        if info:
            # Determine source if not already set
            if 'source' not in info:
                if channel:
                    channel_lower = channel.lower()
                    if "sysmon" in channel_lower or "operational" in channel_lower:
                        info['source'] = 'Sysmon'
                    elif "security" in channel_lower:
                        info['source'] = 'Security'
                    elif "system" in channel_lower or "task" in channel_lower or "powershell" in channel_lower:
                        info['source'] = 'System'
                    else:
                        info['source'] = 'Unknown'
                else:
                    info['source'] = self._detect_channel(event_id)
        else:
            # Event not found in database
            info = {
                "event_id": event_id,
                "name": f"Unknown Event {event_id}",
                "category": "Unknown",
                "risk_score": 5,
                "mitre_tactics": [],
                "mitre_techniques": [],
                "description": "Event not in reference database",
                "suspicious_when": [],
                "severity": "Unknown",
                "source": "Unknown"
            }
        
        # Ensure event_id is set
        info['event_id'] = event_id
        
        return info
    
    def calculate_risk_score(self, event_id: int, channel: str = None, 
                            context: Dict = None) -> int:
        """
        Calculate context-aware risk score for an event.
        
        Args:
            event_id: The EventID
            channel: Optional channel name
            context: Optional context (night time, failed ratio, etc.)
            
        Returns:
            Risk score (1-10)
        """
        info = self.get_event_intelligence(event_id, channel)
        base_score = info.get('risk_score', 5)
        
        # Adjust score based on context
        if context:
            # Night-time activity increases risk
            if context.get('is_night_time'):
                base_score = min(10, base_score + 1)
            
            # High frequency increases risk
            if context.get('events_per_minute', 0) > 10:
                base_score = min(10, base_score + 1)
            
            # Failed login ratio
            if context.get('failed_login_ratio', 0) > 0.5:
                base_score = min(10, base_score + 2)
            
            # External IP
            if context.get('is_external_ip'):
                base_score = min(10, base_score + 1)
            
            # Suspicious content
            if context.get('has_suspicious_content'):
                base_score = min(10, base_score + 2)
        
        return int(base_score)
    
    def get_mitre_mapping(self, event_id: int, channel: str = None) -> Dict:
        """
        Get MITRE ATT&CK mapping for an EventID from database.
        
        Returns:
            Dictionary with tactics, techniques, and all related TTPs
        """
        info = self.get_event_intelligence(event_id, channel)
        event_tactics = info.get('mitre_tactics', [])
        event_techniques = info.get('mitre_techniques', [])
        
        # Get all techniques for each tactic from database
        all_techniques_by_tactic = {}
        for tactic in event_tactics:
            if tactic not in self._tactic_cache:
                techniques = self.db.get_techniques_for_tactic(tactic)
                self._tactic_cache[tactic] = {t['technique_id']: t['technique_name'] for t in techniques}
            all_techniques_by_tactic[tactic] = self._tactic_cache[tactic]
        
        # Get technique names from database
        technique_names = []
        for tech_id in event_techniques:
            if tech_id not in self._technique_cache:
                tech = self.db.get_technique_by_id(tech_id)
                self._technique_cache[tech_id] = tech['technique_name'] if tech else f"Unknown ({tech_id})"
            technique_names.append(self._technique_cache[tech_id])
        
        return {
            'tactics': event_tactics,
            'techniques': event_techniques,
            'primary_tactic': event_tactics[0] if event_tactics else 'Execution',
            'all_techniques_by_tactic': all_techniques_by_tactic,
            'technique_names': technique_names
        }
    
    def is_suspicious(self, event_id: int, channel: str = None, 
                     context: Dict = None) -> Tuple[bool, List[str]]:
        """
        Determine if an event is suspicious based on EventID knowledge.
        
        Returns:
            Tuple of (is_suspicious, reasons)
        """
        info = self.get_event_intelligence(event_id, channel)
        risk_score = self.calculate_risk_score(event_id, channel, context)
        
        # High risk score = suspicious
        if risk_score >= 7:
            return True, info.get('suspicious_when', ['High risk EventID'])
        
        # Check context against known suspicious patterns
        suspicious_when = info.get('suspicious_when', [])
        matched_patterns = []
        
        if context and suspicious_when:
            # Check for pattern matches
            for pattern in suspicious_when:
                pattern_lower = pattern.lower()
                
                # Night-time check
                if 'night' in pattern_lower and context.get('is_night_time'):
                    matched_patterns.append(pattern)
                
                # Failed login check
                if 'fail' in pattern_lower and context.get('is_failed_login'):
                    matched_patterns.append(pattern)
                
                # PowerShell check
                if 'powershell' in pattern_lower and context.get('has_powershell'):
                    matched_patterns.append(pattern)
                
                # Unusual check
                if 'unusual' in pattern_lower and context.get('is_unusual'):
                    matched_patterns.append(pattern)
        
        if matched_patterns:
            return True, matched_patterns
        
        return False, []
    
    def enrich_events(self, events_df: pd.DataFrame) -> pd.DataFrame:
        """
        Enrich DataFrame with EventID intelligence.
        Adds risk scores, MITRE mappings, and classifications.
        
        Args:
            events_df: DataFrame with 'EventID' and optionally 'Channel' columns
            
        Returns:
            Enriched DataFrame
        """
        if 'EventID' not in events_df.columns:
            return events_df
        
        # Initialize new columns
        events_df['EventID_RiskScore'] = 5
        events_df['EventID_Category'] = 'Unknown'
        events_df['EventID_Name'] = 'Unknown'
        events_df['EventID_Severity'] = 'Unknown'
        events_df['EventID_PrimaryTactic'] = 'Unknown'
        events_df['EventID_IsSuspicious'] = 0
        
        # Process each event
        for idx, row in events_df.iterrows():
            event_id = row.get('EventID')
            channel = row.get('Channel', None)
            
            if pd.isna(event_id):
                continue
            
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                continue
            
            # Get intelligence
            info = self.get_event_intelligence(event_id, channel)
            
            # Build context from row
            context = {
                'is_night_time': row.get('IsNightTime', 0) > 0,
                'events_per_minute': row.get('EventsPerMinute', 0),
                'failed_login_ratio': row.get('FailedLoginRatio', 0),
                'has_powershell': row.get('LogHasPowerShell', 0) > 0,
                'has_suspicious_content': row.get('LogHasSuspicious', 0) > 0,
                'is_failed_login': row.get('IsFailedLogin', 0) > 0,
                'is_unusual': row.get('EventIDRarity', 0) > 0.8
            }
            
            # Calculate risk
            risk_score = self.calculate_risk_score(event_id, channel, context)
            is_suspicious, reasons = self.is_suspicious(event_id, channel, context)
            
            # Get MITRE mapping
            mitre = self.get_mitre_mapping(event_id, channel)
            
            # Update DataFrame
            events_df.at[idx, 'EventID_RiskScore'] = risk_score
            events_df.at[idx, 'EventID_Category'] = info.get('category', 'Unknown')
            events_df.at[idx, 'EventID_Name'] = info.get('name', 'Unknown')
            events_df.at[idx, 'EventID_Severity'] = info.get('severity', 'Unknown')
            events_df.at[idx, 'EventID_PrimaryTactic'] = mitre['primary_tactic']
            events_df.at[idx, 'EventID_IsSuspicious'] = 1 if is_suspicious else 0
        
        return events_df
    
    def get_attack_stage_from_eventid(self, event_id: int, channel: str = None) -> str:
        """
        Get likely MITRE ATT&CK stage based solely on EventID knowledge.
        More accurate than feature-based inference for known EventIDs.
        
        Returns:
            MITRE stage string
        """
        mitre = self.get_mitre_mapping(event_id, channel)
        primary_tactic = mitre['primary_tactic']
        
        # Map MITRE tactics to attack stages
        tactic_to_stage = {
            'Initial Access': 'Stage 1: Initial Access',
            'Execution': 'Stage 2: Execution',
            'Persistence': 'Stage 3: Persistence',
            'Privilege Escalation': 'Stage 3: Privilege Escalation',
            'Defense Evasion': 'Stage 3: Defense Evasion',
            'Credential Access': 'Stage 2: Credential Access',
            'Discovery': 'Stage 4: Discovery',
            'Lateral Movement': 'Stage 4: Lateral Movement',
            'Collection': 'Stage 5: Collection',
            'Command and Control': 'Stage 5: Command & Control',
            'Exfiltration': 'Stage 6: Exfiltration',
            'Impact': 'Stage 7: Impact'
        }
        
        return tactic_to_stage.get(primary_tactic, 'Stage 2: Execution')
    
    def _detect_channel(self, event_id: int) -> str:
        """Auto-detect channel based on EventID by checking database"""
        # Try to find in each table
        if self.db.get_sysmon_event(event_id):
            return "Sysmon"
        elif self.db.get_security_event(event_id):
            return "Security"
        elif self.db.get_system_event(event_id):
            return "System"
        elif self.db.get_sql_event(event_id):
            return "SQL"
        else:
            # Make educated guess based on common ranges
            if event_id >= 4600 and event_id < 6000:
                return "Security"
            elif event_id >= 1 and event_id <= 29:
                return "Sysmon"
            else:
                return "System"
    
    def get_statistics(self) -> Dict:
        """Get statistics about the reference databases from database"""
        stats = self.db.get_statistics()
        
        # Add high risk count
        high_risk_events = self.db.search_events_by_risk(min_risk=7)
        stats['high_risk_events'] = len(high_risk_events)
        
        # Add critical severity count
        critical_events = self.db.search_events_by_risk(min_risk=9)
        stats['critical_severity'] = len(critical_events)
        
        return stats


# Global instance
_mapper = None

def get_mapper(db_path: str = "event_references.db") -> EventIDMapper:
    """Get singleton EventIDMapper instance"""
    global _mapper
    if _mapper is None:
        _mapper = EventIDMapper(db_path)
    return _mapper
