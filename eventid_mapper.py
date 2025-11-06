"""
EventID Mapper - Correlation Engine
Integrates all EventID reference databases to provide knowledge-based threat detection.
Maps EventIDs to risk scores, MITRE tactics, and attack patterns.
"""

import pandas as pd
from typing import Dict, List, Tuple, Optional
from eventid_reference_security import SECURITY_EVENTS, get_event_info as get_security_info
from eventid_reference_sysmon import SYSMON_EVENTS, get_sysmon_event_info
from eventid_reference_system import SYSTEM_EVENTS, get_system_event_info
from mitre_ttps_reference import MITRE_TACTICS, get_all_techniques_for_tactic, get_technique_name


class EventIDMapper:
    """Knowledge-based EventID correlation engine"""
    
    def __init__(self):
        self.security_db = SECURITY_EVENTS
        self.sysmon_db = SYSMON_EVENTS
        self.system_db = SYSTEM_EVENTS
        
        # Combined database for quick lookups
        self.all_events = {
            **{f"Security_{k}": v for k, v in self.security_db.items()},
            **{f"Sysmon_{k}": v for k, v in self.sysmon_db.items()},
            **{f"System_{k}": v for k, v in self.system_db.items()}
        }
    
    def get_event_intelligence(self, event_id: int, channel: str = None) -> Dict:
        """
        Get comprehensive intelligence for an EventID.
        
        Args:
            event_id: The EventID to look up
            channel: Optional channel name (Security, Sysmon, System)
            
        Returns:
            Dictionary with all available intelligence
        """
        # Auto-detect channel if not provided
        if channel is None:
            channel = self._detect_channel(event_id)
        
        # Get event info from appropriate database
        if "sysmon" in channel.lower() or "operational" in channel.lower():
            info = get_sysmon_event_info(event_id)
            info['source'] = 'Sysmon'
        elif "security" in channel.lower():
            info = get_security_info(event_id)
            info['source'] = 'Security'
        elif "system" in channel.lower() or "task" in channel.lower() or "powershell" in channel.lower():
            info = get_system_event_info(event_id)
            info['source'] = 'System'
        else:
            # Unknown channel, try all databases
            info = self._search_all_databases(event_id)
            info['source'] = 'Unknown'
        
        # Enrich with EventID
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
        Get MITRE ATT&CK mapping for an EventID.
        
        Returns:
            Dictionary with tactics, techniques, and all related TTPs
        """
        info = self.get_event_intelligence(event_id, channel)
        event_tactics = info.get('mitre_tactics', [])
        event_techniques = info.get('mitre_techniques', [])
        
        # Get all techniques for each tactic
        all_techniques_by_tactic = {}
        for tactic in event_tactics:
            all_techniques_by_tactic[tactic] = get_all_techniques_for_tactic(tactic)
        
        return {
            'tactics': event_tactics,
            'techniques': event_techniques,
            'primary_tactic': event_tactics[0] if event_tactics else 'Execution',
            'all_techniques_by_tactic': all_techniques_by_tactic,
            'technique_names': [get_technique_name(t) for t in event_techniques]
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
        """Auto-detect channel based on EventID"""
        if event_id in self.sysmon_db:
            return "Sysmon"
        elif event_id in self.security_db:
            return "Security"
        elif event_id in self.system_db:
            return "System"
        else:
            # Make educated guess based on common ranges
            if event_id >= 4600 and event_id < 6000:
                return "Security"
            elif event_id >= 1 and event_id <= 29:
                return "Sysmon"
            else:
                return "System"
    
    def _search_all_databases(self, event_id: int) -> Dict:
        """Search all databases for an EventID"""
        # Try Sysmon first
        if event_id in self.sysmon_db:
            return get_sysmon_event_info(event_id)
        
        # Try Security
        if event_id in self.security_db:
            return get_security_info(event_id)
        
        # Try System
        if event_id in self.system_db:
            return get_system_event_info(event_id)
        
        # Not found
        return {
            "name": f"Unknown Event {event_id}",
            "category": "Unknown",
            "risk_score": 5,
            "mitre_tactics": [],
            "mitre_techniques": [],
            "description": "Event not in reference database",
            "suspicious_when": [],
            "severity": "Unknown"
        }
    
    def get_statistics(self) -> Dict:
        """Get statistics about the reference databases"""
        return {
            'total_events': len(self.security_db) + len(self.sysmon_db) + len(self.system_db),
            'security_events': len(self.security_db),
            'sysmon_events': len(self.sysmon_db),
            'system_events': len(self.system_db),
            'high_risk_events': sum(1 for info in {**self.security_db, **self.sysmon_db, **self.system_db}.values() 
                                   if info.get('risk_score', 0) >= 7),
            'critical_severity': sum(1 for info in {**self.security_db, **self.sysmon_db, **self.system_db}.values() 
                                    if info.get('severity') == 'Critical')
        }


# Global instance
_mapper = None

def get_mapper() -> EventIDMapper:
    """Get singleton EventIDMapper instance"""
    global _mapper
    if _mapper is None:
        _mapper = EventIDMapper()
    return _mapper
