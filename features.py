"""
Feature Engineering Module
Extracts ML-ready features from parsed log events for anomaly detection.
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any, Tuple
from collections import Counter, defaultdict
import re
from eventid_mapper import get_mapper


class FeatureEngineer:
    """Extracts and engineers features from log events"""
    
    def __init__(self):
        self.feature_names = []
        self.event_stats = {}
    
    def extract_features(self, events: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Extract ML features from parsed events.
        
        Args:
            events: List of parsed event dictionaries
            
        Returns:
            DataFrame with engineered features
        """
        if not events:
            return pd.DataFrame()
        
        df = pd.DataFrame(events)
        
        # Store original data for later reference
        original_cols = df.columns.tolist()
        
        # Temporal features
        df = self._add_temporal_features(df)
        
        # Categorical encoding
        df = self._encode_categorical_features(df)
        
        # Event frequency features
        df = self._add_frequency_features(df)
        
        # Security-specific features
        df = self._add_security_features(df)
        
        # Text-based features
        df = self._add_text_features(df)
        
        # Statistical aggregates
        df = self._add_statistical_features(df)
        
        # EventID intelligence enrichment
        df = self._add_eventid_intelligence(df)
        
        # Fill NaN values
        df = df.fillna(0)
        
        # Store feature names (excluding original columns for ML)
        self.feature_names = [col for col in df.columns if col not in original_cols]
        
        return df
    
    def _add_eventid_intelligence(self, df: pd.DataFrame) -> pd.DataFrame:
        """Enrich events with EventID knowledge base intelligence"""
        if 'EventID' not in df.columns:
            return df
        
        try:
            mapper = get_mapper()
            df = mapper.enrich_events(df)
        except Exception as e:
            print(f"Warning: EventID enrichment failed: {e}")
        
        return df
    
    def _add_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add time-based features"""
        
        # Hour-based features
        if 'Hour' in df.columns:
            df['IsNightTime'] = df['Hour'].apply(lambda x: 1 if x is not None and (x < 6 or x > 22) else 0)
            df['IsBusinessHours'] = df['Hour'].apply(lambda x: 1 if x is not None and 9 <= x <= 17 else 0)
            df['HourSin'] = df['Hour'].apply(lambda x: np.sin(2 * np.pi * x / 24) if x is not None else 0)
            df['HourCos'] = df['Hour'].apply(lambda x: np.cos(2 * np.pi * x / 24) if x is not None else 0)
        
        # Time since previous event (in seconds)
        if 'EpochSeconds' in df.columns:
            df['TimeSincePrevEvent'] = df['EpochSeconds'].diff().fillna(0)
            df['TimeSincePrevEvent'] = df['TimeSincePrevEvent'].clip(lower=0, upper=3600)  # Cap at 1 hour
        
        # Weekend indicator already exists (IsWeekend)
        
        return df
    
    def _encode_categorical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Encode categorical features"""
        
        # Event ID frequency encoding
        if 'EventID' in df.columns:
            event_counts = df['EventID'].value_counts().to_dict()
            df['EventIDFrequency'] = df['EventID'].map(event_counts).fillna(0)
            df['EventIDRarity'] = df['EventIDFrequency'].apply(lambda x: 1 / (x + 1))
        
        # Level encoding
        if 'Level' in df.columns:
            level_map = {1: 5, 2: 4, 3: 3, 4: 2, 5: 1}  # Critical=5, Error=4, etc.
            df['LevelSeverity'] = df['Level'].map(level_map).fillna(0)
        
        # Computer/Host encoding
        if 'Computer' in df.columns:
            computer_counts = df['Computer'].value_counts().to_dict()
            df['ComputerEventCount'] = df['Computer'].map(computer_counts).fillna(0)
        
        # Channel encoding
        if 'Channel' in df.columns:
            channel_counts = df['Channel'].value_counts().to_dict()
            df['ChannelEventCount'] = df['Channel'].map(channel_counts).fillna(0)
        
        # User encoding (if available)
        if 'User' in df.columns:
            user_counts = df['User'].value_counts().to_dict()
            df['UserEventCount'] = df['User'].map(user_counts).fillna(0)
        
        return df
    
    def _add_frequency_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add event frequency features"""
        
        # Events per minute
        if 'EpochSeconds' in df.columns and len(df) > 1:
            df['EventsPerMinute'] = 0
            
            for idx in range(len(df)):
                current_time = df.loc[idx, 'EpochSeconds']
                if pd.notna(current_time):
                    time_window = df[
                        (df['EpochSeconds'] >= current_time - 60) & 
                        (df['EpochSeconds'] <= current_time)
                    ]
                    df.loc[idx, 'EventsPerMinute'] = len(time_window)
        
        # Unique Event IDs in window
        if 'EventID' in df.columns and 'EpochSeconds' in df.columns:
            df['UniqueEventIDsInWindow'] = 0
            
            for idx in range(len(df)):
                current_time = df.loc[idx, 'EpochSeconds']
                if pd.notna(current_time):
                    time_window = df[
                        (df['EpochSeconds'] >= current_time - 300) & 
                        (df['EpochSeconds'] <= current_time)
                    ]
                    df.loc[idx, 'UniqueEventIDsInWindow'] = time_window['EventID'].nunique()
        
        return df
    
    def _add_security_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add security-specific features"""
        
        # Comprehensive Event ID indicators for threat detection
        if 'EventID' in df.columns:
            # Authentication & Access
            df['IsFailedLogin'] = df['EventID'].apply(lambda x: 1 if x == 4625 else 0)
            df['IsSuccessfulLogin'] = df['EventID'].apply(lambda x: 1 if x == 4624 else 0)
            df['IsExplicitCredentials'] = df['EventID'].apply(lambda x: 1 if x == 4648 else 0)
            
            # Execution
            df['IsProcessCreation'] = df['EventID'].apply(lambda x: 1 if x in [4688, 1] else 0)  # 1 for Sysmon
            
            # Network
            df['IsNetworkConnection'] = df['EventID'].apply(lambda x: 1 if x in [3, 5156] else 0)  # Sysmon & Windows Filtering
            
            # File Operations
            df['IsFileCreation'] = df['EventID'].apply(lambda x: 1 if x == 11 else 0)  # Sysmon
            df['IsFileAccess'] = df['EventID'].apply(lambda x: 1 if x in [4663, 4656] else 0)
            
            # Registry
            df['IsRegistryModification'] = df['EventID'].apply(lambda x: 1 if x in [12, 13, 14, 4657] else 0)
            
            # Privilege & Security
            df['IsPrivilegeUse'] = df['EventID'].apply(lambda x: 1 if x in [4672, 4673, 4674] else 0)
            df['IsGroupModification'] = df['EventID'].apply(lambda x: 1 if x == 4732 else 0)
            df['IsServiceInstalled'] = df['EventID'].apply(lambda x: 1 if x == 4697 else 0)
            
            # Defense Evasion
            df['IsSecurityLogCleared'] = df['EventID'].apply(lambda x: 1 if x in [1102, 104, 1100] else 0)
            df['IsAuditPolicyChange'] = df['EventID'].apply(lambda x: 1 if x == 4719 else 0)
            
            # Scheduled Tasks
            df['IsScheduledTask'] = df['EventID'].apply(lambda x: 1 if x in [4698, 4699, 4700, 4701, 106, 200, 201] else 0)
            
            # Kerberos & NTLM
            df['IsKerberos'] = df['EventID'].apply(lambda x: 1 if x in [4768, 4769, 4770, 4771] else 0)
            df['IsNTLM'] = df['EventID'].apply(lambda x: 1 if x == 4776 else 0)
            
            # Failed login ratio in window
            if 'EpochSeconds' in df.columns:
                df['FailedLoginRatio'] = 0
                
                for idx in range(len(df)):
                    current_time = df.loc[idx, 'EpochSeconds']
                    if pd.notna(current_time):
                        time_window = df[
                            (df['EpochSeconds'] >= current_time - 300) & 
                            (df['EpochSeconds'] <= current_time)
                        ]
                        total_logins = len(time_window[time_window['IsFailedLogin'] + time_window['IsSuccessfulLogin'] > 0])
                        failed_logins = time_window['IsFailedLogin'].sum()
                        
                        if total_logins > 0:
                            df.loc[idx, 'FailedLoginRatio'] = failed_logins / total_logins
        
        # Process ID features
        if 'ExecutionProcessID' in df.columns:
            df['HasProcessID'] = df['ExecutionProcessID'].notna().astype(int)
            
            # Unique process count in window
            if 'EpochSeconds' in df.columns:
                df['UniqueProcessCount'] = 0
                
                for idx in range(len(df)):
                    current_time = df.loc[idx, 'EpochSeconds']
                    if pd.notna(current_time):
                        time_window = df[
                            (df['EpochSeconds'] >= current_time - 300) & 
                            (df['EpochSeconds'] <= current_time)
                        ]
                        df.loc[idx, 'UniqueProcessCount'] = time_window['ExecutionProcessID'].nunique()
        
        # IP address features
        if 'IP' in df.columns:
            ip_counts = df['IP'].value_counts().to_dict()
            df['IPFrequency'] = df['IP'].map(ip_counts).fillna(0)
            
            # Unique IP count in window
            if 'EpochSeconds' in df.columns:
                df['UniqueIPCount'] = 0
                
                for idx in range(len(df)):
                    current_time = df.loc[idx, 'EpochSeconds']
                    if pd.notna(current_time):
                        time_window = df[
                            (df['EpochSeconds'] >= current_time - 300) & 
                            (df['EpochSeconds'] <= current_time)
                        ]
                        df.loc[idx, 'UniqueIPCount'] = time_window['IP'].nunique()
        
        return df
    
    def _add_text_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add text-based features"""
        
        # Enhanced RawLog features for threat detection
        if 'RawLog' in df.columns:
            df['LogLength'] = df['RawLog'].fillna('').apply(len)
            df['LogWordCount'] = df['RawLog'].fillna('').apply(lambda x: len(str(x).split()))
            
            # Error and failure indicators
            df['LogHasError'] = df['RawLog'].fillna('').str.contains('error|fail|denied|refused', case=False, regex=True).astype(int)
            
            # Command execution indicators
            df['LogHasPowerShell'] = df['RawLog'].fillna('').str.contains('powershell|pwsh|ps1', case=False, regex=True).astype(int)
            df['LogHasCmd'] = df['RawLog'].fillna('').str.contains(r'\bcmd\b|cmd\.exe|command\.com', case=False, regex=True).astype(int)
            df['LogHasScript'] = df['RawLog'].fillna('').str.contains('script|vbs|js|py|bat', case=False, regex=True).astype(int)
            
            # Encoding/Obfuscation indicators
            df['LogHasBase64'] = df['RawLog'].fillna('').str.contains('base64|frombase64', case=False, regex=True).astype(int)
            df['LogHasEncoding'] = df['RawLog'].fillna('').str.contains('encode|decode|compress|decompress', case=False, regex=True).astype(int)
            
            # Network indicators
            df['LogHasURL'] = df['RawLog'].fillna('').str.contains(r'http[s]?://|ftp://', case=False, regex=True).astype(int)
            df['LogHasIP'] = df['RawLog'].fillna('').str.contains(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', regex=True).astype(int)
            
            # Suspicious commands
            df['LogHasSuspicious'] = df['RawLog'].fillna('').str.contains(
                'invoke-expression|iex|downloadstring|webclient|invoke-webrequest|'
                'mimikatz|metasploit|payload|shellcode|empire|covenant|'
                'certutil|bitsadmin|reg add|schtasks|net user|net localgroup',
                case=False, regex=True
            ).astype(int)
            
            # Privilege escalation indicators
            df['LogHasPrivEsc'] = df['RawLog'].fillna('').str.contains(
                'runas|elevate|uac|bypass|admin|administrator|system',
                case=False, regex=True
            ).astype(int)
            
            # Entropy calculation for obfuscation detection
            df['LogEntropy'] = df['RawLog'].fillna('').apply(self._calculate_entropy)
        
        # EventData features
        if 'EventData' in df.columns:
            df['EventDataCount'] = df['EventData'].apply(lambda x: len(x) if isinstance(x, dict) else 0)
        
        # Action features
        if 'Action' in df.columns:
            action_severity = {
                'Login': 1, 'Logout': 1, 'Connect': 1,
                'Access': 2, 'Failed': 3, 'Denied': 4, 'Error': 4
            }
            df['ActionSeverity'] = df['Action'].map(action_severity).fillna(0)
        
        return df
    
    def _add_statistical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add statistical aggregate features"""
        
        # Running statistics per computer/user
        if 'Computer' in df.columns and 'EventID' in df.columns:
            df['EventIDStdPerComputer'] = 0
            
            for computer in df['Computer'].unique():
                if pd.notna(computer):
                    mask = df['Computer'] == computer
                    std_val = df.loc[mask, 'EventID'].std()
                    df.loc[mask, 'EventIDStdPerComputer'] = std_val if pd.notna(std_val) else 0
        
        # Z-score for numeric features
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        for col in ['EventID', 'ExecutionProcessID', 'EventsPerMinute']:
            if col in numeric_cols:
                mean_val = df[col].mean()
                std_val = df[col].std()
                if pd.notna(mean_val) and pd.notna(std_val) and std_val > 0:
                    df[f'{col}_ZScore'] = (df[col] - mean_val) / std_val
                else:
                    df[f'{col}_ZScore'] = 0
        
        return df
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        
        for count in counter.values():
            p = count / length
            entropy -= p * np.log2(p)
        
        return entropy
    
    def get_ml_features(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
        """
        Get only ML-ready numeric features.
        
        Args:
            df: Full dataframe with all features
            
        Returns:
            Tuple of (feature_df, feature_names)
        """
        # Select numeric features only
        numeric_df = df.select_dtypes(include=[np.number])
        
        # Exclude ID columns and timestamps
        exclude_cols = ['EventRecordID', 'EpochSeconds', 'Year', 'Month', 'Day', 
                       'Minute', 'LineNumber', 'ExecutionThreadID']
        
        feature_cols = [col for col in numeric_df.columns if col not in exclude_cols]
        ml_df = numeric_df[feature_cols].copy()
        
        # Replace inf values
        ml_df = ml_df.replace([np.inf, -np.inf], 0)
        ml_df = ml_df.fillna(0)
        
        return ml_df, feature_cols
