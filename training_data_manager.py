"""
Training Data Manager
Handles labeled anomaly training data for supervised learning.
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime


class TrainingDataManager:
    """Manages labeled training data for anomaly detection"""
    
    def __init__(self, training_data_dir: str = "training_data"):
        """
        Initialize training data manager.
        
        Args:
            training_data_dir: Directory to store training datasets
        """
        self.training_data_dir = Path(training_data_dir)
        self.training_data_dir.mkdir(exist_ok=True)
        
        # Define anomaly categories
        self.anomaly_categories = {
            'brute_force': 'Brute Force Attack',
            'powershell_exploit': 'PowerShell Exploit',
            'suspicious_process': 'Suspicious Process Execution',
            'lateral_movement': 'Lateral Movement',
            'privilege_escalation': 'Privilege Escalation',
            'defense_evasion': 'Defense Evasion',
            'persistence': 'Persistence Mechanism',
            'credential_theft': 'Credential Theft',
            'data_exfiltration': 'Data Exfiltration',
            'network_recon': 'Network Reconnaissance',
            'service_injection': 'Service/DLL Injection',
            'c2_beaconing': 'Command & Control Beaconing',
            'log_tampering': 'Log Tampering',
            'malware_execution': 'Malware Execution',
            'sql_injection': 'SQL Injection',
            'ransomware': 'Ransomware Activity',
            'normal': 'Normal Activity'
        }
        
    def create_training_dataset(self, name: str, description: str = "") -> str:
        """
        Create a new training dataset file.
        
        Args:
            name: Dataset name
            description: Optional description
            
        Returns:
            Path to created dataset file
        """
        dataset_path = self.training_data_dir / f"{name}.json"
        
        dataset = {
            'name': name,
            'description': description,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'version': '1.0',
            'samples': []
        }
        
        with open(dataset_path, 'w') as f:
            json.dump(dataset, f, indent=2)
        
        return str(dataset_path)
    
    def add_training_sample(self, dataset_name: str, event_data: Dict[str, Any], 
                           label: str, attack_type: str, 
                           severity: str = 'medium', notes: str = "") -> bool:
        """
        Add a labeled training sample to a dataset.
        
        Args:
            dataset_name: Name of the dataset
            event_data: Event log data (can include EventID, RawLog, features, etc.)
            label: 'anomaly' or 'normal'
            attack_type: Type of attack (from anomaly_categories) or 'normal'
            severity: 'low', 'medium', 'high', 'critical'
            notes: Additional notes about this sample
            
        Returns:
            True if successful
        """
        dataset_path = self.training_data_dir / f"{dataset_name}.json"
        
        if not dataset_path.exists():
            raise FileNotFoundError(f"Dataset {dataset_name} not found")
        
        with open(dataset_path, 'r') as f:
            dataset = json.load(f)
        
        sample = {
            'id': len(dataset['samples']) + 1,
            'label': label,
            'attack_type': attack_type,
            'severity': severity,
            'event_data': event_data,
            'notes': notes,
            'added_at': datetime.now().isoformat()
        }
        
        dataset['samples'].append(sample)
        dataset['updated_at'] = datetime.now().isoformat()
        
        with open(dataset_path, 'w') as f:
            json.dump(dataset, f, indent=2)
        
        return True
    
    def load_training_dataset(self, dataset_name: str) -> Dict[str, Any]:
        """
        Load a training dataset.
        
        Args:
            dataset_name: Name of the dataset
            
        Returns:
            Dataset dictionary
        """
        dataset_path = self.training_data_dir / f"{dataset_name}.json"
        
        if not dataset_path.exists():
            raise FileNotFoundError(f"Dataset {dataset_name} not found")
        
        with open(dataset_path, 'r') as f:
            return json.load(f)
    
    def get_training_dataframe(self, dataset_name: str) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
        """
        Convert training dataset to pandas DataFrame for ML training.
        
        Args:
            dataset_name: Name of the dataset
            
        Returns:
            Tuple of (features_df, labels, attack_types)
        """
        dataset = self.load_training_dataset(dataset_name)
        
        samples = dataset['samples']
        if not samples:
            return pd.DataFrame(), pd.Series(), pd.Series()
        
        # Extract event data
        events = [s['event_data'] for s in samples]
        labels = [1 if s['label'] == 'anomaly' else 0 for s in samples]
        attack_types = [s['attack_type'] for s in samples]
        
        df = pd.DataFrame(events)
        labels_series = pd.Series(labels, name='Label')
        attack_types_series = pd.Series(attack_types, name='AttackType')
        
        return df, labels_series, attack_types_series
    
    def list_datasets(self) -> List[Dict[str, str]]:
        """
        List all available training datasets.
        
        Returns:
            List of dataset info dictionaries
        """
        datasets = []
        
        for dataset_file in self.training_data_dir.glob("*.json"):
            try:
                with open(dataset_file, 'r') as f:
                    data = json.load(f)
                    datasets.append({
                        'name': data['name'],
                        'description': data.get('description', ''),
                        'samples': len(data.get('samples', [])),
                        'created_at': data.get('created_at', ''),
                        'updated_at': data.get('updated_at', '')
                    })
            except Exception as e:
                print(f"Error loading {dataset_file}: {e}")
        
        return datasets
    
    def export_to_csv(self, dataset_name: str, output_path: str):
        """
        Export training dataset to CSV format.
        
        Args:
            dataset_name: Name of the dataset
            output_path: Path to save CSV file
        """
        df, labels, attack_types = self.get_training_dataframe(dataset_name)
        
        if df.empty:
            print(f"Dataset {dataset_name} is empty")
            return
        
        df['Label'] = labels
        df['AttackType'] = attack_types
        
        df.to_csv(output_path, index=False)
        print(f"Exported {len(df)} samples to {output_path}")
    
    def import_from_csv(self, dataset_name: str, csv_path: str, 
                       label_column: str = 'Label', 
                       attack_type_column: str = 'AttackType'):
        """
        Import training data from CSV file.
        
        Args:
            dataset_name: Name of the dataset to create/update
            csv_path: Path to CSV file
            label_column: Column name for labels (0=normal, 1=anomaly)
            attack_type_column: Column name for attack types
        """
        df = pd.read_csv(csv_path)
        
        if label_column not in df.columns:
            raise ValueError(f"Label column '{label_column}' not found in CSV")
        
        # Create dataset if it doesn't exist
        dataset_path = self.training_data_dir / f"{dataset_name}.json"
        if not dataset_path.exists():
            self.create_training_dataset(dataset_name, f"Imported from {csv_path}")
        
        # Add samples
        for idx, row in df.iterrows():
            label = 'anomaly' if row[label_column] == 1 else 'normal'
            attack_type = row.get(attack_type_column, 'normal')
            
            # Remove label columns from event data
            event_data = row.drop([label_column], errors='ignore')
            if attack_type_column in event_data:
                event_data = event_data.drop([attack_type_column])
            
            self.add_training_sample(
                dataset_name=dataset_name,
                event_data=event_data.to_dict(),
                label=label,
                attack_type=str(attack_type),
                severity='medium',
                notes=f"Imported from CSV row {idx}"
            )
        
        print(f"Imported {len(df)} samples to dataset '{dataset_name}'")
    
    def create_sample_dataset(self) -> str:
        """
        Create a sample training dataset with example anomalies.
        
        Returns:
            Path to created dataset
        """
        dataset_name = "sample_anomalies"
        self.create_training_dataset(
            dataset_name, 
            "Sample dataset with common attack patterns"
        )
        
        # Sample 1: Brute Force Attack
        self.add_training_sample(
            dataset_name=dataset_name,
            event_data={
                'EventID': 4625,
                'Level': 2,
                'Channel': 'Security',
                'Computer': 'SERVER01',
                'Hour': 2,
                'IsNightTime': 1,
                'IsFailedLogin': 1,
                'FailedLoginRatio': 0.8,
                'EventsPerMinute': 15,
                'RawLog': 'An account failed to log on. Subject: Security ID: NULL SID Account Name: - Account Domain: - Logon ID: 0x0'
            },
            label='anomaly',
            attack_type='brute_force',
            severity='high',
            notes='Multiple failed login attempts at night'
        )
        
        # Sample 2: PowerShell Exploit
        self.add_training_sample(
            dataset_name=dataset_name,
            event_data={
                'EventID': 4688,
                'Level': 2,
                'Channel': 'Security',
                'Computer': 'WORKSTATION05',
                'Hour': 14,
                'IsProcessCreation': 1,
                'LogHasPowerShell': 1,
                'LogHasBase64': 1,
                'LogHasSuspicious': 1,
                'LogEntropy': 5.2,
                'RawLog': 'A new process has been created. Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe Command Line: powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0A'
            },
            label='anomaly',
            attack_type='powershell_exploit',
            severity='critical',
            notes='Encoded PowerShell command execution'
        )
        
        # Sample 3: Privilege Escalation
        self.add_training_sample(
            dataset_name=dataset_name,
            event_data={
                'EventID': 4732,
                'Level': 2,
                'Channel': 'Security',
                'Computer': 'DC01',
                'Hour': 3,
                'IsNightTime': 1,
                'IsGroupModification': 1,
                'IsPrivilegeUse': 1,
                'RawLog': 'A member was added to a security-enabled local group. Subject: Security ID: S-1-5-21-xxx Account Name: admin Target Account: Security ID: S-1-5-21-yyy Group: Name: Administrators'
            },
            label='anomaly',
            attack_type='privilege_escalation',
            severity='critical',
            notes='User added to Administrators group at night'
        )
        
        # Sample 4: Log Tampering
        self.add_training_sample(
            dataset_name=dataset_name,
            event_data={
                'EventID': 1102,
                'Level': 1,
                'Channel': 'Security',
                'Computer': 'SERVER02',
                'Hour': 4,
                'IsNightTime': 1,
                'IsSecurityLogCleared': 1,
                'RawLog': 'The audit log was cleared. Subject: Security ID: S-1-5-21-xxx Account Name: admin'
            },
            label='anomaly',
            attack_type='defense_evasion',
            severity='critical',
            notes='Security log cleared - covering tracks'
        )
        
        # Sample 5: Lateral Movement
        self.add_training_sample(
            dataset_name=dataset_name,
            event_data={
                'EventID': 4624,
                'Level': 2,
                'Channel': 'Security',
                'Computer': 'SERVER03',
                'Hour': 2,
                'IsNightTime': 1,
                'IsSuccessfulLogin': 1,
                'IsNetworkConnection': 1,
                'UniqueIPCount': 8,
                'EventsPerMinute': 12,
                'RawLog': 'An account was successfully logged on. Logon Type: 3 (Network) Workstation Name: WORKSTATION07 Source Network Address: 192.168.1.50'
            },
            label='anomaly',
            attack_type='lateral_movement',
            severity='high',
            notes='Multiple network logins from different IPs at night'
        )
        
        # Sample 6: Persistence - Scheduled Task
        self.add_training_sample(
            dataset_name=dataset_name,
            event_data={
                'EventID': 4698,
                'Level': 2,
                'Channel': 'Security',
                'Computer': 'WORKSTATION02',
                'Hour': 23,
                'IsNightTime': 1,
                'IsScheduledTask': 1,
                'LogHasScript': 1,
                'RawLog': 'A scheduled task was created. Task Name: \\Microsoft\\Windows\\UpdateTask Actions: C:\\Windows\\Temp\\update.bat'
            },
            label='anomaly',
            attack_type='persistence',
            severity='high',
            notes='Suspicious scheduled task created at night'
        )
        
        # Sample 7: Normal Activity
        self.add_training_sample(
            dataset_name=dataset_name,
            event_data={
                'EventID': 4624,
                'Level': 2,
                'Channel': 'Security',
                'Computer': 'WORKSTATION01',
                'Hour': 9,
                'IsBusinessHours': 1,
                'IsSuccessfulLogin': 1,
                'EventsPerMinute': 2,
                'RawLog': 'An account was successfully logged on. Logon Type: 2 (Interactive) Account Name: john.doe'
            },
            label='normal',
            attack_type='normal',
            severity='low',
            notes='Normal user login during business hours'
        )
        
        # Sample 8: Normal Activity - System Event
        self.add_training_sample(
            dataset_name=dataset_name,
            event_data={
                'EventID': 7036,
                'Level': 4,
                'Channel': 'System',
                'Computer': 'SERVER01',
                'Hour': 10,
                'IsBusinessHours': 1,
                'EventsPerMinute': 1,
                'RawLog': 'The Windows Update service entered the running state.'
            },
            label='normal',
            attack_type='normal',
            severity='low',
            notes='Normal service state change'
        )
        
        print(f"✅ Created sample dataset '{dataset_name}' with 8 training samples")
        return str(self.training_data_dir / f"{dataset_name}.json")
    
    def get_statistics(self, dataset_name: str) -> Dict[str, Any]:
        """
        Get statistics about a training dataset.
        
        Args:
            dataset_name: Name of the dataset
            
        Returns:
            Statistics dictionary
        """
        dataset = self.load_training_dataset(dataset_name)
        samples = dataset['samples']
        
        if not samples:
            return {'total_samples': 0}
        
        # Count by label
        label_counts = {}
        attack_type_counts = {}
        severity_counts = {}
        
        for sample in samples:
            label = sample['label']
            attack_type = sample['attack_type']
            severity = sample['severity']
            
            label_counts[label] = label_counts.get(label, 0) + 1
            attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_samples': len(samples),
            'label_distribution': label_counts,
            'attack_type_distribution': attack_type_counts,
            'severity_distribution': severity_counts,
            'created_at': dataset.get('created_at', ''),
            'updated_at': dataset.get('updated_at', '')
        }


def create_training_template() -> Dict[str, Any]:
    """
    Create a template for manual training data entry.
    
    Returns:
        Template dictionary
    """
    return {
        'EventID': 0,  # Windows Event ID
        'Level': 2,  # 1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose
        'Channel': 'Security',  # Security, System, Application, etc.
        'Computer': 'HOSTNAME',
        'Hour': 0,  # 0-23
        'IsNightTime': 0,  # 1 if hour < 6 or hour > 22
        'IsBusinessHours': 0,  # 1 if 9 <= hour <= 17
        'IsFailedLogin': 0,  # 1 if EventID 4625
        'IsSuccessfulLogin': 0,  # 1 if EventID 4624
        'IsProcessCreation': 0,  # 1 if EventID 4688 or 1
        'IsNetworkConnection': 0,  # 1 if EventID 3 or 5156
        'IsScheduledTask': 0,  # 1 if EventID 4698, 4699, etc.
        'IsRegistryModification': 0,  # 1 if EventID 12, 13, 14, 4657
        'IsPrivilegeUse': 0,  # 1 if EventID 4672, 4673, 4674
        'IsGroupModification': 0,  # 1 if EventID 4732
        'IsSecurityLogCleared': 0,  # 1 if EventID 1102, 104, 1100
        'LogHasPowerShell': 0,  # 1 if log contains powershell
        'LogHasCmd': 0,  # 1 if log contains cmd
        'LogHasScript': 0,  # 1 if log contains script indicators
        'LogHasBase64': 0,  # 1 if log contains base64
        'LogHasSuspicious': 0,  # 1 if log contains suspicious patterns
        'EventsPerMinute': 0,  # Number of events per minute
        'FailedLoginRatio': 0.0,  # Ratio of failed logins (0.0 to 1.0)
        'UniqueIPCount': 0,  # Number of unique IPs in window
        'LogEntropy': 0.0,  # Shannon entropy of log text
        'RawLog': ''  # Raw log text
    }


if __name__ == "__main__":
    # Example usage
    manager = TrainingDataManager()
    
    # Create sample dataset
    dataset_path = manager.create_sample_dataset()
    print(f"\nSample dataset created at: {dataset_path}")
    
    # Show statistics
    stats = manager.get_statistics("sample_anomalies")
    print(f"\nDataset Statistics:")
    print(f"Total Samples: {stats['total_samples']}")
    print(f"Label Distribution: {stats['label_distribution']}")
    print(f"Attack Type Distribution: {stats['attack_type_distribution']}")
    
    # List all datasets
    print(f"\nAvailable Datasets:")
    for ds in manager.list_datasets():
        print(f"  - {ds['name']}: {ds['samples']} samples")
