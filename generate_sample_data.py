"""
Generate Sample Log Data for Testing
Creates synthetic security logs with both normal and anomalous events.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import json

def generate_sample_logs(n_normal=500, n_anomalies=50, output_format='csv'):
    """
    Generate synthetic security logs with anomalies.
    
    Args:
        n_normal: Number of normal events
        n_anomalies: Number of anomalous events
        output_format: 'csv' or 'json'
    """
    
    # Base timestamp
    base_time = datetime.now() - timedelta(days=1)
    
    # Normal events
    normal_events = []
    for i in range(n_normal):
        event = {
            'EventRecordID': i + 1,
            'TimeCreated': (base_time + timedelta(seconds=i*10)).isoformat(),
            'EventID': random.choice([4624, 4634, 4688, 4689]),  # Normal Windows events
            'Level': random.choice([4, 4, 4, 3]),  # Mostly Information
            'Computer': random.choice(['WORKSTATION01', 'WORKSTATION02', 'SERVER01']),
            'Channel': 'Security',
            'User': random.choice(['user1', 'user2', 'admin']),
            'IP': random.choice(['192.168.1.10', '192.168.1.11', '192.168.1.12']),
            'Action': random.choice(['Login', 'Logout', 'Access']),
            'ProcessID': random.randint(1000, 5000)
        }
        normal_events.append(event)
    
    # Anomalous events
    anomalous_events = []
    anomaly_types = [
        # Type 1: Failed login attempts (brute force)
        lambda i: {
            'EventRecordID': n_normal + i + 1,
            'TimeCreated': (base_time + timedelta(hours=12, seconds=i*5)).isoformat(),
            'EventID': 4625,  # Failed login
            'Level': 2,  # Error
            'Computer': 'WORKSTATION01',
            'Channel': 'Security',
            'User': 'administrator',
            'IP': '10.0.0.50',  # External IP
            'Action': 'Failed',
            'ProcessID': random.randint(1000, 2000)
        },
        # Type 2: Suspicious process execution
        lambda i: {
            'EventRecordID': n_normal + i + 1,
            'TimeCreated': (base_time + timedelta(hours=15, seconds=i*20)).isoformat(),
            'EventID': 1,  # Sysmon process creation
            'Level': 4,
            'Computer': 'SERVER01',
            'Channel': 'Microsoft-Windows-Sysmon/Operational',
            'User': 'SYSTEM',
            'IP': '192.168.1.1',
            'Action': 'Connect',
            'ProcessID': random.randint(8000, 9000),
            'RawLog': 'powershell.exe -enc base64encodedcommand'
        },
        # Type 3: Night-time activity
        lambda i: {
            'EventRecordID': n_normal + i + 1,
            'TimeCreated': (base_time + timedelta(hours=2, seconds=i*15)).isoformat(),
            'EventID': 4688,
            'Level': 4,
            'Computer': 'WORKSTATION02',
            'Channel': 'Security',
            'User': 'user3',
            'IP': '192.168.1.100',
            'Action': 'Access',
            'ProcessID': random.randint(3000, 4000)
        },
        # Type 4: Multiple unique IPs (lateral movement)
        lambda i: {
            'EventRecordID': n_normal + i + 1,
            'TimeCreated': (base_time + timedelta(hours=18, seconds=i*8)).isoformat(),
            'EventID': 3,  # Network connection
            'Level': 4,
            'Computer': 'SERVER01',
            'Channel': 'Microsoft-Windows-Sysmon/Operational',
            'User': 'admin',
            'IP': f'192.168.1.{random.randint(20, 100)}',
            'Action': 'Connect',
            'ProcessID': random.randint(5000, 6000)
        }
    ]
    
    for i in range(n_anomalies):
        anomaly_type = random.choice(anomaly_types)
        event = anomaly_type(i)
        anomalous_events.append(event)
    
    # Combine and shuffle
    all_events = normal_events + anomalous_events
    random.shuffle(all_events)
    
    # Re-sort by time
    all_events.sort(key=lambda x: x['TimeCreated'])
    
    # Save to file
    if output_format == 'csv':
        df = pd.DataFrame(all_events)
        df.to_csv('sample_security_logs.csv', index=False)
        print(f"✅ Generated sample_security_logs.csv with {len(all_events)} events")
        print(f"   - Normal events: {n_normal}")
        print(f"   - Anomalous events: {n_anomalies}")
        return 'sample_security_logs.csv'
    
    elif output_format == 'json':
        with open('sample_security_logs.json', 'w') as f:
            json.dump(all_events, f, indent=2)
        print(f"✅ Generated sample_security_logs.json with {len(all_events)} events")
        print(f"   - Normal events: {n_normal}")
        print(f"   - Anomalous events: {n_anomalies}")
        return 'sample_security_logs.json'


if __name__ == "__main__":
    print("🔧 Generating sample security logs...\n")
    
    # Generate CSV
    generate_sample_logs(n_normal=500, n_anomalies=50, output_format='csv')
    
    print("\n📖 Usage:")
    print("1. Run: streamlit run app.py")
    print("2. Upload sample_security_logs.csv")
    print("3. Parse and extract features")
    print("4. Run anomaly detection")
    print("\n✨ Expected: ~50 anomalies should be detected")
