"""
Create Training Data Template
Generates a CSV template for easy training data entry.
"""

import pandas as pd
from training_data_manager import create_training_template


def create_csv_template(output_path: str = "training_data_template.csv"):
    """
    Create a CSV template with example rows for training data.
    
    Args:
        output_path: Path to save the CSV template
    """
    # Get template
    template = create_training_template()
    
    # Create example rows
    examples = []
    
    # Example 1: Brute Force Attack
    example1 = template.copy()
    example1.update({
        'Label': 1,  # 1 = anomaly, 0 = normal
        'AttackType': 'brute_force',
        'EventID': 4625,
        'Level': 2,
        'Channel': 'Security',
        'Computer': 'SERVER01',
        'Hour': 2,
        'IsNightTime': 1,
        'IsFailedLogin': 1,
        'FailedLoginRatio': 0.8,
        'EventsPerMinute': 15,
        'RawLog': 'An account failed to log on. Multiple attempts detected.'
    })
    examples.append(example1)
    
    # Example 2: PowerShell Exploit
    example2 = template.copy()
    example2.update({
        'Label': 1,
        'AttackType': 'powershell_exploit',
        'EventID': 4688,
        'Level': 2,
        'Channel': 'Security',
        'Computer': 'WORKSTATION05',
        'Hour': 14,
        'IsProcessCreation': 1,
        'LogHasPowerShell': 1,
        'LogHasBase64': 1,
        'LogHasSuspicious': 1,
        'RawLog': 'powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0A'
    })
    examples.append(example2)
    
    # Example 3: Normal Activity
    example3 = template.copy()
    example3.update({
        'Label': 0,
        'AttackType': 'normal',
        'EventID': 4624,
        'Level': 2,
        'Channel': 'Security',
        'Computer': 'WORKSTATION01',
        'Hour': 9,
        'IsBusinessHours': 1,
        'IsSuccessfulLogin': 1,
        'EventsPerMinute': 2,
        'RawLog': 'An account was successfully logged on. User: john.doe'
    })
    examples.append(example3)
    
    # Add empty rows for user to fill
    for i in range(5):
        empty = template.copy()
        empty['Label'] = ''
        empty['AttackType'] = ''
        examples.append(empty)
    
    # Create DataFrame
    df = pd.DataFrame(examples)
    
    # Reorder columns - put Label and AttackType first
    cols = ['Label', 'AttackType'] + [col for col in df.columns if col not in ['Label', 'AttackType']]
    df = df[cols]
    
    # Save to CSV
    df.to_csv(output_path, index=False)
    print(f"✅ CSV template created: {output_path}")
    print(f"\nThe template includes:")
    print(f"  - 3 example rows (2 anomalies, 1 normal)")
    print(f"  - 5 empty rows for you to fill in")
    print(f"\nInstructions:")
    print(f"  1. Open the CSV file in Excel or any spreadsheet editor")
    print(f"  2. Fill in the empty rows with your training data")
    print(f"  3. Label: 1 for anomaly, 0 for normal")
    print(f"  4. AttackType: brute_force, powershell_exploit, etc. (or 'normal')")
    print(f"  5. Fill in as many feature columns as you have data for")
    print(f"  6. Save the file")
    print(f"  7. Import using: python train_model.py --import {output_path}")
    
    return output_path


def print_feature_descriptions():
    """Print descriptions of all features"""
    print("\n📋 Feature Descriptions:\n")
    
    features = {
        'Label': '1 = anomaly, 0 = normal (REQUIRED)',
        'AttackType': 'Type of attack or "normal" (REQUIRED)',
        'EventID': 'Windows Event ID (e.g., 4625, 4688)',
        'Level': '1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose',
        'Channel': 'Security, System, Application, etc.',
        'Computer': 'Computer/hostname',
        'Hour': 'Hour of day (0-23)',
        'IsNightTime': '1 if hour < 6 or hour > 22',
        'IsBusinessHours': '1 if 9 <= hour <= 17',
        'IsFailedLogin': '1 if EventID 4625',
        'IsSuccessfulLogin': '1 if EventID 4624',
        'IsProcessCreation': '1 if EventID 4688 or 1',
        'IsNetworkConnection': '1 if EventID 3 or 5156',
        'IsScheduledTask': '1 if EventID 4698, 4699, etc.',
        'IsRegistryModification': '1 if EventID 12, 13, 14, 4657',
        'IsPrivilegeUse': '1 if EventID 4672, 4673, 4674',
        'IsGroupModification': '1 if EventID 4732',
        'IsSecurityLogCleared': '1 if EventID 1102, 104, 1100',
        'LogHasPowerShell': '1 if log contains powershell',
        'LogHasCmd': '1 if log contains cmd',
        'LogHasScript': '1 if log contains script indicators',
        'LogHasBase64': '1 if log contains base64',
        'LogHasSuspicious': '1 if log contains suspicious patterns',
        'EventsPerMinute': 'Number of events per minute',
        'FailedLoginRatio': 'Ratio of failed logins (0.0 to 1.0)',
        'UniqueIPCount': 'Number of unique IPs in time window',
        'LogEntropy': 'Shannon entropy of log text (higher = more random)',
        'RawLog': 'Original log text'
    }
    
    for feature, description in features.items():
        print(f"  {feature:25s} - {description}")
    
    print("\n💡 Tips:")
    print("  - You don't need to fill ALL features, just the ones you have")
    print("  - Missing features will be set to 0 automatically")
    print("  - Focus on Label, AttackType, EventID, and RawLog as minimum")
    print("  - More features = better model accuracy")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--help':
        print_feature_descriptions()
    else:
        output = "training_data_template.csv"
        if len(sys.argv) > 1:
            output = sys.argv[1]
        
        create_csv_template(output)
        print("\nFor feature descriptions, run: python create_training_template.py --help")
