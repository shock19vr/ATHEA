"""
Sysmon Event ID Reference Database
Complete reference for Sysmon log EventIDs with risk scores and MITRE ATT&CK mappings.
"""

SYSMON_EVENTS = {
    1: {
        "name": "Process Creation",
        "category": "Process Activity",
        "risk_score": 5,
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1059"],
        "description": "Process Create events provide extended information about newly created processes",
        "suspicious_when": ["PowerShell", "CMD with encoded commands", "LOLBins", "Mimikatz", "Suspicious parent"],
        "severity": "Medium",
        "key_fields": ["CommandLine", "ParentImage", "User"]
    },
    2: {
        "name": "File Creation Time Changed",
        "category": "File Activity",
        "risk_score": 7,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1070.006"],
        "description": "File creation time was explicitly modified",
        "suspicious_when": ["Timestomping", "Anti-forensics", "Malware"],
        "severity": "High",
        "key_fields": ["Image", "TargetFilename", "CreationUtcTime"]
    },
    3: {
        "name": "Network Connection",
        "category": "Network Activity",
        "risk_score": 4,
        "mitre_tactics": ["Command and Control", "Exfiltration"],
        "mitre_techniques": ["T1071", "T1041"],
        "description": "Network connection detected",
        "suspicious_when": ["Known C2 IP", "Unusual port", "Suspicious process", "Beaconing"],
        "severity": "Medium",
        "key_fields": ["Image", "DestinationIp", "DestinationPort", "DestinationHostname"]
    },
    4: {
        "name": "Sysmon Service State Changed",
        "category": "Sysmon",
        "risk_score": 8,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.001"],
        "description": "Sysmon service state changed",
        "suspicious_when": ["Service stopped", "Configuration changed", "Unauthorized"],
        "severity": "High",
        "key_fields": ["State"]
    },
    5: {
        "name": "Process Terminated",
        "category": "Process Activity",
        "risk_score": 3,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562"],
        "description": "Process terminated",
        "suspicious_when": ["Security tool termination", "EDR killed", "Rapid churn"],
        "severity": "Low",
        "key_fields": ["Image", "ProcessId"]
    },
    6: {
        "name": "Driver Loaded",
        "category": "Driver Activity",
        "risk_score": 7,
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "mitre_techniques": ["T1543.003", "T1068"],
        "description": "Driver loaded into kernel",
        "suspicious_when": ["Unsigned driver", "Known malicious", "Rootkit", "Unusual location"],
        "severity": "High",
        "key_fields": ["ImageLoaded", "Signed", "Signature"]
    },
    7: {
        "name": "Image Loaded",
        "category": "Process Activity",
        "risk_score": 4,
        "mitre_tactics": ["Defense Evasion", "Execution"],
        "mitre_techniques": ["T1055"],
        "description": "DLL/image loaded by a process",
        "suspicious_when": ["DLL injection", "Reflective loading", "Unsigned DLL", "Suspicious location"],
        "severity": "Medium",
        "key_fields": ["Image", "ImageLoaded", "Signed"]
    },
    8: {
        "name": "CreateRemoteThread",
        "category": "Process Activity",
        "risk_score": 9,
        "mitre_tactics": ["Privilege Escalation", "Defense Evasion"],
        "mitre_techniques": ["T1055", "T1055.001"],
        "description": "Remote thread created in another process",
        "suspicious_when": ["Process injection", "Code injection", "Privilege escalation", "LSASS injection", "Elevated process target"],
        "severity": "High",
        "key_fields": ["SourceImage", "TargetImage", "StartAddress"]
    },
    9: {
        "name": "RawAccessRead",
        "category": "Disk Activity",
        "risk_score": 9,
        "mitre_tactics": ["Credential Access", "Defense Evasion"],
        "mitre_techniques": ["T1003"],
        "description": "Raw access to drive data",
        "suspicious_when": ["LSASS dumping", "Volume Shadow Copy", "Credential theft", "Ransomware"],
        "severity": "Critical",
        "key_fields": ["Image", "Device"]
    },
    10: {
        "name": "ProcessAccess",
        "category": "Process Activity",
        "risk_score": 9,
        "mitre_tactics": ["Credential Access", "Privilege Escalation"],
        "mitre_techniques": ["T1003.001", "T1134"],
        "description": "Process accessed another process memory",
        "suspicious_when": ["LSASS access", "Credential dumping", "Mimikatz", "Process hollowing", "Token manipulation", "Elevated process access"],
        "severity": "High",
        "key_fields": ["SourceImage", "TargetImage", "GrantedAccess"]
    },
    11: {
        "name": "FileCreate",
        "category": "File Activity",
        "risk_score": 5,
        "mitre_tactics": ["Persistence", "Defense Evasion"],
        "mitre_techniques": ["T1105"],
        "description": "File created",
        "suspicious_when": ["Startup folder", "Temp files", "Malware drop", "Script files"],
        "severity": "Medium",
        "key_fields": ["Image", "TargetFilename"]
    },
    12: {
        "name": "RegistryEvent (Object create/delete)",
        "category": "Registry Activity",
        "risk_score": 6,
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "mitre_techniques": ["T1547"],
        "description": "Registry object added or deleted",
        "suspicious_when": ["Run keys", "Services", "Autostart", "Image File Execution Options"],
        "severity": "Medium",
        "key_fields": ["EventType", "TargetObject", "Image"]
    },
    13: {
        "name": "RegistryEvent (Value Set)",
        "category": "Registry Activity",
        "risk_score": 6,
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "mitre_techniques": ["T1547"],
        "description": "Registry value set",
        "suspicious_when": ["Run keys", "Services", "LSA", "WDigest", "Security settings"],
        "severity": "Medium",
        "key_fields": ["TargetObject", "Details", "Image"]
    },
    14: {
        "name": "RegistryEvent (Key/Value Rename)",
        "category": "Registry Activity",
        "risk_score": 5,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1112"],
        "description": "Registry key and value renamed",
        "suspicious_when": ["Security keys", "Anti-forensics", "Hiding persistence"],
        "severity": "Medium",
        "key_fields": ["TargetObject", "NewName", "Image"]
    },
    15: {
        "name": "FileCreateStreamHash",
        "category": "File Activity",
        "risk_score": 7,
        "mitre_tactics": ["Defense Evasion", "Execution"],
        "mitre_techniques": ["T1564.004"],
        "description": "Alternate Data Stream (ADS) created",
        "suspicious_when": ["Zone.Identifier bypass", "Hidden payloads", "Data hiding"],
        "severity": "High",
        "key_fields": ["TargetFilename", "Contents", "Hash"]
    },
    16: {
        "name": "ServiceConfigurationChange",
        "category": "System Activity",
        "risk_score": 7,
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "mitre_techniques": ["T1543.003"],
        "description": "Sysmon configuration changed",
        "suspicious_when": ["Unauthorized change", "Weakened monitoring", "Evasion"],
        "severity": "High",
        "key_fields": ["State"]
    },
    17: {
        "name": "PipeEvent (Pipe Created)",
        "category": "IPC Activity",
        "risk_score": 6,
        "mitre_tactics": ["Execution", "Lateral Movement"],
        "mitre_techniques": ["T1559"],
        "description": "Named pipe created",
        "suspicious_when": ["Cobalt Strike pipe", "Meterpreter", "C2 communication"],
        "severity": "Medium",
        "key_fields": ["PipeName", "Image"]
    },
    18: {
        "name": "PipeEvent (Pipe Connected)",
        "category": "IPC Activity",
        "risk_score": 5,
        "mitre_tactics": ["Execution", "Lateral Movement"],
        "mitre_techniques": ["T1559"],
        "description": "Named pipe connected",
        "suspicious_when": ["Known malicious pipe", "C2 beacon", "PSExec"],
        "severity": "Medium",
        "key_fields": ["PipeName", "Image"]
    },
    19: {
        "name": "WmiEvent (WmiEventFilter)",
        "category": "WMI Activity",
        "risk_score": 8,
        "mitre_tactics": ["Persistence", "Execution"],
        "mitre_techniques": ["T1546.003"],
        "description": "WMI event filter activity detected",
        "suspicious_when": ["Persistence mechanism", "Fileless malware", "Unauthorized"],
        "severity": "High",
        "key_fields": ["EventNamespace", "Name", "Query"]
    },
    20: {
        "name": "WmiEvent (WmiEventConsumer)",
        "category": "WMI Activity",
        "risk_score": 8,
        "mitre_tactics": ["Persistence", "Execution"],
        "mitre_techniques": ["T1546.003"],
        "description": "WMI event consumer activity detected",
        "suspicious_when": ["Command line consumer", "Script execution", "Persistence"],
        "severity": "High",
        "key_fields": ["Name", "Type", "Destination"]
    },
    21: {
        "name": "WmiEvent (WmiEventConsumerToFilter)",
        "category": "WMI Activity",
        "risk_score": 9,
        "mitre_tactics": ["Persistence", "Execution"],
        "mitre_techniques": ["T1546.003"],
        "description": "WMI consumer to filter binding detected",
        "suspicious_when": ["WMI persistence", "Fileless attack", "APT activity"],
        "severity": "Critical",
        "key_fields": ["Consumer", "Filter"]
    },
    22: {
        "name": "DNSEvent (DNS query)",
        "category": "Network Activity",
        "risk_score": 4,
        "mitre_tactics": ["Command and Control"],
        "mitre_techniques": ["T1071.004"],
        "description": "DNS query recorded",
        "suspicious_when": ["Known C2 domain", "DGA domains", "DNS tunneling", "Suspicious TLD"],
        "severity": "Low",
        "key_fields": ["QueryName", "QueryResults", "Image"]
    },
    23: {
        "name": "FileDelete (File Deleted)",
        "category": "File Activity",
        "risk_score": 6,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1070.004"],
        "description": "File deletion logged (archived)",
        "suspicious_when": ["Log deletion", "Evidence removal", "Ransomware", "Anti-forensics"],
        "severity": "Medium",
        "key_fields": ["Image", "TargetFilename", "Archived"]
    },
    24: {
        "name": "ClipboardChange",
        "category": "Data Activity",
        "risk_score": 7,
        "mitre_tactics": ["Collection"],
        "mitre_techniques": ["T1115"],
        "description": "Clipboard content changed",
        "suspicious_when": ["Credential theft", "Cryptocurrency address swap", "Data theft"],
        "severity": "High",
        "key_fields": ["Image", "Session", "ClientInfo"]
    },
    25: {
        "name": "ProcessTampering",
        "category": "Process Activity",
        "risk_score": 9,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1055"],
        "description": "Process image tampering detected",
        "suspicious_when": ["Process hollowing", "Code injection", "Reflective loading"],
        "severity": "Critical",
        "key_fields": ["Image", "Type"]
    },
    26: {
        "name": "FileDeleteDetected",
        "category": "File Activity",
        "risk_score": 5,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1070.004"],
        "description": "File delete detected (not archived)",
        "suspicious_when": ["Mass deletion", "Ransomware", "Cover tracks"],
        "severity": "Medium",
        "key_fields": ["Image", "TargetFilename"]
    },
    27: {
        "name": "FileBlockExecutable",
        "category": "File Activity",
        "risk_score": 8,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1036"],
        "description": "File block executable detected",
        "suspicious_when": ["Blocked executable", "Suspicious binary", "Malware prevention"],
        "severity": "High",
        "key_fields": ["Image", "TargetFilename"]
    },
    28: {
        "name": "FileBlockShredding",
        "category": "File Activity",
        "risk_score": 7,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1070.004"],
        "description": "File block shredding detected",
        "suspicious_when": ["Secure deletion", "Anti-forensics", "Evidence destruction"],
        "severity": "High",
        "key_fields": ["Image", "TargetFilename"]
    },
    29: {
        "name": "FileExecutableDetected",
        "category": "File Activity",
        "risk_score": 6,
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1204.002"],
        "description": "Executable file detected",
        "suspicious_when": ["Downloads folder", "Temp folder", "Suspicious location"],
        "severity": "Medium",
        "key_fields": ["Image", "TargetFilename"]
    }
}


def get_sysmon_event_info(event_id):
    """Get information about a specific Sysmon EventID"""
    return SYSMON_EVENTS.get(event_id, {
        "name": f"Unknown Sysmon Event {event_id}",
        "category": "Unknown",
        "risk_score": 5,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "description": "Sysmon event not in reference database",
        "suspicious_when": [],
        "severity": "Unknown",
        "key_fields": []
    })


def get_critical_sysmon_events():
    """Get Sysmon events with Critical or High severity"""
    return {eid: info for eid, info in SYSMON_EVENTS.items() 
            if info.get("severity") in ["Critical", "High"]}
