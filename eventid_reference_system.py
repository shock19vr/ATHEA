"""
Windows System Event ID Reference Database
Key System log EventIDs with risk scores and MITRE ATT&CK mappings.
"""

SYSTEM_EVENTS = {
    7030: {
        "name": "Service Control Manager",
        "category": "System",
        "risk_score": 8,
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1543.003"],
        "description": "Service marked as interactive",
        "suspicious_when": ["Non-interactive service", "Backdoor", "Unauthorized"],
        "severity": "High"
    },
    7034: {
        "name": "Service Crashed",
        "category": "System",
        "risk_score": 6,
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1489"],
        "description": "Service terminated unexpectedly",
        "suspicious_when": ["Security service", "EDR", "Antivirus", "Multiple crashes"],
        "severity": "Medium"
    },
    7035: {
        "name": "Service Control",
        "category": "System",
        "risk_score": 5,
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1569.002"],
        "description": "Service sent start/stop control",
        "suspicious_when": ["Security service stopped", "Unauthorized user"],
        "severity": "Medium"
    },
    7036: {
        "name": "Service State Change",
        "category": "System",
        "risk_score": 6,
        "mitre_tactics": ["Defense Evasion", "Persistence"],
        "mitre_techniques": ["T1562.001", "T1543.003"],
        "description": "Service entered stopped/running state",
        "suspicious_when": ["Security service stopped", "New service started", "EDR disabled"],
        "severity": "Medium"
    },
    7040: {
        "name": "Service Startup Type Changed",
        "category": "System",
        "risk_score": 7,
        "mitre_tactics": ["Persistence", "Defense Evasion"],
        "mitre_techniques": ["T1543.003", "T1562.001"],
        "description": "Service start type was changed",
        "suspicious_when": ["Disabled to Auto", "Security service", "Unauthorized"],
        "severity": "High"
    },
    7045: {
        "name": "Service Installed",
        "category": "System",
        "risk_score": 9,
        "mitre_tactics": ["Persistence", "Lateral Movement"],
        "mitre_techniques": ["T1543.003", "T1021.002"],
        "description": "A service was installed in the system",
        "suspicious_when": ["PSExec pattern", "SYSTEM account", "Unusual binary", "Remote"],
        "severity": "Critical"
    },
    104: {
        "name": "Log Cleared",
        "category": "System",
        "risk_score": 10,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1070.001"],
        "description": "Event log was cleared",
        "suspicious_when": ["Security log", "During incident", "Unauthorized", "Cover tracks"],
        "severity": "Critical"
    },
    106: {
        "name": "Task Scheduler Event",
        "category": "Task Scheduler",
        "risk_score": 6,
        "mitre_tactics": ["Persistence", "Execution"],
        "mitre_techniques": ["T1053.005"],
        "description": "Scheduled task registered",
        "suspicious_when": ["SYSTEM account", "Suspicious command", "Encoded"],
        "severity": "Medium"
    },
    140: {
        "name": "Task Scheduler Updated",
        "category": "Task Scheduler",
        "risk_score": 6,
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1053.005"],
        "description": "Scheduled task updated",
        "suspicious_when": ["Modified action", "Privilege change"],
        "severity": "Medium"
    },
    141: {
        "name": "Task Scheduler Deleted",
        "category": "Task Scheduler",
        "risk_score": 5,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1070"],
        "description": "Scheduled task deleted",
        "suspicious_when": ["Security task", "Monitoring task"],
        "severity": "Medium"
    },
    200: {
        "name": "Task Scheduler Action Started",
        "category": "Task Scheduler",
        "risk_score": 5,
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1053.005"],
        "description": "Scheduled task action started",
        "suspicious_when": ["PowerShell", "CMD", "Suspicious binary"],
        "severity": "Medium"
    },
    201: {
        "name": "Task Scheduler Action Completed",
        "category": "Task Scheduler",
        "risk_score": 4,
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1053.005"],
        "description": "Scheduled task action completed",
        "suspicious_when": ["Failed action", "Unusual timing"],
        "severity": "Low"
    },
    4103: {
        "name": "PowerShell Module Logging",
        "category": "PowerShell",
        "risk_score": 5,
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1059.001"],
        "description": "PowerShell module logging event",
        "suspicious_when": ["Encoded commands", "Download", "Invoke-Expression"],
        "severity": "Medium"
    },
    4104: {
        "name": "PowerShell Script Block Logging",
        "category": "PowerShell",
        "risk_score": 6,
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1059.001"],
        "description": "PowerShell script block logging",
        "suspicious_when": ["Obfuscation", "Mimikatz", "Download", "Base64"],
        "severity": "High"
    },
    800: {
        "name": "Named Pipe Created",
        "category": "Application",
        "risk_score": 6,
        "mitre_tactics": ["Execution", "Lateral Movement"],
        "mitre_techniques": ["T1559"],
        "description": "Named pipe IPC created",
        "suspicious_when": ["Cobalt Strike", "Meterpreter", "Known malicious pipes"],
        "severity": "Medium"
    }
}


def get_system_event_info(event_id):
    """Get information about a specific System EventID"""
    return SYSTEM_EVENTS.get(event_id, {
        "name": f"Unknown System Event {event_id}",
        "category": "Unknown",
        "risk_score": 5,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "description": "System event not in reference database",
        "suspicious_when": [],
        "severity": "Unknown"
    })
