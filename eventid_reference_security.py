"""
Windows Security Event ID Reference Database
Complete reference for Windows Security log EventIDs with risk scores and MITRE ATT&CK mappings.
"""

SECURITY_EVENTS = {
    # ===== ACCOUNT LOGON EVENTS (4768-4776) =====
    4768: {
        "name": "Kerberos TGT Requested",
        "category": "Account Logon",
        "risk_score": 3,
        "mitre_tactics": ["Initial Access", "Credential Access"],
        "mitre_techniques": ["T1078", "T1558"],
        "description": "Kerberos authentication ticket (TGT) was requested",
        "suspicious_when": ["Unusual time", "Service account", "Multiple failures"],
        "severity": "Medium"
    },
    4769: {
        "name": "Kerberos Service Ticket Requested",
        "category": "Account Logon",
        "risk_score": 5,
        "mitre_tactics": ["Credential Access", "Lateral Movement"],
        "mitre_techniques": ["T1558.003"],
        "description": "Kerberos service ticket was requested",
        "suspicious_when": ["Kerberoasting attack", "RC4 encryption (weak)", "Multiple service tickets", 
                          "Unusual service SPNs", "High-privilege account targets"],
        "severity": "Medium"
    },
    4770: {
        "name": "Kerberos Service Ticket Renewed",
        "category": "Account Logon",
        "risk_score": 2,
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1078"],
        "description": "Kerberos service ticket was renewed",
        "suspicious_when": ["Excessive renewals", "Unusual timing"],
        "severity": "Low"
    },
    4771: {
        "name": "Kerberos Pre-authentication Failed",
        "category": "Account Logon",
        "risk_score": 6,
        "mitre_tactics": ["Initial Access", "Credential Access"],
        "mitre_techniques": ["T1110.003"],
        "description": "Kerberos pre-authentication failed",
        "suspicious_when": ["Multiple failures", "Password spray", "Brute force"],
        "severity": "High"
    },
    4776: {
        "name": "NTLM Authentication",
        "category": "Account Logon",
        "risk_score": 6,
        "mitre_tactics": ["Credential Access", "Lateral Movement"],
        "mitre_techniques": ["T1550.002", "T1557.001"],
        "description": "Computer attempted to validate credentials using NTLM",
        "suspicious_when": ["Pass-the-hash attack", "NTLM relay", "Multiple failures", 
                          "Admin account NTLM", "Downgrade from Kerberos", "External source"],
        "severity": "Medium"
    },
    
    # ===== LOGON/LOGOFF EVENTS (4624-4648) =====
    4624: {
        "name": "Successful Logon",
        "category": "Logon/Logoff",
        "risk_score": 2,
        "mitre_tactics": ["Initial Access", "Lateral Movement"],
        "mitre_techniques": ["T1078", "T1021"],
        "description": "An account was successfully logged on",
        "suspicious_when": ["Type 3 from external IP", "Type 10 RDP", "Service account", "Night time"],
        "severity": "Low"
    },
    4625: {
        "name": "Failed Logon",
        "category": "Logon/Logoff",
        "risk_score": 7,
        "mitre_tactics": ["Initial Access", "Credential Access"],
        "mitre_techniques": ["T1110"],
        "description": "An account failed to log on",
        "suspicious_when": ["Multiple attempts", "Password spray", "Brute force", "External IP"],
        "severity": "High"
    },
    4634: {
        "name": "Logoff",
        "category": "Logon/Logoff",
        "risk_score": 1,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "description": "An account was logged off",
        "suspicious_when": ["Unexpected logoff", "Session hijacking"],
        "severity": "Info"
    },
    4647: {
        "name": "User Initiated Logoff",
        "category": "Logon/Logoff",
        "risk_score": 1,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "description": "User initiated logoff",
        "suspicious_when": [],
        "severity": "Info"
    },
    4648: {
        "name": "Logon Using Explicit Credentials",
        "category": "Logon/Logoff",
        "risk_score": 5,
        "mitre_tactics": ["Lateral Movement", "Privilege Escalation"],
        "mitre_techniques": ["T1078", "T1021.002"],
        "description": "A logon was attempted using explicit credentials",
        "suspicious_when": ["RunAs", "PsExec", "Unusual user", "External source"],
        "severity": "Medium"
    },
    
    # ===== PROCESS TRACKING (4688-4689) =====
    4688: {
        "name": "Process Created",
        "category": "Process Tracking",
        "risk_score": 4,
        "mitre_tactics": ["Execution", "Persistence"],
        "mitre_techniques": ["T1059", "T1543"],
        "description": "A new process has been created",
        "suspicious_when": ["PowerShell", "CMD", "Suspicious binary", "Encoded commands", "Service creation", "Scheduled task", "Registry modification"],
        "severity": "Medium"
    },
    4689: {
        "name": "Process Terminated",
        "category": "Process Tracking",
        "risk_score": 2,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "description": "A process has exited",
        "suspicious_when": ["Security tool termination", "Rapid process churn"],
        "severity": "Low"
    },
    
    # ===== PRIVILEGE USE (4672-4674) =====
    4672: {
        "name": "Special Privileges Assigned",
        "category": "Privilege Use",
        "risk_score": 6,
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1078.002"],
        "description": "Special privileges assigned to new logon",
        "suspicious_when": ["Service account", "Unusual user", "External logon"],
        "severity": "High"
    },
    4673: {
        "name": "Sensitive Privilege Use",
        "category": "Privilege Use",
        "risk_score": 7,
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1134"],
        "description": "A privileged service was called",
        "suspicious_when": ["Token manipulation", "Debug privilege", "Backup privilege"],
        "severity": "High"
    },
    4674: {
        "name": "Operation on Privileged Object",
        "category": "Privilege Use",
        "risk_score": 5,
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1134"],
        "description": "An operation was attempted on a privileged object",
        "suspicious_when": ["SAM database", "LSA secrets", "Registry hives"],
        "severity": "Medium"
    },
    4704: {
        "name": "User Right Assigned",
        "category": "User Rights Assignment",
        "risk_score": 8,
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "mitre_techniques": ["T1078", "T1098"],
        "description": "A user right was assigned to an account",
        "suspicious_when": ["SeDebugPrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege", 
                          "SeLoadDriverPrivilege", "Unusual account", "Service account"],
        "severity": "High"
    },
    4705: {
        "name": "User Right Removed",
        "category": "User Rights Assignment",
        "risk_score": 7,
        "mitre_tactics": ["Defense Evasion", "Privilege Escalation"],
        "mitre_techniques": ["T1562.001", "T1078"],
        "description": "A user right was removed from an account",
        "suspicious_when": ["Security monitoring disabled", "Admin rights removed", "Cover tracks"],
        "severity": "High"
    },
    4717: {
        "name": "System Security Access Granted",
        "category": "Security Access Management",
        "risk_score": 8,
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "mitre_techniques": ["T1098", "T1068"],
        "description": "System security access was granted to an account",
        "suspicious_when": ["SecurityPrivilege", "SystemEnvironmentPrivilege", "CreateTokenPrivilege", 
                          "TcbPrivilege", "Unusual account", "Non-admin user"],
        "severity": "High"
    },
    4718: {
        "name": "System Security Access Removed",
        "category": "Security Access Management",
        "risk_score": 6,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.001"],
        "description": "System security access was removed from an account",
        "suspicious_when": ["Security monitoring disabled", "Admin access removed", "Cover tracks"],
        "severity": "Medium"
    },
    
    # ===== POLICY CHANGE (4719, 4739) =====
    4719: {
        "name": "System Audit Policy Changed",
        "category": "Policy Change",
        "risk_score": 9,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.002"],
        "description": "System audit policy was changed",
        "suspicious_when": ["Disabling auditing", "Unauthorized change", "Night time"],
        "severity": "Critical"
    },
    4739: {
        "name": "Domain Policy Changed",
        "category": "Policy Change",
        "risk_score": 7,
        "mitre_tactics": ["Defense Evasion", "Persistence"],
        "mitre_techniques": ["T1484"],
        "description": "Domain policy was changed",
        "suspicious_when": ["Password policy weakened", "Unauthorized admin"],
        "severity": "High"
    },
    
    # ===== ACCOUNT MANAGEMENT (4720-4732) =====
    4720: {
        "name": "User Account Created",
        "category": "Account Management",
        "risk_score": 6,
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1136.001"],
        "description": "A user account was created",
        "suspicious_when": ["Local account", "Unusual time", "Unauthorized admin"],
        "severity": "Medium"
    },
    4722: {
        "name": "User Account Enabled",
        "category": "Account Management",
        "risk_score": 5,
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1098"],
        "description": "A user account was enabled",
        "suspicious_when": ["Disabled service account", "Dormant account", "Night time"],
        "severity": "Medium"
    },
    4723: {
        "name": "Password Change Attempt",
        "category": "Account Management",
        "risk_score": 5,
        "mitre_tactics": ["Persistence", "Credential Access"],
        "mitre_techniques": ["T1098"],
        "description": "An attempt was made to change an account's password",
        "suspicious_when": ["Service account", "Admin account", "Unusual user", "Failed attempt"],
        "severity": "Medium"
    },
    4724: {
        "name": "Password Reset Attempt",
        "category": "Account Management",
        "risk_score": 6,
        "mitre_tactics": ["Credential Access", "Persistence"],
        "mitre_techniques": ["T1098"],
        "description": "An attempt was made to reset an account password",
        "suspicious_when": ["Admin account", "Service account", "Unauthorized user"],
        "severity": "High"
    },
    4725: {
        "name": "User Account Disabled",
        "category": "Account Management",
        "risk_score": 4,
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1531"],
        "description": "A user account was disabled",
        "suspicious_when": ["Admin account", "Mass disable", "Ransomware"],
        "severity": "Medium"
    },
    4726: {
        "name": "User Account Deleted",
        "category": "Account Management",
        "risk_score": 5,
        "mitre_tactics": ["Impact", "Defense Evasion"],
        "mitre_techniques": ["T1531", "T1070"],
        "description": "A user account was deleted",
        "suspicious_when": ["Admin account", "Active account", "Cover tracks"],
        "severity": "Medium"
    },
    4738: {
        "name": "User Account Changed",
        "category": "Account Management",
        "risk_score": 6,
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "mitre_techniques": ["T1098"],
        "description": "A user account was changed",
        "suspicious_when": ["Privilege escalation", "Password never expires", "Account unlock", "UAC flags modified"],
        "severity": "Medium"
    },
    4728: {
        "name": "Member Added to Global Group",
        "category": "Account Management",
        "risk_score": 7,
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "mitre_techniques": ["T1098"],
        "description": "A member was added to a security-enabled global group",
        "suspicious_when": ["Domain Admins", "Enterprise Admins", "Unauthorized change"],
        "severity": "High"
    },
    4732: {
        "name": "Member Added to Local Group",
        "category": "Account Management",
        "risk_score": 8,
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "mitre_techniques": ["T1078.003"],
        "description": "A member was added to a security-enabled local group",
        "suspicious_when": ["Administrators group", "Backup Operators", "Unauthorized"],
        "severity": "High"
    },
    4733: {
        "name": "Member Removed from Local Group",
        "category": "Account Management",
        "risk_score": 5,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1070"],
        "description": "A member was removed from a security-enabled local group",
        "suspicious_when": ["Security group", "Cover tracks"],
        "severity": "Medium"
    },
    4756: {
        "name": "Member Added to Universal Security Group",
        "category": "Account Management",
        "risk_score": 7,
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "mitre_techniques": ["T1098"],
        "description": "A member was added to a security-enabled universal group",
        "suspicious_when": ["Domain-wide group", "Unauthorized admin", "Privilege escalation"],
        "severity": "High"
    },
    4735: {
        "name": "Security-Enabled Local Group Changed",
        "category": "Account Management",
        "risk_score": 7,
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "mitre_techniques": ["T1098"],
        "description": "A security-enabled local group was changed",
        "suspicious_when": ["Administrators group", "Remote Desktop Users", "Unauthorized modification"],
        "severity": "High"
    },
    4737: {
        "name": "Security-Enabled Global Group Changed",
        "category": "Account Management",
        "risk_score": 7,
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "mitre_techniques": ["T1098", "T1484"],
        "description": "A security-enabled global group was changed",
        "suspicious_when": ["Domain Admins", "Enterprise Admins", "Schema Admins", "Unauthorized"],
        "severity": "High"
    },
    4755: {
        "name": "Security-Enabled Universal Group Changed",
        "category": "Account Management",
        "risk_score": 7,
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "mitre_techniques": ["T1098"],
        "description": "A security-enabled universal group was changed",
        "suspicious_when": ["Domain-wide privileges", "Cross-forest access", "Unauthorized"],
        "severity": "High"
    },
    4794: {
        "name": "Directory Services Restore Mode Password Set",
        "category": "Account Management",
        "risk_score": 9,
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "mitre_techniques": ["T1098"],
        "description": "DSRM administrator password was set (Domain Controller)",
        "suspicious_when": ["Unauthorized admin", "Backdoor access", "Domain Controller compromise"],
        "severity": "Critical"
    },
    
    # ===== SCHEDULED TASKS (4698-4702) =====
    4698: {
        "name": "Scheduled Task Created",
        "category": "Task Scheduler",
        "risk_score": 7,
        "mitre_tactics": ["Persistence", "Execution"],
        "mitre_techniques": ["T1053.005"],
        "description": "A scheduled task was created",
        "suspicious_when": ["SYSTEM account", "Suspicious command", "Encoded script", "Remote creation"],
        "severity": "High"
    },
    4699: {
        "name": "Scheduled Task Deleted",
        "category": "Task Scheduler",
        "risk_score": 5,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1070"],
        "description": "A scheduled task was deleted",
        "suspicious_when": ["Security task", "Cover tracks", "Unauthorized"],
        "severity": "Medium"
    },
    4700: {
        "name": "Scheduled Task Enabled",
        "category": "Task Scheduler",
        "risk_score": 6,
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1053.005"],
        "description": "A scheduled task was enabled",
        "suspicious_when": ["Previously disabled", "Unauthorized", "Suspicious timing"],
        "severity": "Medium"
    },
    4701: {
        "name": "Scheduled Task Disabled",
        "category": "Task Scheduler",
        "risk_score": 6,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.001"],
        "description": "A scheduled task was disabled",
        "suspicious_when": ["Security task", "Monitoring disabled", "Unauthorized"],
        "severity": "Medium"
    },
    
    # ===== OBJECT ACCESS (4656-4663) =====
    4656: {
        "name": "Handle to Object Requested",
        "category": "Object Access",
        "risk_score": 7,
        "mitre_tactics": ["Credential Access", "Collection"],
        "mitre_techniques": ["T1003.001", "T1003.002"],
        "description": "A handle to an object was requested",
        "suspicious_when": ["LSASS process access", "SAM database", "SECURITY registry hive", 
                          "Credential Manager", "Unusual process requesting access"],
        "severity": "High"
    },
    4657: {
        "name": "Registry Value Modified",
        "category": "Object Access",
        "risk_score": 6,
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "mitre_techniques": ["T1547"],
        "description": "A registry value was modified",
        "suspicious_when": ["Run keys", "Services", "LSA", "Unusual location"],
        "severity": "High"
    },
    4658: {
        "name": "Handle to Object Closed",
        "category": "Object Access",
        "risk_score": 2,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "description": "The handle to an object was closed",
        "suspicious_when": [],
        "severity": "Low"
    },
    4661: {
        "name": "Handle to Object Requested (SAM/AD)",
        "category": "Object Access",
        "risk_score": 8,
        "mitre_tactics": ["Credential Access", "Discovery"],
        "mitre_techniques": ["T1003.002", "T1003.003", "T1087"],
        "description": "A handle to an object was requested (SAM database, AD objects)",
        "suspicious_when": ["SAM database access", "NTDS.dit access", "AD object enumeration", 
                          "Unusual account", "Non-admin access", "LSASS process"],
        "severity": "High"
    },
    4662: {
        "name": "Operation Performed on Object (AD)",
        "category": "Directory Service Access",
        "risk_score": 7,
        "mitre_tactics": ["Credential Access", "Discovery"],
        "mitre_techniques": ["T1003.006", "T1087.002"],
        "description": "An operation was performed on an Active Directory object",
        "suspicious_when": ["DCSync attack", "AdminSDHolder access", "KRBTGT access", 
                          "Replication rights", "DS-Replication-Get-Changes"],
        "severity": "High"
    },
    4663: {
        "name": "Object Access Attempted",
        "category": "Object Access",
        "risk_score": 6,
        "mitre_tactics": ["Credential Access", "Collection"],
        "mitre_techniques": ["T1003.002", "T1003.003"],
        "description": "An attempt was made to access an object",
        "suspicious_when": ["SAM database", "NTDS.dit", "SECURITY registry", "Credential files", "LSASS dump file"],
        "severity": "Medium"
    },
    
    # ===== SCHEDULED TASKS (4698-4702) =====
    4698: {
        "name": "Scheduled Task Created",
        "category": "Task Scheduler",
        "risk_score": 7,
        "mitre_tactics": ["Persistence", "Execution"],
        "mitre_techniques": ["T1053.005"],
        "description": "A scheduled task was created",
        "suspicious_when": ["SYSTEM account", "PowerShell/CMD", "Encoded commands"],
        "severity": "High"
    },
    4699: {
        "name": "Scheduled Task Deleted",
        "category": "Task Scheduler",
        "risk_score": 5,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1070"],
        "description": "A scheduled task was deleted",
        "suspicious_when": ["Security task", "Monitoring task", "Cover tracks"],
        "severity": "Medium"
    },
    4700: {
        "name": "Scheduled Task Enabled",
        "category": "Task Scheduler",
        "risk_score": 6,
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1053.005"],
        "description": "A scheduled task was enabled",
        "suspicious_when": ["Previously disabled", "Suspicious task"],
        "severity": "Medium"
    },
    4701: {
        "name": "Scheduled Task Disabled",
        "category": "Task Scheduler",
        "risk_score": 5,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562"],
        "description": "A scheduled task was disabled",
        "suspicious_when": ["Security task", "Monitoring task"],
        "severity": "Medium"
    },
    4702: {
        "name": "Scheduled Task Updated",
        "category": "Task Scheduler",
        "risk_score": 6,
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1053.005"],
        "description": "A scheduled task was updated",
        "suspicious_when": ["Modified action", "Changed timing", "Privilege change"],
        "severity": "Medium"
    },
    
    # ===== SERVICE EVENTS (4697, 7045) =====
    4697: {
        "name": "Service Installed",
        "category": "System",
        "risk_score": 9,
        "mitre_tactics": ["Persistence", "Lateral Movement"],
        "mitre_techniques": ["T1543.003", "T1021.002"],
        "description": "A service was installed in the system",
        "suspicious_when": ["PSExec pattern", "SYSTEM account", "Unusual binary", "Remote installation"],
        "severity": "Critical"
    },
    
    # ===== SECURITY LOG EVENTS (1100-1102) =====
    1100: {
        "name": "Event Log Service Shutdown",
        "category": "System",
        "risk_score": 8,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.002"],
        "description": "The event logging service has shut down",
        "suspicious_when": ["Unexpected shutdown", "During attack", "Unauthorized"],
        "severity": "Critical"
    },
    1102: {
        "name": "Security Log Cleared",
        "category": "System",
        "risk_score": 10,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1070.001"],
        "description": "The audit log was cleared",
        "suspicious_when": ["Unauthorized user", "During incident", "Cover tracks"],
        "severity": "Critical"
    },
    
    # ===== WINDOWS FILTERING PLATFORM (5156-5158) =====
    5156: {
        "name": "Network Connection Allowed",
        "category": "Filtering Platform",
        "risk_score": 3,
        "mitre_tactics": ["Command and Control", "Exfiltration"],
        "mitre_techniques": ["T1071", "T1041"],
        "description": "Windows Filtering Platform permitted a connection",
        "suspicious_when": ["Unusual destination", "Known C2", "Data exfil port"],
        "severity": "Low"
    },
    5157: {
        "name": "Network Connection Blocked",
        "category": "Filtering Platform",
        "risk_score": 6,
        "mitre_tactics": ["Discovery", "Command and Control"],
        "mitre_techniques": ["T1046"],
        "description": "Windows Filtering Platform blocked a connection",
        "suspicious_when": ["Scanning pattern", "Multiple blocks", "C2 attempt"],
        "severity": "Medium"
    },
    5158: {
        "name": "Network Bind Allowed",
        "category": "Filtering Platform",
        "risk_score": 4,
        "mitre_tactics": ["Command and Control"],
        "mitre_techniques": ["T1571"],
        "description": "Windows Filtering Platform permitted bind to local port",
        "suspicious_when": ["Unusual port", "Non-standard service", "Backdoor"],
        "severity": "Medium"
    },
}


def get_event_info(event_id):
    """Get information about a specific EventID"""
    return SECURITY_EVENTS.get(event_id, {
        "name": f"Unknown Event {event_id}",
        "category": "Unknown",
        "risk_score": 5,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "description": "Event not in reference database",
        "suspicious_when": [],
        "severity": "Unknown"
    })


def get_risk_score(event_id):
    """Get risk score for an EventID (1-10 scale)"""
    return SECURITY_EVENTS.get(event_id, {}).get("risk_score", 5)


def get_mitre_tactics(event_id):
    """Get MITRE ATT&CK tactics for an EventID"""
    return SECURITY_EVENTS.get(event_id, {}).get("mitre_tactics", [])


def get_events_by_tactic(tactic):
    """Get all EventIDs associated with a MITRE tactic"""
    return [eid for eid, info in SECURITY_EVENTS.items() 
            if tactic in info.get("mitre_tactics", [])]


def get_high_risk_events(threshold=7):
    """Get all EventIDs with risk score above threshold"""
    return {eid: info for eid, info in SECURITY_EVENTS.items() 
            if info.get("risk_score", 0) >= threshold}
