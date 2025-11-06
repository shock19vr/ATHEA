"""
SQL Server Event ID Reference Database
Complete reference for SQL Server Application log EventIDs with risk scores and MITRE ATT&CK mappings.
Focus on credential access, authentication failures, and SQL injection attacks.
"""

SQL_SERVER_EVENTS = {
    # ===== SQL SERVER LOGIN & AUTHENTICATION (18450-18488) =====
    18456: {
        "name": "SQL Server Login Failed",
        "category": "Authentication",
        "risk_score": 7,
        "mitre_tactics": ["Credential Access", "Initial Access"],
        "mitre_techniques": ["T1110.001", "T1110.003"],
        "description": "Login failed for user - SQL Server authentication failure",
        "suspicious_when": ["Multiple failures", "sa account", "Admin accounts", "Password spray pattern", 
                          "Brute force", "State 2 (invalid user)", "State 8 (wrong password)"],
        "severity": "High",
        "states": {
            "2": "Invalid username",
            "5": "Invalid username (Windows auth)",
            "6": "Windows account lockout",
            "7": "Account disabled",
            "8": "Wrong password",
            "11": "Valid login but server access failure",
            "12": "Valid login but server access failure",
            "18": "Password must be changed",
            "38": "Database not available",
            "40": "Database not available"
        }
    },
    18452: {
        "name": "SQL Server Login Succeeded",
        "category": "Authentication",
        "risk_score": 3,
        "mitre_tactics": ["Initial Access", "Lateral Movement"],
        "mitre_techniques": ["T1078"],
        "description": "Successful SQL Server login",
        "suspicious_when": ["sa account", "After multiple failures", "Unusual time", "Unusual source IP", 
                          "Privileged account", "SQL injection context"],
        "severity": "Low"
    },
    18453: {
        "name": "SQL Server Login Succeeded with Warnings",
        "category": "Authentication",
        "risk_score": 5,
        "mitre_tactics": ["Initial Access", "Credential Access"],
        "mitre_techniques": ["T1078"],
        "description": "Login succeeded but with warnings (e.g., password about to expire)",
        "suspicious_when": ["Repeated warnings ignored", "Service accounts", "Privileged accounts"],
        "severity": "Medium"
    },
    18454: {
        "name": "SQL Server Login Failed - Account Locked",
        "category": "Authentication",
        "risk_score": 8,
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.001"],
        "description": "Login failed because account is locked out",
        "suspicious_when": ["Multiple lockouts", "Admin accounts", "Automated attack pattern"],
        "severity": "High"
    },
    18455: {
        "name": "SQL Server Login Failed - Disabled Account",
        "category": "Authentication",
        "risk_score": 6,
        "mitre_tactics": ["Credential Access", "Discovery"],
        "mitre_techniques": ["T1087"],
        "description": "Login attempt on disabled account",
        "suspicious_when": ["Multiple disabled account attempts", "Account enumeration"],
        "severity": "Medium"
    },
    
    # ===== SQL INJECTION & EXPLOITATION (33205, 229, 208) =====
    33205: {
        "name": "SQL Audit Event - DBCC Command",
        "category": "SQL Injection",
        "risk_score": 8,
        "mitre_tactics": ["Credential Access", "Discovery"],
        "mitre_techniques": ["T1190", "T1059.001"],
        "description": "DBCC command executed - potential SQL injection",
        "suspicious_when": ["Unexpected DBCC", "Web application user", "Non-admin account", 
                          "DBCC CHECKIDENT", "DBCC TRACEON", "Suspicious command patterns"],
        "severity": "High"
    },
    229: {
        "name": "SQL Permission Denied",
        "category": "SQL Injection",
        "risk_score": 7,
        "mitre_tactics": ["Credential Access", "Privilege Escalation"],
        "mitre_techniques": ["T1190", "T1059.001"],
        "description": "The EXECUTE permission was denied on object",
        "suspicious_when": ["Multiple rapid failures", "System stored procedures", "xp_cmdshell attempts",
                          "sp_configure attempts", "Web application context", "SQL injection pattern"],
        "severity": "High"
    },
    208: {
        "name": "Invalid Object Name",
        "category": "SQL Injection",
        "risk_score": 6,
        "mitre_tactics": ["Discovery", "Credential Access"],
        "mitre_techniques": ["T1190", "T1087"],
        "description": "Invalid object name - SQL injection reconnaissance",
        "suspicious_when": ["Multiple errors", "System table queries", "Information_schema queries",
                          "Rapid sequential errors", "Pattern matching sys.objects"],
        "severity": "Medium"
    },
    
    # ===== SQL SERVER PRIVILEGE ESCALATION (15247, 15434) =====
    15247: {
        "name": "User Does Not Have Permission",
        "category": "Privilege Escalation",
        "risk_score": 7,
        "mitre_tactics": ["Privilege Escalation", "Credential Access"],
        "mitre_techniques": ["T1068", "T1190"],
        "description": "User does not have permission to perform action",
        "suspicious_when": ["ALTER LOGIN attempts", "GRANT attempts", "sysadmin role attempts",
                          "Multiple permission checks", "Privilege escalation pattern"],
        "severity": "High"
    },
    15434: {
        "name": "Cannot Change sa Password",
        "category": "Privilege Escalation",
        "risk_score": 9,
        "mitre_tactics": ["Persistence", "Credential Access"],
        "mitre_techniques": ["T1098"],
        "description": "Attempt to change sa account password",
        "suspicious_when": ["Unauthorized user", "Web application account", "Non-admin user"],
        "severity": "Critical"
    },
    
    # ===== SQL SERVER CONFIGURATION CHANGES (15457, 17049) =====
    15457: {
        "name": "Configuration Option Changed",
        "category": "Configuration Change",
        "risk_score": 8,
        "mitre_tactics": ["Defense Evasion", "Persistence"],
        "mitre_techniques": ["T1562.001"],
        "description": "SQL Server configuration option changed",
        "suspicious_when": ["xp_cmdshell enabled", "Ad Hoc Distributed Queries enabled",
                          "Remote access enabled", "C2 audit mode disabled", "Unauthorized admin"],
        "severity": "High"
    },
    17049: {
        "name": "Configuration Option Changed - SQL Trace",
        "category": "Configuration Change",
        "risk_score": 9,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.001"],
        "description": "SQL trace or audit configuration changed",
        "suspicious_when": ["Audit disabled", "Trace stopped", "C2 auditing disabled", "Unauthorized change"],
        "severity": "Critical"
    },
    
    # ===== SQL SERVER AUDIT EVENTS (33205-33215) =====
    33210: {
        "name": "SQL Audit - Schema Object Access",
        "category": "Audit",
        "risk_score": 6,
        "mitre_tactics": ["Discovery", "Collection"],
        "mitre_techniques": ["T1087", "T1552.001"],
        "description": "Schema object accessed - credential table access",
        "suspicious_when": ["User credential tables", "Password columns", "sys.sql_logins",
                          "sys.server_principals", "Unusual application user"],
        "severity": "Medium"
    },
    33211: {
        "name": "SQL Audit - Database Object Permission Change",
        "category": "Audit",
        "risk_score": 8,
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "mitre_techniques": ["T1098"],
        "description": "Database object permissions changed",
        "suspicious_when": ["GRANT CONTROL", "GRANT IMPERSONATE", "ALTER ANY LOGIN",
                          "Unauthorized admin", "Web application account"],
        "severity": "High"
    },
    33212: {
        "name": "SQL Audit - Server Principal Management",
        "category": "Audit",
        "risk_score": 9,
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "mitre_techniques": ["T1136", "T1098"],
        "description": "Server principal (login) created, altered, or dropped",
        "suspicious_when": ["New sysadmin login", "sa password change", "Backdoor account creation",
                          "Unauthorized admin", "SQL injection context"],
        "severity": "Critical"
    },
    
    # ===== XP_CMDSHELL & COMMAND EXECUTION (15281, 22022) =====
    15281: {
        "name": "SQL Server xp_cmdshell Enabled",
        "category": "Command Execution",
        "risk_score": 10,
        "mitre_tactics": ["Execution", "Privilege Escalation"],
        "mitre_techniques": ["T1059.001"],
        "description": "xp_cmdshell extended stored procedure enabled",
        "suspicious_when": ["ANY enablement", "Web application user", "Non-DBA account",
                          "SQL injection context", "Unauthorized"],
        "severity": "Critical"
    },
    22022: {
        "name": "SQLAgent Job Executed",
        "category": "Command Execution",
        "risk_score": 7,
        "mitre_tactics": ["Execution", "Persistence"],
        "mitre_techniques": ["T1053", "T1059.001"],
        "description": "SQL Agent job executed",
        "suspicious_when": ["Unexpected job", "Job with cmdexec steps", "PowerShell steps",
                          "Newly created job", "Suspicious command line"],
        "severity": "High"
    },
    
    # ===== SQL SERVER LINKED SERVERS (18483, 18486) =====
    18483: {
        "name": "Linked Server Login Failed",
        "category": "Linked Server",
        "risk_score": 6,
        "mitre_tactics": ["Lateral Movement", "Credential Access"],
        "mitre_techniques": ["T1021"],
        "description": "Connection to linked server failed",
        "suspicious_when": ["Multiple failures", "Unusual linked server", "Credential harvesting attempt"],
        "severity": "Medium"
    },
    18486: {
        "name": "Linked Server Login Succeeded",
        "category": "Linked Server",
        "risk_score": 5,
        "mitre_tactics": ["Lateral Movement"],
        "mitre_techniques": ["T1021"],
        "description": "Successfully connected to linked server",
        "suspicious_when": ["Unusual time", "Web application account", "After SQL injection",
                          "Sensitive database access"],
        "severity": "Medium"
    },
    
    # ===== SQL SERVER BACKUP/RESTORE (3014, 3041, 3009) =====
    3014: {
        "name": "Database Backup Completed",
        "category": "Data Access",
        "risk_score": 5,
        "mitre_tactics": ["Collection", "Exfiltration"],
        "mitre_techniques": ["T1005"],
        "description": "Database backup completed successfully",
        "suspicious_when": ["Unauthorized user", "Unusual time", "Unusual backup location",
                          "UNC path to external server", "After SQL injection"],
        "severity": "Medium"
    },
    3041: {
        "name": "Backup Failed",
        "category": "Data Access",
        "risk_score": 6,
        "mitre_tactics": ["Discovery", "Collection"],
        "mitre_techniques": ["T1005"],
        "description": "Database backup failed",
        "suspicious_when": ["Multiple attempts", "Permission errors", "Access denied",
                          "Unauthorized user attempting backup"],
        "severity": "Medium"
    },
    3009: {
        "name": "Restore Operation Initiated",
        "category": "Data Access",
        "risk_score": 7,
        "mitre_tactics": ["Defense Evasion", "Impact"],
        "mitre_techniques": ["T1490"],
        "description": "Database restore operation initiated",
        "suspicious_when": ["Unauthorized user", "Production database", "Unusual time",
                          "Overwriting current database", "After compromise"],
        "severity": "High"
    },
    
    # ===== SQL SERVER ERROR LOG ACCESS (17120, 17124) =====
    17120: {
        "name": "Error Log Disabled",
        "category": "Defense Evasion",
        "risk_score": 9,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.001"],
        "description": "SQL Server error log was disabled or stopped",
        "suspicious_when": ["ANY occurrence", "Unauthorized admin", "After compromise"],
        "severity": "Critical"
    },
    17124: {
        "name": "Error Log Recycled",
        "category": "Defense Evasion",
        "risk_score": 7,
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1070.001"],
        "description": "SQL Server error log recycled/cleared",
        "suspicious_when": ["Frequent recycling", "After suspicious activity", "Unauthorized admin"],
        "severity": "High"
    }
}

def get_sql_event_info(event_id):
    """Get information about a SQL Server EventID"""
    return SQL_SERVER_EVENTS.get(event_id, None)

def get_sql_events_by_tactic(tactic):
    """Get all SQL EventIDs for a specific MITRE tactic"""
    return {eid: info for eid, info in SQL_SERVER_EVENTS.items() 
            if tactic in info.get('mitre_tactics', [])}

def get_high_risk_sql_events():
    """Get SQL EventIDs with risk score >= 7"""
    return {eid: info for eid, info in SQL_SERVER_EVENTS.items() 
            if info.get('risk_score', 0) >= 7}
