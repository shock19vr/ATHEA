"""
MITRE ATT&CK Tactics, Techniques, and Procedures (TTPs) Reference
Comprehensive mapping of all MITRE ATT&CK Enterprise techniques organized by tactic.
Version: ATT&CK v14 (2024)
"""

MITRE_TACTICS = {
    "Initial Access": {
        "description": "Trying to get into your network",
        "techniques": {
            "T1078": "Valid Accounts",
            "T1078.001": "Valid Accounts: Default Accounts",
            "T1078.002": "Valid Accounts: Domain Accounts",
            "T1078.003": "Valid Accounts: Local Accounts",
            "T1078.004": "Valid Accounts: Cloud Accounts",
            "T1091": "Replication Through Removable Media",
            "T1133": "External Remote Services",
            "T1189": "Drive-by Compromise",
            "T1190": "Exploit Public-Facing Application",
            "T1195": "Supply Chain Compromise",
            "T1195.001": "Supply Chain Compromise: Compromise Software Dependencies",
            "T1195.002": "Supply Chain Compromise: Compromise Software Supply Chain",
            "T1195.003": "Supply Chain Compromise: Compromise Hardware Supply Chain",
            "T1199": "Trusted Relationship",
            "T1566": "Phishing",
            "T1566.001": "Phishing: Spearphishing Attachment",
            "T1566.002": "Phishing: Spearphishing Link",
            "T1566.003": "Phishing: Spearphishing via Service",
            "T1598": "Phishing for Information",
        }
    },
    
    "Execution": {
        "description": "Trying to run malicious code",
        "techniques": {
            "T1047": "Windows Management Instrumentation",
            "T1053": "Scheduled Task/Job",
            "T1053.002": "Scheduled Task/Job: At",
            "T1053.005": "Scheduled Task/Job: Scheduled Task",
            "T1053.006": "Scheduled Task/Job: Systemd Timers",
            "T1059": "Command and Scripting Interpreter",
            "T1059.001": "Command and Scripting Interpreter: PowerShell",
            "T1059.002": "Command and Scripting Interpreter: AppleScript",
            "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
            "T1059.004": "Command and Scripting Interpreter: Unix Shell",
            "T1059.005": "Command and Scripting Interpreter: Visual Basic",
            "T1059.006": "Command and Scripting Interpreter: Python",
            "T1059.007": "Command and Scripting Interpreter: JavaScript",
            "T1059.008": "Command and Scripting Interpreter: Network Device CLI",
            "T1106": "Native API",
            "T1129": "Shared Modules",
            "T1203": "Exploitation for Client Execution",
            "T1204": "User Execution",
            "T1204.001": "User Execution: Malicious Link",
            "T1204.002": "User Execution: Malicious File",
            "T1559": "Inter-Process Communication",
            "T1559.001": "Inter-Process Communication: Component Object Model",
            "T1559.002": "Inter-Process Communication: Dynamic Data Exchange",
            "T1569": "System Services",
            "T1569.001": "System Services: Launchctl",
            "T1569.002": "System Services: Service Execution",
        }
    },
    
    "Persistence": {
        "description": "Trying to maintain their foothold",
        "techniques": {
            "T1053": "Scheduled Task/Job",
            "T1053.005": "Scheduled Task/Job: Scheduled Task",
            "T1078": "Valid Accounts",
            "T1098": "Account Manipulation",
            "T1098.001": "Account Manipulation: Additional Cloud Credentials",
            "T1098.002": "Account Manipulation: Additional Email Delegate Permissions",
            "T1098.003": "Account Manipulation: Additional Cloud Roles",
            "T1098.004": "Account Manipulation: SSH Authorized Keys",
            "T1136": "Create Account",
            "T1136.001": "Create Account: Local Account",
            "T1136.002": "Create Account: Domain Account",
            "T1136.003": "Create Account: Cloud Account",
            "T1137": "Office Application Startup",
            "T1197": "BITS Jobs",
            "T1505": "Server Software Component",
            "T1505.001": "Server Software Component: SQL Stored Procedures",
            "T1505.002": "Server Software Component: Transport Agent",
            "T1505.003": "Server Software Component: Web Shell",
            "T1505.004": "Server Software Component: IIS Components",
            "T1505.005": "Server Software Component: Terminal Services DLL",
            "T1543": "Create or Modify System Process",
            "T1543.001": "Create or Modify System Process: Launch Agent",
            "T1543.002": "Create or Modify System Process: Systemd Service",
            "T1543.003": "Create or Modify System Process: Windows Service",
            "T1543.004": "Create or Modify System Process: Launch Daemon",
            "T1546": "Event Triggered Execution",
            "T1546.001": "Event Triggered Execution: Change Default File Association",
            "T1546.002": "Event Triggered Execution: Screensaver",
            "T1546.003": "Event Triggered Execution: Windows Management Instrumentation Event Subscription",
            "T1546.004": "Event Triggered Execution: Unix Shell Configuration Modification",
            "T1546.007": "Event Triggered Execution: Netsh Helper DLL",
            "T1546.008": "Event Triggered Execution: Accessibility Features",
            "T1546.009": "Event Triggered Execution: AppCert DLLs",
            "T1546.010": "Event Triggered Execution: AppInit DLLs",
            "T1546.011": "Event Triggered Execution: Application Shimming",
            "T1546.012": "Event Triggered Execution: Image File Execution Options Injection",
            "T1546.013": "Event Triggered Execution: PowerShell Profile",
            "T1546.015": "Event Triggered Execution: Component Object Model Hijacking",
            "T1547": "Boot or Logon Autostart Execution",
            "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            "T1547.002": "Boot or Logon Autostart Execution: Authentication Package",
            "T1547.003": "Boot or Logon Autostart Execution: Time Providers",
            "T1547.004": "Boot or Logon Autostart Execution: Winlogon Helper DLL",
            "T1547.005": "Boot or Logon Autostart Execution: Security Support Provider",
            "T1547.006": "Boot or Logon Autostart Execution: Kernel Modules and Extensions",
            "T1547.009": "Boot or Logon Autostart Execution: Shortcut Modification",
            "T1547.012": "Boot or Logon Autostart Execution: Print Processors",
            "T1547.014": "Boot or Logon Autostart Execution: Active Setup",
            "T1574": "Hijack Execution Flow",
            "T1574.001": "Hijack Execution Flow: DLL Search Order Hijacking",
            "T1574.002": "Hijack Execution Flow: DLL Side-Loading",
        }
    },
    
    "Privilege Escalation": {
        "description": "Trying to gain higher-level permissions",
        "techniques": {
            "T1053": "Scheduled Task/Job",
            "T1055": "Process Injection",
            "T1055.001": "Process Injection: Dynamic-link Library Injection",
            "T1055.002": "Process Injection: Portable Executable Injection",
            "T1055.003": "Process Injection: Thread Execution Hijacking",
            "T1055.004": "Process Injection: Asynchronous Procedure Call",
            "T1055.005": "Process Injection: Thread Local Storage",
            "T1055.008": "Process Injection: Ptrace System Calls",
            "T1055.009": "Process Injection: Proc Memory",
            "T1055.011": "Process Injection: Extra Window Memory Injection",
            "T1055.012": "Process Injection: Process Hollowing",
            "T1055.013": "Process Injection: Process Doppelgänging",
            "T1055.014": "Process Injection: VDSO Hijacking",
            "T1055.015": "Process Injection: ListPlanting",
            "T1068": "Exploitation for Privilege Escalation",
            "T1078": "Valid Accounts",
            "T1134": "Access Token Manipulation",
            "T1134.001": "Access Token Manipulation: Token Impersonation/Theft",
            "T1134.002": "Access Token Manipulation: Create Process with Token",
            "T1134.003": "Access Token Manipulation: Make and Impersonate Token",
            "T1134.004": "Access Token Manipulation: Parent PID Spoofing",
            "T1134.005": "Access Token Manipulation: SID-History Injection",
            "T1484": "Domain Policy Modification",
            "T1484.001": "Domain Policy Modification: Group Policy Modification",
            "T1484.002": "Domain Policy Modification: Domain Trust Modification",
            "T1543": "Create or Modify System Process",
            "T1546": "Event Triggered Execution",
            "T1547": "Boot or Logon Autostart Execution",
            "T1548": "Abuse Elevation Control Mechanism",
            "T1548.002": "Abuse Elevation Control Mechanism: Bypass User Account Control",
        }
    },
    
    "Defense Evasion": {
        "description": "Trying to avoid being detected",
        "techniques": {
            "T1027": "Obfuscated Files or Information",
            "T1027.001": "Obfuscated Files or Information: Binary Padding",
            "T1027.002": "Obfuscated Files or Information: Software Packing",
            "T1027.003": "Obfuscated Files or Information: Steganography",
            "T1027.004": "Obfuscated Files or Information: Compile After Delivery",
            "T1027.005": "Obfuscated Files or Information: Indicator Removal from Tools",
            "T1036": "Masquerading",
            "T1036.001": "Masquerading: Invalid Code Signature",
            "T1036.003": "Masquerading: Rename System Utilities",
            "T1036.004": "Masquerading: Masquerade Task or Service",
            "T1036.005": "Masquerading: Match Legitimate Name or Location",
            "T1055": "Process Injection",
            "T1070": "Indicator Removal",
            "T1070.001": "Indicator Removal: Clear Windows Event Logs",
            "T1070.002": "Indicator Removal: Clear Linux or Mac System Logs",
            "T1070.003": "Indicator Removal: Clear Command History",
            "T1070.004": "Indicator Removal: File Deletion",
            "T1070.005": "Indicator Removal: Network Share Connection Removal",
            "T1070.006": "Indicator Removal: Timestomp",
            "T1112": "Modify Registry",
            "T1134": "Access Token Manipulation",
            "T1140": "Deobfuscate/Decode Files or Information",
            "T1197": "BITS Jobs",
            "T1202": "Indirect Command Execution",
            "T1207": "Rogue Domain Controller",
            "T1211": "Exploitation for Defense Evasion",
            "T1216": "System Script Proxy Execution",
            "T1218": "System Binary Proxy Execution",
            "T1218.001": "System Binary Proxy Execution: Compiled HTML File",
            "T1218.003": "System Binary Proxy Execution: CMSTP",
            "T1218.004": "System Binary Proxy Execution: InstallUtil",
            "T1218.005": "System Binary Proxy Execution: Mshta",
            "T1218.007": "System Binary Proxy Execution: Msiexec",
            "T1218.008": "System Binary Proxy Execution: Odbcconf",
            "T1218.009": "System Binary Proxy Execution: Regsvcs/Regasm",
            "T1218.010": "System Binary Proxy Execution: Regsvr32",
            "T1218.011": "System Binary Proxy Execution: Rundll32",
            "T1218.012": "System Binary Proxy Execution: Verclsid",
            "T1220": "XSL Script Processing",
            "T1480": "Execution Guardrails",
            "T1484": "Domain Policy Modification",
            "T1497": "Virtualization/Sandbox Evasion",
            "T1542": "Pre-OS Boot",
            "T1548": "Abuse Elevation Control Mechanism",
            "T1550": "Use Alternate Authentication Material",
            "T1550.002": "Use Alternate Authentication Material: Pass the Hash",
            "T1550.003": "Use Alternate Authentication Material: Pass the Ticket",
            "T1562": "Impair Defenses",
            "T1562.001": "Impair Defenses: Disable or Modify Tools",
            "T1562.002": "Impair Defenses: Disable Windows Event Logging",
            "T1562.003": "Impair Defenses: Impair Command History Logging",
            "T1562.004": "Impair Defenses: Disable or Modify System Firewall",
            "T1562.006": "Impair Defenses: Indicator Blocking",
            "T1562.007": "Impair Defenses: Disable or Modify Cloud Firewall",
            "T1562.008": "Impair Defenses: Disable Cloud Logs",
            "T1564": "Hide Artifacts",
            "T1564.001": "Hide Artifacts: Hidden Files and Directories",
            "T1564.002": "Hide Artifacts: Hidden Users",
            "T1564.003": "Hide Artifacts: Hidden Window",
            "T1564.004": "Hide Artifacts: NTFS File Attributes",
            "T1564.005": "Hide Artifacts: Hidden File System",
            "T1564.006": "Hide Artifacts: Run Virtual Instance",
            "T1564.007": "Hide Artifacts: VBA Stomping",
            "T1574": "Hijack Execution Flow",
        }
    },
    
    "Credential Access": {
        "description": "Trying to steal account names and passwords",
        "techniques": {
            "T1003": "OS Credential Dumping",
            "T1003.001": "OS Credential Dumping: LSASS Memory",
            "T1003.002": "OS Credential Dumping: Security Account Manager",
            "T1003.003": "OS Credential Dumping: NTDS",
            "T1003.004": "OS Credential Dumping: LSA Secrets",
            "T1003.005": "OS Credential Dumping: Cached Domain Credentials",
            "T1003.006": "OS Credential Dumping: DCSync",
            "T1003.007": "OS Credential Dumping: Proc Filesystem",
            "T1003.008": "OS Credential Dumping: /etc/passwd and /etc/shadow",
            "T1040": "Network Sniffing",
            "T1056": "Input Capture",
            "T1056.001": "Input Capture: Keylogging",
            "T1056.002": "Input Capture: GUI Input Capture",
            "T1056.003": "Input Capture: Web Portal Capture",
            "T1056.004": "Input Capture: Credential API Hooking",
            "T1110": "Brute Force",
            "T1110.001": "Brute Force: Password Guessing",
            "T1110.002": "Brute Force: Password Cracking",
            "T1110.003": "Brute Force: Password Spraying",
            "T1110.004": "Brute Force: Credential Stuffing",
            "T1111": "Multi-Factor Authentication Interception",
            "T1212": "Exploitation for Credential Access",
            "T1552": "Unsecured Credentials",
            "T1552.001": "Unsecured Credentials: Credentials In Files",
            "T1552.002": "Unsecured Credentials: Credentials in Registry",
            "T1552.003": "Unsecured Credentials: Bash History",
            "T1552.004": "Unsecured Credentials: Private Keys",
            "T1555": "Credentials from Password Stores",
            "T1555.001": "Credentials from Password Stores: Keychain",
            "T1555.002": "Credentials from Password Stores: Securityd Memory",
            "T1555.003": "Credentials from Password Stores: Credentials from Web Browsers",
            "T1558": "Steal or Forge Kerberos Tickets",
            "T1558.001": "Steal or Forge Kerberos Tickets: Golden Ticket",
            "T1558.002": "Steal or Forge Kerberos Tickets: Silver Ticket",
            "T1558.003": "Steal or Forge Kerberos Tickets: Kerberoasting",
            "T1558.004": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
        }
    },
    
    "Discovery": {
        "description": "Trying to figure out your environment",
        "techniques": {
            "T1007": "System Service Discovery",
            "T1010": "Application Window Discovery",
            "T1012": "Query Registry",
            "T1016": "System Network Configuration Discovery",
            "T1018": "Remote System Discovery",
            "T1033": "System Owner/User Discovery",
            "T1040": "Network Sniffing",
            "T1046": "Network Service Discovery",
            "T1049": "System Network Connections Discovery",
            "T1057": "Process Discovery",
            "T1069": "Permission Groups Discovery",
            "T1069.001": "Permission Groups Discovery: Local Groups",
            "T1069.002": "Permission Groups Discovery: Domain Groups",
            "T1069.003": "Permission Groups Discovery: Cloud Groups",
            "T1082": "System Information Discovery",
            "T1083": "File and Directory Discovery",
            "T1087": "Account Discovery",
            "T1087.001": "Account Discovery: Local Account",
            "T1087.002": "Account Discovery: Domain Account",
            "T1087.003": "Account Discovery: Email Account",
            "T1087.004": "Account Discovery: Cloud Account",
            "T1120": "Peripheral Device Discovery",
            "T1135": "Network Share Discovery",
            "T1201": "Password Policy Discovery",
            "T1217": "Browser Information Discovery",
            "T1482": "Domain Trust Discovery",
            "T1518": "Software Discovery",
            "T1518.001": "Software Discovery: Security Software Discovery",
            "T1526": "Cloud Service Discovery",
            "T1538": "Cloud Service Dashboard",
            "T1580": "Cloud Infrastructure Discovery",
            "T1613": "Container and Resource Discovery",
        }
    },
    
    "Lateral Movement": {
        "description": "Trying to move through your environment",
        "techniques": {
            "T1021": "Remote Services",
            "T1021.001": "Remote Services: Remote Desktop Protocol",
            "T1021.002": "Remote Services: SMB/Windows Admin Shares",
            "T1021.003": "Remote Services: Distributed Component Object Model",
            "T1021.004": "Remote Services: SSH",
            "T1021.005": "Remote Services: VNC",
            "T1021.006": "Remote Services: Windows Remote Management",
            "T1047": "Windows Management Instrumentation",
            "T1091": "Replication Through Removable Media",
            "T1210": "Exploitation of Remote Services",
            "T1534": "Internal Spearphishing",
            "T1550": "Use Alternate Authentication Material",
            "T1563": "Remote Service Session Hijacking",
            "T1563.001": "Remote Service Session Hijacking: SSH Hijacking",
            "T1563.002": "Remote Service Session Hijacking: RDP Hijacking",
            "T1570": "Lateral Tool Transfer",
        }
    },
    
    "Collection": {
        "description": "Trying to gather data of interest",
        "techniques": {
            "T1005": "Data from Local System",
            "T1025": "Data from Removable Media",
            "T1039": "Data from Network Shared Drive",
            "T1056": "Input Capture",
            "T1074": "Data Staged",
            "T1074.001": "Data Staged: Local Data Staging",
            "T1074.002": "Data Staged: Remote Data Staging",
            "T1113": "Screen Capture",
            "T1114": "Email Collection",
            "T1114.001": "Email Collection: Local Email Collection",
            "T1114.002": "Email Collection: Remote Email Collection",
            "T1114.003": "Email Collection: Email Forwarding Rule",
            "T1115": "Clipboard Data",
            "T1119": "Automated Collection",
            "T1123": "Audio Capture",
            "T1125": "Video Capture",
            "T1213": "Data from Information Repositories",
            "T1213.001": "Data from Information Repositories: Confluence",
            "T1213.002": "Data from Information Repositories: Sharepoint",
            "T1560": "Archive Collected Data",
            "T1560.001": "Archive Collected Data: Archive via Utility",
            "T1560.002": "Archive Collected Data: Archive via Library",
            "T1560.003": "Archive Collected Data: Archive via Custom Method",
        }
    },
    
    "Command and Control": {
        "description": "Trying to communicate with compromised systems",
        "techniques": {
            "T1001": "Data Obfuscation",
            "T1001.001": "Data Obfuscation: Junk Data",
            "T1001.002": "Data Obfuscation: Steganography",
            "T1001.003": "Data Obfuscation: Protocol Impersonation",
            "T1008": "Fallback Channels",
            "T1071": "Application Layer Protocol",
            "T1071.001": "Application Layer Protocol: Web Protocols",
            "T1071.002": "Application Layer Protocol: File Transfer Protocols",
            "T1071.003": "Application Layer Protocol: Mail Protocols",
            "T1071.004": "Application Layer Protocol: DNS",
            "T1090": "Proxy",
            "T1090.001": "Proxy: Internal Proxy",
            "T1090.002": "Proxy: External Proxy",
            "T1090.003": "Proxy: Multi-hop Proxy",
            "T1090.004": "Proxy: Domain Fronting",
            "T1095": "Non-Application Layer Protocol",
            "T1102": "Web Service",
            "T1102.001": "Web Service: Dead Drop Resolver",
            "T1102.002": "Web Service: Bidirectional Communication",
            "T1102.003": "Web Service: One-Way Communication",
            "T1104": "Multi-Stage Channels",
            "T1105": "Ingress Tool Transfer",
            "T1132": "Data Encoding",
            "T1132.001": "Data Encoding: Standard Encoding",
            "T1132.002": "Data Encoding: Non-Standard Encoding",
            "T1205": "Traffic Signaling",
            "T1571": "Non-Standard Port",
            "T1572": "Protocol Tunneling",
            "T1573": "Encrypted Channel",
            "T1573.001": "Encrypted Channel: Symmetric Cryptography",
            "T1573.002": "Encrypted Channel: Asymmetric Cryptography",
        }
    },
    
    "Exfiltration": {
        "description": "Trying to steal data",
        "techniques": {
            "T1020": "Automated Exfiltration",
            "T1020.001": "Automated Exfiltration: Traffic Duplication",
            "T1030": "Data Transfer Size Limits",
            "T1041": "Exfiltration Over C2 Channel",
            "T1048": "Exfiltration Over Alternative Protocol",
            "T1048.001": "Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
            "T1048.002": "Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
            "T1048.003": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol",
            "T1052": "Exfiltration Over Physical Medium",
            "T1052.001": "Exfiltration Over Physical Medium: Exfiltration over USB",
            "T1537": "Transfer Data to Cloud Account",
            "T1567": "Exfiltration Over Web Service",
            "T1567.001": "Exfiltration Over Web Service: Exfiltration to Code Repository",
            "T1567.002": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        }
    },
    
    "Impact": {
        "description": "Trying to manipulate, interrupt, or destroy systems and data",
        "techniques": {
            "T1485": "Data Destruction",
            "T1486": "Data Encrypted for Impact",
            "T1489": "Service Stop",
            "T1490": "Inhibit System Recovery",
            "T1491": "Defacement",
            "T1491.001": "Defacement: Internal Defacement",
            "T1491.002": "Defacement: External Defacement",
            "T1495": "Firmware Corruption",
            "T1496": "Resource Hijacking",
            "T1498": "Network Denial of Service",
            "T1498.001": "Network Denial of Service: Direct Network Flood",
            "T1498.002": "Network Denial of Service: Reflection Amplification",
            "T1499": "Endpoint Denial of Service",
            "T1499.001": "Endpoint Denial of Service: OS Exhaustion Flood",
            "T1499.002": "Endpoint Denial of Service: Service Exhaustion Flood",
            "T1499.003": "Endpoint Denial of Service: Application Exhaustion Flood",
            "T1499.004": "Endpoint Denial of Service: Application or System Exploitation",
            "T1529": "System Shutdown/Reboot",
            "T1531": "Account Access Removal",
            "T1561": "Disk Wipe",
            "T1561.001": "Disk Wipe: Disk Content Wipe",
            "T1561.002": "Disk Wipe: Disk Structure Wipe",
        }
    }
}


def get_all_techniques_for_tactic(tactic_name: str) -> dict:
    """Get all techniques for a specific tactic"""
    return MITRE_TACTICS.get(tactic_name, {}).get("techniques", {})


def get_technique_name(technique_id: str) -> str:
    """Get technique name from ID"""
    for tactic in MITRE_TACTICS.values():
        techniques = tactic.get("techniques", {})
        if technique_id in techniques:
            return techniques[technique_id]
    return "Unknown Technique"


def search_techniques(search_term: str) -> dict:
    """Search for techniques by name or ID"""
    results = {}
    search_lower = search_term.lower()
    
    for tactic_name, tactic_info in MITRE_TACTICS.items():
        techniques = tactic_info.get("techniques", {})
        for tid, tname in techniques.items():
            if search_lower in tid.lower() or search_lower in tname.lower():
                if tactic_name not in results:
                    results[tactic_name] = {}
                results[tactic_name][tid] = tname
    
    return results


def get_all_tactics() -> list:
    """Get list of all MITRE ATT&CK tactics"""
    return list(MITRE_TACTICS.keys())


def get_tactic_description(tactic_name: str) -> str:
    """Get description of a tactic"""
    return MITRE_TACTICS.get(tactic_name, {}).get("description", "")
