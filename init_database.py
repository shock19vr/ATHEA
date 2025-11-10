"""
Database Initialization Script
Populates SQLite database with all reference data from Python modules.
"""

from db_manager import DatabaseManager
from eventid_reference_security import SECURITY_EVENTS
from eventid_reference_sysmon import SYSMON_EVENTS
from eventid_reference_system import SYSTEM_EVENTS
from eventid_reference_sql import SQL_SERVER_EVENTS
from mitre_ttps_reference import MITRE_TACTICS


def initialize_database(db_path: str = "event_references.db"):
    """Initialize database with all reference data"""
    
    print("🔧 Initializing Event Reference Database...")
    print(f"📁 Database path: {db_path}\n")
    
    db = DatabaseManager(db_path)
    
    # ==================== SECURITY EVENTS ====================
    print("📥 Loading Security Events...")
    for event_id, event_data in SECURITY_EVENTS.items():
        db.insert_security_event(event_id, event_data)
    print(f"   ✅ Loaded {len(SECURITY_EVENTS)} Security events\n")
    
    # ==================== SYSMON EVENTS ====================
    print("📥 Loading Sysmon Events...")
    for event_id, event_data in SYSMON_EVENTS.items():
        db.insert_sysmon_event(event_id, event_data)
    print(f"   ✅ Loaded {len(SYSMON_EVENTS)} Sysmon events\n")
    
    # ==================== SYSTEM EVENTS ====================
    print("📥 Loading System Events...")
    for event_id, event_data in SYSTEM_EVENTS.items():
        db.insert_system_event(event_id, event_data)
    print(f"   ✅ Loaded {len(SYSTEM_EVENTS)} System events\n")
    
    # ==================== SQL SERVER EVENTS ====================
    print("📥 Loading SQL Server Events...")
    for event_id, event_data in SQL_SERVER_EVENTS.items():
        db.insert_sql_event(event_id, event_data)
    print(f"   ✅ Loaded {len(SQL_SERVER_EVENTS)} SQL Server events\n")
    
    # ==================== MITRE ATT&CK ====================
    print("📥 Loading MITRE ATT&CK Framework...")
    
    # Load tactics
    tactic_count = 0
    for tactic_name, tactic_info in MITRE_TACTICS.items():
        db.insert_mitre_tactic(tactic_name, tactic_info.get('description', ''))
        tactic_count += 1
    print(f"   ✅ Loaded {tactic_count} MITRE tactics")
    
    # Load techniques
    technique_count = 0
    for tactic_name, tactic_info in MITRE_TACTICS.items():
        techniques = tactic_info.get('techniques', {})
        for technique_id, technique_name in techniques.items():
            db.insert_mitre_technique(technique_id, technique_name, tactic_name)
            technique_count += 1
    print(f"   ✅ Loaded {technique_count} MITRE techniques\n")
    
    # ==================== STATISTICS ====================
    print("📊 Database Statistics:")
    stats = db.get_statistics()
    print(f"   • Total Events: {stats['total_events']}")
    print(f"   • Security Events: {stats['security_events']}")
    print(f"   • Sysmon Events: {stats['sysmon_events']}")
    print(f"   • System Events: {stats['system_events']}")
    print(f"   • SQL Server Events: {stats['sql_events']}")
    print(f"   • MITRE Tactics: {stats['mitre_tactics']}")
    print(f"   • MITRE Techniques: {stats['mitre_techniques']}")
    
    # ==================== HIGH RISK EVENTS ====================
    print("\n🔴 High Risk Events (Risk Score >= 7):")
    high_risk = db.search_events_by_risk(min_risk=7)
    print(f"   Found {len(high_risk)} high-risk events")
    
    # Show top 10 by risk score
    high_risk_sorted = sorted(high_risk, key=lambda x: x.get('risk_score', 0), reverse=True)
    print("\n   Top 10 Highest Risk Events:")
    for i, event in enumerate(high_risk_sorted[:10], 1):
        print(f"   {i}. EventID {event['event_id']} ({event['source']}): {event['name']} - Risk: {event['risk_score']}")
    
    db.close()
    
    print("\n✅ Database initialization complete!")
    print(f"📁 Database saved to: {db_path}")


def verify_database(db_path: str = "event_references.db"):
    """Verify database integrity"""
    print("\n🔍 Verifying database integrity...")
    
    db = DatabaseManager(db_path)
    
    # Test queries
    tests_passed = 0
    tests_total = 0
    
    # Test 1: Get a known security event
    tests_total += 1
    event = db.get_security_event(4624)
    if event and event['name'] == 'Successful Logon':
        print("   ✅ Test 1: Security event lookup")
        tests_passed += 1
    else:
        print("   ❌ Test 1: Security event lookup FAILED")
    
    # Test 2: Get a known sysmon event
    tests_total += 1
    event = db.get_sysmon_event(1)
    if event and event['name'] == 'Process Creation':
        print("   ✅ Test 2: Sysmon event lookup")
        tests_passed += 1
    else:
        print("   ❌ Test 2: Sysmon event lookup FAILED")
    
    # Test 3: Get a known system event
    tests_total += 1
    event = db.get_system_event(7045)
    if event and event['name'] == 'Service Installed':
        print("   ✅ Test 3: System event lookup")
        tests_passed += 1
    else:
        print("   ❌ Test 3: System event lookup FAILED")
    
    # Test 4: MITRE tactic lookup
    tests_total += 1
    tactic = db.get_mitre_tactic('Initial Access')
    if tactic:
        print("   ✅ Test 4: MITRE tactic lookup")
        tests_passed += 1
    else:
        print("   ❌ Test 4: MITRE tactic lookup FAILED")
    
    # Test 5: MITRE technique lookup
    tests_total += 1
    technique = db.get_technique_by_id('T1078')
    if technique:
        print("   ✅ Test 5: MITRE technique lookup")
        tests_passed += 1
    else:
        print("   ❌ Test 5: MITRE technique lookup FAILED")
    
    # Test 6: High risk search
    tests_total += 1
    high_risk = db.search_events_by_risk(min_risk=9)
    if len(high_risk) > 0:
        print(f"   ✅ Test 6: High risk search ({len(high_risk)} events found)")
        tests_passed += 1
    else:
        print("   ❌ Test 6: High risk search FAILED")
    
    db.close()
    
    print(f"\n📊 Verification Results: {tests_passed}/{tests_total} tests passed")
    
    if tests_passed == tests_total:
        print("✅ Database verification successful!")
        return True
    else:
        print("❌ Database verification failed!")
        return False


if __name__ == "__main__":
    # Initialize database
    initialize_database()
    
    # Verify database
    verify_database()
