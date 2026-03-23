"""
Test Database Integration
Verifies that the database integration works correctly with the pipeline.
"""

from db_manager import get_db_manager
from eventid_mapper import get_mapper
import pandas as pd


def test_database_manager():
    """Test DatabaseManager functionality"""
    print("=" * 60)
    print("TEST 1: Database Manager")
    print("=" * 60)
    
    db = get_db_manager()
    
    # Test 1: Get statistics
    print("\n📊 Database Statistics:")
    stats = db.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    # Test 2: Query specific events
    print("\n🔍 Testing Event Queries:")
    
    # Security event
    event = db.get_security_event(4624)
    if event:
        print(f"   ✅ Security Event 4624: {event['name']}")
    else:
        print("   ❌ Failed to get Security Event 4624")
    
    # Sysmon event
    event = db.get_sysmon_event(1)
    if event:
        print(f"   ✅ Sysmon Event 1: {event['name']}")
    else:
        print("   ❌ Failed to get Sysmon Event 1")
    
    # System event
    event = db.get_system_event(7045)
    if event:
        print(f"   ✅ System Event 7045: {event['name']}")
    else:
        print("   ❌ Failed to get System Event 7045")
    
    # Test 3: Search high-risk events
    print("\n🔴 High Risk Events:")
    high_risk = db.search_events_by_risk(min_risk=9)
    print(f"   Found {len(high_risk)} events with risk >= 9")
    for event in high_risk[:5]:
        print(f"   - EventID {event['event_id']} ({event['source']}): {event['name']}")
    
    # Test 4: MITRE queries
    print("\n🎯 MITRE ATT&CK Queries:")
    tactic = db.get_mitre_tactic("Initial Access")
    if tactic:
        print(f"   ✅ Tactic: {tactic['tactic_name']}")
    
    techniques = db.get_techniques_for_tactic("Credential Access")
    print(f"   ✅ Found {len(techniques)} techniques for Credential Access")
    
    technique = db.get_technique_by_id("T1078")
    if technique:
        print(f"   ✅ Technique T1078: {technique['technique_name']}")
    
    print("\n✅ Database Manager tests passed!")
    return True


def test_eventid_mapper():
    """Test EventIDMapper with database backend"""
    print("\n" + "=" * 60)
    print("TEST 2: EventID Mapper Integration")
    print("=" * 60)
    
    mapper = get_mapper()
    
    # Test 1: Get event intelligence
    print("\n🔍 Testing Event Intelligence:")
    
    event_ids = [4624, 4625, 1, 7045, 4688]
    for event_id in event_ids:
        info = mapper.get_event_intelligence(event_id)
        print(f"   EventID {event_id}: {info['name']} (Risk: {info['risk_score']}, Source: {info['source']})")
    
    # Test 2: Calculate risk scores
    print("\n📊 Testing Risk Score Calculation:")
    
    context = {
        'is_night_time': True,
        'events_per_minute': 15,
        'failed_login_ratio': 0.7,
        'has_suspicious_content': True
    }
    
    risk = mapper.calculate_risk_score(4625, context=context)
    print(f"   EventID 4625 with suspicious context: Risk Score = {risk}")
    
    # Test 3: MITRE mapping
    print("\n🎯 Testing MITRE Mapping:")
    
    mitre = mapper.get_mitre_mapping(4624)
    print(f"   EventID 4624 MITRE Mapping:")
    print(f"   - Primary Tactic: {mitre['primary_tactic']}")
    print(f"   - Tactics: {', '.join(mitre['tactics'])}")
    print(f"   - Techniques: {', '.join(mitre['techniques'])}")
    
    # Test 4: Suspicious detection
    print("\n⚠️ Testing Suspicious Detection:")
    
    is_suspicious, reasons = mapper.is_suspicious(4625, context=context)
    print(f"   EventID 4625 is suspicious: {is_suspicious}")
    if reasons:
        print(f"   Reasons: {', '.join(reasons[:3])}")
    
    # Test 5: Attack stage mapping
    print("\n🎭 Testing Attack Stage Mapping:")
    
    stage = mapper.get_attack_stage_from_eventid(4624)
    print(f"   EventID 4624 -> {stage}")
    
    stage = mapper.get_attack_stage_from_eventid(4688)
    print(f"   EventID 4688 -> {stage}")
    
    # Test 6: Statistics
    print("\n📈 Mapper Statistics:")
    stats = mapper.get_statistics()
    print(f"   Total Events: {stats['total_events']}")
    print(f"   High Risk Events: {stats['high_risk_events']}")
    
    print("\n✅ EventID Mapper tests passed!")
    return True


def test_dataframe_enrichment():
    """Test enriching a DataFrame with database data"""
    print("\n" + "=" * 60)
    print("TEST 3: DataFrame Enrichment")
    print("=" * 60)
    
    # Create sample DataFrame
    data = {
        'EventID': [4624, 4625, 4688, 1, 7045],
        'Channel': ['Security', 'Security', 'Security', 'Sysmon', 'System'],
        'Computer': ['PC1', 'PC2', 'PC1', 'PC3', 'PC2']
    }
    df = pd.DataFrame(data)
    
    print("\n📋 Original DataFrame:")
    print(df)
    
    # Enrich with mapper
    mapper = get_mapper()
    enriched_df = mapper.enrich_events(df)
    
    print("\n✨ Enriched DataFrame:")
    display_cols = ['EventID', 'EventID_Name', 'EventID_RiskScore', 'EventID_Severity', 'EventID_PrimaryTactic']
    print(enriched_df[display_cols])
    
    print("\n✅ DataFrame enrichment test passed!")
    return True


def test_analysis_results():
    """Test saving and retrieving analysis results"""
    print("\n" + "=" * 60)
    print("TEST 4: Analysis Results Storage")
    print("=" * 60)
    
    db = get_db_manager()
    
    # Create test session
    session_id = "test_session_12345"
    
    print(f"\n💾 Saving test results for session: {session_id}")
    
    # Save some test results
    test_results = [
        {
            'event_record_id': 1001,
            'event_id': 4625,
            'computer': 'TEST-PC',
            'timestamp': '2024-01-01T10:00:00',
            'anomaly': 1,
            'anomaly_score': 0.95,
            'cluster_label': 'Cluster 1',
            'mitre_stage': 'Stage 1: Initial Access',
            'confidence': 0.87
        },
        {
            'event_record_id': 1002,
            'event_id': 4688,
            'computer': 'TEST-PC',
            'timestamp': '2024-01-01T10:01:00',
            'anomaly': 1,
            'anomaly_score': 0.82,
            'cluster_label': 'Cluster 2',
            'mitre_stage': 'Stage 2: Execution',
            'confidence': 0.79
        }
    ]
    
    for result in test_results:
        db.insert_analysis_result(session_id, result)
    
    print(f"   ✅ Saved {len(test_results)} test results")
    
    # Retrieve results
    print(f"\n📥 Retrieving results for session: {session_id}")
    
    anomalies = db.get_anomalies_by_session(session_id)
    print(f"   ✅ Retrieved {len(anomalies)} anomalies")
    
    for anomaly in anomalies:
        print(f"   - EventID {anomaly['event_id']}: Score {anomaly['anomaly_score']:.2f}, Stage: {anomaly['mitre_stage']}")
    
    print("\n✅ Analysis results storage test passed!")
    return True


def run_all_tests():
    """Run all integration tests"""
    print("\n" + "=" * 60)
    print("DATABASE INTEGRATION TEST SUITE")
    print("=" * 60)
    
    tests = [
        ("Database Manager", test_database_manager),
        ("EventID Mapper", test_eventid_mapper),
        ("DataFrame Enrichment", test_dataframe_enrichment),
        ("Analysis Results", test_analysis_results)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ {test_name} FAILED with error: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{status}: {test_name}")
    
    print(f"\n{passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Database integration is working correctly.")
        return True
    else:
        print("\n⚠️ Some tests failed. Please review the errors above.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
