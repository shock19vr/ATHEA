"""
Test EVTX Parser Backend
Diagnose EVTX parsing issues
"""

import sys

print("🔍 Checking EVTX Parser Backend...\n")

# Check python-evtx
print("1️⃣ Testing python-evtx:")
try:
    from Evtx.Evtx import Evtx as EvtxReader
    print("   ✅ python-evtx is installed and importable")
    BACKEND1 = 'python-evtx'
except Exception as e:
    print(f"   ❌ python-evtx not available: {e}")
    BACKEND1 = None

# Check evtx (PyEvtxParser)
print("\n2️⃣ Testing evtx (PyEvtxParser):")
try:
    from evtx import PyEvtxParser
    print("   ✅ evtx (PyEvtxParser) is installed and importable")
    BACKEND2 = 'evtx'
except Exception as e:
    print(f"   ❌ evtx not available: {e}")
    BACKEND2 = None

# Report selected backend
print("\n" + "="*50)
if BACKEND1:
    print(f"✅ Selected Backend: {BACKEND1}")
elif BACKEND2:
    print(f"✅ Selected Backend: {BACKEND2}")
else:
    print("❌ NO BACKEND AVAILABLE!")
    print("\n🔧 To fix this, install one of these:")
    print("   pip install python-evtx")
    print("   pip install evtx")
    sys.exit(1)

# Test with a sample file if provided
print("\n" + "="*50)
print("\n3️⃣ Testing with a file:")

if len(sys.argv) > 1:
    test_file = sys.argv[1]
    print(f"   File: {test_file}")
    
    try:
        from parser import LogParser
        parser = LogParser()
        
        print("   Parsing...")
        events = parser.parse_evtx(test_file)
        
        print(f"   ✅ Successfully parsed {len(events)} events")
        
        if len(events) > 0:
            print("\n   Sample event:")
            sample = events[0]
            for key, value in list(sample.items())[:5]:
                print(f"      {key}: {value}")
        else:
            print("   ⚠️ WARNING: 0 events parsed. File might be empty or corrupted.")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        import traceback
        print("\n   Full traceback:")
        traceback.print_exc()
else:
    print("   ℹ️ No file provided for testing")
    print("   Usage: python test_evtx_parser.py <path_to_evtx_file>")

print("\n" + "="*50)
print("✅ Diagnostic complete")
