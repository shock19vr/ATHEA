import sys

print("Testing imports...")

try:
    import Evtx
    print(f"✅ Evtx imported: {Evtx}")
    print(f"   Location: {Evtx.__file__}")
    print(f"   Contents: {dir(Evtx)}")
except Exception as e:
    print(f"❌ Cannot import Evtx: {e}")

try:
    from Evtx.Evtx import Evtx as EvtxReader
    print(f"✅ Evtx.Evtx.Evtx imported: {EvtxReader}")
except Exception as e:
    print(f"❌ Cannot import Evtx.Evtx.Evtx: {e}")

try:
    import evtx
    print(f"✅ evtx imported: {evtx}")
    print(f"   Location: {evtx.__file__}")
    print(f"   Contents: {dir(evtx)}")
except Exception as e:
    print(f"❌ Cannot import evtx: {e}")
