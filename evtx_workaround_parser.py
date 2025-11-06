"""
EVTX Workaround Parser
For problematic EVTX files that python-evtx can't parse directly.
Uses evtx_dump_json utility as a more robust alternative.
"""

import subprocess
import json
import sys
from pathlib import Path
import pandas as pd


def parse_evtx_via_dump(evtx_file: str, output_json: str = None) -> list:
    """
    Parse EVTX using evtx_dump_json utility (more robust).
    
    Args:
        evtx_file: Path to EVTX file
        output_json: Optional output JSON path
        
    Returns:
        List of event dictionaries
    """
    if output_json is None:
        output_json = str(Path(evtx_file).with_suffix('.json'))
    
    print(f"🔄 Converting EVTX to JSON using evtx_dump_json...")
    
    try:
        # Run evtx_dump_json.exe
        cmd = ['python', '-m', 'Evtx.evtx_dump_json', evtx_file]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        if result.returncode != 0:
            print(f"❌ evtx_dump_json failed: {result.stderr}")
            return []
        
        # Parse JSON output (one JSON object per line)
        events = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError:
                continue
        
        print(f"✅ Extracted {len(events)} events")
        
        # Optionally save to file
        if output_json:
            with open(output_json, 'w', encoding='utf-8') as f:
                json.dump(events, f, indent=2)
            print(f"💾 Saved to: {output_json}")
        
        return events
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return []


def convert_evtx_to_csv(evtx_file: str, output_csv: str = None):
    """Convert EVTX to CSV using the workaround parser"""
    if output_csv is None:
        output_csv = str(Path(evtx_file).with_suffix('.csv'))
    
    events = parse_evtx_via_dump(evtx_file)
    
    if not events:
        print("❌ No events extracted")
        return
    
    # Flatten events to DataFrame
    rows = []
    for event in events:
        row = {}
        
        # Extract Event.System fields
        system = event.get('Event', {}).get('System', {})
        row['EventID'] = system.get('EventID', {}).get('#text')
        row['Level'] = system.get('Level')
        row['TimeCreated'] = system.get('TimeCreated', {}).get('@SystemTime')
        row['Computer'] = system.get('Computer')
        row['Channel'] = system.get('Channel')
        row['Provider'] = system.get('Provider', {}).get('@Name')
        row['EventRecordID'] = system.get('EventRecordID')
        
        # Extract EventData fields
        event_data = event.get('Event', {}).get('EventData', {})
        if isinstance(event_data, dict):
            for key, value in event_data.items():
                if key.startswith('@'):
                    continue
                row[f'EventData.{key}'] = value
        
        rows.append(row)
    
    # Create DataFrame and save
    df = pd.DataFrame(rows)
    df.to_csv(output_csv, index=False)
    print(f"✅ Saved {len(df)} events to: {output_csv}")
    print(f"\n📤 Now upload {output_csv} to the Streamlit app!")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python evtx_workaround_parser.py <evtx_file>")
        print("\nExample:")
        print("  python evtx_workaround_parser.py my_log.evtx")
        print("\nThis will create my_log.csv that you can upload to the app")
        sys.exit(1)
    
    evtx_file = sys.argv[1]
    
    if not Path(evtx_file).exists():
        print(f"❌ File not found: {evtx_file}")
        sys.exit(1)
    
    print(f"🔧 Processing: {evtx_file}\n")
    convert_evtx_to_csv(evtx_file)
