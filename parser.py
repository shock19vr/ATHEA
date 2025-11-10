"""
Log Parser Module
Handles parsing of EVTX, CSV, and generic log files into structured format.
"""

import os
import csv
import json
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import xml.etree.ElementTree as ET

# EVTX backend selection
BACKEND = None
EvtxReader = None
PyEvtxParser = None

try:
    from Evtx.Evtx import Evtx as EvtxReader
    BACKEND = 'python-evtx'
except Exception:
    try:
        from evtx import PyEvtxParser
        BACKEND = 'evtx'
    except Exception:
        BACKEND = None


class LogParser:
    """Unified log parser supporting multiple formats"""
    
    def __init__(self):
        self.supported_formats = ['.evtx', '.csv', '.log', '.json', '.txt']
    
    def parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse a log file based on its extension.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            List of parsed events as dictionaries
        """
        ext = Path(file_path).suffix.lower()
        
        if ext == '.evtx':
            return self.parse_evtx(file_path)
        elif ext == '.csv':
            return self.parse_csv(file_path)
        elif ext == '.json':
            return self.parse_json(file_path)
        elif ext in ['.log', '.txt']:
            return self.parse_generic_log(file_path)
        else:
            raise ValueError(f"Unsupported file format: {ext}")
    
    def parse_evtx(self, evtx_file: str) -> List[Dict[str, Any]]:
        """Parse Windows EVTX file"""
        events = []
        errors = []
        
        # Check backend availability
        if BACKEND is None:
            raise ImportError(
                "No EVTX backend available.\n"
                "Install one of these:\n"
                "  pip install python-evtx\n"
                "  pip install evtx"
            )
        
        try:
            ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
            
            if BACKEND == 'python-evtx' and EvtxReader is not None:
                with EvtxReader(evtx_file) as log:
                    for record_idx, record in enumerate(log.records()):
                        try:
                            # Skip processing if we've hit too many errors
                            if len(errors) > 1000 and len(events) == 0:
                                raise RuntimeError(
                                    f"Too many parsing errors ({len(errors)}) with no successful events. "
                                    "The file may be severely corrupted."
                                )
                                
                            # Try to parse the record
                            try:
                                event_elem = record.lxml()
                            except Exception as e:
                                # If we can't parse with lxml, try to skip this record
                                errors.append(f"Record {record_idx}: Failed to parse record with lxml: {str(e)}")
                                continue
                                
                            if event_elem is None:
                                errors.append(f"Record {record_idx}: lxml() returned None")
                                continue
                                
                            try:
                                event_dict = self._extract_evtx_fields(event_elem, ns)
                                if event_dict:  # Only append if we got a valid event
                                    events.append(event_dict)
                            except Exception as e:
                                errors.append(f"Record {record_idx}: Failed to extract fields: {str(e)}")
                                if len(errors) <= 5:  # Log first 5 errors
                                    print(f"Warning - Field extraction error: {e}")
                                continue
                                
                        except (AttributeError, TypeError) as e:
                            # Handle common parser errors
                            error_msg = str(e)
                            if 'NullTypeNode' in error_msg or 'find_end_of_stream' in error_msg:
                                errors.append(f"Record {record_idx}: Corrupt record - {error_msg}")
                            else:
                                errors.append(f"Record {record_idx}: {error_msg}")
                            continue
                            
                        except Exception as e:
                            errors.append(f"Record {record_idx}: Unexpected error - {str(e)}")
                            if len(errors) <= 5:  # Log first 5 errors
                                print(f"Warning - Unexpected error: {e}")
                            continue
                            
            elif BACKEND == 'evtx' and PyEvtxParser is not None:
                parser = PyEvtxParser(evtx_file)
                for record_idx, record in enumerate(parser.records()):
                    try:
                        # Skip processing if we've hit too many errors
                        if len(errors) > 1000 and len(events) == 0:
                            raise RuntimeError(
                                f"Too many parsing errors ({len(errors)}) with no successful events. "
                                "The file may be severely corrupted."
                            )
                            
                        event_dict = self._extract_evtx_pyparser(record, ns)
                        if event_dict:
                            events.append(event_dict)
                    except Exception as e:
                        errors.append(f"Record {record_idx}: {str(e)}")
                        if len(errors) <= 5:
                            print(f"Warning - Record parse error: {e}")
                        continue
                
        except Exception as e:
            raise RuntimeError(f"Failed to parse EVTX file: {str(e)}\nBackend: {BACKEND}")
        
        # If we got some events, return them even if there were errors
        if len(events) > 0:
            if len(errors) > 0:
                print(f"⚠️ Warning: Parsed {len(events)} events but encountered {len(errors)} errors (skipped corrupt records)")
            return self._enrich_events(events)
        
        # Only raise error if we got zero events
        if len(errors) > 0:
            raise RuntimeError(
                f"Failed to parse any events from EVTX file.\n"
                f"Encountered {len(errors)} errors.\n"
                f"First error: {errors[0] if errors else 'Unknown'}\n"
                f"Backend used: {BACKEND}\n\n"
                f"💡 This file may have corrupted records or use unsupported structures.\n"
                f"Try converting to CSV first using the standalone evtx_to_csv_converter.py"
            )
            
        return self._enrich_events(events)
    
    def _extract_evtx_fields(self, event_elem, ns: str) -> Dict[str, Any]:
        """Extract fields from EVTX XML element"""
        event_dict = {
            'EventID': self._get_xml_text(event_elem, f'.//{ns}EventID'),
            'Level': self._get_xml_text(event_elem, f'.//{ns}Level'),
            'TimeCreated': self._get_xml_attr(event_elem, f'.//{ns}TimeCreated', 'SystemTime'),
            'Computer': self._get_xml_text(event_elem, f'.//{ns}Computer'),
            'Channel': self._get_xml_text(event_elem, f'.//{ns}Channel'),
            'ProviderName': self._get_xml_attr(event_elem, f'.//{ns}Provider', 'Name'),
            'ProviderGuid': self._get_xml_attr(event_elem, f'.//{ns}Provider', 'Guid'),
            'Keywords': self._get_xml_text(event_elem, f'.//{ns}Keywords'),
            'Task': self._get_xml_text(event_elem, f'.//{ns}Task'),
            'Opcode': self._get_xml_text(event_elem, f'.//{ns}Opcode'),
            'EventRecordID': self._get_xml_text(event_elem, f'.//{ns}EventRecordID'),
            'ExecutionProcessID': self._get_xml_attr(event_elem, f'.//{ns}Execution', 'ProcessID'),
            'ExecutionThreadID': self._get_xml_attr(event_elem, f'.//{ns}Execution', 'ThreadID'),
            'SecurityUserID': self._get_xml_attr(event_elem, f'.//{ns}Security', 'UserID'),
            'EventData': {}
        }
        
        for item in event_elem.findall(f'.//{ns}Data'):
            name = item.get('Name') or f"Data_{len(event_dict['EventData'])}"
            event_dict['EventData'][name] = item.text
            
        return event_dict
    
    def _extract_evtx_pyparser(self, record, ns: str) -> Optional[Dict[str, Any]]:
        """Extract fields from PyEvtxParser record"""
        xml_text = None
        event_elem = None
        
        # Try object-like API
        if hasattr(record, 'xml'):
            try:
                xml_text = record.xml()
            except Exception:
                pass
        
        if xml_text and isinstance(xml_text, str):
            try:
                event_elem = ET.fromstring(xml_text)
            except Exception:
                pass
        
        # Try dict-like API
        if event_elem is None and isinstance(record, dict):
            evt = record.get('event') or record.get('Event') or {}
            system = evt.get('System') if isinstance(evt, dict) else {}
            
            if system:
                return {
                    'EventID': system.get('EventID'),
                    'Level': system.get('Level'),
                    'TimeCreated': (system.get('TimeCreated', {}) or {}).get('SystemTime'),
                    'Computer': system.get('Computer'),
                    'Channel': system.get('Channel'),
                    'EventData': evt.get('EventData', {})
                }
        
        if event_elem is not None:
            return self._extract_evtx_fields(event_elem, ns)
        
        return None
    
    def _get_xml_text(self, element, xpath: str) -> Optional[str]:
        """Safely get text from XML element"""
        elem = element.find(xpath)
        return elem.text if elem is not None else None
    
    def _get_xml_attr(self, element, xpath: str, attr: str) -> Optional[str]:
        """Safely get attribute from XML element"""
        elem = element.find(xpath)
        return elem.get(attr) if elem is not None else None
    
    def parse_csv(self, csv_file: str) -> List[Dict[str, Any]]:
        """Parse CSV log file"""
        events = []
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    events.append(dict(row))
        except Exception as e:
            print(f"Error reading CSV file: {e}")
        
        return self._enrich_events(events)
    
    def parse_json(self, json_file: str) -> List[Dict[str, Any]]:
        """Parse JSON log file"""
        events = []
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    events = data
                elif isinstance(data, dict):
                    events = [data]
        except Exception as e:
            print(f"Error reading JSON file: {e}")
        
        return self._enrich_events(events)
    
    def parse_generic_log(self, log_file: str) -> List[Dict[str, Any]]:
        """Parse generic text log file (line-by-line)"""
        events = []
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for idx, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Try to extract timestamp, IP, user, etc.
                    event = self._parse_log_line(line, idx)
                    events.append(event)
        except Exception as e:
            print(f"Error reading log file: {e}")
        
        return self._enrich_events(events)
    
    def _parse_log_line(self, line: str, line_num: int) -> Dict[str, Any]:
        """Parse a single log line with pattern matching"""
        event = {
            'LineNumber': line_num,
            'RawLog': line,
            'Timestamp': None,
            'Level': None,
            'User': None,
            'IP': None,
            'Action': None
        }
        
        # Timestamp patterns
        ts_patterns = [
            r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)',
            r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        ]
        
        for pattern in ts_patterns:
            match = re.search(pattern, line)
            if match:
                event['Timestamp'] = match.group(1)
                break
        
        # IP address
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        if ip_match:
            event['IP'] = ip_match.group(0)
        
        # Level/Severity
        level_match = re.search(r'\b(ERROR|WARN|INFO|DEBUG|CRITICAL|FATAL)\b', line, re.IGNORECASE)
        if level_match:
            event['Level'] = level_match.group(1).upper()
        
        # User patterns
        user_match = re.search(r'user[:\s=]+([^\s,;]+)', line, re.IGNORECASE)
        if user_match:
            event['User'] = user_match.group(1)
        
        # Common actions
        action_keywords = ['login', 'logout', 'failed', 'success', 'denied', 'access', 'error', 'connect']
        for keyword in action_keywords:
            if keyword.lower() in line.lower():
                event['Action'] = keyword.capitalize()
                break
        
        return event
    
    def _enrich_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich events with temporal and derived features"""
        level_names = {
            '1': 'Critical', '2': 'Error', '3': 'Warning', 
            '4': 'Information', '5': 'Verbose',
            1: 'Critical', 2: 'Error', 3: 'Warning', 
            4: 'Information', 5: 'Verbose'
        }
        
        enriched = []
        for ev in events:
            e = dict(ev)
            
            # Parse numeric fields
            e['EventRecordID'] = self._safe_int(e.get('EventRecordID'))
            e['EventID'] = self._safe_int(e.get('EventID'))
            e['Level'] = self._safe_int(e.get('Level'))
            e['ExecutionProcessID'] = self._safe_int(e.get('ExecutionProcessID'))
            e['ExecutionThreadID'] = self._safe_int(e.get('ExecutionThreadID'))
            
            # Parse timestamp
            timestamp_field = e.get('TimeCreated') or e.get('Timestamp')
            dt = self._parse_time(timestamp_field)
            
            if dt is not None:
                e['TimeCreatedISO'] = dt.isoformat()
                e['Year'] = dt.year
                e['Month'] = dt.month
                e['Day'] = dt.day
                e['Hour'] = dt.hour
                e['Minute'] = dt.minute
                e['Weekday'] = dt.weekday()
                e['IsWeekend'] = 1 if dt.weekday() >= 5 else 0
                e['EpochSeconds'] = int(dt.timestamp())
            else:
                e['TimeCreatedISO'] = None
                e['Year'] = e['Month'] = e['Day'] = None
                e['Hour'] = e['Minute'] = e['Weekday'] = None
                e['IsWeekend'] = e['EpochSeconds'] = None
            
            # Level name
            lvl = e.get('Level')
            e['LevelName'] = level_names.get(lvl, e.get('LevelName'))
            
            # Clean EventData
            ed = e.get('EventData', {}) or {}
            if isinstance(ed, dict):
                clean_ed = {}
                for k, v in ed.items():
                    clean_ed[k] = ' '.join(str(v).split()) if v else None
                e['EventData'] = clean_ed
            
            enriched.append(e)
        
        return enriched
    
    def _safe_int(self, val) -> Optional[int]:
        """Safely convert to int"""
        try:
            if val is None:
                return None
            return int(val)
        except Exception:
            return None
    
    def _parse_time(self, ts) -> Optional[datetime]:
        """
        Parse various timestamp formats while preserving timezone information.
        Returns timezone-aware datetime when possible.
        """
        if not ts:
            return None
        
        try:
            # ISO format with Z (UTC)
            if isinstance(ts, str) and ts.endswith('Z'):
                ts_clean = ts[:-1]
                dt = datetime.fromisoformat(ts_clean)
                return dt.replace(tzinfo=timezone.utc)
            
            # ISO format with timezone offset (e.g., +05:30, -08:00)
            # datetime.fromisoformat handles this automatically in Python 3.7+
            if isinstance(ts, str):
                dt = datetime.fromisoformat(str(ts))
                # If no timezone info, assume UTC for consistency
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
        except Exception:
            pass
        
        # Try common formats (these will be timezone-naive, so we'll assume UTC)
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y/%m/%d %H:%M:%S',
            '%d/%b/%Y:%H:%M:%S',
            '%b %d %H:%M:%S'
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(str(ts), fmt)
                # Assume UTC for timezone-naive timestamps
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                continue
        
        return None
