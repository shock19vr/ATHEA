import sys
import os
import json
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, 
                            QPushButton, QFileDialog, QProgressBar, QMessageBox)
from PyQt6.QtCore import Qt, QMimeData
import csv
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# EVTX backend selection: try python-evtx first, then Evtx (PyEvtxParser)
BACKEND = None
EvtxReader = None
PyEvtxParser = None
try:
    from Evtx.Evtx import Evtx as EvtxReader  # python-evtx
    BACKEND = 'python-evtx'
except Exception:
    try:
        from evtx import PyEvtxParser  # Evtx
        BACKEND = 'evtx'
    except Exception:
        BACKEND = None

def parse_evtx_to_json(evtx_file):
    """Convert EVTX file to a list of JSON events."""
    events = []
    try:
        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
        if BACKEND == 'python-evtx' and EvtxReader is not None:
            with EvtxReader(evtx_file) as log:
                for record in log.records():
                    try:
                        event_elem = record.lxml()
                        event_dict = {
                            'EventID': (event_elem.find(f'.//{ns}EventID').text if event_elem.find(f'.//{ns}EventID') is not None else None),
                            'Level': (event_elem.find(f'.//{ns}Level').text if event_elem.find(f'.//{ns}Level') is not None else None),
                            'TimeCreated': (event_elem.find(f'.//{ns}TimeCreated').get('SystemTime') if event_elem.find(f'.//{ns}TimeCreated') is not None else None),
                            'Computer': (event_elem.find(f'.//{ns}Computer').text if event_elem.find(f'.//{ns}Computer') is not None else None),
                            'Channel': (event_elem.find(f'.//{ns}Channel').text if event_elem.find(f'.//{ns}Channel') is not None else None),
                            'ProviderName': (event_elem.find(f'.//{ns}Provider').get('Name') if event_elem.find(f'.//{ns}Provider') is not None else None),
                            'ProviderGuid': (event_elem.find(f'.//{ns}Provider').get('Guid') if event_elem.find(f'.//{ns}Provider') is not None else None),
                            'Keywords': (event_elem.find(f'.//{ns}Keywords').text if event_elem.find(f'.//{ns}Keywords') is not None else None),
                            'Task': (event_elem.find(f'.//{ns}Task').text if event_elem.find(f'.//{ns}Task') is not None else None),
                            'Opcode': (event_elem.find(f'.//{ns}Opcode').text if event_elem.find(f'.//{ns}Opcode') is not None else None),
                            'EventRecordID': (event_elem.find(f'.//{ns}EventRecordID').text if event_elem.find(f'.//{ns}EventRecordID') is not None else None),
                            'ExecutionProcessID': (event_elem.find(f'.//{ns}Execution').get('ProcessID') if event_elem.find(f'.//{ns}Execution') is not None else None),
                            'ExecutionThreadID': (event_elem.find(f'.//{ns}Execution').get('ThreadID') if event_elem.find(f'.//{ns}Execution') is not None else None),
                            'SecurityUserID': (event_elem.find(f'.//{ns}Security').get('UserID') if event_elem.find(f'.//{ns}Security') is not None else None),
                            'EventData': {}
                        }
                        for item in event_elem.findall(f'.//{ns}Data'):
                            name = item.get('Name') or f"Data_{len(event_dict['EventData'])}"
                            event_dict['EventData'][name] = item.text
                        events.append(event_dict)
                    except Exception as e:
                        print(f"Error parsing record: {e}")
                        continue
        elif BACKEND == 'evtx' and PyEvtxParser is not None:
            parser = PyEvtxParser(evtx_file)
            for record in parser.records():
                try:
                    # Some versions yield objects with xml(), others yield dicts
                    xml_text = None
                    event_elem = None
                    # Object-like API
                    if hasattr(record, 'xml'):
                        try:
                            xml_text = record.xml()
                        except Exception:
                            xml_text = None
                    if xml_text is None and hasattr(record, 'get_xml_string'):
                        try:
                            xml_text = record.get_xml_string()
                        except Exception:
                            xml_text = None
                    if xml_text:
                        try:
                            event_elem = ET.fromstring(xml_text)
                        except Exception:
                            event_elem = None
                    # Dict-like API
                    if event_elem is None and isinstance(record, dict):
                        # Try common keys
                        xml_text = record.get('xml') or record.get('data')
                        if isinstance(xml_text, str) and xml_text.strip().startswith('<'):
                            try:
                                event_elem = ET.fromstring(xml_text)
                            except Exception:
                                event_elem = None
                        if event_elem is None:
                            # Try extracting from structured dict: {'Event': {'System': {...}, 'EventData': {...}}}
                            evt = record.get('event') or record.get('Event') or {}
                            system = evt.get('System') if isinstance(evt, dict) else {}
                            event_data_dict = evt.get('EventData') if isinstance(evt, dict) else {}
                            if system:
                                event_dict = {
                                    'EventID': (system.get('EventID') if isinstance(system.get('EventID'), (str, int)) else (system.get('EventID', {}) or {}).get('value')),
                                    'Level': system.get('Level'),
                                    'TimeCreated': (system.get('TimeCreated', {}) or {}).get('SystemTime'),
                                    'Computer': system.get('Computer'),
                                    'Channel': system.get('Channel'),
                                    'EventData': {}
                                }
                                if isinstance(event_data_dict, dict):
                                    for k, v in event_data_dict.items():
                                        event_dict['EventData'][k] = v
                                events.append(event_dict)
                                continue
                    if event_elem is None:
                        continue
                    # Extract from XML element
                    event_dict = {
                        'EventID': (event_elem.find(f'.//{ns}EventID').text if event_elem.find(f'.//{ns}EventID') is not None else None),
                        'Level': (event_elem.find(f'.//{ns}Level').text if event_elem.find(f'.//{ns}Level') is not None else None),
                        'TimeCreated': (event_elem.find(f'.//{ns}TimeCreated').get('SystemTime') if event_elem.find(f'.//{ns}TimeCreated') is not None else None),
                        'Computer': (event_elem.find(f'.//{ns}Computer').text if event_elem.find(f'.//{ns}Computer') is not None else None),
                        'Channel': (event_elem.find(f'.//{ns}Channel').text if event_elem.find(f'.//{ns}Channel') is not None else None),
                        'ProviderName': (event_elem.find(f'.//{ns}Provider').get('Name') if event_elem.find(f'.//{ns}Provider') is not None else None),
                        'ProviderGuid': (event_elem.find(f'.//{ns}Provider').get('Guid') if event_elem.find(f'.//{ns}Provider') is not None else None),
                        'Keywords': (event_elem.find(f'.//{ns}Keywords').text if event_elem.find(f'.//{ns}Keywords') is not None else None),
                        'Task': (event_elem.find(f'.//{ns}Task').text if event_elem.find(f'.//{ns}Task') is not None else None),
                        'Opcode': (event_elem.find(f'.//{ns}Opcode').text if event_elem.find(f'.//{ns}Opcode') is not None else None),
                        'EventRecordID': (event_elem.find(f'.//{ns}EventRecordID').text if event_elem.find(f'.//{ns}EventRecordID') is not None else None),
                        'ExecutionProcessID': (event_elem.find(f'.//{ns}Execution').get('ProcessID') if event_elem.find(f'.//{ns}Execution') is not None else None),
                        'ExecutionThreadID': (event_elem.find(f'.//{ns}Execution').get('ThreadID') if event_elem.find(f'.//{ns}Execution') is not None else None),
                        'SecurityUserID': (event_elem.find(f'.//{ns}Security').get('UserID') if event_elem.find(f'.//{ns}Security') is not None else None),
                        'EventData': {}
                    }
                    for item in event_elem.findall(f'.//{ns}Data'):
                        name = item.get('Name') or f"Data_{len(event_dict['EventData'])}"
                        event_dict['EventData'][name] = (item.text if item.text is not None else None)
                    events.append(event_dict)
                except Exception as e:
                    print(f"Error parsing record: {e}")
                    continue
        else:
            raise ImportError("No EVTX backend available. Install python-evtx or Evtx.")
    except Exception as e:
        print(f"Error reading EVTX file: {e}")
    return events

def _safe_int(val):
    try:
        return int(val)
    except Exception:
        return None

def _parse_time(ts):
    try:
        # Expecting like '2024-01-01T12:34:56.7890123Z'
        if ts and ts.endswith('Z'):
            ts = ts[:-1]
            dt = datetime.fromisoformat(ts)
            return dt.replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(ts) if ts else None
    except Exception:
        return None

def enrich_events_for_ml(events):
    level_names = {
        1: 'Critical',
        2: 'Error',
        3: 'Warning',
        4: 'Information',
        5: 'Verbose'
    }
    enriched = []
    for ev in events:
        e = dict(ev)
        e['EventRecordID'] = _safe_int(e.get('EventRecordID'))
        e['EventID'] = _safe_int(e.get('EventID'))
        e['Level'] = _safe_int(e.get('Level'))
        e['ExecutionProcessID'] = _safe_int(e.get('ExecutionProcessID'))
        e['ExecutionThreadID'] = _safe_int(e.get('ExecutionThreadID'))

        dt = _parse_time(e.get('TimeCreated'))
        if dt is not None:
            e['TimeCreatedISO'] = dt.astimezone(timezone.utc).isoformat()
            e['Year'] = dt.year
            e['Month'] = dt.month
            e['Day'] = dt.day
            e['Hour'] = dt.hour
            e['Weekday'] = dt.weekday()
            e['IsWeekend'] = 1 if dt.weekday() >= 5 else 0
            e['EpochSeconds'] = int(dt.timestamp())
        else:
            e['TimeCreatedISO'] = None
            e['Year'] = None
            e['Month'] = None
            e['Day'] = None
            e['Hour'] = None
            e['Weekday'] = None
            e['IsWeekend'] = None
            e['EpochSeconds'] = None

        lvl = e.get('Level')
        e['LevelName'] = level_names.get(lvl)

        # Normalize EventData values to strings without newlines for readability
        ed = e.get('EventData', {}) or {}
        clean_ed = {}
        for k, v in ed.items():
            if v is None:
                clean_ed[k] = None
            else:
                s = str(v)
                clean_ed[k] = ' '.join(s.split())
        e['EventData'] = clean_ed
        enriched.append(e)
    return enriched

class EVTXConverter(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("EVTX to CSV Converter")
        self.setMinimumSize(600, 400)
        self.setAcceptDrops(True)
        
        # Main widget and layout
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.layout = QVBoxLayout(self.main_widget)
        
        # Drop area
        self.drop_label = QLabel("Drag and drop EVTX files here\nor click 'Select Files'")
        self.drop_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop_label.setStyleSheet(
            """
            QLabel {
                border: 2px dashed #aaa;
                border-radius: 10px;
                padding: 40px;
                font-size: 16px;
                color: #666;
            }
            QLabel:hover {
                background-color: #f5f5f5;
            }
            """
        )
        self.layout.addWidget(self.drop_label)
        
        # Buttons
        self.select_button = QPushButton("Select EVTX Files")
        self.select_button.clicked.connect(self.select_files)
        self.layout.addWidget(self.select_button)
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.hide()
        self.layout.addWidget(self.progress)
        
        # Status label
        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.status_label)
    
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event):
        files = [url.toLocalFile() for url in event.mimeData().urls()
                if url.toLocalFile().lower().endswith('.evtx')]
        if files:
            self.process_files(files)
    
    def select_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select EVTX Files", "", "EVTX Files (*.evtx)")
        if files:
            self.process_files(files)
    
    def process_files(self, file_paths):
        self.progress.setMaximum(len(file_paths))
        self.progress.setValue(0)
        self.progress.show()
        
        for i, file_path in enumerate(file_paths, 1):
            try:
                self.status_label.setText(f"Processing: {os.path.basename(file_path)}")
                QApplication.processEvents()
                
                # First pass: collect events and all headers
                events = parse_evtx_to_json(file_path)
                if not events:
                    self.status_label.setText(f"No valid events found in {os.path.basename(file_path)}")
                    self.progress.setValue(i)
                    continue

                events = enrich_events_for_ml(events)

                base_fields = [
                    'EventRecordID',
                    'TimeCreated',
                    'TimeCreatedISO',
                    'Year',
                    'Month',
                    'Day',
                    'Hour',
                    'Weekday',
                    'IsWeekend',
                    'EpochSeconds',
                    'EventID',
                    'Level',
                    'LevelName',
                    'ProviderName',
                    'Task',
                    'Opcode',
                    'Keywords',
                    'Channel',
                    'Computer',
                    'ExecutionProcessID',
                    'ExecutionThreadID',
                    'SecurityUserID'
                ]
                data_fields = set()
                for ev in events:
                    data_fields.update(ev.get('EventData', {}).keys())
                ordered_data_fields = sorted(data_fields)
                fieldnames = base_fields + [f"EventData.{k}" for k in ordered_data_fields]

                # Write CSV
                output_path = os.path.splitext(file_path)[0] + '.csv'
                with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    for ev in events:
                        row = {key: ev.get(key) for key in base_fields}
                        for k in ordered_data_fields:
                            row[f"EventData.{k}"] = ev.get('EventData', {}).get(k)
                        writer.writerow(row)
                
                self.status_label.setText(f"Successfully converted to {os.path.basename(output_path)}")
                self.progress.setValue(i)
                
            except Exception as e:
                self.status_label.setText(f"Error processing {os.path.basename(file_path)}: {str(e)}")
        
        QMessageBox.information(self, "Conversion Complete", 
                              f"Successfully processed {len(file_paths)} file(s)")
        self.progress.hide()

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern look
    window = EVTXConverter()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
