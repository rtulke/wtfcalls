#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
utils.py – Utility functions for WTFCalls
"""
import json
import csv
import logging
import time
from typing import Dict, List

# Check for optional dependencies
try:
    import yaml
    yaml_available = True
except ImportError:
    yaml_available = False


def export_connections(connections: Dict, filename: str, format: str = 'csv') -> None:
    """Export connections to file"""
    if not connections:
        return
        
    try:
        if format.lower() == 'csv':
            _export_to_csv(connections, filename)
        elif format.lower() == 'json':
            _export_to_json(connections, filename)
        elif format.lower() == 'yaml':
            if yaml_available:
                _export_to_yaml(connections, filename)
            else:
                logging.error("PyYAML ist erforderlich für YAML-Export")
        else:
            logging.error(f"Nicht unterstütztes Exportformat: {format}")
    except Exception as e:
        logging.error(f"Export-Fehler: {str(e)}")
        
def _export_to_csv(connections: Dict, filename: str) -> None:
    """Export connections to CSV format"""
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['pid', 'process_name', 'local_ip', 'local_port', 
                     'remote_ip', 'remote_port', 'timestamp', 
                     'bytes_sent', 'bytes_received', 'suspicious', 'threat_level']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for key, conn in connections.items():
            row = {
                'pid': conn.pid,
                'process_name': conn.process_name,
                'local_ip': conn.lip,
                'local_port': conn.lp,
                'remote_ip': conn.rip,
                'remote_port': conn.rp,
                'timestamp': conn.timestamp,
            }
            
            # Add optional fields if available
            if hasattr(conn, 'bytes_sent'):
                row['bytes_sent'] = conn.bytes_sent
                row['bytes_received'] = conn.bytes_received
            else:
                row['bytes_sent'] = 0
                row['bytes_received'] = 0
                
            if hasattr(conn, 'suspicious'):
                row['suspicious'] = conn.suspicious
                row['threat_level'] = conn.threat_level
            else:
                row['suspicious'] = False
                row['threat_level'] = 0
                
            writer.writerow(row)
            
def _export_to_json(connections: Dict, filename: str) -> None:
    """Export connections to JSON format"""
    data = []
    for key, conn in connections.items():
        if hasattr(conn, 'to_dict'):
            data.append(conn.to_dict())
        else:
            data.append({
                'pid': conn.pid,
                'process_name': conn.process_name,
                'local_ip': conn.lip,
                'local_port': conn.lp,
                'remote_ip': conn.rip,
                'remote_port': conn.rp,
                'timestamp': conn.timestamp
            })
            
    with open(filename, 'w') as jsonfile:
        json.dump(data, jsonfile, indent=2)
        
def _export_to_yaml(connections: Dict, filename: str) -> None:
    """Export connections to YAML format"""
    import yaml
        
    data = []
    for key, conn in connections.items():
        if hasattr(conn, 'to_dict'):
            data.append(conn.to_dict())
        else:
            data.append({
                'pid': conn.pid,
                'process_name': conn.process_name,
                'local_ip': conn.lip,
                'local_port': conn.lp,
                'remote_ip': conn.rip,
                'remote_port': conn.rp,
                'timestamp': conn.timestamp
            })
            
    with open(filename, 'w') as yamlfile:
        yaml.dump(data, yamlfile)


def export_alerts(alerts: List[dict], filename: str, format: str = 'json') -> None:
    """Export security alerts to file"""
    if not alerts:
        return
        
    try:
        with open(filename, 'w') as f:
            if format.lower() == 'json':
                # Convert timestamp to ISO format for better readability
                formatted_alerts = []
                for alert in alerts:
                    alert_copy = alert.copy()
                    alert_copy['timestamp'] = time.strftime(
                        '%Y-%m-%d %H:%M:%S', 
                        time.localtime(alert['timestamp'])
                    )
                    formatted_alerts.append(alert_copy)
                    
                json.dump(formatted_alerts, f, indent=2)
            elif format.lower() == 'yaml':
                if yaml_available:
                    import yaml
                    # Convert timestamp to ISO format for better readability
                    formatted_alerts = []
                    for alert in alerts:
                        alert_copy = alert.copy()
                        alert_copy['timestamp'] = time.strftime(
                            '%Y-%m-%d %H:%M:%S', 
                            time.localtime(alert['timestamp'])
                        )
                        formatted_alerts.append(alert_copy)
                        
                    yaml.dump(formatted_alerts, f)
                else:
                    logging.error("PyYAML ist erforderlich für YAML-Export")
            else:
                logging.error(f"Nicht unterstütztes Exportformat: {format}")
    except Exception as e:
        logging.error(f"Fehler beim Exportieren der Alarme: {str(e)}")
