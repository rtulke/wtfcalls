#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security.py – Security monitoring and threat intelligence
"""
import os
import re
import json
import time
import logging
from typing import Dict, List, Tuple, Set

# Check for optional dependencies
try:
    import yaml
    yaml_available = True
except ImportError:
    yaml_available = False

try:
    import ipaddress
    ipaddress_available = True
except ImportError:
    ipaddress_available = False


class ThreatIntelligence:
    """
    Basic threat intelligence engine for analyzing network connections
    """
    def __init__(self, config_path: str = None):
        self.known_malicious_ips = set()
        self.suspicious_ports = set()
        self.trusted_processes = set()
        self.trusted_connections = set()  # (process, remote_ip) pairs that are trusted
        self.rules = []
        
        # Load default rules
        self._load_default_rules()
        
        # Load custom rules if provided
        if config_path and os.path.exists(config_path):
            self._load_custom_rules(config_path)
    
    def _load_default_rules(self) -> None:
        """Load default security rules"""
        # Suspicious ports (commonly used by malware)
        self.suspicious_ports = {
            # Common backdoor ports
            31337, 1337, 4444, 5555, 
            # Tor
            9050, 9051,
            # Common trojan ports
            6667, 6668, 6669,  # IRC often used for C&C
            8080, 8888, 8443,  # Alternate HTTP/HTTPS ports sometimes used for C&C
            # Uncommon but legitimate ports that might be suspicious in certain contexts
            6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889  # BitTorrent
        }
        
        # Default rule set
        self.rules = [
            {
                'name': 'Suspicious port',
                'description': 'Connection to potentially suspicious port',
                'condition': lambda conn: conn.rp in self.suspicious_ports,
                'threat_level': 1
            },
            {
                'name': 'Private to public',
                'description': 'Process with no internet need connecting to public IP',
                'condition': lambda conn: (self._is_private_ip(conn.lip) and 
                                          not self._is_private_ip(conn.rip) and
                                          conn.process_name in self.get_non_internet_processes()),
                'threat_level': 1
            },
            {
                'name': 'Unusual subprocess connections',
                'description': 'Subprocess making unusual outbound connections',
                'condition': lambda conn: self._is_unusual_subprocess_connection(conn),
                'threat_level': 1
            },
            {
                'name': 'Non-browser on HTTP/HTTPS',
                'description': 'Non-browser process connecting to HTTP/HTTPS ports',
                'condition': lambda conn: (conn.rp in (80, 443, 8080, 8443) and 
                                          not self._is_browser_or_known_http_client(conn.process_name)),
                'threat_level': 1,
                'exceptions': ['com.apple.WebKit', 'updates', 'slack', 'spotify', 'curl', 'wget']
            },
            {
                'name': 'High data volume',
                'description': 'Unusually high data volume for process type',
                'condition': lambda conn: hasattr(conn, 'bytes_sent') and conn.bytes_sent > 10000000,
                'threat_level': 1
            },
            {
                'name': 'Known malicious IP',
                'description': 'Connection to known malicious IP address',
                'condition': lambda conn: conn.rip in self.known_malicious_ips,
                'threat_level': 2
            }
        ]
    
    def _load_custom_rules(self, config_path: str) -> None:
        """Load custom rules from configuration file"""
        try:
            with open(config_path, 'r') as f:
                if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                    if yaml_available:
                        config = yaml.safe_load(f)
                    else:
                        logging.warning("PyYAML ist erforderlich für YAML-Konfigurationsdateien")
                        return
                elif config_path.endswith('.json'):
                    config = json.load(f)
                else:
                    logging.warning(f"Nicht unterstütztes Konfigurationsformat: {config_path}")
                    return
            
            # Load malicious IPs
            if 'malicious_ips' in config:
                self.known_malicious_ips.update(set(config['malicious_ips']))
            
            # Load suspicious ports
            if 'suspicious_ports' in config:
                self.suspicious_ports.update(set(config['suspicious_ports']))
            
            # Load trusted processes
            if 'trusted_processes' in config:
                self.trusted_processes.update(set(config['trusted_processes']))
            
            # Load trusted connections
            if 'trusted_connections' in config:
                for tc in config['trusted_connections']:
                    if 'process' in tc and 'ip' in tc:
                        self.trusted_connections.add((tc['process'], tc['ip']))
            
            # Load custom rules
            if 'custom_rules' in config:
                for rule in config['custom_rules']:
                    if 'name' in rule and 'condition' in rule and 'threat_level' in rule:
                        # Parse condition string into a lambda
                        try:
                            condition_str = rule['condition']
                            # Convert to an actual lambda function
                            # Warning: Security risk if config file is not trusted
                            condition_func = eval(f"lambda conn: {condition_str}")
                            
                            self.rules.append({
                                'name': rule['name'],
                                'description': rule.get('description', ''),
                                'condition': condition_func,
                                'threat_level': int(rule['threat_level']),
                                'exceptions': rule.get('exceptions', [])
                            })
                        except Exception as e:
                            logging.warning(f"Fehler beim Parsen der Regelbedingung: {str(e)}")
        
        except Exception as e:
            logging.warning(f"Fehler beim Laden der Sicherheitskonfiguration: {str(e)}")
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is in private range"""
        if not ipaddress_available:
            # Fallback wenn ipaddress-
