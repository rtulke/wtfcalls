#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security.py – Security monitoring and threat intelligence with persistent suspicious status
"""
import os
import re
import json
import time
import logging
from typing import Dict, List, Tuple, Set

# Setup custom logger instead of using root logger
logger = logging.getLogger("wtfcalls.security")

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
        
        # Keep track of previously analyzed connections
        self.suspicious_keys = set()  # Store keys of connections that were previously marked suspicious
        
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
                        logger.warning("PyYAML ist erforderlich für YAML-Konfigurationsdateien")
                        return
                elif config_path.endswith('.json'):
                    config = json.load(f)
                else:
                    logger.warning(f"Nicht unterstütztes Konfigurationsformat: {config_path}")
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
                            logger.warning(f"Fehler beim Parsen der Regelbedingung: {str(e)}")
        
        except Exception as e:
            logger.warning(f"Fehler beim Laden der Sicherheitskonfiguration: {str(e)}")
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is in private range"""
        if not ipaddress_available:
            # Fallback wenn ipaddress-Modul nicht verfügbar ist
            private_ranges = [
                ('10.0.0.0', '10.255.255.255'),
                ('172.16.0.0', '172.31.255.255'),
                ('192.168.0.0', '192.168.255.255'),
                ('127.0.0.0', '127.255.255.255')
            ]
            
            # Einfache IP-zu-Integer-Konvertierung
            def ip_to_int(ip_str):
                try:
                    octets = ip_str.split('.')
                    if len(octets) != 4:
                        return 0
                    return sum(int(octet) << (24 - 8 * i) for i, octet in enumerate(octets))
                except:
                    return 0
            
            ip_int = ip_to_int(ip)
            
            # Prüfen, ob in einem privaten Bereich
            for start, end in private_ranges:
                if ip_to_int(start) <= ip_int <= ip_to_int(end):
                    return True
            return False
        else:
            try:
                return ipaddress.ip_address(ip).is_private
            except ValueError:
                return False
    
    def _is_browser_or_known_http_client(self, process_name: str) -> bool:
        """Check if process is a known browser or HTTP client"""
        browsers = {'chrome', 'firefox', 'safari', 'opera', 'edge', 'brave', 'vivaldi', 
                    'wget', 'curl', 'httpie', 'requests', 'http', 'browser',
                    'google', 'claude', 'chatgpt', 'code'}
        
        process_lower = process_name.lower()
        
        # Check for common browser names
        for browser in browsers:
            if browser in process_lower:
                return True
        
        # macOS specific browser processes
        if any(x in process_name for x in ['com.apple.WebKit', 'com.apple.Safari']):
            return True
        
        # System update processes
        if 'update' in process_lower or 'apt' in process_lower or 'yum' in process_lower:
            return True
        
        return False
    
    def _is_unusual_subprocess_connection(self, conn) -> bool:
        """Check if this is an unusual subprocess connection"""
        unusual_subprocess_patterns = [
            r'sh$', r'bash$', r'dash$', r'zsh$',
            r'python[0-9.]*$', r'perl$', r'ruby$', r'node$',
            r'cmd.exe$', r'powershell.exe$', r'wscript.exe$', r'cscript.exe$'
        ]
        
        # Check if process matches any unusual subprocess pattern
        for pattern in unusual_subprocess_patterns:
            if re.search(pattern, conn.process_name):
                # If it's in trusted processes, it's not unusual
                if conn.process_name in self.trusted_processes:
                    return False
                
                # If this specific connection is trusted, it's not unusual
                if (conn.process_name, conn.rip) in self.trusted_connections:
                    return False
                
                return True
        
        return False
    
    def get_non_internet_processes(self) -> Set[str]:
        """Get set of processes that typically don't need internet access"""
        # These are examples - should be customized based on environment
        return {
            'vim', 'vi', 'nano', 'emacs', 'gedit', 'textedit',
            'calc', 'calculator', 'terminal', 'konsole', 'iTerm',
            'sshd', 'systemd', 'init', 'cron', 'at', 'launchd'
        }
    
    def analyze_connection(self, conn) -> None:
        """
        Analyze a connection for suspicious activity
        Updates the connection's threat level and suspicious status
        """
        # Check if this connection was previously marked as suspicious
        if hasattr(conn, 'key') and conn.key in self.suspicious_keys:
            conn.suspicious = True
            conn.threat_level = 1  # At least suspicious
            conn.notes = "Previously marked as suspicious"
            return
        
        # Skip trusted processes
        if conn.process_name in self.trusted_processes:
            conn.notes = "Trusted process"
            return
            
        # Skip trusted connections
        if (conn.process_name, conn.rip) in self.trusted_connections:
            conn.notes = "Trusted connection"
            return
        
        # Apply all rules
        triggered_rules = []
        max_threat_level = 0
        
        for rule in self.rules:
            # Skip if there are exceptions and process is in them
            exceptions = rule.get('exceptions', [])
            if any(ex.lower() in conn.process_name.lower() for ex in exceptions):
                continue
                
            # Apply the rule condition
            try:
                if rule['condition'](conn):
                    triggered_rules.append(rule['name'])
                    max_threat_level = max(max_threat_level, rule['threat_level'])
            except Exception as e:
                logger.debug(f"Rule {rule['name']} evaluation error: {str(e)}")
        
        # Update connection with results
        conn.threat_level = max_threat_level
        conn.suspicious = max_threat_level > 0
        
        if triggered_rules:
            conn.notes = "Triggered rules: " + ", ".join(triggered_rules)
            
        # If connection is suspicious, add to tracking set
        if conn.suspicious and hasattr(conn, 'key'):
            self.suspicious_keys.add(conn.key)
    
    def batch_analyze(self, connections: Dict) -> Dict[str, List]:
        """
        Analyze multiple connections and return results categorized by threat level
        """
        results = {
            'safe': [],
            'suspicious': [],
            'malicious': []
        }
        
        for conn in connections.values():
            self.analyze_connection(conn)
            
            if conn.threat_level == 0:
                results['safe'].append(conn)
            elif conn.threat_level == 1:
                results['suspicious'].append(conn)
            else:
                results['malicious'].append(conn)
        
        return results


class SecurityMonitor:
    """
    Monitors connections for security issues and provides alerting
    """
    def __init__(self, config_path: str = None, quiet: bool = False):
        self.threat_intel = ThreatIntelligence(config_path)
        self.alert_history = []
        self.last_check = time.time()
        self.check_interval = 10  # seconds
        self.quiet = quiet  # Control console logging
        
        # Configure logging based on quiet mode
        self._setup_logging()
        
    def _setup_logging(self):
        """Set up logging configuration"""
        # Set up file handler for security alerts
        file_handler = logging.FileHandler("wtfcalls_security.log", mode="a")
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'))
        logger.addHandler(file_handler)
        
        # Set console handler only if not in quiet mode
        if not self.quiet:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(
                '[%(levelname)s] %(message)s'))
            logger.addHandler(console_handler)
            
        # Set level
        logger.setLevel(logging.INFO)
        
    def check_connections(self, connections: Dict) -> List[dict]:
        """
        Check connections for security issues
        Returns a list of alerts
        """
        now = time.time()
        
        # Only check periodically to avoid performance impact
        if now - self.last_check < self.check_interval:
            return []
            
        self.last_check = now
        
        # Analyze all connections
        results = self.threat_intel.batch_analyze(connections)
        
        # Generate alerts for suspicious and malicious connections
        alerts = []
        
        for conn in results.get('suspicious', []) + results.get('malicious', []):
            # Skip generating new alerts for previously alerted connections
            if not self._is_already_alerted(conn):
                alert = {
                    'timestamp': now,
                    'level': 'warning' if conn.threat_level == 1 else 'critical',
                    'message': f"Suspicious connection: {conn.process_name}[{conn.pid}] -> {conn.rip}:{conn.rp}",
                    'details': {
                        'process': conn.process_name,
                        'pid': conn.pid,
                        'remote_ip': conn.rip,
                        'remote_port': conn.rp,
                        'local_ip': conn.lip,
                        'local_port': conn.lp,
                        'threat_level': conn.threat_level,
                        'notes': conn.notes,
                        'connection_key': conn.key if hasattr(conn, 'key') else None
                    }
                }
                
                # Add to history and return
                self.alert_history.append(alert)
                alerts.append(alert)
            
        return alerts
    
    def _is_already_alerted(self, conn) -> bool:
        """Check if this connection has already been alerted"""
        if not hasattr(conn, 'key'):
            return False
            
        # Look for this connection key in recent alerts
        for alert in self.alert_history[-100:]:  # Check only last 100 alerts for performance
            if (alert['details'].get('connection_key') == conn.key and
                time.time() - alert['timestamp'] < 300):  # Only consider alerts from last 5 minutes
                return True
                
        return False
        
    def log_alerts(self, alerts: List[dict]) -> None:
        """Log security alerts"""
        for alert in alerts:
            level = alert['level']
            
            if level == 'critical':
                logger.critical(alert['message'])
            elif level == 'warning':
                logger.warning(alert['message'])
            else:
                logger.info(alert['message'])
                
    def get_recent_alerts(self, seconds: int = 300) -> List[dict]:
        """Get alerts from the last X seconds"""
        now = time.time()
        return [a for a in self.alert_history if now - a['timestamp'] <= seconds]
        
    def get_alerts_by_process(self, process_name: str) -> List[dict]:
        """Get alerts for a specific process"""
        return [a for a in self.alert_history 
                if a['details']['process'].lower() == process_name.lower()]
                
    def export_alerts(self, filename: str, format: str = 'json') -> None:
        """Export alerts to file"""
        if not self.alert_history:
            return
            
        try:
            with open(filename, 'w') as f:
                if format.lower() == 'json':
                    # Convert timestamp to ISO format for better readability
                    formatted_alerts = []
                    for alert in self.alert_history:
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
                        for alert in self.alert_history:
                            alert_copy = alert.copy()
                            alert_copy['timestamp'] = time.strftime(
                                '%Y-%m-%d %H:%M:%S', 
                                time.localtime(alert['timestamp'])
                            )
                            formatted_alerts.append(alert_copy)
                            
                        yaml.dump(formatted_alerts, f)
                    else:
                        logger.error("PyYAML ist erforderlich für YAML-Export")
                else:
                    logger.error(f"Nicht unterstütztes Exportformat: {format}")
        except Exception as e:
            logger.error(f"Fehler beim Exportieren der Alarme: {str(e)}")
