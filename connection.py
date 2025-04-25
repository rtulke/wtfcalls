#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
connection.py – Connection class definitions
"""
import time
from typing import Tuple, Dict


class Connection:
    """
    Represents a network connection with metadata.
    """
    def __init__(self, pid: int, lip: str, lp: int, rip: str, rp: int, 
                 process_name: str, timestamp: float = None):
        self.pid = pid
        self.lip = lip
        self.lp = lp
        self.rip = rip
        self.rp = rp
        self.process_name = process_name
        self.timestamp = timestamp or time.time()
        
    @property
    def key(self) -> Tuple[int, str, int, str, int]:
        """Unique identifier for this connection"""
        return (self.pid, self.lip, self.lp, self.rip, self.rp)
    
    @property
    def direction(self) -> str:
        """
        Determine connection direction (inbound or outbound)
        Heuristic: If remote port is a well-known port, likely outbound
        """
        # Well-known ports (common services)
        well_known_ports = {
            20, 21,     # FTP
            22,         # SSH
            23,         # Telnet
            25,         # SMTP
            53,         # DNS
            80, 443,    # HTTP, HTTPS
            110, 995,   # POP3
            143, 993,   # IMAP
            194,        # IRC
            389, 636,   # LDAP
            427,        # SLP
            445,        # SMB
            465, 587,   # SMTP Submission
            514,        # Syslog
            543, 544,   # Kerberos
            873,        # rsync
            1080,       # SOCKS
            3128, 8080, # HTTP Proxy
            5432,       # PostgreSQL
            3306,       # MySQL
            6667,       # IRC
            8443        # HTTPS Alternate
        }
        
        # If our local port is privileged (< 1024) and remote port is higher, likely inbound
        if self.lp < 1024 and self.rp >= 1024:
            return "in"  # Inbound connection
        
        # If the remote port is a well-known service port, likely outbound
        if self.rp in well_known_ports:
            return "out"  # Outbound connection
            
        # If local port is high and remote port is high, use port numbers as heuristic
        if self.lp >= 1024 and self.rp >= 1024:
            # Client ports are typically higher than server ports
            if self.lp > self.rp:
                return "out"  # Likely outbound
            else:
                return "in"   # Likely inbound
        
        # Default: assume outbound
        return "out"
    
    @property
    def direction_symbol(self) -> str:
        """Return a symbol representing the connection direction with improved visibility"""
        if self.direction == "in":
            return "◀"  # Schwarzes Dreieck nach links (U+25C0)
            # Alternative Optionen:
            # return "⟵"  # Längerer mathematischer Pfeil (U+27F5)
            # return "←"   # Einfacher Pfeil nach links (U+2190)
            # return "<--" # ASCII-Variante
        else:
            return "▶"  # Schwarzes Dreieck nach rechts (U+25B6)
            # Alternative Optionen:
            # return "⟶"  # Längerer mathematischer Pfeil (U+27F6)
            # return "→"   # Einfacher Pfeil nach rechts (U+2192)
            # return "-->" # ASCII-Variante
    
    def __eq__(self, other):
        if not isinstance(other, Connection):
            return False
        return self.key == other.key
    
    def __hash__(self):
        return hash(self.key)


class EnhancedConnection(Connection):
    """
    Extended Connection class with traffic monitoring and security features
    """
    def __init__(self, pid: int, lip: str, lp: int, rip: str, rp: int, 
                 process_name: str, timestamp: float = None):
        super().__init__(pid, lip, lp, rip, rp, process_name, timestamp)
        self.bytes_sent = 0
        self.bytes_received = 0
        self.last_update = time.time()
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.suspicious = False
        self.threat_level = 0  # 0: normal, 1: suspicious, 2: potentially malicious
        self.notes = ""
        self.context = {}  # For storing additional metadata
        
    def update_traffic(self, sent: int, received: int) -> None:
        """Update traffic counters"""
        self.bytes_sent = sent
        self.bytes_received = received
        self.last_update = time.time()
        self.last_seen = time.time()
        
    @property
    def duration(self) -> float:
        """Get connection duration in seconds"""
        return self.last_seen - self.first_seen
        
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            'pid': self.pid,
            'process_name': self.process_name,
            'local_ip': self.lip,
            'local_port': self.lp,
            'remote_ip': self.rip,
            'remote_port': self.rp,
            'direction': self.direction,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'duration': self.duration,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'suspicious': self.suspicious,
            'threat_level': self.threat_level,
            'notes': self.notes
        }
