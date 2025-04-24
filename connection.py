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
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'duration': self.duration,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'suspicious': self.suspicious,
            'threat_level': self.threat_level,
            'notes': self.notes
        }
