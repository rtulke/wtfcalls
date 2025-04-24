#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logger.py – Logging utility for connection events
"""
import logging
import platform
from logging.handlers import SysLogHandler

from dns_resolver import DNSResolver


class ConnectionLogger:
    """
    Handles logging of connection events to syslog.
    """
    def __init__(self, enable: bool = True):
        self.logger = None
        self.dns_resolver = None
        self.enable = enable
        
        if enable:
            self._setup_logger()
            
    def _setup_logger(self) -> None:
        """Configure the syslog logger"""
        self.logger = logging.getLogger("wtfcalls")
        self.logger.setLevel(logging.INFO)
        
        if platform.system() == 'Darwin':
            syslog_address = "/var/run/syslog"
        else:
            syslog_address = "/dev/log"
            
        try:
            handler = SysLogHandler(address=syslog_address)
            handler.setFormatter(logging.Formatter(
                '%(asctime)s wtfcalls: %(message)s', 
                datefmt='%b %d %H:%M:%S'))
            self.logger.addHandler(handler)
        except (FileNotFoundError, PermissionError) as e:
            print(f"Warning: Could not set up logging: {str(e)}")
            self.enable = False
            
    def set_dns_resolver(self, resolver: DNSResolver) -> None:
        """Set the DNS resolver to use for formatting addresses"""
        self.dns_resolver = resolver
        
    def _format_addr(self, ip: str, port: int) -> str:
        """Format address for logging"""
        if self.dns_resolver:
            return self.dns_resolver.format_addr(ip, port)
        return f"{ip}:{port}"
        
    def log_new_connection(self, conn) -> None:
        """Log a new connection"""
        if not self.enable or not self.logger:
            return
            
        self.logger.info(
            f"[NEW] {conn.process_name}[{conn.pid}] "
            f"{self._format_addr(conn.lip, conn.lp)} -> {self._format_addr(conn.rip, conn.rp)}"
        )
        
    def log_closed_connection(self, conn) -> None:
        """Log a closed connection"""
        if not self.enable or not self.logger:
            return
            
        self.logger.info(
            f"[CLOSED] {conn.process_name}[{conn.pid}] "
            f"{self._format_addr(conn.lip, conn.lp)} -> {self._format_addr(conn.rip, conn.rp)}"
        )
