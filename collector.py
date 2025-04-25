#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collector.py – Connection collection classes
"""
import psutil
import platform
import subprocess
import re
from typing import Dict, Tuple

from connection import Connection, EnhancedConnection


class ConnectionCollector:
    """
    Collects network connection information.
    """
    def __init__(self, config: dict):
        self.config = config
        
    def get_connections(self) -> Dict[Tuple, Connection]:
        """Get all current outgoing connections"""
        connections = {}
        
        # Determine which address family to use
        kind = 'inet4' if self.config.get('ipv4') else 'inet6' if self.config.get('ipv6') else 'inet'
        
        try:
            # Try using psutil first
            connections = self._get_connections_psutil(kind)
        except (psutil.AccessDenied, PermissionError):
            # Fall back to lsof if psutil fails due to permissions
            connections = self._get_connections_lsof()
            
        return connections
        
    def _get_connections_psutil(self, kind: str) -> Dict[Tuple, Connection]:
        """Get connections using psutil"""
        connections = {}
        
        for c in psutil.net_connections(kind=kind):
            if c.raddr and c.status != psutil.CONN_LISTEN:
                pid = c.pid or 0
                process_name = self._get_process_name(pid)
                
                # Create Connection object
                conn = Connection(
                    pid=pid, 
                    lip=c.laddr.ip, 
                    lp=c.laddr.port, 
                    rip=c.raddr.ip, 
                    rp=c.raddr.port, 
                    process_name=process_name
                )
                connections[conn.key] = conn
                
        return connections
        
    def _get_connections_lsof(self) -> Dict[Tuple, Connection]:
        """Get connections using lsof command (fallback)"""
        connections = {}
        
        # Prepare lsof command based on config
        cmd = ['lsof', '-i', '-n', '-P']
        if self.config.get('ipv4'):
            cmd = ['lsof', '-i4', '-n', '-P']
        if self.config.get('ipv6'):
            cmd = ['lsof', '-i6', '-n', '-P']
            
        try:
            out = subprocess.check_output(cmd, text=True)
        except Exception:
            return connections
            
        # Parse lsof output
        for line in out.splitlines()[1:]:  # Skip header line
            parts = re.split(r"\s+", line)
            if len(parts) < 9 or '->' not in parts[8]:
                continue
                
            proc_name, pid_str = parts[0], parts[1]
            try:
                pid = int(pid_str)
            except ValueError:
                continue
                
            local, remote = parts[8].split('->')
            try:
                lip, lp = local.rsplit(':', 1)
                rip, rp = remote.rsplit(':', 1)
                lp, rp = int(lp), int(rp)
            except Exception:
                continue
                
            # Create Connection object
            conn = Connection(
                pid=pid, 
                lip=lip, 
                lp=lp, 
                rip=rip, 
                rp=rp, 
                process_name=proc_name
            )
            connections[conn.key] = conn
            
        return connections
        
    def _get_process_name(self, pid: int) -> str:
        """Get process name from PID based on configuration"""
        try:
            proc = psutil.Process(pid)
            
            # Option: Improved process name (default)
            # For macOS, try to extract a meaningful application name
            if platform.system() == 'Darwin':
                try:
                    exe = proc.exe()
                    if exe:
                        # If it's a macOS bundle executable
                        if '/Contents/MacOS/' in exe:
                            parts = exe.split('/')
                            # Find the *.app or *.xpc directory
                            for i, part in enumerate(parts):
                                if part.endswith('.app') or part.endswith('.xpc'):
                                    # Return the bundle identifier if available
                                    exec_name = parts[-1] if len(parts) > 0 else part
                                    if '.' in exec_name and exec_name.startswith('com.'):
                                        return exec_name
                                    # Otherwise return the app/bundle name without extension
                                    return part.rsplit('.', 1)[0]
                            
                            # If we can't find the bundle, use the executable name
                            return exe.split('/')[-1]
                        else:
                            # For non-bundle executables, just use the filename
                            return exe.split('/')[-1]
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Try to get a concise name from command line
            try:
                cmdline = proc.cmdline()
                if cmdline and cmdline[0]:
                    # For command with full path, just return the filename
                    cmd = cmdline[0].split('/')[-1]
                    # If it's a bundle identifier, return it fully
                    if cmd.startswith('com.') and '.' in cmd:
                        return cmd
                    return cmd
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
            # Fall back to process name
            name = proc.name()
            return name
                
        except Exception:
            return '<Unknown>'


class EnhancedConnectionCollector(ConnectionCollector):
    """
    Enhanced version of ConnectionCollector that returns EnhancedConnection objects
    """
    def __init__(self, config: dict):
        super().__init__(config)
        
    def get_connections(self) -> Dict[Tuple, EnhancedConnection]:
        """Get all current outgoing connections as EnhancedConnection objects"""
        # First, get connections using the parent class
        base_connections = super().get_connections()
        
        # Convert to EnhancedConnection objects
        enhanced_connections = {}
        for key, conn in base_connections.items():
            enhanced_conn = EnhancedConnection(
                pid=conn.pid,
                lip=conn.lip,
                lp=conn.lp,
                rip=conn.rip,
                rp=conn.rp,
                process_name=conn.process_name,
                timestamp=conn.timestamp
            )
            enhanced_connections[key] = enhanced_conn
            
        return enhanced_connections
