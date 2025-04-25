#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
table.py – Table display handling with flat list structure
"""
import time
import shutil  # Für Terminal-Größenerkennung
from typing import Dict, List, Tuple, Any, Optional
from rich.table import Table
from rich.console import Console

from dns_resolver import DNSResolver


class ConnectionTable:
    """
    Handles display of connection information in a rich table.
    """
    def __init__(self, config: dict, dns_resolver: DNSResolver):
        self.config = config
        self.dns_resolver = dns_resolver
        self.console = Console()
        
    def build_table(self, active: Dict, new_conns: Dict, closed_conns: Dict) -> Table:
        """Build a rich table with all connections in a flat list"""
        # Terminal-Breite ermitteln
        terminal_width, _ = shutil.get_terminal_size((80, 20))  # Fallback 80x20
        
        # Tabelle mit voller Breite und Expansion erstellen
        table = Table(title="wtfcalls – Connections", width=terminal_width, expand=True)
        
        # Calculate optimal width for program column based on current data
        max_program_length = 15  # Default minimum width
        for conn in list(active.values()):
            program_length = len(conn.process_name)
            max_program_length = max(max_program_length, program_length)
        
        # Kolumnen mit relativen Breiten definieren
        table.add_column("PID", style="cyan", no_wrap=True, width=8, ratio=1)
        table.add_column("Program", style="magenta", no_wrap=True, overflow="ellipsis", ratio=7)
        table.add_column("Local IP", style="green", ratio=5)
        table.add_column("Local Port", style="green", ratio=2)
        table.add_column("Remote IP", style="red", ratio=5)
        table.add_column("Remote Port", style="red", ratio=2)
        
        # Add Connection Direction column - increased width for better visibility
        table.add_column("Connection", style="bright_white", width=6, justify="center", ratio=1)
            
        # Add traffic column if enabled
        if self.config.get('traffic'):
            table.add_column("Traffic", style="yellow", ratio=4)
            
        # Add security status column - now always enabled
        table.add_column("Security", style="bold", ratio=3)
            
        # Add connection status column - renamed to Alert
        table.add_column("Alert", style="cyan", ratio=2)
        
        now = time.time()
        
        # Collect all connections with their status
        all_connections = []
        
        # Add new connections
        delay_new = self.config.get('delay_new', 10)
        for key, ts in new_conns.items():
            if key in active and now - ts <= delay_new:
                conn = active[key]
                conn_info = {
                    'conn': conn,
                    'status': 'new',
                    'ts': ts
                }
                all_connections.append(conn_info)
        
        # Add active connections that are not new
        for key, conn in active.items():
            if key not in new_conns:
                conn_info = {
                    'conn': conn,
                    'status': 'connected',
                    'ts': conn.timestamp
                }
                all_connections.append(conn_info)
        
        # Add closed connections
        delay_closed = self.config.get('delay_closed', 10)
        for key, (conn, ts) in closed_conns.items():
            if now - ts <= delay_closed:
                conn_info = {
                    'conn': conn,
                    'status': 'closed',
                    'ts': ts
                }
                all_connections.append(conn_info)
        
        # Sort connections by timestamp (newest first)
        all_connections.sort(key=lambda x: x['ts'], reverse=True)
        
        # Apply alert filter if specified
        alert_filter = self.config.get('filter_alert', [])
        if alert_filter:
            filtered_connections = []
            for conn_info in all_connections:
                conn = conn_info['conn']
                security_status = self._get_security_status_text(conn, conn_info['status'] == 'closed')
                
                # Check if security status matches any filter
                if any(filter_text.lower() in security_status.lower() for filter_text in alert_filter):
                    filtered_connections.append(conn_info)
            all_connections = filtered_connections
        
        # Apply connection direction filter if specified
        conn_direction_filter = self.config.get('filter_connection')
        if conn_direction_filter:
            filtered_connections = []
            for conn_info in all_connections:
                conn = conn_info['conn']
                # Filter by connection direction
                if conn.direction == conn_direction_filter:
                    filtered_connections.append(conn_info)
            all_connections = filtered_connections
        
        # Add all connections to the table
        for conn_info in all_connections:
            conn = conn_info['conn']
            status = conn_info['status']
            self._add_connection_to_table(table, conn, status, now)
            
        return table
    
    def _get_security_status_text(self, conn, is_closed=False) -> str:
        """Get plain text security status for filtering"""
        if is_closed:
            return "--"
            
        if not hasattr(conn, 'suspicious'):
            return "Normal"
            
        if conn.suspicious:
            if conn.threat_level >= 2:
                return "Malicious"
            else:
                return "Suspicious"
                
        # If it's a trusted connection
        if hasattr(conn, 'notes') and "trusted" in conn.notes.lower():
            return "Trusted"
            
        return "Normal"
        
    def _add_connection_to_table(self, table: Table, conn, status: str, now: float) -> None:
        """Add a single connection to the table"""
        pid, lip, lp, rip, rp = conn.key
        name = conn.process_name
        
        # Set style based on connection status
        if status == 'new':
            style_prefix = "bright_"
            status_style = f"[bright_green]New[/bright_green]"
        elif status == 'closed':
            style_prefix = "grey37"
            status_style = f"[grey37]Closed[/grey37]"
        else:  # connected
            style_prefix = ""
            status_style = "[cyan]Connected[/cyan]"
            
        # Override style for suspicious connections
        if hasattr(conn, 'suspicious') and conn.suspicious and status != 'closed':
            style_prefix = "bold "
            
        # Direction color based on direction (red for incoming, green for outgoing)
        direction_color = "bright_red" if conn.direction == "in" else "bright_green"
        
        # Always using split port format now
        row = [
            f"[{style_prefix}cyan]{pid}[/{style_prefix}cyan]", 
            f"[{style_prefix}magenta]{name}[/{style_prefix}magenta]", 
            f"[{style_prefix}green]{self.dns_resolver.resolve(lip)}[/{style_prefix}green]", 
            f"[{style_prefix}green]{lp}[/{style_prefix}green]", 
            f"[{style_prefix}red]{self.dns_resolver.resolve(rip)}[/{style_prefix}red]", 
            f"[{style_prefix}red]{rp}[/{style_prefix}red]",
            f"[{style_prefix}{direction_color} bold]{conn.direction_symbol}[/{style_prefix}{direction_color} bold]"
        ]
        
        # Add traffic info if available and enabled
        if self.config.get('traffic') and hasattr(conn, 'bytes_sent'):
            traffic = f"{self._format_bytes(conn.bytes_sent)} ↑ / {self._format_bytes(conn.bytes_received)} ↓"
            row.append(f"[{style_prefix}yellow]{traffic}[/{style_prefix}yellow]")
        
        # Add security status - now always enabled
        security_status = self._get_security_status(conn, status == 'closed')
        row.append(security_status)
            
        # Add connection status (now Alert)
        row.append(status_style)
            
        table.add_row(*row)
                
    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human-readable format"""
        if bytes_val < 1024:
            return f"{bytes_val}B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val/1024:.1f}KB"
        elif bytes_val < 1024 * 1024 * 1024:
            return f"{bytes_val/(1024*1024):.1f}MB"
        else:
            return f"{bytes_val/(1024*1024*1024):.1f}GB"
            
    def _get_security_status(self, conn, is_closed=False) -> str:
        """Get formatted security status for a connection"""
        if is_closed:
            return f"[grey37]--[/grey37]"
            
        if not hasattr(conn, 'suspicious'):
            return "[white]Normal[/white]"
            
        if conn.suspicious:
            if conn.threat_level >= 2:
                return f"[bright_red bold]Malicious[/bright_red bold]"
            else:
                return f"[bright_yellow]Suspicious[/bright_yellow]"
                
        # If it's a trusted connection
        if hasattr(conn, 'notes') and "trusted" in conn.notes.lower():
            return f"[green]Trusted[/green]"
            
        return "[white]Normal[/white]"
