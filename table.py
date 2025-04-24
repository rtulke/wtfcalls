#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
table.py – Table display handling
"""
import time
from typing import Dict
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
        """Build a rich table with New, Active, and Closed sections"""
        table = Table(title="wtfcalls – Connections")
        
        # Calculate optimal width for program column based on current data
        max_program_length = 15  # Default minimum width
        for conn in list(active.values()):
            program_length = len(conn.process_name)
            max_program_length = max(max_program_length, program_length)
        
        # Add columns based on configuration
        table.add_column("PID", style="cyan", no_wrap=True, width=8)
        table.add_column("Program", style="magenta", ratio=4, min_width=max_program_length, 
                         no_wrap=True, overflow="ellipsis")
        
        if self.config.get('split_port'):
            table.add_column("Local IP", style="green")
            table.add_column("Local Port", style="green")
            table.add_column("Remote IP", style="red")
            table.add_column("Remote Port", style="red")
        else:
            table.add_column("Local (Host:Port)", style="green")
            table.add_column("Remote (Host:Port)", style="red")
            
        # Add traffic column if enabled
        if self.config.get('traffic'):
            table.add_column("Traffic", style="yellow")
            
        now = time.time()
        
        # Section: New Connections
        delay_new = self.config.get('delay_new', 10)
        table.add_row(
            f"[bold]New (<= {delay_new}s)[/bold]", 
            *['']*(len(table.columns)-1), 
            end_section=True
        )
        
        self._add_new_connections(table, active, new_conns, now)
        
        # Section: Active Connections
        table.add_row(
            "[bold]Active[/bold]", 
            *['']*(len(table.columns)-1), 
            end_section=True
        )
        
        self._add_active_connections(table, active, new_conns)
        
        # Section: Closed Connections
        delay_closed = self.config.get('delay_closed', 10)
        table.add_row(
            f"[bold]Closed (<= {delay_closed}s)[/bold]", 
            *['']*(len(table.columns)-1), 
            end_section=True
        )
        
        self._add_closed_connections(table, closed_conns, now)
        
        return table
        
    def _add_new_connections(self, table: Table, active: Dict, new_conns: Dict, now: float) -> None:
        """Add new connections to the table"""
        delay_new = self.config.get('delay_new', 10)
        
        for key, ts in list(new_conns.items()):
            if key in active and now - ts <= delay_new:
                pid, lip, lp, rip, rp = key
                conn = active[key]
                name = conn.process_name
                
                if self.config.get('split_port'):
                    row = [
                        f"[bright_cyan]{pid}[/bright_cyan]",
                        f"[bright_magenta]{name}[/bright_magenta]",
                        f"[bright_green]{self.dns_resolver.resolve(lip)}[/bright_green]",
                        f"[bright_green]{lp}[/bright_green]",
                        f"[bright_red]{self.dns_resolver.resolve(rip)}[/bright_red]",
                        f"[bright_red]{rp}[/bright_red]"
                    ]
                    
                    # Add traffic info if available and enabled
                    if self.config.get('traffic') and hasattr(conn, 'bytes_sent'):
                        traffic = f"{self._format_bytes(conn.bytes_sent)} ↑ / {self._format_bytes(conn.bytes_received)} ↓"
                        row.append(f"[bright_yellow]{traffic}[/bright_yellow]")
                        
                    table.add_row(*row)
                else:
                    row = [
                        f"[bright_cyan]{pid}[/bright_cyan]",
                        f"[bright_magenta]{name}[/bright_magenta]",
                        f"[bright_green]{self.dns_resolver.format_addr(lip, lp)}[/bright_green]",
                        f"[bright_red]{self.dns_resolver.format_addr(rip, rp)}[/bright_red]"
                    ]
                    
                    # Add traffic info if available and enabled
                    if self.config.get('traffic') and hasattr(conn, 'bytes_sent'):
                        traffic = f"{self._format_bytes(conn.bytes_sent)} ↑ / {self._format_bytes(conn.bytes_received)} ↓"
                        row.append(f"[bright_yellow]{traffic}[/bright_yellow]")
                        
                    table.add_row(*row)
            else:
                new_conns.pop(key, None)
                
    def _add_active_connections(self, table: Table, active: Dict, new_conns: Dict) -> None:
        """Add active connections to the table"""
        for key, conn in active.items():
            if key in new_conns:
                continue
                
            pid, lip, lp, rip, rp = key
            name = conn.process_name
            
            # Highlight suspicious connections if available
            style_prefix = ""
            if hasattr(conn, 'suspicious') and conn.suspicious:
                style_prefix = "bold "
            
            if self.config.get('split_port'):
                row = [
                    f"[{style_prefix}cyan]{pid}[/{style_prefix}cyan]", 
                    f"[{style_prefix}magenta]{name}[/{style_prefix}magenta]", 
                    f"[{style_prefix}green]{self.dns_resolver.resolve(lip)}[/{style_prefix}green]", 
                    f"[{style_prefix}green]{lp}[/{style_prefix}green]", 
                    f"[{style_prefix}red]{self.dns_resolver.resolve(rip)}[/{style_prefix}red]", 
                    f"[{style_prefix}red]{rp}[/{style_prefix}red]"
                ]
                
                # Add traffic info if available and enabled
                if self.config.get('traffic') and hasattr(conn, 'bytes_sent'):
                    traffic = f"{self._format_bytes(conn.bytes_sent)} ↑ / {self._format_bytes(conn.bytes_received)} ↓"
                    row.append(f"[{style_prefix}yellow]{traffic}[/{style_prefix}yellow]")
                    
                table.add_row(*row)
            else:
                row = [
                    f"[{style_prefix}cyan]{pid}[/{style_prefix}cyan]", 
                    f"[{style_prefix}magenta]{name}[/{style_prefix}magenta]", 
                    f"[{style_prefix}green]{self.dns_resolver.format_addr(lip, lp)}[/{style_prefix}green]", 
                    f"[{style_prefix}red]{self.dns_resolver.format_addr(rip, rp)}[/{style_prefix}red]"
                ]
                
                # Add traffic info if available and enabled
                if self.config.get('traffic') and hasattr(conn, 'bytes_sent'):
                    traffic = f"{self._format_bytes(conn.bytes_sent)} ↑ / {self._format_bytes(conn.bytes_received)} ↓"
                    row.append(f"[{style_prefix}yellow]{traffic}[/{style_prefix}yellow]")
                    
                table.add_row(*row)
                
    def _add_closed_connections(self, table: Table, closed_conns: Dict, now: float) -> None:
        """Add closed connections to the table"""
        delay_closed = self.config.get('delay_closed', 10)
        
        for key, (conn, ts) in list(closed_conns.items()):
            if now - ts <= delay_closed:
                pid, lip, lp, rip, rp = key
                name = conn.process_name
                
                if self.config.get('split_port'):
                    row = [
                        f"[grey37]{pid}[/grey37]",
                        f"[grey37]{name}[/grey37]",
                        f"[grey37]{self.dns_resolver.resolve(lip)}[/grey37]",
                        f"[grey37]{lp}[/grey37]",
                        f"[grey37]{self.dns_resolver.resolve(rip)}[/grey37]",
                        f"[grey37]{rp}[/grey37]"
                    ]
                    
                    # Add traffic info if available and enabled
                    if self.config.get('traffic') and hasattr(conn, 'bytes_sent'):
                        traffic = f"{self._format_bytes(conn.bytes_sent)} ↑ / {self._format_bytes(conn.bytes_received)} ↓"
                        row.append(f"[grey37]{traffic}[/grey37]")
                        
                    table.add_row(*row)
                else:
                    row = [
                        f"[grey37]{pid}[/grey37]",
                        f"[grey37]{name}[/grey37]",
                        f"[grey37]{self.dns_resolver.format_addr(lip, lp)}[/grey37]",
                        f"[grey37]{self.dns_resolver.format_addr(rip, rp)}[/grey37]"
                    ]
                    
                    # Add traffic info if available and enabled
                    if self.config.get('traffic') and hasattr(conn, 'bytes_sent'):
                        traffic = f"{self._format_bytes(conn.bytes_sent)} ↑ / {self._format_bytes(conn.bytes_received)} ↓"
                        row.append(f"[grey37]{traffic}[/grey37]")
                        
                    table.add_row(*row)
            else:
                closed_conns.pop(key, None)
                
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
