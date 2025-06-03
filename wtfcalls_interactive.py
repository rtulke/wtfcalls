#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wtfcalls_interactive.py – Interactive TUI version with cursor navigation
Enhanced version with scrollable table and row selection
"""
import asyncio
import time
import signal
import os
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass

# Textual imports for TUI
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, DataTable, Static, Label
from textual.reactive import reactive
from textual.binding import Binding
from textual.message import Message
from textual.timer import Timer

# Rich for styling within textual
from rich.text import Text
from rich.console import Console

# Internal modules
from connection import Connection, EnhancedConnection
from collector import ConnectionCollector, EnhancedConnectionCollector
from dns_resolver import DNSResolver
from logger import ConnectionLogger
from traffic import TrafficMonitor
from security import SecurityMonitor
from utils import export_connections, export_alerts


@dataclass
class ConnectionRow:
    """Represents a single row in the connection table"""
    key: Tuple
    connection: EnhancedConnection
    status: str  # 'new', 'connected', 'closed'
    timestamp: float


class ConnectionDataTable(DataTable):
    """Enhanced DataTable with connection-specific functionality"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connection_rows: List[ConnectionRow] = []
        self.cursor_type = "row"  # Select entire rows
        self.zebra_stripes = True  # Alternating row colors
        
    def update_connections(self, rows: List[ConnectionRow]) -> None:
        """Update the table with new connection data"""
        # Clear existing data
        self.clear()
        self.connection_rows = rows
        
        # Add columns if not already present
        if not self.columns:
            self._setup_columns()
            
        # Add rows
        for row_data in rows:
            self._add_connection_row(row_data)
            
    def _setup_columns(self) -> None:
        """Setup table columns"""
        self.add_column("PID", width=8, key="pid")
        self.add_column("Program", width=20, key="program")
        self.add_column("Local IP", width=15, key="local_ip")
        self.add_column("Local Port", width=8, key="local_port")
        self.add_column("Remote IP", width=15, key="remote_ip")
        self.add_column("Remote Port", width=8, key="remote_port")
        self.add_column("Dir", width=4, key="direction")
        self.add_column("Security", width=12, key="security")
        self.add_column("Traffic", width=18, key="traffic")
        self.add_column("Status", width=10, key="status")
        
    def _add_connection_row(self, row_data: ConnectionRow) -> None:
        """Add a single connection row to the table"""
        conn = row_data.connection
        status = row_data.status
        
        # Format data for display
        pid = str(conn.pid)
        program = conn.process_name[:18] + "..." if len(conn.process_name) > 18 else conn.process_name
        local_ip = conn.lip[:13] + "..." if len(conn.lip) > 13 else conn.lip
        local_port = str(conn.lp)
        remote_ip = conn.rip[:13] + "..." if len(conn.rip) > 13 else conn.rip
        remote_port = str(conn.rp)
        direction = conn.direction_symbol
        
        # Security status
        security = self._get_security_status(conn, status == 'closed')
        
        # Traffic information
        traffic = self._get_traffic_info(conn)
        
        # Status with styling
        status_display = self._get_status_display(status)
        
        # Create row with styling based on status and security
        row_style = self._get_row_style(conn, status)
        
        self.add_row(
            pid, program, local_ip, local_port, remote_ip, remote_port,
            direction, security, traffic, status_display,
            key=str(row_data.key)
        )
        
    def _get_security_status(self, conn: EnhancedConnection, is_closed: bool) -> str:
        """Get security status for display"""
        if is_closed:
            return "--"
            
        if not hasattr(conn, 'suspicious'):
            return "Normal"
            
        if conn.suspicious:
            if conn.threat_level >= 2:
                return "🔴 Malicious"
            else:
                return "🟡 Suspicious"
                
        if hasattr(conn, 'notes') and "trusted" in conn.notes.lower():
            return "🟢 Trusted"
            
        return "Normal"
        
    def _get_traffic_info(self, conn: EnhancedConnection) -> str:
        """Get traffic information for display"""
        if hasattr(conn, 'bytes_sent') and hasattr(conn, 'bytes_received'):
            sent = self._format_bytes(conn.bytes_sent)
            recv = self._format_bytes(conn.bytes_received)
            return f"{sent}↑/{recv}↓"
        return "0B↑/0B↓"
        
    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human-readable format"""
        if bytes_val < 1024:
            return f"{bytes_val}B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val/1024:.1f}K"
        elif bytes_val < 1024 * 1024 * 1024:
            return f"{bytes_val/(1024*1024):.1f}M"
        else:
            return f"{bytes_val/(1024*1024*1024):.1f}G"
            
    def _get_status_display(self, status: str) -> str:
        """Get status display string"""
        status_map = {
            'new': '🆕 New',
            'connected': '🔗 Connected',
            'closed': '❌ Closed'
        }
        return status_map.get(status, status)
        
    def _get_row_style(self, conn: EnhancedConnection, status: str) -> str:
        """Get CSS class for row styling"""
        if hasattr(conn, 'suspicious') and conn.suspicious and status != 'closed':
            return "suspicious"
        elif status == 'new':
            return "new"
        elif status == 'closed':
            return "closed"
        return "normal"
        
    def get_selected_connection(self) -> Optional[ConnectionRow]:
        """Get the currently selected connection"""
        if self.cursor_row >= 0 and self.cursor_row < len(self.connection_rows):
            return self.connection_rows[self.cursor_row]
        return None


class StatusPanel(Static):
    """Panel showing current filter and connection statistics"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connection_count = 0
        self.filter_info = ""
        
    def update_status(self, active_count: int, new_count: int, closed_count: int, 
                     filter_info: str = "") -> None:
        """Update status information"""
        self.connection_count = active_count
        self.filter_info = filter_info
        
        status_text = f"Connections: {active_count} active, {new_count} new, {closed_count} closed"
        if filter_info:
            status_text += f" | Filters: {filter_info}"
            
        self.update(status_text)


class HelpPanel(Static):
    """Panel showing keyboard shortcuts"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        help_text = (
            "Controls: ↑/↓ Navigate | PgUp/PgDn Page | "
            "f Filter | r Refresh | q Quit | "
            "e Export | s Security | h Help"
        )
        self.update(help_text)


class WTFCallsInteractiveApp(App):
    """Main interactive TUI application"""
    
    CSS = """
    ConnectionDataTable {
        height: 1fr;
        margin: 1;
    }
    
    .suspicious {
        background: red 20%;
    }
    
    .new {
        background: green 20%;
    }
    
    .closed {
        background: gray 20%;
    }
    
    StatusPanel {
        height: 1;
        background: blue 20%;
        color: white;
        padding: 0 1;
    }
    
    HelpPanel {
        height: 1;
        background: gray 30%;
        color: white;
        padding: 0 1;
    }
    """
    
    TITLE = "WTFCalls - Interactive Network Monitor"
    
    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("r", "refresh", "Refresh"),
        Binding("f", "filter", "Filter"),
        Binding("e", "export", "Export"),
        Binding("s", "security", "Security"),
        Binding("h", "help", "Help"),
        Binding("escape", "clear_selection", "Clear"),
    ]
    
    def __init__(self, config: dict, **kwargs):
        super().__init__(**kwargs)
        self.config = config
        self.refresh_interval = config.get('poll_interval', 1.0)
        
        # Initialize monitoring components
        self.dns_resolver = DNSResolver(
            enable_resolution=not config.get('show_ip', False),
            max_workers=10
        )
        self.logger = ConnectionLogger(enable=True)
        self.logger.set_dns_resolver(self.dns_resolver)
        self.collector = EnhancedConnectionCollector(config)
        
        # Security monitoring (always enabled)
        self.security_monitor = SecurityMonitor(
            config.get('config'),
            quiet=config.get('quiet', False)
        )
        
        # Traffic monitoring if enabled
        self.traffic_monitor = TrafficMonitor() if config.get('traffic') else None
        
        # Connection tracking
        self.active_connections = {}
        self.new_connections = {}
        self.closed_connections = {}
        
        # UI components
        self.connection_table = None
        self.status_panel = None
        self.help_panel = None
        
        # Refresh timer
        self.refresh_timer = None
        
    def compose(self) -> ComposeResult:
        """Compose the UI layout"""
        yield Header()
        
        with Vertical():
            self.status_panel = StatusPanel(id="status")
            yield self.status_panel
            
            self.connection_table = ConnectionDataTable(id="connections")
            yield self.connection_table
            
            self.help_panel = HelpPanel(id="help")
            yield self.help_panel
            
        yield Footer()
        
    async def on_mount(self) -> None:
        """Initialize the application"""
        # Set up refresh timer
        self.refresh_timer = self.set_interval(
            self.refresh_interval, 
            self.refresh_connections
        )
        
        # Initial data load
        await self.refresh_connections()
        
    async def refresh_connections(self) -> None:
        """Refresh connection data"""
        try:
            await self._process_connections()
            self._update_display()
        except Exception as e:
            self.notify(f"Error refreshing connections: {str(e)}", severity="error")
            
    async def _process_connections(self) -> None:
        """Process connections and update tracking dictionaries"""
        now = time.time()
        
        # Get current connections
        current = self.collector.get_connections()
        
        # Find new and closed connections
        current_keys = set(current.keys())
        active_keys = set(self.active_connections.keys())
        
        new_keys = current_keys - active_keys
        closed_keys = active_keys - current_keys
        
        # Process new connections
        for key in new_keys:
            conn = current[key]
            conn.timestamp = now
            self.new_connections[key] = now
            self.logger.log_new_connection(conn)
            
        # Process closed connections
        for key in closed_keys:
            conn = self.active_connections[key]
            self.closed_connections[key] = (conn, now)
            self.logger.log_closed_connection(conn)
            
        # Update active connections
        self.active_connections = current
        
        # Update security information
        alerts = self.security_monitor.check_connections(self.active_connections)
        if alerts:
            self.security_monitor.log_alerts(alerts)
            for alert in alerts:
                if alert['level'] == 'critical':
                    self.notify(f"SECURITY ALERT: {alert['message']}", severity="error")
                    
        # Update traffic information if enabled
        if self.traffic_monitor:
            self.traffic_monitor.update(self.active_connections)
            self.traffic_monitor.update_history(self.active_connections)
            
        # Update DNS resolutions
        self.dns_resolver.update_cache()
        
    def _update_display(self) -> None:
        """Update the display with current connection data"""
        if not self.connection_table:
            return
            
        now = time.time()
        
        # Apply filters
        filtered_active = self._apply_filters(self.active_connections)
        filtered_new = {k: v for k, v in self.new_connections.items() if k in filtered_active}
        filtered_closed = {k: v for k, v in self.closed_connections.items() 
                          if self._connection_matches_filters(v[0])}
        
        # Create rows for the table
        all_rows = []
        
        # Add new connections
        delay_new = self.config.get('delay_new', 10)
        for key, ts in filtered_new.items():
            if key in filtered_active and now - ts <= delay_new:
                conn = filtered_active[key]
                row = ConnectionRow(key, conn, 'new', ts)
                all_rows.append(row)
                
        # Add active connections that are not new
        for key, conn in filtered_active.items():
            if key not in filtered_new:
                row = ConnectionRow(key, conn, 'connected', conn.timestamp)
                all_rows.append(row)
                
        # Add closed connections
        delay_closed = self.config.get('delay_closed', 10)
        for key, (conn, ts) in filtered_closed.items():
            if now - ts <= delay_closed:
                row = ConnectionRow(key, conn, 'closed', ts)
                all_rows.append(row)
                
        # Sort by timestamp (newest first)
        all_rows.sort(key=lambda x: x.timestamp, reverse=True)
        
        # Update table
        self.connection_table.update_connections(all_rows)
        
        # Update status panel
        filter_info = self._get_filter_summary()
        self.status_panel.update_status(
            len(filtered_active), 
            len(filtered_new), 
            len(filtered_closed), 
            filter_info
        )
        
    def _apply_filters(self, connections: dict) -> dict:
        """Apply filters to connections"""
        # Implementation would depend on your filter logic
        # For now, return all connections
        return connections
        
    def _connection_matches_filters(self, conn: EnhancedConnection) -> bool:
        """Check if connection matches active filters"""
        # Implementation would depend on your filter logic
        return True
        
    def _get_filter_summary(self) -> str:
        """Get a summary of active filters"""
        # Implementation would depend on your filter logic
        return "None"
        
    # Action handlers
    async def action_quit(self) -> None:
        """Quit the application"""
        self.dns_resolver.shutdown()
        self.exit()
        
    async def action_refresh(self) -> None:
        """Manually refresh connections"""
        await self.refresh_connections()
        self.notify("Connections refreshed")
        
    async def action_filter(self) -> None:
        """Show filter dialog"""
        self.notify("Filter dialog not implemented yet")
        
    async def action_export(self) -> None:
        """Export connections"""
        if self.config.get('export_format') and self.config.get('export_file'):
            export_connections(
                self.active_connections, 
                self.config['export_file'], 
                self.config['export_format']
            )
            self.notify(f"Exported to {self.config['export_file']}")
        else:
            self.notify("Export format and file not configured")
            
    async def action_security(self) -> None:
        """Show security information"""
        if self.security_monitor:
            recent_alerts = self.security_monitor.get_recent_alerts()
            alert_count = len(recent_alerts)
            self.notify(f"Security: {alert_count} recent alerts")
        else:
            self.notify("Security monitoring not enabled")
            
    async def action_help(self) -> None:
        """Show help dialog"""
        help_text = """
WTFCalls Interactive Help:

Navigation:
  ↑/↓         Navigate rows
  PgUp/PgDn   Page up/down
  Home/End    First/last row

Actions:
  r           Refresh connections
  f           Filter connections  
  e           Export data
  s           Security status
  q           Quit application

Status Colors:
  🆕 Green    New connections
  🔗 Normal   Active connections  
  ❌ Gray     Closed connections
  🔴 Red      Suspicious/malicious
        """
        self.notify(help_text)
        
    async def action_clear_selection(self) -> None:
        """Clear current selection"""
        if self.connection_table:
            self.connection_table.cursor_row = -1


class InteractiveConnectionMonitor:
    """Main class for the interactive connection monitor"""
    
    def __init__(self, args):
        self.config = vars(args)
        self.app = None
        
    def run(self):
        """Run the interactive monitor"""
        try:
            self.app = WTFCallsInteractiveApp(self.config)
            self.app.run()
        except KeyboardInterrupt:
            print("\nTerminated by user (CTRL+C).")
        except Exception as e:
            print(f"Critical error: {str(e)}")
            raise
        finally:
            if self.app and hasattr(self.app, 'dns_resolver'):
                self.app.dns_resolver.shutdown()


def main_interactive():
    """Entry point for interactive mode"""
    # Import the existing argument parser
    from wtfcalls import parse_arguments
    
    args = parse_arguments()
    
    # Add interactive mode flag
    args.interactive = True
    
    monitor = InteractiveConnectionMonitor(args)
    monitor.run()


if __name__ == '__main__':
    main_interactive()