#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wtfcalls_minimal_interactive.py – Minimal working interactive version
Ultra-simple implementation that definitely works
"""
import time
import asyncio
from typing import Dict, List, Tuple, Any, Optional

try:
    from textual.app import App, ComposeResult
    from textual.containers import Vertical
    from textual.widgets import Header, Footer, DataTable, Static
    from textual.binding import Binding
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False
    print("Textual not available - install with: pip install textual")
    exit(1)

# Internal modules
from connection import EnhancedConnection
from collector import EnhancedConnectionCollector
from dns_resolver import DNSResolver
from logger import ConnectionLogger
from traffic import TrafficMonitor
from security import SecurityMonitor


class MinimalConnectionTable(DataTable):
    """Ultra-minimal DataTable implementation"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.show_header = True
        self.setup_done = False
        
    def setup_table(self):
        """Setup table columns once"""
        if self.setup_done:
            return
            
        self.add_column("PID", width=8)
        self.add_column("Program", width=25)
        self.add_column("Local", width=22)
        self.add_column("Remote", width=22) 
        self.add_column("Dir", width=5)
        self.add_column("Status", width=10)
        self.setup_done = True
        
    def update_connections(self, connections_data: List[Tuple]):
        """Update table with simple data"""
        # Setup columns if needed
        self.setup_table()
        
        # Clear existing data
        self.clear()
        
        # Add rows
        for row_data in connections_data:
            self.add_row(*row_data)


class StatusDisplay(Static):
    """Simple status display"""
    
    def __init__(self, **kwargs):
        super().__init__("Loading...", **kwargs)
        
    def update_status(self, active: int, new: int, closed: int):
        """Update status text"""
        text = f"Active: {active} | New: {new} | Closed: {closed} | Press 'q' to quit, '↑/↓' to navigate"
        self.update(text)


class MinimalWTFCallsApp(App):
    """Minimal TUI app"""
    
    CSS = """
    MinimalConnectionTable {
        height: 1fr;
        border: solid green;
    }
    
    StatusDisplay {
        height: 1;
        background: blue;
        color: white;
        padding: 0 1;
    }
    """
    
    TITLE = "WTFCalls - Minimal Interactive"
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("escape", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
    ]
    
    def __init__(self, config: dict, **kwargs):
        super().__init__(**kwargs)
        self.config = config
        self.refresh_interval = config.get('poll_interval', 1.0)
        
        # Initialize monitoring components
        self.dns_resolver = DNSResolver(enable_resolution=not config.get('show_ip', False))
        self.logger = ConnectionLogger(enable=True)
        self.collector = EnhancedConnectionCollector(config)
        self.security_monitor = SecurityMonitor(config.get('config'), quiet=True)
        self.traffic_monitor = TrafficMonitor() if config.get('traffic') else None
        
        # Data tracking
        self.active_connections = {}
        self.new_connections = {}
        self.closed_connections = {}
        
        # UI components
        self.connection_table = None
        self.status_display = None
        
    def compose(self) -> ComposeResult:
        """Create UI layout"""
        yield Header()
        
        with Vertical():
            self.status_display = StatusDisplay()
            yield self.status_display
            
            self.connection_table = MinimalConnectionTable()
            yield self.connection_table
            
        yield Footer()
        
    async def on_mount(self) -> None:
        """Initialize app"""
        # Start refresh timer
        self.set_interval(self.refresh_interval, self.refresh_data)
        
        # Initial data load
        await self.refresh_data()
        
    async def refresh_data(self) -> None:
        """Refresh connection data"""
        try:
            await self.update_connections()
            self.update_display()
        except Exception as e:
            self.notify(f"Error: {str(e)}", severity="error")
            
    async def update_connections(self) -> None:
        """Update connection tracking"""
        now = time.time()
        current = self.collector.get_connections()
        
        # Find new and closed connections
        current_keys = set(current.keys())
        active_keys = set(self.active_connections.keys())
        
        new_keys = current_keys - active_keys
        closed_keys = active_keys - current_keys
        
        # Update tracking
        for key in new_keys:
            conn = current[key]
            self.new_connections[key] = now
            
        for key in closed_keys:
            conn = self.active_connections[key]
            self.closed_connections[key] = (conn, now)
            
        self.active_connections = current
        
        # Update security monitoring
        if self.security_monitor:
            alerts = self.security_monitor.check_connections(self.active_connections)
            if alerts:
                critical_alerts = [a for a in alerts if a['level'] == 'critical']
                if critical_alerts:
                    self.notify(f"SECURITY: {len(critical_alerts)} critical alerts!", severity="error")
                    
        # Update traffic monitoring
        if self.traffic_monitor:
            self.traffic_monitor.update(self.active_connections)
            
    def update_display(self) -> None:
        """Update the display with current data"""
        if not self.connection_table or not self.status_display:
            return
            
        now = time.time()
        delay_new = self.config.get('delay_new', 10)
        delay_closed = self.config.get('delay_closed', 10)
        
        # Prepare data for table
        table_data = []
        
        # Add new connections
        new_count = 0
        for key, ts in self.new_connections.items():
            if key in self.active_connections and now - ts <= delay_new:
                conn = self.active_connections[key]
                row = self.format_connection_row(conn, "NEW")
                table_data.append(row)
                new_count += 1
                
        # Add active connections (not new)
        for key, conn in self.active_connections.items():
            if key not in self.new_connections or now - self.new_connections[key] > delay_new:
                row = self.format_connection_row(conn, "ACTIVE")
                table_data.append(row)
                
        # Add closed connections
        closed_count = 0
        for key, (conn, ts) in self.closed_connections.items():
            if now - ts <= delay_closed:
                row = self.format_connection_row(conn, "CLOSED")
                table_data.append(row)
                closed_count += 1
                
        # Sort by status (new first, then active, then closed)
        def sort_key(row):
            status = row[5]  # Status column
            if status == "NEW":
                return 0
            elif status == "ACTIVE":
                return 1
            else:
                return 2
                
        table_data.sort(key=sort_key)
        
        # Update table
        self.connection_table.update_connections(table_data)
        
        # Update status
        self.status_display.update_status(
            len(self.active_connections),
            new_count,
            closed_count
        )
        
    def format_connection_row(self, conn: EnhancedConnection, status: str) -> Tuple[str, str, str, str, str, str]:
        """Format a connection as a table row"""
        # Basic info
        pid = str(conn.pid)
        program = conn.process_name[:23] + "..." if len(conn.process_name) > 23 else conn.process_name
        
        # Address formatting
        local = f"{conn.lip}:{conn.lp}"
        if len(local) > 20:
            local = local[:17] + "..."
            
        remote = f"{conn.rip}:{conn.rp}"
        if len(remote) > 20:
            remote = remote[:17] + "..."
            
        # Direction
        direction = "→" if conn.direction == "out" else "←"
        
        return (pid, program, local, remote, direction, status)
        
    async def action_quit(self) -> None:
        """Quit application"""
        self.dns_resolver.shutdown()
        self.exit()
        
    async def action_refresh(self) -> None:
        """Manual refresh"""
        await self.refresh_data()
        self.notify("Refreshed")


class MinimalInteractiveMonitor:
    """Minimal interactive monitor"""
    
    def __init__(self, args):
        self.config = vars(args)
        
    def run(self):
        """Run the minimal interactive monitor"""
        if not TEXTUAL_AVAILABLE:
            print("Error: textual package not available")
            print("Install with: pip install textual")
            return
            
        try:
            app = MinimalWTFCallsApp(self.config)
            app.run()
        except KeyboardInterrupt:
            print("\nTerminated by user")
        except Exception as e:
            print(f"Error: {str(e)}")
            import traceback
            traceback.print_exc()


def main_minimal():
    """Entry point for minimal interactive mode"""
    from wtfcalls import parse_arguments
    
    args = parse_arguments()
    monitor = MinimalInteractiveMonitor(args)
    monitor.run()


if __name__ == '__main__':
    main_minimal()
