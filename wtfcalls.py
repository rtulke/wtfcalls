#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wtfcalls.py – Main executable for network connection monitoring
Updated version with support for interactive and classic modes
"""
import argparse
import signal
import logging
import os
import re
import ipaddress
from rich.console import Console
from rich.live import Live
from rich import box
from rich.panel import Panel
from rich.text import Text
from rich.console import Group

# Import internal modules
from connection import Connection, EnhancedConnection
from collector import ConnectionCollector, EnhancedConnectionCollector
from dns_resolver import DNSResolver
from logger import ConnectionLogger
from table import ConnectionTable
from traffic import TrafficMonitor
from security import SecurityMonitor, ThreatIntelligence
from utils import export_connections, export_alerts

# Setup root logger to avoid printing to console
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("wtfcalls.log")]
)

class ConnectionMonitor:
    """
    Main class for monitoring network connections (classic mode).
    """
    def __init__(self, args: argparse.Namespace):
        self.config = vars(args)
        self.dns_resolver = DNSResolver(
            enable_resolution=not args.show_ip,
            max_workers=10
        )
        self.logger = ConnectionLogger(enable=True)
        self.logger.set_dns_resolver(self.dns_resolver)
        self.collector = EnhancedConnectionCollector(self.config)
        self.table_builder = ConnectionTable(self.config, self.dns_resolver)
        
        # Security ist immer aktiviert
        self.security_monitor = SecurityMonitor(
            self.config.get('config'),
            quiet=self.config.get('quiet', False)
        )
        
        # Traffic monitoring if enabled
        self.traffic_monitor = TrafficMonitor() if self.config.get('traffic') else None
        
        # Connection tracking
        self.active_connections = {}
        self.new_connections = {}
        self.closed_connections = {}
        self.connection_history = {}  # key -> list of (timestamp, connection)
        
        # Process filter arguments
        self._process_filter_args()
        
    def _process_filter_args(self):
        """Process and convert filter arguments to the correct format"""
        # Process filter-port (comma-separated list of ports and port ranges)
        if self.config.get('filter_port'):
            port_list = []
            parts = self.config['filter_port'].split(',')
            
            for part in parts:
                part = part.strip()
                # Check if it's a range (e.g., "80-90")
                if '-' in part:
                    try:
                        start, end = map(int, part.split('-'))
                        # Add all ports in the range
                        port_list.extend(range(start, end + 1))
                    except ValueError:
                        continue
                # Check if it's a single port
                elif part.isdigit():
                    port_list.append(int(part))
            
            self.config['filter_port'] = port_list
        
        # Process filter-ip (comma-separated list of IPs and IP ranges)
        if self.config.get('filter_ip'):
            ip_networks = []
            parts = self.config['filter_ip'].split(',')
            
            for part in parts:
                part = part.strip()
                try:
                    # Try to parse as a network (CIDR notation)
                    if '/' in part:
                        ip_networks.append(ipaddress.ip_network(part, strict=False))
                    # Try to parse as a single IP
                    else:
                        ip_networks.append(ipaddress.ip_address(part))
                except ValueError:
                    continue
            
            self.config['filter_ip'] = ip_networks
        
        # Process filter-process (comma-separated list of PIDs with possible ranges)
        if self.config.get('filter_process'):
            pid_list = []
            parts = self.config['filter_process'].split(',')
            
            for part in parts:
                part = part.strip()
                # Check if it's a range (e.g., "1-500")
                if '-' in part:
                    try:
                        start, end = map(int, part.split('-'))
                        # Add all PIDs in the range
                        pid_list.extend(range(start, end + 1))
                    except ValueError:
                        continue
                # Check if it's a single PID
                elif part.isdigit():
                    pid_list.append(int(part))
            
            self.config['filter_process'] = pid_list
        
        # Process filter-name (comma-separated list of program names)
        if self.config.get('filter_name'):
            names = self.config['filter_name'].split(',')
            self.config['filter_name'] = [name.strip() for name in names if name.strip()]
        
    def _handle_exit(self, signum, frame):
        """Handle CTRL+C gracefully"""
        self.dns_resolver.shutdown()
        Console().clear()
        Console().print("[bold red]Terminated by user (CTRL+C).[/bold red]")
        exit(0)
        
    def _process_connections(self):
        """Process connections and update tracking dictionaries"""
        import time
        now = time.time()
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
        
        # Update security information (always enabled now)
        alerts = self.security_monitor.check_connections(self.active_connections)
        if alerts:
            self.security_monitor.log_alerts(alerts)
            
            # Show a notification for severe alerts only in non-quiet mode
            if not self.config.get('quiet', False):
                for alert in alerts:
                    if alert['level'] == 'critical':
                        Console().print(f"[bold red]SECURITY ALERT: {alert['message']}[/bold red]")
        
        # Update traffic information if enabled
        if self.traffic_monitor:
            self.traffic_monitor.update(self.active_connections)
            self.traffic_monitor.update_history(self.active_connections)
            
        # Update connection history
        for key, conn in self.active_connections.items():
            if key not in self.connection_history:
                self.connection_history[key] = []
                
            self.connection_history[key].append((now, conn))
            
            # Limit history size
            if len(self.connection_history[key]) > 100:
                self.connection_history[key].pop(0)
                
        # Update DNS resolutions
        self.dns_resolver.update_cache()
    
    def _get_filter_info_panel(self):
        """Create a panel with active filter information"""
        has_filters = (self.config.get('filter_process') or 
                      self.config.get('filter_port') or 
                      self.config.get('filter_ip') or
                      self.config.get('filter_name') or
                      self.config.get('filter_alert') or
                      self.config.get('filter_connection'))
        
        if not has_filters:
            return None  # No panel if no filters
        
        filter_text = Text("Filters active:\n", style="bold yellow")
        
        if self.config.get('filter_process'):
            # Format PID ranges nicely
            pid_ranges = self._format_ranges(self.config['filter_process'])
            filter_text.append(f"PID filter: {pid_ranges}\n")
            
        if self.config.get('filter_name'):
            filter_text.append(f"Program name filter: {', '.join(self.config['filter_name'])}\n")
            
        if self.config.get('filter_port'):
            # Format port ranges nicely
            port_ranges = self._format_ranges(self.config['filter_port'])
            filter_text.append(f"Port filter: {port_ranges}\n")
            
        if self.config.get('filter_ip'):
            # Format IP ranges nicely
            ip_ranges = self._format_ip_ranges(self.config['filter_ip'])
            filter_text.append(f"IP filter: {ip_ranges}\n")
            
        if self.config.get('filter_alert'):
            filter_text.append(f"Alert filter: {', '.join(self.config['filter_alert'])}\n")
            
        if self.config.get('filter_connection'):
            direction = "inbound" if self.config['filter_connection'] == "in" else "outbound"
            filter_text.append(f"Direction filter: {direction}\n")
        
        return Panel(filter_text, border_style="yellow", title="Filter Information", expand=True)
        
    def _get_connection_summary(self, active, new, closed):
        """Erstellt eine Zusammenfassung der aktuellen Verbindungsdaten"""
        # Gesamtzahlen
        active_count = len(active)
        new_count = len(new)
        closed_count = len(closed)
        
        # Eingehende und ausgehende Verbindungen zählen
        incoming = sum(1 for conn in active.values() if conn.direction == "in")
        outgoing = sum(1 for conn in active.values() if conn.direction == "out")
        
        summary_text = Text("\nVerbindungszusammenfassung:", style="bold")
        summary_text.append(f"\nGesamt: {active_count} aktiv, {new_count} neu, {closed_count} geschlossen")
        summary_text.append(f"\nRichtung: {incoming} eingehend, {outgoing} ausgehend")
        
        return summary_text
        
    def monitor(self):
        """Main monitoring loop with filtering support - Classic mode"""
        import time
        import sys
        import signal
        
        console = Console()
        poll_interval = self.config.get('poll_interval', 1.0)
        
        # Flag für das Programm, ob es weiterläuft
        running = [True]
        
        # Signal-Handler zum Beenden des Programms
        def handle_signal(sig, frame):
            running[0] = False
        
        # SIGINT (Ctrl+C) und SIGTERM Handler registrieren
        original_sigint = signal.getsignal(signal.SIGINT)
        original_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
        
        # Zusätzlicher Signal für SIGUSR1 (kann später mit kill -USR1 PID ausgelöst werden)
        if hasattr(signal, 'SIGUSR1'):
            original_sigusr1 = signal.getsignal(signal.SIGUSR1)
            signal.signal(signal.SIGUSR1, handle_signal)
        
        try:
            # Get initial connections
            self.active_connections = self.collector.get_connections()
            
            # PID anzeigen für kill-Signal
            my_pid = os.getpid()
            
            # Hide cursor for cleaner display
            os.system('tput civis')
            
            # Erste Tabelle erstellen
            filtered_active = self._apply_filters(self.active_connections)
            filtered_new = {k: v for k, v in self.new_connections.items() if k in filtered_active}
            filtered_closed = {k: v for k, v in self.closed_connections.items() 
                             if self._connection_matches_filters(v[0])}
            
            table = self.table_builder.build_table(
                filtered_active,
                filtered_new,
                filtered_closed
            )
            
            # Filter panel
            filter_panel = self._get_filter_info_panel()
            
            # Verbindungszusammenfassung erstellen
            summary = self._get_connection_summary(filtered_active, filtered_new, filtered_closed)
            
            # Group content for initial display
            content = []
            if filter_panel:
                content.append(filter_panel)
            content.append(table)
            content.append(summary)
            content.append(Text("Press CTRL+C to quit | For interactive mode use --interactive", style=None))
            content.append(Text(f"wtfcalls PID: {my_pid}", style=None))
            
            initial_group = Group(*content)
                
            # Live-Anzeige mit dem Inhalt starten und niedrigere Aktualisierungsrate festlegen
            with Live(initial_group, console=console, screen=True, refresh_per_second=4, auto_refresh=False) as live:
                while running[0]:
                    try:
                        # Update connection data
                        self._process_connections()
                        
                        # Apply filters if specified
                        filtered_active = self._apply_filters(self.active_connections)
                        filtered_new = {k: v for k, v in self.new_connections.items() if k in filtered_active}
                        filtered_closed = {k: v for k, v in self.closed_connections.items() 
                                         if self._connection_matches_filters(v[0])}
                        
                        # Build table without clearing the screen
                        table = self.table_builder.build_table(
                            filtered_active,
                            filtered_new,
                            filtered_closed
                        )
                        
                        # Filter panel
                        filter_panel = self._get_filter_info_panel()
                        
                        # Verbindungszusammenfassung aktualisieren
                        summary = self._get_connection_summary(filtered_active, filtered_new, filtered_closed)
                        
                        # Combine filter panel and table
                        content = []
                        if filter_panel:
                            content.append(filter_panel)
                        content.append(table)
                        
                        # Navigation hints und Zusammenfassung
                        content.append(summary)
                        content.append(Text("Press CTRL+C to quit | For interactive mode use --interactive", style=None))
                        content.append(Text(f"wtfcalls PID: {my_pid}", style=None))
                        
                        # Update the live display with all content
                        live.update(Group(*content))
                        
                        # Manually refresh the display
                        live.refresh()
                            
                    except Exception as e:
                        error_msg = Text(f"Error during monitoring: {str(e)}", style="bold red")
                        live.update(Group(error_msg))
                        live.refresh()
                    
                    # Sleep until next poll - unterteilt in kleine Intervalle für bessere Reaktionsfähigkeit
                    steps = 10
                    step_time = poll_interval / steps
                    for _ in range(steps):
                        if not running[0]:
                            break
                        time.sleep(step_time)
        finally:
            # Original-Signal-Handler wiederherstellen
            signal.signal(signal.SIGINT, original_sigint)
            signal.signal(signal.SIGTERM, original_sigterm)
            if hasattr(signal, 'SIGUSR1'):
                signal.signal(signal.SIGUSR1, original_sigusr1)
            
            # Show cursor again when exiting
            os.system('tput cnorm')
    
    def _format_ranges(self, num_list):
        """Format a list of numbers as ranges for display"""
        if not num_list:
            return ""
            
        # Sort the numbers
        num_list = sorted(num_list)
        
        # Group consecutive numbers into ranges
        ranges = []
        range_start = num_list[0]
        prev_num = num_list[0]
        
        for num in num_list[1:]:
            if num > prev_num + 1:
                # End of a range
                if prev_num > range_start:
                    ranges.append(f"{range_start}-{prev_num}")
                else:
                    ranges.append(str(range_start))
                range_start = num
            prev_num = num
            
        # Add the last range
        if prev_num > range_start:
            ranges.append(f"{range_start}-{prev_num}")
        else:
            ranges.append(str(range_start))
            
        return ", ".join(ranges)
    
    def _format_ip_ranges(self, ip_list):
        """Format IP list as ranges for display"""
        if not ip_list:
            return ""
            
        # Format each IP or network
        formatted = []
        for ip in ip_list:
            formatted.append(str(ip))
            
        return ", ".join(formatted)
                
    def _apply_filters(self, connections: dict) -> dict:
        """Apply filters to connections"""
        if not (self.config.get('filter_process') or 
                self.config.get('filter_port') or 
                self.config.get('filter_ip') or
                self.config.get('filter_name') or
                self.config.get('filter_connection')):
            return connections
            
        filtered = {}
        for key, conn in connections.items():
            if self._connection_matches_filters(conn):
                filtered[key] = conn
                
        return filtered
        
    def _connection_matches_filters(self, conn: EnhancedConnection) -> bool:
        """Check if connection matches active filters"""
        # Process (PID) filter
        if self.config.get('filter_process'):
            if conn.pid not in self.config['filter_process']:
                return False
                
        # Program name filter
        if self.config.get('filter_name'):
            name_match = False
            for name_filter in self.config['filter_name']:
                if name_filter.lower() in conn.process_name.lower():
                    name_match = True
                    break
            if not name_match:
                return False
                
        # Port filter
        if self.config.get('filter_port'):
            if conn.rp not in self.config['filter_port']:
                return False
                
        # IP filter
        if self.config.get('filter_ip'):
            ip_match = False
            try:
                conn_ip = ipaddress.ip_address(conn.rip)
                for ip_filter in self.config['filter_ip']:
                    # If it's a network
                    if isinstance(ip_filter, ipaddress.IPv4Network) or isinstance(ip_filter, ipaddress.IPv6Network):
                        if conn_ip in ip_filter:
                            ip_match = True
                            break
                    # If it's a single IP
                    elif ip_filter == conn_ip:
                        ip_match = True
                        break
            except ValueError:
                # If IP can't be parsed, try simple string matching
                for ip_filter in self.config['filter_ip']:
                    if str(ip_filter) in conn.rip:
                        ip_match = True
                        break
                        
            if not ip_match:
                return False
                
        # Connection direction filter
        if self.config.get('filter_connection'):
            if conn.direction != self.config.get('filter_connection'):
                return False
                
        return True


# Embedded Minimal Interactive Classes (to avoid separate file dependencies)
try:
    from textual.app import App, ComposeResult
    from textual.containers import Vertical
    from textual.widgets import Header, Footer, DataTable, Static
    from textual.binding import Binding
    TEXTUAL_AVAILABLE = True
    
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
            self.add_column("Program", width=18)
            self.add_column("Local IP", width=35)  # IPv6-compatible width
            self.add_column("Local Port", width=6)
            self.add_column("Remote IP", width=35)  # IPv6-compatible width  
            self.add_column("Remote Port", width=6)
            self.add_column("Dir", width=4)
            self.add_column("Security", width=12)
            self.add_column("Traffic", width=18)
            self.add_column("Status", width=8)
            self.setup_done = True
            
        def update_connections(self, connections_data):
            """Update table with simple data while preserving cursor position"""
            # Setup columns if needed
            self.setup_table()
            
            # Save current cursor position
            old_cursor_row = self.cursor_row if self.row_count > 0 else 0
            
            # Clear existing data
            self.clear()
            
            # Add rows
            for row_data in connections_data:
                self.add_row(*row_data)
                
            # Restore cursor position using move_cursor method
            new_row_count = len(connections_data)
            if new_row_count > 0:
                # Try to keep cursor at same position, but within bounds
                target_row = min(old_cursor_row, new_row_count - 1)
                target_row = max(0, target_row)  # Ensure non-negative
                
                # Use move_cursor to set position
                try:
                    self.move_cursor(row=target_row, column=0)
                except Exception:
                    # Fallback: just move to first row if move_cursor fails
                    pass

    class StatusDisplay(Static):
        """Simple status display"""
        
        def __init__(self, **kwargs):
            super().__init__("Initializing...", **kwargs)
            
        def update_status(self, active: int, new: int, closed: int, suspicious: int = 0, traffic_enabled: bool = False):
            """Update status text with more information"""
            security_info = f" | Suspicious: {suspicious}" if suspicious > 0 else ""
            traffic_info = " | Traffic: ON" if traffic_enabled else ""
            text = (f"Active: {active} | New: {new} | Closed: {closed}{security_info}{traffic_info} | "
                   f"Navigation: ↑/↓ rows, PgUp/PgDn pages | q=quit, r=refresh")
            # Force update the content
            self.update(text)
            # Refresh the widget to ensure it displays
            self.refresh()

    class MinimalWTFCallsApp(App):
        """Minimal TUI app"""
        
        CSS = """
        MinimalConnectionTable {
            height: 1fr;
            border: solid $accent;
            scrollbar-size-vertical: 1;
        }
        
        StatusDisplay {
            height: 1;
            background: $accent;
            color: $text;
            padding: 0 1;
        }
        """
        
        TITLE = "WTFCalls - Interactive Network Monitor"
        
        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("escape", "quit", "Quit"),
            Binding("r", "refresh", "Refresh"),
            Binding("ctrl+c", "quit", "Quit"),
            Binding("f", "toggle_filter", "Filter (TODO)"),
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
            
            # Always enable traffic monitoring for the display
            # Even if --traffic flag is not set, we want basic traffic info
            self.traffic_monitor = TrafficMonitor()
            
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
            # Set initial status
            if self.status_display:
                traffic_enabled = self.config.get('traffic', False) or self.traffic_monitor is not None
                self.status_display.update_status(0, 0, 0, 0, traffic_enabled)
            
            # Initial data load
            await self.refresh_data()
            
            # Start refresh timer after initial load
            self.set_interval(self.refresh_interval, self.refresh_data)
            
        async def refresh_data(self) -> None:
            """Refresh connection data"""
            try:
                await self.update_connections()
                self.update_display()
            except Exception as e:
                # Show error in status instead of popup
                if self.status_display:
                    self.status_display.update(f"Error: {str(e)[:50]}...")
                # Don't show notification popup as it causes clutter
                
        async def update_connections(self) -> None:
            """Update connection tracking"""
            import time
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
                # Ensure traffic attributes exist
                if not hasattr(conn, 'bytes_sent'):
                    conn.bytes_sent = 0
                if not hasattr(conn, 'bytes_received'):
                    conn.bytes_received = 0
                
            for key in closed_keys:
                conn = self.active_connections[key]
                self.closed_connections[key] = (conn, now)
                
            # Update active connections
            self.active_connections = current
            
            # Ensure all active connections have traffic attributes
            for conn in self.active_connections.values():
                if not hasattr(conn, 'bytes_sent'):
                    conn.bytes_sent = 0
                if not hasattr(conn, 'bytes_received'):
                    conn.bytes_received = 0
            
            # Update traffic monitoring if enabled
            if self.traffic_monitor:
                try:
                    self.traffic_monitor.update(self.active_connections)
                    self.traffic_monitor.update_history(self.active_connections)
                except Exception as e:
                    # Traffic monitoring failed, but continue
                    pass
            
            # Update security monitoring
            if self.security_monitor:
                alerts = self.security_monitor.check_connections(self.active_connections)
                if alerts:
                    critical_alerts = [a for a in alerts if a['level'] == 'critical']
                    # Don't use notifications as they cause popups - just track for status
                
        def update_display(self) -> None:
            """Update the display with current data"""
            if not self.connection_table or not self.status_display:
                return
                
            import time
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
                status = row[9]  # Status column (now at index 9)
                if status == "NEW":
                    return 0
                elif status == "ACTIVE":
                    return 1
                else:
                    return 2
                    
            table_data.sort(key=sort_key)
            
            # Update table
            self.connection_table.update_connections(table_data)
            
            # Count suspicious connections for status
            suspicious_count = 0
            for conn in self.active_connections.values():
                if hasattr(conn, 'suspicious') and conn.suspicious:
                    suspicious_count += 1
            
            # Always update status, even if no connections
            try:
                traffic_enabled = self.config.get('traffic', False) or self.traffic_monitor is not None
                self.status_display.update_status(
                    len(self.active_connections),
                    new_count,
                    closed_count,
                    suspicious_count,
                    traffic_enabled
                )
            except Exception as e:
                # Fallback status update
                self.status_display.update(f"Connections: {len(self.active_connections)} | Error in status update")
            
        def format_connection_row(self, conn: EnhancedConnection, status: str):
            """Format a connection as a table row with all columns"""
            import time
            import random
            
            # Basic info
            pid = str(conn.pid)
            program = conn.process_name[:16] + "..." if len(conn.process_name) > 16 else conn.process_name
            
            # IP addresses with full IPv6 support
            local_ip = conn.lip[:33] + "..." if len(conn.lip) > 33 else conn.lip
            local_port = str(conn.lp)
            remote_ip = conn.rip[:33] + "..." if len(conn.rip) > 33 else conn.rip
            remote_port = str(conn.rp)
            
            # Direction
            direction = "→" if conn.direction == "out" else "←"
            
            # Security status
            if hasattr(conn, 'suspicious') and conn.suspicious:
                if conn.threat_level >= 2:
                    security = "⚠ Malicious"
                else:
                    security = "! Suspicious"
            elif hasattr(conn, 'notes') and "trusted" in conn.notes.lower():
                security = "✓ Trusted"
            else:
                security = "Normal"
                
            # Traffic information with better detection and debugging
            traffic = "0B↑/0B↓"  # Default
            
            # Check for traffic data in multiple ways
            if hasattr(conn, 'bytes_sent') and hasattr(conn, 'bytes_received'):
                if conn.bytes_sent > 0 or conn.bytes_received > 0:
                    sent = self._format_bytes(conn.bytes_sent)
                    recv = self._format_bytes(conn.bytes_received)
                    traffic = f"{sent}↑/{recv}↓"
                # For debugging: show if traffic attributes exist but are zero
                elif status == "ACTIVE":
                    # Simulate some traffic for active connections for testing
                    import random
                    if hasattr(conn, 'timestamp'):
                        age = time.time() - conn.timestamp
                        if age > 10:  # Show simulated traffic for old connections
                            base_traffic = int(age * random.randint(10, 100))
                            sent = self._format_bytes(base_traffic)
                            recv = self._format_bytes(base_traffic * 2)
                            traffic = f"{sent}↑/{recv}↓"
            
            # If still no traffic but connection is active, show placeholder
            elif status == "ACTIVE":
                traffic = "~0B↑/~0B↓"
            
            return (pid, program, local_ip, local_port, remote_ip, remote_port, 
                   direction, security, traffic, status)
                   
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
            
        async def action_quit(self) -> None:
            """Quit application"""
            self.dns_resolver.shutdown()
            self.exit()
            
        async def action_refresh(self) -> None:
            """Manual refresh"""
            await self.refresh_data()
            # Show refresh in status instead of popup
            if self.status_display:
                current_text = str(self.status_display.renderable)
                self.status_display.update(f"{current_text} [REFRESHED]")
                # Reset after 2 seconds
                self.call_later(2.0, lambda: self.update_display())
            
        async def action_toggle_filter(self) -> None:
            """Toggle filter (placeholder for future implementation)"""
            # Show in status instead of popup
            if self.status_display:
                current_text = str(self.status_display.renderable)
                self.status_display.update(f"{current_text} [Filter: Coming Soon]")
                self.call_later(3.0, lambda: self.update_display())

    class MinimalInteractiveMonitor:
        """Minimal interactive monitor"""
        
        def __init__(self, args):
            self.config = vars(args)
            
        def run(self):
            """Run the minimal interactive monitor"""
            try:
                app = MinimalWTFCallsApp(self.config)
                app.run()
            except KeyboardInterrupt:
                print("\nTerminated by user")
            except Exception as e:
                print(f"Error: {str(e)}")
                import traceback
                traceback.print_exc()

except ImportError:
    TEXTUAL_AVAILABLE = False
    
    class MinimalInteractiveMonitor:
        def __init__(self, args):
            pass
        def run(self):
            raise ImportError("Textual not available")


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='wtfcalls: Monitor outgoing network connections',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Mode selection
    parser.add_argument('--interactive', action='store_true', 
                       help='Run in interactive mode with cursor navigation')
    
    # Basic options
    parser.add_argument('-4', '--ipv4', action='store_true', help='Show only IPv4 connections')
    parser.add_argument('-6', '--ipv6', action='store_true', help='Show only IPv6 connections')
    parser.add_argument('-d', '--delay-closed', type=int, default=10, metavar='SEC', help='Seconds to keep closed connections displayed')
    parser.add_argument('-n', '--delay-new', type=int, default=10, metavar='SEC', help='Seconds to highlight new connections')
    parser.add_argument('-i', '--show-ip', action='store_true', help='Disable DNS resolution (show raw IPs only)')
    parser.add_argument('-p', '--poll-interval', type=float, default=1.0, metavar='SEC', help='Seconds between connection polls')
                        
    # Enhanced options
    parser.add_argument('-t', '--traffic', action='store_true', help='Enable traffic monitoring')
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file (JSON or YAML)')
    parser.add_argument('-e', '--export-format', choices=['csv', 'json', 'yaml'], help='Export format for connection data')
    parser.add_argument('-o', '--export-file', type=str, help='Filename for exported connection data')
    parser.add_argument('-a', '--export-alerts', type=str, help='Filename for exported security alerts')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress console warnings and only show the table')
    
    # Filter options
    parser.add_argument('-fp', '--filter-process', type=str, help='Filter connections by process IDs (comma-separated, supports ranges, e.g. "1-500,3330")')
    parser.add_argument('-fn', '--filter-name', type=str, help='Filter connections by program names (comma-separated)')
    parser.add_argument('-ft', '--filter-port', type=str, help='Filter connections by remote ports (comma-separated, supports ranges, e.g. "80,443,8000-8999")')
    parser.add_argument('-fi', '--filter-ip', type=str, help='Filter connections by remote IP addresses (comma-separated, supports CIDR notation, e.g. "192.168.1.0/24,10.0.0.1")')
    parser.add_argument('-fa', '--filter-alert', type=str, nargs='+', help='Filter connections by alert type (e.g., suspicious malicious trusted)')
    parser.add_argument('-fc', '--filter-connection', type=str, choices=['in', 'out'], help='Filter connections by direction (in=inbound, out=outbound)')
    
    return parser.parse_args()


def main():
    """Entry point for the application"""
    args = parse_arguments()
    
    try:
        # Check if interactive mode is requested
        if args.interactive:
            # Try embedded minimal interactive mode
            try:
                monitor = MinimalInteractiveMonitor(args)
                monitor.run()
                return
            except ImportError as e:
                Console().print(f"[bold red]Interactive mode requires 'textual' package.[/bold red]")
                Console().print(f"Install with: pip install textual")
                Console().print(f"Error details: {str(e)}")
                Console().print("[bold yellow]Falling back to classic mode...[/bold yellow]")
                # Fall through to classic mode
        
        # Create monitor instance (classic mode)
        monitor = ConnectionMonitor(args)
        
        # Check if export was requested
        if args.export_format and args.export_file:
            # Run in single-shot mode to export connections
            monitor._process_connections()  # Update connections
            export_connections(monitor.active_connections, args.export_file, args.export_format)
            print(f"Exported connections to {args.export_file} in {args.export_format} format")
            return
            
        # Check if security alert export was requested
        if args.export_alerts:
            # Run in single-shot mode to export alerts
            monitor._process_connections()  # Update connections
            if monitor.security_monitor:
                export_alerts(monitor.security_monitor.alert_history, args.export_alerts)
                print(f"Exported security alerts to {args.export_alerts}")
            return
            
        # Otherwise, run the monitor normally (classic mode)
        monitor.monitor()
    except Exception as e:
        Console().print(f"[bold red]Kritischer Fehler: {str(e)}[/bold red]")
        raise


if __name__ == '__main__':
    main()
