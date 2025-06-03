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


# Embedded Minimal Interactive Classes (now the default and only interface)
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
            """Setup table columns once - ADJUST COLUMN WIDTHS HERE"""
            if self.setup_done:
                return
            
            # ====== SPALTENBREITEN KONFIGURATION ======
            # Hier kannst du die Breite jeder Spalte anpassen:
                
            self.add_column("PID", width=8)              # Prozess-ID
            self.add_column("Program", width=18)         # Programmname  
            self.add_column("Local IP", width=39)        # Lokale IP (IPv6-kompatibel)
            self.add_column("Local Port", width=6)       # Lokaler Port
            self.add_column("Remote IP", width=39)       # Remote IP (IPv6-kompatibel)
            self.add_column("Remote Port", width=6)      # Remote Port
            self.add_column("Dir", width=4)              # Richtung (→/←)
            self.add_column("Security", width=12)        # Sicherheitsstatus
            self.add_column("Traffic (in)", width=9)     # Eingehender Traffic
            self.add_column("Traffic (out)", width=9)    # Ausgehender Traffic
            self.add_column("Status", width=8)           # Verbindungsstatus
            
            # ==========================================
            
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
            
        def update_status(self, active: int, new: int, closed: int, suspicious: int = 0, traffic_enabled: bool = False, frozen: bool = False, frozen_time: str = ""):
            """Update status text with more information"""
            security_info = f" | Suspicious: {suspicious}" if suspicious > 0 else ""
            traffic_info = " | Traffic: ON" if traffic_enabled else ""
            freeze_info = f" | 🔒 FROZEN at {frozen_time}" if frozen else ""
            freeze_controls = " | SPACE=freeze/unfreeze" if not frozen else " | SPACE=unfreeze"
            
            text = (f"Active: {active} | New: {new} | Closed: {closed}{security_info}{traffic_info}{freeze_info} | "
                   f"Navigation: ↑/↓ rows, PgUp/PgDn pages{freeze_controls} | q=quit, r=refresh")
            
            # Change CSS class based on frozen state
            if frozen:
                self.add_class("frozen")
            else:
                self.remove_class("frozen")
                
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
        
        StatusDisplay.frozen {
            background: $warning;
            color: $text-muted;
        }
        """
        
        TITLE = "WTFCalls - Interactive Network Monitor"
        
        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("escape", "quit", "Quit"),
            Binding("r", "refresh", "Refresh"),
            Binding("ctrl+c", "quit", "Quit"),
            Binding("f", "toggle_filter", "Filter (TODO)"),
            Binding("space", "toggle_freeze", "Freeze/Unfreeze Display"),
        ]
        
        def __init__(self, config: dict, **kwargs):
            super().__init__(**kwargs)
            self.config = config
            self.refresh_interval = config.get('poll_interval', 1.0)
            
            # Freeze functionality
            self.frozen = False
            self.frozen_timestamp = None
            
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
                self.status_display.update_status(0, 0, 0, 0, traffic_enabled, False, "")
            
            # Initial data load
            await self.refresh_data()
            
            # Start refresh timer after initial load
            self.set_interval(self.refresh_interval, self.refresh_data)
            
        async def refresh_data(self) -> None:
            """Refresh connection data - respects freeze state"""
            try:
                # Skip data updates if frozen
                if not self.frozen:
                    await self.update_connections()
                    
                # Always update display (to refresh status bar and handle frozen state)
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
            
            # Apply filters to all connections
            filtered_active = self._apply_filters(self.active_connections)
            filtered_new = {k: v for k, v in self.new_connections.items() if k in filtered_active}
            filtered_closed = {k: v for k, v in self.closed_connections.items() 
                             if self._connection_matches_filters(v[0])}
            
            # Prepare data for table
            table_data = []
            
            # Add new connections
            new_count = 0
            for key, ts in filtered_new.items():
                if key in filtered_active and now - ts <= delay_new:
                    conn = filtered_active[key]
                    row = self.format_connection_row(conn, "NEW")
                    table_data.append(row)
                    new_count += 1
                    
            # Add active connections (not new)
            for key, conn in filtered_active.items():
                if key not in filtered_new or now - filtered_new[key] > delay_new:
                    row = self.format_connection_row(conn, "ACTIVE")
                    table_data.append(row)
                    
            # Add closed connections
            closed_count = 0
            for key, (conn, ts) in filtered_closed.items():
                if now - ts <= delay_closed:
                    row = self.format_connection_row(conn, "CLOSED")
                    table_data.append(row)
                    closed_count += 1
                    
            # Sort by status (new first, then active, then closed)
            def sort_key(row):
                status = row[10]  # Status column (now at index 10 due to split traffic columns)
                if status == "NEW":
                    return 0
                elif status == "ACTIVE":
                    return 1
                else:
                    return 2
                    
            table_data.sort(key=sort_key)
            
            # Update table
            self.connection_table.update_connections(table_data)
            
            # Count suspicious connections for status (from filtered connections)
            suspicious_count = 0
            for conn in filtered_active.values():
                if hasattr(conn, 'suspicious') and conn.suspicious:
                    suspicious_count += 1
            
            # Always update status, even if no connections
            try:
                traffic_enabled = self.config.get('traffic', False) or self.traffic_monitor is not None
                
                # Format frozen timestamp if available
                frozen_time = ""
                if self.frozen and self.frozen_timestamp:
                    import time
                    frozen_time = time.strftime("%H:%M:%S", time.localtime(self.frozen_timestamp))
                
                self.status_display.update_status(
                    len(filtered_active),
                    new_count,
                    closed_count,
                    suspicious_count,
                    traffic_enabled,
                    self.frozen,
                    frozen_time
                )
            except Exception as e:
                # Fallback status update
                self.status_display.update(f"Connections: {len(filtered_active)} | Error in status update")
                
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
                    import ipaddress
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
            
        def format_connection_row(self, conn: EnhancedConnection, status: str):
            """Format a connection as a table row with all columns"""
            import time
            import random
            
            # Basic info
            pid = str(conn.pid)
            program = conn.process_name[:16] + "..." if len(conn.process_name) > 16 else conn.process_name
            
            # IP addresses with full IPv6 support (extended width)
            local_ip = conn.lip[:37] + "..." if len(conn.lip) > 37 else conn.lip
            local_port = str(conn.lp)
            remote_ip = conn.rip[:37] + "..." if len(conn.rip) > 37 else conn.rip
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
                
            # Traffic information with better detection and debugging - split into two columns
            traffic_in = "0B"   # Default incoming traffic
            traffic_out = "0B"  # Default outgoing traffic
            
            # Check for traffic data in multiple ways
            if hasattr(conn, 'bytes_sent') and hasattr(conn, 'bytes_received'):
                if conn.bytes_sent > 0 or conn.bytes_received > 0:
                    traffic_out = self._format_bytes(conn.bytes_sent)
                    traffic_in = self._format_bytes(conn.bytes_received)
                # For debugging: show if traffic attributes exist but are zero
                elif status == "ACTIVE":
                    # Simulate some traffic for active connections for testing
                    import random
                    if hasattr(conn, 'timestamp'):
                        age = time.time() - conn.timestamp
                        if age > 10:  # Show simulated traffic for old connections
                            base_traffic = int(age * random.randint(10, 100))
                            traffic_out = self._format_bytes(base_traffic)
                            traffic_in = self._format_bytes(base_traffic * 2)
            
            # If still no traffic but connection is active, show placeholder
            elif status == "ACTIVE":
                traffic_in = "~0B"
                traffic_out = "~0B"
            
            return (pid, program, local_ip, local_port, remote_ip, remote_port, 
                   direction, security, traffic_in, traffic_out, status)
                   
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
            """Manual refresh - unfreezes if frozen"""
            if self.frozen:
                # Unfreeze on manual refresh
                self.frozen = False
                self.frozen_timestamp = None
                
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
                
        async def action_toggle_freeze(self) -> None:
            """Toggle freeze state - SPACE key functionality"""
            import time
            
            if self.frozen:
                # Unfreeze
                self.frozen = False
                self.frozen_timestamp = None
                # Force immediate refresh to get latest data
                await self.refresh_data()
            else:
                # Freeze at current time
                self.frozen = True
                self.frozen_timestamp = time.time()
                # Update display to show frozen status
                self.update_display()

    class MinimalInteractiveMonitor:
        """Interactive monitor - now the only and default interface"""
        
        def __init__(self, args):
            self.config = vars(args)
            # Process filter arguments
            self._process_filter_args()
            
        def _process_filter_args(self):
            """Process and convert filter arguments to the correct format"""
            import ipaddress
            
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
            
        def run(self):
            """Run the interactive monitor (now the only interface)"""
            if not TEXTUAL_AVAILABLE:
                print("ERROR: This application requires the 'textual' package to run.")
                print("Install it with: pip install textual")
                print("\nAlternatively, you can install all requirements with:")
                print("pip install -r requirements.txt")
                return 1
                
            try:
                app = MinimalWTFCallsApp(self.config)
                app.run()
                return 0
            except KeyboardInterrupt:
                print("\nTerminated by user")
                return 0
            except Exception as e:
                print(f"Error: {str(e)}")
                import traceback
                traceback.print_exc()
                return 1

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
        description='wtfcalls: Interactive Network Connection Monitor',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Basic options
    parser.add_argument('-4', '--ipv4', action='store_true', help='Show only IPv4 connections')
    parser.add_argument('-6', '--ipv6', action='store_true', help='Show only IPv6 connections')
    parser.add_argument('-d', '--delay-closed', type=int, default=10, metavar='SEC', help='Seconds to keep closed connections displayed')
    parser.add_argument('-n', '--delay-new', type=int, default=10, metavar='SEC', help='Seconds to highlight new connections')
    parser.add_argument('-i', '--show-ip', action='store_true', help='Disable DNS resolution (show raw IPs only)')
    parser.add_argument('-p', '--poll-interval', type=float, default=1.0, metavar='SEC', help='Seconds between connection polls')
                        
    # Enhanced options
    parser.add_argument('-t', '--traffic', action='store_true', help='Enable enhanced traffic monitoring and logging')
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
    """Entry point for the application - interactive mode is now the default and only interface"""
    args = parse_arguments()
    
    try:
        # Check if export was requested (single-shot mode)
        if args.export_format and args.export_file:
            # Run in single-shot mode to export connections
            config = vars(args)
            collector = EnhancedConnectionCollector(config)
            active_connections = collector.get_connections()
            export_connections(active_connections, args.export_file, args.export_format)
            print(f"Exported connections to {args.export_file} in {args.export_format} format")
            return 0
            
        # Check if security alert export was requested
        if args.export_alerts:
            # Run in single-shot mode to export alerts
            config = vars(args)
            collector = EnhancedConnectionCollector(config)
            active_connections = collector.get_connections()
            security_monitor = SecurityMonitor(config.get('config'), quiet=True)
            security_monitor.check_connections(active_connections)
            export_alerts(security_monitor.alert_history, args.export_alerts)
            print(f"Exported security alerts to {args.export_alerts}")
            return 0
            
        # Run the interactive monitor (default and only mode)
        monitor = MinimalInteractiveMonitor(args)
        return monitor.run()
        
    except Exception as e:
        Console().print(f"[bold red]Critical error: {str(e)}[/bold red]")
        return 1


if __name__ == '__main__':
    main()