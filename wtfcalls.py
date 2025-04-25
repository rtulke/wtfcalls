#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wtfcalls.py – Main executable for network connection monitoring
Updated version with filter information displayed above the table
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
    Main class for monitoring network connections.
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
        """Main monitoring loop with filtering support - Flimmerfreie Version"""
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
            content.append(Text("Press CTRL+C to quit", style=None))
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
                        content.append(Text("Press CTRL+C to quit", style=None))
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


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='wtfcalls: Monitor outgoing network connections',
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
        # Create monitor instance
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
            
        # Otherwise, run the monitor normally
        monitor.monitor()
    except Exception as e:
        Console().print(f"[bold red]Kritischer Fehler: {str(e)}[/bold red]")
        raise


if __name__ == '__main__':
    main()
