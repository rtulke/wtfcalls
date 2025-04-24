#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wtfcalls.py – Main executable for network connection monitoring
"""
import argparse
import signal
import logging
from rich.console import Console
from rich.live import Live

# Import internal modules
from connection import Connection, EnhancedConnection
from collector import ConnectionCollector, EnhancedConnectionCollector
from dns_resolver import DNSResolver
from logger import ConnectionLogger
from table import ConnectionTable
from traffic import TrafficMonitor
from security import SecurityMonitor, ThreatIntelligence
from utils import export_connections, export_alerts

class ConnectionMonitor:
    """
    Main class for monitoring network connections.
    """
    def __init__(self, args: argparse.Namespace):
        self.config = vars(args)
        self.dns_resolver = DNSResolver(
            enable_resolution=not args.no_resolve,
            max_workers=10
        )
        self.logger = ConnectionLogger(enable=True)
        self.logger.set_dns_resolver(self.dns_resolver)
        self.collector = ConnectionCollector(self.config)
        self.table_builder = ConnectionTable(self.config, self.dns_resolver)
        
        self.active_connections = {}
        self.new_connections = {}
        self.closed_connections = {}
        
        # Set up signal handler for graceful exit
        signal.signal(signal.SIGINT, self._handle_exit)
        
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
        
        # Update DNS resolutions
        self.dns_resolver.update_cache()
        
    def monitor(self):
        """Main monitoring loop"""
        import time
        console = Console()
        poll_interval = self.config.get('poll_interval', 1.0)
        
        # Get initial connections
        self.active_connections = self.collector.get_connections()
        
        with Live(console=console, refresh_per_second=4) as live:
            while True:
                try:
                    # Update connection data
                    self._process_connections()
                    
                    # Build and update table
                    table = self.table_builder.build_table(
                        self.active_connections,
                        self.new_connections,
                        self.closed_connections
                    )
                    live.update(table)
                except Exception as e:
                    console.print(f"[bold red]Error during monitoring: {str(e)}[/bold red]")
                
                # Sleep until next poll
                time.sleep(poll_interval)


class EnhancedConnectionMonitor(ConnectionMonitor):
    """
    Enhanced version of ConnectionMonitor with additional features
    """
    def __init__(self, args: argparse.Namespace):
        super().__init__(args)
        
        # Replace collector with enhanced version
        self.collector = EnhancedConnectionCollector(self.config)
        
        # Add traffic monitoring if enabled
        self.traffic_monitor = TrafficMonitor() if self.config.get('traffic') else None
        
        # Add security monitoring if enabled
        self.security_monitor = SecurityMonitor(self.config.get('security_config')) if self.config.get('security') else None
        
        # Connection history tracking
        self.connection_history = {}  # key -> list of (timestamp, connection)
        
    def _process_connections(self):
        """Process connections with enhanced features"""
        # First use parent class to process connections
        super()._process_connections()
        
        import time
        now = time.time()
        
        # Update traffic information if enabled
        if self.traffic_monitor:
            self.traffic_monitor.update(self.active_connections)
            self.traffic_monitor.update_history(self.active_connections)
            
        # Update security information if enabled
        if self.security_monitor:
            alerts = self.security_monitor.check_connections(self.active_connections)
            if alerts:
                self.security_monitor.log_alerts(alerts)
                
                # Show a notification for severe alerts
                for alert in alerts:
                    if alert['level'] == 'critical':
                        Console().print(f"[bold red]SECURITY ALERT: {alert['message']}[/bold red]")
        
        # Update connection history
        for key, conn in self.active_connections.items():
            if key not in self.connection_history:
                self.connection_history[key] = []
                
            self.connection_history[key].append((now, conn))
            
            # Limit history size
            if len(self.connection_history[key]) > 100:
                self.connection_history[key].pop(0)
                
    def monitor(self):
        """Main monitoring loop with filtering support"""
        import time
        console = Console()
        poll_interval = self.config.get('poll_interval', 1.0)
        
        # Get initial connections
        self.active_connections = self.collector.get_connections()
        
        # Apply filters if specified
        if self.config.get('filter_process') or self.config.get('filter_port') or self.config.get('filter_ip'):
            console.print("[bold yellow]Filters active:[/bold yellow]")
            if self.config.get('filter_process'):
                console.print(f"Process filter: {self.config['filter_process']}")
            if self.config.get('filter_port'):
                console.print(f"Port filter: {self.config['filter_port']}")
            if self.config.get('filter_ip'):
                console.print(f"IP filter: {self.config['filter_ip']}")
                
        with Live(console=console, refresh_per_second=4) as live:
            while True:
                try:
                    # Update connection data
                    self._process_connections()
                    
                    # Apply filters if specified
                    filtered_active = self._apply_filters(self.active_connections)
                    filtered_new = {k: v for k, v in self.new_connections.items() if k in filtered_active}
                    filtered_closed = {k: v for k, v in self.closed_connections.items() 
                                     if self._connection_matches_filters(v[0])}
                    
                    # Build and update table
                    table = self.table_builder.build_table(
                        filtered_active,
                        filtered_new,
                        filtered_closed
                    )
                    live.update(table)
                except Exception as e:
                    console.print(f"[bold red]Error during monitoring: {str(e)}[/bold red]")
                
                # Sleep until next poll
                time.sleep(poll_interval)
                
    def _apply_filters(self, connections: dict) -> dict:
        """Apply filters to connections"""
        if not (self.config.get('filter_process') or 
                self.config.get('filter_port') or 
                self.config.get('filter_ip')):
            return connections
            
        filtered = {}
        for key, conn in connections.items():
            if self._connection_matches_filters(conn):
                filtered[key] = conn
                
        return filtered
        
    def _connection_matches_filters(self, conn: EnhancedConnection) -> bool:
        """Check if connection matches active filters"""
        # Process filter
        if self.config.get('filter_process'):
            filter_text = self.config['filter_process'].lower()
            if filter_text not in conn.process_name.lower():
                return False
                
        # Port filter
        if self.config.get('filter_port'):
            filter_port = int(self.config['filter_port'])
            if conn.rp != filter_port:
                return False
                
        # IP filter
        if self.config.get('filter_ip'):
            filter_ip = self.config['filter_ip']
            if filter_ip not in conn.rip:
                return False
                
        return True


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='wtfcalls: Monitor outgoing network connections',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Basic options
    parser.add_argument('--ipv4', action='store_true', 
                        help='Show only IPv4 connections')
    parser.add_argument('--ipv6', action='store_true', 
                        help='Show only IPv6 connections')
    parser.add_argument('--delay-closed', type=int, default=10,
                        metavar='SEC',
                        help='Seconds to keep closed connections displayed (default: 10)')
    parser.add_argument('--delay-new', type=int, default=10,
                        metavar='SEC',
                        help='Seconds to highlight new connections (default: 10)')
    parser.add_argument('--no-resolve', action='store_true', 
                        help='Disable DNS resolution (show raw IPs only)')
    parser.add_argument('--split-port', action='store_true', 
                        help='Split IP and port into separate columns')
    parser.add_argument('--poll-interval', type=float, default=1.0,
                        metavar='SEC',
                        help='Seconds between connection polls (default: 1.0)')
    parser.add_argument('--full-path', action='store_true', 
                        help='Show full executable path for processes')
                        
    # Enhanced options
    parser.add_argument('--traffic', action='store_true',
                        help='Enable traffic monitoring')
    parser.add_argument('--security', action='store_true',
                        help='Enable security monitoring')
    parser.add_argument('--security-config', type=str,
                        help='Path to security configuration file (JSON or YAML)')
    parser.add_argument('--export-format', choices=['csv', 'json', 'yaml'], 
                        help='Export format for connection data')
    parser.add_argument('--export-file', type=str,
                        help='Filename for exported connection data')
    parser.add_argument('--export-alerts', type=str,
                        help='Filename for exported security alerts')
    
    # Filter options
    parser.add_argument('--filter-process', type=str,
                        help='Filter connections by process name (case-insensitive)')
    parser.add_argument('--filter-port', type=int,
                        help='Filter connections by remote port')
    parser.add_argument('--filter-ip', type=str,
                        help='Filter connections by remote IP address')
    
    return parser.parse_args()


def main():
    """Entry point for the application"""
    args = parse_arguments()
    
    try:
        # Use enhanced or basic monitor based on whether advanced features are requested
        if (args.traffic or args.security or args.filter_process or 
            args.filter_port or args.filter_ip or 
            args.export_format or args.export_alerts):
            monitor = EnhancedConnectionMonitor(args)
        else:
            monitor = ConnectionMonitor(args)
        
        # Check if export was requested
        if args.export_format and args.export_file:
            # Run in single-shot mode to export connections
            monitor._process_connections()  # Update connections
            export_connections(monitor.active_connections, args.export_file, args.export_format)
            print(f"Exported connections to {args.export_file} in {args.export_format} format")
            return
            
        # Check if security alert export was requested
        if args.security and args.export_alerts:
            # Run in single-shot mode to export alerts
            monitor._process_connections()  # Update connections
            if hasattr(monitor, 'security_monitor') and monitor.security_monitor:
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
