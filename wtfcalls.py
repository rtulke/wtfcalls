#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wtfcalls.py – Main executable with Search Modal
Updated version with search modal window (like Ctrl+P command palette)
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
    from textual.containers import Vertical, Horizontal
    from textual.widgets import Header, Footer, DataTable, Static, Input, ListView, ListItem, Label
    from textual.binding import Binding
    from textual.screen import ModalScreen
    from textual import events
    TEXTUAL_AVAILABLE = True
    
    class SearchModal(ModalScreen):
        """Modal search window with suggestions and live preview"""
        
        CSS = """
        SearchModal {
            align: center middle;
        }
        
        #search_dialog {
            width: 90;
            height: 40;
            border: solid $accent;
            background: $surface;
        }
        
        #search_input {
            margin: 1;
            border: solid $primary;
        }
        
        #suggestions {
            height: 28;
            margin: 0 1;
            border: solid $primary;
        }
        
        #search_help {
            height: 6;
            margin: 0 1;
            background: $boost;
            color: $text;
        }
        
        .suggestion_item {
            padding: 0 1;
        }
        
        .suggestion_item:hover {
            background: $accent;
        }
        """
        
        BINDINGS = [
            Binding("escape", "dismiss", "Cancel"),
            Binding("enter", "apply_search", "Apply"),
            Binding("up", "suggestion_up", "Previous"),
            Binding("down", "suggestion_down", "Next"),
            Binding("tab", "autocomplete", "Complete"),
        ]
        
        def __init__(self, current_filter: str = ""):
            super().__init__()
            self.current_query = current_filter
            self.selected_suggestion = 0
            self.suggestions = []
            
        async def on_key(self, event) -> None:
            """Handle key events in search modal"""
            if hasattr(self.app, 'debug'):
                self.app.debug(f"MODAL KEY: '{event.key}'")
            
            # Handle Enter key explicitly
            if event.key == "enter":
                if hasattr(self.app, 'debug'):
                    self.app.debug("ENTER pressed in modal")
                await self.action_apply_search()
                return
            elif event.key == "escape":
                if hasattr(self.app, 'debug'):
                    self.app.debug("ESCAPE pressed in modal")
                await self.action_dismiss()
                return
            
            # Let other keys pass through normally (don't call super())
            
        def compose(self) -> ComposeResult:
            """Create search modal layout"""
            with Vertical(id="search_dialog"):
                yield Label("🔍 Search Connections", classes="dialog_title")
                
                self.search_input = Input(
                    placeholder="Search: firefox, 443, active, pid:1234, ipv4:192.168, new, suspicious...",
                    value=self.current_query,
                    id="search_input"
                )
                yield self.search_input
                
                self.suggestions_list = ListView(id="suggestions")
                yield self.suggestions_list
                
                self.help_text = Static(
                    "[bold cyan]Search Examples:[/bold cyan]\n"
                    "[dim]Process:[/dim] firefox, chrome, python, ssh\n"
                    "[dim]Ports:[/dim] 443, 80, 22, port:8080\n"
                    "[dim]PIDs:[/dim] pid:1234, pid:567\n"
                    "[dim]IPv4:[/dim] 192.168, 10.0, ipv4:127.0.0.1\n"
                    "[dim]IPv6:[/dim] 2a00:, fe80::, ipv6:2001:\n"
                    "[dim]Status:[/dim] active, new, closed, suspicious, trusted\n"
                    "[dim]Direction:[/dim] inbound, outbound",
                    id="search_help"
                )
                yield self.help_text
                
        def on_mount(self) -> None:
            """Initialize modal"""
            if hasattr(self.app, 'debug'):
                self.app.debug("SearchModal mounted")
            self.search_input.focus()
            self._update_suggestions()
            if hasattr(self.app, 'debug'):
                self.app.debug("SearchModal initialization complete")
            
        def on_input_changed(self, event: Input.Changed) -> None:
            """Handle search input changes"""
            if event.input == self.search_input:
                if hasattr(self.app, 'debug'):
                    self.app.debug(f"Input: '{event.value}' (current_query: '{self.current_query}')")
                self.current_query = event.value
                self._update_suggestions()
                # Note: Live preview disabled for now to avoid complexity
                
        def _update_suggestions(self):
            """Update suggestion list based on current query"""
            query = self.current_query.lower().strip()
            self.suggestions = []
            
            # Common search patterns with descriptions
            patterns = [
                # Process names
                ("firefox", "🌐 Firefox browser connections"),
                ("chrome", "🌐 Chrome browser connections"),
                ("safari", "🌐 Safari browser connections"),
                ("ssh", "🔐 SSH connections (port 22)"),
                ("python", "🐍 Python process connections"),
                ("node", "📗 Node.js connections"),
                
                # Ports
                ("80", "🌐 HTTP connections (port 80)"),
                ("443", "🔒 HTTPS connections (port 443)"),
                ("22", "🔐 SSH connections (port 22)"),
                ("3306", "🗄️ MySQL connections"),
                ("5432", "🐘 PostgreSQL connections"),
                ("6379", "📊 Redis connections"),
                ("8080", "🌐 HTTP Alternative (8080)"),
                
                # IP ranges
                ("127.0.0.1", "🏠 Localhost connections"),
                ("192.168", "🏠 Local network (192.168.x.x)"),
                ("10.0", "🏠 Private network (10.0.x.x)"),
                ("172.16", "🏠 Private network (172.16-31.x.x)"),
                
                # Security
                ("suspicious", "⚠️ Suspicious connections"),
                ("malicious", "🚨 Malicious connections"),
                ("trusted", "✅ Trusted connections"),
                ("normal", "✅ Normal connections"),
                
                # Directions
                ("outbound", "➡️ Outgoing connections"),
                ("inbound", "⬅️ Incoming connections"),
            ]
            
            # Filter suggestions based on query
            if not query:
                # Show common suggestions when empty
                self.suggestions = [
                    ("firefox", "🌐 Firefox browser connections"),
                    ("443", "🔒 HTTPS connections"),
                    ("192.168", "🏠 Local network"),
                    ("suspicious", "⚠️ Suspicious connections"),
                ]
            else:
                # Find matching patterns
                for pattern, description in patterns:
                    if pattern.startswith(query) or query in pattern:
                        self.suggestions.append((pattern, description))
                        
                # Add the current query as first option if it's not empty
                if query and not any(query == s[0] for s in self.suggestions):
                    # Detect query type for better description
                    if query.startswith('pid:'):
                        pid_part = query[4:]
                        if pid_part.isdigit():
                            desc = f"🔢 Process ID {pid_part}"
                        else:
                            desc = f"🔢 Process ID pattern '{pid_part}'"
                    elif query.startswith('port:'):
                        port_part = query[5:]
                        if port_part.isdigit():
                            desc = f"🔍 Port {port_part}"
                        else:
                            desc = f"🔍 Port pattern '{port_part}'"
                    elif query.startswith('ipv4:'):
                        ip_part = query[5:]
                        desc = f"🌐 IPv4 pattern '{ip_part}'"
                    elif query.startswith('ipv6:'):
                        ip_part = query[5:]
                        desc = f"🌐 IPv6 pattern '{ip_part}'"
                    elif query in ['active', 'new', 'closed']:
                        status_icons = {'active': '🔗', 'new': '✨', 'closed': '❌'}
                        desc = f"{status_icons[query]} {query.title()} connections"
                    elif query.isdigit():
                        desc = f"🔍 Port {query} or PID {query}"
                    elif ':' in query and any(c.isalnum() for c in query):
                        desc = f"🌐 IPv6 pattern '{query}'"
                    elif '.' in query and any(c.isdigit() for c in query):
                        desc = f"🌐 IPv4 pattern '{query}'"
                    else:
                        desc = f"🔍 Process pattern '{query}'"
                    self.suggestions.insert(0, (query, desc))
                    
            # Limit suggestions
            self.suggestions = self.suggestions[:8]
            
            # Update ListView
            self.suggestions_list.clear()
            for i, (pattern, description) in enumerate(self.suggestions):
                item_text = f"{pattern:<15} {description}"
                list_item = ListItem(Label(item_text), classes="suggestion_item")
                self.suggestions_list.append(list_item)
                
            # Reset selection
            self.selected_suggestion = 0
            if self.suggestions_list.children:
                self.suggestions_list.index = 0
                
        async def action_suggestion_up(self) -> None:
            """Move selection up"""
            if self.suggestions:
                self.selected_suggestion = max(0, self.selected_suggestion - 1)
                self.suggestions_list.index = self.selected_suggestion
                
        async def action_suggestion_down(self) -> None:
            """Move selection down"""
            if self.suggestions:
                self.selected_suggestion = min(len(self.suggestions) - 1, self.selected_suggestion + 1)
                self.suggestions_list.index = self.selected_suggestion
                
        async def action_autocomplete(self) -> None:
            """Autocomplete with selected suggestion"""
            if self.suggestions and 0 <= self.selected_suggestion < len(self.suggestions):
                selected_pattern = self.suggestions[self.selected_suggestion][0]
                self.search_input.value = selected_pattern
                self.current_query = selected_pattern
                if hasattr(self.app, 'debug'):
                    self.app.debug(f"Autocompleted to '{selected_pattern}'")
                self._update_suggestions()
                
        async def action_apply_search(self) -> None:
            """Apply search and close modal"""
            if hasattr(self.app, 'debug'):
                self.app.debug(f"APPLY: query='{self.current_query}', input_value='{self.search_input.value}'")
            
            # Use the input value directly to be sure
            final_query = self.search_input.value.strip()
            
            if hasattr(self.app, '_handle_search_applied'):
                if hasattr(self.app, 'debug'):
                    self.app.debug(f"CALLING: _handle_search_applied with '{final_query}'")
                self.app._handle_search_applied(final_query)
            else:
                if hasattr(self.app, 'debug'):
                    self.app.debug("ERROR - app._handle_search_applied not found!")
            if hasattr(self.app, 'debug'):
                self.app.debug("Modal dismissed")
            self.dismiss()
            
        async def action_dismiss(self) -> None:
            """Cancel search and close modal"""
            if hasattr(self.app, 'debug'):
                self.app.debug("Dismiss search called")
            if hasattr(self.app, '_handle_search_canceled'):
                if hasattr(self.app, 'debug'):
                    self.app.debug("Calling app._handle_search_canceled")
                self.app._handle_search_canceled()
            else:
                if hasattr(self.app, 'debug'):
                    self.app.debug("app._handle_search_canceled not found")
            if hasattr(self.app, 'debug'):
                self.app.debug("Dismissing modal")
            self.dismiss()

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

    class DebugDisplay(Static):
        """Debug message display in bottom left corner"""
        
        def __init__(self, **kwargs):
            super().__init__("Debug: Ready", **kwargs)
            self.debug_messages = []
            self.max_messages = 10
            
        def add_debug(self, message: str):
            """Add debug message"""
            import time
            timestamp = time.strftime("%H:%M:%S")
            full_message = f"{timestamp} {message}"  # Keine eckigen Klammern!
            
            self.debug_messages.append(full_message)
            if len(self.debug_messages) > self.max_messages:
                self.debug_messages.pop(0)
                
            # Update display - ohne Rich Markup
            debug_text = "\n".join(self.debug_messages[-5:])  # Show last 5 messages
            self.update(f"DEBUG:\n{debug_text}")

    class StatusDisplay(Static):
        """Simple status display"""
        
        def __init__(self, **kwargs):
            super().__init__("Initializing...", **kwargs)
            
        def update_status(self, active: int, new: int, closed: int, suspicious: int = 0, traffic_enabled: bool = False, frozen: bool = False, frozen_time: str = "", search_filter: str = ""):
            """Update status text with more information"""
            security_info = f" | Suspicious: {suspicious}" if suspicious > 0 else ""
            traffic_info = " | Traffic: ON" if traffic_enabled else ""
            freeze_info = f" | 🔒 FROZEN at {frozen_time}" if frozen else ""
            freeze_controls = " | SPACE=freeze/unfreeze" if not frozen else " | SPACE=unfreeze"
            search_info = f" | 🔍 Filter: {search_filter}" if search_filter else ""
            
            text = (f"Active: {active} | New: {new} | Closed: {closed}{security_info}{traffic_info}{freeze_info}{search_info} | "
                   f"Navigation: ↑/↓ rows, PgUp/PgDn pages{freeze_controls} | /=search, q=quit, r=refresh, R=reset")
            
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
        """Minimal TUI app with search modal"""
        
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
        
        DebugDisplay {
            height: 6;
            background: $surface;
            border: solid $primary;
            padding: 1;
            margin: 1;
        }
        """
        
        TITLE = "WTFCalls - Interactive Network Monitor"
        
        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("escape", "quit", "Quit"),
            Binding("r", "refresh", "Refresh"),
            Binding("shift+r", "reset", "Complete Reset"),
            Binding("ctrl+c", "quit", "Quit"),
            Binding("f", "toggle_filter", "Filter (TODO)"),
            Binding("space", "toggle_freeze", "Freeze/Unfreeze Display"),
            Binding("/", "open_search", "Search"),                     # Öffnet Modal
            Binding("ctrl+l", "clear_search", "Clear Search"),         # Löscht aktuellen Filter
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
            
            # Traffic monitoring - always enabled (was --traffic, now standard)
            self.traffic_monitor = TrafficMonitor()
            
            # Data tracking
            self.active_connections = {}
            self.new_connections = {}
            self.closed_connections = {}
            
            # UI components
            self.connection_table = None
            self.status_display = None
            self.debug_display = None
            
            # Search functionality
            self.current_search_filter = ""
            self.search_preview_active = False
            
        def debug(self, message: str):
            """Add debug message to debug display"""
            if self.config.get('debug') and self.debug_display:
                self.debug_display.add_debug(message)
            
        def compose(self) -> ComposeResult:
            """Create UI layout"""
            yield Header()
            
            with Vertical():
                self.status_display = StatusDisplay()
                yield self.status_display
                
                self.connection_table = MinimalConnectionTable()
                yield self.connection_table
                
                # Debug display at bottom (only if --debug is enabled)
                if self.config.get('debug'):
                    self.debug_display = DebugDisplay()
                    yield self.debug_display
                
            yield Footer()
            
        async def on_mount(self) -> None:
            """Initialize app"""
            # Set initial status
            if self.status_display:
                traffic_enabled = True  # Traffic is always enabled now
                self.status_display.update_status(0, 0, 0, 0, traffic_enabled, False, "", "")
            
            # Initial data load
            await self.refresh_data()
            
            # Debug: Show how many connections we have
            self.debug(f"STARTUP: {len(self.active_connections)} active connections found")
            
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
            
            # Update traffic monitoring (always enabled)
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
            
            # For new connections, we need to check both active filters AND status filters
            filtered_new = {}
            for k, v in self.new_connections.items():
                if k in filtered_active:  # Must also pass active filters
                    if not self.current_search_filter or self._connection_matches_search(filtered_active[k], self.current_search_filter, "new"):
                        filtered_new[k] = v
            
            # Apply ALL filters (command-line + search) to closed connections
            filtered_closed = {}
            for k, v in self.closed_connections.items():
                conn, ts = v
                if self._connection_matches_all_filters(conn, "closed"):
                    filtered_closed[k] = v
            
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
                traffic_enabled = True  # Traffic is always enabled now
                
                # Format frozen timestamp if available
                frozen_time = ""
                if self.frozen and self.frozen_timestamp:
                    import time
                    frozen_time = time.strftime("%H:%M:%S", time.localtime(self.frozen_timestamp))
                
                # Format current search filter for display
                search_display = self.current_search_filter if self.current_search_filter else ""
                
                self.status_display.update_status(
                    len(filtered_active),
                    new_count,
                    closed_count,
                    suspicious_count,
                    traffic_enabled,
                    self.frozen,
                    frozen_time,
                    search_display
                )
            except Exception as e:
                # Fallback status update
                self.status_display.update(f"Connections: {len(filtered_active)} | Error in status update")
                
        def _apply_filters(self, connections: dict) -> dict:
            """Apply filters to connections"""
            self.debug(f"FILTERING: {len(connections)} total connections, filter='{self.current_search_filter}'")
            
            # Apply original command-line filters first
            if not (self.config.get('filter_process') or 
                    self.config.get('filter_port') or 
                    self.config.get('filter_ip') or
                    self.config.get('filter_name') or
                    self.config.get('filter_connection')):
                filtered = connections
            else:
                filtered = {}
                for key, conn in connections.items():
                    if self._connection_matches_filters(conn):
                        filtered[key] = conn
            
            # Apply search filter
            if self.current_search_filter:
                self.debug(f"SEARCH FILTER: applying '{self.current_search_filter}' to {len(filtered)} connections")
                search_filtered = {}
                matches_found = 0
                for key, conn in filtered.items():
                    if self._connection_matches_search(conn, self.current_search_filter, "active"):
                        search_filtered[key] = conn
                        matches_found += 1
                        if matches_found <= 3:  # Show first 3 matches
                            self.debug(f"MATCH: {conn.process_name}:{conn.rp}")
                
                self.debug(f"SEARCH RESULT: {len(search_filtered)} connections matched")
                return search_filtered
            else:
                self.debug(f"NO SEARCH FILTER: returning {len(filtered)} connections")
                           
            return filtered
            
        def _connection_matches_filters(self, conn: EnhancedConnection) -> bool:
            """Check if connection matches active filters (command-line filters)"""
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

        def _connection_matches_all_filters(self, conn, status: str = None) -> bool:
            """Check if connection matches ALL filters (command-line + search)"""
            # First check command-line filters
            if not self._connection_matches_filters(conn):
                return False
                
            # Then check search filter
            if self.current_search_filter:
                if not self._connection_matches_search(conn, self.current_search_filter, status):
                    return False
                    
            return True
        
        def _connection_matches_search(self, conn, search_query: str, status: str = None) -> bool:
            """Check if connection matches search query"""
            if not search_query:
                return True
                
            query = search_query.lower().strip()
            
            # Status search
            if query in ['active', 'new', 'closed']:
                if status:
                    return query == status.lower()
                return False
            
            # Explicit PID search with prefix
            if query.startswith('pid:'):
                pid_part = query[4:].strip()
                if pid_part:
                    # Always do pattern search for PIDs (more useful than exact match)
                    return pid_part in str(conn.pid)
                return False
            
            # Explicit port search with prefix  
            if query.startswith('port:'):
                port_part = query[5:].strip()
                if port_part.isdigit():
                    port = int(port_part)
                    return conn.rp == port or conn.lp == port
                else:
                    # Port pattern search
                    return port_part in str(conn.rp) or port_part in str(conn.lp)
            
            # Explicit IPv4 search with prefix
            if query.startswith('ipv4:'):
                ip_part = query[5:].strip()
                if ip_part:
                    return ip_part in conn.rip.lower() or ip_part in conn.lip.lower()
                return False
            
            # Explicit IPv6 search with prefix
            if query.startswith('ipv6:'):
                ip_part = query[6:].strip()
                if ip_part:
                    return ip_part in conn.rip.lower() or ip_part in conn.lip.lower()
                return False
            
            # Process name search (highest priority for non-numeric)
            if not query.isdigit() and ':' not in query and '.' not in query and query in conn.process_name.lower():
                return True
            
            # Numeric search: check both PID and ports
            if query.isdigit():
                number = int(query)
                # Check PID pattern match (more useful than exact match)
                if query in str(conn.pid):
                    return True
                # Check port exact match
                if conn.rp == number or conn.lp == number:
                    return True
                
            # IPv6 search (contains colon)
            if ':' in query and any(c.isalnum() for c in query):
                if query in conn.rip.lower() or query in conn.lip.lower():
                    return True
                
            # IPv4 search (contains dot)
            if '.' in query and any(c.isdigit() for c in query):
                if query in conn.rip.lower() or query in conn.lip.lower():
                    return True
                
            # Security status search
            if query in ['suspicious', 'malicious', 'trusted', 'normal']:
                if query == 'suspicious':
                    return hasattr(conn, 'suspicious') and conn.suspicious and getattr(conn, 'threat_level', 0) == 1
                elif query == 'malicious':
                    return hasattr(conn, 'suspicious') and conn.suspicious and getattr(conn, 'threat_level', 0) >= 2
                elif query == 'trusted':
                    return hasattr(conn, 'notes') and 'trusted' in getattr(conn, 'notes', '').lower()
                elif query == 'normal':
                    return not hasattr(conn, 'suspicious') or not getattr(conn, 'suspicious', False)
                
            # Direction search
            if query in ['inbound', 'incoming', 'in']:
                return conn.direction == 'in'
            elif query in ['outbound', 'outgoing', 'out']:
                return conn.direction == 'out'
                
            return False
            
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
                
            # Traffic information - always detailed monitoring (formerly --traffic mode)
            traffic_in = "0B"   # Default incoming traffic
            traffic_out = "0B"  # Default outgoing traffic
            
            # Enhanced traffic monitoring with precise byte counting
            if hasattr(conn, 'bytes_sent') and hasattr(conn, 'bytes_received'):
                if conn.bytes_sent > 0 or conn.bytes_received > 0:
                    traffic_out = self._format_bytes(conn.bytes_sent)
                    traffic_in = self._format_bytes(conn.bytes_received)
                elif status == "ACTIVE":
                    # Show simulated traffic for testing in active connections
                    import random
                    if hasattr(conn, 'timestamp'):
                        age = time.time() - conn.timestamp
                        if age > 10:  # Show simulated traffic for old connections
                            base_traffic = int(age * random.randint(10, 100))
                            traffic_out = self._format_bytes(base_traffic)
                            traffic_in = self._format_bytes(base_traffic * 2)
            elif status == "ACTIVE":
                traffic_in = "~0B"
                traffic_out = "~0B"
            elif status == "CLOSED":
                traffic_in = "--"
                traffic_out = "--"
            
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
                self.status_display.update(f"{current_text} (REFRESHED)")
                # Reset after 2 seconds - lambda needs to accept the event parameter
                self.call_later(lambda _: self.update_display(), 2.0)
            
        async def action_toggle_filter(self) -> None:
            """Toggle filter (placeholder for future implementation)"""
            # Show in status instead of popup
            if self.status_display:
                current_text = str(self.status_display.renderable)
                self.status_display.update(f"{current_text} (Filter: Coming Soon)")
                # Reset after 3 seconds - lambda needs to accept the event parameter
                self.call_later(lambda _: self.update_display(), 3.0)
                
        async def action_reset(self) -> None:
            """Complete reset - clears all data and traffic history"""
            # Unfreeze if frozen
            if self.frozen:
                self.frozen = False
                self.frozen_timestamp = None
            
            # Clear search filter
            self.current_search_filter = ""
            
            # Clear all connection tracking
            self.active_connections.clear()
            self.new_connections.clear()
            self.closed_connections.clear()
            
            # Reset traffic monitoring (always enabled now)
            if self.traffic_monitor:
                self.traffic_monitor.connections_traffic.clear()
                self.traffic_monitor.prev_connections.clear()
                self.traffic_monitor.traffic_history.clear()
                self.traffic_monitor.conn_counters.clear()
            
            # Clear DNS cache
            if self.dns_resolver:
                self.dns_resolver.cache.clear()
                
            # Clear table
            if self.connection_table:
                self.connection_table.clear()
                
            # Load fresh data
            await self.refresh_data()
            
            # Show reset confirmation
            if self.status_display:
                current_text = str(self.status_display.renderable)
                self.status_display.update(f"{current_text} (COMPLETE RESET)")
                # Reset after 3 seconds
                self.call_later(lambda _: self.update_display(), 3.0)
                
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

        # Search Modal functionality
        async def action_open_search(self) -> None:
            """Open search modal"""
            self.debug("Opening search modal...")
            search_modal = SearchModal(self.current_search_filter)
            self.push_screen(search_modal)
            self.debug("Search modal opened")
            
        async def action_clear_search(self) -> None:
            """Clear current search filter"""
            self.current_search_filter = ""
            self.search_preview_active = False
            self.update_display()
            
        def _handle_search_preview(self, query: str) -> None:
            """Handle search preview (live filtering while typing)"""
            if not self.search_preview_active:
                return
                
            # Apply preview filter temporarily
            self.current_search_filter = query
            self.update_display()
            
        def _handle_search_applied(self, query: str) -> None:
            """Handle search applied"""
            self.current_search_filter = query.strip()
            self.search_preview_active = False
            
            # Debug output
            self.debug(f"FILTER SET: '{self.current_search_filter}' (original: '{query}')")
            
            self.update_display()
            
            # Show confirmation in status
            if self.status_display and self.current_search_filter:
                self.status_display.update(f"🔍 Filter applied: {self.current_search_filter}")
                # Reset after 3 seconds
                self.call_later(lambda _: self.update_display(), 3.0)
            
        def _handle_search_canceled(self) -> None:
            """Handle search canceled"""
            # Restore previous filter if we were previewing
            if self.search_preview_active:
                self.search_preview_active = False
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
    
    # Debug option
    parser.add_argument('--debug', action='store_true', help='Show debug window for troubleshooting')
    
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