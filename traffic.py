#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
traffic.py – Traffic monitoring for network connections
"""
import time
import logging
import platform
import subprocess
from typing import Dict, Tuple, List


class TrafficMonitor:
    """
    Monitors network traffic for connections
    """
    def __init__(self):
        self.connections_traffic = {}  # key -> (bytes_sent, bytes_received)
        self.prev_connections = {}  # For calculating deltas
        self.traffic_history = {}  # key -> list of (timestamp, bytes_sent, bytes_received)
        
    def update(self, connections: Dict) -> None:
        """Update traffic information for connections"""
        # Get current traffic counters
        try:
            # Try to get per-connection traffic from /proc on Linux
            if platform.system() == 'Linux':
                self._update_linux(connections)
            # For macOS, use lsof or other tools if available
            elif platform.system() == 'Darwin':
                self._update_macos(connections)
        except Exception as e:
            # Just log but continue if traffic monitoring fails
            logging.warning(f"Traffic monitoring error: {str(e)}")
            
    def _update_linux(self, connections: Dict) -> None:
        """Update traffic for Linux by reading /proc/net/tcp and /proc/PID/fd"""
        try:
            # Read /proc/net/tcp for TCP connections
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()[1:]  # Skip header
                
            for line in lines:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                
                # Parse local and remote addresses
                local_hex = parts[1]
                remote_hex = parts[2]
                
                # Convert hex addresses to IP:port
                try:
                    local_ip, local_port = self._hex_to_ip_port(local_hex)
                    remote_ip, remote_port = self._hex_to_ip_port(remote_hex)
                    
                    # Find matching connection
                    for key, conn in connections.items():
                        if (conn.lip == local_ip and conn.lp == local_port and
                            conn.rip == remote_ip and conn.rp == remote_port):
                            
                            # Get traffic counters
                            tx_bytes = int(parts[4], 16)  # tx_bytes column
                            rx_bytes = int(parts[5], 16)  # rx_bytes column
                            
                            # Update connection
                            conn.update_traffic(tx_bytes, rx_bytes)
                            break
            
        except Exception as e:
            logging.debug(f"Error updating Linux traffic: {str(e)}")
                
    def _hex_to_ip_port(self, hex_str: str) -> Tuple[str, int]:
        """Convert hex representation of IP:port to string:int"""
        ip_hex, port_hex = hex_str.split(':')
        
        # Convert IP (reverse byte order for endianness)
        ip_parts = [ip_hex[i:i+2] for i in range(0, len(ip_hex), 2)]
        ip_parts.reverse()
        ip = '.'.join(str(int(part, 16)) for part in ip_parts)
        
        # Convert port
        port = int(port_hex, 16)
        
        return ip, port
            
    def _update_macos(self, connections: Dict) -> None:
        """Update traffic for macOS using netstat"""
        try:
            # Use netstat to get traffic stats
            output = subprocess.check_output(['netstat', '-n', '-b'], text=True)
            lines = output.splitlines()
            
            # Process netstat output
            for i, line in enumerate(lines):
                if i < 2:  # Skip headers
                    continue
                    
                parts = line.split()
                if len(parts) < 10:
                    continue
                    
                # Check if it's a TCP connection
                if 'tcp' not in parts[0].lower():
                    continue
                    
                # Parse addresses
                try:
                    local_addr = parts[3]
                    remote_addr = parts[4]
                    
                    # Split IP and port
                    local_ip, local_port = local_addr.rsplit('.', 1)
                    remote_ip, remote_port = remote_addr.rsplit('.', 1)
                    
                    # Convert to integers
                    local_port = int(local_port)
                    remote_port = int(remote_port)
                    
                    # Get traffic stats
                    bytes_in = int(parts[6])
                    bytes_out = int(parts[9])
                    
                    # Find matching connection
                    for key, conn in connections.items():
                        if (conn.lip == local_ip and conn.lp == local_port and
                            conn.rip == remote_ip and conn.rp == remote_port):
                            
                            # Update connection
                            conn.update_traffic(bytes_out, bytes_in)
                            break
                            
                except (ValueError, IndexError):
                    continue
                    
        except Exception as e:
            logging.debug(f"Error updating macOS traffic: {str(e)}")
            
    def update_history(self, connections: Dict) -> None:
        """Update traffic history for trend analysis"""
        now = time.time()
        
        for key, conn in connections.items():
            if key not in self.traffic_history:
                self.traffic_history[key] = []
                
            # Add current data point
            self.traffic_history[key].append((now, conn.bytes_sent, conn.bytes_received))
            
            # Keep history limited to prevent memory bloat
            if len(self.traffic_history[key]) > 60:  # Keep last 60 data points
                self.traffic_history[key].pop(0)
                
    def get_traffic_rate(self, key: Tuple) -> Tuple[float, float]:
        """Get current traffic rate (bytes/sec) for a connection"""
        if key not in self.traffic_history or len(self.traffic_history[key]) < 2:
            return 0.0, 0.0
            
        history = self.traffic_history[key]
        newest = history[-1]
        oldest = history[0]
        
        # Calculate time difference
        time_diff = newest[0] - oldest[0]
        if time_diff <= 0:
            return 0.0, 0.0
            
        # Calculate byte difference
        sent_diff = newest[1] - oldest[1]
        recv_diff = newest[2] - oldest[2]
        
        # Calculate rate
        sent_rate = sent_diff / time_diff
        recv_rate = recv_diff / time_diff
        
        return sent_rate, recv_rate
