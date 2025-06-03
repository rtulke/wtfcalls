#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dns_resolver.py – DNS resolution handling
"""
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict


class DNSResolver:
    """
    Handles DNS resolution with caching and asynchronous lookups.
    """
    def __init__(self, max_workers: int = 10, enable_resolution: bool = True):
        self.cache = {}  # IP -> hostname mapping
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.enable_resolution = enable_resolution
        self.pending_futures = {}  # IP -> Future

    def _cleanup_completed_futures(self) -> None:
        """Remove completed futures from pending list"""
        completed = [ip for ip, future in list(self.pending_futures.items()) 
                    if future.done()]
        for ip in completed:
            self.pending_futures.pop(ip, None)        


    def resolve(self, ip: str) -> str:
        """Resolve IP address to hostname, using cache if available"""
        if not self.enable_resolution:
            return ip
            
        if ip in self.cache:
            return self.cache[ip]
            
        # Check and clean completed futures before adding new ones
        #self._cleanup_completed_futures()
            
        if ip in self.pending_futures:
            return ip
            
        future = self.executor.submit(self._resolve_dns, ip)
        self.pending_futures[ip] = future
        return ip
    

        
    def _resolve_dns(self, ip: str) -> str:
        """Perform actual DNS resolution"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.cache[ip] = hostname
            return hostname
        except Exception:
            self.cache[ip] = ip  # Cache failures too
            return ip
            
    def update_cache(self) -> None:
        """Check for completed DNS resolutions and update cache"""
        completed = [ip for ip, future in list(self.pending_futures.items()) 
                    if future.done()]
                     
        for ip in completed:
            future = self.pending_futures.pop(ip)
            try:
                # Update cache with resolved hostname
                hostname = future.result()
                self.cache[ip] = hostname
            except Exception:
                # On failure, cache the IP itself
                self.cache[ip] = ip
                
    def format_addr(self, ip: str, port: int) -> str:
        """Format an address as hostname:port"""
        return f"{self.resolve(ip)}:{port}"
        
    def shutdown(self) -> None:
        """Clean shutdown of the executor"""
        self.executor.shutdown(wait=False)
