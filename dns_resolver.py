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
        
    def resolve(self, ip: str) -> str:
        """Resolve IP address to hostname, using cache if available"""
        if not self.enable_resolution:
            return ip
            
        if ip in self.cache:
            return self.cache[ip]
            
        # If resolution is already in progress, return the IP for now
        if ip in self.pending_futures:
