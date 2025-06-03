#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Debug script for WTFCalls Program column issues
Analyzes potential problems in process name detection and display
"""
import psutil
import platform
import subprocess
import re
import os
from typing import Dict, List, Tuple


def debug_process_names():
    """Debug process name detection issues"""
    print("=== WTFCalls Program Column Debug ===\n")
    
    # Get all network connections
    try:
        connections = psutil.net_connections(kind='inet')
        print(f"Found {len(connections)} network connections\n")
    except Exception as e:
        print(f"ERROR getting connections: {e}")
        return
    
    # Analyze each connection
    issues = []
    for i, conn in enumerate(connections):
        if conn.raddr and conn.status != psutil.CONN_LISTEN:
            pid = conn.pid or 0
            
            print(f"Connection {i+1}:")
            print(f"  PID: {pid}")
            print(f"  Local: {conn.laddr}")
            print(f"  Remote: {conn.raddr}")
            
            # Test process name detection
            try:
                process_name = get_process_name_debug(pid)
                print(f"  Process Name: '{process_name}'")
                
                # Check for potential issues
                if len(process_name) > 50:
                    issues.append(f"PID {pid}: Process name too long ({len(process_name)} chars)")
                
                if any(ord(c) > 127 for c in process_name):
                    issues.append(f"PID {pid}: Non-ASCII characters in process name")
                
                if process_name == '<Unknown>':
                    issues.append(f"PID {pid}: Unknown process name")
                
                # Test Rich formatting
                test_formatted = f"[magenta]{process_name}[/magenta]"
                print(f"  Rich Formatted: {test_formatted}")
                
            except Exception as e:
                issues.append(f"PID {pid}: Exception getting process name: {e}")
                print(f"  ERROR: {e}")
            
            print()
            
            # Limit output for debugging
            if i >= 5:
                print("... (showing first 5 connections only)")
                break
    
    # Report issues
    if issues:
        print("\n=== DETECTED ISSUES ===")
        for issue in issues:
            print(f"⚠️  {issue}")
    else:
        print("\n✅ No obvious issues detected")


def get_process_name_debug(pid: int) -> str:
    """Debug version of process name detection with detailed logging"""
    print(f"    Debugging process name for PID {pid}...")
    
    if pid <= 0:
        print("    → Invalid PID")
        return '<Invalid PID>'
    
    try:
        proc = psutil.Process(pid)
        print(f"    → Process object created successfully")
        
        # macOS specific handling
        if platform.system() == 'Darwin':
            print("    → macOS detected, trying bundle detection")
            try:
                exe = proc.exe()
                print(f"    → Executable path: {exe}")
                
                if exe and '/Contents/MacOS/' in exe:
                    print("    → Bundle executable detected")
                    parts = exe.split('/')
                    for i, part in enumerate(parts):
                        if part.endswith('.app') or part.endswith('.xpc'):
                            exec_name = parts[-1] if len(parts) > 0 else part
                            if '.' in exec_name and exec_name.startswith('com.'):
                                print(f"    → Bundle identifier: {exec_name}")
                                return exec_name
                            bundle_name = part.rsplit('.', 1)[0]
                            print(f"    → Bundle name: {bundle_name}")
                            return bundle_name
                    
                    exe_name = exe.split('/')[-1]
                    print(f"    → Executable name: {exe_name}")
                    return exe_name
                elif exe:
                    exe_name = exe.split('/')[-1]
                    print(f"    → Simple executable: {exe_name}")
                    return exe_name
                    
            except (psutil.AccessDenied, psutil.ZombieProcess) as e:
                print(f"    → exe() failed: {e}")
        
        # Try command line
        try:
            cmdline = proc.cmdline()
            print(f"    → Command line: {cmdline}")
            
            if cmdline and cmdline[0]:
                cmd = cmdline[0].split('/')[-1]
                if cmd.startswith('com.') and '.' in cmd:
                    print(f"    → Bundle ID from cmdline: {cmd}")
                    return cmd
                print(f"    → Command from cmdline: {cmd}")
                return cmd
                
        except (psutil.AccessDenied, psutil.ZombieProcess) as e:
            print(f"    → cmdline() failed: {e}")
        
        # Fall back to process name
        name = proc.name()
        print(f"    → Process name: {name}")
        return name
        
    except psutil.NoSuchProcess:
        print("    → Process no longer exists")
        return '<Process Terminated>'
    except psutil.AccessDenied:
        print("    → Access denied")
        return '<Access Denied>'
    except Exception as e:
        print(f"    → Unexpected error: {e}")
        return '<Unknown>'


def test_rich_formatting():
    """Test Rich formatting with various process names"""
    print("\n=== Rich Formatting Tests ===")
    
    test_names = [
        "python3",
        "com.apple.Safari.SafeBrowsing.Service",
        "firefox",
        "Process with spaces",
        "Process-with-dashes",
        "Process_with_underscores",
        "Process.with.dots",
        "Process[with]brackets",
        "Process(with)parentheses",
        "ProcessWithVeryLongNameThatMightCauseIssues",
        "Процесс_с_юникодом",  # Unicode test
        "",  # Empty string
        "<Unknown>",
    ]
    
    from rich.console import Console
    from rich.table import Table
    
    console = Console()
    table = Table(title="Process Name Formatting Test")
    table.add_column("Original", style="cyan")
    table.add_column("Formatted", style="magenta")
    table.add_column("Length", style="yellow")
    table.add_column("Issues", style="red")
    
    for name in test_names:
        try:
            formatted = f"[magenta]{name}[/magenta]"
            issues = []
            
            if len(name) > 50:
                issues.append("Too long")
            if any(ord(c) > 127 for c in name):
                issues.append("Non-ASCII")
            if not name:
                issues.append("Empty")
            if any(c in name for c in ['[', ']']):
                issues.append("Rich conflicts")
            
            table.add_row(
                name,
                formatted,
                str(len(name)),
                ", ".join(issues) if issues else "OK"
            )
            
        except Exception as e:
            table.add_row(name, f"ERROR: {e}", str(len(name)), "Exception")
    
    console.print(table)


def check_platform_specifics():
    """Check platform-specific issues"""
    print(f"\n=== Platform-Specific Checks ===")
    print(f"Platform: {platform.system()}")
    print(f"Platform Release: {platform.release()}")
    print(f"Python Version: {platform.python_version()}")
    
    # Check psutil version
    print(f"psutil Version: {psutil.__version__}")
    
    # Check if lsof is available (fallback method)
    try:
        result = subprocess.run(['lsof', '-v'], 
                              capture_output=True, text=True, timeout=5)
        print(f"lsof available: Yes (version info in stderr)")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("lsof available: No")
    except Exception as e:
        print(f"lsof check failed: {e}")
    
    # Check permissions
    try:
        connections = psutil.net_connections(kind='inet')
        print("Network connections access: OK")
    except psutil.AccessDenied:
        print("Network connections access: DENIED - Need sudo?")
    except Exception as e:
        print(f"Network connections access: ERROR - {e}")


if __name__ == "__main__":
    try:
        debug_process_names()
        test_rich_formatting() 
        check_platform_specifics()
        
        print("\n=== Debugging Complete ===")
        print("Run this script to identify issues with process name detection.")
        print("Common solutions:")
        print("1. Run with sudo for better process access")
        print("2. Check for non-ASCII characters in process names")
        print("3. Handle overly long process names")
        print("4. Escape Rich markup characters in process names")
        
    except KeyboardInterrupt:
        print("\nDebug interrupted by user")
    except Exception as e:
        print(f"Debug script failed: {e}")
        raise
