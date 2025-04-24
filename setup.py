#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup.py – Installation script for WTFCalls
"""
from setuptools import setup, find_packages, Command
import os
import stat
import sys

class MakeExecutableCommand(Command):
    """Custom command to make wtfcalls.py executable."""
    description = "Make wtfcalls.py executable"
    user_options = []
    
    def initialize_options(self):
        pass
        
    def finalize_options(self):
        pass
        
    def run(self):
        """Execute the command."""
        try:
            # Pfad zur wtfcalls.py bestimmen
            package_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wtfcalls")
            main_file = os.path.join(package_dir, "__init__.py")
            
            if os.path.exists(main_file):
                # Aktuelle Berechtigungen holen
                current_permissions = os.stat(main_file).st_mode
                
                # Ausführbare Rechte hinzufügen
                os.chmod(main_file, current_permissions | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                print(f"Made {main_file} executable")
            else:
                print(f"Warning: File {main_file} not found")
        except Exception as e:
            print(f"Error making file executable: {e}")

# Post-Installation Hook
class InstallCommand(Command):
    """Custom install command that makes the main file executable after installation."""
    description = "Custom install command"
    user_options = []
    
    def initialize_options(self):
        pass
        
    def finalize_options(self):
        pass
        
    def run(self):
        # Führe Standard-Installation aus
        self.run_command('install')
        # Führe unser Custom-Command aus
        self.run_command('make_executable')

setup(
    name="wtfcalls",
    version="0.2.0",
    description="Live detector for outgoing network calls on both macOS and Linux",
    author="Robert Tulke",
    author_email="rt@debian.sh",
    url="https://github.com/rtulke/wtfcalls",
    packages=find_packages(),
    install_requires=[
        "psutil>=5.8.0",
        "rich>=10.0.0",
    ],
    extras_require={
        "full": [
            "textual>=0.1.18",
            "pyyaml>=5.1",
            "ipaddress"
        ],
    },
    entry_points={
        "console_scripts": [
            "wtfcalls=wtfcalls:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    cmdclass={
        'make_executable': MakeExecutableCommand,
        'custom_install': InstallCommand,
    },
)

# Ausführen beim direkten Aufruf von setup.py
if __name__ == "__main__":
    # Führe das Command auch aus, wenn setup.py direkt aufgerufen wird
    if len(sys.argv) <= 1 or sys.argv[1] not in ['make_executable', 'custom_install']:
        cmd = MakeExecutableCommand(None)
        cmd.run()
