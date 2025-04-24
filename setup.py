#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup.py – Installation script for WTFCalls
"""
from setuptools import setup, find_packages

setup(
    name="wtfcalls",
    version="0.2.0",
    description="Live detector for outgoing network calls on both macOS and Linux",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/wtfcalls",
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
)
