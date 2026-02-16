#!/usr/bin/env python3
"""
CatoScan

Main executable entry point for the CIS benchmark audit tool.
This script runs the CLI and exits with appropriate status codes.

Usage:
    ./catoscan.py [options]
    python3 catoscan.py [options]

Exit Codes:
    0 - Success, all checks passed
    1 - Error occurred during execution
    2 - Warnings present (e.g., running without sudo)

Examples:
    # Run with default settings
    sudo ./catoscan.py
    
    # Run without sudo (some checks will be skipped)
    ./catoscan.py --no-sudo
    
    # Force server environment detection
    sudo ./catoscan.py --force-server
    
    # Output to file with verbose mode
    sudo ./catoscan.py -o results.json -v
"""

import sys
from src.cli import main

if __name__ == "__main__":
    sys.exit(main())
