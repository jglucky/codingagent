#!/usr/bin/env python3
"""Convenience entry point: python scan.py <owner/repo>"""

from repo_scanner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())