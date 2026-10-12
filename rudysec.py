#!/usr/bin/env python3
"""Backward-compatible entry point: rudysec.py used to be a near copy of rudynet.py.

It now runs the same CLI, so fixes only need to be made once.
"""

from rudynet import cli

if __name__ == '__main__':
    cli()
