#!/usr/bin/env python3
"""JEHAD — terminal-only entrypoint (no GUI dependencies)."""
import sys

if __name__ == '__main__':
    # Preserve pre-existing CLI automation flags from the previous release.
    if '-m' in sys.argv or '--module' in sys.argv:
        from jehad_cli import main
    else:
        from jehad_terminal import main
    main()
