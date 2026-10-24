"""Executable entry point: ssl-doctor (CLI)."""

import sys

from ssl_doctor.cli import main

if __name__ == "__main__":
    sys.exit(main())
