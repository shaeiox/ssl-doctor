#!/usr/bin/env python3
"""SSL Doctor entry point.

Interactive:   python3 ssldoctor.py
One-shot:      python3 ssldoctor.py "/tls example.com"
Batch:         python3 ssldoctor.py -c "/tls example.com:443" -c "/report html r.html"
"""

from ssl_doctor.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
