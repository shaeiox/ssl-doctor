"""Executable entry point: ssl-doctor-agent.

    ssl-doctor-agent enroll <url> <token> [--state FILE]
    ssl-doctor-agent run [--once] [--state FILE]
    ssl-doctor-agent service install|start|stop|remove [--state FILE]   (Windows)
"""

import sys

from ssl_doctor.agent import main

if __name__ == "__main__":
    if sys.platform == "win32" and (sys.argv[1:2] == ["service"] or len(sys.argv) == 1):
        import winsvc
        sys.exit(winsvc.handle("agent", sys.argv[2:]))
    sys.exit(main(sys.argv[1:]))
