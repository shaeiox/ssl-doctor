"""Executable entry point: ssldoctor-server.

    ssldoctor-server init|run|upgrade|backup|verify-audit|version ...
    ssldoctor-server service install|start|stop|remove --data DIR      (Windows)
"""

import sys

from ssldoctor_service.server_main import main

if __name__ == "__main__":
    if sys.platform == "win32" and (sys.argv[1:2] == ["service"] or len(sys.argv) == 1):
        import winsvc
        sys.exit(winsvc.handle("server", sys.argv[2:]))
    sys.exit(main())
