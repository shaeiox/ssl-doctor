"""Windows service hosting for ssl-doctor-agent.exe and ssldoctor-server.exe.

Built into the Windows executables only (pywin32). The service runs the same
code as the console commands; arguments are stored in the service's
registry parameters at install time.

    <exe> service install [--state FILE | --data DIR]
    <exe> service start|stop|remove
"""

from __future__ import annotations

import os
import sys
import threading

import servicemanager
import win32event
import win32service
import win32serviceutil

NAMES = {
    "agent": ("SSLDoctorAgent", "SSL Doctor scan agent"),
    "server": ("SSLDoctorServer", "SSL Doctor platform server"),
}
_KIND = "agent"


def _run_kind(kind: str, args):
    if kind == "agent":
        from ssl_doctor.agent import load_state, serve, DEFAULT_STATE
        state = args[args.index("--state") + 1] if "--state" in args else DEFAULT_STATE
        return serve(load_state(state))
    from ssldoctor_service.server_main import main
    return main(["run", *args])


class _Service(win32serviceutil.ServiceFramework):
    _svc_name_, _svc_display_name_ = NAMES[_KIND]

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):  # noqa: N802
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        os._exit(0)              # child PostgreSQL is stopped by the server's own handler

    def SvcDoRun(self):  # noqa: N802
        servicemanager.LogInfoMsg(f"{self._svc_display_name_} starting")
        args = win32serviceutil.GetServiceCustomOption(self._svc_name_, "args", "").split("\x1f")
        t = threading.Thread(target=_run_kind, args=(_KIND, [a for a in args if a]),
                             daemon=True)
        t.start()
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)


def handle(kind: str, argv) -> int:
    global _KIND
    _KIND = kind
    _Service._svc_name_, _Service._svc_display_name_ = NAMES[kind]
    if not argv:                         # started by the Service Control Manager
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(_Service)
        servicemanager.StartServiceCtrlDispatcher()
        return 0
    action, extra = argv[0], argv[1:]
    name = NAMES[kind][0]
    if action == "install":
        win32serviceutil.InstallService(
            None, name, NAMES[kind][1], startType=win32service.SERVICE_AUTO_START,
            exeName=sys.executable, exeArgs="")
        win32serviceutil.SetServiceCustomOption(name, "args", "\x1f".join(extra))
        print(f"installed service {name} (auto start)")
    elif action == "start":
        win32serviceutil.StartService(name)
    elif action == "stop":
        win32serviceutil.StopService(name)
    elif action == "remove":
        win32serviceutil.RemoveService(name)
    else:
        print("usage: service install|start|stop|remove [args]", file=sys.stderr)
        return 64
    return 0
