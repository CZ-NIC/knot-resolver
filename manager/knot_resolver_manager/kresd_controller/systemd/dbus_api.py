# pyright: reportUnknownMemberType=false
# pyright: reportMissingTypeStubs=false

from enum import Enum, auto
from threading import Thread
from typing import Any, List, Union

from gi.repository import GLib
from pydbus import SystemBus
from pydbus.bus import SessionBus
from typing_extensions import Literal

# ugly global result variable, but this module will be used once in a every
# process, so we should get away with it
#
# Used to storing result state of systemd's jobs
result_state = None


class SystemdType(Enum):
    SYSTEM = auto()
    SESSION = auto()


class SystemdException(Exception):
    pass


def _create_manager_interface(type_: SystemdType) -> Any:
    bus: Any = SystemBus() if type_ is SystemdType.SYSTEM else SessionBus()
    systemd = bus.get(".systemd1")
    return systemd


def _wait_for_job_completion(systemd: Any, job: Any):
    def event_loop_isolation_thread():
        global result_state

        loop: Any = GLib.MainLoop()
        systemd.JobRemoved.connect(_wait_for_job_completion_handler(loop, job))
        result_state = None
        loop.run()

        if result_state != "done":
            raise SystemdException(f"Job completed with state '{result_state}' instead of expected 'done'")

    thread = Thread(target=event_loop_isolation_thread)
    thread.start()
    thread.join()


def _wait_for_job_completion_handler(loop: Any, job_path: Any) -> Any:
    def event_hander(_job_id: Any, path: Any, _unit: Any, state: Any):
        global result_state

        # if the job is no longer queued, stop the loop
        if path == job_path:
            result_state = state
            loop.quit()
        # otherwise do nothing

    return event_hander


def get_unit_file_state(
    type_: SystemdType,
    unit_name: str,
) -> Union[Literal["disabled"], Literal["enabled"]]:
    res = str(_create_manager_interface(type_).GetUnitFileState(unit_name))
    assert res == "disabled" or res == "enabled"
    return res


def list_units(type_: SystemdType) -> List[str]:
    return [str(u[0]) for u in _create_manager_interface(type_).ListUnits()]


def restart_unit(type_: SystemdType, unit_name: str):
    systemd = _create_manager_interface(type_)
    job = systemd.RestartUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)


def start_unit(type_: SystemdType, unit_name: str):
    systemd = _create_manager_interface(type_)
    job = systemd.StartUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)


def stop_unit(type_: SystemdType, unit_name: str):
    systemd = _create_manager_interface(type_)
    job = systemd.StopUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)


def list_unit_files(type_: SystemdType) -> List[str]:
    systemd = _create_manager_interface(type_)
    files = systemd.ListUnitFiles()
    return [str(x[0]) for x in files]


def has_some_exec_start_commands(type_: SystemdType, unit_name: str) -> bool:
    systemd = _create_manager_interface(type_)
    try:
        unit_object = systemd.LoadUnit(unit_name)
        return len(unit_object.ExecStart) != 0
    except Exception:
        # if this fails in any way, we can assume that the unit is not properly loaded
        return False
