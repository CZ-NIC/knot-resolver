from typing import List, Union
from typing_extensions import Literal

from pydbus import SystemBus
from gi.repository import GLib

# ugly global result variable, but this module will be used once in a every
# process, so we should get away with it
#
# Used to storing result state of systemd's jobs
result_state = None


class SystemdException(Exception):
    pass


def _create_manager_interface():
    bus = SystemBus()
    systemd = bus.get(".systemd1")
    return systemd


def _wait_for_job_completion(systemd, job):
    global result_state

    loop = GLib.MainLoop()
    systemd.JobRemoved.connect(_wait_for_job_completion_handler(loop, job))
    result_state = None
    loop.run()

    if result_state != "done":
        raise SystemdException(
            f"Job completed with state '{result_state}' instead of expected 'done'"
        )


def _wait_for_job_completion_handler(loop, job_path):
    def event_hander(_job_id, path, _unit, state):
        global result_state

        # if the job is no longer queued, stop the loop
        if path == job_path:
            result_state = state
            loop.quit()
        # otherwise do nothing

    return event_hander


def get_unit_file_state(
    unit_name: str,
) -> Union[Literal["disabled"], Literal["enabled"]]:
    res = str(_create_manager_interface().GetUnitFileState(unit_name))
    assert res == "disabled" or res == "enabled"
    return res


def list_units() -> List[str]:
    return [str(u[0]) for u in _create_manager_interface().ListUnits()]


def restart_unit(unit_name: str):
    systemd = _create_manager_interface()
    job = systemd.RestartUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)


def start_unit(unit_name: str):
    systemd = _create_manager_interface()
    job = systemd.StartUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)


def stop_unit(unit_name: str):
    systemd = _create_manager_interface()
    job = systemd.StopUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)
