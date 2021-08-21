# pyright: reportUnknownMemberType=false
# pyright: reportMissingTypeStubs=false

import logging
from dataclasses import dataclass
from enum import Enum, auto
from threading import Thread
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from gi.repository import GLib
from pydbus import SystemBus
from pydbus.bus import SessionBus
from typing_extensions import Literal

from knot_resolver_manager.constants import KRES_CACHE_DIR, KRESD_CONFIG_FILE, RUNTIME_DIR
from knot_resolver_manager.exceptions import SubprocessControllerException
from knot_resolver_manager.kresd_controller.interface import SubprocessType

logger = logging.getLogger(__name__)


class SystemdType(Enum):
    SYSTEM = auto()
    SESSION = auto()


def _create_object_proxy(type_: SystemdType, bus_name: str, path: Optional[str] = None) -> Any:
    bus: Any = SystemBus() if type_ is SystemdType.SYSTEM else SessionBus()
    systemd = bus.get(bus_name, path)
    return systemd


def _create_manager_proxy(type_: SystemdType) -> Any:
    return _create_object_proxy(type_, ".systemd1")


def _wait_for_job_completion(systemd: Any, job_creating_func: Callable[[], str]):
    """
    Takes a function returning a systemd job path, executes it while simultaneously waiting
    for its completion. This prevents race conditions.
    """

    result_state: Optional[str] = None
    job_path: Optional[str] = None

    def _wait_for_job_completion_handler(loop: Any) -> Any:
        completed_jobs: Dict[str, str] = dict()

        def event_hander(_job_id: Any, path: Any, _unit: Any, state: Any):
            nonlocal result_state
            nonlocal completed_jobs

            # save the current job as completed
            completed_jobs[path] = state

            if job_path is not None and job_path in completed_jobs:
                # if we've already seen the job
                result_state = completed_jobs[job_path]
                loop.quit()

            # if we already have the job path we are looking for and it's not been seen yet,
            # it's safe to remove all previous completed job references as we don't care
            if job_path is not None:
                completed_jobs.clear()

        return event_hander

    def event_loop_isolation_thread():
        loop: Any = GLib.MainLoop()
        systemd.JobRemoved.connect(_wait_for_job_completion_handler(loop))
        loop.run()

    # first start the thread to watch for results to prevent race conditions
    thread = Thread(target=event_loop_isolation_thread)
    thread.start()

    # then create the job
    job_path = job_creating_func()

    # then wait for the results
    thread.join()

    if result_state != "done":
        raise SubprocessControllerException(f"Job completed with state '{result_state}' instead of expected 'done'")


def get_unit_file_state(
    type_: SystemdType,
    unit_name: str,
) -> Union[Literal["disabled"], Literal["enabled"]]:
    res = str(_create_manager_proxy(type_).GetUnitFileState(unit_name))
    assert res == "disabled" or res == "enabled"
    return res


@dataclass
class Unit:
    name: str
    state: str


def _list_units_internal(type_: SystemdType) -> List[Any]:
    return _create_manager_proxy(type_).ListUnits()


def list_units(type_: SystemdType) -> List[Unit]:
    return [Unit(name=str(u[0]), state=str(u[4])) for u in _list_units_internal(type_)]


def list_unit_names(type_: SystemdType) -> List[str]:
    return [str(u[0]) for u in _list_units_internal(type_)]


def list_failed_unit_names(type_: SystemdType) -> List[str]:
    return [str(u[0]) for u in _list_units_internal(type_) if str(u[3]) == "failed"]


def restart_unit(type_: SystemdType, unit_name: str):
    systemd = _create_manager_proxy(type_)

    def job():
        return systemd.RestartUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)


def _kresd_unit_properties(unit_name: str) -> List[Tuple[str, str]]:
    val: Any = [
        ("Description", GLib.Variant("s", "transient Knot Resolver unit started by Knot Resolver Manager")),
        ("Type", GLib.Variant("s", "notify")),
        ("WorkingDirectory", GLib.Variant("s", str(RUNTIME_DIR))),
        (
            "ExecStart",
            GLib.Variant(
                "a(sasb)", [("/usr/bin/kresd", ["/usr/bin/kresd", "-c", str(KRESD_CONFIG_FILE), "-n"], False)]
            ),
        ),
        ("TimeoutStopUSec", GLib.Variant("t", 10000000)),
        ("WatchdogUSec", GLib.Variant("t", 10000000)),
        ("Restart", GLib.Variant("s", "on-abnormal")),
        ("LimitNOFILE", GLib.Variant("t", 524288)),
        ("Environment", GLib.Variant("as", [f"SYSTEMD_INSTANCE={unit_name}"])),
    ]
    return val


def _gc_unit_properties() -> Any:
    val: Any = [
        (
            "Description",
            GLib.Variant("s", "transient Knot Resolver Garbage Collector unit started by Knot Resolver Manager"),
        ),
        ("Type", GLib.Variant("s", "simple")),
        ("WorkingDirectory", GLib.Variant("s", str(RUNTIME_DIR))),
        (
            "ExecStart",
            GLib.Variant(
                "a(sasb)",
                [("/usr/bin/kres-cache-gc", ["/usr/bin/kres-cache-gc", "-c", str(KRES_CACHE_DIR), "-d", "1000"], True)],
            ),
        ),
        ("Restart", GLib.Variant("s", "on-failure")),
        ("RestartUSec", GLib.Variant("t", 30000000)),
        ("StartLimitIntervalUSec", GLib.Variant("t", 400000000)),
        ("StartLimitBurst", GLib.Variant("u", 10)),
    ]
    return val


def start_transient_unit(type_: SystemdType, unit_name: str, subprocess_type: SubprocessType):
    properties = {SubprocessType.KRESD: _kresd_unit_properties(unit_name), SubprocessType.GC: _gc_unit_properties()}[
        subprocess_type
    ]

    systemd = _create_manager_proxy(type_)

    def job():
        return systemd.StartTransientUnit(unit_name, "fail", properties, [])

    _wait_for_job_completion(systemd, job)


def start_unit(type_: SystemdType, unit_name: str):
    systemd = _create_manager_proxy(type_)

    def job():
        return systemd.StartUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)


def stop_unit(type_: SystemdType, unit_name: str):
    systemd = _create_manager_proxy(type_)

    def job():
        return systemd.StopUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)


def list_unit_files(type_: SystemdType) -> List[str]:
    systemd = _create_manager_proxy(type_)
    files = systemd.ListUnitFiles()
    return [str(x[0]) for x in files]


def can_load_unit(type_: SystemdType, unit_name: str) -> bool:
    systemd = _create_manager_proxy(type_)
    try:
        unit_path: str = systemd.LoadUnit(unit_name)
        unit_object = _create_object_proxy(type_, ".systemd1", unit_path)
        load_error = unit_object.LoadError
        return load_error == ("", "")
    except Exception:
        # if this fails in any way, we can assume that the unit is not properly loaded
        return False
