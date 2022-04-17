# pyright: reportUnknownMemberType=false
# pyright: reportMissingTypeStubs=false

import logging
import os
from enum import Enum, auto
from threading import Thread
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar

from gi.repository import GLib  # type: ignore[import]
from pydbus import SystemBus  # type: ignore[import]
from pydbus.bus import SessionBus  # type: ignore[import]
from typing_extensions import Literal

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.constants import (
    kres_gc_executable,
    kresd_cache_dir,
    kresd_config_file,
    kresd_executable,
    user_constants,
)
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.exceptions import SubprocessControllerException, SubprocessControllerTimeoutException
from knot_resolver_manager.kresd_controller.interface import KresID, SubprocessType

logger = logging.getLogger(__name__)


class SystemdType(Enum):
    SYSTEM = auto()
    SESSION = auto()


def _clean_error_message(msg: str) -> str:
    if "org.freedesktop.systemd1." in msg:
        msg = msg.split("org.freedesktop.systemd1.", maxsplit=1)[1]
    return msg


T = TypeVar("T")


def _wrap_dbus_errors(func: Callable[..., T]) -> Callable[..., T]:
    def inner(*args: Any, **kwargs: Any) -> T:
        try:
            return func(*args, **kwargs)
        except GLib.Error as e:
            raise SubprocessControllerException(_clean_error_message(str(e))) from e

    return inner


def _create_object_proxy(type_: SystemdType, bus_name: str, path: Optional[str] = None) -> Any:
    bus: Any = SystemBus() if type_ is SystemdType.SYSTEM else SessionBus()
    systemd = bus.get(bus_name, path)
    return systemd


def _create_manager_proxy(type_: SystemdType) -> Any:
    return _create_object_proxy(type_, ".systemd1")


def _wait_for_job_completion(systemd: Any, job_creating_func: Callable[[], str], timeout_sec: int = 10) -> None:
    """
    Takes a function returning a systemd job path, executes it while simultaneously waiting
    for its completion. This prevents race conditions.
    """

    result_state: Optional[str] = None
    job_path: Optional[str] = None
    loop: Any = None
    completed_jobs: Dict[str, str] = {}
    thread_exception: Optional[Exception] = None

    def job_removed_event(_job_id: Any, path: Any, _unit: Any, state: Any) -> None:
        nonlocal result_state
        nonlocal completed_jobs
        nonlocal loop

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

    def timeout_event():
        nonlocal loop
        nonlocal result_state
        result_state = "timeout"
        loop.quit()

    def idle_event():
        # start the systemd task
        nonlocal job_path
        job_path = job_creating_func()
        # do not repeat the event
        return False

    def event_loop_isolation_thread() -> None:
        try:
            nonlocal loop
            loop = GLib.MainLoop()
            GLib.timeout_add_seconds(timeout_sec, timeout_event)
            systemd.JobRemoved.connect(job_removed_event)
            GLib.idle_add(idle_event)
            loop.run()
        except Exception as e:
            nonlocal thread_exception
            thread_exception = e

    # start the event loop isolation thread handling the work
    thread = Thread(target=event_loop_isolation_thread, name="glib-loop-isolation-thread")
    thread.start()

    # then wait for the results
    thread.join()

    # the thread sets `result_state` and `thread_exception` variables, which we check here
    if thread_exception is not None:
        raise thread_exception  # pyright: reportGeneralTypeIssues=false
    if result_state == "timeout":  # pyright: reportUnnecessaryComparison=false
        raise SubprocessControllerTimeoutException(f"systemd job '{job_path}' did not finish in {timeout_sec} seconds")
    if result_state != "done":
        raise SubprocessControllerException(
            f"systemd job '{job_path}' completed with state '{result_state}' instead of expected 'done'"
        )


@_wrap_dbus_errors
def get_unit_file_state(
    type_: SystemdType,
    unit_name: str,
) -> Literal["disabled", "enabled"]:
    res = str(_create_manager_proxy(type_).GetUnitFileState(unit_name))
    assert res == "disabled" or res == "enabled"
    return res  # type: ignore


@dataclass
class Unit:
    name: str
    state: str


def _list_units_internal(type_: SystemdType) -> List[Any]:
    return _create_manager_proxy(type_).ListUnits()


@_wrap_dbus_errors
def list_units(type_: SystemdType) -> List[Unit]:
    return [Unit(name=str(u[0]), state=str(u[4])) for u in _list_units_internal(type_)]  # type: ignore[call-arg]


@_wrap_dbus_errors
def list_unit_names(type_: SystemdType) -> List[str]:
    return [str(u[0]) for u in _list_units_internal(type_)]


@_wrap_dbus_errors
def reset_failed_unit(typ: SystemdType, unit_name: str) -> None:
    systemd = _create_manager_proxy(typ)
    systemd.ResetFailedUnit(unit_name)


@_wrap_dbus_errors
def _list_slice_services(typ: SystemdType, slice_name: str) -> Set[str]:
    # uses DBus method call, which is not documented, but is present since 2016 and is used by `systemctl status`
    # appears for the first time in commit 291d565a04263452c03beaf537773ade4f0b1617 in systemd

    systemd = _create_manager_proxy(typ)
    data = systemd.GetUnitProcesses(slice_name)
    return set((p[0].split("/")[-1] for p in data))


@_wrap_dbus_errors
def restart_unit(type_: SystemdType, unit_name: str) -> None:
    systemd = _create_manager_proxy(type_)

    def job():
        return systemd.RestartUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)


def _slice_name(systemd_type: SystemdType) -> str:
    if systemd_type is SystemdType.SESSION:
        return f"kres-{user_constants().ID}.slice"
    else:
        return f"system-kres-{user_constants().ID}.slice"


def _kresd_unit_properties(config: KresConfig, kres_id: KresID, systemd_type: SystemdType) -> List[Tuple[str, str]]:
    val: Any = [
        ("Description", GLib.Variant("s", "transient Knot Resolver unit started by Knot Resolver Manager")),
        ("Type", GLib.Variant("s", "notify")),
        ("WorkingDirectory", GLib.Variant("s", os.getcwd())),
        (
            "ExecStart",
            GLib.Variant(
                "a(sasb)",
                [
                    (
                        str(kresd_executable()),
                        [str(kresd_executable()), "-c", str(kresd_config_file(config, kres_id)), "-n"],
                        False,
                    )
                ],
            ),
        ),
        ("TimeoutStopUSec", GLib.Variant("t", 10000000)),
        # The manager assumes that the subprocess is always running. When this is not the case, we end up with a hard
        # crash, because no code is expecting to deal with this state. Therefore, there is no condition under which
        # kresd instances could be not running ==> we configure systemd to restart them always
        ("Restart", GLib.Variant("s", "always")),
        ("LimitNOFILE", GLib.Variant("t", 524288)),
        ("Environment", GLib.Variant("as", [f"SYSTEMD_INSTANCE={kres_id}"])),
        ("Slice", GLib.Variant("s", _slice_name(systemd_type))),
    ]

    if config.server.watchdog:
        val.append(
            ("WatchdogUSec", GLib.Variant("t", 10000000)),
        )

    return val


def _gc_unit_properties(config: KresConfig, systemd_type: SystemdType) -> Any:
    val: Any = [
        (
            "Description",
            GLib.Variant("s", "transient Knot Resolver Garbage Collector unit started by Knot Resolver Manager"),
        ),
        ("Type", GLib.Variant("s", "simple")),
        ("WorkingDirectory", GLib.Variant("s", os.getcwd())),
        (
            "ExecStart",
            GLib.Variant(
                "a(sasb)",
                [
                    (
                        str(kres_gc_executable()),
                        [str(kres_gc_executable()), "-c", str(kresd_cache_dir(config)), "-d", "1000"],
                        True,
                    )
                ],
            ),
        ),
        ("Restart", GLib.Variant("s", "always")),  # see reasoning at kresd instance properties
        ("RestartUSec", GLib.Variant("t", 30000000)),
        ("StartLimitIntervalUSec", GLib.Variant("t", 400000000)),
        ("StartLimitBurst", GLib.Variant("u", 10)),
        ("Slice", GLib.Variant("s", _slice_name(systemd_type))),
    ]
    return val


def _kres_slice_properties() -> Any:
    val: Any = [
        ("Description", GLib.Variant("s", "Knot Resolver processes")),
    ]
    return val


@_wrap_dbus_errors
def _start_transient_unit(systemd_type: SystemdType, name: str, properties: Any) -> None:
    systemd = _create_manager_proxy(systemd_type)

    def job():
        return systemd.StartTransientUnit(name, "fail", properties, [])

    try:
        _wait_for_job_completion(systemd, job)
    except SubprocessControllerTimeoutException:
        logger.error(
            f"Failed to start transient '{name}'. The start operation did not finish within the expected timeframe"
        )
        raise
    except SubprocessControllerException as e:
        logger.error(f"Failed to start transient '{name}':")
        for (k, v) in properties:
            logger.error(f"    {k}={v}")
        logger.error(f"More useful details might be found in the service's log by running 'journalctl -u {name}'")
        raise SubprocessControllerException(f"Failed to start systemd transient service '{name}': {e}") from e


def start_transient_kresd_unit(config: KresConfig, type_: SystemdType, kres_id: KresID) -> None:
    properties = {
        SubprocessType.KRESD: _kresd_unit_properties(config, kres_id, type_),
        SubprocessType.GC: _gc_unit_properties(config, type_),
    }[kres_id.subprocess_type]
    name = str(kres_id)

    _start_transient_unit(type_, name, properties)


def start_slice(systemd_type: SystemdType) -> None:
    _start_transient_unit(systemd_type, _slice_name(systemd_type), _kres_slice_properties())


def stop_slice(systemd_type: SystemdType) -> None:
    stop_unit(systemd_type, _slice_name(systemd_type))


def list_our_slice_processes(systemd_type: SystemdType) -> Set[str]:
    return _list_slice_services(systemd_type, _slice_name(systemd_type))


@_wrap_dbus_errors
def start_unit(type_: SystemdType, unit_name: str) -> None:
    systemd = _create_manager_proxy(type_)

    def job() -> Any:
        return systemd.StartUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)


@_wrap_dbus_errors
def stop_unit(type_: SystemdType, unit_name: str) -> None:
    systemd = _create_manager_proxy(type_)

    def job() -> Any:
        return systemd.StopUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)


@_wrap_dbus_errors
def list_unit_files(type_: SystemdType) -> List[str]:
    systemd = _create_manager_proxy(type_)
    files = systemd.ListUnitFiles()
    return [str(x[0]) for x in files]


@_wrap_dbus_errors
def is_unit_failed(typ: SystemdType, unit_name: str) -> bool:
    systemd = _create_manager_proxy(typ)
    unit_path = systemd.LoadUnit(unit_name)
    unit_object = _create_object_proxy(typ, ".systemd1", unit_path)
    return unit_object.ActiveState == "failed"


@_wrap_dbus_errors
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
