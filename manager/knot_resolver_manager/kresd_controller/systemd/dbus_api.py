# pyright: reportUnknownMemberType=false
# pyright: reportMissingTypeStubs=false

import logging
import os
import re
from enum import Enum, auto
from threading import Thread
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

from gi.repository import GLib  # type: ignore[import]
from pydbus import SystemBus  # type: ignore[import]
from pydbus.bus import SessionBus  # type: ignore[import]
from typing_extensions import Literal

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.constants import kres_gc_executable, kresd_cache_dir, kresd_config_file, kresd_executable
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.exceptions import SubprocessControllerException
from knot_resolver_manager.kres_id import KresID
from knot_resolver_manager.kresd_controller.interface import SubprocessType

logger = logging.getLogger(__name__)

_PREFIX = "mkres"
GC_SERVICE_NAME = f"{_PREFIX}_cache_gc.service"
KRESD_SERVICE_PATTERN = re.compile(rf"^{_PREFIX}d_([0-9]+).service$")


def kres_id_from_service_name(service_name: str) -> KresID:
    kid = KRESD_SERVICE_PATTERN.search(service_name)
    if kid:
        return KresID.from_string(kid.groups()[0])
    return KresID.from_string(service_name)


def service_name_from_kres_id(kid: KresID) -> str:
    rep = str(kid)
    if rep.isnumeric():
        return f"{_PREFIX}d_{rep}.service"
    return rep


def is_service_name_ours(service_name: str) -> bool:
    is_ours = service_name == GC_SERVICE_NAME
    is_ours |= bool(KRESD_SERVICE_PATTERN.match(service_name))
    return is_ours


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


def _wait_for_job_completion(systemd: Any, job_creating_func: Callable[[], str]) -> None:
    """
    Takes a function returning a systemd job path, executes it while simultaneously waiting
    for its completion. This prevents race conditions.
    """

    result_state: Optional[str] = None
    job_path: Optional[str] = None

    def _wait_for_job_completion_handler(loop: Any) -> Any:
        completed_jobs: Dict[str, str] = {}

        def event_hander(_job_id: Any, path: Any, _unit: Any, state: Any) -> None:
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

    def event_loop_isolation_thread() -> None:
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
def restart_unit(type_: SystemdType, unit_name: str) -> None:
    systemd = _create_manager_proxy(type_)

    def job():
        return systemd.RestartUnit(unit_name, "fail")

    _wait_for_job_completion(systemd, job)


def _kresd_unit_properties(config: KresConfig, kres_id: KresID) -> List[Tuple[str, str]]:
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
    ]

    if config.server.watchdog:
        val.append(
            ("WatchdogUSec", GLib.Variant("t", 10000000)),
        )

    return val


def _gc_unit_properties(config: KresConfig) -> Any:
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
    ]
    return val


@_wrap_dbus_errors
def start_transient_kresd_unit(
    config: KresConfig, type_: SystemdType, kres_id: KresID, subprocess_type: SubprocessType
) -> None:
    name, properties = {
        SubprocessType.KRESD: (service_name_from_kres_id(kres_id), _kresd_unit_properties(config, kres_id)),
        SubprocessType.GC: (service_name_from_kres_id(kres_id), _gc_unit_properties(config)),
    }[subprocess_type]

    systemd = _create_manager_proxy(type_)

    def job():
        return systemd.StartTransientUnit(name, "fail", properties, [])

    try:
        _wait_for_job_completion(systemd, job)
    except SubprocessControllerException as e:
        logger.error(f"Failed to start transient '{name}':")
        for (k, v) in properties:
            logger.error(f"    {k}={v}")
        logger.error(f"More useful details might be found in the service's log by running 'journalctl -u {name}'")
        raise SubprocessControllerException(f"Failed to start systemd transient service '{name}'") from e


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
