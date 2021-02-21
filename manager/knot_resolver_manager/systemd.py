from typing import List, Union
import dbus
from typing_extensions import Literal


def _create_manager_interface():
    bus = dbus.SystemBus()
    systemd = bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")

    manager = dbus.Interface(systemd, "org.freedesktop.systemd1.Manager")

    return manager


def get_unit_file_state(
    unit_name: str,
) -> Union[Literal["disabled"], Literal["enabled"]]:
    res = str(_create_manager_interface().GetUnitFileState(unit_name))
    assert res == "disabled" or res == "enabled"
    return res


def list_units() -> List[str]:
    return [str(u[0]) for u in _create_manager_interface().ListUnits()]


def list_jobs():
    return _create_manager_interface().ListJobs()


def restart_unit(unit_name: str):
    return _create_manager_interface().RestartUnit(unit_name, "fail")
