import os
from typing import List

from jinja2 import Template

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.constants import (
    kres_gc_executable,
    kresd_cache_dir,
    kresd_config_file,
    kresd_executable,
    supervisord_config_file,
    supervisord_config_file_tmp,
    supervisord_log_file,
    supervisord_pid_file,
    supervisord_sock_file,
    supervisord_subprocess_log_dir,
)
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.kresd_controller.interface import KresID, SubprocessType
from knot_resolver_manager.utils.async_utils import read_resource, writefile


class SupervisordKresID(KresID):
    # WARNING: be really careful with renaming. If the naming schema is changing,
    # we should be able to parse the old one as well, otherwise updating manager will
    # cause weird behavior

    @staticmethod
    def from_string(val: str) -> "SupervisordKresID":
        if val == "gc":
            return SupervisordKresID.new(SubprocessType.GC, -1)
        else:
            val = val.replace("kresd", "")
            return SupervisordKresID.new(SubprocessType.KRESD, int(val))

    def __str__(self) -> str:
        if self.subprocess_type is SubprocessType.GC:
            return "gc"
        elif self.subprocess_type is SubprocessType.KRESD:
            return f"kresd{self._id}"
        else:
            raise RuntimeError(f"Unexpected subprocess type {self.subprocess_type}")


def _get_command_based_on_type(config: KresConfig, i: "SupervisordKresID") -> str:
    if i.subprocess_type is SubprocessType.KRESD:
        return f"{kresd_executable()} -c {kresd_config_file(config, i)} -n"
    elif i.subprocess_type is SubprocessType.GC:
        return f"{kres_gc_executable()} -c {kresd_cache_dir(config)} -d 1000"
    else:
        raise NotImplementedError("This subprocess type is not supported")


@dataclass
class _Instance:
    """
    Data structure holding data for supervisord config template
    """

    type: str
    logfile: str
    id: str
    workdir: str
    command: str
    environment: str

    @staticmethod
    def create_list(config: KresConfig) -> List["_Instance"]:
        cwd = str(os.getcwd())

        instances = [
            SupervisordKresID(SubprocessType.KRESD, i, _i_know_what_i_am_doing=True)
            for i in range(1, int(config.max_workers) + 1)
        ] + [SupervisordKresID(SubprocessType.GC, -1, _i_know_what_i_am_doing=True)]

        return [
            _Instance(  # type: ignore[call-arg]
                type=i.subprocess_type.name,
                logfile=supervisord_subprocess_log_dir(config) / f"{i}.log",
                id=str(i),
                workdir=cwd,
                command=_get_command_based_on_type(config, i),
                environment=f"SYSTEMD_INSTANCE={i}",
            )
            for i in instances
        ]


@dataclass
class SupervisordConfig:
    unix_http_server: str
    pid_file: str
    workdir: str
    logfile: str

    @staticmethod
    def create(config: KresConfig) -> "SupervisordConfig":
        cwd = str(os.getcwd())
        return SupervisordConfig(  # type: ignore[call-arg]
            unix_http_server=supervisord_sock_file(config),
            pid_file=supervisord_pid_file(config),
            workdir=cwd,
            logfile=supervisord_log_file(config),
        )


async def write_config_file(config: KresConfig) -> None:
    if not supervisord_subprocess_log_dir(config).exists():
        supervisord_subprocess_log_dir(config).mkdir(exist_ok=True)

    template = await read_resource(__package__, "supervisord.conf.j2")
    assert template is not None
    template = template.decode("utf8")
    config_string = Template(template).render(  # pyright: reportUnknownMemberType=false
        instances=_Instance.create_list(config),
        config=SupervisordConfig.create(config),
    )
    await writefile(supervisord_config_file_tmp(config), config_string)
    # atomically replace (we don't technically need this right now, but better safe then sorry)
    os.rename(supervisord_config_file_tmp(config), supervisord_config_file(config))
