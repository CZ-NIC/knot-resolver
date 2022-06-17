import os

from jinja2 import Template

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.constants import (
    kres_gc_executable,
    kresd_cache_dir,
    kresd_config_file_supervisord_pattern,
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


@dataclass
class ProcessTypeConfig:
    """
    Data structure holding data for supervisord config template
    """

    logfile: str
    workdir: str
    command: str
    environment: str
    max_procs: int = 1

    @staticmethod
    def create_gc_config(config: KresConfig) -> "ProcessTypeConfig":
        cwd = str(os.getcwd())
        return ProcessTypeConfig(  # type: ignore[call-arg]
            logfile=supervisord_subprocess_log_dir(config) / "gc.log",
            workdir=cwd,
            command=f"{kres_gc_executable()} -c {kresd_cache_dir(config)} -d 1000",
            environment="",
        )

    @staticmethod
    def create_kresd_config(config: KresConfig) -> "ProcessTypeConfig":
        cwd = str(os.getcwd())
        return ProcessTypeConfig(  # type: ignore[call-arg]
            logfile=supervisord_subprocess_log_dir(config) / "kresd%(process_num)d.log",
            workdir=cwd,
            command=f"{kresd_executable()} -c {kresd_config_file_supervisord_pattern(config)} -n",
            environment='SYSTEMD_INSTANCE="%(process_num)d",X-SUPERVISORD-TYPE=notify',
            max_procs=config.max_workers,
        )


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
        gc=ProcessTypeConfig.create_gc_config(config),
        kresd=ProcessTypeConfig.create_kresd_config(config),
        config=SupervisordConfig.create(config),
    )
    await writefile(supervisord_config_file_tmp(config), config_string)
    # atomically replace (we don't technically need this right now, but better safe then sorry)
    os.rename(supervisord_config_file_tmp(config), supervisord_config_file(config))
