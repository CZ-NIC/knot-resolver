import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from jinja2 import Template

from knot_resolver.constants import APPLE_SYS, KRES_CACHE_GC_EXECUTABLE, KRESD_EXECUTABLE, LINUX_SYS
from knot_resolver.controller.interface import KresID, SubprocessType
from knot_resolver.datamodel.config_schema import KresConfig, workers_max_count
from knot_resolver.datamodel.logging_schema import LogTargetEnum
from knot_resolver.manager.constants import (
    kres_cache_dir,
    kresd_config_file_supervisord_pattern,
    policy_loader_config_file,
    supervisord_config_file,
    supervisord_config_file_tmp,
    supervisord_pid_file,
    supervisord_sock_file,
    supervisord_subprocess_log_dir,
    user_constants,
)
from knot_resolver.utils.async_utils import read_resource, writefile

logger = logging.getLogger(__name__)


class SupervisordKresID(KresID):
    # WARNING: be really careful with renaming. If the naming schema is changing,
    # we should be able to parse the old one as well, otherwise updating manager will
    # cause weird behavior

    @staticmethod
    def from_string(val: str) -> "SupervisordKresID":
        # the double name is checked because thats how we read it from supervisord
        if val in ("cache-gc", "cache-gc:cache-gc"):
            return SupervisordKresID.new(SubprocessType.GC, 0)
        if val in ("policy-loader", "policy-loader:policy-loader"):
            return SupervisordKresID.new(SubprocessType.POLICY_LOADER, 0)
        val = val.replace("kresd:kresd", "")
        return SupervisordKresID.new(SubprocessType.KRESD, int(val))

    def __str__(self) -> str:
        if self.subprocess_type is SubprocessType.GC:
            return "cache-gc"
        if self.subprocess_type is SubprocessType.POLICY_LOADER:
            return "policy-loader"
        if self.subprocess_type is SubprocessType.KRESD:
            return f"kresd:kresd{self._id}"
        raise RuntimeError(f"Unexpected subprocess type {self.subprocess_type}")


def kres_cache_gc_args(config: KresConfig) -> str:
    args = ""

    if config.logging.level == "debug" or (config.logging.groups and "cache-gc" in config.logging.groups):
        args += " -v"

    gc_config = config.cache.garbage_collector
    args += (
        f" -d {gc_config.interval.millis()}"
        f" -u {gc_config.threshold}"
        f" -f {gc_config.release}"
        f" -l {gc_config.rw_deletes}"
        f" -L {gc_config.rw_reads}"
        f" -t {gc_config.temp_keys_space.mbytes()}"
        f" -m {gc_config.rw_duration.micros()}"
        f" -w {gc_config.rw_delay.micros()}"
    )
    if gc_config.dry_run:
        args += " -n"
    return args


@dataclass
class ProcessTypeConfig:
    """
    Data structure holding data for supervisord config template
    """

    logfile: Path
    workdir: str
    command: str
    startsecs: int
    environment: str
    max_procs: int = 1

    @staticmethod
    def create_gc_config(config: KresConfig) -> "ProcessTypeConfig":
        cwd = str(os.getcwd())
        return ProcessTypeConfig(  # type: ignore[call-arg]
            logfile=supervisord_subprocess_log_dir(config) / "gc.log",
            workdir=cwd,
            command=f"{KRES_CACHE_GC_EXECUTABLE} -c {kres_cache_dir(config)}{kres_cache_gc_args(config)}",
            startsecs=0,
            environment="",
        )

    @staticmethod
    def create_policy_loader_config(config: KresConfig) -> "ProcessTypeConfig":
        cwd = str(os.getcwd())
        return ProcessTypeConfig(  # type: ignore[call-arg]
            logfile=supervisord_subprocess_log_dir(config) / "policy-loader.log",
            workdir=cwd,
            command=f"{KRESD_EXECUTABLE} -c {(policy_loader_config_file(config))} -c - -n",
            startsecs=0,
            environment="",
        )

    @staticmethod
    def create_kresd_config(config: KresConfig) -> "ProcessTypeConfig":
        cwd = str(os.getcwd())
        startsecs = 3
        environment = 'SYSTEMD_INSTANCE="%(process_num)d"'

        if LINUX_SYS:
            # Wait for NOTIFY message
            startsecs = 60
            environment += ",X-SUPERVISORD-TYPE=notify"
        if APPLE_SYS:
            # There is no need to wait for anything on macOS
            # No NOTIFY message and only 1 kresd worker
            startsecs = 0

        return ProcessTypeConfig(  # type: ignore[call-arg]
            logfile=supervisord_subprocess_log_dir(config) / "kresd%(process_num)d.log",
            workdir=cwd,
            command=f"{KRESD_EXECUTABLE} -c {kresd_config_file_supervisord_pattern(config)} -n",
            startsecs=startsecs,
            environment=environment,
            max_procs=int(workers_max_count()) + 1,  # +1 for the canary process
        )

    @staticmethod
    def create_manager_config(_config: KresConfig) -> "ProcessTypeConfig":
        if LINUX_SYS:
            # read original command from /proc
            with open("/proc/self/cmdline", "rb") as f:
                args = [s.decode("utf-8") for s in f.read()[:-1].split(b"\0")]
        else:
            # other systems
            args = [sys.executable] + sys.argv

        # insert debugger when asked
        if os.environ.get("KRES_DEBUG_MANAGER"):
            logger.warning("Injecting debugger into the supervisord config")
            # the args array looks like this:
            # [PYTHON_PATH, "-m", "knot_resolver", ...]
            args = args[:1] + ["-m", "debugpy", "--listen", "0.0.0.0:5678", "--wait-for-client"] + args[2:]

        cmd = '"' + '" "'.join(args) + '"'
        environment = "KRES_SUPRESS_LOG_PREFIX=true"
        if LINUX_SYS:
            environment += ",X-SUPERVISORD-TYPE=notify"

        return ProcessTypeConfig(  # type: ignore[call-arg]
            workdir=user_constants().working_directory_on_startup,
            command=cmd,
            startsecs=600 if LINUX_SYS else 0,
            environment=environment,
            logfile=Path(""),  # this will be ignored
        )


@dataclass
class SupervisordConfig:
    unix_http_server: Path
    pid_file: Path
    workdir: str
    logfile: Path
    loglevel: Literal["critical", "error", "warn", "info", "debug", "trace", "blather"]
    target: LogTargetEnum
    linux_sys: bool

    @staticmethod
    def create(config: KresConfig) -> "SupervisordConfig":
        # determine the correct logging level
        if config.logging.groups and "supervisord" in config.logging.groups:
            loglevel = "info"
        else:
            loglevel = {
                "crit": "critical",
                "err": "error",
                "warning": "warn",
                "notice": "warn",
                "info": "info",
                "debug": "debug",
            }[config.logging.level]
        cwd = str(os.getcwd())
        return SupervisordConfig(  # type: ignore[call-arg]
            unix_http_server=supervisord_sock_file(config),
            pid_file=supervisord_pid_file(config),
            workdir=cwd,
            logfile=Path("syslog" if config.logging.target == "syslog" else "/dev/null"),
            loglevel=loglevel,  # type: ignore[arg-type]
            target=config.logging.target,
            linux_sys=LINUX_SYS,
        )


async def write_config_file(config: KresConfig) -> None:
    if not supervisord_subprocess_log_dir(config).exists():
        supervisord_subprocess_log_dir(config).mkdir(exist_ok=True)

    template = await read_resource(__package__, "supervisord.conf.j2")
    assert template is not None
    template = template.decode("utf8")
    config_string = Template(template).render(
        gc=ProcessTypeConfig.create_gc_config(config),
        loader=ProcessTypeConfig.create_policy_loader_config(config),
        kresd=ProcessTypeConfig.create_kresd_config(config),
        manager=ProcessTypeConfig.create_manager_config(config),
        config=SupervisordConfig.create(config),
    )
    await writefile(supervisord_config_file_tmp(config), config_string)
    # atomically replace (we don't technically need this right now, but better safe then sorry)
    os.rename(supervisord_config_file_tmp(config), supervisord_config_file(config))
