from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from knot_resolver.constants import CACHE_GC_EXECUTABLE, DAEMON_EXECUTABLE, MANAGER_EXECUTABLE, NOTIFY_SUPPORT

if TYPE_CHECKING:
    from knot_resolver.args import KresArgs
    from knot_resolver.datamodel import KresConfig
    from knot_resolver.datamodel.logging_schema import LogLevelEnum

SupervisordLogLevel = Literal["critical", "error", "warn", "info", "debug", "trace", "blather"]
SupervisordLogTarget = Literal["stdout", "stderr", "syslog"]

SUPERVISORD_SOCKET_NAME = "supervisord.sock"
SUPERVISORD_CONFIGFILE_NAME = "supervisord.conf"
SUPERVISORD_CONFIGFILE_NAME_TMP = f"{SUPERVISORD_CONFIGFILE_NAME}.tmp"
WORKER_CONFIGFILE_NAME = "worker%(process_num)d.conf"
LOADER_CONFIGFILE_NAME = "loader.conf"

X_TYPE_VAR_NAME = "X-SUPERVISORD-TYPE"
X_TYPE_NOTIFY = "notify"
INSTANCE_VAR_NAME = "SYSTEMD_INSTANCE"
ENVIRONMENT_TYPE_NOTIFY = f"{X_TYPE_VAR_NAME}={X_TYPE_NOTIFY}"
ENVIRONMENT_INSTANCE_NUM = f'{INSTANCE_VAR_NAME}="%(process_num)d"'

LOGLEVEL_MAP: dict[LogLevelEnum, SupervisordLogLevel] = {
    "crit": "critical",
    "err": "error",
    "warning": "warn",
    "notice": "warn",
    "info": "info",
    "debug": "debug",
}


@dataclass(frozen=True)
class SupervisordConfig:
    loglevel: SupervisordLogLevel
    logtarget: SupervisordLogTarget
    unix_http_server: Path

    @staticmethod
    def create(_args: KresArgs, config: KresConfig) -> SupervisordConfig:
        if config.logging.groups and "supervisord" in config.logging.groups:
            loglevel = "debug"
        else:
            loglevel: SupervisordLogLevel = LOGLEVEL_MAP[config.logging.level]

        return SupervisordConfig(
            loglevel=loglevel,
            logtarget=config.logging.target,
            unix_http_server=Path(SUPERVISORD_SOCKET_NAME).absolute(),
        )


@dataclass(frozen=True)
class SubprocessConfig:
    command: str
    startsecs: int = 0
    max_procs: int = 1
    environment: str = ""

    @staticmethod
    def create_manager(args: KresArgs, _config: KresConfig) -> SubprocessConfig:
        startsecs = 0

        environment = ""
        if NOTIFY_SUPPORT:
            startsecs = 600
            environment += f"{ENVIRONMENT_TYPE_NOTIFY}"

        command_args: tuple[str, ...] = (str(MANAGER_EXECUTABLE),)
        if not MANAGER_EXECUTABLE.exists():
            command_args = (
                str(shutil.which("python3")),
                "-m",
                "knot_resolver.manager",
            )

        command_args += (
            "--logtarget",
            args.logtarget,
            "--loglevel",
            args.loglevel,
            "--config",
            *map(str, args.config),
        )

        return SubprocessConfig(
            command=" ".join(command_args),
            environment=environment,
            startsecs=startsecs,
        )

    @staticmethod
    def create_worker(_args: KresArgs, _config: KresConfig) -> SubprocessConfig:
        max_procs = 1

        # Default for non-Linux systems without support for systemd NOTIFY message.
        # Therefore, we need to give the kresd workers a few seconds to start properly.
        environment = ENVIRONMENT_INSTANCE_NUM
        startsecs = 3

        if NOTIFY_SUPPORT:
            # There is support for systemd NOTIFY message.
            # Here, 'startsecs' serves as a timeout for waiting for notify message.
            environment += f",{ENVIRONMENT_TYPE_NOTIFY}"
            startsecs = 60

        config_path = Path(WORKER_CONFIGFILE_NAME).absolute()
        command_args: tuple[str, ...] = (str(DAEMON_EXECUTABLE), "--config", str(config_path), "-n")

        return SubprocessConfig(
            command=" ".join(command_args),
            environment=environment,
            startsecs=startsecs,
            max_procs=max_procs,
        )

    @staticmethod
    def create_loader(_args: KresArgs, _config: KresConfig) -> SubprocessConfig:
        config_path = Path(LOADER_CONFIGFILE_NAME).absolute()
        command_args: tuple[str, ...] = (str(DAEMON_EXECUTABLE), "--config", str(config_path), "-c", "-", "-n")

        return SubprocessConfig(
            command=" ".join(command_args),
        )

    @staticmethod
    def create_cache_gc(_args: KresArgs, config: KresConfig) -> SubprocessConfig:
        cache_dir = str(config.cache.storage)
        command_args: tuple[str, ...] = (str(CACHE_GC_EXECUTABLE), "-c", cache_dir)

        cache_gc_config = config.cache.garbage_collector
        command_args += (
            f"-d {cache_gc_config.interval.millis()}",
            f"-u {cache_gc_config.threshold}",
            f"-f {cache_gc_config.release}",
            f"-l {cache_gc_config.rw_deletes}",
            f"-L {cache_gc_config.rw_reads}",
            f"-t {cache_gc_config.temp_keys_space.mbytes()}",
            f"-m {cache_gc_config.rw_duration.micros()}",
            f"-w {cache_gc_config.rw_delay.micros()}",
        )
        if config.logging.level == "debug" or (config.logging.groups and "cache-gc" in config.logging.groups):
            command_args += ("-v",)
        if cache_gc_config.dry_run:
            command_args += ("-n",)

        return SubprocessConfig(
            command=" ".join(command_args),
        )
