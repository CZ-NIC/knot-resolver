from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from knot_resolver.config import KresConfig
from knot_resolver.constants import (
    CACHE_DIR,
    CACHE_GC_EXECUTABLE,
    DAEMON_EXECUTABLE,
    MANAGER_EXECUTABLE,
    NOTIFY_SUPPORT,
)
from knot_resolver.logging import NO_PREFIX_FORMAT_ENV_VAR, get_logger

if TYPE_CHECKING:
    from knot_resolver.args import KresArgs

    SupervisordLogLevel = Literal["critical", "error", "warn", "info", "debug", "trace", "blather"]
    SupervisordLogTarget = Literal["stdout", "stderr", "syslog"]

#  files names
SUPERVISORD_SOCK_NAME = "supervisord.sock"
SUPERVISORD_PIDFILE_NAME = "supervisord.pid"
SUPERVISORD_CONFIGFILE_NAME = "supervisord.conf"
SUPERVISORD_CONFIGFILE_NAME_TMP = f"{SUPERVISORD_CONFIGFILE_NAME}.tmp"
WORKER_CONFIGFILE_NAME = "worker%(process_num)d.conf"
LOADER_CONFIGFILE_NAME = "loader.conf"

# logfiles/logdirs names
SUPERVISORD_LOGDIR_NAME = "logs"
SUPERVISORD_LOGFILE_NAME = "supervisord.log"
MANAGER_LOGFILE_NAME = "manager.log"
WORKER_LOGFILE_NAME = "worker%(process_num)d.log"
LOADER_LOGFILE_NAME = "loader.log"
CACHE_GC_LOGFILE_NAME = "cache_gc.log"

X_TYPE_VAR_NAME = "X-SUPERVISORD-TYPE"
X_TYPE_NOTIFY = "notify"
INSTANCE_VAR_NAME = "SYSTEMD_INSTANCE"
ENVIRONMENT_TYPE_NOTIFY = f"{X_TYPE_VAR_NAME}={X_TYPE_NOTIFY}"
ENVIRONMENT_INSTANCE_NUM = f'{INSTANCE_VAR_NAME}="%(process_num)d"'

logger = get_logger(__name__)


def get_absolute_path(path: str | Path | None = None) -> Path:
    return Path(path).absolute() if path else Path().absolute()


def get_workdir_path() -> Path:
    return get_absolute_path()


def get_logfile_path(logfile: str) -> Path:
    return get_absolute_path(SUPERVISORD_LOGDIR_NAME) / logfile


@dataclass
class SupervisordConfig:
    workdir: Path
    pidfile: Path
    logfile: Path
    loglevel: SupervisordLogLevel
    logtarget: SupervisordLogTarget
    unix_http_server: Path
    notify_support: bool = NOTIFY_SUPPORT

    @staticmethod
    def create(args: KresArgs, config: KresConfig) -> SupervisordConfig:
        return SupervisordConfig(
            workdir=get_workdir_path(),
            pidfile=get_absolute_path(SUPERVISORD_PIDFILE_NAME),
            logfile=get_logfile_path(SUPERVISORD_LOGFILE_NAME),
            loglevel="debug",  # TODO(amrazek): use logging level from KresConfig
            logtarget="stdout",  # TODO(amrazek): use logging target from KresConfig
            unix_http_server=get_absolute_path(
                SUPERVISORD_SOCK_NAME  # TODO(amrazek): use management API from KresConfig
            ),
        )


@dataclass
class SubprocessConfig:
    command: str
    workdir: Path
    logfile: Path
    startsecs: int = 0
    max_procs: int = 1
    environment: str = ""

    @staticmethod
    def create_manager(args: KresArgs, config: KresConfig) -> SubprocessConfig:
        startsecs = 0
        environment = f"{NO_PREFIX_FORMAT_ENV_VAR}=true"

        if NOTIFY_SUPPORT:
            startsecs = 600
            environment += f",{ENVIRONMENT_TYPE_NOTIFY}"

        if MANAGER_EXECUTABLE.exists():
            command_args = [str(MANAGER_EXECUTABLE)]
        if not MANAGER_EXECUTABLE.exists():
            command_args = [
                str(shutil.which("python3")),
                "-m",
                "knot_resolver.manager",
            ]

        command_args += [
            "--logtarget",
            args.logtarget,
            "--loglevel",
            args.loglevel,
            "--config",
            *args.config,
        ]

        return SubprocessConfig(
            command=" ".join(command_args),
            workdir=get_workdir_path(),
            environment=environment,
            startsecs=startsecs,
            logfile=get_logfile_path(MANAGER_LOGFILE_NAME),
        )

    @staticmethod
    def create_worker(args: KresArgs, config: KresConfig) -> SubprocessConfig:
        max_procs = 1

        # Default for non-Linux systems without support for systemd NOTIFY message.
        # Therefore, we need to give the kresd workers a few seconds to start properly.
        environment = ENVIRONMENT_INSTANCE_NUM
        startsecs = 3

        if NOTIFY_SUPPORT:
            # There is support for systemd NOTIFY message.
            # Here, 'startsecs' serves as a timeout for waiting for NOTIFY message.
            environment += f",{ENVIRONMENT_TYPE_NOTIFY}"
            startsecs = 60

        config_path = get_absolute_path(WORKER_CONFIGFILE_NAME)
        command_args: list[str] = [str(DAEMON_EXECUTABLE), "--config", str(config_path), "-n"]

        return SubprocessConfig(
            command=" ".join(command_args),
            workdir=get_workdir_path(),
            environment=environment,
            startsecs=startsecs,
            logfile=get_logfile_path(WORKER_LOGFILE_NAME),
            max_procs=max_procs,
        )

    @staticmethod
    def create_loader(args: KresArgs, config: KresConfig) -> SubprocessConfig:
        config_path = get_absolute_path(LOADER_CONFIGFILE_NAME)

        command_args: list[str] = [str(DAEMON_EXECUTABLE), "--config", str(config_path), "-c", "-", "-n"]

        return SubprocessConfig(
            command=" ".join(command_args),
            workdir=get_workdir_path(),
            logfile=get_logfile_path(LOADER_LOGFILE_NAME),
        )

    @staticmethod
    def create_cache_gc(args: KresArgs, config: KresConfig) -> SubprocessConfig:
        # TODO(amrazek): use cache_dir from KresConfig
        cache_dir = CACHE_DIR

        command_args: list[str] = [str(CACHE_GC_EXECUTABLE), "-c", str(cache_dir)]

        # TODO(amrazek): convert KresConfig to cache gc flags

        return SubprocessConfig(
            command=" ".join(command_args),
            workdir=get_workdir_path(),
            logfile=get_logfile_path(CACHE_GC_LOGFILE_NAME),
        )
