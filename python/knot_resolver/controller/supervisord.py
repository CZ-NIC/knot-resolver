# ruff: noqa: N802
# mypy: disable-error-code=import-untyped

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast
from xmlrpc.client import Fault, ServerProxy

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from supervisor.xmlrpc import SupervisorTransport

from knot_resolver.logging import get_logger

from .config import (
    SUPERVISORD_CONFIGFILE_NAME,
    SUPERVISORD_CONFIGFILE_NAME_TMP,
    SUPERVISORD_SOCKET_NAME,
    SubprocessConfig,
    SupervisordConfig,
)
from .exceptions import ControllerError
from .subprocess import Subprocess, SubprocessID, SubprocessStatus, SubprocessType

if TYPE_CHECKING:
    from typing import Any

    from knot_resolver.args import KresArgs
    from knot_resolver.datamodel import KresConfig

    class SupervisorRPC(Protocol):
        def getState(self) -> dict[str, Any]: ...
        def getAllProcessInfo(self) -> list[dict[str, Any]]: ...
        def getProcessInfo(self, name: str) -> dict[str, Any]: ...
        def startProcess(self, name: str, wait: bool = True) -> bool: ...
        def stopProcess(self, name: str, wait: bool = True) -> bool: ...
        def shutdown(self) -> bool: ...


logger = get_logger(__name__)


def _create_server_proxy() -> ServerProxy:
    serverurl = "unix://" + str(Path(SUPERVISORD_SOCKET_NAME).absolute())
    transport = SupervisorTransport(
        username=None,
        password=None,
        serverurl=serverurl,
    )
    return ServerProxy("http://localhost", transport=transport)


def _create_supervisord_proxy() -> SupervisorRPC:
    server_proxy = _create_server_proxy()
    return cast("SupervisorRPC", server_proxy.supervisor)


class SupervisordController:
    def __init__(self, args: KresArgs, config: KresConfig) -> None:
        self._args = args
        self._config = config

    def get_proxy(self) -> SupervisorRPC:
        return _create_supervisord_proxy()

    def write_config(self) -> None:
        logger.info("Creating supervisord controller configuration...")

        ldr = FileSystemLoader(Path(__file__).resolve().parent)
        env = Environment(trim_blocks=True, lstrip_blocks=True, loader=ldr, undefined=StrictUndefined)
        template = env.get_template("supervisord.conf.j2")

        config: str = template.render(
            supervisord=SupervisordConfig.create(self._args, self._config),
            manager=SubprocessConfig.create_manager(self._args, self._config),
            worker=SubprocessConfig.create_worker(self._args, self._config),
            loader=SubprocessConfig.create_loader(self._args, self._config),
            cache_gc=SubprocessConfig.create_cache_gc(self._args, self._config),
        )

        config_path_tmp = Path(SUPERVISORD_CONFIGFILE_NAME_TMP).absolute()
        config_path_tmp.write_text(config, encoding="utf-8")
        config_path_tmp.rename(SUPERVISORD_CONFIGFILE_NAME)

    def exec(self) -> None:
        supervisord = shutil.which("supervisord")
        if not supervisord:
            msg = "failed to find 'supervisord' executable"
            raise ControllerError(msg)

        config_path = Path(SUPERVISORD_CONFIGFILE_NAME).absolute()
        if not config_path.exists():
            msg = f"failed to find supervisord configuration file '{config_path}'"
            raise ControllerError(msg)

        args = (
            str(supervisord),
            "--configuration",
            str(config_path),
        )

        logger.notice("Execing supervisord controller...")
        logging.shutdown()

        try:
            os.execv(supervisord, args)
        except OSError as e:
            msg = f"supervisord controller exec failed: {e}"
            raise ControllerError(msg) from e

    async def create_subprocess(self, subprocess_type: SubprocessType) -> Subprocess:
        return Subprocess(subprocess_type, self)

    def _get_all_subprocess_info(self) -> list[dict[str, Any]]:
        supervisord = self.get_proxy()
        return supervisord.getAllProcessInfo()

    async def get_all_subprocess_status(self) -> dict[SubprocessID, SubprocessStatus]:
        subprocesses_info = self._get_all_subprocess_info()

        statuses: dict[SubprocessID, SubprocessStatus] = {}
        for info in subprocesses_info:
            status = SubprocessStatus(cast("int", info["state"]))
            # filter 'not started' processes
            if status is not SubprocessStatus.STOPPED:
                statuses[SubprocessID.from_name(cast("str", info["name"]))] = status
        return statuses

    async def shutdown(self) -> None:
        supervisord = self.get_proxy()

        try:
            supervisord.shutdown()
        except Fault as exc:
            if (exc.faultCode, exc.faultString) != (6, "SHUTDOWN_STATE"):
                raise

        config_path = Path(SUPERVISORD_CONFIGFILE_NAME)
        await asyncio.to_thread(config_path.unlink, missing_ok=True)
