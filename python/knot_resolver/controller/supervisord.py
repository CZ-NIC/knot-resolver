# mypy: disable-error-code=import-untyped

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, cast
from xmlrpc.client import Fault, ServerProxy

from supervisor.xmlrpc import SupervisorTransport

from knot_resolver.config import KresConfig
from knot_resolver.config.templates import SUPERVISORD_TEMPLATE
from knot_resolver.logging import get_logger

from .config import (
    SUPERVISORD_CONFIGFILE_NAME,
    SUPERVISORD_CONFIGFILE_NAME_TMP,
    SUPERVISORD_SOCK_NAME,
    SubprocessConfig,
    SupervisordConfig,
    get_absolute_path,
)
from .errors import ControllerError

if TYPE_CHECKING:
    from typing import Any, Protocol

    from knot_resolver.args import KresArgs

    class SupervisorRPC(Protocol):
        def getState(self) -> dict[str, Any]: ...
        def getAllProcessInfo(self) -> list[dict[str, Any]]: ...
        def getProcessInfo(self, name: str) -> dict[str, Any]: ...
        def startProcess(self, name: str, wait: bool = True) -> bool: ...
        def stopProcess(self, name: str, wait: bool = True) -> bool: ...
        def shutdown(self) -> bool: ...


logger = get_logger(__name__)


def _create_server_proxy(config: KresConfig) -> ServerProxy:
    # TODO(amrazek): get serverurl from configuration
    serverurl = "unix://" + str(get_absolute_path(SUPERVISORD_SOCK_NAME))
    transport = SupervisorTransport(
        username=None,
        password=None,
        serverurl=serverurl,
    )
    return ServerProxy("http://localhost", transport=transport)


def _create_supervisord_proxy(config: KresConfig) -> SupervisorRPC:
    server_proxy = _create_server_proxy(config)
    return cast(SupervisorRPC, server_proxy.supervisor)


class SupervisordController:
    def __init__(self, args: KresArgs, config: KresConfig) -> None:
        self._args = args
        self._config = config

    def get_proxy(self) -> SupervisorRPC:
        return _create_supervisord_proxy(self._config)

    def write_config(self) -> None:
        logger.notice("Creating supervisord controller configuration...")

        config: str = SUPERVISORD_TEMPLATE.render(
            supervisord=SupervisordConfig.create(self._args, self._config),
            manager=SubprocessConfig.create_manager(self._args, self._config),
            worker=SubprocessConfig.create_worker(self._args, self._config),
            loader=SubprocessConfig.create_loader(self._args, self._config),
            cache_gc=SubprocessConfig.create_cache_gc(self._args, self._config),
        )

        config_path_tmp = Path(SUPERVISORD_CONFIGFILE_NAME_TMP)
        with config_path_tmp.open("w") as file:
            file.write(config)
        config_path_tmp.rename(SUPERVISORD_CONFIGFILE_NAME)

    def exec(self) -> None:
        supervisord = shutil.which("supervisord")
        if not supervisord:
            msg = "failed to find 'supervisord' executable"
            raise ControllerError(msg)

        config_path = Path(SUPERVISORD_CONFIGFILE_NAME)
        if not config_path.exists():
            msg = f"failed to find supervisord configuration file '{config_path}'"
            raise ControllerError(msg)

        args = [
            str(supervisord),
            "--configuration",
            str(config_path),
        ]

        logger.notice("Execing supervisord...")
        logging.shutdown()

        try:
            os.execv(supervisord, args)
        except OSError as e:
            msg = f"supervisord exec failed: {e}"
            raise ControllerError(msg) from e

    async def shutdown(self) -> None:
        supervisord = self.get_proxy()

        try:
            supervisord.shutdown()
        except Fault as e:
            if e.faultCode == 6 and e.faultString == "SHUTDOWN_STATE":
                # already shutting down
                pass
            else:
                raise

        config_path = Path(SUPERVISORD_CONFIGFILE_NAME)
        config_path.unlink(missing_ok=True)
