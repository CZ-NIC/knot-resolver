from __future__ import annotations

import logging
import os
import shutil
import xmlrpc.client
from pathlib import Path
from typing import TYPE_CHECKING

import supervisor.xmlrpc

from knot_resolver.config.templates import SUPERVISORD_TEMPLATE
from knot_resolver.logging import get_logger

from .config import SUPERVISORD_CONFIGFILE_NAME, SUPERVISORD_CONFIGFILE_NAME_TMP, SubprocessConfig, SupervisordConfig
from .errors import ControllerError

if TYPE_CHECKING:
    from knot_resolver.args import KresArgs

logger = get_logger(__name__)


class SupervisordController:
    def __init__(self, args: KresArgs) -> None:
        # TODO(amrazek): add declarative configuration
        # self._config = config
        self._args = args

    def write_config(self) -> None:
        logger.debug("Creating supervisord configuration")

        config: str = SUPERVISORD_TEMPLATE.render(
            supervisord=SupervisordConfig.create(self._args),
            manager=SubprocessConfig.create_manager(self._args),
            worker=SubprocessConfig.create_worker(self._args),
            loader=SubprocessConfig.create_loader(self._args),
            cache_gc=SubprocessConfig.create_cache_gc(self._args),
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
            os.execv(supervisord, args)  # noqa: S606
        except OSError as e:
            msg = f"supervisord exec failed: {e}"
            raise ControllerError(msg) from e
