import logging
import os
import shutil
import xmlrpc.client
from pathlib import Path

import supervisor.xmlrpc

from .errors import ControllerError

logger = logging.getLogger(__name__)


class SupervisordController:
    def __init__(self) -> None:
        self._config = None

    def initialize(self) -> None:
        logger.info("Initializing supervisord...")
        logger.debug("Creating supervisord configuration")

    def exec(self) -> None:
        supervisord = shutil.which("supervisord")
        if not supervisord:
            msg = "failed to find 'supervisord' executable"
            raise ControllerError(msg)

        args = [
            "supervisord",
            "--configuration",
            str(Path("supervisord.conf").absolute()),
        ]

        logger.debug("Execing supervisord...")
        logging.shutdown()
        os.execv(supervisord, args)  # noqa: S606

    async def shutdown(self) -> None:
        pass

