from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from knot_resolver.logging import get_logger

if TYPE_CHECKING:
    from knot_resolver.args import KresArgs

logger = get_logger(__name__)

CONFIG_NAME = "supervisord.conf"
CONFIG_NAME_TMP = f"{CONFIG_NAME}.tmp"


class SupervisordController:
    def __init__(self, args: KresArgs) -> None:
        # TODO(amrazek): add declarative configuration
        # self._config = config
        self._args = args

    def write_config(self) -> None:
        logger.debug("Creating supervisord configuration")

    def exec(self) -> None:
        logger.debug("Execing supervisord...")
        logging.shutdown()
