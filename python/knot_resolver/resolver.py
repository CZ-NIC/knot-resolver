from __future__ import annotations

import logging
from pathlib import Path

from .controller import SupervisordController
from .controller.errors import ControllerError
from .utils.modeling.errors import DataModelingError

logger = logging.getLogger(__name__)


def start_resolver(config: list[str]) -> int:
    logger.notice("Starting Knot Resolver...")

    try:
        # Ensure that configuration files paths do not change
        # even when the working directory is changed.
        config_paths = [Path(file).absolute() for file in config]

        logger.info("Loading configuration...")

        # load configuration here

        controller = SupervisordController()
        controller.initialize()
        controller.exec()

    except DataModelingError as e:
        logger.exception("")

    except ControllerError as e:
        logger.critical("")
