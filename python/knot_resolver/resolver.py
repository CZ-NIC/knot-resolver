from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .constants import RUN_DIR
from .controller import SupervisordController
from .controller.errors import ControllerError
from .logging import get_logger

if TYPE_CHECKING:
    from .args import KresArgs

logger = get_logger(__name__)


def start_resolver(args: KresArgs) -> None:
    logger.notice("Starting Knot Resolver...")

    # Ensure that configuration files paths do not change
    # even when the working directory is changed.
    _config_paths = [Path(file).absolute() for file in args.config]

    # TODO(amrazek): load/parse/validate configuration here

    # TODO(amrazek): use 'rundir' from configuration
    logger.debug("Changing working directory to '%s'", RUN_DIR)
    os.chdir(RUN_DIR)

    try:
        controller = SupervisordController(args)
        controller.write_config()
        controller.exec()
    except ControllerError as e:
        logger.critical(e)
        sys.exit(1)
