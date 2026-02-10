from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from knot_resolver.config.templates import SUPERVISORD_TEMPLATE
from knot_resolver.logging import get_logger

from .config import SUPERVISORD_CONFIGFILE_NAME, SUPERVISORD_CONFIGFILE_NAME_TMP, SubprocessConfig, SupervisordConfig

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
        logger.debug("Execing supervisord...")
        logging.shutdown()
