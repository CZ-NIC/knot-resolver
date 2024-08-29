import logging
import logging.handlers
import os
import sys
from typing import Optional

from knot_resolver.constants import LOGGING_LEVEL_STARTUP
from knot_resolver.datamodel.config_schema import KresConfig
from knot_resolver.datamodel.logging_schema import LogTargetEnum
from knot_resolver.manager.config_store import ConfigStore, only_on_real_changes_update

logger = logging.getLogger(__name__)


def get_log_format(config: KresConfig) -> str:
    """
    Based on an environment variable $KRES_SUPRESS_LOG_PREFIX, returns the appropriate format string for logger.
    """

    if os.environ.get("KRES_SUPRESS_LOG_PREFIX") == "true":
        # In this case, we are running under supervisord and it's adding prefixes to our output
        return "[%(levelname)s] %(name)s: %(message)s"
    else:
        # In this case, we are running standalone during inicialization and we need to add a prefix to each line
        # by ourselves to make it consistent
        assert config.logging.target != "syslog"
        stream = ""
        if config.logging.target == "stderr":
            stream = " (stderr)"

        pid = os.getpid()
        return f"%(asctime)s manager[{pid}]{stream}: [%(levelname)s] %(name)s: %(message)s"


async def _set_log_level(config: KresConfig) -> None:
    levels_map = {
        "crit": "CRITICAL",
        "err": "ERROR",
        "warning": "WARNING",
        "notice": "WARNING",
        "info": "INFO",
        "debug": "DEBUG",
    }

    # when logging group is set to make us log with DEBUG
    if config.logging.groups and "manager" in config.logging.groups:
        target = "DEBUG"
    # otherwise, follow the standard log level
    else:
        target = levels_map[config.logging.level]

    # expect exactly one existing log handler on the root
    logger.warning(f"Changing logging level to '{target}'")
    logging.getLogger().setLevel(target)


async def _set_logging_handler(config: KresConfig) -> None:
    target: Optional[LogTargetEnum] = config.logging.target

    if target is None:
        target = "stdout"

    handler: logging.Handler
    if target == "syslog":
        handler = logging.handlers.SysLogHandler(address="/dev/log")
        handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    elif target == "stdout":
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(get_log_format(config)))
    elif target == "stderr":
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(get_log_format(config)))
    else:
        raise RuntimeError(f"Unexpected value '{target}' for log target in the config")

    root = logging.getLogger()

    # if we had a MemoryHandler before, we should give it the new handler where we can flush it
    if isinstance(root.handlers[0], logging.handlers.MemoryHandler):
        root.handlers[0].setTarget(handler)

    # stop the old handler
    root.handlers[0].flush()
    root.handlers[0].close()
    root.removeHandler(root.handlers[0])

    # configure the new handler
    root.addHandler(handler)


@only_on_real_changes_update(lambda config: config.logging)
async def _configure_logger(config: KresConfig) -> None:
    await _set_logging_handler(config)
    await _set_log_level(config)


async def logger_init(config_store: ConfigStore) -> None:
    await config_store.register_on_change_callback(_configure_logger)


def logger_startup() -> None:
    logging.getLogger().setLevel(LOGGING_LEVEL_STARTUP)
    err_handler = logging.StreamHandler(sys.stderr)
    err_handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
    logging.getLogger().addHandler(logging.handlers.MemoryHandler(10_000, logging.ERROR, err_handler))
