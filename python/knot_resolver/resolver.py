from __future__ import annotations

import fcntl
import os
import signal
from pathlib import Path
from pwd import getpwuid
from typing import TYPE_CHECKING, Any

from .constants import USER
from .controller import get_best_controller_implementation
from .controller.exceptions import KresSubprocessControllerError, KresSubprocessControllerExec
from .datamodel.config_schema import KresConfig, get_rundir_without_validation
from .datamodel.globals import Context, set_global_validation_context
from .exceptions import KresError
from .logging import get_logger, reconfigure_logging
from .manager.server import load_raw_config
from .utils.modeling.parsing import data_combine

if TYPE_CHECKING:
    from .args import KresArgs

logger = get_logger(__name__)


async def start_resolver(args: KresArgs) -> int:
    logger.notice("Starting Knot Resolver...")

    # Block signals during initialization
    blocked_signals = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
    signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)

    # Check that we are running under the intended user
    current_user = getpwuid(os.getuid()).pw_name
    if current_user != USER:
        logger.warning(
            "Knot Resolver does not run as the default '%s' user, but as '%s' instead."
            " This may or may not affect the configuration validation and the proper functioning of the resolver.",
            USER,
            current_user,
        )
    # Check that we are not running as root
    if os.geteuid() == 0:
        logger.warning("It is not recommended to run under root privileges unless there is no other option.")

    try:
        config_files = [Path(config_file).absolute() for config_file in args.config]  # noqa: ASYNC240

        config_data: dict[str, Any] = {}
        for config_file in config_files:
            # warning about the different parent directories of each config file
            # compared to the first one which is used as the prefix path
            if config_files[0].parent != config_file.parent:
                logger.warning(
                    "The configuration file '%s' has a parent directory that is different"
                    " from '%s', which is used as the prefix for relative paths."
                    "This can cause issues with files that are configured with relative paths.",
                    config_file,
                    config_files[0]
                )

            # Preprocess config - load from file or in general take it to the last step before validation.
            config_raw = await load_raw_config(config_file)

            # combine data from all config files
            config_data = data_combine(config_data, config_raw)

        # before processing any configuration, set validation context
        #  - resolve_root: root against which all relative paths will be resolved
        #  - strict_validation: check for path existence during configuration validation
        #  - permissions_default: validate dirs/files rwx permissions against default user:group in constants
        set_global_validation_context(Context(config_files[0].parent, True, False))

        # Change current working directory
        rundir = get_rundir_without_validation(config_data).to_path()
        logger.debug("Changing working directory to '%s'.", rundir.absolute())
        os.chdir(rundir)

        # Validate configuration data
        config = KresConfig(config_data)

        # Reconfigure logging based on config
        reconfigure_logging(config)

        # We don't want more than one Knot Resolver in a single working directory.
        lock_path: Path = rundir / ".lock"
        lock = lock_path.open("w")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logger.error("Rundir already in use: %s", rundir.absolute())
            return 1

        # Start the controller
        controller = await get_best_controller_implementation(config)
        logger.info("Initializing controller...")
        await controller.initialize_controller(args, config)

    except KresSubprocessControllerExec as e:
        # if we caught this exception, some component wants to perform a reexec during startup. Most likely, it would
        # be a subprocess manager like supervisord, which wants to make sure the manager runs under supervisord in
        # the process tree. So now we stop everything, and exec what we are told to. We are assuming, that the thing
        # we'll exec will invoke us again.
        logger.info("Exec requested with arguments: %s", str(e.exec_args))

        # Unblock signals, this could actually terminate us straight away
        signal.pthread_sigmask(signal.SIG_UNBLOCK, blocked_signals)

        # Critical: make the lock FD survive exec()
        os.set_inheritable(lock.fileno(), True)

        # Finally exec what we were told to exec
        os.execl(*e.exec_args)

    except KresSubprocessControllerError as e:
        logger.error("Controller initialization failed: %s", e)
        return 1

    except KresError as e:
        logger.error(e)
        return 1

    except Exception:
        logger.exception("Uncaught generic exception during Knot Resolver startup...")
        return 1

    # Should not get here: controller should raise KresSubprocessControllerExec.
    logger.error("Controller did not raise KresSubprocessControllerExec")
    return 1
