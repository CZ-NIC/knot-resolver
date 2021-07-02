import logging
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import click

from knot_resolver_manager import compat
from knot_resolver_manager.constants import LISTEN_SOCKET_PATH, LOG_LEVEL, MANAGER_CONFIG_FILE
from knot_resolver_manager.kresd_controller import list_controller_names
from knot_resolver_manager.server import start_server
from knot_resolver_manager.utils import ignore_exceptions_optional


@click.command()
@click.argument("listen", type=str, nargs=1, required=False, default=None)
@click.option(
    "--config",
    "-c",
    type=str,
    nargs=1,
    required=False,
    default=None,
    help="Overrides default config location at '" + str(MANAGER_CONFIG_FILE) + "'",
)
@click.option(
    "--backend",
    "-b",
    type=str,
    nargs=1,
    required=False,
    default=None,
    help="Use specified subprocess controller, default auto detection",
)
@click.option("--list-backends", "-l", type=bool, is_flag=True, default=False)
def main(listen: Optional[str], config: Optional[str], backend: Optional[str], list_backends: bool):
    # pylint: disable=expression-not-assigned

    """Knot Resolver Manager

    [listen] ... numeric port or a path for a Unix domain socket, default is """ + str(
        MANAGER_CONFIG_FILE
    )

    # print list of backends and exit (if specified)
    if list_backends:
        click.echo("Available subprocess controllers are:")
        for n in list_controller_names():
            click.echo(f" - {n}")
        sys.exit(0)

    # determine where should the manager listen based on the given argument
    tcp: List[Tuple[str, int]] = []
    unix: List[Path] = []
    if listen is None:
        unix.append(LISTEN_SOCKET_PATH)
    else:
        port = ignore_exceptions_optional(int, None, ValueError)(int)(listen)
        if port is not None:
            tcp.append(("localhost", port))
        else:
            unix.append(Path(listen))

    # where to look for config
    config_path = MANAGER_CONFIG_FILE if config is None else Path(config)

    compat.asyncio.run(start_server(tcp=tcp, unix=unix, config=config_path, subprocess_controller_name=backend))


if __name__ == "__main__":
    logging.basicConfig(level=LOG_LEVEL)
    main()  # pylint: disable=no-value-for-parameter
