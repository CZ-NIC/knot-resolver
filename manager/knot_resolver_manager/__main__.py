import logging
import sys
from pathlib import Path
from typing import Optional

import click

from knot_resolver_manager import compat
from knot_resolver_manager.constants import MANAGER_CONFIG_FILE, STARTUP_LOG_LEVEL
from knot_resolver_manager.kresd_controller import list_controller_names
from knot_resolver_manager.server import start_server


@click.command()
@click.option(
    "--config",
    "-c",
    type=str,
    nargs=1,
    required=False,
    default=None,
    help="Overrides default config location at '" + str(MANAGER_CONFIG_FILE) + "'",
)
@click.option("--list-backends", "-l", type=bool, is_flag=True, default=False)
def main(config: Optional[str], list_backends: bool):
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

    # where to look for config
    config_path = MANAGER_CONFIG_FILE if config is None else Path(config)

    compat.asyncio.run(start_server(config=config_path))


if __name__ == "__main__":
    logging.basicConfig(level=STARTUP_LOG_LEVEL)
    main()  # pylint: disable=no-value-for-parameter
