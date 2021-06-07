import logging
from pathlib import Path
from typing import List, Optional, Tuple

import click

from knot_resolver_manager import compat
from knot_resolver_manager.constants import LISTEN_SOCKET_PATH, MANAGER_CONFIG_FILE
from knot_resolver_manager.server import start_server
from knot_resolver_manager.utils import ignore_exceptions


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
def main(listen: Optional[str], config: Optional[str]):
    # pylint: disable=expression-not-assigned

    """Knot Resolver Manager

    [listen] ... numeric port or a path for a Unix domain socket, default is """ + str(
        MANAGER_CONFIG_FILE
    )

    tcp: List[Tuple[str, int]] = []
    unix: List[Path] = []

    if listen is None:
        unix.append(LISTEN_SOCKET_PATH)
    else:
        port = ignore_exceptions(None, ValueError)(int)(listen)
        if port is not None:
            tcp.append(("localhost", port))
        else:
            unix.append(Path(listen))

    config_path = MANAGER_CONFIG_FILE if config is None else Path(config)

    compat.asyncio.run(start_server(tcp=tcp, unix=unix, config_path=config_path))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()  # pylint: disable=no-value-for-parameter
