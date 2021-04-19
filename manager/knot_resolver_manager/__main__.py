import logging
import sys
from pathlib import Path
from time import time
from typing import Optional

import click
from aiohttp import web

from .datamodel import KresConfig
from .kres_manager import KresManager
from .utils import ignore_exceptions

# when changing this, change the help message in main()
_SOCKET_PATH = "/tmp/manager.sock"
_MANAGER = "kres_manager"


logger = logging.getLogger(__name__)


async def index(_request: web.Request) -> web.Response:
    return web.Response(text="Knot Resolver Manager is running! The configuration endpoint is at /config")


async def apply_config(request: web.Request) -> web.Response:
    manager: KresManager = request.app[_MANAGER]
    if manager is None:
        # handle the case when the manager is not yet initialized
        return web.Response(
            status=503, headers={"Retry-After": "3"}, text="Knot Resolver Manager is not yet fully initialized"
        )

    # process the request
    config = KresConfig.from_json(await request.text())
    await manager.apply_config(config)
    return web.Response(text="OK")


@click.command()
@click.argument("listen", type=str, nargs=1, required=False, default=None)
@click.option("--config", "-c", type=str, nargs=1, required=False, default=None)
def main(listen: Optional[str], config: Optional[str]):
    """Knot Resolver Manager

    [listen] ... numeric port or a path for a Unix domain socket, default is \"/tmp/manager.sock\"
    """
    start_time = time()

    app = web.Application()

    # initialize KresManager
    app[_MANAGER] = None

    async def init_manager(app: web.Application):
        manager = await KresManager.create()
        app[_MANAGER] = manager
        if config is not None:
            # TODO Use config loaded from the file system
            pass
        end_time = time()
        logger.info(f"Manager fully initialized after {end_time - start_time} seconds")

    app.on_startup.append(init_manager)

    # configure routing
    app.add_routes([web.get("/", index), web.post("/config", apply_config)])

    # run forever, listen at the appropriate place
    maybe_port = ignore_exceptions(None, ValueError, TypeError)(int)(listen)
    if listen is None:
        web.run_app(app, path=_SOCKET_PATH)
    elif maybe_port is not None:
        web.run_app(app, port=maybe_port)
    elif Path(listen).parent.exists():
        web.run_app(app, path=listen)
    else:
        print(
            "Failed to parse LISTEN argument. Not an integer, not a valid path to a file in an existing directory.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
