from typing import Optional
from pathlib import Path
import sys

from aiohttp import web
import click

from .kres_manager import KresManager
from .utils import ignore_exceptions
from . import configuration

# when changing this, change the help message in main()
_SOCKET_PATH = "/tmp/manager.sock"


async def hello(_request: web.Request) -> web.Response:
    return web.Response(text="Hello, world")


async def apply_config(request: web.Request) -> web.Response:
    config = await configuration.parse_yaml(await request.text())
    manager: KresManager = request.app["kres_manager"]
    await manager.apply_config(config)
    return web.Response(text="OK")


@click.command()
@click.argument("listen", type=str, nargs=1, required=False, default=None)
def main(listen: Optional[str]):
    """Knot Resolver Manager

    [listen] ... numeric port or a path for a Unix domain socket, default is \"/tmp/manager.sock\"
    """

    app = web.Application()

    # initialize KresManager
    manager = KresManager()
    app["kres_manager"] = manager

    async def init_manager(app):
        await app["kres_manager"].load_system_state()

    app.on_startup.append(init_manager)

    # configure routing
    app.add_routes([web.get("/", hello), web.post("/config", apply_config)])

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
