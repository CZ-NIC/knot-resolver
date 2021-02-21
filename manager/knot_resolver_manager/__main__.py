from aiohttp import web
from knot_resolver_manager.kresd_manager import KresdManager

from . import confmodel
from . import compat


async def hello(_request: web.Request) -> web.Response:
    return web.Response(text="Hello, world")


async def apply_config(request: web.Request) -> web.Response:
    config = await confmodel.parse(await request.text())
    manager: KresdManager = request.app["kresd_manager"]
    await manager.apply_config(config)
    return web.Response(text="OK")


def main():
    app = web.Application()

    # initialize KresdManager
    manager = KresdManager()
    compat.asyncio_run(manager.load_system_state())
    app["kresd_manager"] = manager

    # configure routing
    app.add_routes([web.get("/", hello), web.post("/config", apply_config)])

    # run forever
    web.run_app(app, path="./manager.sock")


if __name__ == "__main__":
    main()
