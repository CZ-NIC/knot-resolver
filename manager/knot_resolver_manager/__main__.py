from aiohttp import web
from knot_resolver_manager.kresd_manager import KresdManager

from . import confmodel

_SOCKET_PATH = "/tmp/manager.sock"


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
    app["kresd_manager"] = manager

    async def init_manager(app):
        await app["kresd_manager"].load_system_state()

    app.on_startup.append(init_manager)

    # configure routing
    app.add_routes([web.get("/", hello), web.post("/config", apply_config)])

    # run forever
    web.run_app(app, path=_SOCKET_PATH)


if __name__ == "__main__":
    main()
