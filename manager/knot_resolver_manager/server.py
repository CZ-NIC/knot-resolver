import asyncio
import logging
from http import HTTPStatus
from pathlib import Path
from time import time
from typing import Any, List, Tuple

from aiohttp import web
from aiohttp.web import middleware

from knot_resolver_manager.constants import MANAGER_CONFIG_FILE
from knot_resolver_manager.utils.async_utils import readfile
from knot_resolver_manager.utils.dataclasses_parservalidator import ValidationException

from .datamodel import KresConfig
from .kres_manager import KresManager

_MANAGER = "kres_manager"
_SHUTDOWN_EVENT = "shutdown-event"

logger = logging.getLogger(__name__)


async def _index(_request: web.Request) -> web.Response:
    """
    Dummy index handler to indicate that the server is indeed running...
    """
    return web.Response(text="Knot Resolver Manager is running! The configuration endpoint is at /config")


async def _apply_config(request: web.Request) -> web.Response:
    """
    Route handler for changing resolver configuration
    """

    manager: KresManager = get_kres_manager(request.app)
    if manager is None:
        # handle the case when the manager is not yet initialized
        return web.Response(
            status=503, headers={"Retry-After": "3"}, text="Knot Resolver Manager is not yet fully initialized"
        )

    # parse the incoming data

    # JSON or not-set
    #
    # aiohttp docs https://docs.aiohttp.org/en/stable/web_reference.html#aiohttp.web.BaseRequest.content_type:
    #
    # "Returns value is 'application/octet-stream' if no Content-Type header present in HTTP headers according to
    #  RFC 2616"
    if request.content_type == "application/json" or request.content_type == "application/octet-stream":
        config = KresConfig.from_json(await request.text())
    elif "yaml" in request.content_type:
        config = KresConfig.from_yaml(await request.text())
    else:
        return web.Response(
            text="Unsupported content-type header. Use application/json or text/x-yaml",
            status=HTTPStatus.BAD_REQUEST,
        )

    # apply config
    await manager.apply_config(config)

    # return success
    return web.Response()


async def _stop(request: web.Request) -> web.Response:
    """
    Route handler for shutting down the server (and whole manager)
    """

    stop_server(request.app)
    return web.Response(text="Shutting down...")


@middleware
async def error_handler(request: web.Request, handler: Any):
    """
    Generic error handler for route handlers.

    If an exception is thrown during request processing, this middleware catches it
    and responds accordingly.
    """

    try:
        return await handler(request)
    except ValidationException as e:
        logger.error("Failed to parse given data in API request", exc_info=True)
        return web.Response(text=f"Schema validation failed: {e}", status=HTTPStatus.BAD_REQUEST)


def setup_routes(app: web.Application):
    app.add_routes([web.get("/", _index), web.post("/config", _apply_config), web.post("/stop", _stop)])


def stop_server(app: web.Application):
    app[_SHUTDOWN_EVENT].set()
    logger.info("Shutdown event triggered...")


def get_kres_manager(app: web.Application) -> KresManager:
    if _MANAGER not in app:
        raise ValueError("Accessing manager in an application where it was not defined")

    return app[_MANAGER]


async def start_server(tcp: List[Tuple[str, int]], unix: List[Path], config_path: Path = MANAGER_CONFIG_FILE):
    start_time = time()

    app = web.Application(middlewares=[error_handler])

    app[_MANAGER] = None
    app[_SHUTDOWN_EVENT] = asyncio.Event()

    async def init_manager(app: web.Application):
        """
        Called asynchronously when the application initializes.
        """
        # Create KresManager. This will perform autodetection of available service managers and
        # select the most appropriate to use
        manager = await KresManager.create()
        app[_MANAGER] = manager

        # Initial static configuration of the manager
        # optional step, could be skipped
        if config_path is not None:
            if not config_path.exists():
                logger.warning(
                    "Manager is configured to load config file at %s on startup, but the file does not exist.",
                    config_path,
                )
            else:
                initial_config = KresConfig.from_yaml(await readfile(config_path))
                await manager.apply_config(initial_config)

        logger.info("Process manager initialized...")

    app.on_startup.append(init_manager)

    # configure routing
    setup_routes(app)

    # run forever, listen at the appropriate place
    runner = web.AppRunner(app)
    await runner.setup()

    for host, port in tcp:
        site = web.TCPSite(runner, host, port)
        await site.start()
        logger.info(f"HTTP server started listening on http://{host}:{port} ===")
    for file in unix:
        file.parent.mkdir(exist_ok=True)
        site = web.UnixSite(runner, str(file))
        await site.start()
        logger.info(f"HTTP server started listening on on http+unix://{file} ===")

    # stop the server gracefully and cleanup everything
    logger.info(f"Manager fully initialized and running in {round(time() - start_time, 3)} seconds")
    await app[_SHUTDOWN_EVENT].wait()
    logger.info("Gracefull shutdown triggered. Cleaning up...")
    await runner.cleanup()
    await get_kres_manager(app).stop()
    logger.info(f"The manager run for {round(time() - start_time)} seconds... Hope it served well. Bye!")
