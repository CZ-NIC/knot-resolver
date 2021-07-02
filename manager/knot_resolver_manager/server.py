import asyncio
import logging
import sys
from functools import partial
from http import HTTPStatus
from pathlib import Path
from time import time
from typing import Any, List, Optional, Tuple, Union

from aiohttp import web
from aiohttp.web import middleware
from aiohttp.web_response import json_response

from knot_resolver_manager.constants import MANAGER_CONFIG_FILE
from knot_resolver_manager.exceptions import ValidationException
from knot_resolver_manager.kresd_controller import get_controller_by_name
from knot_resolver_manager.kresd_controller.interface import SubprocessController
from knot_resolver_manager.utils.async_utils import readfile
from knot_resolver_manager.utils.dataclasses_parservalidator import Format

from .datamodel import KresConfig
from .kres_manager import KresManager

_MANAGER = "kres_manager"
_SHUTDOWN_EVENT = "shutdown-event"

logger = logging.getLogger(__name__)


async def _index(request: web.Request) -> web.Response:
    """
    Dummy index handler to indicate that the server is indeed running...
    """
    return json_response(
        {
            "msg": "Knot Resolver Manager is running! The configuration endpoint is at /config",
            "status": "RUNNING" if get_kres_manager(request.app) is not None else "INITIALIZING",
        }
    )


async def _apply_config(request: web.Request) -> web.Response:
    """
    Route handler for changing resolver configuration
    """

    document_path = request.match_info["path"]

    manager: KresManager = get_kres_manager(request.app)
    if manager is None:
        # handle the case when the manager is not yet initialized
        return web.Response(
            status=503, headers={"Retry-After": "3"}, text="Knot Resolver Manager is not yet fully initialized"
        )

    # parse the incoming data
    last: KresConfig = manager.get_last_used_config() or KresConfig()
    fmt = Format.from_mime_type(request.content_type)
    config = last.copy_with_changed_subtree(fmt, document_path, await request.text())

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
        return web.Response(text=f"Data validation failed: {e}", status=HTTPStatus.BAD_REQUEST)


def setup_routes(app: web.Application):
    app.add_routes([web.get("/", _index), web.post(r"/config{path:.*}", _apply_config), web.post("/stop", _stop)])


def stop_server(app: web.Application):
    app[_SHUTDOWN_EVENT].set()
    logger.info("Shutdown event triggered...")


def get_kres_manager(app: web.Application) -> KresManager:
    if _MANAGER not in app:
        raise ValueError("Accessing manager in an application where it was not defined")

    return app[_MANAGER]


class _DefaultSentinel:
    pass


_DEFAULT_SENTINEL = _DefaultSentinel()


async def _init_manager(
    config: Union[None, Path, KresConfig, _DefaultSentinel],
    subprocess_controller_name: Optional[str],
    app: web.Application,
):
    """
    Called asynchronously when the application initializes.
    """
    try:
        # if configured, create a subprocess controller manually
        controller: Optional[SubprocessController] = None
        if subprocess_controller_name is not None:
            controller = await get_controller_by_name(subprocess_controller_name)

        # Create KresManager. This will perform autodetection of available service managers and
        # select the most appropriate to use (or use the one configured directly)
        manager = await KresManager.create(controller)
        app[_MANAGER] = manager

        # Initial configuration of the manager
        if config is None:
            # do nothing, there won't be any initial config
            pass
        if isinstance(config, _DefaultSentinel):
            # use default
            config = MANAGER_CONFIG_FILE
        if isinstance(config, Path):
            if not config.exists():
                logger.error(
                    "Manager is configured to load config file at %s on startup, but the file does not exist.",
                    config,
                )
                sys.exit(1)
            else:
                logger.info("Loading initial configuration from %s", config)
                config = KresConfig.from_yaml(await readfile(config))
        if isinstance(config, KresConfig):
            await manager.apply_config(config)
            logger.info("Initial configuration applied...")

        logger.info("Process manager initialized...")
    except BaseException:
        logger.error("Manager initialization failed... Shutting down!", exc_info=True)
        sys.exit(1)


async def start_server(
    tcp: List[Tuple[str, int]],
    unix: List[Path],
    config: Union[None, Path, KresConfig, _DefaultSentinel] = _DEFAULT_SENTINEL,
    subprocess_controller_name: Optional[str] = None,
):
    start_time = time()

    app = web.Application(middlewares=[error_handler])

    app[_MANAGER] = None
    app[_SHUTDOWN_EVENT] = asyncio.Event()

    app.on_startup.append(partial(_init_manager, config, subprocess_controller_name))

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
