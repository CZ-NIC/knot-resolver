import asyncio
import logging
import sys
from http import HTTPStatus
from pathlib import Path
from time import time
from typing import Any, List, Optional, Tuple, Union

from aiohttp import web
from aiohttp.web import middleware
from aiohttp.web_response import json_response

from knot_resolver_manager.constants import MANAGER_CONFIG_FILE
from knot_resolver_manager.exceptions import DataException, KresdManagerException, TreeException
from knot_resolver_manager.kresd_controller import get_controller_by_name
from knot_resolver_manager.kresd_controller.interface import SubprocessController
from knot_resolver_manager.utils.async_utils import readfile
from knot_resolver_manager.utils.parsing import ParsedTree, parse, parse_yaml

from .kres_manager import KresManager

_SHUTDOWN_EVENT = "shutdown-event"

logger = logging.getLogger(__name__)


async def _index(_request: web.Request) -> web.Response:
    """
    Dummy index handler to indicate that the server is indeed running...
    """
    return json_response(
        {
            "msg": "Knot Resolver Manager is running! The configuration endpoint is at /config",
            "status": "RUNNING",
        }
    )


async def _apply_config(request: web.Request) -> web.Response:
    """
    Route handler for changing resolver configuration
    """

    document_path = request.match_info["path"]

    manager: KresManager = KresManager.get_instance()
    if manager is None:
        # handle the case when the manager is not yet initialized
        return web.Response(
            status=503, headers={"Retry-After": "3"}, text="Knot Resolver Manager is not yet fully initialized"
        )

    # parse the incoming data
    last: ParsedTree = manager.get_last_used_config_raw() or ParsedTree({})
    new_partial: ParsedTree = parse(await request.text(), request.content_type)
    config = last.update(document_path, new_partial)

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
    except KresdManagerException as e:
        if isinstance(e, TreeException):
            return web.Response(
                text=f"Configuration validation failed @ '{e.where()}': {e}", status=HTTPStatus.BAD_REQUEST
            )
        elif isinstance(e, (DataException, DataException)):
            return web.Response(text=f"Configuration validation failed: {e}", status=HTTPStatus.BAD_REQUEST)
        else:
            logger.error("Request processing failed", exc_info=True)
            return web.Response(text=f"Request processing failed: {e}", status=HTTPStatus.INTERNAL_SERVER_ERROR)


def setup_routes(app: web.Application):
    app.add_routes([web.get("/", _index), web.post(r"/config{path:.*}", _apply_config), web.post("/stop", _stop)])


def stop_server(app: web.Application):
    app[_SHUTDOWN_EVENT].set()
    logger.info("Shutdown event triggered...")


class _DefaultSentinel:
    pass


_DEFAULT_SENTINEL = _DefaultSentinel()


async def _init_manager(
    config: Union[None, Path, ParsedTree, _DefaultSentinel],
    subprocess_controller_name: Optional[str],
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
        manager = await KresManager.create_instance(controller)

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
                config = parse_yaml(await readfile(config))
        if isinstance(config, ParsedTree):
            await manager.apply_config(config)
            logger.info("Initial configuration applied...")

        logger.info("Process manager initialized...")
    except BaseException:
        logger.error("Manager initialization failed... Shutting down!", exc_info=True)
        sys.exit(1)


async def start_server(
    tcp: List[Tuple[str, int]],
    unix: List[Path],
    config: Union[None, Path, ParsedTree, _DefaultSentinel] = _DEFAULT_SENTINEL,
    subprocess_controller_name: Optional[str] = None,
):
    start_time = time()

    # before starting any server, initialize the subprocess controller etc.
    await _init_manager(config, subprocess_controller_name)

    app = web.Application(middlewares=[error_handler])
    app[_SHUTDOWN_EVENT] = asyncio.Event()

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
    await KresManager.get_instance().stop()
    logger.info(f"The manager run for {round(time() - start_time)} seconds... Hope it served well. Bye!")
