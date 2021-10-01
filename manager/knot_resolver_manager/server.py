import asyncio
import logging
import sys
from http import HTTPStatus
from pathlib import Path
from time import time
from typing import Any, Optional, Union

from aiohttp import web
from aiohttp.web import middleware
from aiohttp.web_app import Application
from aiohttp.web_response import json_response
from aiohttp.web_runner import AppRunner, TCPSite, UnixSite

from knot_resolver_manager.constants import MANAGER_CONFIG_FILE
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.datamodel.types import Listen, ListenType
from knot_resolver_manager.exceptions import DataException, KresdManagerException, TreeException
from knot_resolver_manager.kresd_controller import get_controller_by_name
from knot_resolver_manager.kresd_controller.interface import SubprocessController
from knot_resolver_manager.utils.async_utils import readfile
from knot_resolver_manager.utils.parsing import ParsedTree, parse, parse_yaml
from knot_resolver_manager.utils.types import NoneType

from .kres_manager import KresManager

logger = logging.getLogger(__name__)


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


class Server:
    # pylint: disable=too-many-instance-attributes
    # This is top-level class containing pretty much everything. Instead of global
    # variables, we use instance attributes. That's why there are so many and it's
    # ok.
    def __init__(self, manager: KresManager):

        self.manager = manager
        self.app = Application(middlewares=[error_handler])
        self.runner = AppRunner(self.app)

        self.listen: Optional[Listen] = None
        self.site: Union[NoneType, TCPSite, UnixSite] = None
        self.listen_lock = asyncio.Lock()

        self.log_level = "dummy"

        self.shutdown_event = asyncio.Event()

    async def _reconfigure(self, config: KresConfig):
        self._set_log_level(config)
        await self._reconfigure_listen_address(config)

    async def start(self):
        config = self.manager.get_last_used_config()
        self.setup_routes()
        await self.runner.setup()
        await self._reconfigure(config)

    async def wait_for_shutdown(self):
        await self.shutdown_event.wait()

    async def _handler_index(self, _request: web.Request) -> web.Response:
        """
        Dummy index handler to indicate that the server is indeed running...
        """
        return json_response(
            {
                "msg": "Knot Resolver Manager is running! The configuration endpoint is at /config",
                "status": "RUNNING",
            }
        )

    async def _handler_apply_config(self, request: web.Request) -> web.Response:
        """
        Route handler for changing resolver configuration
        """

        # parse the incoming data
        document_path = request.match_info["path"]
        last: ParsedTree = self.manager.get_last_used_config().get_unparsed_data()
        new_partial: ParsedTree = parse(await request.text(), request.content_type)
        config = last.update(document_path, new_partial)

        # validate config
        config_validated = KresConfig(config)

        # apply config
        await self._reconfigure(config_validated)
        await self.manager.apply_config(config_validated)

        # return success
        return web.Response()

    def _set_log_level(self, config: KresConfig):
        if self.log_level != config.server.management.log_level:
            # expects one existing log handler on the root
            h = logging.getLogger().handlers
            assert len(h) == 1
            target = config.server.management.log_level
            logger.warning(f"Changing log level to '{target}'")
            h[0].setLevel(target)
            self.log_level = target

    async def _handler_stop(self, _request: web.Request) -> web.Response:
        """
        Route handler for shutting down the server (and whole manager)
        """

        self.shutdown_event.set()
        logger.info("Shutdown event triggered...")
        return web.Response(text="Shutting down...")

    def setup_routes(self):
        self.app.add_routes(
            [
                web.get("/", self._handler_index),
                web.post(r"/config{path:.*}", self._handler_apply_config),
                web.post("/stop", self._handler_stop),
            ]
        )

    async def _reconfigure_listen_address(self, config: KresConfig):
        async with self.listen_lock:
            mgn = config.server.management

            # if the listen address did not change, do nothing
            if self.listen == mgn.listen:
                return

            # start the new listen address
            if mgn.listen.typ is ListenType.UNIX_SOCKET:
                nsite = web.UnixSite(self.runner, str(mgn.listen.unix_socket))
                logger.info(f"Starting API HTTP server on http+unix://{mgn.listen.unix_socket}")
            elif mgn.listen.typ is ListenType.IP_AND_PORT:
                nsite = web.TCPSite(self.runner, str(mgn.listen.ip), mgn.listen.port)
                logger.info(f"Starting API HTTP server on http://{mgn.listen.ip}:{mgn.listen.port}")
            else:
                raise KresdManagerException(f"Requested API on unsupported configuration format {mgn.listen.typ}")
            await nsite.start()

            # stop the old listen
            assert (self.listen is None) == (self.site is None)
            if self.listen is not None and self.site is not None:
                if self.listen.typ is ListenType.UNIX_SOCKET:
                    logger.info(f"Stopping API HTTP server on http+unix://{mgn.listen.unix_socket}")
                elif mgn.listen.typ is ListenType.IP_AND_PORT:
                    logger.info(f"Stopping API HTTP server on http://{mgn.listen.ip}:{mgn.listen.port}")
                await self.site.stop()

            # save new state
            self.listen = mgn.listen
            self.site = nsite

    async def shutdown(self):
        if self.site is not None:
            await self.site.stop()
        await self.runner.cleanup()


class _DefaultSentinel:
    pass


_DEFAULT_SENTINEL = _DefaultSentinel()


async def _init_manager(config: Union[Path, ParsedTree, _DefaultSentinel]) -> KresManager:
    """
    Called asynchronously when the application initializes.
    """
    try:
        # Initial configuration of the manager
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

        # validate the initial configuration
        assert isinstance(config, ParsedTree)
        logger.info("Validating initial configuration...")
        config_validated = KresConfig(config)

        # if configured, create a subprocess controller manually
        controller: Optional[SubprocessController] = None
        if config_validated.server.management.backend != "auto":
            controller = await get_controller_by_name(config_validated.server.management.backend)

        # Create KresManager. This will perform autodetection of available service managers and
        # select the most appropriate to use (or use the one configured directly)
        manager = await KresManager.create_instance(controller, config_validated)

        logger.info("Initial configuration applied. Process manager initialized...")
        return manager
    except BaseException:
        logger.error("Manager initialization failed... Shutting down!", exc_info=True)
        sys.exit(1)


async def start_server(config: Union[Path, ParsedTree, _DefaultSentinel] = _DEFAULT_SENTINEL):
    start_time = time()

    # before starting server, initialize the subprocess controller etc.
    manager = await _init_manager(config)

    server = Server(manager)
    await server.start()

    # stop the server gracefully and cleanup everything
    logger.info(f"Manager fully initialized and running in {round(time() - start_time, 3)} seconds")

    await server.wait_for_shutdown()

    logger.info("Gracefull shutdown triggered. Cleaning up...")
    await server.shutdown()
    await manager.stop()
    logger.info(f"The manager run for {round(time() - start_time)} seconds... Hope it served well. Bye!")
