import asyncio
import logging
import os
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

from knot_resolver_manager.config_store import ConfigStore
from knot_resolver_manager.constants import DEFAULT_MANAGER_CONFIG_FILE
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.datamodel.types import Listen, ListenType
from knot_resolver_manager.exceptions import DataException, KresdManagerException, TreeException
from knot_resolver_manager.kresd_controller import get_controller_by_name
from knot_resolver_manager.kresd_controller.interface import SubprocessController
from knot_resolver_manager.utils.async_utils import readfile
from knot_resolver_manager.utils.functional import Result
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
    def __init__(self, store: ConfigStore):
        # config store & server dynamic reconfiguration
        self.config_store = store

        # HTTP server
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
        self._setup_routes()
        await self.runner.setup()
        await self.config_store.register_on_change_callback(self._reconfigure)

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
        last: ParsedTree = self.config_store.get().get_unparsed_data()
        new_partial: ParsedTree = parse(await request.text(), request.content_type)
        config = last.update(document_path, new_partial)

        # validate config
        config_validated = KresConfig(config)

        # apply config
        await self.config_store.update(config_validated)

        # return success
        return web.Response()

    async def _handler_schema(self, _request: web.Request) -> web.Response:
        return web.json_response(KresConfig.json_schema(), headers={"Access-Control-Allow-Origin": "*"})

    async def _handle_view_schema(self, _request: web.Request) -> web.Response:
        """
        Provides a UI for visuallising and understanding JSON schema.

        The feature in the Knot Resolver Manager to render schemas is unwanted, as it's completely
        out of scope. However, it can be convinient. We therefore rely on a public web-based viewers
        and provide just a redirect. If this feature ever breaks due to disapearance of the public
        service, we can fix it. But we are not guaranteeing, that this will always work.
        """

        return web.Response(
            text="""
        <html>
        <head><title>Redirect to schema viewer</title></head>
        <body>
        <script>
          // we are using JS in order to use proper host
          let protocol = window.location.protocol;
          let host = window.location.host;
          let url = encodeURIComponent(`${protocol}//${host}/schema`);
          window.location.replace(`https://json-schema.app/view/%23?url=${url}`);
        </script>
        <h1>JavaScript required for a dynamic redirect...</h1>
        </body>
        </html>
        """,
            content_type="text/html",
        )

    def _set_log_level(self, config: KresConfig):

        levels_map = {
            "crit": "CRITICAL",
            "err": "ERROR",
            "warning": "WARNING",
            "notice": "WARNING",
            "info": "INFO",
            "debug": "DEBUG",
        }

        target = levels_map[config.logging.level]
        if config.logging.groups and "manager" in config.logging.groups:
            target = "DEBUG"

        if self.log_level != target:
            # expects one existing log handler on the root
            h = logging.getLogger().handlers
            assert len(h) == 1
            logger.warning(f"Changing logging level to '{target}'")
            h[0].setLevel(target)
            self.log_level = target

    async def _handler_stop(self, _request: web.Request) -> web.Response:
        """
        Route handler for shutting down the server (and whole manager)
        """

        self.shutdown_event.set()
        logger.info("Shutdown event triggered...")
        return web.Response(text="Shutting down...")

    def _setup_routes(self):
        self.app.add_routes(
            [
                web.get("/", self._handler_index),
                web.post(r"/config{path:.*}", self._handler_apply_config),
                web.post("/stop", self._handler_stop),
                web.get("/schema", self._handler_schema),
                web.get("/schema/ui", self._handle_view_schema),
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


async def _init_config_store(config: Union[Path, ParsedTree, _DefaultSentinel]) -> ConfigStore:
    # Initial configuration of the manager
    if isinstance(config, _DefaultSentinel):
        # use default
        config = DEFAULT_MANAGER_CONFIG_FILE
    if isinstance(config, Path):
        if not config.exists():
            raise KresdManagerException(f"Manager is configured to load config file at {config} on startup, but the file does not exist.")
        else:
            logger.info("Loading initial configuration from %s", config)
            config = parse_yaml(await readfile(config))

    # validate the initial configuration
    assert isinstance(config, ParsedTree)
    logger.info("Validating initial configuration...")
    config_validated = KresConfig(config)

    return ConfigStore(config_validated)


async def _init_manager(config_store: ConfigStore) -> KresManager:
    """
    Called asynchronously when the application initializes.
    """
    # if configured, create a subprocess controller manually
    controller: Optional[SubprocessController] = None
    if config_store.get().server.management.backend != "auto":
        controller = await get_controller_by_name(config_store.get(), config_store.get().server.management.backend)

    # Create KresManager. This will perform autodetection of available service managers and
    # select the most appropriate to use (or use the one configured directly)
    manager = await KresManager.create(controller, config_store)

    logger.info("Initial configuration applied. Process manager initialized...")
    return manager


async def _validate_working_directory(config_old: KresConfig, config_new: KresConfig) -> Result[None, str]:
    if config_old.server.management.rundir != config_new.server.management.rundir:
        return Result.err("Changing manager's `rundir` during runtime is not allowed.")
    
    if not config_new.server.management.rundir.to_path().exists():
        return Result.err(f"Configured `rundir` directory ({config_new.server.management.rundir}) does not exist!")

    return Result.ok(None)


async def _set_working_directory(config: KresConfig):
    os.chdir(config.server.management.rundir.to_path())


async def start_server(config: Union[Path, ParsedTree, _DefaultSentinel] = _DEFAULT_SENTINEL):
    start_time = time()

    # before starting server, initialize the subprocess controller etc. Any errors during inicialization are fatal
    try:
        config_store = await _init_config_store(config)
        await config_store.register_verifier(_validate_working_directory)
        await config_store.register_on_change_callback(_set_working_directory)
        manager = await _init_manager(config_store)
    except KresdManagerException as e:
        logger.error(e)
        sys.exit(1)
    except BaseException as e:
        logger.error("Uncaught generic exception during manager inicialization..." , exc_info=True)
        sys.exit(1)

    server = Server(config_store)
    await server.start()

    # stop the server gracefully and cleanup everything
    logger.info(f"Manager fully initialized and running in {round(time() - start_time, 3)} seconds")

    await server.wait_for_shutdown()

    logger.info("Gracefull shutdown triggered.")
    logger.info("Stopping API service...")
    await server.shutdown()
    logger.info("Stopping kresd manager...")
    await manager.stop()
    logger.info(f"The manager run for {round(time() - start_time)} seconds... Hope it served well. Bye!")
