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

from knot_resolver_manager import log
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

        self.shutdown_event = asyncio.Event()

    async def _reconfigure(self, config: KresConfig):
        await self._reconfigure_listen_address(config)

    async def _deny_listen_address_changes(self, config_old: KresConfig, config_new: KresConfig) -> Result[None, str]:
        if config_old.server.management.listen != config_new.server.management.listen:
            return Result.err(
                "Changing API listen address dynamically is not allowed as it's really dangerous. If you"
                " really need this feature, please contact the developers and explain why. Technically,"
                " there are no problems in supporting it. We are only blocking the dynamic changes because"
                " we think the consequences of leaving this footgun unprotected are worse than its usefulness."
            )

        return Result.ok(None)

    async def start(self):
        self._setup_routes()
        await self.runner.setup()
        await self.config_store.register_verifier(self._deny_listen_address_changes)
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
            elif mgn.listen.typ is ListenType.IP:
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
                elif mgn.listen.typ is ListenType.IP:
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


async def _load_raw_config(config: Union[Path, ParsedTree, _DefaultSentinel]) -> ParsedTree:
    # Initial configuration of the manager
    if isinstance(config, _DefaultSentinel):
        # use default
        config = DEFAULT_MANAGER_CONFIG_FILE
    if isinstance(config, Path):
        if not config.exists():
            raise KresdManagerException(
                f"Manager is configured to load config file at {config} on startup, but the file does not exist."
            )
        else:
            logger.info("Loading initial configuration from %s", config)
            config = parse_yaml(await readfile(config))

    # validate the initial configuration
    assert isinstance(config, ParsedTree)
    return config


async def _load_config(config: ParsedTree) -> KresConfig:
    logger.info("Validating initial configuration...")
    config_validated = KresConfig(config)
    return config_validated


async def _init_config_store(config: ParsedTree) -> ConfigStore:
    config_validated = await _load_config(config)
    return ConfigStore(config_validated)


async def _init_manager(config_store: ConfigStore) -> KresManager:
    """
    Called asynchronously when the application initializes.
    """
    # if configured, create a subprocess controller manually
    controller: Optional[SubprocessController] = None
    if config_store.get().server.backend != "auto":
        controller = await get_controller_by_name(config_store.get(), config_store.get().server.backend)

    # Create KresManager. This will perform autodetection of available service managers and
    # select the most appropriate to use (or use the one configured directly)
    manager = await KresManager.create(controller, config_store)

    logger.info("Initial configuration applied. Process manager initialized...")
    return manager


async def _deny_working_directory_changes(config_old: KresConfig, config_new: KresConfig) -> Result[None, str]:
    if config_old.server.rundir != config_new.server.rundir:
        return Result.err("Changing manager's `rundir` during runtime is not allowed.")

    return Result.ok(None)


def _set_working_directory(config_raw: ParsedTree):
    config = KresConfig(config_raw)

    if not config.server.rundir.to_path().exists():
        raise KresdManagerException(f"`rundir` directory ({config.server.rundir}) does not exist!")

    os.chdir(config.server.rundir.to_path())


async def start_server(config: Union[Path, ParsedTree, _DefaultSentinel] = _DEFAULT_SENTINEL):
    start_time = time()

    # before starting server, initialize the subprocess controller, config store, etc. Any errors during inicialization
    # are fatal
    try:
        # Preprocess config - load from file or in general take it to the last step before validation.
        config_raw = await _load_raw_config(config)

        # We want to change cwd as soon as possible. Especially before any real config validation, because cwd
        # is used for resolving relative paths. Thats also a reason, why in practice, we validate the config twice.
        # Once when setting up the cwd just to read the `rundir` property. When cwd is set, we do it again to resolve
        # all paths correctly.
        # Note: the first config validation is done here - therefore all initial config validation errors will
        # originate from here.
        _set_working_directory(config_raw)

        # After the working directory is set, we can initialize proper config store with a newly parsed configuration.
        config_store = await _init_config_store(config_raw)

        # This behaviour described above with paths means, that we MUST NOT allow `rundir` change after initialization.
        # It would cause strange problems because every other path configuration depends on it. Therefore, we have to
        # add a check to the config store, which disallows changes.
        await config_store.register_verifier(_deny_working_directory_changes)

        # Up to this point, we have been logging to memory buffer. But now, when we have the configuration loaded, we
        # can flush the buffer into the proper place
        await log.logger_init(config_store)

        # After we have loaded the configuration, we can start worring about subprocess management.
        manager = await _init_manager(config_store)
    except KresdManagerException as e:
        logger.error(e)
        sys.exit(1)
    except BaseException:
        logger.error("Uncaught generic exception during manager inicialization...", exc_info=True)
        sys.exit(1)

    # At this point, all backend functionality-providing components are initialized. It's therefore save to start
    # the API server.
    server = Server(config_store)
    await server.start()
    logger.info(f"Manager fully initialized and running in {round(time() - start_time, 3)} seconds")

    await server.wait_for_shutdown()

    # After triggering shutdown, we neet to clean everything up
    logger.info("Gracefull shutdown triggered.")
    logger.info("Stopping API service...")
    await server.shutdown()
    logger.info("Stopping kresd manager...")
    await manager.stop()
    logger.info(f"The manager run for {round(time() - start_time)} seconds... Hope it served well. Bye!")
