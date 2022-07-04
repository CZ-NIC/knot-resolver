import asyncio
import atexit
import errno
import logging
import os
import signal
import sys
from http import HTTPStatus
from pathlib import Path
from time import time
from typing import Any, Optional, Set, Union

from aiohttp import web
from aiohttp.web import middleware
from aiohttp.web_app import Application
from aiohttp.web_response import json_response
from aiohttp.web_runner import AppRunner, TCPSite, UnixSite

from knot_resolver_manager import log, statistics
from knot_resolver_manager.compat import asyncio as asyncio_compat
from knot_resolver_manager.config_store import ConfigStore
from knot_resolver_manager.constants import DEFAULT_MANAGER_CONFIG_FILE, PID_FILE_NAME, init_user_constants
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.datamodel.management_schema import ManagementSchema
from knot_resolver_manager.exceptions import DataException, KresManagerException, SchemaException
from knot_resolver_manager.utils.async_utils import readfile
from knot_resolver_manager.utils.functional import Result
from knot_resolver_manager.utils.parsing import ParsedTree, parse, parse_yaml
from knot_resolver_manager.utils.types import NoneType

from .kres_manager import KresManager

logger = logging.getLogger(__name__)


@middleware
async def error_handler(request: web.Request, handler: Any) -> web.Response:
    """
    Generic error handler for route handlers.

    If an exception is thrown during request processing, this middleware catches it
    and responds accordingly.
    """

    try:
        return await handler(request)
    except KresManagerException as e:
        if isinstance(e, (SchemaException, DataException)):
            return web.Response(text=f"validation of configuration failed: {e}", status=HTTPStatus.BAD_REQUEST)
        else:
            logger.error("Request processing failed", exc_info=True)
            return web.Response(text=f"Request processing failed: {e}", status=HTTPStatus.INTERNAL_SERVER_ERROR)


class Server:
    # pylint: disable=too-many-instance-attributes
    # This is top-level class containing pretty much everything. Instead of global
    # variables, we use instance attributes. That's why there are so many and it's
    # ok.
    def __init__(self, store: ConfigStore, config_path: Optional[Path]):
        # config store & server dynamic reconfiguration
        self.config_store = store

        # HTTP server
        self.app = Application(middlewares=[error_handler])
        self.runner = AppRunner(self.app)
        self.listen: Optional[ManagementSchema] = None
        self.site: Union[NoneType, TCPSite, UnixSite] = None
        self.listen_lock = asyncio.Lock()
        self._config_path: Optional[Path] = config_path
        self._exit_code: int = 0
        self._shutdown_event = asyncio.Event()

    async def _reconfigure(self, config: KresConfig) -> None:
        await self._reconfigure_listen_address(config)

    async def _deny_management_changes(self, config_old: KresConfig, config_new: KresConfig) -> Result[None, str]:
        if config_old.management != config_new.management:
            return Result.err(
                "/server/management: Changing management API address/unix-socket dynamically is not allowed as it's really dangerous."
                " If you really need this feature, please contact the developers and explain why. Technically,"
                " there are no problems in supporting it. We are only blocking the dynamic changes because"
                " we think the consequences of leaving this footgun unprotected are worse than its usefulness."
            )
        return Result.ok(None)

    async def sigint_handler(self) -> None:
        logger.info("Received SIGINT, triggering graceful shutdown")
        self.trigger_shutdown(0)

    async def sigterm_handler(self) -> None:
        logger.info("Received SIGTERM, triggering graceful shutdown")
        self.trigger_shutdown(0)

    async def sighup_handler(self) -> None:
        logger.info("Received SIGHUP, reloading configuration file")
        if self._config_path is None:
            logger.warning("The manager was started with inlined configuration - can't reload")
        else:
            try:
                data = await readfile(self._config_path)
                config = KresConfig(parse_yaml(data))
                await self.config_store.update(config)
                logger.info("Configuration file successfully reloaded")
            except FileNotFoundError:
                logger.error(
                    f"Configuration file was not found at '{self._config_path}'."
                    " Something must have happened to it while we were running."
                )
                logger.error("Configuration have NOT been changed.")
            except SchemaException as e:
                logger.error(f"Failed to parse the updated configuration file: {e}")
                logger.error("Configuration have NOT been changed.")
            except KresManagerException as e:
                logger.error(f"Reloading of the configuration file failed: {e}")
                logger.error("Configuration have NOT been changed.")

    @staticmethod
    def all_handled_signals() -> Set[signal.Signals]:
        return {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}

    def bind_signal_handlers(self):
        asyncio_compat.add_async_signal_handler(signal.SIGTERM, self.sigterm_handler)
        asyncio_compat.add_async_signal_handler(signal.SIGINT, self.sigint_handler)
        asyncio_compat.add_async_signal_handler(signal.SIGHUP, self.sighup_handler)

    def unbind_signal_handlers(self):
        asyncio_compat.remove_signal_handler(signal.SIGTERM)
        asyncio_compat.remove_signal_handler(signal.SIGINT)
        asyncio_compat.remove_signal_handler(signal.SIGHUP)

    async def start(self) -> None:
        self._setup_routes()
        await self.runner.setup()
        await self.config_store.register_verifier(self._deny_management_changes)
        await self.config_store.register_on_change_callback(self._reconfigure)

    async def wait_for_shutdown(self) -> None:
        await self._shutdown_event.wait()

    def trigger_shutdown(self, exit_code: int) -> None:
        self._shutdown_event.set()
        self._exit_code = exit_code

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

    @statistics.async_timing_histogram(statistics.MANAGER_REQUEST_RECONFIGURE_LATENCY)
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

    async def _handler_metrics(self, _request: web.Request) -> web.Response:
        return web.Response(
            body=await statistics.report_stats(),
            content_type="text/plain",
            charset="utf8",
        )

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

        self._shutdown_event.set()
        logger.info("Shutdown event triggered...")
        return web.Response(text="Shutting down...")

    def _setup_routes(self) -> None:
        self.app.add_routes(
            [
                web.get("/", self._handler_index),
                web.post(r"/config{path:.*}", self._handler_apply_config),
                web.post("/stop", self._handler_stop),
                web.get("/schema", self._handler_schema),
                web.get("/schema/ui", self._handle_view_schema),
                web.get("/metrics", self._handler_metrics),
            ]
        )

    async def _reconfigure_listen_address(self, config: KresConfig) -> None:
        async with self.listen_lock:
            mgn = config.management

            # if the listen address did not change, do nothing
            if self.listen == mgn:
                return

            # start the new listen address
            nsite: Union[web.TCPSite, web.UnixSite]
            if mgn.unix_socket:
                nsite = web.UnixSite(self.runner, str(mgn.unix_socket))
                logger.info(f"Starting API HTTP server on http+unix://{mgn.unix_socket}")
            elif mgn.interface:
                nsite = web.TCPSite(self.runner, str(mgn.interface.addr), int(mgn.interface.port))
                logger.info(f"Starting API HTTP server on http://{mgn.interface.addr}:{mgn.interface.port}")
            else:
                raise KresManagerException("Requested API on unsupported configuration format.")
            await nsite.start()

            # stop the old listen
            assert (self.listen is None) == (self.site is None)
            if self.listen is not None and self.site is not None:
                if self.listen.unix_socket:
                    logger.info(f"Stopping API HTTP server on http+unix://{mgn.unix_socket}")
                elif self.listen.interface:
                    logger.info(
                        f"Stopping API HTTP server on http://{self.listen.interface.addr}:{self.listen.interface.port}"
                    )
                await self.site.stop()

            # save new state
            self.listen = mgn
            self.site = nsite

    async def shutdown(self) -> None:
        if self.site is not None:
            await self.site.stop()
        await self.runner.cleanup()

    def get_exit_code(self) -> int:
        return self._exit_code


async def _load_raw_config(config: Union[Path, ParsedTree]) -> ParsedTree:
    # Initial configuration of the manager
    if isinstance(config, Path):
        if not config.exists():
            raise KresManagerException(
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
    config_store = ConfigStore(config_validated)
    await init_user_constants(config_store)
    return config_store


async def _init_manager(config_store: ConfigStore, server: Server) -> KresManager:
    """
    Called asynchronously when the application initializes.
    """

    # Create KresManager. This will perform autodetection of available service managers and
    # select the most appropriate to use (or use the one configured directly)
    manager = await KresManager.create(None, config_store, server.trigger_shutdown)

    logger.info("Initial configuration applied. Process manager initialized...")
    return manager


async def _deny_working_directory_changes(config_old: KresConfig, config_new: KresConfig) -> Result[None, str]:
    if config_old.rundir != config_new.rundir:
        return Result.err("Changing manager's `rundir` during runtime is not allowed.")

    return Result.ok(None)


def _set_working_directory(config_raw: ParsedTree) -> None:
    config = KresConfig(config_raw)

    if not config.rundir.to_path().exists():
        raise KresManagerException(f"`rundir` directory ({config.rundir}) does not exist!")

    os.chdir(config.rundir.to_path())


def _lock_working_directory(attempt: int = 0) -> None:
    # the following syscall is atomic, it's essentially the same as acquiring a lock
    try:
        pidfile_fd = os.open(PID_FILE_NAME, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except OSError as e:
        if e.errno == errno.EEXIST and attempt == 0:
            # the pid file exists, let's check PID
            with open(PID_FILE_NAME, "r", encoding="utf-8") as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, 0)
            except OSError as e:
                if e.errno == errno.ESRCH:
                    os.unlink(PID_FILE_NAME)
                    _lock_working_directory(attempt=attempt + 1)
                    return
            raise KresManagerException(
                "Another manager is running in the same working directory."
                f" PID file is located at {os.getcwd()}/{PID_FILE_NAME}"
            )
        else:
            raise KresManagerException(
                "Another manager is running in the same working directory."
                f" PID file is located at {os.getcwd()}/{PID_FILE_NAME}"
            )

    # now we know that we are the only manager running in this directory

    # write PID to the pidfile and close it afterwards
    pidfile = os.fdopen(pidfile_fd, "w")
    pid = os.getpid()
    pidfile.write(f"{pid}\n")
    pidfile.close()

    # make sure that the file is deleted on shutdown
    atexit.register(lambda: os.unlink(PID_FILE_NAME))


async def _sigint_while_shutting_down():
    logger.warning(
        "Received SIGINT while already shutting down. Ignoring."
        " If you want to forcefully stop the manager right now, use SIGTERM."
    )


async def _sigterm_while_shutting_down():
    logger.warning("Received SIGTERM. Invoking dirty shutdown!")
    sys.exit(128 + signal.SIGTERM)


async def start_server(config: Union[Path, ParsedTree] = DEFAULT_MANAGER_CONFIG_FILE) -> int:
    start_time = time()
    manager: Optional[KresManager] = None

    # Block signals during initialization to force their processing once everything is ready
    signal.pthread_sigmask(signal.SIG_BLOCK, Server.all_handled_signals())

    # before starting server, initialize the subprocess controller, config store, etc. Any errors during inicialization
    # are fatal
    try:
        # Make sure that the config path does not change meaning when we change working directory
        if isinstance(config, Path):
            config = config.absolute()

        # Preprocess config - load from file or in general take it to the last step before validation.
        config_raw = await _load_raw_config(config)

        # We want to change cwd as soon as possible. Especially before any real config validation, because cwd
        # is used for resolving relative paths. Thats also a reason, why in practice, we validate the config twice.
        # Once when setting up the cwd just to read the `rundir` property. When cwd is set, we do it again to resolve
        # all paths correctly.
        # Note: the first config validation is done here - therefore all initial config validation errors will
        # originate from here.
        _set_working_directory(config_raw)

        # We don't want more than one manager in a single working directory. So we lock it with a PID file.
        # Warning - this does not prevent multiple managers with the same naming of kresd service.
        _lock_working_directory()

        # After the working directory is set, we can initialize proper config store with a newly parsed configuration.
        config_store = await _init_config_store(config_raw)

        # This behaviour described above with paths means, that we MUST NOT allow `rundir` change after initialization.
        # It would cause strange problems because every other path configuration depends on it. Therefore, we have to
        # add a check to the config store, which disallows changes.
        await config_store.register_verifier(_deny_working_directory_changes)

        # Up to this point, we have been logging to memory buffer. But now, when we have the configuration loaded, we
        # can flush the buffer into the proper place
        await log.logger_init(config_store)

        # With configuration on hand, we can initialize monitoring. We want to do this before any subprocesses are
        # started, therefore before initializing manager
        await statistics.init_monitoring(config_store)

        # prepare instance of the server (no side effects)
        server = Server(config_store, config if isinstance(config, Path) else None)

        # After we have loaded the configuration, we can start worring about subprocess management.
        manager = await _init_manager(config_store, server)
    except KresManagerException as e:
        logger.error(e)
        return 1
    except BaseException:
        logger.error("Uncaught generic exception during manager inicialization...", exc_info=True)
        return 1

    # At this point, all backend functionality-providing components are initialized. It's therefore save to start
    # the API server.
    try:
        await server.start()
    except OSError as e:
        if e.errno in (errno.EADDRINUSE, errno.EADDRNOTAVAIL):
            # fancy error reporting of network binding errors
            logger.error(str(e))
            await manager.stop()
            return 1
        raise

    # At this point, pretty much everything is ready to go. We should just make sure the user can shut
    # the manager down with signals.
    server.bind_signal_handlers()
    signal.pthread_sigmask(signal.SIG_UNBLOCK, Server.all_handled_signals())

    logger.info(f"Manager fully initialized and running in {round(time() - start_time, 3)} seconds")

    await server.wait_for_shutdown()

    # Ok, now we are tearing everything down.

    # First of all, let's block all unwanted interruptions. We don't want to be reconfiguring kresd's while
    # shutting down.
    signal.pthread_sigmask(signal.SIG_BLOCK, Server.all_handled_signals())
    server.unbind_signal_handlers()
    # on the other hand, we want to immediatelly stop when the user really wants us to stop
    asyncio_compat.add_async_signal_handler(signal.SIGTERM, _sigterm_while_shutting_down)
    asyncio_compat.add_async_signal_handler(signal.SIGINT, _sigint_while_shutting_down)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})

    # After triggering shutdown, we neet to clean everything up
    logger.info("Stopping API service...")
    await server.shutdown()
    logger.info("Stopping kresd manager...")
    await manager.stop()
    logger.info(f"The manager run for {round(time() - start_time)} seconds...")
    return server.get_exit_code()
