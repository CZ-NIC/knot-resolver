import asyncio
import errno
import json
import logging
import os
import signal
import sys
from functools import partial
from http import HTTPStatus
from pathlib import Path
from time import time
from typing import Any, Dict, List, Optional, Set, Union, cast

from aiohttp import web
from aiohttp.web import middleware
from aiohttp.web_app import Application
from aiohttp.web_response import json_response
from aiohttp.web_runner import AppRunner, TCPSite, UnixSite
from typing_extensions import Literal

import knot_resolver_manager.utils.custom_atexit as atexit
from knot_resolver_manager import log, statistics
from knot_resolver_manager.compat import asyncio as asyncio_compat
from knot_resolver_manager.config_store import ConfigStore
from knot_resolver_manager.constants import DEFAULT_MANAGER_CONFIG_FILE, PID_FILE_NAME, init_user_constants
from knot_resolver_manager.datamodel.cache_schema import CacheClearRPCSchema
from knot_resolver_manager.datamodel.config_schema import KresConfig, get_rundir_without_validation
from knot_resolver_manager.datamodel.globals import Context, set_global_validation_context
from knot_resolver_manager.datamodel.management_schema import ManagementSchema
from knot_resolver_manager.exceptions import CancelStartupExecInsteadException, KresManagerException
from knot_resolver_manager.kresd_controller import get_best_controller_implementation
from knot_resolver_manager.kresd_controller.registered_workers import command_single_registered_worker
from knot_resolver_manager.kresd_controller.interface import SubprocessType
from knot_resolver_manager.utils import ignore_exceptions_optional
from knot_resolver_manager.utils.async_utils import readfile
from knot_resolver_manager.utils.etag import structural_etag
from knot_resolver_manager.utils.functional import Result
from knot_resolver_manager.utils.modeling.exceptions import (
    AggregateDataValidationError,
    DataParsingError,
    DataValidationError,
)
from knot_resolver_manager.utils.modeling.parsing import DataFormat, try_to_parse
from knot_resolver_manager.utils.modeling.query import query
from knot_resolver_manager.utils.modeling.types import NoneType
from knot_resolver_manager.utils.systemd_notify import systemd_notify

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
    except DataValidationError as e:
        return web.Response(text=f"validation of configuration failed:\n{e}", status=HTTPStatus.BAD_REQUEST)
    except DataParsingError as e:
        return web.Response(text=f"request processing error:\n{e}", status=HTTPStatus.BAD_REQUEST)
    except KresManagerException as e:
        return web.Response(text=f"request processing failed:\n{e}", status=HTTPStatus.INTERNAL_SERVER_ERROR)


def from_mime_type(mime_type: str) -> DataFormat:
    formats = {
        "application/json": DataFormat.JSON,
        "application/octet-stream": DataFormat.JSON,  # default in aiohttp
    }
    if mime_type not in formats:
        raise DataParsingError(f"unsupported MIME type '{mime_type}', expected: {str(formats)[1:-1]}")
    return formats[mime_type]


def parse_from_mime_type(data: str, mime_type: str) -> Any:
    return from_mime_type(mime_type).parse_to_dict(data)


class Server:
    # pylint: disable=too-many-instance-attributes
    # This is top-level class containing pretty much everything. Instead of global
    # variables, we use instance attributes. That's why there are so many and it's
    # ok.
    def __init__(self, store: ConfigStore, config_path: Optional[Path], manager: KresManager):
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
        self._manager = manager

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

    async def _reload_config(self) -> None:
        if self._config_path is None:
            logger.warning("The manager was started with inlined configuration - can't reload")
        else:
            try:
                data = await readfile(self._config_path)
                config = KresConfig(try_to_parse(data))
                await self.config_store.update(config)
                logger.info("Configuration file successfully reloaded")
            except FileNotFoundError:
                logger.error(
                    f"Configuration file was not found at '{self._config_path}'."
                    " Something must have happened to it while we were running."
                )
                logger.error("Configuration have NOT been changed.")
            except (DataParsingError, DataValidationError) as e:
                logger.error(f"Failed to parse the updated configuration file: {e}")
                logger.error("Configuration have NOT been changed.")
            except KresManagerException as e:
                logger.error(f"Reloading of the configuration file failed: {e}")
                logger.error("Configuration have NOT been changed.")

    async def sigint_handler(self) -> None:
        logger.info("Received SIGINT, triggering graceful shutdown")
        self.trigger_shutdown(0)

    async def sigterm_handler(self) -> None:
        logger.info("Received SIGTERM, triggering graceful shutdown")
        self.trigger_shutdown(0)

    async def sighup_handler(self) -> None:
        logger.info("Received SIGHUP, reloading configuration file")
        systemd_notify(RELOADING="1")
        await self._reload_config()
        systemd_notify(READY="1")

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

    async def _handler_config_query(self, request: web.Request) -> web.Response:
        """
        Route handler for changing resolver configuration
        """
        # There are a lot of local variables in here, but they are usually immutable (almost SSA form :) )
        # pylint: disable=too-many-locals

        # parse the incoming data
        if request.method == "GET":
            update_with: Optional[Dict[str, Any]] = None
        else:
            update_with = parse_from_mime_type(await request.text(), request.content_type)
        document_path = request.match_info["path"]
        getheaders = ignore_exceptions_optional(List[str], None, KeyError)(request.headers.getall)
        etags = getheaders("if-match")
        not_etags = getheaders("if-none-match")
        current_config: Dict[str, Any] = self.config_store.get().get_unparsed_data()

        # stop processing if etags
        def strip_quotes(s: str) -> str:
            return s.strip('"')

        # WARNING: this check is prone to race conditions. When changing, make sure that the current config
        # is really the latest current config (i.e. no await in between obtaining the config and the checks)
        status = HTTPStatus.NOT_MODIFIED if request.method in ("GET", "HEAD") else HTTPStatus.PRECONDITION_FAILED
        if etags is not None and structural_etag(current_config) not in map(strip_quotes, etags):
            return web.Response(status=status)
        if not_etags is not None and structural_etag(current_config) in map(strip_quotes, not_etags):
            return web.Response(status=status)

        # run query
        op = cast(Literal["get", "delete", "patch", "put"], request.method.lower())
        new_config, to_return = query(current_config, op, document_path, update_with)

        # update the config
        if request.method != "GET":
            # validate
            config_validated = KresConfig(new_config)
            # apply
            await self.config_store.update(config_validated)

        # serialize the response (the `to_return` object is a Dict/list/scalar, we want to return json)
        resp_text: Optional[str] = json.dumps(to_return) if to_return is not None else None

        # create the response and return it
        res = web.Response(status=HTTPStatus.OK, text=resp_text, content_type="application/json")
        res.headers.add("ETag", f'"{structural_etag(new_config)}"')
        return res

    async def _handler_metrics(self, request: web.Request) -> web.Response:
        raise web.HTTPMovedPermanently("/metrics/json")

    async def _handler_metrics_json(self, _request: web.Request) -> web.Response:
        return web.Response(
            body=await statistics.report_stats(),
            content_type="application/json",
            charset="utf8",
        )

    async def _handler_metrics_prometheus(self, _request: web.Request) -> web.Response:

        metrics_report = await statistics.report_stats(prometheus_format=True)
        if not metrics_report:
            raise web.HTTPNotFound()

        return web.Response(
            body=metrics_report,
            content_type="text/plain",
            charset="utf8",
        )

    async def _handler_cache_clear(self, request: web.Request) -> web.Response:
        data = parse_from_mime_type(await request.text(), request.content_type)

        try:
            config = CacheClearRPCSchema(data)
        except (AggregateDataValidationError, DataValidationError) as e:
            return web.Response(
                body=e,
                status=HTTPStatus.BAD_REQUEST,
                content_type="text/plain",
                charset="utf8",
            )

        _, result = await command_single_registered_worker(config.render_lua())
        return web.Response(
            body=json.dumps(result),
            content_type="application/json",
            charset="utf8",
        )

    async def _handler_schema(self, _request: web.Request) -> web.Response:
        return web.json_response(
            KresConfig.json_schema(), headers={"Access-Control-Allow-Origin": "*"}, dumps=partial(json.dumps, indent=4)
        )

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

    async def _handler_reload(self, _request: web.Request) -> web.Response:
        """
        Route handler for reloading the server
        """

        logger.info("Reloading event triggered...")
        await self._reload_config()
        return web.Response(text="Reloading...")

    async def _handler_pids(self, request: web.Request) -> web.Response:
        """
        Route handler for listing PIDs of subprocesses
        """

        proc_type: Optional[SubprocessType] = None

        if "path" in request.match_info and len(request.match_info["path"]) > 0:
            ptstr = request.match_info["path"]
            if ptstr == "/kresd":
                proc_type = SubprocessType.KRESD
            elif ptstr == "/gc":
                proc_type = SubprocessType.GC
            elif ptstr == "/all":
                proc_type = None
            else:
                return web.Response(text=f"Invalid process type '{ptstr}'", status=400)

        return web.json_response(
            await self._manager.get_pids(proc_type),
            headers={"Access-Control-Allow-Origin": "*"},
            dumps=partial(json.dumps, indent=4),
        )

    def _setup_routes(self) -> None:
        self.app.add_routes(
            [
                web.get("/", self._handler_index),
                web.get(r"/v1/config{path:.*}", self._handler_config_query),
                web.put(r"/v1/config{path:.*}", self._handler_config_query),
                web.delete(r"/v1/config{path:.*}", self._handler_config_query),
                web.patch(r"/v1/config{path:.*}", self._handler_config_query),
                web.post("/stop", self._handler_stop),
                web.post("/reload", self._handler_reload),
                web.get("/schema", self._handler_schema),
                web.get("/schema/ui", self._handle_view_schema),
                web.get("/metrics", self._handler_metrics),
                web.get("/metrics/json", self._handler_metrics_json),
                web.get("/metrics/prometheus", self._handler_metrics_prometheus),
                web.post("/cache/clear", self._handler_cache_clear),
                web.get("/pids{path:.*}", self._handler_pids),
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


async def _load_raw_config(config: Union[Path, Dict[str, Any]]) -> Dict[str, Any]:
    # Initial configuration of the manager
    if isinstance(config, Path):
        if not config.exists():
            raise KresManagerException(
                f"Manager is configured to load config file at {config} on startup, but the file does not exist."
            )
        else:
            logger.info(f"Loading configuration from '{config}' file.")
            config = try_to_parse(await readfile(config))

    # validate the initial configuration
    assert isinstance(config, dict)
    return config


async def _load_config(config: Dict[str, Any]) -> KresConfig:
    config_validated = KresConfig(config)
    return config_validated


async def _init_config_store(config: Dict[str, Any]) -> ConfigStore:
    config_validated = await _load_config(config)
    config_store = ConfigStore(config_validated)
    return config_store


async def _init_manager(config_store: ConfigStore) -> KresManager:
    """
    Called asynchronously when the application initializes.
    """

    # Instantiate subprocess controller (if we wanted to, we could switch it at this point)
    controller = await get_best_controller_implementation(config_store.get())

    # Create KresManager. This will perform autodetection of available service managers and
    # select the most appropriate to use (or use the one configured directly)
    manager = await KresManager.create(controller, config_store)

    logger.info("Initial configuration applied. Process manager initialized...")
    return manager


async def _deny_working_directory_changes(config_old: KresConfig, config_new: KresConfig) -> Result[None, str]:
    if config_old.rundir != config_new.rundir:
        return Result.err("Changing manager's `rundir` during runtime is not allowed.")

    return Result.ok(None)


def _set_working_directory(config_raw: Dict[str, Any]) -> None:
    try:
        rundir = get_rundir_without_validation(config_raw)
    except ValueError as e:
        raise DataValidationError(str(e), "/rundir") from e

    logger.debug(f"Changing working directory to '{rundir.to_path().absolute()}'.")
    os.chdir(rundir.to_path())


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
            except OSError as e2:
                if e2.errno == errno.ESRCH:
                    os.unlink(PID_FILE_NAME)
                    _lock_working_directory(attempt=attempt + 1)
                    return
            raise KresManagerException(
                "Another manager is running in the same working directory."
                f" PID file is located at {os.getcwd()}/{PID_FILE_NAME}"
            ) from e
        else:
            raise KresManagerException(
                "Another manager is running in the same working directory."
                f" PID file is located at {os.getcwd()}/{PID_FILE_NAME}"
            ) from e

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


async def start_server(config: Path = DEFAULT_MANAGER_CONFIG_FILE) -> int:
    # This function is quite long, but it describes how manager runs. So let's silence pylint
    # pylint: disable=too-many-statements

    start_time = time()
    working_directory_on_startup = os.getcwd()
    manager: Optional[KresManager] = None

    # Block signals during initialization to force their processing once everything is ready
    signal.pthread_sigmask(signal.SIG_BLOCK, Server.all_handled_signals())

    # before starting server, initialize the subprocess controller, config store, etc. Any errors during inicialization
    # are fatal
    try:
        # Make sure that the config path does not change meaning when we change working directory
        config = config.absolute()

        # Preprocess config - load from file or in general take it to the last step before validation.
        config_raw = await _load_raw_config(config)

        # before processing any configuration, set validation context
        #  - resolve_root = root against which all relative paths will be resolved
        set_global_validation_context(Context(config.parent, True))

        # We want to change cwd as soon as possible. Some parts of the codebase are using os.getcwd() to get the
        # working directory.
        #
        # If we fail to read rundir from unparsed config, the first config validation error comes from here
        _set_working_directory(config_raw)

        # We don't want more than one manager in a single working directory. So we lock it with a PID file.
        # Warning - this does not prevent multiple managers with the same naming of kresd service.
        _lock_working_directory()

        # set_global_validation_context(Context(config.parent))

        # After the working directory is set, we can initialize proper config store with a newly parsed configuration.
        config_store = await _init_config_store(config_raw)

        # Some "constants" need to be loaded from the initial config, some need to be stored from the initial run conditions
        await init_user_constants(config_store, working_directory_on_startup)

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

        # After we have loaded the configuration, we can start worring about subprocess management.
        manager = await _init_manager(config_store)

        # prepare instance of the server (no side effects)
        server = Server(config_store, config, manager)

        # add Server's shutdown trigger to the manager
        manager.add_shutdown_trigger(server.trigger_shutdown)

    except CancelStartupExecInsteadException as e:
        # if we caught this exception, some component wants to perform a reexec during startup. Most likely, it would
        # be a subprocess manager like supervisord, which wants to make sure the manager runs under supervisord in
        # the process tree. So now we stop everything, and exec what we are told to. We are assuming, that the thing
        # we'll exec will invoke us again.
        logger.info("Exec requested with arguments: %s", str(e.exec_args))

        # unblock signals, this could actually terminate us straight away
        signal.pthread_sigmask(signal.SIG_UNBLOCK, Server.all_handled_signals())

        # run exit functions
        atexit.run_callbacks()

        # and finally exec what we were told to exec
        os.execl(*e.exec_args)

    except KresManagerException as e:
        # We caught an error with a pretty error message. Just print it and exit.
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

    # notify systemd/anything compatible that we are ready
    systemd_notify(READY="1")

    await server.wait_for_shutdown()

    # notify systemd that we are shutting down
    systemd_notify(STOPPING="1")

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
