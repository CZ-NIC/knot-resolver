import logging
from pathlib import Path
from threading import Timer
from typing import Any, List, Optional

from knot_resolver.constants import WATCHDOG_LIB
from knot_resolver.controller.registered_workers import command_registered_workers
from knot_resolver.datamodel import KresConfig
from knot_resolver.manager.config_store import ConfigStore, only_on_real_changes_update
from knot_resolver.utils import compat

logger = logging.getLogger(__name__)


def workers_config(config: KresConfig) -> List[Any]:
    return []


def policy_loader_config(config: KresConfig) -> List[Any]:
    return []


def tls_cert_config(config: KresConfig) -> List[Any]:
    return [
        config.network.tls.files_watchdog,
        config.network.tls.cert_file,
        config.network.tls.key_file,
    ]


class WatchedFile:
    def __init__(self, file: Path, lua_cmd: Optional[str]) -> None:
        self.file = file
        self.lua_template = lua_cmd.format(file=file) if lua_cmd else None


if WATCHDOG_LIB:
    from watchdog.events import (
        FileSystemEvent,
        FileSystemEventHandler,
    )
    from watchdog.observers import Observer

    _workers_files_watchdog: Optional["WorkersFilesWatchdog"] = None

    _policy_loader_files_watchdog: Optional["PolicyLoaderFilesWatchdog"] = None

    _tls_cert_files_watchdog: Optional["TLSCertFilesWatchdog"] = None

    class WorkersFilesEventHandler(FileSystemEventHandler):
        def __init__(self, files: List[Path]) -> None:
            self._files = files

    class WorkersFilesWatchdog:
        def __init__(self, files: List[Path]) -> None:
            self._observer = Observer()

        def start(self) -> None:
            self._observer.start()

        def stop(self) -> None:
            self._observer.stop()
            self._observer.join()

    class PolicyLoaderFilesEventHandler(FileSystemEventHandler):
        def __init__(self, files: List[Path]) -> None:
            self._files = files

    class PolicyLoaderFilesWatchdog:
        def __init__(self, files: List[Path]) -> None:
            self._observer = Observer()

        def start(self) -> None:
            self._observer.start()

        def stop(self) -> None:
            self._observer.stop()
            self._observer.join()

    class TLSCertFilesEventHandler(FileSystemEventHandler):
        def __init__(self, files: List[Path], cmd: str) -> None:
            self._files = files
            self._cmd = cmd
            self._timer: Optional[Timer] = None

        def _reload(self) -> None:
            def command() -> None:
                if compat.asyncio.is_event_loop_running():
                    compat.asyncio.create_task(command_registered_workers(self._cmd))
                else:
                    compat.asyncio.run(command_registered_workers(self._cmd))
                logger.info("Reloading of TLS certificate files has finished")

            # skipping if reload was already triggered
            if self._timer and self._timer.is_alive():
                logger.info("Skipping TLS certificate files reloading, reload command was already triggered")
                return
            # start a 5sec timer
            logger.info("Delayed reload of TLS certificate files has started")
            self._timer = Timer(5, command)
            self._timer.start()

        def on_created(self, event: FileSystemEvent) -> None:
            src_path = Path(str(event.src_path))
            if src_path in self._files:
                logger.info(f"Watched file '{src_path}' has been created")
                self._reload()

        def on_deleted(self, event: FileSystemEvent) -> None:
            src_path = Path(str(event.src_path))
            if src_path in self._files:
                logger.warning(f"Watched file '{src_path}' has been deleted")
                if self._timer:
                    self._timer.cancel()
            for file in self._files:
                if file.parent == src_path:
                    logger.warning(f"Watched directory '{src_path}' has been deleted")
                    if self._timer:
                        self._timer.cancel()

        def on_modified(self, event: FileSystemEvent) -> None:
            src_path = Path(str(event.src_path))
            if src_path in self._files:
                logger.info(f"Watched file '{src_path}' has been modified")
                self._reload()

    class TLSCertFilesWatchdog:
        def __init__(self, cert_file: Path, key_file: Path) -> None:
            self._observer = Observer()

            cmd = f"net.tls('{cert_file}', '{key_file}')"

            cert_files: List[Path] = []
            cert_files.append(cert_file)
            cert_files.append(key_file)

            cert_dirs: List[Path] = []
            cert_dirs.append(cert_file.parent)
            if cert_file.parent != key_file.parent:
                cert_dirs.append(key_file.parent)

            event_handler = TLSCertFilesEventHandler(cert_files, cmd)
            for d in cert_dirs:
                self._observer.schedule(
                    event_handler,
                    str(d),
                    recursive=False,
                )
                logger.info(f"Directory '{d}' scheduled for watching")

        def start(self) -> None:
            self._observer.start()

        def stop(self) -> None:
            self._observer.stop()
            self._observer.join()


@only_on_real_changes_update(workers_config)
async def _init_workers_files_watchdog(config: KresConfig) -> None:
    if WATCHDOG_LIB:
        global _workers_files_watchdog

        if _workers_files_watchdog:
            _workers_files_watchdog.stop()

        files_to_watch: List[Path] = []
        if config.local_data.rpz:
            for rpz in config.local_data.rpz:
                if rpz.watchdog:
                    files_to_watch.append(rpz.file.to_path())

        if files_to_watch:
            logger.info("Initializing workers files Watchdog")
            _workers_files_watchdog = WorkersFilesWatchdog(files_to_watch)
            _workers_files_watchdog.start()


@only_on_real_changes_update(policy_loader_config)
async def _init_policy_loader_files_watchdog(config: KresConfig) -> None:
    if WATCHDOG_LIB:
        global _policy_loader_files_watchdog

        if _policy_loader_files_watchdog:
            _policy_loader_files_watchdog.stop()

        files_to_watch: List[Path] = []
        if config.local_data.rpz:
            for rpz in config.local_data.rpz:
                if rpz.watchdog:
                    files_to_watch.append(rpz.file.to_path())

        if files_to_watch:
            logger.info("Initializing policy=loader files Watchdog")
            _policy_loader_files_watchdog = PolicyLoaderFilesWatchdog(files_to_watch)
            _policy_loader_files_watchdog.start()


@only_on_real_changes_update(tls_cert_config)
async def _init_tls_cert_watchdog(config: KresConfig) -> None:
    if WATCHDOG_LIB:
        global _tls_cert_files_watchdog

        if _tls_cert_files_watchdog:
            _tls_cert_files_watchdog.stop()

        if config.network.tls.files_watchdog and config.network.tls.cert_file and config.network.tls.key_file:
            logger.info("Initializing TLS certificate files Watchdog")
            _tls_cert_files_watchdog = TLSCertFilesWatchdog(
                config.network.tls.cert_file.to_path(),
                config.network.tls.key_file.to_path(),
            )
            _tls_cert_files_watchdog.start()


async def init_files_watchdog(config_store: ConfigStore) -> None:
    # watchdog for workers files
    await config_store.register_on_change_callback(_init_workers_files_watchdog)

    # watchdog for policy-loader files
    await config_store.register_on_change_callback(_init_policy_loader_files_watchdog)

    # watchdogs for special cases
    await config_store.register_on_change_callback(_init_tls_cert_watchdog)
