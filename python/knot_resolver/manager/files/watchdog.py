import importlib
import logging
import os
import time
from pathlib import Path
from threading import Timer
from typing import List, Optional, Union

from knot_resolver.controller.registered_workers import command_registered_workers
from knot_resolver.datamodel import KresConfig
from knot_resolver.datamodel.types import File
from knot_resolver.manager.config_store import ConfigStore, only_on_real_changes_update
from knot_resolver.utils import compat

_watchdog = False
if importlib.util.find_spec("watchdog"):
    _watchdog = True

logger = logging.getLogger(__name__)


def tls_cert_paths(config: KresConfig) -> List[str]:
    files: List[Optional[File]] = [
        config.network.tls.cert_file,
        config.network.tls.key_file,
    ]
    return [str(file) for file in files if file is not None]


if _watchdog:
    from watchdog.events import (
        DirDeletedEvent,
        DirModifiedEvent,
        FileDeletedEvent,
        FileModifiedEvent,
        FileSystemEventHandler,
    )
    from watchdog.observers import Observer

    _tls_cert_watchdog: Optional["TLSCertWatchDog"] = None

    class TLSCertEventHandler(FileSystemEventHandler):
        def __init__(self, cmd: str, delay: int = 5) -> None:
            self._delay = delay
            self._timer: Optional[Timer] = None
            self._cmd = cmd

        def _reload_cmd(self) -> None:
            logger.info("Reloading TLS certificate files for the all workers")
            if compat.asyncio.is_event_loop_running():
                compat.asyncio.create_task(command_registered_workers(self._cmd))
            else:
                compat.asyncio.run(command_registered_workers(self._cmd))

        def on_deleted(self, event: Union[DirDeletedEvent, FileDeletedEvent]) -> None:
            path = str(event.src_path)
            logger.info(f"Stopped watching '{path}', because it was deleted")

            # do not send command when the file was deleted
            if self._timer and self._timer.is_alive():
                self._timer.cancel()
                self._timer.join()

            if _tls_cert_watchdog:
                _tls_cert_watchdog.reschedule()

        def on_modified(self, event: Union[DirModifiedEvent, FileModifiedEvent]) -> None:
            path = str(event.src_path)
            logger.info(f"TLS certificate file '{path}' has been modified")

            # skipping if command was already triggered
            if self._timer and self._timer.is_alive():
                logger.info(f"Skipping '{path}', reload file already triggered")
                return
            # start a new timer
            self._timer = Timer(self._delay, self._reload_cmd)
            self._timer.start()
            logger.info("Delayed reload of TLS certificate files has started")

    class TLSCertWatchDog:
        def __init__(self, cert_file: Path, key_file: Path) -> None:
            self._observer = Observer()
            self._cert_file = cert_file
            self._key_file = key_file
            self._cmd = f"net.tls('{cert_file}', '{key_file}')"

        def schedule(self) -> None:
            event_handler = TLSCertEventHandler(self._cmd)
            logger.info("Schedule watching of TLS certificate files")
            self._observer.schedule(
                event_handler,
                str(self._cert_file),
                recursive=False,
            )
            self._observer.schedule(
                event_handler,
                str(self._key_file),
                recursive=False,
            )

        def reschedule(self) -> None:
            self._observer.unschedule_all()

            # wait for files creation
            while not (os.path.exists(self._cert_file) and os.path.exists(self._key_file)):
                if os.path.exists(self._cert_file):
                    logger.error(f"Cannot start watching TLS cert file, '{self._cert_file}' is missing.")
                if os.path.exists(self._key_file):
                    logger.error(f"Cannot start watching TLS cert key file, '{self._key_file}' is missing.")
                time.sleep(1)
            self.schedule()

        def start(self) -> None:
            self._observer.start()

        def stop(self) -> None:
            self._observer.stop()
            self._observer.join()

    @only_on_real_changes_update(tls_cert_paths)
    async def _init_tls_cert_watchdog(config: KresConfig) -> None:
        global _tls_cert_watchdog
        if _tls_cert_watchdog:
            _tls_cert_watchdog.stop()

        if config.network.tls.cert_file and config.network.tls.key_file:
            logger.info("Starting TLS certificate files WatchDog")
            _tls_cert_watchdog = TLSCertWatchDog(
                config.network.tls.cert_file.to_path(), config.network.tls.key_file.to_path()
            )
            _tls_cert_watchdog.schedule()
            _tls_cert_watchdog.start()


async def init_files_watchdog(config_store: ConfigStore) -> None:
    if _watchdog:
        # watchdog for TLS certificate files
        await config_store.register_on_change_callback(_init_tls_cert_watchdog)
