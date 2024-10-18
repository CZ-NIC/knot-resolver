import importlib
import logging
from pathlib import Path
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


def files_to_watch(config: KresConfig) -> List[Path]:
    files: List[Optional[File]] = [
        config.network.tls.cert_file,
        config.network.tls.key_file,
    ]
    return [file.to_path() for file in files if file is not None]


if _watchdog:
    from watchdog.events import (
        DirModifiedEvent,
        FileModifiedEvent,
        FileSystemEventHandler,
    )
    from watchdog.observers import Observer

    _files_watchdog: Optional["FilesWatchDog"] = None

    class CertificatesEventHandler(FileSystemEventHandler):

        def __init__(self, config: KresConfig) -> None:
            self._config = config
            self._command = f"net.tls('{config.network.tls.cert_file}', '{config.network.tls.key_file}')"

        # def on_any_event(self, event: FileSystemEvent) -> None:
        #     pass

        # def on_created(self, event: Union[DirCreatedEvent, FileCreatedEvent]) -> None:
        #     pass

        # def on_deleted(self, event: Union[DirDeletedEvent, FileDeletedEvent]) -> None:
        #     pass

        def on_modified(self, event: Union[DirModifiedEvent, FileModifiedEvent]) -> None:
            if compat.asyncio.is_event_loop_running():
                compat.asyncio.create_task(command_registered_workers(self._command))
            else:
                compat.asyncio.run(command_registered_workers(self._command))

        # def on_closed(self, event: FileClosedEvent) -> None:
        #     pass

    class FilesWatchDog:
        def __init__(self, config: KresConfig, files: List[Path]) -> None:
            self._observer = Observer()
            for file in files:
                self._observer.schedule(CertificatesEventHandler(config), str(file), recursive=False)
                logger.info(f"Watching '{file}. file")

        def start(self) -> None:
            if self._observer:
                self._observer.start()

        def stop(self) -> None:
            if self._observer:
                self._observer.stop()
                self._observer.join()

    @only_on_real_changes_update(files_to_watch)
    async def _init_files_watchdog(config: KresConfig) -> None:
        global _files_watchdog
        if _files_watchdog is None:
            logger.info("Starting files WatchDog")
            _files_watchdog = FilesWatchDog(config, files_to_watch(config))
            _files_watchdog.start()


async def init_files_watchdog(config_store: ConfigStore) -> None:
    if _watchdog:
        await config_store.register_on_change_callback(_init_files_watchdog)
