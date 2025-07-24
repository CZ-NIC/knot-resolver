import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from knot_resolver.constants import WATCHDOG_LIB
from knot_resolver.datamodel import KresConfig
from knot_resolver.manager.config_store import ConfigStore, only_on_real_changes_update
from knot_resolver.manager.triggers import cancel_cmd, trigger_cmd, trigger_renew

logger = logging.getLogger(__name__)

FilesToWatch = Dict[Path, Optional[str]]


def watched_files_config(config: KresConfig) -> List[Any]:
    return [
        config.network.tls.files_watchdog,
        config.network.tls.cert_file,
        config.network.tls.key_file,
        config.local_data.rpz,
    ]


if WATCHDOG_LIB:
    from watchdog.events import (
        FileSystemEvent,
        FileSystemEventHandler,
    )
    from watchdog.observers import Observer

    class FilesWatchdogEventHandler(FileSystemEventHandler):
        def __init__(self, files: FilesToWatch, config: KresConfig) -> None:
            self._files = files
            self._config = config

        def _trigger(self, cmd: Optional[str]) -> None:
            if cmd:
                trigger_cmd(self._config, cmd)
            trigger_renew(self._config)

        def on_created(self, event: FileSystemEvent) -> None:
            src_path = Path(str(event.src_path))
            if src_path in self._files.keys():
                logger.info(f"Watched file '{src_path}' has been created")
                self._trigger(self._files[src_path])

        def on_deleted(self, event: FileSystemEvent) -> None:
            src_path = Path(str(event.src_path))
            if src_path in self._files.keys():
                logger.warning(f"Watched file '{src_path}' has been deleted")
                cmd = self._files[src_path]
                if cmd:
                    cancel_cmd(cmd)
            for file in self._files.keys():
                if file.parent == src_path:
                    logger.warning(f"Watched directory '{src_path}' has been deleted")
                    cmd = self._files[file]
                    if cmd:
                        cancel_cmd(cmd)

        def on_moved(self, event: FileSystemEvent) -> None:
            src_path = Path(str(event.src_path))
            if src_path in self._files.keys():
                logger.info(f"Watched file '{src_path}' has been moved")
                self._trigger(self._files[src_path])

        def on_modified(self, event: FileSystemEvent) -> None:
            src_path = Path(str(event.src_path))
            if src_path in self._files.keys():
                logger.info(f"Watched file '{src_path}' has been modified")
                self._trigger(self._files[src_path])

    _files_watchdog: Optional["FilesWatchdog"] = None

    class FilesWatchdog:
        def __init__(self, files_to_watch: FilesToWatch, config: KresConfig) -> None:
            self._observer = Observer()

            event_handler = FilesWatchdogEventHandler(files_to_watch, config)
            dirs_to_watch: List[Path] = []
            for file in files_to_watch.keys():
                if file.parent not in dirs_to_watch:
                    dirs_to_watch.append(file.parent)

            for d in dirs_to_watch:
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


@only_on_real_changes_update(watched_files_config)
async def _init_files_watchdog(config: KresConfig) -> None:
    if WATCHDOG_LIB:
        global _files_watchdog

        if _files_watchdog:
            _files_watchdog.stop()
        files_to_watch: FilesToWatch = {}

        # network.tls
        if config.network.tls.files_watchdog and config.network.tls.cert_file and config.network.tls.key_file:
            net_tls = f"net.tls('{config.network.tls.cert_file}', '{config.network.tls.key_file}')"
            files_to_watch[config.network.tls.cert_file.to_path()] = net_tls
            files_to_watch[config.network.tls.key_file.to_path()] = net_tls

        # local-data.rpz
        if config.local_data.rpz:
            for rpz in config.local_data.rpz:
                if rpz.watchdog:
                    files_to_watch[rpz.file.to_path()] = None

        if files_to_watch:
            logger.info("Initializing files watchdog")
            _files_watchdog = FilesWatchdog(files_to_watch, config)
            _files_watchdog.start()


async def init_files_watchdog(config_store: ConfigStore) -> None:
    # register files watchdog callback
    await config_store.register_on_change_callback(_init_files_watchdog)
