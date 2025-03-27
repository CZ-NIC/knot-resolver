import logging
from pathlib import Path
from threading import Timer
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from knot_resolver.constants import WATCHDOG_LIB
from knot_resolver.controller.registered_workers import command_registered_workers
from knot_resolver.datamodel import KresConfig
from knot_resolver.manager.config_store import ConfigStore, only_on_real_changes_update
from knot_resolver.utils import compat
from knot_resolver.utils.requests import SocketDesc, request

logger = logging.getLogger(__name__)

FilesToWatch = Dict[Path, Optional[str]]


def watched_files_config(config: KresConfig) -> List[Any]:
    return [
        config.network.tls.watchdog,
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
            self._policy_timer: Optional[Timer] = None
            self._timers: Dict[str, Timer] = {}

        def _trigger(self, cmd: Optional[str]) -> None:
            def policy_reload() -> None:
                management = self._config.management
                socket = SocketDesc(
                    f'http+unix://{quote(str(management.unix_socket), safe="")}/',
                    'Key "/management/unix-socket" in validated configuration',
                )
                if management.interface:
                    socket = SocketDesc(
                        f"http://{management.interface.addr}:{management.interface.port}",
                        'Key "/management/interface" in validated configuration',
                    )

                response = request(socket, "POST", "renew")
                if response.status != 200:
                    logger.error(f"Failed to reload policy rules: {response.body}")
                logger.info("Reloading policy rules has finished")

            if not cmd:
                # skipping if reload was already triggered
                if self._policy_timer and self._policy_timer.is_alive():
                    logger.info("Skipping reloading policy rules, it was already triggered")
                    return
                # start a 5sec timer
                logger.info("Delayed policy rules reload has started")
                self._policy_timer = Timer(5, policy_reload)
                self._policy_timer.start()
                return

            def command() -> None:
                if compat.asyncio.is_event_loop_running():
                    compat.asyncio.create_task(command_registered_workers(cmd))
                else:
                    compat.asyncio.run(command_registered_workers(cmd))
                logger.info(f"Sending '{cmd}' command to reload watched files has finished")

            # skipping if command was already triggered
            if cmd in self._timers and self._timers[cmd].is_alive():
                logger.info(f"Skipping sending '{cmd}' command, it was already triggered")
                return
            # start a 5sec timer
            logger.info(f"Delayed send of '{cmd}' command has started")
            self._timers[cmd] = Timer(5, command)
            self._timers[cmd].start()

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
                if cmd in self._timers:
                    self._timers[cmd].cancel()
            for file in self._files.keys():
                if file.parent == src_path:
                    logger.warning(f"Watched directory '{src_path}' has been deleted")
                    cmd = self._files[file]
                    if cmd in self._timers:
                        self._timers[cmd].cancel()

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
        if config.network.tls.watchdog and config.network.tls.cert_file and config.network.tls.key_file:
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
