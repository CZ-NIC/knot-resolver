import logging
from threading import Timer
from typing import Dict, Optional
from urllib.parse import quote

from knot_resolver.controller.registered_workers import command_registered_workers
from knot_resolver.datamodel import KresConfig
from knot_resolver.utils import compat
from knot_resolver.utils.requests import SocketDesc, request

logger = logging.getLogger(__name__)

_triggers: Optional["Triggers"] = None


class Triggers:
    def __init__(self, config: KresConfig) -> None:
        self._config = config

        self._renew_timer: Optional[Timer] = None
        self._reload_timer: Optional[Timer] = None
        self._cmd_timers: Dict[str, Timer] = {}

        management = config.management
        socket = SocketDesc(
            f'http+unix://{quote(str(management.unix_socket), safe="")}/',
            'Key "/management/unix-socket" in validated configuration',
        )
        if management.interface:
            socket = SocketDesc(
                f"http://{management.interface.addr}:{management.interface.port}",
                'Key "/management/interface" in validated configuration',
            )
        self._socket = socket

    def trigger_cmd(self, cmd: str) -> None:
        def _cmd() -> None:
            if compat.asyncio.is_event_loop_running():
                compat.asyncio.create_task(command_registered_workers(cmd))
            else:
                compat.asyncio.run(command_registered_workers(cmd))
            logger.info(f"Sending '{cmd}' command to reload watched files has finished")

        # skipping if command was already triggered
        if cmd in self._cmd_timers and self._cmd_timers[cmd].is_alive():
            logger.info(f"Skipping sending '{cmd}' command, it was already triggered")
            return
        # start a 5sec timer
        logger.info(f"Delayed send of '{cmd}' command has started")
        self._cmd_timers[cmd] = Timer(5, _cmd)
        self._cmd_timers[cmd].start()

    def cancel_cmd(self, cmd: str) -> None:
        if cmd in self._cmd_timers:
            self._cmd_timers[cmd].cancel()

    def trigger_renew(self) -> None:
        def _renew() -> None:
            response = request(self._socket, "POST", "renew")
            if response.status != 200:
                logger.error(f"Failed to renew configuration: {response.body}")
            logger.info("Renewing configuration has finished")

        # do not trigger renew if reload is scheduled
        if self._reload_timer and self._reload_timer.is_alive():
            return

        # skipping if reload was already triggered
        if self._renew_timer and self._renew_timer.is_alive():
            logger.info("Skipping renewing configuration, it was already triggered")
            return
        # start a 5sec timer
        logger.info("Delayed configuration renew has started")
        self._renew_timer = Timer(5, _renew)
        self._renew_timer.start()

    def trigger_reload(self) -> None:
        def _reload() -> None:
            response = request(self._socket, "POST", "reload")
            if response.status != 200:
                logger.error(f"Failed to reload configuration: {response.body}")
            logger.info("Reloading configuration has finished")

        # cancel renew
        if self._renew_timer and self._renew_timer.is_alive():
            self._renew_timer.cancel()

        # skipping if reload was already triggered
        if self._reload_timer and self._reload_timer.is_alive():
            logger.info("Skipping renewing configuration, it was already triggered")
            return
        # start a 5sec timer
        logger.info("Delayed configuration renew has started")
        self._reload_timer = Timer(5, _reload)
        self._reload_timer.start()


def trigger_cmd(config: KresConfig, cmd: str) -> None:
    global _triggers
    if not _triggers:
        _triggers = Triggers(config)
    _triggers.trigger_cmd(cmd)


def cancel_cmd(cmd: str) -> None:
    global _triggers  # noqa: PLW0602
    if _triggers:
        _triggers.cancel_cmd(cmd)


def trigger_renew(config: KresConfig) -> None:
    global _triggers
    if not _triggers:
        _triggers = Triggers(config)
    _triggers.trigger_renew()


def trigger_reload(config: KresConfig) -> None:
    global _triggers
    if not _triggers:
        _triggers = Triggers(config)
    _triggers.trigger_reload()
