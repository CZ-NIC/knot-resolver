from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
from urllib.parse import quote

from knot_resolver.constants import API_SOCK_FILE
from knot_resolver.datamodel.types import IPAddressPort, WritableFilePath
from knot_resolver.utils.modeling import try_to_parse
from knot_resolver.utils.modeling.exceptions import DataValidationError
from knot_resolver.utils.requests import SocketDesc

if TYPE_CHECKING:
    import argparse
    from pathlib import Path

    from .args import KresClientArgs
    from .completion import CompletionWords


def get_socket_from_config(config: Path) -> SocketDesc | None:

    if not config.exists():
        print(f"Can't get the management API socket: '{config!s}' config file doesn't exist.")
        sys.exit(1)

    with config.open() as f:
        data = try_to_parse(f.read())

    management_key = "management"
    management = data.get(management_key)

    unix_socket_key = "unix-socket"
    inteface_key = "interface"

    try:
        if management and unix_socket_key in management:
            sock = WritableFilePath(
                management[unix_socket_key],
                object_path=f"/{management_key}/{unix_socket_key}",
            )
            encoded_sock = quote(str(sock), safe="")
            return SocketDesc(
                f"http+unix://{encoded_sock}",
                f"/{management_key}/{unix_socket_key} from '{config}' config file (--config argument)",
            )

        if management and inteface_key in management:
            ip = IPAddressPort(
                management[inteface_key],
                object_path=f"/{management_key}/{inteface_key}",
            )
            return SocketDesc(
                f"http://{ip.addr}:{ip.port}",
                f"/{management_key}/{inteface_key} from '{config}' config file (--config argument)",
            )
    except ValueError as e:
        raise DataValidationError(*e.args) from e
    else:
        return None


def get_socket(args: KresClientArgs) -> SocketDesc:
    if args.socket:
        encoded_socket = quote(str(args.socket), safe="")
        return SocketDesc(
            f"http+unix://{encoded_socket}",
            f"--socket argument '{args.socket}'",
        )
    sock = get_socket_from_config(args.config)
    if sock:
        return sock
    encoded_socket = quote(str(API_SOCK_FILE), safe="")
    return SocketDesc(
        f"http+unix://{encoded_socket}",
        f"default value '{API_SOCK_FILE}'",
    )


class KresClientCommand(ABC):
    @abstractmethod
    def __init__(self, args: KresClientArgs) -> None:
        raise NotImplementedError

    @abstractmethod
    def run(self) -> None:
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def completion(args: list[str], parser: argparse.ArgumentParser) -> CompletionWords:
        raise NotImplementedError
