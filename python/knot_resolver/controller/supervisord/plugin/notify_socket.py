import os
import logging
import socket
import struct
from pathlib import Path
from typing import Optional, Union

from knot_resolver.controller.exceptions import KresSubprocessControllerErrorNotifySocketError

NOTIFY_SOCKET = "NOTIFY_SOCKET"
NOTIFY_SOCKET_NAME = "supervisor-notify-socket"

CREDENTIALS_FORMAT = "3i"
CREDENTIALS_SIZE = struct.calcsize(CREDENTIALS_FORMAT)
RECEIVE_BUFFER_SIZE = 2048

logger = logging.getLogger(__name__)


def init_notify_socket() -> int:
    notify_socket_path = Path.cwd() / NOTIFY_SOCKET_NAME
    notify_socket_path.unlink(missing_ok=True)

    notify_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
    try:
        notify_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        notify_socket.bind(str(notify_socket_path))
    except OSError as e:
        notify_socket.close()
        notify_socket_path.unlink(missing_ok=True)
        msg = f"failed to initialize notify socket at '{notify_socket_path}'"
        raise KresSubprocessControllerErrorNotifySocketError(msg) from e

    if NOTIFY_SOCKET in os.environ:
        logger.info("running under systemd, overwriting 'NOTIFY_SOCKET' environment variable")

    os.environ[NOTIFY_SOCKET] = str(notify_socket_path)
    return notify_socket.detach()


def read_notify_socket(fd: int) -> Optional[tuple[int, bytes]]:
    sock = sock = socket.socket(fileno=fd)

    try:
        data, ancdata, flags, _ = sock.recvmsg(
            RECEIVE_BUFFER_SIZE,
            socket.CMSG_SPACE(CREDENTIALS_SIZE),
        )
    except BlockingIOError:
        return None
    finally:
        sock.detach()

    if flags & socket.MSG_TRUNC:
        raise KresSubprocessControllerErrorNotifySocketError("received datagram was truncated")

    pid = next(
        (
            struct.unpack(CREDENTIALS_FORMAT, cdata[:CREDENTIALS_SIZE])[0]
            for level, ctype, cdata in ancdata
            if level == socket.SOL_SOCKET and ctype == socket.SCM_CREDENTIALS
        ),
        None,
    )

    if pid is None:
        logger.warning("ignoring received data without credentials: %s", data)
        return None

    return pid, data


def send_notify_socket_message(notify_socket_path: Optional[str] = None, **values: Union[str, int]) -> None:
    if notify_socket_path is None:
        notify_socket_path = os.getenv(NOTIFY_SOCKET)
        if notify_socket_path is None:
            logger.warning("failed to get $NOTIFY_SOCKET environment variable")
            return

    if notify_socket_path.startswith("@"):
        notify_socket_path = notify_socket_path.replace("@", "\0", 1)

    try:
        notify_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        notify_socket.connect(notify_socket_path)
    except OSError:
        logger.exception("failed to connect to $NOTIFY_SOCKET at '%s'", notify_socket_path)
        return

    payload = "\n".join((f"{key}={value}" for key, value in values.items()))
    try:
        notify_socket.send(payload.encode("utf8"))
    except OSError:
        logger.exception("failed to send notify message to $NOTIFY_SOCKET at '%s'", notify_socket_path)

    notify_socket.close()
