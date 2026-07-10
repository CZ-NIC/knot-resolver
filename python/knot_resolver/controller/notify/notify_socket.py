from __future__ import annotations

from knot_resolver.constants import NOTIFY_SUPPORT

NOTIFY_SOCKET_NAME = "supervisor-notify-socket"
NOTIFY_SOCKET_ENV_VAR = "NOTIFY_SOCKET"


if NOTIFY_SUPPORT:
    import os
    import socket
    import struct
    from pathlib import Path

    from knot_resolver.controller.errors import ControllerNotifySocketError
    from knot_resolver.logging import get_logger

    logger = get_logger(__name__)

    CREDENTIALS_FORMAT = "3i"
    CREDENTIALS_SIZE = struct.calcsize(CREDENTIALS_FORMAT)
    RECEIVE_BUFFER_SIZE = 2048

    def init_notify_socket() -> socket.socket:
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
            raise ControllerNotifySocketError(msg) from e

        os.environ[NOTIFY_SOCKET_ENV_VAR] = str(notify_socket_path)
        return notify_socket

    def read_notify_socket(sock: socket.socket) -> tuple[int, bytes] | None:
        try:
            data, ancdata, flags, _ = sock.recvmsg(
                RECEIVE_BUFFER_SIZE,
                socket.CMSG_SPACE(CREDENTIALS_SIZE),
            )
        except BlockingIOError:
            return None

        if flags & socket.MSG_TRUNC:
            raise ControllerNotifySocketError("received datagram was truncated")

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

    def send_notify_message(**values: str | int) -> None:
        notify_socket_path = os.getenv(NOTIFY_SOCKET_ENV_VAR)

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
