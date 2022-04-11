import enum
import logging
import os
import socket


logger = logging.getLogger(__name__)


class _Status(enum.Enum):
    NOT_INITIALIZED = 1
    FUNCTIONAL = 2
    FAILED = 3


_status = _Status.NOT_INITIALIZED
_socket = None


def systemd_notify(**values: str) -> None:
    global _status
    global _socket

    if _status is _Status.NOT_INITIALIZED:
        socket_addr = os.getenv("NOTIFY_SOCKET")
        os.unsetenv("NOTIFY_SOCKET")
        if socket_addr is None:
            _status = _Status.FAILED
            return
        if socket_addr.startswith("@"):
            socket_addr = socket_addr.replace("@", "\0", 1)

        try:
            _socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            _socket.connect(socket_addr)
            _status = _Status.FUNCTIONAL
        except Exception:
            _socket = None
            _status = _Status.FAILED
            logger.warning(f"Failed to connect to $NOTIFY_SOCKET at '{socket_addr}'", exc_info=True)
            return

    elif _status is _Status.FAILED:
        return

    if _status is _Status.FUNCTIONAL:
        assert _socket is not None
        payload = "\n".join((f"{key}={value}" for key, value in values.items()))
        try:
            _socket.send(payload.encode("utf8"))
        except Exception:
            logger.warning("Failed to send notification to systemd", exc_info=True)
            _status = _Status.FAILED
            _socket.close()
            _socket = None
