import logging
import os
import socket

logger = logging.getLogger(__name__)


def systemd_notify(**values: str) -> None:
    """
    Send systemd notify message to notify socket.

    Notify socket location (unix socket) should be saved in $NOTIFY_SOCKET environment variable.
    It is typically set by the processes supervisor (supervisord).
    If $NOTIFY_SOCKET is not configured, it is not possible to send a notification and the operation will fail.
    """
    socket_addr = os.getenv("NOTIFY_SOCKET")
    if socket_addr is None:
        logger.warning("Failed to get $NOTIFY_SOCKET environment variable")
        return

    if socket_addr.startswith("@"):
        socket_addr = socket_addr.replace("@", "\0", 1)

    try:
        notify_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        notify_socket.connect(socket_addr)
    except OSError:
        logger.exception("Failed to connect to $NOTIFY_SOCKET at '%s'", socket_addr)
        return

    payload = "\n".join((f"{key}={value}" for key, value in values.items()))
    try:
        notify_socket.send(payload.encode("utf8"))
    except OSError:
        logger.exception("Failed to send systemd notification to $NOTIFY_SOCKET at '%s'", socket_addr)

    notify_socket.close()
