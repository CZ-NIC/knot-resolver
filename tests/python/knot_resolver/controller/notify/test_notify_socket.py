import os

import pytest

from knot_resolver.controller.notify.notify_socket import init_notify_socket, read_notify_socket, send_notify_message


@pytest.mark.parametrize(
    "msg",
    [
        {"READY": 1},
        {"RELOADING": 1},
        {"STOPPING": 1},
    ],
)
def test_notify_socket(msg: dict[str, int]) -> None:
    key, value = next(iter(msg.items()))

    notify_socket = init_notify_socket()
    send_notify_message(**msg)
    pid, message = read_notify_socket(notify_socket)

    assert pid == os.getpid()
    assert message.decode() == f"{key}={value}"
