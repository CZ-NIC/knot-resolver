import logging
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

from pytest import LogCaptureFixture
from supervisor.events import ProcessStateStartingEvent, ProcessStateStoppingEvent
from supervisor.process import Subprocess
from supervisor.supervisord import Supervisor

from knot_resolver.controller.config import X_TYPE_NOTIFY, X_TYPE_VAR_NAME
from knot_resolver.controller.notify.notify_dispatcher import NotifyDispatcher, NotifyPlugin
from knot_resolver.controller.notify.notify_socket import send_notify_message


def test_notify_plugin() -> None:
    plugin = NotifyPlugin()
    assert plugin.starting_subprocesses == {}

    worker1_name = "worker:worker1"
    subprocess1 = MagicMock(spec=Subprocess)
    subprocess1.config = Mock()
    subprocess1.config.name = worker1_name

    starting_event1 = MagicMock(spec=ProcessStateStartingEvent)
    starting_event1.process = subprocess1

    plugin.track_starting_subprocesses(starting_event1)
    assert worker1_name in plugin.starting_subprocesses

    worker2_name = "worker:worker2"
    subprocess2 = MagicMock(spec=Subprocess)
    subprocess2.config = Mock()
    subprocess2.config.name = worker2_name

    starting_event2 = MagicMock(spec=ProcessStateStartingEvent)
    starting_event2.process = subprocess2

    plugin.track_starting_subprocesses(starting_event2)
    assert worker2_name in plugin.starting_subprocesses

    stopping_event = MagicMock(spec=ProcessStateStoppingEvent)
    stopping_event.process = subprocess1

    plugin.track_starting_subprocesses(stopping_event)
    assert worker1_name not in plugin.starting_subprocesses
    assert worker2_name in plugin.starting_subprocesses


def test_notify_dispatcher(caplog: LogCaptureFixture) -> None:
    plugin = NotifyPlugin()

    supervisor = MagicMock(spec=Supervisor)
    supervisor.options = Mock()
    supervisor.options.logger = logging.getLogger(__name__)

    subprocess = MagicMock(spec=Subprocess)
    subprocess.pid = os.getpid()
    subprocess.config = SimpleNamespace(
        name="subprocess",
        environment={},
    )

    dispatcher = NotifyDispatcher(supervisor, plugin)

    caplog.clear()
    with caplog.at_level(logging.INFO):
        send_notify_message(READY=1)
        dispatcher.handle_read_event()
    assert any("ignoring notify message from unregistered subprocess" in record.message for record in caplog.records)

    starting_event = MagicMock(spec=ProcessStateStartingEvent)
    starting_event.process = subprocess
    plugin.track_starting_subprocesses(starting_event)

    caplog.clear()
    with caplog.at_level(logging.INFO):
        send_notify_message(READY=1)
        dispatcher.handle_read_event()
    assert any("that is not configured to send it" in record.message for record in caplog.records)

    subprocess.config = SimpleNamespace(
        name="subprocess",
        environment={
            X_TYPE_VAR_NAME: X_TYPE_NOTIFY,
        },
    )

    caplog.clear()
    with caplog.at_level(logging.INFO):
        send_notify_message(READY=1)
        dispatcher.handle_read_event()
    assert any("received READY notify message" in record.message for record in caplog.records)

    caplog.clear()
    with caplog.at_level(logging.INFO):
        send_notify_message(STOPPING=1)
        dispatcher.handle_read_event()
    assert any("received STOPPING notify message" in record.message for record in caplog.records)

    caplog.clear()
    with caplog.at_level(logging.INFO):
        send_notify_message(UNRECOGNIZED=1)
        dispatcher.handle_read_event()
    assert any("ignoring unrecognized data on $NOTIFY_SOCKET" in record.message for record in caplog.records)

    dispatcher.close()
