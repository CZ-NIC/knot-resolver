"""TCP Connection Management tests - prefix length

RFC1035
4.2.2. TCP usage
The message is prefixed with a two byte length field which gives the message
length, excluding the two byte length field.

The following test suite focuses on edge cases for the prefix - when it
is either too short or too long, instead of matching the length of DNS
message exactly.

The tests with invalid prefix attempt to sequentially send the invalid
message. After a certain period of time (affected by net.tcp_in_idle,
TCP_DEFER_ACCEPT, ...), kresd should close the connection. There are
three variants of these tests - either no valid query is sent, or one
valid query is sent along with the invalid buffer at once, or one valid
query is sent and afterwards the invalid buffer is sent.
"""

import time

import pytest

import utils


def send_invalid_repeatedly(sock, buff, delay=1):
    """Utility function to keep sending the buffer until MAX_TIMEOUT is reached.

    It is expected kresd will close the connection, since the buffer
    contains invalid prefix of the message.

    If the connection remains open, test is failed.
    """
    end_time = time.time() + utils.MAX_TIMEOUT

    with utils.expect_kresd_close():
        while time.time() < end_time:
            sock.sendall(buff)
            time.sleep(delay)


@pytest.fixture(params=[
    'no_query_before',
    'send_query_before_invalid',
    'send_query_before_invalid_single_buffer',
])
def send_query_before(request):
    """This either performs no query, or sends a query along with invalid buffer at once, or
    sends a query and then the invalid buffer."""

    # pylint: disable=possibly-unused-variable

    def no_query_before(*args, **kwargs):  # pylint: disable=unused-argument
        pass

    def send_query_before_invalid(sock, invalid_buff, single_buffer=False):
        """Send an initial query and expect a response."""
        msg_buff, msgid = utils.get_msgbuff()

        if single_buffer:
            sock.sendall(msg_buff + invalid_buff)
        else:
            sock.sendall(msg_buff)
            sock.sendall(invalid_buff)

        answer = utils.receive_parse_answer(sock)
        assert answer.id == msgid

    def send_query_before_invalid_single_buffer(sock, invalid_buff):
        return send_query_before_invalid(sock, invalid_buff, single_buffer=True)

    return locals()[request.param]


def test_prefix_less_than_header(kresd_sock, send_query_before):
    """Prefix is less than the length of the DNS message header."""
    wire, _ = utils.prepare_wire()
    datalen = 11  # DNS header size minus 1
    invalid_buff = utils.prepare_buffer(wire, datalen)

    send_query_before(kresd_sock, invalid_buff)
    send_invalid_repeatedly(kresd_sock, invalid_buff)


def test_prefix_greater_than_message(kresd_sock, send_query_before):
    """Prefix is greater than the length of the entire DNS message."""
    wire, _ = utils.prepare_wire()
    datalen = len(wire) + 16
    invalid_buff = utils.prepare_buffer(wire, datalen)

    send_query_before(kresd_sock, invalid_buff)
    send_invalid_repeatedly(kresd_sock, invalid_buff)


def test_prefix_cuts_message(kresd_sock, send_query_before):
    """Prefix is greater than the length of the DNS message header, but shorter than
    the entire DNS message."""
    wire, _ = utils.prepare_wire()
    datalen = 14  # DNS Header size plus 2
    assert datalen < len(wire)
    invalid_buff = utils.prepare_buffer(wire, datalen)

    send_query_before(kresd_sock, invalid_buff)
    send_invalid_repeatedly(kresd_sock, invalid_buff)


def test_trailing_garbage(kresd_sock):
    """Send messages with trailing garbage (its length included in prefix)."""
    for _ in range(10):
        wire, msgid = utils.prepare_wire()
        wire += utils.get_garbage(8)
        buff = utils.prepare_buffer(wire)

        kresd_sock.sendall(buff)
        answer = utils.receive_parse_answer(kresd_sock)
        assert answer.id == msgid

        time.sleep(0.1)
