"""TCP Connection Management tests - prefix length

RFC1035
4.2.2. TCP usage
The message is prefixed with a two byte length field which gives the message
length, excluding the two byte length field.

The following test suite focuses on edge cases for the prefix - when it
is either too short or too long, instead of matching the length of DNS
message exactly.

The tests with incorrect prefix attempt to sequentially send the incorrect
message. After a certain period of time (affected by net.tcp_in_idle,
TCP_DEFER_ACCEPT, ...), kresd should close the connection.
"""

import time

import pytest

import utils


# default net.tcp_in_idle is 10s, TCP_DEFER_ACCEPT 3s, some extra for
# Python handling / edge cases
MAX_TIMEOUT = 16


def send_incorrect_repeatedly(sock, buff, delay=1):
    """Utility function to keep sending the buffer until MAX_TIMEOUT is reached.

    It is expected kresd will close the connection, since the buffer
    contains incorrect prefix of the message.

    If the connection remains open, test is failed.
    """
    end_time = time.time() + MAX_TIMEOUT

    with pytest.raises(BrokenPipeError, message="kresd didn't close connection"):
        while time.time() < end_time:
            try:
                sock.sendall(buff)
            except ConnectionResetError:
                pytest.skip("kresd closed connection with TCP RST")
            time.sleep(delay)


def test_less_than_header(kresd_sock):
    """Prefix is less than the length of the DNS message header."""
    wire = utils.prepare_wire()
    datalen = 11  # DNS header size minus 1
    buff = utils.prepare_buffer(wire, datalen)
    send_incorrect_repeatedly(kresd_sock, buff)


def test_greater_than_message(kresd_sock):
    """Prefix is greater than the length of the entire DNS message."""
    wire = utils.prepare_wire()
    datalen = len(wire) + 16
    buff = utils.prepare_buffer(wire, datalen)
    send_incorrect_repeatedly(kresd_sock, buff)


def test_cuts_message(kresd_sock):
    """Prefix is greater than the length of the DNS message header, but shorter than
    the entire DNS message."""
    wire = utils.prepare_wire()
    datalen = 14  # DNS Header size plus 2
    assert datalen < len(wire)
    buff = utils.prepare_buffer(wire, datalen)
    send_incorrect_repeatedly(kresd_sock, buff)


def test_cuts_message_after_ok(kresd_sock):
    """First, normal DNS message is sent. Afterwards, message with incorrect prefix
    (greater than header, less than entire message) is sent. First message must be
    answered, then the connection should be closed after timeout."""
    normal_msg_id = 1
    normal_wire = utils.prepare_wire(normal_msg_id)
    normal_buff = utils.prepare_buffer(normal_wire)

    cut_wire = utils.prepare_wire()
    cut_datalen = 14
    assert cut_datalen < len(cut_wire)
    cut_buff = utils.prepare_buffer(cut_wire, cut_datalen)

    kresd_sock.sendall(normal_buff)
    kresd_sock.sendall(cut_buff)

    msg_answer = utils.receive_parse_answer(kresd_sock)
    assert msg_answer.id == normal_msgid

    send_incorrect_repeatedly(kresd_sock, cut_buff)


def test_trailing_garbage(kresd_sock):
    """Prefix is correct, but the message has trailing garbage. The connection must
    stay open until all message have been sent and answered."""
    for _ in range(10):
        msgid = utils.random_msgid()
        wire = utils.prepare_wire(msgid) + utils.get_garbage(8)
        buff = utils.prepare_buffer(wire)

        kresd_sock.sendall(buff)
        answer = utils.receive_parse_answer(kresd_sock)
        assert answer.id == msgid

        time.sleep(0.1)
