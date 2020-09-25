# SPDX-License-Identifier: GPL-3.0-or-later
"""TCP Connection Management tests - prefix length

RFC1035
4.2.2. TCP usage
The message is prefixed with a two byte length field which gives the message
length, excluding the two byte length field.

The following test suite focuses on edge cases for the prefix - when it
is either too short or too long, instead of matching the length of DNS
message exactly.
"""

import time

import pytest

import utils


@pytest.fixture(params=[
    'no_query_before',
    'query_before',
    'query_before_in_single_buffer',
])
def send_query(request):
    """Function sends a buffer, either by itself, or with a valid query before.
    If a valid query is sent before, it can be sent either in a separate buffer, or
    along with the provided buffer."""

    # pylint: disable=possibly-unused-variable

    def no_query_before(sock, buff):  # pylint: disable=unused-argument
        sock.sendall(buff)

    def query_before(sock, buff, single_buffer=False):
        """Send an initial query and expect a response."""
        msg_buff, msgid = utils.get_msgbuff()

        if single_buffer:
            sock.sendall(msg_buff + buff)
        else:
            sock.sendall(msg_buff)
            sock.sendall(buff)

        answer = utils.receive_parse_answer(sock)
        assert answer.id == msgid

    def query_before_in_single_buffer(sock, buff):
        return query_before(sock, buff, single_buffer=True)

    return locals()[request.param]


@pytest.mark.parametrize('datalen', [
  1,   # just one byte of DNS header
  11,  # DNS header size minus 1
  14,  # DNS Header size plus 2
])
def test_prefix_cuts_message(kresd_sock, datalen, send_query):
    """Prefix is shorter than the DNS message."""
    wire, _ = utils.prepare_wire()
    assert datalen < len(wire)
    invalid_buff = utils.prepare_buffer(wire, datalen)

    send_query(kresd_sock, invalid_buff)  # buffer breaks parsing of TCP stream

    with utils.expect_kresd_close():
        utils.ping_alive(kresd_sock)


def test_prefix_greater_than_message(kresd_sock, send_query):
    """Prefix is greater than the length of the entire DNS message."""
    wire, invalid_msgid = utils.prepare_wire()
    datalen = len(wire) + 16
    invalid_buff = utils.prepare_buffer(wire, datalen)

    send_query(kresd_sock, invalid_buff)

    valid_buff, _ = utils.get_msgbuff()
    kresd_sock.sendall(valid_buff)

    # invalid_buff is answered (treats additional data as trailing garbage)
    answer = utils.receive_parse_answer(kresd_sock)
    assert answer.id == invalid_msgid

    # parsing stream is broken by the invalid_buff, valid query is never answered
    with utils.expect_kresd_close():
        utils.receive_parse_answer(kresd_sock)


@pytest.mark.parametrize('glength', [
    0,
    1,
    8,
    1024,
    4096,
    20000,
])
def test_prefix_trailing_garbage(kresd_sock, glength, query_before):
    """Send messages with trailing garbage (its length included in prefix)."""
    if query_before:
        utils.ping_alive(kresd_sock)

    for _ in range(10):
        wire, msgid = utils.prepare_wire()
        wire += utils.get_garbage(glength)
        buff = utils.prepare_buffer(wire)

        kresd_sock.sendall(buff)
        answer = utils.receive_parse_answer(kresd_sock)
        assert answer.id == msgid

        time.sleep(0.1)
