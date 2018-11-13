"""TCP Connection Management tests"""
import struct
import time

import dns
import dns.message
import pytest

import utils


def test_ignore_garbage(kresd_sock):
    """
    Send chunk of garbage, correctly prefixed by garbage length. Then, send
    correct DNS query.

    Expected: garbage must be ignored and the second query must be answered
    """
    MSG_ID = 1

    msg = utils.get_msgbuf('localhost.', dns.rdatatype.A, MSG_ID)
    garbage = utils.get_prefixed_garbage(1024)
    buf = garbage + msg

    kresd_sock.sendall(buf)
    msg_answer = utils.receive_parse_answer(kresd_sock)

    assert msg_answer.id == MSG_ID


def test_pipelining(kresd_sock):
    """
    Test sends two queries to kresd - 1000.delay.getdnsapi.net and 1.delay.getdnsapi.net.

    Expected: answer to the second query must come first.
    """
    MSG_ID_FIRST = 1
    MSG_ID_SECOND = 2

    buf = utils.get_msgbuf('1000.delay.getdnsapi.net.', dns.rdatatype.A, MSG_ID_FIRST) \
        + utils.get_msgbuf('1.delay.getdnsapi.net.', dns.rdatatype.A, MSG_ID_SECOND)

    kresd_sock.sendall(buf)
    msg_answer = utils.receive_parse_answer(kresd_sock)

    assert msg_answer.id == MSG_ID_SECOND


def test_prefix_shorter_than_header(kresd_sock):
    """
    Test prefixes message by the value, which is less then the length of the DNS
    message header and sequentially sends it over TCP connection. (RFC1035 4.2.2)

    Expected: TCP connection must be closed after `net.tcp_in_idle` milliseconds.
              (by default, after about 10s after connection is established)
    """
    msg = dns.message.make_query('localhost.', dns.rdatatype.A, dns.rdataclass.IN)
    data = msg.to_wire()
    datalen = 11  # DNS Header size minus 1
    buf = struct.pack("!H", datalen) + data

    for _ in range(15):
        try:
            kresd_sock.sendall(buf)
        except BrokenPipeError:
            break
        else:
            time.sleep(1)
    else:
        assert False, "kresd didn't close connection"


def test_prefix_longer_than_message(kresd_sock):
    """
    Test prefixes message by the value, which is greater then the length of the
    whole message and sequentially sends it over TCP connection.

    Expected: TCP connection must be closed after net.tcp_in_idle milliseconds
    """
    msg = dns.message.make_query('localhost.', dns.rdatatype.A, dns.rdataclass.IN)
    data = msg.to_wire()
    datalen = len(data) + 16
    buf = struct.pack("!H", datalen) + data

    # TODO check the removal of sendall + sleep(2) was safe

    for _ in range(15):
        try:
            kresd_sock.sendall(buf)
        except BrokenPipeError:
            break
        else:
            time.sleep(1)
    else:
        assert False, "kresd didn't close the connection"


def test_prefix_cuts_message(kresd_sock):
    """
    Test prefixes message by value, which is greater than the
    length of DNS message header but less than length of the whole DNS message
    and sequentially sends it over TCP connection.

    Expected: TCP connection must be closed after approx. 13 seconds after establishing.
    13 s is a sum of two timeouts
    1) 3 seconds is a result of TCP_DEFER_ACCEPT server socket option
    2) 10 second is a default kresd idle timeout for tcp connection (net.tcp_in_idle())
    """
    msg = dns.message.make_query('localhost.', dns.rdatatype.A, dns.rdataclass.IN)
    data = msg.to_wire()
    datalen = 14  # DNS Header size plus 2
    assert datalen < len(data)
    buf = struct.pack("!H", datalen) + data

    for _ in range(15):
        try:
            kresd_sock.sendall(buf)
        except BrokenPipeError:
            break
        else:
            time.sleep(1)
    else:
        assert False, "kresd didn't close the connection"


def test_prefix_cut_message_after_ok(kresd_sock):
    """
    At first test send normal DNS message. Then, it sequentially sends DNS message
    with incorrect prefix, which is greater than the length of DNS message header,
    but less than length of the whole DNS message.

    Expected: TCP connection is closed after a timeout period.
    """
    NORMAL_MSG_ID = 1
    CUT_MSG_ID = 2
    buf_normal = utils.get_msgbuf('localhost.', dns.rdatatype.A, NORMAL_MSG_ID)

    msg = dns.message.make_query('localhost.', dns.rdatatype.A, dns.rdataclass.IN)
    msg.id = CUT_MSG_ID
    data = msg.to_wire()
    datalen = 14  # DNS Header size plus 2
    assert datalen < len(data)
    buf_cut = struct.pack("!H", datalen) + data

    kresd_sock.sendall(buf_normal)
    kresd_sock.sendall(buf_cut)

    msg_answer = utils.receive_parse_answer(kresd_sock)
    assert msg_answer.id == NORMAL_MSG_ID

    for _ in range(12):
        try:
            kresd_sock.sendall(buf_cut)
        except BrokenPipeError:
            break
        except ConnectionResetError:
            break
        else:
            time.sleep(1)
    else:
        assert False, "kresd didn't close the connection"


def test_prefix_trailing_garbage(kresd_sock):
    """
    Test repeatedly sends correct message with garbage after the message's end.
    Message is prefixed by the length that includes garbage length.

    Expected: TCP connection must not be closed until all the queries have been sent
    """
    msg = dns.message.make_query('localhost.', dns.rdatatype.A, dns.rdataclass.IN)
    msg.id = 1

    for _ in range(10):
        msg.id += 1
        data = msg.to_wire() + b'garbage'
        data_len = len(data)
        buf = struct.pack("!H", data_len) + data
        try:
            kresd_sock.sendall(buf)
        except BrokenPipeError:
            raise pytest.fail("kresd closed the connection")

        try:
            msg_answer = utils.receive_parse_answer(kresd_sock)
        except BrokenPipeError:
            raise pytest.fail("kresd closed the connection")
        else:
            assert msg_answer.id == msg.id

        time.sleep(0.1)
