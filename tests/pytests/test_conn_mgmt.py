"""TCP Connection Management tests"""
import struct
import time

import dns
import dns.message

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
