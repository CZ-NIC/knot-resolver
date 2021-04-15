# SPDX-License-Identifier: GPL-3.0-or-later
"""TCP Connection Management tests"""

import socket
import struct
import time

import pytest

import utils


@pytest.mark.parametrize('garbage_lengths', [
    (1,),
    (1024,),
    (65533,),  # max size garbage
    (65533, 65533),
    (1024, 1024, 1024),
    # (0,),       # currently kresd uses this as a heuristic of "lost in bytestream"
    # (0, 1024),  # and closes the connection
])
def test_ignore_garbage(kresd_sock, garbage_lengths, single_buffer, query_before):
    """Send chunk of garbage, prefixed by garbage length. It should be ignored."""
    buff = b''
    if query_before:  # optionally send initial query
        msg_buff_before, msgid_before = utils.get_msgbuff()
        if single_buffer:
            buff += msg_buff_before
        else:
            kresd_sock.sendall(msg_buff_before)

    for glength in garbage_lengths:  # prepare garbage data
        if glength is None:
            continue
        garbage_buff = utils.get_prefixed_garbage(glength)
        if single_buffer:
            buff += garbage_buff
        else:
            kresd_sock.sendall(garbage_buff)

    msg_buff, msgid = utils.get_msgbuff()  # final query
    buff += msg_buff
    kresd_sock.sendall(buff)

    if query_before:
        answer_before = utils.receive_parse_answer(kresd_sock)
        assert answer_before.id == msgid_before
    answer = utils.receive_parse_answer(kresd_sock)
    assert answer.id == msgid


def test_pipelining(kresd_sock):
    """
    First query takes longer to resolve - answer to second query should arrive sooner.

    This test requires internet connection.
    """
    # initialization (to avoid issues with net.ipv6=true)
    buff_pre, msgid_pre = utils.get_msgbuff('0.delay.getdnsapi.net.')
    kresd_sock.sendall(buff_pre)
    msg_answer = utils.receive_parse_answer(kresd_sock)
    assert msg_answer.id == msgid_pre

    # test
    buff1, msgid1 = utils.get_msgbuff('1500.delay.getdnsapi.net.', msgid=1)
    buff2, msgid2 = utils.get_msgbuff('1.delay.getdnsapi.net.', msgid=2)
    buff = buff1 + buff2
    kresd_sock.sendall(buff)

    msg_answer = utils.receive_parse_answer(kresd_sock)
    assert msg_answer.id == msgid2

    msg_answer = utils.receive_parse_answer(kresd_sock)
    assert msg_answer.id == msgid1


@pytest.mark.parametrize('duration, delay', [
    (utils.MAX_TIMEOUT, 0.1),
    (utils.MAX_TIMEOUT, 3),
    (utils.MAX_TIMEOUT, 7),
    (utils.MAX_TIMEOUT + 10, 3),
])
def test_long_lived(kresd_sock, duration, delay):
    """Establish and keep connection alive for longer than maximum timeout."""
    utils.ping_alive(kresd_sock)
    end_time = time.time() + duration

    while time.time() < end_time:
        time.sleep(delay)
        utils.ping_alive(kresd_sock)


def test_close(kresd_sock, query_before):
    """Establish a connection and wait for timeout from kresd."""
    if query_before:
        utils.ping_alive(kresd_sock)
    time.sleep(utils.MAX_TIMEOUT)

    with utils.expect_kresd_close():
        utils.ping_alive(kresd_sock)


def test_slow_lorris(kresd_sock, query_before):
    """Simulate slow-lorris attack by sending byte after byte with delays in between."""
    if query_before:
        utils.ping_alive(kresd_sock)

    buff, _ = utils.get_msgbuff()
    end_time = time.time() + utils.MAX_TIMEOUT

    with utils.expect_kresd_close():
        assert(0)
        for i in range(len(buff)):
            b = buff[i:i+1]
            kresd_sock.send(b)
            if time.time() > end_time:
                break
            time.sleep(1)


@pytest.mark.parametrize('sock_func_name', [
    'ip_tcp_socket',
    'ip6_tcp_socket',
])
def test_oob(kresd, sock_func_name):
    """TCP out-of-band (urgent) data must not crash resolver."""
    make_sock = getattr(kresd, sock_func_name)
    sock = make_sock()
    msg_buff, msgid = utils.get_msgbuff()
    sock.sendall(msg_buff, socket.MSG_OOB)

    try:
        msg_answer = utils.receive_parse_answer(sock)
        assert msg_answer.id == msgid
    except ConnectionError:
        pass  # TODO kresd responds with TCP RST, this should be fixed

    # check kresd is alive
    sock2 = make_sock()
    utils.ping_alive(sock2)


def flood_buffer(msgcount):
    flood_buff = bytes()
    msgbuff, _ = utils.get_msgbuff()
    noid_msgbuff = msgbuff[2:]

    def gen_msg(msgid):
        return struct.pack("!H", len(msgbuff)) + struct.pack("!H", msgid) + noid_msgbuff

    for i in range(msgcount):
        flood_buff += gen_msg(i)
    return flood_buff


def test_query_flood_close(make_kresd_sock):
    """Flood resolver with queries and close the connection."""
    buff = flood_buffer(10000)
    sock1 = make_kresd_sock()
    sock1.sendall(buff)
    sock1.close()

    sock2 = make_kresd_sock()
    utils.ping_alive(sock2)


def test_query_flood_no_recv(make_kresd_sock):
    """Flood resolver with queries but don't read any data."""
    # A use-case for TCP_USER_TIMEOUT socket option? See RFC 793 and RFC 5482

    # It seems it doesn't works as expected.  libuv doesn't return any error
    # (neither on uv_write() call, not in the callback) when kresd sends answers,
    # so kresd can't recognize that client didn't read any answers.  At a certain
    # point, kresd stops receiving queries from the client (whilst client keep
    # sending) and closes connection due to timeout.

    buff = flood_buffer(10000)
    sock1 = make_kresd_sock()
    end_time = time.time() + utils.MAX_TIMEOUT

    with utils.expect_kresd_close(rst_ok=True):  # connection must be closed
        while time.time() < end_time:
            sock1.sendall(buff)
            time.sleep(0.5)

    sock2 = make_kresd_sock()
    utils.ping_alive(sock2)  # resolver must stay alive


@pytest.mark.parametrize('glength, gcount, delay', [
    (65533, 100, 0.5),
    (0, 100000, 0.5),
    (1024, 1000, 0.5),
    (65533, 1, 0),
    (0, 1, 0),
    (1024, 1, 0),
])
def test_query_flood_garbage(make_kresd_silent_sock, glength, gcount, delay, query_before):
    """Flood resolver with prefixed garbage."""
    sock1 = make_kresd_silent_sock()
    if query_before:
        utils.ping_alive(sock1)

    gbuff = utils.get_prefixed_garbage(glength)
    buff = gbuff * gcount

    end_time = time.time() + utils.MAX_TIMEOUT

    with utils.expect_kresd_close(rst_ok=True):  # connection must be closed
        while time.time() < end_time:
            sock1.sendall(buff)
            time.sleep(delay)

    sock2 = make_kresd_silent_sock()
    utils.ping_alive(sock2)  # resolver must stay alive
