"""TCP Connection Management tests"""

import struct
import time

import pytest

import utils


def test_ignore_garbage(kresd_sock):
    """
    Send chunk of garbage, correctly prefixed by garbage length. Then, send
    correct DNS query.

    Expected: garbage must be ignored and the second query must be answered
    """
    msg_buff, msgid = utils.get_msgbuff()
    garbage_buff = utils.get_prefixed_garbage(1024)
    kresd_sock.sendall(garbage_buff + msg_buff)

    msg_answer = utils.receive_parse_answer(kresd_sock)
    assert msg_answer.id == msgid


def test_pipelining(kresd_sock):
    """
    Test sends two queries to kresd - 1000.delay.getdnsapi.net and 1.delay.getdnsapi.net.

    Expected: answer to the second query must come first.
    """
    buff1, msgid1 = utils.get_msgbuff('1000.delay.getdnsapi.net.', msgid=1)
    buff2, msgid2 = utils.get_msgbuff('1.delay.getdnsapi.net.', msgid=2)
    buff = buff1 + buff2
    kresd_sock.sendall(buff)

    msg_answer = utils.receive_parse_answer(kresd_sock)
    assert msg_answer.id == msgid2

    msg_answer = utils.receive_parse_answer(kresd_sock)
    assert msg_answer.id == msgid1


def test_long_lived(kresd_sock):
    """
    Test establishes a TCP connection a sends several queries over it. They are sent
    seqeuntially, each with a delay, which in total exceeds maximum timeout.

    Expected: kresd must not close the connection
    """
    utils.ping_alive(kresd_sock)
    end_time = time.time() + utils.MAX_TIMEOUT

    while time.time() < end_time:
        time.sleep(3)
        utils.ping_alive(kresd_sock)


@pytest.mark.parametrize('query_before', [
    True,  # test closing idle connection
    False  # test closing established connection after handshake
])
def test_close(kresd_sock, query_before):
    """
    Test establishes a TCP connection, optionally sends a query and waits for response,
    and then pauses (MAX_TIMEOUT). Afterwards, another query is sent.

    Expected: kresd closes the connection
    """
    if query_before:
        utils.ping_alive(kresd_sock)
    time.sleep(utils.MAX_TIMEOUT)

    with utils.expect_kresd_close():
        utils.ping_alive(kresd_sock)


@pytest.mark.parametrize('query_before', [
    True,  # test slow-lorris after sending valid query
    False  # test slow-lorris right after handshake
])
def test_slow_lorris(kresd_sock, query_before):
    """
    Test simulates slow-lorris attack by sending byte after byte with a delay in between.

    Expected: kresd closes the connection
    """
    if query_before:
        utils.ping_alive(kresd_sock)

    buff, _ = utils.get_msgbuff()
    end_time = time.time() + utils.MAX_TIMEOUT

    with utils.expect_kresd_close():
        for i in range(len(buff)):
            b = buff[i:i+1]
            kresd_sock.send(b)
            if time.time() > end_time:
                break
            time.sleep(1)


def test_ignore_jumbo_message(kresd_sock):
    """
    Test if kresd correcty ignores bigger queries than 4096 (current maximum size in kresd).

    Expected: jumbo message must be ignored, other queries answered
    """
    buff1, msgid1 = utils.get_msgbuff(msgid=1)
    gbuff = utils.get_prefixed_garbage(65000)  # TODO TLS with 65533 closes connection
    kresd_sock.sendall(buff1 + gbuff)

    answer = utils.receive_parse_answer(kresd_sock)
    assert answer.id == msgid1

    buff2, msgid2 = utils.get_msgbuff(msgid=2)
    kresd_sock.sendall(buff2)

    answer = utils.receive_parse_answer(kresd_sock)
    assert answer.id == msgid2


def test_query_flood_close(make_kresd_sock):
    """
    Test floods resolver with queries and closes the connection.

    Expected: resolver must not crash
    """
    def flood_buffer(msgcount):
        flood_buff = bytes()
        msgbuff, _ = utils.get_msgbuff()
        noid_msgbuff = msgbuff[2:]

        def gen_msg(msgid):
            return struct.pack("!H", len(msgbuff)) + struct.pack("!H", msgid) + noid_msgbuff

        for i in range(msgcount):
            flood_buff += gen_msg(i)
        return flood_buff

    buff = flood_buffer(10000)
    sock1 = make_kresd_sock()
    sock1.sendall(buff)
    sock1.close()

    sock2 = make_kresd_sock()
    utils.ping_alive(sock2)
