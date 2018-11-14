"""TCP Connection Management tests"""

import time

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
