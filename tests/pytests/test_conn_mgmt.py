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
