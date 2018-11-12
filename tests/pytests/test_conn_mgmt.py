"""TCP Connection Management tests"""

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
