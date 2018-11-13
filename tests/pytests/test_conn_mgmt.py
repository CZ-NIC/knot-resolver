"""TCP Connection Management tests"""

import utils


def test_ignore_garbage(kresd_sock):
    """
    Send chunk of garbage, correctly prefixed by garbage length. Then, send
    correct DNS query.

    Expected: garbage must be ignored and the second query must be answered
    """
    buff, msgid = utils.get_msgbuff()
    kresd_sock.sendall(buff)

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
