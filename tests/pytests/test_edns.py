# SPDX-License-Identifier: GPL-3.0-or-later
"""EDNS tests"""

import dns
import pytest

import utils


@pytest.mark.parametrize('dname, code, text', [
    ('deny.test.', dns.edns.EDECode.BLOCKED, 'CR36'),
    ('refuse.test.', dns.edns.EDECode.PROHIBITED, 'EIM4'),
    ('forge.test.', dns.edns.EDECode.FORGED_ANSWER, '5DO5'),
])
def test_edns_ede(kresd_sock, dname, code, text):
    """Check that kresd responds with EDNS EDE codes in selected cases."""
    buff, msgid = utils.get_msgbuff(dname)
    kresd_sock.sendall(buff)
    answer = utils.receive_parse_answer(kresd_sock)
    assert answer.id == msgid
    assert answer.options[0].code == code
    assert answer.options[0].text == text
