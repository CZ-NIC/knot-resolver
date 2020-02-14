# SPDX-License-Identifier: GPL-3.0-or-later
from contextlib import contextmanager
import os
import subprocess

import dns
import dns.rcode

from kresd import CERTS_DIR
import utils


HINTS = {
    '0.foo.': '127.0.0.1',
    '1.foo.': '127.0.0.1',
    '2.foo.': '127.0.0.1',
    '3.foo.': '127.0.0.1',
}

PROXY_CA_FILE = os.path.join(CERTS_DIR, 'tt.cert.pem')


def resolve_hint(sock, qname):
    buff, msgid = utils.get_msgbuff(qname)
    sock.sendall(buff)
    answer = utils.receive_parse_answer(sock)
    assert answer.id == msgid
    assert answer.rcode() == dns.rcode.NOERROR
    assert answer.answer[0][0].address == HINTS[qname]


@contextmanager
def proxy(path):
    cwd, cmd = os.path.split(path)
    cmd = './' + cmd
    try:
        proxy = subprocess.Popen(
            [cmd], cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        yield proxy
    finally:
        proxy.terminate()
