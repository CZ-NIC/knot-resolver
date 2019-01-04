"""TLS rehandshake test

Test utilizes rehandshake/tls-proxy, which forwards queries to configured
resolver, but when it sends the response back to the query source, it
performs a rehandshake after every 8 bytes sent.

It is expected the answer will be received by the source kresd instance
and sent back to the client (this test).

Make sure to run `make all` in `rehandshake/` to compile the proxy.
"""

import os
import re
import subprocess
import time

import dns
import dns.rcode
import pytest

from kresd import CERTS_DIR, Forward, make_kresd, PYTESTS_DIR
import utils


REHANDSHAKE_PROXY = os.path.join(PYTESTS_DIR, 'rehandshake', 'tlsproxy')


@pytest.mark.skipif(not os.path.exists(REHANDSHAKE_PROXY),
                    reason="tlsproxy not found (did you compile it?)")
def test_rehandshake(tmpdir):
    def resolve_hint(sock, qname):
        buff, msgid = utils.get_msgbuff(qname)
        sock.sendall(buff)
        answer = utils.receive_parse_answer(sock)
        assert answer.id == msgid
        assert answer.rcode() == dns.rcode.NOERROR
        assert answer.answer[0][0].address == '127.0.0.1'

    hints = {
        '0.foo.': '127.0.0.1',
        '1.foo.': '127.0.0.1',
        '2.foo.': '127.0.0.1',
        '3.foo.': '127.0.0.1',
    }
    # run forward target instance
    workdir = os.path.join(str(tmpdir), 'kresd_fwd_target')
    os.makedirs(workdir)

    with make_kresd(workdir, hints=hints, port=53910) as kresd_fwd_target:
        sock = kresd_fwd_target.ip_tls_socket()
        resolve_hint(sock, '0.foo.')

        # run proxy
        cwd, cmd = os.path.split(REHANDSHAKE_PROXY)
        cmd = './' + cmd
        ca_file = os.path.join(CERTS_DIR, 'tt.cert.pem')
        try:
            proxy = subprocess.Popen(
                [cmd], cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # run test kresd instance
            workdir2 = os.path.join(str(tmpdir), 'kresd')
            os.makedirs(workdir2)
            forward = Forward(proto='tls', ip='127.0.0.1', port=53921,
                              hostname='transport-test-server.com', ca_file=ca_file)
            with make_kresd(workdir2, forward=forward) as kresd:
                sock2 = kresd.ip_tcp_socket()
                try:
                    for hint in hints:
                        resolve_hint(sock2, hint)
                        time.sleep(0.1)
                finally:
                    # verify log
                    n_connecting_to = 0
                    n_rehandshake = 0
                    partial_log = kresd.partial_log()
                    print(partial_log)
                    for line in partial_log.splitlines():
                        if re.search(r"connecting to: .*", line) is not None:
                            n_connecting_to += 1
                        elif re.search(r"TLS rehandshake .* has started", line) is not None:
                            n_rehandshake += 1
                    # assert n_connecting_to == 0  # shouldn't be present in partial log
                    assert n_rehandshake > 0
        finally:
            proxy.terminate()
