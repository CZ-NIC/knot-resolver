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
import time

import pytest

from kresd import Forward, make_kresd, PYTESTS_DIR
import proxyutils


PROXY_PATH = os.path.join(PYTESTS_DIR, 'rehandshake', 'tlsproxy')


@pytest.mark.skipif(not os.path.exists(PROXY_PATH),
                    reason="{} not found (did you compile it?)".format(PROXY_PATH))
def test_proxy_rehandshake(tmpdir):
    # run forward target instance
    workdir = os.path.join(str(tmpdir), 'kresd_fwd_target')
    os.makedirs(workdir)

    with make_kresd(workdir, hints=proxyutils.HINTS, port=53910) as kresd_fwd_target:
        sock = kresd_fwd_target.ip_tls_socket()
        proxyutils.resolve_hint(sock, list(proxyutils.HINTS.keys())[0])

        with proxyutils.proxy(PROXY_PATH):
            # run test kresd instance
            workdir2 = os.path.join(str(tmpdir), 'kresd')
            os.makedirs(workdir2)
            forward = Forward(
                proto='tls', ip='127.0.0.1', port=53921,
                hostname='transport-test-server.com', ca_file=proxyutils.PROXY_CA_FILE)
            with make_kresd(workdir2, forward=forward) as kresd:
                sock2 = kresd.ip_tcp_socket()
                try:
                    for hint in proxyutils.HINTS:
                        proxyutils.resolve_hint(sock2, hint)
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
                    assert n_connecting_to == 0  # shouldn't be present in partial log
                    assert n_rehandshake > 0
