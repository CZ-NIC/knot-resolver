# SPDX-License-Identifier: GPL-3.0-or-later
"""TLS rehandshake test

Test is using TLS proxy with rehandshake. When queries are sent, they are
simply forwarded. When the responses are sent back, a rehandshake is performed
after every 8 bytes.

It is expected the answer will be received by the source kresd instance
and sent back to the client (this test).
"""

import re
import time

import pytest

from proxy import HINTS, kresd_tls_client, resolve_hint, TLSProxy


def verify_rehandshake(tmpdir, proxy):
    with kresd_tls_client(str(tmpdir), proxy) as kresd:
        sock2 = kresd.ip_tcp_socket()
        try:
            for hint in HINTS:
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
            assert n_connecting_to == 1  # should connect exactly once
            assert n_rehandshake > 0


def test_proxy_rehandshake_tls12(tmpdir):
    proxy = TLSProxy(rehandshake=True)
    verify_rehandshake(tmpdir, proxy)


# TODO fix TLS v1.3 proxy / kresd rehandshake
@pytest.mark.xfail(
    reason="TLS 1.3 rehandshake isn't properly supported either in tlsproxy or in kresd")
def test_proxy_rehandshake_tls13(tmpdir):
    proxy = TLSProxy(rehandshake=True, force_tls13=True)
    verify_rehandshake(tmpdir, proxy)
