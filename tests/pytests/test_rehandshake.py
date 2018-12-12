"""TLS rehandshake test

Test utilizes rehandshake/tls-proxy, which forwards queries to configured
resolver, but when it sends the response back to the query source, it
performs a rehandshake after every 8 bytes sent.

It is expected the answer will be received by the source kresd instance
and sent back to the client (this test).

Make sure to run `make all` in `rehandshake/` to compile the proxy.
"""

import re
import time

from proxy import HINTS, kresd_tls_client, resolve_hint, TLSProxy


def test_proxy_rehandshake(tmpdir):
    proxy = TLSProxy()

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
            assert n_connecting_to == 0  # shouldn't be present in partial log
            assert n_rehandshake > 0
