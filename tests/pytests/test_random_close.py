# SPDX-License-Identifier: GPL-3.0-or-later
"""TLS test when forward target closes connection after one second

Test utilizes TLS proxy, which forwards queries to configured
resolver, but closes the connection 1s after establishing.

Kresd must stay alive and be able to answer queries.
"""

import random
import string
import time

from proxy import HINTS, kresd_tls_client, resolve_hint, TLSProxy
import utils


QPS = 500


def random_string(size=32, chars=(string.ascii_lowercase + string.digits)):
    return ''.join(random.choice(chars) for x in range(size))


def rsa_cannon(sock, duration, domain='test.', qps=QPS):
    end_time = time.time() + duration

    while time.time() < end_time:
        next_time = time.time() + 1/qps
        buff, _ = utils.get_msgbuff('{}.{}'.format(random_string(), domain))
        sock.sendall(buff)
        time_left = next_time - time.time()
        if time_left > 0:
            time.sleep(time_left)


def test_proxy_random_close(tmpdir):
    proxy = TLSProxy(close=1000)

    kresd_tls_client_kwargs = {
        'verbose': False,
        'policy_test_pass': True
        }
    kresd_fwd_target_kwargs = {
        'verbose': False
        }
    with kresd_tls_client(str(tmpdir), proxy, kresd_tls_client_kwargs, kresd_fwd_target_kwargs) \
            as kresd:
        sock2 = kresd.ip_tcp_socket()
        rsa_cannon(sock2, 20)
        sock3 = kresd.ip_tcp_socket()
        for hint in HINTS:
            resolve_hint(sock3, hint)
            time.sleep(0.1)
