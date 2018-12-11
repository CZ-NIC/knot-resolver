"""TLS test when forward target closes connection after one second

Test utilizes random_close/tls-proxy, which forwards queries to configured
resolver, but closes the connection 1s after establishing.

Kresd must stay alive and be able to answer queries.

Make sure to run `make all` in `random_close/` to compile the proxy.
"""

import os
import random
import string
import time

import pytest

from kresd import Forward, make_kresd, PYTESTS_DIR
import proxyutils
import utils


PROXY_PATH = os.path.join(PYTESTS_DIR, 'random_close', 'tlsproxy')

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


@pytest.mark.skipif(not os.path.exists(PROXY_PATH),
                    reason="{} not found (did you compile it?)".format(PROXY_PATH))
def test_proxy_random_close(tmpdir):
    # run forward target instance
    workdir = os.path.join(str(tmpdir), 'kresd_fwd_target')
    os.makedirs(workdir)

    with make_kresd(workdir, hints=proxyutils.HINTS, port=54010,
                    verbose=False) as kresd_fwd_target:
        sock = kresd_fwd_target.ip_tls_socket()
        proxyutils.resolve_hint(sock, list(proxyutils.HINTS.keys())[0])

        with proxyutils.proxy(PROXY_PATH):
            # run test kresd instance
            workdir2 = os.path.join(str(tmpdir), 'kresd')
            os.makedirs(workdir2)
            forward = Forward(
                proto='tls', ip='127.0.0.1', port=54021,
                hostname='transport-test-server.com', ca_file=proxyutils.PROXY_CA_FILE)
            with make_kresd(workdir2, forward=forward, policy_test_pass=True,
                            verbose=False) as kresd:
                sock2 = kresd.ip_tcp_socket()
                rsa_cannon(sock2, 20)
                sock3 = kresd.ip_tcp_socket()
                for hint in proxyutils.HINTS:
                    proxyutils.resolve_hint(sock3, hint)
