# SPDX-License-Identifier: GPL-3.0-or-later

"""Test opening as many connections as possible.

Due to resource-intensity of this test, it's filename doesn't contain
"test" on purpose, so it doesn't automatically get picked up by pytest
(to allow easy parallel testing).

To execute this test, pass the filename of this file to pytest directly.
Also, make sure not to use parallel execution (-n).
"""

import resource
import time

import pytest

from kresd import Kresd
import utils


MAX_SOCKETS = 10000  # upper bound of how many connections to open
MAX_ITERATIONS = 10  # number of iterations to run the test

# we can't use softlimit ifself since kresd already has open sockets,
# so use lesser value
RESERVED_NOFILE = 40  # 40 is empirical value


@pytest.mark.parametrize('sock_func_name', [
    'ip_tcp_socket',
    'ip6_tcp_socket',
    'ip_tls_socket',
    'ip6_tls_socket',
])
def test_conn_flood(tmpdir, sock_func_name):
    def create_sockets(make_sock, nsockets):
        sockets = []
        next_ping = time.time() + 4  # less than tcp idle timeout / 2
        while True:
            additional_sockets = 0
            while time.time() < next_ping:
                nsock_to_init = min(100, nsockets - len(sockets))
                if not nsock_to_init:
                    return sockets
                sockets.extend([make_sock() for _ in range(nsock_to_init)])
                additional_sockets += nsock_to_init

            # large number of connections can take a lot of time to open
            # send some valid data to avoid TCP idle timeout for already open sockets
            next_ping = time.time() + 4
            for s in sockets:
                utils.ping_alive(s)

            # break when no more than 20% additional sockets are created
            if additional_sockets / len(sockets) < 0.2:
                return sockets

    max_num_of_open_files = resource.getrlimit(resource.RLIMIT_NOFILE)[0] - RESERVED_NOFILE
    nsockets = min(max_num_of_open_files, MAX_SOCKETS)

    # create kresd instance with verbose=False
    ip = '127.0.0.1'
    ip6 = '::1'
    with Kresd(tmpdir, ip=ip, ip6=ip6, verbose=False) as kresd:
        make_sock = getattr(kresd, sock_func_name)  # function for creating sockets
        sockets = create_sockets(make_sock, nsockets)
        print("\nEstablished {} connections".format(len(sockets)))

        print("Start sending data")
        for i in range(MAX_ITERATIONS):
            for s in sockets:
                utils.ping_alive(s)
            print("Iteration {} done...".format(i))

        print("Close connections")
        for s in sockets:
            s.close()

        # check in kresd is alive
        print("Check upstream is still alive")
        sock = make_sock()
        utils.ping_alive(sock)

        print("OK!")
