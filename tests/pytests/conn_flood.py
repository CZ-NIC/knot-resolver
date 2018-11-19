"""Test opening as many connections as possible.

Due to resource-intensity of this test, it's filename doesn't contain
"test" on purpose, so it doesn't automatically get picked up by pytest
(to allow easy parallel testing).

To execute this test, pass the filename of this file to pytest directly.
Also, make sure not to use parallel execution (-n).
"""

import resource
import time

import utils


MAX_SOCKETS = 25000  # upper bound of how many connections to open
MAX_ITERATIONS = 20  # number of iterations to run the test

# we can't use softlimit ifself since kresd already has open sockets,
# so use lesser value
RESERVED_NOFILE = 40  # 40 is empirical value


# TODO turn off verbose - generates a lot of data
def test_conn_flood(make_kresd_sock):
    def create_sockets(nsockets):
        buff, _ = utils.get_msgbuff()
        sockets = []

        next_ping = time.time() + 5  # less than tcp idle timeout
        while True:
            while time.time() < next_ping:
                nsock_to_init = min(100, nsockets - len(sockets))
                if not nsock_to_init:
                    return sockets
                sockets.extend([make_kresd_sock() for _ in range(nsock_to_init)])

            # large number of connections can take a lot of time to open
            # send some valid data to avoid TCP idle timeout for already open sockets
            for s in sockets:
                s.sendall(buff)
            next_ping = time.time() + 5

    max_num_of_open_files = resource.getrlimit(resource.RLIMIT_NOFILE)[0] - RESERVED_NOFILE
    nsockets = min(max_num_of_open_files, MAX_SOCKETS)

    print("\nEstablishing {} connections".format(nsockets))
    sockets = create_sockets(nsockets)

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
    sock = make_kresd_sock()
    utils.ping_alive(sock)

    print("OK!")
