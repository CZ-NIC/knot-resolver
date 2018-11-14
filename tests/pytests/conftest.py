import random
import socket

import pytest

from kresd import Kresd


def is_port_free(port, ip=None, ip6=None):
    def check(family, type_, dest):
        sock = socket.socket(family, type_)
        sock.bind(dest)
        sock.close()

    try:
        if ip is not None:
            check(socket.AF_INET, socket.SOCK_STREAM, (ip, port))
            check(socket.AF_INET, socket.SOCK_DGRAM, (ip, port))
        if ip6 is not None:
            check(socket.AF_INET6, socket.SOCK_STREAM, (ip6, port, 0, 0))
            check(socket.AF_INET6, socket.SOCK_DGRAM, (ip6, port, 0, 0))
    except OSError as exc:
        if exc.errno == 98:  # address alrady in use
            return False
        else:
            raise
    return True


@pytest.fixture
def kresd(tmpdir):
    ip = '127.0.0.1'
    ip6 = '::1'

    def make_port():
        for _ in range(10):  # max attempts
            port = random.randint(1024, 65535)
            if is_port_free(port, ip, ip6):
                return port
        raise RuntimeError("No available port found!")

    port = make_port()
    tls_port = make_port()
    with Kresd(tmpdir, port, tls_port, ip, ip6) as kresd:
        yield kresd
        # TODO: add verbose option?
        # with open(kresd.logfile_path) as log:
        #     print(log.read())  # display log for debugging purposes


@pytest.fixture(params=[
    'ip_tcp_socket',
    'ip6_tcp_socket',
    'ip_tls_socket',
    'ip6_tls_socket',
])
def kresd_sock(request, kresd):
    return getattr(kresd, request.param)()
