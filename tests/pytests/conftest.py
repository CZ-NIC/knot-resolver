import socket

import pytest

from kresd import make_kresd


@pytest.fixture
def kresd(tmpdir):
    with make_kresd(tmpdir) as kresd:
        yield kresd


@pytest.fixture
def kresd_tt(tmpdir):
    with make_kresd(tmpdir, 'tt') as kresd:
        yield kresd


@pytest.fixture
def kresd_tt_expired(tmpdir):
    with make_kresd(tmpdir, 'tt-expired') as kresd:
        yield kresd


@pytest.fixture(params=[
    'ip_tcp_socket',
    'ip6_tcp_socket',
    'ip_tls_socket',
    'ip6_tls_socket',
])
def make_kresd_sock(request, kresd):
    sock_func = getattr(kresd, request.param)

    def _make_kresd_sock():
        return sock_func()

    return _make_kresd_sock


@pytest.fixture
def kresd_sock(make_kresd_sock):
    return make_kresd_sock()


@pytest.fixture(params=[
    socket.AF_INET,
    socket.AF_INET6,
])
def sock_family(request):
    return request.param


def pytest_configure(config):
    # don't let gitlab CI publish sensitive data in pytest html report
    config._metadata = {}  # pylint: disable=protected-access
