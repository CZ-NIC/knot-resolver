# SPDX-License-Identifier: GPL-3.0-or-later

import socket

import pytest

from kresd import init_portdir, make_kresd


@pytest.fixture
def kresd(tmpdir):
    with make_kresd(tmpdir) as kresd:
        yield kresd


@pytest.fixture
def kresd_silent(tmpdir):
    with make_kresd(tmpdir, verbose=False) as kresd:
        yield kresd


@pytest.fixture
def kresd_tt(tmpdir):
    with make_kresd(tmpdir, 'tt') as kresd:
        yield kresd


@pytest.fixture(params=[
    'ip_tcp_socket',
    'ip6_tcp_socket',
    'ip_tls_socket',
    'ip6_tls_socket',
])
def make_kresd_sock(request, kresd):
    """Factory function to create sockets of the same kind."""
    sock_func = getattr(kresd, request.param)

    def _make_kresd_sock():
        return sock_func()

    return _make_kresd_sock


@pytest.fixture(params=[
    'ip_tcp_socket',
    'ip6_tcp_socket',
    'ip_tls_socket',
    'ip6_tls_socket',
])
def make_kresd_silent_sock(request, kresd_silent):
    """Factory function to create sockets of the same kind (no verbose)."""
    sock_func = getattr(kresd_silent, request.param)

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


@pytest.fixture(params=[
    True,
    False
])
def single_buffer(request):  # whether to send all data in a single buffer
    return request.param


@pytest.fixture(params=[
    True,
    False
])
def query_before(request):  # whether to send an initial query
    return request.param


@pytest.mark.optionalhook
def pytest_metadata(metadata):  # filter potentially sensitive data from GitLab CI
    keys_to_delete = []
    for key in metadata.keys():
        key_lower = key.lower()
        if 'password' in key_lower or 'token' in key_lower or \
                key_lower.startswith('ci') or key_lower.startswith('gitlab'):
            keys_to_delete.append(key)
    for key in keys_to_delete:
        del metadata[key]


def pytest_sessionstart(session):  # pylint: disable=unused-argument
    init_portdir()
