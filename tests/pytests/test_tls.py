# SPDX-License-Identifier: GPL-3.0-or-later
"""TLS-specific tests"""

import itertools
import os
from socket import AF_INET, AF_INET6
import ssl
import sys

import pytest

from kresd import make_kresd
import utils


def test_tls_no_cert(kresd, sock_family):
    """Use TLS without certificates."""
    sock, dest = kresd.stream_socket(sock_family, tls=True)
    ctx = utils.make_ssl_context(insecure=True)
    ssock = ctx.wrap_socket(sock)
    ssock.connect(dest)

    utils.ping_alive(ssock)


def test_tls_selfsigned_cert(kresd_tt, sock_family):
    """Use TLS with a self signed certificate."""
    sock, dest = kresd_tt.stream_socket(sock_family, tls=True)
    ctx = utils.make_ssl_context(verify_location=kresd_tt.tls_cert_path)
    ssock = ctx.wrap_socket(sock, server_hostname='transport-test-server.com')
    ssock.connect(dest)

    utils.ping_alive(ssock)


def test_tls_cert_hostname_mismatch(kresd_tt, sock_family):
    """Attempt to use self signed certificate and incorrect hostname."""
    sock, dest = kresd_tt.stream_socket(sock_family, tls=True)
    ctx = utils.make_ssl_context(verify_location=kresd_tt.tls_cert_path)
    ssock = ctx.wrap_socket(sock, server_hostname='wrong-host-name')

    with pytest.raises(ssl.CertificateError):
        ssock.connect(dest)


@pytest.mark.skipif(sys.version_info < (3, 6),
                    reason="requires python3.6 or higher")
@pytest.mark.parametrize('sf1, sf2, sf3', itertools.product(
    [AF_INET, AF_INET6], [AF_INET, AF_INET6], [AF_INET, AF_INET6]))
def test_tls_session_resumption(tmpdir, sf1, sf2, sf3):
    """Attempt TLS session resumption against the same kresd instance and a different one."""
    # TODO ensure that session can't be resumed after session ticket key regeneration
    # at the first kresd instance

    # NOTE TLS 1.3 is intentionally disabled for session resumption tests,
    # because python's SSLSocket.session isn't compatible with TLS 1.3
    # https://docs.python.org/3/library/ssl.html?highlight=ssl%20ticket#tls-1-3

    def connect(kresd, ctx, sf, session=None):
        sock, dest = kresd.stream_socket(sf, tls=True)
        ssock = ctx.wrap_socket(
            sock, server_hostname='transport-test-server.com', session=session)
        ssock.connect(dest)
        new_session = ssock.session
        assert new_session.has_ticket
        assert ssock.session_reused == (session is not None)
        utils.ping_alive(ssock)
        ssock.close()
        return new_session

    workdir = os.path.join(str(tmpdir), 'kresd')
    os.makedirs(workdir)

    with make_kresd(workdir, 'tt') as kresd:
        ctx = utils.make_ssl_context(
            verify_location=kresd.tls_cert_path, extra_options=[ssl.OP_NO_TLSv1_3])
        session = connect(kresd, ctx, sf1)  # initial conn
        connect(kresd, ctx, sf2, session)  # resume session on the same instance

    workdir2 = os.path.join(str(tmpdir), 'kresd2')
    os.makedirs(workdir2)
    with make_kresd(workdir2, 'tt') as kresd2:
        connect(kresd2, ctx, sf3, session)  # resume session on a different instance
