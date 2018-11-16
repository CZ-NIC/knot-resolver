"""TLS-specific tests"""

import ssl

import pytest

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


def test_tls_cert_expired(kresd_tt_expired, sock_family):
    """Attempt to use expired certificate."""
    sock, dest = kresd_tt_expired.stream_socket(sock_family, tls=True)
    ctx = utils.make_ssl_context(verify_location=kresd_tt_expired.tls_cert_path)
    ssock = ctx.wrap_socket(sock, server_hostname='transport-test-server.com')

    with pytest.raises(ssl.SSLError):
        ssock.connect(dest)
