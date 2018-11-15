"""Tests with TLS certificates"""

import ssl

import pytest

import utils


def test_tls_no_cert(kresd, sock_family):
    sock, dest = kresd.stream_socket(sock_family, tls=True)
    ctx = utils.make_ssl_context(insecure=True)
    ssock = ctx.wrap_socket(sock)
    ssock.connect(dest)

    utils.ping_alive(ssock)


def test_tls_selfsigned_cert(kresd_tt, sock_family):
    sock, dest = kresd_tt.stream_socket(sock_family, tls=True)
    ctx = utils.make_ssl_context(verify_location=kresd_tt.tls_cert_path)
    ssock = ctx.wrap_socket(sock, server_hostname='transport-test-server.com')
    ssock.connect(dest)

    utils.ping_alive(ssock)


def test_tls_cert_hostname_mismatch(kresd_tt, sock_family):
    sock, dest = kresd_tt.stream_socket(sock_family, tls=True)
    ctx = utils.make_ssl_context(verify_location=kresd_tt.tls_cert_path)
    ssock = ctx.wrap_socket(sock, server_hostname='wrong-host-name')

    with pytest.raises(ssl.CertificateError):
        ssock.connect(dest)
