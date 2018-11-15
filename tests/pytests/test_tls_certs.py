"""Tests with TLS certificates"""

import utils


def test_tls_no_cert(kresd, sock_family):
    sock, dest = kresd.stream_socket(sock_family, tls=True)
    ctx = utils.make_ssl_context(insecure=True)
    ssock = ctx.wrap_socket(sock)
    ssock.connect(dest)

    utils.ping_alive(ssock)
