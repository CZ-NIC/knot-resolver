# SPDX-License-Identifier: GPL-3.0-or-later

from contextlib import contextmanager, ContextDecorator
import os
import subprocess
from typing import Any, Dict, Optional

import dns
import dns.rcode
import pytest

from kresd import CERTS_DIR, Forward, Kresd, make_kresd, make_port
import utils


HINTS = {
    '0.foo.': '127.0.0.1',
    '1.foo.': '127.0.0.1',
    '2.foo.': '127.0.0.1',
    '3.foo.': '127.0.0.1',
}


def resolve_hint(sock, qname):
    buff, msgid = utils.get_msgbuff(qname)
    sock.sendall(buff)
    answer = utils.receive_parse_answer(sock)
    assert answer.id == msgid
    assert answer.rcode() == dns.rcode.NOERROR
    assert answer.answer[0][0].address == HINTS[qname]


class Proxy(ContextDecorator):
    EXECUTABLE = ''

    def __init__(
                self,
                local_ip: str = '127.0.0.1',
                local_port: Optional[int] = None,
                upstream_ip: str = '127.0.0.1',
                upstream_port: Optional[int] = None
            ) -> None:
        self.local_ip = local_ip
        self.local_port = local_port
        self.upstream_ip = upstream_ip
        self.upstream_port = upstream_port
        self.proxy = None

    def get_args(self):
        args = []
        args.append('--local')
        args.append(self.local_ip)
        if self.local_port is not None:
            args.append('--lport')
            args.append(str(self.local_port))
        args.append('--upstream')
        args.append(self.upstream_ip)
        if self.upstream_port is not None:
            args.append('--uport')
            args.append(str(self.upstream_port))
        return args

    def __enter__(self):
        args = [self.EXECUTABLE] + self.get_args()
        print(' '.join(args))

        try:
            self.proxy = subprocess.Popen(
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pytest.skip("proxy '{}' failed to run (did you compile it?)"
                        .format(self.EXECUTABLE))

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.proxy is not None:
            self.proxy.terminate()
            self.proxy = None


class TLSProxy(Proxy):
    EXECUTABLE = 'tlsproxy'

    def __init__(
                self,
                local_ip: str = '127.0.0.1',
                local_port: Optional[int] = None,
                upstream_ip: str = '127.0.0.1',
                upstream_port: Optional[int] = None,
                certname: Optional[str] = 'tt',
                close: Optional[int] = None,
                rehandshake: bool = False,
                force_tls13: bool = False
            ) -> None:
        super().__init__(local_ip, local_port, upstream_ip, upstream_port)
        if certname is not None:
            self.cert_path = os.path.join(CERTS_DIR, certname + '.cert.pem')
            self.key_path = os.path.join(CERTS_DIR, certname + '.key.pem')
        else:
            self.cert_path = None
            self.key_path = None
        self.close = close
        self.rehandshake = rehandshake
        self.force_tls13 = force_tls13

    def get_args(self):
        args = super().get_args()
        if self.cert_path is not None:
            args.append('--cert')
            args.append(self.cert_path)
        if self.key_path is not None:
            args.append('--key')
            args.append(self.key_path)
        if self.close is not None:
            args.append('--close')
            args.append(str(self.close))
        if self.rehandshake:
            args.append('--rehandshake')
        if self.force_tls13:
            args.append('--tls13')
        return args


@contextmanager
def kresd_tls_client(
            workdir: str,
            proxy: TLSProxy,
            kresd_tls_client_kwargs: Optional[Dict[Any, Any]] = None,
            kresd_fwd_target_kwargs: Optional[Dict[Any, Any]] = None
        ) -> Kresd:
    """kresd_tls_client --(tls)--> tlsproxy --(tcp)--> kresd_fwd_target"""
    ALLOWED_IPS = {'127.0.0.1', '::1'}
    assert proxy.local_ip in ALLOWED_IPS, "only localhost IPs supported for proxy"
    assert proxy.upstream_ip in ALLOWED_IPS, "only localhost IPs are supported for proxy"

    if kresd_tls_client_kwargs is None:
        kresd_tls_client_kwargs = dict()
    if kresd_fwd_target_kwargs is None:
        kresd_fwd_target_kwargs = dict()

    # run forward target instance
    dir1 = os.path.join(workdir, 'kresd_fwd_target')
    os.makedirs(dir1)

    with make_kresd(dir1, hints=HINTS, **kresd_fwd_target_kwargs) as kresd_fwd_target:
        sock = kresd_fwd_target.ip_tcp_socket()
        resolve_hint(sock, list(HINTS.keys())[0])

        proxy.local_port = make_port('127.0.0.1', '::1')
        proxy.upstream_port = kresd_fwd_target.port

        with proxy:
            # run test kresd instance
            dir2 = os.path.join(workdir, 'kresd_tls_client')
            os.makedirs(dir2)
            forward = Forward(
                proto='tls', ip=proxy.local_ip, port=proxy.local_port,
                hostname='transport-test-server.com', ca_file=proxy.cert_path)
            with make_kresd(dir2, forward=forward, **kresd_tls_client_kwargs) as kresd:
                yield kresd
