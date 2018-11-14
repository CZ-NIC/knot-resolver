from contextlib import ContextDecorator
import os
import re
import socket
import ssl
import subprocess
import time

import jinja2
import pytest

import utils


TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'templates')
KRESD_CONF_TEMPLATE = 'kresd.conf.j2'


def create_file_from_template(template_path, dest, data):
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATES_DIR))
    template = env.get_template(template_path)
    rendered_template = template.render(**data)

    with open(dest, "w") as fh:
        fh.write(rendered_template)


def make_ssl_context():
    # set TLS v1.2+
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1

    # turn off certificate verification
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    return context


class Kresd(ContextDecorator):
    def __init__(self, workdir, port, tls_port, ip=None, ip6=None):
        if ip is None and ip6 is None:
            raise ValueError("IPv4 or IPv6 must be specified!")
        self.workdir = str(workdir)
        self.port = port
        self.tls_port = tls_port
        self.ip = ip
        self.ip6 = ip6
        self.process = None
        self.sockets = []
        self.logfile = None

    @property
    def config_path(self):
        return str(os.path.join(self.workdir, 'kresd.conf'))

    @property
    def logfile_path(self):
        return str(os.path.join(self.workdir, 'kresd.log'))

    def __enter__(self):
        create_file_from_template(KRESD_CONF_TEMPLATE, self.config_path, {'kresd': self})
        self.logfile = open(self.logfile_path, 'w')
        self.process = subprocess.Popen(
            ['/usr/bin/env', 'kresd', '-c', self.config_path, self.workdir, '-f', '1'],
            stdout=self.logfile, env=os.environ.copy())

        try:
            self._wait_for_tcp_port()  # wait for ports to be up and responding
            if not self.all_ports_alive():
                raise RuntimeError("Kresd not listening on all ports")
            self.process.poll()
            if self.process.returncode is not None:
                raise RuntimeError("Kresd crashed with returncode: {}".format(
                    self.process.returncode))
        except RuntimeError:  # pylint: disable=try-except-raise
            raise
        finally:
            # handle cases where we accidentally attempt to bind to same port
            # as another test that runs in parallel
            self.logfile.flush()
            with open(self.logfile_path) as f:
                for line in f:
                    if re.search('Address already in use', line) is not None:
                        pytest.skip(line)  # mark as skipped instead of failed/error

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if not self.all_ports_alive():
                raise RuntimeError("Kresd crashed")
        finally:
            for sock in self.sockets:
                sock.close()
            self.process.terminate()
            self.logfile.close()

    def all_ports_alive(self):
        alive = True
        if self.ip:
            alive &= utils.ping_alive(self.ip_tcp_socket())
            alive &= utils.ping_alive(self.ip_tls_socket())
        if self.ip6:
            alive &= utils.ping_alive(self.ip6_tcp_socket())
            alive &= utils.ping_alive(self.ip6_tls_socket())
        return alive

    def _wait_for_tcp_port(self, delay=0.1, max_attempts=20):
        family = socket.AF_INET if self.ip else socket.AF_INET6
        for _ in range(max_attempts):
            try:
                sock, dest = self.stream_socket(family, timeout=3)
                sock.connect(dest)
            except ConnectionRefusedError:
                time.sleep(delay)
                continue
            else:
                return utils.ping_alive(sock)
            finally:
                sock.close()
        raise RuntimeError("Kresd didn't start in time")

    def socket_dest(self, family, tls=False):
        port = self.tls_port if tls else self.port
        if family == socket.AF_INET:
            return self.ip, port
        elif family == socket.AF_INET6:
            return self.ip6, port, 0, 0
        raise RuntimeError("Unsupported socket family: {}".format(family))

    def stream_socket(self, family, tls=False, timeout=20):
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        dest = self.socket_dest(family, tls)
        self.sockets.append(sock)
        return sock, dest

    def _tcp_socket(self, family):
        sock, dest = self.stream_socket(family)
        sock.connect(dest)
        return sock

    def ip_tcp_socket(self):
        return self._tcp_socket(socket.AF_INET)

    def ip6_tcp_socket(self):
        return self._tcp_socket(socket.AF_INET6)

    def _tls_socket(self, family):
        sock, dest = self.stream_socket(family, tls=True)
        ctx = make_ssl_context()
        ssock = ctx.wrap_socket(sock)
        try:
            ssock.connect(dest)
        except OSError as exc:
            if exc.errno == 0:  # sometimes happens shortly after startup
                return None
        return ssock

    def _tls_socket_with_retry(self, family):
        sock = self._tls_socket(family)
        if sock is None:
            time.sleep(0.1)
            sock = self._tls_socket(family)
            if sock is None:
                raise RuntimeError("Failed to create TLS socket!")
        return sock

    def ip_tls_socket(self):
        return self._tls_socket_with_retry(socket.AF_INET)

    def ip6_tls_socket(self):
        return self._tls_socket_with_retry(socket.AF_INET6)
