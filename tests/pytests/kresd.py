# SPDX-License-Identifier: GPL-3.0-or-later

from collections import namedtuple
from contextlib import ContextDecorator, contextmanager
import os
from pathlib import Path
import random
import re
import shutil
import socket
import subprocess
import time

import jinja2

import utils


PYTESTS_DIR = os.path.dirname(os.path.realpath(__file__))
CERTS_DIR = os.path.join(PYTESTS_DIR, 'certs')
TEMPLATES_DIR = os.path.join(PYTESTS_DIR, 'templates')
KRESD_CONF_TEMPLATE = 'kresd.conf.j2'
KRESD_STARTUP_MSGID = 10005  # special unique ID at the start of the "test" log
KRESD_PORTDIR = '/tmp/pytest-kresd-portdir'
KRESD_TESTPORT_MIN = 1024
KRESD_TESTPORT_MAX = 32768  # avoid overlap with docker ephemeral port range


def init_portdir():
    try:
        shutil.rmtree(KRESD_PORTDIR)
    except FileNotFoundError:
        pass
    os.makedirs(KRESD_PORTDIR)


def create_file_from_template(template_path, dest, data):
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATES_DIR))
    template = env.get_template(template_path)
    rendered_template = template.render(**data)

    with open(dest, "w") as fh:
        fh.write(rendered_template)


Forward = namedtuple('Forward', ['proto', 'ip', 'port', 'hostname', 'ca_file'])


class Kresd(ContextDecorator):
    def __init__(
            self, workdir, port=None, tls_port=None, ip=None, ip6=None, certname=None,
            verbose=True, hints=None, forward=None, policy_test_pass=False):
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
        self.verbose = verbose
        self.hints = {} if hints is None else hints
        self.forward = forward
        self.policy_test_pass = policy_test_pass

        if certname:
            self.tls_cert_path = os.path.join(CERTS_DIR, certname + '.cert.pem')
            self.tls_key_path = os.path.join(CERTS_DIR, certname + '.key.pem')
        else:
            self.tls_cert_path = None
            self.tls_key_path = None

    @property
    def config_path(self):
        return str(os.path.join(self.workdir, 'kresd.conf'))

    @property
    def logfile_path(self):
        return str(os.path.join(self.workdir, 'kresd.log'))

    def __enter__(self):
        if self.port is not None:
            take_port(self.port, self.ip, self.ip6, timeout=120)
        else:
            self.port = make_port(self.ip, self.ip6)
        if self.tls_port is not None:
            take_port(self.tls_port, self.ip, self.ip6, timeout=120)
        else:
            self.tls_port = make_port(self.ip, self.ip6)

        create_file_from_template(KRESD_CONF_TEMPLATE, self.config_path, {'kresd': self})
        self.logfile = open(self.logfile_path, 'w')
        self.process = subprocess.Popen(
            ['kresd', '-c', self.config_path, '-n', self.workdir],
            stdout=self.logfile, env=os.environ.copy())

        try:
            self._wait_for_tcp_port()  # wait for ports to be up and responding
            if not self.all_ports_alive(msgid=10001):
                raise RuntimeError("Kresd not listening on all ports")

            # issue special msgid to mark start of test log
            sock = self.ip_tcp_socket() if self.ip else self.ip6_tcp_socket()
            assert utils.try_ping_alive(sock, close=True, msgid=KRESD_STARTUP_MSGID)

            # sanity check - kresd didn't crash
            self.process.poll()
            if self.process.returncode is not None:
                raise RuntimeError("Kresd crashed with returncode: {}".format(
                    self.process.returncode))
        except (RuntimeError, ConnectionError):  # pylint: disable=try-except-raise
            with open(self.logfile_path) as log:  # print log for debugging
                print(log.read())
            raise

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if not self.all_ports_alive(msgid=1006):
                raise RuntimeError("Kresd crashed")
        finally:
            for sock in self.sockets:
                sock.close()
            self.process.terminate()
            self.logfile.close()
            Path(KRESD_PORTDIR, str(self.port)).unlink()

    def all_ports_alive(self, msgid=10001):
        alive = True
        if self.ip:
            alive &= utils.try_ping_alive(self.ip_tcp_socket(), close=True, msgid=msgid)
            alive &= utils.try_ping_alive(self.ip_tls_socket(), close=True, msgid=msgid + 1)
        if self.ip6:
            alive &= utils.try_ping_alive(self.ip6_tcp_socket(), close=True, msgid=msgid + 2)
            alive &= utils.try_ping_alive(self.ip6_tls_socket(), close=True, msgid=msgid + 3)
        return alive

    def _wait_for_tcp_port(self, max_delay=10, delay_step=0.2):
        family = socket.AF_INET if self.ip else socket.AF_INET6
        i = 0
        end_time = time.time() + max_delay

        while time.time() < end_time:
            i += 1

            # use exponential backoff algorhitm to choose next delay
            rand_delay = random.randrange(0, i)
            time.sleep(rand_delay * delay_step)

            try:
                sock, dest = self.stream_socket(family, timeout=5)
                sock.connect(dest)
            except ConnectionRefusedError:
                continue
            else:
                try:
                    return utils.try_ping_alive(sock, close=True, msgid=10000)
                except socket.timeout:
                    continue
            finally:
                sock.close()
        raise RuntimeError("Kresd didn't start in time {}".format(dest))

    def socket_dest(self, family, tls=False):
        port = self.tls_port if tls else self.port
        if family == socket.AF_INET:
            return self.ip, port
        elif family == socket.AF_INET6:
            return self.ip6, port, 0, 0
        raise RuntimeError("Unsupported socket family: {}".format(family))

    def stream_socket(self, family, tls=False, timeout=20):
        """Initialize a socket and return it along with the destination without connecting."""
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
        ctx = utils.make_ssl_context(insecure=True)
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

    def partial_log(self):
        partial_log = '\n (... ommiting log start)\n'
        with open(self.logfile_path) as log:  # display partial log for debugging
            past_startup_msgid = False
            past_startup = False
            for line in log:
                if past_startup:
                    partial_log += line
                else:  # find real start of test log (after initial alive-pings)
                    if not past_startup_msgid:
                        if re.match(KRESD_LOG_STARTUP_MSGID, line) is not None:
                            past_startup_msgid = True
                    else:
                        if re.match(KRESD_LOG_IO_CLOSE, line) is not None:
                            past_startup = True
        return partial_log


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


def take_port(port, ip=None, ip6=None, timeout=0):
    port_path = Path(KRESD_PORTDIR, str(port))
    end_time = time.time() + timeout
    try:
        port_path.touch(exist_ok=False)
    except FileExistsError as ex:
        raise ValueError(
            "Port {} already reserved by system or another kresd instance!".format(port)) from ex

    while True:
        if is_port_free(port, ip, ip6):
            # NOTE: The port_path isn't removed, so other instances don't have to attempt to
            # take the same port again. This has the side effect of leaving many of these
            # files behind, because when another kresd shuts down and removes its file, the
            # port still can't be reserved for a while. This shouldn't become an issue unless
            # we have thousands of tests (and run out of the port range).
            break

        if time.time() < end_time:
            time.sleep(5)
        else:
            raise ValueError(
                "Port {} is reserved by system!".format(port))
    return port


def make_port(ip=None, ip6=None):
    for _ in range(10):  # max attempts
        port = random.randint(KRESD_TESTPORT_MIN, KRESD_TESTPORT_MAX)
        try:
            take_port(port, ip, ip6)
        except ValueError:
            continue  # port reserved by system / another kresd instance
        return port
    raise RuntimeError("No available port found!")


KRESD_LOG_STARTUP_MSGID = re.compile(r'^\[[^]]+\]\[{}.*'.format(KRESD_STARTUP_MSGID))
KRESD_LOG_IO_CLOSE = re.compile(r'^\[io    \].*closed by peer.*')


@contextmanager
def make_kresd(workdir, certname=None, ip='127.0.0.1', ip6='::1', **kwargs):
    with Kresd(workdir, ip=ip, ip6=ip6, certname=certname, **kwargs) as kresd:
        yield kresd
        print(kresd.partial_log())
