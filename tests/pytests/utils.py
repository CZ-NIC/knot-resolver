# SPDX-License-Identifier: GPL-3.0-or-later
from contextlib import contextmanager
import random
import ssl
import struct
import time

import dns
import dns.message
import pytest


# default net.tcp_in_idle is 10s, TCP_DEFER_ACCEPT 3s, some extra for
# Python handling / edge cases
MAX_TIMEOUT = 16


def receive_answer(sock):
    answer_total_len = 0
    data = sock.recv(2)
    if not data:
        return None
    answer_total_len = struct.unpack_from("!H", data)[0]

    answer_received_len = 0
    data_answer = b''
    while answer_received_len < answer_total_len:
        data_chunk = sock.recv(answer_total_len - answer_received_len)
        if not data_chunk:
            return None
        data_answer += data_chunk
        answer_received_len += len(data_answer)

    return data_answer


def receive_parse_answer(sock):
    data_answer = receive_answer(sock)

    if data_answer is None:
        raise BrokenPipeError("kresd closed connection")

    msg_answer = dns.message.from_wire(data_answer, one_rr_per_rrset=True)
    return msg_answer


def prepare_wire(
        qname='localhost.',
        qtype=dns.rdatatype.A,
        qclass=dns.rdataclass.IN,
        msgid=None):
    """Utility function to generate DNS wire format message"""
    msg = dns.message.make_query(qname, qtype, qclass, use_edns=True)
    if msgid is not None:
        msg.id = msgid
    return msg.to_wire(), msg.id


def prepare_buffer(wire, datalen=None):
    """Utility function to prepare TCP buffer from DNS message in wire format"""
    assert isinstance(wire, bytes)
    if datalen is None:
        datalen = len(wire)
    return struct.pack("!H", datalen) + wire


def get_msgbuff(qname='localhost.', qtype=dns.rdatatype.A, msgid=None):
    wire, msgid = prepare_wire(qname, qtype, msgid=msgid)
    buff = prepare_buffer(wire)
    return buff, msgid


def get_garbage(length):
    return bytes(random.getrandbits(8) for _ in range(length))


def get_prefixed_garbage(length):
    data = get_garbage(length)
    return prepare_buffer(data)


def try_ping_alive(sock, msgid=None, close=False):
    try:
        ping_alive(sock, msgid)
    except AssertionError:
        return False
    finally:
        if close:
            sock.close()
    return True


def ping_alive(sock, msgid=None):
    buff, msgid = get_msgbuff(msgid=msgid)
    sock.sendall(buff)
    answer = receive_parse_answer(sock)
    assert answer.id == msgid


@contextmanager
def expect_kresd_close(rst_ok=False):
    with pytest.raises(BrokenPipeError):
        try:
            time.sleep(0.2)  # give kresd time to close connection with TCP FIN
            yield
        except ConnectionResetError as ex:
            if rst_ok:
                raise BrokenPipeError from ex
            pytest.skip("kresd closed connection with TCP RST")
        pytest.fail("kresd didn't close the connection")


def make_ssl_context(insecure=False, verify_location=None, extra_options=None):
    # set TLS v1.2+
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1

    if extra_options is not None:
        for option in extra_options:
            context.options |= option

    if insecure:
        # turn off certificate verification
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True

        if verify_location is not None:
            context.load_verify_locations(verify_location)

    return context
