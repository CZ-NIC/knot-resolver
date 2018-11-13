import struct
import random

import dns
import dns.message


def receive_answer(sock):
    answer_total_len = 0
    data = sock.recv(2)
    if not data:
        return None
    answer_total_len = struct.unpack_from("!H", data)[0]

    answer_received_len = 0
    data_answer = b''
    while answer_received_len < answer_total_len:
        data_chunk = sock.recv(2048)
        if not data_chunk:
            return None
        data_answer = data_answer + data_chunk
        answer_received_len = answer_received_len + len(data_answer)

    return data_answer


def receive_parse_answer(sock):
    data_answer = receive_answer(sock)

    if data_answer is None:
        raise RuntimeError("Kresd closed connection")

    msg_answer = dns.message.from_wire(data_answer, one_rr_per_rrset=True)
    return msg_answer


def prepare_wire(
        qname='localhost.',
        qtype=dns.rdatatype.A,
        qclass=dns.rdataclass.IN,
        msgid=None):
    """Utility function to generate DNS wire format message"""
    msg = dns.message.make_query(qname, qtype, qclass)
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
    return bytearray(random.getrandbits(8) for _ in range(length))


def get_prefixed_garbage(length):
    data = get_garbage(length)
    return prepare_buffer(data)
