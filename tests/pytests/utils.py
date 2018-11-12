import struct
import random

import dns


def random_msgid():
    return random.randint(1, 65535)


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


def get_msgbuf(qname, qtype, msgid):
    msg = dns.message.make_query(qname, qtype, dns.rdataclass.IN)
    msg.id = msgid
    data = msg.to_wire()
    datalen = len(data)
    buf = struct.pack("!H", datalen) + data
    return buf


def get_garbage(length):
    return bytearray(random.getrandbits(8) for _ in range(length))


def get_prefixed_garbage(length):
    data = get_garbage(length)
    datalen = len(data)
    buf = struct.pack("!H", datalen) + data
    return buf
