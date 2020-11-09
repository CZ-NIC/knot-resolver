#!/usr/bin/env python3
import argparse
import base64

import dns
import dns.message


def main():
    parser = argparse.ArgumentParser(
        description='Convert query name and type to base64 URL-encoded form')
    parser.add_argument('qname', type=str, help='query name')
    parser.add_argument('qtype', type=str, help='query type')
    args = parser.parse_args()

    msg = dns.message.make_query(args.qname, args.qtype, dns.rdataclass.IN)
    msg.id = 0
    wire = msg.to_wire()
    encoded = base64.urlsafe_b64encode(wire)
    printable = encoded.decode('utf-8')

    print(printable)


if __name__ == '__main__':
    main()
