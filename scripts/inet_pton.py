#!/usr/bin/env python3
"""
Print IP address to binary representation in Python hex format \x12
"""

from socket import inet_pton, AF_INET6, AF_INET
import sys
from binascii import hexlify

try:
    arg = sys.argv[1]
except:
    sys.exit('Usage: inet_pton.py <IPv4 or IPv6 address>')

if ':' in arg:
    addr_type = AF_INET6
else:
    addr_type = AF_INET

print(repr(inet_pton(addr_type, arg)).strip("'"))
