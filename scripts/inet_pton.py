#!/usr/bin/env python

from socket import inet_pton,AF_INET6,AF_INET
import sys
from binascii import hexlify
from string import find

if find(sys.argv[1], ":") == -1:
    addr_type = AF_INET
else:
    addr_type = AF_INET6

x = hexlify(inet_pton(addr_type, sys.argv[1]))

out = ""
for i in range(0, len(x) / 2):
    out += "\\x" + x[i*2] + x[i*2+1]

print out
