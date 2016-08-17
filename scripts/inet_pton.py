#!/usr/bin/python

from socket import inet_pton,AF_INET6
import sys
from binascii import hexlify

x = hexlify(inet_pton(AF_INET6, sys.argv[1]))

out = ""
for i in range(0, 15):
    out += "\\x" + x[i*2] + x[i*2+1]

print out
