#!/usr/bin/env python
#
# This is an example of simple supervisor process owning bound sockets and
# handing them over to supervised process, allowing for graceful restarts.
#
import time, datetime
import socket
import os, sys

# Help
def help():
	print('Usage: %s <bin> addr@port ...' % sys.argv[0])
	print('Example: python scripts/supervisor.py ./daemon/kresd -a 127.0.0.1')
	sys.exit(1)
if len(sys.argv) < 3:
	help()
# Bind to sockets
args = []
unparsed = sys.argv[1:]
sockets = []
while len(unparsed) > 0:
	tok = unparsed.pop(0)
	# Rewrite '-a' only, copy otherwise
	if tok != '-a':
		args.append(tok)
		continue
	# Parse address
	addr = unparsed.pop(0)
	try:
		if '@' in addr:
			addr, port = addr.split('@')
			port = int(port)
		elif '#' in addr:
			addr, port = addr.split('#')
			port = int(port)
		else:
			port = 53
	except: help()
	# Open TCP socket
	family = socket.AF_INET6 if ':' in addr else socket.AF_INET
	tcp = socket.socket(family, socket.SOCK_STREAM)
	tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	tcp.bind((addr, port))
	tcp.listen(16)
	sockets.append(tcp)
	# Open UDP socket
	udp = socket.socket(family, socket.SOCK_DGRAM)
	udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	udp.bind((addr, port))
	sockets.append(udp)
args = args + ['-S %d' % s.fileno() for s in sockets]
while True: # Fork forever
	pid = os.fork()
	if pid == 0:
		os.execv(args[0], args)
	else: # Wait for fork to die
		start = datetime.datetime.now()
		_, status = os.waitpid(pid, 0)
		end = datetime.datetime.now()
		print('[%s] process finished, pid = %d, status = %d, uptime = %s' % \
			(start, pid, status, end - start))
		time.sleep(0.5)
