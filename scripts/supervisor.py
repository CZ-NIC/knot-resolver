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
	print('Example: python scripts/supervisor.py ./daemon/kresd 127.0.0.1')
	sys.exit(1)
if len(sys.argv) < 3:
	help()
# Bind to sockets
daemon = sys.argv[1]
sockets = []
for addr in sys.argv[2:]:
	try:
		if '@' in addr:
			addr, port = addr.split('@')
			port = int(port)
		else:
			port = 53
	except: help()
	# Open TCP socket
	tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	tcp.bind((addr, port))
	tcp.listen(5)
	sockets.append(tcp)
	# Open UDP socket
	udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	udp.bind((addr, port))
	sockets.append(udp)
while True: # Fork forever
	pid = os.fork()
	if pid == 0:
		args = ['kresd'] + ['--fd=%d' % s.fileno() for s in sockets]
		os.execv('./daemon/kresd', args)
	else: # Wait for fork to die
		start = datetime.datetime.now()
		_, status = os.waitpid(pid, 0)
		end = datetime.datetime.now()
		print('[%s] process finished, pid = %d, status = %d, uptime = %s' % \
			(start, pid, status, end - start))
		time.sleep(0.5)