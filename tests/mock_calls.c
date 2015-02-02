/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <Python.h>
#include <libknot/descriptor.h>
#include <libknot/packet/pkt.h>
#include <libknot/internal/net.h>

/*
 * Globals
 */
struct timeval g_mock_time;        /* Mocked system time */
PyObject *g_mock_server  = NULL;   /* Mocked endpoint for recursive queries */

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	memcpy(tv, &g_mock_time, sizeof(struct timeval));
	return 0;
}

int tcp_recv_msg(int fd, uint8_t *buf, size_t len, struct timeval *timeout)
{
	/* Unlock GIL and attempt to receive message. */
	uint16_t msg_len = 0;
	int rcvd = 0;
	Py_BEGIN_ALLOW_THREADS
	rcvd = read(fd, (char *)&msg_len, sizeof(msg_len));
	if (rcvd == sizeof(msg_len)) {
		msg_len = htons(msg_len);
		rcvd = read(fd, buf, msg_len);
	}
	Py_END_ALLOW_THREADS
	return rcvd;
}

int udp_recv_msg(int fd, uint8_t *buf, size_t len, struct timeval *timeout)
{
	/* Tunnel via TCP. */
	return tcp_recv_msg(fd, buf, len, timeout);
}


int tcp_send_msg(int fd, const uint8_t *msg, size_t len)
{
	/* Unlock GIL and attempt to send message over. */
	uint16_t msg_len = htons(len);
	int sent = 0;
	Py_BEGIN_ALLOW_THREADS
	sent = write(fd, (char *)&msg_len, sizeof(msg_len));
	if (sent == sizeof(msg_len)) {
		sent = write(fd, msg, len);
	}
	Py_END_ALLOW_THREADS
	return sent;
}

int udp_send_msg(int fd, const uint8_t *msg, size_t msglen,
                 const struct sockaddr *addr)
{
	/* Tunnel via TCP. */
	return tcp_send_msg(fd, msg, msglen);
}


int net_connected_socket(int type, const struct sockaddr_storage *dst_addr,
                         const struct sockaddr_storage *src_addr, unsigned flags)
{
	char addr_str[SOCKADDR_STRLEN];
	sockaddr_tostr(addr_str, sizeof(addr_str), dst_addr);

	PyObject *result = PyObject_CallMethod(g_mock_server, "client", "s", addr_str);
	if (result == NULL) {
		return -1;
	}

	/* Refcount decrement is going to close the fd, dup() it */
	int fd = dup(PyObject_AsFileDescriptor(result));
	Py_DECREF(result);
	return fd;
}

int net_is_connected(int fd)
{
	fprintf(stderr, "%s (%d)\n", __func__, fd);
	return true;
}
