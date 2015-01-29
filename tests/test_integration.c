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

#include "tests/test.h"
#include "lib/rplan.h"
#include "lib/resolve.h"

/*
 * Globals
 */
static mm_ctx_t global_mm;               /* Test memory context */
static struct kr_context global_context; /* Resolution context */
static const char *global_tmpdir = NULL; /* Temporary directory */
static struct timeval _mock_time;        /* Mocked system time */
static PyObject *mock_server  = NULL;   /* Mocked endpoint for recursive queries */

/*
 * PyModule implementation.
 */

static PyObject* init(PyObject* self, PyObject* args)
{
	const char *config= NULL;
	if (!PyArg_ParseTuple(args, "s", &config)) {
		return NULL;
	}

	/* Initialize mock variables */
	memset(&_mock_time, 0, sizeof(struct timeval));
	mock_server = NULL;

	/* Initialize resolution context */
	#define CACHE_SIZE 100*1024
	test_mm_ctx_init(&global_mm);
	kr_context_init(&global_context, &global_mm);
	global_tmpdir = test_tmpdir_create();
	assert(global_tmpdir);
	global_context.cache = kr_cache_open(global_tmpdir, &global_mm, CACHE_SIZE);
	assert(global_context.cache);

	/* Test context options. */
	global_context.options = QUERY_TCP;

	/* No configuration parsing support yet. */
	if (strstr(config, "query-minimization: on") == NULL) {
		global_context.options |= QUERY_NO_MINIMIZE; 
	}

	return Py_BuildValue("s", PACKAGE_STRING " (integration tests)");
}

static PyObject* deinit(PyObject* self, PyObject* args)
{
	if (global_tmpdir == NULL) {
		return NULL;
	}

	kr_context_deinit(&global_context);
	test_tmpdir_remove(global_tmpdir);
	global_tmpdir = NULL;
	if (mock_server) {
		Py_XDECREF(mock_server);
		mock_server = NULL;
	}

	return Py_BuildValue("");
}

static PyObject* resolve(PyObject *self, PyObject *args)
{
	const char *query_wire = NULL;
	size_t query_size = 0;
	if (!PyArg_ParseTuple(args, "s#", &query_wire, &query_size)) {
		return NULL;
	}

	/* Prepare input */
	knot_pkt_t *query = knot_pkt_new((uint8_t *)query_wire, query_size, &global_mm);
	assert(query);
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK) {
		knot_pkt_free(&query);
		return NULL;
	}

	/* Resolve query */
	knot_pkt_t *answer = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, &global_mm);
	assert(answer);
	knot_pkt_init_response(answer, query);
	ret = kr_resolve(&global_context, answer, knot_pkt_qname(query),
	                 knot_pkt_qclass(query), knot_pkt_qtype(query));

	/* Return wire and cleanup. */
	PyObject *out = Py_BuildValue("s#", answer->wire, answer->size);
	knot_pkt_free(&answer);
	knot_pkt_free(&query);
	return out;
}

static PyObject* set_time(PyObject *self, PyObject *args)
{
	unsigned long arg_time = 0;
	if (!PyArg_ParseTuple(args, "k", &arg_time)) {
		return NULL;
	}

	_mock_time.tv_sec  = arg_time;
	_mock_time.tv_usec = 0;

	return Py_BuildValue("");
}

static PyObject* set_server(PyObject *self, PyObject *args)
{
	/* Get client socket getter method. */
	PyObject *arg_client = NULL;
	if (!PyArg_ParseTuple(args, "O", &arg_client)) {
		return NULL;
	}

	/* Swap the server implementation. */
	Py_XINCREF(arg_client);
	Py_XDECREF(mock_server);
	mock_server = arg_client;

	return Py_BuildValue("");
}

static PyObject* test_connect(PyObject *self, PyObject *args)
{
	/* Fetch a new client */
	struct sockaddr_storage addr;
	sockaddr_set(&addr, AF_INET, "127.0.0.1", 0);
	int sock = net_connected_socket(SOCK_STREAM, &addr, NULL, 0);
	if (sock < 0) {
		return NULL;
	}

	int ret = 0;
	bool test_passed = true;
	knot_pkt_t *query = NULL, *reply = NULL;

	/* Send and receive a query. */
	query = knot_pkt_new(NULL, 512, NULL);
	knot_pkt_put_question(query, (const uint8_t *)"", KNOT_CLASS_IN, KNOT_RRTYPE_NS);
	ret = tcp_send_msg(sock, query->wire, query->size);
	if (ret != query->size) {
		test_passed = false;
		goto finish;
	}

	reply = knot_pkt_new(NULL, 512, NULL);
	ret = tcp_recv_msg(sock, reply->wire, reply->max_size, NULL); 
	if (ret <= 0) {
		test_passed = false;
		goto finish;
	}

finish:
	close(sock);
	knot_pkt_free(&query);
	knot_pkt_free(&reply);
	if (test_passed) {
		return Py_BuildValue("");
	} else {
		return NULL;
	}
}

static PyMethodDef module_methods[] = {
    {"init", init, METH_VARARGS, "Initialize resolution context."},
    {"deinit", deinit, METH_VARARGS, "Clean up resolution context."},
    {"resolve", resolve, METH_VARARGS, "Resolve query."},
    {"set_time", set_time, METH_VARARGS, "Set mock system time."},
    {"set_server", set_server, METH_VARARGS, "Set fake server object."},
	{"test_connect", test_connect, METH_VARARGS, "Test server connection."},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC init_test_integration(void)
{
	(void) Py_InitModule("_test_integration", module_methods);
}

/*
 * Mock symbol reimplementation.
 * These effectively allow to manipulate time/networking during resolution.
 */

int __wrap_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	fprintf(stderr, "gettimeofday = %ld\n", tv->tv_sec);
	memcpy(tv, &_mock_time, sizeof(struct timeval));
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

	PyObject *result = PyObject_CallMethod(mock_server, "client", "s", addr_str);
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
