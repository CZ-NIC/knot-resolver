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
#include "lib/resolve.h"

/*
 * Globals
 */
mm_ctx_t global_mm;               /* Test memory context */
struct kr_context global_context; /* Resolution context */
const char *global_tmpdir = NULL; /* Temporary directory */
struct timeval _mock_time;        /* Mocked system time */
int _mock_fd;                     /* Mocked endpoint for recursive queries */

/*
 * PyModule implementation.
 */

static PyObject* init(PyObject* self, PyObject* args)
{
	/* Initialize mock variables */
	memset(&_mock_time, 0, sizeof(struct timeval));
	_mock_fd = -1;

	/* Initialize resolution context */
	#define CACHE_SIZE 100*1024
	test_mm_ctx_init(&global_mm);
	kr_context_init(&global_context, &global_mm);
	global_tmpdir = test_tmpdir_create();
	assert(global_tmpdir);
	global_context.cache = kr_cache_open(global_tmpdir, &global_mm, CACHE_SIZE);
	assert(global_context.cache);

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
	_mock_fd = -1;

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

static PyObject* set_endpoint(PyObject *self, PyObject *args)
{
	PyObject *arg_socket = NULL;
	if (!PyArg_ParseTuple(args, "O", &arg_socket)) {
		return NULL;
	}

	int fd = PyObject_AsFileDescriptor(arg_socket);
	if (fd < 0) {
		return NULL;
	}

	_mock_fd = fd;
	return Py_BuildValue("");
}

static PyMethodDef module_methods[] = {
    {"init", init, METH_VARARGS, "Initialize resolution context."},
    {"deinit", deinit, METH_VARARGS, "Clean up resolution context."},
    {"resolve", resolve, METH_VARARGS, "Resolve query."},
    {"set_time", set_time, METH_VARARGS, "Set mock system time."},
    {"set_endpoint", set_endpoint, METH_VARARGS, "Set endpoint for recursive queries."},
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

int net_unbound_socket(int type, const struct sockaddr_storage *ss)
{
	char addr_str[SOCKADDR_STRLEN];
	sockaddr_tostr(addr_str, sizeof(addr_str), ss);
	fprintf(stderr, "%s (%d, %s)\n", __func__, type, addr_str);
	return _mock_fd;
}

int net_bound_socket(int type, const struct sockaddr_storage *ss)
{
	char addr_str[SOCKADDR_STRLEN];
	sockaddr_tostr(addr_str, sizeof(addr_str), ss);
	fprintf(stderr, "%s (%d, %s)\n", __func__, type, addr_str);
	return _mock_fd;
}

int net_connected_socket(int type, const struct sockaddr_storage *dst_addr,
                         const struct sockaddr_storage *src_addr, unsigned flags)
{
	char dst_addr_str[SOCKADDR_STRLEN], src_addr_str[SOCKADDR_STRLEN];
	sockaddr_tostr(dst_addr_str, sizeof(dst_addr_str), dst_addr);
	sockaddr_tostr(src_addr_str, sizeof(src_addr_str), src_addr);
	fprintf(stderr, "%s (%d, %s, %s, %u)\n", __func__, type, dst_addr_str, src_addr_str, flags);
	return _mock_fd;
}

int net_is_connected(int fd)
{
	fprintf(stderr, "%s (%d)\n", __func__, fd);
	return true;
}
