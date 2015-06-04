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
#include <libknot/internal/namedb/namedb_lmdb.h>

#include "tests/test.h"
#include "lib/rplan.h"
#include "lib/resolve.h"

/*
 * Globals
 */
static mm_ctx_t global_mm;                 /* Test memory context */
static module_array_t global_modules;        /* Array of modules. */
static struct kr_context global_context;   /* Resolution context */
static const char *global_tmpdir = NULL;   /* Temporary directory */

/*
 * Test driver global variables.
 */
extern struct timeval g_mock_time;        /* Mocked system time */
extern PyObject *g_mock_server;           /* Mocked endpoint for recursive queries */

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
	memset(&g_mock_time, 0, sizeof(struct timeval));
	g_mock_server = NULL;

	/* Load basic modules. */
	array_init(global_modules);
	const char *load_modules[3] = {"iterate", "rrcache", "pktcache"};
	for (unsigned i = 0; i < 3; ++i) {
		struct kr_module *mod = malloc(sizeof(*mod));
		kr_module_load(mod, load_modules[i], NULL);
		array_push(global_modules, mod);
	}

	/* Initialize resolution context */
	mm_ctx_init(&global_mm);
	memset(&global_context, 0, sizeof(struct kr_context));
	global_context.pool = &global_mm;
	global_context.modules = &global_modules;

	/* Create cache */
	global_tmpdir = test_tmpdir_create();
	assert(global_tmpdir);
	struct namedb_lmdb_opts opts;
	memset(&opts, 0, sizeof(opts));
	opts.path = global_tmpdir;
	opts.mapsize = 100 * 4096;
	int ret = kr_cache_open(&global_context.cache, NULL, &opts, &global_mm);
	if (ret != 0) {
	    return NULL;
	}

	/* Create RTT tracking */
	global_context.nsrep = malloc(lru_size(kr_nsrep_lru_t, 1000));
	assert(global_context.nsrep);
	lru_init(global_context.nsrep, 1000);
	global_context.options = QUERY_NO_THROTTLE;

	/* No configuration parsing support yet. */
	if (strstr(config, "query-minimization: on") == NULL) {
		global_context.options |= QUERY_NO_MINIMIZE;
	}

	return Py_BuildValue("");
}

static PyObject* deinit(PyObject* self, PyObject* args)
{
	if (global_tmpdir == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < global_modules.len; ++i) {
		kr_module_unload(global_modules.at[i]);
	}
	array_clear(global_modules);
	kr_cache_close(&global_context.cache);
	lru_deinit(global_context.nsrep);
	free(global_context.nsrep);

	test_tmpdir_remove(global_tmpdir);
	global_tmpdir = NULL;
	if (g_mock_server) {
		Py_XDECREF(g_mock_server);
		g_mock_server = NULL;
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

	g_mock_time.tv_sec  += arg_time;
	g_mock_time.tv_usec = 0;

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
	Py_XDECREF(g_mock_server);
	g_mock_server = arg_client;

	return Py_BuildValue("");
}

static PyMethodDef module_methods[] = {
    {"init", init, METH_VARARGS, "Initialize resolution context."},
    {"deinit", deinit, METH_VARARGS, "Clean up resolution context."},
    {"resolve", resolve, METH_VARARGS, "Resolve query."},
    {"set_time", set_time, METH_VARARGS, "Set mock system time."},
    {"set_server", set_server, METH_VARARGS, "Set fake server object."},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC init_test_integration(void)
{
	(void) Py_InitModule("_test_integration", module_methods);
}
