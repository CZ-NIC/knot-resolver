/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * @file dnstap.c
 * @brief dnstap based query logging support
 *
 */

#include "lib/module.h"
#include "lib/layer.h"
#include "lib/resolve.h"
#include "modules/dnstap/dnstap.pb-c.h"
#include <ccan/json/json.h>
#include <fstrm.h>
#include "contrib/cleanup.h"

#define DEBUG_MSG(fmt, ...) kr_log_verbose("[dnstap] " fmt, ##__VA_ARGS__);
#define CFG_SOCK_PATH "socket_path"
#define CFG_LOG_RESP_PKT "log_responses"
#define DEFAULT_SOCK_PATH "/tmp/dnstap.sock"
#define DNSTAP_CONTENT_TYPE "protobuf:dnstap.Dnstap"
#define DNSTAP_INITIAL_BUF_SIZE         256

#define auto_destroy_uopts __attribute__((cleanup(fstrm_unix_writer_options_destroy)))
#define auto_destroy_wopts __attribute__((cleanup(fstrm_writer_options_destroy)))

/* Internal data structure */
struct dnstap_data {
	bool log_resp_pkt;
	struct fstrm_iothr *iothread;
	struct fstrm_iothr_queue *ioq;
};

/*
 * dt_pack packs the dnstap message for transport
 * https://gitlab.nic.cz/knot/knot-dns/blob/master/src/contrib/dnstap/dnstap.c#L24
 * */
uint8_t* dt_pack(const Dnstap__Dnstap *d, uint8_t **buf, size_t *sz)
{
	ProtobufCBufferSimple sbuf = { { NULL } };

	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.alloced = DNSTAP_INITIAL_BUF_SIZE;
	sbuf.data = malloc(sbuf.alloced);
	if (sbuf.data == NULL) {
		return NULL;
	}
	sbuf.must_free_data = true;

	*sz = dnstap__dnstap__pack_to_buffer(d, (ProtobufCBuffer *) &sbuf);
	*buf = sbuf.data;
	return *buf;
}

/* set_address fills in address detail in dnstap_message
 * https://gitlab.nic.cz/knot/knot-dns/blob/master/src/contrib/dnstap/message.c#L28
 */
static void set_address(const struct sockaddr *sockaddr,
		ProtobufCBinaryData   *addr,
		protobuf_c_boolean    *has_addr,
		uint32_t              *port,
		protobuf_c_boolean    *has_port) {
	const char *saddr = kr_inaddr(sockaddr);
	if (saddr == NULL) {
		*has_addr = false;
		*has_port = false;
		return;
	}

	addr->data = (uint8_t *)(saddr);
	addr->len = kr_inaddr_len(sockaddr);
	*has_addr = true;
	*port = kr_inaddr_port(sockaddr);
	*has_port = true;
}

/* dnstap_log prepares dnstap message and sent it to fstrm */
static int dnstap_log(kr_layer_t *ctx) {
	const struct kr_request *req = ctx->req;
	const struct kr_module *module = ctx->api->data;
	const struct kr_rplan *rplan = &req->rplan;
	const struct dnstap_data *dnstap_dt = module->data;

	/* check if we have a valid iothread */
	if (!dnstap_dt->iothread || !dnstap_dt->ioq) {
		DEBUG_MSG("dnstap_dt->iothread or dnstap_dt->ioq is NULL\n");
		return kr_error(EFAULT);
	}

	/* current time */
	struct timeval now;
	gettimeofday(&now, NULL);

	/* Create dnstap message */
	Dnstap__Message m;

	memset(&m, 0, sizeof(m));

	m.base.descriptor = &dnstap__message__descriptor;
	/* Only handling response */
	m.type = DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE;

	if (req->qsource.addr) {
		set_address(req->qsource.addr,
				&m.query_address,
				&m.has_query_address,
				&m.query_port,
				&m.has_query_port);
	}

	if (req->qsource.dst_addr) {
		if (req->qsource.flags.tcp) {
			m.socket_protocol = DNSTAP__SOCKET_PROTOCOL__TCP;
		} else {
			m.socket_protocol = DNSTAP__SOCKET_PROTOCOL__UDP;
		}
		m.has_socket_protocol = true;

		set_address(req->qsource.dst_addr,
				&m.response_address,
				&m.has_response_address,
				&m.response_port,
				&m.has_response_port);
		switch (req->qsource.dst_addr->sa_family) {
			case AF_INET:
				m.socket_family = DNSTAP__SOCKET_FAMILY__INET;
				m.has_socket_family = true;
				break;
			case AF_INET6:
				m.socket_family = DNSTAP__SOCKET_FAMILY__INET6;
				m.has_socket_family = true;
				break;
		}
	}

	if (dnstap_dt->log_resp_pkt) {
		const knot_pkt_t *rpkt = req->answer;
		m.response_message.len = rpkt->size;
		m.response_message.data = (uint8_t *)rpkt->wire;
		m.has_response_message = true;
	}

	/* set query time to the timestamp of the first kr_query
	 * set response time to now
	 */
	if (rplan->resolved.len > 0) {
		struct kr_query *first = rplan->resolved.at[0];

		m.query_time_sec = first->timestamp.tv_sec;
		m.has_query_time_sec = true;
		m.query_time_nsec = first->timestamp.tv_usec * 1000;
		m.has_query_time_nsec = true;
	}

	/* Response time */
	m.response_time_sec = now.tv_sec;
	m.has_response_time_sec = true;
	m.response_time_nsec = now.tv_usec * 1000;
	m.has_response_time_nsec = true;

	/* Query Zone */
	if (rplan->resolved.len > 0) {
		struct kr_query *last = array_tail(rplan->resolved);
		/* Only add query_zone when not answered from cache */
		if (!(last->flags.CACHED)) {
			const knot_dname_t *zone_cut_name = last->zone_cut.name;
			if (zone_cut_name != NULL) {
				m.query_zone.data = (uint8_t *)zone_cut_name;
				m.query_zone.len = knot_dname_size(zone_cut_name);
				m.has_query_zone = true;
			}
		}
	}

	/* Create a dnstap Message */
	Dnstap__Dnstap dnstap = DNSTAP__DNSTAP__INIT;
	dnstap.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
	dnstap.message = (Dnstap__Message *)&m;

	/* Pack the message */
	uint8_t *frame = NULL;
	size_t size = 0;
	dt_pack(&dnstap, &frame, &size);
	if (!frame) {
		return kr_error(ENOMEM);
	}

	/* Submit a request to send message to fstrm_iothr*/
	fstrm_res res = fstrm_iothr_submit(dnstap_dt->iothread, dnstap_dt->ioq, frame, size,
			fstrm_free_wrapper, NULL);
	if (res != fstrm_res_success) {
		DEBUG_MSG("Error submitting dnstap message to iothr\n");
		free(frame);
		return kr_error(EBUSY);
	}

	return ctx->state;
}

KR_EXPORT
int dnstap_init(struct kr_module *module) {
	static kr_layer_api_t layer = {
		.finish = &dnstap_log,
	};
	/* Store module reference */
	layer.data = module;
	module->layer = &layer;

	/* allocated memory for internal data */
	struct dnstap_data *data = malloc(sizeof(*data));
	if (!data) {
		return kr_error(ENOMEM);
	}
	memset(data, 0, sizeof(*data));

	/* save pointer to internal struct in module for future reference */
	module->data = data;
	return kr_ok();
}

KR_EXPORT
int dnstap_deinit(struct kr_module *module) {
	struct dnstap_data *data = module->data;
	/* Free allocated memory */
	if (data) {
		fstrm_iothr_destroy(&data->iothread);
		DEBUG_MSG("fstrm iothread destroyed\n");
		free(data);
	}
	return kr_ok();
}

/* dnstap_unix_writer returns a unix fstream writer
 * https://gitlab.nic.cz/knot/knot-dns/blob/master/src/knot/modules/dnstap.c#L159
 */
static struct fstrm_writer* dnstap_unix_writer(const char *path) {

	auto_destroy_uopts struct fstrm_unix_writer_options *opt = fstrm_unix_writer_options_init();
	if (!opt) {
		return NULL;
	}
	fstrm_unix_writer_options_set_socket_path(opt, path);

	auto_destroy_wopts struct fstrm_writer_options *wopt = fstrm_writer_options_init();
	if (!wopt) {
		fstrm_unix_writer_options_destroy(&opt);
		return NULL;
	}
	fstrm_writer_options_add_content_type(wopt, DNSTAP_CONTENT_TYPE,
			strlen(DNSTAP_CONTENT_TYPE));

	struct fstrm_writer *writer = fstrm_unix_writer_init(opt, wopt);
	fstrm_unix_writer_options_destroy(&opt);
	fstrm_writer_options_destroy(&wopt);
	if (!writer) {
		return NULL;
	}

	fstrm_res res = fstrm_writer_open(writer);
	if (res != fstrm_res_success) {
		DEBUG_MSG("fstrm_writer_open returned %d\n", res);
		fstrm_writer_destroy(&writer);
		return NULL;
	}

	return writer;
}

/* find_string 
 * create a new string from json
 * *var is set to pointer of new string
 * node must of type JSON_STRING
 * new string can be at most len bytes
 */
static int find_string(const JsonNode *node, char **val, size_t len) {
	if (!node || !node->key) {
		return kr_error(EINVAL);
	}
	assert(node->tag == JSON_STRING);
	*val = strndup(node->string_, len);
	assert(*val != NULL);
	return kr_ok();
}

/* find_bool returns bool from json */
static bool find_bool(const JsonNode *node) {
	if (!node || !node->key) {
		return false;
	}
	assert(node->tag == JSON_BOOL);
	return node->bool_;
}

/* parse config */
KR_EXPORT
int dnstap_config(struct kr_module *module, const char *conf) {
	struct dnstap_data *data = module->data;
	auto_free char *sock_path = NULL;

	/* Empty conf passed, set default */
	if (!conf || strlen(conf) < 1) {
		sock_path = strndup(DEFAULT_SOCK_PATH, PATH_MAX);
	} else {

		JsonNode *root_node = json_decode(conf);
		if (!root_node) {
			DEBUG_MSG("error parsing json\n");
			return kr_error(EINVAL);
		}

		JsonNode *node;
		/* dnstapPath key */
		node = json_find_member(root_node, CFG_SOCK_PATH);
		if (!node || find_string(node, &sock_path, PATH_MAX) != kr_ok()) {
			sock_path = strndup(DEFAULT_SOCK_PATH, PATH_MAX);
		}

		/* logRespPkt key */
		node = json_find_member(root_node, CFG_LOG_RESP_PKT);
		if (node) {
			data->log_resp_pkt = find_bool(node);
		} else {
			data->log_resp_pkt = false;
		}

		/* clean up json, we don't need it no more */
		json_delete(root_node);
	}

	DEBUG_MSG("opening sock file %s\n",sock_path);
	struct fstrm_writer *writer = dnstap_unix_writer(sock_path);
	if (!writer) {
		DEBUG_MSG("can't create unix writer\n");
		return kr_error(EINVAL);
	}

	struct fstrm_iothr_options *opt = fstrm_iothr_options_init();
	if (!opt) {
		DEBUG_MSG("can't init fstrm options\n");
		fstrm_writer_destroy(&writer);
		return kr_error(EINVAL);
	}

	/* Create the I/O thread. */
	data->iothread = fstrm_iothr_init(opt, &writer);
	fstrm_iothr_options_destroy(&opt);
	if (!data->iothread) {
		DEBUG_MSG("can't init fstrm_iothr\n");
		fstrm_writer_destroy(&writer);
		return kr_error(ENOMEM);
	}

	/* Get fstrm thread handle
	 * We only have one input queue, hence idx=0
	 */
	data->ioq = fstrm_iothr_get_input_queue_idx(data->iothread, 0);
	if (!data->ioq) {
		fstrm_iothr_destroy(&data->iothread);
		DEBUG_MSG("can't get fstrm queue\n");
		return kr_error(EBUSY);
	}

	return kr_ok();
}

KR_MODULE_EXPORT(dnstap)

