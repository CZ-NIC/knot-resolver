/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * @file dnstap.c
 * @brief dnstap based query logging support
 *
 */

#include "lib/module.h"
#include "modules/dnstap/dnstap.pb-c.h"

#include "contrib/cleanup.h"
#include "daemon/session.h"
#include "daemon/worker.h"
#include "lib/layer.h"
#include "lib/resolve.h"

#include <ccan/json/json.h>
#include <fstrm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <uv.h>

#define DEBUG_MSG(fmt, ...) kr_log_debug(DNSTAP, fmt, ##__VA_ARGS__);
#define ERROR_MSG(fmt, ...) kr_log_error(DNSTAP, fmt, ##__VA_ARGS__);
#define CFG_SOCK_PATH "socket_path"
#define CFG_IDENTITY_STRING "identity"
#define CFG_VERSION_STRING "version"
#define CFG_LOG_CLIENT_PKT "client"
#define CFG_LOG_QR_PKT "log_queries"
#define CFG_LOG_RESP_PKT "log_responses"
#define CFG_LOG_TCP_RTT "log_tcp_rtt"
#define DEFAULT_SOCK_PATH "/tmp/dnstap.sock"
#define DNSTAP_CONTENT_TYPE "protobuf:dnstap.Dnstap"
#define DNSTAP_INITIAL_BUF_SIZE         256

#define auto_destroy_uopts __attribute__((cleanup(fstrm_unix_writer_options_destroy)))
#define auto_destroy_wopts __attribute__((cleanup(fstrm_writer_options_destroy)))

/*
 * Internal processing phase
 * Distinguishes whether query or response should be processed
 */
enum dnstap_log_phase {
	CLIENT_QUERY_PHASE = 0,
	CLIENT_RESPONSE_PHASE,
};

/* Internal data structure */
struct dnstap_data {
	char *identity;
	size_t identity_len;
	char *version;
	size_t version_len;
	bool log_qr_pkt;
	bool log_resp_pkt;
	bool log_tcp_rtt;
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

#ifndef HAS_TCP_INFO
	/* TCP RTT: not portable; not sure where else it might work. */
	#define HAS_TCP_INFO __linux__
#endif
#if HAS_TCP_INFO
/** Fill a tcp_info or return kr_error(). */
static int get_tcp_info(const struct kr_request *req, struct tcp_info *info)
{
	if(kr_fails_assert(req && info))
		return kr_error(EINVAL);
	if (!req->qsource.dst_addr || !req->qsource.flags.tcp) /* not TCP-based */
		return -abs(ENOENT);
	/* First obtain the file-descriptor. */
	uv_handle_t *h = session_get_handle(worker_request_get_source_session(req));
	uv_os_fd_t fd;
	int ret = uv_fileno(h, &fd);
	if (ret)
		return kr_error(ret);

	socklen_t tcp_info_length = sizeof(*info);
	if (getsockopt(fd, SOL_TCP, TCP_INFO, info, &tcp_info_length))
		return kr_error(errno);
	return kr_ok();
}
#endif

/* dnstap_log prepares dnstap message and sends it to fstrm
 *
 * Return codes are kr_error(E*) and unused for now.
 */
static int dnstap_log(kr_layer_t *ctx, enum dnstap_log_phase phase) {
	const struct kr_request *req = ctx->req;
	const struct kr_module *module = ctx->api->data;
	const struct kr_rplan *rplan = &req->rplan;
	const struct dnstap_data *dnstap_dt = module->data;

	if (!req->qsource.addr) {
		return kr_ok();
	}

	/* check if we have a valid iothread */
	if (!dnstap_dt->iothread || !dnstap_dt->ioq) {
		DEBUG_MSG("dnstap_dt->iothread or dnstap_dt->ioq is NULL\n");
		return kr_error(EFAULT);
	}

	/* Create dnstap message */
	Dnstap__Message m;
	Dnstap__Dnstap dnstap = DNSTAP__DNSTAP__INIT;
	dnstap.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
	dnstap.message = &m;

	memset(&m, 0, sizeof(m));

	m.base.descriptor = &dnstap__message__descriptor;

	if (req->qsource.addr) {
		set_address(req->qsource.addr,
				&m.query_address,
				&m.has_query_address,
				&m.query_port,
				&m.has_query_port);
	}

	if (req->qsource.dst_addr) {
		if (req->qsource.flags.http) {
			m.socket_protocol = DNSTAP__SOCKET_PROTOCOL__DOH;
		} else if (req->qsource.flags.tls) {
			m.socket_protocol = DNSTAP__SOCKET_PROTOCOL__DOT;
		} else if (req->qsource.flags.tcp) {
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

	char dnstap_extra_buf[24];
	if (phase == CLIENT_QUERY_PHASE) {
		m.type = DNSTAP__MESSAGE__TYPE__CLIENT_QUERY;

		if (dnstap_dt->log_qr_pkt) {
			const knot_pkt_t *qpkt = req->qsource.packet;
			m.has_query_message = qpkt != NULL;
			if (qpkt != NULL) {
				m.query_message.len = qpkt->size;
				m.query_message.data = (uint8_t *)qpkt->wire;
			}
		}

		/* set query time to the timestamp of the first kr_query */
		if (rplan->initial) {
			struct kr_query *first = rplan->initial;

			m.query_time_sec = first->timestamp.tv_sec;
			m.has_query_time_sec = true;
			m.query_time_nsec = first->timestamp.tv_usec * 1000;
			m.has_query_time_nsec = true;
		}
#if HAS_TCP_INFO
		struct tcp_info ti = { 0 };
		if (dnstap_dt->log_tcp_rtt && get_tcp_info(req, &ti) == kr_ok()) {
			int len = snprintf(dnstap_extra_buf, sizeof(dnstap_extra_buf),
						"rtt=%u\n", (unsigned)ti.tcpi_rtt);
			if (len < sizeof(dnstap_extra_buf)) {
				dnstap.extra.data = (uint8_t *)dnstap_extra_buf;
				dnstap.extra.len = len;
				dnstap.has_extra = true;
			}
		}
#else
		(void)dnstap_extra_buf;
#endif
	} else if (phase == CLIENT_RESPONSE_PHASE) {
		m.type = DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE;

		/* current time */
		struct timeval now;
		gettimeofday(&now, NULL);

		if (dnstap_dt->log_resp_pkt) {
			const knot_pkt_t *rpkt = req->answer;
			m.has_response_message = rpkt != NULL;
			if (rpkt != NULL) {
				m.response_message.len = rpkt->size;
				m.response_message.data = rpkt->wire;
			}
		}

		/* Set response time to now */
		m.response_time_sec = now.tv_sec;
		m.has_response_time_sec = true;
		m.response_time_nsec = now.tv_usec * 1000;
		m.has_response_time_nsec = true;
	}

	if (dnstap_dt->identity) {
		dnstap.identity.data = (uint8_t*)dnstap_dt->identity;
		dnstap.identity.len = dnstap_dt->identity_len;
		dnstap.has_identity = true;
	}

	if (dnstap_dt->version) {
		dnstap.version.data = (uint8_t*)dnstap_dt->version;
		dnstap.version.len = dnstap_dt->version_len;
		dnstap.has_version = true;
	}

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

	return kr_ok();
}

/* dnstap_log_query prepares dnstap CLIENT_QUERY message and sends it to fstrm */
static int dnstap_log_query(kr_layer_t *ctx) {
	dnstap_log(ctx, CLIENT_QUERY_PHASE);
	return ctx->state;
}

/* dnstap_log_response prepares dnstap CLIENT_RESPONSE message and sends it to fstrm */
static int dnstap_log_response(kr_layer_t *ctx) {
	dnstap_log(ctx, CLIENT_RESPONSE_PHASE);
	return ctx->state;
}

KR_EXPORT
int dnstap_init(struct kr_module *module) {
	static kr_layer_api_t layer = {
		.begin = &dnstap_log_query,
		.finish = &dnstap_log_response,
	};
	/* Store module reference */
	layer.data = module;
	module->layer = &layer;

	/* allocated memory for internal data */
	struct dnstap_data *data = calloc(1, sizeof(*data));
	if (!data) {
		return kr_error(ENOMEM);
	}

	/* save pointer to internal struct in module for future reference */
	module->data = data;
	return kr_ok();
}

/** Clear, i.e. get to state as after the first dnstap_init(). */
static void dnstap_clear(struct kr_module *module) {
	struct dnstap_data *data = module->data;
	if (data) {
		free(data->identity);
		free(data->version);

		fstrm_iothr_destroy(&data->iothread);
		DEBUG_MSG("fstrm iothread destroyed\n");
	}
}

KR_EXPORT
int dnstap_deinit(struct kr_module *module) {
	dnstap_clear(module);
	free(module->data);
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
	if (!node || !node->key)
		return kr_error(EINVAL);
	if (kr_fails_assert(node->tag == JSON_STRING))
		return kr_error(EINVAL);
	*val = strndup(node->string_, len);
	if (kr_fails_assert(*val != NULL))
		return kr_error(errno);
	return kr_ok();
}

/* find_bool returns bool from json */
static bool find_bool(const JsonNode *node) {
	if (!node || !node->key)
		return false;
	if (kr_fails_assert(node->tag == JSON_BOOL))
		return false;
	return node->bool_;
}

/* parse config */
KR_EXPORT
int dnstap_config(struct kr_module *module, const char *conf) {
	dnstap_clear(module);
	if (!conf) return kr_ok(); /* loaded module without configuring */
	struct dnstap_data *data = module->data;
	auto_free char *sock_path = NULL;

	/* Empty conf passed, set default */
	if (strlen(conf) < 1) {
		sock_path = strdup(DEFAULT_SOCK_PATH);
	} else {

		JsonNode *root_node = json_decode(conf);
		if (!root_node) {
			ERROR_MSG("error parsing json\n");
			return kr_error(EINVAL);
		}

		JsonNode *node;
		/* dnstapPath key */
		node = json_find_member(root_node, CFG_SOCK_PATH);
		if (!node || find_string(node, &sock_path, PATH_MAX) != kr_ok()) {
			sock_path = strdup(DEFAULT_SOCK_PATH);
		}

		/* identity string key */
		node = json_find_member(root_node, CFG_IDENTITY_STRING);
		if (!node || find_string(node, &data->identity, KR_EDNS_PAYLOAD) != kr_ok()) {
			data->identity = NULL;
			data->identity_len = 0;
		} else {
			data->identity_len = strlen(data->identity);
		}

		/* version string key */
		node = json_find_member(root_node, CFG_VERSION_STRING);
		if (!node || find_string(node, &data->version, KR_EDNS_PAYLOAD) != kr_ok()) {
			data->version = strdup("Knot Resolver " PACKAGE_VERSION);
			if (data->version) {
				data->version_len = strlen(data->version);
			}
		} else {
			data->version_len = strlen(data->version);
		}

		node = json_find_member(root_node, CFG_LOG_CLIENT_PKT);
		if (node) {
			JsonNode *subnode;
			/* logRespPkt key */
			subnode = json_find_member(node, CFG_LOG_RESP_PKT);
			if (subnode) {
				data->log_resp_pkt = find_bool(subnode);
			} else {
				data->log_resp_pkt = false;
			}

			/* logQrPkt key */
			subnode = json_find_member(node, CFG_LOG_QR_PKT);
			if (subnode) {
				data->log_qr_pkt = find_bool(subnode);
			} else {
				data->log_qr_pkt = false;
			}

			subnode = json_find_member(node, CFG_LOG_TCP_RTT);
			if (subnode) {
				data->log_tcp_rtt = find_bool(subnode);
			} else {
				data->log_tcp_rtt = false;
			}
		} else {
			data->log_qr_pkt = false;
			data->log_resp_pkt = false;
			data->log_tcp_rtt = false;
		}

		/* clean up json, we don't need it no more */
		json_delete(root_node);
	}

	DEBUG_MSG("opening sock file %s\n",sock_path);
	struct fstrm_writer *writer = dnstap_unix_writer(sock_path);
	if (!writer) {
		ERROR_MSG("failed to open socket %s\n"
			"Please ensure that it exists beforehand and has appropriate access permissions.\n",
			sock_path);
		return kr_error(EINVAL);
	}

	struct fstrm_iothr_options *opt = fstrm_iothr_options_init();
	if (!opt) {
		ERROR_MSG("can't init fstrm options\n");
		fstrm_writer_destroy(&writer);
		return kr_error(EINVAL);
	}

	/* Create the I/O thread. */
	data->iothread = fstrm_iothr_init(opt, &writer);
	fstrm_iothr_options_destroy(&opt);
	if (!data->iothread) {
		ERROR_MSG("can't init fstrm_iothr\n");
		fstrm_writer_destroy(&writer);
		return kr_error(ENOMEM);
	}

	/* Get fstrm thread handle
	 * We only have one input queue, hence idx=0
	 */
	data->ioq = fstrm_iothr_get_input_queue_idx(data->iothread, 0);
	if (!data->ioq) {
		fstrm_iothr_destroy(&data->iothread);
		ERROR_MSG("can't get fstrm queue\n");
		return kr_error(EBUSY);
	}

	return kr_ok();
}

KR_MODULE_EXPORT(dnstap)

