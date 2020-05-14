
#include <stdlib.h>
#include <openssl/pem.h>

#include "daemon/quic.h"
#include "daemon/io.h"
#include "daemon/worker.h"
#include "daemon/session.h"

#include "contrib/ucw/mempool.h"
#include "contrib/quicly/defaults.h"
#include "contrib/quicly/streambuf.h"
#include "contrib/quicly/picotls/picotls/openssl.h"

static void on_stop_sending(quicly_stream_t *stream, int err)
{
	fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
	quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
	struct session *s = quic_get_session(stream->conn);
	session_quic_get_server_ctx(s)->processed_stream = stream;

	quicly_streambuf_t *sbuf = (quicly_streambuf_t *)stream->data;
	if (sbuf->ingress.is_allocated) {
		free(sbuf->ingress.base);
		sbuf->ingress.is_allocated = false;
	}
	sbuf->ingress.base = session_wirebuf_get_free_start(s);
	sbuf->ingress.capacity = session_wirebuf_get_free_size(s);

	/* read input to receive buffer */
	if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
		return;

	/* obtain contiguous bytes from the receive buffer */
	ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

	if (quicly_sendstate_is_open(&stream->sendstate)) {
		session_wirebuf_consume(s, input.base, input.len);
		session_wirebuf_process(s, quicly_get_peername(stream->conn));
		session_wirebuf_discard(s);
		/* shutdown the stream after echoing all data */
		if (quicly_recvstate_transfer_complete(&stream->recvstate))
			quicly_streambuf_egress_shutdown(stream);
	}

	/* remove used bytes from receive buffer */
	quicly_streambuf_ingress_shift(stream, input.len);
}

static void on_receive_reset(quicly_stream_t *stream, int err)
{
	fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
	quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
	static const quicly_stream_callbacks_t stream_callbacks = {
		quicly_streambuf_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit,
		on_stop_sending, on_receive, on_receive_reset
	};
	
	int ret;
	if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0) {
		return ret;
	}
	stream->callbacks = &stream_callbacks;

	return 0;
}

static quicly_stream_open_t stream_open = {on_stream_open};

struct quic_ctx_t* new_quic()
{
	struct quic_ctx_t *ctx = (struct quic_ctx_t *)calloc(1, sizeof(struct quic_ctx_t));
	if (!ctx) {
		return NULL;
	}

	ctx->quicly = quicly_spec_context;
	ctx->quicly.stream_open = &stream_open;
	memset(ctx->conns, 0, sizeof(ctx->conns));
	
	return ctx;
}

static int str_replace(char **where_ptr, const char *with)
{
	char *copy = with ? strdup(with) : NULL;
	if (with && !copy) {
		return kr_error(ENOMEM);
	}

	free(*where_ptr);
	*where_ptr = copy;
	return kr_ok();
}

int quic_certificate_set(struct network *net, const char *quic_cert, const char *quic_key)
{
	if (!net) {
		return kr_error(EINVAL);
	}
	struct quic_credentials *quic_credentials = (struct quic_credentials *)calloc(1, sizeof(*quic_credentials));
	if (quic_credentials == NULL) {
		return kr_error(ENOMEM);
	}

	quic_credentials->credentials.random_bytes = ptls_openssl_random_bytes;
	quic_credentials->credentials.get_time = &ptls_get_time;
	quic_credentials->credentials.key_exchanges = ptls_openssl_key_exchanges;
	quic_credentials->credentials.cipher_suites = ptls_openssl_cipher_suites;

	quicly_amend_ptls_context(&quic_credentials->credentials);

	int err = 0;
	if (err = ptls_load_certificates(&quic_credentials->credentials, quic_cert)) {
		kr_log_error("[quic] ptls_load_certificates() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		//tls_credentials_free(tls_credentials);
		return kr_error(ENOMEM);
	}
	
	FILE *fp;
	if ((fp = fopen(quic_key, "r")) == NULL) {
		fprintf(stderr, "failed to open file:%s:%s\n", quic_key, strerror(errno));
		//exit(1);
		return kr_error(EIO);
	}
	EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (pkey == NULL) {
		fprintf(stderr, "failed to load private key from file:%s\n", quic_key);
		//exit(1);
		return kr_error(EIO);
	}
	ptls_openssl_init_sign_certificate(&quic_credentials->sign_certificate, pkey);
	EVP_PKEY_free(pkey);
	quic_credentials->credentials.sign_certificate = &quic_credentials->sign_certificate.super;

	if ((quic_credentials->credentials.certificates.count != 0) != (quic_credentials->credentials.sign_certificate != NULL)) {
		return kr_error(EINVAL);
	}

	if ((str_replace(&quic_credentials->quic_cert, quic_cert) != 0) ||
	    (str_replace(&quic_credentials->quic_key, quic_key) != 0)) {
		//tls_credentials_free(tls_credentials);
		return kr_error(ENOMEM);
	}

	/* Exchange the x509 credentials */
	struct quic_credentials *old_credentials = net->quic_credentials;

	/* Start using the new x509_credentials */
	net->quic_credentials = quic_credentials;

	if (old_credentials) {
		free(old_credentials->quic_cert);
		free(old_credentials->quic_key);
		//TODO free properly
	}

	return kr_ok();
}

static int on_send(uv_udp_send_t *req, int status)
{
	free(req);
}

void quic_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags)
{
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;
	struct session *s = handle->data;
	struct quic_ctx_t *ctx = session_quic_get_server_ctx(s);
	
	//TODO idk how to set quicly.tls only once when net session is set (in better way), need someones help
	if (unlikely(ctx->quicly.tls == NULL)) {
		ctx->quicly.tls = &worker->engine->net.quic_credentials->credentials;
	}

	if (session_flags(s)->closing) {
		return;
	}

	if (nread <= 0) {
		if (nread < 0) { /* Error response, notify resolver */
			worker_submit(s, NULL, NULL);
		} /* nread == 0 is for freeing buffers, we don't need to do this */
		return;
	}
	if (addr->sa_family == AF_UNSPEC) {
		return;
	}

	if (session_flags(s)->outgoing) {
		const struct sockaddr *peer = session_get_peer(s);
		assert(peer->sa_family != AF_UNSPEC);
		if (kr_sockaddr_cmp(peer, addr) != 0) {
			kr_log_verbose("[io] <= ignoring UDP from unexpected address '%s'\n",
					kr_straddr(addr));
			return;
		}
	}

	size_t off, i, packet_len;
	/* split UDP datagram into multiple QUIC packets */
	for (off = 0; off < nread; off += packet_len) {
		quicly_decoded_packet_t decoded;
		if ((packet_len = quicly_decode_packet(&ctx->quicly, &decoded, buf->base + off, nread - off)) == SIZE_MAX) {
			return;
		}
		/* find the corresponding connection (TODO handle version negotiation, rebinding, retry, etc.) */
		for (i = 0; ctx->conns[i] != NULL; ++i) {
			if (quicly_is_destination(ctx->conns[i], NULL, addr, &decoded)) {
				break;
			}
		}

		if (ctx->conns[i] != NULL) {
			/* let the current connection handle ingress packets */
			quicly_receive(ctx->conns[i], NULL, addr, &decoded);
		} else {
			quicly_accept(&ctx->conns + i, &ctx->quicly, NULL, addr, &decoded, NULL, &ctx->next_cid, NULL);
		}

		quicly_conn_t *connection = NULL;
		if ((connection = ctx->conns[i]) == NULL) {
			continue;
		}

		quicly_datagram_t *dgrams[16];
		size_t num_dgrams = sizeof(dgrams) / sizeof(*dgrams);
		int ret = quicly_send(connection, dgrams, &num_dgrams);
		switch (ret) {
		case 0:
			{
				size_t j;
				size_t sent = 0;
				for (j = 0; j < num_dgrams; ++j) {
					sent += dgrams[j]->data.len;
					uv_udp_send_t*ioreq = malloc(sizeof(uv_udp_send_t));
					uv_udp_send(ioreq, handle, (uv_buf_t *)&dgrams[j]->data, 1, &dgrams[j]->dest.sin, on_send);
					ctx->quicly.packet_allocator->free_packet(ctx->quicly.packet_allocator, dgrams[j]);
				}
				if (sent) {
					printf("send %d\n", sent);
				}
			} break;
		case QUICLY_ERROR_FREE_CONNECTION:
			/* connection has been closed, free, and exit when running as a client */
			quicly_free(ctx->conns[i]);
			memmove(ctx->conns + i, ctx->conns + i + 1, sizeof(ctx->conns) - sizeof(ctx->conns[0]) * (i + 1));
			--i;
			break;
		default:
			fprintf(stderr, "quicly_send returned %d\n", ret);
			return;
		}
	}
	//ssize_t consumed = session_wirebuf_consume(s, (const uint8_t *)buf->base, nread);
	//assert(consumed == nread); (void)consumed;
	//session_wirebuf_process(s, addr);
	//session_wirebuf_discard(s);
	mp_flush(worker->pkt_pool.ctx);
}

int quic_write(uv_udp_send_t *ioreq, uv_udp_t *handle, const uv_buf_t *buf, unsigned int nbuf, quicly_stream_t *stream)
{
	for (size_t i = 0; i < nbuf; ++i) {
		quicly_streambuf_egress_write(stream, buf[i].base, buf[i].len);
	}

	quicly_datagram_t *dgrams[16];
	size_t num_dgrams = sizeof(dgrams) / sizeof(*dgrams);
	int ret = quicly_send(stream->conn, dgrams, &num_dgrams);
	
	size_t j;
	for (j = 0; j < num_dgrams; ++j) {
		uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t));
		uv_udp_send(req, handle, buf, nbuf, quicly_get_peername(stream->conn), on_send);
	}
	
	struct worker_ctx *worker = handle->loop->data;
	mp_flush(worker->pkt_pool.ctx);

	return 0;
}

struct session *quic_get_session(quicly_conn_t *conn)
{
	return *(struct session **)(quicly_get_context(conn) + 1);
}
