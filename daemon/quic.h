
#pragma once

#include "contrib/quicly/quicly.h"
#include "contrib/quicly/constants.h"
#include "contrib/quicly/picotls/picotls.h"
#include "contrib/quicly/picotls/picotls/openssl.h"

#include "lib/utils.h"
#include "lib/defines.h"

#include <uv.h>
#include <sys/socket.h>
#include <libknot/packet/pkt.h>

struct session;

struct quic_ctx_t;

struct worker_ctx;
struct network;

struct quic_credentials {
    char *quic_cert;
    char *quic_key;
    ptls_context_t credentials;
    ptls_openssl_sign_certificate_t sign_certificate;
};

struct quic_ctx_t {
    quicly_context_t quicly;
    struct session *session; /*! Keep session right under `quicly_context_t quicly`, it's used offset to access this member */
    quicly_conn_t *conns[256]; //TODO use some hashmap struct or just malloc this array
    quicly_cid_plaintext_t next_cid;
	quicly_stream_t *processed_stream;
};

struct quic_ctx_t* new_quic();
int quic_certificate_set(struct network *net, const char *quic_cert, const char *quic_key);
void quic_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);
int quic_write(uv_udp_send_t *ioreq, uv_udp_t *handle, const uv_buf_t *buf, unsigned int nbuf, quicly_stream_t *stream);
struct session *quic_get_session(quicly_conn_t *conn);
