-- SPDX-License-Identifier: GPL-3.0-or-later

local ffi = require('ffi')
--[[ This file is generated by ./kres-gen.sh ]] ffi.cdef[[
typedef long time_t;
typedef long __time_t;
typedef long __suseconds_t;
struct timeval {
	__time_t tv_sec;
	__suseconds_t tv_usec;
};

typedef struct knot_dump_style knot_dump_style_t;
extern const knot_dump_style_t KNOT_DUMP_STYLE_DEFAULT;
struct kr_cdb_api {};
struct lru {};
typedef enum {KNOT_ANSWER, KNOT_AUTHORITY, KNOT_ADDITIONAL} knot_section_t;
typedef struct {
	uint16_t pos;
	uint16_t flags;
	uint16_t compress_ptr[16];
} knot_rrinfo_t;
typedef unsigned char knot_dname_t;
typedef struct {
	uint16_t len;
	uint8_t data[];
} knot_rdata_t;
typedef struct {
	uint16_t count;
	uint32_t size;
	knot_rdata_t *rdata;
} knot_rdataset_t;

typedef struct knot_mm {
	void *ctx, *alloc, *free;
} knot_mm_t;

typedef void *(*map_alloc_f)(void *, size_t);
typedef void (*map_free_f)(void *baton, void *ptr);
typedef void (*trace_log_f) (const struct kr_request *, const char *);
typedef void (*trace_callback_f)(struct kr_request *);
typedef uint8_t * (*alloc_wire_f)(struct kr_request *req, uint16_t *maxlen);
typedef bool (*addr_info_f)(struct sockaddr*);
typedef struct {
	knot_dname_t *_owner;
	uint32_t _ttl;
	uint16_t type;
	uint16_t rclass;
	knot_rdataset_t rrs;
	void *additional;
} knot_rrset_t;

struct kr_module;
typedef char *(kr_prop_cb)(void *, struct kr_module *, const char *);
typedef struct knot_pkt knot_pkt_t;
typedef struct {
	uint8_t *ptr[15];
} knot_edns_options_t;
typedef struct {
	knot_pkt_t *pkt;
	uint16_t pos;
	uint16_t count;
} knot_pktsection_t;
typedef struct knot_compr {
	uint8_t *wire;
	knot_rrinfo_t *rrinfo;
	struct {
		uint16_t pos;
		uint8_t labels;
	} suffix;
} knot_compr_t;
struct knot_pkt {
	uint8_t *wire;
	size_t size;
	size_t max_size;
	size_t parsed;
	uint16_t reserved;
	uint16_t qname_size;
	uint16_t rrset_count;
	uint16_t flags;
	knot_rrset_t *opt_rr;
	knot_rrset_t *tsig_rr;
	knot_edns_options_t *edns_opts;
	struct {
		uint8_t *pos;
		size_t len;
	} tsig_wire;
	knot_section_t current;
	knot_pktsection_t sections[3];
	size_t rrset_allocd;
	knot_rrinfo_t *rr_info;
	knot_rrset_t *rr;
	knot_mm_t mm;
	knot_compr_t compr;
};
typedef struct {
	void *root;
	struct knot_mm *pool;
} map_t;
typedef struct trie trie_t;
struct kr_qflags {
	_Bool NO_MINIMIZE : 1;
	_Bool NO_IPV6 : 1;
	_Bool NO_IPV4 : 1;
	_Bool TCP : 1;
	_Bool RESOLVED : 1;
	_Bool AWAIT_IPV4 : 1;
	_Bool AWAIT_IPV6 : 1;
	_Bool AWAIT_CUT : 1;
	_Bool NO_EDNS : 1;
	_Bool CACHED : 1;
	_Bool NO_CACHE : 1;
	_Bool EXPIRING : 1;
	_Bool ALLOW_LOCAL : 1;
	_Bool DNSSEC_WANT : 1;
	_Bool DNSSEC_BOGUS : 1;
	_Bool DNSSEC_INSECURE : 1;
	_Bool DNSSEC_CD : 1;
	_Bool STUB : 1;
	_Bool ALWAYS_CUT : 1;
	_Bool DNSSEC_WEXPAND : 1;
	_Bool PERMISSIVE : 1;
	_Bool STRICT : 1;
	_Bool BADCOOKIE_AGAIN : 1;
	_Bool CNAME : 1;
	_Bool REORDER_RR : 1;
	_Bool TRACE : 1;
	_Bool NO_0X20 : 1;
	_Bool DNSSEC_NODS : 1;
	_Bool DNSSEC_OPTOUT : 1;
	_Bool NONAUTH : 1;
	_Bool FORWARD : 1;
	_Bool DNS64_MARK : 1;
	_Bool CACHE_TRIED : 1;
	_Bool NO_NS_FOUND : 1;
	_Bool PKT_IS_SANE : 1;
};
typedef struct ranked_rr_array_entry {
	uint32_t qry_uid;
	uint8_t rank;
	uint8_t revalidation_cnt;
	_Bool cached : 1;
	_Bool yielded : 1;
	_Bool to_wire : 1;
	_Bool expiring : 1;
	_Bool in_progress : 1;
	_Bool dont_cache : 1;
	knot_rrset_t *rr;
} ranked_rr_array_entry_t;
typedef struct {
	ranked_rr_array_entry_t **at;
	size_t len;
	size_t cap;
} ranked_rr_array_t;
typedef struct kr_http_header_array_entry {
	char *name;
	char *value;
} kr_http_header_array_entry_t;
typedef struct {
	kr_http_header_array_entry_t *at;
	size_t len;
	size_t cap;
} kr_http_header_array_t;
typedef struct {
	union inaddr *at;
	size_t len;
	size_t cap;
} inaddr_array_t;
struct kr_zonecut {
	knot_dname_t *name;
	knot_rrset_t *key;
	knot_rrset_t *trust_anchor;
	struct kr_zonecut *parent;
	trie_t *nsset;
	knot_mm_t *pool;
};
typedef struct {
	struct kr_query **at;
	size_t len;
	size_t cap;
} kr_qarray_t;
struct kr_rplan {
	kr_qarray_t pending;
	kr_qarray_t resolved;
	struct kr_query *initial;
	struct kr_request *request;
	knot_mm_t *pool;
	uint32_t next_uid;
};
struct kr_request_qsource_flags {
	_Bool tcp : 1;
	_Bool tls : 1;
	_Bool http : 1;
	_Bool xdp : 1;
};
struct kr_request {
	struct kr_context *ctx;
	knot_pkt_t *answer;
	struct kr_query *current_query;
	struct {
		const struct sockaddr *addr;
		const struct sockaddr *dst_addr;
		const knot_pkt_t *packet;
		struct kr_request_qsource_flags flags;
		size_t size;
		int32_t stream_id;
		kr_http_header_array_t headers;
	} qsource;
	struct {
		unsigned int rtt;
		const struct kr_transport *transport;
	} upstream;
	struct kr_qflags options;
	int state;
	ranked_rr_array_t answ_selected;
	ranked_rr_array_t auth_selected;
	ranked_rr_array_t add_selected;
	_Bool answ_validated;
	_Bool auth_validated;
	uint8_t rank;
	struct kr_rplan rplan;
	trace_log_f trace_log;
	trace_callback_f trace_finish;
	int vars_ref;
	knot_mm_t pool;
	unsigned int uid;
	struct {
		addr_info_f is_tls_capable;
		addr_info_f is_tcp_connected;
		addr_info_f is_tcp_waiting;
		inaddr_array_t forwarding_targets;
	} selection_context;
	unsigned int count_no_nsaddr;
	unsigned int count_fail_row;
	alloc_wire_f alloc_wire_cb;
};
enum kr_rank {KR_RANK_INITIAL, KR_RANK_OMIT, KR_RANK_TRY, KR_RANK_INDET = 4, KR_RANK_BOGUS, KR_RANK_MISMATCH, KR_RANK_MISSING, KR_RANK_INSECURE, KR_RANK_AUTH = 16, KR_RANK_SECURE = 32};
typedef struct kr_cdb * kr_cdb_pt;
struct kr_cdb_stats {
	uint64_t open;
	uint64_t close;
	uint64_t count;
	uint64_t count_entries;
	uint64_t clear;
	uint64_t commit;
	uint64_t read;
	uint64_t read_miss;
	uint64_t write;
	uint64_t remove;
	uint64_t remove_miss;
	uint64_t match;
	uint64_t match_miss;
	uint64_t read_leq;
	uint64_t read_leq_miss;
	double usage_percent;
};
typedef struct uv_timer_s uv_timer_t;
struct kr_cache {
	kr_cdb_pt db;
	const struct kr_cdb_api *api;
	struct kr_cdb_stats stats;
	uint32_t ttl_min;
	uint32_t ttl_max;
	struct timeval checkpoint_walltime;
	uint64_t checkpoint_monotime;
	uv_timer_t *health_timer;
};
typedef struct kr_layer {
	int state;
	struct kr_request *req;
	const struct kr_layer_api *api;
	knot_pkt_t *pkt;
	struct sockaddr *dst;
	_Bool is_stream;
} kr_layer_t;
typedef struct kr_layer_api {
	int (*begin)(kr_layer_t *);
	int (*reset)(kr_layer_t *);
	int (*finish)(kr_layer_t *);
	int (*consume)(kr_layer_t *, knot_pkt_t *);
	int (*produce)(kr_layer_t *, knot_pkt_t *);
	int (*checkout)(kr_layer_t *, knot_pkt_t *, struct sockaddr *, int);
	int (*answer_finalize)(kr_layer_t *);
	void *data;
	int cb_slots[];
} kr_layer_api_t;
struct kr_prop {
	kr_prop_cb *cb;
	const char *name;
	const char *info;
};
struct kr_module {
	char *name;
	int (*init)(struct kr_module *);
	int (*deinit)(struct kr_module *);
	int (*config)(struct kr_module *, const char *);
	const kr_layer_api_t *layer;
	const struct kr_prop *props;
	void *lib;
	void *data;
};
struct kr_server_selection {
	_Bool initialized;
	void (*choose_transport)(struct kr_query *, struct kr_transport **);
	void (*update_rtt)(struct kr_query *, const struct kr_transport *, unsigned int);
	void (*error)(struct kr_query *, const struct kr_transport *, enum kr_selection_error);
	struct local_state *local_state;
};
typedef int kr_log_level_t;
enum kr_log_group {LOG_GRP_UNKNOWN = -1, LOG_GRP_SYSTEM = 1, LOG_GRP_CACHE, LOG_GRP_IO, LOG_GRP_NETWORK, LOG_GRP_TA, LOG_GRP_TLS, LOG_GRP_GNUTLS, LOG_GRP_TLSCLIENT, LOG_GRP_XDP, LOG_GRP_ZIMPORT, LOG_GRP_ZSCANNER, LOG_GRP_DOH, LOG_GRP_DNSSEC, LOG_GRP_HINT, LOG_GRP_PLAN, LOG_GRP_ITERATOR, LOG_GRP_VALIDATOR, LOG_GRP_RESOLVER, LOG_GRP_SELECTION, LOG_GRP_ZCUT, LOG_GRP_COOKIES, LOG_GRP_STATISTICS, LOG_GRP_REBIND, LOG_GRP_WORKER, LOG_GRP_POLICY, LOG_GRP_TASENTINEL, LOG_GRP_TASIGNALING, LOG_GRP_TAUPDATE, LOG_GRP_DAF, LOG_GRP_DETECTTIMEJUMP, LOG_GRP_DETECTTIMESKEW, LOG_GRP_GRAPHITE, LOG_GRP_PREFILL, LOG_GRP_PRIMING, LOG_GRP_SRVSTALE, LOG_GRP_WATCHDOG, LOG_GRP_NSID, LOG_GRP_DNSTAP, LOG_GRP_TESTS, LOG_GRP_DOTAUTH, LOG_GRP_HTTP, LOG_GRP_CONTROL, LOG_GRP_MODULE, LOG_GRP_RDEBUG, LOG_GRP_DEVEL};

kr_layer_t kr_layer_t_static;
_Bool kr_dbg_assertion_abort;
int kr_dbg_assertion_fork;

typedef int32_t (*kr_stale_cb)(int32_t ttl, const knot_dname_t *owner, uint16_t type,
				const struct kr_query *qry);

void kr_rrset_init(knot_rrset_t *rrset, knot_dname_t *owner,
			uint16_t type, uint16_t rclass, uint32_t ttl);
struct kr_query {
	struct kr_query *parent;
	knot_dname_t *sname;
	uint16_t stype;
	uint16_t sclass;
	uint16_t id;
	uint16_t reorder;
	struct kr_qflags flags;
	struct kr_qflags forward_flags;
	uint32_t secret;
	uint32_t uid;
	uint64_t creation_time_mono;
	uint64_t timestamp_mono;
	struct timeval timestamp;
	struct kr_zonecut zone_cut;
	struct kr_layer_pickle *deferred;
	int8_t cname_depth;
	struct kr_query *cname_parent;
	struct kr_request *request;
	kr_stale_cb stale_cb;
	struct kr_server_selection server_selection;
};
struct kr_context {
	struct kr_qflags options;
	knot_rrset_t *downstream_opt_rr;
	knot_rrset_t *upstream_opt_rr;
	map_t trust_anchors;
	map_t negative_anchors;
	struct kr_zonecut root_hints;
	struct kr_cache cache;
	unsigned int cache_rtt_tout_retry_interval;
	char _stub[];
};
struct kr_transport {
	knot_dname_t *ns_name;
	/* beware: hidden stub, to avoid hardcoding sockaddr lengths */
};
const char *knot_strerror(int);
knot_dname_t *knot_dname_copy(const knot_dname_t *, knot_mm_t *);
knot_dname_t *knot_dname_from_str(uint8_t *, const char *, size_t);
int knot_dname_in_bailiwick(const knot_dname_t *, const knot_dname_t *);
_Bool knot_dname_is_equal(const knot_dname_t *, const knot_dname_t *);
size_t knot_dname_labels(const uint8_t *, const uint8_t *);
size_t knot_dname_size(const knot_dname_t *);
void knot_dname_to_lower(knot_dname_t *);
char *knot_dname_to_str(char *, const knot_dname_t *, size_t);
knot_rdata_t *knot_rdataset_at(const knot_rdataset_t *, uint16_t);
int knot_rdataset_merge(knot_rdataset_t *, const knot_rdataset_t *, knot_mm_t *);
int knot_rrset_add_rdata(knot_rrset_t *, const uint8_t *, uint16_t, knot_mm_t *);
void knot_rrset_free(knot_rrset_t *, knot_mm_t *);
int knot_rrset_txt_dump(const knot_rrset_t *, char **, size_t *, const knot_dump_style_t *);
int knot_rrset_txt_dump_data(const knot_rrset_t *, const size_t, char *, const size_t, const knot_dump_style_t *);
size_t knot_rrset_size(const knot_rrset_t *);
int knot_pkt_begin(knot_pkt_t *, knot_section_t);
int knot_pkt_put_question(knot_pkt_t *, const knot_dname_t *, uint16_t, uint16_t);
int knot_pkt_put_rotate(knot_pkt_t *, uint16_t, const knot_rrset_t *, uint16_t, uint16_t);
knot_pkt_t *knot_pkt_new(void *, uint16_t, knot_mm_t *);
void knot_pkt_free(knot_pkt_t *);
int knot_pkt_parse(knot_pkt_t *, unsigned int);
knot_pkt_t *kr_request_ensure_answer(struct kr_request *);
struct kr_rplan *kr_resolve_plan(struct kr_request *);
knot_mm_t *kr_resolve_pool(struct kr_request *);
struct kr_query *kr_rplan_push(struct kr_rplan *, struct kr_query *, const knot_dname_t *, uint16_t, uint16_t);
int kr_rplan_pop(struct kr_rplan *, struct kr_query *);
struct kr_query *kr_rplan_resolved(struct kr_rplan *);
struct kr_query *kr_rplan_last(struct kr_rplan *);
int kr_forward_add_target(struct kr_request *, const struct sockaddr *);
void kr_log_req1(const struct kr_request * const, uint32_t, const unsigned int, enum kr_log_group, const char *, const char *, ...);
void kr_log_q1(const struct kr_query * const, enum kr_log_group, const char *, const char *, ...);
const char *kr_log_grp2name(enum kr_log_group);
void kr_log_fmt(enum kr_log_group, kr_log_level_t, const char *, const char *, const char *, const char *, ...);
int kr_make_query(struct kr_query *, knot_pkt_t *);
void kr_pkt_make_auth_header(knot_pkt_t *);
int kr_pkt_put(knot_pkt_t *, const knot_dname_t *, uint32_t, uint16_t, uint16_t, const uint8_t *, uint16_t);
int kr_pkt_recycle(knot_pkt_t *);
int kr_pkt_clear_payload(knot_pkt_t *);
uint16_t kr_pkt_has_dnssec(const knot_pkt_t *);
uint16_t kr_pkt_qclass(const knot_pkt_t *);
uint16_t kr_pkt_qtype(const knot_pkt_t *);
char *kr_pkt_text(const knot_pkt_t *);
void kr_rnd_buffered(void *, unsigned int);
uint32_t kr_rrsig_sig_inception(const knot_rdata_t *);
uint32_t kr_rrsig_sig_expiration(const knot_rdata_t *);
uint16_t kr_rrsig_type_covered(const knot_rdata_t *);
const char *kr_inaddr(const struct sockaddr *);
int kr_inaddr_family(const struct sockaddr *);
int kr_inaddr_len(const struct sockaddr *);
int kr_inaddr_str(const struct sockaddr *, char *, size_t *);
int kr_sockaddr_cmp(const struct sockaddr *, const struct sockaddr *);
int kr_sockaddr_len(const struct sockaddr *);
uint16_t kr_inaddr_port(const struct sockaddr *);
int kr_straddr_family(const char *);
int kr_straddr_subnet(void *, const char *);
int kr_bitcmp(const char *, const char *, int);
int kr_family_len(int);
struct sockaddr *kr_straddr_socket(const char *, int, knot_mm_t *);
int kr_straddr_split(const char *, char * restrict, uint16_t *);
_Bool kr_rank_test(uint8_t, uint8_t);
int kr_ranked_rrarray_add(ranked_rr_array_t *, const knot_rrset_t *, uint8_t, _Bool, uint32_t, knot_mm_t *);
int kr_ranked_rrarray_finalize(ranked_rr_array_t *, uint32_t, knot_mm_t *);
void kr_qflags_set(struct kr_qflags *, struct kr_qflags);
void kr_qflags_clear(struct kr_qflags *, struct kr_qflags);
int kr_zonecut_add(struct kr_zonecut *, const knot_dname_t *, const void *, int);
_Bool kr_zonecut_is_empty(struct kr_zonecut *);
void kr_zonecut_set(struct kr_zonecut *, const knot_dname_t *);
uint64_t kr_now();
const char *kr_strptime_diff(const char *, const char *, const char *, double *);
time_t kr_file_mtime(const char *);
long long kr_fssize(const char *);
const char *kr_dirent_name(const struct dirent *);
void lru_free_items_impl(struct lru *);
struct lru *lru_create_impl(unsigned int, unsigned int, knot_mm_t *, knot_mm_t *);
void *lru_get_impl(struct lru *, const char *, unsigned int, unsigned int, _Bool, _Bool *);
void *mm_realloc(knot_mm_t *, void *, size_t, size_t);
knot_rrset_t *kr_ta_get(map_t *, const knot_dname_t *);
int kr_ta_add(map_t *, const knot_dname_t *, uint16_t, uint32_t, const uint8_t *, uint16_t);
int kr_ta_del(map_t *, const knot_dname_t *);
void kr_ta_clear(map_t *);
_Bool kr_dnssec_key_ksk(const uint8_t *);
_Bool kr_dnssec_key_revoked(const uint8_t *);
int kr_dnssec_key_tag(uint16_t, const uint8_t *, size_t);
int kr_dnssec_key_match(const uint8_t *, size_t, const uint8_t *, size_t);
int kr_cache_closest_apex(struct kr_cache *, const knot_dname_t *, _Bool, knot_dname_t **);
int kr_cache_insert_rr(struct kr_cache *, const knot_rrset_t *, const knot_rrset_t *, uint8_t, uint32_t);
int kr_cache_remove(struct kr_cache *, const knot_dname_t *, uint16_t);
int kr_cache_remove_subtree(struct kr_cache *, const knot_dname_t *, _Bool, int);
int kr_cache_commit(struct kr_cache *);
uint32_t packet_ttl(const knot_pkt_t *, _Bool);
typedef struct {
	int sock_type;
	_Bool tls;
	_Bool http;
	_Bool xdp;
	_Bool freebind;
	const char *kind;
} endpoint_flags_t;
typedef struct {
	char **at;
	size_t len;
	size_t cap;
} addr_array_t;
typedef struct {
	int fd;
	endpoint_flags_t flags;
} flagged_fd_t;
typedef struct {
	flagged_fd_t *at;
	size_t len;
	size_t cap;
} flagged_fd_array_t;
typedef struct {
	const char **at;
	size_t len;
	size_t cap;
} config_array_t;
struct args {
	addr_array_t addrs;
	addr_array_t addrs_tls;
	flagged_fd_array_t fds;
	int control_fd;
	int forks;
	config_array_t config;
	const char *rundir;
	_Bool interactive;
	_Bool quiet;
	_Bool tty_binary_output;
};
struct args *the_args;
struct endpoint {
	void *handle;
	int fd;
	int family;
	uint16_t port;
	int16_t nic_queue;
	_Bool engaged;
	endpoint_flags_t flags;
};
struct request_ctx {
	struct kr_request req;
	struct worker_ctx *worker;
	struct qr_task *task;
	/* beware: hidden stub, to avoid hardcoding sockaddr lengths */
};
struct qr_task {
	struct request_ctx *ctx;
	/* beware: hidden stub, to avoid qr_tasklist_t */
};
int worker_resolve_exec(struct qr_task *, knot_pkt_t *);
knot_pkt_t *worker_resolve_mk_pkt(const char *, uint16_t, uint16_t, const struct kr_qflags *);
struct qr_task *worker_resolve_start(knot_pkt_t *, struct kr_qflags);
struct engine {
	struct kr_context resolver;
	char _stub[];
};
struct worker_ctx {
	struct engine *engine;
	char _stub[];
};
struct worker_ctx *the_worker;
typedef struct {
	uint8_t bitmap[32];
	uint8_t length;
} zs_win_t;
typedef struct {
	uint8_t excl_flag;
	uint16_t addr_family;
	uint8_t prefix_length;
} zs_apl_t;
typedef struct {
	uint32_t d1;
	uint32_t d2;
	uint32_t m1;
	uint32_t m2;
	uint32_t s1;
	uint32_t s2;
	uint32_t alt;
	uint64_t siz;
	uint64_t hp;
	uint64_t vp;
	int8_t lat_sign;
	int8_t long_sign;
	int8_t alt_sign;
} zs_loc_t;
typedef enum {ZS_STATE_NONE, ZS_STATE_DATA, ZS_STATE_ERROR, ZS_STATE_INCLUDE, ZS_STATE_EOF, ZS_STATE_STOP} zs_state_t;
typedef struct zs_scanner zs_scanner_t;
typedef struct zs_scanner {
	int cs;
	int top;
	int stack[16];
	_Bool multiline;
	uint64_t number64;
	uint64_t number64_tmp;
	uint32_t decimals;
	uint32_t decimal_counter;
	uint32_t item_length;
	uint32_t item_length_position;
	uint8_t *item_length_location;
	uint32_t buffer_length;
	uint8_t buffer[65535];
	char include_filename[65535];
	char *path;
	zs_win_t windows[256];
	int16_t last_window;
	zs_apl_t apl;
	zs_loc_t loc;
	uint8_t addr[16];
	_Bool long_string;
	uint8_t *dname;
	uint32_t *dname_length;
	uint32_t dname_tmp_length;
	uint32_t r_data_tail;
	uint32_t zone_origin_length;
	uint8_t zone_origin[318];
	uint16_t default_class;
	uint32_t default_ttl;
	zs_state_t state;
	struct {
		_Bool automatic;
		void (*record)(zs_scanner_t *);
		void (*error)(zs_scanner_t *);
		void (*comment)(zs_scanner_t *);
		void *data;
	} process;
	struct {
		const char *start;
		const char *current;
		const char *end;
		_Bool eof;
		_Bool mmaped;
	} input;
	struct {
		char *name;
		int descriptor;
	} file;
	struct {
		int code;
		uint64_t counter;
		_Bool fatal;
	} error;
	uint64_t line_counter;
	uint32_t r_owner_length;
	uint8_t r_owner[318];
	uint16_t r_class;
	uint32_t r_ttl;
	uint16_t r_type;
	uint32_t r_data_length;
	uint8_t r_data[65535];
} zs_scanner_t;
void zs_deinit(zs_scanner_t *);
int zs_init(zs_scanner_t *, const char *, const uint16_t, const uint32_t);
int zs_parse_record(zs_scanner_t *);
int zs_set_input_file(zs_scanner_t *, const char *);
int zs_set_input_string(zs_scanner_t *, const char *, size_t);
const char *zs_strerror(const int);
]]
