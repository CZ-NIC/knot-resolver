#!/bin/bash
set -o pipefail -o errexit

### Dev's guide
#
# C declarations for lua are (mostly) generated to simplify maintenance.
# (Avoid typos, accidental mismatches, etc.)
#
# To regenerate the C definitions for lua:
# - you need to have debugging symbols for knot-dns and knot-resolver;
#   you get those by compiling with -g; for knot-dns it might be enough
#   to just install it with debugging symbols included (in your distro way)
# - remove file ./kres-gen.lua and run make as usual
# - the knot-dns libraries are found via pkg-config
# - you also need gdb on $PATH


printf -- "local ffi = require('ffi')\n"
printf -- "--[[ This file is generated by ./kres-gen.sh ]] ffi.cdef[[\n"

## Various types (mainly), from libknot and libkres

printf "
typedef struct knot_dump_style knot_dump_style_t;
extern const knot_dump_style_t KNOT_DUMP_STYLE_DEFAULT;
typedef void knot_db_t;
struct kr_cdb_api {};
struct lru {};
"

# The generator doesn't work well with typedefs of functions.
printf "
typedef struct knot_mm {
	void *ctx, *alloc, *free;
} knot_mm_t;

typedef void *(*map_alloc_f)(void *, size_t);
typedef void (*map_free_f)(void *baton, void *ptr);
typedef void (*trace_log_f) (const struct kr_query *, const char *, const char *);
typedef void (*trace_callback_f)(struct kr_request *);
"

./scripts/gen-cdefs.sh libkres types <<-EOF
	knot_section_t
	knot_rrinfo_t
	knot_dname_t
	knot_rdata_t
	knot_rdataset_t
	struct knot_rdataset
	knot_rrset_t
	knot_pktsection_t
	struct knot_compr
	knot_compr_t
	struct knot_pkt
	knot_pkt_t
	knot_edns_client_subnet_t
	# generics
	map_t
	# libkres
	struct kr_cache_scope
	kr_cache_scope_t
	struct kr_qflags
	rr_array_t
	struct ranked_rr_array_entry
	ranked_rr_array_entry_t
	ranked_rr_array_t
	trie_t
	struct kr_zonecut
	kr_qarray_t
	struct kr_rplan
	struct kr_request
	enum kr_rank
	struct kr_cache
EOF

printf "
typedef int32_t (*kr_stale_cb)(int32_t ttl, const knot_dname_t *owner, uint16_t type,
				const struct kr_query *qry);
"

genResType() {
	echo "$1" | ./scripts/gen-cdefs.sh libkres types
}

# No simple way to fixup this rename in ./kres.lua AFAIK.
genResType "struct knot_rrset" | sed 's/\<owner\>/_owner/'

## Some definitions would need too many deps, so shorten them.

genResType "struct kr_nsrep" | sed '/union/,$ d'
printf "\t/* beware: hidden stub, to avoid hardcoding sockaddr lengths */\n};\n"

genResType "struct kr_query"

genResType "struct kr_context" | sed '/kr_nsrep_rtt_lru_t/,$ d'
printf "\tchar _stub[];\n};\n"

## libknot API
./scripts/gen-cdefs.sh libknot functions <<-EOF
# Utils
	knot_strerror
# Domain names
	knot_dname_copy
	knot_dname_from_str
	knot_dname_is_equal
	knot_dname_is_sub
	knot_dname_labels
	knot_dname_size
	knot_dname_to_str
# Resource records
	knot_rdata_rdlen
	knot_rdata_data
	knot_rdata_array_size
	knot_rdataset_at
	knot_rdataset_merge
	knot_rrset_add_rdata
	knot_rrset_init_empty
	knot_rrset_ttl
	knot_rrset_txt_dump
	knot_rrset_txt_dump_data
	knot_rrset_size
	knot_rrsig_type_covered
	knot_rrsig_sig_expiration
	knot_rrsig_sig_inception
# Packet
	knot_pkt_qname
	knot_pkt_qtype
	knot_pkt_qclass
	knot_pkt_begin
	knot_pkt_put_question
	knot_pkt_put
	knot_pkt_rr
	knot_pkt_section
	knot_pkt_new
	knot_pkt_free
	knot_pkt_parse
	knot_pkt_reserve
	knot_pkt_reclaim
# OPT
	knot_edns_get_version
	knot_edns_get_payload
	knot_edns_has_option
	knot_edns_get_option
	knot_edns_add_option
	knot_edns_client_subnet_size
	knot_edns_client_subnet_write
	knot_edns_client_subnet_parse
	knot_edns_client_subnet_set_addr
EOF

## libkres API
./scripts/gen-cdefs.sh libkres functions <<-EOF
# Resolution request
	kr_resolve_plan
	kr_resolve_pool
# Resolution plan
	kr_rplan_push
	kr_rplan_pop
	kr_rplan_resolved
	kr_rplan_last
# Nameservers
	kr_nsrep_set
# Utils
	kr_rand_uint
	kr_make_query
	kr_pkt_put
	kr_pkt_recycle
	kr_pkt_clear_payload
	kr_inaddr
	kr_inaddr_family
	kr_inaddr_len
	kr_inaddr_str
	kr_sockaddr_len
	kr_inaddr_port
	kr_straddr_family
	kr_straddr_subnet
	kr_bitcmp
	kr_family_len
	kr_straddr_socket
	kr_ranked_rrarray_add
	kr_qflags_set
	kr_qflags_clear
	kr_zonecut_add
	kr_zonecut_is_empty
	kr_zonecut_set
	kr_zonecut_find_nsname
	kr_now
	lru_free_items_impl
	lru_create_impl
	lru_get_impl
	mm_realloc
# Trust anchors
	kr_ta_get
	kr_ta_add
	kr_ta_del
	kr_ta_clear
# DNSSEC
	kr_dnssec_key_ksk
	kr_dnssec_key_revoked
	kr_dnssec_key_tag
	kr_dnssec_key_match
# Cache
	kr_cache_insert_rr
	kr_cache_sync
EOF

printf "]]\n"

exit 0
