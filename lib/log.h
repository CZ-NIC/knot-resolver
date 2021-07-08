/*  Copyright (C) 2014-2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdarg.h>
#include <syslog.h>
#include "lib/defines.h"


#define LOG_DEFAULT_LEVEL	LOG_NOTICE

/* Targets */

typedef enum {
	LOG_TARGET_SYSLOG = 0,
	LOG_TARGET_STDERR = 1,
	LOG_TARGET_STDOUT = 2,
} log_target_t;

/* Groups */

typedef uint64_t log_groups_t;
typedef struct {
	char		*g_name;
	log_groups_t	g_val;
} log_group_names_t;

/* Don't forget add *_TAG below, log_group_names[] item (log.c) and generate
 * new kres-gen.lua */
enum kr_log_groups_type {
	LOG_GRP_SYSTEM = 1,
	LOG_GRP_CACHE,
	LOG_GRP_IO,
	LOG_GRP_NETWORK,
	LOG_GRP_TA,
	LOG_GRP_TLS,
	LOG_GRP_GNUTLS,
	LOG_GRP_TLSCLIENT,
	LOG_GRP_XDP,
	LOG_GRP_ZIMPORT,
	LOG_GRP_ZSCANNER,
	LOG_GRP_DOH,
	LOG_GRP_DNSSEC,
	LOG_GRP_HINT,
	LOG_GRP_PLAN,
	LOG_GRP_ITERATOR,
	LOG_GRP_VALIDATOR,
	LOG_GRP_RESOLVER,
	LOG_GRP_SELECTION,
	LOG_GRP_ZCUT,
	LOG_GRP_COOKIES,
	LOG_GRP_STATISTICS,
	LOG_GRP_REBIND,
	LOG_GRP_WORKER,
	LOG_GRP_POLICY,
	LOG_GRP_TASENTINEL,
	LOG_GRP_TASIGNALING,
	LOG_GRP_TAUPDATE,
	LOG_GRP_DAF,
	LOG_GRP_DETECTTIMEJUMP,
	LOG_GRP_DETECTTIMESKEW,
	LOG_GRP_GRAPHITE,
	LOG_GRP_PREFILL,
	LOG_GRP_PRIMING,
	LOG_GRP_SRVSTALE,
	LOG_GRP_WATCHDOG,
	LOG_GRP_NSID,
	LOG_GRP_DNSTAP,
	LOG_GRP_TESTS,
};


#define LOG_GRP_SYSTEM_TAG		"system"
#define LOG_GRP_CACHE_TAG		"cache"
#define LOG_GRP_IO_TAG			"io"
#define LOG_GRP_NETWORK_TAG		"net"
#define LOG_GRP_TA_TAG			"ta"
#define LOG_GRP_TLS_TAG			"tls"
#define LOG_GRP_GNUTLS_TAG		"gnutls"
#define LOG_GRP_TLSCLIENT_TAG		"tls_cl"
#define LOG_GRP_XDP_TAG			"xdp"
#define LOG_GRP_ZIMPORT_TAG		"zimprt"
#define LOG_GRP_ZSCANNER_TAG		"zscann"
#define LOG_GRP_DOH_TAG			"doh"
#define LOG_GRP_DNSSEC_TAG		"dnssec"
#define LOG_GRP_HINT_TAG		"hint"
#define LOG_GRP_PLAN_TAG		"plan"
#define LOG_GRP_ITERATOR_TAG		"iterat"
#define LOG_GRP_VALIDATOR_TAG		"valdtr"
#define LOG_GRP_RESOLVER_TAG		"resolv"
#define LOG_GRP_SELECTION_TAG		"select"
#define LOG_GRP_ZCUT_TAG		"zoncut"
#define LOG_GRP_COOKIES_TAG		"cookie"
#define LOG_GRP_STATISTICS_TAG		"statis"
#define LOG_GRP_REBIND_TAG		"rebind"
#define LOG_GRP_WORKER_TAG		"worker"
#define LOG_GRP_POLICY_TAG		"policy"
#define LOG_GRP_TASENTINEL_TAG		"tasent"
#define LOG_GRP_TASIGNALING_TAG		"tasign"
#define LOG_GRP_TAUPDATE_TAG		"taupd"
#define LOG_GRP_DAF_TAG			"daf"
#define LOG_GRP_DETECTTIMEJUMP_TAG	"timejm"
#define LOG_GRP_DETECTTIMESKEW_TAG	"timesk"
#define LOG_GRP_GRAPHITE_TAG		"graphi"
#define LOG_GRP_PREFILL_TAG		"prefil"
#define LOG_GRP_PRIMING_TAG		"primin"
#define LOG_GRP_SRVSTALE_TAG		"srvstl"
#define LOG_GRP_WATCHDOG_TAG		"wtchdg"
#define LOG_GRP_NSID_TAG		"nsid"
#define LOG_GRP_DNSTAP_TAG		"dnstap"
#define LOG_GRP_TESTS_TAG		"tests"

KR_EXPORT
extern log_groups_t kr_log_groups;
KR_EXPORT
int kr_log_group_is_set(log_groups_t group);
KR_EXPORT
void kr_log_add_group(log_groups_t group);
KR_EXPORT
void kr_log_del_group(log_groups_t group);
KR_EXPORT
char *kr_log_grp2name(log_groups_t group);
KR_EXPORT
log_groups_t kr_log_name2grp(const char *name);

/* Log */

typedef int log_level_t;

KR_EXPORT
extern log_level_t kr_log_level;
KR_EXPORT
extern log_target_t kr_log_target;
KR_EXPORT KR_PRINTF(6)
void kr_log_fmt(log_groups_t group, log_level_t level, const char *file, const char *line,
		const char *func, const char *fmt, ...);
KR_EXPORT
int kr_log_level_set(log_level_t level);
KR_EXPORT
log_level_t kr_log_level_get(void);
KR_EXPORT
void kr_log_init(log_level_t level, log_target_t target);

#define TO_STR_A(x) #x
#define TO_STR(x) TO_STR_A(x)
#define SD_JOURNAL_METADATA "CODE_FILE=" __FILE__, "CODE_LINE=" TO_STR(__LINE__), ""

#define kr_log_debug(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_DEBUG, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)
#define kr_log_info(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_INFO, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)
#define kr_log_notice(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_NOTICE, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)
#define kr_log_warning(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_WARNING, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)
#define kr_log_error(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_ERR, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)
#define kr_log_fatal(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_CRIT, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)

#define kr_log_deprecate(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_WARNING,SD_JOURNAL_METADATA, \
			"[%-6s] deprecation WARNING: " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)

#define KR_LOG_LEVEL_IS(exp) ((kr_log_level >= (exp)) ? true : false)


/* Syslog */

KR_EXPORT
char *kr_log_level2name(log_level_t level);
KR_EXPORT
log_level_t kr_log_name2level(const char *name);

#ifndef SYSLOG_NAMES
typedef struct _code {
	char	*c_name;
	int	c_val;
} syslog_code_t;

KR_EXPORT
extern syslog_code_t prioritynames[];
#endif


/* Misc. */

struct kr_request;
struct kr_query;

/**
 * Log a message through the request log handler or stdout.
 * Caller is responsible for detecting verbose mode, use QRVERBOSE() macro.
 * @param  qry_uid query ID to append to request ID, 0 means "no query"
 * @param  indent level of indentation between [req.qry][source] and message
 * @param  source message source
 * @param  fmt message format
 */
#define kr_log_req(req, qry_id, indent, grp, fmt, ...) \
       kr_log_req1(req, qry_id, indent, LOG_GRP_ ## grp, LOG_GRP_ ## grp ## _TAG, fmt, ## __VA_ARGS__)
KR_EXPORT KR_PRINTF(6)
void kr_log_req1(const struct kr_request * const req, uint32_t qry_uid,
		const unsigned int indent, log_groups_t group, const char *tag, const char *fmt, ...);

/**
 * Log a message through the request log handler or stdout.
 * Caller is responsible for detecting verbose mode, use QRVERBOSE() macro.
 * @param  qry current query
 * @param  source message source
 * @param  fmt message format
 */
#define kr_log_q(qry, grp, fmt, ...) kr_log_q1(qry, LOG_GRP_ ## grp, LOG_GRP_ ## grp ## _TAG, fmt, ## __VA_ARGS__)
KR_EXPORT KR_PRINTF(4)
void kr_log_q1(const struct kr_query *qry, log_groups_t group, const char *tag, const char *fmt, ...);

/** Block run in --verbose mode; optimized when not run. */
#define VERBOSE_STATUS __builtin_expect(KR_LOG_LEVEL_IS(LOG_DEBUG), false) // TODO vyhodit
#define WITH_VERBOSE(query) if(__builtin_expect(KR_LOG_LEVEL_IS(LOG_DEBUG) || kr_log_qtrace_enabled(query), false))

