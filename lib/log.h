/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <syslog.h>
#include "lib/defines.h"

#define LOG_UNKNOWN_LEVEL	-1 /**< Negative error value. */
#define LOG_GNUTLS_LEVEL	5 /**< GnuTLS level is 5. */

/* Targets */

typedef enum {
	LOG_TARGET_SYSLOG = 0,
	LOG_TARGET_STDERR = 1,
	LOG_TARGET_STDOUT = 2,
	/* The default also applies *before* configuration changes it. */
	LOG_TARGET_DEFAULT = LOG_TARGET_STDERR,
} kr_log_target_t;

/** Current logging target.  Read only, please. */
KR_EXPORT extern
kr_log_target_t kr_log_target;

/** Set the current logging target. */
KR_EXPORT
void kr_log_target_set(kr_log_target_t target);


/* Groups */

#define LOG_GRP_MAP(XX, XX_VAL) \
	XX_VAL(SYSTEM,     "system", 1, "catch-all log for generic messages") /* Must be second */ \
	\
	/* vv  Add new log groups below - keep sorted  vv */ \
	XX(CACHE,          "cache",     "record cache operations") \
	XX(CONTROL,        "contrl",    "TTY control sockets") \
	XX(COOKIES,        "cookie",    "DNS cookies") \
	XX(DAF,            "daf",       "DNS Application Firewall module") \
	XX(DETECTTIMEJUMP, "timejm",    "time jump detection") \
	XX(DETECTTIMESKEW, "timesk",    "time skew detection") \
	XX(DEVEL,          "devel",     "development purposes") \
	XX(DNSSEC,         "dnssec",    "DNSSEC") \
	XX(DNSTAP,         "dnstap",    "DNSTAP (traffic collection)") \
	XX(DOH,            "doh",       "DNS-over-HTTPS") \
	XX(DOTAUTH,        "dotaut",    "DNS-over-TLS towards authoritative servers") \
	XX(EDE,            "exterr",    "extended error module") \
	XX(GNUTLS,         "gnutls",    "low-level logs from GnuTLS") \
	XX(GRAPHITE,       "graphi",    "Graphite protocol module") \
	XX(HINT,           "hint",      "static hints") \
	XX(HTTP,           "http",      "legacy DNS-over-HTTPS module") \
	XX(IO,             "io",        "resolver input/output") \
	XX(ITERATOR,       "iterat",    "iterator layer") \
	XX(MODULE,         "module",    "for user-defined modules") \
	XX(NETWORK,        "net",       "network configuration and operation") \
	XX(NSID,           "nsid",      "name server identifier module") \
	XX(PLAN,           "plan",      "resolution planning") \
	XX(POLICY,         "policy",    "policy module") \
	XX(PREFILL,        "prefil",    "cache prefilling module") \
	XX(PRIMING,        "primin",    "priming queries module") \
	XX(PROTOLAYER,     "prlayr",    "protocol layer system") \
	XX(REBIND,         "rebind",    "rebinding attack protection module") \
	XX(RENUMBER,       "renum",     "IP address renumbering module") \
	XX(RESOLVER,       "resolv",    "name resolution") \
	XX(RULES,          "rules",     "rules module") \
	XX(SELECTION,      "select",    "server selection") \
	XX(SRVSTALE,       "srvstl",    "serve-stale module") \
	XX(STATISTICS,     "statis",    "statistics module") \
	XX(TA,             "ta",        "trust anchors") \
	XX(TASENTINEL,     "tasent",    "trust anchor sentinel module") \
	XX(TASIGNALING,    "tasign",    "trust anchor knowledge signaling module") \
	XX(TAUPDATE,       "taupd",     "trust anchor updater module") \
	XX(TESTS,          "tests",     "resolver testing") \
	XX(TLS,            "tls",       "TLS server") \
	XX(TLSCLIENT,      "tls_cl",    "TLS client") \
	XX(VALIDATOR,      "valdtr",    "validate layer") \
	XX(WATCHDOG,       "wtchdg",    "systemd watchdog integration module") \
	XX(WORKER,         "worker",    "task management") \
	XX(XDP,            "xdp",       "XDP") \
	XX(ZCUT,           "zoncut",    "zone cuts") \
	/* ^^  Add new log groups above - keep sorted  ^^ */ \
	\
	XX(REQDBG,         "reqdbg",    "request debugging") /* Must be first non-displayed entry in enum! */

/* Don't forget add *_TAG below, log_group_names[] item (log.c) and generate
 * new kres-gen.lua */
enum kr_log_group {
	LOG_GRP_UNKNOWN = -1,

#define XX(grp, str, desc) LOG_GRP_ ## grp,
#define XX_VAL(grp, str, val, desc) LOG_GRP_ ## grp = (val),
	LOG_GRP_MAP(XX, XX_VAL)
#undef XX_VAL
#undef XX

	LOG_GRP_COUNT
};

KR_EXPORT
extern const char *const kr_log_grp_names[];

KR_EXPORT
bool kr_log_group_is_set(enum kr_log_group group);
KR_EXPORT
void kr_log_group_add(enum kr_log_group group);
KR_EXPORT
void kr_log_group_reset(void);
KR_EXPORT
const char *kr_log_grp2name(enum kr_log_group group);
KR_EXPORT
enum kr_log_group kr_log_name2grp(const char *name);
KR_EXPORT
void kr_log_list_grps(void);


/* Levels */

typedef int kr_log_level_t;

/** Current logging level.  Read only, please. */
KR_EXPORT extern
kr_log_level_t kr_log_level;

/** Set the current logging level. */
KR_EXPORT
void kr_log_level_set(kr_log_level_t level);

KR_EXPORT
const char *kr_log_level2name(kr_log_level_t level);

/** Return negative on error. */
KR_EXPORT
kr_log_level_t kr_log_name2level(const char *name);

#define KR_LOG_LEVEL_IS(exp) ((kr_log_level >= (exp)) ? true : false)

/**
 * @name Logging levels
 *
 * We stick very close to POSIX syslog.h
 */
/// @{

#define kr_log_on_level(grp, level, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, (level), SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, kr_log_grp_names[LOG_GRP_ ## grp], ## __VA_ARGS__)

/** Levels less severe than ``notice`` are not logged by default. */
#define LOG_DEFAULT_LEVEL	LOG_NOTICE

/** Debugging message.  Can be very verbose.
 * The level is most often used through VERBOSE_MSG. */
#define kr_log_debug(grp, fmt, ...) \
	kr_log_on_level(grp, LOG_DEBUG, fmt, ## __VA_ARGS__)

#define kr_log_info(grp, fmt, ...) \
	kr_log_on_level(grp, LOG_INFO, fmt, ## __VA_ARGS__)

#define kr_log_notice(grp, fmt, ...) \
	kr_log_on_level(grp, LOG_NOTICE, fmt, ## __VA_ARGS__)

#define kr_log_warning(grp, fmt, ...) \
	kr_log_on_level(grp, LOG_WARNING, fmt, ## __VA_ARGS__)

/** Significant error.  The process continues, except for configuration errors during startup. */
#define kr_log_error(grp, fmt, ...) \
	kr_log_on_level(grp, LOG_ERR, fmt, ## __VA_ARGS__)

/** Critical condition.  The process dies.  Bad configuration should not cause this. */
#define kr_log_crit(grp, fmt, ...) \
	kr_log_on_level(grp, LOG_CRIT, fmt, ## __VA_ARGS__)

#define kr_log_deprecate(grp, fmt, ...) \
	kr_log_on_level(grp, LOG_WARNING, "deprecation WARNING: " fmt, ## __VA_ARGS__)

/**
 * Logging function for user modules. Uses group LOG_GRP_MODULE and ``info`` level.
 * @param fmt Format string
 */
#define kr_log(fmt, ...) \
	kr_log_fmt(LOG_GRP_MODULE, LOG_INFO, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_MODULE_TAG, ## __VA_ARGS__)

/// @}

struct kr_request;
struct kr_query;

/**
 * Log a debug-level message from a kr_request.  Typically we call kr_log_q() instead.
 *
 * @param  qry_uid query ID to append to request ID, 0 means "no query"
 * @param  indent level of indentation between [group ][req.qry] and message
 * @param  grp GROUP_NAME (without the LOG_GRP_ prefix)
 * @param  fmt printf-like format string
 */
#define kr_log_req(req, qry_uid, indent, grp, fmt, ...) \
       kr_log_req1(req, qry_uid, indent, LOG_GRP_ ## grp, kr_log_grp_names[LOG_GRP_ ## grp], fmt, ## __VA_ARGS__)
KR_EXPORT KR_PRINTF(6)
void kr_log_req1(const struct kr_request * const req, uint32_t qry_uid,
		const unsigned int indent, enum kr_log_group group, const char *tag, const char *fmt, ...);

/**
 * Log a debug-level message from a kr_query.
 *
 * @param  qry current query
 * @param  grp GROUP_NAME (without the LOG_GRP_ prefix)
 * @param  fmt printf-like format string
 */
#define kr_log_q(qry, grp, fmt, ...) \
	kr_log_q1(qry, LOG_GRP_ ## grp, kr_log_grp_names[LOG_GRP_ ## grp], fmt, ## __VA_ARGS__)
KR_EXPORT KR_PRINTF(4)
void kr_log_q1(const struct kr_query *qry, enum kr_log_group group, const char *tag, const char *fmt, ...);

/**
 * Return whether a particular log group in a request is in debug/verbose mode.
 *
 * Typically you use this as condition to compute some data to be logged,
 * in case that's considered too expensive to do unless it really gets logged.
 *
 * The request can be NULL, and there's a _qry() shorthand to specify query instead.
 */
#define kr_log_is_debug(grp, req) \
	__builtin_expect(kr_log_is_debug_fun(LOG_GRP_ ## grp, (req)), false)
#define kr_log_is_debug_qry(grp, qry) kr_log_is_debug(grp, (qry) ? (qry)->request : NULL)
KR_EXPORT
bool kr_log_is_debug_fun(enum kr_log_group group, const struct kr_request *req);


/* Helpers "internal" to log.* */

/** @internal
 *
 * If you don't have location, pass ("CODE_FILE=", "CODE_LINE=", "CODE_FUNC=")
 * Others than systemd don't utilize these metadata.
 */
KR_EXPORT KR_PRINTF(6)
void kr_log_fmt(enum kr_log_group group, kr_log_level_t level, const char *file, const char *line,
		const char *func, const char *fmt, ...);

#define KR_LOG_SJM_STR(x) #x
#define SD_JOURNAL_METADATA "CODE_FILE=" __FILE__, "CODE_LINE=" KR_LOG_SJM_STR(__LINE__), ""

