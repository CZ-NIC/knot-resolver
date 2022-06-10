/*  Copyright (C) 2014-2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <syslog.h>
#include "lib/defines.h"

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

/* Don't forget add *_TAG below, log_group_names[] item (log.c) and generate
 * new kres-gen.lua */
enum kr_log_group {
	LOG_GRP_UNKNOWN = -1,
	LOG_GRP_SYSTEM = 1,  /* Must be first in enum. */
	LOG_GRP_CACHE,
	LOG_GRP_IO,
	LOG_GRP_NETWORK,
	LOG_GRP_TA,
	LOG_GRP_TLS,
	LOG_GRP_GNUTLS,
	LOG_GRP_TLSCLIENT,
	LOG_GRP_XDP,
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
	LOG_GRP_DOTAUTH,
	LOG_GRP_HTTP,
	LOG_GRP_CONTROL,
	LOG_GRP_MODULE,
	LOG_GRP_DEVEL,
	LOG_GRP_RENUMBER,
	LOG_GRP_EDE,
	LOG_GRP_WEAKPTR,
	/* ^^ Add new log groups above ^^. */
	LOG_GRP_REQDBG, /* Must be first non-displayed entry in enum! */
};

/**
 * @name Group names
 */
///@{
#define LOG_GRP_SYSTEM_TAG		"system"	/**< ``system``: catch-all log for generic messages*/
#define LOG_GRP_CACHE_TAG		"cache"		/**< ``cache``: operations related to cache */
#define LOG_GRP_IO_TAG			"io"		/**< ``io``: input/output operations */
#define LOG_GRP_NETWORK_TAG		"net"		/**< ``net``: network configuration and operation */
#define LOG_GRP_TA_TAG			"ta"		/**< ``ta``: basic log for trust anchors (TA) */
#define LOG_GRP_TASENTINEL_TAG		"tasent"	/**< ``tasent``: TA sentinel */
#define LOG_GRP_TASIGNALING_TAG		"tasign"	/**< ``tasign``: TA signal query */
#define LOG_GRP_TAUPDATE_TAG		"taupd"		/**< ``taupd``: TA update */
#define LOG_GRP_TLS_TAG			"tls"		/**< ``tls``: TLS encryption layer */
#define LOG_GRP_GNUTLS_TAG		"gnutls"	/**< ``gnutls``: low-level logs from GnuTLS */
#define LOG_GRP_TLSCLIENT_TAG		"tls_cl"	/**< ``tls_cl``: TLS client messages (used for TLS forwarding) */
#define LOG_GRP_XDP_TAG			"xdp"		/**< ``xdp``: operations related to XDP */
#define LOG_GRP_DOH_TAG			"doh"		/**< ``doh``: DNS-over-HTTPS logger (doh2 implementation) */
#define LOG_GRP_DNSSEC_TAG		"dnssec"	/**< ``dnssec``: operations related to DNSSEC */
#define LOG_GRP_HINT_TAG		"hint"		/**< ``hint``: operations related to static hints */
#define LOG_GRP_PLAN_TAG		"plan"		/**< ``plan``: operations related to resolution plan */
#define LOG_GRP_ITERATOR_TAG		"iterat"	/**< ``iterat``: operations related to iterate layer */
#define LOG_GRP_VALIDATOR_TAG		"valdtr"	/**< ``valdtr``: operations related to validate layer */
#define LOG_GRP_RESOLVER_TAG		"resolv"	/**< ``resolv``: operations related to resolving */
#define LOG_GRP_SELECTION_TAG		"select"	/**< ``select``: operations related to server selection */
#define LOG_GRP_ZCUT_TAG		"zoncut"	/**< ``zonecut``: operations related to zone cut */
#define LOG_GRP_COOKIES_TAG		"cookie"	/**< ``cookie``: operations related to cookies */
#define LOG_GRP_STATISTICS_TAG		"statis"	/**< ``statis``: operations related to statistics */
#define LOG_GRP_REBIND_TAG		"rebind"	/**< ``rebind``: operations related to rebinding */
#define LOG_GRP_WORKER_TAG		"worker"	/**< ``worker``: operations related to worker layer */
#define LOG_GRP_POLICY_TAG		"policy"	/**< ``policy``: operations related to policy */
#define LOG_GRP_DAF_TAG			"daf"		/**< ``daf``: operations related to DAF module */
#define LOG_GRP_DETECTTIMEJUMP_TAG	"timejm"	/**< ``timejm``: operations related to time jump */
#define LOG_GRP_DETECTTIMESKEW_TAG	"timesk"	/**< ``timesk``: operations related to time skew */
#define LOG_GRP_GRAPHITE_TAG		"graphi"	/**< ``graphi``: operations related to graphite */
#define LOG_GRP_PREFILL_TAG		"prefil"	/**< ``prefil``: operations related to prefill */
#define LOG_GRP_PRIMING_TAG		"primin"	/**< ``primin``: operations related to priming */
#define LOG_GRP_SRVSTALE_TAG		"srvstl"	/**< ``srvstl``: operations related to serve stale */
#define LOG_GRP_WATCHDOG_TAG		"wtchdg"	/**< ``wtchdg``: operations related to watchdog */
#define LOG_GRP_NSID_TAG		"nsid"		/**< ``nsid``: operations related to NSID */
#define LOG_GRP_DNSTAP_TAG		"dnstap"	/**< ``dnstap``: operations related to dnstap */
#define LOG_GRP_TESTS_TAG		"tests"		/**< ``tests``: operations related to tests  */
#define LOG_GRP_DOTAUTH_TAG		"dotaut"	/**< ``dotaut``: DNS-over-TLS against authoritative servers */
#define LOG_GRP_HTTP_TAG		"http"		/**< ``http``: http module, its web interface and legacy DNS-over-HTTPS */
#define LOG_GRP_CONTROL_TAG		"contrl"	/**< ``contrl``: TTY control sockets*/
#define LOG_GRP_MODULE_TAG		"module"	/**< ``module``: suitable for user-defined modules */
#define LOG_GRP_DEVEL_TAG		"devel"		/**< ``devel``: for development purposes */
#define LOG_GRP_RENUMBER_TAG		"renum"		/**< ``renum``: operation related to renumber */
#define LOG_GRP_EDE_TAG			"exterr"	/**< ``exterr``: extended error module */
#define LOG_GRP_WEAKPTR_TAG		"weakptr"	/**< ``weakptr``: weak pointer manager */
#define LOG_GRP_REQDBG_TAG		"reqdbg"	/**< ``reqdbg``: debug logs enabled by policy actions */
///@}

KR_EXPORT
bool kr_log_group_is_set(enum kr_log_group group);
KR_EXPORT
void kr_log_group_add(enum kr_log_group group);
KR_EXPORT
void kr_log_group_reset();
KR_EXPORT
const char *kr_log_grp2name(enum kr_log_group group);
KR_EXPORT
enum kr_log_group kr_log_name2grp(const char *name);


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

/** Debugging message.  Can be very verbose.
 * The level is most often used through VERBOSE_MSG. */
#define kr_log_debug(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_DEBUG, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)

#define kr_log_info(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_INFO, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)

#define kr_log_notice(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_NOTICE, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)

/** Levels less severe than ``notice`` are not logged by default. */
#define LOG_DEFAULT_LEVEL	LOG_NOTICE

#define kr_log_warning(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_WARNING, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)

/** Significant error.  The process continues, except for configuration errors during startup. */
#define kr_log_error(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_ERR, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)

/** Critical condition.  The process dies.  Bad configuration should not cause this. */
#define kr_log_crit(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_CRIT, SD_JOURNAL_METADATA, \
			"[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)

#define kr_log_deprecate(grp, fmt, ...) \
	kr_log_fmt(LOG_GRP_ ## grp, LOG_WARNING, SD_JOURNAL_METADATA, \
			"[%-6s] deprecation WARNING: " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__)

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
#define kr_log_req(req, qry_id, indent, grp, fmt, ...) \
       kr_log_req1(req, qry_id, indent, LOG_GRP_ ## grp, LOG_GRP_ ## grp ## _TAG, fmt, ## __VA_ARGS__)
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
#define kr_log_q(qry, grp, fmt, ...) kr_log_q1(qry, LOG_GRP_ ## grp, LOG_GRP_ ## grp ## _TAG, fmt, ## __VA_ARGS__)
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

