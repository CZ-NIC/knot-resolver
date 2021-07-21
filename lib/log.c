/*  Copyright (C) 2014-2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "kresconfig.h"

#include <stdio.h>
#include <gnutls/gnutls.h>
#include "contrib/ucw/mempool.h"
#include "lib/log.h"
#include "lib/resolve.h"

#if ENABLE_LIBSYSTEMD
#include <stdlib.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>

int use_journal = 0;
#endif

log_level_t kr_log_level = LOG_CRIT;
log_target_t kr_log_target = LOG_TARGET_STDOUT;

/** Set of log-groups that are on debug level.  It's a bitmap over 1 << enum kr_log_group. */
static uint64_t kr_log_groups = 0;

static_assert(LOG_GRP_DEVEL <= 8 * sizeof(kr_log_groups), "Too many log groups.");

#define GRP_NAME_ITEM(grp) { grp ## _TAG, grp }

log_group_names_t log_group_names[] = {
	GRP_NAME_ITEM(LOG_GRP_SYSTEM),
	GRP_NAME_ITEM(LOG_GRP_CACHE),
	GRP_NAME_ITEM(LOG_GRP_IO),
	GRP_NAME_ITEM(LOG_GRP_NETWORK),
	GRP_NAME_ITEM(LOG_GRP_TA),
	GRP_NAME_ITEM(LOG_GRP_TLS),
	GRP_NAME_ITEM(LOG_GRP_GNUTLS),
	GRP_NAME_ITEM(LOG_GRP_TLSCLIENT),
	GRP_NAME_ITEM(LOG_GRP_XDP),
	GRP_NAME_ITEM(LOG_GRP_ZIMPORT),
	GRP_NAME_ITEM(LOG_GRP_ZSCANNER),
	GRP_NAME_ITEM(LOG_GRP_DOH),
	GRP_NAME_ITEM(LOG_GRP_DNSSEC),
	GRP_NAME_ITEM(LOG_GRP_HINT),
	GRP_NAME_ITEM(LOG_GRP_PLAN),
	GRP_NAME_ITEM(LOG_GRP_ITERATOR),
	GRP_NAME_ITEM(LOG_GRP_VALIDATOR),
	GRP_NAME_ITEM(LOG_GRP_RESOLVER),
	GRP_NAME_ITEM(LOG_GRP_SELECTION),
	GRP_NAME_ITEM(LOG_GRP_ZCUT),
	GRP_NAME_ITEM(LOG_GRP_COOKIES),
	GRP_NAME_ITEM(LOG_GRP_STATISTICS),
	GRP_NAME_ITEM(LOG_GRP_REBIND),
	GRP_NAME_ITEM(LOG_GRP_WORKER),
	GRP_NAME_ITEM(LOG_GRP_POLICY),
	GRP_NAME_ITEM(LOG_GRP_TASENTINEL),
	GRP_NAME_ITEM(LOG_GRP_TASIGNALING),
	GRP_NAME_ITEM(LOG_GRP_TAUPDATE),
	GRP_NAME_ITEM(LOG_GRP_DAF),
	GRP_NAME_ITEM(LOG_GRP_DETECTTIMEJUMP),
	GRP_NAME_ITEM(LOG_GRP_DETECTTIMESKEW),
	GRP_NAME_ITEM(LOG_GRP_GRAPHITE),
	GRP_NAME_ITEM(LOG_GRP_PREFILL),
	GRP_NAME_ITEM(LOG_GRP_PRIMING),
	GRP_NAME_ITEM(LOG_GRP_SRVSTALE),
	GRP_NAME_ITEM(LOG_GRP_WATCHDOG),
	GRP_NAME_ITEM(LOG_GRP_NSID),
	GRP_NAME_ITEM(LOG_GRP_DNSTAP),
	GRP_NAME_ITEM(LOG_GRP_TESTS),
	GRP_NAME_ITEM(LOG_GRP_DOTAUTH),
	GRP_NAME_ITEM(LOG_GRP_HTTP),
	GRP_NAME_ITEM(LOG_GRP_CONTROL),
	GRP_NAME_ITEM(LOG_GRP_MODULE),
	GRP_NAME_ITEM(LOG_GRP_DEVEL),
	{ NULL,		-1 },
};

#ifndef SYSLOG_NAMES
syslog_code_t prioritynames[] = {
	{ "alert",	LOG_ALERT },
	{ "crit",	LOG_CRIT },
	{ "debug",	LOG_DEBUG },
	{ "emerg",	LOG_EMERG },
	{ "err",	LOG_ERR },
	{ "info",	LOG_INFO },
	{ "notice",	LOG_NOTICE },
	{ "warning",	LOG_WARNING },
	{ NULL,		-1 },
};
#endif

bool kr_log_group_is_set(enum kr_log_group group)
{
	return kr_log_groups & (1ULL << group);
}

void kr_log_fmt(enum kr_log_group group, log_level_t level, const char *file,
		const char *line, const char *func, const char *fmt, ...)
{
	va_list args;

	if (!(KR_LOG_LEVEL_IS(level) || kr_log_group_is_set(group)))
		return;

	if (kr_log_target == LOG_TARGET_SYSLOG) {
		if (kr_log_group_is_set(group))
			setlogmask(LOG_UPTO(LOG_DEBUG));

		va_start(args, fmt);
#if ENABLE_LIBSYSTEMD
		if (use_journal) {
			sd_journal_printv_with_location(level, file, line, func, fmt, args);
		} else {
			vsyslog(level, fmt, args);
		}
#else
		vsyslog(level, fmt, args);
#endif
		va_end(args);

		if (kr_log_group_is_set(group))
			setlogmask(LOG_UPTO(kr_log_level));
	} else {

		FILE *stream;
		switch(kr_log_target) {
		case LOG_TARGET_STDOUT: stream = stdout; break;
		case LOG_TARGET_STDERR: stream = stderr; break;
		default: stream = stdout; break;
		}

		va_start(args, fmt);
		vfprintf(stream, fmt, args);
		va_end(args);
	}
}

static void kres_gnutls_log(int level, const char *message)
{
	kr_log_debug(GNUTLS, "(%d) %s", level, message);
}

char *kr_log_level2name(log_level_t level)
{
	for (int i = 0; prioritynames[i].c_name; ++i)
	{
		if (prioritynames[i].c_val == level)
			return prioritynames[i].c_name;
	}

	return NULL;
}

log_level_t kr_log_name2level(const char *name)
{
	if (kr_fails_assert(name))
		return -1;

	for (int i = 0; prioritynames[i].c_name; ++i)
	{
		if (strcmp(prioritynames[i].c_name, name) == 0)
			return prioritynames[i].c_val;
	}

	return -1;
}

const char *kr_log_grp2name(enum kr_log_group group)
{
	for (int i = 0; log_group_names[i].g_val != -1; ++i)
	{
		if (log_group_names[i].g_val == group)
			return log_group_names[i].g_name;
	}

	return NULL;
}

enum kr_log_group kr_log_name2grp(const char *name)
{
	if (kr_fails_assert(name))
		return 0;

	for (int i = 0; log_group_names[i].g_name; ++i)
	{
		if (strcmp(log_group_names[i].g_name, name) == 0)
			return log_group_names[i].g_val;
	}

	return 0;
}



static void kr_gnutls_log_level_set()
{
	/* gnutls logs messages related to our TLS and also libdnssec,
	 * and the logging is set up in a global way only */
	if (KR_LOG_LEVEL_IS(LOG_DEBUG) || kr_log_group_is_set(LOG_GRP_GNUTLS)) {
		gnutls_global_set_log_function(kres_gnutls_log);
		gnutls_global_set_log_level(LOG_GNUTLS_LEVEL);
	} else {
		gnutls_global_set_log_level(0);
	}
}

int kr_log_level_set(log_level_t level)
{
	if (level < LOG_CRIT || level > LOG_DEBUG) {
		kr_log_warning(SYSTEM, "invalid log level\n");
		return kr_log_level;
	}

	kr_log_level = level;
	setlogmask(LOG_UPTO(kr_log_level));

	kr_gnutls_log_level_set();

	return kr_log_level;

}

log_level_t kr_log_level_get(void)
{
	return kr_log_level;
}

void kr_log_add_group(enum kr_log_group group)
{
	kr_log_groups |= (1ULL << group);
	if (group == LOG_GRP_GNUTLS)
		kr_gnutls_log_level_set();
}

void kr_log_del_group(enum kr_log_group group)
{
	kr_log_groups &= (~(1ULL << group));
	if (group == LOG_GRP_GNUTLS)
		kr_gnutls_log_level_set();
}

void kr_log_init(log_level_t level, log_target_t target)
{
	kr_log_target = target;
	kr_log_groups = 0;

#if ENABLE_LIBSYSTEMD
	use_journal = sd_booted();
#endif
	openlog(NULL, LOG_PID, LOG_DAEMON);
	kr_log_level_set(level);
}

static inline bool req_has_trace_log(const struct kr_request *req)
{
	return unlikely(req && req->trace_log);
}

static void kr_vlog_req(
	const struct kr_request * const req, uint32_t qry_uid,
	const unsigned int indent, enum kr_log_group group, const char *tag, const char *fmt,
	va_list args)
{
	struct mempool *mp = mp_new(512);

	const uint32_t req_uid = req ? req->uid : 0;
	char *msg = mp_printf(mp, "[%05u.%02u] %*s",
				req_uid, qry_uid, indent, "");

	msg = mp_vprintf_append(mp, msg, fmt, args);

	if (req_has_trace_log(req))
		req->trace_log(req, msg);

	kr_log_fmt(group, LOG_DEBUG, SD_JOURNAL_METADATA, "[%-6s]%s", tag, msg);

	mp_delete(mp);
}

void kr_log_req1(const struct kr_request * const req, uint32_t qry_uid,
		const unsigned int indent, enum kr_log_group group, const char *tag, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	kr_vlog_req(req, qry_uid, indent, group, tag, fmt, args);
	va_end(args);
}

bool kr_log_is_debug_fun(enum kr_log_group group, const struct kr_request *req)
{
	return req_has_trace_log(req)
		|| kr_log_group_is_set(group)
		|| KR_LOG_LEVEL_IS(LOG_DEBUG);
}

void kr_log_q1(const struct kr_query * const qry,
		enum kr_log_group group, const char *tag, const char *fmt, ...)
{
	// Optimize: this is probably quite a hot path.
	const struct kr_request *req = likely(qry != NULL) ? qry->request : NULL;
	if (likely(!kr_log_is_debug_fun(group, req)))
		return;

	unsigned ind = 0;
	for (const struct kr_query *q = qry; q; q = q->parent)
		ind += 2;
	const uint32_t qry_uid = qry ? qry->uid : 0;

	va_list args;
	va_start(args, fmt);
	kr_vlog_req(req, qry_uid, ind, group, tag, fmt, args);
	va_end(args);
}

