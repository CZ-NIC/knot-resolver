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
log_groups_t kr_log_groups = 0;

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
	GRP_NAME_ITEM(LOG_GRP_MODULE),
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

int group_is_set(log_groups_t group)
{
	return kr_log_groups & (group);
}

void kr_log_fmt(log_groups_t group, log_level_t level, const char *file,
		const char *line, const char *func, const char *fmt, ...)
{
	va_list args;

	if (!(KR_LOG_LEVEL_IS(level) || group_is_set(group)))
		return;

	if (kr_log_target == LOG_TARGET_SYSLOG) {
		if (group_is_set(group))
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

		if (group_is_set(group))
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
	for (int i = 0; prioritynames[i].c_name; ++i)
	{
		if (strcmp(prioritynames[i].c_name, name) == 0)
			return prioritynames[i].c_val;
	}

	return -1;
}

char *kr_log_grp2name(log_groups_t group)
{
	for (int i = 0; log_group_names[i].g_val != -1; ++i)
	{
		if (log_group_names[i].g_val == group)
			return log_group_names[i].g_name;
	}

	return NULL;
}

log_groups_t kr_log_name2grp(const char *name)
{
	if (!name)
		return 0;

	for (int i = 0; log_group_names[i].g_name; ++i)
	{
		if (strcmp(log_group_names[i].g_name, name) == 0)
			return log_group_names[i].g_val;
	}

	return 0;
}



int kr_log_level_set(log_level_t level)
{
	if (level < LOG_CRIT || level > LOG_DEBUG)
		return kr_log_level;

	kr_log_level = level;
	setlogmask(LOG_UPTO(kr_log_level));

	/* gnutls logs messages related to our TLS and also libdnssec,
	 * and the logging is set up in a global way only */
	if (KR_LOG_LEVEL_IS(LOG_DEBUG) || group_is_set(LOG_GRP_TLS) || group_is_set(LOG_GRP_TLSCLIENT)) {
		gnutls_global_set_log_function(kres_gnutls_log);
	}

	gnutls_global_set_log_level(kr_log_level_get() == LOG_DEBUG ? 5 : 0);

	return kr_log_level;

}

log_level_t kr_log_level_get(void)
{
	return kr_log_level;
}

void kr_log_add_group(log_groups_t mask)
{
       kr_log_groups |= mask;
}

void kr_log_del_group(log_groups_t mask)
{
       kr_log_groups &= (~mask);
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


/*
 * Cleanup callbacks.
 */
static void kr_vlog_req(
	const struct kr_request * const req, uint32_t qry_uid,
	const unsigned int indent, log_groups_t group, const char *tag, const char *fmt,
	va_list args)
{
	struct mempool *mp = mp_new(512);

	const uint32_t req_uid = req ? req->uid : 0;
	char *msg = mp_printf(mp, "[%05u.%02u] %*s",
				req_uid, qry_uid, indent, "");

	msg = mp_vprintf_append(mp, msg, fmt, args);

	if (kr_log_rtrace_enabled(req))
		req->trace_log(req, msg);
	else
		kr_log_fmt(group, LOG_DEBUG, SD_JOURNAL_METADATA, "[%s]%s", tag, msg);

	mp_delete(mp);
}

void kr_log_req1(const struct kr_request * const req, uint32_t qry_uid,
		const unsigned int indent, log_groups_t group, const char *tag, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	kr_vlog_req(req, qry_uid, indent, group, tag, fmt, args);
	va_end(args);
}

void kr_log_q1(const struct kr_query * const qry,
		log_groups_t group, const char *tag, const char *fmt, ...)
{
	unsigned ind = 0;
	for (const struct kr_query *q = qry; q; q = q->parent)
		ind += 2;
	const uint32_t qry_uid = qry ? qry->uid : 0;
	const struct kr_request *req = qry ? qry->request : NULL;

	va_list args;
	va_start(args, fmt);
	kr_vlog_req(req, qry_uid, ind, group, tag, fmt, args);
	va_end(args);
}

