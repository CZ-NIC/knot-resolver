/*  Copyright (C) 2014-2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdarg.h>
#include <syslog.h>
#include "lib/defines.h"


#define LOG_DEFAULT_LEVEL	LOG_WARNING

/* Targets */

typedef enum {
	LOG_TARGET_SYSLOG = 0,
	LOG_TARGET_STDERR = 1,
	LOG_TARGET_STDOUT = 2,
} log_target_t;

/* Groups */

typedef uint32_t log_groups_t;
typedef struct {
	char		*g_name;
	log_groups_t	g_val;
} log_group_names_t;

#define LOG_GRP_SYSTEM		(1 << 1)
#define LOG_GRP_CACHE		(1 << 2)
#define LOG_GRP_IO		(1 << 3)
#define LOG_GRP_NETWORK		(1 << 4)
#define LOG_GRP_TA		(1 << 5)
#define LOG_GRP_TLS		(1 << 6)
#define LOG_GRP_GNUTLS		(1 << 7)
#define LOG_GRP_TLSCLIENT	(1 << 8)
#define LOG_GRP_XDP		(1 << 9)
#define LOG_GRP_ZIMPORT		(1 << 10)
#define LOG_GRP_ZSCANNER	(1 << 11)
#define LOG_GRP_DOH		(1 << 12)
#define LOG_GRP_DNSSEC		(1 << 13)
#define LOG_GRP_HINT		(1 << 14)

#define LOG_GRP_SYSTEM_TAG "[system] "
#define LOG_GRP_CACHE_TAG "[cache] "
#define LOG_GRP_IO_TAG "[io] "
#define LOG_GRP_NETWORK_TAG "[network] "
#define LOG_GRP_TA_TAG "[ta] "
#define LOG_GRP_TLS_TAG "[tls] "
#define LOG_GRP_GNUTLS_TAG "[gnutls] "
#define LOG_GRP_TLSCLIENT_TAG "[tlsclient] "
#define LOG_GRP_XDP_TAG "[xdp] "
#define LOG_GRP_ZIMPORT_TAG "[zimport] "
#define LOG_GRP_ZSCANNER_TAG "[zscanner] "
#define LOG_GRP_DOH_TAG "[doh] "
#define LOG_GRP_DNSSEC_TAG "[dnssec] "
#define LOG_GRP_HINT_TAG "[hint] "

KR_EXPORT
extern log_groups_t kr_log_groups;
KR_EXPORT
int group_is_set(log_groups_t group);
KR_EXPORT
void kr_log_add_group(log_groups_t mask);
KR_EXPORT
void kr_log_del_group(log_groups_t mask);
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
	kr_log_fmt(grp, LOG_DEBUG, SD_JOURNAL_METADATA, grp ## _TAG fmt, ## __VA_ARGS__)
#define kr_log_info(grp, fmt, ...) \
	kr_log_fmt(grp, LOG_INFO, SD_JOURNAL_METADATA, grp ## _TAG fmt, ## __VA_ARGS__)
#define kr_log_notice(grp, fmt, ...) \
	kr_log_fmt(grp, LOG_NOTICE, SD_JOURNAL_METADATA, grp ## _TAG fmt, ## __VA_ARGS__)
#define kr_log_warning(grp, fmt, ...) \
	kr_log_fmt(grp, LOG_WARNING, SD_JOURNAL_METADATA, grp ## _TAG fmt, ## __VA_ARGS__)
#define kr_log_error(grp, fmt, ...) \
	kr_log_fmt(grp, LOG_ERR, SD_JOURNAL_METADATA, grp ## _TAG fmt, ## __VA_ARGS__)
#define kr_log_fatal(grp, fmt, ...) \
	kr_log_fmt(grp, LOG_CRIT, SD_JOURNAL_METADATA, grp ## _TAG fmt, ## __VA_ARGS__)

#define kr_log_deprecate(grp, fmt, ...) \
	kr_log_fmt(grp, LOG_WARNING, SD_JOURNAL_METADATA, "deprecation WARNING: " grp ## _TAG fmt, ## __VA_ARGS__)

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
