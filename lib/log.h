/*  Copyright (C) 2014-2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdarg.h>
#include <syslog.h>
#include "lib/defines.h"

typedef int log_level_t;

typedef enum {
	LOG_TARGET_SYSLOG = 0,
	LOG_TARGET_STDERR = 1,
	LOG_TARGET_STDOUT = 2,
} log_target_t;

KR_EXPORT
extern log_level_t kr_log_level;
KR_EXPORT
extern log_target_t kr_log_target;
KR_EXPORT KR_PRINTF(2)
void kr_log_fmt(log_level_t level, const char *fmt, ...);
KR_EXPORT
int kr_log_level_set(log_level_t level);
KR_EXPORT
log_level_t kr_log_level_get(void);
KR_EXPORT
void kr_log_init(log_level_t level, log_target_t target);

#define kr_log_debug(fmt, ...) kr_log_fmt(LOG_DEBUG, fmt, ## __VA_ARGS__)
#define kr_log_info(fmt, ...) kr_log_fmt(LOG_INFO, fmt, ## __VA_ARGS__)
#define kr_log_notice(fmt, ...) kr_log_fmt(LOG_NOTICE, fmt, ## __VA_ARGS__)
#define kr_log_warning(fmt, ...) kr_log_fmt(LOG_WARNING, fmt, ## __VA_ARGS__)
#define kr_log_error(fmt, ...) kr_log_fmt(LOG_ERR, fmt, ## __VA_ARGS__)
#define kr_log_fatal(fmt, ...) kr_log_fmt(LOG_CRIT, fmt, ## __VA_ARGS__)

#define kr_log_deprecate(fmt, ...) kr_log_fmt(LOG_WARNING, "deprecation WARNING: " fmt, ## __VA_ARGS__)

#define KR_LOG_LEVEL_IS(exp) ((kr_log_level >= exp) ? true : false)
