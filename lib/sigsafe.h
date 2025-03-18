/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once
#include "lib/defines.h"
#include "lib/log.h"

/// Async-signal-safe snprintf-like formatting function, it supports:
///   * %% prints %;
///   * %s takes (char *), supports width and '-'-flag;
///   * %i takes int,      supports width and '0'-flag;
///   * %u takes unsigned, supports width and '0'-flag;
///   * %x takes unsigned, supports width and '0'-flag;
///   * %f takes double,   supports width and precision (defaults to .3);
///   * %r takes (struct sockaddr *).
KR_EXPORT
int sigsafe_format(char *str, size_t size, const char *fmt, ...);
#define sigsafe_format(...) sigsafe_format(__VA_ARGS__) // NOLINT, all calls are async-signal-safe

/// Log according to the set target to stdout or stderr;
/// for syslog, print to stderr prefixed with <loglevel>, as syslog() is not async-signal-safe.
#define sigsafe_log(level, grp, max_size, fmt, ...) { \
	if ((KR_LOG_LEVEL_IS(level) || KR_LOG_GROUP_IS_SET(grp))) { \
		char msg[max_size + 12]; \
		int len = 0; \
		if (kr_log_target == LOG_TARGET_SYSLOG) \
			len += sigsafe_format(msg, sizeof(msg), "<%u>", level); \
		len += sigsafe_format(msg + len, sizeof(msg) - len, "[%-6s] " fmt, LOG_GRP_ ## grp ## _TAG, ## __VA_ARGS__); \
		write(kr_log_target == LOG_TARGET_STDOUT ? 1 : 2, msg, len); \
	}}
