/*  Copyright (C) 2014-2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "kresconfig.h"

#include <stdio.h>
#include <gnutls/gnutls.h>
#include "lib/log.h"

#if ENABLE_LIBSYSTEMD
#include <stdlib.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>

int use_journal = 0;
#endif

log_level_t kr_log_level = LOG_CRIT;
log_target_t kr_log_target = LOG_TARGET_STDOUT;


void kr_log_fmt(log_level_t level, const char *fmt, ...)
{
	va_list args;

	if (kr_log_target == LOG_TARGET_SYSLOG) {
		va_start(args, fmt);
#if ENABLE_LIBSYSTEMD
		if (use_journal) {
			char *code_line = NULL;
			if (asprintf(&code_line, "%d", __LINE__) == -1) {
				sd_journal_printv(level, fmt, args);
			} else {
				sd_journal_printv_with_location(level,
						__FILE__, code_line, __func__,
						fmt, args);
				free(code_line);
			}
		} else
#endif
		{
			vsyslog(level, fmt, args);
		}
		va_end(args);
	} else {
		if (!KR_LOG_LEVEL_IS(level))
			return;

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
	kr_log_debug("[gnutls] (%d) %s", level, message);
}

int kr_log_level_set(log_level_t level)
{
	if (level < LOG_CRIT || level > LOG_DEBUG)
		return kr_log_level;

	kr_log_level = level;
	setlogmask(LOG_UPTO(kr_log_level));

	/* gnutls logs messages related to our TLS and also libdnssec,
	 * and the logging is set up in a global way only */
	if (KR_LOG_LEVEL_IS(LOG_DEBUG)) {
		gnutls_global_set_log_function(kres_gnutls_log);
	}
	gnutls_global_set_log_level(level);

	return kr_log_level;

}

log_level_t kr_log_level_get(void)
{
	return kr_log_level;
}

void kr_log_init(log_level_t level, log_target_t target)
{
	kr_log_level = level;
	kr_log_target = target;

#if ENABLE_LIBSYSTEMD
	use_journal = sd_booted();
#endif
	openlog(NULL, LOG_PID, LOG_DAEMON);
	setlogmask(LOG_UPTO(kr_log_level));
}
