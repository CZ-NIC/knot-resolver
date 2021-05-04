/*  Copyright (C) 2014-2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <gnutls/gnutls.h>
#include "lib/log.h"

log_level_t kr_log_level = LOG_CRIT;

void kr_log_fmt(log_level_t level, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	if (KR_LOG_LEVEL_IS(level))
		vfprintf(stdout, fmt, args);
	va_end(args);
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

void kr_log_init(log_level_t level)
{
	kr_log_level = level;
}

