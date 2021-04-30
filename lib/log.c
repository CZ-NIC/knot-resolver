/*  Copyright (C) 2014-2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include "lib/log.h"

log_level_t kr_log_level = LOG_CRIT;

void kr_log_fmt(log_level_t level, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	if (level <= kr_log_level)
		vfprintf(stdout, fmt, args);
	va_end(args);
}

void kr_log_init(log_level_t level)
{
	kr_log_level = level;
}

