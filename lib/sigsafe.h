/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/defines.h"

/// Async-signal-safe snprintf-like formatting function, it supports:
///   * %% prints %;
///   * %s takes (char *), supports width and '-'-flag;
///   * %i takes int,      supports width and '0'-flag;
///   * %u takes unsigned, supports width and '0'-flag;
///   * %x takes unsigned, supports width and '0'-flag;
///   * %f takes double,   supports width and precision (defaults to .3);
///   * %r takes (struct sockaddr *).
KR_EXPORT
int sigsafe_format(char *str, size_t size, const char *fmt, ...);  // NOLINT(bugprone-signal-handler)
