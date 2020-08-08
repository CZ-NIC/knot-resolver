/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#define RULE_TTL_DEFAULT ((uint16_t)10800)

/** Insert all the default rules. in ./defaults.c */
int rules_defaults_insert(void);

