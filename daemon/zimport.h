/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdbool.h>
#include <libknot/rrset.h>
#include "lib/defines.h"

/**
 * Completion callback
 *
 * @param state  0 for OK completion, < 0 for errors (unfinished)
 * @param param  pointer to user data
 */
typedef void (*zi_callback)(int state, void *param);
typedef struct {
	/* Parser, see zs_init() */
	const char *zone_file;
	const char *origin;
	uint32_t ttl;

	/// Source of time: current real time, or file modification time.
	enum { ZI_STAMP_NOW = 0, ZI_STAMP_MTIM } time_src;

	/* Validator */
	bool downgrade; /// true -> disable validation
	bool zonemd; /// true -> verify zonemd
	const knot_rrset_t *ds; /// NULL -> use trust anchors

	zi_callback cb;
	void *cb_param;
} zi_config_t;

/** Import zone from a file.
 *
 * Error can be directly returned in the first phase (parsing + ZONEMD);
 * otherwise it will be kr_ok() and config->cb gets (optionally) called finally.
 *
 * Large zone would pause other processing for longer time;
 * that's generally not advisable.
 *
 * Zone origin is detected from SOA, but it's certainly not perfect now.
 */
KR_EXPORT
int zi_zone_import(const zi_config_t config);

