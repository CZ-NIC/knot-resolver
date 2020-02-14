/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/module.h"

/*
 * Mock module implementation.
 */

int mock_cmodule_init(struct kr_module *module)
{
	return kr_ok();
}

int mock_cmodule_deinit(struct kr_module *module)
{
	return kr_ok();
}

KR_MODULE_EXPORT(mock_cmodule)
