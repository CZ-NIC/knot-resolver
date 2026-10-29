/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once
#include <stddef.h>

#define DGA_N_FEATURES 5007

/// Fill out_features (DGA_N_FEATURES floats). Returns 0 on success.
int build_features(const char *domain_name, float *out_features);

/// mmap the container and parse it. The mapping stays alive until unload.
int dga_model_load(const char *path);
void dga_model_unload(void);

/// P(dga) in [0, 1], or a negative value on error.
float dga_predict(const char *domain_name);