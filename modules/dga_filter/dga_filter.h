/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
*  SPDX-License-Identifier: GPL-3.0-or-later
*/

/**
 * @file dga_filter.h
 * @brief blocks DGA domains using ML
 *
 */

#define ORT_CHECK(expr, label)  \
	do {                        \
		status = (expr);        \
		if (status) goto label; \
	} while (0)

#define DGA_FAIL_PROB -1

#define DGA_BYPASS_MIN_SLD_LEN 4

typedef struct {
	size_t expected_inputs;
	size_t expected_outputs;

	int64_t expected_output_probs_dims[2];

	size_t output_probs_index;
	size_t output_probs_dga_index;
} ModelDefinition;

struct model_context{
	const OrtApi*      api;
	OrtEnv*            env;
	OrtSessionOptions* session_options;
	OrtSession*        session;
	OrtAllocator*      allocator;
	char*              input_name;
	char**             output_names;
	size_t             num_inputs;
	size_t             num_outputs;
};
