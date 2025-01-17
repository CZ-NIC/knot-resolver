/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file filter.c
 * @brief blocks queries that contain other than writelisted characters
 *
 * whitelist is for 'extra' characters, ascii characters listed in RFC 1035
 * shall be added by automatically. Characters can be specified by
 * code point \\N{U+00DF} = ß, (\N hast to escaped, while it is
 * a valid pcre2 syntax it is a not valid utf code in C)
 */

#include <idn2.h>
#include <stdlib.h>
#include <string.h>
#include <lib/log.h>
#include "lib/layer.h"
#include "lib/resolve.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#define CHWHITELIST "ěščřžýáíéóůúďťľĺŕäôäąćęłńśźż\\N{U+00DF}\\N{U+00FC}\\N{U+00F6}"
#define HEAD "^[a-z0-9"
#define TAIL "-]+$"

#define ASCIILIMIT 0x80
#define MAXLABELSIZE (63 * 4) + 1

struct filter_data {
	uint32_t option_bits;
	PCRE2_SIZE erroroffset;
	PCRE2_SIZE subject_length;
	pcre2_match_data *match_data;
	pcre2_code *re;
};

static int create_mismatch_answer(kr_layer_t *ctx)
{
	struct kr_request *req = ctx->req;
	knot_pkt_t *answer = kr_request_ensure_answer(req);
	if (!answer)
		return ctx->state;

	knot_wire_set_rcode(answer->wire, KNOT_RCODE_NXDOMAIN);
	knot_wire_clear_ad(answer->wire);

	kr_request_set_extended_error(req, KNOT_EDNS_EDE_BLOCKED,
				      "RIQZ: suspicious query");
	ctx->state = KR_STATE_DONE;
	return ctx->state;
}

int is_ascii(char *str)
{
	for (; *str; str++)
		if (*str & ASCIILIMIT)
			return -1;
	return 0;
}

char *prep_regstr(const char *whitelist)
{
	size_t total_len = strlen(HEAD) + strlen(whitelist) + strlen(TAIL);
	char *regstr = malloc(total_len + 1);
	if (!regstr)
		return NULL;

	if (snprintf(regstr, total_len + 1, "%s%s%s",
		     HEAD, whitelist, TAIL) != total_len)
		return NULL;

	return regstr;
}

void regex_deinit(struct filter_data *re)
{
	if (re) {
		if (re->match_data)
			pcre2_match_data_free(re->match_data);
		if(re->re)
			pcre2_code_free(re->re);
		free(re);
	}
}

int regex_init(struct filter_data *data)
{
	char *regstr = NULL;
	int errornumber = 0;

	regstr = prep_regstr(CHWHITELIST);
	if (!regstr)
		return kr_error(ENOMEM);

	PCRE2_SPTR pattern = (PCRE2_SPTR)regstr;
	data->option_bits = PCRE2_UTF | PCRE2_UCP | PCRE2_CASELESS;
	data->re = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED, data->option_bits,
				 &errornumber, &data->erroroffset, NULL);
	free(regstr);

	if (data->re == NULL) {
		PCRE2_UCHAR buffer[256];
		pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
		// kr_log_warning(FILTER, "pcre2 regex compilation failed: %s\n", buffer);
		return kr_error(errornumber == PCRE2_ERROR_NOMEMORY ? ENOMEM : EINVAL);
	}

	data->match_data = pcre2_match_data_create_from_pattern(data->re, NULL);
	if (!data->match_data) {
		// kr_log_warning(FILTER, "Failed to create match data from pattern (likely due to ENOMEM)\n");
		pcre2_code_free(data->re);
		return kr_error(ENOMEM);
	}

	return kr_ok();
}

static int matches(kr_layer_t *ctx)
{
	int ret = -1;
	char *output = NULL;
	struct kr_module *module = ctx->api->data;
	struct filter_data *data = module->data;
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	char label[MAXLABELSIZE] = { 0 };

	if (!qry || !qry->sname || qry->flags.CACHED)
		return ctx->state;

	int ptr = 0;
	while (qry->sname[ptr] != '\0') {
		uint8_t length = qry->sname[ptr++];

		strncat(label, (char *)(qry->sname + ptr), length);
		ptr += length;

		if (is_ascii(label) == -1)
			return create_mismatch_answer(ctx);

		ret = idn2_to_unicode_8z8z(label, &output, 0);
		if (ret != IDN2_OK)
			return create_mismatch_answer(ctx);

		PCRE2_SPTR subject = (PCRE2_SPTR)output;
		PCRE2_SIZE subject_length = (PCRE2_SIZE)strlen((char *)subject);

		ret = pcre2_match(data->re, subject, subject_length,
				  0, 0, data->match_data, NULL);

		idn2_free(output);
		output = NULL;

		if (ret < 0)
			return create_mismatch_answer(ctx);

		label[0] = '\0';
	}

	return ctx->state;
}

KR_EXPORT
int filter_init(struct kr_module *module)
{
	static kr_layer_api_t layer = {
		.begin = &matches,
	};

	layer.data = module;
	module->layer = &layer;

	static const struct kr_prop props[] = {
	    { NULL, NULL, NULL }
	};
	module->props = props;

	struct filter_data *data = calloc(1, sizeof(struct filter_data));
	if (!data)
		return kr_error(ENOMEM);

	data->re = NULL;
	data->match_data = NULL;

	int ret = regex_init(data);
	if (ret != kr_ok()) {
		free(data);
		return kr_error(ret);
	}

	module->data = data;
	return kr_ok();
}

KR_EXPORT
int filter_deinit(struct kr_module *module)
{
	struct filter_data *data = module->data;
	if (data) {
		regex_deinit(data);
		module->data = NULL;
	}
	return kr_ok();
}

KR_MODULE_EXPORT(filter)
