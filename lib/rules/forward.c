/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/rules/api.h"
#include "lib/rules/impl.h"

#include "lib/layer/iterate.h"
#include "lib/resolve.h"

static void setup_fwd_flags(struct kr_query *qry)
{
	if (qry->flags.FORWARD || qry->flags.STUB)
		return; // someone else has set it unexpectedly - policy?
	// TODO: disallow or restrict somehow?
	//if (kr_fails_assert(!qry->flags.FORWARD && !qry->flags.STUB))

	if (!qry->data_src.initialized) {
		// no VAL_ZLAT_FORWARD -> standard iteration
		qry->data_src.initialized = true;
		qry->data_src.rule_depth = 0;
		qry->data_src.flags.is_auth = true;
		return;
	}

	const kr_rule_fwd_flags_t zf = qry->data_src.flags;

	qry->flags.TCP |= zf.is_tcp;

	if (!zf.is_auth && !zf.is_nods) { // mostly like policy.(TLS_)FORWARD
		qry->flags.FORWARD = true;
		qry->flags.NO_MINIMIZE = true;
		   // this ^^ probably won't be needed after moving iterator's produce
		return;
	}

	if (!zf.is_auth && zf.is_nods) { // mostly like policy.STUB
		qry->flags.STUB = true;
		return;
	}

	if (zf.is_auth) {
		return;
	}

	kr_require(false);
}

// Wrapper around rule_local_data_answer() to finish forwarding-related flags.
int kr_rule_local_data_answer(struct kr_query *qry, knot_pkt_t *pkt)
{
	int ret = rule_local_data_answer(qry, pkt); // the main body of work
	if (ret < 0)
		kr_log_debug(RULES, "policy rules failed: %s\n", kr_strerror(ret));
	// deal with setting up .FORWARD and .STUB, so that cache lookup knows
	setup_fwd_flags(qry);
	// unfortunately, changing flags can change this from iterator
	if (ret == 0 && (qry->flags.FORWARD || qry->flags.STUB))
		ret = kr_make_query(qry, pkt);

	//kr_assert(qry->data_src.initialized); // TODO: broken by old policy.FORWARD, etc.
	return ret;
}

int kr_rule_data_src_check(struct kr_query *qry, struct knot_pkt *pkt)
{
	if (qry->data_src.all_set)
		return kr_ok(); // everything should be in order from before

	if (/*kr_fails_assert!*/(!qry->data_src.initialized)) { // FIXME ci val_ad_qtype_ds
		// fall back to standard iteration
		goto fallback;
	}

	if (!qry->data_src.flags.is_auth && qry->data_src.targets_ptr.data) {
		struct kr_request *req = qry->request;
		// In old policy this used to be done by kr_forward_add_target()
		// For TLS see policy.TLS_FORWARD() and net_tls_client()
		// The mapping from address+port to parameters are in tls_client_param_t
		kr_sockaddr_array_t *targets = &req->selection_context.forwarding_targets;
		const size_t t_bytes = qry->data_src.targets_ptr.len;
		kr_assert(t_bytes > 0 && t_bytes % sizeof(targets->at[0]) == 0);
		targets->cap = targets->len = t_bytes / sizeof(targets->at[0]);
		targets->at = mm_alloc(&req->pool, t_bytes);
		memcpy(targets->at, qry->data_src.targets_ptr.data, t_bytes);
		qry->data_src.all_set = true;

		kr_server_selection_init(qry); // this assumes `forwarding_targets` was filled
		return kr_ok();
	}

	if (qry->data_src.flags.is_auth) {
		if (!qry->data_src.targets_ptr.data)
			goto fallback; // default iteration falls here
		const knot_dname_t *apex = qry->sname;
		for (int labels = knot_dname_labels(apex, NULL);
			labels > qry->data_src.rule_depth;
			--labels, apex = knot_wire_next_label(apex, NULL));
		kr_zonecut_set(&qry->zone_cut, apex);
		knot_db_val_t targets = qry->data_src.targets_ptr;
		kr_assert(targets.len > 0);
		while (targets.len > 0) {
			union kr_sockaddr target;
			if (deserialize_fails_assert(&targets, &target))
				goto fallback;
			int ret = kr_zonecut_add(&qry->zone_cut,
				(const knot_dname_t *)"\2ns\7invalid",
				kr_inaddr(&target.ip), kr_inaddr_len(&target.ip));
			if (kr_fails_assert(ret == 0))
				goto fallback;
		}
		kr_assert(targets.len == 0);
		qry->flags.AWAIT_CUT = false;
		qry->data_src.all_set = true;
		kr_server_selection_init(qry);
		// unfortunately, zone cut depth might've changed
		return kr_make_query(qry, pkt);
	}

	kr_assert(false);
fallback:
	qry->data_src.initialized = true;
	qry->data_src.rule_depth = 0;
	qry->data_src.all_set = true;
	kr_server_selection_init(qry);
	return kr_ok();
}

int kr_rule_forward(const knot_dname_t *apex, kr_rule_fwd_flags_t flags,
			const struct sockaddr * targets[])
{
	ENSURE_the_rules;
	const kr_rule_tags_t tags = KR_RULE_TAGS_ALL;
	const val_zla_type_t ztype = VAL_ZLAT_FORWARD;

	int count = 0;
	if (targets) {
		while (targets[count])
			++count;
	}

	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key = zla_key(apex, key_data);

	const size_t targets_bytes = count * sizeof(union kr_sockaddr);
	knot_db_val_t val = {
		.data = NULL,
		.len = sizeof(tags) + sizeof(ztype) + sizeof(flags) + targets_bytes,
	};
	int ret = ruledb_op(write, &key, &val, 1);
	if (kr_fails_assert(ret >= 0))
		return kr_error(ret);
	memcpy(val.data, &tags, sizeof(tags));
	val.data += sizeof(tags);
	memcpy(val.data, &ztype, sizeof(ztype));
	val.data += sizeof(ztype);
	memcpy(val.data, &flags, sizeof(flags));
	val.data += sizeof(flags);
	for (int i = 0; i < count; ++i) {
		// targets[i] may be shorter than union kr_sockaddr, so we zero-pad
		// LATER: for is_auth we really drop anything but address (e.g. port!=53)
		union kr_sockaddr a = { 0 };
		memcpy(&a, targets[i], kr_sockaddr_len(targets[i]));
		memcpy(val.data, &a, sizeof(a));
		val.data += sizeof(a);
	}
	return kr_ok();
}
