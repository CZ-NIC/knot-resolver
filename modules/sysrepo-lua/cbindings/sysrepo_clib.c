/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "sysrepo_clib.h"

#include <stdio.h>
#include <stdlib.h>
#include <sysrepo.h>
#include <uv.h>

#include "lib/module.h"
#include "common/sysrepo_conf.h"

EXPORT_STRDEF_TO_LUA_IMPL(YM_COMMON)
EXPORT_STRDEF_TO_LUA_IMPL(XPATH_BASE)

struct el_subscription_ctx {
	sr_conn_ctx_t *connection;
	sr_session_ctx_t *session;
	sr_subscription_ctx_t *subscription;
	el_subsription_cb callback;
	uv_poll_t uv_handle;
};

/** Callback to Lua used for applying configuration  */
static set_leaf_conf_t apply_conf_f = NULL;
static el_subscription_ctx_t *el_subscription_ctx = NULL;

/**
 * Change callback getting called by sysrepo. Iterates over changed options and passes
 * them over to Lua.
 */
static int sysrepo_conf_change_callback(sr_session_ctx_t *session,
					const char *module_name,
					const char *xpath, sr_event_t event,
					uint32_t request_id, void *private_data)
{
	if (event == SR_EV_CHANGE) {
		// gets called before the actual change of configuration is commited. If we
		// return an error, the change is aborted can be used for configuration
		// verification. Must have no sideeffects.

		// TODO
	} else if (event == SR_EV_ABORT) {
		// Gets called when the transaction gets aborted. Because we have no
		// sideeffects during verification, we don't care and and there is nothing
		// to do
	} else if (event == SR_EV_DONE) {
		// after configuration change commit. We should apply the configuration.
		// Will not hurt if we verify the changes again, but we have no way of
		// declining the change now

		int sr_err = SR_ERR_OK;
		sr_change_iter_t *it = NULL;
		sr_change_oper_t oper;
		sr_val_t *old_value = NULL;
		sr_val_t *new_value = NULL;

		// get all changes
		sr_err = sr_get_changes_iter(session, XPATH_BASE "//.", &it);
		if (sr_err != SR_ERR_OK)
			goto cleanup;

		while ((sr_get_change_next(session, it, &oper, &old_value,
					   &new_value)) == SR_ERR_OK) {
			apply_conf_f(new_value);
		}
	cleanup:
		if (sr_err != SR_ERR_OK && sr_err != SR_ERR_NOT_FOUND)
			kr_log_error("Sysrepo module error: %s\n",
				     sr_strerror(sr_err));
		sr_free_val(old_value);
		sr_free_val(new_value);
		sr_free_change_iter(it);
	}
	return SR_ERR_OK;
}

void el_subscr_finish_closing(uv_handle_t *handle)
{
	el_subscription_ctx_t *el_subscr = handle->data;
	assert(el_subscr != NULL);
	free(el_subscr);
}

/** Free a event loop subscription. */
void el_subscription_free(el_subscription_ctx_t *el_subscr)
{
	sr_disconnect(el_subscr->connection);
	uv_close((uv_handle_t *)&el_subscr->uv_handle,
		 el_subscr_finish_closing);
}

static void el_subscr_cb_tramp(uv_poll_t *handle, int status, int events)
{
	el_subscription_ctx_t *el_subscr = handle->data;
	el_subscr->callback(el_subscr, status);
}

/** Start a new event loop subscription.  */
static el_subscription_ctx_t *
el_subscription_new(sr_subscription_ctx_t *sr_subscr,
		    el_subsription_cb el_callback)
{
	int fd;
	int err = sr_get_event_pipe(sr_subscr, &fd);
	if (err != SR_ERR_OK)
		return NULL;
	el_subscription_ctx_t *el_subscr = malloc(sizeof(*el_subscr));
	if (el_subscr == NULL)
		return NULL;
	err = uv_poll_init(uv_default_loop(), &el_subscr->uv_handle, fd);
	if (err != 0) {
		free(el_subscr);
		return NULL;
	}
	el_subscr->subscription = sr_subscr;
	el_subscr->callback = el_callback;
	el_subscr->uv_handle.data = el_subscr;
	err = uv_poll_start(&el_subscr->uv_handle, UV_READABLE,
			    el_subscr_cb_tramp);
	if (err != 0) {
		el_subscription_free(el_subscr);
		return NULL;
	}
	return el_subscr;
}

static void el_subscr_cb(el_subscription_ctx_t *el_subscr, int status)
{
	if (status) {
		/* some error */
		return;
	}
	/* normal state */
	sr_process_events(el_subscr->subscription, el_subscr->session, NULL);
}

int sysrepo_init(set_leaf_conf_t apply_conf_callback)
{
	// store callback to Lua
	apply_conf_f = apply_conf_callback;

	int sr_err = SR_ERR_OK;
	sr_conn_ctx_t *sr_connection = NULL;
	sr_session_ctx_t *sr_session = NULL;
	sr_subscription_ctx_t *sr_subscription = NULL;

	sr_err = sr_connect(0, &sr_connection);
	if (sr_err != SR_ERR_OK)
		goto cleanup;

	sr_err = sr_connection_recover(sr_connection);
	if (sr_err != SR_ERR_OK)
		goto cleanup;

	sr_err = sr_session_start(sr_connection, SR_DS_RUNNING, &sr_session);
	if (sr_err != SR_ERR_OK)
		goto cleanup;

	/* register sysrepo subscriptions and callbacks
		SR_SUBSCR_NO_THREAD - don't create a thread for handling them
		SR_SUBSCR_ENABLED - send us current configuration in a callback just after subscribing
	 */
	sr_err = sr_module_change_subscribe(
		sr_session, YM_COMMON, XPATH_BASE, sysrepo_conf_change_callback,
		NULL, 0, SR_SUBSCR_NO_THREAD | SR_SUBSCR_ENABLED,
		&sr_subscription);
	if (sr_err != SR_ERR_OK)
		goto cleanup;

	/* add subscriptions to kres event loop */
	el_subscription_ctx =
		el_subscription_new(sr_subscription, el_subscr_cb);
	el_subscription_ctx->connection = sr_connection;
	el_subscription_ctx->session = sr_session;

	return kr_ok();

cleanup:
	sr_disconnect(sr_connection);
	kr_log_error("Error (%s)\n", sr_strerror(sr_err));
	return kr_error(sr_err);
}

int sysrepo_deinit()
{
	el_subscription_free(el_subscription_ctx);
	// remove reference to Lua callback so that it can be free'd safely
	apply_conf_f = NULL;
	return kr_ok();
}
