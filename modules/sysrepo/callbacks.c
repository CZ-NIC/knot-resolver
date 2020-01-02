#include "callbacks.h"

#include <string.h>
#include <sysrepo.h>

#include "conversion.h"
#include "daemon/worker.h"
#include "utils/common/string_helper.h"
#include "utils/common/sysrepo_conf.h"

int conf_set_current(sr_session_ctx_t *session, const char *module_name)
{
	size_t count = 0;
	int sr_err = SR_ERR_OK;
	sr_val_t *values = NULL;

	sr_err = sr_get_items(session, XPATH_BASE "/*//.", 0, &values, &count);
	if (sr_err != SR_ERR_OK)
		goto cleanup;

	for (size_t i = 0; i < count; i++) {
		sr_val_t *value = &values[i];
		set_leaf_conf(value);
	}
cleanup:
	sr_free_values(values, count);
	return sr_err;
}

int cache_change_cb(sr_session_ctx_t *session, const char *module_name,
		    const char *xpath, sr_event_t event, uint32_t request_id,
		    void *private_data)
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

		(void)xpath;
		(void)request_id;
		(void)private_data;

		sr_err = sr_get_changes_iter(session, XPATH_BASE "/cache//.",
					     &it);
		if (sr_err != SR_ERR_OK)
			goto cleanup;

		while ((sr_get_change_next(session, it, &oper, &old_value,
					   &new_value)) == SR_ERR_OK) {
			remove_substr(new_value->xpath, XPATH_BASE "/");
			set_leaf_conf(new_value);
		}
	cleanup:
		if (sr_err != (SR_ERR_OK && SR_ERR_NOT_FOUND))
			printf("%s\n", sr_strerror(sr_err));
		sr_free_val(old_value);
		sr_free_val(new_value);
		sr_free_change_iter(it);
	}
	return SR_ERR_OK;
}

int net_change_cb(sr_session_ctx_t *session, const char *module_name,
		  const char *xpath, sr_event_t event, uint32_t request_id,
		  void *private_data)
{
	if (event == SR_EV_CHANGE) {
		/* code */
	} else if (event == SR_EV_ABORT) {
		/* code */
	} else if (event == SR_EV_DONE) {
		size_t count = 0;
		int sr_err = SR_ERR_OK;
		sr_change_iter_t *it = NULL;
		sr_change_oper_t oper;
		sr_val_t *old_value = NULL;
		sr_val_t *new_value = NULL;
		sr_val_t *values = NULL;
		const char *ch_xpath =
			"/cznic-resolver-common:dns-resolver/network/listen-interfaces//.";

		(void)xpath;
		(void)request_id;
		(void)private_data;

		sr_err = sr_get_changes_iter(session, ch_xpath, &it);
		if (sr_err != SR_ERR_OK)
			goto cleanup;

		while ((sr_get_change_next(session, it, &oper, &old_value,
					   &new_value)) == SR_ERR_OK) {
			remove_substr(new_value->xpath, "/port");
			remove_substr(new_value->xpath, "/ip-address");
			remove_substr(new_value->xpath, "/port");
			printf("%s\n", new_value->xpath);

			sr_err = sr_get_items(session, new_value->xpath, 0,
					      &values, &count);
			if (sr_err != SR_ERR_OK)
				goto cleanup;
			/*
            for (size_t i = 0; i < count; i++){
                sr_val_t *value = &values[i];
                new_value->xpath = remove_substr(xpath, XPATH_BASE"/");
            }
            */
		}
	cleanup:
		if (sr_err != (SR_ERR_OK && SR_ERR_NOT_FOUND))
			printf("%s\n", sr_strerror(sr_err));
		sr_free_values(values, count);
		sr_free_change_iter(it);
		sr_free_val(old_value);
		sr_free_val(new_value);
	}
	return SR_ERR_OK;
}
