#include <libyang/libyang.h>
#include <sysrepo.h>

#include "callbacks.h"
#include "conversion.h"
#include "common/sysrepo_conf.h"


static int kresd_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
sr_event_t event, uint32_t request_id, void *private_data)
{
	if(event == SR_EV_CHANGE)
	{
		/* validation actions*/
	}
	else if (event == SR_EV_DONE)
	{
		int err = SR_ERR_OK;
		sr_change_oper_t oper;
		sr_val_t *old_value = NULL;
		sr_val_t *new_value = NULL;
		sr_change_iter_t *it = NULL;

		err = sr_get_changes_iter(session, XPATH_BASE"/*/*//.", &it);
		if (err != SR_ERR_OK) goto cleanup;

		while ((sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {

			printf("%s\n", new_value->xpath);

			/* apply configuration here */

			sr_free_val(old_value);
			sr_free_val(new_value);
		}

		cleanup:
		sr_free_change_iter(it);

		if(err != SR_ERR_OK && err != SR_ERR_NOT_FOUND)
			printf("Error: %s\n",sr_strerror(err));
	}
	else if(event == SR_EV_ABORT)
	{
		/* abortion actions */
	}

	return SR_ERR_OK;
}

int sysrepo_subscr_register(sr_session_ctx_t *session, sr_subscription_ctx_t **subscription)
{
	int err = SR_ERR_OK;

	err = sr_module_change_subscribe(session, YM_COMMON, XPATH_BASE,
	kresd_change_cb, NULL, 0, SR_SUBSCR_NO_THREAD|SR_SUBSCR_ENABLED, subscription);
	if (err != SR_ERR_OK)
		return err;

	return err;
}