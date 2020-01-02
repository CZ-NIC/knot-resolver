#pragma once

#include <sysrepo.h>

int conf_set_current(sr_session_ctx_t *session, const char *module_name);

int cache_change_cb(sr_session_ctx_t *session, const char *module_name,
		    const char *xpath, sr_event_t event, uint32_t request_id,
		    void *private_data);

int net_change_cb(sr_session_ctx_t *session, const char *module_name,
		  const char *xpath, sr_event_t event, uint32_t request_id,
		  void *private_data);
