#pragma once

#include <sysrepo.h>

int conf_set_current(sr_session_ctx_t *session, const char *module_name);

int conf_cache_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

