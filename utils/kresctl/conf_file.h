#pragma once

#include <sysrepo.h>
#include <libyang/libyang.h>


int step_load_data(sr_session_ctx_t *sess, const char *file_path, int flags, struct lyd_node **data);
