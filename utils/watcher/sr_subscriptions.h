#pragma once

#include <sysrepo.h>
#include <libyang/libyang.h>

int sysrepo_subscr_register(sr_session_ctx_t *session, sr_subscription_ctx_t **subscription);

int set_tst_secret(const char *secret);

int resolver_start();
