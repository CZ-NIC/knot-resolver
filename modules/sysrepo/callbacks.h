#pragma once

#include <libyang/libyang.h>
#include <sysrepo.h>

/** Register sysrepo subscriptions */
int sysrepo_subscr_register(sr_session_ctx_t *session, sr_subscription_ctx_t **subscription);