#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>

#include "sysrepo.h"
#include "lib/module.h"

static void* observe(void *arg)
{
        /* ... do some observing ... */
}

int sysrepo_init(struct kr_module *module)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;
    const char *mod_name, *xpath = NULL;
}

int sysrepo_deinit(struct kr_module *module)
{

}

KR_MODULE_EXPORT(sysrepo)
