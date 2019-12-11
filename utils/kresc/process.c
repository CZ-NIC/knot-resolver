#include <sysrepo.h>
#include <string.h>

#include "process.h"

int process_cmd(int argc, const char **argv, params_t *params)
{
    int ret = 0;
    int sr_err = SR_ERR_OK;
	sr_conn_ctx_t *sr_connection = NULL;
    sr_session_ctx_t *sr_session = NULL;

    sr_err = sr_connect(0, &sr_connection);
    if (sr_err != SR_ERR_OK) goto cleanup;
    
    sr_err = sr_session_start(sr_connection, SR_DS_CANDIDATE, &sr_session);
    if (sr_err != SR_ERR_OK) goto cleanup;

    /* TODO: processing commands */

    cleanup:
        if (sr_err != SR_ERR_OK) printf("Error (%s)\n", sr_strerror(sr_err));
        sr_disconnect(sr_connection);
        return ret;
}

