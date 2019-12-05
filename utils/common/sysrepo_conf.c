//#include <assert.h>
//#include <string.h>
#include "sysrepo_conf.h"


int configure_sysrepo(sr_conn_ctx_t *connection){

    int sr_rc = SR_ERR_OK;
    const char *set_group = "set-group";

    sr_rc = sr_install_module(connection, YM_COMMON, YM_DIR, NULL, 1);
    if (sr_rc != SR_ERR_OK) goto cleanup;

    sr_rc = sr_enable_module_feature(connection, YM_COMMON, set_group);
    if (sr_rc != SR_ERR_OK) goto cleanup;

    sr_rc = sr_install_module(connection, YM_KNOT, YM_DIR, NULL, 0);
    if (sr_rc != SR_ERR_OK) goto cleanup;

    cleanup:
        return sr_rc;
}
/*
// TODO: zatim nefunguje
int install_startup_configuration(char *file_path, LYD_FORMAT file_format, sr_client_ctx_t *client_ctx){

    int sr_rc = SR_ERR_OK;
    struct lyd_node *startup_data;
    struct ly_ctx *ly_ctx;
    

    ly_ctx = (struct ly_ctx *)sr_get_context(sr_session_get_connection(client_ctx->session));

    if (file_format == LYD_UNKNOWN) {
        if (!file_path) return 1;

        char *ptr = strrchr(file_path, '.');
        if (ptr && !strcmp(ptr, ".xml"))  
            file_format = LYD_XML;
        else if (ptr && !strcmp(ptr, ".json")) 
            file_format = LYD_JSON;
        else if (ptr && !strcmp(ptr, ".lyb")) 
            file_format = LYD_LYB;
        else 
            return 1;
    }

    // do not validate candidate data 
    if (sr_session_get_ds(sess) == SR_DS_CANDIDATE) {
        flags |= LYD_OPT_TRUSTED;
    }

    // parse import data 
    if (file_path) {
        *startup_data = lyd_parse_path(ly_ctx, file_path, file_format, flags, NULL);
    } else {
        //we need to load the data into memory first 
        if (step_read_file(stdin, &ptr)) {
            return EXIT_FAILURE;
        }
        *data = lyd_parse_mem(ly_ctx, ptr, format, flags);
        free(ptr);
    }
    if (ly_errno) {
        error_ly_print(ly_ctx);
        error_print(0, "Data parsing failed");
        return EXIT_FAILURE;
    }


    flags = LYD_OPT_CONFIG | LYD_OPT_TRUSTED | (not_strict ? 0 : LYD_OPT_STRICT);

    sr_rc = step_load_data(sess, file_path, format, flags, &data));
    if (sr_rc != SR_ERR_OK) goto cleanup;

    sr_rc = sr_replace_config(client_ctx->session, YANG_MODULE_COMMON, startup_data, sr_session_get_ds(client_ctx->session), 0);
    if (sr_rc != SR_ERR_OK) goto cleanup;

    cleanup:
    return sr_rc;

}
*/


