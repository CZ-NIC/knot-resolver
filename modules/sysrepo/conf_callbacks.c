#include <string.h>
#include <sysrepo.h>

#include "conf_callbacks.h"
#include "conf_conversion.h"
#include "utils/common/sysrepo_conf.h"
#include "utils/common/string_helper.h"


int conf_set_current(sr_session_ctx_t *session, const char *module_name)
{ 
    size_t count = 0;  
    int sr_err = SR_ERR_OK;
    sr_val_t *values = NULL;
    char *xpath = NULL;

    sr_err = sr_get_items(session, XPATH_BASE"/*//.", 0, &values, &count);
    if (sr_err != SR_ERR_OK) goto cleanup;

    for (size_t i = 0; i < count; i++){

        sr_val_t *value = &values[i];
        value->xpath = remove_substr(value->xpath, XPATH_BASE);

        if (starts_with(value->xpath, "/cache") == 0)
            conf_cache(value);
    }

    cleanup:
        free(xpath);
        sr_free_values(values, count);
        return sr_err;
}

int conf_cache_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data){

    int sr_err = SR_ERR_OK;
    sr_change_iter_t *it = NULL;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;

    (void)xpath;
    (void)request_id;
    (void)private_data;

    sr_err = sr_get_changes_iter(session, XPATH_BASE"/cache//." , &it);    
    if (sr_err != SR_ERR_OK) goto cleanup;
    
    if (event == SR_EV_DONE) {
        while ((sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            new_value->xpath = remove_substr(new_value->xpath, XPATH_BASE);
            
            if (starts_with(new_value->xpath, "/cache") == 0)
                conf_cache(new_value);
        }      
    }
    else if(event == SR_EV_ABORT)
    {
        /* code */
    }
    
    cleanup:
        if(sr_err != (SR_ERR_OK && SR_ERR_NOT_FOUND)) printf("%s\n",sr_strerror(sr_err));
        sr_free_val(old_value);
        sr_free_val(new_value);
        sr_free_change_iter(it);   
        return SR_ERR_OK;
            
}
