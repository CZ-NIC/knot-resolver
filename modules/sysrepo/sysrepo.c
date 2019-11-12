#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>

#include <sysrepo.h>
#include <uv.h>

#include "lib/module.h"
#include "daemon/worker.h"
#include "daemon/network.h"

typedef struct subscr subscr_t;
/** Callback for our sysrepo subscriptions */
typedef void (*subscr_cb)(subscr_t *sub, int status);

/** Context for our sysrepo subscriptions.
 * might add some other fields in future */
struct subscr {
	sr_subscription_ctx_t *sr_ctx;
    sr_session_ctx_t * sr_session;
	subscr_cb cb;
	uv_poll_t uv_handle;
};

static sr_conn_ctx_t *sr_connection;

void subscr_finish_closing(uv_handle_t *handle)
{
	subscr_t *sub = handle->data;
	assert(sub);
	free(sub);
}
/** Free a subscription. */
void subscr_free(subscr_t *sub)
{
	uv_close((uv_handle_t *)&sub->uv_handle, subscr_finish_closing);  
}

static void subscr_cb_tramp(uv_poll_t *handle, int status, int events)
{
	subscr_t *sub = handle->data;
	sub->cb(sub, status);
}
/** Start a new subscription.  */
static subscr_t * subscr_new(sr_subscription_ctx_t *sr_sub, subscr_cb cb)
{
	int fd;
	errno = sr_get_event_pipe(sr_sub, &fd);
	if (errno != SR_ERR_OK) return NULL;
	subscr_t *sub = malloc(sizeof(*sub));
	if (!sub) return NULL;
	errno = uv_poll_init(uv_default_loop(), &sub->uv_handle, fd);
	if (errno) {
		free(sub);
		return NULL;
	}
    sub->sr_ctx = sr_sub;
    sub->cb = cb;
	sub->uv_handle.data = sub;
	errno = uv_poll_start(&sub->uv_handle, UV_READABLE, subscr_cb_tramp);
	if (errno) {
		subscr_free(sub);
		return NULL;
	}
	return sub;
}

static void print_val(const sr_val_t *value)
{
    if (NULL == value) {
        return;
    }

    printf("%s ", value->xpath);

    switch (value->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        printf("(container)");
        break;
    case SR_LIST_T:
        printf("(list instance)");
        break;
    case SR_STRING_T:
        printf("= %s", value->data.string_val);
        break;
    case SR_BOOL_T:
        printf("= %s", value->data.bool_val ? "true" : "false");
        break;
    case SR_DECIMAL64_T:
        printf("= %g", value->data.decimal64_val);
        break;
    case SR_INT8_T:
        printf("= %" PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        printf("= %" PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        printf("= %" PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        printf("= %" PRId64, value->data.int64_val);
        break;
    case SR_UINT8_T:
        printf("= %" PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        printf("= %" PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        printf("= %" PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        printf("= %" PRIu64, value->data.uint64_val);
        break;
    case SR_IDENTITYREF_T:
        printf("= %s", value->data.identityref_val);
        break;
    case SR_INSTANCEID_T:
        printf("= %s", value->data.instanceid_val);
        break;
    case SR_BITS_T:
        printf("= %s", value->data.bits_val);
        break;
    case SR_BINARY_T:
        printf("= %s", value->data.binary_val);
        break;
    case SR_ENUM_T:
        printf("= %s", value->data.enum_val);
        break;
    case SR_LEAF_EMPTY_T:
        printf("(empty leaf)");
        break;
    default:
        printf("(unprintable)");
        break;
    }

    switch (value->type) {
    case SR_UNKNOWN_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LIST_T:
    case SR_LEAF_EMPTY_T:
        printf("\n");
        break;
    default:
        printf("%s\n", value->dflt ? " [default]" : "");
        break;
    }
}

static void print_change(sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val)
{
    switch(op) {
    case SR_OP_CREATED:
        printf("CREATED: ");
        print_val(new_val);
        break;
    case SR_OP_DELETED:
        printf("DELETED: ");
        print_val(old_val);
        break;
    case SR_OP_MODIFIED:
        printf("MODIFIED: ");
        print_val(old_val);
        printf("to ");
        print_val(new_val);
        break;
    case SR_OP_MOVED:
        printf("MOVED: %s\n", new_val->xpath);
        break;
    }
}

static void set_current_config(sr_session_ctx_t *session, const char *module_name)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char *xpath;

    asprintf(&xpath, "/%s:*//.", module_name);

    rc = sr_get_items(session, xpath, 0, &values, &count);
    free(xpath);
    if (rc != SR_ERR_OK) {
        return;
    }

    printf("\n\nCHANGING CONFIG TO: \n");

    for (size_t i = 0; i < count; i++){

        sr_val_t *value = &values[i];

        if (strcmp(value->xpath,"/cznic-resolver-common:dns-resolver/cache/min-ttl")==0)
        {         
            the_worker->engine->resolver.cache.ttl_min = value->data.uint32_val;
            printf("\n%s = %d\n", value->xpath, value->data.uint32_val);
        }
        else if (strcmp(value->xpath,"/cznic-resolver-common:dns-resolver/cache/max-ttl")==0){
            the_worker->engine->resolver.cache.ttl_max = value->data.uint32_val;
            printf("\n%s = %d\n", value->xpath, value->data.uint32_val);
        }
    }
    printf("\n\n");

    sr_free_values(values, count);
}

const char *ev_to_str(sr_event_t ev)
{
    switch (ev) {
    case SR_EV_CHANGE:
        return "CHANGE";
    case SR_EV_DONE:
        return "DONE";
    case SR_EV_ABORT:
    default:
        return "ABORT";
    }
}

static int module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;

    (void)xpath;
    (void)request_id;
    (void)private_data;

    rc = sr_get_changes_iter(session, "//." , &it);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    if (event == SR_EV_CHANGE){
        printf("\n\n%s callback\n\n", ev_to_str(event));

        while ((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            print_change(oper, old_value, new_value);
            sr_free_val(old_value);
            sr_free_val(new_value);
        }
    }

    if (event == SR_EV_DONE) {   
        set_current_config(session, module_name);
    }

cleanup:
    sr_free_change_iter(it);
    return SR_ERR_OK;
}

static void new_subscr_cb(subscr_t *sub, int status)
{
	if (status) {
		/* some error */
		return;
	}
	/* normal state */
    sr_process_events(sub->sr_ctx, sub->sr_session,NULL);
}

KR_EXPORT
int sysrepo_init(struct kr_module *module)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;
    const char *mod_name, *xpath = NULL;
    mod_name = "cznic-resolver-common";

    /* connect to sysrepo */
    rc = sr_connect(0, &connection);
    if (rc != SR_ERR_OK) {
        sr_disconnect(sr_connection);
        return kr_error(rc);
    }

    sr_connection = connection;

    /* start session with sysrepo */
    rc = sr_session_start(connection, SR_DS_RUNNING, &session);
    if (rc != SR_ERR_OK) {
        sr_disconnect(sr_connection);
        return kr_error(rc);
    }

    /* read and set current config to knot-resolver*/
    set_current_config(session, mod_name);

    /* subscribe for changes */
    rc = sr_module_change_subscribe(session, mod_name, xpath, module_change_cb, NULL, 0, SR_SUBSCR_NO_THREAD , &subscription);
    if (rc != SR_ERR_OK) {
        sr_disconnect(sr_connection);
        return kr_error(rc);
    }

    /* add subscription to event loop */
    subscr_t *subscr_ctx = subscr_new(subscription, new_subscr_cb);
    subscr_ctx->sr_session = session;
    module->data = subscr_ctx;

    return kr_ok();  
}

KR_EXPORT
int sysrepo_deinit(struct kr_module *module)
{
    sr_disconnect(sr_connection);
    subscr_t *data = module->data;
    subscr_free(data);
    
    return kr_ok();
}

KR_MODULE_EXPORT(sysrepo)
