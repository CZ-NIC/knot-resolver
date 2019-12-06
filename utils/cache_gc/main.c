#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libyang/libyang.h>
#include <sysrepo.h>
#include <poll.h>

#include <lib/defines.h>
#include <libknot/libknot.h>

#include "kr_cache_gc.h"
#include "utils/common/sysrepo_conf.h"
#include "utils/common/string_helper.h"

#define XPATH_GC    XPATH_BASE"/cache/cznic-resolver-knot:garbage-collector"

typedef struct pollfd pollfd_t;

volatile static int killed = 0;

kr_cache_gc_cfg_t cfg = {
		.rw_txn_items = 100,
		.cache_max_usage = 80,
		.cache_to_be_freed = 10
	};

static void got_killed(int signum)
{
	(void)signum;
	switch (++killed) {
	case 1:
		break;
	case 2:
		exit(5);
		break;
	case 3:
		abort();
	default:
		assert(0);
	}
}

static void print_help()
{
	printf("Usage: kr_cache_gc -c <resolver_cache> [ optional params... ]\n");
	printf("Optional params:\n");
	printf(" -d <garbage_interval(millis)>\n");
	printf(" -l <deletes_per_txn>\n");
	printf(" -m <rw_txn_duration(usecs)>\n");
	printf(" -u <cache_max_usage(percent)>\n");
	printf(" -f <cache_to_be_freed(percent)>\n");
	printf(" -w <wait_next_rw_txn(usecs)>\n");
	printf(" -t <temporary_memory(MBytes)>\n");
	printf(" -n (= dry run)\n");
}

static long get_nonneg_optarg()
{
	char *end;
	const long result = strtol(optarg, &end, 10);
	if (result >= 0 && end && *end == '\0')
		return result;
	// not OK
	print_help();
	exit(2);
}

int conf_gc(sr_val_t *value){

    value->xpath = remove_substr(value->xpath, XPATH_GC"/");

    if (!strcmp(value->xpath, "interval")){
        cfg.gc_interval = value->data.uint64_val*1000;
    }   
    else if (!strcmp(value->xpath, "threshold")){
        cfg.cache_max_usage = value->data.uint8_val;
    }   
    else if (!strcmp(value->xpath, "release-percentage")){
        cfg.cache_to_be_freed = value->data.uint8_val;
    }
    else if (!strcmp(value->xpath, "temporary-keys-space")){
        cfg.temp_keys_space = value->data.uint64_val;
    }
    else if (!strcmp(value->xpath, "rw-items")){
        cfg.rw_txn_items = value->data.uint64_val;
    }
    else if (!strcmp(value->xpath, "rw-duration")){
        cfg.rw_txn_duration = value->data.uint64_val;
    }
    else if (!strcmp(value->xpath, "rw-delay")){
        cfg.rw_txn_delay = value->data.uint64_val; 
    }
    else if (!strcmp(value->xpath, "dry-run")){
        cfg.dry_run = value->data.bool_val;
    }
    else return 1;

    return 0;
}

int conf_gc_set_current(sr_session_ctx_t *session, const char *module_name)
{
    size_t count = 0;  
    int sr_err = SR_ERR_OK;
    sr_val_t *values = NULL;

    sr_err = sr_get_items(session, XPATH_GC"/*//.", 0, &values, &count);
    if (sr_err != SR_ERR_OK) goto cleanup;

    for (size_t i = 0; i < count; i++){
        sr_val_t *value = &values[i];
        conf_gc(value);
    }
    cleanup:
        if(sr_err) printf("%s\n",sr_strerror(sr_err));
        sr_free_values(values, count);
        return sr_err;
}

static int gc_conf_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, 
                        sr_event_t event, uint32_t request_id, void *private_data)
{
    int sr_err = SR_ERR_OK;
    sr_change_iter_t *it = NULL;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;

    (void)xpath;
    (void)request_id;
    (void)private_data;

    sr_err = sr_get_changes_iter(session, XPATH_GC"//." , &it);    
    if (sr_err != SR_ERR_OK) goto cleanup;
    
    if (event == SR_EV_DONE) {
        while ((sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {       
            conf_gc(new_value);
        }      
    }
    else if(event == SR_EV_ABORT)
    {
        /* code */
    }
    
    cleanup:
        if(sr_err != (SR_ERR_OK && SR_ERR_NOT_FOUND)) 
            printf("%s\n",sr_strerror(sr_err));
        sr_free_val(old_value);
        sr_free_val(new_value);
        sr_free_change_iter(it);   
        return SR_ERR_OK;    
}

static int gc_version_request_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, 
                              uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    (void)session;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    if (!strcmp(module_name, YM_COMMON) && !strcmp(xpath, XPATH_GC"/version"))
        //TODO: this cause memory leaks, check it
        *parent = lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), XPATH_GC"/version", KR_CACHE_GC_VERSION, 0, 0);

    return SR_ERR_OK;
}

 pollfd_t *new_pollfd(sr_subscription_ctx_t *subscription){

    int fd, sr_err;
    sr_err = sr_get_event_pipe(subscription, &fd);
    if (sr_err != SR_ERR_OK) {
        printf("Error (%s)\n", sr_strerror(sr_err));
        return NULL;
    }

    pollfd_t *sr_poll = malloc(sizeof(sr_poll));
    sr_poll->fd = fd;
    sr_poll->events = POLLIN;

    return sr_poll;
}

int main(int argc, char *argv[])
{
	printf("Knot Resolver Cache Garbage Collector v. %s\n", KR_CACHE_GC_VERSION);

	signal(SIGTERM, got_killed);
	signal(SIGKILL, got_killed);
	signal(SIGPIPE, got_killed);
	signal(SIGCHLD, got_killed);
	signal(SIGINT, got_killed);

	int o;
	while ((o = getopt(argc, argv, "hnc:d:l:m:u:f:w:t:")) != -1) {
		switch (o) {
		case 'c':
			cfg.cache_path = optarg;
			break;
		case 'd':
			cfg.gc_interval = get_nonneg_optarg();
			cfg.gc_interval *= 1000;
			break;
		case 'l':
			cfg.rw_txn_items = get_nonneg_optarg();
			break;
		case 'm':
			cfg.rw_txn_duration = get_nonneg_optarg();
			break;
		case 'u':
			cfg.cache_max_usage = get_nonneg_optarg();
			break;
		case 'f':
			cfg.cache_to_be_freed = get_nonneg_optarg();
			break;
		case 'w':
			cfg.rw_txn_delay = get_nonneg_optarg();
			break;
		case 't':
			cfg.temp_keys_space = get_nonneg_optarg();
			cfg.temp_keys_space *= 1048576;
			break;
		case 'n':
			cfg.dry_run = true;
			break;
		case ':':
		case '?':
		case 'h':
			print_help();
			return 1;
		default:
			assert(0);
		}
	}

	if (cfg.cache_path == NULL) {
		print_help();
		return 1;
	}

	/* sysrepo client */
    int sr_err = SR_ERR_OK;
	sr_conn_ctx_t *sr_connection = NULL;
    sr_session_ctx_t *sr_session = NULL;
    sr_subscription_ctx_t *sr_subscription = NULL;
    pollfd_t *sr_poll = NULL;

    sr_err = sr_connect(0, &sr_connection);
    if (sr_err != SR_ERR_OK) goto cleanup;

    //sr_err = sr_connection_recover(sr_connection);
    //if (sr_err != SR_ERR_OK) goto cleanup;

    sr_err = sr_session_start(sr_connection, SR_DS_RUNNING, &sr_session);
    if (sr_err != SR_ERR_OK) goto cleanup;

    /* read and set current running configuration */
	sr_err = conf_gc_set_current(sr_session, YM_COMMON);
    if (sr_err != SR_ERR_OK) goto cleanup;

    /* setup sysrepo subscriptions */
    sr_err = sr_module_change_subscribe(sr_session, YM_COMMON, XPATH_GC, gc_conf_cb, NULL, 0, SR_SUBSCR_NO_THREAD, &sr_subscription);
    if (sr_err != SR_ERR_OK) goto cleanup;

    /* subscribe for providing the operational data */
    sr_err = sr_oper_get_items_subscribe(sr_session, YM_COMMON, XPATH_GC"/version", gc_version_request_cb, NULL, SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, &sr_subscription);
    if (sr_err != SR_ERR_OK) goto cleanup;

    sr_poll = new_pollfd(sr_subscription);
    if(!sr_poll) goto cleanup;

	do {
		int gc_ret = kr_cache_gc(&cfg);
		// ENOENT: kresd may not be started yet or cleared the cache now
		if (gc_ret && gc_ret != -ENOENT) {
			printf("Error (%s)\n", knot_strerror(gc_ret));
			goto cleanup;
		}

        int poll_ret = poll(sr_poll, (unsigned long)1, (int)cfg.gc_interval/1000);
        if(poll_ret) 
            sr_process_events(sr_subscription, sr_session, NULL);

	} while (cfg.gc_interval > 0 && !killed);

	cleanup:
        if (sr_err != SR_ERR_OK) 
            printf("Error (%s)\n", sr_strerror(sr_err));
        free(sr_poll);
	    sr_disconnect(sr_connection);

	return 0;
}
