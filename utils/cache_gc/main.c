#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <libyang/libyang.h>
#include <sysrepo.h>

#include <lib/defines.h>
#include <libknot/libknot.h>

#include "kr_cache_gc.h"

volatile static int killed = 0;

const char *kr_mod_name = "cznic-resolver-common";
const char *gc_xpath = "/cznic-resolver-common:dns-resolver/cache/cznic-resolver-knot:garbage-collector";

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

char *sub_str_remove(char *str, const char *sub) {
    char *p, *q, *r;
    if ((q = r = strstr(str, sub)) != NULL) {
        size_t len = strlen(sub);
        while ((r = strstr(p = r + len, sub)) != NULL) {
            memmove(q, p, r - p);
            q += r - p;
        }
        memmove(q, p, strlen(p) + 1);
    }
    return str;
}

char* concat(const char *s1, const char *s2)
{
    const size_t len1 = strlen(s1);
    const size_t len2 = strlen(s2);
    char *result = malloc(len1 + len2 + 1); // +1 for the null-terminator
    // in real code you would check for errors in malloc here
    memcpy(result, s1, len1);
    memcpy(result + len1, s2, len2 + 1); // +1 to copy the null-terminator
    return result;
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

int set_gc_config(sr_val_t *value){
    char *option;
    option = sub_str_remove(value->xpath, gc_xpath);

    if (strcmp(option, "/collecting-interval")==0)        
        cfg.gc_interval = value->data.uint64_val*1000;
    else 
    if (strcmp(option, "/trigger-threshold")==0)     
        cfg.cache_max_usage = value->data.uint8_val;
    else 
    if (strcmp(option, "/release-percentage")==0)
        cfg.cache_to_be_freed = value->data.uint8_val;
    else 
    if (strcmp(option, "/temporary-keys-space")==0)
        cfg.temp_keys_space = value->data.uint64_val;
    else 
    if (strcmp(option, "/rw-items")==0)
        cfg.rw_txn_items = value->data.uint64_val;
    else 
    if (strcmp(option, "/rw-duration")==0)
        cfg.rw_txn_duration = value->data.uint64_val;
    else 
    if (strcmp(option, "/rw-delay")==0)
        cfg.rw_txn_delay = value->data.uint64_val;
    else 
    if (strcmp(option, "/dry-run")==0)
        cfg.dry_run = value->data.bool_val;
    else
        return 1;
    return 0;
}

int set_current_config(sr_session_ctx_t *session, const char *module_name)
{

	sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char *xpath,*cpath;

    /* get location of the cache */
    /*
    sr_get_item(session,"",0,&cpath);
    cfg.cache_path = cpath;
    free(cpath);
    */
    asprintf(&xpath, "%s/*", gc_xpath);

    rc = sr_get_items(session, xpath, 0, &values, &count);
    free(xpath);

    if (rc != SR_ERR_OK) {
        return rc;
    }

    for (size_t i = 0; i < count; i++){

        sr_val_t *value = &values[i];

        rc = set_gc_config(value);

        if (rc != SR_ERR_OK) {
            printf("Error (%s)\n", sr_strerror(rc));      
        }
    }
    
    sr_free_values(values, count);
    return SR_ERR_OK;
}

static int gc_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, 
                        sr_event_t event, uint32_t request_id, void *private_data)
{
    sr_change_oper_t oper;
    sr_change_iter_t *it = NULL;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    int rc = SR_ERR_OK;

    (void)xpath;
    (void)request_id;
    (void)private_data;

    

    rc = sr_get_changes_iter(session, "//." , &it);
    if (rc != SR_ERR_OK) {
        goto cleanup;    
    }

    if (event == SR_EV_CHANGE){
        printf("Sysrepo: Configuration change callback.\n");

        while ((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            rc = set_gc_config(new_value);
            sr_free_val(old_value);
            sr_free_val(new_value);

            if (rc != SR_ERR_OK) {
                goto cleanup;    
            }
        }
    }  

    if (event == SR_EV_DONE) {
        printf("Sysrepo: Configuration succesfully changed.\n");
    }

cleanup:
    sr_free_change_iter(it);
    return SR_ERR_OK;
}

static int op_data_request_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, 
                              uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    //(void)session;
    //(void)request_xpath;
    //(void)request_id;
    //(void)private_data;

    if (!strcmp(module_name, kr_mod_name) && !strcmp(xpath, concat(gc_xpath,"/version"))) {
        *parent = lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), concat(gc_xpath,"/version"), KR_CACHE_GC_VERSION, 0, 0);
    }

    return SR_ERR_OK;
}

int main(int argc, char *argv[])
{
	printf("Knot Resolver Cache Garbage Collector v. %s\n", KR_CACHE_GC_VERSION);

	signal(SIGTERM, got_killed);
	signal(SIGKILL, got_killed);
	signal(SIGPIPE, got_killed);
	signal(SIGCHLD, got_killed);
	signal(SIGINT, got_killed);
/*
	kr_cache_gc_cfg_t cfg = {
		.rw_txn_items = 100,
		.cache_max_usage = 80,
		.cache_to_be_freed = 10
	};
*/
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
	sr_conn_ctx_t *sr_connection = NULL;
    sr_session_ctx_t *sr_session = NULL;
    sr_subscription_ctx_t *sr_subscription = NULL;
    sr_subscription_ctx_t *sr_oper_subscr = NULL;

    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    rc = sr_connect(0, &sr_connection);
    if (rc != SR_ERR_OK) {
        printf("Error (%s)\n", sr_strerror(rc));
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(sr_connection, SR_DS_RUNNING, &sr_session);
    if (rc != SR_ERR_OK) {
        printf("Error (%s)\n", sr_strerror(rc));
        goto cleanup;
    }

	/* Set current Garbage collector configuration */
	rc = set_current_config(sr_session, kr_mod_name);
    if (rc != SR_ERR_OK) {
        printf("Error (%s)\n", sr_strerror(rc));
        goto cleanup;
    }

	/* subscribe for changes in running config */
    rc = sr_module_change_subscribe(sr_session, kr_mod_name, gc_xpath, gc_change_cb, NULL, 0, SR_SUBSCR_NO_THREAD , &sr_subscription);
    if (rc != SR_ERR_OK) {
        printf("Error (%s)\n", sr_strerror(rc));
        goto cleanup;
    }
    /* subscribe for providing the operational data */
    rc = sr_oper_get_items_subscribe(sr_session, kr_mod_name, concat(gc_xpath,"/version"), op_data_request_cb, NULL, SR_SUBSCR_NO_THREAD, &sr_oper_subscr);
    if (rc != SR_ERR_OK) {
        printf("Error (%s)\n", sr_strerror(rc));
        goto cleanup;
    }

	do {
		int ret = kr_cache_gc(&cfg);
		// ENOENT: kresd may not be started yet or cleared the cache now
		if (ret && ret != -ENOENT) {
			printf("Error (%s)\n", knot_strerror(ret));
			return 10;
		}

		//usleep(cfg.gc_interval);
        int sleep_time = 0;
        do {
            rc = sr_process_events(sr_subscription, sr_session, NULL);
            if (rc != SR_ERR_OK) {
                printf("Error (%s)\n", sr_strerror(rc));
            }
            rc = sr_process_events(sr_oper_subscr, sr_session, NULL);
            if (rc != SR_ERR_OK) {
                printf("Error (%s)\n", sr_strerror(rc));
            }
            if (cfg.gc_interval<100){
                usleep(100);          
            }
            sleep_time += 100;
        }while( sleep_time < cfg.gc_interval);

	} while (cfg.gc_interval > 0 && !killed);

	cleanup:
	sr_disconnect(sr_connection);

	return 0;
}
