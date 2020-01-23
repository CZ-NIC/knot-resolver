#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <lib/defines.h>
#include <libknot/libknot.h>

#include "kresconfig.h"
#include "kr_cache_gc.h"

#ifdef ENABLE_SYSREPO

#include <poll.h>
#include <string.h>

#include <sysrepo.h>
#include <libyang/libyang.h>

#include "modules/sysrepo/common/sysrepo_conf.h"
#include "modules/sysrepo/common/string_helper.h"

#endif

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

#ifdef ENABLE_SYSREPO

static int get_gc_version_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	const char *gc_version_xpath = XPATH_GC"/version";

	if (!strcmp(module_name, YM_COMMON) && !strcmp(xpath, gc_version_xpath))
	{
		lyd_new_path(*parent, NULL, gc_version_xpath, KR_CACHE_GC_VERSION, 0, 0);
	}
	return SR_ERR_OK;
}

static int cache_storage_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
sr_event_t event, uint32_t request_id, void *private_data)
{
	if(event == SR_EV_CHANGE)
	{
		/* validation actions*/
	}
	else if (event == SR_EV_DONE)
	{
		int sr_err = SR_ERR_OK;
		sr_change_oper_t oper;
		sr_val_t *old_value = NULL;
		sr_val_t *new_value = NULL;
		sr_change_iter_t *it = NULL;

		sr_err = sr_get_changes_iter(session, XPATH_BASE"/cache/"YM_KRES":storage" , &it);
		if (sr_err != SR_ERR_OK) goto cleanup;

		while ((sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {

			strcpy(cfg.cache_path , new_value->data.string_val);

			sr_free_val(old_value);
			sr_free_val(new_value);
		}

		cleanup:
		sr_free_change_iter(it);

		if(sr_err != SR_ERR_OK && sr_err != SR_ERR_NOT_FOUND)
			printf("Error: %s\n",sr_strerror(sr_err));
	}
	else if(event == SR_EV_ABORT)
	{
		/* abortion actions */
	}
	return SR_ERR_OK;
}

static int cache_gc_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
sr_event_t event, uint32_t request_id, void *private_data)
{
	if(event == SR_EV_CHANGE)
	{
		/* validation actions*/
	}
	else if (event == SR_EV_DONE)
	{
		int sr_err = SR_ERR_OK;
		sr_change_oper_t oper;
		sr_val_t *old_value = NULL;
		sr_val_t *new_value = NULL;
		sr_change_iter_t *it = NULL;

		sr_err = sr_get_changes_iter(session, XPATH_GC"/*/." , &it);
		if (sr_err != SR_ERR_OK) goto cleanup;

		while ((sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {

			const char *leaf = remove_substr(new_value->xpath, XPATH_GC"/");

			if (!strcmp(leaf, "interval"))
				cfg.gc_interval = new_value->data.uint64_val*1000;
			else if (!strcmp(leaf, "threshold"))
				cfg.cache_max_usage = new_value->data.uint8_val;
			else if (!strcmp(leaf, "release-percentage"))
				cfg.cache_to_be_freed = new_value->data.uint8_val;
			else if (!strcmp(leaf, "temporary-keys-space"))
				cfg.temp_keys_space = new_value->data.uint64_val*1048576;
			else if (!strcmp(leaf, "rw-items"))
				cfg.rw_txn_items = new_value->data.uint64_val;
			else if (!strcmp(leaf, "rw-duration"))
				cfg.rw_txn_duration = new_value->data.uint64_val;
			else if (!strcmp(leaf, "rw-delay"))
				cfg.rw_txn_delay = new_value->data.uint64_val;
			else if (!strcmp(leaf, "dry-run"))
				cfg.dry_run = new_value->data.bool_val;
			else
				printf("Uknown configuration option: %s\n", leaf);

			sr_free_val(old_value);
			sr_free_val(new_value);
		}

		cleanup:
		sr_free_change_iter(it);

		if(sr_err != SR_ERR_OK && sr_err != SR_ERR_NOT_FOUND)
			printf("Error: %s\n",sr_strerror(sr_err));
	}
	else if(event == SR_EV_ABORT)
	{
		/* abortion actions */
	}
	return SR_ERR_OK;
}

#endif

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

	#ifdef ENABLE_SYSREPO
	int fd;
	int rv = SR_ERR_OK;
	struct pollfd fds[1];
	sr_conn_ctx_t *sr_connection = NULL;
	sr_session_ctx_t *sr_session = NULL;
	sr_subscription_ctx_t *sr_subscription = NULL;

	rv = sr_connect(0, &sr_connection);
	if (rv != SR_ERR_OK) goto sr_error;

	rv = sr_connection_recover(sr_connection);
	if (rv != SR_ERR_OK) goto sr_error;

	rv = sr_session_start(sr_connection, SR_DS_RUNNING, &sr_session);
	if (rv != SR_ERR_OK) goto sr_error;

	/* config data subscriptions*/
	rv = sr_module_change_subscribe(sr_session, YM_COMMON, XPATH_GC, cache_gc_change_cb, NULL, 0, SR_SUBSCR_NO_THREAD|SR_SUBSCR_ENABLED, &sr_subscription);
	if (rv != SR_ERR_OK) goto sr_error;

	rv = sr_module_change_subscribe(sr_session, YM_COMMON, XPATH_BASE"/cache/"YM_KRES":storage", cache_storage_change_cb, NULL, 0, SR_SUBSCR_NO_THREAD|SR_SUBSCR_ENABLED|SR_SUBSCR_CTX_REUSE, &sr_subscription);
	if (rv != SR_ERR_OK) goto sr_error;

	/* state data subscriptions*/
	rv = sr_oper_get_items_subscribe(sr_session, YM_COMMON, XPATH_GC"/version", get_gc_version_cb, NULL, SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, &sr_subscription);
	if (rv != SR_ERR_OK) goto sr_error;

	/* get file descriptor */
	rv = sr_get_event_pipe(sr_subscription, &fd);
	if (rv != SR_ERR_OK) goto sr_error;

	fds[0].fd = fd;
	fds[0].events = POLLIN;

	#endif

	do {
		int ret = kr_cache_gc(&cfg);
		// ENOENT: kresd may not be started yet or cleared the cache now
		if (ret && ret != -ENOENT) {
			printf("Error (%s)\n", knot_strerror(ret));
			#ifdef ENABLE_SYSREPO
				rv = 10;
				goto cleanup;
			#else
				return 10;
			#endif
		}

		#ifdef ENABLE_SYSREPO
			int poll_res = poll(fds, 1, (int)cfg.gc_interval/1000);
			if(poll_res > 0)
				sr_process_events(sr_subscription, sr_session, NULL);
			else if (poll_res < 0){
				rv = errno;
				if (rv && rv != EINTR)
					printf("Error (%s)\n", strerror(rv));
				goto cleanup;
			}
		#else
			usleep(cfg.gc_interval);
		#endif

	} while (cfg.gc_interval > 0 && !killed);

	#ifdef ENABLE_SYSREPO
		sr_error:
		if (rv != SR_ERR_OK)
			printf("Error (%s)\n", sr_strerror(rv));

		cleanup:
		sr_disconnect(sr_connection);

		return rv;
	#else
		return 0;
	#endif
}
