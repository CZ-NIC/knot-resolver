#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <uv.h>
#include <string.h>
#include <stdbool.h>

#include <lib/defines.h>
#include <libknot/libknot.h>

#include "kresconfig.h"
#include "modules/sysrepo/common/sysrepo_utils.h"
#include "lib/utils.h"
#include "watcher.h"

#define CONF_FILE_DEF		"/etc/knot-resolver/kres-conf.json"
#define YMODS_PATH_DEF		"/etc/knot-resolver/yang-modules"
#define SPACE 				"    "

static void print_header()
{
	printf("Knot Resolver (%s) v. %s\n", PROGRAM_NAME, KR_WATCHER_VERSION);
}

static void print_help()
{
	print_header();

	printf("\n"
			"Usage: "PROGRAM_NAME" -c <file> -y <dir>\n"
			"\n"
			"Optional params:\n"
			" -c <file>"SPACE"Use a JSON/XML configuration file.\n"
			" -y <dir> "SPACE"Path to YANG modules directory.\n"
			" -h       "SPACE"Print the program help.\n"
			" -v       "SPACE"Print the program version.\n"
			"\n");
}

static void signal_handler(uv_signal_t *handle, int signum)
{
	uv_stop(uv_default_loop());
	uv_signal_stop(handle);
}

int sysrepo_preconfig(const char *ymods_path)
{
	int ret = 0;
	sr_conn_ctx_t *conn = NULL;

	/* connect to sysrepo */
	ret = sr_connect(0, &conn);
	if (ret) {
		kr_log_error("[sysrepo] failed to connect to sysrepo:  %s\n",
			sr_strerror(ret));
		goto cleanup;
	}

	/* configure sysrepo repository, install/update modules */
	ret = sysrepo_repository_configure(conn, ymods_path);
	if (ret == 6) {
		kr_log_info("[sysrepo] modules are up-to-date\n");
		ret = 0;
	}
	cleanup:
	sr_disconnect(conn);

	return ret;
}

int import_file_conf(const char *conf_file_path)
{
	int ret = 0;
	sr_conn_ctx_t *conn = NULL;
	sr_session_ctx_t *session = NULL;

	/* connect to sysrepo */
	ret = sr_connect(0, &conn);
	if (ret) {
		kr_log_error("[sysrepo] failed to connect to sysrepo:  %s\n",
			sr_strerror(ret));
		goto cleanup;
	}

	/* start sysrepo session with startup datastore to import
	startup configuration from file in next step*/
	ret = sr_session_start(conn, SR_DS_STARTUP, &session);
	if (ret) {
		kr_log_error("[sysrepo] failed to start sysrepo session:  %s\n",
			sr_strerror(ret));
		sr_disconnect(conn);
		goto cleanup;
	}

	/* import startup configuration from configuration file
	 * to startup datastore and then copy it to running datastore */
	kr_log_info("[sysrepo] imorting configuration from %s file\n", conf_file_path);

	ret = import_from_file(session, conf_file_path, YM_COMMON, LYD_JSON, 0, 0);
	if (!ret) ret = sr_copy_config(session, YM_COMMON, SR_DS_STARTUP, SR_DS_RUNNING, 0);
	if (ret) {
		kr_log_error("[sysrepo] failed to import configuration:  %s\n",
			sr_strerror(ret));
		goto cleanup;
	}
	kr_log_info("[sysrepo] configuration file succesfully imported\n");

	cleanup:
	/* client has to be disconnected and the connected again
	 * to update all changes in sysrepo */
	sr_disconnect(conn);

	return ret;
}

int main(int argc, char *argv[])
{
	int opt;
	const char *conf_file_path = CONF_FILE_DEF;
	const char *ymods_path = YMODS_PATH_DEF;

	while((opt = getopt(argc, argv, "+c:+y:vh")) != -1)
	{
		switch(opt)
		{
			case 'c':
				conf_file_path = optarg;
				break;
			case 'y':
				ymods_path = optarg;
				break;
			case ':':
			case '?':
			case 'v':
				printf("%s\n", KR_WATCHER_VERSION);
				return 1;
			case 'h':
				print_help();
				return 1;
		}
	}

	print_header();

	/* event loop init */
	int ret = 0;
	uv_signal_t sigint, sigterm;
	uv_loop_t *loop = uv_default_loop();

	if (true) ret = uv_signal_init(loop, &sigint);
	if (!ret) ret = uv_signal_init(loop, &sigterm);
	if (!ret) ret = uv_signal_start(&sigint, signal_handler, SIGINT);
	if (!ret) ret = uv_signal_start(&sigterm, signal_handler, SIGTERM);
	if (ret) goto cleanup;

	/* Preconfigure sysrepo before running kresd,
	 * install module and import configuration file */
	if (!ret) ret = sysrepo_preconfig(ymods_path);
	if (!ret) ret = import_file_conf(conf_file_path);
	if (ret) goto cleanup;

	/* Initialize and run watcher*/
	if (!ret) ret = watcher_init(loop);
	if (!ret) ret = watcher_run(loop);

	/* Deinit watcher */
	watcher_deinit(loop);

	cleanup:
	if (loop != NULL) {
		uv_loop_close(loop);
	}

	return ret;
}
