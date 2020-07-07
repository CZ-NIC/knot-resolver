#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "kresconfig.h"
#include "interactive.h"
#include "process.h"
#include "commands.h"


params_t params = {
	.timeout = SYSREPO_TIMEOUT * 1000
};

sysrepo_ctx_t *sysrepo_ctx;
sysrepo_ctx_t sysrepo_ctx_value = {
    .connection = NULL,
	.session = NULL
};

static void print_help(void)
{
	print_version(NULL);

	printf("\nUsage:\n"
	       " %s [parameters] <command> [command-arguments]\n"
	       "\n"
	       "Parameters:\n"
	       " -t, --timeout <sec> "SPACE"Timeout for sysrepo operations.\n"
	       "                     "SPACE" (default %d seconds)\n"
	       " -h, --help          "SPACE"Print the program help.\n"
	       " -V, --version       "SPACE"Print the program version.\n",
	       PROGRAM_NAME, SYSREPO_TIMEOUT);

	print_commands(NULL);
}

int main(int argc, char *argv[])
{
	/* Long options. */
	struct option opts[] = {
		{ "timeout", required_argument, NULL, 't' },
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, 'V' },
		{ NULL }
	};

	/* Init sysrepo connection */
	sysrepo_ctx = &sysrepo_ctx_value;
	int ret = sr_connect(0, &sysrepo_ctx->connection);
	if (ret){
		printf("[kresctl] failed to connect to sysrepo:  %s\n",
		       sr_strerror(ret));
		goto sr_cleanup;
	}

	/* Create dynamic commands table */
	ret = create_cmd_table(sysrepo_ctx->connection);
	if (ret){
		printf("[kresctl] failed to create commands table\n");
		goto sr_cleanup;
	}

	/* Parse command line parameters */
	int opt = 0;
	while ((opt = getopt_long(argc, argv, "+t:hV", opts, NULL)) != -1) {
		switch (opt) {
			case 't':
				params.timeout = atoi(optarg);
				if (params.timeout < 1) {
					printf("[kresctl] error '-t' requires a positive"
					       " number, not '%s'\n", optarg);
					return EXIT_FAILURE;
				}
				/* Convert to milliseconds. */
				params.timeout *= 1000;
				break;
			case 'h':
				print_help();
				return EXIT_SUCCESS;
			case 'V':
				print_version(NULL);
				return EXIT_SUCCESS;
			default:
				print_help();
				return EXIT_FAILURE;
		}
	}

	if (argc - optind < 1) {
		/* start interactive loop */
		ret = interactive_loop(&params);
	} else {
		/*
		 * Session with RUNNING datastore
		 * needs to be created here, because there
		 * is no interactive loop to create
		 * transaction with candidate datastore.
		 */
		ret = sr_session_start(sysrepo_ctx->connection, SR_DS_RUNNING, &sysrepo_ctx->session);
		if (ret) {
			printf("failed to start sysrepo session, %s\n", sr_strerror(ret));
			goto cleanup;
		}
		/* execute commands added from terminal */
		if (!ret) ret = process_cmd(argc - optind, (const char **)argv + optind, &params);

		/* Stop sysrepo session. */
		ret = sr_session_stop(sysrepo_ctx->session);
		if (ret) {
			printf("failed to stop sysrepo session, %s\n", sr_strerror(ret));
		}
	}

cleanup:
	/* free all dynamic tables */
	destroy_cmd_table();

sr_cleanup:
	sr_disconnect(sysrepo_ctx->connection);

	return (ret == CLI_EOK) ? EXIT_SUCCESS : EXIT_FAILURE;
}