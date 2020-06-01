#include <stdio.h>
#include <histedit.h>
#include <string.h>
#include <sysrepo.h>
#include <libyang/libyang.h>

#include <contrib/ccan/asprintf/asprintf.h>

#include "commands.h"
#include "interactive.h"
#include "process.h"


static void cmds_lookup(EditLine *el, const char *str, size_t str_len)
{
	//TODO: fill the lookup with command names
}

static unsigned char complete(EditLine *el, int ch)
{
	int argc, token, pos;
	const char **argv;

	const LineInfo *li = el_line(el);
	Tokenizer *tok = tok_init(NULL);

	/* Parse the line. */
	int ret = tok_line(tok, li, &argc, &argv, &token, &pos);
	if (ret != 0) {
		goto complete_exit;
	}

	/* Show possible commands. */
	if (argc == 0) {
		print_commands(NULL);
		goto complete_exit;
	}

	/* Complete the command name. */
	if (token == 0) {
		cmds_lookup(el, argv[0], pos);
		goto complete_exit;
	}

	/* Find the command descriptor. */
	const cmd_desc_t *desc = cmd_table;
	while (desc->name != NULL && strcmp(desc->name, argv[0]) != 0) {
		desc++;
	}
	if (desc->name == NULL) {
		goto complete_exit;
	}

	/* TODO: show list instances */

	complete_exit:
	tok_reset(tok);
	tok_end(tok);

	return CC_REDISPLAY;
}

static char *prompt(EditLine *el)
{
	return PROGRAM_NAME"> ";
}

int interactive_loop(params_t *process_params)
{
	char *hist_file = NULL;
	const char *home = getenv("HOME");
	if (home != NULL) {
		asprintf(&hist_file, "%s/"HISTORY_FILE, home);
	}
	if (hist_file == NULL) {
		printf("failed to get home directory");
	}

	EditLine *el = el_init(PROGRAM_NAME, stdin, stdout, stderr);
	if (el == NULL) {
		printf("interactive mode not available");
		free(hist_file);
		return 1;
	}

	History *hist = history_init();
	if (hist == NULL) {
		printf("interactive mode not available");
		el_end(el);
		free(hist_file);
		return 1;
	}

	HistEvent hev = { 0 };
	history(hist, &hev, H_SETSIZE, 100);
	el_set(el, EL_HIST, history, hist);
	history(hist, &hev, H_LOAD, hist_file);

	el_set(el, EL_TERMINAL, NULL);
	el_set(el, EL_EDITOR, "emacs");
	el_set(el, EL_PROMPT, prompt);
	el_set(el, EL_SIGNAL, 1);
	el_source(el, NULL);

	el_set(el, EL_ADDFN, PROGRAM_NAME"-complete",
	       "Perform "PROGRAM_NAME" completion.", complete);
	el_set(el, EL_BIND, "^I",  PROGRAM_NAME"-complete", NULL);

	int count;
	const char *line;
	while ((line = el_gets(el, &count)) != NULL && count > 0) {
		history(hist, &hev, H_ENTER, line);

		Tokenizer *tok = tok_init(NULL);

		/* Tokenize the current line. */
		int argc;
		const char **argv;
		const LineInfo *li = el_line(el);
		int ret = tok_line(tok, li, &argc, &argv, NULL, NULL);
		if (ret != 0) {
			continue;
		}

		/* Process the command. */
		ret = process_cmd(argc, argv, process_params);

		history(hist, &hev, H_SAVE, hist_file);
		tok_reset(tok);
		tok_end(tok);

		/* Check for the exit command. */
		if (ret == CLI_EXIT) {
			break;
		}
	}

	history_end(hist);
	free(hist_file);

	el_end(el);

	return 0;
}