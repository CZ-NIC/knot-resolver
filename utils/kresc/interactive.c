#include <stdio.h>
#include <histedit.h>
#include <sysrepo.h>
#include <string.h>

#include "interactive.h"
#include "commands.h"
#include "process.h"

#define HISTORY_FILE	".kresc_history"


static void complete_cmd(EditLine *el, const char *str, size_t str_len)
{

}

static unsigned char cmd_completion(EditLine *el, int ch)
{
	const char **argv;
	int argc, token, pos;

	Tokenizer *tok = tok_init(NULL);
	const LineInfo *li = el_line(el);

    // Parse the line.
	int ret = tok_line(tok, li, &argc, &argv, &token, &pos);
	if (ret != 0) goto complete_exit;
	
    // Show all possible commands.
	if (argc == 0) {
		printf("\n");
		print_commands_help();
		goto complete_exit;
	}

	// Complete the command name.
	if (token == 0) {
		//complete_cmd(el, argv[0], pos);
		goto complete_exit;
	}

    /* commands completion will be here */

    complete_exit:
        tok_reset(tok);
        tok_end(tok);
        return CC_REDISPLAY;
}

static char *prompt(EditLine *el)
{
	return PROGRAM_NAME"> ";
}

int interactive_loop(params_t *params)
{
    EditLine *el = NULL;
	History *hist = NULL;
	char *hist_file = NULL;

    const char *home = getenv("HOME");
	if (home != NULL) asprintf(&hist_file, "%s/"HISTORY_FILE, home);

    el = el_init(PROGRAM_NAME, stdin, stdout, stderr);
	if (el == NULL) goto cleanup;
    
    hist = history_init();
    if (hist == NULL) {
        el_end(el);
        goto cleanup;
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
	       "Perform "PROGRAM_NAME" completion.", cmd_completion);
	el_set(el, EL_BIND, "^I",  PROGRAM_NAME"-complete", NULL);

    int count;
    const char *line;

	/* interactive loop */
    while ((line = el_gets(el, &count)) != NULL && count > 0) {

		history(hist, &hev, H_ENTER, line);
		Tokenizer *tok = tok_init(NULL);

		int argc, ret;
		const char **argv;
		const LineInfo *li = el_line(el);
		ret = tok_line(tok, li, &argc, &argv, NULL, NULL);
		if (ret != 0) continue;

		ret = process_cmd(argc, argv, params);

		history(hist, &hev, H_SAVE, hist_file);
		tok_reset(tok);
		tok_end(tok);

		// Check for the exit command.
		if (ret == -1) break;
	}

    el_end(el);
    history_end(hist);

    cleanup:
        free(hist_file);
        return 0;
}