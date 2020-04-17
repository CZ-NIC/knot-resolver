#include <stdio.h>
#include <histedit.h>

#include <sysrepo.h>
#include <libyang/libyang.h>

#include "common.h"
#include "interactive.h"
#include "process.h"


sr_conn_ctx_t *sr_connection = NULL;
sr_session_ctx_t *sr_session = NULL;

static unsigned char complete(EditLine *el, int ch)
{

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

    // TODO: sysrepo connection
    if (sr_connect(0, &sr_connection)) {
        goto cleanup;
    }

    int count;
    const char *line;
    while ((line = el_gets(el, &count)) != NULL && count > 0) {
        history(hist, &hev, H_ENTER, line);

        Tokenizer *tok = tok_init(NULL);

        /* Tokenize the current line */
        int argc;
        const char **argv;
        const LineInfo *li = el_line(el);
        int ret = tok_line(tok, li, &argc, &argv, NULL, NULL);
        if (ret != 0) {
            continue;
        }

        history(hist, &hev, H_SAVE, hist_file);
        tok_reset(tok);
        tok_end(tok);
    }

    cleanup:
    // TODO: sysrepo cleanup
    sr_disconnect(sr_connection);

    history_end(hist);
    free(hist_file);

    el_end(el);

    return 0;
}